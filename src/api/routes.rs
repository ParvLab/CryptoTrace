use std::sync::Arc;
use std::time::Instant;

use axum::extract::Extension;
use axum::Json;

use crate::api::errors::ApiError;
use crate::sanitization::sandbox::Sandbox;
use crate::types::DetectionResult;

/// Shared application state injected via Extension.
pub struct AppState {
    pub startup_time: Instant,
    pub engine_version: String,
    pub sig_db_version: String,
    pub sandbox: Option<Sandbox>,
}

/// GET /health — returns service status, version, and uptime.
pub async fn health(
    Extension(state): Extension<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let uptime = state.startup_time.elapsed().as_secs();
    Ok(Json(serde_json::json!({
        "status": "ok",
        "engine_version": state.engine_version,
        "signature_db_version": state.sig_db_version,
        "uptime_seconds": uptime,
    })))
}

/// GET /version — returns engine and signature DB versions.
pub async fn version(
    Extension(state): Extension<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "engine": state.engine_version,
        "signature_db": state.sig_db_version,
    }))
}

/// Request body for POST /analyze.
#[derive(serde::Deserialize)]
pub struct AnalyzeRequest {
    /// Input string, file path, or base64-encoded data.
    pub input: String,
    /// How to interpret `input`: "string" (default), "file", or "base64".
    #[serde(default = "default_input_type")]
    pub input_type: String,
    /// Detection context: "forensics" (default), "malware", or "password".
    #[serde(default = "default_context")]
    pub context: String,
    /// Enable recursive layer analysis.
    #[serde(default)]
    pub deep: bool,
    /// Enable AI narrative (requires AI provider config).
    #[serde(default)]
    pub ai: bool,
    /// Run analysis in a sandboxed subprocess.
    #[serde(default)]
    pub sandbox: bool,
}

fn default_input_type() -> String {
    "string".to_string()
}
fn default_context() -> String {
    "forensics".to_string()
}

/// POST /analyze — run the detection pipeline on provided input.
pub async fn analyze(
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<AnalyzeRequest>,
) -> Result<Json<DetectionResult>, ApiError> {
    let detection_context = match body.context.as_str() {
        "malware" => crate::types::DetectionContext::Malware,
        "password" => crate::types::DetectionContext::Password,
        _ => crate::types::DetectionContext::Forensics,
    };

    // Resolve input based on input_type
    let (data, source_type) = resolve_input(&body.input, &body.input_type)?;

    // Run detection — sandboxed or in-process
    let mut result = if body.sandbox {
        let sandbox = state
            .sandbox
            .as_ref()
            .ok_or_else(|| ApiError::BadRequest("Sandbox requested but not configured".to_string()))?;
        crate::analyzers::file::analyze_bytes_sandboxed(&data, sandbox)?
    } else {
        crate::analyzers::file::analyze_bytes(&data, source_type)?
    };

    result.detection_context = detection_context;

    // Recursive analysis
    if body.deep && !result.algorithm.as_deref().map_or(true, |a| a.is_empty()) {
        let config = crate::analyzers::recursive::RecursiveConfig::default();
        let layers = crate::analyzers::recursive::analyze_recursive(&data, &config)?;
        for layer in layers {
            result.layers.push(DetectionResult {
                input_hash: result.input_hash.clone(),
                source_type: crate::types::SourceType::Binary,
                entropy: 0.0,
                sliding_entropy: None,
                detected_type: layer.detected_type,
                algorithm: Some(layer.algorithm),
                confidence: layer.confidence,
                calibrated: false,
                calibration_samples: None,
                heuristic_raw: None,
                confidence_is_provisional: true,
                false_positive_risk: 0.0,
                risk_level: crate::types::RiskLevel::Unknown,
                weakness: None,
                weakness_cve: vec![],
                recommendations: vec![],
                signals: None,
                primary_drivers: vec![],
                conflicting_signals: vec![],
                decision_trace: None,
                layers: vec![],
                ai_narrative: None,
                detection_context: result.detection_context,
                engine_version: result.engine_version.clone(),
                signature_db_version: result.signature_db_version.clone(),
            });
        }
    }

    // Log audit
    crate::intelligence::audit::log_analysis(&result);

    // Optional AI narrative
    if body.ai {
        if let Ok(provider) = crate::cli::load_ai_provider() {
            match crate::analyzers::file::attach_ai_narrative(&result, &*provider).await {
                Ok(r) => result = r,
                Err(e) => tracing::warn!("AI narrative failed: {}", e),
            }
        }
    }

    Ok(Json(result))
}

/// Resolve input data from a string, file path, or base64-encoded value.
fn resolve_input(input: &str, input_type: &str) -> Result<(Vec<u8>, crate::types::SourceType), ApiError> {
    match input_type {
        "file" => {
            let path = std::path::Path::new(input);
            if !path.exists() {
                return Err(ApiError::BadRequest(format!("File not found: {}", input)));
            }
            let guard = crate::sanitization::InputGuard::new();
            let sanitized = guard.sanitize_file(path).map_err(|e| {
                ApiError::BadRequest(format!("File read error: {}", e))
            })?;
            Ok((sanitized.raw_bytes, crate::types::SourceType::File))
        }
        "base64" => {
            let bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                input.as_bytes(),
            )
            .map_err(|e| ApiError::BadRequest(format!("Base64 decode error: {}", e)))?;
            Ok((bytes, crate::types::SourceType::Binary))
        }
        _ => {
            let guard = crate::sanitization::InputGuard::new();
            let sanitized = guard.sanitize_string(input).map_err(|e| {
                ApiError::BadRequest(format!("Input error: {}", e))
            })?;
            Ok((sanitized.raw_bytes, crate::types::SourceType::String))
        }
    }
}

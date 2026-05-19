use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Extension, Path};
use axum::Json;

use crate::api::errors::ApiError;
use crate::jobs::{JobQueue, JobStatus};
use crate::sanitization::sandbox::Sandbox;
use crate::types::DetectionResult;

/// Shared application state injected via Extension.
pub struct AppState {
    pub startup_time: Instant,
    pub engine_version: String,
    pub sig_db_version: String,
    pub sandbox: Option<Sandbox>,
    pub job_queue: Option<Arc<JobQueue>>,
}

/// GET /docs — returns the OpenAPI specification.
pub async fn docs() -> Json<serde_json::Value> {
    let spec = serde_json::from_str(crate::api::OPENAPI_SPEC)
        .unwrap_or_else(|_| serde_json::json!({"error": "OpenAPI spec failed to parse"}));
    Json(spec)
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
    pub input: String,
    #[serde(default = "default_input_type")]
    pub input_type: String,
    #[serde(default = "default_context")]
    pub context: String,
    #[serde(default)]
    pub deep: bool,
    #[serde(default)]
    pub ai: bool,
    #[serde(default)]
    pub sandbox: bool,
}

fn default_input_type() -> String {
    "string".to_string()
}
fn default_context() -> String {
    "forensics".to_string()
}

/// POST /analyze — run the detection pipeline synchronously.
pub async fn analyze(
    Extension(_state): Extension<Arc<AppState>>,
    Json(body): Json<AnalyzeRequest>,
) -> Result<Json<DetectionResult>, ApiError> {
    let result = run_analysis(&body.input, &body.input_type, &body.context, body.deep, body.ai, body.sandbox).await?;
    Ok(Json(result))
}

/// POST /v1/jobs — submit an analysis job and return immediately with a job ID.
pub async fn submit_job(
    Extension(state): Extension<Arc<AppState>>,
    Json(body): Json<AnalyzeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let queue = state.job_queue.as_ref()
        .ok_or_else(|| ApiError::BadRequest("Job queue not enabled".to_string()))?
        .clone();

    let id = queue.submit(
        body.input,
        body.input_type,
        body.context,
        body.deep,
        body.ai,
        false, // sandbox not available in job queue
    ).await;

    // Worker loop picks up pending jobs automatically

    Ok(Json(serde_json::json!({
        "job_id": id,
        "status": "pending",
        "endpoint": format!("/v1/jobs/{}", id),
    })))
}

/// GET /v1/jobs/:id — poll job status and result.
pub async fn get_job(
    Extension(state): Extension<Arc<AppState>>,
    Path(id): Path<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let queue = state.job_queue.as_ref()
        .ok_or_else(|| ApiError::BadRequest("Job queue not enabled".to_string()))?;

    let job = queue.get(id).await
        .ok_or_else(|| ApiError::NotFound(format!("Job {} not found", id)))?;

    let mut response = serde_json::json!({
        "job_id": job.id,
        "status": serde_json::to_value(&job.status).unwrap_or(serde_json::Value::Null),
        "created_at": job.created_at,
        "updated_at": job.updated_at,
    });

    if let Some(result) = job.result {
        response["result"] = serde_json::to_value(result).unwrap_or(serde_json::Value::Null);
    }

    if let JobStatus::Failed(ref err) = job.status {
        response["error"] = serde_json::Value::String(err.clone());
    }

    Ok(Json(response))
}

/// DELETE /v1/jobs/:id — cancel or remove a job.
pub async fn delete_job(
    Extension(state): Extension<Arc<AppState>>,
    Path(id): Path<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let queue = state.job_queue.as_ref()
        .ok_or_else(|| ApiError::BadRequest("Job queue not enabled".to_string()))?;

    let cancelled = queue.cancel(id).await;
    if let Some(job) = cancelled {
        Ok(Json(serde_json::json!({
            "job_id": job.id,
            "status": serde_json::to_value(&job.status).unwrap_or(serde_json::Value::Null),
        })))
    } else {
        Err(ApiError::NotFound(format!("Job {} not found", id)))
    }
}

/// Run analysis pipeline — shared between sync and async paths.
pub async fn run_analysis(
    input: &str,
    input_type: &str,
    context: &str,
    deep: bool,
    ai: bool,
    sandbox: bool,
) -> Result<DetectionResult, ApiError> {
    let detection_context = match context {
        "malware" => crate::types::DetectionContext::Malware,
        "password" => crate::types::DetectionContext::Password,
        _ => crate::types::DetectionContext::Forensics,
    };

    let (data, source_type) = resolve_input(input, input_type)?;

    let mut result = if sandbox {
        crate::analyzers::file::analyze_bytes(&data, source_type)?
    } else {
        crate::analyzers::file::analyze_bytes(&data, source_type)?
    };

    result.detection_context = detection_context;

    // Recursive analysis
    if deep && !result.algorithm.as_deref().map_or(true, |a| a.is_empty()) {
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
    if ai {
        if let Ok(provider) = crate::cli::load_ai_provider() {
            match crate::analyzers::file::attach_ai_narrative(&result, &*provider).await {
                Ok(r) => result = r,
                Err(e) => tracing::warn!("AI narrative failed: {}", e),
            }
        }
    }

    Ok(result)
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

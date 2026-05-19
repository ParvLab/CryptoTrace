use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceType {
    File,
    String,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
            RiskLevel::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionContext {
    Malware,
    Password,
    Forensics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedInput {
    pub raw_bytes: Vec<u8>,
    pub source_type: SourceType,
    pub original_length: usize,
    pub was_truncated: bool,
    pub safe: bool,
    pub has_null_bytes: bool,
    pub resolved_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlidingEntropy {
    pub window_size_bytes: usize,
    pub window_stride_bytes: usize,
    pub window_scores: Vec<f64>,
    pub max_window_entropy: f64,
    pub entropy_variance: f64,
    pub embedded_regions: Vec<OffsetRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalBreakdown {
    pub entropy: f64,
    pub byte_distribution: Option<f64>,
    pub block_alignment: f64,
    pub magic_bytes: f64,
    pub length_pattern: f64,
    pub charset_purity: Option<f64>,
    pub window_variance: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationInfo {
    pub dataset_size: usize,
    pub calibration_date: String,
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationModel {
    /// Learned weights for each signal: [entropy, block_alignment, magic_bytes, length_pattern, charset_purity, window_variance]
    pub weights: [f64; 6],
    /// Logistic regression intercept term
    pub intercept: f64,
    /// Number of training samples used
    pub dataset_size: usize,
    /// ISO-8601 date of calibration
    pub calibration_date: String,
    /// Method description (e.g. "Platt scaling")
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalContribution {
    pub signal_name: String,
    pub coefficient: f64,
    pub contribution: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiNarrative {
    pub summary: String,
    pub risk_reason: String,
    pub recommended_action: String,
    pub confidence_statement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub input_hash: String,
    pub source_type: SourceType,
    pub entropy: f64,
    pub sliding_entropy: Option<SlidingEntropy>,
    pub detected_type: String,
    pub algorithm: Option<String>,
    pub confidence: f64,
    pub calibrated: bool,
    pub calibration_samples: Option<usize>,
    pub heuristic_raw: Option<f64>,
    pub confidence_is_provisional: bool,
    pub false_positive_risk: f64,
    pub risk_level: RiskLevel,
    pub weakness: Option<String>,
    pub weakness_cve: Vec<String>,
    pub recommendations: Vec<String>,
    pub signals: Option<SignalBreakdown>,
    pub primary_drivers: Vec<String>,
    pub conflicting_signals: Vec<String>,
    pub decision_trace: Option<String>,
    pub layers: Vec<DetectionResult>,
    pub ai_narrative: Option<AiNarrative>,
    pub detection_context: DetectionContext,
    pub engine_version: String,
    pub signature_db_version: String,
}

impl Default for DetectionResult {
    fn default() -> Self {
        Self {
            input_hash: String::new(),
            source_type: SourceType::String,
            entropy: 0.0,
            sliding_entropy: None,
            detected_type: String::new(),
            algorithm: None,
            confidence: 0.0,
            calibrated: false,
            calibration_samples: None,
            heuristic_raw: None,
            confidence_is_provisional: true,
            false_positive_risk: 0.0,
            risk_level: RiskLevel::Unknown,
            weakness: None,
            weakness_cve: vec![],
            recommendations: vec![],
            signals: None,
            primary_drivers: vec![],
            conflicting_signals: vec![],
            decision_trace: None,
            layers: vec![],
            ai_narrative: None,
            detection_context: DetectionContext::Forensics,
            engine_version: String::new(),
            signature_db_version: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub depth: usize,
    pub detected_type: String,
    pub algorithm: String,
    pub confidence: f64,
    pub decoded_preview: Option<Vec<u8>>,
    pub decoded_length: usize,
    pub expansion_ratio: Option<f64>,
    pub children: Vec<Layer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub ai: AiConfig,
    pub performance: PerformanceConfig,
    pub api: ApiConfig,
    pub entropy: EntropyConfig,
    pub risk: RiskConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    pub enabled: bool,
    pub provider: Option<String>,
    pub model_family: Option<String>,
    pub base_url: Option<String>,
    pub max_words: Option<usize>,
    pub temperature: Option<f64>,
    pub max_tokens: Option<usize>,
    pub response_timeout_seconds: Option<u64>,
    pub cache: Option<AiCacheConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCacheConfig {
    pub enabled: bool,
    pub ttl_days: u64,
    pub max_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub use_rust_engine: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub api_key: Option<String>,
    pub rate_limit_per_minute: u64,
    pub allowed_origins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyConfig {
    pub thresholds: EntropyThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyThresholds {
    pub plaintext_max: f64,
    pub mixed_max: f64,
    pub compressed_max: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskConfig {
    pub overrides: std::collections::HashMap<String, RiskLevel>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            ai: AiConfig {
                enabled: false,
                provider: None,
                model_family: None,
                base_url: None,
                max_words: Some(150),
                temperature: Some(0.1),
                max_tokens: Some(512),
                response_timeout_seconds: Some(30),
                cache: Some(AiCacheConfig {
                    enabled: true,
                    ttl_days: 7,
                    max_entries: 10000,
                }),
            },
            performance: PerformanceConfig {
                use_rust_engine: true,
            },
            api: ApiConfig {
                api_key: None,
                rate_limit_per_minute: 60,
                allowed_origins: vec!["http://localhost:*".to_string()],
            },
            entropy: EntropyConfig {
                thresholds: EntropyThresholds {
                    plaintext_max: 3.5,
                    mixed_max: 6.0,
                    compressed_max: 7.5,
                },
            },
            risk: RiskConfig {
                overrides: std::collections::HashMap::new(),
            },
        }
    }
}

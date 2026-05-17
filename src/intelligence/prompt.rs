/// Re-export narrative prompt builder and validator for backward compatibility.
pub use super::narrative::{build_prompt, build_signals_string, validate_narrative};

use crate::error::Result;
use crate::types::DetectionResult;

/// Generate a constrained AI narrative for a detection result.
/// This is the high-level entry point used by the analysis pipeline.
pub async fn generate_ai_narrative(
    result: &DetectionResult,
    provider: &dyn crate::providers::AiProvider,
) -> Result<crate::types::AiNarrative> {
    // Build signal string from result signals
    let signals_str = if let Some(ref s) = result.signals {
        build_signals_string(s.entropy, s.magic_bytes, s.length_pattern, s.charset_purity)
    } else {
        "no signal data".to_string()
    };

    // Build a safe prompt (no raw input bytes)
    let prompt = build_prompt(
        result.algorithm.as_deref(),
        &result.detected_type,
        result.entropy,
        &format!("{:?}", result.risk_level),
        result.confidence,
        result.confidence_is_provisional,
        &signals_str,
        result.weakness.as_deref(),
    );

    // Call the provider
    provider.generate(&prompt).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_prompt_no_raw_data() {
        let prompt = build_prompt(
            Some("SHA256"),
            "hash",
            4.0,
            "Low",
            0.97,
            false,
            "entropy=4.00, pattern=1.00",
            None,
        );
        assert!(prompt.contains("SHA256"));
        assert!(!prompt.contains("raw_bytes"));
        assert!(!prompt.contains("file content"));
    }
}

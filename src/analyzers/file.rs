use crate::error::Result;
use crate::providers::AiProvider;
use crate::sanitization::sandbox::Sandbox;
use crate::signatures::{default_registry, match_signatures, MagicEntry};
use crate::types::DetectionResult;

/// Analyze a file by reading its contents and running the full detection pipeline.
pub fn analyze_file(path: &std::path::Path) -> Result<DetectionResult> {
    let guard = crate::sanitization::InputGuard::new();
    let sanitized = guard.sanitize_file(path)?;
    analyze_bytes(&sanitized.raw_bytes, crate::types::SourceType::File)
}

/// Analyze raw bytes through the detection pipeline.
pub fn analyze_bytes(data: &[u8], source_type: crate::types::SourceType) -> Result<DetectionResult> {
    // Entropy analysis
    let (entropy, _freq) = crate::core::entropy::shannon_entropy(data);
    let sliding = crate::core::sliding_entropy::sliding_window_entropy(data, None, None, None);

    // String analysis (if input looks like text)
    let input_str = String::from_utf8_lossy(data);

    // Hash detection
    let hash_detection = crate::core::hashing::detect_hash(&input_str);

    // Encoding detection
    let encoding_detection = crate::core::encoding::detect_encoding(&input_str);

    // Compression detection
    let _compression_detection = crate::core::compression::detect_compression(data);

    // Encryption detection
    let _encryption_detection = crate::core::encryption::detect_encryption(data, entropy);

    // Signature registry matching
    let registry = default_registry().ok();
    let matched_signatures: Vec<&MagicEntry> = registry
        .as_ref()
        .map(|r| match_signatures(data, r))
        .unwrap_or_default();

    // Build result with confidence engine + signature info
    let mut result = crate::core::confidence::build_detection_result(
        data,
        source_type,
        hash_detection.as_ref(),
        encoding_detection.as_ref(),
        entropy,
        Some(&sliding),
    );

    // Overlay signature registry info (strongest signal)
    if let Some(best) = matched_signatures.iter().max_by_key(|e| e.magic_bytes.len()) {
        if result.algorithm.is_none() && result.detected_type == "plaintext" {
            result.detected_type = best.category.clone();
            result.algorithm = Some(best.id.clone());
            result.risk_level = crate::signatures::category_risk_level(&best.category);
            if result.confidence < 0.9 {
                result.confidence = 0.9;
            }
            result.confidence_is_provisional = true;
        }
        if let Some(ref mut signals) = result.signals {
            signals.magic_bytes = 1.0;
        }
    }

    Ok(result)
}

/// Run detection through the sandboxed worker subprocess.
/// The worker performs the actual analysis; if it crashes, we fall back to
/// in-process analysis and log a warning.
pub fn analyze_file_sandboxed(path: &std::path::Path, sandbox: &Sandbox) -> Result<DetectionResult> {
    let guard = crate::sanitization::InputGuard::new();
    let sanitized = guard.sanitize_file(path)?;

    // Try sandboxed detection
    match sandbox.run_worker("detect", &sanitized.raw_bytes) {
        Ok(output) => {
            serde_json::from_slice(&output).map_err(|e| {
                crate::error::CryptoTraceError::Other(format!(
                    "Failed to parse worker output as DetectionResult: {}",
                    e
                ))
            })
        }
        Err(e) => {
            tracing::warn!("Sandboxed detection failed, falling back to in-process: {}", e);
            analyze_bytes(&sanitized.raw_bytes, crate::types::SourceType::File)
        }
    }
}

/// Run byte analysis through the sandboxed worker subprocess.
pub fn analyze_bytes_sandboxed(data: &[u8], sandbox: &Sandbox) -> Result<DetectionResult> {
    match sandbox.run_worker("detect", data) {
        Ok(output) => {
            serde_json::from_slice(&output).map_err(|e| {
                crate::error::CryptoTraceError::Other(format!(
                    "Failed to parse worker output: {}",
                    e
                ))
            })
        }
        Err(e) => {
            tracing::warn!("Sandboxed byte analysis failed, falling back: {}", e);
            analyze_bytes(data, crate::types::SourceType::Binary)
        }
    }
}

/// Attach an AI narrative to a detection result (async, opt-in).
pub async fn attach_ai_narrative(
    result: &DetectionResult,
    provider: &dyn AiProvider,
) -> Result<DetectionResult> {
    let narrative = crate::intelligence::prompt::generate_ai_narrative(result, provider).await?;
    let mut out = result.clone();
    out.ai_narrative = Some(narrative);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_bytes_plaintext() {
        let result = analyze_bytes(b"hello world", crate::types::SourceType::String).unwrap();
        assert_eq!(result.detected_type, "plaintext");
    }

    #[test]
    fn test_analyze_bytes_md5() {
        let result =
            analyze_bytes(b"5f4dcc3b5aa765d61d8327deb882cf99", crate::types::SourceType::String)
                .unwrap();
        assert_eq!(result.detected_type, "hash");
        assert_eq!(result.algorithm.as_deref(), Some("MD5"));
    }

    #[test]
    fn test_analyze_pdf_magic() {
        let result = analyze_bytes(b"%PDF-1.4\n...", crate::types::SourceType::File).unwrap();
        assert_eq!(result.detected_type, "document");
        assert_eq!(result.algorithm.as_deref(), Some("pdf"));
        assert!(result.signals.map_or(false, |s| s.magic_bytes > 0.5));
    }

    #[test]
    fn test_analyze_png_magic() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...";
        let result = analyze_bytes(data, crate::types::SourceType::File).unwrap();
        assert_eq!(result.detected_type, "image");
        assert_eq!(result.algorithm.as_deref(), Some("png"));
    }
}

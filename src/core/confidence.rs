use crate::core::calibration;
use crate::core::encoding::EncodingDetection;
use crate::core::hashing::HashDetection;
use crate::types::{
    CalibrationModel, DetectionResult, RiskLevel, SignalBreakdown, SlidingEntropy, SourceType,
};

/// Global calibration model protected by a read-write lock.
use std::sync::RwLock;
static CALIBRATION_MODEL: RwLock<Option<CalibrationModel>> = RwLock::new(None);

fn get_model() -> Option<CalibrationModel> {
    CALIBRATION_MODEL.read().ok()?.clone()
}

/// Set the global calibration model (used by `cryptotrace calibrate train`).
pub fn set_model(model: CalibrationModel) {
    if let Ok(mut guard) = CALIBRATION_MODEL.write() {
        *guard = Some(model);
    }
}

/// Reset to no calibration model (reverts to provisional).
pub fn reset_model() {
    if let Ok(mut guard) = CALIBRATION_MODEL.write() {
        *guard = None;
    }
}

/// Compute confidence using calibrated model if available, else provisional heuristic.
pub fn compute_confidence(
    hash_detection: Option<&HashDetection>,
    encoding_detection: Option<&EncodingDetection>,
    entropy: f64,
    _sliding: Option<&SlidingEntropy>,
) -> f64 {
    let signal_strength = hash_detection
        .map(|h| h.confidence)
        .or_else(|| encoding_detection.map(|e| e.confidence))
        .unwrap_or(0.0);

    let entropy_consistency = if hash_detection.is_some() {
        if entropy < 4.0 {
            0.9
        } else {
            0.3
        }
    } else if encoding_detection.is_some() {
        if entropy > 3.0 && entropy < 7.0 {
            0.8
        } else {
            0.4
        }
    } else {
        0.5
    };

    signal_strength * 0.5 + entropy_consistency * 0.3 + 0.2
}

/// Full detection result with optional calibration overlay.
pub fn build_detection_result(
    input: &[u8],
    source_type: SourceType,
    hash_detection: Option<&HashDetection>,
    encoding_detection: Option<&EncodingDetection>,
    entropy: f64,
    sliding: Option<&SlidingEntropy>,
) -> DetectionResult {
    let input_hash = crate::core::hashing::sha256_hex(input);
    let heuristic_confidence = compute_confidence(
        hash_detection,
        encoding_detection,
        entropy,
        sliding,
    );

    // Build signal breakdown (same as Phase 1/2)
    let (detected_type, algorithm, weakness, risk_level, recommendations) =
        if let Some(h) = hash_detection {
            (
                "hash".to_string(),
                Some(h.algorithm.clone()),
                Some(h.weakness_flags.join(", ")),
                h.risk_level.clone(),
                match h.algorithm.as_str() {
                    "MD5" => vec!["Replace with bcrypt (cost ≥ 12) or Argon2id.".to_string()],
                    "SHA1" => vec!["Upgrade to SHA256 or stronger.".to_string()],
                    "NTLM" => vec!["Replace with bcrypt or Argon2id.".to_string()],
                    _ => vec![],
                },
            )
        } else if let Some(e) = encoding_detection {
            (
                "encoding".to_string(),
                Some(e.encoding_type.clone()),
                None,
                RiskLevel::Low,
                vec![],
            )
        } else {
            (
                if entropy > 7.5 {
                    "high_entropy".to_string()
                } else {
                    "plaintext".to_string()
                },
                None,
                None,
                RiskLevel::Unknown,
                vec![],
            )
        };

    let signals = SignalBreakdown {
        entropy,
        byte_distribution: None,
        block_alignment: 0.0,
        magic_bytes: 0.0,
        length_pattern: if algorithm.is_some() { 1.0 } else { 0.0 },
        charset_purity: encoding_detection.map(|_| 1.0),
        window_variance: sliding.map(|s| s.entropy_variance),
    };

    // Apply calibration if available
    let model = get_model();
    let (calibrated_conf, is_calibrated, decision_trace_str) = if let Some(ref m) = model {
        let cal_conf = calibration::predict_proba(m, &signals);
        let contribs = calibration::signal_contributions(m, &signals);
        let trace = calibration::format_contributions(&contribs);
        (cal_conf, true, Some(trace))
        } else {
            (heuristic_confidence, false, None)
        };

    DetectionResult {
        input_hash,
        source_type,
        entropy,
        sliding_entropy: sliding.cloned(),
        detected_type,
        algorithm,
        confidence: calibrated_conf.min(1.0).max(0.0),
        calibrated: is_calibrated,
        calibration_samples: model.as_ref().map(|m| m.dataset_size),
        heuristic_raw: Some(heuristic_confidence),
        confidence_is_provisional: !is_calibrated,
        false_positive_risk: 0.0,
        risk_level,
        weakness,
        weakness_cve: vec![],
        recommendations,
        signals: Some(signals),
        primary_drivers: vec![],
        conflicting_signals: vec![],
        decision_trace: decision_trace_str,
        layers: vec![],
        ai_narrative: None,
        detection_context: crate::types::DetectionContext::Forensics,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        signature_db_version: crate::signatures::default_registry()
            .map(|r| r.version)
            .unwrap_or_else(|_| "0.0.0".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_bounds() {
        let result = compute_confidence(None, None, 5.0, None);
        assert!(result >= 0.0 && result <= 1.0);
    }

    #[test]
    fn test_calibrated_vs_fallback() {
        // Verify fallback when no model
        reset_model();
        let result = build_detection_result(
            b"5f4dcc3b5aa765d61d8327deb882cf99",
            SourceType::String,
            Some(&HashDetection {
                algorithm: "MD5".to_string(),
                confidence: 0.95,
                risk_level: RiskLevel::Critical,
                weakness_flags: vec!["collision_vulnerable".to_string()],
            }),
            None,
            3.8,
            None,
        );
        assert!(!result.calibrated);
        assert!(result.confidence_is_provisional);

        // Then verify calibration overlay
        let model = CalibrationModel {
            weights: [1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            intercept: -3.0,
            dataset_size: 100,
            calibration_date: "2026-05-17".to_string(),
            method: "test".to_string(),
        };
        set_model(model);

        let result = build_detection_result(
            b"test",
            SourceType::String,
            None,
            None,
            4.0,
            None,
        );
        assert!(result.calibrated);
        assert!(!result.confidence_is_provisional);
        assert!((result.confidence - 0.731).abs() < 0.01);
        assert!(result.decision_trace.is_some());
        assert!(result.calibration_samples == Some(100));

        reset_model();
    }
}

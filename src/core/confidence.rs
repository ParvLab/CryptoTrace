use std::collections::HashMap;

use crate::core::calibration;
use crate::core::encoding::EncodingDetection;
use crate::core::hashing::HashDetection;
use crate::types::{
    CalibrationModel, DetectionResult, RiskLevel, SignalBreakdown, SlidingEntropy, SourceType,
};

/// Load risk overrides from cryptotrace.toml, if present.
pub fn load_risk_overrides() -> HashMap<String, RiskLevel> {
    let mut overrides = HashMap::new();
    let config_path = std::path::Path::new("cryptotrace.toml");
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            if let Ok(parsed) = toml::from_str::<serde_json::Value>(&content) {
                if let Some(risk) = parsed.get("risk") {
                    if let Some(overrides_val) = risk.get("overrides") {
                        if let Some(obj) = overrides_val.as_object() {
                            for (key, val) in obj {
                                if let Some(level_str) = val.as_str() {
                                    let level = match level_str.to_lowercase().as_str() {
                                        "low" => RiskLevel::Low,
                                        "medium" => RiskLevel::Medium,
                                        "high" => RiskLevel::High,
                                        "critical" => RiskLevel::Critical,
                                        _ => continue,
                                    };
                                    overrides.insert(key.clone(), level);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    overrides
}

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

const BASELINE_CONFIDENCE: f64 = 0.2;
const SIGNAL_STRENGTH_WEIGHT: f64 = 0.5;
const ENTROPY_WEIGHT: f64 = 0.3;

/// Compute confidence using calibrated model if available, else provisional heuristic.
#[allow(unused_variables)]
pub fn compute_confidence(
    hash_detection: Option<&HashDetection>,
    encoding_detection: Option<&EncodingDetection>,
    entropy: f64,
    sliding: Option<&SlidingEntropy>,
) -> f64 {
    let signal_strength = hash_detection
        .map(|h| h.confidence)
        .or_else(|| encoding_detection.map(|e| e.confidence))
        .unwrap_or(0.0);

    let entropy_consistency = if hash_detection.is_some() {
        if entropy < 4.0 { 0.9 } else { 0.3 }
    } else if encoding_detection.is_some() {
        if entropy > 3.0 && entropy < 7.0 {
            0.8
        } else {
            0.4
        }
    } else {
        0.5
    };

    // Correlated signal cap: if both hash AND encoding are positive, cap
    // the combined contribution to prevent overcounting.
    let combined = signal_strength * SIGNAL_STRENGTH_WEIGHT
        + entropy_consistency * ENTROPY_WEIGHT
        + BASELINE_CONFIDENCE;
    if hash_detection.is_some() && encoding_detection.is_some() {
        combined.min(0.95)
    } else {
        combined
    }
}

/// Compute primary signal drivers — the signals that most influence confidence.
fn compute_primary_drivers(signal_strength: f64, entropy_consistency: f64) -> Vec<String> {
    let signal_contrib = signal_strength * SIGNAL_STRENGTH_WEIGHT;
    let entropy_contrib = entropy_consistency * ENTROPY_WEIGHT;

    let mut drivers: Vec<(&str, f64)> = vec![
        ("signal_strength", signal_contrib),
        ("entropy_consistency", entropy_contrib),
    ];
    drivers.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    drivers
        .into_iter()
        .filter(|(_, v)| *v > 0.0)
        .take(2)
        .map(|(name, val)| format!("{} ({:.2})", name, val))
        .collect()
}

/// Detect conflicting signals — signals that disagree with each other.
fn compute_conflicting_signals(
    hash_detection: Option<&HashDetection>,
    encoding_detection: Option<&EncodingDetection>,
    entropy: f64,
) -> Vec<String> {
    let mut conflicts = Vec::new();

    // Hash detected but entropy is too high for a hash
    if let Some(h) = hash_detection {
        if entropy > 5.0 && h.algorithm != "NTLM" {
            conflicts.push(format!(
                "Hash mismatch: {} detected but entropy {:.1} is too high for a hash",
                h.algorithm, entropy
            ));
        }
        if encoding_detection.is_some() {
            conflicts.push(format!(
                "Type conflict: hash ({}) and encoding ({}) both detected",
                h.algorithm,
                encoding_detection.unwrap().encoding_type
            ));
        }
    }

    conflicts
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

    // Compute heuristic signals
    let signal_strength = hash_detection
        .map(|h| h.confidence)
        .or_else(|| encoding_detection.map(|e| e.confidence))
        .unwrap_or(0.0);

    let entropy_consistency = if hash_detection.is_some() {
        if entropy < 4.0 { 0.9 } else { 0.3 }
    } else if encoding_detection.is_some() {
        if entropy > 3.0 && entropy < 7.0 {
            0.8
        } else {
            0.4
        }
    } else {
        0.5
    };

    let heuristic_confidence = signal_strength * SIGNAL_STRENGTH_WEIGHT
        + entropy_consistency * ENTROPY_WEIGHT
        + BASELINE_CONFIDENCE;

    // Build signal breakdown using risk overrides
    let risk_overrides = load_risk_overrides();
    let (detected_type, algorithm, weakness, mut risk_level, recommendations) =
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

    // Compute primary drivers and conflicting signals
    let primary_drivers = compute_primary_drivers(signal_strength, entropy_consistency);
    let conflicting_signals =
        compute_conflicting_signals(hash_detection, encoding_detection, entropy);

    // Apply calibration if available
    // Apply risk overrides and CVE data
    let mut weakness_cve = Vec::new();
    if let Some(ref algo) = algorithm {
        let (overridden_risk, algo_cves) =
            crate::intelligence::risk::resolve_risk_level(algo, &risk_overrides);
        if risk_overrides.contains_key(algo) {
            risk_level = overridden_risk;
        }
        weakness_cve = algo_cves.clone();
        // Also try loading from external CVE databases
        let ext_cves =
            crate::intelligence::risk::build_cve_map("signatures/cve_map.yaml", "cve-db.json");
        for (cve_id, desc) in &ext_cves {
            if algo.contains(cve_id) || desc.to_lowercase().contains(&algo.to_lowercase()) {
                if !weakness_cve.contains(cve_id) {
                    weakness_cve.push(cve_id.clone());
                }
            }
        }
    }

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
        weakness_cve,
        recommendations,
        signals: Some(signals),
        primary_drivers,
        conflicting_signals,
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

        let result = build_detection_result(b"test", SourceType::String, None, None, 4.0, None);
        assert!(result.calibrated);
        assert!(!result.confidence_is_provisional);
        assert!((result.confidence - 0.731).abs() < 0.01);
        assert!(result.decision_trace.is_some());
        assert!(result.calibration_samples == Some(100));

        reset_model();
    }
}

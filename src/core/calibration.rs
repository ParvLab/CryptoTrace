use crate::error::CryptoTraceError;
use crate::types::{CalibrationModel, SignalBreakdown, SignalContribution};

/// Default model path bundled into the binary at compile time.
/// Set to an empty model when no calibration has been performed.
const MODEL_PATH: &str = "calibration_data/model.json";

/// A single labeled training example.
#[derive(Debug, Clone)]
pub struct CalibrationSample {
    pub signals: SignalBreakdown,
    pub label: f64, // 0.0 or 1.0
    pub detected_type: String,
}

/// Platt scaling: logistic regression mapping raw signal vector → calibrated probability.
const SIGNAL_NAMES: &[&str] = &[
    "entropy",
    "block_alignment",
    "magic_bytes",
    "length_pattern",
    "charset_purity",
    "window_variance",
];

/// Predict calibrated probability from a signal breakdown using a trained model.
pub fn predict_proba(model: &CalibrationModel, signals: &SignalBreakdown) -> f64 {
    let linear = model.intercept
        + model.weights[0] * signals.entropy
        + model.weights[1] * signals.block_alignment
        + model.weights[2] * signals.magic_bytes
        + model.weights[3] * signals.length_pattern
        + model.weights[4] * signals.charset_purity.unwrap_or(0.5)
        + model.weights[5] * signals.window_variance.unwrap_or(0.0);
    logistic(linear)
}

/// Compute per-signal contributions to the log-odds.
pub fn signal_contributions(
    model: &CalibrationModel,
    signals: &SignalBreakdown,
) -> Vec<SignalContribution> {
    let signal_values = [
        signals.entropy,
        signals.block_alignment,
        signals.magic_bytes,
        signals.length_pattern,
        signals.charset_purity.unwrap_or(0.5),
        signals.window_variance.unwrap_or(0.0),
    ];

    SIGNAL_NAMES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let contribution = model.weights[i] * signal_values[i];
            SignalContribution {
                signal_name: name.to_string(),
                coefficient: model.weights[i],
                contribution,
            }
        })
        .collect()
}

/// Format contributions as a short string for the terminal report.
pub fn format_contributions(contributions: &[SignalContribution]) -> String {
    let mut parts: Vec<String> = contributions
        .iter()
        .map(|c| {
            let sign = if c.contribution >= 0.0 { "+" } else { "" };
            format!("{}{:.2}", sign, c.contribution)
        })
        .collect();
    parts.insert(0, "contrib:".to_string());
    parts.join(" ")
}

/// Logistic function (sigmoid).
fn logistic(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Train a calibration model using gradient descent on a labeled dataset.
/// Uses binary cross-entropy loss with L2 regularization.
pub fn train(
    dataset: &[CalibrationSample],
    learning_rate: f64,
    epochs: usize,
    l2_lambda: f64,
) -> CalibrationModel {
    let n_features = 6;
    let n = dataset.len() as f64;

    let mut weights = [0.0; 6];
    let mut intercept = 0.0;

    for _epoch in 0..epochs {
        let mut grad_w = [0.0; 6];
        let mut grad_b = 0.0;

        for sample in dataset {
            let signal_values = feature_vector(&sample.signals);
            let linear = intercept + dot(&weights, &signal_values);
            let pred = logistic(linear);
            let error = pred - sample.label;

            for i in 0..n_features {
                grad_w[i] += error * signal_values[i];
            }
            grad_b += error;
        }

        // Average gradients + L2 regularization
        for i in 0..n_features {
            grad_w[i] = grad_w[i] / n + l2_lambda * weights[i];
            weights[i] -= learning_rate * grad_w[i];
        }
        grad_b = grad_b / n;
        intercept -= learning_rate * grad_b;
    }

    CalibrationModel {
        weights,
        intercept,
        dataset_size: dataset.len(),
        calibration_date: chrono_now(),
        method: "Platt scaling (logistic regression + gradient descent)".to_string(),
    }
}

/// Save a calibration model to a JSON file.
pub fn save_model(model: &CalibrationModel, path: &str) -> Result<(), CryptoTraceError> {
    let json = serde_json::to_string_pretty(model)
        .map_err(|e| CryptoTraceError::Other(format!("Cannot serialize model: {}", e)))?;
    std::fs::write(path, &json)
        .map_err(|e| CryptoTraceError::Other(format!("Cannot write model: {}", e)))
}

/// Load a calibration model from a JSON file.
pub fn load_model(path: &str) -> Result<CalibrationModel, CryptoTraceError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| CryptoTraceError::Other(format!("Cannot read model: {}", e)))?;
    serde_json::from_str(&content)
        .map_err(|e| CryptoTraceError::Other(format!("Cannot parse model: {}", e)))
}

/// Load the default bundled model (if available), or None.
pub fn default_model() -> Option<CalibrationModel> {
    load_model(MODEL_PATH).ok()
}

/// Generate synthetic training data from known signal profiles.
pub fn generate_synthetic_dataset(size_per_class: usize) -> Vec<CalibrationSample> {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut samples = Vec::with_capacity(size_per_class * 5);

    // Hash samples: low entropy, strong length/charset, no magic
    for _ in 0..size_per_class {
        samples.push(CalibrationSample {
            signals: SignalBreakdown {
                entropy: rng.random_range(2.0..4.5),
                byte_distribution: None,
                block_alignment: 0.0,
                magic_bytes: 0.0,
                length_pattern: 0.8 + rng.random::<f64>() * 0.2,
                charset_purity: Some(0.9 + rng.random::<f64>() * 0.1),
                window_variance: Some(rng.random::<f64>() * 0.3),
            },
            label: 1.0,
            detected_type: "hash".to_string(),
        });
    }

    // Encoding samples: moderate entropy, strong charset, no magic
    for _ in 0..size_per_class {
        samples.push(CalibrationSample {
            signals: SignalBreakdown {
                entropy: rng.random_range(3.0..6.5),
                byte_distribution: None,
                block_alignment: 0.0,
                magic_bytes: 0.0,
                length_pattern: 0.6 + rng.random::<f64>() * 0.3,
                charset_purity: Some(0.8 + rng.random::<f64>() * 0.2),
                window_variance: Some(rng.random::<f64>() * 0.5),
            },
            label: 1.0,
            detected_type: "encoding".to_string(),
        });
    }

    // Compression samples: high entropy, magic bytes present
    for _ in 0..size_per_class {
        samples.push(CalibrationSample {
            signals: SignalBreakdown {
                entropy: rng.random_range(6.0..8.0),
                byte_distribution: None,
                block_alignment: 0.0,
                magic_bytes: 0.8 + rng.random::<f64>() * 0.2,
                length_pattern: 0.4 + rng.random::<f64>() * 0.3,
                charset_purity: None,
                window_variance: Some(0.1 + rng.random::<f64>() * 0.4),
            },
            label: 1.0,
            detected_type: "compression".to_string(),
        });
    }

    // Encrypted samples: high entropy, block alignment
    for _ in 0..size_per_class {
        samples.push(CalibrationSample {
            signals: SignalBreakdown {
                entropy: rng.random_range(7.0..8.0),
                byte_distribution: None,
                block_alignment: 0.6 + rng.random::<f64>() * 0.4,
                magic_bytes: 0.0,
                length_pattern: 0.2 + rng.random::<f64>() * 0.3,
                charset_purity: None,
                window_variance: Some(0.1 + rng.random::<f64>() * 0.3),
            },
            label: 1.0,
            detected_type: "encrypted".to_string(),
        });
    }

    // Plaintext (negative) samples: moderate entropy, no signals
    for _ in 0..size_per_class {
        samples.push(CalibrationSample {
            signals: SignalBreakdown {
                entropy: rng.random_range(2.0..4.5),
                byte_distribution: None,
                block_alignment: 0.0,
                magic_bytes: 0.0,
                length_pattern: 0.0 + rng.random::<f64>() * 0.2,
                charset_purity: None,
                window_variance: Some(rng.random::<f64>() * 0.2),
            },
            label: 0.0,
            detected_type: "plaintext".to_string(),
        });
    }

    samples
}

/// Extract signal values as a flat feature vector.
fn feature_vector(signals: &SignalBreakdown) -> [f64; 6] {
    [
        signals.entropy,
        signals.block_alignment,
        signals.magic_bytes,
        signals.length_pattern,
        signals.charset_purity.unwrap_or(0.5),
        signals.window_variance.unwrap_or(0.0),
    ]
}

/// Dot product of two 6-element arrays.
fn dot(a: &[f64; 6], b: &[f64; 6]) -> f64 {
    a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3] + a[4] * b[4] + a[5] * b[5]
}

/// Get the current date in ISO-8601 format.
fn chrono_now() -> String {
    // Simple date formatting without external crate
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Approximate date (not exact but good enough for metadata)
    let days = secs / 86400;
    let years = 1970 + (days / 365) as u32;
    let remaining_days = days % 365;
    let month = 1 + remaining_days / 30;
    let day = 1 + remaining_days % 30;
    format!("{:04}-{:02}-{:02}", years, month.min(12), day.min(28))
}

/// Load calibration samples from a CSV file.
pub fn load_csv(path: &str) -> Result<Vec<CalibrationSample>, CryptoTraceError> {
    let mut reader = csv::Reader::from_path(path)
        .map_err(|e| CryptoTraceError::Other(format!("Cannot open CSV: {}", e)))?;

    let mut samples = Vec::new();
    for result in reader.deserialize() {
        #[derive(serde::Deserialize)]
        struct Row {
            entropy: f64,
            block_alignment: f64,
            magic_bytes: f64,
            length_pattern: f64,
            charset_purity: Option<f64>,
            window_variance: Option<f64>,
            label: u8,
            detected_type: String,
        }

        let row: Row =
            result.map_err(|e| CryptoTraceError::Other(format!("CSV parse error: {}", e)))?;
        samples.push(CalibrationSample {
            signals: SignalBreakdown {
                entropy: row.entropy,
                byte_distribution: None,
                block_alignment: row.block_alignment,
                magic_bytes: row.magic_bytes,
                length_pattern: row.length_pattern,
                charset_purity: row.charset_purity,
                window_variance: row.window_variance,
            },
            label: row.label as f64,
            detected_type: row.detected_type,
        });
    }

    Ok(samples)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logistic_bounds() {
        assert!((logistic(0.0) - 0.5).abs() < 0.001);
        assert!(logistic(100.0) > 0.999);
        assert!(logistic(-100.0) < 0.001);
    }

    #[test]
    fn test_predict_proba_default_model() {
        let model = CalibrationModel {
            weights: [0.5, 0.3, 1.0, 0.8, 0.4, 0.2],
            intercept: -2.0,
            dataset_size: 100,
            calibration_date: "2026-05-17".to_string(),
            method: "test".to_string(),
        };
        let signals = SignalBreakdown {
            entropy: 3.0,
            byte_distribution: None,
            block_alignment: 0.0,
            magic_bytes: 0.0,
            length_pattern: 1.0,
            charset_purity: Some(1.0),
            window_variance: Some(0.0),
        };
        let p = predict_proba(&model, &signals);
        assert!(p >= 0.0 && p <= 1.0);
    }

    #[test]
    fn test_train_converges() {
        // Create linearly separable data
        let mut samples = Vec::new();
        for _ in 0..100 {
            samples.push(CalibrationSample {
                signals: SignalBreakdown {
                    entropy: 7.5,
                    byte_distribution: None,
                    block_alignment: 0.8,
                    magic_bytes: 0.0,
                    length_pattern: 0.0,
                    charset_purity: None,
                    window_variance: Some(0.1),
                },
                label: 1.0,
                detected_type: "encrypted".to_string(),
            });
            samples.push(CalibrationSample {
                signals: SignalBreakdown {
                    entropy: 3.0,
                    byte_distribution: None,
                    block_alignment: 0.0,
                    magic_bytes: 0.0,
                    length_pattern: 0.0,
                    charset_purity: Some(1.0),
                    window_variance: Some(0.0),
                },
                label: 0.0,
                detected_type: "plaintext".to_string(),
            });
        }

        let model = train(&samples, 0.1, 500, 0.001);

        // High-entropy + block alignment → positive
        let pos = predict_proba(&model, &samples[0].signals);
        assert!(pos > 0.5, "Positive sample should score > 0.5, got {}", pos);

        // Low-entropy plaintext → negative
        let neg = predict_proba(&model, &samples[1].signals);
        assert!(neg < 0.5, "Negative sample should score < 0.5, got {}", neg);
    }

    #[test]
    fn test_signal_contributions_format() {
        let model = CalibrationModel {
            weights: [0.5, 0.0, 1.0, 0.0, 0.0, 0.0],
            intercept: 0.0,
            dataset_size: 1,
            calibration_date: "2026-01-01".to_string(),
            method: "test".to_string(),
        };
        let signals = SignalBreakdown {
            entropy: 4.0,
            byte_distribution: None,
            block_alignment: 0.0,
            magic_bytes: 1.0,
            length_pattern: 0.0,
            charset_purity: None,
            window_variance: None,
        };
        let contribs = signal_contributions(&model, &signals);
        assert_eq!(contribs.len(), 6);
        // entropy: 0.5 * 4.0 = 2.0
        assert!((contribs[0].contribution - 2.0).abs() < 0.001);
        // magic_bytes: 1.0 * 1.0 = 1.0
        assert!((contribs[2].contribution - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_synthetic_dataset_size() {
        let samples = generate_synthetic_dataset(50);
        assert_eq!(samples.len(), 250);
        let pos_count = samples.iter().filter(|s| s.label > 0.5).count();
        let neg_count = samples.iter().filter(|s| s.label < 0.5).count();
        assert_eq!(pos_count, 200);
        assert_eq!(neg_count, 50);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let model = CalibrationModel {
            weights: [0.1, 0.2, 0.3, 0.4, 0.5, 0.6],
            intercept: -1.0,
            dataset_size: 500,
            calibration_date: "2026-05-17".to_string(),
            method: "Platt scaling".to_string(),
        };
        let path = std::env::temp_dir().join("test_model.json");
        save_model(&model, path.to_str().unwrap()).unwrap();
        let loaded = load_model(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.weights, model.weights);
        assert!((loaded.intercept - model.intercept).abs() < 0.001);
        assert_eq!(loaded.dataset_size, model.dataset_size);
        std::fs::remove_file(&path).ok();
    }
}

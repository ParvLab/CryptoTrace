use crate::types::{OffsetRange, SlidingEntropy};

const DEFAULT_WINDOW_SIZE: usize = 4096; // 4KB
const DEFAULT_STRIDE: usize = 2048; // 2KB overlap
const DEFAULT_ENTROPY_THRESHOLD: f64 = 7.0;

/// Compute sliding-window entropy over byte data.
/// Returns per-window entropy scores, max, variance, and high-entropy regions.
pub fn sliding_window_entropy(
    data: &[u8],
    window_size: Option<usize>,
    stride: Option<usize>,
    threshold: Option<f64>,
) -> SlidingEntropy {
    let window_size = window_size.unwrap_or(DEFAULT_WINDOW_SIZE);
    let stride = stride.unwrap_or(DEFAULT_STRIDE);
    let threshold = threshold.unwrap_or(DEFAULT_ENTROPY_THRESHOLD);

    if data.is_empty() || data.len() < window_size {
        return SlidingEntropy {
            window_size_bytes: window_size,
            window_stride_bytes: stride,
            window_scores: vec![],
            max_window_entropy: 0.0,
            entropy_variance: 0.0,
            embedded_regions: vec![],
        };
    }

    let mut window_scores = Vec::new();
    let mut embedded_regions = Vec::new();
    let mut i = 0;

    while i + window_size <= data.len() {
        let window = &data[i..i + window_size];
        let (score, _) = crate::core::entropy::shannon_entropy(window);
        window_scores.push(score);
        if score >= threshold {
            embedded_regions.push(OffsetRange {
                start: i,
                end: i + window_size,
            });
        }
        i += stride;
    }

    let max_window_entropy = window_scores.iter().cloned().fold(0.0_f64, f64::max);

    let variance = if window_scores.len() > 1 {
        let mean = window_scores.iter().sum::<f64>() / window_scores.len() as f64;
        window_scores
            .iter()
            .map(|s| (s - mean).powi(2))
            .sum::<f64>()
            / (window_scores.len() - 1) as f64
    } else {
        0.0
    };

    SlidingEntropy {
        window_size_bytes: window_size,
        window_stride_bytes: stride,
        window_scores,
        max_window_entropy,
        entropy_variance: variance,
        embedded_regions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let result = sliding_window_entropy(b"", None, None, None);
        assert!(result.window_scores.is_empty());
    }

    #[test]
    fn test_uniform_data() {
        let data = vec![0x41u8; 4096 * 4]; // all 'A'
        let result = sliding_window_entropy(&data, None, None, None);
        assert!(!result.window_scores.is_empty());
        assert!(result.entropy_variance < 0.01);
        assert!(result.embedded_regions.is_empty());
    }

    #[test]
    fn test_mixed_data() {
        let mut data = Vec::new();
        // First 4KB: plaintext
        data.extend_from_slice(&b"A".repeat(4096));
        // Next 4KB: high entropy (all bytes)
        for i in 0..4096 {
            data.push((i % 256) as u8);
        }
        // Next 4KB: plaintext
        data.extend_from_slice(&b"B".repeat(4096));

        let result = sliding_window_entropy(&data, None, None, None);
        assert!(result.max_window_entropy > 6.0);
        assert!(result.entropy_variance > 0.1); // mixed content
    }

    #[test]
    fn test_threshold_detects_embedded() {
        let mut data = vec![0x41u8; 8192]; // plaintext section
        // Embed a high-entropy region in the middle
        for i in 0..4096 {
            data.push((i % 256) as u8);
        }
        data.extend_from_slice(&b"A".repeat(4096));

        let result = sliding_window_entropy(&data, Some(4096), Some(2048), Some(6.5));
        assert!(
            !result.embedded_regions.is_empty(),
            "Should detect high-entropy region"
        );
    }

    #[test]
    fn test_small_input_no_windows() {
        let data = b"too small";
        let result = sliding_window_entropy(data, None, None, None);
        assert!(result.window_scores.is_empty());
    }
}

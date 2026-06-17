use std::collections::HashMap;

/// Shannon entropy calculation over a byte distribution.
/// Returns entropy score (0.0–8.0) and byte frequency histogram.
pub fn shannon_entropy(data: &[u8]) -> (f64, HashMap<u8, usize>) {
    if data.is_empty() {
        return (0.0, HashMap::new());
    }

    let mut freq: HashMap<u8, usize> = HashMap::with_capacity(256);
    for &byte in data {
        *freq.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    let entropy: f64 = freq
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            if p > 0.0 { -p * p.log2() } else { 0.0 }
        })
        .sum();

    (entropy, freq)
}

/// Classify entropy score into a human-readable category using configurable thresholds.
pub fn classify_entropy(
    score: f64,
    plaintext_max: f64,
    mixed_max: f64,
    compressed_max: f64,
) -> &'static str {
    if score < plaintext_max {
        "plaintext/structured"
    } else if score < mixed_max {
        "mixed/partially_encoded"
    } else if score < compressed_max {
        "compressed/encoded"
    } else {
        "high_entropy"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let (entropy, freq) = shannon_entropy(b"");
        assert_eq!(entropy, 0.0);
        assert!(freq.is_empty());
    }

    #[test]
    fn test_constant_byte() {
        let (entropy, _) = shannon_entropy(&[0x41; 100]);
        assert!((entropy - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_max_entropy() {
        // All 256 bytes equally distributed → ~8.0
        let data: Vec<u8> = (0..=255).cycle().take(256 * 100).collect();
        let (entropy, _) = shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.1);
    }

    #[test]
    fn test_plaintext_entropy() {
        let text = b"The quick brown fox jumps over the lazy dog. ";
        let (entropy, _) = shannon_entropy(text);
        assert!(entropy < 5.0);
    }

    #[test]
    fn test_classify_entropy() {
        assert_eq!(classify_entropy(2.0, 3.5, 6.0, 7.5), "plaintext/structured");
        assert_eq!(
            classify_entropy(4.5, 3.5, 6.0, 7.5),
            "mixed/partially_encoded"
        );
        assert_eq!(classify_entropy(7.0, 3.5, 6.0, 7.5), "compressed/encoded");
        assert_eq!(classify_entropy(7.8, 3.5, 6.0, 7.5), "high_entropy");
    }
}

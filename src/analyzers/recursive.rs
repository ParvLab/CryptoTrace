use crate::error::{CryptoTraceError, Result};
use crate::types::Layer;
use std::collections::HashSet;

const DEFAULT_MAX_DEPTH: usize = 10;
const DEFAULT_MAX_TIME_SECS: u64 = 30;
const DEFAULT_MAX_EXPANSION_RATIO: f64 = 100.0;

/// Recursive layer analyzer configuration.
pub struct RecursiveConfig {
    pub max_depth: usize,
    pub max_time_secs: u64,
    pub max_expansion_ratio: f64,
}

impl Default for RecursiveConfig {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_time_secs: DEFAULT_MAX_TIME_SECS,
            max_expansion_ratio: DEFAULT_MAX_EXPANSION_RATIO,
        }
    }
}

/// Analyze input recursively, unwrapping layers of encoding/compression/encryption.
/// Each layer is detected, the content is decoded/decompressed, and analysis continues
/// on the result up to max_depth.
pub fn analyze_recursive(data: &[u8], config: &RecursiveConfig) -> Result<Vec<Layer>> {
    let start = std::time::Instant::now();
    let mut seen_hashes = HashSet::new();
    let mut layers = Vec::new();

    let mut current_data = data.to_vec();
    let mut depth = 0;

    while depth < config.max_depth {
        // Check timeout
        if start.elapsed().as_secs() > config.max_time_secs {
            return Err(CryptoTraceError::RecursionTimeout {
                timeout: config.max_time_secs,
            });
        }

        // Check for cycle
        let current_hash = crate::core::hashing::sha256_hex(&current_data);
        if !seen_hashes.insert(current_hash) {
            return Err(CryptoTraceError::CycleDetected);
        }

        // Detect the current layer
        let input_str = String::from_utf8_lossy(&current_data);
        let _hash_detection = crate::core::hashing::detect_hash(&input_str);
        let encoding_detection = crate::core::encoding::detect_encoding(&input_str);
        let compression_detection = crate::core::compression::detect_compression(&current_data);
        let (entropy, _) = crate::core::entropy::shannon_entropy(&current_data);
        let encryption_detection =
            crate::core::encryption::detect_encryption(&current_data, entropy);

        // Determine if we should try to unwrap
        let (detected_type, algorithm, confidence) = if let Some(e) = encoding_detection.as_ref() {
            (
                "encoding".to_string(),
                e.encoding_type.clone(),
                e.confidence,
            )
        } else if let Some(c) = compression_detection.as_ref() {
            ("compression".to_string(), c.format.clone(), c.confidence)
        } else if let Some(e) = encryption_detection.as_ref() {
            ("encryption".to_string(), e.algorithm.clone(), e.confidence)
        } else {
            // No more layers to unwrap
            break;
        };

        // Try to decode/decompress
        let decoded: Option<Vec<u8>> = if let Some(e) = &encoding_detection {
            // For Base64, attempt decode
            if e.encoding_type == "Base64" {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(&current_data)
                    .ok()
            } else if e.encoding_type == "Hex" {
                let input_str = String::from_utf8_lossy(&current_data);
                (0..input_str.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&input_str[i..i + 2], 16).ok())
                    .collect::<Vec<u8>>()
                    .into()
            } else {
                None
            }
        } else if let Some(c) = &compression_detection {
            crate::core::compression::try_decompress(&current_data, &c.format)
                .ok()
                .map(|r| r.data)
        } else {
            None
        };

        // Check expansion ratio
        if let Some(ref decoded) = decoded {
            if !decoded.is_empty() && !current_data.is_empty() {
                let ratio = decoded.len() as f64 / current_data.len() as f64;
                if ratio > config.max_expansion_ratio {
                    return Err(CryptoTraceError::CompressionBomb {
                        ratio,
                        limit: config.max_expansion_ratio,
                    });
                }
            }
        }

        let expansion_ratio = decoded.as_ref().map(|d| {
            if !current_data.is_empty() {
                d.len() as f64 / current_data.len() as f64
            } else {
                1.0
            }
        });

        let preview = decoded
            .as_ref()
            .map(|d| d.iter().take(64).cloned().collect());

        let layer = Layer {
            depth,
            detected_type,
            algorithm,
            confidence,
            decoded_preview: preview,
            decoded_length: decoded.as_ref().map_or(0, |d| d.len()),
            expansion_ratio,
            children: vec![],
        };

        layers.push(layer);
        depth += 1;

        // Continue with decoded content if available
        if let Some(decoded) = decoded {
            current_data = decoded;
        } else {
            break;
        }
    }

    Ok(layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input_no_layers() {
        let config = RecursiveConfig::default();
        let layers = analyze_recursive(b"hello world", &config).unwrap();
        assert!(layers.is_empty());
    }

    #[test]
    fn test_single_base64_layer() {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD.encode(b"hello world");
        let config = RecursiveConfig::default();
        let layers = analyze_recursive(data.as_bytes(), &config).unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].detected_type, "encoding");
    }
}

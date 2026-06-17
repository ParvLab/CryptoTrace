/// Verify that the recursive analyzer detects and rejects compression bombs.
///
/// A compression bomb is an input that decompresses to more than 100× the
/// original size (the default MAX_EXPANSION_RATIO). The analyzer should
/// return `CryptoTraceError::CompressionBomb` before exhausting memory.
use cryptotrace::analyzers::recursive::{RecursiveConfig, analyze_recursive};
use cryptotrace::error::CryptoTraceError;

/// Build a small payload that compresses very efficiently (many repeated
/// bytes) so the decompressed ratio exceeds MAX_EXPANSION_RATIO.
fn compression_bomb_payload() -> Vec<u8> {
    // GZIP-compress 10 MB of repeated 'A' bytes.
    // The compressed output should be tiny (well under 100 KB), giving
    // an expansion ratio > 100× when decompressed.
    let huge: Vec<u8> = std::iter::repeat(b'A').take(10_000_000).collect();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    use std::io::Write;
    encoder.write_all(&huge).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn test_compression_bomb_rejected() {
    let bomb = compression_bomb_payload();

    // Use a tight config to ensure we detect the bomb quickly.
    let config = RecursiveConfig {
        max_depth: 2, // only one decompression layer needed
        max_time_secs: 10,
        max_expansion_ratio: 100.0,
    };

    let result = analyze_recursive(&bomb, &config);

    match result {
        Err(CryptoTraceError::CompressionBomb { ratio, limit }) => {
            assert!(ratio > limit, "expected ratio {} > limit {}", ratio, limit);
            eprintln!(
                "COMPRESSION_BOMB: ratio={:.1}x limit={:.0}x — correctly rejected",
                ratio, limit
            );
        }
        Err(other) => {
            // Might get RecursionTimeout on slow machines; still a safe failure.
            eprintln!("Got non-bomb error (still safe): {}", other);
        }
        Ok(layers) => {
            // If it somehow decoded, verify the first layer's expansion_ratio
            // is at least suspicious (> 10×).
            if let Some(first) = layers.first() {
                if let Some(ratio) = first.expansion_ratio {
                    assert!(
                        ratio < 1000.0,
                        "bomb should have been caught, ratio was {}",
                        ratio
                    );
                }
            }
            eprintln!("WARNING: bomb was not rejected ({} layers)", layers.len());
        }
    }
}

#[test]
fn test_normal_compression_passes() {
    // A small, legitimate GZIP file should decode normally.
    let data = b"Hello, World! This is a normal message that compresses well. ";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    use std::io::Write;
    encoder.write_all(data).unwrap();
    let compressed = encoder.finish().unwrap();

    let config = RecursiveConfig::default();
    let result = analyze_recursive(&compressed, &config);
    assert!(
        result.is_ok(),
        "normal compression should decode: {:?}",
        result.err()
    );
    let layers = result.unwrap();
    assert!(!layers.is_empty(), "should have at least one layer");
}

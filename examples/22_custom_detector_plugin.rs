trait EncodingDetector {
    fn name(&self) -> &'static str;
    fn detect(&self, input: &str) -> Option<f64>;
}

struct Rot13Detector;

impl EncodingDetector for Rot13Detector {
    fn name(&self) -> &'static str { "ROT13" }

    fn detect(&self, input: &str) -> Option<f64> {
        if input.is_empty() || input.len() > 1024 { return None; }

        let alpha_count = input.chars().filter(|c| c.is_ascii_alphabetic()).count();
        if (alpha_count as f64) / (input.len() as f64) < 0.5 { return None; }

        Some(alpha_count as f64 / input.len() as f64)
    }
}

struct HexSpacedDetector;

impl EncodingDetector for HexSpacedDetector {
    fn name(&self) -> &'static str { "HexSpaced" }

    fn detect(&self, input: &str) -> Option<f64> {
        let trimmed = input.trim();
        if trimmed.len() < 5 { return None; }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 { return None; }

        let hex_count = parts.iter().filter(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())).count();
        if (hex_count as f64) / (parts.len() as f64) > 0.8 {
            Some(hex_count as f64 / parts.len() as f64)
        } else {
            None
        }
    }
}

fn main() {
    println!("=== Custom Detector Plugin System ===\n");

    let detectors: Vec<Box<dyn EncodingDetector>> = vec![
        Box::new(Rot13Detector),
        Box::new(HexSpacedDetector),
    ];

    let test_cases = vec![
        "Gur dhvpx oebja sbk whzcf bire gur ynml qbt",
        "48 65 6C 6C 6F 20 57 6F 72 6C 64",
        "This is just a normal sentence for testing",
        "SGVsbG8gV29ybGQ=",
    ];

    for input in &test_cases {
        println!("Input: {:?}", input);

        if let Some(h) = cryptotrace::core::hashing::detect_hash(input) {
            println!("  Built-in hash: {} (conf={:.2})", h.algorithm, h.confidence);
        }
        if let Some(e) = cryptotrace::core::encoding::detect_encoding(input) {
            println!("  Built-in encoding: {} (conf={:.2})", e.encoding_type, e.confidence);
        }

        for detector in &detectors {
            if let Some(confidence) = detector.detect(input) {
                println!("  Custom [{}]: detected (conf={:.2})", detector.name(), confidence);
            }
        }
        println!();
    }
}

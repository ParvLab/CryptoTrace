use cryptotrace::core::calibration::{generate_synthetic_dataset, train, predict_proba};
use cryptotrace::types::SignalBreakdown;

fn main() {
    println!("=== False Positive Analysis ===\n");

    let plaintexts = [
        "The quick brown fox jumps over the lazy dog",
        "Hello World! This is a simple test.",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        "12345 67890 12345 67890 12345",
        "Monday Tuesday Wednesday Thursday Friday",
        "abcdefghijklmnopqrstuvwxyz",
    ];

    println!("Running detection on {} plaintext samples:\n", plaintexts.len());
    for text in &plaintexts {
        let hash_detection = cryptotrace::core::hashing::detect_hash(text);
        let enc_detection = cryptotrace::core::encoding::detect_encoding(text);

        let algo = hash_detection.as_ref().map(|h| h.algorithm.as_str()).unwrap_or("none");
        let enc = enc_detection.as_ref().map(|e| e.encoding_type.as_str()).unwrap_or("none");

        let is_false_positive = algo != "none" || enc != "none";
        println!("  {:60} hash={:8} enc={:8}{}",
            text, algo, enc,
            if is_false_positive { "  FP" } else { "" });
    }

    println!("\n--- Calibration to Suppress False Positives ---");
    let dataset = generate_synthetic_dataset(200);
    let model = train(&dataset, 0.01, 500, 0.001);

    println!("\nCalibrated scores:");
    for text in &plaintexts {
        let test_signals = SignalBreakdown {
            entropy: 0.3,
            block_alignment: 0.3,
            magic_bytes: 0.1,
            length_pattern: 0.3,
            charset_purity: Some(0.85),
            byte_distribution: None,
            window_variance: Some(0.3),
        };
        let prob = predict_proba(&model, &test_signals);
        println!("  {:50} calibrated_prob={:.4} {}",
            text, prob,
            if prob < 0.3 { "suppressed" } else { "still flagged" });
    }
}

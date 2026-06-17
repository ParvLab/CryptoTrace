use cryptotrace::core::calibration::{generate_synthetic_dataset, train, predict_proba, signal_contributions, save_model, load_model};
use cryptotrace::types::SignalBreakdown;

fn main() {
    println!("Generating synthetic training data...");

    let dataset = generate_synthetic_dataset(250);
    println!("  {} samples generated", dataset.len());

    let model = train(&dataset, 0.01, 1000, 0.001);
    println!("Model trained: intercept={:.4}, weights={:?}", model.intercept, model.weights);
    println!("Dataset size: {}", model.dataset_size);

    let test_signals = SignalBreakdown {
        entropy: 0.85,
        block_alignment: 0.72,
        magic_bytes: 0.65,
        length_pattern: 0.91,
        charset_purity: Some(0.48),
        byte_distribution: None,
        window_variance: Some(0.73),
    };
    let prob = predict_proba(&model, &test_signals);
    println!("\nPrediction for high-entropy sample: {:.4}", prob);

    let contribs = signal_contributions(&model, &test_signals);
    println!("\nSignal contributions:");
    for sc in &contribs {
        println!("  {:20} {:>8} {:.4}", sc.signal_name, if sc.coefficient > 0.0 { "+" } else { "-" }, sc.contribution);
    }

    save_model(&model, "calibration_example.json").ok();
    if let Ok(loaded) = load_model("calibration_example.json") {
        println!("\nModel save/load roundtrip: OK (weights={:?})", loaded.weights);
    }
    std::fs::remove_file("calibration_example.json").ok();
}

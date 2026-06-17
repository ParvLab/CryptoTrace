use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = if args.len() > 1 { &args[1] } else { "Cargo.toml" };
    let data = fs::read(path).expect("Failed to read file");

    println!("File: {} ({} bytes)", path, data.len());
    let (entropy, _) = cryptotrace::core::entropy::shannon_entropy(&data);
    println!("Global Shannon entropy: {:.2} bits/byte", entropy);

    let sw = cryptotrace::core::sliding_entropy::sliding_window_entropy(&data, Some(4096), None, Some(7.5));

    if sw.window_scores.is_empty() {
        println!("File too small for any window");
        return;
    }

    let avg: f64 = sw.window_scores.iter().sum::<f64>() / sw.window_scores.len() as f64;
    let max_score = sw.window_scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min_score = sw.window_scores.iter().cloned().fold(f64::INFINITY, f64::min);

    println!("Windows analyzed: {}", sw.window_scores.len());
    println!("Avg window entropy: {:.2}", avg);
    println!("Max window entropy: {:.2}", max_score);
    println!("Min window entropy: {:.2}", min_score);
    println!("Max window entropy (struct): {:.2}", sw.max_window_entropy);
    println!("Entropy variance: {:.2}", sw.entropy_variance);

    let hot_count = sw.window_scores.iter().filter(|&&s| s > 7.5).count();
    if hot_count > 0 {
        println!("\nHigh-entropy regions (>7.5 bits/byte):");
        println!("  {} windows above threshold", hot_count);
        for region in sw.embedded_regions.iter().take(10) {
            println!("  offset {}-{}", region.start, region.end);
        }
        if sw.embedded_regions.len() > 10 {
            println!("  ... and {} more", sw.embedded_regions.len() - 10);
        }
    }
}

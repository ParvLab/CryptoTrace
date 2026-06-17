use rand::Rng;
use std::time::Instant;

struct FuzzStats {
    total_inputs: u64,
    hash_detections: u64,
    enc_detections: u64,
    avg_entropy: f64,
    min_len: usize,
    max_len: usize,
}

fn main() {
    println!("=== In-Process Fuzz Harness Simulation ===\n");

    let iterations: u64 = std::env::var("FUZZ_ITERATIONS")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(10_000);

    let mut stats = FuzzStats {
        total_inputs: 0,
        hash_detections: 0,
        enc_detections: 0,
        avg_entropy: 0.0,
        min_len: usize::MAX,
        max_len: 0,
    };

    println!("Fuzzing with {} iterations...\n", iterations);
    let start = Instant::now();

    for _ in 0..iterations {
        let input = generate_random_input();
        stats.total_inputs += 1;
        stats.min_len = stats.min_len.min(input.len());
        stats.max_len = stats.max_len.max(input.len());

        let text = String::from_utf8_lossy(&input);

        if cryptotrace::core::hashing::detect_hash(&text).is_some() {
            stats.hash_detections += 1;
        }
        if cryptotrace::core::encoding::detect_encoding(&text).is_some() {
            stats.enc_detections += 1;
        }

        let (entropy, _) = cryptotrace::core::entropy::shannon_entropy(&input);
        stats.avg_entropy += entropy;

        let _sw = cryptotrace::core::sliding_entropy::sliding_window_entropy(&input, Some(4096), None, Some(0.75));
    }

    let elapsed = start.elapsed();
    stats.avg_entropy /= stats.total_inputs as f64;

    println!("=== Fuzz Results ===");
    println!("  Total inputs:     {}", stats.total_inputs);
    println!("  Time:             {:.2}s", elapsed.as_secs_f64());
    println!("  Throughput:       {:.0} inputs/sec", stats.total_inputs as f64 / elapsed.as_secs_f64());
    println!("  Hash detections:  {}", stats.hash_detections);
    println!("  Encoding detects: {}", stats.enc_detections);
    println!("  Avg entropy:      {:.2}", stats.avg_entropy);
    println!("  Input range:      {} - {} bytes", stats.min_len, stats.max_len);
    println!("\nAll detectors stable under fuzzing");
}

fn generate_random_input() -> Vec<u8> {
    let mut rng = rand::rng();
    let len = rng.random_range(1..256);
    (0..len).map(|_| rng.random::<u8>()).collect()
}

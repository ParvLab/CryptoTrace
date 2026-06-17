// Build worker binary first: cargo build --bin cryptotrace-worker

use std::time::Instant;

fn main() {
    println!("=== Memory-Safe Sandboxed Worker ===\n");

    let config = cryptotrace::sanitization::sandbox::SandboxConfig {
        enabled: true,
        timeout_seconds: 30,
        max_memory_mb: 256,
        max_concurrent: 4,
        worker_path: None,
    };
    let sandbox = cryptotrace::sanitization::sandbox::Sandbox::new(config);

    let mut test_input = Vec::with_capacity(5_000_000);
    for i in 0..100_000 {
        test_input.extend_from_slice(format!("data_point_{}={}\n", i, i * 7).as_bytes());
    }
    println!("Input size: {} bytes", test_input.len());

    let start = Instant::now();
    match sandbox.run_worker("passthrough", &test_input) {
        Ok(output) => {
            let elapsed = start.elapsed();
            println!("Worker succeeded in {:.2}s", elapsed.as_secs_f64());
            println!("Output size: {} bytes", output.len());
            if output == test_input {
                println!("PASSTHROUGH VERIFIED: output matches input");
            }
        }
        Err(e) => {
            println!("Worker (expected if no binary): {}", e);
            println!("Build the worker binary: cargo build --bin cryptotrace-worker");
        }
    }
}

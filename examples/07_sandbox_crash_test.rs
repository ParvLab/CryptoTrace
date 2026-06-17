// Build worker binary first: cargo build --bin cryptotrace-worker

fn main() {
    let config = cryptotrace::sanitization::sandbox::SandboxConfig {
        enabled: true,
        timeout_seconds: 5,
        max_memory_mb: 256,
        max_concurrent: 2,
        worker_path: None,
    };
    let sandbox = cryptotrace::sanitization::sandbox::Sandbox::new(config);

    let test_data = b"5d41402abc4b2a76b9719d911017c592";
    match sandbox.run_worker("detect", test_data) {
        Ok(output) => {
            println!("Sandbox worker succeeded ({} bytes)", output.len());
            if let Ok(text) = String::from_utf8(output) {
                println!("Output: {}", text);
            }
        }
        Err(e) => {
            println!("Sandbox worker failed (expected if no worker binary): {}", e);
            println!("Falling back to in-process analysis...");
            match cryptotrace::analyzers::file::analyze_bytes(test_data, cryptotrace::types::SourceType::Binary) {
                Ok(r) => println!("In-process result: algo={:?} ent={}", r.algorithm, r.entropy),
                Err(e2) => eprintln!("Fallback also failed: {}", e2),
            }
        }
    }

    let tight = cryptotrace::sanitization::sandbox::SandboxConfig {
        enabled: true,
        timeout_seconds: 1,
        worker_path: None,
        ..Default::default()
    };
    let tight_sandbox = cryptotrace::sanitization::sandbox::Sandbox::new(tight);
    let large_input = vec![b'A'; 1_000_000];
    match tight_sandbox.run_worker("detect", &large_input) {
        Ok(_) => println!("Tight timeout: worker finished in time"),
        Err(e) => println!("Tight timeout: worker timed out as expected: {}", e),
    }
}

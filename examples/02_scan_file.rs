use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = if args.len() > 1 { &args[1] } else { "Cargo.toml" };

    let data = fs::read(path).expect("Failed to read file");

    match cryptotrace::analyzers::file::analyze_bytes(&data, cryptotrace::types::SourceType::Binary) {
        Ok(result) => {
            println!("File: {}", path);
            println!("Algorithm: {}", result.algorithm.unwrap_or_else(|| "<none>".into()));
            println!("Encoding: {}", result.detected_type);
            let (entropy, _) = cryptotrace::core::entropy::shannon_entropy(&data);
            println!("Entropy: {:.2}", entropy);
            println!("Confidence: {:.2}", result.confidence);
            println!("Risk: {:?}", result.risk_level);
            if !result.weakness_cve.is_empty() {
                println!("CVEs: {:?}", result.weakness_cve);
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let dir = if args.len() > 1 { &args[1] } else { "." };
    let max_size: u64 = std::env::var("MAX_FILE_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(10_485_760);

    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }

        let _meta = match fs::metadata(&path) {
            Ok(m) if m.len() <= max_size => m,
            _ => continue,
        };

        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        match cryptotrace::analyzers::file::analyze_bytes(&data, cryptotrace::types::SourceType::Binary) {
            Ok(result) => {
                let algo = result.algorithm.unwrap_or_else(|| "-".into());
                let (entropy, _) = cryptotrace::core::entropy::shannon_entropy(&data);
                println!("{}\t{}\t{}\t{:.2}\t{:.2}",
                    path.display(), algo, result.detected_type, entropy, result.confidence);
            }
            Err(e) => eprintln!("Error scanning {}: {}", path.display(), e),
        }
    }
}

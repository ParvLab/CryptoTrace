use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let dir = args.get(1).map(|s| s.as_str()).unwrap_or(".");
    let out = args.get(2).map(|s| s.as_str()).unwrap_or("scan_report.csv");

    let mut wtr = csv::Writer::from_path(out).expect("Failed to create CSV");
    wtr.write_record(["path", "algorithm", "detected_type", "entropy", "confidence", "risk_level"])
        .unwrap();

    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }
        let data = match fs::read(&path) {
            Ok(d) if d.len() <= 10_485_760 => d,
            _ => continue,
        };
        if let Ok(r) = cryptotrace::analyzers::file::analyze_bytes(&data, cryptotrace::types::SourceType::Binary) {
            let (entropy, _) = cryptotrace::core::entropy::shannon_entropy(&data);
            wtr.write_record([
                path.to_string_lossy().as_ref(),
                r.algorithm.as_deref().unwrap_or("-"),
                &r.detected_type,
                &format!("{:.4}", entropy),
                &format!("{:.4}", r.confidence),
                &format!("{:?}", r.risk_level),
            ]).ok();
        }
    }
    wtr.flush().ok();
    println!("Report written to {}", out);
}

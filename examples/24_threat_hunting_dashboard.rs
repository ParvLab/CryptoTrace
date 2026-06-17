use std::fs;
use std::path::Path;
use std::time::Instant;

const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

#[derive(Debug)]
struct ThreatEntry {
    path: String,
    entropy: f64,
    algorithm: Option<String>,
    #[allow(dead_code)]
    confidence: f64,
    risk_score: f64,
    cves: Vec<String>,
}

fn main() {
    println!("=== Threat Hunting Dashboard ===\n");
    let start = Instant::now();

    let args: Vec<String> = std::env::args().collect();
    let scan_dir = args.get(1).map(|s| s.as_str()).unwrap_or("src");
    let max_size: u64 = std::env::var("MAX_FILE_SIZE").ok().and_then(|s| s.parse().ok()).unwrap_or(1_048_576);

    let mut threats: Vec<ThreatEntry> = Vec::new();
    scan_directory(scan_dir, max_size, &mut threats);
    threats.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap_or(std::cmp::Ordering::Equal));

    let elapsed = start.elapsed();
    println!("Scanned {} files in {:.2}s\n", threats.len(), elapsed.as_secs_f64());

    let critical = threats.iter().filter(|t| t.risk_score > 7.0).count();
    let high = threats.iter().filter(|t| t.risk_score > 4.0 && t.risk_score <= 7.0).count();
    let medium = threats.iter().filter(|t| t.risk_score > 2.0 && t.risk_score <= 4.0).count();

    println!("=== Risk Summary ===");
    println!("  Critical: {}  High: {}  Medium: {}", critical, high, medium);

    println!("\n=== Top Threats ===");
    println!("{:6} {:50} {:12} {:8} {:20}", "Score", "Path", "Algorithm", "Entropy", "CVEs");
    println!("{}", "-".repeat(100));

    for t in threats.iter().filter(|t| t.risk_score > 2.0).take(20) {
        let algo = t.algorithm.as_deref().unwrap_or("-");
        let cve_str = if t.cves.is_empty() { "-".into() } else { t.cves.join(",") };
        let path_trunc = if t.path.len() > 50 { format!("...{}", &t.path[t.path.len()-47..]) } else { t.path.clone() };
        println!("{:>5.1}  {:50} {:12} {:>7.2} {:20}", t.risk_score, path_trunc, algo, t.entropy, cve_str);
    }

    let avg_entropy: f64 = threats.iter().map(|t| t.entropy).sum::<f64>() / threats.len().max(1) as f64;
    println!("\n=== Statistics ===");
    println!("  Average entropy: {:.2}", avg_entropy);
    println!("  Files with CVEs: {}", threats.iter().filter(|t| !t.cves.is_empty()).count());
}

fn should_skip(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| SKIP_DIRS.contains(&name) || name.starts_with('.'))
}

fn scan_directory(dir: &str, max_size: u64, threats: &mut Vec<ThreatEntry>) {
    let iter = match fs::read_dir(dir) {
        Ok(it) => it,
        Err(_) => return,
    };

    for entry in iter.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if !should_skip(&path) {
                scan_directory(&path.to_string_lossy(), max_size, threats);
            }
            continue;
        }

        if !path.is_file() { continue; }
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.len() > max_size || meta.len() < 4 { continue; }

        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let result = cryptotrace::analyzers::file::analyze_bytes(&data, cryptotrace::types::SourceType::Binary);
        let (entropy, _) = cryptotrace::core::entropy::shannon_entropy(&data);

        if let Ok(r) = result {
            let risk_score = r.confidence * 10.0 * match r.risk_level {
                cryptotrace::types::RiskLevel::Critical => 10.0,
                cryptotrace::types::RiskLevel::High => 7.0,
                cryptotrace::types::RiskLevel::Medium => 4.0,
                cryptotrace::types::RiskLevel::Low => 2.0,
                cryptotrace::types::RiskLevel::Unknown => 1.0,
            };

            threats.push(ThreatEntry {
                path: path.to_string_lossy().into_owned(),
                entropy,
                algorithm: r.algorithm,
                confidence: r.confidence,
                risk_score,
                cves: r.weakness_cve,
            });
        }
    }
}

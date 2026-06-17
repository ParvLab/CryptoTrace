#[tokio::main]
async fn main() {
    let sample_hash = "d41d8cd98f00b204e9800998ecf8427e";

    println!("Step 1: Hash identification");
    if let Some(h) = cryptotrace::core::hashing::detect_hash(sample_hash) {
        println!("  Algorithm: {} (confidence {:.2})", h.algorithm, h.confidence);
    }

    println!("\nStep 2: CVE lookup");
    let cve_map = cryptotrace::intelligence::risk::build_cve_map(
        "signatures/cve_map.yaml",
        "cve-db.json",
    );
    if let Some(cves) = cve_map.get("MD5") {
        println!("  Known CVEs for MD5: {:?}", cves);
    }

    println!("\nStep 3: Threat intel scan");
    let config = cryptotrace::intelligence::threat_intel::ThreatIntelConfig {
        vt_api_key: None,
        yara_rules_path: None,
        enable_scan: true,
    };

    let reports = cryptotrace::intelligence::threat_intel::composite_threat_scan(
        sample_hash,
        &[],
        &config,
    ).await.unwrap_or_default();
    println!("  Threat reports: {}", reports.len());
    for report in &reports {
        println!("    Source: {} | Positives: {}/{} | Malicious: {}",
            report.source, report.positives, report.total_scanners, report.malicious);
    }

    let malicious = reports.iter().any(|r| r.malicious);
    let max_positives = reports.iter().map(|r| r.positives).max().unwrap_or(0);
    let risk = if malicious {
        "Critical"
    } else if max_positives > 5 {
        "High"
    } else if max_positives > 2 {
        "Medium"
    } else {
        "Low"
    };
    println!("\nStep 4: Composite risk assessment");
    println!("  Final risk level: {}", risk);
}

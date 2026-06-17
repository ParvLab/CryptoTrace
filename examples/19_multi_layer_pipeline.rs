use std::time::Instant;

fn main() {
    println!("=== Multi-Layer Detection Pipeline ===\n");
    let start = Instant::now();

    let input = br#"-----BEGIN PGP PRIVATE KEY BLOCK-----
lI0EY8fH4hMFAiiX/gEBAf4A+wYtKxSGHgQEQAoYCQQALCBiZXN0IGVmZm9ydCB0
byBkZXRlY3QgdGhpcyBzZWNyZXQga2V5IGFuZCBpdHMgZW5jb2Rpbmc=
-----END PGP PRIVATE KEY BLOCK-----"#;
    println!("Step 1: Input ({} bytes)", input.len());

    let format_result = cryptotrace::analyzers::file::analyze_bytes(input, cryptotrace::types::SourceType::Binary)
        .expect("Analysis failed");
    println!("Step 2: Detection complete");
    println!("  Algorithm: {:?}", format_result.algorithm);
    println!("  Type: {}", format_result.detected_type);
    let (entropy, _) = cryptotrace::core::entropy::shannon_entropy(input);
    println!("  Entropy: {:.2}", entropy);
    println!("  Confidence: {:.2}", format_result.confidence);
    println!("  Risk: {:?}", format_result.risk_level);
    if !format_result.weakness_cve.is_empty() {
        println!("  CVEs: {:?}", format_result.weakness_cve);
    }

    let sw = cryptotrace::core::sliding_entropy::sliding_window_entropy(input, Some(4096), None, Some(0.75));
    println!("Step 3: Sliding window ({} windows, peak {:.2})",
        sw.window_scores.len(), sw.max_window_entropy);
    if let Some(region) = sw.embedded_regions.first() {
        println!("  Peak region offset: {}-{}", region.start, region.end);
    }

    let cef = cryptotrace::intelligence::siem::format_cef(&format_result);
    println!("Step 4: SIEM export (CEF, {} chars)", cef.len());

    let total = start.elapsed();
    println!("\n=== Pipeline complete in {:.2}s ===", total.as_secs_f64());
}

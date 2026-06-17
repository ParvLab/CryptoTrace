use std::io::Read;
use std::path::Path;

fn main() {
    let test_data = b"Hello World this is a test string with some data to analyze";

    // Method 1: Raw bytes
    println!("=== Raw bytes ===");
    let r1 = cryptotrace::analyzers::file::analyze_bytes(test_data, cryptotrace::types::SourceType::Binary).unwrap();
    println!("  algo={:?} type={} ent={:.2} conf={:.2}", r1.algorithm, r1.detected_type, r1.entropy, r1.confidence);

    // Method 2: File
    println!("=== From file ===");
    let r2 = cryptotrace::analyzers::file::analyze_file(Path::new("Cargo.toml")).unwrap();
    println!("  algo={:?} type={} ent={:.2} conf={:.2}", r2.algorithm, r2.detected_type, r2.entropy, r2.confidence);

    // Method 3: Stdin (if piped)
    println!("=== Stdin (pipe data or skip) ===");
    let mut buf = Vec::new();
    if std::io::stdin().read_to_end(&mut buf).is_ok() && !buf.is_empty() {
        let r3 = cryptotrace::analyzers::file::analyze_bytes(&buf, cryptotrace::types::SourceType::Binary).unwrap();
        println!("  algo={:?} type={} ent={:.2} conf={:.2}", r3.algorithm, r3.detected_type, r3.entropy, r3.confidence);
    } else {
        println!("  (no stdin data)");
    }
}

fn main() {
    let test_data = b"d41d8cd98f00b204e9800998ecf8427e";
    let result = cryptotrace::analyzers::file::analyze_bytes(test_data, cryptotrace::types::SourceType::Binary)
        .expect("Analysis failed");

    let cef = cryptotrace::intelligence::siem::format_cef(&result);
    println!("=== CEF Format ===");
    println!("{}", cef);

    let leef = cryptotrace::intelligence::siem::format_leef(&result);
    println!("\n=== LEEF Format ===");
    println!("{}", leef);
}

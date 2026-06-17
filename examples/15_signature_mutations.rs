fn main() {
    println!("=== Signature Detection & Mutations ===\n");

    let registry = cryptotrace::signatures::default_registry().expect("Failed to load registry");
    println!("Loaded {} signatures", registry.signatures.len());

    let test_cases: [(&str, &[u8]); 6] = [
        ("ELF binary", &[0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]),
        ("GZip file", &[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]),
        ("PNG image", &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
        ("PDF file", &[0x25, 0x50, 0x44, 0x46]),
        ("JPEG image", &[0xff, 0xd8, 0xff, 0xe0]),
        ("ZIP archive", &[0x50, 0x4b, 0x03, 0x04]),
    ];

    for (name, magic) in &test_cases {
        let matches = cryptotrace::signatures::match_signatures(magic, &registry);
        println!("{}: {:?}", name, matches.iter().map(|m| &m.name).collect::<Vec<_>>());
    }

    // Test mutation resistance
    println!("\n--- Mutation Testing ---");
    let png_header: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    let base = cryptotrace::signatures::match_signatures(&png_header, &registry);
    println!("Original PNG: {:?}", base.iter().map(|m| &m.name).collect::<Vec<_>>());

    for offset in 0..png_header.len().min(4) {
        for bit in 0..4 {
            let mut mutated = png_header;
            mutated[offset] ^= 1 << bit;
            let matches = cryptotrace::signatures::match_signatures(&mutated, &registry);
            if matches.is_empty() {
                println!("  Mutation at byte {} bit {}: detection lost", offset, bit);
            }
        }
    }
}

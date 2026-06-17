use std::io::Write;

fn main() {
    println!("=== Compression Bomb Defense ===\n");

    let bomb_data = vec![b'A'; 1_000_000];

    let mut compressed = Vec::new();
    {
        let mut encoder = flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::best());
        encoder.write_all(&bomb_data).unwrap();
        encoder.finish().unwrap();
    }

    let ratio = bomb_data.len() as f64 / compressed.len() as f64;
    println!("Original: {} bytes", bomb_data.len());
    println!("Compressed: {} bytes", compressed.len());
    println!("Ratio: {:.1}:1", ratio);

    if let Some(fmt) = cryptotrace::core::compression::detect_compression(&compressed) {
        println!("\nDetected compression format: {:?}", fmt);
    }

    println!("\nAttempting decompression with expansion guard...");
    let result = cryptotrace::core::compression::try_decompress(&compressed, "GZIP");

    match result {
        Ok(decompressed) => {
            println!("Decompressed: {} bytes (ratio: {:.1})", decompressed.data.len(), decompressed.expansion_ratio);
        }
        Err(e) => {
            println!("Decompression denied: {}", e);
            println!("This is the intended defense against compression bombs.");
        }
    }

    let normal_data = b"Hello World! This is a test of the compression bomb defense mechanism.";
    let mut normal_compressed = Vec::new();
    {
        let mut encoder = flate2::write::GzEncoder::new(&mut normal_compressed, flate2::Compression::default());
        encoder.write_all(normal_data).unwrap();
        encoder.finish().unwrap();
    }

    println!("\n--- Normal compression test ---");
    println!("Original: {} bytes, Compressed: {} bytes", normal_data.len(), normal_compressed.len());

    match cryptotrace::core::compression::try_decompress(&normal_compressed, "GZIP") {
        Ok(d) => println!("Normal decompression OK: {} bytes (ratio: {:.1})", d.data.len(), d.expansion_ratio),
        Err(e) => println!("Unexpected rejection: {}", e),
    }
}

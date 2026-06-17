use std::io::{Read, Write};

fn main() {
    let plaintext = b"Secret configuration: API_KEY=sk-abc123 SECRET=xyz789";

    // Gzip then base64 encode
    let mut compressed = Vec::new();
    {
        let mut encoder = flate2::write::GzEncoder::new(&mut compressed, flate2::Compression::default());
        encoder.write_all(plaintext).unwrap();
        encoder.finish().unwrap();
    }

    use base64::Engine;
    let b64_payload = base64::engine::general_purpose::STANDARD.encode(&compressed);

    println!("Encoded payload (first 80 chars): {:?}", &b64_payload[..80.min(b64_payload.len())]);

    // Decode layer by layer
    let mut current = b64_payload.as_bytes().to_vec();
    for layer in 1..=5 {
        let s = String::from_utf8_lossy(&current);

        if let Some(enc) = cryptotrace::core::encoding::detect_encoding(&s) {
            println!("Layer {}: detected encoding = {} (conf={:.2})", layer, enc.encoding_type, enc.confidence);

            match enc.encoding_type.as_str() {
                "Base64" => {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s.trim()) {
                        current = decoded;
                        continue;
                    }
                }
                _ => { break; }
            }
        }

        if cryptotrace::core::compression::detect_compression(&current).is_some() {
            let mut decompressed = Vec::new();
            let mut d = flate2::read::GzDecoder::new(std::io::Cursor::new(&current));
            if d.read_to_end(&mut decompressed).is_ok() && !decompressed.is_empty() {
                println!("Layer {}: gzip decompressed ({} bytes)", layer, decompressed.len());
                current = decompressed;
                continue;
            }
        }
        break;
    }

    println!("Final decoded text: {:?}", String::from_utf8_lossy(&current));
}

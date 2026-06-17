use rand::Rng;
use rand::SeedableRng;
use std::io::Write;

fn main() {
    println!("=== Entropy Confusion Zones ===\n");

    struct Sample {
        label: &'static str,
        data: Vec<u8>,
    }

    let samples = vec![
        Sample { label: "Plaintext (English)", data: b"The quick brown fox jumps over the lazy dog. This is a normal English sentence with typical letter frequencies.".to_vec() },
        Sample { label: "Compressed (gzip)", data: {
            let mut c = Vec::new();
            let mut enc = flate2::write::GzEncoder::new(&mut c, flate2::Compression::default());
            enc.write_all(b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD").unwrap();
            enc.finish().unwrap();
            c
        }},
        Sample { label: "Base64 encoded", data: {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(b"This is some secret data that we want to encode").into_bytes()
        }},
        Sample { label: "Random (encryption-like)", data: {
            let mut rng = rand::rngs::StdRng::seed_from_u64(42);
            (0..256).map(|_| rng.random()).collect()
        }},
        Sample { label: "AES-like ciphertext", data: vec![
            0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
            0x1c, 0x8e, 0x5f, 0xbf, 0x43, 0x12, 0x67, 0x8a, 0x9b, 0x2c, 0xd4, 0xe5, 0x7f, 0x91, 0x0a, 0x3b,
            0x4d, 0xe8, 0x15, 0x62, 0x9c, 0xa1, 0xb5, 0x4c, 0x72, 0xd3, 0x1f, 0x89, 0xec, 0x50, 0x26, 0x78,
            0xaa, 0x5a, 0xbe, 0x07, 0x33, 0x62, 0x19, 0x8d, 0xc0, 0xeb, 0x14, 0x59, 0x83, 0x2a, 0xcd, 0x6f,
        ]},
        Sample { label: "UUID strings", data: "550e8400-e29b-41d4-a716-446655440000\n550e8400-e29b-41d4-a716-446655440001\n".as_bytes().to_vec() },
        Sample { label: "Base64 (short)", data: {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(b"hello").into_bytes()
        }},
    ];

    println!("{:30} {:>8} {:>12} {:>15} {:>10}", "Type", "Entropy", "Sliding Avg", "Encoding", "Algo");
    println!("{}", "-".repeat(80));

    for s in &samples {
        let (entropy, _freq) = cryptotrace::core::entropy::shannon_entropy(&s.data);
        let text = String::from_utf8_lossy(&s.data);
        let hash = cryptotrace::core::hashing::detect_hash(&text);
        let enc = cryptotrace::core::encoding::detect_encoding(&text);

        let algo_s = hash.as_ref().map(|h| h.algorithm.as_str()).unwrap_or("-");
        let enc_s = enc.as_ref().map(|e| e.encoding_type.as_str()).unwrap_or("-");

        let sw = cryptotrace::core::sliding_entropy::sliding_window_entropy(&s.data, Some(4096), None, Some(0.75));
        let sliding_avg = if !sw.window_scores.is_empty() {
            sw.window_scores.iter().sum::<f64>() / sw.window_scores.len() as f64
        } else {
            0.0
        };

        println!("{:30} {:>7.2}  {:>10.2} {:>15} {:>10}", s.label, entropy, sliding_avg, enc_s, algo_s);
    }

    println!("\n--- Entropy Confusion Zones ---");
    println!("  Low entropy (0-4):    Plaintext, UUID");
    println!("  Medium entropy (4-6): Compressed, Base64");
    println!("  High entropy (6-8):   Encrypted, Random");
    println!("\n  Overlap zone (5-7): Compressed vs Encrypted");
}

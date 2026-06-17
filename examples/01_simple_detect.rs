fn main() {
    let inputs = [
        "5d41402abc4b2a76b9719d911017c592",
        "SGVsbG8gV29ybGQ=",
        "The quick brown fox jumps over the lazy dog",
    ];

    for input in inputs {
        println!("Input: {:?}", input);

        if let Some(hash) = cryptotrace::core::hashing::detect_hash(input) {
            println!("  Hash: {} (confidence {:.2})", hash.algorithm, hash.confidence);
        }
        if let Some(enc) = cryptotrace::core::encoding::detect_encoding(input) {
            println!("  Encoding: {} (confidence {:.2})", enc.encoding_type, enc.confidence);
        }

        let (entropy, _freq) = cryptotrace::core::entropy::shannon_entropy(input.as_bytes());
        println!("  Entropy: {:.2}", entropy);
        println!();
    }
}

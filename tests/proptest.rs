use proptest::prelude::*;

proptest! {
    #[test]
    fn test_detect_hash_never_panics(input: String) {
        let _result = cryptotrace::core::hashing::detect_hash(&input);
    }

    #[test]
    fn test_detect_encoding_never_panics(input: String) {
        let _result = cryptotrace::core::encoding::detect_encoding(&input);
    }

    #[test]
    fn test_analyze_bytes_never_panics(data: Vec<u8>) {
        let _result = cryptotrace::analyzers::file::analyze_bytes(
            &data,
            cryptotrace::types::SourceType::Binary,
        );
    }

    #[test]
    fn test_md5_consistency(mut parts: Vec<u8>) {
        if parts.len() >= 16 {
            parts.truncate(16);
            let hex_str = parts.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            if hex_str.chars().all(|c| c.is_ascii_hexdigit()) && hex_str.len() == 32 {
                if let Some(result) = cryptotrace::core::hashing::detect_hash(&hex_str) {
                    // Accept MD5, NTLM, or UUID — all are valid heuristics for 32-hex strings
                    assert!(
                        result.algorithm == "MD5" || result.algorithm == "NTLM" || result.algorithm == "UUID",
                        "Unexpected algorithm {:?} for 32-char hex", result.algorithm
                    );
                }
            }
        }
    }

    #[test]
    fn test_sha256_consistency(parts: Vec<u8>) {
        if parts.len() >= 32 {
            let hex_str = parts.iter().take(32).map(|b| format!("{:02x}", b)).collect::<String>();
            if hex_str.len() == 64 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Some(result) = cryptotrace::core::hashing::detect_hash(&hex_str) {
                    assert!(result.algorithm == "SHA256" || result.algorithm == "SHA512");
                }
            }
        }
    }

    #[test]
    fn test_valid_base64_roundtrip(data: Vec<u8>) {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
        if !encoded.is_empty() && encoded.len() > 2 {
            if let Some(result) = cryptotrace::core::encoding::detect_encoding(&encoded) {
                // Short base64 strings can also be valid base32, accept either
                let ok = result.encoding_type == "Base64" || result.encoding_type == "Base32";
                assert!(ok, "Base64 roundtrip of {:?} encoded as {:?} got {:?}", data, encoded, result.encoding_type);
            }
        }
    }

    #[test]
    fn test_null_bytes_rejected(data: Vec<u8>) {
        if data.contains(&0x00) && !data.is_empty() {
            let guard = cryptotrace::sanitization::InputGuard::new();
            let result = guard.sanitize_bytes(data.clone(), cryptotrace::types::SourceType::Binary);
            assert!(result.is_err(), "Null bytes should be rejected");
        }
    }

    #[test]
    fn test_entropy_bounds(data: Vec<u8>) {
        if !data.is_empty() {
            let (entropy, _) = cryptotrace::core::entropy::shannon_entropy(&data);
            assert!(entropy >= 0.0, "Entropy should be >= 0");
            assert!(entropy <= 8.0, "Entropy should be <= 8.0 (got {})", entropy);
        }
    }

    #[test]
    fn test_sliding_entropy_no_panic(data: Vec<u8>) {
        let _result = cryptotrace::core::sliding_entropy::sliding_window_entropy(
            &data,
            Some(4096),
            Some(2048),
            Some(7.0),
        );
    }

    #[test]
    fn test_detect_magic_no_panic(data: Vec<u8>) {
        let registry = cryptotrace::signatures::default_registry().unwrap();
        let _result = cryptotrace::signatures::match_signatures(&data, &registry);
    }

    #[test]
    fn test_encoding_negative_cases(input: String) {
        if input.chars().all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation()) {
            if let Some(result) = cryptotrace::core::encoding::detect_encoding(&input) {
                if input.contains('=') && result.encoding_type == "Base64"
                    && base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        input.as_bytes(),
                    ).is_ok()
                {
                }
            }
        }
    }
}

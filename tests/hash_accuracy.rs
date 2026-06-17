use cryptotrace::core::hashing::detect_hash;

#[test]
fn test_md5_accuracy() {
    let cases = vec![
        ("d41d8cd98f00b204e9800998ecf8427e", true),   // empty hash
        ("5f4dcc3b5aa765d61d8327deb882cf99", true),   // "password"
        ("900150983cd24fb0d6963f7d28e17f72", true),   // "abc"
        ("notahash0000000000000000000000000", false), // wrong length
        ("00000000000000000000000000000000", true),   // all zeros
    ];
    for (input, expected) in cases {
        let result = detect_hash(input);
        assert_eq!(result.is_some(), expected, "MD5: '{}'", input);
        if let Some(r) = result {
            assert_eq!(r.algorithm, "MD5", "Expected MD5 for '{}'", input);
        }
    }
}

#[test]
fn test_sha1_accuracy() {
    let cases = vec![
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", true), // empty
        ("a9993e364706816aba3e25717850c26c9cd0d89d", true), // "abc"
        ("not40characterslongenough1234567890", false),
    ];
    for (input, expected) in cases {
        let result = detect_hash(input);
        assert_eq!(result.is_some(), expected, "SHA1: '{}'", input);
        if let Some(r) = result {
            assert_eq!(r.algorithm, "SHA1");
        }
    }
}

#[test]
fn test_sha256_accuracy() {
    let hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let result = detect_hash(hash);
    assert!(result.is_some());
    assert_eq!(result.unwrap().algorithm, "SHA256");
}

#[test]
fn test_sha512_accuracy() {
    let hash = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    let result = detect_hash(hash);
    assert!(result.is_some());
    assert_eq!(result.unwrap().algorithm, "SHA512");
}

#[test]
fn test_bcrypt_accuracy() {
    let cases = vec![
        ("$2b$12$LJ3m4ys3Lv4S7K7K7K7K7O", true),
        (
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
            true,
        ),
        ("plaintext", false),
    ];
    for (input, expected) in cases {
        let result = detect_hash(input);
        assert_eq!(result.is_some(), expected, "bcrypt: '{}'", input);
        if let Some(r) = result {
            assert_eq!(r.algorithm, "bcrypt");
        }
    }
}

#[test]
fn test_argon2_accuracy() {
    let cases = vec![
        ("$argon2id$v=19$m=65536,t=3,p=4$salt$hash", true),
        ("$argon2i$v=19$m=65536,t=3,p=4$salt$hash", true),
        ("$argon2d$v=19$m=65536,t=3,p=4$salt$hash", false), // not in our detection
    ];
    for (input, expected) in cases {
        let result = detect_hash(input);
        assert_eq!(result.is_some(), expected, "Argon2: '{}'", input);
    }
}

#[test]
fn test_pbkdf2_accuracy() {
    let cases = vec![
        ("$pbkdf2-sha256$100000$salt$hash", true),
        ("$pbkdf2-sha512$50000$salt$hash", true),
        ("$pbkdf2-unknown$1000$salt$hash", true), // still detected
        ("notpbkdf2$format", false),
    ];
    for (input, expected) in cases {
        let result = detect_hash(input);
        assert_eq!(result.is_some(), expected, "PBKDF2: '{}'", input);
        if let Some(r) = result {
            assert!(
                r.algorithm.starts_with("PBKDF2-"),
                "Expected PBKDF2 for '{}'",
                input
            );
        }
    }
}

#[test]
fn test_ntlm_accuracy() {
    let result = detect_hash("A0B1C2D3E4F5060708090A0B0C0D0E0F");
    assert!(result.is_some());
    assert_eq!(result.unwrap().algorithm, "NTLM");
}

#[test]
fn test_negative_cases() {
    let non_hashes = vec![
        "hello world",
        "short",
        "not hex string at all",
        "0xdeadbeef",
        "12345",
    ];
    for input in non_hashes {
        let result = detect_hash(input);
        assert!(result.is_none(), "Should not detect '{}' as a hash", input);
    }
}

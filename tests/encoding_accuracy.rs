use cryptotrace::core::encoding::detect_encoding;

#[test]
fn test_base64_accuracy() {
    // Padded base64: unique, unambiguous
    let r = detect_encoding("SGVsbG8gV29ybGQ=").unwrap();
    assert_eq!(r.encoding_type, "Base64");

    // unpadded base64 that's NOT valid as any other encoding
    let r2 = detect_encoding("dGVzdA==").unwrap();
    assert_eq!(r2.encoding_type, "Base64");

    // not base64 (trailing bits, no padding — should fail decode)
    assert!(detect_encoding("abcde").is_none());
}

#[test]
fn test_hex_accuracy() {
    let r = detect_encoding("deadbeef").unwrap();
    assert_eq!(r.encoding_type, "Hex");

    let r2 = detect_encoding("48656c6c6f").unwrap();
    assert_eq!(r2.encoding_type, "Hex");

    // odd length is not valid hex
    assert!(detect_encoding("abc").is_none());
}

#[test]
fn test_url_encoding_accuracy() {
    let r = detect_encoding("hello%20world").unwrap();
    assert_eq!(r.encoding_type, "URLEncoding");

    let r2 = detect_encoding("%48%65%6c%6c%6f").unwrap();
    assert_eq!(r2.encoding_type, "URLEncoding");

    // no percent sign = not URL encoded
    assert!(detect_encoding("hello").is_none());
}

#[test]
fn test_base32_accuracy() {
    let r = detect_encoding("JBSWY3DPEB3W64TMMQ======").unwrap();
    assert_eq!(r.encoding_type, "Base32");

    let r2 = detect_encoding("NBSWY3DP").unwrap();
    assert_eq!(r2.encoding_type, "Base32");

    // wrong length for base32
    assert!(detect_encoding("AAA").is_none());
}

#[test]
fn test_base58_accuracy() {
    // Bitcoin address: starts with 1, mix of case and digits
    let r = detect_encoding("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
    assert_eq!(r.encoding_type, "Base58");

    // Pure lowercase with no digits or uppercase → not Base58
    assert!(detect_encoding("abcdefghijkmnopqrstuvwxyz").is_none());

    // Contains excluded char 'l' → not Base58
    assert!(detect_encoding("abc0def").is_none());
}

#[test]
fn test_ascii85_accuracy() {
    let r = detect_encoding("~<hello~>").unwrap();
    assert_eq!(r.encoding_type, "Ascii85");

    let r2 = detect_encoding("~<data~>").unwrap();
    assert_eq!(r2.encoding_type, "Ascii85");

    // Doesn't end with ~> → not Ascii85
    assert!(detect_encoding("~oops").is_none());
}

#[test]
fn test_z85_accuracy() {
    let r = detect_encoding("abc.xyz+hello$").unwrap();
    assert_eq!(r.encoding_type, "Z85");

    // No special chars → not Z85
    assert!(detect_encoding("plaintext").is_none());
}

#[test]
fn test_base91_accuracy() {
    let r = detect_encoding("!\"#$%&()*+,./0123456789:;<=>?@ABCD~").unwrap();
    assert_eq!(r.encoding_type, "Base91");

    // pure text → not Base91 (too little non-alpha)
    assert!(detect_encoding("hello world").is_none());
}

#[test]
fn test_negative_cases() {
    let non_encodings = vec!["spaces in text", "foo\tbar"];
    for input in non_encodings {
        let result = detect_encoding(input);
        assert!(
            result.is_none(),
            "Should not detect '{}' as encoding. Got: {:?}",
            input,
            result.map(|r| r.encoding_type)
        );
    }
}

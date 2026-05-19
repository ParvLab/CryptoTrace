use base64::Engine as _;

#[derive(Debug, Clone)]
pub struct EncodingDetection {
    pub encoding_type: String,
    pub confidence: f64,
    pub decoded_preview: Option<Vec<u8>>,
}

/// Detect if input string matches a known encoding format.
pub fn detect_encoding(input: &str) -> Option<EncodingDetection> {
    // Hex first — any hex string is also valid Base64 (alphanumeric charset),
    // so we must check Hex before Base64 to avoid false positives.
    if let Some(result) = detect_hex(input) {
        return Some(result);
    }

    // URL encoding
    if let Some(result) = detect_url_encoding(input) {
        return Some(result);
    }

    // Base32 before Base58 — Base32 has stricter structure (length % 8 == 0,
    // charset A-Z, 2-7, =) so it should be preferred over Base58 when both match.
    if let Some(result) = detect_base32(input) {
        return Some(result);
    }

    // Base64
    if let Some(result) = detect_base64(input) {
        return Some(result);
    }

    // Base58 — checked after Base64 to let padded Base64 strings win.
    // Base58 excludes 0/O/I/l and requires mixed character classes.
    if let Some(result) = detect_base58(input) {
        return Some(result);
    }

    // Base85 (Z85 / Ascii85)
    if let Some(result) = detect_base85(input) {
        return Some(result);
    }

    // Base91
    if let Some(result) = detect_base91(input) {
        return Some(result);
    }

    None
}

fn detect_base64(input: &str) -> Option<EncodingDetection> {
    let charset_ok = input.chars().all(|c| {
        matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '+' | '/' | '=')
    });
    if !charset_ok {
        return None;
    }

    let trimmed = input.trim_end_matches('=');
    let padding_count = input.len() - trimmed.len();
    if padding_count > 2 {
        return None;
    }

    // Require valid base64 length: input without padding must be a valid
    // encoding of whole bytes (no leftover bits).
    let raw_len = trimmed.len();
    if raw_len == 0 {
        return None;
    }
    let valid_length = raw_len % 4 == 0 // no padding, multiple of 4
        || (raw_len % 4 == 2 && padding_count == 2) // 2 padding chars
        || (raw_len % 4 == 3 && padding_count == 1); // 1 padding char
    // raw_len % 4 == 1 is always invalid in base64
    if !valid_length && padding_count == 0 {
        // Without padding, the length must be a multiple of 4
        if raw_len % 4 != 0 {
            return None;
        }
    }

    // Decode attempt
    let decode_ok = base64::engine::general_purpose::STANDARD
        .decode(input)
        .is_ok();

    let openssl_prefix = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(input) {
        decoded.starts_with(b"Salted__")
    } else {
        false
    };

    let charset_score = if charset_ok { 1.0 } else { 0.0 };
    let padding_score = if padding_count <= 2 { 1.0 } else { 0.0 };
    let decode_score = if decode_ok { 1.0 } else { 0.0 };
    let openssl_score = if openssl_prefix { 1.0 } else { 0.0 };

    let confidence: f64 = charset_score * 0.3 + padding_score * 0.2 + decode_score * 0.4 + openssl_score * 0.1;

    if confidence < 0.5 {
        return None;
    }

    let decoded_preview = if decode_ok {
        base64::engine::general_purpose::STANDARD
            .decode(input)
            .ok()
            .map(|v| v.into_iter().take(64).collect())
    } else {
        None
    };

    Some(EncodingDetection {
        encoding_type: "Base64".to_string(),
        confidence: confidence.min(0.99),
        decoded_preview,
    })
}

fn detect_hex(input: &str) -> Option<EncodingDetection> {
    if input.is_empty() || input.len() % 2 != 0 {
        return None;
    }
    if !input.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F')) {
        return None;
    }

    let decoded: Vec<u8> = (0..input.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&input[i..i + 2], 16).ok())
        .collect();

    Some(EncodingDetection {
        encoding_type: "Hex".to_string(),
        confidence: 0.95,
        decoded_preview: Some(decoded.into_iter().take(64).collect()),
    })
}

fn detect_url_encoding(input: &str) -> Option<EncodingDetection> {
    let has_pct = input.contains('%');
    if !has_pct {
        return None;
    }

    let valid_pairs = input
        .as_bytes()
        .windows(3)
        .filter(|w| w[0] == b'%')
        .all(|w| {
            w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit()
        });

    if !valid_pairs {
        return None;
    }

    Some(EncodingDetection {
        encoding_type: "URLEncoding".to_string(),
        confidence: 0.90,
        decoded_preview: None,
    })
}

fn detect_base32(input: &str) -> Option<EncodingDetection> {
    if input.len() % 8 != 0 {
        return None;
    }
    if !input.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7' | '=')) {
        return None;
    }

    Some(EncodingDetection {
        encoding_type: "Base32".to_string(),
        confidence: 0.85,
        decoded_preview: None,
    })
}

fn detect_base58(input: &str) -> Option<EncodingDetection> {
    // Base58 alphabet (Bitcoin): no 0, O, I, l
    let base58_chars = |c: char| {
        matches!(c, '1'..='9' | 'A'..='H' | 'J'..='N' | 'P'..='Z' | 'a'..='k' | 'm'..='z')
    };
    if input.len() < 4 || !input.chars().all(base58_chars) {
        return None;
    }
    // Require at least two character classes (upper, lower, digit) because
    // pure-lowercase strings without 'l' are almost never Base58 in practice.
    let has_upper = input.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = input.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = input.chars().any(|c| c.is_ascii_digit());
    let class_count = [has_upper, has_lower, has_digit].iter().filter(|&&x| x).count();
    if class_count < 2 {
        return None;
    }
    Some(EncodingDetection {
        encoding_type: "Base58".to_string(),
        confidence: 0.85,
        decoded_preview: None,
    })
}

fn detect_base85(input: &str) -> Option<EncodingDetection> {
    // Z85 (ZeroMQ): [0-9a-zA-Z._:+-=^!/*?&<>()[]{}@%$#]
    let z85_chars = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '_' | ':' | '+' | '-' | '=' | '^' | '!' | '/' | '*' | '?' | '&' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '@' | '%' | '$' | '#')
    };
    // Ascii85 (Adobe): starts with ~<, ends with ~>
    if input.starts_with("~<") && input.ends_with("~>") && input.len() > 4 {
        return Some(EncodingDetection {
            encoding_type: "Ascii85".to_string(),
            confidence: 0.95,
            decoded_preview: None,
        });
    }
    // Z85: at least 4 chars, at least one non-alphanumeric Z85 char (to avoid
    // colliding with Base58/Base64 which also match pure alphanumeric strings).
    if input.len() >= 4 && input.chars().all(z85_chars) {
        let has_special = input.chars().any(|c| {
            matches!(c, '.' | '_' | ':' | '+' | '-' | '=' | '^' | '!' | '/' | '*' | '?' | '&' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '@' | '%' | '$' | '#')
        });
        if !has_special {
            return None;
        }
        return Some(EncodingDetection {
            encoding_type: "Z85".to_string(),
            confidence: 0.80,
            decoded_preview: None,
        });
    }
    None
}

fn detect_base91(input: &str) -> Option<EncodingDetection> {
    // Base91 uses all printable ASCII except ' (apostrophe) and - (minus)
    // Most chars in the range 0x21-0x7E except ' and -
    // Require minimum length and a mix of character types to avoid false
    // positives on plain English text (which is mostly lowercase letters).
    if input.len() < 8 {
        return None;
    }
    let is_valid = |c: char| {
        let b = c as u8;
        b >= 0x21 && b <= 0x7E && c != '\'' && c != '-'
    };
    let count_valid = input.chars().filter(|c| is_valid(*c)).count();
    let valid_ratio = count_valid as f64 / input.len() as f64;
    if valid_ratio < 0.95 {
        return None;
    }
    // Require at least some non-alphabetic characters (Base91 encodes binary
    // data so it should have a wide distribution across the charset).
    let non_alpha = input.chars().filter(|c| !c.is_ascii_alphabetic()).count();
    let non_alpha_ratio = non_alpha as f64 / input.len() as f64;
    if non_alpha_ratio < 0.3 {
        return None;
    }
    Some(EncodingDetection {
        encoding_type: "Base91".to_string(),
        confidence: valid_ratio * 0.70 + non_alpha_ratio.min(0.5) * 0.20,
        decoded_preview: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let result = detect_encoding("SGVsbG8gV29ybGQ=").unwrap();
        assert_eq!(result.encoding_type, "Base64");
        assert!(result.confidence >= 0.9);
    }

    #[test]
    fn test_base64_openssl() {
        let data = base64::engine::general_purpose::STANDARD
            .encode(b"Salted__some_encrypted_data");
        let result = detect_encoding(&data).unwrap();
        assert_eq!(result.encoding_type, "Base64");
        assert!(result.confidence > 0.95);
    }

    #[test]
    fn test_hex() {
        let result = detect_encoding("48656c6c6f").unwrap();
        assert_eq!(result.encoding_type, "Hex");
    }

    #[test]
    fn test_url_encoding() {
        let result = detect_encoding("hello%20world%21").unwrap();
        assert_eq!(result.encoding_type, "URLEncoding");
    }

    #[test]
    fn test_base32() {
        let result = detect_encoding("JBSWY3DPEB3W64TMMQ======").unwrap();
        assert_eq!(result.encoding_type, "Base32");
    }

    #[test]
    fn test_base58() {
        let result = detect_encoding("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        assert_eq!(result.encoding_type, "Base58");
    }

    #[test]
    fn test_ascii85() {
        let result = detect_encoding("~<hello~>").unwrap();
        assert_eq!(result.encoding_type, "Ascii85");
    }

    #[test]
    fn test_z85() {
        let result = detect_encoding("abc123.ABC+def$").unwrap();
        assert_eq!(result.encoding_type, "Z85");
    }

    #[test]
    fn test_base91() {
        let result = detect_encoding("!\"#$%&()*+,./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~").unwrap();
        assert_eq!(result.encoding_type, "Base91");
    }

    #[test]
    fn test_invalid() {
        let result = detect_encoding("this is plain text with no encoding");
        assert!(result.is_none());
    }
}

use crate::types::RiskLevel;

#[derive(Debug, Clone)]
pub struct HashDetection {
    pub algorithm: String,
    pub confidence: f64,
    pub risk_level: RiskLevel,
    pub weakness_flags: Vec<String>,
}

/// Detect if input string matches a known hash format.
pub fn detect_hash(input: &str) -> Option<HashDetection> {
    // Try the full string first (trimmed)
    let trimmed = input.trim();
    if let Some(result) = try_detect(trimmed) {
        return Some(result);
    }

    // If no match, split on whitespace and try each token
    for token in trimmed.split_whitespace() {
        if let Some(result) = try_detect(token) {
            return Some(result);
        }
    }

    None
}

fn try_detect(s: &str) -> Option<HashDetection> {
    let len = s.len();
    let is_hex = s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F'));

    if !is_hex && !is_prefix_based(s) {
        return None;
    }

    if is_hex {
        // NTLM must come before MD5 (both are 32 chars; NTLM is always uppercase
        // with at least one uppercase letter to distinguish from pure-digit hashes)
        if len == 32
            && s.chars().any(|c| c.is_ascii_uppercase())
            && s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            return Some(HashDetection {
                algorithm: "NTLM".to_string(),
                confidence: 0.85,
                risk_level: RiskLevel::Critical,
                weakness_flags: vec!["no_salt".to_string(), "no_modern_kdf".to_string()],
            });
        }
        if len == 32 {
            // Could be MD5 or UUID without dashes
            if looks_like_uuid(s) {
                return Some(HashDetection {
                    algorithm: "UUID".to_string(),
                    confidence: 0.70,
                    risk_level: RiskLevel::Low,
                    weakness_flags: vec![],
                });
            }
            return Some(HashDetection {
                algorithm: "MD5".to_string(),
                confidence: 0.95,
                risk_level: RiskLevel::Critical,
                weakness_flags: vec!["collision_vulnerable".to_string(), "rainbow_table_crackable".to_string()],
            });
        }
        if len == 40 {
            return Some(HashDetection {
                algorithm: "SHA1".to_string(),
                confidence: 0.95,
                risk_level: RiskLevel::High,
                weakness_flags: vec!["collision_attacks_demonstrated".to_string()],
            });
        }
        if len == 64 {
            return Some(HashDetection {
                algorithm: "SHA256".to_string(),
                confidence: 0.97,
                risk_level: RiskLevel::Low,
                weakness_flags: vec![],
            });
        }
        if len == 128 {
            return Some(HashDetection {
                algorithm: "SHA512".to_string(),
                confidence: 0.97,
                risk_level: RiskLevel::Low,
                weakness_flags: vec![],
            });
        }
    }

    // Prefix-based KDFs
    detect_prefix_based(s)
}

fn looks_like_uuid(s: &str) -> bool {
    // UUID without dashes: 8-4-4-4-12 pattern
    if s.len() != 32 {
        return false;
    }
    // Check version nibble (13th hex char, index 12, should be 4 for UUIDv4)
    let version_char = s.as_bytes().get(12).copied().unwrap_or(0);
    if version_char != b'4' {
        return false;
    }
    // Check variant nibble (17th hex char, index 16, should be 8/9/a/b)
    let variant_char = s.as_bytes().get(16).copied().unwrap_or(0);
    matches!(variant_char, b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
}

fn is_prefix_based(s: &str) -> bool {
    s.starts_with("$2a$")
        || s.starts_with("$2b$")
        || s.starts_with("$2y$")
        || s.starts_with("$argon2id$")
        || s.starts_with("$argon2i$")
        || s.starts_with("$pbkdf2-")
}

fn detect_prefix_based(s: &str) -> Option<HashDetection> {
    // bcrypt: $2a$/$2b$/$2y$ + cost factor + 53-char hash
    if s.starts_with("$2a$") || s.starts_with("$2b$") || s.starts_with("$2y$") {
        let parts: Vec<&str> = s.split('$').collect();
        if parts.len() >= 4 {
            // Extract cost factor
            let cost_str = parts.get(2).copied().unwrap_or("");
            if let Ok(cost) = cost_str.parse::<u32>() {
                return Some(HashDetection {
                    algorithm: "bcrypt".to_string(),
                    confidence: 0.99,
                    risk_level: if cost >= 12 { RiskLevel::Low } else { RiskLevel::Medium },
                    weakness_flags: if cost < 12 {
                        vec!["insufficient_work_factor".to_string()]
                    } else {
                        vec![]
                    },
                });
            }
            return Some(HashDetection {
                algorithm: "bcrypt".to_string(),
                confidence: 0.95,
                risk_level: RiskLevel::Low,
                weakness_flags: vec![],
            });
        }
    }

    // Argon2id: $argon2id$v=19$m=...,t=...,p=...
    if s.starts_with("$argon2id$") || s.starts_with("$argon2i$") {
        return Some(HashDetection {
            algorithm: if s.starts_with("$argon2id$") {
                "Argon2id".to_string()
            } else {
                "Argon2i".to_string()
            },
            confidence: 0.99,
            risk_level: RiskLevel::Low,
            weakness_flags: vec![],
        });
    }

    // PBKDF2: $pbkdf2-{digest}${iterations}${salt}${hash}
    // e.g. $pbkdf2-sha256$100000$salt$hash
    if s.starts_with("$pbkdf2-") {
        let parts: Vec<&str> = s.split('$').collect();
        // Minimum: $pbkdf2-digest$iterations$salt$hash
        if parts.len() >= 4 {
            let digest = parts.first().and_then(|_| parts.get(1).and_then(|p| {
                // extract digest after "$pbkdf2-"
                let rest = p.strip_prefix("pbkdf2-").unwrap_or("");
                if rest.is_empty() { None } else { Some(rest) }
            }));
            let algo = digest.unwrap_or("unknown");
            let has_iterations = parts.get(2).map(|i| i.parse::<u64>().is_ok()).unwrap_or(false);

            return Some(HashDetection {
                algorithm: format!("PBKDF2-{}", algo.to_uppercase()),
                confidence: if has_iterations { 0.98 } else { 0.90 },
                risk_level: RiskLevel::Low,
                weakness_flags: vec![],
            });
        }
    }

    None
}

/// Compute SHA256 hex digest for deduplication.
pub fn sha256_hex(data: &[u8]) -> String {
    use ring::digest::{Context, SHA256};
    let mut ctx = Context::new(&SHA256);
    ctx.update(data);
    let digest = ctx.finish();
    hex_encode(digest.as_ref())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let result = detect_hash("5f4dcc3b5aa765d61d8327deb882cf99").unwrap();
        assert_eq!(result.algorithm, "MD5");
        assert!((result.confidence - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_sha1() {
        let result = detect_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap();
        assert_eq!(result.algorithm, "SHA1");
    }

    #[test]
    fn test_sha256() {
        let result = detect_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
        assert_eq!(result.algorithm, "SHA256");
    }

    #[test]
    fn test_sha512() {
        let result = detect_hash("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e").unwrap();
        assert_eq!(result.algorithm, "SHA512");
    }

    #[test]
    fn test_bcrypt() {
        let result = detect_hash("$2b$12$LJ3m4ys3Lv4S7K7K7K7K7O").unwrap();
        assert_eq!(result.algorithm, "bcrypt");
    }

    #[test]
    fn test_argon2id() {
        let result = detect_hash("$argon2id$v=19$m=65536,t=3,p=4$...").unwrap();
        assert_eq!(result.algorithm, "Argon2id");
    }

    #[test]
    fn test_uuid_disambiguation() {
        let uuid = "550e8400e29b41d4a716446655440000";
        let result = detect_hash(uuid).unwrap();
        assert_eq!(result.algorithm, "UUID");
    }

    #[test]
    fn test_whitespace_stripping() {
        let input = "da39a3ee5e6b4b0d3255bfef95601890afd80709  filename.txt";
        let result = detect_hash(input).unwrap();
        assert_eq!(result.algorithm, "SHA1");
    }

    #[test]
    fn test_sha256hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
    }

    #[test]
    fn test_ntlm() {
        let result = detect_hash("A0B1C2D3E4F5060708090A0B0C0D0E0F").unwrap();
        assert_eq!(result.algorithm, "NTLM");
    }

    #[test]
    fn test_pbkdf2_sha256() {
        let result = detect_hash("$pbkdf2-sha256$100000$salt$hashvaluehere12345").unwrap();
        assert_eq!(result.algorithm, "PBKDF2-SHA256");
        assert!(result.confidence > 0.95);
    }

    #[test]
    fn test_pbkdf2_sha512() {
        let result = detect_hash("$pbkdf2-sha512$50000$other_salt$abcdefhash").unwrap();
        assert_eq!(result.algorithm, "PBKDF2-SHA512");
    }

    #[test]
    fn test_not_a_hash() {
        let result = detect_hash("this is not a hash");
        assert!(result.is_none());
    }
}

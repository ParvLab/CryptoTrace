use crate::types::RiskLevel;

#[derive(Debug, Clone)]
pub struct EncryptionDetection {
    pub algorithm: String,
    pub confidence: f64,
    pub risk_level: RiskLevel,
}

/// AES-256-CBC via OpenSSL: data starts with "Salted__"
const OPENSSL_AES_PREFIX: &[u8] = b"Salted__";

/// RSA PEM headers
const RSA_PRIVATE_HEADER: &str = "-----BEGIN RSA PRIVATE KEY-----";
const RSA_PUBLIC_HEADER: &str = "-----BEGIN PUBLIC KEY-----";
const RSA_PRIVATE_FOOTER: &str = "-----END RSA PRIVATE KEY-----";
const RSA_PUBLIC_FOOTER: &str = "-----END PUBLIC KEY-----";

/// Detect encryption by checking for known signatures and heuristics.
/// This is NOT decryption — detection only.
pub fn detect_encryption(data: &[u8], entropy: f64) -> Option<EncryptionDetection> {
    // OpenSSL AES detection
    if data.starts_with(OPENSSL_AES_PREFIX) {
        // Salted__ prefix indicates OpenSSL AES-256-CBC
        return Some(EncryptionDetection {
            algorithm: "AES-256-CBC (OpenSSL)".to_string(),
            confidence: 0.90,
            risk_level: RiskLevel::Medium,
        });
    }

    // RSA PEM detection
    let text = String::from_utf8_lossy(data);
    if text.contains(RSA_PRIVATE_HEADER) && text.contains(RSA_PRIVATE_FOOTER) {
        return Some(EncryptionDetection {
            algorithm: "RSA (private key)".to_string(),
            confidence: 0.99,
            risk_level: RiskLevel::Low,
        });
    }
    if text.contains(RSA_PUBLIC_HEADER) && text.contains(RSA_PUBLIC_FOOTER) {
        return Some(EncryptionDetection {
            algorithm: "RSA (public key)".to_string(),
            confidence: 0.99,
            risk_level: RiskLevel::Low,
        });
    }

    // Generic high-entropy detection (possible encryption or compression)
    if entropy > 7.5 {
        let len = data.len();
        // ChaCha20: 64-byte block aligned (typical)
        // Check before AES because 64 also divides 16, but ChaCha20 is 64-block
        if len > 0 && len % 64 == 0 && len % 16 != 0 {
            return Some(EncryptionDetection {
                algorithm: "ChaCha20 (possible)".to_string(),
                confidence: 0.50,
                risk_level: RiskLevel::Unknown,
            });
        }
        // Salsa20: 64-byte blocks with 8-byte nonce prefix
        if len > 8 && len % 64 == 8 {
            return Some(EncryptionDetection {
                algorithm: "Salsa20 (possible)".to_string(),
                confidence: 0.45,
                risk_level: RiskLevel::Unknown,
            });
        }
        // AES: 16-byte block aligned
        let aes_aligned = len % 16 == 0;
        let confidence = if aes_aligned { 0.60 } else { 0.55 };
        return Some(EncryptionDetection {
            algorithm: if aes_aligned {
                "AES (possible)".to_string()
            } else {
                "ChaCha20 (possible)".to_string()
            }
            .to_string(),
            confidence,
            risk_level: RiskLevel::Unknown,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openssl_aes() {
        let data = b"Salted__\x00\x00\x00\x00\x00\x00\x00\x00encrypted_data";
        let result = detect_encryption(data, 7.9).unwrap();
        assert_eq!(result.algorithm, "AES-256-CBC (OpenSSL)");
    }

    #[test]
    fn test_rsa_private() {
        let data = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n";
        let result = detect_encryption(data, 0.0).unwrap();
        assert_eq!(result.algorithm, "RSA (private key)");
    }

    #[test]
    fn test_chacha20_heuristic() {
        // ChaCha20: high entropy, not 16-byte aligned → generic fallback
        let data = vec![0u8; 55]; // 55 bytes, not 16-byte aligned
        let result = detect_encryption(&data, 7.9).unwrap();
        assert_eq!(result.algorithm, "ChaCha20 (possible)");
    }

    #[test]
    fn test_salsa20_heuristic() {
        // Salsa20: 64-byte aligned with trailing 8-byte nonce
        let data = vec![0u8; 72]; // 64 + 8 = 72
        let result = detect_encryption(&data, 7.9).unwrap();
        assert_eq!(result.algorithm, "Salsa20 (possible)");
    }

    #[test]
    fn test_plaintext_no_detection() {
        let result = detect_encryption(b"hello world", 3.0);
        assert!(result.is_none());
    }
}

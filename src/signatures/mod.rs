use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct SignatureRegistry {
    pub version: String,
    pub signatures: Vec<MagicEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MagicEntry {
    pub id: String,
    pub name: String,
    pub magic_bytes: String,
    pub offset: usize,
    pub category: String,
    pub risk_level: String,
    pub notes: Option<String>,
    #[serde(default)]
    pub subtypes: Vec<SubtypeEntry>,
    #[serde(default)]
    pub provenance: Option<Provenance>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubtypeEntry {
    pub id: String,
    pub name: String,
    pub detect: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Provenance {
    pub contributor: Option<String>,
    pub review_status: Option<String>,
    pub review_date: Option<String>,
    pub reviewer: Option<String>,
    pub origin_reference: Option<String>,
}

/// Decode a hex string to bytes (e.g. "1F8B" → [0x1f, 0x8b]).
fn decode_magic(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Match raw bytes against the signature registry.
/// Returns all matching entries (by magic bytes at specified offset).
pub fn match_signatures<'a>(
    data: &'a [u8],
    registry: &'a SignatureRegistry,
) -> Vec<&'a MagicEntry> {
    registry
        .signatures
        .iter()
        .filter(|entry| {
            let magic = match decode_magic(&entry.magic_bytes) {
                Some(m) => m,
                None => return false,
            };
            let offset = entry.offset;
            if offset + magic.len() > data.len() {
                return false;
            }
            data[offset..offset + magic.len()] == magic[..]
        })
        .collect()
}

/// Load the built-in default signature registry (embedded at compile time).
pub fn default_registry() -> std::result::Result<SignatureRegistry, String> {
    let yaml = include_str!("../../signatures/default.yaml");
    serde_yaml::from_str(yaml).map_err(|e| format!("Cannot parse default registry: {}", e))
}

/// Load a signature registry from a file path.
pub fn load_registry(path: &str) -> std::result::Result<SignatureRegistry, String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Cannot read '{}': {}", path, e))?;
    serde_yaml::from_str(&content).map_err(|e| format!("Cannot parse '{}': {}", path, e))
}

/// Look up the risk level for an entry's category.
pub fn category_risk_level(category: &str) -> crate::types::RiskLevel {
    match category {
        "executable" => crate::types::RiskLevel::High,
        "cryptographic" => crate::types::RiskLevel::Critical,
        "compression" => crate::types::RiskLevel::Low,
        "document" => crate::types::RiskLevel::Medium,
        "image" => crate::types::RiskLevel::Low,
        "audio" => crate::types::RiskLevel::Low,
        "video" => crate::types::RiskLevel::Low,
        "archive" => crate::types::RiskLevel::Low,
        "disk" => crate::types::RiskLevel::Low,
        "database" => crate::types::RiskLevel::Low,
        "code" => crate::types::RiskLevel::Medium,
        "font" => crate::types::RiskLevel::Low,
        _ => crate::types::RiskLevel::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_magic() {
        let bytes = decode_magic("1F8B").unwrap();
        assert_eq!(bytes, vec![0x1f, 0x8b]);
    }

    #[test]
    fn test_decode_magic_long() {
        let bytes = decode_magic("25504446").unwrap();
        assert_eq!(bytes, vec![0x25, 0x50, 0x44, 0x46]);
    }

    #[test]
    fn test_decode_magic_odd_length() {
        assert!(decode_magic("1F8").is_none());
    }

    #[test]
    fn test_default_registry_loads() {
        let reg = default_registry().unwrap();
        assert_eq!(reg.version, "1.0.0");
        let count = reg.signatures.len();
        assert!(count >= 100, "Expected 100+ signatures, got {}", count);
        // Verify some expected entries exist
        let ids: Vec<&str> = reg.signatures.iter().map(|e| e.id.as_str()).collect();
        assert!(ids.contains(&"gzip"));
        assert!(ids.contains(&"pdf"));
        assert!(ids.contains(&"png"));
        assert!(ids.contains(&"elf"));
        assert!(ids.contains(&"pe"));
        assert!(ids.contains(&"java_class"));
        assert!(ids.contains(&"sqlite"));
        assert!(ids.contains(&"wasm"));
        // Verify new additions
        assert!(ids.contains(&"heic"), "HEIC should be in registry");
        assert!(ids.contains(&"pcapng"), "PCAPNG should be in registry");
        assert!(ids.contains(&"age"), "age should be in registry");
    }

    #[test]
    fn test_match_gzip() {
        let reg = default_registry().unwrap();
        let data = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03";
        let matches = match_signatures(data, &reg);
        // Multiple entries may match GZIP magic (gzip, gzip_tar, dockertar)
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.id == "gzip"));
    }

    #[test]
    fn test_match_pdf() {
        let reg = default_registry().unwrap();
        let data = b"%PDF-1.4";
        let matches = match_signatures(data, &reg);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.id == "pdf"));
    }

    #[test]
    fn test_match_png() {
        let reg = default_registry().unwrap();
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let matches = match_signatures(data, &reg);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.id == "png"));
    }

    #[test]
    fn test_match_elf() {
        let reg = default_registry().unwrap();
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let matches = match_signatures(data, &reg);
        // ELF magic matches elf, elf_s390, elf_core
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.id == "elf"));
    }

    #[test]
    fn test_match_pe() {
        let reg = default_registry().unwrap();
        let data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00";
        let matches = match_signatures(data, &reg);
        // MZ magic matches pe, pe32, msdos_stub
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.id == "pe"));
    }

    #[test]
    fn test_match_no_hit() {
        let reg = default_registry().unwrap();
        let data = b"hello world plaintext";
        let matches = match_signatures(data, &reg);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_category_risk_mapping() {
        assert_eq!(
            category_risk_level("executable"),
            crate::types::RiskLevel::High
        );
        assert_eq!(
            category_risk_level("cryptographic"),
            crate::types::RiskLevel::Critical
        );
        assert_eq!(
            category_risk_level("compression"),
            crate::types::RiskLevel::Low
        );
    }
}

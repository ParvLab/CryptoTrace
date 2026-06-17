use crate::signatures::{MagicEntry, SubtypeEntry};

/// Inferred hierarchical format type.
#[derive(Debug, Clone)]
pub enum FormatHierarchy {
    Simple(String),
    Nested {
        category: String,
        format: String,
        subtype: Option<String>,
        detail: Option<String>,
    },
}

/// Infer hierarchical format from magic signature match + content analysis.
/// Returns a formatted string like "Archive > ZIP > Office Open XML > Word (.docx)"
/// or "Executable > PE > Subsystem > GUI".
pub fn infer_format_hierarchy(entry: &MagicEntry, data: &[u8]) -> FormatHierarchy {
    // Check subtypes if available
    if !entry.subtypes.is_empty() {
        let subtype = detect_subtype(entry, data);
        if let Some(sub) = subtype {
            return FormatHierarchy::Nested {
                category: entry.category.clone(),
                format: entry.name.clone(),
                subtype: Some(sub.name.clone()),
                detail: Some(sub.id.clone()),
            };
        }
    }

    // PE subsystem inference
    if entry.id == "pe" {
        if let Some(subsystem) = detect_pe_subsystem(data) {
            return FormatHierarchy::Nested {
                category: entry.category.clone(),
                format: entry.name.clone(),
                subtype: Some(subsystem),
                detail: None,
            };
        }
    }

    // GPG key type inference
    if entry.id == "gpg_key" {
        if let Some(key_type) = detect_gpg_key_type(data) {
            return FormatHierarchy::Nested {
                category: entry.category.clone(),
                format: entry.name.clone(),
                subtype: Some(key_type),
                detail: None,
            };
        }
    }

    FormatHierarchy::Simple(entry.name.clone())
}

/// Render the hierarchy as a tree-like string.
pub fn format_tree_string(hierarchy: &FormatHierarchy) -> String {
    match hierarchy {
        FormatHierarchy::Simple(name) => name.clone(),
        FormatHierarchy::Nested { category, format, subtype, detail } => {
            let mut parts = vec![category.clone(), format.clone()];
            if let Some(sub) = subtype {
                parts.push(sub.clone());
            }
            if let Some(det) = detail {
                parts.push(det.clone());
            }
            parts.join(" > ")
        }
    }
}

/// Detect ZIP subtype by looking for characteristic files.
fn detect_subtype<'a>(entry: &'a MagicEntry, data: &[u8]) -> Option<&'a SubtypeEntry> {
    let text = String::from_utf8_lossy(data);
    for sub in &entry.subtypes {
        if text.contains(&sub.detect) {
            return Some(sub);
        }
    }
    None
}

/// PE subsystem detection from the optional header.
/// Subsystem field is at offset 0x5C (PE32) or 0x5E (PE32+) from the start
/// of the PE header, which is at offset e_lfanew in the DOS header.
pub fn detect_pe_subsystem(data: &[u8]) -> Option<String> {
    if data.len() < 0x40 + 4 {
        return None;
    }
    // Read e_lfanew at offset 0x3C (4 bytes, little-endian)
    let e_lfanew = u32::from_le_bytes([
        data[0x3C],
        data[0x3D],
        data[0x3E],
        data[0x3F],
    ]) as usize;

    if e_lfanew + 0x5C + 2 > data.len() {
        return None;
    }

    // Check PE signature
    if data[e_lfanew..e_lfanew + 4] != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }

    // Determine if PE32 or PE32+ from Magic field in optional header
    let magic_offset = e_lfanew + 0x18; // offset to Magic in optional header
    if magic_offset + 2 > data.len() {
        return None;
    }
    let magic = u16::from_le_bytes([data[magic_offset], data[magic_offset + 1]]);
    let subsystem_offset = if magic == 0x10B {
        // PE32: subsystem at offset 0x44 from optional header start
        e_lfanew + 0x18 + 0x44
    } else if magic == 0x20B {
        // PE32+: subsystem at offset 0x44 from optional header start
        e_lfanew + 0x18 + 0x44
    } else {
        return None;
    };

    if subsystem_offset + 2 > data.len() {
        return None;
    }
    let subsystem = u16::from_le_bytes([
        data[subsystem_offset],
        data[subsystem_offset + 1],
    ]);

    Some(match subsystem {
        1 => "Native (Driver)".to_string(),
        2 => "GUI Application".to_string(),
        3 => "Console Application".to_string(),
        7 => "POSIX Subsystem".to_string(),
        0x10 => "EFI Application".to_string(),
        0x11 => "EFI Boot Service Driver".to_string(),
        0x12 => "EFI Runtime Driver".to_string(),
        _ => format!("Unknown (subsystem {})", subsystem),
    })
}

/// Detect GPG key packet type from binary key data.
/// GPG packet tag is the first byte: bits 7-6 are CTB, bits 5-0 are tag.
pub fn detect_gpg_key_type(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0] & 0x3F;
    Some(match tag {
        5 => "Secret Key".to_string(),
        6 => "Public Key".to_string(),
        7 => "Secret Subkey".to_string(),
        13 => "User ID".to_string(),
        14 => "Public Subkey".to_string(),
        _ => format!("Packet type {}", tag),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::MagicEntry;

    fn make_zip_entry() -> MagicEntry {
        MagicEntry {
            id: "zip".to_string(),
            name: "ZIP Archive".to_string(),
            magic_bytes: "504B0304".to_string(),
            offset: 0,
            category: "compression".to_string(),
            risk_level: "LOW".to_string(),
            notes: None,
            subtypes: vec![
                crate::signatures::SubtypeEntry {
                    id: "zip_docx".to_string(),
                    name: "Office Open XML Document (DOCX)".to_string(),
                    detect: "[Content_Types].xml".to_string(),
                },
            ],
            provenance: None,
        }
    }

    #[test]
    fn test_docx_subtype_detected() {
        let entry = make_zip_entry();
        let data = b"PK\x03\x04... [Content_Types].xml ...";
        let hierarchy = infer_format_hierarchy(&entry, data);
        let tree = format_tree_string(&hierarchy);
        assert!(tree.contains("Office Open XML Document"));
    }

    #[test]
    fn test_zip_no_subtype() {
        let entry = make_zip_entry();
        let data = b"PK\x03\x04... plain files ...";
        let hierarchy = infer_format_hierarchy(&entry, data);
        let tree = format_tree_string(&hierarchy);
        assert_eq!(tree, "ZIP Archive");
    }

    #[test]
    fn test_pe_subsystem_gui() {
        // Minimal DOS header + PE signature + optional header indicating GUI
        let mut data = vec![0u8; 0x100];
        data[0] = b'M'; data[1] = b'Z';
        data[0x3C] = 0x40; // e_lfanew = 0x40

        // PE signature at 0x40
        data[0x40..0x44].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);

        // PE optional header magic at 0x40 + 0x18 = 0x58
        data[0x58] = 0x0B; data[0x59] = 0x01; // PE32 magic (0x010B)

        // Subsystem at offset 0x40 + 0x18 + 0x44 = 0x9C
        data[0x9C] = 2; data[0x9D] = 0; // GUI subsystem

        let result = detect_pe_subsystem(&data);
        assert_eq!(result, Some("GUI Application".to_string()));
    }

    #[test]
    fn test_pe_no_signature() {
        let data = b"no MZ header here";
        assert!(detect_pe_subsystem(data).is_none());
    }

    #[test]
    fn test_gpg_packet_type() {
        // Public key packet: tag 6
        let data = vec![0x06];
        let result = detect_gpg_key_type(&data);
        assert_eq!(result, Some("Public Key".to_string()));
    }
}

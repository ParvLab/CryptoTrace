use crate::error::{CryptoTraceError, Result};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Manages signature database updates, rollback, air-gap import, and
/// cryptographic verification of update packages.
pub struct UpdateManager {
    registry_path: PathBuf,
    backup_path: PathBuf,
    provenance_path: PathBuf,
    public_key_path: Option<PathBuf>,
}

/// A single entry in the update provenance log.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceEntry {
    pub timestamp: String,
    pub action: String,
    pub version: String,
    pub fingerprint: Option<String>,
    pub verified: bool,
}

impl UpdateManager {
    pub const REGISTRY_FILE: &'static str = "default.yaml";
    pub const PROVENANCE_FILE: &'static str = "provenance.jsonl";

    pub fn new(registry_dir: &Path) -> Self {
        let registry_path = registry_dir.join(Self::REGISTRY_FILE);
        let backup_path = registry_dir.join("backup.yaml");
        let provenance_path = registry_dir.join(Self::PROVENANCE_FILE);
        Self {
            registry_path,
            backup_path,
            provenance_path,
            public_key_path: None,
        }
    }

    /// Set the path to a trusted Ed25519 public key for signature verification.
    pub fn set_public_key_path(&mut self, path: &Path) {
        self.public_key_path = Some(path.to_path_buf());
    }

    pub fn check_for_updates(&self) -> Result<String> {
        let content = std::fs::read_to_string(&self.registry_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot read registry: {}", e)))?;
        let parsed: serde_yaml::Value = serde_yaml::from_str(&content)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot parse registry: {}", e)))?;
        let version = parsed
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        Ok(version)
    }

    pub fn apply_update(&self, new_registry_path: &Path) -> Result<()> {
        if self.registry_path.exists() {
            std::fs::copy(&self.registry_path, &self.backup_path)
                .map_err(|e| CryptoTraceError::Other(format!("Cannot create backup: {}", e)))?;
        }

        if let Some(parent) = self.registry_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CryptoTraceError::Other(format!("Cannot create registry dir: {}", e))
            })?;
        }

        let content = std::fs::read_to_string(new_registry_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot read new registry: {}", e)))?;
        let registry: crate::signatures::SignatureRegistry = serde_yaml::from_str(&content)
            .map_err(|e| CryptoTraceError::Other(format!("Invalid registry format: {}", e)))?;

        if registry.signatures.is_empty() {
            return Err(CryptoTraceError::Other(
                "Refusing to apply empty signature registry".to_string(),
            ));
        }

        std::fs::copy(new_registry_path, &self.registry_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot install new registry: {}", e)))?;

        tracing::info!(
            "Signature database updated to version {} ({} entries)",
            registry.version,
            registry.signatures.len()
        );

        Ok(())
    }

    /// Apply an update with GPG/Ed25519 signature verification.
    /// `signature_path` should be a detached Ed25519 signature file (raw 64-byte)
    /// or a GPG detached signature (`.sig`/`.asc`).
    pub fn apply_verified_update(
        &self,
        new_registry_path: &Path,
        signature_path: &Path,
    ) -> Result<()> {
        let public_key = self.load_public_key()?;
        let verified = self.verify_detached(new_registry_path, signature_path, &public_key)?;
        if !verified {
            return Err(CryptoTraceError::Other(
                "Signature verification failed — update rejected".to_string(),
            ));
        }
        self.apply_update(new_registry_path)?;

        let version = self.current_version();
        self.log_provenance("apply_verified", &version, Some("ed25519"));
        Ok(())
    }

    /// Verify a detached Ed25519 signature on a file using the ring crate.
    /// `signature_path` must contain the raw 64-byte Ed25519 signature.
    pub fn verify_detached(
        &self,
        data_path: &Path,
        signature_path: &Path,
        public_key: &[u8],
    ) -> Result<bool> {
        // First, try ring-based Ed25519 verification
        if let Ok(result) = self.verify_ed25519(data_path, signature_path, public_key) {
            return Ok(result);
        }

        // Fall back to shelling out to `gpg` if GPG is available
        self.verify_gpg(data_path, signature_path)
    }

    fn verify_ed25519(
        &self,
        data_path: &Path,
        signature_path: &Path,
        public_key: &[u8],
    ) -> Result<bool> {
        use ring::signature;

        let data = std::fs::read(data_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot read data file: {}", e)))?;
        let sig_bytes = std::fs::read(signature_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot read signature file: {}", e)))?;

        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
        match public_key.verify(&data, &sig_bytes) {
            Ok(()) => {
                tracing::info!("Ed25519 signature verified for {:?}", data_path);
                Ok(true)
            }
            Err(_) => Ok(false),
        }
    }

    fn verify_gpg(&self, data_path: &Path, signature_path: &Path) -> Result<bool> {
        let output = std::process::Command::new("gpg")
            .arg("--verify")
            .arg(signature_path)
            .arg(data_path)
            .output();

        match output {
            Ok(out) => {
                if out.status.success() {
                    tracing::info!("GPG signature verified for {:?}", data_path);
                    Ok(true)
                } else {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!("GPG verification failed: {}", stderr);
                    Ok(false)
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Err(CryptoTraceError::Other(
                        "GPG not found on system and Ed25519 verification failed".to_string(),
                    ));
                }
                Err(CryptoTraceError::Other(format!(
                    "GPG execution error: {}",
                    e
                )))
            }
        }
    }

    /// Load the trusted Ed25519 public key from the configured path.
    fn load_public_key(&self) -> Result<Vec<u8>> {
        let path = self.public_key_path.as_ref().ok_or_else(|| {
            CryptoTraceError::Other("No public key configured for verification".to_string())
        })?;

        let data = std::fs::read(path).map_err(|e| {
            CryptoTraceError::Other(format!(
                "Cannot read public key '{}': {}",
                path.display(),
                e
            ))
        })?;

        Ok(data)
    }

    /// Append an entry to the provenance log (JSON-lines format).
    pub fn log_provenance(&self, action: &str, version: &str, fingerprint: Option<&str>) {
        let timestamp = unix_timestamp();
        let entry = ProvenanceEntry {
            timestamp,
            action: action.to_string(),
            version: version.to_string(),
            fingerprint: fingerprint.map(|s| s.to_string()),
            verified: fingerprint.is_some(),
        };

        if let Ok(json) = serde_json::to_string(&entry) {
            if let Some(parent) = self.provenance_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.provenance_path);
            if let Ok(ref mut f) = file {
                use std::io::Write;
                let _ = writeln!(f, "{}", json);
            }
        }
    }

    /// Read the full provenance log.
    pub fn read_provenance(&self) -> Vec<ProvenanceEntry> {
        let content = match std::fs::read_to_string(&self.provenance_path) {
            Ok(c) => c,
            Err(_) => return vec![],
        };

        content
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    pub fn rollback(&self) -> Result<()> {
        if !self.backup_path.exists() {
            return Err(CryptoTraceError::Other(
                "No backup available for rollback".to_string(),
            ));
        }

        std::fs::copy(&self.backup_path, &self.registry_path)
            .map_err(|e| CryptoTraceError::Other(format!("Cannot restore backup: {}", e)))?;

        let version = self.current_version();
        self.log_provenance("rollback", &version, None);

        tracing::info!("Signature database rolled back to previous version");
        Ok(())
    }

    /// Import a signature update from a local file (air-gap mode).
    /// Optionally verifies a detached signature.
    pub fn import_local(&self, path: &Path, signature_path: Option<&Path>) -> Result<()> {
        if let Some(sig) = signature_path {
            self.apply_verified_update(path, sig)
        } else {
            self.apply_update(path)?;
            let version = self.current_version();
            self.log_provenance("import_local", &version, None);
            Ok(())
        }
    }

    pub fn current_version(&self) -> String {
        if !self.registry_path.exists() {
            return "0.0.0".to_string();
        }
        match std::fs::read_to_string(&self.registry_path) {
            Ok(content) => {
                let parsed: std::result::Result<serde_yaml::Value, _> =
                    serde_yaml::from_str(&content);
                match parsed {
                    Ok(v) => v
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("0.0.0")
                        .to_string(),
                    Err(_) => "0.0.0".to_string(),
                }
            }
            Err(_) => "0.0.0".to_string(),
        }
    }
}

fn unix_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| format!("{}.{:03}", d.as_secs(), d.subsec_millis()))
        .unwrap_or_else(|_| "0.000".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_current_version_default() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());
        assert_eq!(mgr.current_version(), "0.0.0");
    }

    #[test]
    fn test_check_updates_after_install() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());

        let registry_content = r#"
version: "1.0.0"
signatures:
  - id: test
    name: Test Entry
    magic_bytes: "00"
    offset: 0
    category: test
    risk_level: LOW
"#;
        let reg_path = dir.path().join("default.yaml");
        std::fs::write(&reg_path, registry_content).unwrap();

        let version = mgr.check_for_updates().unwrap();
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn test_apply_update_and_rollback() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());

        let first = r#"
version: "1.0.0"
signatures:
  - id: a
    name: A
    magic_bytes: "00"
    offset: 0
    category: test
    risk_level: LOW
"#;
        let path_a = dir.path().join("reg_a.yaml");
        std::fs::write(&path_a, first).unwrap();
        mgr.apply_update(&path_a).unwrap();
        assert_eq!(mgr.current_version(), "1.0.0");

        let second = r#"
version: "2.0.0"
signatures:
  - id: b
    name: B
    magic_bytes: "01"
    offset: 0
    category: test
    risk_level: LOW
"#;
        let path_b = dir.path().join("reg_b.yaml");
        std::fs::write(&path_b, second).unwrap();
        mgr.apply_update(&path_b).unwrap();
        assert_eq!(mgr.current_version(), "2.0.0");
        assert!(mgr.backup_path.exists());

        mgr.rollback().unwrap();
        assert_eq!(mgr.current_version(), "1.0.0");
    }

    #[test]
    fn test_reject_empty_registry() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());

        let empty = r#"
version: "1.0.0"
signatures: []
"#;
        let path = dir.path().join("empty.yaml");
        std::fs::write(&path, empty).unwrap();
        assert!(mgr.apply_update(&path).is_err());
    }

    #[test]
    fn test_ed25519_verify_roundtrip() {
        use ring::signature;
        use ring::signature::KeyPair;

        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());

        // Generate an Ed25519 key pair
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        // Sign a test message
        let data = b"test update data for signature verification";
        let data_path = dir.path().join("update.yaml");
        std::fs::write(&data_path, data).unwrap();

        let sig = key_pair.sign(data);
        let sig_path = dir.path().join("update.sig");
        std::fs::write(&sig_path, sig.as_ref()).unwrap();

        // Verify using the public key
        let public_key = key_pair.public_key();
        let result = mgr
            .verify_detached(&data_path, &sig_path, public_key.as_ref())
            .unwrap();
        assert!(result);

        // Tampered data should fail
        let tampered_path = dir.path().join("tampered.yaml");
        std::fs::write(&tampered_path, b"tampered data").unwrap();
        let result2 = mgr
            .verify_detached(&tampered_path, &sig_path, public_key.as_ref())
            .unwrap();
        assert!(!result2);
    }

    #[test]
    fn test_provenance_log() {
        let dir = TempDir::new().unwrap();
        let mgr = UpdateManager::new(dir.path());

        mgr.log_provenance("apply", "1.0.0", Some("abc123"));
        mgr.log_provenance("rollback", "0.9.0", None);

        let log = mgr.read_provenance();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].action, "apply");
        assert_eq!(log[0].version, "1.0.0");
        assert_eq!(log[1].action, "rollback");
        assert_eq!(log[1].version, "0.9.0");
    }

    #[test]
    fn test_import_local_with_signature() {
        use ring::signature;
        use ring::signature::KeyPair;

        let dir = TempDir::new().unwrap();
        let mut mgr = UpdateManager::new(dir.path());

        // Set up public key
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = key_pair.public_key();

        let pubkey_path = dir.path().join("pubkey.bin");
        std::fs::write(&pubkey_path, public_key.as_ref()).unwrap();
        mgr.set_public_key_path(&pubkey_path);

        // Create signed update
        let update_content = r#"
version: "2.0.0"
signatures:
  - id: signed
    name: Signed Entry
    magic_bytes: "AABB"
    offset: 0
    category: test
    risk_level: LOW
"#;
        let update_path = dir.path().join("signed_update.yaml");
        std::fs::write(&update_path, update_content).unwrap();

        let sig = key_pair.sign(update_content.as_bytes());
        let sig_path = dir.path().join("signed_update.sig");
        std::fs::write(&sig_path, sig.as_ref()).unwrap();

        // Apply verified update
        mgr.apply_verified_update(&update_path, &sig_path).unwrap();
        assert_eq!(mgr.current_version(), "2.0.0");
    }
}

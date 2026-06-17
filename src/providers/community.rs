use crate::error::{CryptoTraceError, Result};
use std::path::{Path, PathBuf};

/// A community-contributed signature provider entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommunityProvider {
    pub id: String,
    pub name: String,
    pub description: String,
    pub url: String,
    pub signature_path: String,
    pub version: String,
    pub trust_level: String,
    pub maintainer: String,
    pub signature_fingerprint: Option<String>,
    pub entries: u32,
    pub categories: Vec<String>,
    pub last_updated: String,
    pub homepage: Option<String>,
}

/// The registry of all community providers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CommunityRegistry {
    pub version: String,
    pub description: String,
    pub providers: Vec<CommunityProvider>,
}

impl CommunityRegistry {
    /// Load the registry from its default path (`docs/community-providers.json`).
    pub fn load_default() -> Result<Self> {
        Self::from_file(Path::new("docs/community-providers.json"))
    }

    /// Load a registry from a specific JSON file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            CryptoTraceError::Other(format!(
                "Cannot read community registry at '{}': {}",
                path.display(),
                e
            ))
        })?;

        let registry: Self = serde_json::from_str(&content).map_err(|e| {
            CryptoTraceError::Other(format!("Invalid community registry JSON: {}", e))
        })?;

        if registry.providers.is_empty() {
            return Err(CryptoTraceError::Other(
                "Community registry contains no providers".to_string(),
            ));
        }

        Ok(registry)
    }

    /// Find a provider by its ID.
    pub fn get(&self, id: &str) -> Option<&CommunityProvider> {
        self.providers.iter().find(|p| p.id == id)
    }

    /// Return providers filtered by trust level.
    pub fn by_trust_level(&self, level: &str) -> Vec<&CommunityProvider> {
        self.providers
            .iter()
            .filter(|p| p.trust_level == level)
            .collect()
    }

    /// Return providers matching any of the given categories.
    pub fn by_categories(&self, categories: &[&str]) -> Vec<&CommunityProvider> {
        self.providers
            .iter()
            .filter(|p| {
                p.categories
                    .iter()
                    .any(|c| categories.contains(&c.as_str()))
            })
            .collect()
    }

    /// Ensure the local signature path for a provider exists.
    /// Returns the full path to the local signature file.
    pub fn resolve_local_path(&self, provider: &CommunityProvider) -> PathBuf {
        Path::new("signatures")
            .join("community")
            .join(&provider.signature_path)
    }
}

/// Load a community provider's signature file, downloading it if necessary.
pub async fn load_community_signatures(provider: &CommunityProvider) -> Result<Vec<u8>> {
    let local_path = Path::new("signatures")
        .join("community")
        .join(&provider.signature_path);

    // If the local file exists, load it
    if local_path.exists() {
        return std::fs::read(&local_path).map_err(|e| {
            CryptoTraceError::Other(format!("Cannot read local signature file: {}", e))
        });
    }

    // Otherwise, download from the provider's URL
    download_provider_signatures(provider).await
}

/// Download a community provider's signature file from its URL.
async fn download_provider_signatures(provider: &CommunityProvider) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| CryptoTraceError::Other(format!("HTTP client error: {}", e)))?;

    let resp = client.get(&provider.url).send().await.map_err(|e| {
        CryptoTraceError::Other(format!("Download failed for '{}': {}", provider.id, e))
    })?;

    if !resp.status().is_success() {
        return Err(CryptoTraceError::Other(format!(
            "Download failed for '{}': HTTP {}",
            provider.id,
            resp.status()
        )));
    }

    let data = resp
        .bytes()
        .await
        .map_err(|e| CryptoTraceError::Other(format!("Download read error: {}", e)))?;

    // Ensure the target directory exists
    let local_path = Path::new("signatures")
        .join("community")
        .join(&provider.signature_path);
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CryptoTraceError::Other(format!(
                "Cannot create directory '{}': {}",
                parent.display(),
                e
            ))
        })?;
    }

    // Cache the downloaded file locally
    std::fs::write(&local_path, &data)
        .map_err(|e| CryptoTraceError::Other(format!("Cannot cache signature file: {}", e)))?;

    tracing::info!(
        "Downloaded community provider '{}' ({} bytes)",
        provider.id,
        data.len()
    );

    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_default_registry() {
        let registry = CommunityRegistry::load_default().unwrap();
        assert!(!registry.providers.is_empty());
        assert_eq!(registry.version, "1.0.0");
    }

    #[test]
    fn test_get_provider() {
        let registry = CommunityRegistry::load_default().unwrap();
        let provider = registry.get("yara-forge").unwrap();
        assert_eq!(provider.name, "YARA-Forge Community Rules");
        assert_eq!(provider.trust_level, "verified");
    }

    #[test]
    fn test_by_trust_level() {
        let registry = CommunityRegistry::load_default().unwrap();
        let verified = registry.by_trust_level("verified");
        assert!(!verified.is_empty());
        assert!(verified.iter().all(|p| p.trust_level == "verified"));
    }

    #[test]
    fn test_by_categories() {
        let registry = CommunityRegistry::load_default().unwrap();
        let malware_sigs = registry.by_categories(&["malware"]);
        assert!(!malware_sigs.is_empty());
    }

    #[test]
    fn test_resolve_local_path() {
        let registry = CommunityRegistry::load_default().unwrap();
        let provider = registry.get("yara-forge").unwrap();
        let path = registry.resolve_local_path(provider);
        assert!(path.to_string_lossy().contains("yara-forge.yaml"));
    }

    #[test]
    fn test_invalid_path_fails() {
        let result = CommunityRegistry::from_file(Path::new("/nonexistent/path.json"));
        assert!(result.is_err());
    }
}

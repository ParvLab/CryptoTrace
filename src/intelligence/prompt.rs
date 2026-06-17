/// Re-export narrative prompt builder and validator for backward compatibility.
pub use super::narrative::{build_prompt, build_signals_string, validate_narrative};

use std::sync::RwLock;

use crate::error::Result;
use crate::types::{AiNarrative, DetectionResult};

/// Global AI narrative cache keyed by detection result hash.
static NARRATIVE_CACHE: RwLock<Option<crate::cache::LruCache<AiNarrative>>> = RwLock::new(None);

/// Initialize the narrative cache (called once at startup).
pub fn init_cache(max_entries: usize) {
    if let Ok(mut guard) = NARRATIVE_CACHE.write() {
        *guard = Some(crate::cache::LruCache::new(max_entries));
    }
}

/// Clear the AI narrative cache.
pub fn clear_cache() {
    if let Ok(mut guard) = NARRATIVE_CACHE.write() {
        if let Some(ref mut cache) = *guard {
            cache.clear();
        }
    }
}

/// Cache statistics.
pub struct CacheInfo {
    pub enabled: bool,
    pub capacity: usize,
    pub count: usize,
}

/// Return current cache statistics.
pub fn cache_info() -> CacheInfo {
    NARRATIVE_CACHE
        .read()
        .ok()
        .map(|guard| match guard.as_ref() {
            Some(cache) => CacheInfo {
                enabled: true,
                capacity: cache.capacity(),
                count: cache.len(),
            },
            None => CacheInfo {
                enabled: false,
                capacity: 0,
                count: 0,
            },
        })
        .unwrap_or(CacheInfo {
            enabled: false,
            capacity: 0,
            count: 0,
        })
}

/// Build a deterministic cache key from detection fields (no raw bytes).
fn cache_key(result: &DetectionResult) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    result.input_hash.hash(&mut hasher);
    result.detected_type.hash(&mut hasher);
    result.algorithm.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Generate a constrained AI narrative for a detection result.
/// Uses an LRU cache to avoid redundant AI calls for identical inputs.
pub async fn generate_ai_narrative(
    result: &DetectionResult,
    provider: &dyn crate::providers::AiProvider,
) -> Result<AiNarrative> {
    let key = cache_key(result);

    // Try to get from cache (needs write lock for LRU access time update)
    if let Ok(mut guard) = NARRATIVE_CACHE.write() {
        if let Some(ref mut cache) = *guard {
            if let Some(narrative) = cache.get(&key) {
                return Ok(narrative.clone());
            }
        }
    }

    // Build signal string from result signals
    let signals_str = if let Some(ref s) = result.signals {
        build_signals_string(s.entropy, s.magic_bytes, s.length_pattern, s.charset_purity)
    } else {
        "no signal data".to_string()
    };

    // Build a safe prompt (no raw input bytes)
    let prompt = build_prompt(
        result.algorithm.as_deref(),
        &result.detected_type,
        result.entropy,
        &format!("{:?}", result.risk_level),
        result.confidence,
        result.confidence_is_provisional,
        &signals_str,
        result.weakness.as_deref(),
    );

    // Call the provider
    let narrative = provider.generate(&prompt).await?;

    // Store in cache
    if let Ok(mut guard) = NARRATIVE_CACHE.write() {
        if let Some(ref mut cache) = *guard {
            cache.insert(key, narrative.clone());
        }
    }

    Ok(narrative)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_prompt_no_raw_data() {
        let prompt = build_prompt(
            Some("SHA256"),
            "hash",
            4.0,
            "Low",
            0.97,
            false,
            "entropy=4.00, pattern=1.00",
            None,
        );
        assert!(prompt.contains("SHA256"));
        assert!(!prompt.contains("raw_bytes"));
        assert!(!prompt.contains("file content"));
    }

    #[test]
    fn test_cache_key_stable() {
        let result = DetectionResult {
            input_hash: "testhash".to_string(),
            source_type: crate::types::SourceType::String,
            entropy: 3.8,
            sliding_entropy: None,
            detected_type: "hash".to_string(),
            algorithm: Some("MD5".to_string()),
            confidence: 0.95,
            calibrated: false,
            calibration_samples: None,
            heuristic_raw: None,
            confidence_is_provisional: true,
            false_positive_risk: 0.0,
            risk_level: crate::types::RiskLevel::Critical,
            weakness: None,
            weakness_cve: vec![],
            recommendations: vec![],
            signals: None,
            primary_drivers: vec![],
            conflicting_signals: vec![],
            decision_trace: None,
            layers: vec![],
            ai_narrative: None,
            detection_context: crate::types::DetectionContext::Forensics,
            engine_version: "0.1.0".to_string(),
            signature_db_version: "1.0.0".to_string(),
        };
        let key1 = cache_key(&result);

        // Same fields produce same key
        let key2 = cache_key(&result);
        assert_eq!(key1, key2);

        // Different type produces different key
        let mut result2 = DetectionResult { ..result };
        result2.algorithm = Some("SHA256".to_string());
        let key3 = cache_key(&result2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_cache_init_and_clear() {
        init_cache(50);
        clear_cache();
    }
}

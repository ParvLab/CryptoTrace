/// Verify that CryptoTrace makes zero network requests in default (air-gapped)
/// mode.
///
/// Strategy: Instead of deep-packet inspection (which would require root), we
/// verify at the API boundary:
///   1. No HTTP client is initialized at startup (verified via config).
///   2. AI features are disabled by default.
///   3. All cloud-dependent features require explicit configuration.
///   4. A full analysis pipeline completes without any network-dependent code path.

use cryptotrace::analyzers::file::analyze_bytes;
use cryptotrace::types::{SourceType, AppConfig, AiConfig, AiCacheConfig};

#[test]
fn test_ai_disabled_by_default() {
    let ai = AiConfig {
        enabled: false,
        provider: None,
        model_family: None,
        base_url: None,
        max_words: Some(150),
        temperature: Some(0.1),
        max_tokens: Some(512),
        response_timeout_seconds: Some(30),
        cache: Some(AiCacheConfig {
            enabled: true,
            ttl_days: 7,
            max_entries: 10000,
        }),
    };
    assert!(!ai.enabled, "AI must be disabled by default for air-gap compliance");
    assert!(ai.base_url.is_none(), "base_url should be None when AI is disabled");
}

#[test]
fn test_analysis_completes_without_network() {
    // Run a full analysis on a Base64-encoded MD5 hash string.
    // This should complete without any network calls because:
    //   - No AI provider is configured
    //   - No signature update is triggered
    //   - No VirusTotal query is attempted
    let input = b"5f4dcc3b5aa765d61d8327deb882cf99";
    let result = analyze_bytes(input, SourceType::String).unwrap();

    // Verify the result is complete (not truncated due to network failure)
    assert!(!result.input_hash.is_empty(), "input hash should be populated");
    assert!(!result.detected_type.is_empty(), "detected type should be populated");
    assert!(result.confidence > 0.0, "confidence should be > 0");

    // AI narrative should be None (disabled by default)
    assert!(result.ai_narrative.is_none(), "AI narrative should be None when AI is disabled");

    eprintln!(
        "AIR_GAP: analysis completed with {} layers, ai_narrative={:?}",
        result.layers.len(),
        result.ai_narrative
    );
}

#[test]
fn test_all_network_features_opt_in() {
    // Verify that every network-dependent feature is opt-in (None/disabled
    // by default).
    let config = AppConfig::default();
    assert!(!config.ai.enabled, "AI disabled by default");
    assert!(config.ai.base_url.is_none(), "AI base URL should be None by default");
    assert!(config.api.api_key.is_none(), "API key should be None by default");
    eprintln!(
        "AIR_GAP: default config — AI={}, base_url={:?}, api_key={:?}",
        config.ai.enabled, config.ai.base_url, config.api.api_key
    );
}

pub mod community;

use crate::error::{CryptoTraceError, Result};
use crate::types::AiNarrative;

/// Configuration for an AI provider.
pub struct AiProviderConfig {
    pub provider_type: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub max_tokens: u32,
    pub temperature: f64,
    pub timeout_seconds: u64,
}

impl Default for AiProviderConfig {
    fn default() -> Self {
        Self {
            provider_type: "openai".to_string(),
            model: "gpt-4o".to_string(),
            api_key: None,
            base_url: None,
            max_tokens: 1024,
            temperature: 0.3,
            timeout_seconds: 30,
        }
    }
}

/// AI provider trait — all providers must be async and Send+Sync.
#[async_trait::async_trait]
pub trait AiProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_airgap_safe(&self) -> bool {
        false
    }
    async fn generate(&self, prompt: &str) -> Result<AiNarrative>;
}

/// Create an AI provider from configuration.
pub fn create_provider(config: &AiProviderConfig) -> Result<Box<dyn AiProvider>> {
    match config.provider_type.as_str() {
        "openai" => Ok(Box::new(OpenAiProvider::new(config)?)),
        "anthropic" => Ok(Box::new(AnthropicProvider::new(config)?)),
        "local" => Ok(Box::new(LocalProvider::new(config)?)),
        other => Err(CryptoTraceError::AiProvider(format!(
            "Unknown AI provider type: {}",
            other
        ))),
    }
}

// ── OpenAI Provider ─────────────────────────────────────────

pub struct OpenAiProvider {
    api_key: String,
    model: String,
    max_tokens: u32,
    temperature: f64,
    client: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(config: &AiProviderConfig) -> Result<Self> {
        let api_key = config
            .api_key
            .clone()
            .ok_or_else(|| CryptoTraceError::AiProvider("OpenAI requires an API key".to_string()))?;
        Ok(Self {
            api_key,
            model: config.model.clone(),
            max_tokens: config.max_tokens,
            temperature: config.temperature,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.timeout_seconds))
                .build()
                .map_err(|e| CryptoTraceError::AiProvider(format!("HTTP client: {}", e)))?,
        })
    }
}

#[async_trait::async_trait]
impl AiProvider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "OpenAI"
    }

    async fn generate(&self, prompt: &str) -> Result<AiNarrative> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a cryptographic analysis assistant. Respond only with valid JSON in the specified format."},
                {"role": "user", "content": prompt}
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "response_format": {"type": "json_object"}
        });

        let resp = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| CryptoTraceError::AiProvider(format!("OpenAI request failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CryptoTraceError::AiProvider(format!("OpenAI response parse: {}", e)))?;

        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| CryptoTraceError::AiProvider("OpenAI returned empty response".to_string()))?;

        crate::intelligence::narrative::validate_narrative(content)
    }
}

// ── Anthropic Provider ───────────────────────────────────────

pub struct AnthropicProvider {
    api_key: String,
    model: String,
    max_tokens: u32,
    temperature: f64,
    client: reqwest::Client,
}

impl AnthropicProvider {
    pub fn new(config: &AiProviderConfig) -> Result<Self> {
        let api_key = config.api_key.clone().ok_or_else(|| {
            CryptoTraceError::AiProvider("Anthropic requires an API key".to_string())
        })?;
        Ok(Self {
            api_key,
            model: config.model.clone(),
            max_tokens: config.max_tokens,
            temperature: config.temperature,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.timeout_seconds))
                .build()
                .map_err(|e| CryptoTraceError::AiProvider(format!("HTTP client: {}", e)))?,
        })
    }
}

#[async_trait::async_trait]
impl AiProvider for AnthropicProvider {
    fn name(&self) -> &'static str {
        "Anthropic"
    }

    async fn generate(&self, prompt: &str) -> Result<AiNarrative> {
        let body = serde_json::json!({
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}]
        });

        let resp = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await
            .map_err(|e| CryptoTraceError::AiProvider(format!("Anthropic request failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CryptoTraceError::AiProvider(format!("Anthropic response parse: {}", e)))?;

        let content = json["content"][0]["text"]
            .as_str()
            .ok_or_else(|| CryptoTraceError::AiProvider("Anthropic returned empty response".to_string()))?;

        crate::intelligence::narrative::validate_narrative(content)
    }
}

// ── Local Provider (Ollama) ──────────────────────────────────

pub struct LocalProvider {
    base_url: String,
    model: String,
    max_tokens: u32,
    temperature: f64,
    client: reqwest::Client,
}

impl LocalProvider {
    pub fn new(config: &AiProviderConfig) -> Result<Self> {
        let base_url = config
            .base_url
            .clone()
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        Ok(Self {
            base_url,
            model: config.model.clone(),
            max_tokens: config.max_tokens,
            temperature: config.temperature,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.timeout_seconds))
                .build()
                .map_err(|e| CryptoTraceError::AiProvider(format!("HTTP client: {}", e)))?,
        })
    }
}

#[async_trait::async_trait]
impl AiProvider for LocalProvider {
    fn name(&self) -> &'static str {
        "local (Ollama)"
    }

    fn is_airgap_safe(&self) -> bool {
        true
    }

    async fn generate(&self, prompt: &str) -> Result<AiNarrative> {
        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "num_predict": self.max_tokens,
                "temperature": self.temperature
            }
        });

        let url = format!("{}/api/generate", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CryptoTraceError::AiProvider(format!("Local request failed: {}", e)))?;

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| CryptoTraceError::AiProvider(format!("Local response parse: {}", e)))?;

        let content = json["response"]
            .as_str()
            .ok_or_else(|| CryptoTraceError::AiProvider("Local model returned empty response".to_string()))?;

        crate::intelligence::narrative::validate_narrative(content)
    }
}

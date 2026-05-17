#[tokio::main]
async fn main() {
    // Initialize tracing/logging
    tracing_subscriber::fmt::init();

    // Load calibration model from default path if available
    if let Some(model) = cryptotrace::core::calibration::default_model() {
        cryptotrace::core::confidence::set_model(model);
    }

    // Check for --api flag to start in server mode
    let is_api = std::env::args().any(|a| a == "--api");

    if is_api {
        // Load API config from cryptotrace.toml or use defaults
        let api_config = load_api_config();
        if let Err(e) = cryptotrace::api::run(api_config).await {
            eprintln!("API server error: {}", e);
            std::process::exit(1);
        }
    } else {
        // Normal CLI mode
        match cryptotrace::cli::run().await {
            Ok(Some(result)) => {
                let json = std::env::args().any(|a| a == "--json");
                cryptotrace::cli::print_result(&result, json);
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

/// Load API configuration from cryptotrace.toml or environment.
fn load_api_config() -> cryptotrace::api::ApiConfig {
    let mut config = cryptotrace::api::ApiConfig::default();

    // Check env vars first
    if let Ok(bind) = std::env::var("API_BIND") {
        config.bind = bind;
    }
    if std::env::var("API_KEY").is_ok() {
        config.api_key = std::env::var("API_KEY").ok();
    }
    if let Ok(rl) = std::env::var("API_RATE_LIMIT") {
        if let Ok(n) = rl.parse() {
            config.rate_limit_per_minute = n;
        }
    }
    if std::env::var("API_SANDBOX").map_or(false, |v| v == "true" || v == "1") {
        config.sandbox_enabled = true;
    }

    // Try cryptotrace.toml for overrides
    let toml_path = std::path::Path::new("cryptotrace.toml");
    if toml_path.exists() {
        if let Ok(content) = std::fs::read_to_string(toml_path) {
            if let Ok(parsed) = toml::from_str::<serde_json::Value>(&content) {
                if let Some(api) = parsed.get("api") {
                    if let Some(bind) = api.get("bind").and_then(|v| v.as_str()) {
                        config.bind = bind.to_string();
                    }
                    config.api_key = api.get("api_key").and_then(|v| v.as_str()).map(|s| s.to_string());
                    if let Some(rl) = api.get("rate_limit").and_then(|v| v.as_u64()) {
                        config.rate_limit_per_minute = rl as usize;
                    }
                    if let Some(sb) = api.get("sandbox_enabled").and_then(|v| v.as_bool()) {
                        config.sandbox_enabled = sb;
                    }
                }
            }
        }
    }

    config
}



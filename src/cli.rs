use crate::error::Result;
use crate::types::DetectionResult;
use clap::{Parser, Subcommand};

/// Cryptographic Fingerprinting & Data Classification Engine
#[derive(Parser)]
#[command(name = "cryptotrace")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a string or file for cryptographic fingerprints
    Analyze {
        /// Input to analyze (string literal or file path)
        input: String,

        /// Threat context: malware, password, or forensics (default: forensics)
        #[arg(long, default_value = "forensics")]
        context: String,

        /// Enable recursive layer analysis
        #[arg(long)]
        deep: bool,

        /// Output raw JSON
        #[arg(long)]
        json: bool,

        /// Show full explanation: signal breakdown, primary drivers, conflicts
        #[arg(long)]
        explain: bool,

        /// Append AI narrative (requires AI provider config)
        #[arg(long)]
        ai: bool,

        /// Run analysis in a sandboxed subprocess (resource limits + timeout)
        #[arg(long)]
        sandbox: bool,
    },

    /// Update the signature database (GPG-verified)
    Update {
        /// Roll back to previous signature database version
        #[arg(long)]
        rollback: bool,

        /// Import signature update from a local file (air-gap mode)
        #[arg(long)]
        from_file: Option<String>,

        /// Path to detached Ed25519 or GPG signature for verification
        #[arg(long)]
        verify: Option<String>,
    },

    /// Show engine and signature database versions
    Version,

    /// Clear AI output cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },

    /// Show active configuration (secrets redacted)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Train or manage the calibration model
    Calibrate {
        #[command(subcommand)]
        action: CalibrateAction,
    },
}

#[derive(Subcommand)]
pub enum CacheAction {
    /// Clear AI narrative cache
    Clear,
    /// Show cache statistics
    Status,
}

#[derive(Subcommand)]
pub enum ConfigAction {
    Show,
}

#[derive(Subcommand)]
pub enum CalibrateAction {
    /// Train a new calibration model from CSV data
    Train {
        /// Path to CSV training dataset
        #[arg(long, default_value = "calibration_data/train.csv")]
        data: String,

        /// Path to save the trained model (default: calibration_data/model.json)
        #[arg(long, default_value = "calibration_data/model.json")]
        output: String,

        /// Gradient descent learning rate
        #[arg(long, default_value_t = 0.1)]
        learning_rate: f64,

        /// Number of training epochs
        #[arg(long, default_value_t = 1000)]
        epochs: usize,

        /// L2 regularization strength
        #[arg(long, default_value_t = 0.001)]
        l2_lambda: f64,
    },

    /// Generate synthetic training data for initial calibration
    Generate {
        /// Number of samples per class
        #[arg(long, default_value_t = 200)]
        samples: usize,

        /// Output CSV path
        #[arg(long, default_value = "calibration_data/train.csv")]
        output: String,
    },

    /// Show current calibration model info
    Status,
}

/// Run the CLI command and return a DetectionResult (if applicable) along with format flags.
pub async fn run() -> Result<Option<(DetectionResult, bool, bool)>> {
    let cli = Cli::parse();
    run_with_cli(&cli).await
}

/// Run the CLI command using a pre-parsed Cli struct.
pub async fn run_with_cli(cli: &Cli) -> Result<Option<(DetectionResult, bool, bool)>> {
    match &cli.command {
        Commands::Analyze {
            input,
            context,
            deep,
            json,
            explain,
            ai,
            sandbox,
        } => {
            let detection_context = match context.as_str() {
                "malware" => crate::types::DetectionContext::Malware,
                "password" => crate::types::DetectionContext::Password,
                _ => crate::types::DetectionContext::Forensics,
            };

            // Build sandbox if enabled
            let sandbox_instance = if *sandbox {
                let sand_config = crate::sanitization::sandbox::SandboxConfig {
                    enabled: true,
                    ..Default::default()
                };
                Some(crate::sanitization::sandbox::Sandbox::new(sand_config))
            } else {
                None
            };

            // Try as file first, then as string
            let path = std::path::Path::new(input);
            let mut result = if path.exists() {
                if let Some(ref sb) = sandbox_instance {
                    crate::analyzers::file::analyze_file_sandboxed(path, sb)?
                } else {
                    crate::analyzers::file::analyze_file(path)?
                }
            } else if let Some(ref sb) = sandbox_instance {
                let data = input.as_bytes();
                crate::analyzers::file::analyze_bytes_sandboxed(data, sb)?
            } else {
                crate::analyzers::string::analyze_string(input)?
            };

            // Apply detection context
            result.detection_context = detection_context;

            // Recursive analysis
            if *deep && !result.algorithm.as_deref().map_or(true, |a| a.is_empty()) {
                let config = crate::analyzers::recursive::RecursiveConfig::default();
                let layers = crate::analyzers::recursive::analyze_recursive(
                    &result.input_hash.as_bytes(),
                    &config,
                )?;
                // Convert recursive layers to DetectionResult layers
                for layer in layers {
                    let layer_result = DetectionResult {
                        input_hash: result.input_hash.clone(),
                        source_type: crate::types::SourceType::Binary,
                        entropy: 0.0,
                        sliding_entropy: None,
                        detected_type: layer.detected_type,
                        algorithm: Some(layer.algorithm),
                        confidence: layer.confidence,
                        calibrated: false,
                        calibration_samples: None,
                        heuristic_raw: None,
                        confidence_is_provisional: true,
                        false_positive_risk: 0.0,
                        risk_level: crate::types::RiskLevel::Unknown,
                        weakness: None,
                        weakness_cve: vec![],
                        recommendations: vec![],
                        signals: None,
                        primary_drivers: vec![],
                        conflicting_signals: vec![],
                        decision_trace: None,
                        layers: vec![],
                        ai_narrative: None,
                        detection_context: result.detection_context,
                        engine_version: result.engine_version.clone(),
                        signature_db_version: result.signature_db_version.clone(),
                    };
                    result.layers.push(layer_result);
                }
            }

            // Log audit trail
            crate::intelligence::audit::log_analysis(&result);

            // Optional AI narrative
            if *ai {
                if let Ok(provider) = load_ai_provider() {
                    match crate::analyzers::file::attach_ai_narrative(&result, &*provider).await {
                        Ok(r) => result = r,
                        Err(e) => eprintln!("AI narrative: {}", e),
                    }
                } else {
                    eprintln!(
                        "AI narrative requested but no AI provider configured. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or configure a local provider."
                    );
                }
            }

            Ok(Some((result, *json, *explain)))
        }

        Commands::Update {
            rollback,
            from_file,
            verify,
        } => {
            let update_mgr = crate::update::UpdateManager::new(std::path::Path::new("signatures"));

            if *rollback {
                update_mgr.rollback()?;
                println!(
                    "Rolled back to signature DB: {}",
                    update_mgr.current_version()
                );
            } else if let Some(path) = from_file {
                let import_path = std::path::Path::new(path);
                let sig_path = verify.as_ref().map(|s| std::path::Path::new(s));
                update_mgr.import_local(import_path, sig_path)?;
                println!("Imported signature DB: {}", update_mgr.current_version());
            } else {
                let version = update_mgr.check_for_updates()?;
                println!("Current signature DB: {}", version);
            }

            Ok(None)
        }

        Commands::Version => {
            let update_mgr = crate::update::UpdateManager::new(std::path::Path::new("signatures"));
            println!("CryptoTrace v{}", env!("CARGO_PKG_VERSION"));
            println!("Engine: {}", env!("CARGO_PKG_VERSION"));
            println!("Signature DB: {}", update_mgr.current_version());
            Ok(None)
        }

        Commands::Cache { action } => {
            match action {
                CacheAction::Clear => {
                    crate::intelligence::prompt::clear_cache();
                    tracing::info!("AI narrative cache cleared");
                    println!("AI narrative cache cleared.");
                }
                CacheAction::Status => {
                    let info = crate::intelligence::prompt::cache_info();
                    println!("AI narrative cache:");
                    println!("  Enabled:           {}", info.enabled);
                    println!("  Capacity:          {} entries", info.capacity);
                    println!("  Current entries:   {}", info.count);
                }
            }
            Ok(None)
        }

        Commands::Config { action } => {
            match action {
                ConfigAction::Show => {
                    let config = crate::types::AppConfig::default();
                    println!("AI enabled:            {}", config.ai.enabled);
                    println!(
                        "AI provider:           {}",
                        config.ai.provider.as_deref().unwrap_or("none")
                    );
                    println!(
                        "AI model:              {}",
                        config.ai.model_family.as_deref().unwrap_or("gpt-4o")
                    );
                    println!(
                        "AI temperature:        {}",
                        config.ai.temperature.as_ref().map_or(0.1, |t| *t)
                    );
                    println!(
                        "AI max tokens:         {}",
                        config.ai.max_tokens.as_ref().map_or(512, |t| *t)
                    );
                    if let Some(ref cache) = config.ai.cache {
                        println!("AI cache enabled:      {}", cache.enabled);
                        println!("AI cache TTL days:     {}", cache.ttl_days);
                        println!("AI cache max entries:  {}", cache.max_entries);
                    }
                    println!("Sandbox enabled:       {}", false);
                    println!("Sandbox max memory:    512 MB");
                    println!("Sandbox max concurrent: 4");
                    println!("Sandbox timeout:       30s");
                    println!(
                        "Entropy thresholds:    plaintext<={}, mixed<={}, compressed<={}",
                        config.entropy.thresholds.plaintext_max,
                        config.entropy.thresholds.mixed_max,
                        config.entropy.thresholds.compressed_max
                    );
                    println!(
                        "Risk overrides:        {} rules",
                        config.risk.overrides.len()
                    );
                    println!("Max file size:         50 MB");
                    println!("Max string size:       10 MB");
                }
            }
            Ok(None)
        }

        Commands::Calibrate { action } => {
            match action {
                CalibrateAction::Train {
                    data,
                    output,
                    learning_rate,
                    epochs,
                    l2_lambda,
                } => {
                    let samples = crate::core::calibration::load_csv(data)?;
                    if samples.is_empty() {
                        eprintln!("No samples loaded from {}", data);
                        std::process::exit(1);
                    }
                    println!(
                        "Training on {} samples (lr={}, epochs={}, l2={})...",
                        samples.len(),
                        learning_rate,
                        epochs,
                        l2_lambda,
                    );
                    let model = crate::core::calibration::train(
                        &samples,
                        *learning_rate,
                        *epochs,
                        *l2_lambda,
                    );
                    crate::core::calibration::save_model(&model, output)?;
                    crate::core::confidence::set_model(model);
                    println!("Model saved to {}", output);
                    println!("Dataset size: {} samples", samples.len());
                    println!("Calibration method: Platt scaling");
                }
                CalibrateAction::Generate { samples, output } => {
                    let data = crate::core::calibration::generate_synthetic_dataset(*samples);
                    // Write CSV
                    let mut wtr = csv::Writer::from_path(output).map_err(|e| {
                        crate::error::CryptoTraceError::Other(format!("Cannot create CSV: {}", e))
                    })?;
                    wtr.write_record(&[
                        "entropy",
                        "block_alignment",
                        "magic_bytes",
                        "length_pattern",
                        "charset_purity",
                        "window_variance",
                        "label",
                        "detected_type",
                    ])
                    .ok();
                    for sample in &data {
                        wtr.write_record(&[
                            format!("{:.6}", sample.signals.entropy),
                            format!("{:.6}", sample.signals.block_alignment),
                            format!("{:.6}", sample.signals.magic_bytes),
                            format!("{:.6}", sample.signals.length_pattern),
                            sample
                                .signals
                                .charset_purity
                                .map(|v| format!("{:.6}", v))
                                .unwrap_or_default(),
                            sample
                                .signals
                                .window_variance
                                .map(|v| format!("{:.6}", v))
                                .unwrap_or_default(),
                            format!("{}", sample.label as u8),
                            sample.detected_type.clone(),
                        ])
                        .ok();
                    }
                    wtr.flush().ok();
                    println!("Generated {} synthetic samples → {}", data.len(), output);
                }
                CalibrateAction::Status => {
                    let model = crate::core::calibration::default_model();
                    if let Some(m) = model {
                        println!("Calibration model loaded");
                        println!("  Dataset size: {}", m.dataset_size);
                        println!("  Method: {}", m.method);
                        println!("  Date: {}", m.calibration_date);
                        println!("  Weights:");
                        println!("    entropy:          {:.4}", m.weights[0]);
                        println!("    block_alignment:  {:.4}", m.weights[1]);
                        println!("    magic_bytes:      {:.4}", m.weights[2]);
                        println!("    length_pattern:   {:.4}", m.weights[3]);
                        println!("    charset_purity:   {:.4}", m.weights[4]);
                        println!("    window_variance:  {:.4}", m.weights[5]);
                        println!("  Intercept: {:.4}", m.intercept);
                    } else {
                        println!("No calibration model loaded (provisional fallback active)");
                    }
                }
            }
            Ok(None)
        }
    }
}

/// Format and print the analysis result based on CLI flags.
pub fn print_result(result: &DetectionResult, json: bool) {
    print_result_ext(result, json, false)
}

pub fn print_result_ext(result: &DetectionResult, json: bool, explain: bool) {
    if json {
        println!("{}", crate::reports::json::format_json(result));
    } else {
        print!(
            "{}",
            crate::reports::terminal::format_terminal_ext(result, explain)
        );
    }
}

/// Load AI provider from environment or config file.
pub fn load_ai_provider() -> Result<Box<dyn crate::providers::AiProvider>> {
    let mut config = crate::providers::AiProviderConfig::default();

    // Check environment variables first
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        config.provider_type = "openai".to_string();
        config.api_key = Some(key);
        if let Ok(model) = std::env::var("OPENAI_MODEL") {
            config.model = model;
        }
    } else if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        config.provider_type = "anthropic".to_string();
        config.api_key = Some(key);
        if let Ok(model) = std::env::var("ANTHROPIC_MODEL") {
            config.model = model;
        }
    } else if std::env::var("AI_PROVIDER").map_or(false, |v| v == "local") {
        config.provider_type = "local".to_string();
        config.base_url = std::env::var("AI_BASE_URL").ok();
        if let Ok(model) = std::env::var("AI_MODEL") {
            config.model = model;
        }
    } else {
        // Try to load from cryptotrace.toml
        let toml_path = std::path::Path::new("cryptotrace.toml");
        if toml_path.exists() {
            let content = std::fs::read_to_string(toml_path).map_err(|e| {
                crate::error::CryptoTraceError::Other(format!("Config read: {}", e))
            })?;
            let parsed: serde_json::Value = toml::from_str(&content).map_err(|e| {
                crate::error::CryptoTraceError::Other(format!("Config parse: {}", e))
            })?;
            if let Some(ai) = parsed.get("ai") {
                if let Some(provider) = ai.get("provider").and_then(|v| v.as_str()) {
                    config.provider_type = provider.to_string();
                }
                config.api_key = ai
                    .get("api_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                config.model = ai
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or(config.model);
                config.temperature = ai
                    .get("temperature")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(config.temperature);
                config.max_tokens = ai
                    .get("max_tokens")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32)
                    .unwrap_or(config.max_tokens);
                config.base_url = ai
                    .get("base_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                config.timeout_seconds = ai
                    .get("timeout_seconds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(config.timeout_seconds);
            }
        }
    }

    crate::providers::create_provider(&config)
}

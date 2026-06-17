#[tokio::main]
async fn main() {
    // Initialize tracing/logging
    tracing_subscriber::fmt::init();

    // Load calibration model from default path if available
    if let Some(model) = cryptotrace::core::calibration::default_model() {
        cryptotrace::core::confidence::set_model(model);
    }

    // Initialize AI narrative cache
    cryptotrace::intelligence::prompt::init_cache(100);

    // Run CLI command
    match cryptotrace::cli::run().await {
        Ok(Some((result, json, explain))) => {
            cryptotrace::cli::print_result_ext(&result, json, explain);
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

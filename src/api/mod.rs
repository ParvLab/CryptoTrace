pub mod auth;
pub mod errors;
pub mod routes;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;

use crate::sanitization::sandbox::{Sandbox, SandboxConfig};
use routes::AppState;

/// API server configuration.
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind: String,
    pub api_key: Option<String>,
    pub rate_limit_per_minute: usize,
    pub sandbox_enabled: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:8080".to_string(),
            api_key: None,
            rate_limit_per_minute: 60,
            sandbox_enabled: false,
        }
    }
}

/// Start the API server. Blocks until a shutdown signal is received.
pub async fn run(config: ApiConfig) -> Result<(), crate::error::CryptoTraceError> {
    let sandbox = if config.sandbox_enabled {
        Some(Sandbox::new(SandboxConfig {
            enabled: true,
            ..Default::default()
        }))
    } else {
        None
    };

    let state = Arc::new(AppState {
        startup_time: Instant::now(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        sig_db_version: crate::update::UpdateManager::new(std::path::Path::new("signatures"))
            .current_version(),
        sandbox,
    });

    let rate_limiter = Arc::new(auth::RateLimiter::new(config.rate_limit_per_minute));

    // Build router (Router<()> — no state, state injected via Extension)
    let mut router = Router::new()
        .route("/health", get(routes::health))
        .route("/version", get(routes::version))
        .route("/analyze", post(routes::analyze))
        .layer(middleware::from_fn(auth::auth_middleware));

    // Inject API key into extensions
    if let Some(ref key) = config.api_key {
        let k = key.clone();
        router = router.layer(middleware::from_fn(move |mut req: axum::http::Request<axum::body::Body>, next: middleware::Next| {
            let k = k.clone();
            async move {
                req.extensions_mut().insert(k);
                next.run(req).await
            }
        }));
    }

    // Inject rate limiter into extensions
    router = router.layer(middleware::from_fn(move |mut req: axum::http::Request<axum::body::Body>, next: middleware::Next| {
        let rl = rate_limiter.clone();
        async move {
            req.extensions_mut().insert(rl);
            next.run(req).await
        }
    }));

    // Inject app state into extensions
    router = router.layer(middleware::from_fn(move |mut req: axum::http::Request<axum::body::Body>, next: middleware::Next| {
        let state = state.clone();
        async move {
            req.extensions_mut().insert(state);
            next.run(req).await
        }
    }));

    let addr: SocketAddr = config.bind.parse().map_err(|e| {
        crate::error::CryptoTraceError::Other(format!("Invalid bind address '{}': {}", config.bind, e))
    })?;

    tracing::info!("API server starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        crate::error::CryptoTraceError::Other(format!("Failed to bind {}: {}", addr, e))
    })?;

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| crate::error::CryptoTraceError::Other(format!("Server error: {}", e)))?;

    Ok(())
}

/// Wait for Ctrl+C or SIGTERM to trigger graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm => {},
    }

    tracing::info!("Shutdown signal received, draining connections...");
}

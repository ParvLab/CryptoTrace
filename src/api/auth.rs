use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::header;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::api::errors::ApiError;

/// Global rate limit state (not per-IP, to avoid needing ConnectInfo).
pub struct RateLimiter {
    inner: Mutex<Vec<Instant>>,
    max_per_minute: usize,
}

impl RateLimiter {
    pub fn new(max_per_minute: usize) -> Self {
        Self {
            inner: Mutex::new(Vec::new()),
            max_per_minute,
        }
    }

    /// Check if a request should be allowed. Returns `Ok(())` or the
    /// number of seconds to wait before retrying.
    pub fn check(&self) -> Result<(), u64> {
        let now = Instant::now();
        let mut timestamps = self.inner.lock().unwrap();

        // Remove timestamps older than 1 minute
        let cutoff = now - Duration::from_secs(60);
        timestamps.retain(|t| *t > cutoff);

        if timestamps.len() >= self.max_per_minute {
            let oldest = timestamps.first().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest).as_secs();
            let retry_after = 60u64.saturating_sub(elapsed).max(1);
            return Err(retry_after);
        }

        timestamps.push(now);
        Ok(())
    }
}

/// Axum middleware: validate API key if configured, enforce rate limit.
pub async fn auth_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // Rate limit check (global, not per-IP)
    if let Some(rl) = req.extensions().get::<std::sync::Arc<RateLimiter>>() {
        if let Err(retry_after) = rl.check() {
            return Err(ApiError::RateLimited { retry_after_seconds: retry_after });
        }
    }

    // API key check (if configured)
    if let Some(expected_key) = req.extensions().get::<String>() {
        let provided = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .or_else(|| {
                req.headers()
                    .get("X-API-Key")
                    .and_then(|v| v.to_str().ok())
            });

        match provided {
            Some(key) if key == expected_key => {}
            _ => {
                return Err(ApiError::Unauthorized(
                    "Missing or invalid API key. Provide via Authorization: Bearer <key> or X-API-Key: <key> header."
                        .to_string(),
                ));
            }
        }
    }

    Ok(next.run(req).await)
}

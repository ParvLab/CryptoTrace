use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// Structured JSON error response body.
#[derive(Debug, serde::Serialize)]
pub struct ApiErrorBody {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

/// Unified API error type.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    RateLimited { retry_after_seconds: u64 },
    NotFound(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body, retry) = match &self {
            ApiError::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                ApiErrorBody {
                    error: "bad_request".to_string(),
                    message: msg.clone(),
                    retry_after_seconds: None,
                },
                None,
            ),
            ApiError::Unauthorized(msg) => (
                StatusCode::UNAUTHORIZED,
                ApiErrorBody {
                    error: "unauthorized".to_string(),
                    message: msg.clone(),
                    retry_after_seconds: None,
                },
                None,
            ),
            ApiError::RateLimited { retry_after_seconds } => (
                StatusCode::TOO_MANY_REQUESTS,
                ApiErrorBody {
                    error: "rate_limited".to_string(),
                    message: format!(
                        "Too many requests. Try again in {}s.",
                        retry_after_seconds
                    ),
                    retry_after_seconds: Some(*retry_after_seconds),
                },
                Some(*retry_after_seconds),
            ),
            ApiError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                ApiErrorBody {
                    error: "not_found".to_string(),
                    message: msg.clone(),
                    retry_after_seconds: None,
                },
                None,
            ),
            ApiError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ApiErrorBody {
                    error: "internal_error".to_string(),
                    message: msg.clone(),
                    retry_after_seconds: None,
                },
                None,
            ),
        };

        let mut resp = Json(body).into_response();
        *resp.status_mut() = status;

        if let Some(retry_after) = retry {
            resp.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                retry_after.to_string().parse().unwrap(),
            );
        }

        resp
    }
}

impl From<crate::error::CryptoTraceError> for ApiError {
    fn from(e: crate::error::CryptoTraceError) -> Self {
        ApiError::Internal(e.to_string())
    }
}

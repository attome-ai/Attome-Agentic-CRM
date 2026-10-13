//! The console routes' error type: every local failure is the platform's
//! `AppError` (same JSON envelope and status mapping); a failure of the
//! customer call a route proxies is `502 fleet_remote_error` carrying the
//! customer's status, its error code and message (never its raw body), so
//! the developer sees *which* side refused and why.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::client::RemoteError;
use attome_types::AppError;

/// The response code of a refused non-loopback peer (design §2.5).
pub const LOOPBACK_ONLY: &str = "fleet_console_loopback_only";
/// The response code of a failed customer call.
pub const REMOTE_ERROR: &str = "fleet_remote_error";

#[derive(Debug)]
pub enum ConsoleError {
    Local(AppError),
    Remote(RemoteError),
}

impl From<AppError> for ConsoleError {
    fn from(error: AppError) -> Self {
        Self::Local(error)
    }
}

impl From<RemoteError> for ConsoleError {
    fn from(error: RemoteError) -> Self {
        Self::Remote(error)
    }
}

impl IntoResponse for ConsoleError {
    fn into_response(self) -> Response {
        match self {
            Self::Local(error) => error.into_response(),
            Self::Remote(error) => {
                let (code, message) = match &error {
                    RemoteError::Status { code, message, .. } => (code.clone(), message.clone()),
                    _ => (None, None),
                };
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": REMOTE_ERROR,
                        "message": format!("the customer server refused or failed: {error}"),
                        "remote_error": error.code(),
                        "remote_status": error.status(),
                        "remote_code": code,
                        "remote_message": message,
                    })),
                )
                    .into_response()
            }
        }
    }
}

/// The 403 a non-loopback peer gets (design §2.5).
pub fn loopback_refusal() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": LOOPBACK_ONLY,
            "message": "the fleet console answers only on the developer's own machine (loopback)",
        })),
    )
        .into_response()
}

pub type ConsoleResult<T> = Result<T, ConsoleError>;

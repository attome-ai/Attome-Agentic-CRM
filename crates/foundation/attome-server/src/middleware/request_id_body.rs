//! Duplicates the `x-request-id` (already set by `SetRequestIdLayer` and
//! echoed in the response header via `PropagateRequestIdLayer`) into the JSON
//! body of any error response, so a client that only logs/displays the body
//! — not response headers — can still correlate a failure with server-side
//! tracing (`touch-error.rs` TARGET, ex-audit-roadmap item).
//!
//! Every `AppError` response is a JSON object (`{"error", "message"}`, see
//! `attome-types::AppError::into_response`) — this only ever adds a field to
//! that shape, never replaces it, and leaves any non-JSON or 2xx/3xx response
//! byte-for-byte untouched.
//!
//! BSV-F09 (A5) — an error body larger than [`MAX_ERROR_BODY_BYTES`] used to be
//! replaced by an empty body. It is now logged with its request id and
//! forwarded unmodified (the part already read chained with the rest), so a
//! large validation error reaches the client whole; its `request_id` is in the
//! `x-request-id` header only.

use crate::middleware::idempotency::{Buffered, buffer_up_to};
use axum::{
    body::Body, extract::Request, http::header::CONTENT_LENGTH, middleware::Next,
    response::Response,
};
use tower_http::request_id::RequestId;

/// Error bodies are a small fixed JSON shape — this is a generous ceiling,
/// not a real limit; past it the body is forwarded unmodified rather than
/// buffered without bound.
pub(crate) const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

pub async fn attach_request_id_to_error_body(req: Request, next: Next) -> Response {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .map(str::to_owned);
    // Z14-T1: the problem's `instance`, the path it happened at.
    let instance = req.uri().path().to_owned();

    let response = next.run(req).await;

    let Some(request_id) = request_id else {
        return response;
    };
    if !response.status().is_client_error() && !response.status().is_server_error() {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let bytes = match buffer_up_to(body, MAX_ERROR_BODY_BYTES).await {
        Buffered::Complete(bytes) => bytes,
        Buffered::Unreplayable(body) => {
            tracing::warn!(
                request_id = %request_id,
                status = parts.status.as_u16(),
                limit = MAX_ERROR_BODY_BYTES,
                "error body over the request-id ceiling; forwarded without request_id in the body"
            );
            return Response::from_parts(parts, body);
        }
    };

    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    let Some(obj) = value.as_object_mut() else {
        return Response::from_parts(parts, Body::from(bytes));
    };

    obj.insert(
        "request_id".to_owned(),
        serde_json::Value::String(request_id),
    );
    if obj.contains_key("code") {
        obj.insert("instance".to_owned(), serde_json::Value::String(instance));
    }
    let new_bytes = serde_json::to_vec(&value).unwrap_or(bytes.to_vec());
    parts.headers.remove(CONTENT_LENGTH); // body length changed; let the server recompute it
    Response::from_parts(parts, Body::from(new_bytes))
}

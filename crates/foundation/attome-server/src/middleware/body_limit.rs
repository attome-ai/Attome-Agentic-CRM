//! Proactive `Content-Length` guard — rejects a declared-oversized body with
//! 413 before any other layer (including auth) runs.
//!
//! `tower_http::limit::RequestBodyLimitLayer` (still applied alongside this,
//! in `apply_outer_layers`) only errors once something actually *reads* the
//! body past the limit. A request that a downstream layer rejects without
//! ever touching the body (e.g. `authn` returning 401 for a missing session)
//! never reads the body, so that streaming limit never fires and the client
//! sees whatever status the downstream layer returned instead of 413 — a gap
//! found by `middleware_pipeline.rs::oversized_body_is_rejected_before_authn_runs`
//! (P1.8, 2026-07-07) contradicting this pipeline's documented guarantee.
//! This guard checks only the `Content-Length` header (no body read, so it's
//! cheap). It runs inside request-id/tracing/CORS so its 413 carries the
//! standard `payload_too_large` envelope, and it is defense-in-depth alongside
//! — not a replacement for — the streaming limit, which still caps a request
//! that lies about or omits `Content-Length`. An overflow on that streaming
//! path surfaces in whatever reads the body: the idempotency gate answers
//! `payload_too_large`, while axum's own `Json`/`Bytes` extractors answer with
//! their plain-text 413.

use attome_types::AppError;
use axum::{
    body::Body,
    http::{Request, header::CONTENT_LENGTH},
    middleware::Next,
    response::{IntoResponse, Response},
};

pub(crate) async fn reject_declared_oversized_body(
    max_bytes: usize,
    req: Request<Body>,
    next: Next,
) -> Response {
    let declared_len = req
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());

    if let Some(len) = declared_len
        && len > max_bytes
    {
        return AppError::PayloadTooLarge.into_response();
    }

    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::{Router, routing::post};
    use tower::ServiceExt;

    /// `next.run` never touches the body for these tests — the whole point
    /// of `reject_declared_oversized_body` is a header-only check, so an
    /// inner handler that would fail if the body were actually read (there
    /// isn't one to read past what's declared) still proves the "pass
    /// through" path never buffers anything.
    fn app_with_limit(max_bytes: usize) -> Router {
        Router::new()
            .route("/", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn(move |req, next| {
                reject_declared_oversized_body(max_bytes, req, next)
            }))
    }

    fn request_with_content_length(len: Option<usize>) -> axum::http::Request<Body> {
        let mut builder = axum::http::Request::builder().method("POST").uri("/");
        if let Some(len) = len {
            builder = builder.header(CONTENT_LENGTH, len.to_string());
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn a_declared_length_over_the_limit_is_rejected_with_413() {
        let app = app_with_limit(100);
        let req = request_with_content_length(Some(101));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_declared_length_at_exactly_the_limit_passes_through() {
        let app = app_with_limit(100);
        let req = request_with_content_length(Some(100));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_declared_length_under_the_limit_passes_through() {
        let app = app_with_limit(100);
        let req = request_with_content_length(Some(1));
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_missing_content_length_passes_through() {
        // No Content-Length declared: this header-only guard has nothing to
        // check and defers to the streaming RequestBodyLimitLayer instead
        // (see the module doc comment for why both exist).
        let app = app_with_limit(100);
        let req = request_with_content_length(None);
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_unparseable_content_length_is_treated_as_absent() {
        let app = app_with_limit(1);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/")
            .header(CONTENT_LENGTH, "not-a-number")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

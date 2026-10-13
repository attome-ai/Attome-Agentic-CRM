//! Integration test for the `request_id`-in-error-body middleware
//! (`attome_server::middleware::request_id_body`) — verifies the same
//! `x-request-id` value shows up both as the response header
//! (`PropagateRequestIdLayer`, already in place) and inside the JSON error
//! body, and that a successful (2xx) JSON body is left untouched.
//!
//! Self-contained: builds a bare router with just the two request-id layers
//! plus a couple of throwaway handlers — no DB/Redis/AppState required.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::middleware::request_id_body::attach_request_id_to_error_body;
use attome_types::AppError;
use axum::{
    Router,
    http::StatusCode,
    routing::{get, post},
};
use tower::ServiceExt;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

fn test_app() -> Router {
    Router::new()
        .route("/boom", get(|| async { AppError::NotFound }))
        .route(
            "/big",
            get(|| async { AppError::Validation("x".repeat(70 * 1024)) }),
        )
        .route(
            "/ok",
            post(|| async { axum::Json(serde_json::json!({"status": "ok"})) }),
        )
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(axum::middleware::from_fn(attach_request_id_to_error_body))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

#[tokio::test]
async fn error_response_carries_the_same_request_id_in_header_and_body() {
    let app = test_app();
    let req = axum::http::Request::builder()
        .uri("/boom")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let header_id = response
        .headers()
        .get("x-request-id")
        .expect("x-request-id header must be set")
        .to_str()
        .unwrap()
        .to_owned();

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "not_found");
    assert_eq!(
        body["request_id"], header_id,
        "body's request_id must match the response header's x-request-id"
    );
}

#[tokio::test]
async fn successful_response_body_is_left_untouched() {
    let app = test_app();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/ok")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body, serde_json::json!({"status": "ok"}));
    assert!(
        body.get("request_id").is_none(),
        "request_id must never be injected into a non-error response"
    );
}

/// BSV-F09 (A5): an error body over the 64 KiB ceiling used to arrive empty.
#[tokio::test]
async fn a_70_kib_error_body_arrives_whole() {
    let req = axum::http::Request::builder()
        .uri("/big")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = test_app().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(response.headers().get("x-request-id").is_some());
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"], "validation_error");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.ends_with(&"x".repeat(70 * 1024))),
        "the whole 70 KiB message must arrive"
    );
}

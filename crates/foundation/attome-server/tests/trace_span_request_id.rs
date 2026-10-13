//! Regression test for the "request_id never reaches the logs" gap: the
//! `TraceLayer` in `apply_outer_layers` used to be `TraceLayer::new_for_http()`
//! with no `.make_span_with(...)`, so the per-request span carried no
//! `request_id` field and nothing an operator could grep for connected a
//! customer-reported request ID to `tracing::error!` output. Fixed by
//! `attome_server::app::request_span`.
//!
//! Self-contained: builds a bare router with just `SetRequestIdLayer` and a
//! `TraceLayer` wired to `request_span` — no DB/Redis/AppState required.
//! Captures span fields via a minimal custom `tracing_subscriber::Layer`
//! rather than pulling in a new dev-dependency.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_server::request_span;
use axum::{Router, routing::get};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, Registry};

#[derive(Default)]
struct CapturedRequestId(Mutex<Option<String>>);

struct RequestIdVisitor<'a>(&'a Mutex<Option<String>>);

impl Visit for RequestIdVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "request_id" {
            *self.0.lock().unwrap() = Some(format!("{value:?}").trim_matches('"').to_owned());
        }
    }
}

struct CaptureLayer(Arc<CapturedRequestId>);

impl<S: tracing::Subscriber> Layer<S> for CaptureLayer {
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        attrs.record(&mut RequestIdVisitor(&self.0.0));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn trace_span_carries_the_same_request_id_as_the_response_header() {
    let captured = Arc::new(CapturedRequestId::default());
    let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
    let _guard = tracing::subscriber::set_default(subscriber);

    let app = Router::new()
        .route("/ping", get(|| async { "pong" }))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(TraceLayer::new_for_http().make_span_with(request_span))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid));

    let req = axum::http::Request::builder()
        .uri("/ping")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();

    let header_id = response
        .headers()
        .get("x-request-id")
        .expect("x-request-id header must be set")
        .to_str()
        .unwrap()
        .to_owned();

    let span_id = captured
        .0
        .lock()
        .unwrap()
        .clone()
        .expect("request_span must record a request_id field on the span");

    assert_eq!(
        span_id, header_id,
        "the span's request_id must match the response header's x-request-id \
         so a customer-reported ID can be grepped straight out of the logs"
    );
}

//! P-observability-bcdr Track A — no live DB/Redis needed: `build_layer_and_handle`
//! and `PrometheusHandle::render` are pure in-process state, so this drives a
//! request through the layer via `tower::ServiceExt::oneshot` rather than binding
//! a real port. Run: `cargo test -p attome-server --test metrics`.
//!
//! A4 (BSV-F10) is covered here too: an unmatched path must not become an
//! unbounded Prometheus `endpoint` label. axum sets `MatchedPath` only on real
//! (non-fallback) routes, so the default `EndpointLabel::MatchedPath` labelled
//! every 404 with the raw request path.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::OnceLock;

use attome_server::build_layer_and_handle;
use axum::{Router, http::StatusCode, routing::get};
use axum_prometheus::PrometheusMetricLayer;
use metrics_exporter_prometheus::PrometheusHandle;
use tower::ServiceExt;

/// `build_layer_and_handle` installs a process-global recorder, so every test
/// in this binary must share one pair rather than installing it again.
fn shared_pair() -> &'static (PrometheusMetricLayer<'static>, PrometheusHandle) {
    static PAIR: OnceLock<(PrometheusMetricLayer<'static>, PrometheusHandle)> = OnceLock::new();
    PAIR.get_or_init(build_layer_and_handle)
}

#[tokio::test]
async fn metrics_render_includes_recorded_request() {
    let (layer, handle) = shared_pair();

    let app = Router::new()
        .route("/dummy", get(|| async { "ok" }))
        .layer(layer.clone());

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/dummy")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let rendered = handle.render();
    assert!(
        rendered.contains("axum_http_requests_total"),
        "expected the default axum-prometheus counter in the render output, got:\n{rendered}"
    );
    assert!(
        rendered.contains("/dummy"),
        "expected the matched path label for the request just driven through the layer, got:\n{rendered}"
    );
}

/// A4 (BSV-F10) — fifty random paths, one bounded `unmatched` series, and no
/// raw path anywhere in a label.
#[tokio::test]
async fn fifty_random_404_paths_make_one_unmatched_series() {
    let (layer, handle) = shared_pair();
    let app = Router::new()
        .route("/known", get(|| async { "ok" }))
        .layer(layer.clone());

    for i in 0..50 {
        let response = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/random-{i}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router is infallible");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    let rendered = handle.render();
    assert!(
        rendered.contains("endpoint=\"unmatched\""),
        "an unmatched path must be reported under one bounded label; rendered metrics:\n{rendered}"
    );
    assert!(
        !rendered.contains("/random-"),
        "no raw unmatched path may appear in a metric label; rendered metrics:\n{rendered}"
    );
}

/// M86 O1 — the request-duration histogram carries every SLO bucket edge the
/// `attome-slo` recording rules read, so no class's latency ratio is
/// interpolated or missing (`SloLatencyBucketMissing`).
#[tokio::test]
async fn the_duration_histogram_has_every_slo_bucket() {
    let (layer, handle) = shared_pair();
    let app = Router::new()
        .route("/slo-buckets", get(|| async { "ok" }))
        .layer(layer.clone());
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/slo-buckets")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .expect("router is infallible");
    assert_eq!(response.status(), StatusCode::OK);

    let rendered = handle.render();
    for le in [
        "0.005", "0.01", "0.015", "0.02", "0.03", "0.04", "0.06", "0.1", "0.12", "0.15", "0.2",
        "0.3", "0.5", "1", "2.5", "5", "+Inf",
    ] {
        let bucket = format!("le=\"{le}\"");
        assert!(
            rendered.lines().any(
                |l| l.starts_with("axum_http_requests_duration_seconds_bucket")
                    && l.contains("/slo-buckets")
                    && l.contains(&bucket)
            ),
            "missing duration bucket {bucket}, got:\n{rendered}"
        );
    }
}

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

/// Z5-T11: an enforced CSRF refusal counts once in
/// `http_rejections_total{layer="csrf", reason="cross_site"}`.
#[tokio::test]
async fn csrf_rejection_increments_counter() {
    let (_, handle) = shared_pair();
    let config: attome_config::AppConfig = serde_json::from_value(serde_json::json!({
        "app": {
            "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
            "frontend_port": 4200, "log_level": "error", "threads": 1,
            "max_body_size_bytes": 1_048_576, "request_timeout_secs": 5,
            "enable_session": true, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "use_gzip": false,
            "enable_compression": false, "gzip_level": 1, "br_level": 1,
            "idle_connection_timeout": 30, "keepalive_requests": 100,
            "static_files_cache_time": 0, "server_header_field": "attome-test"
        },
        "database": {
            "host": "localhost", "port": 5555, "dbname": "unused", "user": "unused",
            "password": "unused", "schema": "public", "connection_number": 5, "timeout": 5.0
        },
        "cache": {
            "host": "localhost", "port": 6379, "password": "", "db": 0,
            "connection_pool_size": 4, "timeout": 2000, "l1_cache_size_mb": 8,
            "l1_cache_ttl_seconds": 60, "metadata_registry_enabled": true
        },
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
            "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
            "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
            "jwt_expiry_hours": 1, "oauth_google_client_id": "",
            "oauth_google_client_secret": "", "secure_cookies": false
        },
        "rate_limit": { "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {} },
        "observability": {
            "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "", "smtp_password": "",
            "smtp_from_address": "test@test.local", "smtp_from_name": "test",
            "smtp_use_tls": false, "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
        },
        "google_ai": {
            "api_key": "", "base_url": "https://example.invalid",
            "default_model": "none", "timeout_seconds": 1
        }
    }))
    .unwrap();
    assert!(config.security.csrf_enforce, "enforcement is the default");

    let request = |origin: &str| {
        axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/account")
            .header("cookie", "refresh_token=abc")
            .header("origin", origin)
            .header("sec-fetch-site", "cross-site")
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let series = r#"http_rejections_total{layer="csrf",reason="cross_site"}"#;
    let count = |text: &str| -> u64 {
        text.lines()
            .find_map(|line| line.strip_prefix(series))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0)
    };
    let before = count(&handle.render());

    let refused =
        attome_server::middleware::csrf::refusal(&config, &request("https://evil.example"))
            .expect("a cross-site cookie POST is refused");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        count(&handle.render()),
        before + 1,
        "one refusal, one count"
    );

    // A same-origin request is not refused and not counted.
    let allowed_origin = config
        .allowed_origins()
        .into_iter()
        .next()
        .unwrap_or_default();
    let same = axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/account")
        .header("cookie", "refresh_token=abc")
        .header("origin", allowed_origin)
        .header("sec-fetch-site", "same-origin")
        .body(axum::body::Body::empty())
        .unwrap();
    assert!(attome_server::middleware::csrf::refusal(&config, &same).is_none());
    assert_eq!(count(&handle.render()), before + 1);
}

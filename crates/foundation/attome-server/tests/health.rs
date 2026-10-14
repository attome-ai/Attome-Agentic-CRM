//! Integration test for the P1.3e health/readiness fix (folded into Plan
//! 1.2): `/health/ready` must carry the readiness verdict as an HTTP status
//! code, not just in the JSON body, and must gate on `registry_ready` (the
//! Plan 1.2 metadata-registry pre-warm flag) in addition to DB + Redis.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`DATABASE_URL`) and a Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`, default
//! `localhost:6379`); without `DATABASE_URL` each test prints SKIP.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5432/postgres"
//! $env:TEST_REDIS_HOST = "localhost"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-server --test health
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
use attome_server::{AppState, health};
use attome_testkit::skip_if_no_db;
use axum::Json;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use fred::interfaces::ClientLike;
use std::sync::atomic::Ordering;
use tower::ServiceExt;

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "public",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": true
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "test@test.local",
                "smtp_from_name": "test", "smtp_use_tls": false,
                "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
            }},
            "google_ai": {{
                "api_key": "", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            }},
            "llm_api": {{}},
            "external_api": {{}},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test.
async fn test_state() -> Option<AppState> {
    let url = attome_testkit::migrated_db_url()?;

    let config = test_config();
    let db = attome_testkit::connect(&url, 5).await;
    let db_readonly = db.clone();
    let db_migrator = db.clone();
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect redis");
    let redis_coordination = attome_cache::create_role_redis_pool(
        &config,
        attome_cache::CacheRole::Coordination,
        &redis,
    )
    .await
    .expect("connect coordination redis");
    let storage = attome_storage::create_storage_client(&config)
        .await
        .expect("build storage client");

    Some(AppState::new(
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    ))
}

#[tokio::test]
async fn ready_only_after_registry_ready_flag_is_set() {
    let state = skip_if_no_db!(test_state().await);

    // Before Plan 1.2's pre-warm would set it, registry_ready defaults to
    // false — /health/ready must reflect that in the status code, not just
    // the body (this is the exact P1.3e bug: today's code always returned 200).
    let (status, Json(body)) = health::health_ready(State(state.clone())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["registry"], false);

    // Once the pre-warm (simulated here) completes, the same DB/Redis state
    // reports ready.
    state.registry_ready.store(true, Ordering::Relaxed);
    // The verdict is memoised for READY_VERDICT_TTL; probe again after it.
    tokio::time::sleep(health::READY_VERDICT_TTL + std::time::Duration::from_millis(100)).await;
    let (status, Json(body)) = health::health_ready(State(state)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert_eq!(body["db"], true);
    assert_eq!(body["redis"], true);
    assert_eq!(body["redis_coordination"], true);
}

#[tokio::test]
async fn liveness_is_always_200_regardless_of_readiness() {
    let Json(body) = health::health_check().await;
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn version_reports_app_version_and_schema_state() {
    let state = skip_if_no_db!(test_state().await);

    let Json(body) = health::version(State(state)).await;
    assert_eq!(body["application_version"], env!("CARGO_PKG_VERSION"));
    // No node has set `configuration_version` in this test — the
    // back-compat fallback to `application_version` (see health::version's
    // doc comment; P-environment-promotion §5 step 20 amends the old
    // D-211 "always equal" contract).
    assert_eq!(body["configuration_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["components"]["server"], env!("CARGO_PKG_VERSION"));
    // No APP_REVISION env var set in this test process — the documented
    // "unknown" fallback, not a panic/error.
    assert_eq!(body["git_revision"], "unknown");
    // A real, migrated test database — schema_version must be a real applied
    // migration number, not null (that would mean schema_state's query
    // itself failed).
    assert!(body["schema_version"].is_number());
    assert_eq!(body["schema_dirty"], false);
}

#[tokio::test]
async fn version_reports_the_configuration_hash_once_something_sets_it() {
    let state = skip_if_no_db!(test_state().await);
    state
        .configuration_version
        .store(Some(std::sync::Arc::new("deadbeef".to_string())));

    let Json(body) = health::version(State(state)).await;
    assert_eq!(body["configuration_version"], "deadbeef");
    // Independent of the release version — the whole point of the hash.
    assert_ne!(body["configuration_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["application_version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn schema_check_is_opt_in_and_fails_closed_when_behind() {
    let mut state = skip_if_no_db!(test_state().await);
    state.registry_ready.store(true, Ordering::Relaxed);

    // No expected version attached (every existing boot path/test fixture
    // before P-migration-governance) must stay byte-identical: ready.
    let (status, Json(body)) = health::health_ready(State(state.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["schema"], true);

    // An expected version far beyond anything actually applied must flip
    // readiness to 503 -- this is the rolling-deploy case where a new pod's
    // compiled MIGRATOR is ahead of what the one-shot `migrate` job has
    // applied to the database yet.
    state.expected_schema_version = Some(i64::MAX);
    // The verdict is memoised for READY_VERDICT_TTL; probe again after it.
    tokio::time::sleep(health::READY_VERDICT_TTL + std::time::Duration::from_millis(100)).await;
    let (status, Json(body)) = health::health_ready(State(state)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["schema"], false);
}

// Ran for real 2026-08-09 against the `test` profile's Postgres/Redis (see the
// module doc comment for the exact invocation) — passes. It had carried a
// "never executed, only compiled" TODO until then, and in the meantime a stale
// drill server image reintroduced exactly the masked-500 behavior this test
// exists to catch, which nothing then contradicted. Keep it runnable.
#[tokio::test]
async fn liveness_route_survives_a_redis_outage() {
    // Regression test for the bug fixed by `attome_server::liveness_routes` /
    // `ServerBuilder::with_liveness_routes`: `/health` used to be merged into
    // the same bundle as every other route, so it passed through
    // `apply_pre_auth_rate_limit` like everything else. That layer calls
    // Redis unconditionally on every request and fails closed
    // (`attome_cache::rate_limit::check` maps a Redis timeout/error to
    // `AppError::internal`, i.e. HTTP 500) — so a Redis outage failed the
    // liveness probe on every node at once, and an orchestrator restarting
    // the whole fleet in response would just reconnect everything to the
    // same still-recovering Redis. This test drives the request through the
    // REAL router built by `ServerBuilder`, not the bare handler function
    // (the other tests in this file call `health::health_check`/
    // `health::health_ready` directly, which never exercises the middleware
    // stack and would not have caught this).
    let mut state = skip_if_no_db!(test_state().await);

    // Swap `redis_coordination` (the pool `pre_auth_rate_limit` reads via
    // `state.redis_coordination`) for a pool pointed at a closed local port.
    // Built directly with `fred` instead of `attome_cache::create_role_redis_pool`
    // because that helper awaits `wait_for_connect()`, which would itself
    // fail against a closed port and abort test setup before we even get to
    // the assertion — `pool.connect()` alone is fire-and-forget, mirroring a
    // pool that connected fine at boot and only later lost the connection
    // (the actual outage scenario this test simulates).
    let broken_redis_coordination = {
        let redis_config = fred::prelude::RedisConfig::from_url("redis://127.0.0.1:1/0")
            .expect("redis:// URL syntax is valid regardless of reachability");
        let pool = fred::prelude::Builder::from_config(redis_config)
            .with_performance_config(|c| {
                c.default_command_timeout = std::time::Duration::from_millis(200);
            })
            .build_pool(2)
            .expect("pool object construction doesn't require a live connection");
        pool.connect();
        pool
    };
    state.redis_coordination = broken_redis_coordination.into();

    let config = state.config.as_ref().clone();
    let liveness = attome_server::liveness_routes().with_state(state.clone());
    let app = attome_server::ServerBuilder::new(state, config)
        .with_liveness_routes(liveness)
        .build(|r| r); // no S2S layer needed for this attome-server-only assembly

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("well-formed request"),
        )
        .await
        .expect("router is infallible (axum::Router::oneshot never returns Err)");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/health must stay 200 even when redis_coordination is unreachable — \
         it must never be gated by apply_pre_auth_rate_limit"
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .expect("well-formed request"),
        )
        .await
        .expect("router is infallible (axum::Router::oneshot never returns Err)");

    assert_eq!(
        response.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "/health/ready must return its own dependency-specific 503 during a coordination outage, not the pre-auth limiter's generic 500"
    );
}

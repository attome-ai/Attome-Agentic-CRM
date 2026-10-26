//! S9-T7: a write that stops at any point is never applied twice by a retry
//! with the same idempotency key. Three crash points, each through the whole
//! composed stack (`ServerBuilder`, the real idempotency gate) and a real
//! table:
//!
//! - before the commit: nothing was written; the retry is refused while the
//!   first attempt's marker is fresh and reported `idempotency_outcome_unknown`
//!   once it is stale, and the handler never runs a second time;
//! - after the commit, before the response (the handler panics after
//!   committing, as a process dying there would): one row, and the retry is
//!   never executed, only refused or reported unknown;
//! - after the response (the client lost it): one row, and the retry gets the
//!   stored response back, marked `idempotency-replayed`.
//!
//! Z15-T7's fault injection covers the object store and Redis, not a
//! process stopping between commit and response, so the stop is a panic in
//! the handler at that point (the gate sees the same thing: a request that
//! started and never finished).
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`).
//!
//! ```powershell
//! cargo test -p attome --test idempotency_crash -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
/// Past a pending marker's stale age for a 1 s request timeout.
const PAST_STALE: Duration = Duration::from_secs(8);

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 65536, "request_timeout_secs": 1,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 10, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 16, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": false
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000 }},
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
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["{allowed_origin}"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        allowed_origin = ALLOWED_ORIGIN,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Handler entries, counted.
#[derive(Clone, Default)]
struct Calls(Arc<AtomicUsize>);

impl Calls {
    fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

const BEFORE_COMMIT: &str = "/api/v1/__crash/before_commit";
const AFTER_COMMIT: &str = "/api/v1/__crash/after_commit";
const COMMITTED: &str = "/api/v1/__crash/committed";

#[derive(Clone)]
struct Probe {
    state: AppState,
    calls: Calls,
}

async fn insert(state: &AppState, marker: &str, commit: bool) {
    let mut tx = attome_db::tx::begin(&state.db).await.expect("begin");
    sqlx::query("INSERT INTO idempotency_crash_probe (marker) VALUES ($1)")
        .bind(marker)
        .execute(&mut *tx)
        .await
        .expect("insert");
    if commit {
        tx.commit().await.expect("commit");
    }
}

async fn before_commit(
    State(probe): State<Probe>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> StatusCode {
    probe.calls.0.fetch_add(1, Ordering::SeqCst);
    insert(&probe.state, body["marker"].as_str().unwrap(), false).await;
    panic!("the process stops before the commit")
}

async fn after_commit(
    State(probe): State<Probe>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> StatusCode {
    probe.calls.0.fetch_add(1, Ordering::SeqCst);
    insert(&probe.state, body["marker"].as_str().unwrap(), true).await;
    panic!("the process stops after the commit, before the response")
}

async fn committed(
    State(probe): State<Probe>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (StatusCode, &'static str) {
    probe.calls.0.fetch_add(1, Ordering::SeqCst);
    insert(&probe.state, body["marker"].as_str().unwrap(), true).await;
    (StatusCode::CREATED, "created")
}

/// The composed app with the three probe routes, its state, a session
/// cookie and the handler counter.
async fn test_app() -> Option<(axum::Router, AppState, String, Calls)> {
    let mut config = test_config();
    point_config_at(&mut config, &attome_testkit::migrated_db_url()?);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
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
    let base = AppState::new(
        config.clone(),
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    let system = EngineSystem::builder(EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        .build()
        .await
        .expect("build EngineSystem");
    let base_state = system.state().base.clone();
    // A throwaway-database table of the test's own (guidelines §4's test
    // exemption).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS idempotency_crash_probe \
           (marker text NOT NULL, written_at timestamptz NOT NULL DEFAULT now())",
    )
    .execute(&base_state.db)
    .await
    .expect("create the probe table");
    let calls = Calls::default();
    let probe = Probe {
        state: base_state.clone(),
        calls: calls.clone(),
    };
    let routes = axum::Router::new()
        .route(BEFORE_COMMIT, axum::routing::post(before_commit))
        .route(AFTER_COMMIT, axum::routing::post(after_commit))
        .route(COMMITTED, axum::routing::post(committed))
        .with_state(probe);
    let app = attome_server::ServerBuilder::new(base_state.clone(), config)
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(attome_server::RouteBundle::new(routes))
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    let cookie = session_cookie(&base_state).await;
    Some((app, base_state, cookie, calls))
}

async fn session_cookie(state: &AppState) -> String {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $2 || '@test.invalid', true)",
    )
    .bind(user_id)
    .bind(format!("idem-crash-{user_id}"))
    .execute(&state.db)
    .await
    .expect("insert user_account");
    let now = chrono::Utc::now().timestamp();
    let claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 3600,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: state.config.auth.jwt_issuer.clone(),
        aud: state.config.jwt_audience().to_owned(),
        typ: attome_auth::TokenType::Session,
    };
    let token = attome_auth::create_token(&claims, &KeyRing::single(THROWAWAY_JWT_SECRET.into()))
        .expect("encode jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

fn request(path: &str, cookie: &str, key: &str, marker: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("cookie", cookie)
        .header("origin", ALLOWED_ORIGIN)
        .header("content-type", "application/json")
        .header("x-idempotency-key", key)
        .body(Body::from(
            serde_json::json!({ "marker": marker }).to_string(),
        ))
        .unwrap()
}

async fn error_code(res: axum::response::Response) -> String {
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

async fn rows(state: &AppState, marker: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM idempotency_crash_probe WHERE marker = $1")
        .bind(marker)
        .fetch_one(&state.db)
        .await
        .unwrap()
}

/// Runs the first attempt (which stops) and two retries with the same key:
/// one while the marker is fresh, one once it is stale. The handler runs
/// once; neither retry executes.
async fn crash_then_retry(
    app: &axum::Router,
    cookie: &str,
    calls: &Calls,
    path: &str,
    marker: &str,
) {
    let key = format!("crash-{}", Uuid::now_v7());
    let first = app
        .clone()
        .oneshot(request(path, cookie, &key, marker))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let calls_after_first = calls.get();

    let fresh = app
        .clone()
        .oneshot(request(path, cookie, &key, marker))
        .await
        .unwrap();
    assert_eq!(
        error_code(fresh).await,
        "conflict",
        "a fresh marker refuses"
    );
    tokio::time::sleep(PAST_STALE).await;
    let stale = app
        .clone()
        .oneshot(request(path, cookie, &key, marker))
        .await
        .unwrap();
    assert_eq!(
        error_code(stale).await,
        "idempotency_outcome_unknown",
        "a stale marker reports the outcome unknown, never runs again"
    );
    assert_eq!(
        calls.get(),
        calls_after_first,
        "no retry reached the handler"
    );
}

#[tokio::test]
async fn a_crash_before_the_commit_writes_nothing_and_is_not_retried() {
    let (app, state, cookie, calls) = skip_if_no_db!(test_app().await);
    let marker = format!("before-{}", Uuid::now_v7());
    crash_then_retry(&app, &cookie, &calls, BEFORE_COMMIT, &marker).await;
    assert_eq!(rows(&state, &marker).await, 0, "the rollback left nothing");
}

#[tokio::test]
async fn a_crash_after_the_commit_is_never_applied_twice() {
    let (app, state, cookie, calls) = skip_if_no_db!(test_app().await);
    let marker = format!("after-{}", Uuid::now_v7());
    crash_then_retry(&app, &cookie, &calls, AFTER_COMMIT, &marker).await;
    assert_eq!(rows(&state, &marker).await, 1, "exactly one write");
}

#[tokio::test]
async fn a_lost_response_is_replayed_not_reapplied() {
    let (app, state, cookie, calls) = skip_if_no_db!(test_app().await);
    let marker = format!("lost-{}", Uuid::now_v7());
    let key = format!("lost-{}", Uuid::now_v7());
    let first = app
        .clone()
        .oneshot(request(COMMITTED, &cookie, &key, &marker))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let before = calls.get();
    let retry = app
        .clone()
        .oneshot(request(COMMITTED, &cookie, &key, &marker))
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::CREATED, "the stored response");
    assert!(
        retry.headers().contains_key("idempotency-replayed"),
        "{:?}",
        retry.headers()
    );
    assert_eq!(calls.get(), before, "the retry did not run the handler");
    assert_eq!(rows(&state, &marker).await, 1, "exactly one write");
}

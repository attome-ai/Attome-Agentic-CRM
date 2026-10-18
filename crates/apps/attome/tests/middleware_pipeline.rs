//! Integration tests for the Plan 1.3 middleware pipeline assembly: the
//! explicit-allowlist CORS layer, the Redis-backed rate limiter, the
//! Redis-backed idempotency gate, and — the part that actually fixes the
//! historical bug — that every mounted route (including
//! `/api/v1/auth/api-keys`, previously a silent third mounting site that
//! skipped authz/body-limit/s2s entirely) passes through the same single
//! composed stack `main.rs` builds.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`, defaulting to `localhost:6379`) — panics with a clear
//! message if `DATABASE_URL` is unset, per the attome-api P1.8
//! testing-baseline convention this file mirrors. NOT wired into any CI run
//! yet; run manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p server --test middleware_pipeline -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome::auth;
use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";

fn test_config(anonymous_rpm: u32, authenticated_rpm: u32) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1024, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
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
            "rate_limit": {{
                "anonymous_rpm": {anonymous_rpm}, "authenticated_rpm": {authenticated_rpm}
            }},
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

/// Builds the exact same app `main.rs` assembles: liveness (`GET /health`,
/// mounted via `with_liveness_routes` so it skips the Redis-dependent gates
/// below) + health/readiness/version + XRM + api-keys (`system.core_routes()`,
/// api-keys now mounted from attome-security per Plan 1.6a) + auth
/// (register/login/google/logout/refresh), the latter three passed as
/// `RouteBundle`s to `ServerBuilder`, which applies inner → s2s →
/// PreAuthRateLimit → MutationGate → outer layers exactly once (D-047) —
/// `RouteBundle`'s
/// opaque inner `Router` means there's no way to bypass this and merge a
/// bundle in unlayered, unlike the old `/api/v1/auth/api-keys` bug this file
/// was written to catch.
async fn test_app(config: AppConfig) -> Option<(axum::Router, attome_server::AppState)> {
    test_app_with_extra_routes(config, None).await
}

/// Builds a test's extra routes once `AppState` exists — a route extracting
/// `Available<C>` needs it as router state.
type ExtraRoutes = Box<dyn FnOnce(&attome_server::AppState) -> axum::Router + Send>;

/// `test_app` plus one extra `RouteBundle`, for a test that needs a handler
/// shape no production route has (e.g. one that outlives `request_timeout`).
/// The extra routes go through `ServerBuilder` like every other bundle.
async fn test_app_with_extra_routes(
    mut config: AppConfig,
    extra: Option<ExtraRoutes>,
) -> Option<(axum::Router, attome_server::AppState)> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    point_config_at(&mut config, &throwaway_url);

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
    let db_readonly = db.clone();
    let db_migrator = db.clone();

    let base = AppState::new(
        config.clone(),
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    );
    let state = EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        .build()
        .await
        .expect("build EngineSystem");
    // D-143: entity_crud/bulk routes are now license-gated (now MODULE_CORE, was MODULE_ENTITY pre-D-222) —
    // grant every module so this suite exercises them the same way a fully
    // licensed deployment would.
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));

    let base_state = system.state().base.clone();
    // P-license-enforcement-hardening Phase 5 (d): public_routes now needs
    // the live license handle for seat enforcement.
    let license = system.state().modules.clone();

    let auth_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );

    let mut builder = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle);
    if let Some(extra) = extra {
        builder = builder.add_bundle(attome_server::RouteBundle::new(extra(&base_state)));
    }
    let app = builder.build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

async fn seed_user_and_cookie(state: &attome_server::AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("mw-pipeline-test-{user_id}"))
        .execute(&state.db)
        .await
        .expect("insert throwaway user_account");

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
    let signing_ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &signing_ring).expect("encode throwaway jwt");
    (
        user_id,
        format!("{}={token}", attome_auth::cookie::session_cookie_name(true)),
    )
}

/// A password account whose session token names a real refresh family (`sid`)
/// that already holds a step-up for `api_key_create`. Since attome-auth
/// hardening 2.1d (D-510) `POST /api/v1/auth/api-keys` serves only such a
/// session. The step-up is written straight to the throwaway database with the
/// values a verified password step-up writes; the step-up itself is covered by
/// `step_up_http.rs`.
async fn seed_stepped_up_session_cookie(state: &attome_server::AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let password_hash = attome_auth::hash_password_async(
        attome_auth::NewPassword::platform_generated("mw-pipeline-password-1"),
    )
    .await
    .expect("hash throwaway password");
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, password_hash, is_active) \
         VALUES ($1, $2, $2 || '@test.invalid', $3, true)",
    )
    .bind(user_id)
    .bind(format!("mw-pipeline-test-{user_id}"))
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");

    let issued = attome_auth::refresh::issue(
        &state.db,
        user_id,
        &attome_auth::auth_context::AuthContext::password(),
        attome_auth::refresh::RefreshLifetimes {
            idle_secs: state.config.refresh_token_expiry_secs(),
            absolute_secs: state.config.refresh_absolute_lifetime_secs(),
        },
        &state.pepper_ring(),
    )
    .await
    .expect("issue a refresh family");
    sqlx::query(
        "UPDATE refresh_token
         SET auth_time = NOW(), amr = ARRAY['pwd'], elevated_until = NOW() + INTERVAL '15 minutes'
         WHERE family_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(issued.family_id)
    .execute(&state.db)
    .await
    .expect("record a password step-up on the family");
    let token = attome_auth::accounts::issue_access_token(
        &state.db,
        user_id,
        issued.family_id,
        &KeyRing::single(THROWAWAY_JWT_SECRET.to_string()),
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        3600,
    )
    .await
    .expect("issue a session token naming the family");
    (
        user_id,
        format!("{}={token}", attome_auth::cookie::session_cookie_name(true)),
    )
}

// ── CORS ─────────────────────────────────────────────────────────────────────

/// A client address no other test in this run has used. The rate limiter keys
/// on the client IP, and a counter outlives the test that moved it for the
/// whole window, so tests sharing an address (the old pid-derived one) spend
/// each other's budgets when they run one after another.
fn unique_client_ip() -> String {
    // Documentation prefix 2001:db8::/32 (RFC 3849), never a real client.
    format!(
        "2001:db8::{:x}",
        uuid::Uuid::now_v7().as_u128() & 0xffff_ffff
    )
}

#[tokio::test]
async fn disallowed_origin_preflight_is_not_echoed() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/api/v1/auth/login")
        .header("origin", "http://evil.example")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    let allow_origin = res.headers().get("access-control-allow-origin");
    assert!(
        allow_origin.is_none(),
        "disallowed origin must never be echoed back in Access-Control-Allow-Origin"
    );
}

#[tokio::test]
async fn allowed_origin_is_echoed_with_credentials() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/api/v1/auth/login")
        .header("origin", ALLOWED_ORIGIN)
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    let allow_origin = res
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok());
    assert_eq!(allow_origin, Some(ALLOWED_ORIGIN));
    let allow_creds = res
        .headers()
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok());
    assert_eq!(allow_creds, Some("true"));
}

// ── Rate limit ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn anonymous_login_is_rate_limited_by_ip() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(3, 1000)).await);
    let ip = unique_client_ip();

    let mut last_status = StatusCode::OK;
    for _ in 0..5 {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", &ip)
            .body(Body::from(
                r#"{"email":"nobody@example.com","password":"wrong"}"#,
            ))
            .unwrap();
        last_status = app.clone().oneshot(req).await.expect("request").status();
    }

    assert_eq!(
        last_status,
        StatusCode::TOO_MANY_REQUESTS,
        "the 4th+ request from one IP within the 3 rpm anonymous limit must be rejected"
    );
}

/// M24/D-428: the public consent-capture route is bypass-listed (skips
/// authn/authz entirely) but never skips rate limiting — `rate_limit`
/// classifies it under its own `consent_capture` category
/// (`attome_server::middleware::rate_limit::RATE_LIMIT_CATEGORIES`) and,
/// deliberately, runs the SAME way regardless of the bypass list (see that
/// middleware's own doc comment). This proves the limiter actually rejects
/// before the handler's `Json<CaptureConsentBody>` extractor ever reads the
/// body: every request here carries a body that is not even valid JSON, so
/// a request that reached the handler would fail with a body-parse error
/// (400/422), never a plain 429 — the 4th+ request getting 429 is only
/// possible if the limiter intercepted first.
#[tokio::test]
async fn consent_capture_is_rate_limited_before_the_body_is_read() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(3, 1000)).await);
    let ip = unique_client_ip();

    let mut last_status = StatusCode::OK;
    for _ in 0..5 {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/consents/capture")
            .header("content-type", "application/json")
            .header("x-forwarded-for", &ip)
            // Deliberately not valid JSON, let alone a valid
            // CaptureConsentBody — if this ever reached the handler it would
            // 400/422, never 429.
            .body(Body::from("not valid json"))
            .unwrap();
        last_status = app.clone().oneshot(req).await.expect("request").status();
    }

    assert_eq!(
        last_status,
        StatusCode::TOO_MANY_REQUESTS,
        "the 4th+ request from one IP within the 3 rpm anonymous limit must be rejected by the \
         rate limiter itself, before the malformed body is ever read"
    );
}

/// P-rate-limit-atomicity §4.2: a request classifies by (method, route
/// template), so an unrelated route never draws down the `credential`
/// category's budget for the same caller. `/api/v1/auth/login` classifies as
/// `credential`; `/api/v1/auth/register/config` (GET, unlisted in
/// `RATE_LIMIT_CATEGORIES`) falls to the `api` default — a distinct bucket.
#[tokio::test]
async fn different_categories_from_the_same_ip_do_not_share_a_budget() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(3, 1000)).await);
    let ip = unique_client_ip();
    let peer = unique_peer();

    for _ in 0..3 {
        let req = Request::builder()
            .extension(axum::extract::ConnectInfo(peer))
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", &ip)
            .body(Body::from(
                r#"{"email":"nobody@example.com","password":"wrong"}"#,
            ))
            .unwrap();
        app.clone().oneshot(req).await.expect("request");
    }
    let exhausted_req = Request::builder()
        .extension(axum::extract::ConnectInfo(peer))
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .header("x-forwarded-for", &ip)
        .body(Body::from(
            r#"{"email":"nobody@example.com","password":"wrong"}"#,
        ))
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(exhausted_req)
            .await
            .expect("request")
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the credential category must now be exhausted for this IP"
    );

    let other_category_req = Request::builder()
        .extension(axum::extract::ConnectInfo(peer))
        .method("GET")
        .uri("/api/v1/auth/register/config")
        .header("x-forwarded-for", &ip)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone()
            .oneshot(other_category_req)
            .await
            .expect("request")
            .status(),
        StatusCode::OK,
        "an unrelated (api-default-category) route must not be rejected just \
         because this IP's `credential` budget is exhausted"
    );
}

/// P-rate-limit-atomicity §4.1/§4.3: `Retry-After`/`X-RateLimit-*` are
/// derived from the atomic script's own state, never a hardcoded constant.
#[tokio::test]
async fn a_rejected_request_carries_real_rate_limit_headers() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1, 1000)).await);
    let ip = unique_client_ip();

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", &ip)
            .body(Body::from(
                r#"{"email":"nobody@example.com","password":"wrong"}"#,
            ))
            .unwrap()
    };

    let first = app.clone().oneshot(make_req()).await.expect("request");
    assert_eq!(
        first
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok()),
        Some("0"),
        "the sole admitted request against limit=1 must report 0 remaining"
    );

    let rejected = app.clone().oneshot(make_req()).await.expect("request");
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = rejected
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .expect("Retry-After must be present and a valid integer");
    assert!(
        retry_after > 0 && retry_after <= 60,
        "Retry-After must be derived from the window, not a hardcoded value, got {retry_after}"
    );
    assert_eq!(
        rejected
            .headers()
            .get("x-ratelimit-limit")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
}

// ── Idempotency ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn duplicate_idempotency_key_replays_first_response() {
    let (app, state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    let (_user_id, cookie) = seed_stepped_up_session_cookie(&state).await;
    let idem_key = format!("idem-test-{}", Uuid::now_v7());
    // Unique per run — a fixed literal name would accumulate rows across
    // repeated test runs against the same shared `attomedb_test` and make
    // this count assertion flaky (standing P1.8 convention: never assert
    // counts that aren't scoped to this test's own uniquely-named data).
    let key_name = format!("idem-test-key-{}", Uuid::now_v7());

    let make_req = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/auth/api-keys")
            .header("cookie", &cookie)
            // csrf_protect (P-cookie-csrf-hardening) rejects a cookie-
            // authenticated unsafe-method request that carries neither a safe
            // Sec-Fetch-Site nor an allow-listed Origin — an in-process
            // oneshot() request has neither by default, unlike a real browser
            // request. Same origin already wired into test_config()'s
            // cors.allowed_origins as the disallowed_origin_preflight test
            // above uses.
            .header("origin", ALLOWED_ORIGIN)
            .header("content-type", "application/json")
            .header("x-idempotency-key", &idem_key)
            .body(Body::from(format!(r#"{{"name":"{key_name}"}}"#)))
            .unwrap()
    };

    let res1 = app
        .clone()
        .oneshot(make_req())
        .await
        .expect("first request");
    assert_eq!(res1.status(), StatusCode::CREATED);
    let body1 = axum::body::to_bytes(res1.into_body(), usize::MAX)
        .await
        .unwrap();

    let res2 = app
        .clone()
        .oneshot(make_req())
        .await
        .expect("second request");
    assert_eq!(res2.status(), StatusCode::CREATED);
    let body2 = axum::body::to_bytes(res2.into_body(), usize::MAX)
        .await
        .unwrap();

    assert_eq!(
        body1, body2,
        "replayed response must be byte-identical to the original"
    );

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_key WHERE name = $1")
        .bind(&key_name)
        .fetch_one(&state.db)
        .await
        .expect("count api keys");
    assert_eq!(
        count, 1,
        "the handler must not have re-run — only one row created"
    );
}

// ── Server timeout (attome-server hardening P1.4) ──────────────────────────────

/// A mutating route that outlives `request_timeout` and counts how often its
/// body was entered, plus a fast sibling that never times out. Mounted as an
/// extra `RouteBundle`, so both run the full production stack.
fn timeout_test_routes(slow_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> axum::Router {
    axum::Router::new()
        .route(
            "/api/v1/__timeout_test/slow",
            axum::routing::post(move || {
                let slow_calls = slow_calls.clone();
                async move {
                    slow_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    StatusCode::CREATED
                }
            }),
        )
        .route(
            "/api/v1/__timeout_test/fast",
            axum::routing::post(|| async { StatusCode::CREATED }),
        )
}

#[tokio::test]
async fn request_timeout_returns_json_503_and_keeps_the_idempotency_key() {
    let mut config = test_config(1000, 1000);
    config.app.request_timeout_secs = 1;
    let slow_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (app, state) = skip_if_no_db!(
        test_app_with_extra_routes(config, {
            let slow_calls = slow_calls.clone();
            Some(Box::new(move |_| timeout_test_routes(slow_calls)))
        })
        .await
    );
    let (_user_id, cookie) = seed_user_and_cookie(&state).await;
    let idem_key = format!("timeout-test-{}", Uuid::now_v7());

    let make_req = |uri: &str, key: &str| {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("cookie", &cookie)
            .header("origin", ALLOWED_ORIGIN)
            .header("content-type", "application/json")
            .header("x-idempotency-key", key)
            .body(Body::from("{}"))
            .unwrap()
    };

    let res = app
        .clone()
        .oneshot(make_req("/api/v1/__timeout_test/slow", &idem_key))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let headers = res.headers().clone();
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("x-request-id header")
        .to_owned();
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some(ALLOWED_ORIGIN)
    );
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
    assert_eq!(json["error"], "server_timeout");
    assert_eq!(json["request_id"], request_id);
    assert_eq!(slow_calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    // A timeout is not a known-not-applied outcome: the key must not have been
    // released, so an immediate same-key retry is refused instead of running
    // the handler again. (What a retry gets once the marker is stale is P1.1's
    // concern — race scenario 4.)
    let retry = app
        .clone()
        .oneshot(make_req("/api/v1/__timeout_test/slow", &idem_key))
        .await
        .expect("retry");
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    let retry_body = axum::body::to_bytes(retry.into_body(), usize::MAX)
        .await
        .unwrap();
    let retry_json: serde_json::Value = serde_json::from_slice(&retry_body).unwrap();
    assert_eq!(retry_json["error"], "conflict");
    assert_eq!(
        slow_calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the timed-out handler must not run again"
    );

    // A request that finishes inside the timeout is untouched.
    let fast = app
        .oneshot(make_req(
            "/api/v1/__timeout_test/fast",
            &format!("timeout-test-fast-{}", Uuid::now_v7()),
        ))
        .await
        .expect("fast request");
    assert_eq!(fast.status(), StatusCode::CREATED);
}

// ── Idempotency outcome states (attome-server hardening P1.1) ─────────────────
//
// The race scenarios through the full production stack and real Redis. The
// in-memory store tests in `attome_server::middleware::idempotency` cover the
// same state machine with injected write failures; these prove the assembled
// pipeline — panic and timeout layers outside the gate, extractor rejections
// inside it — behaves the same way.

type Calls = std::sync::Arc<std::sync::atomic::AtomicUsize>;

fn count(calls: &Calls) -> usize {
    calls.load(std::sync::atomic::Ordering::SeqCst)
}

/// Past a `pending` marker's stale age for a 1s request timeout
/// (`request_timeout + 5s` grace), plus margin for whole-second timestamps.
const PAST_STALE: std::time::Duration = std::time::Duration::from_secs(8);

async fn idem_app(
    extra: ExtraRoutes,
    request_timeout_secs: u64,
    replay_max_bytes: usize,
) -> Option<(axum::Router, AppState, String)> {
    let mut config = test_config(1000, 1000);
    config.app.request_timeout_secs = request_timeout_secs;
    config.idempotency.replay_max_bytes = replay_max_bytes;
    config.database.connection_number = 20;
    // authn's revocation and epoch checks each take a Redis round trip with a
    // 300 ms bound and fail closed, so a 4-connection pool under 100
    // simultaneous requests turns some of them into 401s before the gate.
    config.cache.connection_pool_size = 64;
    let (app, state) = test_app_with_extra_routes(config, Some(extra)).await?;
    let (_user_id, cookie) = seed_user_and_cookie(&state).await;
    Some((app, state, cookie))
}

fn idem_req(uri: &str, cookie: &str, key: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", ALLOWED_ORIGIN)
        .header("content-type", "application/json")
        .header("x-idempotency-key", key)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn error_code_of(res: axum::response::Response) -> String {
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// A POST route that counts entries into its body, then awaits `f`.
fn counted<F, Fut, R>(calls: Calls, f: F) -> axum::routing::MethodRouter
where
    F: Fn() -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = R> + Send,
    R: axum::response::IntoResponse,
{
    axum::routing::post(move || {
        let calls = calls.clone();
        let f = f.clone();
        async move {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            f().await.into_response()
        }
    })
}

fn single_route(path: &'static str, route: axum::routing::MethodRouter) -> ExtraRoutes {
    Box::new(move |_| axum::Router::new().route(path, route))
}

/// Scenario 1.
#[tokio::test]
async fn idempotency_a_hundred_concurrent_identical_requests_run_the_handler_once() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/concurrent";
    let route = counted(calls.clone(), || async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        StatusCode::CREATED
    });
    let (app, _state, cookie) =
        skip_if_no_db!(idem_app(single_route(path, route), 30, 1 << 20).await);
    let key = format!("concurrent-{}", Uuid::now_v7());

    let handles: Vec<_> = (0..100)
        .map(|_| {
            let app = app.clone();
            let req = idem_req(path, &cookie, &key, "{}");
            tokio::spawn(async move {
                let res = app.oneshot(req).await.expect("request");
                let status = res.status();
                (status, error_code_of(res).await)
            })
        })
        .collect();
    let mut tally: std::collections::BTreeMap<String, usize> = Default::default();
    for handle in handles {
        let (status, code) = handle.await.expect("task");
        *tally
            .entry(format!("{} {code}", status.as_u16()))
            .or_default() += 1;
    }
    eprintln!("concurrent idempotency outcome tally: {tally:?}");

    // The invariant: one execution, however the other 99 were answered. The
    // handler only ever returns 201, so any other status is a request refused
    // before it ran (a duplicate, or a fail-closed dependency check under load).
    assert_eq!(count(&calls), 1, "tally: {tally:?}");
    assert!(
        tally.keys().any(|outcome| outcome.starts_with("201")),
        "the one execution must have answered someone: {tally:?}"
    );
}

/// Scenarios 2 and 3: while the first request is still inside its handler —
/// including after its write, before the gate stores the response — an
/// identical request is `conflict` and a different body is `idempotency_conflict`.
#[tokio::test]
async fn idempotency_an_in_flight_request_refuses_duplicates_by_body() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/in_flight";
    let route = counted(calls.clone(), || async {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        StatusCode::CREATED
    });
    let (app, _state, cookie) =
        skip_if_no_db!(idem_app(single_route(path, route), 30, 1 << 20).await);
    let key = format!("in-flight-{}", Uuid::now_v7());

    let first = tokio::spawn({
        let app = app.clone();
        let req = idem_req(path, &cookie, &key, "{}");
        async move { app.oneshot(req).await.expect("first").status() }
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let same = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(error_code_of(same).await, "conflict");
    let different = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, r#"{"other":true}"#))
        .await
        .unwrap();
    assert_eq!(error_code_of(different).await, "idempotency_conflict");

    assert_eq!(first.await.expect("task"), StatusCode::CREATED);
    assert_eq!(count(&calls), 1);
}

/// The `execution` id a principal-isolation handler put in its 201 body.
async fn execution_of(res: axum::response::Response) -> String {
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
    json["execution"].as_str().expect("execution id").to_owned()
}

/// Phase 1 security acceptance: the Redis tier scopes a key by principal. A
/// second user reusing the first user's key — while the first request is still
/// in flight, after it completed, with the same body or a different one — runs
/// as its own execution, never receives the first user's cached response, and
/// never sees the first user's key state (`conflict`/`idempotency_conflict`).
#[tokio::test]
async fn idempotency_a_key_is_scoped_to_its_principal() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/principal";
    let route = counted(calls.clone(), || async {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        (
            StatusCode::CREATED,
            axum::Json(serde_json::json!({ "execution": Uuid::now_v7() })),
        )
    });
    let (app, state, cookie_a) =
        skip_if_no_db!(idem_app(single_route(path, route), 30, 1 << 20).await);
    let (_user_b, cookie_b) = seed_user_and_cookie(&state).await;
    let (_user_c, cookie_c) = seed_user_and_cookie(&state).await;
    let key = format!("principal-{}", Uuid::now_v7());

    // B, same key and body, while A is still inside its handler.
    let first_a = tokio::spawn({
        let app = app.clone();
        let req = idem_req(path, &cookie_a, &key, "{}");
        async move { app.oneshot(req).await.expect("A") }
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let b_res = app
        .clone()
        .oneshot(idem_req(path, &cookie_b, &key, "{}"))
        .await
        .unwrap();
    let b_execution = execution_of(b_res).await;
    let a_execution = execution_of(first_a.await.expect("task")).await;
    assert_ne!(
        a_execution, b_execution,
        "B must run its own execution, not receive A's"
    );
    assert_eq!(count(&calls), 2);

    // Each principal replays only its own stored response.
    for (cookie, expected) in [(&cookie_a, &a_execution), (&cookie_b, &b_execution)] {
        let replay = app
            .clone()
            .oneshot(idem_req(path, cookie, &key, "{}"))
            .await
            .unwrap();
        assert_eq!(&execution_of(replay).await, expected);
    }
    assert_eq!(count(&calls), 2, "a replay must not run the handler");

    // A third principal with a different digest is a fresh request, not an
    // `idempotency_conflict` against A's or B's record.
    let c_res = app
        .clone()
        .oneshot(idem_req(path, &cookie_c, &key, r#"{"other":true}"#))
        .await
        .unwrap();
    let c_execution = execution_of(c_res).await;
    assert!(c_execution != a_execution && c_execution != b_execution);
    assert_eq!(count(&calls), 3);
}

/// Scenario 4.
#[tokio::test]
async fn idempotency_a_timed_out_request_is_outcome_unknown_once_stale() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/timeout";
    let route = counted(calls.clone(), || async {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        StatusCode::CREATED
    });
    let (app, _state, cookie) =
        skip_if_no_db!(idem_app(single_route(path, route), 1, 1 << 20).await);
    let key = format!("timeout-{}", Uuid::now_v7());

    let first = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(error_code_of(first).await, "server_timeout");

    tokio::time::sleep(PAST_STALE).await;
    let retry = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(error_code_of(retry).await, "idempotency_outcome_unknown");
    assert_eq!(count(&calls), 1);
}

/// Scenario 5.
#[tokio::test]
async fn idempotency_a_client_disconnect_never_lets_a_retry_run() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/disconnect";
    let route = counted(calls.clone(), || async {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        StatusCode::CREATED
    });
    let (app, _state, cookie) =
        skip_if_no_db!(idem_app(single_route(path, route), 1, 1 << 20).await);
    let key = format!("disconnect-{}", Uuid::now_v7());

    // Dropping the in-flight future is what a client disconnect does to the
    // request under axum::serve.
    let dropped = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        app.clone().oneshot(idem_req(path, &cookie, &key, "{}")),
    )
    .await;
    assert!(
        dropped.is_err(),
        "the request future was dropped mid-handler"
    );
    assert_eq!(count(&calls), 1, "the handler had started");

    let immediate = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(error_code_of(immediate).await, "conflict");

    tokio::time::sleep(PAST_STALE).await;
    let stale = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(error_code_of(stale).await, "idempotency_outcome_unknown");
    assert_eq!(count(&calls), 1);
}

async fn panicking_mutation() -> StatusCode {
    panic!("simulated panic after a write")
}

/// Scenario 6.
#[tokio::test]
async fn idempotency_a_panicking_handler_is_outcome_unknown_once_stale() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/panic";
    let route = counted(calls.clone(), panicking_mutation);
    let (app, _state, cookie) =
        skip_if_no_db!(idem_app(single_route(path, route), 1, 1 << 20).await);
    let key = format!("panic-{}", Uuid::now_v7());

    let first = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(error_code_of(first).await, "internal_error");

    let immediate = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(error_code_of(immediate).await, "conflict");

    tokio::time::sleep(PAST_STALE).await;
    let stale = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(error_code_of(stale).await, "idempotency_outcome_unknown");
    assert_eq!(count(&calls), 1);
}

/// Scenario 7.
#[tokio::test]
async fn idempotency_an_oversized_response_reaches_the_client_and_is_not_replayed() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/oversized";
    let big = "x".repeat(64);
    let route = counted(calls.clone(), move || {
        let big = big.clone();
        async move { (StatusCode::CREATED, big) }
    });
    let (app, _state, cookie) = skip_if_no_db!(idem_app(single_route(path, route), 30, 16).await);
    let key = format!("oversized-{}", Uuid::now_v7());

    let first = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(first.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.len(), 64, "the client gets the whole response");

    let retry = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::CONFLICT);
    assert_eq!(error_code_of(retry).await, "idempotency_replay_unavailable");
    assert_eq!(count(&calls), 1);
}

/// Scenario 8: the `Available<C>` extractor refuses before the handler body,
/// so the key is released and a retry after recovery runs.
#[tokio::test]
async fn idempotency_a_capability_extractor_rejection_releases_the_key() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/capability";
    let extra: ExtraRoutes = {
        let calls = calls.clone();
        Box::new(move |state: &AppState| {
            axum::Router::new()
                .route(
                    path,
                    axum::routing::post(
                        move |_cap: attome_server::capability::Available<
                            attome_server::capability::ObjectStorage,
                        >| {
                            let calls = calls.clone();
                            async move {
                                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                StatusCode::CREATED
                            }
                        },
                    ),
                )
                .with_state(state.clone())
        })
    };
    let (app, state, cookie) = skip_if_no_db!(idem_app(extra, 30, 1 << 20).await);
    let key = format!("capability-{}", Uuid::now_v7());

    for _ in 0..2 {
        state.capabilities.record(
            attome_server::Capability::ObjectStorage,
            attome_server::ProbeOutcome::Unreachable,
        );
    }
    let refused = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code_of(refused).await, "capability_unavailable");
    assert_eq!(count(&calls), 0);

    state.capabilities.record(
        attome_server::Capability::ObjectStorage,
        attome_server::ProbeOutcome::Reachable,
    );
    let retry = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::CREATED);
    assert_eq!(count(&calls), 1);
}

/// Scenario 9.
#[tokio::test]
async fn idempotency_an_internal_error_is_outcome_unknown_and_refuses_a_different_body() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/internal";
    let route = counted(calls.clone(), || async {
        attome_types::AppError::Internal("simulated failure after a write".into())
    });
    let (app, _state, cookie) =
        skip_if_no_db!(idem_app(single_route(path, route), 30, 1 << 20).await);
    let key = format!("internal-{}", Uuid::now_v7());

    let first = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let retry = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(error_code_of(retry).await, "idempotency_outcome_unknown");
    let different = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, r#"{"other":true}"#))
        .await
        .unwrap();
    assert_eq!(error_code_of(different).await, "idempotency_conflict");
    assert_eq!(count(&calls), 1);
}

/// Scenario 10: axum's `Json` rejection is a 4xx produced inside the gate,
/// so the key is released and a corrected retry under the same key runs.
#[tokio::test]
async fn idempotency_a_json_extractor_rejection_releases_the_key() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/json";
    let extra: ExtraRoutes = {
        let calls = calls.clone();
        Box::new(move |_| {
            axum::Router::new().route(
                path,
                axum::routing::post(move |_body: axum::Json<serde_json::Value>| {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        StatusCode::CREATED
                    }
                }),
            )
        })
    };
    let (app, _state, cookie) = skip_if_no_db!(idem_app(extra, 30, 1 << 20).await);
    let key = format!("json-{}", Uuid::now_v7());

    let malformed = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{not json"))
        .await
        .unwrap();
    assert!(
        malformed.status().is_client_error(),
        "{}",
        malformed.status()
    );
    assert_eq!(count(&calls), 0);

    let valid = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(valid.status(), StatusCode::CREATED);
    assert_eq!(count(&calls), 1);
}

/// Scenario 11: the same `capability_unavailable` error raised from handler
/// logic may follow a write, so it carries no not-applied marker.
#[tokio::test]
async fn idempotency_a_capability_error_raised_in_the_handler_is_outcome_unknown() {
    let calls = Calls::default();
    let path = "/api/v1/__idem_test/capability_in_body";
    let route = counted(calls.clone(), || async {
        attome_types::AppError::CapabilityUnavailable("object_storage")
    });
    let (app, _state, cookie) =
        skip_if_no_db!(idem_app(single_route(path, route), 30, 1 << 20).await);
    let key = format!("capability-in-body-{}", Uuid::now_v7());

    let first = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);

    let retry = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(error_code_of(retry).await, "idempotency_outcome_unknown");
    assert_eq!(count(&calls), 1);
}

// ── Body limit before auth ───────────────────────────────────────────────────

#[tokio::test]
async fn oversized_body_is_rejected_before_authn_runs() {
    // test_config sets max_body_size_bytes: 1024
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);

    let oversized = "x".repeat(4096);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/api-keys") // protected route, no auth header supplied at all
        .header("content-type", "application/json")
        // A real HTTP client always sends Content-Length for a non-chunked
        // body — `hyper` populates it on the wire for a real request, but
        // an in-process `oneshot()` call skips that, so it must be set here
        // explicitly to accurately simulate a real oversized request (the
        // proactive `Content-Length` guard in `apply_outer_layers` checks
        // this header rather than reading the body).
        .header("content-length", oversized.len().to_string())
        .header("origin", ALLOWED_ORIGIN)
        .body(Body::from(oversized))
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "body-limit must reject before authn ever runs (would otherwise be 401)"
    );
    // P1.5: the rejection now sits inside RequestId/Trace/CORS, so it carries
    // the same envelope as every other framework error.
    let request_id = res
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("x-request-id header")
        .to_owned();
    assert_eq!(
        res.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some(ALLOWED_ORIGIN)
    );
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
    assert_eq!(json["error"], "payload_too_large");
    assert_eq!(json["request_id"], request_id);
}

/// P1.5. A body with no `Content-Length` passes the header guard; when the
/// idempotency gate buffers it past `max_body_size_bytes` (1024 in
/// `test_config`), the answer is the same JSON `payload_too_large` envelope,
/// not a bare 413.
#[tokio::test]
async fn undeclared_oversized_body_read_by_the_idempotency_gate_gets_json_413() {
    let (app, state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    let (_user_id, cookie) = seed_user_and_cookie(&state).await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/api-keys")
        .header("cookie", &cookie)
        .header("origin", ALLOWED_ORIGIN)
        .header("content-type", "application/json")
        .header("x-idempotency-key", format!("oversized-{}", Uuid::now_v7()))
        // No content-length header: an in-process oneshot() never adds one.
        .body(Body::from("x".repeat(4096)))
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(res.headers().contains_key("x-request-id"));
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).expect("JSON body");
    assert_eq!(json["error"], "payload_too_large");
}

// ── Mutation gate (P-audit-chain-hardening item (e), ingest circuit breaker) ──

#[tokio::test]
async fn tripped_backlog_breaker_rejects_a_mutating_request_with_503() {
    let (app, state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    state
        .audit_ingest_backlog_exceeded
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/api-keys")
        .header("origin", ALLOWED_ORIGIN)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"should-never-be-created"}"#))
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a mutating request must be rejected while the backlog breaker is tripped, \
         even before authn runs (no session cookie was supplied here either)"
    );
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "overloaded");
}

#[tokio::test]
async fn tripped_backlog_breaker_never_blocks_a_read() {
    let (app, state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    state
        .audit_ingest_backlog_exceeded
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/api-keys")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "a GET must still reach authn (401 for no cookie) rather than being \
         short-circuited by the mutation gate — the breaker only ever \
         narrows a request's success path for a mutating verb, never widens \
         it, so this must not become an accidental auth bypass either"
    );
}

// ── Authoring gate (P-environment-promotion Phase 0) ────────────────────────
//
// `test_config` deserializes without `AppConfig::validate()`, so flipping
// `app.deployment_profile` to "production" here exercises the gate without
// also having to satisfy `validate_production_profile`'s TLS/approval/etc.
// floor — the gate keys on the profile string alone. Every request below is
// sent with NO session cookie on purpose: the gate sits outside authn (same
// slot as the mutation gate), so a refused write is 403
// `metadata_authoring_locked` and an admitted one falls through to authn's
// 401 — which is exactly the observable difference these tests pin.

fn production_config() -> AppConfig {
    let mut config = test_config(1000, 1000);
    config.app.deployment_profile = "production".into();
    config
}

/// The `error` code of a JSON error body; empty when the body is empty or
/// not JSON (the router's bare 404 fallback for an unmounted path has no
/// body at all).
async fn error_code(res: axum::response::Response) -> String {
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|json| json["error"].as_str().map(str::to_string))
        .unwrap_or_default()
}

#[tokio::test]
async fn authoring_gate_refuses_metadata_write_on_production_profile() {
    let (app, _state) = skip_if_no_db!(test_app(production_config()).await);

    for path in [
        "/api/v1/admin/entities",
        "/api/v1/admin/queries",
        "/api/v1/admin/views",
        "/api/v1/sidebar/admin",
        "/api/v1/admin/security/roles",
        "/api/v1/workflow/definitions",
        // B4 (BSV-F02): a bundle-applied section.
        "/api/v1/admin/apps",
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("origin", ALLOWED_ORIGIN)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"should":"never-be-parsed"}"#))
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("request");
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "POST {path} must be refused by the authoring gate on the production profile \
             (before authn — no cookie was supplied, and the answer is still 403 not 401)"
        );
        assert_eq!(error_code(res).await, "metadata_authoring_locked", "{path}");
    }
}

/// The same writes on the development profile never see the gate: with no
/// cookie they fall through to authn's 401, proving the profile — and only
/// the profile — is what locks authoring.
#[tokio::test]
async fn authoring_gate_is_a_no_op_on_development_profile() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("origin", ALLOWED_ORIGIN)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"should":"reach-authn"}"#))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "on the development profile a metadata write must reach authn untouched"
    );
}

#[tokio::test]
async fn authoring_gate_never_blocks_reads() {
    let (app, _state) = skip_if_no_db!(test_app(production_config()).await);

    for path in [
        "/api/v1/admin/entities",
        "/api/v1/admin/views",
        "/api/v1/sidebar/admin",
        "/api/v1/admin/security/roles",
    ] {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("request");
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "GET {path} must still reach authn (401 for no cookie) on the production \
             profile — the gate only narrows mutating verbs, never reads"
        );
    }
}

/// The bundle import/apply surface is how metadata reaches production, so the
/// gate must never stand in front of it. The route does not exist yet, so an
/// admitted request lands on the router's bare 404 fallback — what matters is
/// that it is NOT the gate's 403. Once the import route is mounted this
/// naturally tightens to authn's 401.
#[tokio::test]
async fn authoring_gate_allows_metadata_import_prefix() {
    let (app, _state) = skip_if_no_db!(test_app(production_config()).await);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/metadata/import")
        .header("origin", ALLOWED_ORIGIN)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"format":"attome-bundle/v1"}"#))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    let status = res.status();
    let code = error_code(res).await;
    assert_ne!(
        code, "metadata_authoring_locked",
        "the import prefix must be exempt from the authoring gate (got {status})"
    );
    assert_ne!(status, StatusCode::FORBIDDEN);
}

/// Break-glass: while `attome-server:break-glass:window` exists in the
/// coordination Redis, a production metadata write passes the gate (and, with
/// no cookie, falls through to authn's 401). The key is set with a short TTL
/// and deleted afterwards so a failed assertion cannot leave the shared test
/// Redis in an "open" state for the refusal test above — which is also why
/// this file's header says to run it with `--test-threads=1`.
#[tokio::test]
async fn authoring_gate_admits_a_write_while_the_break_glass_window_is_open() {
    let (app, state) = skip_if_no_db!(test_app(production_config()).await);
    let key = attome_server::middleware::authoring_gate::BREAK_GLASS_WINDOW_KEY;
    state
        .redis_coordination
        .set(
            &key,
            &("1").to_string(),
            Some(std::time::Duration::from_secs(10)),
        )
        .await
        .expect("open break-glass window");

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("origin", ALLOWED_ORIGIN)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"should":"reach-authn"}"#))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    let status = res.status();

    state
        .redis_coordination
        .del(key)
        .await
        .expect("close break-glass window");

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "with the break-glass window open the write must pass the gate and reach authn"
    );
}

// ── Deprecation/Sunset headers (P-api-contract Phase 5) ─────────────────────

/// The pre-2026-07-13 unprefixed `/api/sidebar/get` alias was retired (C-25)
/// once its sunset date (2026-08-29) passed — the route is deleted from
/// `attome_api::sidebar::routes()`, not merely unlisted from
/// `attome_server::middleware::deprecation::DEPRECATED_PATHS`.
///
/// The staff fallback runs inside authn (D-585, attome-server A5), so an
/// anonymous caller gets 401 for a path that exists and one that does not
/// alike — no route-existence oracle. That makes an anonymous request unable
/// to tell "gone" from "protected", so the proof authenticates: a signed-in
/// caller reaching the JSON `not_found` fallback is what shows the route is
/// gone. No `deprecation`/`sunset` header on a route that no longer exists.
#[tokio::test]
async fn retired_sidebar_alias_is_gone() {
    let (app, state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    let (_user_id, cookie) = seed_user_and_cookie(&state).await;

    let anonymous = Request::builder()
        .method("GET")
        .uri("/api/sidebar/get")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(anonymous).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "an anonymous caller must not learn whether a path exists"
    );

    let req = Request::builder()
        .method("GET")
        .uri("/api/sidebar/get")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "the retired unprefixed sidebar path must be gone, not merely deprecated"
    );
    assert!(
        res.headers().get("deprecation").is_none(),
        "a route that no longer exists must not carry a deprecation header"
    );
}

#[tokio::test]
async fn v1_sidebar_path_does_not_carry_deprecation_headers() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/sidebar/get")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    assert!(
        res.headers().get("deprecation").is_none(),
        "the current /api/v1 sidebar path must NOT be marked deprecated"
    );
    assert!(
        res.headers().get("sunset").is_none(),
        "the current /api/v1 sidebar path must NOT carry a Sunset header"
    );
}

// ── Liveness bypass (Redis-outage-safe /health) ──────────────────────────────

/// Full-stack proof that `GET /health` never enters `apply_pre_auth_rate_limit`
/// or `apply_inner_layers::rate_limit` — if it did, the response would carry
/// `X-RateLimit-*` headers (`apply_rate_limit_headers`, set on every admitted
/// request that passes through either limiter). The Redis-outage scenario
/// itself (a broken `redis_coordination` pool must not turn `/health` into a
/// 500) is covered at the `attome-server` level in
/// `attome-server/tests/health.rs::liveness_route_survives_a_redis_outage`,
/// which isolates the assertion from this file's heavier XRM-system setup.
#[tokio::test]
async fn liveness_route_bypasses_rate_limiting_through_the_full_stack() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers().get("x-ratelimit-remaining").is_none(),
        "/health must never pass through either rate limiter — a present \
         X-RateLimit-* header would mean it's still gated by Redis"
    );
}

// ── Session cookie naming (attome-auth security contract I1) ───────────────────

#[tokio::test]
async fn an_unprefixed_session_cookie_is_rejected_when_secure_cookies_is_on() {
    // `test_config` leaves `auth.secure_cookies` at its default (true), so
    // authn reads only `__Host-session_token`. A bare `session_token` is what
    // a sibling subdomain or an HTTP man-in-the-middle could plant; the same
    // valid token under that name must not authenticate.
    let (app, state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    let (_user_id, prefixed_cookie) = seed_user_and_cookie(&state).await;
    let (name, token) = prefixed_cookie
        .split_once('=')
        .expect("cookie is name=value");
    assert_eq!(name, "__Host-session_token");

    // Control: the prefixed cookie passes authn, so a 401 below can only come
    // from the cookie name.
    let prefixed = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/api-keys")
        .header("cookie", &prefixed_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(prefixed).await.expect("request");
    assert_ne!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "the __Host-session_token cookie must authenticate"
    );

    let bare = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/api-keys")
        .header("cookie", format!("session_token={token}"))
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(bare).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "an unprefixed session_token must not authenticate when secure_cookies is on"
    );
}

// ── Full-stack coverage — the historical "third mounting site" bug ──────────

#[tokio::test]
async fn api_keys_route_carries_the_full_stack() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);

    // No session cookie at all: must be rejected by authz (401), not silently
    // served — this is exactly the gap that let api-keys skip authz before
    // Plan 1.3 centralized assembly.
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/api-keys")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(
        res.headers().get("x-request-id").is_some(),
        "api-keys must carry the outer stack (X-Request-Id) same as every other route"
    );
}

/// A socket peer no other request uses. `pre_auth_rate_limit` and the anonymous
/// `rate_limit` bucket key on the TCP peer, and an in-process `oneshot()`
/// request has none, so without this every such request shares one `unknown`
/// bucket across tests and runs. IPv6 documentation prefix plus random bits
/// in the network half: B6 buckets IPv6 per /64, so two peers inside one /64
/// would share a budget.
fn unique_peer() -> std::net::SocketAddr {
    let random = u128::from_be_bytes(*Uuid::now_v7().as_bytes()) & ((1u128 << 62) - 1);
    let ip = std::net::Ipv6Addr::from((0x2001_0db8_u128 << 96) | (random << 32));
    std::net::SocketAddr::from((ip, 40_000))
}

fn from_peer(peer: std::net::SocketAddr, method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .extension(axum::extract::ConnectInfo(peer))
}

// ── Ordering (attome-server hardening P1.8) ────────────────────────────────────
//
// Each test sends a request two layers would both reject and asserts which
// answer wins. Edges pinned elsewhere in this file: body limit before authn
// (`oversized_body_is_rejected_before_authn_runs`), authoring gate before authn
// (`authoring_gate_refuses_metadata_write_on_production_profile`), and the panic
// boundary inside the request-id and security-header layers (the 500 row of
// `every_framework_error_carries_the_observable_envelope`). `/health` during a
// coordination-Redis outage is `attome-server/tests/health.rs`.

#[tokio::test]
async fn the_mutation_gate_and_the_pre_auth_limiter_both_answer_before_authn() {
    let mut config = test_config(1000, 1000);
    config.rate_limit.pre_auth_rpm = 1;
    let (app, state) = skip_if_no_db!(test_app(config).await);

    // Pre-auth limiter before authn: a garbage session cookie is a 401, but once
    // the peer's pre-auth budget is spent the limiter answers first.
    let peer = unique_peer();
    let garbage_cookie = || {
        from_peer(peer, "GET", "/api/v1/auth/api-keys")
            .header(
                "cookie",
                format!(
                    "{}=not-a-jwt",
                    attome_auth::cookie::session_cookie_name(true)
                ),
            )
            .body(Body::empty())
            .unwrap()
    };
    let first = app.clone().oneshot(garbage_cookie()).await.unwrap();
    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    let second = app.clone().oneshot(garbage_cookie()).await.unwrap();
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the pre-auth limiter must answer before authn verifies the cookie"
    );
    assert_eq!(error_code(second).await, "rate_limit_exceeded");

    // Mutation gate before the pre-auth limiter (and authn): spend a fresh
    // peer's budget, trip the breaker, and an unauthenticated write from that
    // peer is still 503, not 429 or 401.
    let peer = unique_peer();
    let read = || {
        from_peer(peer, "GET", "/api/v1/auth/api-keys")
            .body(Body::empty())
            .unwrap()
    };
    let spend = app.clone().oneshot(read()).await.unwrap();
    assert_eq!(spend.status(), StatusCode::UNAUTHORIZED);
    state
        .audit_ingest_backlog_exceeded
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let write = from_peer(peer, "POST", "/api/v1/auth/api-keys")
        .header("origin", ALLOWED_ORIGIN)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"never-created"}"#))
        .unwrap();
    let res = app.clone().oneshot(write).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error_code(res).await, "overloaded");

    // The budget really is spent: the gate ignores reads, and the limiter
    // refuses this one.
    let limited = app.oneshot(read()).await.unwrap();
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_csrf_rejection_spends_no_user_budget_and_writes_no_idempotency_key() {
    let calls = Calls::default();
    let path = "/api/v1/__order_test/csrf";
    let route = counted(calls.clone(), || async { StatusCode::CREATED });
    let (app, state) = skip_if_no_db!(
        test_app_with_extra_routes(test_config(1000, 10), Some(single_route(path, route))).await
    );
    let (_user_id, cookie) = seed_user_and_cookie(&state).await;
    let key = format!("csrf-order-{}", Uuid::now_v7());
    let remaining = |res: &axum::response::Response| -> i64 {
        res.headers()
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("an admitted request carries x-ratelimit-remaining")
    };

    let before = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("cookie", &cookie)
                .header("origin", ALLOWED_ORIGIN)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(before.status(), StatusCode::CREATED);
    let before_remaining = remaining(&before);

    let cross_site = Request::builder()
        .method("POST")
        .uri(path)
        .header("cookie", &cookie)
        .header("origin", "http://cross-site.test")
        .header("content-type", "application/json")
        .header("x-idempotency-key", &key)
        .body(Body::from("{}"))
        .unwrap();
    let rejected = app.clone().oneshot(cross_site).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);

    // Same key, same body, now same-origin: the handler runs. Had the CSRF
    // rejection reached the idempotency gate this would be a conflict.
    let after = app
        .clone()
        .oneshot(idem_req(path, &cookie, &key, "{}"))
        .await
        .unwrap();
    assert_eq!(after.status(), StatusCode::CREATED);
    assert_eq!(
        remaining(&after),
        before_remaining - 1,
        "the CSRF rejection must not have spent the user's rate-limit budget"
    );
    assert_eq!(count(&calls), 2);
}

// ── Error envelope matrix (attome-server hardening P1.9, invariant I6) ─────────

/// A framework error carries the JSON envelope, a `request_id` equal to the
/// `x-request-id` header, the security headers, and CORS headers when the
/// request came from an allowed origin.
async fn assert_error_envelope(
    row: &str,
    res: axum::response::Response,
    status: StatusCode,
    code: &str,
    from_allowed_origin: bool,
) {
    assert_eq!(res.status(), status, "{row}: status");
    let headers = res.headers().clone();
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let request_id =
        header("x-request-id").unwrap_or_else(|| panic!("{row}: no x-request-id header"));
    assert_eq!(
        header("x-content-type-options").as_deref(),
        Some("nosniff"),
        "{row}: security headers"
    );
    assert!(
        header("referrer-policy").is_some(),
        "{row}: security headers"
    );
    assert_eq!(
        header("access-control-allow-origin").as_deref(),
        from_allowed_origin.then_some(ALLOWED_ORIGIN),
        "{row}: CORS"
    );
    assert!(
        header("content-type")
            .is_some_and(|ct| ct.starts_with("application/json")
                || ct.starts_with("application/problem+json")),
        "{row}: JSON content type"
    );
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|e| panic!("{row}: body is not JSON: {e}"));
    assert_eq!(json["error"], code, "{row}: error code");
    assert!(json["message"].is_string(), "{row}: message");
    assert_eq!(
        json["request_id"],
        request_id.as_str(),
        "{row}: body request_id matches the header"
    );
}

#[tokio::test]
async fn every_framework_error_carries_the_observable_envelope() {
    // authenticated_rpm = 1, so each cookie row seeds its own user.
    let mut config = test_config(1000, 1);
    config.app.request_timeout_secs = 1;
    let routes: ExtraRoutes = Box::new(|_| {
        axum::Router::new()
            .route(
                "/api/v1/__envelope_test/panic",
                axum::routing::post(panicking_mutation),
            )
            .route(
                "/api/v1/__envelope_test/slow",
                axum::routing::post(|| async {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    StatusCode::CREATED
                }),
            )
            .route(
                "/api/v1/__envelope_test/ok",
                axum::routing::post(|| async { StatusCode::CREATED }),
            )
            .route(
                "/api/v1/__envelope_test/large_422",
                axum::routing::get(|| async {
                    attome_types::AppError::Validation("x".repeat(70 * 1024))
                }),
            )
    });
    let (app, state) = skip_if_no_db!(test_app_with_extra_routes(config, Some(routes)).await);
    let send = |req: Request<Body>| app.clone().oneshot(req);
    let cookie_post = |uri: &str, cookie: &str| {
        from_peer(unique_peer(), "POST", uri)
            .header("cookie", cookie)
            .header("origin", ALLOWED_ORIGIN)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap()
    };

    let res = send(
        from_peer(unique_peer(), "GET", "/api/v1/auth/api-keys")
            .header("origin", ALLOWED_ORIGIN)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_error_envelope(
        "401 authn",
        res,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        true,
    )
    .await;

    let (_, cookie) = seed_user_and_cookie(&state).await;
    let res = send(
        from_peer(unique_peer(), "GET", "/api/v1/admin/entities")
            .header("cookie", &cookie)
            .header("origin", ALLOWED_ORIGIN)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_error_envelope("403 authz", res, StatusCode::FORBIDDEN, "forbidden", true).await;

    // CSRF rejects only a request without an allowed Origin, so this row can
    // never carry allowed-origin CORS headers; it must not echo the origin.
    let (_, cookie) = seed_user_and_cookie(&state).await;
    let res = send(
        from_peer(unique_peer(), "POST", "/api/v1/__envelope_test/ok")
            .header("cookie", &cookie)
            .header("origin", "http://cross-site.test")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_error_envelope("403 csrf", res, StatusCode::FORBIDDEN, "forbidden", false).await;

    let oversized = "x".repeat(4096);
    let res = send(
        from_peer(unique_peer(), "POST", "/api/v1/auth/api-keys")
            .header("origin", ALLOWED_ORIGIN)
            .header("content-type", "application/json")
            .header("content-length", oversized.len().to_string())
            .body(Body::from(oversized))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_error_envelope(
        "413 body limit",
        res,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
        true,
    )
    .await;

    let (_, cookie) = seed_user_and_cookie(&state).await;
    let peer = unique_peer();
    let limited = || {
        from_peer(peer, "GET", "/api/v1/auth/api-keys")
            .header("cookie", &cookie)
            .header("origin", ALLOWED_ORIGIN)
            .body(Body::empty())
            .unwrap()
    };
    let admitted = send(limited()).await.unwrap();
    assert_ne!(admitted.status(), StatusCode::TOO_MANY_REQUESTS);
    let res = send(limited()).await.unwrap();
    assert_error_envelope(
        "429 user rate limit",
        res,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limit_exceeded",
        true,
    )
    .await;

    let (_, cookie) = seed_user_and_cookie(&state).await;
    let res = send(cookie_post("/api/v1/__envelope_test/panic", &cookie))
        .await
        .unwrap();
    assert_error_envelope(
        "500 panic",
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        true,
    )
    .await;

    let (_, cookie) = seed_user_and_cookie(&state).await;
    let res = send(cookie_post("/api/v1/__envelope_test/slow", &cookie))
        .await
        .unwrap();
    assert_error_envelope(
        "503 server timeout",
        res,
        StatusCode::SERVICE_UNAVAILABLE,
        "server_timeout",
        true,
    )
    .await;

    // A5 (BSV-F09): a wrong method and a >64 KiB error body, each sent as a
    // client that accepts compression (A1). (An authenticated unmatched path
    // is answered by authz's 403 before the fallback; the wrong-host test
    // below covers the JSON 404.)
    let cookie_get = |uri: &str, cookie: &str| {
        from_peer(unique_peer(), "GET", uri)
            .header("cookie", cookie)
            .header("origin", ALLOWED_ORIGIN)
            .header("accept-encoding", "gzip, br")
            .body(Body::empty())
            .unwrap()
    };
    let (_, cookie) = seed_user_and_cookie(&state).await;
    let res = send(cookie_get("/api/v1/__envelope_test/ok", &cookie))
        .await
        .unwrap();
    assert_eq!(
        res.headers().get("allow").and_then(|v| v.to_str().ok()),
        Some("POST"),
        "405: the Allow header survives the JSON fallback"
    );
    assert_error_envelope(
        "405 method",
        res,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        true,
    )
    .await;

    // Over 64 KiB the body is forwarded whole rather than rewritten, so
    // `request_id` travels in the header only (attome-server plan §7.10 A5).
    let (_, cookie) = seed_user_and_cookie(&state).await;
    let res = send(cookie_get("/api/v1/__envelope_test/large_422", &cookie))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY, "422 large");
    assert!(
        res.headers().contains_key("x-request-id"),
        "422 large: x-request-id"
    );
    assert!(
        !res.headers().contains_key("content-encoding"),
        "422 large: an error body is never compressed"
    );
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("422 large: the whole body is JSON");
    assert_eq!(json["error"], "validation_error", "422 large: error code");
    assert!(
        json["message"]
            .as_str()
            .is_some_and(|m| m.len() > 70 * 1024),
        "422 large: the message arrives untruncated"
    );

    // Last: the breaker refuses every write on this app from here on.
    state
        .audit_ingest_backlog_exceeded
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let res = send(
        from_peer(unique_peer(), "POST", "/api/v1/auth/api-keys")
            .header("origin", ALLOWED_ORIGIN)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"never-created"}"#))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_error_envelope(
        "503 overloaded",
        res,
        StatusCode::SERVICE_UNAVAILABLE,
        "overloaded",
        true,
    )
    .await;
}

/// A5 (BSV-F09): a request on a host outside `deployment.staff_hosts` gets the
/// same JSON 404 envelope as an unknown path, before any authentication.
#[tokio::test]
async fn a_wrong_host_gets_the_json_not_found_envelope() {
    let mut config = test_config(1000, 1000);
    config.deployment.staff_hosts = vec!["staff.test".to_owned()];
    let (app, _state) = skip_if_no_db!(test_app(config).await);

    let res = app
        .oneshot(
            from_peer(unique_peer(), "GET", "/api/v1/auth/api-keys")
                .header("host", "elsewhere.test")
                .header("origin", ALLOWED_ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_error_envelope(
        "404 wrong host",
        res,
        StatusCode::NOT_FOUND,
        "not_found",
        true,
    )
    .await;
}

// ── Z5-T1: the order, and rejections that never read the body ────────────────

/// A body that panics the moment anything reads it. `CatchPanicLayer` turns
/// the panic into a 500, so a test expecting a specific rejection fails if
/// any layer before that rejection polls the body.
fn panic_on_poll() -> Body {
    Body::from_stream(futures_util::stream::poll_fn(
        |_| -> std::task::Poll<Option<Result<axum::body::Bytes, std::io::Error>>> {
            panic!("the request body was read before the rejection")
        },
    ))
}

#[tokio::test]
async fn pipeline_order_matches_constant() {
    let mut config = test_config(1000, 1000);
    config.app.debug_pipeline_trace = true;
    let (app, state) = skip_if_no_db!(test_app(config).await);
    let (_, cookie) = seed_user_and_cookie(&state).await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/limits/me")
        .header("cookie", cookie)
        .header("origin", ALLOWED_ORIGIN)
        .header("x-forwarded-for", unique_client_ip())
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    let layers = res
        .headers()
        .get(attome_server::middleware::pipeline_trace::HEADER)
        .and_then(|v| v.to_str().ok())
        .expect("the debug pipeline trace header")
        .to_owned();
    assert_eq!(layers, attome_server::app::PIPELINE_ORDER.join(","));
}

#[tokio::test]
async fn oversized_rejected_without_reading_body() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/api-keys")
        .header("content-type", "application/octet-stream")
        .header("content-length", "4096")
        .header("origin", ALLOWED_ORIGIN)
        .header("x-forwarded-for", unique_client_ip())
        .body(panic_on_poll())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn rate_limited_without_reading_body() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(3, 1000)).await);
    let ip = unique_client_ip();
    for _ in 0..3 {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .header("x-forwarded-for", &ip)
            .body(Body::from(
                r#"{"email":"nobody@example.com","password":"wrong"}"#,
            ))
            .unwrap();
        app.clone().oneshot(req).await.expect("request");
    }
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/octet-stream")
        .header("x-forwarded-for", &ip)
        .body(panic_on_poll())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn csrf_rejected_without_reading_body() {
    let (app, state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    let (_, cookie) = seed_user_and_cookie(&state).await;
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/api-keys")
        .header("cookie", cookie)
        .header("content-type", "application/octet-stream")
        .header("origin", "http://evil.example")
        .header("sec-fetch-site", "cross-site")
        .header("x-forwarded-for", unique_client_ip())
        .body(panic_on_poll())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_rejected_without_reading_body() {
    let (app, _state) = skip_if_no_db!(test_app(test_config(1000, 1000)).await);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/api-keys")
        .header("content-type", "application/octet-stream")
        .header("origin", ALLOWED_ORIGIN)
        .header("x-forwarded-for", unique_client_ip())
        .body(panic_on_poll())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

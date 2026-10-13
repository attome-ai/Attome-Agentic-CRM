//! T1-10 (closes B11): the per-*account* sliding-window throttle on
//! `POST /api/v1/auth/login` and `POST /api/v1/auth/mfa/verify[-recovery]`,
//! plus attome-auth hardening 2.5's throttle on `POST /api/v1/auth/reset-request`
//! (`crates/server/src/auth/local.rs`, "Per-account throttle").
//!
//! The category rate limiter (`attome_server::middleware::rate_limit`) keys
//! these routes on the caller's IP. These tests prove the complementary axis:
//! N attempts against ONE account from N *different* peers lock that account
//! (429 on attempt N+1), while the peers themselves — and every other account
//! — are untouched (401). Every request below carries its own
//! `ConnectInfo` peer address, which is what `client_ip` actually reads; an
//! `x-forwarded-for` header on its own is inert in this in-process harness
//! (no peer means no trusted proxy to honour it, so `client_ip` is `None`
//! and every request would share the `ip:unknown` bucket).
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database — attome-testkit
//! clones it per binary) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`).
//! Skips cleanly when `DATABASE_URL` is unset. Run manually:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p server --test account_throttle -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::net::SocketAddr;

use attome::auth;
use attome_api::EngineSystem;
use attome_auth::TokenType;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header::RETRY_AFTER};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";

/// The handler-level constants under test (`local.rs`). Duplicated here on
/// purpose: a silent bump there should fail a test, not be absorbed by it.
const LOGIN_ATTEMPTS_PER_ACCOUNT_RPM: usize = 10;
const MFA_VERIFY_ATTEMPTS_PER_ACCOUNT_RPM: usize = 10;
const RESET_REQUESTS_PER_ACCOUNT_RPM: usize = 3;

/// Per-IP budgets are set far above anything these tests send, so a 429 can
/// only ever come from the per-account throttle — never from the category
/// limiter this suite is proving independence from.
fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4096, "request_timeout_secs": 5,
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
                "anonymous_rpm": 1000, "authenticated_rpm": 1000
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

/// Same assembly as `middleware_pipeline.rs::test_app` — the full `main.rs`
/// stack (pre-auth IP limit, category limit, authn, …) around the auth
/// bundle, so the per-account throttle is exercised *behind* the per-IP
/// layers it complements, not in isolation.
async fn test_app(mut config: AppConfig) -> Option<(axum::Router, AppState)> {
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
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));

    let base_state = system.state().base.clone();
    let license = system.state().modules.clone();
    let auth_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );

    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

/// A distinct TCP peer per attempt — `203.0.113.{n}` (TEST-NET-3) — plus a
/// matching `x-forwarded-for` for realism. `client_ip` reads the peer.
fn from_peer(mut req: Request<Body>, n: u8) -> Request<Body> {
    let peer = SocketAddr::from(([203, 0, 113, n], 40_000 + u16::from(n)));
    req.headers_mut().insert(
        "x-forwarded-for",
        format!("198.51.100.{n}").parse().expect("valid header"),
    );
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

fn login_request(email: &str, password: &str, peer: u8) -> Request<Body> {
    let body = serde_json::json!({ "email": email, "password": password }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    from_peer(req, peer)
}

fn mfa_request(path: &str, pending_token: &str, peer: u8) -> Request<Body> {
    let body = serde_json::json!({ "pending_token": pending_token, "code": "000000" }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    from_peer(req, peer)
}

fn unique_email(tag: &str) -> String {
    format!("t1-10-{tag}-{}@example.test", Uuid::now_v7())
}

/// The `{error, message}` pair of a JSON error body — the parts of the
/// contract that must not vary between a throttled known and unknown
/// account. (`request_id`, if present, is per-request by definition.)
async fn error_body(res: axum::response::Response) -> (String, String) {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON error body");
    (
        json["error"].as_str().unwrap_or_default().to_string(),
        json["message"].as_str().unwrap_or_default().to_string(),
    )
}

fn retry_after_secs(res: &axum::response::Response) -> u64 {
    res.headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok())
        .expect("a throttled response must carry an integer Retry-After")
}

async fn seed_user(state: &AppState, email: Option<&str>, password: Option<&str>) -> Uuid {
    let user_id = Uuid::now_v7();
    let password_hash = match password {
        Some(p) => Some(
            attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(p))
                .await
                .expect("hash throwaway password"),
        ),
        None => None,
    };
    sqlx::query(
        "INSERT INTO user_account \
         (id, user_name, email, password_hash, is_active, email_verified) \
         VALUES ($1, $2, $3, $4, true, true)",
    )
    .bind(user_id)
    .bind(format!("t1-10-{user_id}"))
    .bind(email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    user_id
}

// ── /auth/reset-request (attome-auth hardening 2.5) ────────────────────────────

fn reset_request(email: &str, peer: u8) -> Request<Body> {
    let body = serde_json::json!({ "email": email }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/reset-request")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("build request");
    from_peer(req, peer)
}

/// `test_config()` with email delivery on. Without it `reset_request` answers
/// `FeatureUnavailable` before the throttle ever runs.
fn email_enabled_config() -> AppConfig {
    let mut config = test_config();
    config.email.enabled = true;
    config
}

async fn body_bytes(res: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body")
        .to_vec()
}

async fn queued_emails_to(state: &AppState, email: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM notification_email_delivery WHERE recipient = $1")
        .bind(email)
        .fetch_one(&state.db)
        .await
        .expect("count queued emails")
}

#[tokio::test]
async fn reset_requests_past_the_account_budget_still_answer_200_but_send_nothing() {
    let (app, state) = skip_if_no_db!(test_app(email_enabled_config()).await);
    let email = unique_email("reset");
    seed_user(&state, Some(&email), Some("reset-throttle-password-1")).await;

    for n in 1..=RESET_REQUESTS_PER_ACCOUNT_RPM + 2 {
        let res = app
            .clone()
            .oneshot(reset_request(&email, n as u8))
            .await
            .expect("request");
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "reset request {n} must answer 200 whether or not it is throttled"
        );
    }

    assert_eq!(
        queued_emails_to(&state, &email).await,
        RESET_REQUESTS_PER_ACCOUNT_RPM as i64,
        "only the requests inside the per-account budget may queue a reset email"
    );
}

#[tokio::test]
async fn a_throttled_reset_request_is_identical_for_known_and_unknown_emails() {
    let (app, state) = skip_if_no_db!(test_app(email_enabled_config()).await);
    let known = unique_email("reset-known");
    let unknown = unique_email("reset-unknown");
    seed_user(&state, Some(&known), Some("reset-throttle-password-2")).await;

    let mut throttled = Vec::new();
    for email in [&known, &unknown] {
        for n in 1..=RESET_REQUESTS_PER_ACCOUNT_RPM {
            let res = app
                .clone()
                .oneshot(reset_request(email, n as u8))
                .await
                .expect("request");
            assert_eq!(res.status(), StatusCode::OK);
        }
        let res = app
            .clone()
            .oneshot(reset_request(
                email,
                (RESET_REQUESTS_PER_ACCOUNT_RPM + 1) as u8,
            ))
            .await
            .expect("request");
        throttled.push((res.status(), body_bytes(res).await));
    }

    assert_eq!(throttled[0].0, StatusCode::OK);
    assert_eq!(
        throttled[0], throttled[1],
        "a throttled known and unknown email must get the same status and body"
    );
}

// ── /auth/login ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn failed_logins_for_one_email_from_many_peers_lock_the_email_not_the_peers() {
    let (app, _state) = skip_if_no_db!(test_app(test_config()).await);
    let email = unique_email("login");

    for n in 1..=LOGIN_ATTEMPTS_PER_ACCOUNT_RPM {
        let res = app
            .clone()
            .oneshot(login_request(&email, "wrong-password", n as u8))
            .await
            .expect("request");
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {n} (peer 203.0.113.{n}) is within the per-account budget and must \
             fall through to the engine's 401"
        );
    }

    let next_peer = (LOGIN_ATTEMPTS_PER_ACCOUNT_RPM + 1) as u8;
    let rejected = app
        .clone()
        .oneshot(login_request(&email, "wrong-password", next_peer))
        .await
        .expect("request");
    assert_eq!(
        rejected.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "attempt N+1 from a peer that has never been seen must be throttled by the \
         account, since every earlier attempt came from a different IP"
    );
    let retry_after = retry_after_secs(&rejected);
    assert!(
        (1..=60).contains(&retry_after),
        "Retry-After must come from the sliding window, got {retry_after}"
    );
    assert!(
        rejected.headers().get("x-ratelimit-reset").is_some(),
        "the established 429 shape carries X-RateLimit-Reset alongside Retry-After"
    );
    assert_eq!(error_body(rejected).await.0, "rate_limit_exceeded");

    // The very peer that was just refused is free to try a *different*
    // account — the lock is on the email, not the IP.
    let other = app
        .clone()
        .oneshot(login_request(
            &unique_email("other"),
            "wrong-password",
            next_peer,
        ))
        .await
        .expect("request");
    assert_eq!(
        other.status(),
        StatusCode::UNAUTHORIZED,
        "a different email from the throttled peer must still reach the engine (401)"
    );

    // Case and surrounding whitespace do not open a fresh bucket — the key
    // is derived from the same normalization `accounts::login` applies.
    let disguised = format!("  {}  ", email.to_uppercase());
    let disguised_res = app
        .clone()
        .oneshot(login_request(&disguised, "wrong-password", next_peer + 1))
        .await
        .expect("request");
    assert_eq!(
        disguised_res.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "upper-casing / padding the email must land in the same bucket"
    );
}

/// Anti-enumeration: the throttle runs before any lookup, so a throttled
/// account that exists and one that does not produce the same status, the
/// same error contract, and the same header set — and the lock holds even
/// when the password is right.
#[tokio::test]
async fn a_throttled_known_account_is_indistinguishable_from_a_throttled_unknown_one() {
    let (app, state) = skip_if_no_db!(test_app(test_config()).await);

    let known_email = unique_email("known");
    let password = format!("Correct-Horse-{}", Uuid::now_v7());
    seed_user(&state, Some(&known_email), Some(&password)).await;

    // Attempt 1 with the right password proves the seed is a real, loginable
    // account (mfa_policy defaults to "off" → a plain session).
    let ok = app
        .clone()
        .oneshot(login_request(&known_email, &password, 1))
        .await
        .expect("request");
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "the seeded account must log in"
    );

    for n in 2..=LOGIN_ATTEMPTS_PER_ACCOUNT_RPM {
        let res = app
            .clone()
            .oneshot(login_request(&known_email, "wrong-password", n as u8))
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "attempt {n}");
    }
    let next_peer = (LOGIN_ATTEMPTS_PER_ACCOUNT_RPM + 1) as u8;
    let known_rejected = app
        .clone()
        .oneshot(login_request(&known_email, &password, next_peer))
        .await
        .expect("request");
    assert_eq!(
        known_rejected.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "attempts are what is budgeted: the right password does not bypass the lock"
    );

    let unknown_email = unique_email("unknown");
    for n in 1..=LOGIN_ATTEMPTS_PER_ACCOUNT_RPM {
        let res = app
            .clone()
            .oneshot(login_request(&unknown_email, "wrong-password", n as u8))
            .await
            .expect("request");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "attempt {n}");
    }
    let unknown_rejected = app
        .clone()
        .oneshot(login_request(&unknown_email, "wrong-password", next_peer))
        .await
        .expect("request");
    assert_eq!(unknown_rejected.status(), StatusCode::TOO_MANY_REQUESTS);

    let header_names = |res: &axum::response::Response| {
        let mut names: Vec<String> = res
            .headers()
            .keys()
            .map(|k| k.as_str().to_string())
            .collect();
        names.sort();
        names
    };
    assert_eq!(
        header_names(&known_rejected),
        header_names(&unknown_rejected),
        "a throttled known and unknown account must expose the same header set"
    );
    assert!((1..=60).contains(&retry_after_secs(&known_rejected)));
    assert!((1..=60).contains(&retry_after_secs(&unknown_rejected)));
    assert_eq!(
        error_body(known_rejected).await,
        error_body(unknown_rejected).await,
        "a throttled known and unknown account must return the same error contract"
    );
}

// ── /auth/mfa/verify ─────────────────────────────────────────────────────────

/// A fresh pending token per attempt is exactly the evasion this closes: the
/// per-challenge ceiling (`mfa_challenge_max_attempts`) is per-`jti`, so an
/// attacker holding the password could re-login for a new token every N
/// guesses. The per-account bucket spans every token for the same `sub`.
#[tokio::test]
async fn mfa_verify_attempts_across_fresh_pending_tokens_lock_the_account() {
    let (app, state) = skip_if_no_db!(test_app(test_config()).await);
    let victim = seed_user(&state, Some(&unique_email("mfa-victim")), None).await;
    let bystander = seed_user(&state, Some(&unique_email("mfa-bystander")), None).await;

    let mint = |user_id: Uuid| {
        let state = state.clone();
        async move {
            let secrets = state.secrets.load();
            attome_auth::mfa::start_challenge(
                &state.redis_coordination,
                user_id,
                TokenType::MfaPendingLogin,
                &secrets.jwt_secret,
                &state.config.auth.jwt_issuer,
                state.config.jwt_audience(),
            )
            .await
            .expect("mint a pending-MFA token")
        }
    };

    for n in 1..=MFA_VERIFY_ATTEMPTS_PER_ACCOUNT_RPM {
        let token = mint(victim).await;
        let res = app
            .clone()
            .oneshot(mfa_request("/api/v1/auth/mfa/verify", &token, n as u8))
            .await
            .expect("request");
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "attempt {n} with a fresh pending token must reach the engine (no enrollment → 401)"
        );
    }

    let next_peer = (MFA_VERIFY_ATTEMPTS_PER_ACCOUNT_RPM + 1) as u8;
    let token = mint(victim).await;
    let rejected = app
        .clone()
        .oneshot(mfa_request("/api/v1/auth/mfa/verify", &token, next_peer))
        .await
        .expect("request");
    assert_eq!(
        rejected.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "attempt N+1 with yet another fresh token and a never-seen peer must be \
         throttled by the account"
    );
    assert!((1..=60).contains(&retry_after_secs(&rejected)));
    assert_eq!(error_body(rejected).await.0, "rate_limit_exceeded");

    // The recovery-code route shares the bucket — alternating routes must
    // not double the budget.
    let token = mint(victim).await;
    let recovery = app
        .clone()
        .oneshot(mfa_request(
            "/api/v1/auth/mfa/verify-recovery",
            &token,
            next_peer + 1,
        ))
        .await
        .expect("request");
    assert_eq!(
        recovery.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "verify-recovery for the throttled account must be refused too"
    );

    // Another account, from the throttled peer, is untouched.
    let token = mint(bystander).await;
    let other = app
        .clone()
        .oneshot(mfa_request("/api/v1/auth/mfa/verify", &token, next_peer))
        .await
        .expect("request");
    assert_eq!(
        other.status(),
        StatusCode::UNAUTHORIZED,
        "a different account's pending token from the same peer must still reach the engine"
    );
}

/// A body that is not a JWT at all has no account to bucket; it must fall
/// through to the engine's 401, never 500 and never a spurious 429.
#[tokio::test]
async fn a_malformed_pending_token_is_not_bucketed_and_still_gets_401() {
    let (app, _state) = skip_if_no_db!(test_app(test_config()).await);
    let res = app
        .oneshot(mfa_request("/api/v1/auth/mfa/verify", "not-a-jwt", 1))
        .await
        .expect("request");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

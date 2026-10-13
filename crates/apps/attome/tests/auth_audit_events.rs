//! Audit plan 3.4 (identity half) and 3.5 (D-541 rules 6 and 7), end to end
//! through the assembled HTTP stack: the mandatory `Security`/`Credential`
//! events the auth routes write.
//!
//! - a password login writes `Login`;
//! - failed logins coalesce per account, IP and 5-minute window, and the sweep
//!   writes one summary with `occurrence_count = N - 1`, once;
//! - an unknown identifier stores no record, identifier or raw IP;
//! - with Redis unavailable every failure is written;
//! - a throttled (429) attempt is not a failed-login event;
//! - logout writes `Logout`; refresh-token reuse writes `SessionRevoked`;
//! - reset request and confirm write `PasswordReset` with their outcome.
//!
//! `audit.chainer_enabled` keeps its default (true), so events are read from
//! `audit_ingest` payloads.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p server --test auth_audit_events -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::net::SocketAddr;

use attome::auth;
use attome::auth::failed_login;
use attome_api::EngineSystem;
use attome_audit::AuditOperation;
use attome_audit::security::SecurityAuditor;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use fred::interfaces::{KeysInterface, SetsInterface};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";

/// `mfa_policy = "optional"` so an enrolled account is challenged and an
/// unenrolled one gets a plain session. `secure_cookies` stays at its default
/// (true), so the cookies are the prefixed production names.
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
    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    config.auth.mfa_policy = "optional".into();
    config.auth.mfa_encryption_key = KeyRing::single("ab".repeat(32));
    // reset-request answers FeatureUnavailable without email delivery.
    config.email.enabled = true;
    config
}

/// Same assembly as `account_throttle.rs::test_app`: the full `main.rs` stack
/// around the auth bundle.
async fn test_app() -> Option<(axum::Router, AppState, SecurityAuditor)> {
    let mut config = test_config();
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
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));

    let base_state = system.state().base.clone();
    let license = system.state().license.clone();
    let auditor = SecurityAuditor::from_state(system.state());
    let auth_bundle = attome_server::RouteBundle::new(
        auth::public_routes(license, auditor.clone()).with_state(base_state.clone()),
    );

    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state, auditor))
}

const PASSWORD: &str = "auth-audit-events-password-1";

async fn seed_user(state: &AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let email = format!("auth-audit-events-{user_id}@example.test");
    let password_hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(PASSWORD))
            .await
            .expect("hash throwaway password");
    sqlx::query(
        "INSERT INTO user_account \
         (id, user_name, email, password_hash, is_active, email_verified) \
         VALUES ($1, $2, $3, $4, true, true)",
    )
    .bind(user_id)
    .bind(format!("auth-audit-events-{user_id}"))
    .bind(&email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email)
}

/// `n` names the TCP peer `203.0.113.{n}`, which `client_ip` reads.
fn post_json_from(uri: &str, body: serde_json::Value, n: u8) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("origin", ALLOWED_ORIGIN)
        .body(Body::from(body.to_string()))
        .expect("build request");
    req.extensions_mut().insert(ConnectInfo(SocketAddr::from((
        [203, 0, 113, n],
        40_000 + u16::from(n),
    ))));
    req
}

fn login(email: &str, password: &str, n: u8) -> Request<Body> {
    post_json_from(
        "/api/v1/auth/login",
        serde_json::json!({ "email": email, "password": password }),
        n,
    )
}

/// Cookie header pairs (`name=value`) a response sets.
fn set_cookies(res: &axum::response::Response) -> Vec<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next().map(str::to_owned))
        .filter(|pair| !pair.ends_with('='))
        .collect()
}

fn with_cookies(mut req: Request<Body>, cookies: &[String]) -> Request<Body> {
    req.headers_mut().insert(
        header::COOKIE,
        cookies.join("; ").parse().expect("cookie header"),
    );
    req
}

/// One captured event. `audit.chainer_enabled` keeps its default (true), so
/// every event written by these routes is in `audit_ingest`; the tests
/// read the payloads there.
#[derive(Debug)]
struct Captured {
    category: String,
    user_id: String,
    record_id: Option<String>,
    event_name: Option<String>,
    outcome: Option<String>,
    occurrence_count: Option<i64>,
    ip_address: Option<String>,
    payload: String,
}

/// The ingest payload serializes the enums by variant name.
async fn events(
    state: &AppState,
    operation: AuditOperation,
    record: Option<Uuid>,
) -> Vec<Captured> {
    let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
        "SELECT payload FROM audit_ingest \
         WHERE payload->>'operation' = $1 \
           AND (payload->>'record_id') IS NOT DISTINCT FROM $2 \
         ORDER BY id",
    )
    .bind(format!("{operation:?}"))
    .bind(record.map(|r| r.to_string()))
    .fetch_all(&state.db)
    .await
    .expect("read ingest payloads");
    rows.into_iter()
        .map(|(p,)| Captured {
            category: p["category"].as_str().unwrap_or_default().to_owned(),
            user_id: p["user_context"]["user_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            record_id: p["record_id"].as_str().map(str::to_owned),
            event_name: p["event_name"].as_str().map(str::to_owned),
            outcome: p["extras"]["outcome"].as_str().map(str::to_owned),
            occurrence_count: p["extras"]["occurrence_count"].as_i64(),
            ip_address: p["request_context"]["ip_address"]
                .as_str()
                .map(str::to_owned),
            payload: p.to_string(),
        })
        .collect()
}

/// Waits out the tail of a 5-minute window, so a burst of attempts lands in
/// one window.
async fn inside_one_window() -> i64 {
    let now = chrono::Utc::now().timestamp();
    let left = failed_login::WINDOW_SECS - now.rem_euclid(failed_login::WINDOW_SECS);
    if left < 15 {
        tokio::time::sleep(std::time::Duration::from_secs(left as u64 + 1)).await;
    }
    failed_login::window_start(chrono::Utc::now().timestamp())
}

async fn clear_counter(state: &AppState, key: &str, window: i64) {
    let _: i64 = state
        .redis_coordination
        .del(failed_login::counter_key(key, window))
        .await
        .expect("clear a counter left by an earlier run");
}

const LOGIN: AuditOperation = AuditOperation::Login;
const LOGOUT: AuditOperation = AuditOperation::Logout;
const FAILED_LOGIN: AuditOperation = AuditOperation::FailedLogin;

#[tokio::test]
async fn a_password_login_writes_one_login_event_for_the_account() {
    let (app, state, _) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;

    let res = app
        .clone()
        .oneshot(login(&email, PASSWORD, 1))
        .await
        .expect("login");
    assert_eq!(res.status(), StatusCode::OK);

    let rows = events(&state, LOGIN, Some(user_id)).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].category, "Security");
    assert_eq!(rows[0].user_id, user_id.to_string());
    assert_eq!(rows[0].event_name.as_deref(), Some("login password"));
}

#[tokio::test]
async fn failed_logins_coalesce_per_window_and_the_sweep_writes_one_summary() {
    let (app, state, auditor) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let window = inside_one_window().await;

    for _ in 0..4 {
        let res = app
            .clone()
            .oneshot(login(&email, "wrong-password", 2))
            .await
            .expect("login");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    let rows = events(&state, FAILED_LOGIN, Some(user_id)).await;
    assert_eq!(rows.len(), 1, "only the first failure is written: {rows:?}");
    let first = &rows[0];
    assert_eq!(first.category, "Security");
    assert_eq!(first.occurrence_count, Some(1));
    assert_eq!(
        first.user_id,
        Uuid::nil().to_string(),
        "unauthenticated actor"
    );
    assert_eq!(first.ip_address, None, "request context is Phase 4");
    assert!(
        !first.payload.contains(&email),
        "no typed identifier stored"
    );
    assert!(!first.payload.contains("203.0.113.2"), "no raw IP stored");

    // Close the window by sweeping it directly.
    let swept = failed_login::sweep_window(&auditor, &state.db, &state.redis_coordination, window)
        .await
        .expect("sweep");
    assert!(swept.summaries_written >= 1);
    let rows = events(&state, FAILED_LOGIN, Some(user_id)).await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let summary = &rows[1];
    assert_eq!(summary.occurrence_count, Some(3), "N - 1 later failures");
    let name = summary.event_name.as_deref().unwrap_or_default();
    assert!(name.starts_with("failed_login summary account "), "{name}");
    assert!(name.contains("window="), "{name}");

    // A retried sweep (counter already gone) and a sweep that finds a stale
    // counter for an already-summarized key both write nothing more.
    let key = failed_login::coalesce_key(
        failed_login::Subject::Known {
            user_id,
            organization_ref: None,
        },
        "203.0.113.2",
    );
    let _: () = state
        .redis_coordination
        .set(
            failed_login::counter_key(&key, window),
            4,
            None,
            None,
            false,
        )
        .await
        .expect("replay the counter");
    let _: i64 = state
        .redis_coordination
        .sadd(failed_login::pending_key(window), key.clone())
        .await
        .expect("replay the pending entry");
    failed_login::sweep_window(&auditor, &state.db, &state.redis_coordination, window)
        .await
        .expect("retried sweep");
    assert_eq!(events(&state, FAILED_LOGIN, Some(user_id)).await.len(), 2);
}

#[tokio::test]
async fn an_unknown_identifier_stores_nothing_but_the_ip_window_key() {
    let (app, state, _) = skip_if_no_db!(test_app().await);
    let window = inside_one_window().await;
    let ip = "203.0.113.3";
    clear_counter(
        &state,
        &failed_login::coalesce_key(failed_login::Subject::Unknown, ip),
        window,
    )
    .await;
    let email = format!("nobody-{}@example.test", Uuid::now_v7());

    let res = app
        .clone()
        .oneshot(login(&email, "whatever-password", 3))
        .await
        .expect("login");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let expected = failed_login::event_name(false, &failed_login::ip_key(ip), window, false);
    let rows: Vec<_> = events(&state, FAILED_LOGIN, None)
        .await
        .into_iter()
        .filter(|r| r.event_name.as_deref() == Some(expected.as_str()))
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].record_id, None);
    assert_eq!(rows[0].occurrence_count, Some(1));
    assert!(!rows[0].payload.contains(&email));
    assert!(!rows[0].payload.contains(ip));
}

#[tokio::test]
async fn with_redis_unavailable_every_failure_is_written() {
    let (_, state, auditor) = skip_if_no_db!(test_app().await);
    let (user_id, _) = seed_user(&state).await;
    // Never initialized, and pointed at a closed port: every command errors or
    // times out, which is exactly the outage path.
    let config = fred::types::RedisConfig {
        server: fred::types::ServerConfig::new_centralized("127.0.0.1", 1),
        ..Default::default()
    };
    let dead = fred::clients::RedisPool::new(config, None, None, None, 1).expect("build pool");
    let subject = failed_login::Subject::Known {
        user_id,
        organization_ref: None,
    };
    let now = chrono::Utc::now().timestamp();

    for _ in 0..3 {
        failed_login::record_failure(&auditor, &dead, subject, "203.0.113.4", now)
            .await
            .expect("an outage still records the failure");
    }

    let rows = events(&state, FAILED_LOGIN, Some(user_id)).await;
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert!(rows.iter().all(|r| r.occurrence_count == Some(1)));
}

#[tokio::test]
async fn a_throttled_login_is_not_a_failed_login_event() {
    let (app, state, _) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let window = inside_one_window().await;

    // The per-account budget is 10 attempts per rolling minute.
    for _ in 0..10 {
        let res = app
            .clone()
            .oneshot(login(&email, "wrong-password", 5))
            .await
            .expect("login");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    let res = app
        .clone()
        .oneshot(login(&email, "wrong-password", 5))
        .await
        .expect("login");
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);

    let key = failed_login::coalesce_key(
        failed_login::Subject::Known {
            user_id,
            organization_ref: None,
        },
        "203.0.113.5",
    );
    let counted: Option<i64> = state
        .redis_coordination
        .get(failed_login::counter_key(&key, window))
        .await
        .expect("read counter");
    assert_eq!(counted, Some(10), "the 429 was not counted");
    assert_eq!(events(&state, FAILED_LOGIN, Some(user_id)).await.len(), 1);
}

#[tokio::test]
async fn logout_writes_a_logout_event_and_an_anonymous_logout_writes_none() {
    let (app, state, _) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let res = app
        .clone()
        .oneshot(login(&email, PASSWORD, 6))
        .await
        .expect("login");
    assert_eq!(res.status(), StatusCode::OK);
    let cookies = set_cookies(&res);

    let res = app
        .clone()
        .oneshot(with_cookies(
            post_json_from("/api/v1/auth/logout", serde_json::json!({}), 6),
            &cookies,
        ))
        .await
        .expect("logout");
    assert_eq!(res.status(), StatusCode::OK);
    let rows = events(&state, LOGOUT, Some(user_id)).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].user_id, user_id.to_string());

    let before = events(&state, LOGOUT, None).await.len();
    let res = app
        .clone()
        .oneshot(post_json_from(
            "/api/v1/auth/logout",
            serde_json::json!({}),
            6,
        ))
        .await
        .expect("anonymous logout");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(events(&state, LOGOUT, None).await.len(), before);
}

#[tokio::test]
async fn refresh_token_reuse_writes_session_revoked() {
    let (app, state, _) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let res = app
        .clone()
        .oneshot(login(&email, PASSWORD, 7))
        .await
        .expect("login");
    let refresh: Vec<String> = set_cookies(&res)
        .into_iter()
        .filter(|c| c.contains("refresh_token="))
        .collect();
    assert_eq!(refresh.len(), 1);

    let rotate = || {
        with_cookies(
            post_json_from("/api/v1/auth/refresh", serde_json::json!({}), 7),
            &refresh,
        )
    };
    let res = app.clone().oneshot(rotate()).await.expect("refresh");
    assert_eq!(res.status(), StatusCode::OK);
    let revoked = AuditOperation::SessionRevoked;
    assert!(
        events(&state, revoked, Some(user_id)).await.is_empty(),
        "rotation writes nothing"
    );

    // D-626: a replay inside the grace window is a plain 401 that revokes
    // nothing; age the rotation past it to reach reuse detection.
    sqlx::query(
        "UPDATE refresh_token SET used_at = used_at - interval '11 seconds'
         WHERE user_ref = $1 AND used_at IS NOT NULL",
    )
    .bind(user_id)
    .execute(&state.db)
    .await
    .expect("age the rotation");

    let res = app
        .clone()
        .oneshot(rotate())
        .await
        .expect("replayed refresh");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let rows = events(&state, revoked, Some(user_id)).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].category, "Credential");
}

#[tokio::test]
async fn password_reset_request_and_confirm_write_password_reset() {
    let (app, state, _) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let reset = AuditOperation::PasswordReset;

    // Unknown address: 200 and no event.
    let before = events(&state, reset, None).await.len();
    let res = app
        .clone()
        .oneshot(post_json_from(
            "/api/v1/auth/reset-request",
            serde_json::json!({ "email": format!("nobody-{}@example.test", Uuid::now_v7()) }),
            8,
        ))
        .await
        .expect("reset request (unknown)");
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(events(&state, reset, None).await.len(), before);

    let res = app
        .clone()
        .oneshot(post_json_from(
            "/api/v1/auth/reset-request",
            serde_json::json!({ "email": email }),
            8,
        ))
        .await
        .expect("reset request");
    assert_eq!(res.status(), StatusCode::OK);
    let rows = events(&state, reset, Some(user_id)).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].category, "Credential");
    assert_eq!(rows[0].outcome.as_deref(), Some("Succeeded"));

    // A token minted directly, so the test knows its bearer.
    let mut tx = attome_db::tx::begin(&state.db).await.expect("begin");
    let issued = attome_auth::reset::request_in_tx(&mut tx, &email, 30, &state.pepper_ring())
        .await
        .expect("mint reset token")
        .expect("known account");
    tx.commit().await.expect("commit");
    let confirm = || {
        post_json_from(
            "/api/v1/auth/reset-confirm",
            serde_json::json!({ "token": issued.bearer, "new_password": "a-brand-new-password-9" }),
            8,
        )
    };
    let res = app.clone().oneshot(confirm()).await.expect("confirm");
    assert_eq!(res.status(), StatusCode::OK);
    let res = app
        .clone()
        .oneshot(confirm())
        .await
        .expect("reused confirm");
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let res = app
        .clone()
        .oneshot(post_json_from(
            "/api/v1/auth/reset-confirm",
            serde_json::json!({ "token": "garbage", "new_password": "a-brand-new-password-9" }),
            8,
        ))
        .await
        .expect("invalid token");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    let outcomes: Vec<_> = events(&state, reset, Some(user_id))
        .await
        .into_iter()
        .map(|r| r.outcome)
        .collect();
    assert_eq!(
        outcomes,
        vec![
            Some("Succeeded".to_owned()),
            Some("Succeeded".to_owned()),
            Some("Failed".to_owned())
        ],
        "request, confirm, refused reuse; the invalid token wrote nothing"
    );
}

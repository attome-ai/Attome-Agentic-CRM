//! P0.2 / BAU-9 / OD-1 (D-625) — the `jti` denylist must live on the
//! **coordination** Redis role, not the general cache role.
//!
//! The check is fail-closed on a store *error* but cannot be fail-closed on
//! *absence*: no key reads as "not revoked". The cache role is the one an
//! operator may put an eviction policy on or `FLUSHDB`, and an eviction there
//! would silently un-revoke every token minted in the last access-token
//! lifetime. D-625 amends D-161, which had reaffirmed the cache placement
//! without weighing absence.
//!
//! This suite runs the two roles on **different Redis databases** (cache on
//! DB 1, coordination on DB 0 — the plan's split-DB `cache.roles` config), so
//! "did the record go to the coordination role" is observable without touching
//! the shared DB 0 keyspace every other suite uses. Needs a live Postgres
//! (throwaway — NEVER `attome_dev`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`).
//!
//! `cargo test -p server --test revocation_pool_split -- --test-threads=1`
//! (or run the built binary from `target/debug/deps` when the shared dev
//! server holds `target/debug/server.exe`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome::auth;
use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use fred::prelude::*;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
/// The cache role's database. Deliberately NOT 0: every other suite in this
/// workspace uses DB 0, and this test flushes its own role's database.
const CACHE_ROLE_DB: i64 = 1;
/// The coordination role's database — the conventional default.
const COORDINATION_ROLE_DB: i64 = 0;

/// `secure_cookies = false` so the bare `session_token` name applies and the
/// assertions do not have to mirror the `__Host-` split.
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
                "db": {cache_db}, "connection_pool_size": 4, "timeout": 2000,
                "metadata_registry_enabled": false,
                "roles": {{
                    "coordination": {{
                        "host": "{redis_host}", "port": {redis_port},
                        "password": "", "db": {coordination_db}
                    }}
                }}
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "{jwt_secret}", "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "secure_cookies": false,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{
                "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}}
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
        cache_db = CACHE_ROLE_DB,
        coordination_db = COORDINATION_ROLE_DB,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// The two Redis pools really are on different databases — the test's own
/// precondition, asserted rather than assumed, because a config typo here
/// would make every assertion below vacuous.
async fn assert_the_roles_are_split(state: &AppState) {
    let marker = format!("revocation-pool-split:{}", Uuid::now_v7());
    state
        .redis_coordination
        .set::<(), _, _>(&marker, 1, None, None, false)
        .await
        .expect("write the coordination-role marker");
    // The reverse of the property under test: the cache role must NOT see it.
    let n: i64 = state
        .redis
        .exists(&marker)
        .await
        .expect("EXISTS on the cache role");
    let _ = state.redis_coordination.del::<(), _>(&marker).await;
    assert_eq!(
        n, 0,
        "the coordination and cache roles resolved to the same Redis database, so this \
         suite would prove nothing; check the cache.roles.coordination override"
    );
}

/// Surfaces the server's own `tracing::error!` (which `AppError::internal`
/// emits with the detail the JSON body deliberately withholds) when a request
/// fails for a reason this suite did not assert.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .try_init();
}

async fn test_app() -> Option<(axum::Router, AppState)> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
    point_config_at(&mut config, &throwaway_url);

    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    let redis = attome_cache::create_redis_pool(&config)
        .await
        .expect("connect redis (cache role)");
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
    let public_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );
    let protected_bundle = attome_server::RouteBundle::new(
        auth::protected_routes(attome_audit::security::SecurityAuditor::from_state(
            system.state(),
        ))
        .with_state(base_state.clone()),
    );
    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .add_bundle(system.core_routes())
        .add_bundle(public_bundle)
        .add_bundle(protected_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

/// A password account with a real refresh family and an access token naming
/// it. Returns `(jti, session_token)`.
async fn seed_session(state: &AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let email = format!("revocation-split-{user_id}@example.test");
    let password_hash = attome_auth::hash_password_async(
        attome_auth::NewPassword::platform_generated("revocation-split-password-1"),
    )
    .await
    .expect("hash throwaway password");
    // `email` and `email_verified` are not optional for a request-path
    // account: the authenticated request stack reads them (a NULL there
    // surfaces as a 500 "unexpected null" from an actor lookup), and
    // `GET /api/v1/auth/session` reads the address back out.
    sqlx::query(
        "INSERT INTO user_account \
         (id, user_name, email, password_hash, is_active, email_verified) \
         VALUES ($1, $2, $3, $4, true, true)",
    )
    .bind(user_id)
    .bind(format!("revocation-split-{user_id}"))
    .bind(&email)
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
    .expect("issue a session token");

    let claims = attome_auth::validate_token(
        &token,
        &KeyRing::single(THROWAWAY_JWT_SECRET.to_string()),
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .expect("the freshly minted token must validate");

    (claims.jti, token)
}

/// `GET /api/v1/auth/session` — a protected route, so it passes through the
/// real authn middleware (denylist read included).
async fn session_probe(app: &axum::Router, token: &str) -> StatusCode {
    let req = Request::builder()
        .uri("/api/v1/auth/session")
        .header(header::COOKIE, format!("session_token={token}"))
        .body(Body::empty())
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("session probe request")
        .status()
}

/// `POST /api/v1/auth/logout` with the session cookie. The CSRF layer wants a
/// same-origin signal; `Origin` is drawn from this config's allow-list.
async fn logout(app: &axum::Router, token: &str) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header(header::COOKIE, format!("session_token={token}"))
        .header(header::ORIGIN, ALLOWED_ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    app.clone()
        .oneshot(req)
        .await
        .expect("logout request")
        .status()
}

fn denylist_key(jti: Uuid) -> String {
    format!("auth:denylist:{jti}")
}

/// The behavioural half: a revoked token stays revoked after the cache role's
/// database is flushed. Before BAU-9 both the write and the read were on the
/// cache role, so this flush un-revoked the token and the probe answered 200.
#[tokio::test]
async fn a_revoked_token_stays_revoked_after_the_cache_role_is_flushed() {
    init_tracing();
    let (app, state) = skip_if_no_db!(test_app().await);
    assert_the_roles_are_split(&state).await;
    let (jti, token) = seed_session(&state).await;

    assert_eq!(
        session_probe(&app, &token).await,
        StatusCode::OK,
        "the freshly minted token must authenticate before anything revokes it"
    );

    let status = logout(&app, &token).await;
    assert!(
        status.is_success() || status.is_redirection(),
        "logout must succeed, got {status}"
    );

    // The cache role is flushed — the operation an operator may perform on
    // "the cache" (or an eviction policy may do for them).
    state
        .redis
        .eval::<(), _, _, _>(
            "redis.call('FLUSHDB')",
            Vec::<String>::new(),
            Vec::<String>::new(),
        )
        .await
        .expect("FLUSHDB on the cache role's database");

    assert_eq!(
        session_probe(&app, &token).await,
        StatusCode::UNAUTHORIZED,
        "a flushed cache role must not be able to un-revoke a token: the denylist \
         entry lives on the coordination role (BAU-9, D-625)"
    );
    // And the entry really is still there, on the pool the read uses.
    let present: i64 = state
        .redis_coordination
        .exists(denylist_key(jti))
        .await
        .expect("EXISTS on the coordination role");
    assert_eq!(
        present, 1,
        "the coordination role must still hold the revocation record"
    );
}

/// The placement half, directly: the write lands on the coordination role and
/// the cache role never sees it. This is the invariant the behavioural test
/// above depends on, asserted where it can be read without a browser.
#[tokio::test]
async fn the_denylist_entry_is_written_to_the_coordination_pool_alone() {
    let (app, state) = skip_if_no_db!(test_app().await);
    assert_the_roles_are_split(&state).await;
    let (jti, token) = seed_session(&state).await;

    let status = logout(&app, &token).await;
    assert!(
        status.is_success(),
        "logout must succeed before the denylist is read back, got {status}"
    );
    let key = denylist_key(jti);

    let on_coordination: i64 = state
        .redis_coordination
        .exists(&key)
        .await
        .expect("EXISTS on the coordination role");
    let on_cache: i64 = state
        .redis
        .exists(&key)
        .await
        .expect("EXISTS on the cache role");

    assert_eq!(
        on_coordination, 1,
        "the denylist write must reach the coordination role"
    );
    assert_eq!(
        on_cache, 0,
        "the denylist must never be written to the cache role"
    );
}

//! Integration tests for the admin disable/enable endpoint's D-121 hardening
//! (extends D-113/P-account-state-enforcement): the email advisory lock,
//! the `auth_epoch` bump inside the same transaction as the `is_active`
//! flip, and API-key revocation on disable (which re-enable must NOT undo —
//! review item 6, "indefinite, not a cache window").
//!
//! Also the executable half of D-342's IdP-offboarding runbook: those same
//! properties are what let a single `disable` call stand in for SCIM
//! de-provisioning, so the runbook's step 1 is pinned here rather than only
//! described in `.claude/skills/security-model/SKILL.md`.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as `authz.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test account_disable -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

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
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let db_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &db_url);
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
        config,
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
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));
    Some(system)
}

/// The system and router every test in this binary shares (build-loop plan,
/// Phase 3 task 4). Building a fresh `EngineSystem` per test cost ~0.3 s each;
/// the tests already share this binary's database, and each one provisions
/// its own uniquely named entities, users and roles, so sharing the in-memory
/// system adds no coupling the database did not already have. Tests run on
/// `attome_testkit::shared_runtime`, which keeps the pools' connections alive
/// between tests.
#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

impl TestSystem {
    fn state(&self) -> &EngineState {
        &self.state
    }
}

static SHARED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn test_system() -> Option<TestSystem> {
    SHARED
        .get_or_init(|| async {
            let system = build_test_system().await?;
            let state = system.state().clone();
            Some(TestSystem {
                state,
                app: build_app(system),
            })
        })
        .await
        .clone()
}

fn full_app(system: TestSystem) -> axum::Router {
    system.app
}

fn build_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
}

fn session_cookie(user_id: Uuid) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 3600,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: "attome-test".into(),
        aud: "attome-test".into(),
        typ: attome_auth::TokenType::Session,
    };
    let signing_ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &signing_ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

async fn seed_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("disable-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let key = "system.admin";
    let privilege_id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(key)
        .fetch_one(db)
        .await
        .expect("system.admin privilege must already be seeded by attome_security::seed::seed");

    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway admin grant");

    (user_id, session_cookie(user_id))
}

/// A throwaway non-admin target user with a real email (for the lock-key
/// path) and a live API key.
async fn seed_target_with_api_key(system: &TestSystem) -> (Uuid, Uuid) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("disable-target-{user_id}@example.test");
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("disable-test-target-{user_id}"))
    .bind(&email)
    .execute(db)
    .await
    .expect("insert throwaway target user_account");

    let key_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO api_key (id, user_ref, name, public_key, secret_hash, is_active) \
         VALUES ($1, $2, 'test key', $3, 'hmac256:v0$deadbeef', true)",
    )
    .bind(key_id)
    .bind(user_id)
    .bind(format!("pub-{key_id}"))
    .execute(db)
    .await
    .expect("insert throwaway api key");

    (user_id, key_id)
}

/// A live, unredeemed refresh token for `user_id`. Inserted directly rather
/// than through `attome_auth::refresh::issue` because nothing here ever presents
/// the token — the assertion is on `revoked_at`, so the secret never has to be
/// verifiable and a placeholder hash keeps the test off the KDF entirely.
async fn seed_refresh_token(db: &attome_db::DbPool, user_id: Uuid) -> Uuid {
    let token_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO refresh_token \
         (id, user_ref, public_id, secret_hash, family_id, expires_at) \
         VALUES ($1, $2, $3, 'hmac256:v0$deadbeef', $4, NOW() + INTERVAL '30 days')",
    )
    .bind(token_id)
    .bind(user_id)
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("insert throwaway refresh token");
    token_id
}

async fn fetch_refresh_revoked(db: &attome_db::DbPool, token_id: Uuid) -> bool {
    let revoked_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT revoked_at FROM refresh_token WHERE id = $1")
            .bind(token_id)
            .fetch_one(db)
            .await
            .expect("fetch refresh token revoked_at");
    revoked_at.is_some()
}

async fn fetch_epoch(db: &attome_db::DbPool, user_id: Uuid) -> i32 {
    sqlx::query_scalar("SELECT auth_epoch FROM user_account WHERE id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .expect("fetch auth_epoch")
}

async fn fetch_key_active(db: &attome_db::DbPool, key_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_active FROM api_key WHERE id = $1")
        .bind(key_id)
        .fetch_one(db)
        .await
        .expect("fetch api key is_active")
}

/// D-121: disabling a user bumps auth_epoch (inside the same transaction as
/// the is_active flip) and revokes every live API key the user holds — both
/// in the SAME admin call, not a follow-up step. Re-enabling flips
/// is_active back but must NOT resurrect the disabled keys (review item 6:
/// disable is a termination-style action on this platform, since there is
/// no separate "suspend" endpoint yet).
#[test]
fn disable_bumps_epoch_and_revokes_api_keys_enable_does_not_restore_keys() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_admin(&system).await;
        let (target_id, key_id) = seed_target_with_api_key(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        assert_eq!(fetch_epoch(&db, target_id).await, 0);
        assert!(fetch_key_active(&db, key_id).await);

        let disable_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/security/users/{target_id}/disable"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(disable_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            fetch_epoch(&db, target_id).await,
            1,
            "disable must bump auth_epoch exactly once"
        );
        assert!(
            !fetch_key_active(&db, key_id).await,
            "disable must deactivate the target's live API keys"
        );

        let enable_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/security/users/{target_id}/enable"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(enable_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            fetch_epoch(&db, target_id).await,
            2,
            "enable also bumps auth_epoch (symmetry, see set_user_active's doc comment)"
        );
        assert!(
            !fetch_key_active(&db, key_id).await,
            "re-enabling the account must NOT resurrect a key that was revoked by disable"
        );
    })
}

/// D-342 (IdP-offboarding runbook): step 1 of the runbook — the single
/// `disable` call — must by itself kill the refresh path, not just the access
/// token. Without this, a de-provisioned employee holding a live refresh
/// cookie could mint a fresh access token stamped with the *new* `auth_epoch`
/// and keep working, which would defeat the epoch check
/// `a_disabled_users_already_issued_session_token_is_rejected` proves below.
///
/// Two independent mechanisms already guarantee this, and this test pins the
/// first one — the only one nothing else covers end to end:
///
/// 1. `set_user_active`'s post-commit `attome_auth::refresh::revoke_all_for_user`
///    (`account_state.rs`) stamps `revoked_at` on every live row. Asserted here.
/// 2. `attome_auth::refresh::redeem`'s `is_active` join rejects the token even if
///    (1) somehow did not run — covered by `attome-auth`'s
///    `refresh_flow::a_live_token_for_a_disabled_user_is_rejected`.
///
/// `refresh_flow::revoke_all_for_user_kills_every_family` covers the primitive
/// in isolation; what was untested until now is that this *endpoint* actually
/// calls it, which is the claim the runbook rests on.
#[test]
fn disable_revokes_the_targets_live_refresh_tokens() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_admin(&system).await;
        let (target_id, _) = seed_target_with_api_key(&system).await;
        let db = system.state().base.db.clone();
        let token_id = seed_refresh_token(&db, target_id).await;
        let app = full_app(system);

        assert!(
            !fetch_refresh_revoked(&db, token_id).await,
            "the seeded refresh token must start out live"
        );

        let disable_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/security/users/{target_id}/disable"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(disable_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        assert!(
            fetch_refresh_revoked(&db, token_id).await,
            "disable must revoke every live refresh token the target holds — \
         otherwise a de-provisioned user refreshes back into a valid session"
        );
    })
}

/// A disabled account's already-issued session_token must stop authenticating
/// within the epoch check, not just once the refresh token separately dies —
/// the D-113 Phase 2 gap this session's review round asked to close.
#[test]
fn a_disabled_users_already_issued_session_token_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin_cookie) = seed_admin(&system).await;
        let (target_id, _) = seed_target_with_api_key(&system).await;
        let app = full_app(system);

        // Epoch 0 at issue time (matches the account's epoch 0 at seed time).
        let target_cookie = session_cookie(target_id);
        let whoami = Request::builder()
            .method("GET")
            .uri("/api/v1/auth/mfa/status")
            .header("cookie", &target_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(whoami).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a fresh epoch-0 token for an epoch-0 account must authenticate"
        );

        let disable_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/security/users/{target_id}/disable"))
            .header("cookie", &admin_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(disable_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let stale_whoami = Request::builder()
            .method("GET")
            .uri("/api/v1/auth/mfa/status")
            .header("cookie", &target_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(stale_whoami).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "the same session_token, minted before the disable bumped auth_epoch, \
         must be rejected immediately, not just once it naturally expires"
        );
    })
}

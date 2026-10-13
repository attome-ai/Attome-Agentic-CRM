//! Integration tests for M02/D-412's runtime settings API
//! (`/api/v1/admin/settings`, `/api/v1/settings/me`).
//!
//! The one M02 §6 explicitly requires: a boot-time-only key is rejected when
//! attempted at runtime via the settings API
//! (`boot_time_only_key_is_rejected_at_runtime_by_admin_put`). The rest cover
//! the resolution-order/scope contract the handlers build on top of
//! `attome_core::setting_store`'s already-unit-tested `resolve()`.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as `account_disable.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test settings_admin -- --test-threads=1
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
    attome_testkit::migrated_db_url()?;

    let config = test_config();
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

async fn seed_user(db: &attome_db::DbPool, label: &str) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("settings-test-{label}-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    (user_id, session_cookie(user_id))
}

async fn seed_admin(db: &attome_db::DbPool) -> (Uuid, String) {
    let (user_id, cookie) = seed_user(db, "admin").await;
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
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
    (user_id, cookie)
}

fn put_req(uri: &str, cookie: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_req(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// M02 §6's required test: a boot-time-only descriptor
/// (`auth.session_ttl_minutes`, registered specifically to prove this,
/// see `setting_catalog.rs`) is rejected — even by an admin, even with an
/// otherwise well-formed request — because the descriptor itself declares
/// `boot_time_only = true` (D-038/D-412).
#[test]
fn boot_time_only_key_is_rejected_at_runtime_by_admin_put() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let app = full_app(system);

        let req = put_req(
            "/api/v1/admin/settings/auth.session_ttl_minutes",
            &admin_cookie,
            serde_json::json!({"scope": "deployment", "value": 60}),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a boot_time_only descriptor must never be writable through the runtime API"
        );
    })
}

/// The unknown-key path stays a 404 (never silently accepted, never
/// confused with the boot-time-only 422) — the closed catalogue is the only
/// source of truth for what keys exist.
#[test]
fn unknown_setting_key_is_404() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let app = full_app(system);

        let req = put_req(
            "/api/v1/admin/settings/does.not_exist",
            &admin_cookie,
            serde_json::json!({"scope": "deployment", "value": "x"}),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    })
}

/// Schema validation actually runs at write time — an out-of-range value for
/// `core.list_page_size` (max 200) is rejected before anything is written.
#[test]
fn schema_violation_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let app = full_app(system);

        let req = put_req(
            "/api/v1/admin/settings/core.list_page_size",
            &admin_cookie,
            serde_json::json!({"scope": "deployment", "value": 999}),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

/// The full round trip: an admin sets a deployment-scope default, it shows
/// up in `GET /api/v1/admin/settings` with `source = "deployment"`; a
/// different, ordinary user then sets their own override through
/// `/api/v1/settings/me` and sees `source = "user"` — proving the
/// user-over-deployment half of the resolution order end to end, on top of
/// the DB, not just against `SettingsSnapshot::resolve`'s existing unit test.
#[test]
fn deployment_default_and_user_override_resolve_in_order() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, admin_cookie) = seed_admin(&db).await;
        let (_, user_cookie) = seed_user(&db, "member").await;
        let app = full_app(system);

        // Admin sets the deployment-wide default.
        let req = put_req(
            "/api/v1/admin/settings/core.locale",
            &admin_cookie,
            serde_json::json!({"scope": "deployment", "value": "fr-FR"}),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);

        // Admin overview reflects it.
        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/admin/settings", &admin_cookie))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let listing = body_json(resp).await;
        let locale_item = listing["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["key"] == "core.locale")
            .expect("core.locale must be in the admin listing");
        assert_eq!(locale_item["value"], "fr-FR");
        assert_eq!(locale_item["source"], "deployment");

        // Before any override, the ordinary user inherits the deployment default.
        let resp = app
            .clone()
            .oneshot(get_req("/api/v1/settings/me", &user_cookie))
            .await
            .unwrap();
        let mine = body_json(resp).await;
        let locale_mine = mine["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["key"] == "core.locale")
            .expect("core.locale must be in /settings/me");
        assert_eq!(locale_mine["value"], "fr-FR");
        assert_eq!(locale_mine["source"], "deployment");

        // The user sets their own override.
        let req = put_req(
            "/api/v1/settings/me/core.locale",
            &user_cookie,
            serde_json::json!({"value": "ja-JP"}),
        );
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);

        let resp = app
            .oneshot(get_req("/api/v1/settings/me", &user_cookie))
            .await
            .unwrap();
        let mine = body_json(resp).await;
        let locale_mine = mine["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["key"] == "core.locale")
            .expect("core.locale must be in /settings/me");
        assert_eq!(locale_mine["value"], "ja-JP");
        assert_eq!(locale_mine["source"], "user");
    })
}

/// `core.list_page_size` does not allow the `user` scope
/// (`setting_catalog.rs`) — self-service must not be able to set it through
/// `/api/v1/settings/me` even though it is otherwise a valid, runtime-eligible
/// key.
#[test]
fn self_service_cannot_set_a_key_that_disallows_user_scope() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_, user_cookie) = seed_user(&db, "member").await;
        let app = full_app(system);

        let req = put_req(
            "/api/v1/settings/me/core.list_page_size",
            &user_cookie,
            serde_json::json!({"value": 50}),
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

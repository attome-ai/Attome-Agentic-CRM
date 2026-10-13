//! Integration tests for M95/D-430's feature-flag API
//! (`/api/v1/admin/features`, `/api/v1/features`).
//!
//! `attome_core::feature_flag_store`'s own unit tests already pin the
//! invariant and the dependency check as pure functions; these prove the
//! same behavior end to end through the real HTTP routes — closed catalogue
//! (404), dependency rejection (422), and, most importantly, that an admin
//! turning a flag fully on cannot make it evaluate `true` through
//! `GET /api/v1/features` when the live license doesn't hold that flag's
//! module (D-430's invariant, composed with the real `ModuleSet`
//! arc-swap rather than a hand-built one).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as `settings_admin.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test features_admin -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_modules::{MODULE_CORE, ModuleSet};
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

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

/// `license_module_bits`: which modules the test's `ModuleSet` holds —
/// `None` means "every module" (the default `settings_admin.rs` tests use),
/// `Some(&[...])` sets exactly those and nothing else, so a test can prove
/// the D-430 invariant against a license that genuinely doesn't hold a given
/// flag's module.
async fn test_system(
    license_module_bits: Option<&[attome_modules::ModuleId]>,
) -> Option<EngineSystem> {
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

    let module_bits = match license_module_bits {
        None => [u64::MAX; 4],
        Some(modules) => {
            let mut bits = [0u64; 4];
            for m in modules {
                bits[m.word] |= m.mask;
            }
            bits
        }
    };
    system
        .state()
        .modules
        .store(std::sync::Arc::new(ModuleSet::from_bits(module_bits)));
    Some(system)
}

fn full_app(system: EngineSystem) -> axum::Router {
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
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("features-test-{label}-{user_id}"))
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

fn full_on_policy() -> serde_json::Value {
    serde_json::json!({
        "deployment": true,
        "user_overrides": {},
        "role_overrides": {},
        "percentage": null,
    })
}

/// The closed catalogue: an unregistered key is 404, never silently accepted.
#[tokio::test]
async fn unknown_feature_flag_key_is_404() {
    let system = skip_if_no_db!(test_system(None).await);
    let db = system.state().base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let req = put_req(
        "/api/v1/admin/features/does.not_exist",
        &admin_cookie,
        full_on_policy(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// M95 checklist item 3: enabling `core.beta_ui_advanced_panels`
/// deployment-wide while its prerequisite `core.beta_ui` is off is rejected
/// with a 422, through the real write path (not just the pure-function unit
/// test in `attome_core::feature_flag_store`).
#[tokio::test]
async fn enabling_a_dependent_flag_without_its_prerequisite_is_rejected() {
    let system = skip_if_no_db!(test_system(None).await);
    let db = system.state().base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;
    let app = full_app(system);

    let req = put_req(
        "/api/v1/admin/features/core.beta_ui_advanced_panels",
        &admin_cookie,
        full_on_policy(),
    );
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// The full round trip: an admin turns `core.beta_ui` fully on (deployment
/// scope, licensed module) and an ordinary user's `GET /api/v1/features`
/// reflects it immediately (same-node synchronous cache refresh, D-430).
#[tokio::test]
async fn effective_features_endpoint_reflects_an_admin_write() {
    let system = skip_if_no_db!(test_system(None).await);
    let db = system.state().base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;
    let (_, user_cookie) = seed_user(&db, "member").await;
    let app = full_app(system);

    let req = put_req(
        "/api/v1/admin/features/core.beta_ui",
        &admin_cookie,
        full_on_policy(),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "{:?}", body_json(resp).await);

    let resp = app
        .oneshot(get_req("/api/v1/features", &user_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let effective = body_json(resp).await;
    assert_eq!(effective["flags"]["core.beta_ui"], true);
}

/// D-430's invariant, end to end through the real HTTP routes: an admin can
/// turn `project.gantt_v2_preview` (gated on `MODULE_PROJECT`) fully on —
/// the write itself succeeds, nothing about *storing* the value is
/// license-gated — but a caller under a license that only holds `MODULE_CORE`
/// still sees it `false` via `GET /api/v1/features`. A flag can narrow the
/// license, never widen it.
#[tokio::test]
async fn a_flag_under_an_unlicensed_module_never_evaluates_true_through_the_api() {
    let system = skip_if_no_db!(test_system(Some(&[MODULE_CORE])).await);
    let db = system.state().base.db.clone();
    let (_, admin_cookie) = seed_admin(&db).await;
    let (_, user_cookie) = seed_user(&db, "member").await;
    let app = full_app(system);

    let req = put_req(
        "/api/v1/admin/features/project.gantt_v2_preview",
        &admin_cookie,
        full_on_policy(),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "storing the value itself is not license-gated: {:?}",
        body_json(resp).await
    );

    let resp = app
        .oneshot(get_req("/api/v1/features", &user_cookie))
        .await
        .unwrap();
    let effective = body_json(resp).await;
    assert_eq!(
        effective["flags"]["project.gantt_v2_preview"], false,
        "a flag must never make a feature reachable that the license gate hides"
    );
}

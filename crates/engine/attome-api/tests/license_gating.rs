//! Integration tests for P1.8 money-path #4 — license gating:
//! (1) every registered model route is mounted and checks the live
//!     `Arc<ArcSwap<ModuleSet>>` on every request, so license upgrades and
//!     expiry downgrades take effect without restarting the process;
//! (2) the self-hosted runtime module configuration (`module_configuration`,
//!     Module Management) is the only thing that turns a module off (D-778,
//!     superseding D-635): no signed licence is checked, so every module is
//!     on unless the configuration leaves it out. The signed-licence tests
//!     that used to live here (expired or intermediate-signed rows degrading
//!     the deployment) were removed with that check; `license_precedence.rs`
//!     proves a licence row is ignored.
//!
//! Unlicensed model routes return `AppError::FeatureHidden(module_name)`
//! (D-279, P-license-enforcement-hardening Phase 2, Option 1): a 403 naming
//! the unlicensed module, not a stealth 404 — this deployment model is
//! single-tenant/on-premise (D-002), so there's no multi-tenant traffic for
//! a 404 to protect, and an unnamed 404 was a real support cost for
//! enterprise API integrators.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — skips (loudly) when
//! `DATABASE_URL` is unset, except under `CI`, per the P1.8 testing-baseline convention. Run
//! manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test license_gating -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::sync::Arc;

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::{EngineModel, EngineState};
use attome_modules::{ModuleId, ModuleSet};
use attome_server::AppState;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

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

/// Seeds a throwaway authenticated (non-admin) user — just enough to clear
/// `authn`; license gating happens at the router/registry level, before any
/// privilege check, so no privileges are needed here.
async fn seed_user(db: &attome_db::DbPool) -> String {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("license-gating-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    session_cookie(user_id)
}

/// Minimal test-only licensable model — exercises the real
/// `ModelRegistry::mounted_routes` gating mechanism (not a mock of it).
/// Module id 254 is arbitrary; it doesn't need to avoid collision with real
/// modules for these tests since a degraded license has every bit zero
/// regardless of which id is checked.
struct TestPaidModel;

impl EngineModel for TestPaidModel {
    fn name(&self) -> &'static str {
        "test-paid-model"
    }
    fn module_id(&self) -> ModuleId {
        ModuleId::new(254)
    }
    fn routes(&self) -> Router<EngineState> {
        Router::new().route("/test-paid-feature", get(|| async { "ok" }))
    }
}

fn active_license_with(module_id: ModuleId) -> ModuleSet {
    let mut bits = [0u64; 4];
    bits[module_id.word] |= module_id.mask;
    ModuleSet::from_bits(bits)
}

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

async fn test_system() -> Option<EngineSystem> {
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

    Some(
        EngineSystem::builder(state)
            .register(attome_security::model::SecurityModel)
            .register(attome_notification::NotificationModel)
            .register(attome_workflow::WorkflowModel)
            .register(attome_report::ReportModel)
            .register(attome_project::ProjectModel)
            .register(TestPaidModel)
            .build()
            .await
            .expect("build EngineSystem"),
    )
}

/// csrf_protect (P-cookie-csrf-hardening) rejects a cookie-authenticated
/// unsafe-method request with neither a safe Sec-Fetch-Site nor an allow-
/// listed Origin — a real browser always sends the former, an in-process
/// `oneshot()` call sends neither. This file's `test_config()` has no `cors`
/// section (so no Origin would ever be allow-listed), so Sec-Fetch-Site is
/// the only viable signal — same fix a legitimate non-browser caller would
/// need in production, not a bypass of the check.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    req
}

/// Builds the full assembled app the same way `main.rs` does (Plan 1.3):
/// inner (authn/authz/RateLimit/Idempotency) → s2s_authn → outer
/// (RequestId..BodyLimit). `core_routes()` alone is bare, middleware-free
/// routes as of this plan — using it directly would silently skip auth.
fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
}

/// A fresh database has no `module_configuration` row, so every module is on.
/// Writes the row with every module except `name` enabled.
async fn narrow_configuration_excluding(db: &attome_db::DbPool, name: &str) {
    let kept: Vec<String> = ModuleSet::all()
        .names()
        .filter(|module| *module != name)
        .map(str::to_owned)
        .collect();
    sqlx::query(
        "INSERT INTO module_configuration (singleton, enabled, enabled_modules) VALUES (TRUE, TRUE, $1) ON CONFLICT (singleton) DO UPDATE SET enabled = TRUE, enabled_modules = EXCLUDED.enabled_modules",
    )
    .bind(&kept)
    .execute(db)
    .await
    .expect("narrow runtime module configuration");
}

#[tokio::test]
async fn imported_license_enables_module_without_restarting() {
    // A fresh test DB has no license row, so the system boots degraded.
    // The ArcSwap store below is the same live-state transition the Module
    // Management PUT performs (the licence import route was deleted, D-790).
    let system = skip_if_no_db!(test_system().await);
    // A deployment boots with every module on; narrow to core first.
    system
        .state()
        .modules
        .store(Arc::new(ModuleSet::core_only()));
    assert!(
        !system.state().modules.load().has(ModuleId::new(254)),
        "sanity check: the test module must not be licensed",
    );
    let cookie = seed_user(&system.state().base.db).await;
    let license = system.state().modules.clone();
    let app = full_app(system);

    let denied_request = Request::builder()
        .method("GET")
        .uri("/test-paid-feature")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(denied_request).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an unlicensed module's route must not be reachable"
    );

    license.store(Arc::new(active_license_with(ModuleId::new(254))));

    let enabled_request = Request::builder()
        .method("GET")
        .uri("/test-paid-feature")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(enabled_request).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a newly imported license must enable an already-mounted route without restart"
    );
}

#[tokio::test]
async fn license_degradation_blocks_next_request_without_restarting() {
    let system = skip_if_no_db!(test_system().await);
    let cookie = seed_user(&system.state().base.db).await;
    let license = system.state().modules.clone();
    license.store(Arc::new(active_license_with(ModuleId::new(254))));
    let app = full_app(system);

    let allowed_request = Request::builder()
        .method("GET")
        .uri("/test-paid-feature")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(allowed_request).await.expect("request");
    assert_eq!(res.status(), StatusCode::OK);

    // This simulates the hourly recheck storing ModuleSet::core_only()
    // after it detects expiry. The Router remains the same instance.
    license.store(Arc::new(ModuleSet::core_only()));

    let denied_request = Request::builder()
        .method("GET")
        .uri("/test-paid-feature")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(denied_request).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an expired license must block the next request without restart"
    );
}

/// P2.11/D-010 — the Notification Engine's real `NotificationModel` (not a
/// test double) must be unreachable when the runtime module configuration
/// does not list it as enabled, same as any other paid module. Migration
/// 0075 seeds every module (including 'notification') enabled by default,
/// so this test explicitly narrows the seeded row first — a fresh test DB's
/// default state is licensed, not unlicensed (see this file's header).
#[tokio::test]
async fn notification_dispatch_route_is_hidden_when_unlicensed() {
    let _ = skip_if_no_db!(attome_testkit::migrated_db_url());
    let config = test_config();
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    narrow_configuration_excluding(&db, "notification").await;

    let system = skip_if_no_db!(test_system().await);
    assert!(
        !system
            .state()
            .modules
            .load()
            .has(attome_modules::MODULE_NOTIFICATION),
        "sanity check: notification must not be enabled once removed from the runtime module configuration",
    );
    let cookie = seed_user(&system.state().base.db).await;
    let app = full_app(system);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notification/dispatch")
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an unlicensed notification module's dispatch route must not be reachable"
    );
}

#[tokio::test]
async fn workflow_definitions_route_is_hidden_when_unlicensed() {
    let _ = skip_if_no_db!(attome_testkit::migrated_db_url());
    let config = test_config();
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    narrow_configuration_excluding(&db, "workflow").await;

    let system = skip_if_no_db!(test_system().await);
    assert!(
        !system
            .state()
            .modules
            .load()
            .has(attome_modules::MODULE_WORKFLOW),
        "sanity check: workflow must not be enabled once removed from the runtime module configuration",
    );
    let cookie = seed_user(&system.state().base.db).await;
    let app = full_app(system);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/workflow/definitions")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an unlicensed workflow module's definitions route must not be reachable"
    );
}

/// Project Management (attome-project) — same shape as
/// `workflow_definitions_route_is_hidden_when_unlicensed` above. Migration
/// 0075 seeds every module (including 'project') enabled by default, so this
/// narrows the runtime module configuration first. Hits the project id in a
/// made-up UUID — license gating runs at the `ModelRegistry`/router layer,
/// before the handler's own DB-backed record lookup ever executes, so the
/// route must 403 for a nonexistent project just as it would for a real one.
#[tokio::test]
async fn project_summary_route_is_hidden_when_unlicensed() {
    let _ = skip_if_no_db!(attome_testkit::migrated_db_url());
    let config = test_config();
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    narrow_configuration_excluding(&db, "project").await;

    let system = skip_if_no_db!(test_system().await);
    assert!(
        !system
            .state()
            .modules
            .load()
            .has(attome_modules::MODULE_PROJECT),
        "sanity check: project must not be enabled once removed from the runtime module configuration",
    );
    let cookie = seed_user(&system.state().base.db).await;
    let app = full_app(system);

    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/project/{}/summary", Uuid::now_v7()))
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an unlicensed project module's summary route must not be reachable"
    );
}

#[tokio::test]
async fn report_widget_types_route_is_hidden_when_unlicensed() {
    let _ = skip_if_no_db!(attome_testkit::migrated_db_url());
    let config = test_config();
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    narrow_configuration_excluding(&db, "report").await;

    let system = skip_if_no_db!(test_system().await);
    assert!(
        !system
            .state()
            .modules
            .load()
            .has(attome_modules::MODULE_REPORT),
        "sanity check: report must not be enabled once removed from the runtime module configuration",
    );
    let cookie = seed_user(&system.state().base.db).await;
    let app = full_app(system);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/report/widget-types")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an unlicensed report module's widget-types route must not be reachable"
    );
}

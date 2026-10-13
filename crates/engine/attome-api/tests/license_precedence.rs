//! D-778 (supersedes D-635): no signed licence is ever checked. Every
//! deployment runs every module with no seat cap and no expiry, and the
//! self-hosted runtime module configuration (`module_configuration`,
//! Module Management, PUT /api/v1/admin/license/modules) is the only switch
//! that turns a module off, hiding its routes, entities and sidebar items.
//! There is no seat gate (CLEANUP-REVIEW 1.2): the tests below inject a
//! zero-free-seat limit onto state.license and prove that no
//! principal-activating path refuses on it any more.
//!
//! Requires a live Postgres (DATABASE_URL) and Redis (REDIS_URL or
//! TEST_REDIS_HOST/TEST_REDIS_PORT) and skips loudly when DATABASE_URL is
//! unset, except under CI. Run against a throwaway database:
//!
//! ```powershell
//! cargo test -p attome-api --test license_precedence -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_modules::{MODULE_CORE, MODULE_WORKFLOW, ModuleSet};
use attome_server::AppState;
use attome_testkit::point_config_at;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
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

/// Seeds a throwaway user, optionally granted `system.admin` — same pattern
/// `profiler_admin.rs` uses for its own `Authorized<Admin>`-gated routes.
async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("license-precedence-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    if admin {
        let privilege_id: Uuid =
            sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
                .fetch_one(db)
                .await
                .expect("system.admin privilege must already be seeded by attome_security::seed");
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
    }

    (user_id, session_cookie(user_id))
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

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Builds a fresh `EngineSystem` and lets it boot NATURALLY — i.e. does not
/// override `state.license` afterwards — so `system::load_license`'s real
/// composition (`verify_signed_license` narrowed by the runtime module
/// configuration) is what every test in this file observes, exactly as a
/// real deployment would get it. A fresh test database has no
/// `license` row and migration 0075's seeded
/// `module_configuration` row (`enabled = TRUE`, ~18/20 modules).
async fn test_system() -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
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
            .register(attome_workflow::WorkflowModel)
            .build()
            .await
            .expect("build EngineSystem"),
    )
}

/// Same origin-stamping trick `license_gating.rs` uses: an in-process
/// `oneshot()` call sends neither a browser `Sec-Fetch-Site` header nor an
/// allow-listed `Origin`, and this file's `test_config()` has no `cors`
/// section — so CSRF's same-origin signal has to come from here for the
/// mutating `PUT` request in this file to clear it, same as a real
/// same-origin browser request would.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    req
}

fn full_app(system: EngineSystem) -> Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

/// `ModuleSet::degraded()`'s zero bits with just `MODULE_CORE` set — the
/// expected shape of `system::core_only_license()`'s output, reconstructed
/// here from the public `MODULE_CORE` constant rather than importing a
/// private function.
fn core_only_module_bits() -> [u64; 4] {
    let mut bits = [0u64; 4];
    bits[MODULE_CORE.word] |= MODULE_CORE.mask;
    bits
}

/// Sets the module configuration through the admin route, as an operator does.
async fn put_modules(app: &Router, admin_cookie: &str, enabled: bool, modules: &[&str]) -> Value {
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/admin/license/modules")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "enabled": enabled, "modules": modules }).to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("request");
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "PUT /admin/license/modules: {body:?}"
    );
    body
}

async fn workflow_status(app: &Router, cookie: &str) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/workflow/definitions")
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.expect("request").status()
}

/// Every module name, as Module Management accepts them.
fn every_module() -> Vec<&'static str> {
    attome_modules::MODULE_MAP
        .iter()
        .map(|(name, _)| *name)
        .collect()
}

/// D-778: with no `license` row the deployment is not core-only and
/// not seat-capped: it runs whatever Module Management enables.
#[tokio::test]
async fn no_licence_runs_every_configured_module_with_no_seat_cap() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let license = system.state().license.clone();
    let app = full_app(system);
    put_modules(&app, &admin_cookie, true, &every_module()).await;

    let active = license.load();
    assert!(
        active.has(MODULE_WORKFLOW),
        "workflow is on with no licence"
    );
    assert_eq!(active.max_users, u32::MAX, "no seat cap without a licence");
    assert_eq!(active.mode(), "module_configuration");
    drop(active);
    assert_ne!(
        workflow_status(&app, &admin_cookie).await,
        StatusCode::FORBIDDEN,
        "an enabled module's route is reachable with no licence imported"
    );
}

/// D-778: Module Management can switch any module off and back on, and the
/// switch is what hides the module's routes. There is no
/// `module_not_licensed` refusal any more.
#[tokio::test]
async fn module_management_switches_any_module_off_and_on() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let license = system.state().license.clone();
    let app = full_app(system);

    put_modules(&app, &admin_cookie, true, &["core"]).await;
    let off = license.load().has(MODULE_WORKFLOW);
    let off_status = workflow_status(&app, &admin_cookie).await;

    // Restore before asserting, so a failure cannot leak into other tests.
    let body = put_modules(&app, &admin_cookie, true, &every_module()).await;
    let on = license.load().has(MODULE_WORKFLOW);
    let on_status = workflow_status(&app, &admin_cookie).await;

    assert!(!off, "a module left out of the configuration is off");
    assert_eq!(off_status, StatusCode::FORBIDDEN, "and its route is hidden");
    assert!(
        on,
        "naming it again turns it back on, with no licence check"
    );
    assert_ne!(on_status, StatusCode::FORBIDDEN, "and its route is back");
    assert!(
        body["modules"]
            .as_array()
            .is_some_and(|items| items.iter().all(|m| m["licensed"] == true)),
        "every module is available to switch on: {body:?}"
    );
}

/// D-778: a Module Management write never introduces a seat cap.
#[tokio::test]
async fn module_management_never_imposes_a_seat_limit() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let license = system.state().license.clone();
    let app = full_app(system);
    put_modules(&app, &admin_cookie, true, &[]).await;
    let after = license.load().max_users;
    put_modules(&app, &admin_cookie, true, &every_module()).await;
    assert_eq!(after, u32::MAX);
}

/// D-635 §2: `enabled = false` in the runtime configuration leaves the core
/// module only — configuration can switch modules off, and core is never
/// among them.
#[tokio::test]
async fn a_disabled_runtime_configuration_leaves_core_only() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let license = system.state().license.clone();
    let app = full_app(system);

    let put = |enabled: bool| {
        Request::builder()
            .method("PUT")
            .uri("/api/v1/admin/license/modules")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "enabled": enabled, "modules": ["core"] }).to_string(),
            ))
            .unwrap()
    };
    let res = app.clone().oneshot(put(false)).await.expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    let disabled_bits = license.load().module_bits;

    // Restore an enabled row for the other tests sharing this database
    // before asserting, so a failure here cannot leak into them.
    let res = app.oneshot(put(true)).await.expect("request");
    assert_eq!(res.status(), StatusCode::OK);

    assert_eq!(
        disabled_bits,
        core_only_module_bits(),
        "a disabled configuration leaves core only"
    );
}

/// D-778: a licence row, even an expired and unsigned one, is never read. It
/// cannot degrade the deployment or change its modules. The row is removed
/// before any assertion, because every test in this binary shares the
/// database.
#[tokio::test]
async fn a_licence_row_is_ignored() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();

    let deployment_id = format!("ignored-licence-{}", Uuid::now_v7());
    sqlx::query(
        r#"INSERT INTO license
               (deployment_id, domain, tier, max_users, expiry,
                module_mask_0, module_mask_1, module_mask_2, module_mask_3,
                modules, issued_at, signature, created_at)
           VALUES ($1, 'localhost', 'paid', 1, NOW() - INTERVAL '1 day',
                   0, 0, 0, 0, ARRAY[]::text[], NOW() - INTERVAL '2 days',
                   'not-a-real-signature', NOW())"#,
    )
    .bind(&deployment_id)
    .execute(&db)
    .await
    .expect("insert an expired license row");

    let loaded = attome_api::load_license(&db).await;

    sqlx::query("DELETE FROM license WHERE deployment_id = $1")
        .bind(&deployment_id)
        .execute(&db)
        .await
        .expect("remove the licence's row");

    assert!(
        !loaded.is_degraded(),
        "a licence row never degrades the deployment"
    );
    assert_eq!(loaded.max_users, u32::MAX, "nor sets a seat cap");
}

// ── CLEANUP-REVIEW 1.2: no seat gate on any principal-activating path ──
//
// One licence helper for all three tests below, so they cannot drift from each
// other or from the composition the routes read.

/// Active `user_account` rows, counted the way the gate counts them.
async fn active_seats(db: &attome_db::DbPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM user_account WHERE is_active")
        .fetch_one(db)
        .await
        .expect("count active seats")
}

/// Puts exactly `free_seats` seats on the live licence — 0 meant "the next
/// principal is refused" under the removed gate. Injected onto the arc-swap to
/// prove nothing reads the limit any more.
fn license_with_free_seats(system: &EngineSystem, active: i64, free_seats: u32) {
    system.state().license.store(std::sync::Arc::new(ModuleSet {
        max_users: u32::try_from(active).expect("count fits u32") + free_seats,
        module_bits: [u64::MAX; 4],
        expires: chrono::Utc::now() + chrono::Duration::days(1),
    }));
}

/// Enabling (reactivating) a principal is not seat-gated: with a licence that
/// reports zero free seats, the re-enable still succeeds.
#[tokio::test]
async fn enabling_a_user_with_no_free_seats_succeeds() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();

    // A disabled account that the admin will try to bring back.
    let (target, _) = seed_user(&system, false).await;
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(target)
        .execute(&db)
        .await
        .expect("deactivate the target account");

    // No free seats once the admin exists too — under the removed gate this
    // re-enable would have been refused.
    let (_, admin_cookie) = seed_user(&system, true).await;
    license_with_free_seats(&system, active_seats(&db).await, 0);

    let app = full_app(system);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/security/users/{target}/enable"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    let status = res.status();
    let body = body_json(res).await;
    assert!(
        status.is_success(),
        "re-enabling with no free seats must succeed, got {status}: {body}"
    );

    let active: bool = sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
        .bind(target)
        .fetch_one(&db)
        .await
        .expect("re-read the target");
    assert!(active, "the enable must have written");
}

/// Generic CRUD on `user_account` is a real creation path (the admin
/// UI's user form uses it); with no free seats on the licence it still
/// creates the principal.
#[tokio::test]
async fn generic_crud_create_of_a_systemuser_is_not_seat_gated() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();

    let (_, admin_cookie) = seed_user(&system, true).await;
    license_with_free_seats(&system, active_seats(&db).await, 0);

    let app = full_app(system);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/user_account")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "email": format!("seat-gate-{}@example.test", Uuid::now_v7()) }).to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    let status = res.status();
    let body = body_json(res).await;
    assert!(
        status.is_success(),
        "a generic create of a systemuser with no free seats must succeed, got {status}: {body}"
    );
}

/// `--bootstrap-admin` loads the module availability itself (it runs before
/// any server exists). With no licence there is no seat cap, so a new admin is
/// created, and an existing account still resolves (the idempotent re-run).
#[tokio::test]
async fn bootstrap_admin_creates_without_a_licence_and_an_existing_account_still_resolves() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();

    let fresh_email = format!("bootstrap-new-{}@example.test", Uuid::now_v7());
    let outcome = attome_api::bootstrap_admin_gated(&db, &fresh_email)
        .await
        .expect("bootstrap needs no licence");
    assert!(
        !matches!(outcome, attome_auth::accounts::BootstrapOutcome::Disabled),
        "a new email is created, got {outcome:?}"
    );

    let known_email = format!("bootstrap-existing-{}@example.test", Uuid::now_v7());
    seed_active_with_email(&db, &known_email).await;
    let outcome = attome_api::bootstrap_admin_gated(&db, &known_email)
        .await
        .expect("re-running bootstrap for an existing account");
    assert!(
        matches!(
            outcome,
            attome_auth::accounts::BootstrapOutcome::AlreadyActive { .. }
        ),
        "an existing active account must resolve to AlreadyActive, got {outcome:?}"
    );
}

/// An active `user_account` row that carries an `email` — what
/// `bootstrap_admin` matches an account by, and what `seed_user` (an identity
/// fixture) does not provide.
async fn seed_active_with_email(db: &attome_db::DbPool, email: &str) {
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(Uuid::now_v7())
    .bind(format!("bootstrap-fixture-{}", Uuid::now_v7()))
    .bind(email)
    .execute(db)
    .await
    .expect("insert a seat-consuming fixture row with an email");
}

/// D-778: Module Management lists each installed project (a vertical's sidebar
/// root: top level, no module key, written by a bundle with `is_customized`)
/// with its areas, inactive ones included so they can be switched back on.
/// Platform groups (a module key, or not bundle-written) are not projects.
#[tokio::test]
async fn module_management_lists_each_installed_project_and_its_areas() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let root_name = format!("Test Vertical {}", Uuid::now_v7());
    let root: Uuid = sqlx::query_scalar(
        "INSERT INTO sidebar (name, display_order, is_customized, owner_layer) VALUES ($1, 900, true, 'project') \
         RETURNING id",
    )
    .bind(&root_name)
    .fetch_one(&db)
    .await
    .expect("insert a project root");
    sqlx::query(
        "INSERT INTO sidebar (name, parent_ref, display_order, is_customized, is_active, owner_layer) \
         VALUES ('Area One', $1, 1, true, true, 'project'), ('Area Two', $1, 2, true, false, 'project')",
    )
    .bind(root)
    .execute(&db)
    .await
    .expect("insert its areas");

    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/admin/license/modules")
        .header("cookie", &admin_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    let status = res.status();
    let body = body_json(res).await;

    sqlx::query("DELETE FROM sidebar WHERE id = $1 OR parent_ref = $1")
        .bind(root)
        .execute(&db)
        .await
        .expect("remove the test project");

    assert_eq!(status, StatusCode::OK, "{body:?}");
    let projects = body["projects"].as_array().expect("projects array");
    let project = projects
        .iter()
        .find(|p| p["name"] == root_name.as_str())
        .unwrap_or_else(|| panic!("the test project is listed: {body:?}"));
    let areas: Vec<(&str, bool)> = project["areas"]
        .as_array()
        .expect("areas")
        .iter()
        .map(|a| (a["name"].as_str().unwrap_or(""), a["is_active"] == true))
        .collect();
    assert_eq!(areas, vec![("Area One", true), ("Area Two", false)]);
    assert!(
        projects
            .iter()
            .all(|p| p["name"] != "Audit" && p["name"] != "Dashboard"),
        "platform groups are not projects: {body:?}"
    );
}

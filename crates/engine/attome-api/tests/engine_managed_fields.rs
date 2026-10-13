//! R-03 (`document/module-master-plans/M26-dashboard-remediation.md`) —
//! regression coverage for `attome_records::entity_mutation::
//! validate_engine_managed_fields`: a generic-CRUD `PATCH` must not be able
//! to set a field a model's own bespoke route owns the transition of
//! (`attome_dashboard.lifecycle_status` / `lifecycle.rs::do_publish_dashboard`,
//! `dashboard_decision.status` / `decision.rs::do_approve`), while an ordinary
//! field on the same entity still updates normally.
//!
//! Harness copied near-verbatim from `dashboard_migration.rs` /
//! `reserved_column_entry_points.rs` (this repo's established per-test-file
//! convention).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`).
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test engine_managed_fields -- --test-threads=1
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
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness ──────────────────────────────────────────────────────────────────

fn test_config(db: &DbUrlParts) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4194304, "request_timeout_secs": 15,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0,
                "migrator": {{ "user": "{db_user}", "password": "{db_password}" }}
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
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// Registers `DashboardModel` (not just `SecurityModel`) — this is
/// deliberate and load-bearing: `EngineState::engine_managed_fields` is only
/// populated from models the builder actually registered
/// (`ModelRegistry::engine_managed_fields`, mirroring `entity_modules`), so
/// without this the PATCH-rejection under test would never fire. The
/// `attome_dashboard`/`dashboard_decision` entities themselves are seeded
/// unconditionally by `EngineSystem::build()` regardless of registration (same
/// note `dashboard_migration.rs` makes) — registering the model here is
/// solely to reach its `engine_managed_fields()` declaration.
async fn build_test_system() -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let db_parts = DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse");

    let config = test_config(&db_parts);
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
        .register(attome_dashboard::DashboardModel)
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

async fn seed_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("engine-managed-fields-{user_id}@test.local"))
    .bind(format!("engine-managed-fields-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");

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

    (user_id, session_cookie(user_id))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn req(method: &str, uri: &str, cookie: &str, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(match body {
            Some(v) => Body::from(v.to_string()),
            None => Body::empty(),
        })
        .unwrap()
}

fn req_versioned(
    method: &str,
    uri: &str,
    cookie: &str,
    row_version: i64,
    body: &Value,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn create_record(
    app: &axum::Router,
    cookie: &str,
    entity: &str,
    body: &Value,
) -> (Uuid, i64) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}"),
            cookie,
            Some(body),
        ))
        .await
        .unwrap();
    let status = res.status();
    let seen = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create {entity} record: {seen:?}"
    );
    (
        seen["id"].as_str().unwrap().parse().unwrap(),
        seen["row_version"].as_i64().unwrap(),
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[test]
fn patching_dashboard_lifecycle_status_through_generic_crud_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_actor, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (id, row_version) = create_record(
            &app,
            &cookie,
            "attome_dashboard",
            &json!({ "name": "R-03 test dashboard", "dashboard_type": "personal" }),
        )
        .await;

        let res = app
            .clone()
            .oneshot(req_versioned(
                "PATCH",
                &format!("/api/v1/attome_dashboard/{id}"),
                &cookie,
                row_version,
                &json!({ "lifecycle_status": "published" }),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "PATCH must be rejected, not silently applied: {seen:?}"
        );
        let message = seen["message"]
            .as_str()
            .unwrap_or_else(|| panic!("error response must carry a message: {seen:?}"));
        // `AppError::Validation`'s `#[error("validation error: {0}")]` prefixes
        // every message with "validation error: " (`attome-types/src/error.rs`) —
        // asserted here so a caller's message shape can't regress unnoticed.
        assert_eq!(
            message,
            "validation error: 'lifecycle_status' is managed by the attome_dashboard engine; use its \
         lifecycle routes"
        );
    })
}

#[test]
fn patching_an_ordinary_dashboard_field_through_generic_crud_still_works() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_actor, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (id, row_version) = create_record(
            &app,
            &cookie,
            "attome_dashboard",
            &json!({ "name": "before", "dashboard_type": "personal" }),
        )
        .await;

        let res = app
            .clone()
            .oneshot(req_versioned(
                "PATCH",
                &format!("/api/v1/attome_dashboard/{id}"),
                &cookie,
                row_version,
                &json!({ "name": "after" }),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "ordinary field PATCH must succeed: {seen:?}"
        );
        assert_eq!(seen["data"]["name"], "after");
    })
}

#[test]
fn patching_decision_status_through_generic_crud_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_actor, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (id, row_version) = create_record(
            &app,
            &cookie,
            "dashboard_decision",
            &json!({
                "title": "R-03 test decision",
                "driver": "manual test",
                "status": "proposed",
                "recommended_by": "human",
            }),
        )
        .await;

        let res = app
            .clone()
            .oneshot(req_versioned(
                "PATCH",
                &format!("/api/v1/dashboard_decision/{id}"),
                &cookie,
                row_version,
                &json!({ "status": "approved" }),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "PATCH must be rejected, not silently applied: {seen:?}"
        );
        let message = seen["message"]
            .as_str()
            .unwrap_or_else(|| panic!("error response must carry a message: {seen:?}"));
        assert_eq!(
            message,
            "validation error: 'status' is managed by the dashboard_decision engine; use its lifecycle \
         routes"
        );
    })
}

// ── D-524: create-time guard ─────────────────────────────────────────────────

async fn post(app: &axum::Router, cookie: &str, entity: &str, body: &Value) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}"),
            cookie,
            Some(body),
        ))
        .await
        .unwrap();
    let status = res.status();
    (status, body_json(res).await)
}

#[test]
fn creating_a_dashboard_already_published_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_actor, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (status, seen) = post(
            &app,
            &cookie,
            "attome_dashboard",
            &json!({
                "name": "D-524 born published",
                "dashboard_type": "personal",
                "lifecycle_status": "published",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a dashboard must not be creatable in a published state: {seen:?}"
        );
        assert_eq!(
            seen["message"],
            "validation error: 'lifecycle_status' is managed by the attome_dashboard engine; a new \
         record must start as 'draft'"
        );
    })
}

#[test]
fn creating_a_dashboard_without_lifecycle_status_starts_as_draft() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_actor, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        for body in [
            json!({ "name": "D-524 omitted", "dashboard_type": "personal" }),
            json!({ "name": "D-524 explicit draft", "dashboard_type": "personal", "lifecycle_status": "draft" }),
            json!({ "name": "D-524 null", "dashboard_type": "personal", "lifecycle_status": null }),
        ] {
            let (status, seen) = post(&app, &cookie, "attome_dashboard", &body).await;
            assert_eq!(status, StatusCode::CREATED, "create {body}: {seen:?}");
            assert_eq!(
                seen["data"]["lifecycle_status"], "draft",
                "the initial state must be written explicitly for {body}: {seen:?}"
            );
        }
    })
}

#[test]
fn creating_a_decision_already_approved_is_rejected_and_omitting_status_starts_proposed() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_actor, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (status, seen) = post(
            &app,
            &cookie,
            "dashboard_decision",
            &json!({
                "title": "D-524 born approved",
                "driver": "manual test",
                "status": "approved",
                "recommended_by": "human",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{seen:?}");
        assert_eq!(
            seen["message"],
            "validation error: 'status' is managed by the dashboard_decision engine; a new \
         record must start as 'proposed'"
        );

        // `status` is a required attribute: omitting it must still create the
        // record, because the engine's initial value is written before
        // `validate_body` runs.
        let (status, seen) = post(
            &app,
            &cookie,
            "dashboard_decision",
            &json!({
                "title": "D-524 omitted status",
                "driver": "manual test",
                "recommended_by": "human",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{seen:?}");
        assert_eq!(seen["data"]["status"], "proposed");
    })
}

/// The upsert route reaches `create_one` through its own match-or-create
/// path, so it is proven separately from plain POST. Bulk, staged import and
/// bundle record sets call the same `create_one` (D-524's Phase 0 inventory);
/// the rule's branches are unit-tested in `entity_mutation.rs`.
#[test]
fn upserting_a_new_dashboard_already_published_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let name = format!("D-524 upsert {actor}");
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/attome_dashboard/upsert",
                &cookie,
                Some(&json!({
                    "match": { "name": name },
                    "data": { "dashboard_type": "personal", "lifecycle_status": "published" },
                })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "upsert must not create a published dashboard: {seen:?}"
        );
        assert_eq!(
            seen["message"],
            "validation error: 'lifecycle_status' is managed by the attome_dashboard engine; a new \
         record must start as 'draft'"
        );
    })
}

#[test]
fn patching_an_ordinary_decision_field_through_generic_crud_still_works() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_actor, cookie) = seed_admin(&system).await;
        let app = full_app(system);

        let (id, row_version) = create_record(
            &app,
            &cookie,
            "dashboard_decision",
            &json!({
                "title": "before",
                "driver": "manual test",
                "status": "proposed",
                "recommended_by": "human",
            }),
        )
        .await;

        let res = app
            .clone()
            .oneshot(req_versioned(
                "PATCH",
                &format!("/api/v1/dashboard_decision/{id}"),
                &cookie,
                row_version,
                &json!({ "title": "after" }),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "ordinary field PATCH must succeed: {seen:?}"
        );
        assert_eq!(seen["data"]["title"], "after");
    })
}

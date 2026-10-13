//! P-environment-promotion §5 steps 5 and 13 — the attome-api half of the
//! service reconcile API (`query_admin::reconcile_query`,
//! `view_admin::reconcile_view`, `sidebar::reconcile_sidebar_item` and their
//! retire/reactivate siblings) plus the admin-write ownership marking and
//! the PATCH rewiring onto `attome_metadata::provision::reconcile_*`.
//!
//! Covers:
//! - an admin `POST/PATCH /api/v1/admin/entities` and `.../fields` sets
//!   `is_customized = true` on the row it touches, and `is_sensitive` is
//!   updatable through the PATCH (it was not before);
//! - admin create of a duplicate named query for the same entity is a 409
//!   (`uq_core_sql_query_entity_name`, 0133), not a 500;
//! - `reconcile_query`: create, `Unchanged` on an identical description
//!   (no new version row), `Seed` skips a customized row, `Bundle { false }`
//!   clears the marker, retire/reactivate round-trip;
//! - `reconcile_view`: create / unchanged / retire / reactivate;
//! - `reconcile_sidebar_item`: create under a parent path, unchanged,
//!   retire cascades to children, reactivate, admin duplicate sibling 409.
//!
//! Requires a live Postgres (`DATABASE_URL`, cloned per binary by
//! `attome_testkit`) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same
//! convention as `view_admin.rs`. Tests share one database without per-test
//! cleanup; every fixture name is unique per run.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_HOST = "127.0.0.1"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test reconcile_services -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::model::{QueryRef, SidebarDef, ViewDef};
use attome_api::sidebar::{reactivate_sidebar_item, reconcile_sidebar_item, retire_sidebar_item};
use attome_api::view_admin::{reactivate_view, reconcile_view, retire_view};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_metadata::provision::{ReconcileOutcome, ReconcilePolicy};
use attome_records::query_admin::{QueryDef, reactivate_query, reconcile_query, retire_query};
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
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
    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
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
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
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

/// Seeds an admin `user_account` with the `system.admin` privilege
/// (same shape as `view_admin.rs::seed_user`). Returns `(user_id, cookie)`.
async fn seed_admin(db: &DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("reconcile-test-{user_id}"))
    .bind(format!("reconcile-test-{user_id}@test.local"))
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
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Same-origin headers so the CSRF middleware accepts a cookie-authenticated
/// mutation (matches `view_admin.rs`'s convention).
fn req(method: &str, uri: &str, cookie: &str, body: Option<Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    match body {
        Some(v) => builder
            .header("content-type", "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

/// A short unique logicalname (<= 48 chars, `attome_metadata::provision::MAX_IDENTIFIER_LEN`).
fn unique_name(prefix: &str) -> String {
    let suffix = Uuid::now_v7().simple().to_string();
    format!("{prefix}_{}", &suffix[suffix.len() - 10..])
}

/// Creates a real entity through the admin API (physical table included) and
/// returns `(entity_id, logicalname)`.
async fn create_entity(app: &axum::Router, cookie: &str, prefix: &str) -> (Uuid, String) {
    let logicalname = unique_name(prefix);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            cookie,
            Some(json!({ "logicalname": logicalname, "name": "Reconcile test entity" })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "create entity");
    let body = body_json(resp).await;
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    (id, logicalname)
}

async fn query_marker(db: &DbPool, id: Uuid) -> (bool, bool) {
    sqlx::query_as::<_, (bool, bool)>(
        "SELECT is_customized, (is_active IS NULL OR is_active = true) \
         FROM sql_query WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .expect("query row")
}

async fn version_count(db: &DbPool, query_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sql_query_version WHERE query_id = $1")
        .bind(query_id)
        .fetch_one(db)
        .await
        .expect("version count")
}

fn query_def(entity: &str, name: &str, sql: &str) -> QueryDef {
    // D-477 (T3-2): attome_records::query_admin::QueryDef, a minimal
    // runtime-shape twin of attome_api::bundle::model::QueryDef — no
    // `is_customized` field (the caller derives `policy` from that
    // separately, before calling `reconcile_query`).
    QueryDef {
        entity: Some(entity.to_owned()),
        name: name.to_owned(),
        sql: sql.to_owned(),
        table_definition: None,
        required_privilege: None,
        is_report: false,
        entity_mappings: vec![],
    }
}

// ── Admin writes mark ownership; PATCH goes through reconcile ─────────────────

#[test]
fn admin_customized_entity_create_and_patch_mark_the_row() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let app = full_app(system);
        let db = &state.base.db;
        let (_, cookie) = seed_admin(db).await;

        let (entity_id, logicalname) = create_entity(&app, &cookie, "rc_ent").await;
        let (customized, name): (bool, Option<String>) =
            sqlx::query_as("SELECT is_customized, name FROM entity_info WHERE id = $1")
                .bind(entity_id)
                .fetch_one(db)
                .await
                .unwrap();
        assert!(customized, "admin create must set is_customized");
        assert_eq!(name.as_deref(), Some("Reconcile test entity"));

        // Reset the marker (as a platform-seeded row would be) and PATCH: the
        // reconcile primitive under Admin policy must set it again and apply
        // the change; a second identical PATCH is a no-op but still 200.
        sqlx::query("UPDATE entity_info SET is_customized = false WHERE id = $1")
            .bind(entity_id)
            .execute(db)
            .await
            .unwrap();
        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(req(
                    "PATCH",
                    &format!("/api/v1/admin/entities/{entity_id}"),
                    &cookie,
                    Some(json!({ "name": "Renamed", "category": "Ops" })),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_json(resp).await;
            assert_eq!(body["name"], "Renamed");
            assert_eq!(body["category"], "Ops");
            assert_eq!(body["logicalname"], logicalname);
        }
        let (customized, name, category): (bool, Option<String>, Option<String>) =
            sqlx::query_as("SELECT is_customized, name, category FROM entity_info WHERE id = $1")
                .bind(entity_id)
                .fetch_one(db)
                .await
                .unwrap();
        assert!(customized, "admin PATCH must set is_customized");
        assert_eq!(name.as_deref(), Some("Renamed"));
        assert_eq!(category.as_deref(), Some("Ops"));

        // logicalname stays immutable (D-021).
        let resp = app
            .clone()
            .oneshot(req(
                "PATCH",
                &format!("/api/v1/admin/entities/{entity_id}"),
                &cookie,
                Some(json!({ "logicalname": "something_else" })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // A second POST of the same logicalname is a 409, not a silent upsert.
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/admin/entities",
                &cookie,
                Some(json!({ "logicalname": logicalname, "name": "dup" })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    })
}

#[test]
fn admin_customized_attribute_create_patch_and_is_sensitive() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let app = full_app(system);
        let db = &state.base.db;
        let (_, cookie) = seed_admin(db).await;
        let (entity_id, _) = create_entity(&app, &cookie, "rc_attr").await;

        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                &cookie,
                Some(json!({
                    "logicalname": "secret_note", "name": "Secret note", "field_type": "text",
                    "is_sensitive": true, "max_length": 40, "data_classification": "personal"
                })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_json(resp).await;
        let attr_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(created["is_sensitive"], true);
        assert_eq!(created["max_length"], 40);
        assert_eq!(created["data_classification"], "personal");

        let (customized, sensitive, max_length, classification): (bool, bool, Option<i32>, String) =
        sqlx::query_as(
            "SELECT is_customized, COALESCE(is_sensitive, false), max_length, data_classification \
             FROM attribute_info WHERE id = $1",
        )
        .bind(attr_id)
        .fetch_one(db)
        .await
        .unwrap();
        assert!(customized, "admin field create must set is_customized");
        assert!(sensitive);
        assert_eq!(max_length, Some(40));
        assert_eq!(classification, "personal");

        // Duplicate logicalname on the same entity: 409.
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                &cookie,
                Some(
                    json!({ "logicalname": "secret_note", "name": "again", "field_type": "text" }),
                ),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // PATCH: `is_sensitive` is now updatable (downgrade true -> false), and
        // the marker survives a reset.
        sqlx::query("UPDATE attribute_info SET is_customized = false WHERE id = $1")
            .bind(attr_id)
            .execute(db)
            .await
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req(
                "PATCH",
                &format!("/api/v1/admin/entities/{entity_id}/fields/{attr_id}"),
                &cookie,
                Some(json!({ "is_sensitive": false, "name": "Plain note" })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let patched = body_json(resp).await;
        assert_eq!(patched["is_sensitive"], false);
        assert_eq!(patched["name"], "Plain note");
        assert_eq!(patched["max_length"], 40, "untouched fields carry through");
        let (customized, sensitive, name): (bool, bool, Option<String>) = sqlx::query_as(
            "SELECT is_customized, COALESCE(is_sensitive, false), name \
         FROM attribute_info WHERE id = $1",
        )
        .bind(attr_id)
        .fetch_one(db)
        .await
        .unwrap();
        assert!(customized, "admin field PATCH must set is_customized");
        assert!(!sensitive, "is_sensitive downgrade must be applied");
        assert_eq!(name.as_deref(), Some("Plain note"));

        // A type change is still refused (D-055).
        let resp = app
            .clone()
            .oneshot(req(
                "PATCH",
                &format!("/api/v1/admin/entities/{entity_id}/fields/{attr_id}"),
                &cookie,
                Some(json!({ "field_type": "number" })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

// ── Queries ───────────────────────────────────────────────────────────────────

#[test]
fn admin_customized_duplicate_query_create_is_409() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let app = full_app(system);
        let db = &state.base.db;
        let (_, cookie) = seed_admin(db).await;
        let (entity_id, logicalname) = create_entity(&app, &cookie, "rc_qdup").await;

        let body = json!({
            "name": "Dup query", "sql_query": format!("SELECT id FROM {logicalname}"),
            "entity_logical_name": entity_id
        });
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/admin/queries",
                &cookie,
                Some(body.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let created = body_json(resp).await;
        let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        assert!(query_marker(db, id).await.0, "admin publish marks the row");

        let resp = app
            .clone()
            .oneshot(req("POST", "/api/v1/admin/queries", &cookie, Some(body)))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "uq_core_sql_query_entity_name must surface as 409"
        );
    })
}

#[test]
fn reconcile_query_policy_matrix_and_retire_round_trip() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let app = full_app(system);
        let state = &state;
        let db = &state.base.db;
        let (actor, cookie) = seed_admin(db).await;
        let (_, logicalname) = create_entity(&app, &cookie, "rc_q").await;
        let name = unique_name("q");
        let desc = query_def(
            &logicalname,
            &name,
            &format!("SELECT id FROM {logicalname}"),
        );

        // Bundle create: marker carried (false), one version row.
        let bundle = ReconcilePolicy::Bundle {
            is_customized: false,
        };
        let (id, outcome) = reconcile_query(state, &desc, bundle, Some(actor), false, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::Created);
        assert_eq!(query_marker(db, id).await, (false, true));
        assert_eq!(version_count(db, id).await, 1);

        // Identical description: Unchanged, nothing written (no version row).
        let (same_id, outcome) = reconcile_query(state, &desc, bundle, Some(actor), false, None)
            .await
            .unwrap();
        assert_eq!(same_id, id);
        assert_eq!(outcome, ReconcileOutcome::Unchanged);
        assert_eq!(version_count(db, id).await, 1);

        // Admin policy on an otherwise-identical description: marks the row
        // (a re-publish, so one more version row).
        let (_, outcome) = reconcile_query(
            state,
            &desc,
            ReconcilePolicy::Admin,
            Some(actor),
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome, ReconcileOutcome::Updated);
        assert_eq!(query_marker(db, id).await, (true, true));
        assert_eq!(version_count(db, id).await, 2);

        // Seed policy skips the customized row even when the SQL differs.
        let mut changed = desc.clone();
        changed.sql = format!("SELECT id, id AS twice FROM {logicalname}");
        let (_, outcome) =
            reconcile_query(state, &changed, ReconcilePolicy::Seed, None, false, None)
                .await
                .unwrap();
        assert_eq!(outcome, ReconcileOutcome::SkippedCustomized);
        let (sql,): (Option<String>,) =
            sqlx::query_as("SELECT sql_query FROM sql_query WHERE id = $1")
                .bind(id)
                .fetch_one(db)
                .await
                .unwrap();
        assert_eq!(
            sql.as_deref(),
            Some(desc.sql.as_str()),
            "seed must not touch it"
        );

        // Bundle { false } applies the change AND clears the marker.
        let (_, outcome) = reconcile_query(state, &changed, bundle, None, false, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::Updated);
        assert_eq!(query_marker(db, id).await, (false, true));
        let (sql,): (Option<String>,) =
            sqlx::query_as("SELECT sql_query FROM sql_query WHERE id = $1")
                .bind(id)
                .fetch_one(db)
                .await
                .unwrap();
        assert_eq!(sql.as_deref(), Some(changed.sql.as_str()));

        // Retire / reactivate round-trip, idempotent on both sides.
        assert_eq!(
            retire_query(state, Some(&logicalname), &name)
                .await
                .unwrap(),
            ReconcileOutcome::Updated
        );
        assert!(!query_marker(db, id).await.1);
        assert_eq!(
            retire_query(state, Some(&logicalname), &name)
                .await
                .unwrap(),
            ReconcileOutcome::Unchanged
        );
        assert_eq!(
            reactivate_query(state, Some(&logicalname), &name)
                .await
                .unwrap(),
            ReconcileOutcome::Updated
        );
        assert!(query_marker(db, id).await.1);
        assert_eq!(
            reactivate_query(state, Some(&logicalname), &name)
                .await
                .unwrap(),
            ReconcileOutcome::Unchanged
        );

        // Reconcile over a retired row reactivates it instead of inserting a
        // second one (same id).
        retire_query(state, Some(&logicalname), &name)
            .await
            .unwrap();
        let (again, outcome) = reconcile_query(state, &changed, bundle, None, false, None)
            .await
            .unwrap();
        assert_eq!(again, id);
        assert_eq!(outcome, ReconcileOutcome::Updated);
        assert!(query_marker(db, id).await.1);

        // A query on an unknown entity is a validation error, not a 500.
        let bad = query_def("no_such_entity_xyz", "x", "SELECT 1");
        assert!(matches!(
            reconcile_query(state, &bad, bundle, None, false, None).await,
            Err(attome_types::AppError::Validation(_))
        ));
    })
}

// ── Views ─────────────────────────────────────────────────────────────────────

#[test]
fn reconcile_view_and_retire_round_trip() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let app = full_app(system);
        let state = &state;
        let db = &state.base.db;
        let (actor, cookie) = seed_admin(db).await;
        let (entity_id, logicalname) = create_entity(&app, &cookie, "rc_v").await;
        let qname = unique_name("vq");
        let qdesc = query_def(
            &logicalname,
            &qname,
            &format!("SELECT id FROM {logicalname}"),
        );
        let bundle = ReconcilePolicy::Bundle {
            is_customized: false,
        };
        let (query_id, _) = reconcile_query(state, &qdesc, bundle, Some(actor), false, None)
            .await
            .unwrap();

        let vname = unique_name("view");
        let desc = ViewDef {
            entity: logicalname.clone(),
            name: vname.clone(),
            query: QueryRef {
                entity: Some(logicalname.clone()),
                name: qname.clone(),
            },
            icon: "las la-table".into(),
            table_definition: json!([{ "field": "id" }]),
            is_default: true,
            is_customized: false,
            kind: "list".into(),
            view_metadata: json!({}),
        };
        let (id, outcome) = reconcile_view(state, &desc, bundle, None).await.unwrap();
        assert_eq!(outcome, ReconcileOutcome::Created);
        let (ref_id, is_default, customized, active): (Uuid, bool, bool, bool) = sqlx::query_as(
            "SELECT sql_query_ref, is_default, is_customized, is_active FROM view WHERE id = $1",
        )
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap();
        assert_eq!(ref_id, query_id);
        assert!(is_default && !customized && active);

        // Only one default per entity survives: the seeded "Active ..." view
        // `create_entity` made lost its default flag.
        let defaults: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM view WHERE entity_logical_name = $1 AND is_default AND is_active",
        )
        .bind(entity_id)
        .fetch_one(db)
        .await
        .unwrap();
        assert_eq!(defaults, 1);

        let (same, outcome) = reconcile_view(state, &desc, bundle, None).await.unwrap();
        assert_eq!((same, outcome), (id, ReconcileOutcome::Unchanged));

        let (_, outcome) = reconcile_view(state, &desc, ReconcilePolicy::Admin, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::Updated);
        let mut changed = desc.clone();
        changed.icon = "las la-star".into();
        let (_, outcome) = reconcile_view(state, &changed, ReconcilePolicy::Seed, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::SkippedCustomized);
        let (_, outcome) = reconcile_view(state, &changed, bundle, None).await.unwrap();
        assert_eq!(outcome, ReconcileOutcome::Updated);

        assert_eq!(
            retire_view(state, &logicalname, &vname).await.unwrap(),
            ReconcileOutcome::Updated
        );
        assert_eq!(
            retire_view(state, &logicalname, &vname).await.unwrap(),
            ReconcileOutcome::Unchanged
        );
        assert_eq!(
            reactivate_view(state, &logicalname, &vname).await.unwrap(),
            ReconcileOutcome::Updated
        );
        assert_eq!(
            reactivate_view(state, &logicalname, &vname).await.unwrap(),
            ReconcileOutcome::Unchanged
        );
        // `uq_core_view_name` is a full constraint: reconciling a retired view
        // must reuse the row.
        retire_view(state, &logicalname, &vname).await.unwrap();
        let (again, outcome) = reconcile_view(state, &changed, bundle, None).await.unwrap();
        assert_eq!((again, outcome), (id, ReconcileOutcome::Updated));
    })
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

fn sidebar_def(path: &[&str], route: Option<&str>, order: i32) -> SidebarDef {
    SidebarDef {
        path: path.iter().map(|s| (*s).to_owned()).collect(),
        route: route.map(str::to_owned),
        icon: Some("las la-cube".into()),
        color: Some("#123456".into()),
        display_order: order,
        is_container: route.is_none(),
        entity: None,
        module_key: None,
        is_disabled: false,
        privileges: vec!["system.admin".into()],
        is_customized: false,
    }
}

#[test]
fn reconcile_sidebar_item_tree_and_retire_cascade() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let app = full_app(system);
        let state = &state;
        let db = &state.base.db;
        let (_, cookie) = seed_admin(db).await;
        let bundle = ReconcilePolicy::Bundle {
            is_customized: false,
        };

        let group = unique_name("Group");
        let child = "Child item";
        let group_desc = sidebar_def(&[&group], None, 900);
        let child_desc = sidebar_def(&[&group, child], Some("/rc/child/list"), 1);

        // A child whose parent does not exist yet is a validation error.
        assert!(matches!(
            reconcile_sidebar_item(state, &child_desc, bundle, None).await,
            Err(attome_types::AppError::Validation(_))
        ));

        let (group_id, outcome) = reconcile_sidebar_item(state, &group_desc, bundle, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::Created);
        let (child_id, outcome) = reconcile_sidebar_item(state, &child_desc, bundle, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::Created);
        let (parent_ref, customized, privs): (Option<Uuid>, bool, i64) = sqlx::query_as(
        "SELECT s.parent_ref, s.is_customized, \
                (SELECT COUNT(*) FROM sidebar_mm_privilege p WHERE p.sidebar_ref = s.id AND p.is_deleted = false) \
         FROM sidebar s WHERE s.id = $1",
    )
    .bind(child_id)
    .fetch_one(db)
    .await
    .unwrap();
        assert_eq!(parent_ref, Some(group_id));
        assert!(!customized);
        assert_eq!(privs, 1);

        let (same, outcome) = reconcile_sidebar_item(state, &child_desc, bundle, None)
            .await
            .unwrap();
        assert_eq!((same, outcome), (child_id, ReconcileOutcome::Unchanged));

        // Admin marks; Seed then skips a changed description; Bundle{false}
        // applies it and clears the marker.
        let (_, outcome) = reconcile_sidebar_item(state, &child_desc, ReconcilePolicy::Admin, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::Updated);
        let mut moved = child_desc.clone();
        moved.display_order = 7;
        moved.privileges.clear();
        let (_, outcome) = reconcile_sidebar_item(state, &moved, ReconcilePolicy::Seed, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::SkippedCustomized);
        let (_, outcome) = reconcile_sidebar_item(state, &moved, bundle, None)
            .await
            .unwrap();
        assert_eq!(outcome, ReconcileOutcome::Updated);
        let (order, customized, privs): (i32, bool, i64) = sqlx::query_as(
        "SELECT s.display_order, s.is_customized, \
                (SELECT COUNT(*) FROM sidebar_mm_privilege p WHERE p.sidebar_ref = s.id AND p.is_deleted = false) \
         FROM sidebar s WHERE s.id = $1",
    )
    .bind(child_id)
    .fetch_one(db)
    .await
    .unwrap();
        assert_eq!((order, customized, privs), (7, false, 0));

        // Retiring the group cascades to the child; reactivating restores each.
        let group_path = vec![group.clone()];
        let child_path = vec![group.clone(), child.to_owned()];
        assert_eq!(
            retire_sidebar_item(state, &group_path).await.unwrap(),
            ReconcileOutcome::Updated
        );
        let active: Vec<bool> =
            sqlx::query_scalar("SELECT is_active FROM sidebar WHERE id = ANY($1) ORDER BY id")
                .bind(vec![group_id, child_id])
                .fetch_all(db)
                .await
                .unwrap();
        assert_eq!(active, vec![false, false]);
        assert_eq!(
            retire_sidebar_item(state, &group_path).await.unwrap(),
            ReconcileOutcome::Unchanged
        );
        assert_eq!(
            reactivate_sidebar_item(state, &group_path).await.unwrap(),
            ReconcileOutcome::Updated
        );
        assert_eq!(
            reactivate_sidebar_item(state, &child_path).await.unwrap(),
            ReconcileOutcome::Updated
        );
        assert_eq!(
            reactivate_sidebar_item(state, &child_path).await.unwrap(),
            ReconcileOutcome::Unchanged
        );
        // A retired item is reactivated by reconcile too (same id).
        retire_sidebar_item(state, &child_path).await.unwrap();
        let (again, outcome) = reconcile_sidebar_item(state, &moved, bundle, None)
            .await
            .unwrap();
        assert_eq!((again, outcome), (child_id, ReconcileOutcome::Updated));

        // Admin POST of a duplicate live sibling name: 409 (0133), and the
        // admin write marks its row.
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/sidebar/admin",
                &cookie,
                Some(json!({
                    "name": child, "parent_ref": group_id, "display_order": 2, "route": "/x/list"
                })),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/sidebar/admin",
            &cookie,
            Some(json!({
                "name": "Other child", "parent_ref": group_id, "display_order": 2, "route": "/y/list"
            })),
        ))
        .await
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let created = body_json(resp).await;
        let other_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
        let customized: bool =
            sqlx::query_scalar("SELECT is_customized FROM sidebar WHERE id = $1")
                .bind(other_id)
                .fetch_one(db)
                .await
                .unwrap();
        assert!(customized, "admin sidebar create must set is_customized");
    })
}

//! SEC-3 (behavioural half) — every mutation entry point, driven end to end
//! with a request body that names all ten system columns, asserting none of
//! them moves.
//!
//! # What is being defended
//!
//! `attome_core::ALL_SYSTEM_COLS` — `id`, `created_at`, `created_by`,
//! `modified_at`, `modified_by`, `organization_ref`, `is_active`, `row_version`,
//! `owner_ref`, `owner_type` — are engine-owned. `organization_ref` is read
//! directly by `attome_security::rls`, so writing it moves a record across the
//! row-level-security boundary. `owner_ref`/`owner_type` are ownership, whose
//! only sanctioned writer besides create is the admin-gated
//! `reassign_owner`. `created_by`/`created_at` are audit provenance.
//! `is_active` is the soft-delete flag (D-021), whose own endpoint carries an
//! audit event and a dependent-cascade policy. `id` is the primary key.
//!
//! Neither upstream validator stops a body from naming them, which is why
//! this needs testing at all rather than being obvious:
//!
//! - `validate_body` rejects only names *absent* from metadata, and these can
//!   be present — `setup` below registers all ten as ordinary attributes,
//!   exactly as `user_account` carries `organization_ref` and
//!   `is_active` in the real seed.
//! - `validate_field_write_grants` gates only `is_sensitive` fields, and
//!   ownership columns are not sensitive by default.
//!
//! So the *only* thing standing between the body and the column is the
//! exclusion applied where the SQL is built. SEC-1 was that exclusion missing
//! from `build_update_binds` entirely, and from `upsert_record`'s
//! `ON CONFLICT DO UPDATE` clause.
//!
//! # The attack values are valid, not malformed
//!
//! The five UUID-typed system columns are registered here as `lookup` fields
//! and the value submitted for them is a real, live record id. That matters:
//! it means these tests cannot pass because a type error or a
//! dangling-reference check rejected the request upstream. The write is fully
//! well-formed and would apply cleanly. It does not apply because it is
//! filtered — which is the property under test. See `setup` on why those
//! lookups deliberately target a second entity.
//!
//! # Coverage
//!
//! create, update, upsert (both the insert branch and the conflict branch),
//! bulk create, bulk update, staged import, merge, restore. The two durable
//! paths are driven through `attome_records::bulk::process` /
//! `process_staged_import` directly, the same way `bulk_mutation.rs` drives
//! the worker side deterministically rather than waiting on a live Apalis
//! worker.
//!
//! The structural companion is `server/tests/reserved_column_guard.rs`, which
//! is what fails when a *new* mutation path appears — this file can only
//! cover paths that already exist.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), same convention as `bulk_mutation.rs`:
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test reserved_column_entry_points -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::{ALL_SYSTEM_COLS, EngineState};
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness (same shape as bulk_mutation.rs / entity_round_trip.rs) ──────────

fn test_config() -> AppConfig {
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

async fn seed_admin(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("reserved-cols-{user_id}@test.local"))
    .bind(format!("reserved-cols-{user_id}"))
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

/// See `bulk_mutation.rs`'s copy: `sec-fetch-site: same-origin` is what the
/// CSRF middleware treats as same-origin evidence for a cookie-authenticated
/// unsafe-method request.
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

// ── The reserved-column payload ─────────────────────────────────────────────

/// The five system columns whose physical type is UUID. Registered as
/// self-targeting `lookup` attributes so the submitted value is a live record
/// id and passes `validate_lookup_targets` — see the module header on why the
/// attack value must be valid rather than malformed.
const UUID_SYSTEM_COLS: [&str; 5] = [
    "id",
    "created_by",
    "modified_by",
    "organization_ref",
    "owner_ref",
];

/// The remaining system columns, with the `field_type` matching each one's
/// physical column type so provisioning is a no-op (`ADD COLUMN IF NOT
/// EXISTS`) rather than a type change.
const TYPED_SYSTEM_COLS: [(&str, &str); 5] = [
    ("created_at", "date"),
    ("modified_at", "date"),
    ("is_active", "bool"),
    ("row_version", "number"),
    ("owner_type", "number"),
];

/// Every system column set to a value the caller chose. `decoy_id` is a live
/// record in the same entity, so the five lookup-typed columns reference
/// something real.
fn reserved_column_payload(decoy_id: Uuid) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for col in UUID_SYSTEM_COLS {
        out.insert(col.to_owned(), json!(decoy_id.to_string()));
    }
    out.insert("created_at".to_owned(), json!("1999-01-01T00:00:00Z"));
    out.insert("modified_at".to_owned(), json!("1999-01-01T00:00:00Z"));
    out.insert("is_active".to_owned(), json!(false));
    out.insert("row_version".to_owned(), json!(9999));
    out.insert("owner_type".to_owned(), json!(1));
    out
}

/// `reserved_column_payload` plus the ordinary field the request is nominally
/// about — a real edit the engine must still apply.
fn attack_body(decoy_id: Uuid, title: &str) -> Value {
    let mut obj = reserved_column_payload(decoy_id);
    obj.insert("title".to_owned(), json!(title));
    Value::Object(obj)
}

/// A record's system columns, read straight from the physical table rather
/// than from the API response — the response is shaped by the same code under
/// test, so it is not independent evidence of what was written.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
struct SystemCols {
    id: Uuid,
    created_by: Option<Uuid>,
    modified_by: Option<Uuid>,
    organization_ref: Option<Uuid>,
    owner_ref: Option<Uuid>,
    owner_type: i16,
    is_active: bool,
    row_version: i64,
}

async fn system_cols(db: &attome_db::DbPool, table: &str, id: Uuid) -> SystemCols {
    sqlx::query_as::<_, SystemCols>(&format!(
        "SELECT id, created_by, modified_by, organization_ref, owner_ref, owner_type, \
                is_active, row_version FROM \"{table}\" WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(db)
    .await
    .unwrap_or_else(|e| panic!("read system columns of {table}/{id}: {e}"))
}

/// Asserts nothing the caller tried to set actually landed. `row_version` and
/// `modified_by`/`modified_at` are excluded from the equality check because the
/// engine legitimately advances them on its own — they are checked separately
/// against the *engine's* values, never the caller's.
fn assert_untouched(before: &SystemCols, after: &SystemCols, decoy_id: Uuid, actor: Uuid) {
    assert_eq!(after.id, before.id, "id must not be rewritable from a body");
    assert_eq!(
        after.created_by, before.created_by,
        "created_by is audit provenance and must not be rewritable"
    );
    assert_eq!(
        after.organization_ref, before.organization_ref,
        "organization_ref is read by RLS — rewriting it moves the record across \
         the security boundary"
    );
    assert_eq!(
        after.owner_ref, before.owner_ref,
        "owner_ref must change only through the admin-gated reassign-owner"
    );
    assert_eq!(
        after.owner_type, before.owner_type,
        "owner_type must change only through the admin-gated reassign-owner"
    );
    assert!(
        after.is_active,
        "is_active must not be settable from an update body — deletion has its \
         own endpoint, audit event and cascade policy"
    );

    assert_ne!(
        after.organization_ref,
        Some(decoy_id),
        "the caller's organization_ref value was applied"
    );
    assert_ne!(
        after.owner_ref,
        Some(decoy_id),
        "the caller's owner_ref value was applied"
    );
    assert_ne!(
        after.created_by,
        Some(decoy_id),
        "the caller's created_by value was applied"
    );

    assert_eq!(
        after.modified_by,
        Some(actor),
        "modified_by must be the authenticated actor the engine stamped, not \
         anything the body carried"
    );
    assert_eq!(
        after.row_version,
        before.row_version + 1,
        "row_version must advance by exactly the engine's own increment, not \
         jump to the body's value"
    );
}

// ── Setup ───────────────────────────────────────────────────────────────────

async fn create_entity(app: &axum::Router, admin_cookie: &str, logicalname: &str) -> Uuid {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({ "logicalname": logicalname, "name": "Reserved Columns" })),
        ))
        .await
        .unwrap();
    let status = res.status();
    let seen = body_json(res).await;
    assert_eq!(status, StatusCode::CREATED, "create entity: {seen:?}");
    seen["id"].as_str().unwrap().parse().unwrap()
}

async fn create_field(app: &axum::Router, admin_cookie: &str, entity_id: Uuid, body: Value) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin_cookie,
            Some(&body),
        ))
        .await
        .unwrap();
    let status = res.status();
    let seen = body_json(res).await;
    assert_eq!(status, StatusCode::CREATED, "create field: {seen:?}");
}

/// Provisions the entity under test — `title` (the upsert match key), `note`
/// (an ordinary field every mutation actually changes) and all ten system
/// columns as registered metadata attributes — plus the separate
/// lookup-target entity holding the decoy record the attack payloads
/// reference.
async fn setup(
    app: &axum::Router,
    admin_cookie: &str,
    state: &EngineState,
    prefix: &str,
) -> (String, Uuid) {
    let suffix = Uuid::now_v7().simple().to_string();

    // The lookup target is a *separate* entity on purpose. A self-referencing
    // lookup is a hierarchy field, so pointing these at the entity under test
    // made `guard_hierarchy_cycles` walk `id -> id` and reject every write
    // with "hierarchy chain exceeds 100 levels" — a real guard doing its job,
    // but one that would mask the property this file exists to prove by
    // rejecting the request before the SET clause was ever built.
    let target_name = format!("{prefix}_t_{suffix}");
    let target_id = create_entity(app, admin_cookie, &target_name).await;
    create_field(
        app,
        admin_cookie,
        target_id,
        json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
    )
    .await;

    let logicalname = format!("{prefix}_{suffix}");
    let entity_id = create_entity(app, admin_cookie, &logicalname).await;
    for field in ["title", "note"] {
        create_field(
            app,
            admin_cookie,
            entity_id,
            json!({ "logicalname": field, "name": field, "field_type": "text" }),
        )
        .await;
    }

    // The whole premise of SEC-1: these are ordinary registered attributes, so
    // `validate_body` waves them through. `user_account` really does
    // carry `organization_ref` and `is_active` this way in the seed.
    for col in UUID_SYSTEM_COLS {
        create_field(
            app,
            admin_cookie,
            entity_id,
            json!({
                "logicalname": col,
                "name": col,
                "field_type": "lookup",
                "lookup_entity_ref": target_id.to_string(),
            }),
        )
        .await;
    }
    for (col, field_type) in TYPED_SYSTEM_COLS {
        create_field(
            app,
            admin_cookie,
            entity_id,
            json!({ "logicalname": col, "name": col, "field_type": field_type }),
        )
        .await;
    }

    // Lookup metadata is read from the arc-swap registry regardless of
    // `metadata_registry_enabled` — force the rebuild instead of waiting on
    // the pub/sub doorbell (`entity_round_trip.rs::sync_registry`).
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build_registry");
    state.entities.swap(registry);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{target_name}"),
            admin_cookie,
            Some(&json!({ "title": "decoy" })),
        ))
        .await
        .unwrap();
    let status = res.status();
    let seen = body_json(res).await;
    assert_eq!(status, StatusCode::CREATED, "create decoy record: {seen:?}");
    let decoy_id: Uuid = seen["id"].as_str().unwrap().parse().unwrap();

    (logicalname, decoy_id)
}

/// Creates one ordinary record and returns (id, row_version).
async fn create_record(app: &axum::Router, cookie: &str, entity: &str, title: &str) -> (Uuid, i64) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}"),
            cookie,
            Some(&json!({ "title": title })),
        ))
        .await
        .unwrap();
    let status = res.status();
    let seen = body_json(res).await;
    assert_eq!(status, StatusCode::CREATED, "create record: {seen:?}");
    (
        seen["id"].as_str().unwrap().parse().unwrap(),
        seen["row_version"].as_i64().unwrap(),
    )
}

// ── 1. create ───────────────────────────────────────────────────────────────

/// The path that always had the exclusion. Kept so the suite states the whole
/// invariant in one place rather than only its formerly-broken half.
#[test]
fn create_ignores_every_reserved_column_in_the_body() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (entity, decoy) = setup(&app, &cookie, &state, "rc_create").await;

        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}"),
                &cookie,
                Some(&attack_body(decoy, "created")),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(status, StatusCode::CREATED, "create must succeed: {seen:?}");
        let id: Uuid = seen["id"].as_str().unwrap().parse().unwrap();

        let cols = system_cols(&db, &entity, id).await;
        assert_ne!(cols.id, decoy, "id came from the body");
        assert_eq!(
            cols.created_by,
            Some(actor),
            "created_by must be the authenticated creator"
        );
        assert_eq!(
            cols.owner_ref,
            Some(actor),
            "owner_ref must be the creator (D-137), not the body's value"
        );
        assert_eq!(cols.owner_type, 0, "owner_type must be 0=user");
        assert!(cols.is_active, "is_active must be the column default");
        assert_eq!(cols.row_version, 0, "row_version must start at the default");
        assert_ne!(
            cols.organization_ref,
            Some(decoy),
            "organization_ref must come from the creator's context"
        );
    })
}

// ── 2. update ───────────────────────────────────────────────────────────────

/// SEC-1 itself, end to end: the finding was that `PATCH` bound whatever the
/// body carried straight into the `SET` clause.
#[test]
fn update_ignores_every_reserved_column_in_the_body() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (entity, decoy) = setup(&app, &cookie, &state, "rc_update").await;
        let (id, row_version) = create_record(&app, &cookie, &entity, "before").await;

        let before = system_cols(&db, &entity, id).await;

        let res = app
            .clone()
            .oneshot(req_versioned(
                "PATCH",
                &format!("/api/v1/{entity}/{id}"),
                &cookie,
                row_version,
                &attack_body(decoy, "after"),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(status, StatusCode::OK, "update must succeed: {seen:?}");
        assert_eq!(
            seen["data"]["title"], "after",
            "the ordinary field must still have been applied"
        );

        let after = system_cols(&db, &entity, id).await;
        assert_untouched(&before, &after, decoy, actor);
    })
}

/// A body of nothing *but* reserved columns has no writable field left, so it
/// is a clean validation error rather than a silent no-op that reports 200.
#[test]
fn update_with_only_reserved_columns_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);
        let (entity, decoy) = setup(&app, &cookie, &state, "rc_only").await;
        let (id, row_version) = create_record(&app, &cookie, &entity, "before").await;

        let res = app
            .clone()
            .oneshot(req_versioned(
                "PATCH",
                &format!("/api/v1/{entity}/{id}"),
                &cookie,
                row_version,
                &Value::Object(reserved_column_payload(decoy)),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a body with no writable field must be a validation error"
        );
    })
}

/// The vulnerability in its pure form, with nothing else in the body.
///
/// `update_ignores_every_reserved_column_in_the_body` above submits all ten
/// system columns at once, which means that with SEC-1 reverted it fails with
/// a 500 rather than a takeover: `modified_at`, `modified_by` and `row_version`
/// are also appended to the same `SET` clause by `update_one`, so a
/// body-supplied value for any of the three is a duplicate assignment
/// (Postgres 42701). Useful coverage, but it proves the path is *broken*, not
/// that it is *exploitable*.
///
/// These five had no such accident protecting them. Submitting only them
/// produces a perfectly valid single-statement UPDATE, so before SEC-1 this
/// request returned 200 and really did move the record to another
/// organization, reassign its owner, forge its creator and soft-delete it —
/// from ordinary `{entity}.update` privilege, with no admin gate anywhere.
/// This is the test that fails with a silent success rather than a crash.
#[test]
fn update_cannot_silently_take_over_ownership_and_organization() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (entity, decoy) = setup(&app, &cookie, &state, "rc_takeover").await;
        let (id, row_version) = create_record(&app, &cookie, &entity, "before").await;

        let before = system_cols(&db, &entity, id).await;

        let res = app
            .clone()
            .oneshot(req_versioned(
                "PATCH",
                &format!("/api/v1/{entity}/{id}"),
                &cookie,
                row_version,
                &json!({
                    "note": "an ordinary edit, to keep the request otherwise legitimate",
                    "organization_ref": decoy.to_string(),
                    "owner_ref": decoy.to_string(),
                    "owner_type": 1,
                    "created_by": decoy.to_string(),
                    "is_active": false,
                }),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(status, StatusCode::OK, "update must succeed: {seen:?}");

        let after = system_cols(&db, &entity, id).await;
        assert_eq!(
            after.organization_ref, before.organization_ref,
            "organization_ref moved — the record just crossed the RLS boundary"
        );
        assert_eq!(
            after.owner_ref, before.owner_ref,
            "owner_ref moved — ownership was reassigned without reassign-owner"
        );
        assert_eq!(
            after.owner_type, before.owner_type,
            "owner_type moved — ownership was reassigned without reassign-owner"
        );
        assert_eq!(
            after.created_by, before.created_by,
            "created_by moved — audit attribution was forged"
        );
        assert!(
            after.is_active,
            "is_active was cleared — the record was soft-deleted through the \
         update endpoint, skipping the delete path's audit event and \
         dependent-cascade policy"
        );
        assert_eq!(
            after.modified_by,
            Some(actor),
            "modified_by must still be the real actor"
        );
    })
}

// ── 3. upsert ───────────────────────────────────────────────────────────────

/// Both branches in one test, because the conflict branch is only reachable
/// through the insert branch: the second call collides with the first on the
/// same match key. The `ON CONFLICT DO UPDATE` clause is SEC-1's third site.
#[test]
fn upsert_ignores_reserved_columns_on_both_branches() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (entity, decoy) = setup(&app, &cookie, &state, "rc_upsert").await;

        // `data` deliberately does NOT carry `title`: `data` overrides `match` for
        // an overlapping key, so setting it here would write a row whose title is
        // not the match key, and the second call below would insert a second row
        // instead of reaching the conflict branch this test is about.
        let mut data = reserved_column_payload(decoy);
        data.insert("note".to_owned(), json!("inserted"));

        // Insert branch.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}/upsert"),
                &cookie,
                Some(&json!({ "match": { "title": "upsert-key" }, "data": data })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(status, StatusCode::CREATED, "upsert insert: {seen:?}");
        let id: Uuid = seen["id"].as_str().unwrap().parse().unwrap();

        let before = system_cols(&db, &entity, id).await;
        assert_ne!(before.organization_ref, Some(decoy));
        assert_eq!(before.owner_ref, Some(actor));
        assert!(before.is_active);

        // Conflict branch: same match key, so this resolves to DO UPDATE.
        let mut data = reserved_column_payload(decoy);
        data.insert("note".to_owned(), json!("updated"));
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}/upsert"),
                &cookie,
                Some(&json!({
                    "match": { "title": "upsert-key" },
                    "data": data,
                    "row_version": before.row_version,
                })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(status, StatusCode::OK, "upsert conflict branch: {seen:?}");
        assert_eq!(
            seen["id"].as_str().unwrap().parse::<Uuid>().unwrap(),
            id,
            "the conflict branch must have matched the same row"
        );
        assert_eq!(
            seen["data"]["note"], "updated",
            "the ordinary field must still have been applied"
        );

        let after = system_cols(&db, &entity, id).await;
        assert_untouched(&before, &after, decoy, actor);
    })
}

// ── 4. bulk ─────────────────────────────────────────────────────────────────

/// Bulk reaches the same two builders through `create_one`/`update_one`, but
/// via an enqueue-then-worker path with its own envelope — so it is asserted
/// rather than assumed. `process` is driven directly, as `bulk_mutation.rs`
/// does, instead of waiting on a live worker.
#[test]
fn bulk_create_and_update_ignore_reserved_columns() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (entity, decoy) = setup(&app, &cookie, &state, "rc_bulk").await;

        // Bulk create.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}/bulk"),
                &cookie,
                Some(&json!({
                    "operation": "create",
                    "records": [{ "data": attack_body(decoy, "bulk-created") }],
                })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "bulk create enqueue: {seen:?}"
        );
        let op_id: Uuid = seen["id"].as_str().unwrap().parse().unwrap();

        attome_records::bulk::process(&state, op_id, &entity, "create", Vec::new(), actor)
            .await
            .expect("bulk create process");

        let created_id: Uuid = sqlx::query_scalar(
            "SELECT record_id FROM automation_bulk_operation_item \
         WHERE bulk_operation_id = $1 AND status = 'succeeded' AND item_index = 0",
        )
        .bind(op_id)
        .fetch_one(&db)
        .await
        .expect("bulk create must have produced a record");

        let before = system_cols(&db, &entity, created_id).await;
        assert_ne!(before.id, decoy);
        assert_eq!(before.created_by, Some(actor));
        assert_eq!(before.owner_ref, Some(actor));
        assert!(before.is_active);
        assert_ne!(before.organization_ref, Some(decoy));

        // Bulk update of that same record.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}/bulk"),
                &cookie,
                Some(&json!({
                    "operation": "update",
                    "records": [{
                        "id": created_id.to_string(),
                        "expected_row_version": before.row_version,
                        "data": attack_body(decoy, "bulk-updated"),
                    }],
                })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "bulk update enqueue: {seen:?}"
        );
        let op_id: Uuid = seen["id"].as_str().unwrap().parse().unwrap();

        attome_records::bulk::process(&state, op_id, &entity, "update", Vec::new(), actor)
            .await
            .expect("bulk update process");

        let (item_status,): (String,) = sqlx::query_as(
            "SELECT status FROM automation_bulk_operation_item \
         WHERE bulk_operation_id = $1 AND item_index = 0",
        )
        .bind(op_id)
        .fetch_one(&db)
        .await
        .expect("bulk update item row");
        assert_eq!(item_status, "succeeded", "bulk update must have applied");

        let after = system_cols(&db, &entity, created_id).await;
        assert_untouched(&before, &after, decoy, actor);
    })
}

// ── 5. staged import ────────────────────────────────────────────────────────

#[test]
fn staged_import_ignores_reserved_columns() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (entity, decoy) = setup(&app, &cookie, &state, "rc_staged").await;

        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}/staged-import"),
                &cookie,
                Some(&json!({
                    "operation": "create",
                    "records": [{ "data": attack_body(decoy, "staged") }],
                })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(status, StatusCode::ACCEPTED, "staged import: {seen:?}");
        let import_id: Uuid = seen["id"].as_str().unwrap().parse().unwrap();

        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}/staged-import/{import_id}/approve"),
                &cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED, "approve staged import");

        attome_records::bulk::process_staged_import(
            &state,
            import_id,
            &entity,
            "create",
            Vec::new(),
            actor,
        )
        .await
        .expect("process staged import");

        let record_id: Uuid = sqlx::query_scalar(
            "SELECT record_id FROM automation_staged_import_item \
         WHERE staged_import_id = $1 AND item_index = 0",
        )
        .bind(import_id)
        .fetch_one(&db)
        .await
        .expect("staged import must have produced a record");

        let cols = system_cols(&db, &entity, record_id).await;
        assert_ne!(cols.id, decoy, "id came from the body");
        assert_eq!(cols.created_by, Some(actor));
        assert_eq!(cols.owner_ref, Some(actor));
        assert_eq!(cols.owner_type, 0);
        assert!(cols.is_active);
        assert_ne!(cols.organization_ref, Some(decoy));
    })
}

// ── 6. merge ────────────────────────────────────────────────────────────────

/// Merge shares `build_update_binds` with the interactive update path, so the
/// SEC-1 fix covers it. What is asserted here is the outcome: retiring a
/// duplicate must not import that duplicate's ownership or organization onto
/// the surviving record, and must not resurrect any body-supplied value.
#[test]
fn merge_does_not_move_system_columns_onto_the_canonical_record() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (actor, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (entity, decoy) = setup(&app, &cookie, &state, "rc_merge").await;

        let (canonical, _) = create_record(&app, &cookie, &entity, "canonical").await;
        let (duplicate, _) = create_record(&app, &cookie, &entity, "duplicate").await;
        let before = system_cols(&db, &entity, canonical).await;

        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}/{canonical}/merge"),
                &cookie,
                Some(&json!({ "duplicate_id": duplicate.to_string() })),
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(status, StatusCode::OK, "merge must succeed: {seen:?}");

        let after = system_cols(&db, &entity, canonical).await;
        assert_eq!(after.id, before.id);
        assert_eq!(after.created_by, before.created_by);
        assert_eq!(after.organization_ref, before.organization_ref);
        assert_eq!(after.owner_ref, before.owner_ref);
        assert_eq!(after.owner_type, before.owner_type);
        assert!(after.is_active, "the surviving record must stay live");
        assert_ne!(after.organization_ref, Some(decoy));
        assert_eq!(
            after.modified_by,
            Some(actor),
            "the merge's own modified_by stamp must be the actor"
        );

        let duplicate_active: bool =
            sqlx::query_scalar(&format!("SELECT is_active FROM \"{entity}\" WHERE id = $1"))
                .bind(duplicate)
                .fetch_one(&db)
                .await
                .expect("duplicate row");
        assert!(!duplicate_active, "the duplicate must be retired");
    })
}

// ── 7. restore ──────────────────────────────────────────────────────────────

/// Restore takes no body at all — it flips `is_active` from its own SQL. The
/// assertion is that it does exactly that and nothing else, so the one
/// endpoint allowed to write a system column stays narrow.
#[test]
fn restore_only_flips_is_active() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (entity, _) = setup(&app, &cookie, &state, "rc_restore").await;
        let (id, row_version) = create_record(&app, &cookie, &entity, "to-delete").await;

        let before = system_cols(&db, &entity, id).await;

        let res = app
            .clone()
            .oneshot(req_versioned(
                "DELETE",
                &format!("/api/v1/{entity}/{id}"),
                &cookie,
                row_version,
                &json!({}),
            ))
            .await
            .unwrap();
        assert!(
            res.status().is_success(),
            "soft delete must succeed, got {}",
            res.status()
        );
        assert!(
            !system_cols(&db, &entity, id).await.is_active,
            "soft delete must clear is_active"
        );

        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{entity}/{id}/restore"),
                &cookie,
                None,
            ))
            .await
            .unwrap();
        let status = res.status();
        let seen = body_json(res).await;
        assert_eq!(status, StatusCode::OK, "restore must succeed: {seen:?}");

        let after = system_cols(&db, &entity, id).await;
        assert!(after.is_active, "restore must set is_active back to true");
        assert_eq!(after.id, before.id);
        assert_eq!(after.created_by, before.created_by);
        assert_eq!(after.organization_ref, before.organization_ref);
        assert_eq!(after.owner_ref, before.owner_ref);
        assert_eq!(after.owner_type, before.owner_type);
    })
}

// ── The list this file is written against ───────────────────────────────────

/// If a system column is added to `ALL_SYSTEM_COLS`, the payloads above stop
/// covering the full set and every test here quietly gets weaker. Fail
/// instead, so the new column is added to `UUID_SYSTEM_COLS` or
/// `TYPED_SYSTEM_COLS` deliberately.
#[test]
fn the_payload_covers_every_system_column() {
    let covered: std::collections::BTreeSet<&str> = UUID_SYSTEM_COLS
        .iter()
        .copied()
        .chain(TYPED_SYSTEM_COLS.iter().map(|(c, _)| *c))
        .collect();
    let expected: std::collections::BTreeSet<&str> = ALL_SYSTEM_COLS.iter().copied().collect();
    assert_eq!(
        covered, expected,
        "the reserved-column payload must name exactly ALL_SYSTEM_COLS — add \
         the new column to UUID_SYSTEM_COLS or TYPED_SYSTEM_COLS"
    );
}

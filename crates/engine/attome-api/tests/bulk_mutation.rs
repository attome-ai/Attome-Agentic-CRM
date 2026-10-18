//! Regression coverage for `bulk.rs`/`bulk_graph.rs` — the durable bulk
//! create/update/delete surface and its staged-import (dry-run + approve)
//! counterpart. This surface previously had zero dedicated test coverage:
//! partial-failure handling, per-row authorization, batch-preflight
//! (hierarchy cycles / duplicate-id and unique-key collisions), and size
//! limits had no regression safety net.
//!
//! Covers:
//! - request-shape validation (`validate_request_shape`/`validate_record_envelope`)
//!   — invalid `operation`, `strict: false`, invalid `batch_mode`, empty/oversized
//!   `records`, malformed create/update/delete envelopes,
//! - authorization: bulk requires BOTH the operation privilege AND the
//!   separate `"bulk"` privilege, and is forbidden outright on an
//!   append-only entity,
//! - the happy path: enqueue durably writes the `automation_bulk_operation`
//!   + `..._item` ledger rows,
//! - `GET .../bulk/{id}`: ownership scoping (a non-owner, non-admin caller
//!   gets `404`, not `403`), and `include_items`/pagination,
//! - whole-batch preflight (`bulk_graph::run_preflight`'s unique-key-collision
//!   check, reached through the lazily-provisioned upsert unique index —
//!   no hierarchy attribute needed): `batch_mode="atomic"` rejects the whole
//!   batch and enqueues nothing, `batch_mode="partial"` (the default) seeds
//!   only the offending items as `'rejected'` and leaves the rest `'pending'`,
//! - `attome_records::bulk::process` (called directly, driving the worker side
//!   deterministically instead of waiting on a live Apalis worker): the
//!   D-193 ledger-fallback path (`raw_records: vec![]`), and partial failure
//!   (one item hits a stale `expected_row_version` conflict, the rest still
//!   succeed and the operation still reaches `'completed'`),
//! - staged import: `POST .../staged-import` dry-runs without persisting
//!   anything, and `POST .../staged-import/{id}/approve` +
//!   `attome_records::bulk::process_staged_import` actually apply it.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `rewrap_admin.rs`/`entity_round_trip.rs`.
//! **Verified 2026-08-24 (MAINT-10): 14 passed, 0 failed, 108.88s** against a
//! real Postgres and Redis, retiring the "Not run in this session (code-only,
//! no DB/Redis access) — TODO: run against a throwaway database" note this
//! header carried. The **elapsed time** is the evidence, not the `ok`: this
//! suite reports green in ~0.01s when `DATABASE_URL` is absent, so a pass
//! alone does not distinguish a real run from a skipped one.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test bulk_mutation -- --test-threads=1
//! ```

#![recursion_limit = "512"]
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

// ── Harness (copied near-verbatim from rewrap_admin.rs / entity_round_trip.rs) ──

/// Unlike this file's own previous `test_config()`, `database.{host,port,
/// dbname,user,password}` are the REAL resolved per-binary throwaway-clone
/// values (`db`, from `attome_testkit::migrated_db_url()`), not an `"unused"`/
/// `APP_ENV=debug` placeholder — and `database.migrator` is set (same
/// credentials as `database.user`, which on this harness's Postgres role
/// already carries full DDL rights) rather than left unset.
///
/// This is NOT cosmetic: `attome_config::AppConfig::migrator_database_url()`
/// (`attome_db::create_migrator_pool`'s target, used by
/// `attome_metadata::provision::attribute::sync_attribute_index` for any
/// sortable/filterable/lookup attribute) is built from `database.host`/
/// `.port`/`.dbname` DIRECTLY — it does not consult `DATABASE_URL` or
/// `APP_ENV` at all. `EngineSystem::build()`'s own unconditional
/// `attome_dashboard::seed::seed` call (ordinary build plumbing, unrelated to
/// this file's C-11 coverage — every `EngineSystem::builder(..).build()` call
/// runs it, regardless of which modules are `.register()`ed) resyncs the
/// `widget_type` choice-list attribute as sortable/filterable, which
/// triggers exactly that path. The `"unused"`/`5555` placeholder this file
/// carried until now made `migrator_database_url()` dial a database that
/// isn't the throwaway clone at all — reproduced live 2026-09-06 on the
/// unmodified `dashboard_migration.rs` file under this exact environment
/// (see `dashboard_access.rs`'s identical doc comment), so this is a
/// pre-existing gap in the shared test-harness convention this file copied,
/// not something the C-11 bulk-ring collapse introduced — this file just
/// needs a real result and adopts the same local workaround
/// `dashboard_access.rs` already established, rather than leaving a broken
/// regression test behind.
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

async fn test_system() -> Option<EngineSystem> {
    test_system_with(|_| {}).await
}

async fn test_system_with(configure: impl FnOnce(&mut AppConfig)) -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let db_parts = DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse");

    let mut config = test_config(&db_parts);
    configure(&mut config);
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
    // D-143: entity_crud/bulk routes are license-gated (MODULE_CORE) — grant
    // every module so this suite exercises them the way a fully licensed
    // deployment would.
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
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

/// Seeds a throwaway `user_account` row (with an email, so the target
/// can be named by `POST /api/v1/admin/security/grants`'s `user_email`), and
/// optionally the `system.admin` privilege grant. Returns (user_id, email,
/// cookie).
async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("bulk-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("bulk-test-{user_id}"))
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

    (user_id, email, session_cookie(user_id))
}

/// Same as `seed_user(&system, false)`, but takes the DB pool directly —
/// needed by tests that must seed an extra non-admin user *after* `full_app`
/// has already consumed the `EngineSystem` (the pool is cloned out beforehand,
/// same pattern every test below uses for its own post-`full_app` queries).
async fn seed_non_admin_user(db: &attome_db::DbPool) -> (Uuid, String, String) {
    let user_id = Uuid::now_v7();
    let email = format!("bulk-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("bulk-test-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email, session_cookie(user_id))
}

/// Seeds a non-admin user and grants `{logicalname}.{action}` for every
/// action in `actions` (e.g. `&["read", "create", "bulk"]`) via the admin
/// grants endpoint.
async fn seed_scoped_user(
    db: &attome_db::DbPool,
    app: &axum::Router,
    admin_cookie: &str,
    logicalname: &str,
    actions: &[&str],
) -> (Uuid, String, String) {
    let (user_id, email, cookie) = seed_non_admin_user(db).await;
    for action in actions {
        grant_privilege(
            app,
            admin_cookie,
            &email,
            &format!("{logicalname}.{action}"),
        )
        .await;
    }
    (user_id, email, cookie)
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

/// `sec-fetch-site: same-origin` is what `attome_server::middleware::csrf`'s
/// `csrf_protect` treats as same-origin evidence for a cookie-authenticated
/// unsafe-method request (an `oneshot()`-driven test request otherwise looks
/// like a non-browser client presenting a cookie, which that middleware
/// fails closed on by design) — same approach `rewrap_admin.rs` uses, so
/// `test_config()` above doesn't need a `cors.allowed_origins` entry.
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
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

/// Provisions a throwaway entity with a `title` (text) and `amount` (number)
/// field — mirrors `entity_round_trip.rs`'s `provision_test_entity`, adapted
/// to also hand back the entity id (needed by nothing in this file directly
/// today, but kept for parity/future use) and an `is_append_only` toggle
/// (needed by the append-only-forbids-bulk test).
async fn provision_entity(
    app: &axum::Router,
    admin_cookie: &str,
    prefix: &str,
    is_append_only: bool,
) -> (String, Uuid) {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({
                "logicalname": logicalname,
                "name": "Bulk Mutation Test",
                "is_append_only": is_append_only,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity = body_json(res).await;
    let entity_id: Uuid = entity["id"].as_str().unwrap().parse().unwrap();

    for (ln, ft) in [("title", "text"), ("amount", "number")] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                admin_cookie,
                Some(&json!({ "logicalname": ln, "name": ln, "field_type": ft })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create field {ln}");
    }

    (logicalname, entity_id)
}

/// Provisions `attome_document` with the full production shape (D-364) —
/// copied near-verbatim from `document_management.rs::provision_xrm_document`
/// (same "copied harness" convention this file's header comment already
/// follows for `rewrap_admin.rs`/`entity_round_trip.rs`), except tolerant of
/// `attome_document` already existing. Needed by the C-11 regression test
/// below: `sync_file_field_documents` no-ops when this entity isn't
/// provisioned, same as production.
///
/// `document_management.rs`'s original version asserts `201 CREATED`
/// unconditionally — true when it was written, but `EngineSystem::build()` now
/// unconditionally applies the `attome-document` platform bundle
/// (`system.rs`'s D-364/D-478 `apply_platform_bundle` call, "seeds-to-
/// bundles", REVIEW-2026-09-02 item 11), which provisions `attome_document`
/// with this exact same field shape on every boot — including this
/// harness's `EngineSystem::builder(..).build()` call, regardless of which
/// modules are `.register()`ed. So this now gets `409 Conflict`, not `201`,
/// on a database that's already been through `build()` once (every
/// `test_system()` call in this file). A pre-existing platform change this
/// diff did not make, not something to route around by skipping `build()`
/// or hand-writing SQL (guidelines §4, API-first) — the correct fix is for
/// this helper to accept the entity already existing, the same way
/// `bulk_mutation.rs`'s own `provision_upsert_unique_index` above already
/// tolerates its endpoint's non-201 outcomes.
async fn provision_xrm_document(app: &axum::Router, admin_cookie: &str) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({ "logicalname": "attome_document", "name": "Document" })),
        ))
        .await
        .unwrap();
    if res.status() == StatusCode::CONFLICT {
        // Already provisioned by `EngineSystem::build()`'s unconditional
        // platform-bundle apply, with the identical field shape below —
        // nothing left to do.
        return;
    }
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "create attome_document entity"
    );
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().unwrap();

    for (ln, name, ft, required) in [
        ("name", "Name", "text", true),
        ("entity_name", "Entity Name", "text", true),
        ("record_id", "Record ID", "text", true),
        ("folder", "Folder", "text", true),
        // Optional at the metadata level (D-364): an upload session must be
        // scoped to an *existing* record, so a Document row's own key can
        // only be known after it exists.
        ("file", "File", "file", false),
        ("source_field", "Source Field", "text", false),
    ] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                admin_cookie,
                Some(&json!({
                    "logicalname": ln, "name": name, "field_type": ft,
                    "is_required": required,
                })),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "create attome_document field {ln}"
        );
    }
}

/// Provisions a throwaway entity with a required `title` (text) field and an
/// optional `attachment` (file) field — same shape as `provision_entity`
/// above, plus the file field the C-11 mirror regression needs.
async fn provision_entity_with_file_field(app: &axum::Router, admin_cookie: &str) -> String {
    let logicalname = format!("bulkfile_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({ "logicalname": logicalname, "name": "Bulk File Mirror Test" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    for (ln, ft) in [("title", "text"), ("attachment", "file")] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                admin_cookie,
                Some(&json!({ "logicalname": ln, "name": ln, "field_type": ft })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create field {ln}");
    }

    logicalname
}

/// Grants `privilege_key` to `user_email` via the admin grants endpoint
/// (`authz.rs`'s pattern) — used to build a caller with some but not all of
/// bulk's two required privileges.
async fn grant_privilege(
    app: &axum::Router,
    admin_cookie: &str,
    user_email: &str,
    privilege_key: &str,
) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/security/grants",
            admin_cookie,
            Some(&json!({ "user_email": user_email, "privilege_key": privilege_key })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "grant {privilege_key} to {user_email}"
    );
}

/// Lazily provisions the "upsert match-key" unique index
/// (`ux_{entity}_upsert_{digest}`, `entity_crud/upsert.rs`) on `column` — the
/// same mechanism `bulk_graph.rs`'s own module doc names as the source of
/// `fetch_unique_key_columns`' unique-key tuples. Provisioning a genuinely
/// new upsert key requires `system.admin` (the admin cookie here), and also
/// inserts one throwaway row with `column = seed_value` as a side effect.
async fn provision_upsert_unique_index(
    app: &axum::Router,
    admin_cookie: &str,
    logicalname: &str,
    column: &str,
    seed_value: &str,
) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/upsert"),
            admin_cookie,
            Some(&json!({ "match": { column: seed_value } })),
        ))
        .await
        .unwrap();
    let status = status_or_body(res).await;
    assert_eq!(
        status.0,
        StatusCode::CREATED,
        "provision upsert unique index on {column}: {:?}",
        status.1
    );
}

async fn status_or_body(res: axum::response::Response) -> (StatusCode, Value) {
    let status = res.status();
    (status, body_json(res).await)
}

fn bulk_body(operation: &str, batch_mode: Option<&str>, records: Vec<Value>) -> Value {
    let mut body = json!({ "operation": operation, "records": records });
    if let Some(mode) = batch_mode {
        body["batch_mode"] = json!(mode);
    }
    body
}

async fn row_count(db: &attome_db::DbPool, logicalname: &str) -> i64 {
    let table = attome_core::quote_ident(logicalname);
    sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(db)
        .await
        .expect("count entity rows")
}

// ── 1. Request-shape validation ─────────────────────────────────────────────

/// `validate_request_shape`: an invalid `operation` string, `strict: false`
/// (mutation safeguards can never be disabled), and an invalid `batch_mode`
/// must all 422 before anything is enqueued.
#[tokio::test]
async fn enqueue_rejects_invalid_operation_strict_and_batch_mode() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "shape", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &uri,
            &admin_cookie,
            Some(&bulk_body(
                "not-a-real-operation",
                None,
                vec![json!({ "data": { "title": "x" } })],
            )),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad operation"
    );

    let mut body = bulk_body("create", None, vec![json!({ "data": { "title": "x" } })]);
    body["strict"] = json!(false);
    let res = app
        .clone()
        .oneshot(req("POST", &uri, &admin_cookie, Some(&body)))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "strict: false must be rejected"
    );

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &uri,
            &admin_cookie,
            Some(&bulk_body(
                "create",
                Some("not-partial-or-atomic"),
                vec![json!({ "data": { "title": "x" } })],
            )),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad batch_mode"
    );
}

/// Empty `records` and more than `MAX_BULK_RECORDS` (500) records must both
/// 422 — the count check runs before any per-record validation, so the
/// oversized payload's records don't need to be individually meaningful.
#[tokio::test]
async fn enqueue_rejects_empty_and_oversized_record_batches() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "size", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &uri,
            &admin_cookie,
            Some(&bulk_body("create", None, vec![])),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "empty records"
    );

    let too_many: Vec<Value> = (0..501).map(|_| json!({ "data": {} })).collect();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &uri,
            &admin_cookie,
            Some(&bulk_body("create", None, too_many)),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "501 records must exceed MAX_BULK_RECORDS (AA9-T4: limit_exceeded)"
    );
}

/// `validate_record_envelope`: a `create` record must not carry `id`/
/// `expected_row_version`; `update`/`delete` records must carry both, and
/// `expected_row_version` must be non-negative. `data` must be a JSON object.
#[tokio::test]
async fn enqueue_rejects_malformed_record_envelopes() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "envelope", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");

    let cases: Vec<(&str, Value)> = vec![
        (
            "create with id",
            bulk_body(
                "create",
                None,
                vec![json!({ "id": Uuid::now_v7(), "data": {} })],
            ),
        ),
        (
            "create with expected_row_version",
            bulk_body(
                "create",
                None,
                vec![json!({ "expected_row_version": 0, "data": {} })],
            ),
        ),
        (
            "update missing id",
            bulk_body(
                "update",
                None,
                vec![json!({ "expected_row_version": 0, "data": { "title": "x" } })],
            ),
        ),
        (
            "update missing expected_row_version",
            bulk_body(
                "update",
                None,
                vec![json!({ "id": Uuid::now_v7(), "data": { "title": "x" } })],
            ),
        ),
        (
            "negative expected_row_version",
            bulk_body(
                "update",
                None,
                vec![json!({
                    "id": Uuid::now_v7(),
                    "expected_row_version": -1,
                    "data": { "title": "x" }
                })],
            ),
        ),
        (
            "non-object data",
            bulk_body("create", None, vec![json!({ "data": "not-an-object" })]),
        ),
    ];

    for (label, body) in cases {
        let res = app
            .clone()
            .oneshot(req("POST", &uri, &admin_cookie, Some(&body)))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "case should 422: {label}"
        );
    }
}

// ── 2. Authorization ─────────────────────────────────────────────────────────

/// Bulk requires BOTH `ctx.require(entity, operation)` AND the separate
/// `ctx.require(entity, "bulk")` grant — a caller with only the operation
/// privilege must be forbidden until the dedicated `bulk` privilege is also
/// granted.
#[tokio::test]
async fn bulk_requires_both_operation_privilege_and_dedicated_bulk_privilege() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "authz", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");

    let (_, caller_email, caller_cookie) = seed_non_admin_user(&db).await;
    grant_privilege(
        &app,
        &admin_cookie,
        &caller_email,
        &format!("{logicalname}.create"),
    )
    .await;

    let body = bulk_body(
        "create",
        None,
        vec![json!({ "data": { "title": "no-bulk-yet" } })],
    );
    let res = app
        .clone()
        .oneshot(req("POST", &uri, &caller_cookie, Some(&body)))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "create-only grant must not allow bulk"
    );

    grant_privilege(
        &app,
        &admin_cookie,
        &caller_email,
        &format!("{logicalname}.bulk"),
    )
    .await;
    let res = app
        .clone()
        .oneshot(req("POST", &uri, &caller_cookie, Some(&body)))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::ACCEPTED,
        "create + bulk grants together must allow bulk"
    );
}

/// Bulk mutation is forbidden outright on an append-only entity, regardless
/// of privilege (checked after `ctx.require`, so even an admin is rejected).
#[tokio::test]
async fn bulk_forbidden_on_append_only_entity() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "appendonly", true).await;
    let uri = format!("/api/v1/{logicalname}/bulk");

    let body = bulk_body("create", None, vec![json!({ "data": { "title": "x" } })]);
    let res = app
        .clone()
        .oneshot(req("POST", &uri, &admin_cookie, Some(&body)))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "append-only entity must reject bulk mutation"
    );
}

// ── 2b. The audit ledger is not creatable through generic CRUD (item 1.1) ────

/// D-516 ruling 5 / audit 10/10 plan item 1.1: `audit_header`,
/// `audit_detail` and `audit_snapshot` are written only by the audit
/// writers (`attome_core::crud::append_only_insert` and the chainer's batch
/// append), never through a create path a caller can reach.
///
/// The hole this closes: `create_record_for` resolved the entity and threw
/// away `is_append_only` — unlike update, delete, upsert and bulk, which all
/// refuse on it — so an admin could POST a forged ledger row straight into the
/// chain. A forged header carrying a `chain_batch_ref` was additionally exempt
/// from the per-row signature rule until item 1.2 closed that half.
///
/// The refusal lives in `entity_mutation::create_one`, the one function every
/// create path funnels through (generic API, bundle record sets, the workflow
/// Create Record node, upsert, bulk), so all of D-516 ruling 5's named paths
/// are covered by a single guard. It runs before `validate_body`, so an
/// incomplete payload is refused as forbidden rather than unprocessable —
/// which is the point: the caller never gets far enough to be told what a
/// well-formed forgery would look like.
#[tokio::test]
async fn generic_create_is_forbidden_on_every_audit_ledger_entity() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    for logicalname in ["audit_header", "audit_detail", "audit_snapshot"] {
        let before = row_count(&db, logicalname).await;
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}"),
                &admin_cookie,
                Some(&json!({
                    "entity_name": "forged",
                    "record_id": Uuid::now_v7().to_string(),
                })),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{logicalname} must refuse a generic create, even for an admin"
        );
        assert_eq!(
            row_count(&db, logicalname).await,
            before,
            "{logicalname} must not have gained a row"
        );
    }
}

/// The exclusion half of D-516 ruling 5. `attome_document` shares the polymorphic
/// audit access predicate (`POLYMORPHIC_AUDIT_ENTITIES`) but is an ordinary,
/// creatable entity, so the guard is scoped to the three ledger tables by name
/// — not to that list, and not to the `is_append_only` flag, which
/// `integration_event` also carries while being created through this very
/// path by the inbound webhook.
#[tokio::test]
async fn generic_create_still_works_for_xrm_document() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    provision_xrm_document(&app, &admin_cookie).await;

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/attome_document",
            &admin_cookie,
            Some(&json!({
                "name": "note.txt",
                "entity_name": "some_entity",
                "record_id": Uuid::now_v7().to_string(),
                "folder": "general",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "attome_document is excluded by name from the ledger guard"
    );
}

// ── 2c. Hard-delete snapshots mask sensitive columns (item 1.4) ──────────────

/// Audit 10/10 plan item 1.4: a hard delete captures the whole row through
/// `row_to_json` and stores it in `audit_snapshot`, which is a readable
/// entity. The detail rows for that same event mask `is_sensitive` values
/// (`attome_audit::service`'s `mask_sensitive`); the snapshot did not, so a hard
/// delete was the one mutation that published secrets to anyone able to read
/// the audit trail.
///
/// Interim by design: masking on write destroys the value for authorized
/// auditors too. Phase 5 replaces both paths with encryption at rest plus
/// read-time visibility.
#[tokio::test]
async fn hard_delete_snapshot_masks_sensitive_columns() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    // Kept before `full_app` consumes the system: the chainer needs the same
    // state's signer below.
    let state = system.state().clone();
    let app = full_app(system);
    let (logicalname, entity_id) = provision_entity(&app, &admin_cookie, "masked", false).await;

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            &admin_cookie,
            Some(&json!({
                "logicalname": "secret_hash",
                "name": "Secret Hash",
                "field_type": "text",
                "is_sensitive": true,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create sensitive field");

    const SECRET: &str = "super-secret-value-do-not-log";
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}"),
            &admin_cookie,
            Some(&json!({ "title": "masked", "secret_hash": SECRET })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create record");
    let record_id = body_json(res).await["id"].as_str().unwrap().to_owned();

    let res = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/v1/{logicalname}/{record_id}/hard-delete"),
            &admin_cookie,
            None,
        ))
        .await
        .unwrap();
    assert!(
        res.status().is_success(),
        "hard delete failed: {}",
        res.status()
    );

    // `audit.chainer_enabled` defaults to true (D-316), so the delete's audit
    // event is captured into `audit_ingest` and only becomes an
    // `audit_header` + `audit_snapshot` pair once the chainer drains
    // it. Masking happens at capture, before either storage site, so this
    // proves the stored snapshot — not just the in-flight event.
    attome_audit::chainer::run_once(&state.base.db, state.audit_signer.as_deref(), 1000, None)
        .await
        .expect("drain the audit ingest queue");

    let snapshot: Option<Value> = sqlx::query_scalar(
        "SELECT snapshot_json::jsonb FROM audit_snapshot \
         WHERE entity_name = $1 AND record_id = $2::uuid",
    )
    .bind(&logicalname)
    .bind(&record_id)
    .fetch_optional(&db)
    .await
    .expect("read the hard-delete snapshot");

    let snapshot = snapshot.expect("a hard delete must write an audit snapshot");
    assert_eq!(
        snapshot["secret_hash"], "********",
        "the sensitive column must be masked: {snapshot}"
    );
    assert_eq!(
        snapshot["title"], "masked",
        "non-sensitive columns stay readable: {snapshot}"
    );
    assert!(
        !snapshot.to_string().contains(SECRET),
        "no plaintext secret may survive anywhere in the snapshot: {snapshot}"
    );
}

/// Invariant I1, bundle half — the record-set apply is a second, non-HTTP
/// way into `entity_mutation::create_one` (the create branch of
/// `attome_api::bundle::record_sets`), so the ledger guard has to hold here
/// too and not only on the generic entity API proved above.
///
/// Each row below carries every required attribute of its entity, so the
/// only thing left that can refuse it is the guard itself: a `Validation`
/// error here would mean the row was rejected for being malformed and would
/// prove nothing. `apply_record` resolves the entity before it creates, so
/// a `NotFound` would likewise prove nothing — this harness already has the
/// ledger entities registered, as the generic-API test above depends on.
#[tokio::test]
async fn bundle_record_set_create_is_refused_on_every_audit_ledger_entity() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state().clone();
    let db = state.base.db.clone();

    // Unique per run: these ledger tables are append-only and survive across
    // runs against the same throwaway database.
    let marker = format!("ledger-guard-{}", Uuid::now_v7());
    let obj = |v: Value| v.as_object().cloned().expect("object literal");

    let cases = [
        (
            "audit_header",
            "event_hash",
            obj(json!({
                "category": 1,
                "operation": 1,
                "event_hash": marker.as_str(),
                "initiator": 1,
            })),
        ),
        (
            "audit_detail",
            "field_name",
            // `audit_ref` is a required lookup. The guard runs before
            // `create_one` validates the body, so it never has to resolve
            // to a real header row.
            obj(json!({
                "audit_ref": Uuid::now_v7().to_string(),
                "field_name": marker.as_str(),
            })),
        ),
        (
            "audit_snapshot",
            "entity_name",
            obj(json!({
                "entity_name": marker.as_str(),
                "record_id": Uuid::now_v7().to_string(),
                "version": 1,
                "snapshot_json": "{}",
            })),
        ),
    ];

    for (entity, key_field, body) in cases {
        let before = row_count(&db, entity).await;
        let err = attome_api::bundle::apply_record(
            &state,
            Uuid::nil(),
            entity,
            &[key_field.to_owned()],
            &body,
        )
        .await
        .expect_err("a bundle record set must never create an audit ledger row");
        assert!(
            matches!(err, attome_types::AppError::Forbidden),
            "{entity}: a bundle record-set create must be refused as Forbidden, got {err:?}"
        );
        assert_eq!(
            row_count(&db, entity).await,
            before,
            "{entity} must not have gained a row"
        );
    }
}

// ── 3. Happy path ────────────────────────────────────────────────────────────

/// A valid bulk create enqueue durably writes the operation row (`status =
/// 'pending'`, `total = 3`) and 3 `'pending'` item ledger rows in the same
/// transaction as the Apalis job.
#[tokio::test]
async fn enqueue_creates_pending_bulk_operation_with_pending_items() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "happy", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");

    let body = bulk_body(
        "create",
        None,
        vec![
            json!({ "data": { "title": "a" } }),
            json!({ "data": { "title": "b" } }),
            json!({ "data": { "title": "c" } }),
        ],
    );
    let res = app
        .clone()
        .oneshot(req("POST", &uri, &admin_cookie, Some(&body)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let created = body_json(res).await;
    let bulk_op_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    assert_eq!(created["status"], "pending");
    assert_eq!(created["total"], 3);

    let (status, total): (String, i32) =
        sqlx::query_as("SELECT status, total FROM automation_bulk_operation WHERE id = $1")
            .bind(bulk_op_id)
            .fetch_one(&db)
            .await
            .expect("bulk operation row");
    assert_eq!(status, "pending");
    assert_eq!(total, 3);

    let item_statuses: Vec<String> = sqlx::query_scalar(
        "SELECT status FROM automation_bulk_operation_item
         WHERE bulk_operation_id = $1 ORDER BY item_index",
    )
    .bind(bulk_op_id)
    .fetch_all(&db)
    .await
    .expect("bulk item rows");
    assert_eq!(item_statuses, vec!["pending", "pending", "pending"]);
}

// ── 4. get_status ─────────────────────────────────────────────────────────────

/// `GET .../bulk/{id}`: a bulk operation created by one non-admin user is
/// `404` (not `403`) to a different non-admin user who merely has `read`,
/// `200` to its owner, and `200` to an admin regardless of ownership.
#[tokio::test]
async fn get_status_scopes_by_owner_unless_admin() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_email, admin_cookie) = seed_user(&system, true).await;
    let _ = admin_email;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "owner", false).await;

    let owner = seed_scoped_user(
        &db,
        &app,
        &admin_cookie,
        &logicalname,
        &["read", "create", "bulk"],
    )
    .await;
    let other = seed_scoped_user(&db, &app, &admin_cookie, &logicalname, &["read"]).await;

    let enqueue_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &owner.2,
            Some(&bulk_body(
                "create",
                None,
                vec![json!({ "data": { "title": "x" } })],
            )),
        ))
        .await
        .unwrap();
    assert_eq!(enqueue_res.status(), StatusCode::ACCEPTED);
    let bulk_op_id = body_json(enqueue_res).await["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let status_uri = format!("/api/v1/{logicalname}/bulk/{bulk_op_id}");

    let res = app
        .clone()
        .oneshot(req("GET", &status_uri, &other.2, None))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a non-owner, non-admin caller must get 404, not 403"
    );

    let res = app
        .clone()
        .oneshot(req("GET", &status_uri, &owner.2, None))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the owner must be able to read it"
    );

    let res = app
        .clone()
        .oneshot(req("GET", &status_uri, &admin_cookie, None))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "an admin must be able to read any user's bulk operation"
    );
}

/// `include_items=true` returns the item ledger, and `page`/`page_size`
/// actually slice it (3 items, page_size=2 → 2 then 1).
#[tokio::test]
async fn get_status_include_items_paginates() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "page", false).await;

    let enqueue_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&bulk_body(
                "create",
                None,
                vec![
                    json!({ "data": { "title": "a" } }),
                    json!({ "data": { "title": "b" } }),
                    json!({ "data": { "title": "c" } }),
                ],
            )),
        ))
        .await
        .unwrap();
    assert_eq!(enqueue_res.status(), StatusCode::ACCEPTED);
    let bulk_op_id = body_json(enqueue_res).await["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/{logicalname}/bulk/{bulk_op_id}?include_items=true&page_size=2"),
            &admin_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let page1 = body_json(res).await;
    assert_eq!(
        page1["items"].as_array().unwrap().len(),
        2,
        "page 1 (the default first page) must have 2 items"
    );

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!(
                "/api/v1/{logicalname}/bulk/{bulk_op_id}?include_items=true&page=2&page_size=2"
            ),
            &admin_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let page2 = body_json(res).await;
    assert_eq!(
        page2["items"].as_array().unwrap().len(),
        1,
        "page 2 must have the remaining item"
    );
}

// ── 5/6. Batch preflight (unique-key collision, no hierarchy attribute needed) ──

/// `batch_mode="atomic"`: a whole-batch unique-key collision (both records
/// set the same value for a column the lazily-provisioned upsert unique
/// index covers) rejects the entire batch with `422` and leaves no
/// `automation_bulk_operation` row behind at all.
#[tokio::test]
async fn atomic_batch_mode_rejects_whole_batch_on_unique_key_collision() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "atomic", false).await;
    provision_upsert_unique_index(&app, &admin_cookie, &logicalname, "title", "seed-atomic").await;

    let body = bulk_body(
        "create",
        Some("atomic"),
        vec![
            json!({ "data": { "title": "collide-atomic" } }),
            json!({ "data": { "title": "collide-atomic" } }),
        ],
    );
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let error = body_json(res).await;
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("batch_mode=\"atomic\""),
        "message should name the atomic rejection: {message}"
    );

    let op_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM automation_bulk_operation WHERE entity_logicalname = $1",
    )
    .bind(&logicalname)
    .fetch_one(&db)
    .await
    .expect("count bulk operations for entity");
    assert_eq!(
        op_count, 0,
        "an atomic rejection must leave no bulk operation row behind"
    );
}

/// `batch_mode="partial"` (the default): the same collision seeds only the
/// two offending items as `'rejected'` with a non-null `error`, while an
/// unrelated third item in the same batch stays `'pending'`.
#[tokio::test]
async fn partial_batch_mode_rejects_only_the_colliding_items() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "partial", false).await;
    provision_upsert_unique_index(&app, &admin_cookie, &logicalname, "title", "seed-partial").await;

    let body = bulk_body(
        "create",
        None, // default is "partial"
        vec![
            json!({ "data": { "title": "collide-partial" } }),
            json!({ "data": { "title": "collide-partial" } }),
            json!({ "data": { "title": "unique-value" } }),
        ],
    );
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::ACCEPTED,
        "partial mode must still enqueue the operation"
    );
    let bulk_op_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let items: Vec<(i32, String, Option<String>)> = sqlx::query_as(
        "SELECT item_index, status, error FROM automation_bulk_operation_item
         WHERE bulk_operation_id = $1 ORDER BY item_index",
    )
    .bind(bulk_op_id)
    .fetch_all(&db)
    .await
    .expect("item rows");
    assert_eq!(items.len(), 3);
    assert_eq!(items[0].1, "rejected");
    assert!(items[0].2.is_some(), "rejected item must carry a reason");
    assert_eq!(items[1].1, "rejected");
    assert!(items[1].2.is_some());
    assert_eq!(
        items[2].1, "pending",
        "the non-colliding third item must not be swept into rejection"
    );
    assert!(items[2].2.is_none());
}

async fn enqueued_job_records(db: &attome_db::DbPool, variant: &str, payload: Value) -> Value {
    sqlx::query_scalar("SELECT job->'payload'->'records' FROM apalis.jobs WHERE job @> $1::jsonb")
        .bind(json!({ "variant": variant, "payload": payload }))
        .fetch_one(db)
        .await
        .expect("the enqueued job row exists")
}

// ── 7/8. attome_records::bulk::process (driven directly, no live worker needed) ────

/// `process` with `raw_records: vec![]` exercises the D-193 ledger-fallback
/// path (records are read back from `automation_bulk_operation_item.payload`
/// instead of the job payload) and actually creates the entity rows, flips
/// every item to `'succeeded'` with a `record_id`, and completes the
/// operation with `succeeded = 3, failed = 0`.
#[tokio::test]
async fn process_creates_records_from_ledger_when_raw_records_empty() {
    let system = skip_if_no_db!(test_system().await);
    let (user_id, _, admin_cookie) = seed_user(&system, true).await;
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "process", false).await;

    let enqueue_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&bulk_body(
                "create",
                None,
                vec![
                    json!({ "data": { "title": "p1" } }),
                    json!({ "data": { "title": "p2" } }),
                    json!({ "data": { "title": "p3" } }),
                ],
            )),
        ))
        .await
        .unwrap();
    assert_eq!(enqueue_res.status(), StatusCode::ACCEPTED);
    let bulk_op_id: Uuid = body_json(enqueue_res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // BJB-10b (D-193 Release B): the job carries a pointer, never the records.
    assert_eq!(
        enqueued_job_records(
            &db,
            "BulkEntityOperation",
            json!({ "bulk_op_id": bulk_op_id })
        )
        .await,
        json!([])
    );

    attome_records::bulk::process(
        &state,
        bulk_op_id,
        &logicalname,
        "create",
        Vec::new(),
        user_id,
    )
    .await
    .expect("process must succeed");

    let (status, succeeded, failed): (String, i32, i32) = sqlx::query_as(
        "SELECT status, succeeded, failed FROM automation_bulk_operation WHERE id = $1",
    )
    .bind(bulk_op_id)
    .fetch_one(&db)
    .await
    .expect("bulk operation row");
    assert_eq!(status, "completed");
    assert_eq!(succeeded, 3);
    assert_eq!(failed, 0);

    let item_rows: Vec<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT status, record_id FROM automation_bulk_operation_item
         WHERE bulk_operation_id = $1 ORDER BY item_index",
    )
    .bind(bulk_op_id)
    .fetch_all(&db)
    .await
    .expect("item rows");
    assert_eq!(item_rows.len(), 3);
    for (status, record_id) in &item_rows {
        assert_eq!(status, "succeeded");
        assert!(record_id.is_some());
    }

    assert_eq!(
        row_count(&db, &logicalname).await,
        3,
        "3 real entity rows must exist"
    );
}

/// A stale `expected_row_version` inside one item's own mutation (an
/// `AppError::VersionConflict`, not `AppError::Internal`) must be caught by
/// `apply_one`, mark just that item `'failed'` with a non-null error, and let
/// the rest of the batch still reach `'succeeded'` — the operation itself
/// still lands on `'completed'`, not `'failed'` (partial mode keeps going).
#[tokio::test]
async fn process_partial_failure_marks_one_item_failed_and_completes_the_rest() {
    let system = skip_if_no_db!(test_system().await);
    let (user_id, _, admin_cookie) = seed_user(&system, true).await;
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "partialfail", false).await;

    // Two real records to update, row_version 0 each.
    let mut record_ids = Vec::new();
    for title in ["r1", "r2"] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}"),
                &admin_cookie,
                Some(&json!({ "title": title })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        record_ids.push(created["id"].as_str().unwrap().to_owned());
    }

    let body = bulk_body(
        "update",
        None,
        vec![
            json!({ "id": record_ids[0], "expected_row_version": 0, "data": { "title": "updated" } }),
            // Deliberately stale — the real row_version is 0, not 99.
            json!({ "id": record_ids[1], "expected_row_version": 99, "data": { "title": "updated" } }),
        ],
    );
    let enqueue_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(enqueue_res.status(), StatusCode::ACCEPTED);
    let bulk_op_id: Uuid = body_json(enqueue_res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    attome_records::bulk::process(
        &state,
        bulk_op_id,
        &logicalname,
        "update",
        Vec::new(),
        user_id,
    )
    .await
    .expect("process must not itself error for a business-level item failure");

    let (op_status, succeeded, failed): (String, i32, i32) = sqlx::query_as(
        "SELECT status, succeeded, failed FROM automation_bulk_operation WHERE id = $1",
    )
    .bind(bulk_op_id)
    .fetch_one(&db)
    .await
    .expect("bulk operation row");
    assert_eq!(
        op_status, "completed",
        "a business-level per-item failure must not fail the whole operation"
    );
    assert_eq!(succeeded, 1);
    assert_eq!(failed, 1);

    let items: Vec<(i32, String, Option<String>)> = sqlx::query_as(
        "SELECT item_index, status, error FROM automation_bulk_operation_item
         WHERE bulk_operation_id = $1 ORDER BY item_index",
    )
    .bind(bulk_op_id)
    .fetch_all(&db)
    .await
    .expect("item rows");
    assert_eq!(items[0].1, "succeeded");
    assert!(items[0].2.is_none());
    assert_eq!(items[1].1, "failed");
    assert!(
        items[1].2.is_some(),
        "the stale-version item must carry an error"
    );
}

/// A16-T6: a bulk update of three rows with one stale applies the other
/// two and reports the stale row as a conflict carrying the record's current
/// version, both in the item ledger and in the operation's errors.
#[tokio::test]
async fn bulk_conflict_rows_apply_the_rest_and_report_the_stale_one() {
    let system = skip_if_no_db!(test_system().await);
    let (user_id, _, admin_cookie) = seed_user(&system, true).await;
    let state = system.state().clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "conflictrows", false).await;

    let mut record_ids = Vec::new();
    for title in ["r1", "r2", "r3"] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}"),
                &admin_cookie,
                Some(&json!({ "title": title })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
        record_ids.push(body_json(res).await["id"].as_str().unwrap().to_owned());
    }
    // Someone else edits r2 after the caller read it at version 0.
    let mut patch = req(
        "PATCH",
        &format!("/api/v1/{logicalname}/{}", record_ids[1]),
        &admin_cookie,
        Some(&json!({ "title": "theirs" })),
    );
    patch
        .headers_mut()
        .insert("if-match", "\"0\"".parse().unwrap());
    let res = app.clone().oneshot(patch).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = bulk_body(
        "update",
        None,
        record_ids
            .iter()
            .map(|id| json!({ "id": id, "expected_row_version": 0, "data": { "title": "mine" } }))
            .collect(),
    );
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let bulk_op_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    attome_records::bulk::process(
        &state,
        bulk_op_id,
        &logicalname,
        "update",
        Vec::new(),
        user_id,
    )
    .await
    .expect("a conflicting row does not fail the operation");

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/{logicalname}/bulk/{bulk_op_id}?include_items=true"),
            &admin_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let status = body_json(res).await;
    assert_eq!(status["succeeded"], 2, "{status}");
    assert_eq!(status["failed"], 1, "{status}");
    let outcomes: Vec<&str> = status["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            if item["ok"].is_object() {
                "ok"
            } else {
                item["problem"]["code"].as_str().unwrap()
            }
        })
        .collect();
    assert_eq!(outcomes, ["ok", "version_conflict", "ok"], "{status}");
    assert_eq!(status["items"][1]["index"], 1, "{status}");
    let conflict = &status["items"][1]["problem"]["detail"];
    assert_eq!(conflict["current_version"], 1, "{status}");
    assert_eq!(status["errors"][0]["index"], 1, "{status}");
    assert_eq!(status["errors"][0]["status"], "conflict", "{status}");

    // The two fresh rows took the caller's value; the stale one kept theirs.
    for (index, title) in [(0, "mine"), (1, "theirs"), (2, "mine")] {
        let res = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v1/{logicalname}/{}", record_ids[index]),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(body_json(res).await["data"]["title"], title);
    }
}

// ── 9. Staged import: dry-run, then approve ─────────────────────────────────

/// `POST .../staged-import` dry-runs every record (one real update that
/// passes, one update against a nonexistent id that fails with `NotFound`)
/// and never persists anything — `dry_run_one` always rolls back, so the
/// pre-existing record's `title` must be unchanged afterward.
#[tokio::test]
async fn staged_import_dry_runs_without_persisting() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "stagedryrun", false).await;

    let create_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}"),
            &admin_cookie,
            Some(&json!({ "title": "original" })),
        ))
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::CREATED);
    let created = body_json(create_res).await;
    let record_id = created["id"].as_str().unwrap().to_owned();

    let body = bulk_body(
        "update",
        None,
        vec![
            json!({
                "id": record_id, "expected_row_version": 0,
                "data": { "title": "updated-in-dry-run" }
            }),
            json!({
                "id": Uuid::now_v7(), "expected_row_version": 0,
                "data": { "title": "does-not-exist" }
            }),
        ],
    );
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/staged-import"),
            &admin_cookie,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let report = body_json(res).await;
    assert_eq!(report["total"], 2);
    assert_eq!(report["passed"], 1);
    assert_eq!(report["failed"], 1);
    assert_eq!(report["rejected"], 0);

    let get_res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/{logicalname}/{record_id}"),
            &admin_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(get_res.status(), StatusCode::OK);
    let record = body_json(get_res).await;
    assert_eq!(
        record["data"]["title"], "original",
        "dry_run_one must always roll back — the record must be unchanged"
    );
    assert_eq!(record["row_version"], 0);
}

/// Approving a staged import (`POST .../staged-import/{id}/approve`, admin
/// only) enqueues the apply job but does not itself apply anything;
/// `attome_records::bulk::process_staged_import` (called directly, mirroring
/// `process`'s worker-side role) is what actually creates the record and
/// flips the staged import to `'approved'`.
#[tokio::test]
async fn approve_staged_import_then_process_creates_the_record() {
    let system = skip_if_no_db!(test_system().await);
    let (user_id, _, admin_cookie) = seed_user(&system, true).await;
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "approve", false).await;

    let stage_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/staged-import"),
            &admin_cookie,
            Some(&bulk_body(
                "create",
                None,
                vec![json!({ "data": { "title": "to-be-approved" } })],
            )),
        ))
        .await
        .unwrap();
    assert_eq!(stage_res.status(), StatusCode::ACCEPTED);
    let staged = body_json(stage_res).await;
    assert_eq!(staged["passed"], 1);
    assert_eq!(staged["failed"], 0);
    let import_id: Uuid = staged["id"].as_str().unwrap().parse().unwrap();

    assert_eq!(
        row_count(&db, &logicalname).await,
        0,
        "the dry run must not have created a real row"
    );

    let approve_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/staged-import/{import_id}/approve"),
            &admin_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(approve_res.status(), StatusCode::ACCEPTED);
    let approved = body_json(approve_res).await;
    assert_eq!(approved["status"], "approving");

    // BJB-10b (D-193 Release B): the job carries a pointer, never the records.
    assert_eq!(
        enqueued_job_records(&db, "ApplyStagedImport", json!({ "import_id": import_id })).await,
        json!([])
    );

    attome_records::bulk::process_staged_import(
        &state,
        import_id,
        &logicalname,
        "create",
        Vec::new(),
        user_id,
    )
    .await
    .expect("process_staged_import must succeed");

    let (final_status, rejected): (String, i32) =
        sqlx::query_as("SELECT status, rejected FROM automation_staged_import WHERE id = $1")
            .bind(import_id)
            .fetch_one(&db)
            .await
            .expect("staged import row");
    assert_eq!(final_status, "approved");
    assert_eq!(rejected, 0);

    let (item_status, record_id): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status, record_id FROM automation_staged_import_item
         WHERE staged_import_id = $1 AND item_index = 0",
    )
    .bind(import_id)
    .fetch_one(&db)
    .await
    .expect("staged import item row");
    assert_eq!(item_status, "succeeded");
    assert!(record_id.is_some());

    assert_eq!(
        row_count(&db, &logicalname).await,
        1,
        "approving must actually create the record"
    );
}

// ── 9a. Durable idempotency: completion inside the mutation's transaction ───

const BULK_ENQUEUE: &str = "POST /api/v1/{entity}/bulk";
const STAGED_IMPORT_APPROVE: &str = "POST /api/v1/{entity}/staged-import/{id}/approve";

/// attome-server hardening P1.2 (invariant I5): `reclaim_stale_pending` is
/// sound only if every mandatory-tier operation has a test below proving it
/// completes its record in its own transaction.
#[test]
fn every_mandatory_tier_operation_has_a_durable_completion_test() {
    assert_eq!(
        attome_records::bulk::MANDATORY_TIER_OPERATIONS,
        [BULK_ENQUEUE, STAGED_IMPORT_APPROVE],
        "a new mandatory-tier operation needs its own *_completes_its_durable_record_* test"
    );
}

async fn mandatory_tier_system() -> Option<EngineSystem> {
    test_system_with(|config| {
        config.idempotency.mandatory_operations = attome_records::bulk::MANDATORY_TIER_OPERATIONS
            .iter()
            .map(|op| (*op).to_owned())
            .collect();
    })
    .await
}

fn idempotent_post(uri: &str, cookie: &str, key: &str, body: Option<&Value>) -> Request<Body> {
    let mut request = req("POST", uri, cookie, body);
    request
        .headers_mut()
        .insert("x-idempotency-key", key.parse().unwrap());
    request
}

/// `complete_in_tx` is the only completion that writes `mutation_ref`; the
/// middleware's post-response `complete_best_effort` leaves it NULL. So a
/// completed record whose `mutation_ref` names the resource the handler
/// created was completed by the handler's own transaction.
async fn assert_completed_in_the_mutation_tx(
    db: &attome_db::DbPool,
    operation: &str,
    key: &str,
    mutation: Uuid,
) {
    let (state, mutation_ref): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT state, mutation_ref FROM idempotency_record
         WHERE operation = $1 AND client_key = $2",
    )
    .bind(operation)
    .bind(key)
    .fetch_one(db)
    .await
    .expect("the mandatory gate must have written a durable record");
    assert_eq!(state, "completed");
    assert_eq!(
        mutation_ref,
        Some(mutation),
        "{operation} must complete its record with complete_in_tx, not the non-atomic \
         complete_best_effort fallback (invariant I5)"
    );
}

#[tokio::test]
async fn bulk_enqueue_completes_its_durable_record_in_its_own_transaction() {
    let system = skip_if_no_db!(mandatory_tier_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "durablebulk", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");
    let body = bulk_body(
        "create",
        None,
        vec![json!({ "data": { "title": "durable" } })],
    );
    let key = format!("durable-bulk-{}", Uuid::now_v7());

    let res = app
        .clone()
        .oneshot(idempotent_post(&uri, &admin_cookie, &key, Some(&body)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let bulk_op_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    assert_completed_in_the_mutation_tx(&db, BULK_ENQUEUE, &key, bulk_op_id).await;

    let replay = app
        .clone()
        .oneshot(idempotent_post(&uri, &admin_cookie, &key, Some(&body)))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(
        body_json(replay).await["id"],
        bulk_op_id.to_string(),
        "a retry must replay the recorded response, not enqueue again"
    );
}

// ── Z5-T12: the durable tier end to end over HTTP ─────────────────────────────

async fn bulk_operations_for(db: &attome_db::DbPool, logicalname: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM automation_bulk_operation WHERE entity_logicalname = $1",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .unwrap()
}

async fn body_bytes(res: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

// op: POST /api/v1/{entity}/bulk
#[tokio::test]
async fn durable_tier_replays_same_response_over_http() {
    let system = skip_if_no_db!(mandatory_tier_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "durreplay", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");
    let body = bulk_body("create", None, vec![json!({ "data": { "title": "once" } })]);
    let key = format!("durable-replay-{}", Uuid::now_v7());

    let first = app
        .clone()
        .oneshot(idempotent_post(&uri, &admin_cookie, &key, Some(&body)))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let first = body_bytes(first).await;
    let replay = app
        .clone()
        .oneshot(idempotent_post(&uri, &admin_cookie, &key, Some(&body)))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::ACCEPTED);
    assert_eq!(
        replay
            .headers()
            .get("idempotency-replayed")
            .map(|v| v.to_str().unwrap()),
        Some("true")
    );
    assert_eq!(
        body_bytes(replay).await,
        first,
        "the replay is byte-identical"
    );
    assert_eq!(
        bulk_operations_for(&db, &logicalname).await,
        1,
        "one operation only"
    );
}

// negative: POST /api/v1/{entity}/bulk
#[tokio::test]
async fn durable_tier_conflict_on_different_body() {
    let system = skip_if_no_db!(mandatory_tier_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "durconflict", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");
    let key = format!("durable-conflict-{}", Uuid::now_v7());
    let one = bulk_body("create", None, vec![json!({ "data": { "title": "one" } })]);
    let two = bulk_body("create", None, vec![json!({ "data": { "title": "two" } })]);

    let first = app
        .clone()
        .oneshot(idempotent_post(&uri, &admin_cookie, &key, Some(&one)))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let other = app
        .clone()
        .oneshot(idempotent_post(&uri, &admin_cookie, &key, Some(&two)))
        .await
        .unwrap();
    // idempotency.rs: a durable key reused for a different request is
    // AppError::IdempotencyConflict.
    assert_eq!(other.status(), StatusCode::CONFLICT);
    assert_eq!(body_json(other).await["error"], "idempotency_conflict");
    assert_eq!(
        bulk_operations_for(&db, &logicalname).await,
        1,
        "the second never ran"
    );
}

// op: POST /api/v1/{entity}/bulk
#[tokio::test]
async fn durable_tier_expired_key_executes_again() {
    let system = skip_if_no_db!(mandatory_tier_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "durexpire", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");
    let body = bulk_body(
        "create",
        None,
        vec![json!({ "data": { "title": "again" } })],
    );
    let key = format!("durable-expire-{}", Uuid::now_v7());

    let first = accepted_id(
        app.clone()
            .oneshot(idempotent_post(&uri, &admin_cookie, &key, Some(&body)))
            .await
            .unwrap(),
    )
    .await;
    // The retention sweep (PruneIdempotencyRecords) soft-deletes an old
    // record; on this throwaway database the test does what it does.
    let swept = sqlx::query(
        "UPDATE idempotency_record SET is_deleted = true WHERE operation = $1 AND client_key = $2",
    )
    .bind(BULK_ENQUEUE)
    .bind(&key)
    .execute(&db)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(swept, 1);
    let second = accepted_id(
        app.clone()
            .oneshot(idempotent_post(&uri, &admin_cookie, &key, Some(&body)))
            .await
            .unwrap(),
    )
    .await;
    assert_ne!(second, first, "an expired key runs the operation again");
    assert_eq!(bulk_operations_for(&db, &logicalname).await, 2);
}

#[tokio::test]
async fn staged_import_approve_completes_its_durable_record_in_its_own_transaction() {
    let system = skip_if_no_db!(mandatory_tier_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "durableapprove", false).await;

    let stage_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/staged-import"),
            &admin_cookie,
            Some(&bulk_body(
                "create",
                None,
                vec![json!({ "data": { "title": "durable" } })],
            )),
        ))
        .await
        .unwrap();
    assert_eq!(stage_res.status(), StatusCode::ACCEPTED);
    let import_id: Uuid = body_json(stage_res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let uri = format!("/api/v1/{logicalname}/staged-import/{import_id}/approve");
    let key = format!("durable-approve-{}", Uuid::now_v7());
    let res = app
        .clone()
        .oneshot(idempotent_post(&uri, &admin_cookie, &key, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    assert_eq!(body_json(res).await["id"], import_id.to_string());

    assert_completed_in_the_mutation_tx(&db, STAGED_IMPORT_APPROVE, &key, import_id).await;
}

async fn accepted_id(res: axum::response::Response) -> Uuid {
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// Phase 1 security acceptance: the durable tier's identity includes the
/// principal. Two admins enqueueing with the same key and the same body each
/// get their own operation and their own completed record, and each replay
/// returns that principal's own response — never the other's.
#[tokio::test]
async fn a_durable_idempotency_key_is_scoped_to_its_principal() {
    let system = skip_if_no_db!(mandatory_tier_system().await);
    let (user_a, _, cookie_a) = seed_user(&system, true).await;
    let (user_b, _, cookie_b) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    // `prefix_<32 hex>` must fit attome-metadata's 48-byte identifier limit.
    let (logicalname, _) = provision_entity(&app, &cookie_a, "durableprin", false).await;
    let uri = format!("/api/v1/{logicalname}/bulk");
    let body = bulk_body("create", None, vec![json!({ "data": { "title": "same" } })]);
    let key = format!("durable-principal-{}", Uuid::now_v7());
    let enqueue = |cookie: &str| {
        app.clone()
            .oneshot(idempotent_post(&uri, cookie, &key, Some(&body)))
    };

    let op_a = accepted_id(enqueue(&cookie_a).await.unwrap()).await;
    let op_b = accepted_id(enqueue(&cookie_b).await.unwrap()).await;
    assert_ne!(
        op_a, op_b,
        "B must get its own bulk operation, not A's replay"
    );

    for (user, op) in [(user_a, op_a), (user_b, op_b)] {
        let (state, mutation_ref): (String, Option<Uuid>) = sqlx::query_as(
            "SELECT state, mutation_ref FROM idempotency_record
             WHERE principal_ref = $1 AND operation = $2 AND client_key = $3",
        )
        .bind(user)
        .bind(BULK_ENQUEUE)
        .bind(&key)
        .fetch_one(&db)
        .await
        .expect("each principal gets its own durable record");
        assert_eq!(state, "completed");
        assert_eq!(mutation_ref, Some(op));
    }

    assert_eq!(accepted_id(enqueue(&cookie_a).await.unwrap()).await, op_a);
    assert_eq!(accepted_id(enqueue(&cookie_b).await.unwrap()).await, op_b);
}

// ── 10. C-11 (M01-core §7): the bulk ring must mirror file fields too ──────

/// Before C-11, neither `apply_one` nor `apply_staged_one` ever called
/// `sync_file_field_documents` — the same reconciliation the interactive
/// `PATCH .../{entity}/{id}` path always ran (proven for that path by
/// `document_management.rs::file_field_write_mirrors_into_xrm_document_and_clearing_it_soft_deletes_the_mirror`).
/// This proves the bulk path now does too: a bulk `"update"` that sets a
/// file-typed field to a completed upload session's key produces the same
/// `attome_document` row.
///
/// The upload session backing the file key is seeded directly against this
/// throwaway test database (guidelines §4's "tests against a throwaway
/// database" exemption) rather than driven through the real RustFS/clamd
/// pipeline `document_management.rs` uses for its own, narrower purpose —
/// `entity_mutation::lock_file_field_sessions` (the actual write-time gate)
/// only checks for a matching `status = 'clean'` row, not how it got there,
/// and this suite's `test_config` (unlike `document_management.rs`'s) has no
/// real S3/clamd dependency to begin with.
#[tokio::test]
async fn process_update_of_file_field_mirrors_into_xrm_document() {
    let system = skip_if_no_db!(test_system().await);
    let (user_id, _, admin_cookie) = seed_user(&system, true).await;
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);

    provision_xrm_document(&app, &admin_cookie).await;
    let logicalname = provision_entity_with_file_field(&app, &admin_cookie).await;

    let create_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}"),
            &admin_cookie,
            Some(&json!({ "title": "has-a-file" })),
        ))
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::CREATED);
    let created = body_json(create_res).await;
    let record_id_str = created["id"].as_str().unwrap().to_owned();
    let record_id: Uuid = record_id_str.parse().unwrap();

    let final_key = format!("{}-mirror-test.txt", Uuid::now_v7());
    sqlx::query(
        "INSERT INTO upload_session
            (entity_logicalname, record_id, field_logicalname, owner_user_ref,
             quarantine_key, final_key, declared_filename, declared_content_type,
             declared_max_size_bytes, status)
         VALUES ($1, $2, 'attachment', $3, $4, $4, 'mirror-test.txt', 'text/plain', 1024, 'clean')",
    )
    .bind(&logicalname)
    .bind(record_id)
    .bind(user_id)
    .bind(&final_key)
    .execute(&db)
    .await
    .expect("seed a clean upload session directly (throwaway test DB)");

    let body = bulk_body(
        "update",
        None,
        vec![json!({
            "id": record_id_str, "expected_row_version": 0,
            "data": { "attachment": final_key }
        })],
    );
    let enqueue_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(enqueue_res.status(), StatusCode::ACCEPTED);
    let bulk_op_id: Uuid = body_json(enqueue_res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    attome_records::bulk::process(
        &state,
        bulk_op_id,
        &logicalname,
        "update",
        Vec::new(),
        user_id,
    )
    .await
    .expect("process must succeed");

    let (op_status, succeeded, failed): (String, i32, i32) = sqlx::query_as(
        "SELECT status, succeeded, failed FROM automation_bulk_operation WHERE id = $1",
    )
    .bind(bulk_op_id)
    .fetch_one(&db)
    .await
    .expect("bulk operation row");
    assert_eq!(op_status, "completed");
    assert_eq!(succeeded, 1);
    assert_eq!(
        failed, 0,
        "the file field must pass lock_file_field_sessions"
    );

    let mirror: Option<(String, String, bool)> = sqlx::query_as(
        "SELECT folder, source_field, is_active FROM attome_document
         WHERE entity_name = $1 AND record_id = $2",
    )
    .bind(&logicalname)
    .bind(&record_id_str)
    .fetch_optional(&db)
    .await
    .expect("query attome_document for mirror");
    let (folder, source_field, is_active) =
        mirror.expect("bulk update of a file field must mirror into attome_document (C-11)");
    assert_eq!(
        folder, "uploads",
        "manual uploads default to the uploads folder"
    );
    assert_eq!(
        source_field, "attachment",
        "mirror must name the field it came from"
    );
    assert!(is_active, "freshly mirrored row must be active");
}

// ── C-13: `AccessLevel` resolved once per batch, not once per row ──────────

/// In-memory sink for `tracing_subscriber::fmt`, same shape as
/// `attome-metadata/tests/provision.rs`'s `CapturedLogs` — copied rather than
/// shared because that type is private to its own crate's test binary.
#[derive(Clone, Default)]
struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("capture buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedLogs {
    fn contents(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture buffer lock").clone())
            .expect("captured tracing output must be valid UTF-8")
    }
}

/// Runs `fut` with a process-default `tracing` subscriber installed for the
/// duration (thread-local, valid here because `#[tokio::test]` defaults to
/// the current-thread runtime — same reasoning `attome-metadata/tests/provision.rs`'s
/// `capture_provisioning_ddl` gives) and returns its output alongside
/// everything logged at DEBUG or above. Used only to count
/// `attome_security::db`'s `resolve_entity_access_level`/`resolve_owner_visible`
/// debug events — no `pg_stat_statements` here for the same reason
/// `provision.rs` gives: the plain `postgres:18` image this repo's CI uses
/// doesn't set `shared_preload_libraries`, so `CREATE EXTENSION
/// pg_stat_statements` fails outright.
async fn capture_debug_logs<Fut, T>(fut: Fut) -> (T, String)
where
    Fut: std::future::Future<Output = T>,
{
    let captured = CapturedLogs::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .finish();
    let result = {
        let _guard = tracing::subscriber::set_default(subscriber);
        fut.await
    };
    (result, captured.contents())
}

/// C-13's proof: `apply_ledgered_item`'s per-row `require_record_access` used
/// to call `resolve_entity_access_level`/`resolve_owner_visible`
/// (`attome-security`'s two access-level round trips) once per item — a
/// 1,000-row bulk update paid ~2,000 identical queries for a single
/// `(entity, action)` pair that never changes across one batch (`operation`
/// is `process_ledger`'s own parameter, not per-item). `bulk::process_ledger`
/// now resolves both once before the per-item loop
/// (`resolve_batch_record_access`) and threads the result into
/// `entity_crud::require_record_access_with`, so the count must stay flat
/// regardless of batch size — asserted here at 100 rows, well under the
/// plan's own 1,000-row example.
#[tokio::test]
async fn bulk_update_resolves_access_level_once_per_batch_not_per_row() {
    let system = skip_if_no_db!(test_system().await);
    let (user_id, _, admin_cookie) = seed_user(&system, true).await;
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);
    let (logicalname, _) = provision_entity(&app, &admin_cookie, "acclevel", false).await;

    const N: usize = 100;
    let create_records: Vec<Value> = (0..N)
        .map(|i| json!({ "data": { "title": format!("row-{i}") } }))
        .collect();
    let create_enqueue_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&bulk_body("create", None, create_records)),
        ))
        .await
        .unwrap();
    assert_eq!(create_enqueue_res.status(), StatusCode::ACCEPTED);
    let create_op_id: Uuid = body_json(create_enqueue_res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    attome_records::bulk::process(
        &state,
        create_op_id,
        &logicalname,
        "create",
        Vec::new(),
        user_id,
    )
    .await
    .expect("create batch must succeed");
    assert_eq!(row_count(&db, &logicalname).await, N as i64);

    let record_ids: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {} ORDER BY created_at",
        attome_core::quote_ident(&logicalname)
    ))
    .fetch_all(&db)
    .await
    .expect("record ids");
    assert_eq!(record_ids.len(), N);

    let update_records: Vec<Value> = record_ids
        .iter()
        .map(|id| json!({ "id": id, "expected_row_version": 0, "data": { "title": "updated" } }))
        .collect();
    let update_enqueue_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}/bulk"),
            &admin_cookie,
            Some(&bulk_body("update", None, update_records)),
        ))
        .await
        .unwrap();
    assert_eq!(update_enqueue_res.status(), StatusCode::ACCEPTED);
    let update_op_id: Uuid = body_json(update_enqueue_res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let (result, captured) = capture_debug_logs(attome_records::bulk::process(
        &state,
        update_op_id,
        &logicalname,
        "update",
        Vec::new(),
        user_id,
    ))
    .await;
    result.expect("update batch must succeed");

    let (op_status, succeeded, failed): (String, i32, i32) = sqlx::query_as(
        "SELECT status, succeeded, failed FROM automation_bulk_operation WHERE id = $1",
    )
    .bind(update_op_id)
    .fetch_one(&db)
    .await
    .expect("bulk operation row");
    assert_eq!(op_status, "completed");
    assert_eq!(succeeded, N as i32);
    assert_eq!(failed, 0);

    let access_level_calls = captured
        .matches("attome-security: resolving entity access level")
        .count();
    let owner_visible_calls = captured
        .matches("attome-security: resolving owner visibility")
        .count();
    assert!(
        access_level_calls + owner_visible_calls <= 3,
        "a {N}-row bulk update issued {access_level_calls} access-level + \
         {owner_visible_calls} owner-visibility resolutions; expected the \
         batch to resolve both once and reuse them for every row"
    );
}

/// Audit plan item 3.10 / D-541 rule 5 (C13/I13): `BulkAccepted`/
/// `BulkCompleted` parent events. `use super::*` reuses this file's own
/// harness (`test_system`, `full_app`, `provision_entity`, `bulk_body`,
/// `req`, `body_json`) rather than duplicating it.
///
/// Not covered: a "cancelled mid-way" outcome — `automation_bulk_operation`
/// has no cancellation mechanism today (no code path ever sets
/// `status = 'cancelled'`), so `AuditOutcome::Cancelled` has no real driver to
/// test against. Recorded here, not invented — plan execution rule 9 (a
/// cancellation feature is out of this phase's scope).
mod bulk_parent_events {
    use super::*;

    async fn header_row(
        db: &attome_db::DbPool,
        batch_id: Uuid,
        operation: attome_audit::AuditOperation,
    ) -> Option<(Option<i32>, Option<i32>, Option<i32>, Option<i16>)> {
        sqlx::query_as(
            "SELECT requested_count, affected_count, failed_count, outcome
             FROM audit_header WHERE batch_id = $1 AND operation = $2",
        )
        .bind(batch_id)
        .bind(operation as i32)
        .fetch_optional(db)
        .await
        .expect("query audit_header")
    }

    async fn header_count(
        db: &attome_db::DbPool,
        batch_id: Uuid,
        operation: attome_audit::AuditOperation,
    ) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_header WHERE batch_id = $1 AND operation = $2",
        )
        .bind(batch_id)
        .bind(operation as i32)
        .fetch_one(db)
        .await
        .expect("count audit_header rows")
    }

    async fn drain(db: &attome_db::DbPool, state: &EngineState) {
        attome_audit::chainer::run_once(db, state.audit_signer.as_deref(), 1000, None)
            .await
            .expect("drain the audit ingest queue");
    }

    /// Outcomes: all succeed (`Succeeded`), k of N fail (`PartiallyFailed`,
    /// `affected_count = N-k`), all fail (`Failed`), and the early-bail
    /// "whole batch never started" shape (`mark_batch_failed`, an unknown
    /// operation) — plan item 3.10's "all-or-nothing" case, since this
    /// worker-model has no in-flight transaction to roll back, only a
    /// before-any-item-ran bail.
    #[tokio::test]
    async fn accepted_and_completed() {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, _, admin_cookie) = seed_user(&system, true).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (logicalname, _) = provision_entity(&app, &admin_cookie, "bulkparentacc", false).await;

        // ── all succeed ──────────────────────────────────────────────────
        let body = bulk_body(
            "create",
            None,
            vec![
                json!({ "data": { "title": "a" } }),
                json!({ "data": { "title": "b" } }),
            ],
        );
        let enqueue_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/bulk"),
                &admin_cookie,
                Some(&body),
            ))
            .await
            .unwrap();
        assert_eq!(enqueue_res.status(), StatusCode::ACCEPTED);
        let batch_id: Uuid = body_json(enqueue_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        drain(&db, &state).await;
        let (requested, affected, failed, outcome) =
            header_row(&db, batch_id, attome_audit::AuditOperation::BulkAccepted)
                .await
                .expect("BulkAccepted must be written in the enqueue transaction");
        assert_eq!(requested, Some(2));
        assert_eq!(affected, None);
        assert_eq!(failed, None);
        assert_eq!(outcome, None);
        assert_eq!(
            header_count(&db, batch_id, attome_audit::AuditOperation::BulkCompleted).await,
            0,
            "BulkCompleted must not exist before the operation runs"
        );

        attome_records::bulk::process(
            &state,
            batch_id,
            &logicalname,
            "create",
            Vec::new(),
            user_id,
        )
        .await
        .expect("process");

        drain(&db, &state).await;
        let (requested, affected, failed, outcome) =
            header_row(&db, batch_id, attome_audit::AuditOperation::BulkCompleted)
                .await
                .expect("BulkCompleted must be written when the operation completes");
        assert_eq!(requested, None);
        assert_eq!(affected, Some(2));
        assert_eq!(failed, Some(0));
        assert_eq!(outcome, Some(attome_audit::AuditOutcome::Succeeded as i16));

        // ── k of N fail (partial) ────────────────────────────────────────
        let mut record_ids = Vec::new();
        for title in ["r1", "r2", "r3"] {
            let res = app
                .clone()
                .oneshot(req(
                    "POST",
                    &format!("/api/v1/{logicalname}"),
                    &admin_cookie,
                    Some(&json!({ "title": title })),
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::CREATED);
            record_ids.push(body_json(res).await["id"].as_str().unwrap().to_owned());
        }
        let body = bulk_body(
            "update",
            None,
            vec![
                json!({ "id": record_ids[0], "expected_row_version": 0, "data": { "title": "u1" } }),
                json!({ "id": record_ids[1], "expected_row_version": 99, "data": { "title": "u2" } }),
                json!({ "id": record_ids[2], "expected_row_version": 0, "data": { "title": "u3" } }),
            ],
        );
        let enqueue_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/bulk"),
                &admin_cookie,
                Some(&body),
            ))
            .await
            .unwrap();
        let partial_batch_id: Uuid = body_json(enqueue_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        attome_records::bulk::process(
            &state,
            partial_batch_id,
            &logicalname,
            "update",
            Vec::new(),
            user_id,
        )
        .await
        .expect("process");
        drain(&db, &state).await;
        let (_, affected, failed, outcome) = header_row(
            &db,
            partial_batch_id,
            attome_audit::AuditOperation::BulkCompleted,
        )
        .await
        .expect("BulkCompleted for the partial-failure batch");
        assert_eq!(affected, Some(2), "N-k = 3-1 succeeded");
        assert_eq!(failed, Some(1));
        assert_eq!(
            outcome,
            Some(attome_audit::AuditOutcome::PartiallyFailed as i16)
        );

        // ── all fail ─────────────────────────────────────────────────────
        let body = bulk_body(
            "update",
            None,
            vec![
                json!({ "id": record_ids[0], "expected_row_version": 99, "data": { "title": "x" } }),
                json!({ "id": record_ids[1], "expected_row_version": 99, "data": { "title": "y" } }),
            ],
        );
        let enqueue_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/bulk"),
                &admin_cookie,
                Some(&body),
            ))
            .await
            .unwrap();
        let allfail_batch_id: Uuid = body_json(enqueue_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        attome_records::bulk::process(
            &state,
            allfail_batch_id,
            &logicalname,
            "update",
            Vec::new(),
            user_id,
        )
        .await
        .expect("process");
        drain(&db, &state).await;
        let (_, affected, failed, outcome) = header_row(
            &db,
            allfail_batch_id,
            attome_audit::AuditOperation::BulkCompleted,
        )
        .await
        .expect("BulkCompleted for the all-fail batch");
        assert_eq!(affected, Some(0));
        assert_eq!(failed, Some(2));
        assert_eq!(outcome, Some(attome_audit::AuditOutcome::Failed as i16));

        // ── early bail: mark_batch_failed (unknown operation) ───────────
        // Never reachable through the HTTP route (validated there first) —
        // calling the worker entry point directly, as a metadata-drift race
        // would, is the only way to exercise this branch.
        let early_bail_batch_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO automation_bulk_operation
                (id, entity_logicalname, operation, status, total, created_by, batch_mode)
             VALUES ($1, $2, 'update', 'pending', 1, $3, 'partial')",
        )
        .bind(early_bail_batch_id)
        .bind(&logicalname)
        .bind(user_id)
        .execute(&db)
        .await
        .expect("seed an early-bail bulk operation row");
        attome_records::bulk::process(
            &state,
            early_bail_batch_id,
            &logicalname,
            "not_a_real_operation",
            Vec::new(),
            user_id,
        )
        .await
        .expect("process must not itself error on an unknown operation");
        let status: String =
            sqlx::query_scalar("SELECT status FROM automation_bulk_operation WHERE id = $1")
                .bind(early_bail_batch_id)
                .fetch_one(&db)
                .await
                .expect("early-bail operation row");
        assert_eq!(status, "failed");
        drain(&db, &state).await;
        let (_, affected, failed, outcome) = header_row(
            &db,
            early_bail_batch_id,
            attome_audit::AuditOperation::BulkCompleted,
        )
        .await
        .expect("BulkCompleted for the early-bail batch");
        assert_eq!(affected, Some(0));
        assert_eq!(failed, Some(0));
        assert_eq!(outcome, Some(attome_audit::AuditOutcome::Failed as i16));
        assert_eq!(
            header_count(
                &db,
                early_bail_batch_id,
                attome_audit::AuditOperation::Update
            )
            .await,
            0,
            "the early-bail path must never write a per-record event"
        );
    }

    /// I13: a completed parent's `affected_count` equals the number of
    /// per-record events sharing its `batch_id`.
    #[tokio::test]
    async fn count_invariant() {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, _, admin_cookie) = seed_user(&system, true).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (logicalname, _) = provision_entity(&app, &admin_cookie, "bulkparentcnt", false).await;

        let body = bulk_body(
            "create",
            None,
            vec![
                json!({ "data": { "title": "a" } }),
                json!({ "data": { "title": "b" } }),
                json!({ "data": { "title": "c" } }),
            ],
        );
        let enqueue_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/bulk"),
                &admin_cookie,
                Some(&body),
            ))
            .await
            .unwrap();
        let batch_id: Uuid = body_json(enqueue_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        attome_records::bulk::process(
            &state,
            batch_id,
            &logicalname,
            "create",
            Vec::new(),
            user_id,
        )
        .await
        .expect("process");

        drain(&db, &state).await;
        let (_, affected, _, _) =
            header_row(&db, batch_id, attome_audit::AuditOperation::BulkCompleted)
                .await
                .expect("BulkCompleted");
        assert_eq!(affected, Some(3));
        let per_record_header =
            header_count(&db, batch_id, attome_audit::AuditOperation::Create).await;
        assert_eq!(
            affected,
            Some(per_record_header as i32),
            "still true once ingest has drained into audit_header"
        );
    }

    /// A crash-and-resume (here: calling `process` a second time against a
    /// batch that has already reached its terminal state) writes exactly
    /// one `BulkCompleted` — the advisory-lock-plus-existence-check guard
    /// makes the second terminal-state write a no-op.
    #[tokio::test]
    async fn retry_writes_one_completion() {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, _, admin_cookie) = seed_user(&system, true).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (logicalname, _) =
            provision_entity(&app, &admin_cookie, "bulkparentretry", false).await;

        let body = bulk_body("create", None, vec![json!({ "data": { "title": "a" } })]);
        let enqueue_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/bulk"),
                &admin_cookie,
                Some(&body),
            ))
            .await
            .unwrap();
        let batch_id: Uuid = body_json(enqueue_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        attome_records::bulk::process(
            &state,
            batch_id,
            &logicalname,
            "create",
            Vec::new(),
            user_id,
        )
        .await
        .expect("first process (completes the operation)");
        drain(&db, &state).await;
        assert_eq!(
            header_count(&db, batch_id, attome_audit::AuditOperation::BulkCompleted).await,
            1
        );

        // Second call: every item already `succeeded`, so the worker loop
        // does nothing and falls straight through to the same terminal-state
        // write — exactly the shape a redelivered/resumed job takes.
        attome_records::bulk::process(
            &state,
            batch_id,
            &logicalname,
            "create",
            Vec::new(),
            user_id,
        )
        .await
        .expect("retried process must not error");
        drain(&db, &state).await;
        assert_eq!(
            header_count(&db, batch_id, attome_audit::AuditOperation::BulkCompleted).await,
            1,
            "a retried terminal-state write must not write a second BulkCompleted"
        );
    }

    /// An operation that is accepted but never processed stays open: an
    /// accepted event exists, no completed event does, and the operation's
    /// own status is never a terminal one — never silently treated as
    /// complete.
    #[tokio::test]
    async fn unresumed_reports_open() {
        let system = skip_if_no_db!(test_system().await);
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let (logicalname, _) = provision_entity(&app, &admin_cookie, "bulkparentopen", false).await;

        let body = bulk_body("create", None, vec![json!({ "data": { "title": "a" } })]);
        let enqueue_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/bulk"),
                &admin_cookie,
                Some(&body),
            ))
            .await
            .unwrap();
        let batch_id: Uuid = body_json(enqueue_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        // Deliberately never call `bulk::process` — this operation is never
        // resumed.
        drain(&db, &state).await;
        header_row(&db, batch_id, attome_audit::AuditOperation::BulkAccepted)
            .await
            .expect("BulkAccepted must exist");
        assert_eq!(
            header_count(&db, batch_id, attome_audit::AuditOperation::BulkCompleted).await,
            0,
            "an unresumed operation must never have a BulkCompleted event"
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM automation_bulk_operation WHERE id = $1")
                .bind(batch_id)
                .fetch_one(&db)
                .await
                .expect("operation row");
        assert_ne!(
            status, "completed",
            "an unresumed operation's status must never read as a terminal/complete state"
        );
    }
}

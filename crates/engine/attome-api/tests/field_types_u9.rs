//! Basic-units U9 (D-604, D-605) — the three new field types end to end
//! against a live, seeded database:
//!
//! - **formula** (code 16, B-R6): provisioned as a native column of its
//!   `result_type`; an invalid expression, a missing/ill-typed option, a
//!   `required` formula and a formula reading another formula are all 422 at
//!   field save; the value is computed on create and recomputed on every
//!   update; a client write to it is 422 on create and update; a writer who
//!   cannot set one of its inputs (a D-507 write-restricted field) still
//!   gets it recomputed; it filters (export filter) and exports as its value;
//! - **rich_text** (code 17, B-R7): XSS payloads are stripped on create,
//!   update and bulk create, the stored row itself is clean, the search
//!   corpus indexes its text content without markup, and the export carries
//!   the sanitized value;
//! - **image** (code 18): a `file` column; an upload session declaring a
//!   non-image content type is 422, an image one is accepted, and a plain
//!   `file` field on the same entity still accepts a PDF;
//! - **bundle**: one bundle declaring all three types (formula listed
//!   *before* its inputs), an address field group and a child entity
//!   (forms are code since D-790) plans without a block and applies to this fresh
//!   deployment; a record written through the applied entity computes its
//!   formula.
//!
//! Harness copied from `data_management.rs` (the convention every suite in
//! this crate follows). Requires Postgres (`DATABASE_URL`, cloned per binary)
//! and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`). The export steps also
//! need an object store: `TEST_S3_ENDPOINT`/`TEST_S3_ACCESS_KEY`/
//! `TEST_S3_SECRET_KEY`/`TEST_S3_BUCKET` override the `localhost:9000`
//! `test`/`test`/`attome-test` defaults.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test field_types_u9 -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::{
    EntityDef, PlanOptions, PlanStatus, canonical_json, export_bundle, ledger, plan_bundle,
    run_apply_job,
};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness (copied from data_management.rs) ────────────────────────────────

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

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
                "s3_endpoint": "{s3_endpoint}", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "{s3_access_key}", "s3_secret_key": "{s3_secret_key}",
                "s3_bucket": "{s3_bucket}", "s3_use_path_style": true, "s3_verify_ssl": false
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
        redis_host = env_or("TEST_REDIS_HOST", "localhost"),
        redis_port = env_or("TEST_REDIS_PORT", "6379"),
        s3_endpoint = env_or("TEST_S3_ENDPOINT", "http://localhost:9000"),
        s3_access_key = env_or("TEST_S3_ACCESS_KEY", "test"),
        s3_secret_key = env_or("TEST_S3_SECRET_KEY", "test"),
        s3_bucket = env_or("TEST_S3_BUCKET", "attome-test"),
        jwt_secret = THROWAWAY_JWT_SECRET,
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let config = test_config(&DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse"));
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

async fn seed_user(db: &attome_db::DbPool, admin: bool) -> (Uuid, String, String) {
    let user_id = Uuid::now_v7();
    let email = format!("u9-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("u9-test-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    if admin {
        let privilege_id: Uuid =
            sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
                .fetch_one(db)
                .await
                .expect("system.admin privilege must already be seeded");
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

async fn grant_privilege(app: &axum::Router, admin_cookie: &str, email: &str, key: &str) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/security/grants",
            admin_cookie,
            Some(&json!({ "user_email": email, "privilege_key": key })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "grant {key} to {email}");
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
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
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(req(method, uri, cookie, body))
        .await
        .unwrap();
    let status = res.status();
    (status, body_json(res).await)
}

async fn patch(
    app: &axum::Router,
    uri: &str,
    cookie: &str,
    row_version: i64,
    body: &Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(body.to_string()))
        .unwrap();
    let res = app.clone().oneshot(request).await.unwrap();
    let status = res.status();
    (status, body_json(res).await)
}

async fn create_entity(app: &axum::Router, cookie: &str, prefix: &str) -> (String, Uuid) {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let (status, entity) = send(
        app,
        "POST",
        "/api/v1/admin/entities",
        cookie,
        Some(&json!({ "logicalname": logicalname, "name": "U9 Field Types" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create entity: {entity}");
    (logicalname, entity["id"].as_str().unwrap().parse().unwrap())
}

async fn create_field(
    app: &axum::Router,
    cookie: &str,
    entity_id: Uuid,
    body: Value,
) -> (StatusCode, Value) {
    send(
        app,
        "POST",
        &format!("/api/v1/admin/entities/{entity_id}/fields"),
        cookie,
        Some(&body),
    )
    .await
}

async fn sync_registry(state: &EngineState) {
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build_registry");
    state.entities.swap(registry);
}

async fn column_type(db: &attome_db::DbPool, table: &str, column: &str) -> String {
    sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(db)
    .await
    .unwrap_or_else(|e| panic!("{table}.{column} has no physical column: {e}"))
}

/// Runs an export job inline (no worker) and returns the exported JSON text.
async fn export_json(
    state: &EngineState,
    app: &axum::Router,
    cookie: &str,
    user_id: Uuid,
    logicalname: &str,
    filters: Vec<Value>,
) -> String {
    let (status, enqueued) = send(
        app,
        "POST",
        &format!("/api/v1/{logicalname}/export"),
        cookie,
        Some(&json!({ "format": "json", "columns": [], "filter": filters })),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "enqueue export: {enqueued}");
    let export_id: Uuid = enqueued["id"].as_str().unwrap().parse().unwrap();
    attome_api::data_export::process(
        state,
        attome_jobs::DataExportPayload {
            export_id,
            entity_logicalname: logicalname.to_owned(),
            format: "json".to_string(),
            columns: vec![],
            filters,
            user_id,
        },
    )
    .await
    .expect("run export job");
    let row: (String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT status, object_key, error FROM data_export WHERE id = $1")
            .bind(export_id)
            .fetch_one(&state.base.db)
            .await
            .expect("export row");
    assert_eq!(
        row.0, "completed",
        "export did not complete (object store configured? TEST_S3_*): {:?}",
        row.2
    );
    let path = ObjectPath::parse(row.1.expect("object_key")).expect("valid object key");
    let bytes = state
        .base
        .storage
        .store()
        .get(&path)
        .await
        .expect("download exported object")
        .bytes()
        .await
        .expect("read exported object body");
    String::from_utf8(bytes.to_vec()).expect("export is UTF-8")
}

// ── formula (B-R6, D-604) ───────────────────────────────────────────────────

#[test]
fn formula_field_is_compiled_at_save_computed_on_write_and_never_client_written() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (admin_id, _admin_email, admin_cookie) = seed_user(&db, true).await;
        let app = full_app(system);

        let (entity, entity_id) = create_entity(&app, &admin_cookie, "u9_formula").await;
        for field in [
            json!({"logicalname": "quantity", "name": "Quantity", "field_type": "number"}),
            json!({"logicalname": "unit_price", "name": "Unit price", "field_type": "currency"}),
            // D-507: readable by everyone, writable only with a field grant — the
            // input a non-admin writer below cannot set.
            json!({"logicalname": "rate", "name": "Rate", "field_type": "number",
               "is_write_restricted": true}),
            json!({"logicalname": "label", "name": "Label", "field_type": "text"}),
        ] {
            let (status, body) = create_field(&app, &admin_cookie, entity_id, field).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }

        // ── invalid formulas are 422 at save, before the field exists ─────────
        for (why, body) in [
            (
                "unknown field",
                json!({"logicalname": "bad1", "name": "Bad", "field_type": "formula",
                   "options": {"expression": "nope * 2", "result_type": "number"}}),
            ),
            (
                "type mismatch",
                json!({"logicalname": "bad2", "name": "Bad", "field_type": "formula",
                   "options": {"expression": "quantity * 2", "result_type": "date"}}),
            ),
            (
                "syntax error",
                json!({"logicalname": "bad3", "name": "Bad", "field_type": "formula",
                   "options": {"expression": "quantity * ", "result_type": "number"}}),
            ),
            (
                "missing options",
                json!({"logicalname": "bad4", "name": "Bad", "field_type": "formula"}),
            ),
            (
                "bad result_type",
                json!({"logicalname": "bad5", "name": "Bad", "field_type": "formula",
                   "options": {"expression": "quantity", "result_type": "lookup"}}),
            ),
            (
                "required formula",
                json!({"logicalname": "bad6", "name": "Bad", "field_type": "formula",
                   "is_required": true,
                   "options": {"expression": "quantity", "result_type": "number"}}),
            ),
        ] {
            let (status, err) = create_field(&app, &admin_cookie, entity_id, body).await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{why} must be refused: {err}"
            );
        }
        let stranded: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM attribute_info WHERE entity_ref = $1 AND logicalname LIKE 'bad%'",
        )
        .bind(entity_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(stranded, 0, "a refused formula must leave no attribute row");

        // ── valid formulas: a native column of the result type ────────────────
        let (status, body) = create_field(
            &app,
            &admin_cookie,
            entity_id,
            json!({"logicalname": "total", "name": "Total", "field_type": "formula",
               "is_filterable": true,
               "options": {"expression": "quantity * unit_price * (1 - rate)",
                           "result_type": "number"}}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["field_type"], "formula");
        let (status, body) = create_field(
            &app,
            &admin_cookie,
            entity_id,
            json!({"logicalname": "shout", "name": "Shout", "field_type": "formula",
               "options": {"expression": "upper(label)", "result_type": "text"}}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(column_type(&db, &entity, "total").await, "numeric");
        assert_eq!(column_type(&db, &entity, "shout").await, "text");
        let stored_type: i32 = sqlx::query_scalar(
            "SELECT \"type\" FROM attribute_info WHERE entity_ref = $1 AND logicalname = 'total'",
        )
        .bind(entity_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(stored_type, 16, "formula is field type code 16");

        // A formula may not read another formula.
        let (status, err) = create_field(
            &app,
            &admin_cookie,
            entity_id,
            json!({"logicalname": "bad7", "name": "Bad", "field_type": "formula",
               "options": {"expression": "total * 2", "result_type": "number"}}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
        sync_registry(&state).await;

        // ── create computes; a client-written formula value is refused ────────
        let (status, err) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}"),
            &admin_cookie,
            Some(&json!({"quantity": 2, "unit_price": 10, "rate": 0.5, "total": 999})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
        assert!(
            err.to_string().contains("formula"),
            "the refusal must name the formula: {err}"
        );

        let (status, created) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}"),
            &admin_cookie,
            Some(&json!({"quantity": 2, "unit_price": 10, "rate": 0.5, "label": "abc"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_owned();
        assert_eq!(created["data"]["total"].as_f64(), Some(10.0), "{created}");
        assert_eq!(created["data"]["shout"], "ABC", "{created}");
        let stored: Option<f64> = sqlx::query_scalar(&format!(
            "SELECT total::float8 FROM \"{entity}\" WHERE id = $1"
        ))
        .bind(Uuid::parse_str(&id).unwrap())
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(stored, Some(10.0), "the computed value is stored");

        // ── update recomputes; a client-written formula value is refused ──────
        let rv = created["row_version"].as_i64().unwrap();
        let (status, err) = patch(
            &app,
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            rv,
            &json!({"total": 1}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{err}");
        let (status, updated) = patch(
            &app,
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            rv,
            &json!({"quantity": 4}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(updated["data"]["total"].as_f64(), Some(20.0), "{updated}");

        // ── a writer who cannot set an input still gets the recompute ─────────
        let (_uid, email, user_cookie) = seed_user(&db, false).await;
        for action in ["read", "update"] {
            grant_privilege(&app, &admin_cookie, &email, &format!("{entity}.{action}")).await;
        }
        let rv = updated["row_version"].as_i64().unwrap();
        let (status, err) = patch(
            &app,
            &format!("/api/v1/{entity}/{id}"),
            &user_cookie,
            rv,
            &json!({"rate": 0}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the writer cannot set `rate` (D-507): {err}"
        );
        let (status, by_user) = patch(
            &app,
            &format!("/api/v1/{entity}/{id}"),
            &user_cookie,
            rv,
            &json!({"quantity": 6}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{by_user}");
        assert_eq!(
            by_user["data"]["total"].as_f64(),
            Some(30.0),
            "6 * 10 * (1 - 0.5): the stored `rate` the writer cannot set still feeds the recompute: {by_user}"
        );

        // ── read, filter and export ───────────────────────────────────────────
        let (status, fetched) = send(
            &app,
            "GET",
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(fetched["data"]["total"].as_f64(), Some(30.0));
        let (status, other) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}"),
            &admin_cookie,
            Some(&json!({"quantity": 1, "unit_price": 1, "rate": 0})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{other}");
        assert!(
            other["data"]["shout"].is_null(),
            "a formula over a blank input is blank, not a blocked write: {other}"
        );

        let exported = export_json(
            &state,
            &app,
            &admin_cookie,
            admin_id,
            &entity,
            vec![json!({"field": "total", "op": "gt", "value": "25"})],
        )
        .await;
        assert!(
            exported.contains(&id),
            "the filtered export has the 30 row: {exported}"
        );
        assert!(
            !exported.contains(other["id"].as_str().unwrap()),
            "`total gt 25` filters as a number and drops the 1 row: {exported}"
        );
        assert!(exported.contains("\"total\":30"), "{exported}");
    })
}

// ── rich_text (B-R7, D-605) ─────────────────────────────────────────────────

const XSS: &str = r#"<p onclick="steal()">Hello <strong>team</strong></p><script>alert(document.cookie)</script><img src=x onerror="alert(1)"><iframe src="https://evil.example"></iframe><a href="javascript:alert(1)">click</a><a href="https://ok.example">ok</a><style>body{display:none}</style>"#;

fn assert_clean(html: &str) {
    for needle in [
        "<script",
        "alert",
        "onclick",
        "onerror",
        "<img",
        "<iframe",
        "javascript:",
        "<style",
        "display:none",
    ] {
        assert!(
            !html.to_lowercase().contains(needle),
            "`{needle}` survived sanitizing: {html}"
        );
    }
    assert!(html.contains("<strong>team</strong>"), "{html}");
    assert!(html.contains(r#"href="https://ok.example""#), "{html}");
}

#[test]
fn rich_text_is_sanitized_on_create_update_and_bulk_and_indexed_as_text() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (admin_id, _email, admin_cookie) = seed_user(&db, true).await;
        let app = full_app(system);

        let (entity, entity_id) = create_entity(&app, &admin_cookie, "u9_rich").await;
        for field in [
            json!({"logicalname": "title", "name": "Title", "field_type": "text"}),
            json!({"logicalname": "body", "name": "Body", "field_type": "rich_text"}),
        ] {
            let (status, body) = create_field(&app, &admin_cookie, entity_id, field).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        assert_eq!(column_type(&db, &entity, "body").await, "text");
        sync_registry(&state).await;

        let stored_body = |id: String| {
            let db = db.clone();
            let entity = entity.clone();
            async move {
                sqlx::query_scalar::<_, Option<String>>(&format!(
                    "SELECT body FROM \"{entity}\" WHERE id = $1"
                ))
                .bind(Uuid::parse_str(&id).unwrap())
                .fetch_one(&db)
                .await
                .unwrap()
                .unwrap_or_default()
            }
        };

        // create
        let (status, created) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}"),
            &admin_cookie,
            Some(&json!({"title": "created", "body": XSS})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_owned();
        assert_clean(created["data"]["body"].as_str().unwrap());
        assert_clean(&stored_body(id.clone()).await);

        // update
        let rv = created["row_version"].as_i64().unwrap();
        let payload = format!("<p>updated</p>{XSS}");
        let (status, updated) = patch(
            &app,
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            rv,
            &json!({"body": payload}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        let after_update = stored_body(id.clone()).await;
        assert_clean(&after_update);
        assert!(after_update.starts_with("<p>updated</p>"), "{after_update}");

        // bulk create (the worker side driven inline)
        let (status, enqueued) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}/bulk"),
            &admin_cookie,
            Some(&json!({"operation": "create",
                     "records": [{"data": {"title": "bulk", "body": XSS}}]})),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{enqueued}");
        let bulk_op_id: Uuid = enqueued["id"].as_str().unwrap().parse().unwrap();
        attome_records::bulk::process(&state, bulk_op_id, &entity, "create", Vec::new(), admin_id)
            .await
            .expect("bulk process");
        let bulk_id: Uuid = sqlx::query_scalar(
            "SELECT record_id FROM automation_bulk_operation_item \
         WHERE bulk_operation_id = $1 AND status = 'succeeded'",
        )
        .bind(bulk_op_id)
        .fetch_one(&db)
        .await
        .expect("the bulk item succeeded");
        assert_clean(&stored_body(bulk_id.to_string()).await);

        // search corpus: text content, no markup, no script text
        let registry = state.entities.load();
        let (projected, _, _) =
            attome_search::corpus::project_record(&db, &registry, &entity, bulk_id)
                .await
                .expect("project")
                .expect("indexable");
        // Title or body, whichever the rich-text field landed in, is text only.
        let indexed = format!("{} {}", projected.title, projected.body_indexed);
        assert!(
            indexed.contains("team"),
            "the text content is indexed: {indexed}"
        );
        for markup in ["<", "strong", "href", "script", "alert"] {
            assert!(
                !indexed.contains(markup),
                "`{markup}` reached the search corpus: {indexed}"
            );
        }

        // filter + export carry the sanitized value only
        let exported = export_json(
            &state,
            &app,
            &admin_cookie,
            admin_id,
            &entity,
            vec![json!({"field": "title", "op": "eq", "value": "created"})],
        )
        .await;
        assert!(exported.contains(&id), "{exported}");
        assert!(!exported.contains(&bulk_id.to_string()), "{exported}");
        assert!(exported.contains("updated"), "{exported}");
        assert!(!exported.contains("<script"), "{exported}");
    })
}

// ── image (U9, D-144 reused) ────────────────────────────────────────────────

#[test]
fn image_field_is_a_file_column_that_refuses_non_image_upload_sessions() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (_admin_id, _email, admin_cookie) = seed_user(&db, true).await;
        let app = full_app(system);

        let (entity, entity_id) = create_entity(&app, &admin_cookie, "u9_image").await;
        for field in [
            json!({"logicalname": "title", "name": "Title", "field_type": "text"}),
            json!({"logicalname": "photo", "name": "Photo", "field_type": "image"}),
            json!({"logicalname": "attachment", "name": "Attachment", "field_type": "file"}),
        ] {
            let (status, body) = create_field(&app, &admin_cookie, entity_id, field).await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        assert_eq!(column_type(&db, &entity, "photo").await, "text");
        sync_registry(&state).await;

        let (status, created) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}"),
            &admin_cookie,
            Some(&json!({"title": "has a photo"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let id = created["id"].as_str().unwrap().to_owned();

        let session = |field: &str, content_type: &str| {
            json!({"filename": format!("upload-{field}.bin"), "content_type": content_type,
               "declared_size_bytes": 1024})
        };
        for bad in [
            "application/pdf",
            "text/html",
            "image/svg+xml",
            "application/octet-stream",
        ] {
            let (status, err) = send(
                &app,
                "POST",
                &format!("/api/v1/{entity}/{id}/files/photo/upload-session"),
                &admin_cookie,
                Some(&session("photo", bad)),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "an image field must refuse {bad}: {err}"
            );
            assert!(err.to_string().contains("image"), "{err}");
        }
        let sessions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM upload_session WHERE entity_logicalname = $1")
                .bind(&entity)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(sessions, 0, "a refused content type creates no session");

        // An image content type is accepted (the presign is local signing — no
        // object-store round trip), and a plain file field is unaffected.
        let (status, ok) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}/{id}/files/photo/upload-session"),
            &admin_cookie,
            Some(&session("photo", "image/png")),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{ok}");
        let (status, ok) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}/{id}/files/attachment/upload-session"),
            &admin_cookie,
            Some(&session("attachment", "application/pdf")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a file field still takes a PDF: {ok}"
        );

        // A client cannot plant an arbitrary key in an image field either — the
        // same upload-session ownership check a file field has (D-144).
        let rv = created["row_version"].as_i64().unwrap();
        let (status, err) = patch(
            &app,
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            rv,
            &json!({"photo": format!("{entity}/{id}/photo/not-a-session.png")}),
        )
        .await;
        assert!(
            status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::FORBIDDEN,
            "an unowned key must be refused: {status} {err}"
        );
    })
}

// ── bundle: every U9 type applies to a fresh deployment ─────────────────────

#[test]
fn a_bundle_using_every_u9_type_applies_to_a_fresh_deployment() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let db = state.base.db.clone();
        let (_admin_id, _email, admin_cookie) = seed_user(&db, true).await;

        let entity = attome_testkit::unique_logicalname("u9bndl");
        let child = attome_testkit::unique_logicalname("u9bndlc");
        let attr = |name: &str, field_type: &str, extra: Value| {
            let mut v =
                json!({"logicalname": name, "display_name": name, "field_type": field_type});
            if let (Value::Object(base), Value::Object(more)) = (&mut v, extra) {
                base.extend(more);
            }
            v
        };
        // The formula is listed FIRST, before its inputs: apply orders formula
        // fields after every other field (reconcile compiles against live ones).
        let parent: EntityDef = serde_json::from_value(json!({
            "logicalname": entity,
            "display_name": "U9 Bundle",
            "primary_name_attribute": "name",
            "attributes": [
                attr("line_total", "formula", json!({"options":
                    {"expression": "quantity * unit_price", "result_type": "currency"}})),
                attr("name", "text", json!({})),
                attr("quantity", "number", json!({})),
                attr("unit_price", "currency", json!({})),
                attr("notes", "rich_text", json!({})),
                attr("photo", "image", json!({})),
                // The address field-group convention: `{group}_street` ... .
                attr("billing_street", "text", json!({})),
                attr("billing_city", "text", json!({})),
                attr("billing_region", "text", json!({})),
                attr("billing_postal_code", "text", json!({})),
                attr("billing_country", "text", json!({})),
                attr("billing_latitude", "number", json!({})),
                attr("billing_longitude", "number", json!({})),
            ],
        }))
        .expect("entity def");
        let child_def: EntityDef = serde_json::from_value(json!({
            "logicalname": child,
            "display_name": "U9 Bundle Child",
            "attributes": [
                attr("amount", "number", json!({})),
                attr("parent_ref", "lookup", json!({"lookup_entity": entity})),
            ],
        }))
        .expect("child def");

        let mut bundle = export_bundle(&db).await.expect("export live");
        bundle.entities.push(parent);
        bundle.entities.push(child_def);
        bundle.normalize();

        let license = state.license.load_full();
        let plan = plan_bundle(&db, &license, &bundle, PlanOptions::default())
            .await
            .expect("plan_bundle");
        assert!(plan.blocked.is_empty(), "blocked: {:#?}", plan.blocked);
        let bundle_json: Value = serde_json::from_slice(&canonical_json(&bundle)).unwrap();
        let plan_id = ledger::insert_plan(
            &db,
            &bundle_json,
            &serde_json::to_value(&plan).unwrap(),
            &plan.bundle_hash,
            &plan.basis_hash,
            attome_api::bundle::BUNDLE_FORMAT,
            attome_api::bundle::PLATFORM_VERSION,
            false,
            None,
        )
        .await
        .expect("insert_plan");
        assert!(
            ledger::mark_queued(&db, plan_id, None)
                .await
                .expect("mark_queued")
        );
        run_apply_job(&state, plan_id).await.expect("run_apply_job");
        let row = ledger::get_plan(&db, plan_id)
            .await
            .expect("get_plan")
            .expect("plan row");
        assert_eq!(row.status, PlanStatus::Succeeded, "{row:#?}");

        let types: Vec<(String, i32)> = sqlx::query_as(
            "SELECT a.logicalname, a.\"type\" FROM attribute_info a \
         JOIN entity_info e ON e.id = a.entity_ref \
         WHERE e.logicalname = $1 AND a.logicalname IN ('line_total', 'notes', 'photo') \
         ORDER BY a.logicalname",
        )
        .bind(&entity)
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(
            types,
            vec![
                ("line_total".to_owned(), 16),
                ("notes".to_owned(), 17),
                ("photo".to_owned(), 18)
            ]
        );
        assert_eq!(column_type(&db, &entity, "line_total").await, "numeric");
        assert_eq!(column_type(&db, &entity, "notes").await, "text");
        assert_eq!(column_type(&db, &entity, "photo").await, "text");

        // The applied entity works: the formula computes, the rich text is
        // sanitized.
        sync_registry(&state).await;
        let app = full_app(system);
        let (status, created) = send(
            &app,
            "POST",
            &format!("/api/v1/{entity}"),
            &admin_cookie,
            Some(&json!({"name": "n", "quantity": 3, "unit_price": 2.5,
                     "notes": "<b>ok</b><script>x()</script>",
                     "billing_city": "Riyadh"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(
            created["data"]["line_total"].as_f64(),
            Some(7.5),
            "{created}"
        );
        assert_eq!(created["data"]["notes"], "<b>ok</b>", "{created}");

        // A second plan of the same bundle is a no-op (the exported form of the
        // new types round-trips).
        let mut again = export_bundle(&db).await.expect("export after apply");
        again.normalize();
        let replan = plan_bundle(&db, &license, &bundle, PlanOptions::default())
            .await
            .expect("replan");
        assert!(replan.blocked.is_empty(), "{:#?}", replan.blocked);
        assert!(
            again.entities.iter().any(|e| e.logicalname == entity
                && e.attributes.iter().any(|a| a.field_type == "formula")),
            "export carries the formula field"
        );
    })
}

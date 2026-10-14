//! Solution 7 Phase 1 lane L4 (D-785, `document/general/SOLUTION-7-PHASE-1-DESIGN.md`
//! §1.1 and §4) — the UI-metadata admin routes are hooked into the changeset
//! recorder: system views, sidebar items, apps, calendars (with
//! holidays and exceptions) and rules (with publish).
//!
//! Proves, over HTTP against a real database:
//!
//! 1. **`auto` mode:** every hooked route yields exactly one recorded
//!    operation, of the op the design names, in a closed automatic changeset
//!    of the `project` layer; created rows carry `owner_layer = "project"`.
//! 2. **`required` mode:** a hooked write with no open changeset is a 409
//!    `changeset_required` and writes nothing; with an open changeset (the
//!    caller's own, or named by `X-Attome-Changeset`) it records into it.
//! 3. **Owner layer:** updating, retiring or removing a row another layer owns
//!    is a 409 `layer_mismatch`, changes nothing and records nothing.
//!
//! Needs a test database migrated through 0522 (`changeset*` and the
//! `owner_layer` columns). When the template predates it the tests say so and
//! skip — build a private template (see the `testing` skill; never migrate
//! the shared one).
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test changeset_hooks_ui -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures and inspects state on a raw pool"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_core::changeset::Layer;
use attome_core::changeset::store::{self, NewChangeset};
use attome_db::DbPool;
use attome_server::AppState;
use attome_testkit::{point_config_at, skip_if_no_db};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config(mode: &str) -> AppConfig {
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
            "security": {{ "bootstrap_admin_email": null }},
            "approval": {{ "required_actions": [] }},
            "metadata": {{ "changesets": {{ "mode": "{mode}" }} }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

impl TestSystem {
    fn db(&self) -> DbPool {
        self.state.base.db.clone()
    }
}

async fn build_test_system(mode: &str) -> Option<TestSystem> {
    let url = attome_testkit::migrated_db_url()?;
    let mut config = test_config(mode);
    point_config_at(&mut config, &url);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    let present: bool = sqlx::query_scalar("SELECT to_regclass('changeset_operation') IS NOT NULL")
        .fetch_one(&db)
        .await
        .expect("probe the changeset store");
    if !present {
        eprintln!(
            "the test database predates migration 0521 (no changeset_operation); \
             skipping — build a private template migrated through 0522"
        );
        return None;
    }
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
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    let system = EngineSystem::builder(EngineState::new(base))
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
    let state = system.state().clone();
    let base_state = state.base.clone();
    let app = attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    Some(TestSystem { state, app })
}

static AUTO: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();
static REQUIRED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn auto_system() -> Option<TestSystem> {
    AUTO.get_or_init(|| build_test_system("auto")).await.clone()
}

async fn required_system() -> Option<TestSystem> {
    REQUIRED
        .get_or_init(|| build_test_system("required"))
        .await
        .clone()
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
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// A throwaway `system.admin` user: `(user_id, session_cookie)`.
async fn seed_admin(db: &DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("changeset-hooks-ui-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must be seeded by attome_security::seed");
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

fn suffix() -> String {
    let hex = Uuid::now_v7().simple().to_string();
    hex[hex.len() - 12..].to_owned()
}

/// A throwaway `entity_info` row plus its physical table (see
/// `tests/view_admin.rs::seed_entity` for why the table is load-bearing):
/// `(id, logicalname)`. Enough for views, which resolve the entity
/// against the database; rules need a registered one (`provision_entity`).
async fn seed_entity(db: &DbPool, prefix: &str) -> (Uuid, String) {
    let logicalname = format!("{prefix}_{}", suffix());
    assert!(
        logicalname.len() <= 48
            && logicalname
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
        "fixture entity name must be a short bare identifier, got {logicalname:?}"
    );
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO entity_info (logicalname, name, is_active, owner_layer) \
         VALUES ($1, $2, true, 'project') RETURNING id",
    )
    .bind(&logicalname)
    .bind(&logicalname)
    .fetch_one(db)
    .await
    .expect("insert fixture entity_info");
    // Interpolated: a DDL identifier cannot be bound; the assertion above
    // pins it to a bare identifier built from a literal prefix.
    sqlx::query(&format!(
        "CREATE TABLE IF NOT EXISTS \"{logicalname}\" (id uuid PRIMARY KEY)"
    ))
    .execute(db)
    .await
    .expect("create the fixture entity's table");
    (id, logicalname)
}

async fn seed_query(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query \
         (id, sql_query, table_definition, record_no, is_active, created_at, owner_layer) \
         VALUES ($1, 'SELECT 1', '[]', $2, true, NOW(), 'project')",
    )
    .bind(id)
    .bind(format!("changeset-hooks-ui-query-{id}"))
    .execute(db)
    .await
    .expect("insert fixture sql_query");
    id
}

fn request(
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<Value>,
    changeset: Option<Uuid>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(id) = changeset {
        builder = builder.header("x-attome-changeset", id.to_string());
    }
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("request")
}

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .expect("body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

/// Every operation `actor` has recorded, oldest first:
/// `(op, changeset_ref, seq)`.
async fn ops_by(db: &DbPool, actor: Uuid) -> Vec<(String, Uuid, i32)> {
    sqlx::query_as(
        "SELECT op, changeset_ref, seq FROM changeset_operation \
         WHERE actor_ref = $1 ORDER BY recorded_at, id",
    )
    .bind(actor)
    .fetch_all(db)
    .await
    .expect("read recorded operations")
}

/// Sends `req`, asserts `status`, and asserts it recorded exactly one
/// operation named `op` for `actor`. Returns the response body and the
/// changeset the op went to.
async fn expect_one_op(
    system: &TestSystem,
    actor: Uuid,
    req: Request<Body>,
    status: StatusCode,
    op: &str,
) -> (Value, Uuid) {
    let db = system.db();
    let before = ops_by(&db, actor).await.len();
    let what = format!("{} {}", req.method(), req.uri());
    let (got, body) = send(&system.app, req).await;
    assert_eq!(got, status, "{what}: {body}");
    let ops = ops_by(&db, actor).await;
    assert_eq!(
        ops.len(),
        before + 1,
        "{what} must record exactly one operation, recorded {:?}",
        &ops[before..]
    );
    let (recorded, changeset, _) = ops.last().cloned().expect("one op");
    assert_eq!(recorded, op, "{what} recorded the wrong op");
    (body, changeset)
}

async fn expect_refused(system: &TestSystem, actor: Uuid, req: Request<Body>, code: &str) -> Value {
    let db = system.db();
    let before = ops_by(&db, actor).await.len();
    let what = format!("{} {}", req.method(), req.uri());
    let (status, body) = send(&system.app, req).await;
    assert_eq!(status, StatusCode::CONFLICT, "{what}: {body}");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(code),
        "{what}: expected {code}, got {body}"
    );
    assert_eq!(
        ops_by(&db, actor).await.len(),
        before,
        "{what}: a refused write records nothing"
    );
    body
}

/// An automatic changeset: closed, `auto`, `project` layer.
async fn assert_automatic(db: &DbPool, changeset: Uuid) {
    let (origin, status, layer): (String, String, String) =
        sqlx::query_as("SELECT origin, status, layer FROM changeset WHERE id = $1")
            .bind(changeset)
            .fetch_one(db)
            .await
            .expect("the op's changeset exists");
    assert_eq!(
        (origin.as_str(), status.as_str(), layer.as_str()),
        ("auto", "closed", "project")
    );
}

fn id_of(body: &Value) -> Uuid {
    body["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("response has no id: {body}"))
}

/// Provisions an entity with one number field through the admin API (rules
/// validate against the metadata registry, so a fixture row is not enough).
async fn provision_entity(system: &TestSystem, cookie: &str) -> String {
    let logicalname = format!("l4r_{}", suffix());
    let (status, entity) = send(
        &system.app,
        request(
            "POST",
            "/api/v1/admin/entities",
            cookie,
            Some(json!({ "logicalname": logicalname, "name": "L4 rule test" })),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity create: {entity}");
    let entity_id = id_of(&entity);
    let (status, field) = send(
        &system.app,
        request(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            cookie,
            Some(json!({ "logicalname": "amount", "name": "amount", "field_type": "number" })),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "field create: {field}");
    logicalname
}

// ── 1. auto mode: exactly one op per hooked route ─────────────────────────

#[test]
fn auto_mode_apps_record_one_op_per_write() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(auto_system().await);
        let db = system.db();
        let (actor, cookie) = seed_admin(&db).await;
        let name = format!("l4-app-{}", suffix());

        let (created, changeset) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                "/api/v1/admin/apps",
                &cookie,
                Some(json!({ "name": name })),
                None,
            ),
            StatusCode::CREATED,
            "upsert_app",
        )
        .await;
        assert_eq!(created["owner_layer"], "project");
        assert_automatic(&db, changeset).await;
        let id = id_of(&created);

        expect_one_op(
            &system,
            actor,
            request(
                "PATCH",
                &format!("/api/v1/admin/apps/{id}"),
                &cookie,
                Some(json!({ "name": name, "display_order": 3 })),
                None,
            ),
            StatusCode::OK,
            "upsert_app",
        )
        .await;
        expect_one_op(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/admin/apps/{id}"),
                &cookie,
                None,
                None,
            ),
            StatusCode::NO_CONTENT,
            "retire_app",
        )
        .await;

        // A failed write records nothing: the app is already retired.
        let before = ops_by(&db, actor).await.len();
        let (status, _) = send(
            &system.app,
            request(
                "DELETE",
                &format!("/api/v1/admin/apps/{id}"),
                &cookie,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(ops_by(&db, actor).await.len(), before);
    })
}

#[test]
fn auto_mode_calendars_holidays_and_exceptions_record_one_op_per_write() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(auto_system().await);
        let db = system.db();
        let (actor, cookie) = seed_admin(&db).await;
        let name = format!("L4 calendar {}", suffix());
        let calendar = json!({ "name": name, "tz": "UTC" });

        let (created, changeset) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                "/api/v1/admin/calendars",
                &cookie,
                Some(calendar.clone()),
                None,
            ),
            StatusCode::CREATED,
            "upsert_calendar",
        )
        .await;
        assert_eq!(created["owner_layer"], "project");
        assert_automatic(&db, changeset).await;
        let id = id_of(&created);

        expect_one_op(
            &system,
            actor,
            request(
                "PATCH",
                &format!("/api/v1/admin/calendars/{id}"),
                &cookie,
                Some(json!({ "name": name, "tz": "UTC", "description": "updated" })),
                None,
            ),
            StatusCode::OK,
            "upsert_calendar",
        )
        .await;

        let (holiday, _) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                &format!("/api/v1/admin/calendars/{id}/holidays"),
                &cookie,
                Some(json!({ "name": "National Day", "holiday_date": "2026-12-02" })),
                None,
            ),
            StatusCode::CREATED,
            "add_calendar_holiday",
        )
        .await;
        assert_eq!(holiday["owner_layer"], "project");
        let holiday_id = id_of(&holiday);
        let target: Value = sqlx::query_scalar(
            "SELECT target FROM changeset_operation \
             WHERE actor_ref = $1 AND op = 'add_calendar_holiday'",
        )
        .bind(actor)
        .fetch_one(&db)
        .await
        .expect("holiday op");
        assert_eq!(target, json!({ "calendar": name, "date": "2026-12-02" }));

        expect_one_op(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/admin/calendars/{id}/holidays/{holiday_id}"),
                &cookie,
                None,
                None,
            ),
            StatusCode::NO_CONTENT,
            "remove_calendar_holiday",
        )
        .await;

        let (exception, _) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                &format!("/api/v1/admin/calendars/{id}/exceptions"),
                &cookie,
                Some(json!({ "name": "Half day", "exception_date": "2026-12-24",
                             "ranges": [{ "start_minute": 540, "end_minute": 720 }] })),
                None,
            ),
            StatusCode::CREATED,
            "add_calendar_exception",
        )
        .await;
        let exception_id = id_of(&exception);
        expect_one_op(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/admin/calendars/{id}/exceptions/{exception_id}"),
                &cookie,
                None,
                None,
            ),
            StatusCode::NO_CONTENT,
            "remove_calendar_exception",
        )
        .await;

        expect_one_op(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/admin/calendars/{id}"),
                &cookie,
                None,
                None,
            ),
            StatusCode::NO_CONTENT,
            "retire_calendar",
        )
        .await;
    })
}

#[test]
fn auto_mode_sidebar_items_record_one_op_per_write() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(auto_system().await);
        let db = system.db();
        let (actor, cookie) = seed_admin(&db).await;
        let name = format!("L4 item {}", suffix());

        let (created, _) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                "/api/v1/sidebar/admin",
                &cookie,
                Some(json!({ "name": name, "display_order": 900 })),
                None,
            ),
            StatusCode::OK,
            "upsert_sidebar_item",
        )
        .await;
        assert_eq!(created["owner_layer"], "project");
        let id = id_of(&created);
        let target: Value = sqlx::query_scalar(
            "SELECT target FROM changeset_operation \
             WHERE actor_ref = $1 AND op = 'upsert_sidebar_item' ORDER BY recorded_at LIMIT 1",
        )
        .bind(actor)
        .fetch_one(&db)
        .await
        .expect("sidebar op");
        assert_eq!(target, json!({ "path": name }));

        let (updated, _) = expect_one_op(
            &system,
            actor,
            request(
                "PATCH",
                &format!("/api/v1/sidebar/admin/{id}"),
                &cookie,
                Some(json!({ "name": name, "display_order": 901,
                             "row_version": created["row_version"] })),
                None,
            ),
            StatusCode::OK,
            "upsert_sidebar_item",
        )
        .await;
        expect_one_op(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/sidebar/admin/{id}"),
                &cookie,
                Some(json!({ "row_version": updated["row_version"] })),
                None,
            ),
            StatusCode::OK,
            "retire_sidebar_item",
        )
        .await;
    })
}

#[test]
fn auto_mode_system_views_record_one_op_per_write() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(auto_system().await);
        let db = system.db();
        let (actor, cookie) = seed_admin(&db).await;
        let (entity_id, _) = seed_entity(&db, "l4v").await;
        let query_id = seed_query(&db).await;
        let body = |name: &str| json!({ "name": name, "entity_logical_name": entity_id, "sql_query_ref": query_id });

        let (created, _) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                "/api/v1/admin/views",
                &cookie,
                Some(body("L4 view")),
                None,
            ),
            StatusCode::CREATED,
            "upsert_view",
        )
        .await;
        assert_eq!(created["owner_layer"], "project");
        let id = id_of(&created);
        expect_one_op(
            &system,
            actor,
            request(
                "PATCH",
                &format!("/api/v1/admin/views/{id}"),
                &cookie,
                Some(body("L4 view renamed")),
                None,
            ),
            StatusCode::OK,
            "upsert_view",
        )
        .await;
        // Only the columns change: the granular op (design §4.2), closed
        // (translated) into the automatic changeset like every other op.
        let mut columns_only = body("L4 view renamed");
        columns_only["table_definition"] = json!([{ "name": "title" }, { "name": "created_at" }]);
        let (_, changeset) = expect_one_op(
            &system,
            actor,
            request(
                "PATCH",
                &format!("/api/v1/admin/views/{id}"),
                &cookie,
                Some(columns_only),
                None,
            ),
            StatusCode::OK,
            "set_view_columns",
        )
        .await;
        assert_automatic(&db, changeset).await;
        expect_one_op(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/admin/views/{id}"),
                &cookie,
                None,
                None,
            ),
            StatusCode::NO_CONTENT,
            "retire_view",
        )
        .await;
    })
}

/// D-791 rule 2 / design §7: in `auto` mode without a changeset a business
/// rule write is a customer edit: stamped `customer`, recorded nowhere, and
/// allowed only on customer-layer rules.
#[test]
fn auto_mode_rules_are_customer_edits_that_record_nothing() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(auto_system().await);
        let db = system.db();
        let (actor, cookie) = seed_admin(&db).await;
        let entity = provision_entity(&system, &cookie).await;
        let rule = |message: &str| {
            json!({ "entity_logicalname": entity, "name": "amount_positive",
                    "condition": { "expression": "not (amount > 0)" },
                    "policies": [ { "type": "error", "severity": "error", "message": message } ] })
        };
        let with_if_match = |mut req: Request<Body>, v: i64| {
            req.headers_mut().insert(
                axum::http::header::IF_MATCH,
                format!("\"{v}\"").parse().expect("if-match"),
            );
            req
        };

        let (status, created) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/admin/business-rules",
                &cookie,
                Some(rule("must be positive")),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        assert_eq!(created["owner_layer"], "customer");
        assert_eq!(created["kind"], "business");
        let id = id_of(&created);
        let row_version = created["row_version"].as_i64().expect("row_version");

        // An identical repeat is idempotent.
        let (status, _) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/admin/business-rules",
                &cookie,
                Some(rule("must be positive")),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let patch = json!({ "policies": [ { "type": "error", "severity": "error",
                                            "message": "amount must be positive" } ] });
        let (status, _) = send(
            &system.app,
            request(
                "PATCH",
                &format!("/api/v1/admin/business-rules/{id}"),
                &cookie,
                Some(patch.clone()),
                None,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "If-Match is required"
        );
        let (status, body) = send(
            &system.app,
            with_if_match(
                request(
                    "PATCH",
                    &format!("/api/v1/admin/business-rules/{id}"),
                    &cookie,
                    Some(patch),
                    None,
                ),
                row_version,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, published) = send(
            &system.app,
            request(
                "POST",
                &format!("/api/v1/admin/business-rules/{id}/publish"),
                &cookie,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{published}");
        assert_eq!(
            published["version"],
            created["version"].as_i64().unwrap_or(0) + 1
        );
        let (status, _) = send(
            &system.app,
            request(
                "DELETE",
                &format!("/api/v1/admin/business-rules/{id}"),
                &cookie,
                None,
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        // The entity/field setup above records its own ops; the rule edits
        // (create, patch, publish, delete) must add none.
        let recorded: Vec<_> = ops_by(&db, actor)
            .await
            .into_iter()
            .filter(|(op, _, _)| op.contains("rule"))
            .collect();
        assert!(
            recorded.is_empty(),
            "customer rule edits record nothing before Phase 3: {recorded:?}"
        );

        // A rule of ours is refused to a customer edit.
        let (_, ours) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/admin/business-rules",
                &cookie,
                Some(
                    json!({ "entity": entity, "name": "ours", "condition": { "all": [] },
                             "policies": [ { "type": "error", "severity": "warning" } ] }),
                ),
                None,
            ),
        )
        .await;
        let ours_id = id_of(&ours);
        make_platform_owned(&db, "rule", ours_id).await;
        expect_refused(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/admin/business-rules/{ours_id}"),
                &cookie,
                None,
                None,
            ),
            "layer_mismatch",
        )
        .await;
    })
}

// ── 2. required mode ────────────────────────────────────────────────────────

#[test]
fn required_mode_without_a_changeset_refuses_every_hooked_route() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(required_system().await);
        let db = system.db();
        let (actor, cookie) = seed_admin(&db).await;
        let (entity_id, _) = seed_entity(&db, "l4q").await;
        let query_id = seed_query(&db).await;
        let app_name = format!("l4-required-{}", suffix());
        let missing = Uuid::now_v7();

        let refused = [
            (
                "POST",
                "/api/v1/admin/apps".to_owned(),
                Some(json!({ "name": app_name })),
            ),
            (
                "PATCH",
                format!("/api/v1/admin/apps/{missing}"),
                Some(json!({ "name": app_name })),
            ),
            ("DELETE", format!("/api/v1/admin/apps/{missing}"), None),
            (
                "POST",
                "/api/v1/admin/calendars".to_owned(),
                Some(json!({ "name": app_name, "tz": "UTC" })),
            ),
            ("DELETE", format!("/api/v1/admin/calendars/{missing}"), None),
            (
                "DELETE",
                format!("/api/v1/admin/calendars/{missing}/holidays/{missing}"),
                None,
            ),
            (
                "DELETE",
                format!("/api/v1/admin/calendars/{missing}/exceptions/{missing}"),
                None,
            ),
            (
                "POST",
                "/api/v1/sidebar/admin".to_owned(),
                Some(json!({ "name": app_name, "display_order": 0 })),
            ),
            (
                "DELETE",
                format!("/api/v1/sidebar/admin/{missing}"),
                Some(json!({ "row_version": 0 })),
            ),
            (
                "POST",
                "/api/v1/admin/views".to_owned(),
                Some(json!({ "name": app_name, "entity_logical_name": entity_id,
                             "sql_query_ref": query_id })),
            ),
            ("DELETE", format!("/api/v1/admin/views/{missing}"), None),
            (
                "DELETE",
                format!("/api/v1/admin/business-rules/{missing}"),
                None,
            ),
        ];
        for (method, uri, body) in refused {
            expect_refused(
                &system,
                actor,
                request(method, &uri, &cookie, body, None),
                "changeset_required",
            )
            .await;
        }

        // Nothing was written.
        let apps: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app WHERE name = $1")
            .bind(&app_name)
            .fetch_one(&db)
            .await
            .expect("count apps");
        let sidebar: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sidebar WHERE name = $1")
            .bind(&app_name)
            .fetch_one(&db)
            .await
            .expect("count sidebar items");
        assert_eq!((apps, sidebar), (0, 0));
    })
}

#[test]
fn required_mode_records_into_the_open_changeset_own_or_named() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(required_system().await);
        let db = system.db();
        let (actor, cookie) = seed_admin(&db).await;
        let opened = store::open(
            &db,
            &NewChangeset {
                layer: Layer::Project,
                scope: "l4-test".into(),
                name: format!("l4-{}", suffix()),
                title: "L4 hooks test".into(),
                description: String::new(),
                requires: json!({}),
                author_ref: Some(actor),
                author_label: format!("user:{actor}"),
            },
        )
        .await
        .expect("open a changeset");

        // No header: the caller's own open changeset.
        let (created, changeset) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                "/api/v1/admin/apps",
                &cookie,
                Some(json!({ "name": format!("l4-own-{}", suffix()) })),
                None,
            ),
            StatusCode::CREATED,
            "upsert_app",
        )
        .await;
        assert_eq!(changeset, opened.id);
        assert_eq!(created["owner_layer"], "project");

        // Named by header: the same changeset, next seq.
        let (_, changeset) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                "/api/v1/admin/calendars",
                &cookie,
                Some(json!({ "name": format!("L4 named {}", suffix()), "tz": "UTC" })),
                Some(opened.id),
            ),
            StatusCode::CREATED,
            "upsert_calendar",
        )
        .await;
        assert_eq!(changeset, opened.id);
        let seqs: Vec<i32> = ops_by(&db, actor)
            .await
            .iter()
            .map(|(_, _, s)| *s)
            .collect();
        assert_eq!(seqs, vec![1, 2], "seq follows commit order");
        let count: i32 = sqlx::query_scalar("SELECT op_count FROM changeset WHERE id = $1")
            .bind(opened.id)
            .fetch_one(&db)
            .await
            .expect("op_count");
        assert_eq!(count, 2);

        // A header naming a changeset that is not open is refused.
        expect_refused(
            &system,
            actor,
            request(
                "POST",
                "/api/v1/admin/apps",
                &cookie,
                Some(json!({ "name": format!("l4-closed-{}", suffix()) })),
                Some(Uuid::now_v7()),
            ),
            "changeset_not_open",
        )
        .await;
    })
}

// ── 3. owner layer ──────────────────────────────────────────────────────────

/// Hands a row to the platform layer, as the boot stamp step does.
async fn make_platform_owned(db: &DbPool, table: &str, id: Uuid) {
    // `table` is one of this file's literals below, never input.
    sqlx::query(&format!(
        "UPDATE {table} SET owner_layer = 'platform' WHERE id = $1"
    ))
    .bind(id)
    .execute(db)
    .await
    .expect("stamp the row platform-owned");
}

#[test]
fn a_platform_owned_row_is_refused_to_a_project_write() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(auto_system().await);
        let db = system.db();
        let (actor, cookie) = seed_admin(&db).await;

        // App: update and retire refused.
        let name = format!("l4-owned-{}", suffix());
        let (status, app) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/admin/apps",
                &cookie,
                Some(json!({ "name": name })),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{app}");
        let app_id = id_of(&app);
        make_platform_owned(&db, "app", app_id).await;
        expect_refused(
            &system,
            actor,
            request(
                "PATCH",
                &format!("/api/v1/admin/apps/{app_id}"),
                &cookie,
                Some(json!({ "name": name, "display_order": 7 })),
                None,
            ),
            "layer_mismatch",
        )
        .await;
        expect_refused(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/admin/apps/{app_id}"),
                &cookie,
                None,
                None,
            ),
            "layer_mismatch",
        )
        .await;
        let (order, active): (i32, bool) =
            sqlx::query_as("SELECT display_order, is_active FROM app WHERE id = $1")
                .bind(app_id)
                .fetch_one(&db)
                .await
                .expect("read app");
        assert_eq!(
            (order, active),
            (0, true),
            "the refused writes changed nothing"
        );

        // Calendar: a project may add a holiday to a platform calendar (the
        // parent may belong to a lower layer), but not update the calendar
        // or remove a platform-owned holiday.
        let cal_name = format!("L4 owned {}", suffix());
        let (status, calendar) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/admin/calendars",
                &cookie,
                Some(json!({ "name": cal_name, "tz": "UTC" })),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{calendar}");
        let cal_id = id_of(&calendar);
        make_platform_owned(&db, "calendar", cal_id).await;
        expect_refused(
            &system,
            actor,
            request(
                "PATCH",
                &format!("/api/v1/admin/calendars/{cal_id}"),
                &cookie,
                Some(json!({ "name": cal_name, "tz": "UTC", "description": "x" })),
                None,
            ),
            "layer_mismatch",
        )
        .await;
        let (holiday, _) = expect_one_op(
            &system,
            actor,
            request(
                "POST",
                &format!("/api/v1/admin/calendars/{cal_id}/holidays"),
                &cookie,
                Some(json!({ "name": "Day", "holiday_date": "2027-01-01" })),
                None,
            ),
            StatusCode::CREATED,
            "add_calendar_holiday",
        )
        .await;
        assert_eq!(holiday["owner_layer"], "project");
        let holiday_id = id_of(&holiday);
        make_platform_owned(&db, "calendar_holiday", holiday_id).await;
        expect_refused(
            &system,
            actor,
            request(
                "DELETE",
                &format!("/api/v1/admin/calendars/{cal_id}/holidays/{holiday_id}"),
                &cookie,
                None,
                None,
            ),
            "layer_mismatch",
        )
        .await;

        // Sidebar item: update refused.
        let item_name = format!("L4 owned item {}", suffix());
        let (status, item) = send(
            &system.app,
            request(
                "POST",
                "/api/v1/sidebar/admin",
                &cookie,
                Some(json!({ "name": item_name, "display_order": 950 })),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{item}");
        let item_id = id_of(&item);
        make_platform_owned(&db, "sidebar", item_id).await;
        expect_refused(
            &system,
            actor,
            request(
                "PATCH",
                &format!("/api/v1/sidebar/admin/{item_id}"),
                &cookie,
                Some(json!({ "name": item_name, "display_order": 951,
                             "row_version": item["row_version"] })),
                None,
            ),
            "layer_mismatch",
        )
        .await;
    })
}

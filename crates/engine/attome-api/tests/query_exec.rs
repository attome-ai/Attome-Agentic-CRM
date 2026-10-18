//! Integration tests for P1.1e: read-only pool containment, statement
//! timeout, and per-query privilege gating on `/api/v1/query/execute`.
//!
//! Requires a live Postgres (`DATABASE_URL`) whose database name contains
//! `test`/`e2e`, with migration 0010's `attome_readonly` role present. The
//! host/port/database/schema for both pools are derived from that one URL;
//! `READONLY_DB_PASSWORD` supplies only the role credential. The harness
//! grants LOGIN and synchronizes that password before connecting the readonly
//! pool, so CI and local runs share the same bootstrap contract.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:READONLY_DB_PASSWORD = "test-only-readonly-password"
//! cargo test -p attome-api --test query_exec -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::str::FromStr;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

struct TestDatabase {
    host: String,
    port: u16,
    name: String,
    schema: String,
    user: String,
    password: String,
}

/// `user`/`password` from a `postgres://user:password@host/...` URL. The
/// config's own `database.user/password` must be real: `AppConfig::
/// migrator_database_url()` builds from them, and bundle apply opens that
/// connection when it indexes an attribute (see `dashboard_migration.rs`'s
/// `test_config` for the same fix).
fn url_credentials(url: &str) -> (String, String) {
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .unwrap_or(url);
    let userinfo = rest.split_once('@').map(|(info, _)| info).unwrap_or("");
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    (user.to_owned(), password.to_owned())
}

fn schema_from_options(options: Option<&str>) -> Option<String> {
    options?
        .split_whitespace()
        .find_map(|part| {
            part.strip_prefix("search_path=")
                .or_else(|| part.strip_prefix("--search_path="))
        })
        .and_then(|value| value.split(',').next())
        .filter(|schema| !schema.is_empty())
        .map(str::to_owned)
}

/// `None` when there is no throwaway database configured — unwrap with
/// `skip_if_no_db!`, which prints the reason and returns from the test. The
/// name assertion below still fires when one IS configured: skipping is for
/// "no test database", never for "pointed at the wrong database".
fn require_test_database() -> Option<TestDatabase> {
    let url = attome_testkit::migrated_db_url()?;
    let options = sqlx::postgres::PgConnectOptions::from_str(&url)
        .expect("DATABASE_URL must be a valid postgres:// URL");
    let name = options
        .get_database()
        .expect("DATABASE_URL must include a database name")
        .to_owned();
    let safe_name = name.to_ascii_lowercase();
    assert!(
        safe_name.contains("test")
            || safe_name.contains("e2e")
            || safe_name.starts_with("attome_t_"),
        "refusing to run query_exec against database {name:?}; use a dedicated test database"
    );

    let (user, password) = url_credentials(&url);
    Some(TestDatabase {
        user,
        password,
        host: options.get_host().to_owned(),
        port: options.get_port(),
        name,
        schema: schema_from_options(options.get_options()).unwrap_or_else(|| "public".to_owned()),
    })
}

fn test_config(readonly_password: &str, database: &TestDatabase) -> AppConfig {
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
                "host": {db_host}, "port": {db_port}, "dbname": {db_name},
                "user": {db_user}, "password": {db_password}, "schema": {db_schema},
                "connection_number": 5, "timeout": 5.0,
                "migrator": {{ "user": {db_user}, "password": {db_password} }},
                "readonly": {{ "user": "attome_readonly", "password": {readonly_password} }}
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60
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
            "cors": {{ "allowed_origins": ["http://test.local"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        readonly_password =
            serde_json::to_string(readonly_password).expect("serialize readonly password"),
        db_host = serde_json::to_string(&database.host).expect("serialize database host"),
        db_port = database.port,
        db_name = serde_json::to_string(&database.name).expect("serialize database name"),
        db_schema = serde_json::to_string(&database.schema).expect("serialize database schema"),
        db_user = serde_json::to_string(&database.user).expect("serialize database user"),
        db_password =
            serde_json::to_string(&database.password).expect("serialize database password"),
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn synchronize_readonly_login(db: &attome_db::DbPool, password: &str) {
    let mut tx = db
        .begin()
        .await
        .expect("open readonly-role seed transaction");
    sqlx::query("SELECT set_config('attome.readonly_password', $1, true)")
        .bind(password)
        .execute(&mut *tx)
        .await
        .expect("stage readonly test credential");
    sqlx::query(
        r#"
        DO $$
        BEGIN
            EXECUTE format(
                'ALTER ROLE attome_readonly WITH LOGIN PASSWORD %L',
                current_setting('attome.readonly_password')
            );
        END
        $$;
        "#,
    )
    .execute(&mut *tx)
    .await
    .expect("apply readonly test credential");
    tx.commit()
        .await
        .expect("commit readonly-role seed transaction");
}

async fn build_test_system() -> Option<EngineSystem> {
    let database = require_test_database()?;
    let readonly_password = std::env::var("READONLY_DB_PASSWORD")
        .unwrap_or_else(|_| "test-only-readonly-password".to_owned());

    let config = test_config(&readonly_password, &database);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    synchronize_readonly_login(&db, &readonly_password).await;
    let db_readonly = attome_db::create_readonly_pool(&config)
        .await
        .expect("connect readonly role")
        .expect("database.readonly must be configured in test_config");
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
    // D-143: entity_crud/bulk routes are now license-gated (now MODULE_CORE, was MODULE_ENTITY pre-D-222) —
    // grant every module so this suite exercises them the same way a fully
    // licensed deployment would.
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    Some(system)
}

/// `oneshot()`-driven test requests carry no `Sec-Fetch-Site`/`Origin`
/// header at all (unlike a real browser), which `csrf_protect`
/// (attome-server/src/middleware/csrf.rs) fails closed on for any
/// cookie-authenticated unsafe-method request — by design. Stamping a
/// matching `Origin` here is the same fix a legitimate non-browser caller
/// would need in production — `test_config()`'s `cors.allowed_origins`
/// carries the matching entry. Same pattern as `entity_round_trip.rs`/
/// `authz.rs`/`record_level_security.rs`'s identical helper.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("http://test.local"),
    );
    req
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

/// Builds the full assembled app the same way `main.rs` does (Plan 1.3):
/// inner (authn/authz/RateLimit/Idempotency) → s2s_authn → outer
/// (RequestId..BodyLimit). `core_routes()` alone is bare, middleware-free
/// routes as of this plan — using it directly would silently skip auth.
fn build_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
}

async fn seed_admin(system: &TestSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("query-exec-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

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

    session_cookie(user_id)
}

/// Seeds a non-admin user holding exactly one throwaway privilege key.
/// Returns the session cookie.
async fn seed_user_with_privilege(system: &TestSystem, privilege_key: &str) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("query-exec-test-user-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    let privilege_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) VALUES ($1, $2, $3, true, NOW(), 'project')",
    )
    .bind(privilege_id)
    .bind(privilege_key)
    .bind(privilege_key)
    .execute(db)
    .await
    .expect("insert throwaway privilege");

    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("insert throwaway grant");

    session_cookie(user_id)
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

/// Seeds a `sql_query` row directly (bypassing query_admin.rs, which is
/// out of scope here) and returns its id.
async fn seed_query(
    system: &TestSystem,
    sql: &str,
    required_privilege: Option<&str>,
    is_report: bool,
) -> Uuid {
    let db = &system.state().base.db;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query (id, sql_query, table_definition, is_active, required_privilege, is_report, created_at, owner_layer) \
         VALUES ($1, $2, '[]', true, $3, $4, NOW(), 'project')",
    )
    .bind(id)
    .bind(sql)
    .bind(required_privilege)
    .bind(is_report)
    .execute(db)
    .await
    .expect("insert throwaway sql_query");
    id
}

/// Seeds an entity-scoped query with an explicit table definition so the
/// execution path resolves the choice column as a choice field before it
/// applies the caller's filter.
async fn seed_entity_query(
    state: &EngineState,
    sql: &str,
    entity_id: Uuid,
    table_definition: &str,
) -> Uuid {
    let db = &state.base.db;
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query (id, sql_query, table_definition, entity_logical_name, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $3, $4, true, NOW(), 'project')",
    )
    .bind(id)
    .bind(sql)
    .bind(table_definition)
    .bind(entity_id)
    .execute(db)
    .await
    .expect("insert throwaway entity-scoped sql_query");
    id
}

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn create_entity(app: &axum::Router, admin_cookie: &str, logicalname: &str) -> Uuid {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"Query Choice Test"}}"#
        )))
        .unwrap();
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("create choice entity");
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create entity failed: {body:?}"
    );
    Uuid::parse_str(body["id"].as_str().expect("entity id")).expect("entity UUID")
}

async fn create_choice_field(
    app: &axum::Router,
    admin_cookie: &str,
    entity_id: Uuid,
    logicalname: &str,
    multi: bool,
) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "logicalname": logicalname,
                "name": logicalname,
                "field_type": "choice",
                "options": {"choices": ["red", "green", "blue"], "multi": multi}
            })
            .to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create choice field");
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::CREATED, "create field failed: {body:?}");
}

async fn create_text_field(
    app: &axum::Router,
    admin_cookie: &str,
    entity_id: Uuid,
    logicalname: &str,
) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "logicalname": logicalname,
                "name": logicalname,
                "field_type": "text",
                "max_length": 100
            })
            .to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create text field");
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::CREATED, "create field failed: {body:?}");
}

async fn create_choice_record(
    app: &axum::Router,
    admin_cookie: &str,
    logicalname: &str,
    field: &str,
    value: serde_json::Value,
) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", admin_cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({field: value}).to_string()))
        .unwrap();
    let res = app
        .clone()
        .oneshot(req)
        .await
        .expect("create choice record");
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create record failed: {body:?}"
    );
}

async fn sync_registry(state: &EngineState) {
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build entity metadata registry");
    state.entities.swap(registry);
}

async fn execute_query(app: axum::Router, cookie: &str, query_id: Uuid) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/query/execute")
        .header("cookie", cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"query_id":"{query_id}"}}"#)))
        .unwrap();
    app.oneshot(req).await.expect("request").status()
}

async fn execute_query_body(app: axum::Router, cookie: &str, query_id: Uuid) -> serde_json::Value {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/query/execute")
        .header("cookie", cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"query_id":"{query_id}"}}"#)))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Same as `execute_query_body` but with a caller-built JSON body, for tests
/// (P1.11(g)) that need `page_size`/`order_by`/`after_id` beyond the bare
/// `query_id` the other helper sends.
async fn execute_body(
    app: axum::Router,
    cookie: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/query/execute")
        .header("cookie", cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[test]
fn execute_runs_on_the_readonly_role_not_the_app_owner() {
    attome_testkit::run_shared(async {
        // Postgres's own grammar already rejects data-modifying statements
        // nested inside the wrapping "SELECT ... FROM (stored_sql) AS t"
        // subquery (bare UPDATE: syntax error; a data-modifying CTE: "WITH
        // clause containing a data-modifying statement must be at the top
        // level") — a bonus defense-in-depth layer, but it means a 500 from
        // those shapes wouldn't actually prove the read-only ROLE is what's
        // enforcing anything. Assert the connection identity directly instead:
        // this is what the psql smoke test (see P1.1e verification) proved by
        // hand — attome_readonly can SELECT, not UPDATE — now proven through
        // the real HTTP surface.
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let qid = seed_query(&system, "SELECT current_user AS id", None, false).await;
        let app = full_app(system);

        let body = execute_query_body(app, &admin_cookie, qid).await;
        let current_user = body["data"]["records"][0]["id"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(
            current_user, "attome_readonly",
            "query/execute must run on the attome_readonly role, not the application's full-privilege owner"
        );
    })
}

#[test]
fn runaway_query_is_cancelled_by_the_statement_timeout() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        // `id` must be a real, orderable column — cursor-mode pagination
        // (D-126 phase 2) unconditionally does `ORDER BY t.id`, and Postgres
        // rejects ordering by `pg_sleep`'s `void` return type at plan time,
        // before the sleep ever runs. Using a throwaway uuid for `id` alongside
        // the sleep is what actually exercises the statement_timeout, instead
        // of failing fast on an unrelated planning error.
        let qid = seed_query(
            &system,
            "SELECT gen_random_uuid() AS id, pg_sleep(2)",
            None,
            false,
        )
        .await;
        let app = full_app(system);

        let status = execute_query(app, &admin_cookie, qid).await;
        // AA4-T7: a query past its limit is a 504 query_timeout.
        assert_eq!(
            status,
            StatusCode::GATEWAY_TIMEOUT,
            "a 2s query must be cancelled by the 500ms fast-read statement_timeout"
        );
    })
}

#[test]
fn is_report_raises_the_timeout_ceiling_to_5s() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let qid = seed_query(
            &system,
            "SELECT gen_random_uuid() AS id, pg_sleep(2)",
            None,
            true,
        )
        .await;
        let app = full_app(system);

        let status = execute_query(app, &admin_cookie, qid).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a 2s query flagged is_report must complete under the 5s report ceiling"
        );
    })
}

#[test]
fn required_privilege_gates_execute_per_query() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let key = format!("test.report.view.{}", Uuid::now_v7());
        let unrelated_key = format!("test.unrelated.{}", Uuid::now_v7());
        let holder_cookie = seed_user_with_privilege(&system, &key).await;
        let stranger_cookie = seed_user_with_privilege(&system, &unrelated_key).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let (published, body) =
            create_query_via_admin(app.clone(), &admin_cookie, "SELECT 1 AS id").await;
        assert_eq!(
            published,
            StatusCode::CREATED,
            "publish query failed: {body:?}"
        );
        let qid = Uuid::parse_str(body["id"].as_str().expect("query id")).expect("query UUID");
        sqlx::query("UPDATE sql_query SET required_privilege = $1 WHERE id = $2")
            .bind(&key)
            .bind(qid)
            .execute(&db)
            .await
            .expect("open published query to the throwaway privilege");

        assert_eq!(
            execute_query(app.clone(), &holder_cookie, qid).await,
            StatusCode::OK
        );
        assert_eq!(
            execute_query(app, &stranger_cookie, qid).await,
            StatusCode::FORBIDDEN
        );
    })
}

/// A published custom query records every entity relation it reads. Holding
/// only the query's own privilege must never grant implicit access to those
/// entity rows; the legacy path would execute this query successfully.
#[test]
fn unscoped_query_requires_read_privilege_for_every_referenced_entity() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let logicalname = format!("query_scope_{}", Uuid::now_v7().simple());
        let report_key = format!("test.report.view.{}", Uuid::now_v7());
        let report_reader = seed_user_with_privilege(&system, &report_key).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        create_entity(&app, &admin_cookie, &logicalname).await;

        let (published, body) = create_query_via_admin(
            app.clone(),
            &admin_cookie,
            &format!("SELECT id FROM \"{logicalname}\""),
        )
        .await;
        assert_eq!(
            published,
            StatusCode::CREATED,
            "publish query failed: {body:?}"
        );
        let qid = Uuid::parse_str(body["id"].as_str().expect("query id")).expect("query UUID");

        sqlx::query("UPDATE sql_query SET required_privilege = $1 WHERE id = $2")
            .bind(&report_key)
            .bind(qid)
            .execute(&db)
            .await
            .expect("open published query to the report privilege");

        assert_eq!(
            execute_query(app, &report_reader, qid).await,
            StatusCode::FORBIDDEN,
            "a custom query must require read access to each entity it references"
        );
    })
}

/// D-078 regression: single-select Choice columns are provisioned as TEXT,
/// so query/execute must bind their scalar filter value as text rather than
/// the pre-D-078 integer cast. Multi-select Choice behavior is covered by the
/// dedicated array-filter regression below.
#[test]
fn execute_filters_single_select_choice_as_text() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);
        let logicalname = format!("query_choice_{}", Uuid::now_v7().simple());

        let entity_id = create_entity(&app, &admin_cookie, &logicalname).await;
        create_choice_field(&app, &admin_cookie, entity_id, "status", false).await;
        sync_registry(&state).await;
        create_choice_record(
            &app,
            &admin_cookie,
            &logicalname,
            "status",
            serde_json::json!("red"),
        )
        .await;
        create_choice_record(
            &app,
            &admin_cookie,
            &logicalname,
            "status",
            serde_json::json!("green"),
        )
        .await;

        let physical_type: String = sqlx::query_scalar(
            "SELECT udt_name FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = 'status'",
        )
        .bind(&logicalname)
        .fetch_one(&state.base.db)
        .await
        .expect("query provisioned choice column type");
        assert_eq!(physical_type, "text");

        let table_definition = serde_json::json!([
            {"logicalName": "id", "dataType": "text"},
            {"logicalName": "status", "dataType": "choice"}
        ])
        .to_string();
        let qid = seed_entity_query(
            &state,
            &format!("SELECT id, status FROM \"{logicalname}\" WHERE is_active = true"),
            entity_id,
            &table_definition,
        )
        .await;

        let body = execute_body(
            app,
            &admin_cookie,
            serde_json::json!({
                "query_id": qid,
                "filters": [{"field": "status", "op": "eq", "value": "green"}]
            }),
        )
        .await;
        let records = body["data"]["records"].as_array().expect("query records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["status"], "green");
    })
}

/// Regression: the query/execute response's `columns` list must follow the
/// query's own SELECT order, not alphabetical order. `sql_cols` used to be
/// read off `serde_json::Map::keys()`, and this workspace does not enable
/// serde_json's `preserve_order` feature, so that map (BTreeMap-backed)
/// always iterates alphabetically regardless of insertion order — silently
/// scrambling column order (and therefore which column the frontend grid
/// treats as index 0 / the record link) for any query with no
/// `table_definition`, i.e. every seeded default list view. `zeta_field`/
/// `alpha_field` are chosen because SELECT order and alphabetical order
/// disagree on them.
#[test]
fn execute_column_order_follows_the_select_list_not_alphabetical_key_order() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);
        let logicalname = format!("qorder_{}", Uuid::now_v7().simple());

        let entity_id = create_entity(&app, &admin_cookie, &logicalname).await;
        create_text_field(&app, &admin_cookie, entity_id, "zeta_field").await;
        create_text_field(&app, &admin_cookie, entity_id, "alpha_field").await;
        sync_registry(&state).await;

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"zeta_field": "z", "alpha_field": "a"}).to_string(),
            ))
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("create record");
        assert_eq!(res.status(), StatusCode::CREATED);

        let qid = seed_entity_query(
            &state,
            &format!(
                "SELECT id, zeta_field, alpha_field FROM \"{logicalname}\" WHERE is_active = true"
            ),
            entity_id,
            "[]",
        )
        .await;

        let body = execute_body(app, &admin_cookie, serde_json::json!({ "query_id": qid })).await;
        let names: Vec<&str> = body["data"]["columns"]
            .as_array()
            .expect("columns")
            .iter()
            .map(|c| c["name"].as_str().expect("column name"))
            .collect();
        assert_eq!(
            names,
            vec!["zeta_field", "alpha_field"],
            "column order must follow the query's SELECT list, not alphabetical key order"
        );
    })
}

/// A choice field's `choice_styles` (per-value color/icon presentation
/// hints, `attome_field::ChoiceOptions`) round-trip through to the query/execute
/// response's `ColumnDef.choice_styles` — the wiring the grid needs to
/// render decorated pills instead of plain text.
#[test]
fn execute_surfaces_choice_styles_on_the_column_def() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);
        let logicalname = format!("qcs_{}", Uuid::now_v7().simple());

        let entity_id = create_entity(&app, &admin_cookie, &logicalname).await;

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &admin_cookie)
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "logicalname": "direction",
                    "name": "direction",
                    "field_type": "choice",
                    "options": {
                        "choices": ["Inbound", "Outbound"],
                        "multi": false,
                        "choice_styles": {
                            "Inbound": { "color": "#ef4444", "icon": "las la-arrow-down" },
                            "Outbound": { "color": "#22c55e", "icon": "las la-arrow-up" }
                        }
                    }
                })
                .to_string(),
            ))
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("create choice field");
        let status = res.status();
        let body = body_json(res).await;
        assert_eq!(status, StatusCode::CREATED, "create field failed: {body:?}");

        sync_registry(&state).await;
        create_choice_record(
            &app,
            &admin_cookie,
            &logicalname,
            "direction",
            serde_json::json!("Outbound"),
        )
        .await;

        let table_definition = serde_json::json!([
            {"logicalName": "id", "dataType": "text"},
            {"logicalName": "direction", "dataType": "choice"}
        ])
        .to_string();
        let qid = seed_entity_query(
            &state,
            &format!("SELECT id, direction FROM \"{logicalname}\" WHERE is_active = true"),
            entity_id,
            &table_definition,
        )
        .await;

        let body = execute_body(app, &admin_cookie, serde_json::json!({ "query_id": qid })).await;
        let columns = body["data"]["columns"].as_array().expect("columns");
        let direction_col = columns
            .iter()
            .find(|c| c["name"] == "direction")
            .expect("direction column present");
        assert_eq!(
            direction_col["choice_styles"]["Outbound"]["color"],
            "#22c55e"
        );
        assert_eq!(
            direction_col["choice_styles"]["Inbound"]["icon"],
            "las la-arrow-down"
        );
    })
}

/// Multi-select Choices are stored as PostgreSQL TEXT[]. Query filtering must
/// use array membership operators rather than scalar equality, and the
/// request's array value retains explicit OR/AND semantics.
#[test]
fn execute_filters_multi_select_choice_by_membership_any_and_all() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);
        let logicalname = format!("query_multi_{}", Uuid::now_v7().simple());

        let entity_id = create_entity(&app, &admin_cookie, &logicalname).await;
        create_choice_field(&app, &admin_cookie, entity_id, "tags", true).await;
        sync_registry(&state).await;
        for tags in [
            serde_json::json!(["red", "green"]),
            serde_json::json!(["blue"]),
            serde_json::json!(["green", "blue"]),
        ] {
            create_choice_record(&app, &admin_cookie, &logicalname, "tags", tags).await;
        }

        let physical_type: String = sqlx::query_scalar(
            "SELECT udt_name FROM information_schema.columns \
         WHERE table_name = $1 AND column_name = 'tags'",
        )
        .bind(&logicalname)
        .fetch_one(&state.base.db)
        .await
        .expect("query provisioned multi-select choice column type");
        assert_eq!(physical_type, "_text");

        let table_definition = serde_json::json!([
            {"logicalName": "id", "dataType": "text"},
            {"logicalName": "tags", "dataType": "choice"}
        ])
        .to_string();
        let qid = seed_entity_query(
            &state,
            &format!("SELECT id, tags FROM \"{logicalname}\" WHERE is_active = true"),
            entity_id,
            &table_definition,
        )
        .await;

        let membership = execute_body(
            app.clone(),
            &admin_cookie,
            serde_json::json!({
                "query_id": qid,
                "include_total": true,
                "filters": [{"field": "tags", "op": "contains", "value": "green"}]
            }),
        )
        .await;
        assert_eq!(membership["data"]["total"], 2);

        let any = execute_body(
            app.clone(),
            &admin_cookie,
            serde_json::json!({
                "query_id": qid,
                "include_total": true,
                "filters": [{"field": "tags", "op": "contains_any", "value": ["red", "blue"]}]
            }),
        )
        .await;
        assert_eq!(any["data"]["total"], 3);

        let all = execute_body(
            app,
            &admin_cookie,
            serde_json::json!({
                "query_id": qid,
                "filters": [{"field": "tags", "op": "contains_all", "value": ["green", "blue"]}]
            }),
        )
        .await;
        let records = all["data"]["records"].as_array().expect("query records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["tags"], serde_json::json!(["green", "blue"]));
    })
}

/// P1.11(g) — `after_id` pages through the same ordering an OFFSET request
/// would use, one page at a time, ending with a short page that carries no
/// `next_cursor`; `total`/`total_pages` are absent in this mode (see
/// `ExecData`'s doc comment for why). Uses a real, uniquely-named table
/// (not `generate_series`-generated ids) so the dataset is stable across
/// the multiple times `query/execute` runs the stored SQL per request.
#[test]
fn keyset_cursor_pages_through_in_order_matching_offset_and_terminates() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = &system.state().base.db;

        let table = format!("test_cursor_{}", Uuid::now_v7().simple());
        sqlx::query(&format!(
            r#"CREATE TABLE "{table}" (id UUID PRIMARY KEY, val INT NOT NULL)"#
        ))
        .execute(db)
        .await
        .expect("create throwaway cursor test table");
        // P-stored-query-containment (D-126): this is a raw table, never routed
        // through attome-metadata::provision (which is what grants attome_readonly
        // SELECT automatically for a *registered* entity) — grant it by hand so
        // this test exercises cursor/OFFSET pagination, not the containment
        // boundary (that's the dedicated tests further down).
        sqlx::query(&format!(r#"GRANT SELECT ON "{table}" TO attome_readonly"#))
            .execute(db)
            .await
            .expect("grant readonly select on throwaway cursor test table");
        let ids: Vec<Uuid> = (0..5).map(|_| Uuid::now_v7()).collect();
        for (i, id) in ids.iter().enumerate() {
            sqlx::query(&format!(
                r#"INSERT INTO "{table}" (id, val) VALUES ($1, $2)"#
            ))
            .bind(id)
            .bind(i as i32)
            .execute(db)
            .await
            .expect("insert throwaway cursor test row");
        }

        let qid = seed_query(
            &system,
            &format!("SELECT id, val FROM \"{table}\""),
            None,
            false,
        )
        .await;
        let app = full_app(system);

        // Page 1: OFFSET + exact-total mode, to get the baseline ordering (val
        // ASC) to compare against. P-stored-query-containment phase 2 (D-126)
        // flipped the default away from OFFSET+total (cursor mode is now the
        // default for an unset include_total) — `include_total: true` is
        // required explicitly to reach this branch, per that plan's own
        // cursor-default regression requirement (existing include_total: true
        // callers must keep getting real totals).
        let offset_body = execute_body(
        app.clone(),
        &admin_cookie,
        serde_json::json!({"query_id": qid, "page_size": 2, "order_by": "val", "include_total": true}),
    )
    .await;
        let offset_vals: Vec<i64> = offset_body["data"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["val"].as_i64().unwrap())
            .collect();
        assert_eq!(
            offset_vals,
            vec![0, 1],
            "OFFSET page 1 must be val-ordered starting from 0"
        );
        assert_eq!(offset_body["data"]["total"], serde_json::json!(5));

        // Page 1 has nothing to resume *from* yet, so it's necessarily the
        // OFFSET request above (already asserted: val-ordered, real total).
        // Every page after that is pure keyset/cursor mode, seeded from the
        // OFFSET page's own last row id — must visit 2,3,4 in order, with no
        // `total` and terminating on a short page with no `next_cursor`.
        let mut seen: Vec<i64> = offset_vals.clone();
        let mut after_id = offset_body["data"]["records"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["id"]
            .clone();
        loop {
            let req = serde_json::json!({
                "query_id": qid, "page_size": 2, "order_by": "val", "after_id": after_id,
            });
            let body = execute_body(app.clone(), &admin_cookie, req).await;
            assert_eq!(
                body["data"]["total"],
                serde_json::Value::Null,
                "cursor mode must omit total"
            );

            let records = body["data"]["records"].as_array().unwrap();
            if records.is_empty() {
                break;
            }
            seen.extend(records.iter().map(|r| r["val"].as_i64().unwrap()));

            match body["data"]["next_cursor"].clone() {
                serde_json::Value::Null => break,
                cursor => after_id = cursor,
            }
        }

        assert_eq!(
            seen,
            vec![0, 1, 2, 3, 4],
            "keyset pagination must visit every row exactly once, in order"
        );
    })
}

/// AA4-T4: a raw text-keyed table with five names, readable by the query
/// role, and a stored query over it.
async fn seek_fixture(system: &TestSystem) -> Uuid {
    let db = &system.state().base.db;
    let table = format!("test_seek_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        r#"CREATE TABLE "{table}" (id UUID PRIMARY KEY, name TEXT NOT NULL)"#
    ))
    .execute(db)
    .await
    .expect("create seek table");
    sqlx::query(&format!(r#"GRANT SELECT ON "{table}" TO attome_readonly"#))
        .execute(db)
        .await
        .expect("grant seek table");
    for name in ["alpha", "bravo", "charlie", "delta", "echo"] {
        sqlx::query(&format!(
            r#"INSERT INTO "{table}" (id, name) VALUES ($1, $2)"#
        ))
        .bind(Uuid::now_v7())
        .bind(name)
        .execute(db)
        .await
        .expect("insert seek row");
    }
    seed_query(
        system,
        &format!("SELECT id, name FROM \"{table}\""),
        None,
        false,
    )
    .await
}

/// AA4-T4: a seek on a text sort starts the page at the value, with a cursor.
#[test]
fn seek_on_text_sort_starts_at_value() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let qid = seek_fixture(&system).await;
        let app = full_app(system);
        let body = execute_body(
            app,
            &admin_cookie,
            serde_json::json!({"query_id": qid, "page_size": 2, "order_by": "name", "seek": "c"}),
        )
        .await;
        let names: Vec<&str> = body["data"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["charlie", "delta"]);
        assert!(body["data"]["next_cursor"].is_string(), "{body}");
    })
}

/// AA4-T4: seek and after_id together are refused.
#[test]
fn seek_with_after_id_is_422() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let qid = seek_fixture(&system).await;
        let app = full_app(system);
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/query/execute")
            .header("cookie", &admin_cookie)
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "query_id": qid, "order_by": "name", "seek": "c",
                    "after_id": Uuid::now_v7(),
                })
                .to_string(),
            ))
            .unwrap();
        let res = app.oneshot(req).await.expect("request");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    })
}

// ── P-stored-query-containment (D-126) ──────────────────────────────────────

/// POSTs to `/api/v1/admin/queries` (query_admin.rs) — unlike `seed_query`
/// above, this goes through the real publish path, so the publish-time
/// relation lint (phase 1(b)) and the `sql_query_version` write
/// (phase 2) both run.
async fn create_query_via_admin(
    app: axum::Router,
    admin_cookie: &str,
    sql_query: &str,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/queries")
        .header("cookie", admin_cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "sql_query": sql_query }).to_string(),
        ))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    let status = res.status();
    (status, body_json(res).await)
}

/// Definition-of-done bullet: "Publishing a stored query referencing a
/// non-entity table fails 422 at publish time, naming the relation."
/// `refresh_token` is infrastructure (never registered in
/// entity_info), so the publish-time lint must reject it.
#[test]
fn publish_rejects_a_query_referencing_a_non_entity_relation() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (status, body) =
            create_query_via_admin(app, &admin_cookie, "SELECT id FROM refresh_token").await;

        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "publishing a query against a non-entity table must 422: {body:?}"
        );
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("refresh_token"),
            "422 message must name the offending relation, got: {message}"
        );
    })
}

/// Addendum §11(b): `EXPLAIN`'s planner never descends into a called
/// function's body, so `collect_relation_names` alone would let
/// `SELECT * FROM some_function()` publish clean even if that function
/// reads a forbidden table internally. `generate_series` is a pg_catalog
/// builtin (not schema-local, always present, needs no special grant),
/// chosen specifically so this test exercises `find_function_scan`'s
/// rejection itself, independent of migration 0060's readonly-role
/// EXECUTE revoke (which only touches this app's own schema).
#[test]
fn publish_rejects_a_query_that_calls_a_function() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (status, body) = create_query_via_admin(
            app,
            &admin_cookie,
            "SELECT * FROM generate_series(1, 3) AS s(id)",
        )
        .await;

        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "publishing a query that calls a function must 422: {body:?}"
        );
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("generate_series"),
            "422 message must name the offending function, got: {message}"
        );
    })
}

/// Definition-of-done bullet: `attome_readonly` must not be able to read
/// `user_account.password_hash` even via a column alias — the guarantee
/// migration 0046's column-level grant provides, not query_exec.rs's
/// name-based output filter (which a `password_hash AS x` alias defeats).
/// Uses `seed_query` (bypasses the publish-time lint, same as every other
/// test in this file that seeds a row directly) so this isolates the grant
/// itself rather than the lint that would also catch this at publish time.
#[test]
fn execute_cannot_read_password_hash_even_through_a_column_alias() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let qid = seed_query(
            &system,
            "SELECT password_hash AS x FROM user_account",
            None,
            false,
        )
        .await;
        let app = full_app(system);

        let status = execute_query(app, &admin_cookie, qid).await;
        assert_ne!(
            status,
            StatusCode::OK,
            "attome_readonly must not be able to SELECT password_hash under any alias — \
         a 200 here means the column-level grant (migration 0046) is missing or too broad"
        );
    })
}

/// Definition-of-done bullet: "A newly provisioned entity is queryable via
/// /api/v1/query/execute with no manual grant step." Provisions a brand-new
/// entity purely through the admin HTTP API (no direct grant statement
/// anywhere in this test) and executes a query against it immediately.
#[test]
fn freshly_provisioned_entity_is_queryable_with_zero_manual_grants() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let logicalname = format!("query_fresh_{}", Uuid::now_v7().simple());
        let qid = seed_query(
            &system,
            &format!("SELECT id FROM \"{logicalname}\" WHERE is_active = true"),
            None,
            false,
        )
        .await;
        let app = full_app(system);

        let _entity_id = create_entity(&app, &admin_cookie, &logicalname).await;

        let status = execute_query(app, &admin_cookie, qid).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a freshly provisioned entity table must be readable by attome_readonly \
         immediately, with no manual GRANT step (attome_metadata::provision::grant_readonly_select)"
        );
    })
}

/// Addendum §11(c) — `revalidate_all` immediately after a publish must be a
/// no-op: the plan hasn't had a chance to drift yet, so it must count as
/// `unchanged` and must not append a second `sql_query_version` row.
/// Live-verified against a real Postgres/Redis stack: this test's query
/// selects from `user_account`, which turned out to have no
/// `attome_readonly` grant in any environment at all (see `attome_security::
/// seed::register_readonly_entities`'s own doc comment) — fixed alongside
/// this test's own baseline-relative rewrite (a global `failed == 0`
/// assertion against this suite's shared, never-torn-down database was
/// itself fragile against whatever else already ran).
#[test]
fn revalidate_all_leaves_a_freshly_published_query_untouched() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);

        // `revalidate_all` scans every currently-published query platform-wide,
        // not just this test's own — and this integration suite shares one
        // long-lived database across many sequential tests that never tear down
        // their own stored queries. A prior test's query can legitimately fail
        // the lint later for reasons of its own (e.g. an entity a later test
        // altered), so asserting a global `failed == 0` is fragile against
        // whatever else has already run. A baseline call, taken before this
        // test's own query exists, isolates just the delta this test caused.
        let baseline =
            attome_records::query_admin::revalidate_all(&state.base.db_readonly, &state.base.db)
                .await
                .expect("baseline revalidate_all must succeed");

        let (status, body) =
            create_query_via_admin(app, &admin_cookie, "SELECT id FROM user_account").await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "publish must succeed: {body:?}"
        );
        let query_id: Uuid = body["id"]
            .as_str()
            .expect("published query response must carry an id")
            .parse()
            .expect("id must be a uuid");

        let versions_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sql_query_version WHERE query_id = $1")
                .bind(query_id)
                .fetch_one(&state.base.db)
                .await
                .expect("count versions");
        assert_eq!(
            versions_before, 1,
            "publish must write exactly one version row"
        );

        let summary =
            attome_records::query_admin::revalidate_all(&state.base.db_readonly, &state.base.db)
                .await
                .expect("revalidate_all must succeed");
        assert!(
            summary.failed <= baseline.failed,
            "the freshly published query must still pass the lint (baseline failed={}, now failed={})",
            baseline.failed,
            summary.failed,
        );
        assert!(
            summary.unchanged >= 1,
            "a plan that hasn't drifted must not count as revalidated"
        );

        let versions_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sql_query_version WHERE query_id = $1")
                .bind(query_id)
                .fetch_one(&state.base.db)
                .await
                .expect("count versions");
        assert_eq!(
            versions_after, 1,
            "revalidate_all must not append a version row when nothing has drifted"
        );
    })
}

/// Addendum §11(c) — a row that no longer passes the publish-time lint (its
/// referenced relation is gone/not an entity) must be skipped and counted as
/// `failed`, never propagated as an error that would abort every other
/// query's revalidation, and must never get a version row written for it.
/// `seed_query` bypasses the publish-time lint the same way every other
/// direct-insert test in this file does, so this plants an already-invalid
/// row without needing to provision then remove a real entity. NOT RUN this
/// session (no live Postgres/toolchain).
#[test]
fn revalidate_all_skips_a_query_that_no_longer_passes_the_lint() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let query_id = seed_query(&system, "SELECT id FROM refresh_token", None, false).await;
        let state = system.state().clone();

        let summary =
            attome_records::query_admin::revalidate_all(&state.base.db_readonly, &state.base.db)
                .await
                .expect("revalidate_all must not fail the whole run for one bad query");
        assert!(
            summary.failed >= 1,
            "a query referencing a non-entity relation must be counted as failed, not silently dropped"
        );

        let versions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sql_query_version WHERE query_id = $1")
                .bind(query_id)
                .fetch_one(&state.base.db)
                .await
                .expect("count versions");
        assert_eq!(
            versions, 0,
            "a query that never passed the lint must never get a version row written for it"
        );
    })
}

/// Cursor-default regression (plan §6): a bare request (no `after_id`, no
/// `include_total`) now runs in keyset/cursor mode by default — `total` is
/// absent — rather than the pre-phase-2 OFFSET-with-total default.
#[test]
fn bare_request_defaults_to_cursor_mode_not_offset_with_total() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let qid = seed_query(&system, "SELECT 1 AS id", None, false).await;
        let app = full_app(system);

        let body = execute_query_body(app, &admin_cookie, qid).await;
        assert_eq!(
            body["data"]["total"],
            serde_json::Value::Null,
            "an unset include_total must default to cursor mode (no total) now — \
         set config.query.cursor_default=false to restore the pre-phase-2 default"
        );
    })
}

/// D-133: single-entity stored queries are now record-level-scoped —
/// `execute`'s WHERE-clause construction splices `rls_predicate`'s fragment
/// in exactly like `entity_crud.rs`'s handlers, gated on
/// `entity_logical_name.is_some()` (the same D-057 single-entity marker
/// this file already resolves via `seed_entity_query`). Proves a
/// None-tier caller with no explicit share sees zero rows through a stored
/// query, then sees the row after an entity-default view share is granted
/// — the multi-entity/custom-SQL exclusion boundary itself is unchanged
/// (D-057, not re-tested here; `entity_logical_name.is_none()` queries
/// already have their own coverage in this file).
#[test]
fn stored_query_over_a_single_entity_respects_record_level_scoping() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();

        let logicalname = format!("rls_qexec_{}", Uuid::now_v7().simple());
        let app = full_app(system);
        let entity_id = create_entity(&app, &admin_cookie, &logicalname).await;

        // Seed one record directly via SQL rather than through the generic
        // entity_crud HTTP path: this test file's config doesn't set
        // `metadata_registry_enabled: false` (unlike entity_round_trip.rs), so
        // POST /api/v1/{logicalname} immediately after creating the entity
        // races the arc-swap metadata registry's ~250ms post-meta_version
        // refresh (documented in entity_round_trip.rs's own header) — direct
        // SQL sidesteps that race entirely and keeps this test focused on
        // query_exec.rs's RLS wiring, not registry propagation timing.
        let record_id = Uuid::now_v7();
        sqlx::query(&format!(
            "INSERT INTO \"{logicalname}\" (id, is_active) VALUES ($1, true)"
        ))
        .bind(record_id)
        .execute(&db)
        .await
        .expect("seed one record directly");

        let qid = seed_entity_query(
            &state,
            &format!("SELECT id FROM \"{logicalname}\" WHERE is_active = true"),
            entity_id,
            "[]",
        )
        .await;

        // Non-admin reader, narrowed to None-tier (no role → Global default
        // would bypass filtering entirely, same reasoning
        // record_level_security.rs's tests use throughout).
        let (reader_id, reader_cookie, role_id) = seed_rls_reader(&db, &logicalname).await;

        // seed_entity_query never sets required_privilege (defaults to admin-
        // only, D-036's opt-in gating) — this reader needs the query itself
        // opened up via its own read privilege to reach `execute` at all,
        // independent of the record-level scoping this test actually exercises.
        sqlx::query("UPDATE sql_query SET required_privilege = $1 WHERE id = $2")
            .bind(format!("{logicalname}.read"))
            .bind(qid)
            .execute(&db)
            .await
            .expect("open the query to the reader's privilege");
        sqlx::query(
            "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, 0, 0, 0, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(entity_id)
        .execute(&db)
        .await
        .expect("scope the reader role to None for this entity");
        security.invalidate(reader_id).await;

        let body = execute_query_body(app.clone(), &reader_cookie, qid).await;
        let rows = body["data"]["records"].as_array().expect("records array");
        assert_eq!(
            rows.len(),
            0,
            "a None-tier caller with no share must see zero rows through the \
         stored query, not the admin's record: {body:?}"
        );

        // Grant an entity-default view share and confirm the row now appears.
        sqlx::query(
        "INSERT INTO entity_default_share (entity_ref, principal_type, principal_id, capability, owner_layer) \
         VALUES ($1, 0, $2, 0, 'project')", // principal_type=user, capability=view
    )
    .bind(entity_id)
    .bind(reader_id)
    .execute(&db)
    .await
    .expect("insert entity default share");

        let body = execute_query_body(app, &reader_cookie, qid).await;
        let rows = body["data"]["records"].as_array().expect("records array");
        assert_eq!(
            rows.len(),
            1,
            "after granting a view default-share, the stored query must return \
         the record: {body:?}"
        );
    })
}

/// Seeds a non-admin user holding `{logicalname}.read` through a dedicated
/// role and returns the user id, session cookie, and role id. The privilege
/// must live on the same role as the per-entity depth: post-D-136, direct
/// grants intentionally resolve to Global and cannot be narrowed by a
/// separate role.
async fn seed_rls_reader(db: &sqlx::PgPool, logicalname: &str) -> (Uuid, String, Uuid) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("qexec-reader-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    let read_key = format!("{logicalname}.read");
    let privilege_id: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(&read_key)
    .fetch_one(db)
    .await
    .expect("ensure read privilege");

    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("rls-qexec-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant read privilege to test role");
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign reader role");

    (user_id, session_cookie(user_id), role_id)
}

// ── P-stored-query-containment Phase 3 (D-146): per-record filters for
// custom/multi-entity queries ────────────────────────────────────────────

/// Same as `create_query_via_admin` but exposes `required_privilege` and
/// `entity_mappings` — the two fields the bare helper's minimal JSON body
/// omits and this suite's multi-entity tests need to set at publish time.
async fn create_query_via_admin_full(
    app: axum::Router,
    admin_cookie: &str,
    sql_query: &str,
    required_privilege: Option<&str>,
    entity_mappings: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut body = serde_json::json!({
        "sql_query": sql_query,
        "entity_mappings": entity_mappings,
    });
    if let Some(p) = required_privilege {
        body["required_privilege"] = serde_json::json!(p);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/queries")
        .header("cookie", admin_cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let res = app.oneshot(req).await.expect("request");
    let status = res.status();
    (status, body_json(res).await)
}

/// Grants `role_id` read access to `entity_id` at `access_level` (0=None,
/// 1=Team, 2=BusinessUnit, 3=Global) — the same two-statement shape
/// `seed_rls_reader`/`stored_query_over_a_single_entity_respects_record_level_scoping`
/// already use inline, factored out here since the multi-entity tests below
/// need to scope a *second* entity onto the *same* role (post-D-136, the
/// privilege grant and the per-entity depth must live on one role).
async fn grant_entity_read_privilege_to_role(
    db: &sqlx::PgPool,
    role_id: Uuid,
    entity_id: Uuid,
    logicalname: &str,
) {
    let read_key = format!("{logicalname}.read");
    let privilege_id: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(&read_key)
    .fetch_one(db)
    .await
    .expect("ensure read privilege");
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project') \
         ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant read privilege to role");
    sqlx::query(
        "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, 0, 0, 0, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_id)
    .execute(db)
    .await
    .expect("scope role for entity");
}

/// Grants a bare privilege key (e.g. a query's own `required_privilege`,
/// which has no corresponding `entity_info` row to key off of the way
/// `grant_entity_read_privilege_to_role` does) to `role_id`, creating the
/// `privilege` row first if it doesn't already exist — a plain
/// `INSERT ... SELECT ... FROM privilege WHERE key = $N` silently
/// inserts nothing (not an error) if that row is missing, so this must run
/// before any such grant, not just before the role assignment.
async fn grant_role_privilege_key(db: &sqlx::PgPool, role_id: Uuid, privilege_key: &str) {
    let privilege_id: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(privilege_key)
    .fetch_one(db)
    .await
    .expect("ensure privilege");
    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project') \
         ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant privilege to role");
}

async fn grant_record_view_share(
    db: &sqlx::PgPool,
    entity_id: Uuid,
    record_id: Uuid,
    user_id: Uuid,
) {
    sqlx::query(
        "INSERT INTO record_share (id, record_id, entity_ref, principal_type, principal_id, capability, granted_at) \
         VALUES ($1, $2, $3, 0, $4, 0, NOW())", // principal_type=user, capability=view
    )
    .bind(Uuid::now_v7())
    .bind(record_id)
    .bind(entity_id)
    .bind(user_id)
    .execute(db)
    .await
    .expect("insert record share");
}

/// The core case: a two-entity cross join, both entities mapped, a reader
/// scoped None-tier on both with a record share on exactly one record from
/// each side — proves both predicates apply (AND semantics) and that
/// filtering is genuinely per-record, not just per-entity (a second,
/// unshared record on one side must never appear).
#[test]
fn multi_entity_query_with_full_mapping_filters_per_record_on_both_sides() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let admin_cookie = seed_admin(&system).await;

        let entity_a = format!("qexec_me_a_{}", Uuid::now_v7().simple());
        let entity_b = format!("qexec_me_b_{}", Uuid::now_v7().simple());
        let app = full_app(system);
        let entity_a_id = create_entity(&app, &admin_cookie, &entity_a).await;
        let entity_b_id = create_entity(&app, &admin_cookie, &entity_b).await;

        let rec_a1 = Uuid::now_v7();
        sqlx::query(&format!(
            "INSERT INTO \"{entity_a}\" (id, is_active) VALUES ($1, true)"
        ))
        .bind(rec_a1)
        .execute(&db)
        .await
        .expect("seed entity A record");

        let rec_b1 = Uuid::now_v7();
        let rec_b2 = Uuid::now_v7();
        for rec in [rec_b1, rec_b2] {
            sqlx::query(&format!(
                "INSERT INTO \"{entity_b}\" (id, is_active) VALUES ($1, true)"
            ))
            .bind(rec)
            .execute(&db)
            .await
            .expect("seed entity B record");
        }

        let report_key = format!("test.report.multi.{}", Uuid::now_v7());
        let (status, body) = create_query_via_admin_full(
        app.clone(),
        &admin_cookie,
        &format!(
            "SELECT a.id AS id, a.id AS a_id, b.id AS b_id FROM \"{entity_a}\" a, \"{entity_b}\" b \
             WHERE a.is_active = true AND b.is_active = true"
        ),
        Some(&report_key),
        serde_json::json!([
            {"entity": entity_a, "id_column": "a_id"},
            {"entity": entity_b, "id_column": "b_id"},
        ]),
    )
    .await;
        assert_eq!(status, StatusCode::CREATED, "publish failed: {body:?}");
        let qid = Uuid::parse_str(body["id"].as_str().expect("query id")).expect("query UUID");

        let (reader_id, reader_cookie, role_id) = seed_rls_reader(&db, &entity_a).await;
        // seed_rls_reader already scoped entity_a's own read privilege+role; the
        // reader also needs the query's own required_privilege to reach execute
        // at all, plus entity_b's read privilege+scope on the SAME role.
        sqlx::query(
            "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, 0, 0, 0, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(entity_a_id)
        .execute(&db)
        .await
        .expect("scope reader role to None for entity A");
        grant_entity_read_privilege_to_role(&db, role_id, entity_b_id, &entity_b).await;
        grant_role_privilege_key(&db, role_id, &report_key).await;
        security.invalidate(reader_id).await;

        // No shares yet — zero rows.
        let body = execute_query_body(app.clone(), &reader_cookie, qid).await;
        assert_eq!(
            body["data"]["records"].as_array().expect("records").len(),
            0,
            "a None-tier reader with no shares must see nothing yet: {body:?}"
        );

        // Share exactly one record on each side.
        grant_record_view_share(&db, entity_a_id, rec_a1, reader_id).await;
        grant_record_view_share(&db, entity_b_id, rec_b1, reader_id).await;

        let body = execute_query_body(app, &reader_cookie, qid).await;
        let records = body["data"]["records"].as_array().expect("records");
        assert_eq!(
            records.len(),
            1,
            "exactly one (a,b) pair is shared on both sides: {body:?}"
        );
        let row = &records[0]["b_id"];
        assert_eq!(
            row.as_str(),
            Some(rec_b1.to_string().as_str()),
            "the shared b-side record must be rec_b1, never the unshared rec_b2: {body:?}"
        );
    })
}

/// A relation with no declared mapping keeps the original all-or-nothing
/// gate even when a sibling relation in the same query IS mapped — strictly
/// additive, never less safe than before this plan.
#[test]
fn multi_entity_query_with_a_partially_mapped_relation_still_fails_closed() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let admin_cookie = seed_admin(&system).await;

        let entity_a = format!("qexec_pm_a_{}", Uuid::now_v7().simple());
        let entity_b = format!("qexec_pm_b_{}", Uuid::now_v7().simple());
        let app = full_app(system);
        let entity_a_id = create_entity(&app, &admin_cookie, &entity_a).await;
        let entity_b_id = create_entity(&app, &admin_cookie, &entity_b).await;

        let report_key = format!("test.report.partial.{}", Uuid::now_v7());
        let (status, body) = create_query_via_admin_full(
        app.clone(),
        &admin_cookie,
        &format!(
            "SELECT a.id AS id, a.id AS a_id, b.id AS b_id FROM \"{entity_a}\" a, \"{entity_b}\" b \
             WHERE a.is_active = true AND b.is_active = true"
        ),
        Some(&report_key),
        // Only entity_a is mapped — entity_b is referenced by the query but
        // has no declared id_column.
        serde_json::json!([{"entity": entity_a, "id_column": "a_id"}]),
    )
    .await;
        assert_eq!(status, StatusCode::CREATED, "publish failed: {body:?}");
        let qid = Uuid::parse_str(body["id"].as_str().expect("query id")).expect("query UUID");

        let (reader_id, reader_cookie, role_id) = seed_rls_reader(&db, &entity_a).await;
        sqlx::query(
            "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, 0, 0, 0, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(entity_a_id)
        .execute(&db)
        .await
        .expect("scope reader role to None for entity A");
        // None-tier on entity_b too — the unmapped relation this test exercises.
        grant_entity_read_privilege_to_role(&db, role_id, entity_b_id, &entity_b).await;
        grant_role_privilege_key(&db, role_id, &report_key).await;
        security.invalidate(reader_id).await;

        assert_eq!(
            execute_query(app, &reader_cookie, qid).await,
            StatusCode::FORBIDDEN,
            "entity_b has no declared mapping and the reader's access to it is \
         non-Global — the whole query must still fail closed, exactly as \
         before this plan, even though entity_a IS mapped"
        );
    })
}

/// Admin bypass is unaffected by mapping/scope — same as every other RLS
/// path in this codebase.
#[test]
fn multi_entity_query_admin_bypasses_mapping_and_scope() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let admin_cookie = seed_admin(&system).await;

        let entity_a = format!("qexec_admin_a_{}", Uuid::now_v7().simple());
        let app = full_app(system);
        let entity_a_id = create_entity(&app, &admin_cookie, &entity_a).await;
        let _ = entity_a_id;

        for _ in 0..2 {
            sqlx::query(&format!(
                "INSERT INTO \"{entity_a}\" (id, is_active) VALUES ($1, true)"
            ))
            .bind(Uuid::now_v7())
            .execute(&db)
            .await
            .expect("seed record");
        }

        let (status, body) = create_query_via_admin_full(
            app.clone(),
            &admin_cookie,
            &format!("SELECT a.id AS id FROM \"{entity_a}\" a WHERE a.is_active = true"),
            None,
            // Deliberately unmapped — an admin must still see every row.
            serde_json::json!([]),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "publish failed: {body:?}");
        let qid = Uuid::parse_str(body["id"].as_str().expect("query id")).expect("query UUID");

        let body = execute_query_body(app, &admin_cookie, qid).await;
        assert_eq!(
            body["data"]["records"].as_array().expect("records").len(),
            2,
            "admin must see every row regardless of mapping/scope: {body:?}"
        );
    })
}

/// Self-join: the same entity referenced twice under two id-column
/// mappings — proves `sql_query_entity_mapping`'s
/// `(query_version_id, entity_ref, id_column)` uniqueness (not
/// `(version, entity)`) actually lets two predicates apply for one entity,
/// both correctly gating the same underlying record.
#[test]
fn self_join_style_query_applies_both_id_column_mappings_for_the_same_entity() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let security = system.state().base.security.clone();
        let admin_cookie = seed_admin(&system).await;

        let entity_a = format!("qexec_self_{}", Uuid::now_v7().simple());
        let app = full_app(system);
        let entity_a_id = create_entity(&app, &admin_cookie, &entity_a).await;

        let rec = Uuid::now_v7();
        sqlx::query(&format!(
            "INSERT INTO \"{entity_a}\" (id, is_active) VALUES ($1, true)"
        ))
        .bind(rec)
        .execute(&db)
        .await
        .expect("seed record");

        let report_key = format!("test.report.selfjoin.{}", Uuid::now_v7());
        let (status, body) = create_query_via_admin_full(
        app.clone(),
        &admin_cookie,
        &format!(
            "SELECT a.id AS id, a.id AS mgr_id, a.id AS emp_id FROM \"{entity_a}\" a WHERE a.is_active = true"
        ),
        Some(&report_key),
        serde_json::json!([
            {"entity": entity_a, "id_column": "mgr_id"},
            {"entity": entity_a, "id_column": "emp_id"},
        ]),
    )
    .await;
        assert_eq!(status, StatusCode::CREATED, "publish failed: {body:?}");
        let qid = Uuid::parse_str(body["id"].as_str().expect("query id")).expect("query UUID");

        let (reader_id, reader_cookie, role_id) = seed_rls_reader(&db, &entity_a).await;
        sqlx::query(
            "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, 0, 0, 0, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(entity_a_id)
        .execute(&db)
        .await
        .expect("scope reader role to None");
        grant_role_privilege_key(&db, role_id, &report_key).await;
        security.invalidate(reader_id).await;

        let body = execute_query_body(app.clone(), &reader_cookie, qid).await;
        assert_eq!(
            body["data"]["records"].as_array().expect("records").len(),
            0,
            "no share yet — both mapped predicates must reject: {body:?}"
        );

        grant_record_view_share(&db, entity_a_id, rec, reader_id).await;

        let body = execute_query_body(app, &reader_cookie, qid).await;
        assert_eq!(
            body["data"]["records"].as_array().expect("records").len(),
            1,
            "one real record, shared once, satisfies both id-column predicates \
         since they both resolve to the same underlying row: {body:?}"
        );
    })
}

/// Publish-time validation, D-146 §3: each failure mode 422s naming the
/// problem, never silently drops the mapping.
#[test]
fn publish_rejects_entity_mappings_that_dont_validate() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let entity_a = format!("qexec_bad_map_{}", Uuid::now_v7().simple());
        let app = full_app(system);
        create_entity(&app, &admin_cookie, &entity_a).await;
        let sql = format!("SELECT a.id AS a_id FROM \"{entity_a}\" a WHERE a.is_active = true");

        // (1) id_column doesn't exist in the query's own output.
        let (status, body) = create_query_via_admin_full(
            app.clone(),
            &admin_cookie,
            &sql,
            None,
            serde_json::json!([{"entity": entity_a, "id_column": "does_not_exist"}]),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a nonexistent id_column must 422: {body:?}"
        );

        // (2) id_column exists but isn't uuid-castable.
        let sql_with_text_col = format!(
            "SELECT a.id AS a_id, 'not-a-uuid'::text AS label FROM \"{entity_a}\" a WHERE a.is_active = true"
        );
        let (status, body) = create_query_via_admin_full(
            app.clone(),
            &admin_cookie,
            &sql_with_text_col,
            None,
            serde_json::json!([{"entity": entity_a, "id_column": "label"}]),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a non-uuid-castable id_column must 422: {body:?}"
        );

        // (3) entity not referenced by the query's own relations.
        let other_entity = format!("qexec_bm_other_{}", Uuid::now_v7().simple());
        create_entity(&app, &admin_cookie, &other_entity).await;
        let (status, body) = create_query_via_admin_full(
            app.clone(),
            &admin_cookie,
            &sql,
            None,
            serde_json::json!([{"entity": other_entity, "id_column": "a_id"}]),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "mapping an entity the query never references must 422: {body:?}"
        );
    })
}

/// C-19 (M01-core.md §7): `PATCH /api/v1/admin/queries/{id}` now honors an
/// optional `If-Match: "<row_version>"` (migration 0443 added the column;
/// `attome-records/src/query_admin.rs`'s `republish_query` turns it into a
/// real `WHERE ... AND row_version = $expected` guard, not a check-then-write
/// race). Additive: a caller that never sends the header keeps working
/// exactly as before (covered implicitly by every other `create_query_via_
/// admin`/PATCH-less test in this file); this test covers the guard itself —
/// a stale `If-Match` on a concurrent update must be rejected with 409
/// `version_conflict`, and the record must be left exactly as the winning
/// write left it, never the loser's payload.
#[test]
fn stale_if_match_on_stored_query_update_is_a_409() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let (created_status, created) =
            create_query_via_admin(app.clone(), &admin_cookie, "SELECT 1 AS id").await;
        assert_eq!(created_status, StatusCode::CREATED, "{created:?}");
        let query_id = created["id"].as_str().expect("query id");
        let v0 = created["row_version"]
            .as_i64()
            .expect("row_version present on create");
        assert_eq!(v0, 0, "a freshly published query starts at row_version 0");

        // The first PATCH carries the correct (current) version and succeeds,
        // bumping row_version.
        let first_patch = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/admin/queries/{query_id}"))
            .header("cookie", &admin_cookie)
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json")
            .header("if-match", format!("\"{v0}\""))
            .body(Body::from(
                serde_json::json!({ "sql_query": "SELECT 2 AS id" }).to_string(),
            ))
            .unwrap();
        let res = app.clone().oneshot(first_patch).await.expect("first patch");
        assert_eq!(res.status(), StatusCode::OK, "the first PATCH must succeed");
        let first_updated = body_json(res).await;
        let v1 = first_updated["row_version"]
            .as_i64()
            .expect("row_version present on update");
        assert_eq!(
            v1,
            v0 + 1,
            "a successful PATCH bumps row_version by exactly 1"
        );

        // A second PATCH replaying the now-stale `v0` — simulating a concurrent
        // writer that read the query before the first PATCH committed — must be
        // rejected as a version conflict, not silently applied on top of the
        // winner's write.
        let stale_patch = Request::builder()
            .method("PATCH")
            .uri(format!("/api/v1/admin/queries/{query_id}"))
            .header("cookie", &admin_cookie)
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json")
            .header("if-match", format!("\"{v0}\""))
            .body(Body::from(
                serde_json::json!({ "sql_query": "SELECT 3 AS id" }).to_string(),
            ))
            .unwrap();
        let res = app.clone().oneshot(stale_patch).await.expect("stale patch");
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "a stale If-Match must be rejected with 409"
        );
        let err = body_json(res).await;
        assert_eq!(err["error"], "version_conflict");

        // The record is untouched by the rejected stale attempt — still at the
        // winner's version and content.
        let get_req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/admin/queries/{query_id}"))
            .header("cookie", &admin_cookie)
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(get_req).await.expect("get query");
        assert_eq!(res.status(), StatusCode::OK);
        let fetched = body_json(res).await;
        assert_eq!(fetched["row_version"].as_i64(), Some(v1));
        assert_eq!(fetched["sql_query"], "SELECT 2 AS id");
    })
}

// ── D-521: pinned query versions ─────────────────────────────────────────────
//
// A published dashboard widget executes the exact query version its snapshot
// pinned. The pin selects SQL only: the query must still be active, and every
// authorization gate (required_privilege, entity read, record scope) runs
// exactly as it does for an unpinned call.

async fn execute_status(app: axum::Router, cookie: &str, body: serde_json::Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/query/execute")
        .header("cookie", cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    app.oneshot(req).await.expect("request").status()
}

async fn publish_query(app: &axum::Router, admin_cookie: &str, sql: &str) -> Uuid {
    let (published, body) = create_query_via_admin(app.clone(), admin_cookie, sql).await;
    assert_eq!(
        published,
        StatusCode::CREATED,
        "publish query failed: {body:?}"
    );
    Uuid::parse_str(body["id"].as_str().expect("query id")).expect("query UUID")
}

async fn latest_query_version(db: &sqlx::PgPool, query_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM sql_query_version WHERE query_id = $1 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(query_id)
    .fetch_one(db)
    .await
    .expect("a published query has a version")
}

#[test]
fn a_pinned_version_runs_the_sql_it_was_published_with() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let qid = publish_query(&app, &admin_cookie, "SELECT 1 AS id").await;
        let v1 = latest_query_version(&db, qid).await;

        // A later edit changes the query's live SQL and records a new version.
        sqlx::query("UPDATE sql_query SET sql_query = 'SELECT 2 AS id' WHERE id = $1")
            .bind(qid)
            .execute(&db)
            .await
            .expect("edit the live query SQL");
        sqlx::query(
            "INSERT INTO sql_query_version (query_id, sql_query, cost_estimate) \
         VALUES ($1, 'SELECT 2 AS id', 1.0)",
        )
        .bind(qid)
        .execute(&db)
        .await
        .expect("record the new version");

        let pinned = execute_body(
            app.clone(),
            &admin_cookie,
            serde_json::json!({ "query_id": qid, "query_version_id": v1 }),
        )
        .await;
        assert_eq!(
            pinned["data"]["records"][0]["id"],
            serde_json::json!(1),
            "the pinned call must run version 1's SQL: {pinned:?}"
        );
        let live = execute_body(app, &admin_cookie, serde_json::json!({ "query_id": qid })).await;
        assert_eq!(
            live["data"]["records"][0]["id"],
            serde_json::json!(2),
            "an unpinned call runs the query's current SQL: {live:?}"
        );
    })
}

#[test]
fn a_version_of_another_query_cannot_be_pinned() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let first = publish_query(&app, &admin_cookie, "SELECT 1 AS id").await;
        let second = publish_query(&app, &admin_cookie, "SELECT 2 AS id").await;
        let second_version = latest_query_version(&db, second).await;

        assert_eq!(
            execute_status(
                app,
                &admin_cookie,
                serde_json::json!({ "query_id": first, "query_version_id": second_version }),
            )
            .await,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    })
}

#[test]
fn a_pinned_version_of_a_deactivated_query_does_not_run() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let qid = publish_query(&app, &admin_cookie, "SELECT 1 AS id").await;
        let v1 = latest_query_version(&db, qid).await;
        sqlx::query("UPDATE sql_query SET is_active = false WHERE id = $1")
            .bind(qid)
            .execute(&db)
            .await
            .expect("deactivate the query");

        assert_eq!(
            execute_status(
                app,
                &admin_cookie,
                serde_json::json!({ "query_id": qid, "query_version_id": v1 }),
            )
            .await,
            StatusCode::NOT_FOUND
        );
    })
}

#[test]
fn pinning_a_version_does_not_bypass_required_privilege() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let key = format!("test.pinned.view.{}", Uuid::now_v7());
        let unrelated_key = format!("test.pinned.unrelated.{}", Uuid::now_v7());
        let holder_cookie = seed_user_with_privilege(&system, &key).await;
        let stranger_cookie = seed_user_with_privilege(&system, &unrelated_key).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let qid = publish_query(&app, &admin_cookie, "SELECT 1 AS id").await;
        let v1 = latest_query_version(&db, qid).await;
        sqlx::query("UPDATE sql_query SET required_privilege = $1 WHERE id = $2")
            .bind(&key)
            .bind(qid)
            .execute(&db)
            .await
            .expect("open the query to the throwaway privilege");

        let pinned = serde_json::json!({ "query_id": qid, "query_version_id": v1 });
        assert_eq!(
            execute_status(app.clone(), &holder_cookie, pinned.clone()).await,
            StatusCode::OK
        );
        assert_eq!(
            execute_status(app, &stranger_cookie, pinned).await,
            StatusCode::FORBIDDEN,
            "a revoked or missing privilege still refuses a pinned execution"
        );
    })
}

// ── D-607 (B-R10 Phase A): advanced find — saved view filters ──────────────

/// One JSON request through the full app, returning the status and the body
/// (`Null` for an empty or non-JSON body).
async fn send_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(if body.is_null() {
            Body::empty()
        } else {
            Body::from(body.to_string())
        })
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("request");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

async fn create_record(
    app: &axum::Router,
    admin_cookie: &str,
    logicalname: &str,
    data: serde_json::Value,
) {
    let (status, created) = send_json(
        app,
        "POST",
        &format!("/api/v1/{logicalname}"),
        admin_cookie,
        data,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create record failed: {created:?}"
    );
}

/// An entity-scoped list query over `columns`, open to `{entity}.read`. The
/// seeded default query selects only `id` (plus the display column once one
/// is set), and `query/execute` only filters on columns its query returns.
async fn list_query(
    state: &EngineState,
    entity_id: Uuid,
    logicalname: &str,
    columns: &str,
) -> Uuid {
    let id = seed_entity_query(
        state,
        &format!("SELECT {columns} FROM \"{logicalname}\" WHERE is_active = true"),
        entity_id,
        "[]",
    )
    .await;
    sqlx::query("UPDATE sql_query SET required_privilege = $1 WHERE id = $2")
        .bind(format!("{logicalname}.read"))
        .bind(id)
        .execute(&state.base.db)
        .await
        .expect("open the list query to the entity read privilege");
    id
}

/// Sorted record ids of one `query/execute` page.
fn record_ids(body: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = body["data"]["records"]
        .as_array()
        .expect("records array")
        .iter()
        .map(|r| r["id"].as_str().expect("record id").to_owned())
        .collect();
    ids.sort();
    ids
}

/// An entity with a single-select `status` choice and a `title` text field,
/// and three records: `(red, alpha)`, `(green, beta)`, `(green, gamma)`.
async fn seed_advanced_find_entity(
    app: &axum::Router,
    state: &EngineState,
    admin_cookie: &str,
    prefix: &str,
) -> (Uuid, String) {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let entity_id = create_entity(app, admin_cookie, &logicalname).await;
    create_choice_field(app, admin_cookie, entity_id, "status", false).await;
    create_text_field(app, admin_cookie, entity_id, "title").await;
    sync_registry(state).await;
    for (status, title) in [("red", "alpha"), ("green", "beta"), ("green", "gamma")] {
        create_record(
            app,
            admin_cookie,
            &logicalname,
            serde_json::json!({ "status": status, "title": title }),
        )
        .await;
    }
    (entity_id, logicalname)
}

fn personal_view_body(
    name: &str,
    logicalname: &str,
    query_id: Uuid,
    filters: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "entity": logicalname,
        "sql_query_ref": query_id,
        "kind": "list",
        "view_metadata": { "filters": filters },
    })
}

/// B-R10 Phase A: filters saved in a personal view's `view_metadata.filters`
/// come back unchanged from `GET /api/v1/views`, and sending them with the
/// view to `query/execute` returns exactly the rows the same filters return
/// on the entity's own default query. Also covers `starts_with`, one of the
/// four operators D-607 added to the shared compiler.
#[test]
fn advanced_find_saved_view_replays_the_same_rows() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);
        let (entity_id, logicalname) =
            seed_advanced_find_entity(&app, &state, &admin_cookie, "advfind_replay").await;
        let query_id = list_query(&state, entity_id, &logicalname, "id, status, title").await;

        let filters = serde_json::json!([
            { "field": "status", "op": "eq", "value": "green" },
            { "field": "title", "op": "starts_with", "value": "g" },
        ]);
        let (status, direct) = send_json(
            &app,
            "POST",
            "/api/v1/query/execute",
            &admin_cookie,
            serde_json::json!({ "query_id": query_id, "filters": filters, "include_total": true }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "direct execute: {direct:?}");
        let direct_ids = record_ids(&direct);
        assert_eq!(
            direct_ids.len(),
            1,
            "only (green, gamma) matches: {direct:?}"
        );

        let (status, created) = send_json(
            &app,
            "POST",
            "/api/v1/views",
            &admin_cookie,
            personal_view_body("Green g-titles", &logicalname, query_id, filters.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "save view: {created:?}");
        let view_id = created["id"].as_str().expect("view id").to_owned();

        let (status, views) = send_json(
            &app,
            "GET",
            &format!("/api/v1/views?entity={logicalname}"),
            &admin_cookie,
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let saved = views
            .as_array()
            .expect("views")
            .iter()
            .find(|v| v["id"] == view_id.as_str())
            .expect("the saved view is listed for its owner")
            .clone();
        assert_eq!(saved["view_metadata"]["filters"], filters);

        let (status, replayed) = send_json(
            &app,
            "POST",
            "/api/v1/query/execute",
            &admin_cookie,
            serde_json::json!({
                "view_id": view_id,
                "filters": saved["view_metadata"]["filters"],
                "include_total": true,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "replay: {replayed:?}");
        assert_eq!(record_ids(&replayed), direct_ids);
        assert_eq!(replayed["data"]["total"], 1);
    })
}

/// B-R10 Phase A validation: more than 50 conditions, a field that is not an
/// attribute of the view's entity, an operator the field's type does not
/// take, an unknown operator and a non-array `filters` are each a 422;
/// exactly 50 valid conditions save.
#[test]
fn view_metadata_filters_are_validated() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let app = full_app(system);
        let (entity_id, logicalname) =
            seed_advanced_find_entity(&app, &state, &admin_cookie, "advfind_valid").await;
        let query_id = list_query(&state, entity_id, &logicalname, "id, status, title").await;
        let condition = serde_json::json!({ "field": "status", "op": "eq", "value": "red" });

        let (status, body) = send_json(
            &app,
            "POST",
            "/api/v1/views",
            &admin_cookie,
            personal_view_body(
                "fifty-one",
                &logicalname,
                query_id,
                serde_json::json!(vec![condition.clone(); 51]),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "51 conditions: {body:?}"
        );

        let (status, body) = send_json(
            &app,
            "POST",
            "/api/v1/views",
            &admin_cookie,
            personal_view_body(
                "fifty",
                &logicalname,
                query_id,
                serde_json::json!(vec![condition.clone(); 50]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "50 conditions: {body:?}");

        let rejected = [
            (
                "unknown field",
                serde_json::json!([{ "field": "no_such_field", "op": "eq", "value": "x" }]),
            ),
            (
                "a system column is not an attribute",
                serde_json::json!([{ "field": "id", "op": "is_null" }]),
            ),
            (
                "op not valid for a single-select choice",
                serde_json::json!([{ "field": "status", "op": "contains_any", "value": ["red"] }]),
            ),
            (
                "unknown op",
                serde_json::json!([{ "field": "title", "op": "sounds_like", "value": "x" }]),
            ),
            ("not an array", serde_json::json!({ "field": "title" })),
        ];
        for (label, filters) in rejected {
            let (status, body) = send_json(
                &app,
                "POST",
                "/api/v1/views",
                &admin_cookie,
                personal_view_body(label, &logicalname, query_id, filters),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{label}: {body:?}"
            );
        }
    })
}

/// B-R10 Phase A / D-607: a filter on a field the caller cannot read is
/// REFUSED, never silently dropped (dropping it would widen the result to
/// rows the caller did not ask for). `query/execute` answers 422 "unknown
/// filter field" — the same answer as a field that does not exist — and
/// saving a view with that filter is refused the same way. The admin, who
/// can read the field, gets the filtered row, so the refusal is about the
/// caller and not the field.
#[test]
fn filter_on_an_unreadable_field_is_refused_not_ignored() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let logicalname = format!("advfind_secret_{}", Uuid::now_v7().simple());
        let entity_id = create_entity(&app, &admin_cookie, &logicalname).await;
        create_text_field(&app, &admin_cookie, entity_id, "title").await;
        let (status, created) = send_json(
            &app,
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            &admin_cookie,
            serde_json::json!({
                "logicalname": "secret", "name": "secret", "field_type": "text",
                "max_length": 100, "is_sensitive": true,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "sensitive field: {created:?}");
        sync_registry(&state).await;
        for (title, secret) in [("one", "x"), ("two", "y")] {
            create_record(
                &app,
                &admin_cookie,
                &logicalname,
                serde_json::json!({ "title": title, "secret": secret }),
            )
            .await;
        }
        let (_reader_id, reader_cookie, _role) = seed_rls_reader(&db, &logicalname).await;
        let query_id = list_query(&state, entity_id, &logicalname, "id, title, secret").await;
        let secret_filter = serde_json::json!([{ "field": "secret", "op": "eq", "value": "x" }]);

        let (status, admin_body) = send_json(
        &app,
        "POST",
        "/api/v1/query/execute",
        &admin_cookie,
        serde_json::json!({ "query_id": query_id, "filters": secret_filter, "include_total": true }),
    )
    .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "admin filter on secret: {admin_body:?}"
        );
        assert_eq!(admin_body["data"]["total"], 1);

        let (status, unfiltered) = send_json(
            &app,
            "POST",
            "/api/v1/query/execute",
            &reader_cookie,
            serde_json::json!({ "query_id": query_id, "include_total": true }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the reader can run the view: {unfiltered:?}"
        );
        assert_eq!(unfiltered["data"]["total"], 2);

        let (status, refused) = send_json(
        &app,
        "POST",
        "/api/v1/query/execute",
        &reader_cookie,
        serde_json::json!({ "query_id": query_id, "filters": secret_filter, "include_total": true }),
    )
    .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a filter on an unreadable field must be refused, not ignored: {refused:?}"
        );
        assert!(
            refused.to_string().contains("unknown filter field"),
            "the refusal masks the field as unknown: {refused:?}"
        );

        let (status, body) = send_json(
            &app,
            "POST",
            "/api/v1/views",
            &reader_cookie,
            personal_view_body("secret view", &logicalname, query_id, secret_filter.clone()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "saving a filter on an unreadable field: {body:?}"
        );
        let (status, body) = send_json(
            &app,
            "POST",
            "/api/v1/views",
            &reader_cookie,
            personal_view_body(
                "title view",
                &logicalname,
                query_id,
                serde_json::json!([{ "field": "title", "op": "eq", "value": "one" }]),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "saving a filter on a readable field: {body:?}"
        );
    })
}

// ── AA7-T3: ETags ────────────────────────────────────────────────────────────

/// An admin user and their session cookie.
async fn seed_admin_with_id(system: &TestSystem) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("query-etag-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert etag admin");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin is seeded");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant etag admin");
    (user_id, session_cookie(user_id))
}

/// An entity with a `title` field, one record, and a stored query over it.
/// Returns (logical name, query id, record id).
async fn etag_fixture(
    system: &TestSystem,
    app: &axum::Router,
    cookie: &str,
) -> (String, Uuid, Uuid) {
    let logicalname = format!("etag_{}", &Uuid::now_v7().simple().to_string()[20..]);
    let entity_id = create_entity(app, cookie, &logicalname).await;
    create_text_field(app, cookie, entity_id, "title").await;
    sync_registry(system.state()).await;
    let record_id = create_titled_record(app, cookie, &logicalname, "first").await;
    let qid = seed_entity_query(
        system.state(),
        &format!("SELECT id, title FROM \"{logicalname}\" WHERE is_active = true"),
        entity_id,
        "[]",
    )
    .await;
    (logicalname, qid, record_id)
}

async fn create_titled_record(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    title: &str,
) -> Uuid {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "title": title }).to_string(),
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create record");
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create record failed: {body:?}"
    );
    Uuid::parse_str(body["id"].as_str().expect("record id")).expect("record UUID")
}

/// Runs the query, optionally with `If-None-Match`; (status, ETag, body).
async fn execute_conditional(
    app: &axum::Router,
    cookie: &str,
    query_id: Uuid,
    if_none_match: Option<&str>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/query/execute")
        .header("cookie", cookie)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        // A fresh run each time, not the five-second repeat cache.
        .header("cache-control", "no-cache");
    if let Some(tag) = if_none_match {
        req = req.header("if-none-match", tag);
    }
    let req = req
        .body(Body::from(format!(r#"{{"query_id":"{query_id}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("request");
    let status = res.status();
    let etag = res
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, etag, bytes)
}

#[test]
fn list_etag_unchanged_returns_304() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_admin_with_id(&system).await;
        let app = system.app.clone();
        let (_, qid, _) = etag_fixture(&system, &app, &cookie).await;

        let (status, etag, _) = execute_conditional(&app, &cookie, qid, None).await;
        assert_eq!(status, StatusCode::OK);
        let etag = etag.expect("an entity query answers with an ETag");
        assert!(etag.starts_with("W/\""), "{etag}");

        let (status, again, body) = execute_conditional(&app, &cookie, qid, Some(&etag)).await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert_eq!(again.as_deref(), Some(etag.as_str()));
        assert!(body.is_empty(), "a 304 has no body");
    })
}

#[test]
fn list_etag_changes_after_write() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_admin_with_id(&system).await;
        let app = system.app.clone();
        let (logicalname, qid, _) = etag_fixture(&system, &app, &cookie).await;
        let (_, before, _) = execute_conditional(&app, &cookie, qid, None).await;
        let before = before.expect("etag");

        create_titled_record(&app, &cookie, &logicalname, "second").await;

        let (status, after, body) = execute_conditional(&app, &cookie, qid, Some(&before)).await;
        assert_eq!(status, StatusCode::OK, "a write changes the answer");
        assert_ne!(after.as_deref(), Some(before.as_str()));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            body["data"]["records"].as_array().map(Vec::len),
            Some(2),
            "{body}"
        );
    })
}

#[test]
fn list_etag_changes_after_role_change() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, cookie) = seed_admin_with_id(&system).await;
        let app = system.app.clone();
        let (_, qid, _) = etag_fixture(&system, &app, &cookie).await;
        let (_, before, _) = execute_conditional(&app, &cookie, qid, None).await;
        let before = before.expect("etag");

        // A new privilege for the same user changes their permission set.
        let db = &system.state().base.db;
        let key = format!("test.etag.{}", Uuid::now_v7());
        let privilege_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) \
             VALUES ($1, $2, $2, true, NOW(), 'project')",
        )
        .bind(privilege_id)
        .bind(&key)
        .execute(db)
        .await
        .expect("insert privilege");
        sqlx::query(
            "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
             VALUES ($1, $2, $3, true, NOW())",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("grant privilege");
        system.state().base.security.invalidate(user_id).await;

        let (status, after, _) = execute_conditional(&app, &cookie, qid, Some(&before)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a permission change is a new answer"
        );
        assert_ne!(after.as_deref(), Some(before.as_str()));
    })
}

#[test]
fn list_etag_deleted_record_returns_200() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, cookie) = seed_admin_with_id(&system).await;
        let app = system.app.clone();
        let (logicalname, qid, record_id) = etag_fixture(&system, &app, &cookie).await;
        let (_, before, _) = execute_conditional(&app, &cookie, qid, None).await;
        let before = before.expect("etag");

        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/{logicalname}/{record_id}"))
            .header("cookie", &cookie)
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("delete");
        assert!(res.status().is_success(), "delete failed: {}", res.status());

        let (status, _, body) = execute_conditional(&app, &cookie, qid, Some(&before)).await;
        assert_eq!(status, StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(
            body["data"]["records"].as_array().map(Vec::len),
            Some(0),
            "{body}"
        );
    })
}

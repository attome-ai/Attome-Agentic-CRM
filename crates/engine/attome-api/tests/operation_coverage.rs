//! Q10-T13: every engine checks the operation it performs, not only reading.
//! A role can let someone read an entity's records and still withhold
//! exporting, bulk-changing, reassigning or sharing them (Q10-T12's operation
//! levels). Each test gives a user `{entity}.read` and the operation's
//! privilege through a role whose level for that operation is None, expects
//! 403, then raises the level and expects the same call admitted.
//!
//! ```powershell
//! cargo test -p attome-api --test operation_coverage -- --test-threads=1
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

// ── Harness (copied near-verbatim from bulk_mutation.rs) ────────────────────

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
                "migrator": {{ "user": "{db_user}", "password": "{db_password}" }},
                "readonly": {{ "user": "attome_readonly", "password": "{readonly_password}" }}
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
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
        readonly_password = READONLY_PASSWORD,
        // `TEST_S3_ENDPOINT` moves the object store off the dev store's port.
        s3_endpoint =
            std::env::var("TEST_S3_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into()),
        s3_access_key = attome_testkit::s3_env("S3_ACCESS_KEY"),
        s3_secret_key = attome_testkit::s3_env("S3_SECRET_KEY"),
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// The `attome_readonly` login this suite sets, for the long pool (AB6-T6).
const READONLY_PASSWORD: &str = "test-only-readonly-password";

/// Gives `attome_readonly` a login with [`READONLY_PASSWORD`] (the role
/// exists from the migrations; only its password is per test database).
async fn synchronize_readonly_login(db: &attome_db::DbPool) {
    sqlx::query(&format!(
        "ALTER ROLE attome_readonly WITH LOGIN PASSWORD '{READONLY_PASSWORD}'"
    ))
    .execute(db)
    .await
    .expect("give attome_readonly a test login");
}

async fn test_system() -> Option<EngineSystem> {
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
    // AB6-T6: exports read through the long pool, as at boot.
    synchronize_readonly_login(&db).await;
    let db_long = attome_db::create_long_pool(&config)
        .await
        .expect("connect the long pool");
    let base = AppState::new(
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    )
    .with_long_pool(db_long);
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

async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("opcov-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("opcov-test-{user_id}"))
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

async fn seed_non_admin_user(db: &attome_db::DbPool) -> (Uuid, String, String) {
    let user_id = Uuid::now_v7();
    let email = format!("opcov-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("opcov-test-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email, session_cookie(user_id))
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
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

/// Creates an entity with one record in it (as `admin_cookie`).
async fn entity_with_record(app: &axum::Router, admin_cookie: &str) -> (String, Uuid, Uuid) {
    let logicalname = format!("opcov_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({ "logicalname": logicalname, "name": "Operation Coverage" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin_cookie,
            Some(&json!({ "logicalname": "title", "name": "Title", "field_type": "text" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create field");
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{logicalname}"),
            admin_cookie,
            Some(&json!({ "title": "one" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create record");
    let record_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    (logicalname, entity_id, record_id)
}

/// A user holding `privileges` through one role whose levels on the entity
/// are Global for read, update and delete and `level` for `operation`
/// (`export`, `bulk`, `assign` or `share`). The role keeps operation levels
/// apart (`bulk_field_mode = 1`), so export and bulk do not fall back to the
/// read and update levels.
async fn role_user(
    db: &attome_db::DbPool,
    entity_id: Uuid,
    privileges: &[String],
    operation: &str,
    level: i16,
) -> (Uuid, String, String, Uuid) {
    let (user_id, email, cookie) = seed_non_admin_user(db).await;
    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, bulk_field_mode, owner_layer) VALUES ($1, $2, 1, 'project')",
    )
    .bind(role_id)
    .bind(format!("opcov-{role_id}"))
    .execute(db)
    .await
    .expect("insert role");
    for key in privileges {
        sqlx::query(
            "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer) \
             VALUES ($1, $2, $2, true, NOW(), 'project') ON CONFLICT (key) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(key)
        .execute(db)
        .await
        .expect("ensure privilege");
        sqlx::query(
            "INSERT INTO role_mm_privilege (role_ref, privilege_ref, owner_layer) \
             SELECT $1, id, 'project' FROM privilege WHERE key = $2",
        )
        .bind(role_id)
        .bind(key)
        .execute(db)
        .await
        .expect("grant privilege to role");
    }
    let column = level_column(operation);
    sqlx::query(&format!(
        "INSERT INTO role_mm_entity_access \
             (role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, \
              {column}, owner_layer) \
         VALUES ($1, $2, 3, 3, 3, $3, 'project')"
    ))
    .bind(role_id)
    .bind(entity_id)
    .bind(level)
    .execute(db)
    .await
    .expect("insert entity access");
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role");
    (user_id, email, cookie, role_id)
}

fn level_column(operation: &str) -> &'static str {
    match operation {
        "export" => "export_access_level",
        "bulk" => "bulk_access_level",
        "assign" => "assign_access_level",
        "share" => "share_access_level",
        other => panic!("unknown operation {other}"),
    }
}

/// Raises the role's level for `operation` to Global. The level is read from
/// the database on each call, so no cache stands between this and the API.
async fn raise(db: &attome_db::DbPool, role_id: Uuid, operation: &str) {
    sqlx::query(&format!(
        "UPDATE role_mm_entity_access SET {} = 3 WHERE role_ref = $1",
        level_column(operation)
    ))
    .bind(role_id)
    .execute(db)
    .await
    .expect("raise level");
}

async fn status_of(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Value,
) -> StatusCode {
    app.clone()
        .oneshot(req(method, uri, cookie, Some(&body)))
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn export_requires_export_level() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, entity_id, _) = entity_with_record(&app, &admin_cookie).await;
    let (_, _, cookie, role) =
        role_user(&db, entity_id, &[format!("{entity}.read")], "export", 0).await;

    let uri = format!("/api/v1/{entity}/export");
    let body = json!({ "format": "csv" });
    assert_eq!(
        status_of(&app, "POST", &uri, &cookie, body.clone()).await,
        StatusCode::FORBIDDEN,
        "read Global, export None"
    );
    raise(&db, role, "export").await;
    assert_eq!(
        status_of(&app, "POST", &uri, &cookie, body).await,
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
async fn bulk_requires_bulk_level() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, entity_id, record) = entity_with_record(&app, &admin_cookie).await;
    let privileges = ["read", "update", "bulk"].map(|a| format!("{entity}.{a}"));
    let (_, _, cookie, role) = role_user(&db, entity_id, &privileges, "bulk", 0).await;

    let uri = format!("/api/v1/{entity}/bulk");
    let body = json!({
        "operation": "update",
        "records": [{ "id": record, "expected_row_version": 0, "data": { "title": "two" } }],
    });
    assert_eq!(
        status_of(&app, "POST", &uri, &cookie, body.clone()).await,
        StatusCode::FORBIDDEN,
        "update Global, bulk None"
    );
    raise(&db, role, "bulk").await;
    assert_ne!(
        status_of(&app, "POST", &uri, &cookie, body).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn assign_requires_assign_level() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, entity_id, record) = entity_with_record(&app, &admin_cookie).await;
    let privileges = [
        format!("{entity}.read"),
        format!("{entity}.update"),
        "admin.security".to_owned(),
    ];
    let (_, email, cookie, role) = role_user(&db, entity_id, &privileges, "assign", 0).await;

    let uri = "/api/v1/admin/security/record-shares/reassign-owner";
    let body = json!({ "entity": entity, "record_id": record, "user_email": email });
    assert_eq!(
        status_of(&app, "PUT", uri, &cookie, body.clone()).await,
        StatusCode::FORBIDDEN,
        "the Security area without an assign level"
    );
    raise(&db, role, "assign").await;
    assert_eq!(
        status_of(&app, "PUT", uri, &cookie, body).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn share_requires_share_level() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let (admin_id, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, entity_id, record) = entity_with_record(&app, &admin_cookie).await;
    let privileges = ["read", "share"].map(|a| format!("{entity}.{a}"));
    let (_, _, cookie, role) = role_user(&db, entity_id, &privileges, "share", 0).await;

    let uri = format!("/api/v1/{entity}/{record}/shares");
    let body = json!({ "capability": "view", "user_id": admin_id });
    assert_eq!(
        status_of(&app, "POST", &uri, &cookie, body.clone()).await,
        StatusCode::FORBIDDEN,
        "read Global, share None"
    );
    raise(&db, role, "share").await;
    assert_eq!(
        status_of(&app, "POST", &uri, &cookie, body).await,
        StatusCode::CREATED
    );
}

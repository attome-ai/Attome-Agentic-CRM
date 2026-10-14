//! P0 0.7 (M69 S3) — the bespoke decision routes
//! (`POST /api/v1/project/change-request/{id}/approve|reject`,
//! `POST /api/v1/project/timesheet/{id}/approve|reject`) write `status`
//! through the state engine's update path, so:
//! - an `.update`-only holder is refused (403) — approving is not a status edit;
//! - the requester / the timesheet's own user cannot decide their own (422,
//!   the `current_user` transition guard);
//! - a `Project Approver` succeeds, and the approval is stamped.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`). No approval policy is configured, so `gate()` lets the
//! decision through immediately.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-project --test decision_routes -- --test-threads=1
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
use attome_testkit::skip_if_no_db;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config(db_url: &str) -> AppConfig {
    let rest = db_url
        .strip_prefix("postgres://")
        .or_else(|| db_url.strip_prefix("postgresql://"))
        .expect("DATABASE_URL must be a postgres:// URL");
    let (userinfo, rest) = rest.split_once('@').expect("URL must carry user@host");
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let (hostport, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = hostport.split_once(':').unwrap_or((hostport, "5432"));
    let dbname = path.split(['?', '#']).next().unwrap_or(path);
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
                "host": "{host}", "port": {port}, "dbname": "{dbname}",
                "user": "{user}", "password": "{password}", "schema": "attome_dev",
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
        port = port.parse::<u16>().unwrap_or(5432),
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
    let db_url = attome_testkit::migrated_db_url()?;
    let config = test_config(&db_url);
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
        .register(attome_state::StateModel)
        .register(attome_project::ProjectModel)
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
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

async fn seed_user(db: &attome_db::DbPool) -> (Uuid, String) {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("decide-{id}@test.local"))
    .bind(format!("decide-{id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    (id, session_cookie(id))
}

async fn grant(db: &attome_db::DbPool, user: Uuid, key: &str) {
    let privilege: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(key)
        .fetch_one(db)
        .await
        .unwrap_or_else(|e| panic!("privilege {key}: {e}"));
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user)
    .bind(privilege)
    .execute(db)
    .await
    .expect("grant");
}

async fn assign_role(db: &attome_db::DbPool, user: Uuid, role: &str) {
    let role_id: Uuid =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(role)
            .fetch_one(db)
            .await
            .unwrap_or_else(|e| panic!("role {role}: {e}"));
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role");
}

async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let req = builder
        .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = to_bytes(res.into_body(), 16 * 1024 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// Admin, a plain `.update` holder, the record's owner and a second
/// approver (both `Project Approver`).
struct Cast {
    admin: String,
    plain: String,
    owner_id: Uuid,
    owner: String,
    approver_id: Uuid,
    approver: String,
}

async fn cast(system: &EngineSystem) -> Cast {
    let db = &system.state().base.db;
    let (admin_id, admin) = seed_user(db).await;
    grant(db, admin_id, "system.admin").await;
    let (plain_id, plain) = seed_user(db).await;
    for key in [
        "project_timesheet.read",
        "project_timesheet.update",
        "project_change_request.read",
        "project_change_request.update",
    ] {
        grant(db, plain_id, key).await;
    }
    let (owner_id, owner) = seed_user(db).await;
    let (approver_id, approver) = seed_user(db).await;
    assign_role(db, owner_id, "Project Approver").await;
    assign_role(db, approver_id, "Project Approver").await;
    Cast {
        admin,
        plain,
        owner_id,
        owner,
        approver_id,
        approver,
    }
}

#[tokio::test]
async fn timesheet_decisions_need_approve_and_a_different_user() {
    let system = skip_if_no_db!(test_system().await);
    let c = cast(&system).await;
    let app = full_app(system);

    let (status, ts) = call(
        &app,
        "POST",
        "/api/v1/project_timesheet",
        &c.admin,
        Some(json!({
            "user_id": c.owner_id, "week_start_date": "2026-09-21T00:00:00Z", "status": "draft",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{ts:?}");
    let id = ts["id"].as_str().unwrap().to_owned();

    // The owner submits their own timesheet (no privilege on submit).
    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/v1/project/timesheet/{id}/submit"),
        &c.owner,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["status"], "submitted");

    for action in ["approve", "reject"] {
        let (status, body) = call(
            &app,
            "POST",
            &format!("/api/v1/project/timesheet/{id}/{action}"),
            &c.plain,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{action} by an .update-only holder: {body:?}"
        );

        let (status, body) = call(
            &app,
            "POST",
            &format!("/api/v1/project/timesheet/{id}/{action}"),
            &c.owner,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{action} own timesheet: {body:?}"
        );
        assert_eq!(body["error"], "transition_not_allowed");
    }

    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/v1/project/timesheet/{id}/approve"),
        &c.approver,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["status"], "approved");

    let (_, record) = call(
        &app,
        "GET",
        &format!("/api/v1/project_timesheet/{id}"),
        &c.admin,
        None,
    )
    .await;
    assert_eq!(record["data"]["status"], "approved", "{record:?}");
    assert_eq!(
        record["data"]["approved_by"],
        json!(c.approver_id),
        "{record:?}"
    );

    // Approved is terminal: a second decision is refused.
    let (status, _) = call(
        &app,
        "POST",
        &format!("/api/v1/project/timesheet/{id}/reject"),
        &c.approver,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn change_request_decisions_need_approve_and_a_different_user() {
    let system = skip_if_no_db!(test_system().await);
    let c = cast(&system).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let org = Uuid::now_v7();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org)
        .bind(format!("decide-org-{org}"))
        .execute(&db)
        .await
        .expect("insert throwaway organization");
    let (status, project) = call(
        &app,
        "POST",
        "/api/v1/attome_project",
        &c.admin,
        Some(json!({
            "name": "Decision routes", "project_code": format!("DR-{}", org.simple()),
            "organization_id": org,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{project:?}");
    let (status, cr) = call(
        &app,
        "POST",
        "/api/v1/project_change_request",
        &c.admin,
        Some(json!({
            "title": "scope", "project_id": project["id"], "requested_by": c.owner_id,
            "status": "pending",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{cr:?}");
    let id = cr["id"].as_str().unwrap().to_owned();

    for action in ["approve", "reject"] {
        let (status, body) = call(
            &app,
            "POST",
            &format!("/api/v1/project/change-request/{id}/{action}"),
            &c.plain,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{action} by an .update-only holder: {body:?}"
        );

        let (status, body) = call(
            &app,
            "POST",
            &format!("/api/v1/project/change-request/{id}/{action}"),
            &c.owner,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{action} own change request: {body:?}"
        );
        assert_eq!(body["error"], "transition_not_allowed");
    }

    let (status, body) = call(
        &app,
        "POST",
        &format!("/api/v1/project/change-request/{id}/approve"),
        &c.approver,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["status"], "approved");
    let (_, record) = call(
        &app,
        "GET",
        &format!("/api/v1/project_change_request/{id}"),
        &c.admin,
        None,
    )
    .await;
    assert_eq!(record["data"]["status"], "approved", "{record:?}");
}

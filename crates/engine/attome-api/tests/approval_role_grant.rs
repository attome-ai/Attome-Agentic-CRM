//! D-195 / `document/detailed-plans/P-four-eyes-approval.md` — the first
//! live-database test for the four-eyes approval gate itself (previously
//! none existed for any of the three wired action types — see that plan's
//! §6/§10). Exercises `attome_security::admin::assign_user_role`'s gating via
//! `ACTION_ROLE_GRANT`: default-off passthrough, gated submit-without-assign,
//! the separation-of-duties Forbidden, a different admin's approve actually
//! executing the grant, and re-deciding an already-decided request.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `jobs_admin.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test approval_role_grant -- --test-threads=1
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
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// `required_actions`: pass `&["security.role_grant"]` to gate direct
/// user->role assignment behind approval, or `&[]` for today's default
/// (ungated) behavior.
fn test_config(required_actions: &[&str]) -> AppConfig {
    let required_actions_json = serde_json::to_string(required_actions).unwrap();
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
            "approval": {{ "required_actions": {required_actions_json} }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system(required_actions: &[&str]) -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config(required_actions);
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

async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("approval-role-grant-test-{user_id}"))
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

async fn seed_role(db: &attome_db::DbPool) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(role_id)
    .bind(format!("approval-role-grant-test-role-{role_id}"))
    .bind("throwaway test role")
    .execute(db)
    .await
    .expect("insert throwaway role");
    role_id
}

async fn user_has_role(db: &attome_db::DbPool, user_id: Uuid, role_id: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
    )
    .bind(user_id)
    .bind(role_id)
    .fetch_one(db)
    .await
    .expect("query user_account_mm_role")
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn assign_role_request(admin_cookie: &str, user_id: Uuid, role_id: Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/security/users/{user_id}/roles"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({ "role_id": role_id }).to_string(),
        ))
        .unwrap()
}

fn decide_request(
    admin_cookie: &str,
    request_id: Uuid,
    decision: &str,
    row_version: i64,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/approvals/{request_id}/decide"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({ "decision": decision, "row_version": row_version }).to_string(),
        ))
        .unwrap()
}

/// `approval.required_actions = []` (today's default): assigning a role
/// directly still succeeds immediately, exactly as before this session's
/// gating change — no behavior change for a deployment that hasn't opted in.
#[tokio::test]
async fn ungated_assignment_succeeds_immediately() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (admin_id, admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(assign_role_request(&admin_cookie, target_user_id, role_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["approval_pending"], false);
    assert!(body["id"].is_string());

    assert!(user_has_role(&db, target_user_id, role_id).await);
    let _ = admin_id;
}

/// `approval.required_actions = ["security.role_grant"]`: the same call now
/// returns `202 approval_pending: true` and does NOT assign the role.
#[tokio::test]
async fn gated_assignment_submits_and_does_not_assign() {
    let system = skip_if_no_db!(test_system(&["security.role_grant"]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(assign_role_request(&admin_cookie, target_user_id, role_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = body_json(resp).await;
    assert_eq!(body["approval_pending"], true);
    assert!(body["id"].is_null());
    assert!(body["approval_request_id"].is_string());

    assert!(!user_has_role(&db, target_user_id, role_id).await);
}

/// Separation-of-duties: the requesting admin cannot decide their own
/// request (`attome_approval::decide`'s core correctness check).
#[tokio::test]
async fn requester_cannot_approve_own_role_grant_request() {
    let system = skip_if_no_db!(test_system(&["security.role_grant"]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(assign_role_request(&admin_cookie, target_user_id, role_id))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let request_id: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let resp = app
        .clone()
        .oneshot(decide_request(&admin_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A different `system.admin` approving actually executes the grant in the
/// same call (`execute_approved`'s `ACTION_ROLE_GRANT` dispatch arm calling
/// `attome_security::admin::do_assign_user_role`) — and deciding the same,
/// now-closed request a second time is a 409, not a silent no-op.
#[tokio::test]
async fn different_admin_approving_executes_the_grant_and_a_second_decide_conflicts() {
    let system = skip_if_no_db!(test_system(&["security.role_grant"]).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(assign_role_request(
            &requester_cookie,
            target_user_id,
            role_id,
        ))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let request_id: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    assert!(body["executed"]["id"].is_string());

    assert!(user_has_role(&db, target_user_id, role_id).await);

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

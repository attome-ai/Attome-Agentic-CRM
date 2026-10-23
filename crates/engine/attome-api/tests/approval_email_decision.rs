//! M9-T3 — approve or reject from email: the sweep mails each pending
//! step once, a low-risk request is decided from its link once, a reused or
//! expired link is refused, and a high-risk request's link only opens the
//! signed-in request page.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis, as `jobs_admin.rs`.
//!
//! ```powershell
//! cargo test -p attome-api --test approval_email_decision -- --test-threads=1
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
use axum::body::Body;
use axum::http::{Request, StatusCode};
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

async fn seed_user(system: &TestSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("approval-email-test-{user_id}"))
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

fn post(uri: &str, cookie: &str, body: Option<serde_json::Value>) -> Request<Body> {
    let builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

async fn json_of(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// A throwaway entity with a `title` (text) and `discount` (number) field.
async fn provision_entity(app: &axum::Router, admin_cookie: &str) -> String {
    let logicalname = format!("aem_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(post(
            "/api/v1/admin/entities",
            admin_cookie,
            Some(serde_json::json!({ "logicalname": logicalname, "name": "Approval Email" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity_id = json_of(res).await["id"].as_str().unwrap().to_owned();
    for (ln, ft) in [("title", "text"), ("discount", "number")] {
        let res = app
            .clone()
            .oneshot(post(
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                admin_cookie,
                Some(serde_json::json!({ "logicalname": ln, "name": ln, "field_type": ft })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create field {ln}");
    }
    logicalname
}

fn public_post(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A record submitted to a process whose one step `approver` decides; the
/// request id.
async fn submitted_request(app: &axum::Router, requester_cookie: &str, approver: Uuid) -> Uuid {
    let entity = provision_entity(app, requester_cookie).await;
    let res = app
        .clone()
        .oneshot(post(
            "/api/v1/admin/approval-processes",
            requester_cookie,
            Some(serde_json::json!({
                "name": "Large discount",
                "entity_logicalname": entity,
                "plan": { "steps": [{
                    "mode": "any",
                    "approvers": [format!("user:{approver}")],
                    "sla_minutes": 60,
                    "on_timeout": "escalate",
                }] },
                "lock_record": false,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create the process");
    let process_id = json_of(res).await["id"].as_str().unwrap().to_owned();
    let res = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/{entity}"),
            requester_cookie,
            Some(serde_json::json!({ "title": "deal", "discount": 30 })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create the record");
    let record_id = json_of(res).await["id"].as_str().unwrap().to_owned();
    let res = app
        .clone()
        .oneshot(post(
            &format!("/api/v1/approval-processes/{process_id}/submit"),
            requester_cookie,
            Some(serde_json::json!({ "record_id": record_id, "reason": "three-year deal" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "submit");
    json_of(res).await["request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

async fn issue(state: &EngineState, request_id: Uuid, approver: Uuid) -> String {
    let request = attome_approval::get(&state.base.db, request_id)
        .await
        .unwrap();
    let mut tx = attome_db::tx::begin(&state.base.db).await.unwrap();
    let token = attome_api::approval_email::issue_link_in_tx(&mut tx, state, &request, approver)
        .await
        .unwrap();
    attome_db::tx::commit(tx).await.unwrap();
    token
}

#[test]
fn approval_email_decision_low_risk_link_decides_once() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (_requester, requester_cookie) = seed_user(&system, true).await;
        let (approver, _approver_cookie) = seed_user(&system, true).await;
        let app = full_app(system);
        let request_id = submitted_request(&app, &requester_cookie, approver).await;
        let token = issue(&state, request_id, approver).await;

        let res = app
            .clone()
            .oneshot(public_post(
                "/api/v1/approvals/email-link",
                serde_json::json!({ "token": token }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "reading needs no session");
        let view = json_of(res).await;
        assert_eq!(view["decide_here"], true);
        assert_eq!(view["reason"], "three-year deal");

        let res = app
            .clone()
            .oneshot(public_post(
                "/api/v1/approvals/email-link/decide",
                serde_json::json!({ "token": token, "decision": "approve", "comment": "ok" }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{:?}", json_of(res).await);
        let status: String =
            sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
                .bind(request_id)
                .fetch_one(&state.base.db)
                .await
                .unwrap();
        assert_eq!(status, "approved");
        let decided_by: Uuid =
            sqlx::query_scalar("SELECT approver_id FROM approval_grant WHERE request_id = $1")
                .bind(request_id)
                .fetch_one(&state.base.db)
                .await
                .unwrap();
        assert_eq!(decided_by, approver, "decided as the link's approver");

        let res = app
            .clone()
            .oneshot(public_post(
                "/api/v1/approvals/email-link/decide",
                serde_json::json!({ "token": token, "decision": "approve" }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT, "a used link is refused");
    });
}

#[test]
fn approval_email_decision_expired_or_wrong_link_refused() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (_requester, requester_cookie) = seed_user(&system, true).await;
        let (approver, _) = seed_user(&system, true).await;
        let app = full_app(system);
        let request_id = submitted_request(&app, &requester_cookie, approver).await;
        let token = issue(&state, request_id, approver).await;

        let (public_id, secret) = token.split_once('.').unwrap();
        let wrong = format!("{public_id}.{}", "0".repeat(secret.len()));
        let res = app
            .clone()
            .oneshot(public_post(
                "/api/v1/approvals/email-link/decide",
                serde_json::json!({ "token": wrong, "decision": "approve" }),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "a wrong secret is refused"
        );

        sqlx::query(
            "UPDATE approval_email_link SET expires_at = now() - interval '1 minute' \
              WHERE public_id = $1",
        )
        .bind(Uuid::parse_str(public_id).unwrap())
        .execute(&state.base.db)
        .await
        .unwrap();
        let res = app
            .clone()
            .oneshot(public_post(
                "/api/v1/approvals/email-link/decide",
                serde_json::json!({ "token": token, "decision": "approve" }),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "an expired link is refused"
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
                .bind(request_id)
                .fetch_one(&state.base.db)
                .await
                .unwrap();
        assert_eq!(status, "pending", "nothing was decided");
    });
}

#[test]
fn approval_email_decision_high_risk_link_needs_sign_in() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (requester, _) = seed_user(&system, true).await;
        let (approver, _) = seed_user(&system, true).await;
        let app = full_app(system);
        let plan: attome_approval::ApprovalPlan = serde_json::from_value(serde_json::json!({
            "steps": [{ "mode": "any", "approvers": [format!("user:{approver}")], "sla_minutes": 60, "on_timeout": "escalate" }]
        }))
        .unwrap();
        let request = attome_audit::approval::gate_with_plan_regarding(
            &state,
            "test.approval_email.high_risk",
            serde_json::json!({}),
            requester,
            plan,
            None,
        )
        .await
        .unwrap();
        let token = issue(&state, request.id, approver).await;

        let res = app
            .clone()
            .oneshot(public_post(
                "/api/v1/approvals/email-link",
                serde_json::json!({ "token": token }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(json_of(res).await["decide_here"], false);
        let res = app
            .clone()
            .oneshot(public_post(
                "/api/v1/approvals/email-link/decide",
                serde_json::json!({ "token": token, "decision": "approve" }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let used: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT used_at FROM approval_email_link WHERE request_id = $1")
                .bind(request.id)
                .fetch_one(&state.base.db)
                .await
                .unwrap();
        assert!(used.is_none(), "a refused link stays unused");
    });
}

#[test]
fn approval_email_decision_sweep_mails_each_step_once() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let state = system.state().clone();
        let (_requester, requester_cookie) = seed_user(&system, true).await;
        let (approver, _) = seed_user(&system, true).await;
        let app = full_app(system);
        let request_id = submitted_request(&app, &requester_cookie, approver).await;

        attome_api::approval_email::sweep(&state).await.unwrap();
        attome_api::approval_email::sweep(&state).await.unwrap();
        let links: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM approval_email_link WHERE request_id = $1 AND approver_id = $2",
        )
        .bind(request_id)
        .bind(approver)
        .fetch_one(&state.base.db)
        .await
        .unwrap();
        assert_eq!(
            links, 1,
            "one link for the approver, however often the sweep runs"
        );
        let rounds: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM approval_email_round WHERE request_id = $1")
                .bind(request_id)
                .fetch_one(&state.base.db)
                .await
                .unwrap();
        assert_eq!(rounds, 1);
    });
}

//! Dashboard 10/10 Phase 6 — live-database test for `GET /api/v1/my-work/*`
//! and the Approvals `MyWorkProvider`. Same harness shape as
//! `approval_policy_governance.rs` (this repo's convention: each integration
//! test builds its own `EngineSystem`, not a shared helper module).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `approval_policy_governance.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test my_work -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::my_work_approvals::ApprovalsMyWorkProvider;
use attome_api::my_work_service::ServiceMyWorkProvider;
use attome_api::my_work_workflow::WorkflowMyWorkProvider;
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
            "security": {{ "bootstrap_admin_email": null }},
            "approval": {{ "required_actions": [] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &url);
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
        .register_my_work_provider(ApprovalsMyWorkProvider)
        .register_my_work_provider(ServiceMyWorkProvider)
        .register_my_work_provider(WorkflowMyWorkProvider)
        .register_my_work_provider(attome_api::my_work_project::ProjectMyWorkProvider)
        .register_my_work_provider(attome_api::my_work_decisions::DecisionsMyWorkProvider)
        .build()
        .await
        .expect("build EngineSystem");

    // service_ticket/work_queue/work_queue_member come from
    // platform-bundles/attome-service.json (D-478 seeds-to-bundles) —
    // `.register(ServiceModel)` alone does not provision them.
    attome_service::seed::seed_for_tests(&system.state().base.db)
        .await
        .expect("seed attome-service entities");
    // Same reason, for the Project and Decisions providers: their entities
    // come from platform-bundles/attome-project.json and attome-dashboard.json.
    attome_project::seed::seed_for_tests(&system.state().base.db)
        .await
        .expect("seed attome-project entities");
    attome_dashboard::seed::seed_for_tests(&system.state().base.db)
        .await
        .expect("seed attome-dashboard entities");
    // Workflow checkpoint commits audit every node-run transition through
    // attome_metadata::crud::insert, which resolves audit_header from
    // entity_info (needs attome_audit::seed); the create_record node
    // type needs autovalue (attome_metadata::autovalue::seed_for_tests).
    // Same two seeds execution.rs's own `seed_platform` documents needing —
    // the attome-workflow platform bundle is not needed, the engine's own tables are
    // plain SQL.
    attome_audit::seed(&system.state().base.db)
        .await
        .expect("seed audit entity metadata");
    attome_metadata::autovalue::seed_for_tests(&system.state().base.db)
        .await
        .expect("seed autovalue entity + table");

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
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("my-work-test-{user_id}"))
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
    .bind(format!("my-work-test-role-{role_id}"))
    .bind("throwaway test role")
    .execute(db)
    .await
    .expect("insert throwaway role");
    role_id
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn json_request(method: &str, uri: String, cookie: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn plain_request(method: &str, uri: String, cookie: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

fn assign_role_request(admin_cookie: &str, user_id: Uuid, role_id: Uuid) -> Request<Body> {
    json_request(
        "POST",
        format!("/api/v1/admin/security/users/{user_id}/roles"),
        admin_cookie,
        serde_json::json!({ "role_id": role_id }),
    )
}

/// Same shape as `approval_policy_governance.rs`'s own helper: a one-step,
/// `any`-mode policy naming `approver_id` directly for `security.role_grant`.
async fn create_single_approver_policy(
    app: &axum::Router,
    db: &sqlx::PgPool,
    admin_cookie: &str,
    approver_id: Uuid,
) -> Uuid {
    sqlx::query(
        "UPDATE approval_policy SET is_deleted = TRUE, is_active = FALSE \
         WHERE action_type = 'security.role_grant'",
    )
    .execute(db)
    .await
    .expect("clean up any pre-existing security.role_grant policy");

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/approval-policies".to_string(),
            admin_cookie,
            serde_json::json!({
                "name": format!("my-work-policy-test-{approver_id}"),
                "action_type": "security.role_grant",
                "plan": {
                    "steps": [{
                        "mode": "any",
                        "approvers": [format!("user:{approver_id}")],
                        "sla_minutes": 60,
                        "on_timeout": "escalate",
                    }]
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    Uuid::parse_str(body["id"].as_str().expect("policy id")).expect("policy id must be a uuid")
}

async fn cleanup_role_grant_policy(db: &sqlx::PgPool) {
    sqlx::query(
        "UPDATE approval_policy SET is_deleted = TRUE, is_active = FALSE \
         WHERE action_type = 'security.role_grant'",
    )
    .execute(db)
    .await
    .expect("clean up the security.role_grant policy this test created");
}

/// The whole point of the read model: an eligible decider's counts/list show
/// the pending, policy-gated request, and the item carries a working
/// `approve`/`reject` action pointing at the non-admin decide route.
#[test]
fn an_eligible_approver_sees_the_pending_request_with_actions() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (requester_id, requester_cookie) = seed_user(&system, true).await;
        let (approver_id, approver_cookie) = seed_user(&system, true).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_single_approver_policy(&app, &db, &requester_cookie, approver_id).await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_json(resp).await;
        let request_id: Uuid = body["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/counts".to_string(),
                &approver_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let counts = body_json(resp).await;
        assert_eq!(
            counts["approvals"], 1,
            "the eligible approver must see exactly this one pending request"
        );

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/approvals".to_string(),
                &approver_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let page = body_json(resp).await;
        let items = page["items"].as_array().expect("items array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["record_id"], request_id.to_string());
        assert_eq!(items[0]["provider"], "approvals");
        let actions = items[0]["actions"].as_array().expect("actions array");
        assert_eq!(actions.len(), 2, "approve + reject");
        assert!(actions.iter().any(|a| a["key"] == "approve"
            && a["route"] == format!("/api/v1/approvals/{request_id}/decide")));

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                format!("/api/v1/my-work/approvals/{request_id}/actions"),
                &approver_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let actions = body_json(resp).await;
        assert_eq!(actions.as_array().unwrap().len(), 2);

        let _ = requester_id;
        cleanup_role_grant_policy(&db).await;
    })
}

/// A caller who is neither the named approver nor otherwise eligible sees
/// zero items — the trait's own visibility rule, not a 403 (the route itself
/// is `SelfService`, so it never rejects an authenticated caller; it just
/// shows them nothing).
#[test]
fn an_ineligible_caller_sees_no_items() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_requester_id, requester_cookie) = seed_user(&system, true).await;
        let (approver_id, _) = seed_user(&system, true).await;
        let (bystander_id, bystander_cookie) = seed_user(&system, false).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_single_approver_policy(&app, &db, &requester_cookie, approver_id).await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/counts".to_string(),
                &bystander_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let counts = body_json(resp).await;
        assert_eq!(counts.get("approvals").and_then(|v| v.as_u64()), Some(0));

        let _ = bystander_id;
        cleanup_role_grant_policy(&db).await;
    })
}

/// Once decided, the item is no longer pending: `actions()` re-resolves fresh
/// and returns none for it, even for the same caller who just decided it.
#[test]
fn a_decided_request_no_longer_offers_actions() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (requester_id, requester_cookie) = seed_user(&system, true).await;
        let (approver_id, approver_cookie) = seed_user(&system, true).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_single_approver_policy(&app, &db, &requester_cookie, approver_id).await;

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
            .oneshot(json_request(
                "POST",
                format!("/api/v1/approvals/{request_id}/decide"),
                &approver_cookie,
                serde_json::json!({ "decision": "approve", "row_version": 0 }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                format!("/api/v1/my-work/approvals/{request_id}/actions"),
                &approver_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let actions = body_json(resp).await;
        assert!(
            actions.as_array().unwrap().is_empty(),
            "a decided request must offer no further actions"
        );

        let _ = requester_id;
        cleanup_role_grant_policy(&db).await;
    })
}

/// A two-step, `any`-mode `security.role_grant` policy: step 0 names
/// `first_approver`, step 1 names `second_approver`.
async fn create_two_step_policy(
    app: &axum::Router,
    db: &sqlx::PgPool,
    admin_cookie: &str,
    first_approver: Uuid,
    second_approver: Uuid,
) {
    sqlx::query(
        "UPDATE approval_policy SET is_deleted = TRUE, is_active = FALSE \
         WHERE action_type = 'security.role_grant'",
    )
    .execute(db)
    .await
    .expect("clean up any pre-existing security.role_grant policy");

    let step = |approver: Uuid| {
        serde_json::json!({
            "mode": "any",
            "approvers": [format!("user:{approver}")],
            "sla_minutes": 60,
            "on_timeout": "escalate",
        })
    };
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/approval-policies".to_string(),
            admin_cookie,
            serde_json::json!({
                "name": format!("my-work-two-step-{second_approver}"),
                "action_type": "security.role_grant",
                "plan": { "steps": [step(first_approver), step(second_approver)] }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// The approver inbox's own item for `request_id`, as `caller` sees it.
async fn inbox_item(app: &axum::Router, cookie: &str, request_id: Uuid) -> Value {
    let resp = app
        .clone()
        .oneshot(plain_request(
            "GET",
            "/api/v1/my-work/approvals".to_string(),
            cookie,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let page = body_json(resp).await;
    page["items"]
        .as_array()
        .expect("items array")
        .iter()
        .find(|item| item["record_id"] == request_id.to_string())
        .cloned()
        .unwrap_or_else(|| panic!("request {request_id} missing from the inbox: {page:?}"))
}

/// basic-units-10-10 §8 P1 follow-up: the inbox item carries the approval
/// request's current `row_version`, so a non-admin approver of a *later*
/// plan step (whose request has already moved past version 0) can decide it
/// from the inbox data alone. A stale version is still a 409, a comment
/// over the bound is a 422, and a valid comment lands on the grant row.
#[test]
fn a_second_step_is_decidable_by_a_non_admin_from_the_inbox_row_version() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_requester_id, requester_cookie) = seed_user(&system, true).await;
        let (first_id, first_cookie) = seed_user(&system, true).await;
        let (second_id, second_cookie) = seed_user(&system, false).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_two_step_policy(&app, &db, &requester_cookie, first_id, second_id).await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let request_id: Uuid = body_json(resp).await["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        // Step 0, decided through the inbox data like the page does.
        let item = inbox_item(&app, &first_cookie, request_id).await;
        let first_version = item["row_version"]
            .as_i64()
            .expect("row_version on the item");
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/approvals/{request_id}/decide"),
                &first_cookie,
                serde_json::json!({ "decision": "approve", "row_version": first_version }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "step 0 decide");
        assert_eq!(
            body_json(resp).await["status"],
            "pending",
            "step 0 only advances"
        );

        // Step 1: the non-admin's inbox now shows the moved-on version.
        let item = inbox_item(&app, &second_cookie, request_id).await;
        let second_version = item["row_version"]
            .as_i64()
            .expect("row_version on the item");
        assert!(
            second_version > first_version,
            "the item must carry the request's current row_version, got {second_version}"
        );

        // The version the inbox used to send (0) is stale now: 409.
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/approvals/{request_id}/decide"),
                &second_cookie,
                serde_json::json!({ "decision": "approve", "row_version": first_version }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT, "stale row_version");

        // A comment over the bound is refused before anything is decided.
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/approvals/{request_id}/decide"),
                &second_cookie,
                serde_json::json!({
                    "decision": "approve",
                    "row_version": second_version,
                    "comment": "x".repeat(attome_approval::MAX_DECISION_COMMENT_CHARS + 1),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "comment too long"
        );

        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/approvals/{request_id}/decide"),
                &second_cookie,
                serde_json::json!({
                    "decision": "approve",
                    "row_version": second_version,
                    "comment": "  checked against the access policy  ",
                }),
            ))
            .await
            .unwrap();
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "step 1 decide by the non-admin: {body:?}"
        );
        assert_eq!(body["status"], "approved");

        let comments: Vec<(i32, Option<String>)> = sqlx::query_as(
            "SELECT step, comment FROM approval_grant WHERE request_id = $1 ORDER BY step",
        )
        .bind(request_id)
        .fetch_all(&db)
        .await
        .expect("read the request's grants");
        assert_eq!(
            comments,
            vec![
                (0, None),
                (1, Some("checked against the access policy".to_string())),
            ],
            "the trimmed comment is stored on the step it explains, and only there"
        );

        // The decision's audit event carries the comment too. Read from the
        // ingest queue: the chainer that moves events into `audit_header`
        // does not run in this harness (same as `ai_action_attribution.rs`).
        let audit_comment: Option<String> = sqlx::query_scalar(
            "SELECT payload->>'event_comment' FROM audit_ingest \
         WHERE payload->>'entity_name' = 'approval_request' \
           AND payload->>'record_id' = $1 \
           AND payload->>'operation' = 'Approved' \
           AND payload->>'event_comment' LIKE '%(overall status: approved)%' \
         ORDER BY created_at DESC LIMIT 1",
        )
        .bind(request_id.to_string())
        .fetch_optional(&db)
        .await
        .expect("read the decision's audit event");
        assert!(
            audit_comment
                .as_deref()
                .is_some_and(|c| c.contains("comment: checked against the access policy")),
            "the audit event must carry the decision comment, got {audit_comment:?}"
        );

        cleanup_role_grant_policy(&db).await;
    })
}

/// The admin decide route validates a comment the same way.
#[test]
fn the_admin_decide_route_rejects_an_overlong_comment() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_requester_id, requester_cookie) = seed_user(&system, true).await;
        let (approver_id, approver_cookie) = seed_user(&system, true).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_single_approver_policy(&app, &db, &requester_cookie, approver_id).await;
        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let request_id: Uuid = body_json(resp).await["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/admin/approvals/{request_id}/decide"),
                &approver_cookie,
                serde_json::json!({
                    "decision": "reject",
                    "row_version": 0,
                    "comment": "x".repeat(attome_approval::MAX_DECISION_COMMENT_CHARS + 1),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            format!("/api/v1/admin/approvals/{request_id}/decide"),
            &approver_cookie,
            serde_json::json!({ "decision": "reject", "row_version": 0, "comment": "duplicate" }),
        ))
        .await
        .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the request was still pending"
        );
        let stored: Option<String> =
            sqlx::query_scalar("SELECT comment FROM approval_grant WHERE request_id = $1")
                .bind(request_id)
                .fetch_one(&db)
                .await
                .expect("the rejection's grant row");
        assert_eq!(stored.as_deref(), Some("duplicate"));

        cleanup_role_grant_policy(&db).await;
    })
}

/// An unregistered provider name is a 404, not an empty page — the caller
/// asked for something that does not exist, distinct from "exists but has
/// nothing for you."
#[test]
fn an_unknown_provider_name_is_not_found() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_user_id, cookie) = seed_user(&system, false).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/not-a-real-provider".to_string(),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    })
}

// ── Service work (ServiceMyWorkProvider) ────────────────────────────────────

/// `ServiceMyWorkProvider` layers `require_record_access` on top of its own
/// assignee/queue-membership predicate (its own module doc explains why:
/// the two are independent). Generic RLS resolves `AccessLevel::None` for a
/// caller who holds no role at all (`record_level_security.rs`'s own
/// `caller_with_no_role_defaults_to_global_access` test documents the
/// opposite corner — table-level privilege alone, no role-entity-access row,
/// resolves `Global`), so every Service test needs its caller to hold
/// `{entity}.read` via a role, same shape as that file's
/// `create_role_with_privileges`/`assign_role_to_user`.
async fn grant_entity_read(db: &sqlx::PgPool, user_id: Uuid, entity_logicalname: &str) {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("my-work-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert throwaway role");

    let key = format!("{entity_logicalname}.read");
    let privilege_id: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $3, $3, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(&key)
    .bind(&key)
    .fetch_one(db)
    .await
    .expect("ensure privilege");

    sqlx::query(
        "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant role privilege");

    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role to user");
}

async fn insert_ticket(
    db: &sqlx::PgPool,
    title: &str,
    status: &str,
    assignee_id: Option<Uuid>,
    work_queue_ref: Option<Uuid>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_ticket \
             (id, ticket_number, title, priority, status, assignee_id, work_queue_ref) \
         VALUES ($1, $2, $3, 'medium', $4, $5, $6)",
    )
    .bind(id)
    .bind(format!("TKT-MYWORK-{id}"))
    .bind(title)
    .bind(status)
    .bind(assignee_id)
    .bind(work_queue_ref)
    .execute(db)
    .await
    .expect("insert throwaway service_ticket");
    id
}

async fn insert_work_queue(db: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO service_work_queue (id, name, distribution, capacity, is_active) \
         VALUES ($1, $2, 'round_robin', 10, true)",
    )
    .bind(id)
    .bind(format!("My Work Test Queue {id}"))
    .execute(db)
    .await
    .expect("insert throwaway service_work_queue");
    id
}

async fn insert_queue_member(db: &sqlx::PgPool, queue_id: Uuid, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO service_work_queue_member (id, queue_ref, user_ref, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(Uuid::now_v7())
    .bind(queue_id)
    .bind(user_id)
    .execute(db)
    .await
    .expect("insert throwaway service_work_queue_member");
}

/// A ticket assigned directly to the caller shows up with its one available
/// `new -> open` transition, pointed at the generic transition route.
#[test]
fn an_assigned_ticket_shows_up_with_its_transition() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, cookie) = seed_user(&system, false).await;
        let db = system.state().base.db.clone();
        grant_entity_read(&db, user_id, "service_ticket").await;
        let ticket_id =
            insert_ticket(&db, "My Work Assigned Ticket", "new", Some(user_id), None).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/counts".to_string(),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let counts = body_json(resp).await;
        assert_eq!(counts["service"], 1);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/service".to_string(),
                &cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let page = body_json(resp).await;
        let items = page["items"].as_array().expect("items array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["record_id"], ticket_id.to_string());
        assert_eq!(items[0]["source_entity"], "service_ticket");
        let actions = items[0]["actions"].as_array().expect("actions array");
        assert!(
            actions.iter().any(|a| a["key"] == "new_to_open"
                && a["route"] == format!("/api/v1/service_ticket/{ticket_id}/transition")),
            "expected a new_to_open transition action, got {actions:?}"
        );
    })
}

/// An unassigned ticket sitting in a work queue is visible to an active
/// member of that queue, even though it names no individual assignee.
#[test]
fn an_unassigned_queue_ticket_is_visible_to_an_active_queue_member() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (member_id, member_cookie) = seed_user(&system, false).await;
        let (bystander_id, bystander_cookie) = seed_user(&system, false).await;
        let db = system.state().base.db.clone();
        grant_entity_read(&db, member_id, "service_ticket").await;
        grant_entity_read(&db, bystander_id, "service_ticket").await;
        let queue_id = insert_work_queue(&db).await;
        insert_queue_member(&db, queue_id, member_id).await;
        let ticket_id =
            insert_ticket(&db, "My Work Queue Ticket", "open", None, Some(queue_id)).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/service".to_string(),
                &member_cookie,
            ))
            .await
            .unwrap();
        let page = body_json(resp).await;
        let items = page["items"].as_array().expect("items array");
        assert!(
            items
                .iter()
                .any(|i| i["record_id"] == ticket_id.to_string()),
            "an active queue member must see an unassigned ticket in their queue"
        );

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/service".to_string(),
                &bystander_cookie,
            ))
            .await
            .unwrap();
        let page = body_json(resp).await;
        let items = page["items"].as_array().expect("items array");
        assert!(
            !items
                .iter()
                .any(|i| i["record_id"] == ticket_id.to_string()),
            "a caller outside the queue must not see its unassigned tickets"
        );
        let _ = bystander_id;
    })
}

// ── Workflow (WorkflowMyWorkProvider) ───────────────────────────────────────

async fn create_workflow_approval_policy(
    db: &sqlx::PgPool,
    admin_id: Uuid,
    action_type: &str,
    approver_id: Uuid,
) {
    sqlx::query(
        "INSERT INTO approval_policy (name, action_type, plan, created_by) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(format!("my-work-workflow-policy-{action_type}"))
    .bind(action_type)
    .bind(serde_json::json!({
        "steps": [{
            "mode": "any",
            "approvers": [format!("user:{approver_id}")],
            "sla_minutes": 60,
            "on_timeout": "escalate",
        }]
    }))
    .bind(admin_id)
    .execute(db)
    .await
    .expect("insert throwaway approval_policy");
}

/// Publishes a one-node-Approval workflow gated by a policy naming
/// `approver_id`, starts an instance, and drives it to its waiting
/// checkpoint — same sequence `attome-workflow`'s own
/// `approval_round_trip_through_base_approval` integration test uses.
/// Returns `(instance_id, approval_request_id)`.
async fn start_waiting_workflow_instance(
    state: &EngineState,
    action_type: &str,
    started_by: Uuid,
) -> (Uuid, Uuid) {
    let graph = serde_json::json!({
        "nodes": [
            {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
            {"id": "ap", "type": "approval", "config": {"action_type": action_type, "ttl_hours": 1}}
        ],
        "edges": [
            {"from_node": "t", "from_port": "out", "to_node": "ap", "to_port": "payload"}
        ]
    });

    let logicalname = format!("my-work-workflow-test-{}", Uuid::now_v7());
    let definition_id: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_definition (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
    )
    .bind(&logicalname)
    .fetch_one(&state.base.db)
    .await
    .expect("insert workflow definition");

    let version_id: Uuid = sqlx::query_scalar(
        "INSERT INTO workflow_definition_version (definition_id, version_number, graph, status) \
         VALUES ($1, 1, $2, 'draft') RETURNING id",
    )
    .bind(definition_id)
    .bind(&graph)
    .fetch_one(&state.base.db)
    .await
    .expect("insert draft workflow version");

    let parsed = attome_workflow::graph::Graph::parse(&graph).expect("graph parses");
    let schema_hash = attome_workflow::graph::validate(&parsed).expect("graph validates");

    let mut tx = attome_db::tx::begin(&state.base.db)
        .await
        .expect("begin tx");
    sqlx::query(
        "UPDATE workflow_definition_version SET status = 'published', node_schema_hash = $2 \
         WHERE id = $1",
    )
    .bind(version_id)
    .bind(&schema_hash)
    .execute(&mut *tx)
    .await
    .expect("publish workflow version");
    attome_workflow::trigger_index::rebuild_entry_rows(&mut tx, version_id, &parsed)
        .await
        .expect("rebuild entry rows");
    tx.commit().await.expect("commit publish");

    let instance_id = attome_workflow::instance_admin::start_instance_internal(
        state,
        version_id,
        None,
        Some(started_by),
        None,
        serde_json::json!({}),
    )
    .await
    .expect("start instance");

    let mut status = "running".to_string();
    for _ in 0..50 {
        attome_workflow::scheduler::execute_instance(state, instance_id)
            .await
            .expect("execute_instance");
        status = sqlx::query_scalar("SELECT status FROM workflow_instance WHERE id = $1")
            .bind(instance_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read instance status");
        if status != "running" {
            break;
        }
    }
    assert_eq!(
        status, "waiting",
        "instance must reach the approval wait checkpoint"
    );

    let request_id: Uuid = sqlx::query_scalar(
        "SELECT (node_data -> 'ap' ->> 'approval_request_id')::uuid \
         FROM workflow_instance WHERE id = $1",
    )
    .bind(instance_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read approval_request_id from node_data");

    (instance_id, request_id)
}

/// A workflow instance blocked on an approval the caller is eligible to
/// decide shows up under the `workflow` provider, and its action re-uses
/// the exact same non-admin decide route the `approvals` provider offers
/// for the underlying request.
#[test]
fn a_waiting_workflow_shows_up_and_can_be_decided() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, _) = seed_user(&system, true).await;
        let (starter_id, _) = seed_user(&system, true).await;
        let (approver_id, approver_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let action_type = format!("my_work_workflow_test.{}", Uuid::now_v7());
        create_workflow_approval_policy(&db, admin_id, &action_type, approver_id).await;

        let (instance_id, request_id) =
            start_waiting_workflow_instance(system.state(), &action_type, starter_id).await;
        let _ = instance_id;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/workflow".to_string(),
                &approver_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let page = body_json(resp).await;
        let items = page["items"].as_array().expect("items array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["source_entity"], "workflow_instance");
        let node_run_id: Uuid = items[0]["record_id"]
            .as_str()
            .expect("record_id")
            .parse()
            .expect("record_id must be a uuid");
        let actions = items[0]["actions"].as_array().expect("actions array");
        assert!(
            actions.iter().any(|a| a["key"] == "approve"
                && a["route"] == format!("/api/v1/approvals/{request_id}/decide")),
            "expected an approve action pointed at the request's own decide route, got {actions:?}"
        );

        // Decided through the non-admin HTTP route, not around it: an approval
        // whose action another engine carries out (this workflow node) must
        // decide cleanly with nothing dispatched, and returns `executed: null`.
        // Before D-551 this POST 500'd — `do_decide` routed every `Approve` into
        // execution dispatch unconditionally — which is exactly why the workflow
        // provider's action has to be proven reachable, not merely listed.
        let current = attome_approval::get(&db, request_id)
            .await
            .expect("re-fetch request");
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/approvals/{request_id}/decide"),
                &approver_cookie,
                serde_json::json!({ "decision": "approve", "row_version": current.row_version }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the non-admin decide route must decide a workflow-carried-out approval cleanly"
        );
        let decided = body_json(resp).await;
        assert!(
            decided["executed"].is_null(),
            "the approval dispatcher must not execute an action its owning engine runs, got {decided:?}"
        );

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                format!("/api/v1/my-work/workflow/{node_run_id}/actions"),
                &approver_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let actions = body_json(resp).await;
        assert!(
            actions.as_array().unwrap().is_empty(),
            "a decided request's workflow wait must offer no further actions"
        );
    })
}

/// A caller with no standing on the underlying approval sees no workflow
/// items either — the same eligibility question, just asked through a
/// different provider.
#[test]
fn an_ineligible_caller_sees_no_waiting_workflows() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, _) = seed_user(&system, true).await;
        let (starter_id, _) = seed_user(&system, true).await;
        let (approver_id, _) = seed_user(&system, true).await;
        let (bystander_id, bystander_cookie) = seed_user(&system, false).await;
        let db = system.state().base.db.clone();
        let action_type = format!("my_work_workflow_test.{}", Uuid::now_v7());
        create_workflow_approval_policy(&db, admin_id, &action_type, approver_id).await;

        start_waiting_workflow_instance(system.state(), &action_type, starter_id).await;
        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/counts".to_string(),
                &bystander_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let counts = body_json(resp).await;
        assert_eq!(counts.get("workflow").and_then(|v| v.as_u64()), Some(0));
        let _ = bystander_id;
    })
}

/// The Project provider unions its three sources — a pending change request,
/// a submitted timesheet, and the caller's own open work item — each with the
/// authoritative route for its action.
#[test]
fn project_items_cover_change_requests_timesheets_and_own_work_items() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (caller_id, caller_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();

        let project_id = Uuid::now_v7();
        sqlx::query("INSERT INTO attome_project (id, name, is_active) VALUES ($1, $2, true)")
            .bind(project_id)
            .bind(format!("my-work-project-{project_id}"))
            .execute(&db)
            .await
            .expect("insert throwaway attome_project");

        let cr_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO project_change_request \
             (id, title, project_id, status, requested_date, is_active) \
         VALUES ($1, $2, $3, 'pending', NOW(), true)",
        )
        .bind(cr_id)
        .bind("Add a fourth delivery phase")
        .bind(project_id)
        .execute(&db)
        .await
        .expect("insert throwaway change request");

        let ts_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO project_timesheet (id, user_id, week_start_date, status, is_active) \
         VALUES ($1, $2, NOW(), 'submitted', true)",
        )
        .bind(ts_id)
        .bind(caller_id)
        .execute(&db)
        .await
        .expect("insert throwaway timesheet");

        let wi_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO project_work_item \
             (id, name, project_id, item_type, status, owner_id, due_date, is_active) \
         VALUES ($1, $2, $3, 'task', 'in_progress', $4, NOW() + INTERVAL '3 days', true)",
        )
        .bind(wi_id)
        .bind("Draft the migration plan")
        .bind(project_id)
        .bind(caller_id)
        .execute(&db)
        .await
        .expect("insert throwaway work item");

        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/project".to_string(),
                &caller_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let page = body_json(resp).await;
        let items = page["items"].as_array().expect("items array");
        assert_eq!(
            items.len(),
            3,
            "one change request, one timesheet and one work item: {items:?}"
        );

        let by_entity = |entity: &str| {
            items
                .iter()
                .find(|item| item["source_entity"] == entity)
                .unwrap_or_else(|| panic!("no item for {entity}: {items:?}"))
        };
        let cr_actions = by_entity("project_change_request")["actions"]
            .as_array()
            .expect("change request actions");
        assert!(
            cr_actions
                .iter()
                .any(|a| a["route"] == format!("/api/v1/project/change-request/{cr_id}/approve")),
            "expected the change request's own approve route, got {cr_actions:?}"
        );
        let ts_actions = by_entity("project_timesheet")["actions"]
            .as_array()
            .expect("timesheet actions");
        assert!(
            ts_actions
                .iter()
                .any(|a| a["route"] == format!("/api/v1/project/timesheet/{ts_id}/approve")),
            "expected the timesheet's own approve route, got {ts_actions:?}"
        );
        assert_eq!(by_entity("project_work_item")["state"], "in_progress");

        // `actions()` re-resolves one id fresh, without a list round trip.
        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                format!("/api/v1/my-work/project/{cr_id}/actions"),
                &caller_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let actions = body_json(resp).await;
        assert_eq!(
            actions.as_array().expect("actions array").len(),
            2,
            "approve + reject"
        );
    })
}

/// A `proposed` decision is an item for a caller who may decide it, with the
/// approve route (which takes the chosen option as a body) as its action.
#[test]
fn a_proposed_decision_shows_up_for_a_decider() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, caller_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();

        let decision_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO dashboard_decision \
             (id, title, driver, status, recommended_by, measure_at, is_active) \
         VALUES ($1, $2, $3, 'proposed', 'human', NOW() + INTERVAL '7 days', true)",
        )
        .bind(decision_id)
        .bind("Retire the legacy pricing tier")
        .bind("Renewal win rate fell 6 points")
        .execute(&db)
        .await
        .expect("insert throwaway decision");

        let app = full_app(system);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                "/api/v1/my-work/decisions".to_string(),
                &caller_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let page = body_json(resp).await;
        let items = page["items"].as_array().expect("items array");
        assert_eq!(items.len(), 1, "exactly the one proposed decision");
        assert_eq!(items[0]["record_id"], decision_id.to_string());
        assert_eq!(items[0]["provider"], "decisions");
        let actions = items[0]["actions"].as_array().expect("actions array");
        assert_eq!(actions.len(), 1, "the approve route is the only action");
        assert_eq!(actions[0]["key"], "approve");
        assert_eq!(
            actions[0]["route"],
            format!("/api/v1/decisions/{decision_id}/approve")
        );
    })
}

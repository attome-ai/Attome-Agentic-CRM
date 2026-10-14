//! D-448 / M98 — the first live-database test for an agent-initiated
//! Consequential action's full lifecycle: `dispatch` submits it for
//! four-eyes approval (`GateDecision::RequiresApproval`), and a different
//! admin's `POST /api/v1/admin/approvals/{id}/decide` actually runs it —
//! closing the gap `execute.rs`'s `ApprovalRequired` doc comment used to
//! describe as still open ("nothing ever actually executed it").
//!
//! There is no HTTP submission endpoint to drive here the way
//! `approval_role_grant.rs` drives one: `POST /api/v1/actions/{id}/invoke`
//! always builds `ActionContext::user` (`engine.rs::invoke_action`), so an
//! agent-initiated invocation — the only initiator `gate::evaluate` ever
//! returns `RequiresApproval` for — is reached by calling
//! `attome_ai::execute::dispatch` directly, the same way a real AI
//! orchestration caller would. The approval half is genuinely HTTP-level,
//! through the same `execute_approved` chokepoint every other gated action
//! type in this file's sibling tests goes through.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `approval_role_grant.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test approval_agent_action -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use attome_ai::actions::agent_supervise::AGENT_PAUSE;
use attome_ai::context::ActionContext;
use attome_ai::descriptor::RiskTier;
use attome_ai::execute::{ActionOutcome, Executors, dispatch};
use attome_ai::gate::GateInputs;
use attome_ai::registry::ActionRegistry;
use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_server::security::SecurityContext;
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
            "inference": {{ "ai": {{
                "enabled": true, "fields": true, "chat": true,
                "semantic_search": true, "workflow_nodes": true
            }} }},
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
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
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
        .bind(format!("approval-agent-action-test-{user_id}"))
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

/// Grants `ai_agent.supervise` (`agent.pause`'s required privilege)
/// directly to `user_id`. Execution re-resolves the requester from the
/// database, so a requester who never held it has nothing to be approved for.
async fn grant_supervise(db: &attome_db::DbPool, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, 'ai_agent.supervise', 'ai_agent.supervise', 'test', true, NOW(), 'project') \
         ON CONFLICT (key) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .execute(db)
    .await
    .expect("ensure privilege row");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT $1, $2, id, true, NOW() FROM privilege WHERE key = 'ai_agent.supervise'",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .execute(db)
    .await
    .expect("grant privilege");
}

/// The agent session an owner starts — separate from the *supervised*
/// session `agent.pause`'s `args.session_id` targets, exactly the way a
/// live deployment can have one live agent submit a Consequential action
/// against a different one it (or another agent) is supervising.
async fn open_agent_session(db: &attome_db::DbPool, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface) \
         VALUES ($1, 2, 'test') RETURNING id",
    )
    .bind(owner)
    .fetch_one(db)
    .await
    .expect("open agent session")
}

async fn session_paused_at(
    db: &attome_db::DbPool,
    session_id: Uuid,
) -> Option<chrono::DateTime<chrono::Utc>> {
    sqlx::query_scalar("SELECT paused_at FROM agent_session WHERE id = $1")
        .bind(session_id)
        .fetch_one(db)
        .await
        .expect("read agent_session.paused_at")
}

fn security_context(user_id: Uuid) -> Arc<SecurityContext> {
    Arc::new(SecurityContext {
        user_id,
        is_admin: true,
        privileges: HashSet::new(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    })
}

fn all_on_gate_inputs(ai: &attome_config::AiEnablement) -> GateInputs<'_> {
    GateInputs {
        licensed: true,
        ai,
        surface: None,
        external_effects_enabled: false,
    }
}

fn all_on() -> attome_config::AiEnablement {
    attome_config::AiEnablement {
        enabled: true,
        fields: true,
        chat: true,
        semantic_search: true,
        workflow_nodes: true,
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
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

/// **The whole path, end to end.** An agent-initiated `agent.pause` (a real
/// registered `Consequential` action) is refused execution by `dispatch`
/// and submitted for four-eyes approval instead; nothing pauses yet. A
/// *different* admin approving it over HTTP runs it for real — the session
/// named in the original call's `args` actually ends up paused — and the
/// approval row is marked executed so a repeat decide 409s.
#[test]
fn a_different_admins_approval_actually_pauses_the_session() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (owner, _) = seed_user(&system, false).await;
        grant_supervise(&db, owner).await;
        let (_, approver_cookie) = seed_user(&system, true).await;
        let agent_session_id = open_agent_session(&db, owner).await;
        let target_session_id = open_agent_session(&db, owner).await;

        let ctx = ActionContext::agent(security_context(owner), RiskTier::Consequential)
            .with_agent_session(agent_session_id);
        let ai = all_on();
        let registry = ActionRegistry::new();
        let executors = Executors::new();
        let args = serde_json::json!({
            "session_id": target_session_id,
            "reason": "test: agent asked a supervisor to pause a runaway session",
        });

        let outcome = dispatch(
            system.state(),
            &registry,
            &executors,
            AGENT_PAUSE,
            &ctx,
            &all_on_gate_inputs(&ai),
            &args,
        )
        .await
        .expect("dispatch must succeed");

        let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
            panic!(
                "a Consequential agent action must require approval, not execute inline: {outcome:?}"
            );
        };

        assert!(
            session_paused_at(&db, target_session_id).await.is_none(),
            "nothing may execute before approval"
        );

        let app = full_app(system);
        let resp = app
            .clone()
            .oneshot(decide_request(&approver_cookie, approval_id, "approve", 0))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["status"], "approved");
        assert_eq!(
            body["executed"]["session_id"],
            target_session_id.to_string()
        );
        assert_eq!(body["executed"]["changed"], true);

        assert!(
            session_paused_at(&db, target_session_id).await.is_some(),
            "approval must actually run agent.pause against the target session"
        );

        let resp = app
            .clone()
            .oneshot(decide_request(&approver_cookie, approval_id, "approve", 1))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "an already-executed approval must not run twice"
        );
    })
}

/// **NEGATIVE, the P0 half.** The requester loses the action's required
/// privilege between asking and a second admin approving. Approval succeeds as
/// a decision, but execution revalidates and refuses: the approver gets a 409,
/// nothing is paused, and the request lands in the terminal `invalidated`
/// status — so `retry-execution` cannot run it later either, even if the
/// privilege is granted back.
#[test]
fn an_approval_granted_after_the_requester_lost_the_privilege_is_invalidated_not_run() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (owner, _) = seed_user(&system, false).await;
        grant_supervise(&db, owner).await;
        let (_, approver_cookie) = seed_user(&system, true).await;
        let agent_session_id = open_agent_session(&db, owner).await;
        let target_session_id = open_agent_session(&db, owner).await;

        let ctx = ActionContext::agent(security_context(owner), RiskTier::Consequential)
            .with_agent_session(agent_session_id);
        let ai = all_on();
        let args = serde_json::json!({ "session_id": target_session_id });
        let outcome = dispatch(
            system.state(),
            &ActionRegistry::new(),
            &Executors::new(),
            AGENT_PAUSE,
            &ctx,
            &all_on_gate_inputs(&ai),
            &args,
        )
        .await
        .expect("dispatch must succeed");
        let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
            panic!("expected ApprovalRequired: {outcome:?}");
        };

        sqlx::query("DELETE FROM user_account_mm_privilege WHERE user_ref = $1")
            .bind(owner)
            .execute(&db)
            .await
            .expect("revoke the requester's privilege");

        let app = full_app(system);
        let resp = app
            .clone()
            .oneshot(decide_request(&approver_cookie, approval_id, "approve", 0))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "execution must refuse an action the requester is no longer permitted"
        );
        assert!(
            session_paused_at(&db, target_session_id).await.is_none(),
            "an invalidated approval must not have run the action"
        );

        let (status, executed_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as("SELECT status, executed_at FROM approval_request WHERE id = $1")
                .bind(approval_id)
                .fetch_one(&db)
                .await
                .expect("read the approval request");
        assert_eq!(
            status, "invalidated",
            "the request must be terminal, not approved forever"
        );
        assert!(executed_at.is_none());

        // The privilege comes back. The old approval must still not run.
        grant_supervise(&db, owner).await;
        let retry = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/admin/approvals/{approval_id}/retry-execution"
            ))
            .header("cookie", &approver_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(retry).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(session_paused_at(&db, target_session_id).await.is_none());
    })
}

/// **D-502, over HTTP: pause is "not now".** The requesting agent session is
/// paused when a second admin approves. The approver gets a 409 naming the
/// pause, nothing runs, and the request stays `approved` — not `invalidated`.
/// After the session is resumed, `retry-execution` runs the same approval and
/// the request ends `executed`.
#[test]
fn an_approval_taken_while_the_session_is_paused_waits_and_runs_after_resume() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (owner, _) = seed_user(&system, false).await;
        grant_supervise(&db, owner).await;
        let (_, approver_cookie) = seed_user(&system, true).await;
        let agent_session_id = open_agent_session(&db, owner).await;
        let target_session_id = open_agent_session(&db, owner).await;

        let ctx = ActionContext::agent(security_context(owner), RiskTier::Consequential)
            .with_agent_session(agent_session_id);
        let ai = all_on();
        let args = serde_json::json!({ "session_id": target_session_id });
        let outcome = dispatch(
            system.state(),
            &ActionRegistry::new(),
            &Executors::new(),
            AGENT_PAUSE,
            &ctx,
            &all_on_gate_inputs(&ai),
            &args,
        )
        .await
        .expect("dispatch must succeed");
        let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
            panic!("expected ApprovalRequired: {outcome:?}");
        };

        attome_ai::session::pause(&db, agent_session_id, owner, "test: supervisor pause")
            .await
            .expect("pause the requesting session");

        let app = full_app(system);
        let resp = app
            .clone()
            .oneshot(decide_request(&approver_cookie, approval_id, "approve", 0))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert!(
            session_paused_at(&db, target_session_id).await.is_none(),
            "nothing may run while the requesting session is paused"
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
                .bind(approval_id)
                .fetch_one(&db)
                .await
                .expect("read status");
        assert_eq!(
            status, "approved",
            "a pause must not invalidate the approval"
        );

        attome_ai::session::resume(&db, agent_session_id)
            .await
            .expect("resume");

        let retry = Request::builder()
            .method("POST")
            .uri(format!(
                "/api/v1/admin/approvals/{approval_id}/retry-execution"
            ))
            .header("cookie", &approver_cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(retry).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "after resume the approval must run"
        );
        assert!(
            session_paused_at(&db, target_session_id).await.is_some(),
            "the approved action must have run after resume"
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
                .bind(approval_id)
                .fetch_one(&db)
                .await
                .expect("read status");
        assert_eq!(status, "executed");
    })
}

/// Separation-of-duties holds for this action family too:
/// `attome_approval::decide`'s `approver_id != requested_by` check refuses the
/// agent's own owner, the human `request_approval` records as requester
/// (`AgentActionRequest`'s doc comment / `consequential_gate.rs`'s own test).
#[test]
fn the_agents_owner_cannot_approve_their_own_agents_pause_request() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (owner, owner_cookie) = seed_user(&system, true).await;
        let agent_session_id = open_agent_session(&db, owner).await;
        let target_session_id = open_agent_session(&db, owner).await;

        let ctx = ActionContext::agent(security_context(owner), RiskTier::Consequential)
            .with_agent_session(agent_session_id);
        let ai = all_on();
        let registry = ActionRegistry::new();
        let executors = Executors::new();
        let args = serde_json::json!({ "session_id": target_session_id });

        let outcome = dispatch(
            system.state(),
            &registry,
            &executors,
            AGENT_PAUSE,
            &ctx,
            &all_on_gate_inputs(&ai),
            &args,
        )
        .await
        .expect("dispatch must succeed");
        let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
            panic!("expected ApprovalRequired: {outcome:?}");
        };

        let app = full_app(system);
        let resp = app
            .oneshot(decide_request(&owner_cookie, approval_id, "approve", 0))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(session_paused_at(&db, target_session_id).await.is_none());
    })
}

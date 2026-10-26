//! Audit 10/10 contract C19 (plan items 3.4 and 4.3): an AI-executed action
//! records the agent, the model, the approval request and the initiating
//! user, and keeps them on the production chainer path.
//!
//! Harness copied from `approval_agent_action.rs` (same `point_config_at`
//! fix for the migrator connection).
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test ai_action_attribution -- --test-threads=1
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

async fn test_system() -> Option<EngineSystem> {
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
        unit_scope: Default::default(),
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

/// Provisions just the `ai_model` and `ai_agent` columns the C19
/// model lookup reads (the same minimal posture as
/// `attome-ai/tests/agent_session_governance.rs`), then refreshes the registry.
async fn seed_agent_catalog(system: &EngineSystem) {
    let state = system.state();
    let db = &state.base.db;
    let model =
        attome_metadata::provision::ensure_entity(db, "ai_model", "AI Model", Some("name"), false)
            .await
            .expect("ensure_entity ai_model");
    for logicalname in ["name", "provider_model_id"] {
        attome_metadata::provision::ensure_attribute(
            db,
            model,
            logicalname,
            logicalname,
            "text",
            false,
            false,
            true,
            true,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure_attribute ai_model.{logicalname}: {e:?}"));
    }
    let agent =
        attome_metadata::provision::ensure_entity(db, "ai_agent", "AI Agent", Some("name"), false)
            .await
            .expect("ensure_entity ai_agent");
    for logicalname in ["name", "status", "primary_model_ref"] {
        attome_metadata::provision::ensure_attribute(
            db,
            agent,
            logicalname,
            logicalname,
            "text",
            false,
            false,
            true,
            true,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure_attribute ai_agent.{logicalname}: {e:?}"));
    }
    let registry = attome_core::build_registry(db)
        .await
        .expect("build_registry");
    state.entities.swap(registry);
}

/// An agent definition whose primary model has `provider_model_id`, and an
/// agent session started from it.
async fn session_from_definition(
    db: &attome_db::DbPool,
    owner: Uuid,
    provider_model_id: &str,
) -> Uuid {
    let model = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_model (id, name, provider_model_id, created_at) \
         VALUES ($1, 'c19 model', $2, NOW())",
    )
    .bind(model)
    .bind(provider_model_id)
    .execute(db)
    .await
    .expect("insert ai_model");
    let definition = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent (id, name, status, primary_model_ref, created_at) \
         VALUES ($1, 'c19 agent', 'active', $2, NOW())",
    )
    .bind(definition)
    .bind(model.to_string())
    .execute(db)
    .await
    .expect("insert ai_agent");
    sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface, agent_definition_ref) \
         VALUES ($1, 2, 'test', $2) RETURNING id",
    )
    .bind(owner)
    .bind(definition)
    .fetch_one(db)
    .await
    .expect("open agent session from the definition")
}

/// `(initiator, agent_session_id, agent_action_id, ai_model_id,
/// approval_request_ref, user_id, hash_version)` of one header.
type HeaderAttribution = (
    i16,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Uuid,
    i16,
);

/// **C19.** An agent-initiated Consequential action (`agent.pause`) that a
/// second admin approves writes one mandatory `Ai` + `Execute` event that
/// names the initiating user (`user_id`, attribution `acting_user_id`), the
/// agent (`initiator = agent`, `agent_session_id`, `agent_action_id`), the
/// model (`ai_model_id`, the definition's provider model id) and the approval
/// request (`approval_request_ref`). The event is captured on the production
/// chainer path, and every one of those fields survives the chainer into
/// `audit_header`.
#[tokio::test]
async fn records_agent_model_approval_and_initiator() {
    let system = skip_if_no_db!(test_system().await);
    assert!(
        system.state().base.config.audit.chainer_enabled,
        "this test proves the chainer path; audit.chainer_enabled must be on (its default)"
    );
    seed_agent_catalog(&system).await;
    let db = system.state().base.db.clone();
    let (owner, _) = seed_user(&system, false).await;
    grant_supervise(&db, owner).await;
    let (approver, approver_cookie) = seed_user(&system, true).await;
    let model_id = format!("c19-model-{}", Uuid::now_v7().simple());
    let agent_session_id = session_from_definition(&db, owner, &model_id).await;
    let target_session_id = open_agent_session(&db, owner).await;

    let ctx = ActionContext::agent(security_context(owner), RiskTier::Consequential)
        .with_agent_session(agent_session_id);
    let ai = all_on();
    let outcome = dispatch(
        system.state(),
        &ActionRegistry::new(),
        &Executors::new(),
        AGENT_PAUSE,
        &ctx,
        &all_on_gate_inputs(&ai),
        &serde_json::json!({ "session_id": target_session_id, "reason": "c19" }),
    )
    .await
    .expect("dispatch");
    let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
        panic!("a Consequential agent action must require approval: {outcome:?}");
    };

    let resp = full_app(system)
        .oneshot(decide_request(&approver_cookie, approval_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Captured on the chainer path: one ingest row carrying every C19 field.
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT payload FROM audit_ingest \
         WHERE payload->>'category' = 'Ai' AND payload->>'operation' = 'Execute' \
           AND payload->>'record_id' = $1",
    )
    .bind(agent_session_id.to_string())
    .fetch_all(&db)
    .await
    .expect("read ingest");
    assert_eq!(rows.len(), 1, "exactly one Ai+Execute event: {rows:?}");
    let payload = &rows[0];
    assert_eq!(payload["user_context"]["user_id"], owner.to_string());
    assert_eq!(payload["attribution"]["acting_user_id"], owner.to_string());
    assert_eq!(payload["attribution"]["initiator"], "agent");
    assert_eq!(
        payload["attribution"]["agent_session_id"],
        agent_session_id.to_string()
    );
    assert_eq!(payload["attribution"]["agent_action_id"], AGENT_PAUSE);
    assert_eq!(payload["extras"]["ai_model_id"], model_id);
    assert_eq!(
        payload["extras"]["approval_request_ref"],
        approval_id.to_string()
    );

    // The approval's own execution event names the approver.
    let executed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_ingest \
         WHERE payload->>'category' = 'BusinessEvent' AND payload->>'operation' = 'Execute' \
           AND payload->>'record_id' = $1 AND payload->'user_context'->>'user_id' = $2",
    )
    .bind(approval_id.to_string())
    .bind(approver.to_string())
    .fetch_one(&db)
    .await
    .expect("count execution events");
    assert_eq!(executed, 1);

    // Kept on the chainer path: drain and read the header columns back.
    attome_audit::chainer::run_once(&db, None, 10_000, None)
        .await
        .expect("chainer run");
    let header: HeaderAttribution = sqlx::query_as(
        "SELECT initiator, agent_session_id, agent_action_id, ai_model_id, \
                    approval_request_ref, user_id, hash_version \
             FROM audit_header \
             WHERE category = $1 AND operation = $2 AND record_id = $3",
    )
    .bind(attome_audit::AuditCategory::Ai as i32)
    .bind(attome_audit::AuditOperation::Execute as i32)
    .bind(agent_session_id)
    .fetch_one(&db)
    .await
    .expect("the chainer wrote the Ai+Execute header");
    assert_eq!(header.0, attome_audit::Initiator::Agent.as_i16());
    assert_eq!(header.1, Some(agent_session_id));
    assert_eq!(header.2.as_deref(), Some(AGENT_PAUSE));
    assert_eq!(header.3.as_deref(), Some(model_id.as_str()));
    assert_eq!(header.4, Some(approval_id));
    assert_eq!(header.5, owner);
    assert_eq!(header.6, attome_audit::canonical::HASH_VERSION_V2);
}

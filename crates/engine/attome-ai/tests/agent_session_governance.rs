//! D-503 — agent session governance against a real database.
//!
//! These tests prove **effective authority**, not stored fields. Each one
//! drives the real gate (`dispatch`) or the real approval re-check
//! (`dispatch_approved_agent_action`) under a session opened through
//! `agent::start_session`, and asserts what the session can and cannot do:
//!
//! - a session starts only from an `active` definition with a live model, and
//!   only for a caller who can read the definition;
//! - the session carries exactly the constraints its surface supplied, with
//!   the caller as owner;
//! - the ceiling cannot be exceeded, even by an admin owner;
//! - the allow-list cannot be widened;
//! - the owner's privileges are the hard cap, whatever the ceiling;
//! - constraints do not change after start (definition edits, pause/resume);
//! - an approved action from a governed session is re-checked at execution.
//!
//! The D-505 governance snapshot, at the storage layer:
//! - it round-trips through every session loader;
//! - editing, retiring or deleting its policy never changes it;
//! - the database refuses an inconsistent snapshot.
//!
//! And the policy as enforced (D-505, made exact by D-512):
//! - a definition-started session requires a resolvable, valid policy, and a
//!   refused start leaves no session behind;
//! - the policy only narrows: lowest ceiling, intersected allow-lists;
//! - the effective values and limits are snapshotted at start;
//! - every call reaching a live session and a known action consumes
//!   invocation budget before the gate, atomically under concurrency;
//! - a session past its duration is gone, and its approved work dies with it;
//! - the daily write total is session-wide and holds under concurrency;
//! - a session with no policy term keeps D-503 semantics (MCP, webchat).
//!
//! No model is called: the agent execution loop does not exist yet, so the
//! per-model-call gates are not tested here. The knowledge scope is proven
//! end to end in `knowledge_answer.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! $env:APP_ENV = "debug"
//! cargo test -p attome-ai --test agent_session_governance -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;

use attome_ai::actions::agent_supervise::{AGENT_PAUSE, AGENT_RESUME};
use attome_ai::actions::memory::MEMORY_REMEMBER;
use attome_ai::agent::{SessionConstraints, start_session};
use attome_ai::approval::{AgentActionRequest, approved_payload};
use attome_ai::capability_pack::CapabilityPackRef;
use attome_ai::context::ActionContext;
use attome_ai::descriptor::{ActionId, RiskTier};
use attome_ai::execute::{
    ActionOutcome, ApprovedExecution, Executors, dispatch, dispatch_approved_agent_action,
};
use attome_ai::gate::GateInputs;
use attome_ai::registry::ActionRegistry;
use attome_ai::session::{
    self, AgentSession, PolicySnapshot, SessionForExecution, SessionStart, WriteReservation,
};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_modules::ModuleSet;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// The privilege `agent.pause` requires (`AgentSupervise::KEY`).
const SUPERVISE: &str = "ai_agent.supervise";

fn test_config(direct_url: &str) -> AppConfig {
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
                "user": "unused", "password": "unused", "schema": "public",
                "connection_number": 5, "timeout": 5.0,
                "direct_url": "{direct_url}"
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
                "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
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
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        direct_url = direct_url,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

// SAFETY: see `attome-workflow/tests/execution.rs`'s identical `ENV_LOCK` doc
// comment — `attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` from the
// environment synchronously before its first `.await`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
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
    let state = EngineState::new(base);
    state.license.store(Arc::new(ModuleSet {
        module_bits: [u64::MAX; 4],
        max_users: u32::MAX,
        expires: chrono::Utc::now() + chrono::Duration::days(365),
    }));
    seed_agent_entities(&state).await;
    Some(state)
}

/// Provisions just the `ai_agent` and `ai_model` columns
/// `start_session` reads, not the full platform bundles (their lookup chains
/// are not under test) — the same posture `ai_governance.rs` takes.
async fn seed_agent_entities(state: &EngineState) {
    let db = &state.base.db;
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");

    let model =
        attome_metadata::provision::ensure_entity(db, "ai_model", "AI Model", Some("name"), false)
            .await
            .expect("ensure_entity ai_model");
    attome_metadata::provision::ensure_attribute(
        db, model, "name", "Name", "text", true, false, true, true, None, None,
    )
    .await
    .expect("ensure_attribute ai_model.name");
    // C19: the mandatory `Ai` + `Execute` event reads the definition's
    // provider model id.
    attome_metadata::provision::ensure_attribute(
        db,
        model,
        "provider_model_id",
        "Provider Model ID",
        "text",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .expect("ensure_attribute ai_model.provider_model_id");

    let agent =
        attome_metadata::provision::ensure_entity(db, "ai_agent", "AI Agent", Some("name"), false)
            .await
            .expect("ensure_entity ai_agent");
    for (logicalname, display) in [
        ("name", "Name"),
        ("status", "Status"),
        ("primary_model_ref", "Primary Model"),
        ("system_instructions", "System Instructions"),
        ("policy_ref", "Policy"),
        ("retrieval_mode", "Knowledge Retrieval"),
    ] {
        attome_metadata::provision::ensure_attribute(
            db,
            agent,
            logicalname,
            display,
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

    // D-505: the policy columns `start_session` reads, typed as in the bundle:
    // the allow-list is a multi-valued choice (`TEXT[]`), the knowledge scope
    // a JSON-array text field, and the limits numbers.
    let policy = attome_metadata::provision::ensure_entity(
        db,
        "ai_agent_policy",
        "AI Agent Policy",
        Some("name"),
        false,
    )
    .await
    .expect("ensure_entity ai_agent_policy");
    let action_choices = serde_json::json!({
        "choices": ActionRegistry::new()
            .all()
            .map(|descriptor| descriptor.id.as_str())
            .collect::<Vec<_>>(),
        "multi": true,
    });
    for (logicalname, display, field_type, options) in [
        ("name", "Name", "text", None),
        ("risk_ceiling", "Risk Ceiling", "text", None),
        (
            "allowed_action_ids",
            "Allowed Actions",
            "choice",
            Some(action_choices),
        ),
        ("knowledge_source_refs", "Knowledge Sources", "text", None),
        // C6/D-556: the pack references, a JSON array of pack ids in a text
        // field exactly like the knowledge scope above.
        ("capability_pack_refs", "Capability Packs", "text", None),
        (
            "max_invocations_per_session",
            "Max Invocations",
            "number",
            None,
        ),
        ("max_writes_per_day", "Max Writes per Day", "number", None),
        ("max_tokens_per_session", "Max Tokens", "number", None),
        (
            "max_session_duration_minutes",
            "Max Duration (minutes)",
            "number",
            None,
        ),
    ] {
        attome_metadata::provision::ensure_attribute(
            db,
            policy,
            logicalname,
            display,
            field_type,
            false,
            false,
            false,
            false,
            None,
            options,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure_attribute ai_agent_policy.{logicalname}: {e:?}"));
    }

    // C6/D-556: the pack entity `capability_pack::resolve` reads through
    // `entity_crud::read_record` — an ordinary metadata entity, provisioned
    // here the way the platform bundle provisions it at boot.
    let pack = attome_metadata::provision::ensure_entity(
        db,
        "ai_capability_pack",
        "AI Capability Pack",
        Some("name"),
        false,
    )
    .await
    .expect("ensure_entity ai_capability_pack");
    for (logicalname, display, field_type) in [
        ("name", "Name", "text"),
        ("description", "Description", "text"),
        ("action_ids", "Action IDs", "text"),
    ] {
        attome_metadata::provision::ensure_attribute(
            db,
            pack,
            logicalname,
            display,
            field_type,
            false,
            false,
            true,
            true,
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("ensure_attribute ai_capability_pack.{logicalname}: {e:?}"));
    }

    let registry = attome_core::build_registry(db)
        .await
        .expect("build_registry");
    state.entities.swap(registry);
}

async fn seed_user(db: &DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("agent-session-governance-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Grants `key` directly to `user_id`, creating the privilege row if needed.
async fn grant_privilege(db: &DbPool, user_id: Uuid, key: &str) {
    sqlx::query(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, 'test', true, NOW(), 'project') ON CONFLICT (key) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(key)
    .execute(db)
    .await
    .expect("ensure privilege row");
    let privilege_id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(key)
        .fetch_one(db)
        .await
        .expect("read privilege id");
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
}

/// The caller's security context, resolved from the database like a request.
async fn resolve(db: &DbPool, user_id: Uuid) -> SecurityContext {
    attome_security::resolve_uncached(db, user_id)
        .await
        .expect("resolve security context")
}

async fn admin(db: &DbPool) -> (Uuid, SecurityContext) {
    let user = seed_user(db).await;
    grant_privilege(db, user, "system.admin").await;
    let security = resolve(db, user).await;
    assert!(security.is_admin, "system.admin must resolve to an admin");
    (user, security)
}

async fn live_model(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO ai_model (id, name, created_at) VALUES ($1, 'test model', NOW())")
        .bind(id)
        .execute(db)
        .await
        .expect("insert ai_model row");
    id
}

/// The four D-512 execution limits.
const LIMITS: [&str; 4] = [
    "max_invocations_per_session",
    "max_writes_per_day",
    "max_tokens_per_session",
    "max_session_duration_minutes",
];

/// A valid policy that narrows nothing the D-503 tests rely on: a
/// `consequential` ceiling, no lists, and generous limits.
fn open_policy() -> Value {
    serde_json::json!({
        "risk_ceiling": "consequential",
        "max_invocations_per_session": 1000,
        "max_writes_per_day": 1000,
        "max_tokens_per_session": 200000,
        "max_session_duration_minutes": 600,
    })
}

/// [`open_policy`] with `overrides` applied.
fn policy_with(overrides: &[(&str, Value)]) -> Value {
    let mut policy = open_policy();
    for (field, value) in overrides {
        policy[*field] = value.clone();
    }
    policy
}

/// Inserts an `ai_agent_policy` row from `fields`, each converted to its
/// column type by Postgres; an absent field is NULL.
async fn insert_policy(db: &DbPool, fields: &Value) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent_policy \
            (id, name, risk_ceiling, allowed_action_ids, knowledge_source_refs, \
             capability_pack_refs, max_invocations_per_session, max_writes_per_day, \
             max_tokens_per_session, max_session_duration_minutes, created_at) \
         SELECT $1, 'test policy', p.risk_ceiling, p.allowed_action_ids, p.knowledge_source_refs, \
                p.capability_pack_refs, p.max_invocations_per_session, p.max_writes_per_day, \
                p.max_tokens_per_session, p.max_session_duration_minutes, NOW() \
           FROM json_populate_record(NULL::ai_agent_policy, $2::json) p",
    )
    .bind(id)
    .bind(fields)
    .execute(db)
    .await
    .expect("insert ai_agent_policy row");
    id
}

/// The policy's `capability_pack_refs` value: a JSON array of pack ids stored
/// in a text column, exactly as the entity form writes it.
fn pack_refs_json(packs: &[Uuid]) -> Value {
    Value::String(serde_json::to_string(packs).expect("pack refs as json"))
}

/// Inserts an `ai_capability_pack` row and returns `(id, row_version)`.
async fn insert_pack(db: &DbPool, action_ids: &[&str]) -> (Uuid, i64) {
    let id = Uuid::now_v7();
    let ids = Value::Array(
        action_ids
            .iter()
            .map(|id| Value::String((*id).to_owned()))
            .collect(),
    );
    let row_version: i64 = sqlx::query_scalar(
        "INSERT INTO ai_capability_pack (id, name, action_ids, created_at) \
         VALUES ($1, 'test pack', $2, NOW()) RETURNING row_version",
    )
    .bind(id)
    .bind(ids.to_string())
    .fetch_one(db)
    .await
    .expect("insert ai_capability_pack row");
    (id, row_version)
}

/// An agent definition under a fresh [`open_policy`].
async fn definition(db: &DbPool, status: &str, primary_model_ref: Option<Uuid>) -> Uuid {
    let policy = insert_policy(db, &open_policy()).await;
    definition_with_policy(db, status, primary_model_ref, Some(policy)).await
}

async fn definition_with_policy(
    db: &DbPool,
    status: &str,
    primary_model_ref: Option<Uuid>,
    policy_ref: Option<Uuid>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent \
            (id, name, status, primary_model_ref, system_instructions, policy_ref, created_at) \
         VALUES ($1, 'test agent', $2, $3, 'Be concise.', $4, NOW())",
    )
    .bind(id)
    .bind(status)
    .bind(primary_model_ref.map(|m| m.to_string()))
    .bind(policy_ref.map(|p| p.to_string()))
    .execute(db)
    .await
    .expect("insert ai_agent row");
    id
}

/// An active definition with a live model under a new policy built from
/// `fields`. Returns `(policy, definition)`.
async fn governed_definition(db: &DbPool, fields: &Value) -> (Uuid, Uuid) {
    let policy = insert_policy(db, fields).await;
    let model = live_model(db).await;
    let def = definition_with_policy(db, "active", Some(model), Some(policy)).await;
    (policy, def)
}

async fn invocations_used(db: &DbPool, session_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT invocations_used FROM agent_session WHERE id = $1")
        .bind(session_id)
        .fetch_one(db)
        .await
        .expect("read invocations_used")
}

/// Completed ledger rows for `session_id`, optionally for one action.
async fn completed_writes(db: &DbPool, session_id: Uuid, action: Option<&str>) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_invocation \
          WHERE agent_session_id = $1 AND outcome = 'completed' \
            AND ($2::text IS NULL OR action_id = $2)",
    )
    .bind(session_id)
    .bind(action)
    .fetch_one(db)
    .await
    .expect("count completed invocations")
}

/// Moves a session's start into the past, as if `minutes` had elapsed.
async fn started_minutes_ago(db: &DbPool, session_id: Uuid, minutes: i32) {
    sqlx::query(
        "UPDATE agent_session SET started_at = NOW() - make_interval(mins => $2) \
          WHERE id = $1",
    )
    .bind(session_id)
    .bind(minutes)
    .execute(db)
    .await
    .expect("age the session");
}

async fn sessions_started_from(db: &DbPool, definition_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM agent_session WHERE agent_definition_ref = $1")
        .bind(definition_id)
        .fetch_one(db)
        .await
        .expect("count sessions")
}

fn constraints(risk_ceiling: RiskTier, allowed: Option<&[&str]>) -> SessionConstraints {
    SessionConstraints {
        risk_ceiling,
        allowed_action_ids: allowed.map(|ids| ids.iter().map(|id| (*id).to_owned()).collect()),
    }
}

/// A session opened directly with the session primitive, for a target the
/// agent asks to pause, or for an owner who cannot read any definition.
async fn raw_session(db: &DbPool, owner: Uuid, risk_ceiling: RiskTier) -> AgentSession {
    session::start(
        db,
        &attome_audit::AuditService::new(db, None).with_chainer_enabled(true),
        SessionStart {
            owner_user_id: owner,
            risk_ceiling,
            allowed_action_ids: None,
            surface: "test",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("open session")
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

/// The agent, acting in `session` for the owner in `security`, asks to pause
/// `target`. Goes through the real `dispatch` gate.
async fn agent_asks_to_pause(
    state: &EngineState,
    security: SecurityContext,
    session: &AgentSession,
    target: Uuid,
) -> Result<ActionOutcome, AppError> {
    let ctx = ActionContext::for_session(Arc::new(security), session)
        .with_idempotency_key(format!("governance-{}", Uuid::now_v7()));
    let ai = all_on();
    let inputs = GateInputs {
        licensed: true,
        ai: &ai,
        surface: None,
        external_effects_enabled: false,
    };
    dispatch(
        state,
        &ActionRegistry::new(),
        &Executors::new(),
        AGENT_PAUSE,
        &ctx,
        &inputs,
        &serde_json::json!({ "session_id": target, "reason": "governance test" }),
    )
    .await
}

/// The agent, acting in `session`, invokes `action` as tool call `key`,
/// through the real `dispatch` gate.
async fn agent_invokes(
    state: &EngineState,
    security: Arc<SecurityContext>,
    session: &AgentSession,
    action: &str,
    key: &str,
    args: Value,
) -> Result<ActionOutcome, AppError> {
    let ctx = ActionContext::for_session(security, session).with_idempotency_key(key.to_owned());
    let ai = all_on();
    let inputs = GateInputs {
        licensed: true,
        ai: &ai,
        surface: None,
        external_effects_enabled: false,
    };
    dispatch(
        state,
        &ActionRegistry::new(),
        &Executors::new(),
        action,
        &ctx,
        &inputs,
        &args,
    )
    .await
}

/// A `memory.remember` proposal: an agent save always stops at confirmation
/// (M35 C1), so it is a known action that runs nothing.
fn remember_args() -> Value {
    serde_json::json!({ "kind": "preference", "summary": "prefers short answers" })
}

/// The agent in `session` asks for supervision `action` on `target`, and a
/// different user approves it. Returns the approved request.
async fn approved_supervision(
    state: &EngineState,
    security: &Arc<SecurityContext>,
    session: &AgentSession,
    action: &str,
    target: Uuid,
    approver: Uuid,
) -> AgentActionRequest {
    let outcome = agent_invokes(
        state,
        Arc::clone(security),
        session,
        action,
        &format!("governance-{}", Uuid::now_v7()),
        serde_json::json!({ "session_id": target, "reason": "governance test" }),
    )
    .await
    .expect("dispatch");
    let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
        panic!("a Consequential agent action must require approval: {outcome:?}");
    };
    let db = &state.base.db;
    attome_approval::decide(
        db,
        approval_id,
        approver,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("a distinct approver may approve");
    approved_payload(db, approval_id)
        .await
        .expect("read")
        .expect("approved payload")
}

async fn is_paused(db: &DbPool, session_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT paused_at IS NOT NULL FROM agent_session WHERE id = $1")
        .bind(session_id)
        .fetch_one(db)
        .await
        .expect("read paused_at")
}

/// D-503 §5: only an `active` definition with a live primary model starts a
/// session, and a refused start leaves no session behind.
#[tokio::test]
async fn only_an_active_definition_with_a_live_model_can_start_a_session() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;
    let model = live_model(db).await;

    for status in ["draft", "testing", "suspended", "archived", ""] {
        let def = definition(db, status, Some(model)).await;
        let started = start_session(
            &state,
            &security,
            def,
            "admin",
            constraints(RiskTier::Read, None),
            false,
        )
        .await;
        assert!(
            matches!(started, Err(AppError::Validation(_))),
            "status {status:?} must not start a session: {started:?}"
        );
        assert_eq!(sessions_started_from(db, def).await, 0, "{status:?}");
    }

    for model_ref in [None, Some(Uuid::now_v7())] {
        let def = definition(db, "active", model_ref).await;
        let started = start_session(
            &state,
            &security,
            def,
            "admin",
            constraints(RiskTier::Read, None),
            false,
        )
        .await;
        assert!(
            matches!(started, Err(AppError::Validation(_))),
            "an active definition without a live model must not start: {started:?}"
        );
        assert_eq!(sessions_started_from(db, def).await, 0);
    }

    let def = definition(db, "active", Some(model)).await;
    start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Read, None),
        false,
    )
    .await
    .expect("an active definition with a live model starts a session");
    assert_eq!(sessions_started_from(db, def).await, 1);
}

/// D-503 §3: the session carries exactly the surface-supplied constraints and
/// the definition reference, and it acts for the caller, never anyone else.
#[tokio::test]
async fn a_session_carries_the_supplied_constraints_and_acts_for_the_caller() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (caller, security) = admin(db).await;
    let def = definition(db, "active", Some(live_model(db).await)).await;

    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Reversible, Some(&["record.get"])),
        false,
    )
    .await
    .expect("start");

    let loaded = session::load_live(db, session.id)
        .await
        .expect("load")
        .expect("live");
    assert_eq!(loaded.owner_user_id, caller);
    assert_eq!(loaded.risk_ceiling, RiskTier::Reversible);
    assert_eq!(
        loaded.allowed_action_ids,
        Some(vec!["record.get".to_owned()])
    );
    assert!(!loaded.tainted);
    assert!(
        loaded.policy.policy_ref.is_some() && loaded.policy.policy_row_version.is_some(),
        "a definition-started session records the policy it started under: {:?}",
        loaded.policy
    );
    assert_eq!(
        (
            loaded.policy.knowledge_source_refs.clone(),
            loaded.policy.max_invocations_per_session,
            loaded.policy.max_writes_per_day,
            loaded.policy.max_tokens_per_session,
            loaded.policy.max_session_duration_minutes,
        ),
        (None, Some(1000), Some(1000), Some(200_000), Some(600)),
        "the open policy's limits are snapshotted"
    );

    let (surface, definition_ref): (String, Option<Uuid>) =
        sqlx::query_as("SELECT surface, agent_definition_ref FROM agent_session WHERE id = $1")
            .bind(session.id)
            .fetch_one(db)
            .await
            .expect("read session row");
    assert_eq!(surface, "admin");
    assert_eq!(definition_ref, Some(def));
}

/// **The ceiling cannot be exceeded.** An admin owner holds every privilege,
/// so the only thing that can refuse a Consequential action here is the
/// session's `Read` ceiling. Control: the same owner in a `Consequential`
/// session reaches the gate's approval path.
#[tokio::test]
async fn the_session_ceiling_cannot_be_exceeded_even_by_an_admin_owner() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let def = definition(db, "active", Some(live_model(db).await)).await;
    let target = raw_session(db, owner, RiskTier::Read).await;

    let read_only = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Read, None),
        false,
    )
    .await
    .expect("start read-only session");
    let refused =
        agent_asks_to_pause(&state, resolve(db, owner).await, &read_only, target.id).await;
    assert!(
        matches!(refused, Err(AppError::Forbidden)),
        "a Read session must not reach a Consequential action: {refused:?}"
    );

    let consequential = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start consequential session");
    let control =
        agent_asks_to_pause(&state, resolve(db, owner).await, &consequential, target.id).await;
    assert!(
        matches!(control, Ok(ActionOutcome::ApprovalRequired { .. })),
        "control: within the ceiling the gate reaches approval: {control:?}"
    );
    assert!(
        !is_paused(db, target.id).await,
        "nothing ran without approval"
    );
}

/// **The allow-list cannot be widened.** A session limited to other actions,
/// or to none, cannot invoke `agent.pause`, and the refusal looks like an
/// absent action.
#[tokio::test]
async fn the_session_allow_list_cannot_be_widened() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let def = definition(db, "active", Some(live_model(db).await)).await;
    let target = raw_session(db, owner, RiskTier::Read).await;

    for allowed in [&["record.get"][..], &[][..]] {
        let session = start_session(
            &state,
            &security,
            def,
            "admin",
            constraints(RiskTier::Consequential, Some(allowed)),
            false,
        )
        .await
        .expect("start");
        let refused =
            agent_asks_to_pause(&state, resolve(db, owner).await, &session, target.id).await;
        assert!(
            matches!(refused, Err(AppError::NotFound)),
            "an action outside the allow-list {allowed:?} must be refused: {refused:?}"
        );
    }
    assert!(!is_paused(db, target.id).await);
}

/// **The owner's privileges are the hard cap.** A caller who cannot read a
/// definition cannot start a session from it. And an owner without the
/// privilege an action needs is refused even at the highest ceiling; granting
/// the privilege, and nothing else, is what lets the same session reach the
/// gate's approval path.
#[tokio::test]
async fn owner_privileges_are_the_hard_cap_whatever_the_ceiling() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let def = definition(db, "active", Some(live_model(db).await)).await;
    let owner = seed_user(db).await;

    let started = start_session(
        &state,
        &resolve(db, owner).await,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await;
    assert!(
        started.is_err(),
        "a caller who cannot read the definition must not start a session from it"
    );
    assert_eq!(sessions_started_from(db, def).await, 0);

    // `start_session` always makes the caller the owner (proven above), so a
    // session for this unprivileged owner is opened with the same primitive
    // `start_session` writes through.
    let session = raw_session(db, owner, RiskTier::Consequential).await;
    let target = raw_session(db, owner, RiskTier::Read).await;

    let refused = agent_asks_to_pause(&state, resolve(db, owner).await, &session, target.id).await;
    assert!(
        matches!(refused, Err(AppError::Forbidden)),
        "an owner without ai_agent.supervise must be refused at any ceiling: {refused:?}"
    );

    grant_privilege(db, owner, SUPERVISE).await;
    let control = agent_asks_to_pause(&state, resolve(db, owner).await, &session, target.id).await;
    assert!(
        matches!(control, Ok(ActionOutcome::ApprovalRequired { .. })),
        "control: the privilege was the only thing missing: {control:?}"
    );
    assert!(!is_paused(db, target.id).await);
}

/// D-503 §4: a running session's constraints do not change. Editing or
/// suspending its definition, and pausing then resuming it, leave its owner,
/// ceiling and allow-list exactly as started. The edited definition can no
/// longer start a new session.
#[tokio::test]
async fn session_constraints_do_not_change_after_start() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let def = definition(db, "active", Some(live_model(db).await)).await;

    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Reversible, Some(&["record.get"])),
        false,
    )
    .await
    .expect("start");

    sqlx::query(
        "UPDATE ai_agent SET status = 'suspended', primary_model_ref = NULL, \
                system_instructions = 'You may do anything.' WHERE id = $1",
    )
    .bind(def)
    .execute(db)
    .await
    .expect("edit the definition");
    assert!(
        session::pause(db, session.id, owner, "test")
            .await
            .expect("pause")
    );
    assert!(session::resume(db, session.id).await.expect("resume"));

    let loaded = session::load_live(db, session.id)
        .await
        .expect("load")
        .expect("still live");
    assert_eq!(loaded.owner_user_id, owner);
    assert_eq!(loaded.risk_ceiling, RiskTier::Reversible);
    assert_eq!(
        loaded.allowed_action_ids,
        Some(vec!["record.get".to_owned()])
    );
    // Row A-76: the persona is the snapshot taken at start. The definition's
    // rewritten instructions never reach the running session.
    assert_eq!(
        loaded.policy.persona.as_deref(),
        Some("Be concise."),
        "an edited definition's instructions must not reach a running session"
    );

    let restarted = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Reversible, None),
        false,
    )
    .await;
    assert!(
        matches!(restarted, Err(AppError::Validation(_))),
        "a suspended definition must not start a new session: {restarted:?}"
    );
}

/// **Approved-action enforcement on a governed session.** An agent in a
/// session opened through `start_session` asks for a Consequential action, a
/// different user approves it, and the session is then revoked. Execution
/// re-checks the session and refuses; nothing runs.
#[tokio::test]
async fn an_approved_action_from_a_governed_session_is_rechecked_at_execution() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let approver = seed_user(db).await;
    let def = definition(db, "active", Some(live_model(db).await)).await;
    let target = raw_session(db, owner, RiskTier::Read).await;

    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");

    let outcome = agent_asks_to_pause(&state, resolve(db, owner).await, &session, target.id)
        .await
        .expect("dispatch");
    let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
        panic!("a Consequential agent action must require approval: {outcome:?}");
    };
    attome_approval::decide(
        db,
        approval_id,
        approver,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("a distinct approver may approve");
    let request = approved_payload(db, approval_id)
        .await
        .expect("read")
        .expect("approved payload");

    assert!(
        session::revoke(db, session.id, owner, "test")
            .await
            .expect("revoke")
    );
    let execution = dispatch_approved_agent_action(&state, &request)
        .await
        .expect("a refusal is a verdict, not a transient error");
    assert!(
        matches!(execution, ApprovedExecution::Invalidated { .. }),
        "an approval must not outlive its session: {execution:?}"
    );
    assert!(!is_paused(db, target.id).await, "nothing may have run");
}

/// A governance policy row, as a later `start_session` will read it: its id
/// and current `row_version`.
async fn policy(db: &DbPool, risk_ceiling: &str, max_writes_per_day: i32) -> (Uuid, i64) {
    let id = Uuid::now_v7();
    let row_version: i64 = sqlx::query_scalar(
        "INSERT INTO ai_agent_policy (id, name, risk_ceiling, max_writes_per_day, created_at) \
         VALUES ($1, 'test policy', $2, $3::numeric, NOW()) RETURNING row_version",
    )
    .bind(id)
    .bind(risk_ceiling)
    .bind(max_writes_per_day)
    .fetch_one(db)
    .await
    .expect("insert ai_agent_policy row");
    (id, row_version)
}

/// A snapshot with every D-505 value set.
fn full_snapshot(policy_ref: Uuid, policy_row_version: i64) -> session::PolicySnapshot {
    session::PolicySnapshot {
        policy_ref: Some(policy_ref),
        policy_row_version: Some(policy_row_version),
        knowledge_source_refs: Some(vec![Uuid::now_v7(), Uuid::now_v7()]),
        capability_pack_refs: Some(vec![CapabilityPackRef {
            id: Uuid::now_v7(),
            row_version: 4,
        }]),
        max_invocations_per_session: Some(40),
        max_writes_per_day: Some(10),
        max_tokens_per_session: Some(50_000),
        max_session_duration_minutes: Some(30),
        // The non-default mode, so the round trip proves it is stored (0481).
        retrieval_mode: session::KnowledgeRetrievalMode::PreRetrieved,
        // C11 B2: the persona snapshot round-trips like every other value (0490).
        persona: Some("Speak plainly.".into()),
    }
}

/// Opens a session carrying `snapshot` through the session primitive, the one
/// INSERT every start path writes through.
async fn open_with_snapshot(
    db: &DbPool,
    owner: Uuid,
    agent_definition_ref: Option<Uuid>,
    snapshot: session::PolicySnapshot,
) -> Result<AgentSession, AppError> {
    session::start(
        db,
        &attome_audit::AuditService::new(db, None).with_chainer_enabled(true),
        SessionStart {
            owner_user_id: owner,
            risk_ceiling: RiskTier::Reversible,
            allowed_action_ids: None,
            surface: "test",
            agent_definition_ref,
            integration_system_id: None,
            tainted: false,
            policy: snapshot,
        },
    )
    .await
}

async fn snapshot_of(db: &DbPool, session_id: Uuid) -> session::PolicySnapshot {
    session::load_live(db, session_id)
        .await
        .expect("load")
        .expect("live")
        .policy
}

/// D-505 §4, storage half: every snapshot value written at start comes back
/// unchanged through all three loaders. An empty knowledge scope stays
/// distinct from no scope. A session with no policy term (MCP, webchat) loads
/// as exactly `PolicySnapshot::NONE`.
#[tokio::test]
async fn a_policy_snapshot_round_trips_through_every_session_loader() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let owner = seed_user(db).await;
    let def = definition(db, "active", Some(live_model(db).await)).await;
    let (policy_ref, row_version) = policy(db, "reversible", 10).await;
    let snapshot = full_snapshot(policy_ref, row_version);

    let started = open_with_snapshot(db, owner, Some(def), snapshot.clone())
        .await
        .expect("start");
    assert_eq!(started.policy, snapshot, "start returns what it stored");

    assert_eq!(snapshot_of(db, started.id).await, snapshot, "load_live");
    let owned = session::load_live_owned(db, started.id, owner, "test")
        .await
        .expect("load_live_owned")
        .expect("live and owned");
    assert_eq!(owned.policy, snapshot, "load_live_owned");
    let session::SessionForExecution::Live(for_execution) =
        session::load_for_execution(db, started.id)
            .await
            .expect("load_for_execution")
    else {
        panic!("a live session must load as runnable");
    };
    assert_eq!(for_execution.policy, snapshot, "load_for_execution");

    let no_retrieval = session::PolicySnapshot {
        knowledge_source_refs: Some(vec![]),
        ..snapshot.clone()
    };
    let narrowed = open_with_snapshot(db, owner, Some(def), no_retrieval)
        .await
        .expect("start");
    assert_eq!(
        snapshot_of(db, narrowed.id).await.knowledge_source_refs,
        Some(vec![]),
        "an empty knowledge scope must not load as no scope"
    );

    let unscoped = open_with_snapshot(db, owner, None, session::PolicySnapshot::NONE)
        .await
        .expect("start");
    assert_eq!(
        snapshot_of(db, unscoped.id).await,
        session::PolicySnapshot::NONE
    );
}

/// D-505 §4, the snapshot boundary: a session keeps the policy values and the
/// `row_version` it started with while its policy is tightened, loosened,
/// retired and finally deleted. Nothing about a running session reads the
/// policy row.
#[tokio::test]
async fn editing_or_deleting_the_policy_never_changes_a_started_sessions_snapshot() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let owner = seed_user(db).await;
    let def = definition(db, "active", Some(live_model(db).await)).await;
    let (policy_ref, row_version) = policy(db, "reversible", 10).await;
    let snapshot = full_snapshot(policy_ref, row_version);
    let session = open_with_snapshot(db, owner, Some(def), snapshot.clone())
        .await
        .expect("start");

    for (edit, sql) in [
        (
            "tightened",
            "UPDATE ai_agent_policy SET risk_ceiling = 'read', max_writes_per_day = 1, \
             row_version = row_version + 1 WHERE id = $1",
        ),
        (
            "loosened",
            "UPDATE ai_agent_policy SET risk_ceiling = 'consequential', \
             max_writes_per_day = 50, row_version = row_version + 1 WHERE id = $1",
        ),
        (
            "retired",
            "UPDATE ai_agent_policy SET is_active = false, row_version = row_version + 1 \
             WHERE id = $1",
        ),
        ("deleted", "DELETE FROM ai_agent_policy WHERE id = $1"),
    ] {
        let affected = sqlx::query(sql)
            .bind(policy_ref)
            .execute(db)
            .await
            .unwrap_or_else(|e| panic!("policy {edit}: {e}"))
            .rows_affected();
        assert_eq!(affected, 1, "the policy row was {edit}");
        assert_eq!(
            snapshot_of(db, session.id).await,
            snapshot,
            "a policy that was {edit} must not reach a running session"
        );
    }
}

/// Migration 0466's invariants hold for every row, whatever writes it:
/// - a policy reference always carries its `row_version`, and the reverse;
/// - only a definition-started session carries a policy;
/// - every limit that is present is positive (D-512 §2: zero and negative are
///   refused).
///
/// Control: the consistent snapshot is accepted.
#[tokio::test]
async fn the_database_refuses_an_inconsistent_policy_snapshot() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let owner = seed_user(db).await;
    let def = definition(db, "active", Some(live_model(db).await)).await;
    let (policy_ref, row_version) = policy(db, "reversible", 10).await;
    let consistent = full_snapshot(policy_ref, row_version);

    let cases = [
        (
            "a policy reference without its row_version",
            Some(def),
            session::PolicySnapshot {
                policy_row_version: None,
                ..consistent.clone()
            },
        ),
        (
            "a row_version without a policy reference",
            Some(def),
            session::PolicySnapshot {
                policy_ref: None,
                ..consistent.clone()
            },
        ),
        (
            "a policy on a session not started from a definition",
            None,
            consistent.clone(),
        ),
        (
            "a negative limit",
            Some(def),
            session::PolicySnapshot {
                max_writes_per_day: Some(-1),
                ..consistent.clone()
            },
        ),
        (
            "a zero limit",
            Some(def),
            session::PolicySnapshot {
                max_invocations_per_session: Some(0),
                ..consistent.clone()
            },
        ),
        (
            "a zero-minute session",
            Some(def),
            session::PolicySnapshot {
                max_session_duration_minutes: Some(0),
                ..consistent.clone()
            },
        ),
    ];
    for (what, agent_definition_ref, snapshot) in cases {
        let refused = open_with_snapshot(db, owner, agent_definition_ref, snapshot).await;
        assert!(refused.is_err(), "{what} must be refused by the database");
    }

    open_with_snapshot(db, owner, Some(def), consistent)
        .await
        .expect("control: a consistent snapshot is accepted");
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM agent_session WHERE owner_user_id = $1")
            .bind(owner)
            .fetch_one(db)
            .await
            .expect("count sessions");
    assert_eq!(rows, 1, "no refused snapshot left a session behind");
}

// ── D-505 / D-512: the policy as enforced ──────────────────────────────────

/// **D-505 §3: no policy, no session.** A definition with no `policy_ref`, one
/// that names no policy, and one whose policy was retired each refuse the
/// start and leave no session behind. Clearing the reference stops sessions;
/// it never removes a constraint.
#[tokio::test]
async fn a_definition_without_a_resolvable_policy_cannot_start_a_session() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;
    let model = live_model(db).await;

    let retired = insert_policy(db, &open_policy()).await;
    sqlx::query("UPDATE ai_agent_policy SET is_active = false WHERE id = $1")
        .bind(retired)
        .execute(db)
        .await
        .expect("retire the policy");

    for policy_ref in [None, Some(Uuid::now_v7()), Some(retired)] {
        let def = definition_with_policy(db, "active", Some(model), policy_ref).await;
        let started = start_session(
            &state,
            &security,
            def,
            "admin",
            constraints(RiskTier::Read, None),
            false,
        )
        .await;
        assert!(
            matches!(started, Err(AppError::Validation(_))),
            "policy_ref {policy_ref:?} must refuse the start: {started:?}"
        );
        assert_eq!(sessions_started_from(db, def).await, 0, "{policy_ref:?}");
    }
}

/// **D-512 §§1–2: every limit is explicit, and existing maxima hold.** A
/// missing, zero, negative or fractional limit, a token limit above
/// `Budget::PER_SESSION_DEFAULT`, an unknown ceiling, an unknown action id and
/// a malformed knowledge scope each refuse the start, and no session is left
/// behind. There is no default to fall back on.
#[tokio::test]
async fn an_invalid_policy_refuses_the_start_and_leaves_no_session() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;

    let mut invalid: Vec<(String, Value)> = Vec::new();
    for field in LIMITS {
        for bad in [
            Value::Null,
            serde_json::json!(0),
            serde_json::json!(-5),
            serde_json::json!(2.5),
        ] {
            invalid.push((format!("{field} = {bad}"), policy_with(&[(field, bad)])));
        }
    }
    let above_default = attome_inference::budget::Budget::PER_SESSION_DEFAULT.tokens + 1;
    for (label, field, value) in [
        (
            "tokens above the per-session default",
            "max_tokens_per_session",
            serde_json::json!(above_default),
        ),
        (
            "unknown ceiling",
            "risk_ceiling",
            serde_json::json!("godmode"),
        ),
        (
            "unknown action",
            "allowed_action_ids",
            serde_json::json!(["record.get", "record.nuke"]),
        ),
        (
            "malformed knowledge scope",
            "knowledge_source_refs",
            serde_json::json!("[\"not-a-uuid\"]"),
        ),
    ] {
        invalid.push((label.to_owned(), policy_with(&[(field, value)])));
    }

    for (label, fields) in invalid {
        let (_, def) = governed_definition(db, &fields).await;
        let started = start_session(
            &state,
            &security,
            def,
            "admin",
            constraints(RiskTier::Read, None),
            false,
        )
        .await;
        assert!(
            matches!(started, Err(AppError::Validation(_))),
            "{label} must refuse the start: {started:?}"
        );
        assert_eq!(sessions_started_from(db, def).await, 0, "{label}");
    }

    let (_, def) = governed_definition(db, &open_policy()).await;
    start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Read, None),
        false,
    )
    .await
    .expect("control: a valid policy starts a session");
}

/// **D-505 §1: the policy only narrows.** A policy ceiling below the request's
/// wins, and so does a request ceiling below the policy's. Allow-lists
/// intersect: an action named by only one source is absent, and a policy's
/// empty list leaves nothing. An admin owner holds every privilege, so each
/// refusal here comes from the combination alone.
#[tokio::test]
async fn the_policy_only_narrows_what_the_start_source_allows() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let security = Arc::new(security);
    let target = raw_session(db, owner, RiskTier::Read).await;
    let pause_target = serde_json::json!({ "session_id": target.id });

    let (_, def) = governed_definition(
        db,
        &policy_with(&[
            ("risk_ceiling", serde_json::json!("reversible")),
            (
                "allowed_action_ids",
                serde_json::json!(["agent.pause", "record.get"]),
            ),
        ]),
    )
    .await;
    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(
            RiskTier::Consequential,
            Some(&["agent.pause", "memory.remember"]),
        ),
        false,
    )
    .await
    .expect("start");
    assert_eq!(session.risk_ceiling, RiskTier::Reversible);
    assert_eq!(
        session.allowed_action_ids,
        Some(vec!["agent.pause".to_owned()])
    );
    let above_ceiling = agent_invokes(
        &state,
        Arc::clone(&security),
        &session,
        AGENT_PAUSE,
        "narrow-1",
        pause_target.clone(),
    )
    .await;
    assert!(
        matches!(above_ceiling, Err(AppError::Forbidden)),
        "the policy's ceiling must win: {above_ceiling:?}"
    );
    let outside_policy_list = agent_invokes(
        &state,
        Arc::clone(&security),
        &session,
        MEMORY_REMEMBER,
        "narrow-2",
        remember_args(),
    )
    .await;
    assert!(
        matches!(outside_policy_list, Err(AppError::NotFound)),
        "an action only the request names must be absent: {outside_policy_list:?}"
    );

    let (_, def) = governed_definition(db, &open_policy()).await;
    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Read, None),
        false,
    )
    .await
    .expect("start");
    assert_eq!(
        session.risk_ceiling,
        RiskTier::Read,
        "the request's lower ceiling wins"
    );
    assert_eq!(session.allowed_action_ids, None);

    let (_, def) = governed_definition(
        db,
        &policy_with(&[("allowed_action_ids", serde_json::json!([]))]),
    )
    .await;
    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");
    assert_eq!(session.allowed_action_ids, Some(vec![]));
    let nothing = agent_invokes(
        &state,
        Arc::clone(&security),
        &session,
        AGENT_PAUSE,
        "narrow-3",
        pause_target.clone(),
    )
    .await;
    assert!(matches!(nothing, Err(AppError::NotFound)), "{nothing:?}");

    let (_, def) = governed_definition(db, &open_policy()).await;
    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");
    let control = agent_invokes(
        &state,
        Arc::clone(&security),
        &session,
        AGENT_PAUSE,
        "narrow-4",
        pause_target,
    )
    .await;
    assert!(
        matches!(control, Ok(ActionOutcome::ApprovalRequired { .. })),
        "{control:?}"
    );
    assert!(!is_paused(db, target.id).await);
}

/// **D-505 §4: `start_session` snapshots the policy.** The effective ceiling
/// and allow-list, the knowledge scope, every limit, the policy reference and
/// its `row_version` are on the session row. Editing the policy and clearing
/// the definition's reference afterwards changes nothing about the running
/// session; the edited definition can no longer start a new one.
#[tokio::test]
async fn start_session_snapshots_the_policy_and_later_edits_never_reach_it() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let security = Arc::new(security);
    let source = Uuid::now_v7();
    let (policy_id, def) = governed_definition(
        db,
        &serde_json::json!({
            "risk_ceiling": "consequential",
            "allowed_action_ids": ["agent.pause"],
            "knowledge_source_refs": format!("[\"{source}\"]"),
            "max_invocations_per_session": 7,
            "max_writes_per_day": 3,
            "max_tokens_per_session": 1234,
            "max_session_duration_minutes": 45,
        }),
    )
    .await;
    let row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM ai_agent_policy WHERE id = $1")
            .bind(policy_id)
            .fetch_one(db)
            .await
            .expect("read policy row_version");

    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");
    let expected = PolicySnapshot {
        policy_ref: Some(policy_id),
        policy_row_version: Some(row_version),
        knowledge_source_refs: Some(vec![source]),
        // The policy referenced no pack, so no provenance is recorded.
        capability_pack_refs: None,
        max_invocations_per_session: Some(7),
        max_writes_per_day: Some(3),
        max_tokens_per_session: Some(1234),
        max_session_duration_minutes: Some(45),
        // The definition sets no retrieval_mode: D-561's default.
        retrieval_mode: attome_ai::session::KnowledgeRetrievalMode::ToolInvoked,
        // C11 B2: the definition's instructions, composed at start.
        persona: Some("Be concise.".into()),
    };
    assert_eq!(session.policy, expected);
    let ctx = ActionContext::for_session(Arc::clone(&security), &session);
    assert_eq!(ctx.session_knowledge_source_refs, Some(vec![source]));
    assert_eq!(ctx.session_max_tokens, Some(1234));

    sqlx::query(
        "UPDATE ai_agent_policy SET risk_ceiling = 'read', allowed_action_ids = '{}', \
                knowledge_source_refs = '[]', max_invocations_per_session = 1, \
                max_writes_per_day = 1, max_tokens_per_session = 1, \
                max_session_duration_minutes = 1, row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(policy_id)
    .execute(db)
    .await
    .expect("edit the policy");
    sqlx::query("UPDATE ai_agent SET policy_ref = NULL WHERE id = $1")
        .bind(def)
        .execute(db)
        .await
        .expect("clear the definition's policy");

    let loaded = session::load_live(db, session.id)
        .await
        .expect("load")
        .expect("still live");
    assert_eq!(loaded.policy, expected);
    assert_eq!(loaded.risk_ceiling, RiskTier::Consequential);
    assert_eq!(
        loaded.allowed_action_ids,
        Some(vec!["agent.pause".to_owned()])
    );

    let target = raw_session(db, owner, RiskTier::Read).await;
    let control = agent_invokes(
        &state,
        Arc::clone(&security),
        &loaded,
        AGENT_PAUSE,
        "snapshot-1",
        serde_json::json!({ "session_id": target.id }),
    )
    .await;
    assert!(
        matches!(control, Ok(ActionOutcome::ApprovalRequired { .. })),
        "the running session keeps its snapshot: {control:?}"
    );

    let restarted = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await;
    assert!(
        matches!(restarted, Err(AppError::Validation(_))),
        "{restarted:?}"
    );
}

/// **D-512 §4: invocation budget is consumed before the gate.** Counted: a
/// submission for approval, a D-502 replay of the same tool call, a
/// confirmation, and a gate refusal. Not counted: an unknown action, a call
/// refused because the limit is used up, and a call on a session that is no
/// longer live. Usage is separate from the D-502 ledger.
#[tokio::test]
async fn every_call_on_a_live_session_to_a_known_action_consumes_invocation_budget() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let security = Arc::new(security);
    let target = raw_session(db, owner, RiskTier::Read).await;
    let pause_target = serde_json::json!({ "session_id": target.id });
    let (_, def) = governed_definition(
        db,
        &policy_with(&[("max_invocations_per_session", serde_json::json!(4))]),
    )
    .await;
    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");
    let call = |action: &'static str, key: &'static str, args: Value| {
        agent_invokes(&state, Arc::clone(&security), &session, action, key, args)
    };

    let first = call(AGENT_PAUSE, "tool-call-1", pause_target.clone()).await;
    let Ok(ActionOutcome::ApprovalRequired { approval_id }) = first else {
        panic!("{first:?}");
    };
    assert_eq!(invocations_used(db, session.id).await, 1);

    let replayed = call(AGENT_PAUSE, "tool-call-1", pause_target.clone()).await;
    assert!(
        matches!(replayed, Ok(ActionOutcome::ApprovalRequired { approval_id: again }) if again == approval_id),
        "D-502 replays the same approval: {replayed:?}"
    );
    assert_eq!(invocations_used(db, session.id).await, 2, "a replay counts");

    let confirmation = call(MEMORY_REMEMBER, "tool-call-2", remember_args()).await;
    assert!(
        matches!(confirmation, Ok(ActionOutcome::ConfirmationRequired { .. })),
        "counting never turns a confirmation into anything else: {confirmation:?}"
    );
    assert_eq!(invocations_used(db, session.id).await, 3);

    let unknown = call("record.nuke", "tool-call-3", serde_json::json!({})).await;
    assert!(matches!(unknown, Err(AppError::NotFound)), "{unknown:?}");
    assert_eq!(
        invocations_used(db, session.id).await,
        3,
        "an unknown action is not counted"
    );

    let fourth = call(AGENT_PAUSE, "tool-call-4", pause_target.clone()).await;
    assert!(
        matches!(fourth, Ok(ActionOutcome::ApprovalRequired { .. })),
        "{fourth:?}"
    );
    assert_eq!(invocations_used(db, session.id).await, 4);

    for (action, key, args) in [
        (MEMORY_REMEMBER, "tool-call-5", remember_args()),
        (AGENT_PAUSE, "tool-call-6", pause_target.clone()),
    ] {
        let refused = call(action, key, args).await;
        assert!(
            matches!(
                refused,
                Err(AppError::TooManyRequests {
                    retry_after_secs: None
                })
            ),
            "{action} past the limit: {refused:?}"
        );
    }
    assert_eq!(invocations_used(db, session.id).await, 4, "nothing past it");

    // Usage is not the D-502 ledger: two approval submissions, four calls.
    let ledger_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM action_invocation WHERE agent_session_id = $1")
            .bind(session.id)
            .fetch_one(db)
            .await
            .expect("count ledger rows");
    assert_eq!(ledger_rows, 2);
    let approvals: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_request WHERE payload->>'agent_session_id' = $1",
    )
    .bind(session.id.to_string())
    .fetch_one(db)
    .await
    .expect("count approval requests");
    assert_eq!(approvals, 2, "a refused call submitted nothing");

    // A gate refusal is counted.
    let (_, def) = governed_definition(db, &open_policy()).await;
    let read_only = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Read, None),
        false,
    )
    .await
    .expect("start");
    let refused = agent_invokes(
        &state,
        Arc::clone(&security),
        &read_only,
        AGENT_PAUSE,
        "refused-1",
        pause_target,
    )
    .await;
    assert!(matches!(refused, Err(AppError::Forbidden)), "{refused:?}");
    assert_eq!(invocations_used(db, read_only.id).await, 1);

    // A paused or revoked session is refused and consumes nothing.
    assert!(
        session::pause(db, read_only.id, owner, "test")
            .await
            .unwrap()
    );
    let paused = agent_invokes(
        &state,
        Arc::clone(&security),
        &read_only,
        MEMORY_REMEMBER,
        "dead-1",
        remember_args(),
    )
    .await;
    assert!(matches!(paused, Err(AppError::Validation(_))), "{paused:?}");
    assert!(session::resume(db, read_only.id).await.unwrap());
    assert!(
        session::revoke(db, read_only.id, owner, "test")
            .await
            .unwrap()
    );
    let revoked = agent_invokes(
        &state,
        Arc::clone(&security),
        &read_only,
        MEMORY_REMEMBER,
        "dead-2",
        remember_args(),
    )
    .await;
    assert!(
        matches!(revoked, Err(AppError::Validation(_))),
        "{revoked:?}"
    );
    assert_eq!(invocations_used(db, read_only.id).await, 1);
}

/// **D-512 §4: the counter cannot be overshot.** Twenty concurrent calls
/// against a limit of five: exactly five are admitted and the rest refused,
/// because Postgres checks and raises the counter in one statement.
#[tokio::test]
async fn concurrent_calls_cannot_overshoot_the_invocation_limit() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;
    let security = Arc::new(security);
    let (_, def) = governed_definition(
        db,
        &policy_with(&[("max_invocations_per_session", serde_json::json!(5))]),
    )
    .await;
    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");

    let mut calls = Vec::new();
    for i in 0..20 {
        let state = state.clone();
        let security = Arc::clone(&security);
        let session = session.clone();
        calls.push(tokio::spawn(async move {
            agent_invokes(
                &state,
                security,
                &session,
                MEMORY_REMEMBER,
                &format!("concurrent-{i}"),
                remember_args(),
            )
            .await
        }));
    }
    let (mut admitted, mut refused) = (0, 0);
    for call in calls {
        match call.await.expect("join") {
            Ok(ActionOutcome::ConfirmationRequired { .. }) => admitted += 1,
            Err(AppError::TooManyRequests {
                retry_after_secs: None,
            }) => refused += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!((admitted, refused), (5, 15));
    assert_eq!(invocations_used(db, session.id).await, 5);
}

/// **D-512 §6: past its duration a session is gone.** At 29 of 30 minutes it
/// is live. At 31 it is gone to every loader, a call is refused without
/// consuming budget, and an action approved while it was live is invalidated
/// rather than deferred. A paused session past its duration is gone too.
#[tokio::test]
async fn a_session_past_its_duration_is_gone_and_its_approved_work_dies_with_it() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let security = Arc::new(security);
    let approver = seed_user(db).await;
    let target = raw_session(db, owner, RiskTier::Read).await;
    let (_, def) = governed_definition(
        db,
        &policy_with(&[("max_session_duration_minutes", serde_json::json!(30))]),
    )
    .await;
    let start = || {
        start_session(
            &state,
            &security,
            def,
            "admin",
            constraints(RiskTier::Consequential, None),
            false,
        )
    };

    let session = start().await.expect("start");
    let request = approved_supervision(
        &state,
        &security,
        &session,
        AGENT_PAUSE,
        target.id,
        approver,
    )
    .await;

    started_minutes_ago(db, session.id, 29).await;
    assert!(session::load_live(db, session.id).await.unwrap().is_some());

    started_minutes_ago(db, session.id, 31).await;
    assert!(session::load_live(db, session.id).await.unwrap().is_none());
    assert!(
        session::load_live_owned(db, session.id, owner, "admin")
            .await
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        session::load_for_execution(db, session.id).await.unwrap(),
        SessionForExecution::Gone
    ));

    let used = invocations_used(db, session.id).await;
    let refused = agent_invokes(
        &state,
        Arc::clone(&security),
        &session,
        MEMORY_REMEMBER,
        "expired-1",
        remember_args(),
    )
    .await;
    assert!(
        matches!(refused, Err(AppError::Validation(_))),
        "{refused:?}"
    );
    assert_eq!(invocations_used(db, session.id).await, used);

    let execution = dispatch_approved_agent_action(&state, &request)
        .await
        .expect("a refusal is a verdict, not a transient error");
    assert!(
        matches!(execution, ApprovedExecution::Invalidated { .. }),
        "approved work must not outlive the session's duration: {execution:?}"
    );
    assert!(!is_paused(db, target.id).await, "nothing may have run");

    let paused = start().await.expect("start");
    assert!(session::pause(db, paused.id, owner, "test").await.unwrap());
    assert!(matches!(
        session::load_for_execution(db, paused.id).await.unwrap(),
        SessionForExecution::Paused
    ));
    started_minutes_ago(db, paused.id, 31).await;
    assert!(matches!(
        session::load_for_execution(db, paused.id).await.unwrap(),
        SessionForExecution::Gone
    ));
}

/// **D-512 §3: the daily write total is session-wide.** Under a limit of two,
/// one `agent.pause` and one `agent.resume` use it up, though each action is
/// far below its own count, so a second pause waits: deferred, not
/// invalidated. And the limit holds under concurrency: two approved writes
/// executed at once against a limit of one run exactly once.
#[tokio::test]
async fn the_daily_write_total_is_session_wide_and_holds_under_concurrency() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let security = Arc::new(security);
    let approver = seed_user(db).await;

    let (_, def) = governed_definition(
        db,
        &policy_with(&[("max_writes_per_day", serde_json::json!(2))]),
    )
    .await;
    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");
    let first = raw_session(db, owner, RiskTier::Read).await;
    let second = raw_session(db, owner, RiskTier::Read).await;
    let third = raw_session(db, owner, RiskTier::Read).await;
    assert!(session::pause(db, second.id, owner, "test").await.unwrap());

    let pause_first =
        approved_supervision(&state, &security, &session, AGENT_PAUSE, first.id, approver).await;
    let resume_second = approved_supervision(
        &state,
        &security,
        &session,
        AGENT_RESUME,
        second.id,
        approver,
    )
    .await;
    let pause_third =
        approved_supervision(&state, &security, &session, AGENT_PAUSE, third.id, approver).await;

    for request in [&pause_first, &resume_second] {
        let executed = dispatch_approved_agent_action(&state, request)
            .await
            .expect("execute");
        assert!(
            matches!(executed, ApprovedExecution::Executed(_)),
            "{}: {executed:?}",
            request.action_id
        );
    }
    for _ in 0..2 {
        let waiting = dispatch_approved_agent_action(&state, &pause_third)
            .await
            .expect("execute");
        assert!(
            matches!(waiting, ApprovedExecution::Deferred { .. }),
            "the session-wide total is used up: {waiting:?}"
        );
    }
    assert!(is_paused(db, first.id).await);
    assert!(!is_paused(db, second.id).await);
    assert!(
        !is_paused(db, third.id).await,
        "the deferred write must not run"
    );
    assert_eq!(completed_writes(db, session.id, Some(AGENT_PAUSE)).await, 1);
    assert_eq!(
        completed_writes(db, session.id, Some(AGENT_RESUME)).await,
        1
    );
    assert_eq!(completed_writes(db, session.id, None).await, 2);

    // Concurrency: a limit of one, two approved writes at once.
    let (_, def) = governed_definition(
        db,
        &policy_with(&[("max_writes_per_day", serde_json::json!(1))]),
    )
    .await;
    let racing = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");
    let left = raw_session(db, owner, RiskTier::Read).await;
    let right = raw_session(db, owner, RiskTier::Read).await;
    let pause_left =
        approved_supervision(&state, &security, &racing, AGENT_PAUSE, left.id, approver).await;
    let pause_right =
        approved_supervision(&state, &security, &racing, AGENT_PAUSE, right.id, approver).await;

    let (state_a, state_b) = (state.clone(), state.clone());
    let a =
        tokio::spawn(async move { dispatch_approved_agent_action(&state_a, &pause_left).await });
    let b =
        tokio::spawn(async move { dispatch_approved_agent_action(&state_b, &pause_right).await });
    let a = a.await.expect("join").expect("execute");
    let b = b.await.expect("join").expect("execute");
    let executed = [&a, &b]
        .iter()
        .filter(|e| matches!(e, ApprovedExecution::Executed(_)))
        .count();
    let deferred = [&a, &b]
        .iter()
        .filter(|e| matches!(e, ApprovedExecution::Deferred { .. }))
        .count();
    assert_eq!((executed, deferred), (1, 1), "{a:?} / {b:?}");
    assert_eq!(
        usize::from(is_paused(db, left.id).await) + usize::from(is_paused(db, right.id).await),
        1
    );
    assert_eq!(completed_writes(db, racing.id, None).await, 1);
}

/// **D-512 §8: a session with no policy term keeps D-503 semantics.** A
/// session opened by the bare primitive — as MCP `initialize` and webchat do —
/// has no snapshot, no knowledge narrowing, no token limit, no duration and no
/// write limit. Its calls are still counted, and never refused for it.
#[tokio::test]
async fn a_session_without_a_policy_term_keeps_d503_semantics() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let security = Arc::new(security);
    let session = raw_session(db, owner, RiskTier::Consequential).await;

    assert_eq!(session.policy, PolicySnapshot::NONE);
    let ctx = ActionContext::for_session(Arc::clone(&security), &session);
    assert_eq!(ctx.session_knowledge_source_refs, None);
    assert_eq!(ctx.session_max_tokens, None);

    for i in 0..3 {
        let outcome = agent_invokes(
            &state,
            Arc::clone(&security),
            &session,
            MEMORY_REMEMBER,
            &format!("unlimited-{i}"),
            remember_args(),
        )
        .await;
        assert!(
            matches!(outcome, Ok(ActionOutcome::ConfirmationRequired { .. })),
            "{outcome:?}"
        );
    }
    assert_eq!(invocations_used(db, session.id).await, 3);

    let reservation = session::reserve_session_write(
        db,
        session.id,
        Some("unlimited-write"),
        ActionId(MEMORY_REMEMBER),
        owner,
    )
    .await
    .expect("reserve");
    assert!(
        matches!(reservation, WriteReservation::Unlimited),
        "{reservation:?}"
    );
    let ledger_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM action_invocation WHERE agent_session_id = $1")
            .bind(session.id)
            .fetch_one(db)
            .await
            .expect("count ledger rows");
    assert_eq!(ledger_rows, 0, "an unlimited session reserves nothing");

    started_minutes_ago(db, session.id, 60 * 24 * 3650).await;
    assert!(session::load_live(db, session.id).await.unwrap().is_some());
    assert!(matches!(
        session::load_for_execution(db, session.id).await.unwrap(),
        SessionForExecution::Live(_)
    ));
}

// ── C6: capability packs (D-556) ────────────────────────────────────────────

/// **A-20.** Lowering a policy's `risk_ceiling` mid-conversation reaches the
/// **next** session, never the running one — snapshots are immutable by design
/// (D-505 §4). The immediate lever for a live session is `agent.kill`, which the
/// administration UI must say out loud.
#[tokio::test]
async fn a_lowered_ceiling_reaches_the_next_session_not_the_running_one() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;
    let (policy, def) = governed_definition(
        db,
        &policy_with(&[("risk_ceiling", serde_json::json!("consequential"))]),
    )
    .await;

    let running = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start under the original ceiling");
    assert_eq!(running.risk_ceiling, RiskTier::Consequential);

    sqlx::query(
        "UPDATE ai_agent_policy SET risk_ceiling = 'read', row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(policy)
    .execute(db)
    .await
    .expect("lower the policy ceiling");

    let still_running = session::load_live(db, running.id)
        .await
        .expect("load")
        .expect("still live");
    assert_eq!(
        still_running.risk_ceiling,
        RiskTier::Consequential,
        "A-20: a running session keeps the ceiling it started with"
    );
    assert_eq!(
        still_running.policy, running.policy,
        "and its whole snapshot"
    );

    let next = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start the next session");
    assert_eq!(
        next.risk_ceiling,
        RiskTier::Read,
        "A-20: the next session starts under the lowered ceiling"
    );
}

/// **A-37.** A pack that names an action above the policy's ceiling does not
/// make it available. A pack contributes term 5 (the allow-list) and nothing
/// else; the ceiling (term 4) is still checked on every invocation.
#[tokio::test]
async fn a_capability_pack_cannot_widen_the_policys_ceiling() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (owner, security) = admin(db).await;
    let security = Arc::new(security);
    let target = raw_session(db, owner, RiskTier::Read).await;

    // The pack grants one Consequential action and one Read action.
    let (pack, _) = insert_pack(db, &[AGENT_PAUSE, "record.get"]).await;
    let (_, def) = governed_definition(
        db,
        &policy_with(&[
            ("risk_ceiling", serde_json::json!("read")),
            ("allowed_action_ids", serde_json::json!(null)),
            ("capability_pack_refs", pack_refs_json(&[pack])),
        ]),
    )
    .await;

    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");
    // The pack did grant both ids — this is term 5 working.
    assert_eq!(
        session.allowed_action_ids,
        Some(vec![AGENT_PAUSE.to_owned(), "record.get".to_owned()])
    );
    assert_eq!(session.risk_ceiling, RiskTier::Read);

    // The ceiling still refuses the Consequential grant: a pack grants, it
    // never authorizes.
    let refused = agent_asks_to_pause(&state, resolve(db, owner).await, &session, target.id).await;
    assert!(
        matches!(refused, Err(AppError::Forbidden)),
        "A-37: a pack cannot raise the ceiling: {refused:?}"
    );
    assert!(!is_paused(db, target.id).await, "nothing ran");

    // Control: the same pack under a ceiling that permits the action reaches
    // the gate's approval path — so the ceiling is what refused above.
    let (_, def) = governed_definition(
        db,
        &policy_with(&[
            ("risk_ceiling", serde_json::json!("consequential")),
            ("allowed_action_ids", serde_json::json!(null)),
            ("capability_pack_refs", pack_refs_json(&[pack])),
        ]),
    )
    .await;
    let permitted = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Consequential, None),
        false,
    )
    .await
    .expect("start");
    let control =
        agent_asks_to_pause(&state, resolve(db, owner).await, &permitted, target.id).await;
    assert!(
        matches!(control, Ok(ActionOutcome::ApprovalRequired { .. })),
        "control: the pack's grant is real once the ceiling permits it: {control:?}"
    );
}

/// **A-47.** A pack edited (or deleted) after a session started from it reaches
/// that session nowhere: the resolved `allowed_action_ids` are authoritative and
/// the recorded pack `row_version` still says what the session held at start.
#[tokio::test]
async fn editing_or_deleting_a_pack_never_changes_a_running_session() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;
    let (pack, pack_version) = insert_pack(db, &["record.get"]).await;
    let (_, def) = governed_definition(
        db,
        &policy_with(&[
            ("risk_ceiling", serde_json::json!("read")),
            ("allowed_action_ids", serde_json::json!(null)),
            ("capability_pack_refs", pack_refs_json(&[pack])),
        ]),
    )
    .await;

    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Read, None),
        false,
    )
    .await
    .expect("start");
    assert_eq!(
        session.allowed_action_ids,
        Some(vec!["record.get".to_owned()])
    );
    assert_eq!(
        session.policy.capability_pack_refs,
        Some(vec![CapabilityPackRef {
            id: pack,
            row_version: pack_version,
        }]),
        "the snapshot records which pack version produced the grants"
    );

    // Widen the pack and bump its version: a running session must not move.
    sqlx::query(
        "UPDATE ai_capability_pack SET action_ids = $2, row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(pack)
    .bind(serde_json::json!(["record.get", "record.summarize"]).to_string())
    .execute(db)
    .await
    .expect("widen the pack");

    let reloaded = session::load_live(db, session.id)
        .await
        .expect("load")
        .expect("live");
    assert_eq!(
        reloaded.allowed_action_ids, session.allowed_action_ids,
        "A-47: a widened pack does not widen a running session"
    );
    assert_eq!(
        reloaded.policy.capability_pack_refs, session.policy.capability_pack_refs,
        "A-47: the recorded pack version still says what it held at start"
    );

    // Deleting it reaches the running session nowhere either...
    sqlx::query("DELETE FROM ai_capability_pack WHERE id = $1")
        .bind(pack)
        .execute(db)
        .await
        .expect("delete the pack");
    assert_eq!(snapshot_of(db, session.id).await, session.policy);

    // ...while the next session refuses to start rather than silently
    // granting nothing (fail closed, D-556 §1).
    let refused = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Read, None),
        false,
    )
    .await;
    assert!(
        matches!(refused, Err(AppError::Validation(_))),
        "a missing pack must refuse the next start: {refused:?}"
    );
    assert_eq!(
        sessions_started_from(db, def).await,
        1,
        "the refused start left no second session"
    );
}

/// **D-556 §1: union, then intersect.** A policy's effective allow-list is the
/// union of its referenced packs' ids and its explicitly named ids; only then
/// is it intersected with the start source. An action a pack grants but the
/// start source excludes is absent — a pack cannot widen the source either.
#[tokio::test]
async fn packs_union_with_explicit_ids_then_intersect_the_start_source() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;
    let security = Arc::new(security);

    let (readers, _) = insert_pack(db, &[AGENT_PAUSE, "record.get"]).await;
    let (writers, _) = insert_pack(db, &["record.get", MEMORY_REMEMBER]).await;
    let (_, def) = governed_definition(
        db,
        &policy_with(&[
            ("risk_ceiling", serde_json::json!("consequential")),
            ("allowed_action_ids", serde_json::json!([MEMORY_REMEMBER])),
            ("capability_pack_refs", pack_refs_json(&[readers, writers])),
        ]),
    )
    .await;

    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(
            RiskTier::Consequential,
            Some(&[AGENT_PAUSE, MEMORY_REMEMBER]),
        ),
        false,
    )
    .await
    .expect("start");

    // Union({agent.pause, record.get} + {record.get, memory.remember} + the
    // explicit {memory.remember}) = {agent.pause, record.get, memory.remember};
    // intersected with the start source = {agent.pause, memory.remember}.
    assert_eq!(
        session.allowed_action_ids,
        Some(vec![AGENT_PAUSE.to_owned(), MEMORY_REMEMBER.to_owned()]),
        "the pack union is intersected with the start source, not unioned with it"
    );

    // `record.get` is in the policy's union but not in the source: absent.
    let outside_source = agent_invokes(
        &state,
        Arc::clone(&security),
        &session,
        "record.get",
        "pack-union-1",
        serde_json::json!({ "entity": "ai_agent", "id": Uuid::now_v7() }),
    )
    .await;
    assert!(
        matches!(outside_source, Err(AppError::NotFound)),
        "an action only a pack grants, and the source excludes, must be absent: {outside_source:?}"
    );

    // One granted by a pack AND by the source is indistinguishable from a
    // hand-picked id by the time the gate sees it.
    let from_pack = agent_invokes(
        &state,
        Arc::clone(&security),
        &session,
        MEMORY_REMEMBER,
        "pack-union-2",
        remember_args(),
    )
    .await;
    assert!(
        matches!(from_pack, Ok(ActionOutcome::ConfirmationRequired { .. })),
        "a pack-granted action inside the source behaves exactly like a hand-picked one: {from_pack:?}"
    );
}

/// **I-16 holds on the pack path too.** An absent pack list and an empty one
/// both contribute nothing; neither invents an allow-list. A policy whose
/// explicit list is absent and whose packs are empty stays unrestricted by the
/// list, while an explicit empty list stays "nothing".
#[tokio::test]
async fn pack_lists_keep_absent_and_empty_apart() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;

    // The policy row's fields are bound through `json_populate_record`, so the
    // multi-choice `allowed_action_ids` column takes a JSON array (or null) —
    // `[]` is the empty TEXT[] that means "this policy grants nothing", while
    // null is the column's NULL that means "no list from this policy".
    let cases: [(Value, Value, Option<Vec<String>>); 3] = [
        (serde_json::json!(null), serde_json::json!(null), None),
        (serde_json::json!("[]"), serde_json::json!(null), None),
        (
            serde_json::json!(null),
            serde_json::json!([]),
            Some(Vec::new()),
        ),
    ];
    for (pack_refs, explicit, expected) in cases {
        let (_, def) = governed_definition(
            db,
            &policy_with(&[
                ("allowed_action_ids", explicit.clone()),
                ("capability_pack_refs", pack_refs.clone()),
            ]),
        )
        .await;
        let session = start_session(
            &state,
            &security,
            def,
            "admin",
            constraints(RiskTier::Read, None),
            false,
        )
        .await
        .expect("start");
        assert_eq!(
            session.allowed_action_ids, expected,
            "packs {pack_refs} explicit {explicit}"
        );
        assert_eq!(
            session.policy.capability_pack_refs, None,
            "an absent or empty pack list records no provenance"
        );
    }

    // A referenced pack that grants nothing still grants nothing: the union of
    // "no explicit list" with an empty pack is an empty list, fail-closed.
    let (empty, empty_version) = insert_pack(db, &[]).await;
    let (_, def) = governed_definition(
        db,
        &policy_with(&[
            ("allowed_action_ids", serde_json::json!(null)),
            ("capability_pack_refs", pack_refs_json(&[empty])),
        ]),
    )
    .await;
    let session = start_session(
        &state,
        &security,
        def,
        "admin",
        constraints(RiskTier::Read, None),
        false,
    )
    .await
    .expect("start");
    assert_eq!(
        session.allowed_action_ids,
        Some(Vec::new()),
        "a pack that grants nothing grants nothing"
    );
    assert_eq!(
        session.policy.capability_pack_refs,
        Some(vec![CapabilityPackRef {
            id: empty,
            row_version: empty_version,
        }]),
        "an empty pack is still recorded as provenance"
    );
}

/// A policy that references a pack which does not resolve — or one naming an
/// action the registry does not know — refuses the start and leaves no session
/// behind, rather than silently granting nothing.
#[tokio::test]
async fn an_unresolvable_or_unknown_pack_refuses_the_start() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_, security) = admin(db).await;

    let (unknown_action, _) = insert_pack(db, &["record.nuke"]).await;
    for pack_refs in [
        pack_refs_json(&[Uuid::now_v7()]),
        pack_refs_json(&[unknown_action]),
    ] {
        let (_, def) =
            governed_definition(db, &policy_with(&[("capability_pack_refs", pack_refs)])).await;
        let refused = start_session(
            &state,
            &security,
            def,
            "admin",
            constraints(RiskTier::Read, None),
            false,
        )
        .await;
        assert!(
            matches!(refused, Err(AppError::Validation(_))),
            "must refuse: {refused:?}"
        );
        assert_eq!(sessions_started_from(db, def).await, 0);
    }
}

// ---------------------------------------------------------------------------
// C8 — D-561 §5: retrieval_mode is resolved at start and fixed for the session
// ---------------------------------------------------------------------------

async fn set_definition_mode(db: &DbPool, def: Uuid, mode: &str) {
    sqlx::query("UPDATE ai_agent SET retrieval_mode = $2 WHERE id = $1")
        .bind(def)
        .bind(mode)
        .execute(db)
        .await
        .expect("set the definition's retrieval_mode");
}

/// **Resolved once, at start; never after.** A definition set to
/// `pre_retrieved` starts a `PreRetrieved` session, stored on the row and read
/// back by the loader. Editing the definition afterwards leaves the running
/// session as it was — its snapshot, not the definition, is what every turn
/// reads — while a session started after the edit resolves the new value.
#[tokio::test]
async fn retrieval_mode_is_resolved_at_start_and_fixed_for_the_session() {
    use attome_ai::session::KnowledgeRetrievalMode::{PreRetrieved, ToolInvoked};
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_owner, security) = admin(db).await;
    let (_policy, def) = governed_definition(db, &open_policy()).await;
    set_definition_mode(db, def, "pre_retrieved").await;

    let first = start_session(
        &state,
        &security,
        def,
        "internal",
        constraints(RiskTier::Reversible, None),
        false,
    )
    .await
    .expect("start");
    assert_eq!(
        first.policy.retrieval_mode, PreRetrieved,
        "resolved from the definition"
    );
    assert_eq!(
        snapshot_of(db, first.id).await.retrieval_mode,
        PreRetrieved,
        "stored on the row"
    );

    set_definition_mode(db, def, "tool_invoked").await;
    let reloaded = session::load_live(db, first.id)
        .await
        .expect("load")
        .expect("live");
    assert_eq!(
        reloaded.policy.retrieval_mode, PreRetrieved,
        "a definition edit never reaches a running session"
    );

    let second = start_session(
        &state,
        &security,
        def,
        "internal",
        constraints(RiskTier::Reversible, None),
        false,
    )
    .await
    .expect("start again");
    assert_eq!(
        second.policy.retrieval_mode, ToolInvoked,
        "a new session resolves the current value"
    );
    let first_again = session::load_live(db, first.id)
        .await
        .expect("load")
        .expect("live");
    assert_eq!(
        first_again.policy.retrieval_mode, PreRetrieved,
        "the first session still holds its own"
    );
}

/// An unknown `retrieval_mode` on the definition refuses the start and leaves
/// no session behind — the mode is never guessed.
#[tokio::test]
async fn an_unknown_retrieval_mode_refuses_the_start_and_leaves_no_session() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let (_owner, security) = admin(db).await;
    let (_policy, def) = governed_definition(db, &open_policy()).await;
    set_definition_mode(db, def, "hybrid").await;
    let refused = start_session(
        &state,
        &security,
        def,
        "internal",
        constraints(RiskTier::Reversible, None),
        false,
    )
    .await;
    assert!(
        matches!(refused, Err(AppError::Validation(_))),
        "{refused:?}"
    );
    assert_eq!(sessions_started_from(db, def).await, 0);
}

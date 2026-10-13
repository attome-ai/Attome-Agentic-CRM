//! D-448 / M98 — the whole path, end to end, for an agent-initiated
//! Consequential action: `dispatch` refuses to run it and submits it for
//! four-eyes approval instead (`ActionOutcome::ApprovalRequired`), and once
//! a different admin decides `Approve`, `dispatch_approved_agent_action`
//! actually runs it. Closes the gap `execute.rs`'s `ApprovalRequired` doc
//! comment used to name as still open: an approved request that nothing
//! ever executed.
//!
//! **And the P0 authorization half: an approval does not freeze the security
//! state it was requested under.** Every `..._invalidates_the_action` test
//! below approves a request, then changes one condition the action depends on
//! — the requester's privilege, the agent session, the licence, the AI
//! kill-switch, the requester's account — and proves execution is refused
//! *and nothing ran*. `a_tainted_sessions_approved_action_runs_without_reconfirmation`
//! pins the other direction: revalidation never asks the human again.
//!
//! This suite builds a bare `EngineState` (`EngineState::new(AppState::new(...))`,
//! the same shape `record_update_field.rs` uses), never
//! `attome_api::EngineSystem::builder(...).build()` — deliberately, so it does
//! not depend on the platform-bundle boot sequence. `attome-api/tests/
//! approval_agent_action.rs` is the sibling end-to-end test that goes through
//! the real HTTP `/api/v1/admin/approvals/{id}/decide` route and proves the
//! request's terminal `invalidated` status.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! $env:APP_ENV = "debug"
//! cargo test -p attome-ai --test agent_action_approval_execution -- --test-threads=1
//! ```

#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use attome_ai::actions::agent_supervise::AGENT_PAUSE;
use attome_ai::approval::{AgentActionRequest, approved_payload};
use attome_ai::context::ActionContext;
use attome_ai::descriptor::RiskTier;
use attome_ai::execute::{
    ActionOutcome, ApprovedExecution, Executors, dispatch, dispatch_approved_agent_action,
    dispatch_approved_agent_action_under,
};
use attome_ai::gate::GateInputs;
use attome_ai::registry::ActionRegistry;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_modules::ModuleSet;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use uuid::Uuid;

/// The privilege `agent.pause` requires (`AgentSupervise::KEY`).
const SUPERVISE: &str = "ai_agent.supervise";

/// Same shape `record_update_field.rs::test_config` uses, plus the AI
/// kill-switch: `agent.pause` is `MODULE_AI`, so execution-time revalidation
/// consults `inference.ai` exactly as a live deployment would.
fn test_config(direct_url: &str, ai_on: bool) -> AppConfig {
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
                "enabled": {ai_on}, "fields": {ai_on}, "chat": {ai_on},
                "semantic_search": {ai_on}, "workflow_nodes": {ai_on}
            }} }},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        direct_url = direct_url,
        ai_on = ai_on,
    );
    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
}

// SAFETY: see `attome-workflow/tests/execution.rs`'s identical `ENV_LOCK` doc
// comment — `attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` from the
// environment synchronously before its first `.await`, and this suite's
// `#[tokio::test]` functions run concurrently by default.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn full_license() -> Arc<ModuleSet> {
    Arc::new(ModuleSet::from_bits([u64::MAX; 4]))
}

async fn test_state(ai_on: bool) -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let config = test_config(&db_url, ai_on);
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
    state.modules.store(full_license());
    Some(state)
}

async fn seed_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("agent-action-approval-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Grants `key` directly to `user_id`, creating the privilege row if this
/// throwaway database has not seeded it.
async fn grant_privilege(db: &attome_db::DbPool, user_id: Uuid, key: &str) {
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

async fn revoke_all_direct_privileges(db: &attome_db::DbPool, user_id: Uuid) {
    sqlx::query("DELETE FROM user_account_mm_privilege WHERE user_ref = $1")
        .bind(user_id)
        .execute(db)
        .await
        .expect("revoke privileges");
}

async fn open_agent_session(db: &attome_db::DbPool, owner: Uuid, tainted: bool) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface, tainted) \
         VALUES ($1, 2, 'test', $2) RETURNING id",
    )
    .bind(owner)
    .bind(tainted)
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

/// The submission-time context. Deliberately NOT what execution uses:
/// `dispatch_approved_agent_action` re-resolves the acting user from the
/// database, which is the property every test below depends on.
fn security_context(user_id: Uuid) -> Arc<SecurityContext> {
    Arc::new(SecurityContext {
        user_id,
        is_admin: false,
        privileges: HashSet::from([SUPERVISE.to_owned()]),
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

fn all_on() -> attome_config::AiEnablement {
    attome_config::AiEnablement {
        enabled: true,
        fields: true,
        chat: true,
        semantic_search: true,
        workflow_nodes: true,
    }
}

/// A supervising owner, their agent session, and a second session it will
/// ask to pause — the fixture every test starts from.
struct Fixture {
    owner: Uuid,
    agent_session_id: Uuid,
    target_session_id: Uuid,
}

async fn fixture(state: &EngineState, tainted_agent_session: bool) -> Fixture {
    let db = &state.base.db;
    let owner = seed_user(db).await;
    grant_privilege(db, owner, SUPERVISE).await;
    Fixture {
        owner,
        agent_session_id: open_agent_session(db, owner, tainted_agent_session).await,
        target_session_id: open_agent_session(db, owner, false).await,
    }
}

/// The agent asks to pause the target session (refused inline, submitted for
/// approval), and a different user approves it. Returns the approved payload
/// exactly as the approval callback would receive it.
async fn submit_and_approve(state: &EngineState, f: &Fixture) -> AgentActionRequest {
    let db = &state.base.db;
    let approver = seed_user(db).await;
    let approval_id = submit(state, f).await;

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
        .expect("an approved request yields its payload")
}

/// The agent asks to pause the target session; `dispatch` refuses it inline
/// and submits it for approval. Returns the pending request's id.
async fn submit(state: &EngineState, f: &Fixture) -> Uuid {
    let db = &state.base.db;
    let ctx = ActionContext::agent(security_context(f.owner), RiskTier::Consequential)
        .with_agent_session(f.agent_session_id);
    let ai = all_on();
    let inputs = GateInputs {
        licensed: true,
        ai: &ai,
        surface: None,
        external_effects_enabled: false,
    };
    let args = serde_json::json!({
        "session_id": f.target_session_id,
        "reason": "test: agent asked a supervisor to pause a runaway session",
    });

    let outcome = dispatch(
        state,
        &ActionRegistry::new(),
        &Executors::new(),
        AGENT_PAUSE,
        &ctx,
        &inputs,
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
        session_paused_at(db, f.target_session_id).await.is_none(),
        "nothing may execute before approval"
    );
    approval_id
}

/// Runs the approved request and asserts revalidation refused it and the
/// target session was NOT paused — the consequence, not just the verdict.
async fn assert_invalidated_and_nothing_ran(
    state: &EngineState,
    f: &Fixture,
    req: &AgentActionRequest,
) {
    let execution = dispatch_approved_agent_action(state, req)
        .await
        .expect("revalidation refusing is a verdict, not a transient error");
    assert!(
        matches!(execution, ApprovedExecution::Invalidated { .. }),
        "an approval must not outlive the security state it was granted under: {execution:?}"
    );
    assert!(
        session_paused_at(&state.base.db, f.target_session_id)
            .await
            .is_none(),
        "an invalidated approval must not have run the action"
    );
}

/// **The whole path, end to end** (at the crate-API level — see the module
/// doc for why this suite does not go through the HTTP admin surface).
/// `dispatch` refuses to run `agent.pause` inline and submits it for
/// approval; nothing pauses yet. A different user's `attome_approval::decide`
/// approves it, and `dispatch_approved_agent_action` — the function
/// `approval_admin::execute_approved`'s `attome-ai/invoke` arm calls —
/// actually runs it: the target session ends up paused for real.
#[tokio::test]
async fn approving_an_agent_pause_request_actually_pauses_the_session() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let request = submit_and_approve(&state, &f).await;

    let execution = dispatch_approved_agent_action(&state, &request)
        .await
        .expect("dispatch_approved_agent_action must run the approved action");
    let ApprovedExecution::Executed(result) = execution else {
        panic!("nothing changed since approval, so the action must run: {execution:?}");
    };
    assert_eq!(result["session_id"], f.target_session_id.to_string());
    assert_eq!(result["changed"], true);

    assert!(
        session_paused_at(&state.base.db, f.target_session_id)
            .await
            .is_some(),
        "the approved action must actually pause the target session"
    );
}

/// NEGATIVE: the requester loses the action's required privilege after the
/// approval. Before revalidation existed this ran anyway — the approved path
/// re-resolved the user but never re-checked what they held.
#[tokio::test]
async fn revoking_the_requesters_privilege_after_approval_invalidates_the_action() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let request = submit_and_approve(&state, &f).await;

    revoke_all_direct_privileges(&state.base.db, f.owner).await;

    assert_invalidated_and_nothing_ran(&state, &f, &request).await;
}

/// **Pause is "not now", not "never"** (D-502). The requesting session is
/// paused after approval: execution is deferred, nothing runs, and the request
/// stays approved and executable. Once the session is resumed the same
/// approved request runs.
#[tokio::test]
async fn pausing_the_requesting_session_defers_the_action_and_resuming_lets_it_run() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let request = submit_and_approve(&state, &f).await;
    let approval_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM approval_request \
          WHERE action_type = 'attome-ai/invoke:agent.pause' AND payload->>'agent_session_id' = $1",
    )
    .bind(f.agent_session_id.to_string())
    .fetch_one(&state.base.db)
    .await
    .expect("find the approval request");

    attome_ai::session::pause(&state.base.db, f.agent_session_id, f.owner, "test: pause")
        .await
        .expect("pause");

    let deferred = dispatch_approved_agent_action(&state, &request)
        .await
        .expect("a paused session is a verdict, not a transient error");
    assert!(
        matches!(deferred, ApprovedExecution::Deferred { .. }),
        "a paused session must defer, never invalidate: {deferred:?}"
    );
    assert!(
        session_paused_at(&state.base.db, f.target_session_id)
            .await
            .is_none(),
        "a deferred approval must not have run the action"
    );
    assert!(
        approved_payload(&state.base.db, approval_id)
            .await
            .expect("read")
            .is_some(),
        "a deferred request must still be approved and executable"
    );

    attome_ai::session::resume(&state.base.db, f.agent_session_id)
        .await
        .expect("resume");

    let executed = dispatch_approved_agent_action(&state, &request)
        .await
        .expect("run after resume");
    assert!(
        matches!(executed, ApprovedExecution::Executed(_)),
        "after resume the same approval must run: {executed:?}"
    );
    assert!(
        session_paused_at(&state.base.db, f.target_session_id)
            .await
            .is_some()
    );
}

/// NEGATIVE: the agent session that asked is killed after the approval. A
/// killed agent's queued actions die with it — otherwise the kill switch
/// stops future requests but not the ones already approved.
#[tokio::test]
async fn killing_the_agent_session_after_approval_invalidates_the_action() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let request = submit_and_approve(&state, &f).await;

    attome_ai::session::revoke(&state.base.db, f.agent_session_id, f.owner, "test: kill")
        .await
        .expect("revoke");

    assert_invalidated_and_nothing_ran(&state, &f, &request).await;
}

/// NEGATIVE: the deployment's licence stops covering the action's module
/// after the approval.
#[tokio::test]
async fn losing_the_licence_after_approval_invalidates_the_action() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let request = submit_and_approve(&state, &f).await;

    state.modules.store(Arc::new(ModuleSet::core_only()));

    assert_invalidated_and_nothing_ran(&state, &f, &request).await;
}

/// NEGATIVE: the AI kill-switch is off when the approved action runs. An
/// operator turning AI off during an incident must stop already-approved
/// agent actions too, not only new requests.
#[tokio::test]
async fn the_ai_kill_switch_at_execution_time_invalidates_the_action() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let request = submit_and_approve(&state, &f).await;

    // The same database with the switch off — the deployment as it is after
    // an operator flips `inference.ai.enabled` and restarts.
    let switched_off = skip_if_no_db!(test_state(false).await);

    assert_invalidated_and_nothing_ran(&switched_off, &f, &request).await;
}

/// NEGATIVE: the requesting account is disabled after the approval. Disable
/// does not strip grants (D-342's runbook treats that as a separate records
/// step), so a privilege re-check alone would miss it.
#[tokio::test]
async fn disabling_the_requesting_account_after_approval_invalidates_the_action() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let request = submit_and_approve(&state, &f).await;

    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(f.owner)
        .execute(&state.base.db)
        .await
        .expect("disable account");

    assert_invalidated_and_nothing_ran(&state, &f, &request).await;
}

/// Revalidation re-checks authorization, never the confirm/approve matrix.
/// An approved action from a tainted session still runs: the four-eyes
/// approval already was the human-in-the-loop step, and asking again would
/// send an approved action back to a human in a loop.
#[tokio::test]
async fn a_tainted_sessions_approved_action_runs_without_reconfirmation() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, true).await;
    let request = submit_and_approve(&state, &f).await;

    let execution = dispatch_approved_agent_action(&state, &request)
        .await
        .expect("run");
    assert!(
        matches!(execution, ApprovedExecution::Executed(_)),
        "a tainted session's approved action must run, not re-raise confirmation: {execution:?}"
    );
    assert!(
        session_paused_at(&state.base.db, f.target_session_id)
            .await
            .is_some()
    );
}

/// A pending (not yet decided) request's payload is never executable —
/// mirrors `consequential_gate.rs`'s own assertion of the same property for
/// `record.delete`, now proven for a real, registered action too.
#[tokio::test]
async fn a_pending_requests_payload_is_never_executable() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;

    let ctx = ActionContext::agent(security_context(f.owner), RiskTier::Consequential)
        .with_agent_session(f.agent_session_id);
    let ai = all_on();
    let inputs = GateInputs {
        licensed: true,
        ai: &ai,
        surface: None,
        external_effects_enabled: false,
    };
    let args = serde_json::json!({ "session_id": f.target_session_id });

    let outcome = dispatch(
        &state,
        &ActionRegistry::new(),
        &Executors::new(),
        AGENT_PAUSE,
        &ctx,
        &inputs,
        &args,
    )
    .await
    .expect("dispatch must succeed");
    let ActionOutcome::ApprovalRequired { approval_id } = outcome else {
        panic!("expected ApprovalRequired: {outcome:?}");
    };

    assert!(
        approved_payload(&state.base.db, approval_id)
            .await
            .expect("read")
            .is_none(),
        "a pending request must not yield an executable payload"
    );
    assert!(
        session_paused_at(&state.base.db, f.target_session_id)
            .await
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// ai-10-10 A0.5 — the D-518 execution claim, proven on an approved agent write
// ---------------------------------------------------------------------------
//
// `agent.pause` is a `Consequential` `Effect::Write` action, so an approved
// request for it is exactly the "approved agent write" A0.5 names. Every
// caller that runs an approved request in production (`attome-api`'s
// `approval_admin`: the decide route, `retry-execution`, the auto-approval
// job) goes through one composition: `attome_approval::claim_execution` with
// the `row_version` it read, `dispatch_approved_agent_action_under` only
// under that claim, then close the claim by outcome. `claim_and_run` below is
// that composition minus the HTTP layer and the audit hooks, so these tests
// pin the property on the AI side: however the callers interleave, the agent
// write runs once, and the loser is refused with the claim's own `Conflict`.
// The HTTP-level races are `attome-api/tests/approval_lifecycle.rs`.

/// What one caller of the approved-request path got.
#[derive(Debug)]
enum Attempt {
    /// This caller held the claim and dispatched the action.
    Ran(ApprovedExecution),
    /// `claim_execution` refused this caller; it ran nothing.
    Lost(AppError),
}

/// Claim, dispatch under the claim, close: `approval_admin::execute_approved`'s
/// order (D-518).
async fn claim_and_run(
    state: &EngineState,
    request_id: Uuid,
    row_version: i64,
    claimant: Uuid,
) -> Attempt {
    let db = &state.base.db;
    let claimed =
        match attome_approval::claim_execution(db, request_id, row_version, claimant).await {
            Ok(claimed) => claimed,
            Err(e) => return Attempt::Lost(e),
        };
    let payload: AgentActionRequest =
        serde_json::from_value(claimed.payload.clone()).expect("an agent action payload");
    let execution = dispatch_approved_agent_action_under(state, &payload, Some(claimed.id))
        .await
        .expect("nothing changed since approval, so dispatch is a verdict");
    match &execution {
        ApprovedExecution::Executed(_) => {
            attome_approval::complete_execution(db, claimed.id, claimed.row_version)
                .await
                .expect("close the claim as executed");
        }
        ApprovedExecution::Invalidated { .. } => {
            attome_approval::invalidate_execution(db, claimed.id, claimed.row_version)
                .await
                .expect("close the claim as invalidated");
        }
        ApprovedExecution::Deferred { .. } => {
            attome_approval::release_execution(db, claimed.id, claimed.row_version)
                .await
                .expect("release the claim");
        }
    }
    Attempt::Ran(execution)
}

/// How many times the approved `agent.pause` actually ran: the invocation
/// ledger gets one row per completed `Effect::Write` dispatch (the structural
/// ledger in `execute::run_executor`), and every test here opens a fresh
/// requesting session, so the count is this request's alone.
async fn executions(state: &EngineState, f: &Fixture) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_invocation           WHERE agent_session_id = $1 AND action_id = $2",
    )
    .bind(f.agent_session_id)
    .bind(AGENT_PAUSE)
    .fetch_one(&state.base.db)
    .await
    .expect("count ledger rows")
}

/// Asserts exactly one attempt ran the action and every other one lost to the
/// claim with `Conflict` ("being executed" or "already executed"), never a
/// `VersionConflict`, which would mean the request was still `approved` and
/// the loser could claim it again.
fn assert_exactly_one_ran(attempts: &[Attempt]) {
    let ran: Vec<_> = attempts
        .iter()
        .filter(|a| matches!(a, Attempt::Ran(_)))
        .collect();
    assert_eq!(
        ran.len(),
        1,
        "exactly one caller holds the claim: {attempts:?}"
    );
    assert!(
        matches!(ran[0], Attempt::Ran(ApprovedExecution::Executed(_))),
        "the winner runs the approved write: {attempts:?}"
    );
    for attempt in attempts {
        if let Attempt::Lost(e) = attempt {
            assert!(
                matches!(e, AppError::Conflict(_)),
                "the loser must see the claim, not a stale-version hint: {e:?}"
            );
        }
    }
}

/// Approves the pending request as a distinct user; returns the approved row.
async fn approve(state: &EngineState, approval_id: Uuid) -> attome_approval::ApprovalRequest {
    let approver = seed_user(&state.base.db).await;
    attome_approval::decide(
        &state.base.db,
        approval_id,
        approver,
        attome_approval::Decision::Approve,
        0,
    )
    .await
    .expect("a distinct approver may approve")
}

/// **A0.5 exit test.** `decide` racing `retry-execution` on one approved agent
/// write: once the decision commits, the deciding call's claim and a retry
/// that read the same `approved` row present the same `row_version`. Exactly
/// one runs `agent.pause`; the other sees the claim. Repeated so more than one
/// interleaving is exercised.
#[tokio::test]
async fn a_decide_racing_a_retry_executes_the_approved_agent_write_once() {
    let state = skip_if_no_db!(test_state(true).await);
    for round in 0..3 {
        let f = fixture(&state, false).await;
        let approval_id = submit(&state, &f).await;
        let decided = approve(&state, approval_id).await;
        let decider = seed_user(&state.base.db).await;
        let retrier = seed_user(&state.base.db).await;
        // What `retry-execution` reads before it claims.
        let read_by_retry = attome_approval::get(&state.base.db, approval_id)
            .await
            .expect("read the request");
        assert_eq!(
            read_by_retry.status,
            attome_approval::ApprovalStatus::Approved
        );
        assert_eq!(read_by_retry.row_version, decided.row_version);

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let decide_side = {
            let (state, barrier) = (state.clone(), Arc::clone(&barrier));
            tokio::spawn(async move {
                barrier.wait().await;
                claim_and_run(&state, approval_id, decided.row_version, decider).await
            })
        };
        let retry_side = {
            let (state, barrier) = (state.clone(), Arc::clone(&barrier));
            tokio::spawn(async move {
                barrier.wait().await;
                claim_and_run(&state, approval_id, read_by_retry.row_version, retrier).await
            })
        };
        let attempts = [
            decide_side.await.expect("join decide"),
            retry_side.await.expect("join retry"),
        ];
        assert_exactly_one_ran(&attempts);

        assert_eq!(
            executions(&state, &f).await,
            1,
            "round {round}: the approved agent write ran exactly once"
        );
        assert!(
            session_paused_at(&state.base.db, f.target_session_id)
                .await
                .is_some()
        );
        let closed = attome_approval::get(&state.base.db, approval_id)
            .await
            .expect("read the closed request");
        assert_eq!(closed.status, attome_approval::ApprovalStatus::Executed);
    }
}

/// Eight concurrent retries of one approved agent write (a double-clicked
/// retry, a retry racing the auto-approval job): one claim, one run.
#[tokio::test]
async fn concurrent_retries_of_an_approved_agent_write_execute_it_once() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let approval_id = submit(&state, &f).await;
    let decided = approve(&state, approval_id).await;

    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let claimant = seed_user(&state.base.db).await;
        let (state, barrier) = (state.clone(), Arc::clone(&barrier));
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            claim_and_run(&state, approval_id, decided.row_version, claimant).await
        }));
    }
    let mut attempts = Vec::new();
    for task in tasks {
        attempts.push(task.await.expect("join"));
    }
    assert_exactly_one_ran(&attempts);
    assert_eq!(executions(&state, &f).await, 1);
}

/// A retry after the approved agent write executed is refused as "already
/// executed" and runs nothing, even presenting the request's current
/// `row_version`.
#[tokio::test]
async fn a_retry_after_the_approved_agent_write_executed_runs_nothing() {
    let state = skip_if_no_db!(test_state(true).await);
    let f = fixture(&state, false).await;
    let approval_id = submit(&state, &f).await;
    let decided = approve(&state, approval_id).await;
    let runner = seed_user(&state.base.db).await;
    let first = claim_and_run(&state, approval_id, decided.row_version, runner).await;
    assert!(
        matches!(first, Attempt::Ran(ApprovedExecution::Executed(_))),
        "{first:?}"
    );

    let current = attome_approval::get(&state.base.db, approval_id)
        .await
        .expect("read the executed request");
    let retry = claim_and_run(&state, approval_id, current.row_version, runner).await;
    assert!(
        matches!(retry, Attempt::Lost(AppError::Conflict(_))),
        "an executed request is never claimed again: {retry:?}"
    );
    assert_eq!(executions(&state, &f).await, 1);
}

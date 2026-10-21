//! D-502 — claim-first invocation idempotency, against a real database.
//!
//! The property: **one logical tool call produces its side effect at most
//! once**, however it is retried and however many retries race. Every test
//! asserts the side effect itself (approval requests raised, records
//! written), not only what `dispatch` returned.
//!
//! The auto-executing agent write used here is `record.update_field`: since
//! M35 v1 C1 `memory.remember` never completes for an agent, so it can no
//! longer carry a race on the auto-execute path. Its fixtures are the ones
//! `record_update_field.rs` already uses. Bare `EngineState`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_HOST = "127.0.0.1"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test invocation_idempotency -- --test-threads=1
//! ```

#![recursion_limit = "512"]
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
use attome_ai::actions::memory::MEMORY_REMEMBER;
use attome_ai::actions::record_update_field::RECORD_UPDATE_FIELD;
use attome_ai::context::ActionContext;
use attome_ai::descriptor::RiskTier;
use attome_ai::execute::{ActionOutcome, Executors, dispatch};
use attome_ai::gate::GateInputs;
use attome_ai::registry::ActionRegistry;
use attome_ai::session::AgentSession;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_modules::ModuleSet;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

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
                "connection_number": 8, "timeout": 5.0,
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
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

// SAFETY: see `agent_action_approval_execution.rs`'s identical `ENV_LOCK`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Same two seeds `record_update_field.rs::seed_platform` runs: record writes
/// and memory saves audit themselves, and the audit header and autovalue
/// entities are metadata that migrations do not create.
async fn seed_platform(db: &attome_db::DbPool) {
    static SEEDED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    SEEDED
        .get_or_init(|| async {
            attome_audit::seed(db)
                .await
                .expect("seed audit entity metadata");
            attome_metadata::autovalue::seed_for_tests(db)
                .await
                .expect("seed autovalue entity + table");
        })
        .await;
}

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
    seed_platform(&db).await;
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
    state
        .modules
        .store(Arc::new(ModuleSet::from_bits([u64::MAX; 4])));
    Some(state)
}

async fn seed_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("invocation-idempotency-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// An untainted session at the Consequential ceiling, so a Reversible write
/// auto-executes (the path that has a side effect to duplicate) and a
/// Consequential one raises an approval.
async fn open_session(db: &attome_db::DbPool, owner: Uuid) -> AgentSession {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface, tainted) \
         VALUES ($1, 2, 'test', false) RETURNING id",
    )
    .bind(owner)
    .fetch_one(db)
    .await
    .expect("open agent session");
    AgentSession {
        id,
        owner_user_id: owner,
        risk_ceiling: RiskTier::Consequential,
        allowed_action_ids: None,
        tainted: false,
        policy: attome_ai::session::PolicySnapshot::NONE,
        anonymous_channel: false,
        surface: "test".to_owned(),
        trial: false,
    }
}

/// An admin (so `record.update_field`'s entity update privilege holds) that
/// also carries `ai_agent.supervise` explicitly.
fn security_context(user_id: Uuid) -> Arc<SecurityContext> {
    Arc::new(SecurityContext {
        user_id,
        is_admin: true,
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

fn inputs(ai: &attome_config::AiEnablement) -> GateInputs<'_> {
    GateInputs {
        licensed: true,
        ai,
        surface: None,
        external_effects_enabled: false,
    }
}

/// A throwaway entity with a `status` field (allow-listed) and a `note` field
/// (not), plus one record — `record_update_field.rs`'s fixture, trimmed.
async fn provision_record(state: &EngineState) -> (String, Uuid) {
    let logicalname = format!("idem_test_{}", Uuid::now_v7().simple());
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "Invocation Idempotency Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    for (field, label) in [("status", "Status"), ("note", "Note")] {
        attome_metadata::provision::ensure_attribute(
            &state.base.db,
            entity_id,
            field,
            label,
            "text",
            false,
            false,
            false,
            false,
            None,
            None,
        )
        .await
        .expect("provision attribute");
    }
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    let table = attome_core::quote_ident(&logicalname);
    let record_id: Uuid = sqlx::query_scalar(&format!(
        "INSERT INTO {table} (id, status, note, is_active, row_version) \
         VALUES ($1, 'open', 'n/a', true, 0) RETURNING id"
    ))
    .bind(Uuid::now_v7())
    .fetch_one(&state.base.db)
    .await
    .expect("insert throwaway test record");

    set_allowlist(state, &logicalname, &["status"]).await;
    (logicalname, record_id)
}

/// Writes (or replaces) the deployment-scope `ai.record_update_field_allowlist`
/// row and reloads settings — `record_update_field.rs::set_allowlist`.
async fn set_allowlist(state: &EngineState, entity: &str, fields: &[&str]) {
    let value = json!({ entity: fields });
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM setting \
          WHERE key = 'ai.record_update_field_allowlist' AND scope = 'deployment' \
            AND scope_ref IS NULL AND is_deleted = FALSE",
    )
    .fetch_optional(&state.base.db)
    .await
    .expect("look up existing allow-list row");
    if let Some(id) = existing {
        sqlx::query(
            "UPDATE setting SET value = $2, row_version = row_version + 1, \
             updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .bind(&value)
        .execute(&state.base.db)
        .await
        .expect("update allow-list setting");
    } else {
        sqlx::query(
            "INSERT INTO setting (key, scope, scope_ref, value, schema) \
             VALUES ('ai.record_update_field_allowlist', 'deployment', NULL, $1, $2)",
        )
        .bind(&value)
        .bind(json!({"type": "object"}))
        .execute(&state.base.db)
        .await
        .expect("insert allow-list setting");
    }
    state.settings.swap(
        attome_core::load_all_settings(&state.base.db)
            .await
            .expect("reload settings"),
    );
}

/// Policy auto-approval requests this user's agent raised. Each executed
/// `record.update_field` agent write raises exactly one, before its write —
/// so a second executor for the same tool call shows up here even when its
/// own write then loses the record's optimistic-concurrency check.
async fn policy_approvals_for(db: &attome_db::DbPool, user_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_request \
          WHERE action_type LIKE 'attome-ai/policy-approved:%' AND requested_by = $1",
    )
    .bind(user_id)
    .fetch_one(db)
    .await
    .expect("count policy approvals")
}

async fn ledger_outcomes(db: &attome_db::DbPool, session_id: Uuid, key: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT outcome FROM action_invocation \
          WHERE agent_session_id = $1 AND tool_call_id = $2",
    )
    .bind(session_id)
    .bind(key)
    .fetch_all(db)
    .await
    .expect("read ledger")
}

fn update_status(entity: &str, record_id: Uuid, value: &str) -> Value {
    json!({
        "entity": entity,
        "record_id": record_id,
        "field": "status",
        "value": value,
        "row_version": 0,
    })
}

fn is_replay(outcome: &ActionOutcome) -> bool {
    matches!(outcome, ActionOutcome::Completed { result, .. } if result["replayed"] == true)
}

/// **The race.** Two retries of one tool call, in flight at the same moment.
/// Exactly one executes: one policy approval is raised and the record is
/// written once. The other replays that result or is told the call is in
/// progress — it never runs the executor. A later retry replays.
#[tokio::test]
async fn concurrent_retries_of_one_tool_call_execute_exactly_once() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let session = open_session(&state.base.db, owner).await;
    let (entity, record_id) = provision_record(&state).await;
    let key = format!("call_{}", Uuid::now_v7().simple());
    let ctx =
        ActionContext::for_session(security_context(owner), &session).with_idempotency_key(&key);
    let (registry, executors, ai) = (ActionRegistry::new(), Executors::new(), all_on());
    // Bound once, not built inline: `tokio::join!` holds both futures, so a
    // temporary `GateInputs` would be dropped while they still borrow it.
    let gate = inputs(&ai);
    let args = update_status(&entity, record_id, "closed");

    let (a, b) = tokio::join!(
        dispatch(
            &state,
            &registry,
            &executors,
            RECORD_UPDATE_FIELD,
            &ctx,
            &gate,
            &args
        ),
        dispatch(
            &state,
            &registry,
            &executors,
            RECORD_UPDATE_FIELD,
            &ctx,
            &gate,
            &args
        ),
    );

    assert_eq!(
        policy_approvals_for(&state.base.db, owner).await,
        1,
        "two concurrent retries of one tool call must run the executor exactly once"
    );

    let mut executed = 0;
    for outcome in [a, b] {
        match outcome {
            Ok(o @ ActionOutcome::Completed { .. }) if !is_replay(&o) => executed += 1,
            Ok(o) if is_replay(&o) => {}
            Err(AppError::Conflict(message)) => {
                assert!(message.contains("in progress"), "{message}")
            }
            other => panic!("unexpected outcome for a raced retry: {other:?}"),
        }
    }
    assert_eq!(executed, 1, "exactly one of the two calls may execute");

    let later = dispatch(
        &state,
        &registry,
        &executors,
        RECORD_UPDATE_FIELD,
        &ctx,
        &gate,
        &args,
    )
    .await
    .expect("a later retry replays");
    assert!(
        is_replay(&later),
        "a later retry must replay, not re-run: {later:?}"
    );
    assert_eq!(policy_approvals_for(&state.base.db, owner).await, 1);

    let table = attome_core::quote_ident(&entity);
    let (status, row_version): (String, i64) = sqlx::query_as(&format!(
        "SELECT status, row_version::bigint FROM {table} WHERE id = $1"
    ))
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read the record");
    assert_eq!(status, "closed");
    assert_eq!(row_version, 1, "the record is written exactly once");

    assert_eq!(
        ledger_outcomes(&state.base.db, session.id, &key).await,
        vec!["completed".to_string()],
        "one ledger row for the key, completed"
    );
}

/// A retried Consequential tool call raises ONE four-eyes request, even when
/// the retries race. An approver seeing two identical requests cannot tell
/// which is real, or whether approving both does the thing twice.
#[tokio::test]
async fn racing_retries_of_a_consequential_call_raise_one_approval_request() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let session = open_session(&state.base.db, owner).await;
    let target = open_session(&state.base.db, owner).await;
    let key = format!("call_{}", Uuid::now_v7().simple());
    let ctx =
        ActionContext::for_session(security_context(owner), &session).with_idempotency_key(&key);
    let (registry, executors, ai) = (ActionRegistry::new(), Executors::new(), all_on());
    let gate = inputs(&ai);
    let args = json!({ "session_id": target.id });

    let (a, b) = tokio::join!(
        dispatch(
            &state,
            &registry,
            &executors,
            AGENT_PAUSE,
            &ctx,
            &gate,
            &args
        ),
        dispatch(
            &state,
            &registry,
            &executors,
            AGENT_PAUSE,
            &ctx,
            &gate,
            &args
        ),
    );
    let later = dispatch(
        &state,
        &registry,
        &executors,
        AGENT_PAUSE,
        &ctx,
        &gate,
        &args,
    )
    .await;

    let requests: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_request \
          WHERE action_type = 'attome-ai/invoke:agent.pause' AND payload->>'agent_session_id' = $1",
    )
    .bind(session.id.to_string())
    .fetch_one(&state.base.db)
    .await
    .expect("count approval requests");
    assert_eq!(requests, 1, "one intent, one approval request");

    let mut approval_ids = HashSet::new();
    for outcome in [a, b, later] {
        match outcome {
            Ok(ActionOutcome::ApprovalRequired { approval_id }) => {
                approval_ids.insert(approval_id);
            }
            Err(AppError::Conflict(message)) => {
                assert!(message.contains("in progress"), "{message}")
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(
        approval_ids.len(),
        1,
        "every reply names the same approval request"
    );

    let paused: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT paused_at FROM agent_session WHERE id = $1")
            .bind(target.id)
            .fetch_one(&state.base.db)
            .await
            .expect("read target");
    assert!(paused.is_none(), "nothing executes before approval");
}

/// Retryability: an attempt whose executor refuses must not occupy the key,
/// or the tool call could never succeed. The same key then executes normally.
#[tokio::test]
async fn a_failed_attempt_releases_its_key_so_the_call_can_be_retried() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let session = open_session(&state.base.db, owner).await;
    let (entity, record_id) = provision_record(&state).await;
    let key = format!("call_{}", Uuid::now_v7().simple());
    let ctx =
        ActionContext::for_session(security_context(owner), &session).with_idempotency_key(&key);
    let (registry, executors, ai) = (ActionRegistry::new(), Executors::new(), all_on());
    let gate = inputs(&ai);

    // `note` is not on the allow-list: the executor refuses before writing.
    let refused_args = json!({
        "entity": entity,
        "record_id": record_id,
        "field": "note",
        "value": "changed",
        "row_version": 0,
    });
    let failed = dispatch(
        &state,
        &registry,
        &executors,
        RECORD_UPDATE_FIELD,
        &ctx,
        &gate,
        &refused_args,
    )
    .await;
    assert!(
        failed.is_err(),
        "a non-allow-listed field must be refused: {failed:?}"
    );
    assert!(
        ledger_outcomes(&state.base.db, session.id, &key)
            .await
            .is_empty(),
        "a failed attempt must leave no claim behind"
    );

    let retried = dispatch(
        &state,
        &registry,
        &executors,
        RECORD_UPDATE_FIELD,
        &ctx,
        &gate,
        &update_status(&entity, record_id, "closed"),
    )
    .await
    .expect("the retry executes");
    assert!(
        matches!(retried, ActionOutcome::Completed { .. }) && !is_replay(&retried),
        "the retry must execute, not replay a failure: {retried:?}"
    );
    assert_eq!(
        ledger_outcomes(&state.base.db, session.id, &key).await,
        vec!["completed".to_string()]
    );
}

/// Sessionless (human) invocations are not deduplicated by the ledger — their
/// idempotency is the HTTP `X-Idempotency-Key` tier (D-502 §3). Two clicks are
/// two writes, and neither claims a key.
#[tokio::test]
async fn an_unkeyed_human_invocation_is_not_deduplicated_by_the_ledger() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let marker = format!("idempotency-human-{}", Uuid::now_v7());
    let ctx = ActionContext::user(security_context(owner));
    let (registry, executors, ai) = (ActionRegistry::new(), Executors::new(), all_on());
    let gate = inputs(&ai);
    let args = json!({ "scope_kind": "user", "kind": "note", "summary": marker });

    for _ in 0..2 {
        let outcome = dispatch(
            &state,
            &registry,
            &executors,
            MEMORY_REMEMBER,
            &ctx,
            &gate,
            &args,
        )
        .await
        .expect("a human invocation executes");
        assert!(!is_replay(&outcome), "{outcome:?}");
    }
    let written: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM memory WHERE summary = $1")
        .bind(&marker)
        .fetch_one(&state.base.db)
        .await
        .expect("count memories");
    assert_eq!(written, 2);

    let claimed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_invocation \
          WHERE acting_user_id = $1 AND outcome = 'claimed'",
    )
    .bind(owner)
    .fetch_one(&state.base.db)
    .await
    .expect("count claims");
    assert_eq!(claimed, 0, "a human invocation never takes a claim");
}

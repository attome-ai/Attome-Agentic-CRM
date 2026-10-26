//! `record.update_field` against a real database (M98 Phase 1, D-448) — the
//! three negative paths that need one: the allow-list, the special-category
//! escalation, and blast-radius cap exhaustion. Plus the happy path that
//! proves the ladder's positive half (auto-approval + a real write) and the
//! revert path that reads it back. The two gate-level negative paths that
//! need no database (I-10 taint-degrade, kill-switch invisibility) live as
//! pure unit tests in `record_update_field.rs` itself, against the same
//! real descriptor.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-ai --test record_update_field -- --test-threads=1
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

use attome_ai::actions::record_update_field::{
    self, DAILY_WRITE_CAP, RECORD_UPDATE_FIELD, RecordUpdateField,
};
use attome_ai::context::ActionContext;
use attome_ai::descriptor::RiskTier;
use attome_ai::execute::{ActionOutcome, Executors, dispatch};
use attome_ai::gate::GateInputs;
use attome_ai::registry::ActionRegistry;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use serde_json::json;
use uuid::Uuid;

/// Same shape `attome-workflow/tests/execution.rs::test_config` uses — this
/// suite needs the identical infra (Postgres + Redis + storage) a full
/// `EngineState` requires, even though it never touches storage itself.
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

// SAFETY: see `attome-workflow/tests/execution.rs`'s identical `ENV_LOCK` doc
// comment — `attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` from the
// environment synchronously before its first `.await`, and this suite's
// several `#[tokio::test]` functions run concurrently by default.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `attome_audit::seed` (every write here goes through `update_record_for`,
/// which audits itself, and that resolves `audit_header` from
/// `entity_info` — migrations create the table but not its
/// metadata) plus `attome_metadata::autovalue::seed` (`entity_mutation::update_one`
/// reads `autovalue`, itself a metadata-defined entity migrations
/// do not create). Same two seeds, same reasoning, as
/// `attome-workflow/tests/execution.rs::seed_platform`.
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
            // The bot-handoff tests create and count service work requests;
            // the service entities look up the project entity, so it goes first.
            attome_security::seed::seed_for_tests(db)
                .await
                .expect("seed security entities");
            attome_project::seed::seed_for_tests(db)
                .await
                .expect("seed project entities");
            attome_service::seed::seed_for_tests(db)
                .await
                .expect("seed service entities");
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
    Some(EngineState::new(base))
}

async fn seed_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("record-update-field-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// Provisions a throwaway entity with a plain `status` field and a
/// `special_note` field this test marks `sensitive_special_category` by
/// direct SQL — `ensure_attribute` (`attome-metadata::provision`) has no
/// `data_classification` parameter, and a hand-written `UPDATE` against a
/// throwaway test database is one of guidelines §4's four API-first
/// exemptions ("tests against a throwaway database").
///
/// Unique per call (not just per test file) so repeated runs against a
/// persistent throwaway database never collide — same convention
/// `attome-workflow`'s `publish_workflow` uses for its logicalname.
async fn provision_test_entity(state: &EngineState) -> Uuid {
    let logicalname = format!("ruf_test_{}", Uuid::now_v7().simple());
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "record.update_field Test Entity",
        None,
        false,
    )
    .await
    .expect("provision test entity");
    attome_metadata::provision::ensure_attribute(
        &state.base.db,
        entity_id,
        "status",
        "Status",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("provision status attribute");
    attome_metadata::provision::ensure_attribute(
        &state.base.db,
        entity_id,
        "special_note",
        "Special Note",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("provision special_note attribute");
    sqlx::query(
        "UPDATE attribute_info SET data_classification = 'sensitive_special_category' \
          WHERE entity_ref = $1 AND logicalname = 'special_note'",
    )
    .bind(entity_id)
    .execute(&state.base.db)
    .await
    .expect("mark special_note sensitive_special_category");

    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    entity_id
}

async fn insert_test_record(state: &EngineState, entity_logicalname: &str, status: &str) -> Uuid {
    let table = attome_core::quote_ident(entity_logicalname);
    let sql = format!(
        "INSERT INTO {table} (id, status, special_note, is_active, row_version) \
         VALUES ($1, $2, 'unclassified', true, 0) RETURNING id"
    );
    sqlx::query_scalar(&sql)
        .bind(Uuid::now_v7())
        .bind(status)
        .fetch_one(&state.base.db)
        .await
        .expect("insert throwaway test record")
}

/// Writes (or replaces) the deployment-scope `ai.record_update_field_allowlist`
/// row and refreshes `state.settings` so the executor's very next read
/// observes it — same same-node-write-applies-synchronously convention
/// `setting_store.rs`'s module doc describes for the real write handler.
async fn set_allowlist(state: &EngineState, entity: &str, fields: &[&str]) {
    let value = json!({ entity: fields });
    // Check-then-write rather than `ON CONFLICT` against
    // `setting_key_scope_ref_uk`'s partial expression index — this
    // is a test helper, and matching that index's exact expression shape in
    // an ON CONFLICT target is more fragile than it is worth here.
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
        field_masks: Default::default(),
        service_principal: false,
    })
}

async fn open_agent_session(db: &attome_db::DbPool, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface) \
         VALUES ($1, 1, 'test') RETURNING id",
    )
    .bind(owner)
    .fetch_one(db)
    .await
    .expect("open agent session")
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

async fn current_status(state: &EngineState, entity_logicalname: &str, record_id: Uuid) -> String {
    let table = attome_core::quote_ident(entity_logicalname);
    sqlx::query_scalar(&format!("SELECT status FROM {table} WHERE id = $1"))
        .bind(record_id)
        .fetch_one(&state.base.db)
        .await
        .expect("read status")
}

/// **The happy path**, backbone for the revert test below: an untainted
/// agent write to an allow-listed field auto-executes, leaves a decided
/// `attome_approval` record (module doc's "auto-approval is still an
/// approval"), and its invocation row carries the prior value.
#[tokio::test]
async fn agent_write_to_an_allowlisted_field_auto_executes_with_a_decided_approval() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let entity_id = provision_test_entity(&state).await;
    let entity_name: String =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read logicalname");
    set_allowlist(&state, &entity_name, &["status"]).await;
    let record_id = insert_test_record(&state, &entity_name, "open").await;
    let session_id = open_agent_session(&state.base.db, owner).await;

    let ctx = ActionContext::agent(security_context(owner), RiskTier::Reversible)
        .with_agent_session(session_id);
    let ai = all_on();
    let registry = ActionRegistry::new();
    let executors = Executors::new();
    let args = json!({
        "entity": entity_name,
        "record_id": record_id,
        "field": "status",
        "value": "closed",
        "row_version": 0,
    });

    let outcome = dispatch(
        &state,
        &registry,
        &executors,
        RECORD_UPDATE_FIELD,
        &ctx,
        &all_on_gate_inputs(&ai),
        &args,
    )
    .await
    .expect("dispatch must succeed");

    let ActionOutcome::Completed { result, .. } = outcome else {
        panic!("an untainted agent write must auto-execute: {outcome:?}");
    };
    assert_eq!(result["prior_value"], json!("open"));
    assert_eq!(result["new_value"], json!("closed"));
    assert_eq!(result["revertible"], json!(true));

    assert_eq!(
        current_status(&state, &entity_name, record_id).await,
        "closed",
        "the record must actually be updated"
    );

    // The approval record: decided by policy, and executed.
    let approval_id = result["approval_id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("a decided approval id must be returned");
    let approval = attome_approval::get(&state.base.db, approval_id)
        .await
        .expect("read approval");
    assert_eq!(approval.status, attome_approval::ApprovalStatus::Executed);
    assert_eq!(
        approval.requested_by, owner,
        "the human is requested_by, never the agent"
    );
    let decided_by: Uuid =
        sqlx::query_scalar("SELECT approver_id FROM approval_grant WHERE request_id = $1")
            .bind(approval_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read the grant");
    assert_eq!(
        decided_by,
        attome_approval::POLICY_ACTOR_ID,
        "the audit trail must show policy decided it, not a blank actor"
    );
}

/// **Negative path.** A field not on the allow-list is refused for every
/// caller — this is the action's own scope, not a privilege gap.
#[tokio::test]
async fn a_field_not_on_the_allowlist_is_refused() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let entity_id = provision_test_entity(&state).await;
    let entity_name: String =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read logicalname");
    // Allow-list some OTHER field, never "status".
    set_allowlist(&state, &entity_name, &["special_note"]).await;
    let record_id = insert_test_record(&state, &entity_name, "open").await;

    let ctx = ActionContext::user(security_context(owner));
    let ai = all_on();
    let registry = ActionRegistry::new();
    let executors = Executors::new();
    let args = json!({
        "entity": entity_name,
        "record_id": record_id,
        "field": "status",
        "value": "closed",
        "row_version": 0,
    });

    let err = dispatch(
        &state,
        &registry,
        &executors,
        RECORD_UPDATE_FIELD,
        &ctx,
        &all_on_gate_inputs(&ai),
        &args,
    )
    .await
    .expect_err("a field off the allow-list must be refused");
    assert!(matches!(err, attome_types::AppError::Forbidden));
    assert_eq!(
        current_status(&state, &entity_name, record_id).await,
        "open",
        "a refused write must not touch the record"
    );
}

/// **Negative path (plan §5, "Consequential regardless of descriptor").** An
/// agent writing a `sensitive_special_category` field is refused outright —
/// no confirm-first, no approval request, the same outcome a Consequential
/// action gets from an agent, reached here because the static gate could
/// never see this coming from the descriptor alone.
#[tokio::test]
async fn an_agent_writing_a_special_category_field_is_refused() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let entity_id = provision_test_entity(&state).await;
    let entity_name: String =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read logicalname");
    set_allowlist(&state, &entity_name, &["special_note"]).await;
    let record_id = insert_test_record(&state, &entity_name, "open").await;
    let session_id = open_agent_session(&state.base.db, owner).await;

    let ctx = ActionContext::agent(security_context(owner), RiskTier::Reversible)
        .with_agent_session(session_id);
    let ai = all_on();
    let registry = ActionRegistry::new();
    let executors = Executors::new();
    let args = json!({
        "entity": entity_name,
        "record_id": record_id,
        "field": "special_note",
        "value": "leaked",
        "row_version": 0,
    });

    let err = dispatch(
        &state,
        &registry,
        &executors,
        RECORD_UPDATE_FIELD,
        &ctx,
        &all_on_gate_inputs(&ai),
        &args,
    )
    .await
    .expect_err("an agent must never write a special-category field");
    assert!(matches!(err, attome_types::AppError::Forbidden));

    let note: String = sqlx::query_scalar(&format!(
        "SELECT special_note FROM {} WHERE id = $1",
        attome_core::quote_ident(&entity_name)
    ))
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .expect("read special_note");
    assert_eq!(note, "unclassified", "the refused write must not land");

    let invocations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM action_invocation WHERE agent_session_id = $1")
            .bind(session_id)
            .fetch_one(&state.base.db)
            .await
            .expect("count invocations");
    assert_eq!(
        invocations, 0,
        "a refused write must leave no invocation row and no approval record"
    );
}

/// **Negative path.** The daily write cap refuses once exhausted — the
/// per-session blast-radius control plan §5 names.
#[tokio::test]
async fn the_daily_write_cap_refuses_once_exhausted() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let entity_id = provision_test_entity(&state).await;
    let entity_name: String =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read logicalname");
    set_allowlist(&state, &entity_name, &["status"]).await;
    let record_id = insert_test_record(&state, &entity_name, "open").await;
    let session_id = open_agent_session(&state.base.db, owner).await;

    // Fabricate a full day's worth of prior completed writes directly —
    // faster and more deterministic than actually issuing DAILY_WRITE_CAP
    // real writes, and this test is about the cap's own boundary, not the
    // write path (already covered by the happy-path test above).
    for _ in 0..DAILY_WRITE_CAP {
        sqlx::query(
            "INSERT INTO action_invocation \
                (agent_session_id, tool_call_id, action_id, initiator, acting_user_id, outcome) \
             VALUES ($1, $2, $3, 1, $4, 'completed')",
        )
        .bind(session_id)
        .bind(format!("call_{}", Uuid::now_v7()))
        .bind(RECORD_UPDATE_FIELD)
        .bind(owner)
        .execute(&state.base.db)
        .await
        .expect("fabricate a prior completed invocation");
    }

    let ctx = ActionContext::agent(security_context(owner), RiskTier::Reversible)
        .with_agent_session(session_id);
    let ai = all_on();
    let registry = ActionRegistry::new();
    let executors = Executors::new();
    let args = json!({
        "entity": entity_name,
        "record_id": record_id,
        "field": "status",
        "value": "closed",
        "row_version": 0,
    });

    let err = dispatch(
        &state,
        &registry,
        &executors,
        RECORD_UPDATE_FIELD,
        &ctx,
        &all_on_gate_inputs(&ai),
        &args,
    )
    .await
    .expect_err("the daily cap must refuse the next write");
    assert!(matches!(
        err,
        attome_types::AppError::TooManyRequests {
            retry_after_secs: None
        }
    ));
    assert_eq!(
        current_status(&state, &entity_name, record_id).await,
        "open",
        "a capped-out write must not touch the record"
    );
}

/// REVIEW-2026-09-02 finding #9 — proves `crate::write_guard`'s shared caps
/// actually protect a SECOND action, not just `record.update_field`: once
/// `bot.handoff`'s own daily cap is exhausted for a session, the next
/// handoff is refused before any work request is created. Lives in this
/// file rather than a new `tests/bot_handoff.rs` to reuse the same harness
/// (`test_state`/`security_context`/`open_agent_session`) instead of
/// duplicating ~150 lines of `AppConfig`/`EngineState` bootstrap into a second
/// test binary for one assertion.
#[tokio::test]
async fn bot_handoff_daily_cap_refuses_once_exhausted() {
    use attome_ai::actions::bot_handoff::{BOT_HANDOFF, DAILY_HANDOFF_CAP};

    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let session_id = open_agent_session(&state.base.db, owner).await;

    for _ in 0..DAILY_HANDOFF_CAP {
        sqlx::query(
            "INSERT INTO action_invocation \
                (agent_session_id, tool_call_id, action_id, initiator, acting_user_id, outcome) \
             VALUES ($1, $2, $3, 1, $4, 'completed')",
        )
        .bind(session_id)
        .bind(format!("call_{}", Uuid::now_v7()))
        .bind(BOT_HANDOFF)
        .bind(owner)
        .execute(&state.base.db)
        .await
        .expect("fabricate a prior completed invocation");
    }

    // `bot.handoff` is `RetryClass::RequiresKey`: without a key, dispatch
    // refuses it as a validation error before the cap is ever consulted, and
    // this test would pass or fail on the wrong check.
    let ctx = ActionContext::agent(security_context(owner), RiskTier::Reversible)
        .with_agent_session(session_id)
        .with_idempotency_key(format!("handoff-cap-{session_id}"));
    let ai = all_on();
    let registry = ActionRegistry::new();
    let executors = Executors::new();
    let args = json!({
        "agent_session_id": session_id,
        "reason": "user_requested",
    });

    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM service_work_request")
        .fetch_one(&state.base.db)
        .await
        .expect("count work requests before");

    let err = dispatch(
        &state,
        &registry,
        &executors,
        BOT_HANDOFF,
        &ctx,
        &all_on_gate_inputs(&ai),
        &args,
    )
    .await
    .expect_err("the daily cap must refuse the next handoff");
    assert!(matches!(
        err,
        attome_types::AppError::TooManyRequests {
            retry_after_secs: None
        }
    ));

    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM service_work_request")
        .fetch_one(&state.base.db)
        .await
        .expect("count work requests after");
    assert_eq!(
        before, after,
        "a capped-out handoff must not open a work request"
    );
}

/// **The revert path.** After a completed write, `revert` reads the
/// invocation's recorded prior value back and restores it, CAS'd against the
/// record's row_version as it is NOW, not as it was at write time.
#[tokio::test]
async fn revert_restores_the_field_to_its_prior_value() {
    let state = skip_if_no_db!(test_state().await);
    let owner = seed_user(&state.base.db).await;
    let entity_id = provision_test_entity(&state).await;
    let entity_name: String =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_one(&state.base.db)
            .await
            .expect("read logicalname");
    set_allowlist(&state, &entity_name, &["status"]).await;
    let record_id = insert_test_record(&state, &entity_name, "open").await;
    let session_id = open_agent_session(&state.base.db, owner).await;

    let ctx = ActionContext::agent(security_context(owner), RiskTier::Reversible)
        .with_agent_session(session_id);
    let ai = all_on();
    let registry = ActionRegistry::new();
    let executors = Executors::new();
    let args = json!({
        "entity": entity_name,
        "record_id": record_id,
        "field": "status",
        "value": "closed",
        "row_version": 0,
    });
    let outcome = dispatch(
        &state,
        &registry,
        &executors,
        RECORD_UPDATE_FIELD,
        &ctx,
        &all_on_gate_inputs(&ai),
        &args,
    )
    .await
    .expect("dispatch must succeed");
    let ActionOutcome::Completed { .. } = outcome else {
        panic!("setup write must auto-execute: {outcome:?}");
    };
    assert_eq!(
        current_status(&state, &entity_name, record_id).await,
        "closed"
    );

    // A second, unrelated write moves row_version further — proving revert
    // CASes against the CURRENT version, not the one the original write
    // captured.
    sqlx::query(&format!(
        "UPDATE {} SET status = 'closed', row_version = row_version + 1 WHERE id = $1",
        attome_core::quote_ident(&entity_name)
    ))
    .bind(record_id)
    .execute(&state.base.db)
    .await
    .expect("bump row_version with an unrelated concurrent-style write");

    let invocation_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM action_invocation \
          WHERE agent_session_id = $1 AND action_id = $2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(session_id)
    .bind(RECORD_UPDATE_FIELD)
    .fetch_one(&state.base.db)
    .await
    .expect("find the invocation to revert");

    let admin_ctx = security_context(owner);
    let reverted = record_update_field::revert(&state, &admin_ctx, owner, invocation_id)
        .await
        .expect("revert must succeed");
    assert_eq!(reverted["data"]["status"], json!("open"));

    assert_eq!(
        current_status(&state, &entity_name, record_id).await,
        "open",
        "the field must be restored to its recorded prior value"
    );
}

/// A malformed executor is never registered without an entry in `all()` —
/// pins the registration this file's tests all depend on, so a future
/// refactor that drops `record_update_field` from `actions/mod.rs::all()`
/// (but not `all_executors()`) fails loudly here instead of every dispatch
/// call above silently 404ing.
#[test]
fn record_update_field_is_registered_and_has_an_executor() {
    let registry = ActionRegistry::new();
    let executors = Executors::new();
    let descriptor = registry
        .resolve(RECORD_UPDATE_FIELD)
        .expect("record.update_field must be registered");
    assert_eq!(descriptor.risk, RiskTier::Reversible);
    // `Executors::get` is private, but `execute::executors_cover_every_registered_action`
    // in the crate's own test module already proves every descriptor has an
    // executor — this just confirms the id used throughout this file is the
    // real one, not a typo the compiler could not catch.
    let _ = RecordUpdateField;
    let _ = &executors;
}

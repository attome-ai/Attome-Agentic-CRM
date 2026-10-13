//! The confirm round-trip (C4), through the real `confirm_tool_call` path,
//! against Postgres — never through `tool_call::claim` alone.
//!
//! A human confirms a server-persisted agent proposal, which then runs **as
//! that agent action** (the session's own context, its persisted
//! `tool_call_id` as the D-502 key). These tests prove the state machine and
//! the A-41 contract:
//!
//! - lockable session/account state is read under `FOR SHARE` in the check
//!   transaction T, and the refusal it causes commits with it;
//! - the other admission checks are point-in-time, and a change after them
//!   does not cancel an admitted execution;
//! - every post-claim write is conditional on the claimed `row_version`, no
//!   normal path leaves a proposal `executing`, and nothing executes twice.
//!
//! Every "nothing ran" assertion checks the business row (a real, writable,
//! provisioned test entity — so "unchanged" means something), the invocation
//! ledger, and agent-attributed audit events.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test confirm -- --test-threads=1
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

use std::sync::Arc;
use std::time::Duration;

use attome_ai::confirm::{ConfirmOutcome, ConfirmRefusal, ConfirmRequest, confirm_tool_call};
use attome_ai::conversation::{self, NewConversation, Surface};
use attome_ai::execute::Executors;
use attome_ai::registry::ActionRegistry;
use attome_ai::session::AgentSession;
use attome_ai::tool_call::{self, Status};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_modules::ModuleSet;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

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
                "connection_number": 12, "timeout": 5.0,
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
            "inference": {{
                "ai": {{
                    "enabled": true, "fields": true, "chat": true,
                    "semantic_search": true, "workflow_nodes": true
                }}
            }},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `update_record_for` audits itself and reads `autovalue` — the
/// same two seeds `record_update_field.rs` needs, for the same reason.
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

fn full_licence() -> Arc<ModuleSet> {
    Arc::new(ModuleSet::from_bits([u64::MAX; 4]))
}

async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK, same posture as the sibling suites.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let config = test_config(&db_url);
    let db = attome_db::create_pool(&config).await.expect("connect db");
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
        .expect("storage client");
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
    state.modules.store(full_licence());
    Some(state)
}

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
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT $1, $2, id, true, NOW() FROM privilege WHERE key = $3",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(key)
    .execute(db)
    .await
    .expect("grant privilege");
}

async fn revoke_privilege(db: &attome_db::DbPool, user_id: Uuid, key: &str) {
    sqlx::query(
        "DELETE FROM user_account_mm_privilege \
          WHERE user_ref = $1 AND privilege_ref = (SELECT id FROM privilege WHERE key = $2)",
    )
    .bind(user_id)
    .bind(key)
    .execute(db)
    .await
    .expect("revoke privilege");
}

/// A throwaway entity with one plain `status` field, allow-listed for
/// `record.update_field` — the writable target that makes "the business row
/// is unchanged" a real assertion. Unique per call.
async fn provision_test_entity(state: &EngineState) -> String {
    let logicalname = format!("cnf_test_{}", Uuid::now_v7().simple());
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "Confirm Test Entity",
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
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    set_allowlist(state, &logicalname, &["status"]).await;
    logicalname
}

/// Deployment-scope `ai.record_update_field_allowlist`, then a settings
/// reload — `record_update_field.rs`'s helper, unchanged in shape.
async fn set_allowlist(state: &EngineState, entity: &str, fields: &[&str]) {
    let value = json!({ entity: fields });
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM setting \
          WHERE key = 'ai.record_update_field_allowlist' AND scope = 'deployment' \
            AND scope_ref IS NULL AND is_deleted = FALSE",
    )
    .fetch_optional(&state.base.db)
    .await
    .expect("look up allow-list row");
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

struct Fixture {
    state: EngineState,
    owner: Uuid,
    session: AgentSession,
    conversation_id: Uuid,
    entity: String,
    record_id: Uuid,
}

async fn fixture() -> Option<Fixture> {
    let state = test_state().await?;
    let db = state.base.db.clone();
    let owner = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(owner)
        .bind(attome_testkit::unique("confirm"))
        .execute(&db)
        .await
        .expect("seed user");
    grant_privilege(&db, owner, "system.admin").await;

    let entity = provision_test_entity(&state).await;
    let table = attome_core::quote_ident(&entity);
    let record_id: Uuid = sqlx::query_scalar(&format!(
        "INSERT INTO {table} (id, status, is_active, row_version) \
         VALUES ($1, 'open', true, 0) RETURNING id"
    ))
    .bind(Uuid::now_v7())
    .fetch_one(&db)
    .await
    .expect("insert the business record");

    let session = attome_ai::session::start(
        &db,
        &attome_audit::audit_service(&state),
        attome_ai::session::SessionStart {
            owner_user_id: owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Reversible,
            allowed_action_ids: None,
            surface: "internal",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start session");
    let conversation = conversation::create(
        &db,
        NewConversation {
            agent_session_id: session.id,
            owner_user_id: owner,
            agent_definition_ref: None,
            surface: Surface::Internal,
            title: None,
        },
    )
    .await
    .expect("conversation");

    Some(Fixture {
        state,
        owner,
        session,
        conversation_id: conversation.id,
        entity,
        record_id,
    })
}

impl Fixture {
    /// The write the model proposed: set this fixture's record to `closed`.
    fn write_args(&self) -> Value {
        json!({
            "entity": self.entity,
            "record_id": self.record_id,
            "field": "status",
            "value": "closed",
            "row_version": 0,
        })
    }

    async fn propose(&self, tool_call_id: &str, action_id: &str, arguments: Value) -> String {
        tool_call::propose(
            &self.state.base.db,
            tool_call::NewToolCall {
                conversation_id: self.conversation_id,
                message_id: None,
                turn_id: Uuid::now_v7(),
                tool_call_id: Some(tool_call_id.into()),
                action_id: action_id.into(),
                arguments,
                initiator_is_agent: true,
                gate_decision: None,
            },
        )
        .await
        .expect("propose")
        .arguments_hash
    }

    async fn propose_write(&self, tool_call_id: &str) -> String {
        self.propose(tool_call_id, "record.update_field", self.write_args())
            .await
    }

    async fn confirm(&self, tool_call_id: &str, hash: &str) -> ConfirmOutcome {
        self.confirm_as(self.owner, tool_call_id, hash)
            .await
            .expect("confirm_tool_call")
    }

    async fn confirm_as(
        &self,
        caller: Uuid,
        tool_call_id: &str,
        hash: &str,
    ) -> Result<ConfirmOutcome, attome_types::AppError> {
        confirm_tool_call(
            &self.state,
            &ActionRegistry::new(),
            &Executors::new(),
            ConfirmRequest {
                caller,
                conversation_id: self.conversation_id,
                tool_call_id,
                displayed_hash: hash,
            },
        )
        .await
    }

    /// `(status, claimed_at IS NULL, row_version)` of the proposal.
    async fn proposal(&self, tool_call_id: &str) -> (String, bool, i64) {
        sqlx::query_as(
            "SELECT status, claimed_at IS NULL, row_version FROM ai_tool_call \
              WHERE conversation_id = $1 AND tool_call_id = $2",
        )
        .bind(self.conversation_id)
        .bind(tool_call_id)
        .fetch_one(&self.state.base.db)
        .await
        .expect("read proposal")
    }

    async fn business_status(&self) -> String {
        let table = attome_core::quote_ident(&self.entity);
        sqlx::query_scalar(&format!("SELECT status FROM {table} WHERE id = $1"))
            .bind(self.record_id)
            .fetch_one(&self.state.base.db)
            .await
            .expect("read business status")
    }

    /// Invocation-ledger rows for `(this session, tool_call_id)`, by outcome.
    async fn invocations(&self, tool_call_id: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT outcome FROM action_invocation \
              WHERE agent_session_id = $1 AND tool_call_id = $2",
        )
        .bind(self.session.id)
        .bind(tool_call_id)
        .fetch_all(&self.state.base.db)
        .await
        .expect("read invocations")
    }

    /// Agent-attributed audit events for this session, in whichever sink the
    /// config selects (the same filter C3's A-04 test proved non-vacuous).
    async fn agent_audit_events(&self) -> i64 {
        let session = self.session.id.to_string();
        let header: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_header WHERE agent_session_id::text = $1",
        )
        .bind(&session)
        .fetch_one(&self.state.base.db)
        .await
        .expect("count audit headers");
        let ingest: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_ingest \
              WHERE payload::jsonb -> 'attribution' ->> 'agent_session_id' = $1",
        )
        .bind(&session)
        .fetch_one(&self.state.base.db)
        .await
        .expect("count audit ingest rows");
        header + ingest
    }

    /// Nothing ran for `tool_call_id`: the business row is still `open`, the
    /// ledger has no row for it, and no agent-action audit event exists.
    async fn assert_nothing_ran(&self, tool_call_id: &str) {
        assert_eq!(
            self.business_status().await,
            "open",
            "business row unchanged"
        );
        assert!(
            self.invocations(tool_call_id).await.is_empty(),
            "no execution claim was taken"
        );
        assert_eq!(
            self.agent_audit_events().await,
            0,
            "no agent-action audit event"
        );
    }
}

/// Polls `pg_stat_activity` until a backend in this database is waiting on a
/// lock while running a statement matching `needle`, and returns its pid.
/// Proves the ordering a race test depends on instead of sleeping and hoping.
async fn wait_until_blocked(db: &attome_db::DbPool, needle: &str) -> i32 {
    for _ in 0..200 {
        let pid: Option<i32> = sqlx::query_scalar(
            "SELECT pid FROM pg_stat_activity \
              WHERE datname = current_database() AND wait_event_type = 'Lock' \
                AND query ILIKE $1 AND pid <> pg_backend_pid() \
              LIMIT 1",
        )
        .bind(format!("%{needle}%"))
        .fetch_optional(db)
        .await
        .expect("read pg_stat_activity");
        if let Some(pid) = pid {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no backend ever blocked on a statement matching {needle:?}");
}

// ---------------------------------------------------------------------------
// The happy path, and the classification of a claim that did not take
// ---------------------------------------------------------------------------

/// A confirm runs the **stored** proposal, once, as the agent action: the
/// business row changes, the ledger records one completed claim under the
/// persisted `tool_call_id`, and the mandatory agent-attributed audit event
/// is written. The proposal lands on `executed` with its lease cleared.
#[tokio::test]
async fn a_confirm_runs_the_stored_proposal_once_as_the_agent_action() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("c1").await;

    let outcome = f.confirm("c1", &hash).await;

    let ConfirmOutcome::Executed { result } = outcome else {
        panic!("a valid confirm must execute: {outcome:?}");
    };
    assert_eq!(result["new_value"], json!("closed"));
    assert_eq!(f.business_status().await, "closed");
    assert_eq!(f.invocations("c1").await, vec!["completed".to_owned()]);
    assert!(
        f.agent_audit_events().await >= 1,
        "the agent-action audit event is written — the path ran as the agent, not as a user"
    );
    let (status, lease_cleared, _) = f.proposal("c1").await;
    assert_eq!(status, "executed");
    assert!(lease_cleared);
}

/// **Row A-09**, and the double-bump regression. The displayed hash is part
/// of the claim's own `WHERE`, so a stale confirm never enters `executing`
/// — not even inside its transaction — and changes nothing, `row_version`
/// included.
#[tokio::test]
async fn a_stale_hash_is_refused_and_changes_nothing_not_even_row_version() {
    let f = skip_if_no_db!(fixture().await);
    f.propose_write("stale").await;
    let (_, _, version_before) = f.proposal("stale").await;

    let outcome = f.confirm("stale", "not-the-displayed-hash").await;

    assert!(matches!(
        outcome,
        ConfirmOutcome::Refused(ConfirmRefusal::StaleHash)
    ));
    let (status, lease_cleared, version_after) = f.proposal("stale").await;
    assert_eq!(status, "proposed");
    assert!(lease_cleared);
    assert_eq!(
        version_after, version_before,
        "a stale confirm must not touch the row at all"
    );
    f.assert_nothing_ran("stale").await;
}

/// **Rows A-38 / A-65 at the engine.** Another user's conversation, and an
/// unknown tool call in one's own, are the same answer.
#[tokio::test]
async fn an_unknown_or_foreign_proposal_is_not_found() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("mine").await;

    let stranger = Uuid::now_v7();
    let foreign = f
        .confirm_as(stranger, "mine", &hash)
        .await
        .expect("confirm");
    assert!(matches!(
        foreign,
        ConfirmOutcome::Refused(ConfirmRefusal::NotFound)
    ));
    let unknown = f.confirm("no-such-call", &hash).await;
    assert!(matches!(
        unknown,
        ConfirmOutcome::Refused(ConfirmRefusal::NotFound)
    ));
    f.assert_nothing_ran("mine").await;
    assert_eq!(f.proposal("mine").await.0, "proposed");
}

/// A second confirm after the first completed is answered from the ledger:
/// `already_executed`, carrying the recorded result — never a second run and
/// never a generic replay.
#[tokio::test]
async fn a_confirm_after_completion_is_already_executed_with_the_recorded_result() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("twice").await;
    assert!(matches!(
        f.confirm("twice", &hash).await,
        ConfirmOutcome::Executed { .. }
    ));

    let again = f.confirm("twice", &hash).await;

    let ConfirmOutcome::Refused(ConfirmRefusal::AlreadyExecuted { result }) = again else {
        panic!("a completed proposal is already_executed: {again:?}");
    };
    assert_eq!(
        result.expect("the recorded result")["new_value"],
        json!("closed")
    );
    assert_eq!(
        f.invocations("twice").await,
        vec!["completed".to_owned()],
        "one execution claim — the second confirm did not run"
    );
}

/// A terminal proposal (here: expired by the TTL sweep) is refused with its
/// status, and stays terminal.
#[tokio::test]
async fn a_terminal_proposal_is_refused_with_its_status() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("old").await;
    tool_call::expire_stale_proposals(&f.state.base.db, Duration::ZERO)
        .await
        .expect("expire");

    let outcome = f.confirm("old", &hash).await;

    assert!(matches!(
        outcome,
        ConfirmOutcome::Refused(ConfirmRefusal::Terminal {
            status: Status::Expired
        })
    ));
    f.assert_nothing_ran("old").await;
}

// ---------------------------------------------------------------------------
// Row A-41 — refusals after the claim, each on its row of the table
// ---------------------------------------------------------------------------

/// **Row A-14.** An action that no longer resolves (a release removed it) is
/// `invalidated` in the check transaction, not executed.
#[tokio::test]
async fn a_proposal_whose_action_was_removed_is_invalidated() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f
        .propose("gone", "removed.by_a_release", f.write_args())
        .await;

    let outcome = f.confirm("gone", &hash).await;

    assert!(matches!(
        outcome,
        ConfirmOutcome::Refused(ConfirmRefusal::Invalidated { .. })
    ));
    let (status, lease_cleared, _) = f.proposal("gone").await;
    assert_eq!(status, "invalidated");
    assert!(lease_cleared, "never left executing");
    f.assert_nothing_ran("gone").await;
}

/// A revoked session (lockable state) is `invalidated` in T.
#[tokio::test]
async fn a_revoked_session_invalidates_the_proposal() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("rev").await;
    attome_ai::session::revoke(&f.state.base.db, f.session.id, f.owner, "test")
        .await
        .expect("revoke");

    let outcome = f.confirm("rev", &hash).await;

    assert!(matches!(
        outcome,
        ConfirmOutcome::Refused(ConfirmRefusal::Invalidated { .. })
    ));
    assert_eq!(f.proposal("rev").await.0, "invalidated");
    f.assert_nothing_ran("rev").await;
}

/// A deactivated account (lockable state) is `invalidated` in T.
#[tokio::test]
async fn a_deactivated_account_invalidates_the_proposal() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("inactive").await;
    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(f.owner)
        .execute(&f.state.base.db)
        .await
        .expect("deactivate");

    let outcome = f.confirm("inactive", &hash).await;

    assert!(matches!(
        outcome,
        ConfirmOutcome::Refused(ConfirmRefusal::Invalidated { .. })
    ));
    assert_eq!(f.proposal("inactive").await.0, "invalidated");
    f.assert_nothing_ran("inactive").await;
}

/// A licence that no longer carries the module is refused by `admissible` —
/// a point-in-time check — and the refusal is written in T.
#[tokio::test]
async fn a_removed_licence_invalidates_the_proposal() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("unlicensed").await;
    f.state
        .modules
        .store(Arc::new(ModuleSet::from_bits([0; 4])));

    let outcome = f.confirm("unlicensed", &hash).await;

    assert!(matches!(
        outcome,
        ConfirmOutcome::Refused(ConfirmRefusal::Invalidated { .. })
    ));
    assert_eq!(f.proposal("unlicensed").await.0, "invalidated");
    f.assert_nothing_ran("unlicensed").await;
}

/// A privilege withdrawn before the confirm. `record.update_field` declares
/// no gate-level privilege — it checks entity-write permission itself — so
/// the refusal comes from the executor, after admission. Nothing commits,
/// the claim is released, and because the arguments cannot change the
/// proposal is `invalidated`, not re-offered.
#[tokio::test]
async fn a_withdrawn_privilege_refuses_the_write_and_invalidates_the_proposal() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("priv").await;
    revoke_privilege(&f.state.base.db, f.owner, "system.admin").await;

    let outcome = f.confirm("priv", &hash).await;

    assert!(
        matches!(
            outcome,
            ConfirmOutcome::Refused(ConfirmRefusal::ActionFailed { invalidated: true })
        ),
        "{outcome:?}"
    );
    let (status, lease_cleared, _) = f.proposal("priv").await;
    assert_eq!(status, "invalidated");
    assert!(lease_cleared);
    f.assert_nothing_ran("priv").await;
}

/// **F4.** A paused session refuses the confirm and the proposal returns to
/// `proposed` — distinct from the approval path's deferral: nothing is
/// queued. After resume the **same** proposal confirms and runs exactly once.
#[tokio::test]
async fn a_confirm_while_the_session_is_paused_is_refused_and_stays_proposed() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("paused").await;
    attome_ai::session::pause(&f.state.base.db, f.session.id, f.owner, "test")
        .await
        .expect("pause");

    let outcome = f.confirm("paused", &hash).await;

    assert!(matches!(
        outcome,
        ConfirmOutcome::Refused(ConfirmRefusal::SessionPaused)
    ));
    let (status, lease_cleared, _) = f.proposal("paused").await;
    assert_eq!(status, "proposed");
    assert!(lease_cleared);
    f.assert_nothing_ran("paused").await;

    attome_ai::session::resume(&f.state.base.db, f.session.id)
        .await
        .expect("resume");
    assert!(matches!(
        f.confirm("paused", &hash).await,
        ConfirmOutcome::Executed { .. }
    ));
    assert_eq!(f.business_status().await, "closed");
    assert_eq!(f.invocations("paused").await, vec!["completed".to_owned()]);
}

// ---------------------------------------------------------------------------
// Row A-41 — the transaction ordering, proven by lock waits
// ---------------------------------------------------------------------------

/// **The check and its transition are atomic for lockable state.** A revoke
/// being committed concurrently holds the session row; the confirm's check
/// transaction blocks on its `FOR SHARE` read (observed in
/// `pg_stat_activity`, not assumed), sees the revoke once it commits, and
/// invalidates — nothing runs.
#[tokio::test]
async fn an_uncommitted_revoke_is_waited_for_and_then_observed() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("wait").await;
    let db = f.state.base.db.clone();

    let mut revoker = attome_db::tx::begin(&db).await.expect("begin revoker");
    sqlx::query(
        "UPDATE agent_session SET revoked_at = NOW(), revoked_by = $2, \
         revoked_reason = 'test' WHERE id = $1",
    )
    .bind(f.session.id)
    .bind(f.owner)
    .execute(&mut *revoker)
    .await
    .expect("revoke, uncommitted");

    let confirm = {
        let state = f.state.clone();
        let (conversation_id, owner, hash) = (f.conversation_id, f.owner, hash.clone());
        tokio::spawn(async move {
            confirm_tool_call(
                &state,
                &ActionRegistry::new(),
                &Executors::new(),
                ConfirmRequest {
                    caller: owner,
                    conversation_id,
                    tool_call_id: "wait",
                    displayed_hash: &hash,
                },
            )
            .await
        })
    };
    wait_until_blocked(&db, "FOR SHARE").await;
    revoker.commit().await.expect("commit the revoke");

    let outcome = confirm.await.expect("join").expect("confirm");
    assert!(matches!(
        outcome,
        ConfirmOutcome::Refused(ConfirmRefusal::Invalidated { .. })
    ));
    assert_eq!(f.proposal("wait").await.0, "invalidated");
    f.assert_nothing_ran("wait").await;
}

/// **A database error inside T** (a deadlock is one; here the confirm's
/// backend is cancelled while it waits on the account row). T rolls back,
/// the executor is never reached, the proposal is returned to `proposed` —
/// not stranded in `executing` — and a re-confirm runs it exactly once.
#[tokio::test]
async fn a_database_error_inside_the_check_transaction_executes_nothing_and_recovers() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("dberr").await;
    let db = f.state.base.db.clone();

    let mut holder = attome_db::tx::begin(&db).await.expect("begin holder");
    sqlx::query("SELECT id FROM user_account WHERE id = $1 FOR UPDATE")
        .bind(f.owner)
        .execute(&mut *holder)
        .await
        .expect("hold the account row");

    let confirm = {
        let state = f.state.clone();
        let (conversation_id, owner, hash) = (f.conversation_id, f.owner, hash.clone());
        tokio::spawn(async move {
            confirm_tool_call(
                &state,
                &ActionRegistry::new(),
                &Executors::new(),
                ConfirmRequest {
                    caller: owner,
                    conversation_id,
                    tool_call_id: "dberr",
                    displayed_hash: &hash,
                },
            )
            .await
        })
    };
    let pid = wait_until_blocked(&db, "user_account").await;
    let _: bool = sqlx::query_scalar("SELECT pg_cancel_backend($1)")
        .bind(pid)
        .fetch_one(&db)
        .await
        .expect("cancel the blocked backend");

    let result = confirm.await.expect("join");
    assert!(
        result.is_err(),
        "a database error is an Err, answered as retryable"
    );
    holder.rollback().await.expect("release the account row");

    let (status, lease_cleared, _) = f.proposal("dberr").await;
    assert_eq!(status, "proposed", "returned, never stranded in executing");
    assert!(lease_cleared);
    f.assert_nothing_ran("dberr").await;

    assert!(matches!(
        f.confirm("dberr", &hash).await,
        ConfirmOutcome::Executed { .. }
    ));
    assert_eq!(f.business_status().await, "closed");
    assert_eq!(f.invocations("dberr").await, vec!["completed".to_owned()]);
}

/// **The point-in-time window, after admission.** The executor is admitted
/// and then blocks on the business row, which this test holds. While it is
/// blocked — after T committed — the session is revoked, the privilege is
/// withdrawn and the licence drops the module. The admitted execution still
/// completes exactly once; the changes apply to the next admission: a second
/// confirm of the same proposal is `already_executed`, and a new proposal is
/// refused.
#[tokio::test]
async fn changes_after_admission_do_not_cancel_the_admitted_execution() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("window").await;
    let db = f.state.base.db.clone();
    let table = attome_core::quote_ident(&f.entity);

    let mut holder = attome_db::tx::begin(&db).await.expect("begin holder");
    sqlx::query(&format!("SELECT id FROM {table} WHERE id = $1 FOR UPDATE"))
        .bind(f.record_id)
        .execute(&mut *holder)
        .await
        .expect("hold the business row");

    let confirm = {
        let state = f.state.clone();
        let (conversation_id, owner, hash) = (f.conversation_id, f.owner, hash.clone());
        tokio::spawn(async move {
            confirm_tool_call(
                &state,
                &ActionRegistry::new(),
                &Executors::new(),
                ConfirmRequest {
                    caller: owner,
                    conversation_id,
                    tool_call_id: "window",
                    displayed_hash: &hash,
                },
            )
            .await
        })
    };
    wait_until_blocked(&db, &f.entity).await;

    // After admission: every kind of change the contract names.
    attome_ai::session::revoke(&db, f.session.id, f.owner, "test")
        .await
        .expect("revoke");
    revoke_privilege(&db, f.owner, "system.admin").await;
    f.state
        .modules
        .store(Arc::new(ModuleSet::from_bits([0; 4])));
    holder.rollback().await.expect("release the business row");

    let outcome = confirm.await.expect("join").expect("confirm");
    assert!(
        matches!(outcome, ConfirmOutcome::Executed { .. }),
        "an admitted execution proceeds: {outcome:?}"
    );
    assert_eq!(f.business_status().await, "closed");
    assert_eq!(f.invocations("window").await, vec!["completed".to_owned()]);
    assert_eq!(f.proposal("window").await.0, "executed");

    // The changes apply to what comes next.
    f.state.modules.store(full_licence());
    assert!(matches!(
        f.confirm("window", &hash).await,
        ConfirmOutcome::Refused(ConfirmRefusal::AlreadyExecuted { .. })
    ));
    let next = f.propose_write("next").await;
    assert!(matches!(
        f.confirm("next", &next).await,
        ConfirmOutcome::Refused(ConfirmRefusal::Invalidated { .. })
    ));
    assert_eq!(
        f.invocations("window").await.len() + f.invocations("next").await.len(),
        1,
        "exactly one execution in total"
    );
}

// ---------------------------------------------------------------------------
// Recovery: an aged lease over a completed execution
// ---------------------------------------------------------------------------

/// The process died after the side effect committed and was recorded, but
/// before the proposal's own status was written: the row is left `executing`
/// with an aged lease, and the ledger says `completed`. A confirm reclaims the
/// lease with the sweep's own predicate, meets the completed D-502 claim and
/// answers `already_executed` — the executor runs **zero** times (the
/// business row is untouched by it, and the recorded result is the
/// sentinel no real execution produces).
#[tokio::test]
async fn an_aged_lease_over_a_completed_execution_replays_and_never_runs_again() {
    const SENTINEL: &str = "recorded-by-the-crashed-confirm";
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("crashed").await;
    let db = f.state.base.db.clone();

    sqlx::query(
        "UPDATE ai_tool_call SET status = 'executing', claimed_at = NOW() - INTERVAL '1 hour', \
         row_version = row_version + 1 WHERE conversation_id = $1 AND tool_call_id = 'crashed'",
    )
    .bind(f.conversation_id)
    .execute(&db)
    .await
    .expect("strand the proposal");
    let key = attome_ai::session::InvocationKey {
        session_id: f.session.id,
        tool_call_id: "crashed",
        action_id: attome_ai::descriptor::ActionId("record.update_field"),
        acting_user_id: f.owner,
    };
    let attome_ai::session::Claim::Acquired(id) = attome_ai::session::claim_invocation(&db, key)
        .await
        .expect("claim")
    else {
        panic!("fixture must acquire");
    };
    assert!(
        attome_ai::session::complete_invocation(
            &db,
            id,
            attome_ai::session::OUTCOME_COMPLETED,
            Some(&json!({ "sentinel": SENTINEL })),
        )
        .await
        .expect("complete")
    );

    let outcome = f.confirm("crashed", &hash).await;

    let ConfirmOutcome::Refused(ConfirmRefusal::AlreadyExecuted { result }) = outcome else {
        panic!("a completed execution is replayed as already_executed: {outcome:?}");
    };
    assert_eq!(result.expect("recorded")["sentinel"], json!(SENTINEL));
    assert_eq!(
        f.business_status().await,
        "open",
        "the executor did not run during recovery"
    );
    assert_eq!(f.invocations("crashed").await, vec!["completed".to_owned()]);
    let (status, lease_cleared, _) = f.proposal("crashed").await;
    assert_eq!(status, "executed", "never left executing");
    assert!(lease_cleared);
}

// ---------------------------------------------------------------------------
// Rows A-13 and A-42 — the races, through the real confirm path
// ---------------------------------------------------------------------------

impl Fixture {
    /// The business record's `row_version`: every update bumps it, so it
    /// counts **business mutations** — the assertion A-13 and A-42 ask for,
    /// rather than a status code.
    async fn business_row_version(&self) -> i64 {
        let table = attome_core::quote_ident(&self.entity);
        sqlx::query_scalar(&format!("SELECT row_version FROM {table} WHERE id = $1"))
            .bind(self.record_id)
            .fetch_one(&self.state.base.db)
            .await
            .expect("read business row_version")
    }

    fn spawn_confirm(
        &self,
        tool_call_id: &'static str,
        hash: &str,
    ) -> tokio::task::JoinHandle<Result<ConfirmOutcome, attome_types::AppError>> {
        let state = self.state.clone();
        let (conversation_id, owner, hash) = (self.conversation_id, self.owner, hash.to_owned());
        tokio::spawn(async move {
            confirm_tool_call(
                &state,
                &ActionRegistry::new(),
                &Executors::new(),
                ConfirmRequest {
                    caller: owner,
                    conversation_id,
                    tool_call_id,
                    displayed_hash: &hash,
                },
            )
            .await
        })
    }

    /// Holds the business row `FOR UPDATE` in a transaction the caller
    /// releases, so an admitted executor blocks on it at a known point.
    async fn hold_business_row(&self) -> attome_db::Tx<'_> {
        let table = attome_core::quote_ident(&self.entity);
        let mut holder = attome_db::tx::begin(&self.state.base.db)
            .await
            .expect("begin holder");
        sqlx::query(&format!("SELECT id FROM {table} WHERE id = $1 FOR UPDATE"))
            .bind(self.record_id)
            .execute(&mut *holder)
            .await
            .expect("hold the business row");
        holder
    }
}

/// **Row A-13 — two concurrent confirmations of one proposal, staged.** A is
/// admitted and held inside its executor; B arrives while A owns the claim.
/// B is refused `in_progress` (the persisted state, not a failed update),
/// runs nothing, and A completes: **exactly one business mutation**.
#[tokio::test]
async fn two_concurrent_confirms_produce_exactly_one_mutation() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("dbl").await;
    let db = f.state.base.db.clone();
    assert_eq!(f.business_row_version().await, 0);

    let holder = f.hold_business_row().await;
    let a = f.spawn_confirm("dbl", &hash);
    wait_until_blocked(&db, &f.entity).await;

    let b = f.confirm("dbl", &hash).await;
    assert!(
        matches!(b, ConfirmOutcome::Refused(ConfirmRefusal::InProgress)),
        "the second confirm is refused while the first owns the claim: {b:?}"
    );

    holder.rollback().await.expect("release the business row");
    let a = a.await.expect("join").expect("confirm A");
    assert!(matches!(a, ConfirmOutcome::Executed { .. }), "{a:?}");

    assert_eq!(
        f.business_row_version().await,
        1,
        "exactly one business mutation"
    );
    assert_eq!(f.invocations("dbl").await, vec!["completed".to_owned()]);
    assert_eq!(f.proposal("dbl").await.0, "executed");
}

/// **Row A-13, unstaged.** Four confirms of one proposal released at once:
/// exactly one executes; every other one is refused from the persisted state
/// (`in_progress` while the winner runs, `already_executed` after it
/// finished) — and the business row changes exactly once.
#[tokio::test]
async fn racing_confirms_execute_once_and_refuse_the_rest_by_state() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("race").await;

    let handles: Vec<_> = (0..4).map(|_| f.spawn_confirm("race", &hash)).collect();
    let mut executed = 0;
    for handle in handles {
        match handle.await.expect("join").expect("confirm") {
            ConfirmOutcome::Executed { .. } => executed += 1,
            ConfirmOutcome::Refused(
                ConfirmRefusal::InProgress | ConfirmRefusal::AlreadyExecuted { .. },
            ) => {}
            other => panic!("a losing confirm must be refused by state: {other:?}"),
        }
    }
    assert_eq!(executed, 1, "exactly one confirm executes");
    assert_eq!(
        f.business_row_version().await,
        1,
        "exactly one business mutation"
    );
    assert_eq!(f.invocations("race").await, vec!["completed".to_owned()]);
}

/// **Row A-42 — the full lease race, staged, through `confirm_tool_call`.**
///
/// 1. Confirm A claims `proposed → executing` and begins dispatch.
/// 2. A takes the D-502 claim on `(session, tool_call_id)` — and is held
///    inside its executor.
/// 3. A's lease expires while A is still running.
/// 4. The sweep reclaims the row to `proposed`.
/// 5. Confirm B claims it and dispatches: its `claim_invocation` meets A's
///    claim, so B does **not** perform the side effect — `in_progress`.
///
/// Then A finishes. Its status write-back is conditional on A's own
/// `row_version` and affects **zero rows**: the row is not clobbered to
/// `executed` over the reclaimed state. **Exactly one business mutation**,
/// by row count. A later confirm settles the row from the ledger.
#[tokio::test]
async fn the_lease_race_through_the_confirm_path_mutates_exactly_once() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("lease").await;
    let db = f.state.base.db.clone();

    // 1–2. A is admitted, takes its execution claim, and is held.
    let holder = f.hold_business_row().await;
    let a = f.spawn_confirm("lease", &hash);
    wait_until_blocked(&db, &f.entity).await;
    assert_eq!(f.invocations("lease").await, vec!["claimed".to_owned()]);
    assert_eq!(f.proposal("lease").await.0, "executing");

    // 3. The lease expires under A.
    sqlx::query(
        "UPDATE ai_tool_call SET claimed_at = NOW() - INTERVAL '1 hour' \
          WHERE conversation_id = $1 AND tool_call_id = 'lease'",
    )
    .bind(f.conversation_id)
    .execute(&db)
    .await
    .expect("age the lease");

    // 4. The sweep reclaims it. Deployment-wide, so asserted on this row, not
    //    on the count: a template's aged leftovers are reclaimed too.
    tool_call::reclaim_expired_leases(&db, tool_call::CONFIRM_LEASE)
        .await
        .expect("sweep");
    assert_eq!(f.proposal("lease").await.0, "proposed");

    // 5. B claims and dispatches — and meets A's execution claim.
    let b = f.confirm("lease", &hash).await;
    assert!(
        matches!(b, ConfirmOutcome::Refused(ConfirmRefusal::InProgress)),
        "B must not perform the side effect: {b:?}"
    );
    assert_eq!(f.business_row_version().await, 0, "B ran nothing");
    let (after_b, _, version_after_b) = f.proposal("lease").await;
    assert_eq!(after_b, "proposed");

    // A finishes: its own mutation happened, its write-back lands on nothing.
    holder.rollback().await.expect("release the business row");
    let a = a.await.expect("join").expect("confirm A");
    assert!(matches!(a, ConfirmOutcome::Executed { .. }), "{a:?}");
    let (after_a, _, version_after_a) = f.proposal("lease").await;
    assert_eq!(
        (after_a.as_str(), version_after_a),
        ("proposed", version_after_b),
        "A's write-back affected zero rows and did not clobber the reclaimed state"
    );

    assert_eq!(
        f.business_row_version().await,
        1,
        "exactly one business mutation"
    );
    assert_eq!(f.invocations("lease").await, vec!["completed".to_owned()]);

    // The next confirm settles the row from the ledger — without running.
    let c = f.confirm("lease", &hash).await;
    assert!(
        matches!(
            c,
            ConfirmOutcome::Refused(ConfirmRefusal::AlreadyExecuted { .. })
        ),
        "{c:?}"
    );
    assert_eq!(f.proposal("lease").await.0, "executed");
    assert_eq!(f.business_row_version().await, 1, "still exactly one");
}

// ---------------------------------------------------------------------------
// Row A-40 — the sweep
// ---------------------------------------------------------------------------

/// **Row A-40.** A confirm's process dies after the `proposed → executing`
/// claim and before dispatch: the row is `executing`, its lease ages out, and
/// no execution claim exists. `tool_call::sweep` — what the periodic
/// `AiToolCallSweep` job runs — returns it to `proposed`, so it is **never
/// stranded**, and a re-confirm runs it exactly once.
#[tokio::test]
async fn a_confirm_that_died_after_its_claim_is_swept_back_and_runs_once() {
    let f = skip_if_no_db!(fixture().await);
    let hash = f.propose_write("died").await;
    let db = f.state.base.db.clone();

    // The dead confirm got as far as its claim.
    let claim = tool_call::claim(&db, f.conversation_id, "died", &hash)
        .await
        .expect("claim");
    assert!(matches!(claim, tool_call::Claim::Claimed(_)));
    assert_eq!(f.proposal("died").await.0, "executing");

    // Until the lease expires the sweep leaves it alone ...
    // (The sweep is deployment-wide; its counts include other rows, so the
    // property is asserted on this proposal alone.)
    tool_call::sweep(&db).await.expect("sweep");
    assert_eq!(
        f.proposal("died").await.0,
        "executing",
        "a live lease is not reclaimed"
    );

    // ... and once it has, the sweep returns it to `proposed`.
    sqlx::query(
        "UPDATE ai_tool_call SET claimed_at = NOW() - INTERVAL '1 hour' \
          WHERE conversation_id = $1 AND tool_call_id = 'died'",
    )
    .bind(f.conversation_id)
    .execute(&db)
    .await
    .expect("age the lease");
    let (reclaimed, _) = tool_call::sweep(&db).await.expect("sweep");
    assert!(reclaimed >= 1, "the sweep reclaimed at least this proposal");
    let (status, lease_cleared, _) = f.proposal("died").await;
    assert_eq!(status, "proposed", "never stranded in executing");
    assert!(lease_cleared);
    f.assert_nothing_ran("died").await;

    assert!(matches!(
        f.confirm("died", &hash).await,
        ConfirmOutcome::Executed { .. }
    ));
    assert_eq!(
        f.business_row_version().await,
        1,
        "exactly one business mutation"
    );
    assert_eq!(f.invocations("died").await, vec!["completed".to_owned()]);
}

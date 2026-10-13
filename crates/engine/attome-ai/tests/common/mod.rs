//! The C5 action-suite harness, shared by `record_write.rs` and
//! `c5_read_actions.rs` and `workflow_start.rs`: a throwaway XRM state,
//! a provisioned writable entity, an agent session at the `Consequential`
//! ceiling, and the dispatch / propose / confirm helpers that drive the real
//! gate. Not every target uses every helper.

#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(dead_code)]
use std::sync::Arc;

use attome_ai::confirm::{ConfirmOutcome, ConfirmRequest, confirm_tool_call};
use attome_ai::context::ActionContext;
use attome_ai::conversation::{self, NewConversation, Surface};
use attome_ai::execute::{ActionOutcome, Executors, dispatch};
use attome_ai::gate::GateInputs;
use attome_ai::registry::ActionRegistry;
use attome_ai::session::AgentSession;
use attome_ai::tool_call;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_modules::ModuleSet;
use attome_server::AppState;
use serde_json::Value;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Harness (the same shape as tests/confirm.rs)
// ---------------------------------------------------------------------------

pub fn test_config(direct_url: &str) -> AppConfig {
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
    );
    attome_testkit::with_test_database(serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"), true)
}

pub static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn seed_platform(db: &attome_db::DbPool) {
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

pub async fn test_state() -> Option<EngineState> {
    test_state_with(|_| {}).await
}

/// [`test_state`] with the configuration adjusted before the state is built
/// — for a suite that points inference at its own endpoint (C10-C's
/// conversation evaluation). `config` is immutable once the state exists.
pub async fn test_state_with(configure: impl FnOnce(&mut AppConfig)) -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK, same posture as the sibling suites.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let mut config = test_config(&db_url);
    configure(&mut config);
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
    state
        .modules
        .store(Arc::new(ModuleSet::from_bits([u64::MAX; 4])));
    Some(state)
}

pub async fn seed_user(db: &attome_db::DbPool, admin: bool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(id)
        .bind(attome_testkit::unique("record-write"))
        .execute(db)
        .await
        .expect("seed user");
    if admin {
        sqlx::query(
            "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
             VALUES ($1, 'system.admin', 'system.admin', 'test', true, NOW(), 'project') \
             ON CONFLICT (key) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .execute(db)
        .await
        .expect("ensure system.admin");
        sqlx::query(
            "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
             SELECT $1, $2, id, true, NOW() FROM privilege WHERE key = 'system.admin'",
        )
        .bind(Uuid::now_v7())
        .bind(id)
        .execute(db)
        .await
        .expect("grant system.admin");
    }
    id
}

/// A throwaway entity with a plain `status` field and a `special_note` field
/// marked `sensitive_special_category` (a throwaway-database write, one of
/// guidelines §4's exemptions — `ensure_attribute` has no classification
/// parameter). Unique per call.
pub async fn provision_entity(state: &EngineState, append_only: bool) -> String {
    let logicalname = format!("rw_test_{}", Uuid::now_v7().simple());
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "Record Write Test",
        None,
        append_only,
    )
    .await
    .expect("provision entity");
    for (name, display) in [("status", "Status"), ("special_note", "Special Note")] {
        attome_metadata::provision::ensure_attribute(
            &state.base.db,
            entity_id,
            name,
            display,
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
    sqlx::query(
        "UPDATE attribute_info SET data_classification = 'sensitive_special_category' \
          WHERE entity_ref = $1 AND logicalname = 'special_note'",
    )
    .bind(entity_id)
    .execute(&state.base.db)
    .await
    .expect("classify special_note");
    state.entities.swap(
        attome_core::build_registry(&state.base.db)
            .await
            .expect("rebuild entity registry"),
    );
    logicalname
}

pub struct Fixture {
    pub state: EngineState,
    pub owner: Uuid,
    pub session: AgentSession,
    pub conversation_id: Uuid,
    pub entity: String,
}

pub async fn fixture_with(append_only: bool) -> Option<Fixture> {
    let state = test_state().await?;
    let db = state.base.db.clone();
    let owner = seed_user(&db, true).await;
    let entity = provision_entity(&state, append_only).await;
    let session = attome_ai::session::start(
        &db,
        &attome_audit::audit_service(&state),
        attome_ai::session::SessionStart {
            owner_user_id: owner,
            // Consequential, so delete is visible and reaches the approval arm
            // rather than being refused at the ceiling.
            risk_ceiling: attome_ai::descriptor::RiskTier::Consequential,
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
    })
}

pub async fn fixture() -> Option<Fixture> {
    fixture_with(false).await
}

impl Fixture {
    pub fn db(&self) -> &attome_db::DbPool {
        &self.state.base.db
    }

    pub fn gate(&self) -> GateInputs<'_> {
        GateInputs {
            licensed: true,
            ai: &self.state.base.config.inference.ai,
            surface: Some(attome_config::AiSurface::Chat),
            external_effects_enabled: false,
        }
    }

    /// The session's own agent context — untainted — keyed as chat keys it.
    pub async fn agent_ctx(&self, key: &str) -> ActionContext {
        let security = Arc::new(
            attome_security::resolve_uncached(self.db(), self.owner)
                .await
                .expect("security"),
        );
        let mut ctx = attome_ai::turn::context_for(security, &self.session);
        ctx.idempotency_key = Some(key.to_owned());
        ctx
    }

    pub async fn user_ctx(&self, user: Uuid) -> ActionContext {
        let security = Arc::new(
            attome_security::resolve_uncached(self.db(), user)
                .await
                .expect("security"),
        );
        ActionContext::user(security)
    }

    pub async fn dispatch(
        &self,
        ctx: &ActionContext,
        action: &str,
        args: Value,
    ) -> Result<ActionOutcome, attome_types::AppError> {
        dispatch(
            &self.state,
            &ActionRegistry::new(),
            &Executors::new(),
            action,
            ctx,
            &self.gate(),
            &args,
        )
        .await
    }

    pub async fn propose(&self, tid: &str, action: &str, args: Value) -> String {
        tool_call::propose(
            self.db(),
            tool_call::NewToolCall {
                conversation_id: self.conversation_id,
                message_id: None,
                turn_id: Uuid::now_v7(),
                tool_call_id: Some(tid.into()),
                action_id: action.into(),
                arguments: args,
                initiator_is_agent: true,
                gate_decision: None,
            },
        )
        .await
        .expect("propose")
        .arguments_hash
    }

    pub async fn confirm(&self, tid: &str, hash: &str) -> ConfirmOutcome {
        confirm_tool_call(
            &self.state,
            &ActionRegistry::new(),
            &Executors::new(),
            ConfirmRequest {
                caller: self.owner,
                conversation_id: self.conversation_id,
                tool_call_id: tid,
                displayed_hash: hash,
            },
        )
        .await
        .expect("confirm")
    }

    pub async fn insert_record(&self, status: &str) -> Uuid {
        let table = attome_core::quote_ident(&self.entity);
        sqlx::query_scalar(&format!(
            "INSERT INTO {table} (id, status, is_active, row_version) \
             VALUES ($1, $2, true, 0) RETURNING id"
        ))
        .bind(Uuid::now_v7())
        .bind(status)
        .fetch_one(self.db())
        .await
        .expect("insert record")
    }

    /// `(status, is_active, row_version)` of one record.
    pub async fn record(&self, id: Uuid) -> (Option<String>, bool, i64) {
        let table = attome_core::quote_ident(&self.entity);
        sqlx::query_as(&format!(
            "SELECT status, COALESCE(is_active, true), row_version FROM {table} WHERE id = $1"
        ))
        .bind(id)
        .fetch_one(self.db())
        .await
        .expect("read record")
    }

    pub async fn row_count(&self) -> i64 {
        let table = attome_core::quote_ident(&self.entity);
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(self.db())
            .await
            .expect("count")
    }
}

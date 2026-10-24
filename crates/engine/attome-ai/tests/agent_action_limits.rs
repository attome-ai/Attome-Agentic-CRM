//! AH4-T5 — the agent action limits, end to end against a live database:
//! a daily per-class limit stops the next step of its class, counts across
//! every session of one agent, still binds a request a person approved
//! (the approved path reserves through the same check), and an agent's
//! discount above its cap is refused.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis, as
//! `agent_session_governance.rs`.
//!
//! ```powershell
//! cargo test -p attome-ai --test agent_action_limits -- --test-threads=1
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

use std::sync::Arc;

use attome_ai::context::ActionContext;
use attome_ai::descriptor::{ActionId, RiskTier};
use attome_ai::registry::ActionRegistry;
use attome_ai::session::{self, AgentSession, SessionStart, WriteReservation};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_modules::ModuleSet;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

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
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
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
    state
        .modules
        .store(Arc::new(ModuleSet::from_bits([u64::MAX; 4])));
    seed_agent_entities(&state).await;
    Some(state)
}

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
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("agent-session-governance-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

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

/// A session of `agent` (an agent object) with its daily limits `daily`.
async fn agent_session(db: &DbPool, owner: Uuid, agent: Uuid, daily: Value) -> AgentSession {
    let session = raw_session(db, owner, RiskTier::Consequential).await;
    session::attach_agent_object(db, session.id, agent, Some(daily))
        .await
        .expect("attach the agent object");
    session
}

/// Reserves one step of `action` for `session`, as dispatch does before an
/// agent's write runs (`tool_call` `None` is the approved path's call).
async fn reserve(
    db: &DbPool,
    session: &AgentSession,
    action: &'static str,
    tool_call: Option<&str>,
    owner: Uuid,
) -> WriteReservation {
    session::reserve_session_write(db, session.id, tool_call, ActionId(action), owner)
        .await
        .expect("reserve a step")
}

fn reached(reservation: &WriteReservation) -> bool {
    matches!(reservation, WriteReservation::LimitReached)
}

#[tokio::test]
async fn delete_limit_stops_next_delete() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let owner = seed_user(db).await;
    let agent = Uuid::now_v7();
    let session = agent_session(db, owner, agent, json!({ "deletes": 1 })).await;

    let first = reserve(db, &session, "record.delete", Some("call-1"), owner).await;
    assert!(
        matches!(first, WriteReservation::Reserved(_)),
        "the first delete goes through"
    );
    let second = reserve(db, &session, "record.delete", Some("call-2"), owner).await;
    assert!(
        reached(&second),
        "the second delete is over the agent's daily limit"
    );
    let update = reserve(db, &session, "record.update", Some("call-3"), owner).await;
    assert!(
        !reached(&update),
        "a record change counts against its own class, not the delete limit"
    );
}

#[tokio::test]
async fn limit_counts_across_sessions_of_one_agent() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let owner = seed_user(db).await;
    let agent = Uuid::now_v7();
    let daily = json!({ "record_changes": 2 });
    let morning = agent_session(db, owner, agent, daily.clone()).await;
    let afternoon = agent_session(db, owner, agent, daily.clone()).await;

    assert!(!reached(
        &reserve(db, &morning, "record.update", Some("m-1"), owner).await
    ));
    assert!(!reached(
        &reserve(db, &afternoon, "record.update", Some("a-1"), owner).await
    ));
    assert!(
        reached(&reserve(db, &afternoon, "record.update", Some("a-2"), owner).await),
        "the agent's two record changes are used across both sessions"
    );
    let other_agent = agent_session(db, owner, Uuid::now_v7(), daily).await;
    assert!(
        !reached(&reserve(db, &other_agent, "record.update", Some("o-1"), owner).await),
        "another agent has its own count"
    );
}

#[tokio::test]
async fn approved_request_still_respects_limit() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let owner = seed_user(db).await;
    let agent = Uuid::now_v7();
    let session = agent_session(db, owner, agent, json!({ "deletes": 1 })).await;

    assert!(!reached(
        &reserve(db, &session, "record.delete", Some("call-1"), owner).await
    ));
    // `dispatch_approved_agent_action` reserves with no tool call id; a
    // person's approval does not lift the agent's limit.
    assert!(
        reached(&reserve(db, &session, "record.delete", None, owner).await),
        "an approved delete over the limit waits; the owner raises the limit or does the step"
    );
}

#[tokio::test]
async fn discount_above_limit_is_refused() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    let owner = seed_user(db).await;

    let agent = Uuid::now_v7();
    let registry = attome_metadata::model_edit::registry();
    let kind = attome_model::kinds::AgentKind;
    let doc = json!({
        "role": "Quote helper",
        "instructions": "Prepare quotes.",
        "tools": [],
        "limits": { "max_steps": 5, "max_tool_calls": 5, "max_tokens": 1000, "max_discount_percent": 10 }
    });
    let mut tx = attome_db::tx::begin(db).await.unwrap();
    attome_model::store::save_draft(
        &mut tx,
        registry,
        &kind,
        &attome_model::store::ObjectSpec {
            id: attome_model::ObjectId(agent),
            name: format!("limits-agent-{}", agent.simple()),
            app: "customer".into(),
            layer: attome_model::Layer::Customer,
        },
        &doc,
        Some(owner),
    )
    .await
    .expect("save the agent draft");
    attome_model::publish::publish(
        &mut tx,
        registry,
        &attome_model::validate::CrossChecks::default(),
        &kind,
        agent,
    )
    .await
    .expect("publish the agent");
    attome_db::tx::commit(tx).await.unwrap();

    let session = agent_session(db, owner, agent, json!({})).await;
    let security = Arc::new(
        attome_security::resolve_uncached(db, owner)
            .await
            .expect("resolve the owner"),
    );
    let ctx = ActionContext::for_session(security, &session);
    let refused = attome_ai::discount_rule::check(&state, &ctx, &json!({ "discount_percent": 25 }))
        .await
        .expect_err("a 25% discount is above the agent's 10% cap");
    assert!(
        matches!(&refused, AppError::Validation(m) if m.starts_with("discount_above_agent_limit"))
    );
    attome_ai::discount_rule::check(&state, &ctx, &json!({ "discount_percent": "8" }))
        .await
        .expect("a discount within the cap goes through");
}

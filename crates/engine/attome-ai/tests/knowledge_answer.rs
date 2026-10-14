//! `knowledge.answer` end to end: a real database, Redis and the shared
//! `dispatch`, with a stand-in model server on loopback that speaks the
//! OpenAI-compatible chat-completions API. Nothing leaves this machine.
//!
//! The stand-in returns one scripted reply and records every request, which
//! is what lets these tests assert the properties that matter most: that the
//! code, not the model, decides whether an answer is grounded, and that a
//! question with no readable evidence never reaches a model at all.
//!
//! Knowledge Base seeding reuses `attome-search`'s shared harness, so the corpus
//! is provisioned exactly the way the retrieval suites provision it.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:TEST_REDIS_HOST = "127.0.0.1"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-ai --test knowledge_answer -- --test-threads=1
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
use std::sync::{Arc, Mutex};

use attome_ai::actions::knowledge::SEARCH_KNOWLEDGE;
use attome_ai::actions::knowledge_answer::KNOWLEDGE_ANSWER;
use attome_ai::context::ActionContext;
use attome_ai::execute::{ActionOutcome, Executors, Provenance, dispatch};
use attome_ai::gate::GateInputs;
use attome_ai::registry::ActionRegistry;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use serde_json::{Value, json};
use uuid::Uuid;

#[path = "../../attome-search/tests/knowledge_harness/mod.rs"]
mod knowledge_harness;
use knowledge_harness::{delete_article, insert_article, insert_source, provision_kb};

const APPROVED_MODEL: &str = "stand-in-approved";
const UNAPPROVED_MODEL: &str = "stand-in-unapproved";

// ── The stand-in model server ──────────────────────────────────────────────

struct StandIn {
    base_url: String,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl StandIn {
    fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("stand-in lock").clone()
    }
}

/// Starts a loopback server that answers every chat completion with `reply`.
async fn stand_in(reply: &str) -> StandIn {
    let requests: Arc<Mutex<Vec<Value>>> = Arc::default();
    let seen = Arc::clone(&requests);
    let reply = reply.to_owned();
    // `base_url` below ends in `/v1`; the client appends attome-inference's path.
    let app = axum::Router::new().route(
        &format!("/v1{}", attome_inference::CHAT_COMPLETIONS_PATH),
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let seen = Arc::clone(&seen);
            let reply = reply.clone();
            async move {
                seen.lock().expect("stand-in lock").push(body);
                axum::Json(json!({
                    "choices": [{ "message": { "content": reply }, "finish_reason": "stop" }],
                    "usage": { "prompt_tokens": 40, "completion_tokens": 12 }
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stand-in model server");
    let port = listener.local_addr().expect("stand-in address").port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("stand-in server");
    });
    StandIn {
        base_url: format!("http://127.0.0.1:{port}/v1"),
        requests,
    }
}

// ── State ──────────────────────────────────────────────────────────────────

/// `record_update_field.rs`'s configuration, with generation pointed at the
/// stand-in. `allow_external_provider` stays at its default `false`: loopback
/// is allowed, anything else would be refused.
fn test_config(direct_url: &str, base_url: &str, model: &str) -> AppConfig {
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
    let mut config: AppConfig = attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    );
    config.inference.generation.base_url = base_url.to_owned();
    config.inference.generation.model = model.to_owned();
    config.inference.generation.request_timeout_secs = 10;
    config
}

// SAFETY: see `record_update_field.rs`'s identical `ENV_LOCK`.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_state(base_url: &str, model: &str) -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let config = test_config(&db_url, base_url, model);
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
    seed_once(&db).await;
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

/// The Knowledge Base entities, and the two `ai_model` columns the model
/// approval check reads — the same narrow provisioning `ai_governance.rs` uses.
/// One approved row for [`APPROVED_MODEL`]; [`UNAPPROVED_MODEL`] gets none.
async fn seed_once(db: &attome_db::DbPool) {
    static SEEDED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
    SEEDED
        .get_or_init(|| async {
            provision_kb(db).await;
            let entity = attome_metadata::provision::ensure_entity(
                db,
                "ai_model",
                "AI Model",
                Some("name"),
                false,
            )
            .await
            .expect("ensure_entity ai_model");
            attome_metadata::provision::ensure_attribute(
                db, entity, "name", "Name", "text", true, false, true, true, None, None,
            )
            .await
            .expect("ensure_attribute name");
            attome_metadata::provision::ensure_attribute(
                db,
                entity,
                "provider_model_id",
                "Provider Model ID",
                "text",
                true,
                false,
                true,
                true,
                None,
                None,
            )
            .await
            .expect("ensure_attribute provider_model_id");
            attome_metadata::provision::ensure_attribute(
                db,
                entity,
                "approval_status",
                "Approval Status",
                "choice",
                true,
                false,
                true,
                true,
                None,
                Some(json!({ "choices": ["pending", "approved", "blocked"], "multi": false })),
            )
            .await
            .expect("ensure_attribute approval_status");
            sqlx::query(
                "INSERT INTO ai_model (id, name, provider_model_id, approval_status, created_at) \
                 VALUES ($1, $2, $2, 'approved', NOW())",
            )
            .bind(Uuid::now_v7())
            .bind(APPROVED_MODEL)
            .execute(db)
            .await
            .expect("insert the approved stand-in model");
        })
        .await;
}

async fn seed_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("knowledge-answer-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    user_id
}

/// `is_admin` reads every collection; a non-admin with no grants reads none.
fn security_context(user_id: Uuid, is_admin: bool) -> Arc<SecurityContext> {
    Arc::new(SecurityContext {
        user_id,
        is_admin,
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

/// A letters-only word no other article contains, so each test's question
/// retrieves only its own article however many rows earlier tests left behind.
fn unique_word() -> String {
    Uuid::now_v7()
        .simple()
        .to_string()
        .chars()
        .rev()
        .take(16)
        .map(|c| {
            if c.is_ascii_digit() {
                char::from(b'g' + (c as u8 - b'0'))
            } else {
                c
            }
        })
        .collect()
}

struct Article {
    source: Uuid,
    item: Uuid,
    token: String,
}

async fn seed_article(state: &EngineState) -> Article {
    let db = &state.base.db;
    let token = unique_word();
    let source = insert_source(db, &format!("Answers {token}")).await;
    let text = format!(
        "# Claims {token}\n\nExpense claims for {token} trips must be submitted within 30 days of returning."
    );
    let item = insert_article(db, source, &format!("Claims {token}"), &text, "published").await;
    attome_search::reindex_item(db, item)
        .await
        .expect("reindex the seeded article");
    Article {
        source,
        item,
        token,
    }
}

async fn ask(
    state: &EngineState,
    ctx: &ActionContext,
    question: &str,
) -> Result<ActionOutcome, attome_types::AppError> {
    let ai = attome_config::AiEnablement {
        enabled: true,
        fields: true,
        chat: true,
        semantic_search: true,
        workflow_nodes: true,
    };
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
        KNOWLEDGE_ANSWER,
        ctx,
        &inputs,
        &json!({ "question": question }),
    )
    .await
}

fn completed(outcome: ActionOutcome) -> (Value, Option<Provenance>) {
    match outcome {
        ActionOutcome::Completed { result, provenance } => (result, provenance),
        _ => panic!("knowledge.answer is a Read action and must complete for a user"),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

/// **The happy path.** One model call, a cited answer, the citation resolved
/// to the article and heading it came from — and retrieved text only ever in
/// untrusted user messages, never in the system instruction.
#[tokio::test]
async fn a_cited_answer_comes_back_with_its_citation_resolved() {
    let model = stand_in(
        r#"{"status":"answered","answer":"Within 30 days of returning.","citations":["E1"]}"#,
    )
    .await;
    let state = skip_if_no_db!(test_state(&model.base_url, APPROVED_MODEL).await);
    let user = seed_user(&state.base.db).await;
    let article = seed_article(&state).await;

    let ctx = ActionContext::user(security_context(user, true));
    let question = format!("When is the {} deadline?", article.token);
    let (result, provenance) = completed(ask(&state, &ctx, &question).await.expect("dispatch"));

    assert_eq!(result["status"], "answered", "{result}");
    assert_eq!(result["answer"], "Within 30 days of returning.");
    let citations = result["citations"].as_array().expect("citations array");
    assert_eq!(citations.len(), 1, "{result}");
    assert_eq!(citations[0]["item_id"], json!(article.item));
    assert_eq!(
        citations[0]["heading_path"],
        json!([format!("Claims {}", article.token)])
    );
    let provenance = provenance.expect("a model-backed answer carries provenance");
    assert_eq!(provenance.model_id, APPROVED_MODEL);
    assert_eq!(provenance.prompt_version, "knowledge.answer/v1");
    assert_eq!(
        logged_session(&state, provenance.suggestion_id).await,
        None,
        "a direct user answer runs under no agent session (D-511)"
    );

    let requests = model.requests();
    assert_eq!(requests.len(), 1, "exactly one model call");
    let messages = requests[0]["messages"].as_array().expect("messages");
    assert_eq!(messages[0]["role"], "system");
    let system = messages[0]["content"].as_str().unwrap_or_default();
    assert!(
        !system.contains(&article.token),
        "retrieved text and the question must never reach the system message"
    );
    assert!(messages.iter().skip(1).all(|m| m["role"] == "user"));
    assert!(messages.iter().any(|m| {
        let content = m["content"].as_str().unwrap_or_default();
        content.contains("source=E1") && content.contains("within 30 days")
    }));

    delete_article(&state.base.db, article.item, Some(article.source)).await;
}

/// The agent session a logged suggestion was attributed to (D-511).
async fn logged_session(state: &EngineState, suggestion_id: Option<Uuid>) -> Option<Uuid> {
    let id = suggestion_id.expect("the model call must have been logged");
    sqlx::query_scalar("SELECT agent_session_ref FROM ai_suggestion_outcome WHERE id = $1")
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .expect("read the logged suggestion")
}

/// **D-511 ruling 4.** An answer generated inside an agent session is logged
/// against that session. Reads are not in the invocation ledger, so this row is
/// how an auditor traces what a session caused a model to generate.
#[tokio::test]
async fn an_answer_given_inside_an_agent_session_is_logged_against_it() {
    let model = stand_in(
        r#"{"status":"answered","answer":"Within 30 days of returning.","citations":["E1"]}"#,
    )
    .await;
    let state = skip_if_no_db!(test_state(&model.base_url, APPROVED_MODEL).await);
    let user = seed_user(&state.base.db).await;
    let article = seed_article(&state).await;
    let session_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface) \
         VALUES ($1, 1, 'test') RETURNING id",
    )
    .bind(user)
    .fetch_one(&state.base.db)
    .await
    .expect("open an agent session");

    let ctx = ActionContext::agent(
        security_context(user, true),
        attome_ai::descriptor::RiskTier::Reversible,
    )
    .with_agent_session(session_id);
    let question = format!("When is the {} deadline?", article.token);
    let (result, provenance) = completed(ask(&state, &ctx, &question).await.expect("dispatch"));

    assert_eq!(result["status"], "answered", "{result}");
    let provenance = provenance.expect("a model-backed answer carries provenance");
    assert_eq!(
        logged_session(&state, provenance.suggestion_id).await,
        Some(session_id),
        "the generation must be traceable to the session that caused it"
    );
    assert_eq!(model.requests().len(), 1);

    delete_article(&state.base.db, article.item, Some(article.source)).await;
}

/// **The grounding check is code.** A reply citing a passage the model was not
/// shown is declined, however confident its answer.
#[tokio::test]
async fn a_reply_citing_an_unseen_passage_is_declined_as_ungrounded() {
    let model =
        stand_in(r#"{"status":"answered","answer":"Within 90 days.","citations":["E9"]}"#).await;
    let state = skip_if_no_db!(test_state(&model.base_url, APPROVED_MODEL).await);
    let user = seed_user(&state.base.db).await;
    let article = seed_article(&state).await;

    let ctx = ActionContext::user(security_context(user, true));
    let question = format!("When is the {} deadline?", article.token);
    let (result, provenance) = completed(ask(&state, &ctx, &question).await.expect("dispatch"));

    assert_eq!(
        result,
        json!({ "status": "declined", "reason": "ungrounded" })
    );
    assert!(
        result.get("answer").is_none(),
        "an ungrounded answer must not be returned"
    );
    assert!(
        provenance.is_some(),
        "the model was called, so the call is logged"
    );
    assert_eq!(model.requests().len(), 1);

    delete_article(&state.base.db, article.item, Some(article.source)).await;
}

#[tokio::test]
async fn a_model_that_reports_insufficient_evidence_is_declined() {
    let model = stand_in(r#"{"status":"insufficient","answer":"","citations":[]}"#).await;
    let state = skip_if_no_db!(test_state(&model.base_url, APPROVED_MODEL).await);
    let user = seed_user(&state.base.db).await;
    let article = seed_article(&state).await;

    let ctx = ActionContext::user(security_context(user, true));
    let question = format!("What is the {} refund rate?", article.token);
    let (result, _) = completed(ask(&state, &ctx, &question).await.expect("dispatch"));

    assert_eq!(
        result,
        json!({ "status": "declined", "reason": "insufficient_evidence" })
    );
    assert_eq!(model.requests().len(), 1);

    delete_article(&state.base.db, article.item, Some(article.source)).await;
}

/// **Permission comes before the model.** A caller who can read no collection
/// is declined for lack of evidence, and the model is never called — the
/// article's text cannot reach a model on behalf of someone who may not read
/// it.
#[tokio::test]
async fn a_caller_who_can_read_nothing_is_declined_without_a_model_call() {
    let model = stand_in(r#"{"status":"answered","answer":"Leaked.","citations":["E1"]}"#).await;
    let state = skip_if_no_db!(test_state(&model.base_url, APPROVED_MODEL).await);
    let user = seed_user(&state.base.db).await;
    let article = seed_article(&state).await;

    let ctx = ActionContext::user(security_context(user, false));
    let question = format!("When is the {} deadline?", article.token);
    let (result, provenance) = completed(ask(&state, &ctx, &question).await.expect("dispatch"));

    assert_eq!(
        result,
        json!({ "status": "declined", "reason": "no_evidence" })
    );
    assert!(provenance.is_none(), "no model was involved");
    assert!(
        model.requests().is_empty(),
        "the model must never be called for a caller with no readable evidence"
    );

    delete_article(&state.base.db, article.item, Some(article.source)).await;
}

#[tokio::test]
async fn a_question_that_matches_nothing_is_declined_without_a_model_call() {
    let model = stand_in(r#"{"status":"answered","answer":"Invented.","citations":["E1"]}"#).await;
    let state = skip_if_no_db!(test_state(&model.base_url, APPROVED_MODEL).await);
    let user = seed_user(&state.base.db).await;

    let ctx = ActionContext::user(security_context(user, true));
    let question = format!("What is the {} {} policy?", unique_word(), unique_word());
    let (result, _) = completed(ask(&state, &ctx, &question).await.expect("dispatch"));

    assert_eq!(
        result,
        json!({ "status": "declined", "reason": "no_evidence" })
    );
    assert!(model.requests().is_empty());
}

/// An unapproved model is refused before a single token is spent, even though
/// retrieval found evidence.
#[tokio::test]
async fn an_unapproved_model_is_refused_before_the_call() {
    let model = stand_in(r#"{"status":"answered","answer":"Unvetted.","citations":["E1"]}"#).await;
    let state = skip_if_no_db!(test_state(&model.base_url, UNAPPROVED_MODEL).await);
    let user = seed_user(&state.base.db).await;
    let article = seed_article(&state).await;

    let ctx = ActionContext::user(security_context(user, true));
    let question = format!("When is the {} deadline?", article.token);
    let err = ask(&state, &ctx, &question)
        .await
        .expect_err("an unapproved model must be refused");

    assert!(matches!(err, attome_types::AppError::NotFound), "{err:?}");
    assert!(model.requests().is_empty());

    delete_article(&state.base.db, article.item, Some(article.source)).await;
}

/// `search.knowledge` through the shared `dispatch`, as the agent in `ctx`.
async fn search(state: &EngineState, ctx: &ActionContext, query: &str) -> Value {
    let ai = attome_config::AiEnablement {
        enabled: true,
        fields: true,
        chat: true,
        semantic_search: true,
        workflow_nodes: true,
    };
    let inputs = GateInputs {
        licensed: true,
        ai: &ai,
        surface: None,
        external_effects_enabled: false,
    };
    let outcome = dispatch(
        state,
        &ActionRegistry::new(),
        &Executors::new(),
        SEARCH_KNOWLEDGE,
        ctx,
        &inputs,
        &json!({ "query": query }),
    )
    .await
    .expect("dispatch search.knowledge");
    completed(outcome).0
}

/// **D-512 §7: a session's knowledge scope is enforced inside retrieval.**
/// The scope is intersected with the caller's own readable collections before
/// any chunk is queried, for both retrievals a session can make. A session
/// scoped to another collection, or to none, gets no evidence and never
/// reaches the model; a session scoped to the article's collection, or with no
/// scope, answers from it. The caller here is an admin who can read every
/// collection, so the scope is the only thing that can narrow.
#[tokio::test]
async fn a_session_knowledge_scope_is_enforced_before_any_evidence_is_returned() {
    let model = stand_in(
        r#"{"status":"answered","answer":"Within 30 days of returning.","citations":["E1"]}"#,
    )
    .await;
    let state = skip_if_no_db!(test_state(&model.base_url, APPROVED_MODEL).await);
    let user = seed_user(&state.base.db).await;
    let article = seed_article(&state).await;
    let elsewhere = insert_source(&state.base.db, &format!("Elsewhere {}", article.token)).await;
    let question = format!("When is the {} deadline?", article.token);

    for (scope, reaches_article) in [
        (Some(vec![elsewhere]), false),
        (Some(vec![]), false),
        (Some(vec![elsewhere, article.source]), true),
        (None, true),
    ] {
        let session = attome_ai::session::start(
            &state.base.db,
            &attome_audit::audit_service(&state),
            attome_ai::session::SessionStart {
                owner_user_id: user,
                risk_ceiling: attome_ai::descriptor::RiskTier::Reversible,
                allowed_action_ids: None,
                surface: "test",
                agent_definition_ref: None,
                integration_system_id: None,
                tainted: false,
                policy: attome_ai::session::PolicySnapshot {
                    knowledge_source_refs: scope.clone(),
                    ..attome_ai::session::PolicySnapshot::NONE
                },
            },
        )
        .await
        .expect("open a scoped agent session");
        let ctx = ActionContext::for_session(security_context(user, true), &session);

        let calls_before = model.requests().len();
        let (answer, _) = completed(ask(&state, &ctx, &question).await.expect("dispatch"));
        let passages = search(&state, &ctx, &question).await;
        let found = passages["passages"]
            .as_array()
            .expect("passages array")
            .len();

        if reaches_article {
            assert_eq!(answer["status"], "answered", "{scope:?}: {answer}");
            assert_eq!(model.requests().len(), calls_before + 1, "{scope:?}");
            assert!(found > 0, "{scope:?}: {passages}");
        } else {
            assert_eq!(
                answer,
                json!({ "status": "declined", "reason": "no_evidence" }),
                "{scope:?}"
            );
            assert_eq!(
                model.requests().len(),
                calls_before,
                "{scope:?}: out-of-scope evidence must never reach the model"
            );
            assert_eq!(found, 0, "{scope:?}: {passages}");
        }
    }

    delete_article(&state.base.db, article.item, Some(article.source)).await;
}

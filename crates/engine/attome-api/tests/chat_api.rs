//! C4 — the chat HTTP API through the full middleware stack, against a
//! throwaway database.
//!
//! Rows: A-08 (a confirm body carrying `arguments` is rejected), A-09 (a stale
//! hash), A-10 (an approval raised in a conversation is re-gated at resume),
//! A-13 (a double confirm over HTTP mutates once), A-15 (an approval taken
//! while the session is paused defers), A-38 and A-65 (another user's
//! conversation is `404` on every C4 route, before anything is read or
//! written). Plus start/list/get, a real turn against a scripted model,
//! reject, and end-and-revoke.
//!
//! The engine-level state machine and its races are proven in
//! `crates/engine/attome-ai/tests/confirm.rs`; these tests prove the routes reach
//! it, authorize first, and shape the answers.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<migrate-built template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test chat_api -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool; production code uses attome_db::tx::begin"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use axum::{Json, Router, routing::post};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ORIGIN: &str = "http://localhost:4200";

/// `crates/server/src/boot.rs`'s AI bundle chain, in its order.
const AI_BUNDLES: &[(&str, &str)] = &[
    (
        "attome-ai-personality",
        include_str!("../../../../platform-bundles/attome-ai-personality.json"),
    ),
    (
        "attome-ai-tone",
        include_str!("../../../../platform-bundles/attome-ai-tone.json"),
    ),
    (
        "xrm-core-authentication-type",
        include_str!("../../../../platform-bundles/xrm-core-authentication-type.json"),
    ),
    (
        "attome-ai-provider",
        include_str!("../../../../platform-bundles/attome-ai-provider.json"),
    ),
    (
        "attome-ai-model-catalog",
        include_str!("../../../../platform-bundles/attome-ai-model-catalog.json"),
    ),
    (
        "attome-ai-agent",
        include_str!("../../../../platform-bundles/attome-ai-agent.json"),
    ),
];

// ---------------------------------------------------------------------------
// A scripted model
// ---------------------------------------------------------------------------

/// Replies from a fixed script, in order. Mounted at `/chat/completions` —
/// `attome_inference::CHAT_COMPLETIONS_PATH`, which this crate does not depend on.
#[derive(Clone, Default)]
struct FakeModel {
    script: Arc<Mutex<VecDeque<Value>>>,
}

impl FakeModel {
    fn push(&self, reply: Value) {
        self.script.lock().unwrap().push_back(reply);
    }
}

fn says(text: &str) -> Value {
    json!({"choices": [{"message": {"content": text}, "finish_reason": "stop"}]})
}

fn wants_tool(id: &str, name: &str, arguments: &Value) -> Value {
    json!({"choices": [{
        "message": {"tool_calls": [
            {"id": id, "type": "function",
             "function": {"name": name, "arguments": arguments.to_string()}}
        ]},
        "finish_reason": "tool_calls"
    }]})
}

/// Renders a scripted response as an OpenAI-compatible SSE body (C11 B3):
/// text in four-character deltas, tool-call arguments in fragments, then the
/// finish chunk and `[DONE]` — what a streamed internal turn receives.
fn to_sse(response: &Value) -> String {
    let choice = &response["choices"][0];
    let message = &choice["message"];
    let mut out = String::new();
    let mut push = |v: Value| out.push_str(&format!("data: {v}\n\n"));
    if let Some(text) = message["content"].as_str() {
        let chars: Vec<char> = text.chars().collect();
        for piece in chars.chunks(4) {
            let piece: String = piece.iter().collect();
            push(json!({"choices": [{"index": 0, "delta": {"content": piece}}]}));
        }
    }
    if let Some(calls) = message["tool_calls"].as_array() {
        for (i, call) in calls.iter().enumerate() {
            push(json!({"choices": [{"index": 0, "delta": {"tool_calls": [{
                "index": i, "id": call["id"], "type": "function",
                "function": {"name": call["function"]["name"],
                             "arguments": call["function"]["arguments"]}
            }]}}]}));
        }
    }
    push(json!({"choices": [{"index": 0, "delta": {}, "finish_reason": choice["finish_reason"]}]}));
    out.push_str("data: [DONE]\n\n");
    out
}

async fn spawn_model(model: FakeModel) -> String {
    use axum::response::IntoResponse;
    let app = Router::new().route(
        "/chat/completions",
        post(move |Json(body): Json<Value>| {
            let model = model.clone();
            async move {
                let next = model
                    .script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| says("SCRIPT EXHAUSTED"));
                if body["stream"] == true {
                    (
                        [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
                        to_sse(&next),
                    )
                        .into_response()
                } else {
                    Json(next).into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn test_config(model_base_url: &str) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 30,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 8, "timeout": 5.0
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
            "inference": {{
                "ai": {{
                    "enabled": true, "fields": true, "chat": true,
                    "semantic_search": true, "workflow_nodes": true
                }},
                "generation": {{
                    "base_url": "{model_base_url}", "model": "fake-model-1",
                    "request_timeout_secs": 10
                }}
            }},
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

async fn test_system(model_base_url: &str) -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let mut config = test_config(model_base_url);
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
    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    let system = EngineSystem::builder(EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        // The chat routes are mounted by `ActionModel`, behind its licence gate.
        .register(attome_ai::ActionModel)
        .build()
        .await
        .expect("build EngineSystem");
    // The AI entities (`ai_model`, `ai_agent`, `ai_agent_policy`)
    // are metadata-defined, created by platform bundles that `server`'s boot
    // applies — not by migrations or `EngineSystem::build`. Same bundles, boot's
    // order (lookup targets first), without the `-data` scaffold rows.
    for (name, bundle) in AI_BUNDLES {
        attome_api::bundle::apply_platform_bundle(system.state(), name, bundle)
            .await
            .unwrap_or_else(|e| panic!("apply platform bundle {name}: {e}"));
    }
    system
        .state()
        .modules
        .store(Arc::new(attome_modules::ModuleSet::from_bits(
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

async fn grant(db: &attome_db::DbPool, user_id: Uuid, key: &str) {
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

async fn revoke(db: &attome_db::DbPool, user_id: Uuid, key: &str) {
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

/// A user; an admin holds `system.admin` (which covers `ai_agent.update`).
async fn seed_user(db: &attome_db::DbPool, admin: bool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(attome_testkit::unique("chat-api"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");
    if admin {
        grant(db, user_id, "system.admin").await;
    }
    (user_id, session_cookie(user_id))
}

/// An active agent definition with a live model and a policy whose ceiling
/// admits `Consequential` — the same fixture shape
/// `server/tests/audit_coverage_emission.rs` uses.
async fn agent_definition(db: &attome_db::DbPool) -> Uuid {
    let model = Uuid::now_v7();
    sqlx::query("INSERT INTO ai_model (id, name, created_at) VALUES ($1, 'chat model', NOW())")
        .bind(model)
        .execute(db)
        .await
        .expect("insert ai_model row");
    let policy = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent_policy \
            (id, name, risk_ceiling, max_invocations_per_session, max_writes_per_day, \
             max_tokens_per_session, max_session_duration_minutes, created_at) \
         VALUES ($1, 'chat policy', 'consequential', 1000, 1000, 200000, 600, NOW())",
    )
    .bind(policy)
    .execute(db)
    .await
    .expect("insert ai_agent_policy row");
    let definition = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ai_agent \
            (id, name, status, primary_model_ref, system_instructions, policy_ref, created_at) \
         VALUES ($1, 'chat agent', 'active', $2, 'Be concise.', $3, NOW())",
    )
    .bind(definition)
    .bind(model)
    .bind(policy)
    .execute(db)
    .await
    .expect("insert ai_agent row");
    definition
}

async fn send(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", ORIGIN)
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    let req = match body {
        Some(body) => req
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

struct Fx {
    state: EngineState,
    app: Router,
    model: FakeModel,
    owner: Uuid,
    owner_cookie: String,
}

impl Fx {
    fn db(&self) -> &attome_db::DbPool {
        &self.state.base.db
    }

    /// Starts a conversation over HTTP; returns `(conversation, session)`.
    async fn start(&self, risk_ceiling: &str) -> (Uuid, Uuid) {
        let definition = agent_definition(self.db()).await;
        let (status, body) = send(
            &self.app,
            "POST",
            "/api/v1/ai/conversations",
            Some(&self.owner_cookie),
            Some(json!({"agent_definition_id": definition, "risk_ceiling": risk_ceiling})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "start: {body}");
        let conversation = Uuid::parse_str(body["conversation"]["id"].as_str().unwrap()).unwrap();
        let session =
            Uuid::parse_str(body["conversation"]["agent_session_id"].as_str().unwrap()).unwrap();
        (conversation, session)
    }
}

async fn fixture() -> Option<Fx> {
    let model = FakeModel::default();
    let base_url = spawn_model(model.clone()).await;
    let system = test_system(&base_url).await?;
    let state = system.state().clone();
    let app = full_app(system);
    let (owner, owner_cookie) = seed_user(&state.base.db, true).await;
    Some(Fx {
        state,
        app,
        model,
        owner,
        owner_cookie,
    })
}

/// A provisioned entity allow-listed for `record.update_field`, with one
/// record — so "exactly one mutation" is its `row_version`.
async fn writable_record(fx: &Fx) -> (String, Uuid) {
    let state = &fx.state;
    let logicalname = format!("chat_test_{}", Uuid::now_v7().simple());
    let entity_id = attome_metadata::provision::ensure_entity(
        &state.base.db,
        &logicalname,
        "Chat Test Entity",
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
    sqlx::query(
        "DELETE FROM setting WHERE key = 'ai.record_update_field_allowlist' \
            AND scope = 'deployment' AND scope_ref IS NULL",
    )
    .execute(&state.base.db)
    .await
    .expect("clear allow-list");
    sqlx::query(
        "INSERT INTO setting (key, scope, scope_ref, value, schema) \
         VALUES ('ai.record_update_field_allowlist', 'deployment', NULL, $1, $2)",
    )
    .bind(json!({ logicalname.clone(): ["status"] }))
    .bind(json!({"type": "object"}))
    .execute(&state.base.db)
    .await
    .expect("allow-list setting");
    state.settings.swap(
        attome_core::load_all_settings(&state.base.db)
            .await
            .expect("reload settings"),
    );
    let table = attome_core::quote_ident(&logicalname);
    let record_id: Uuid = sqlx::query_scalar(&format!(
        "INSERT INTO {table} (id, status, is_active, row_version) \
         VALUES ($1, 'open', true, 0) RETURNING id"
    ))
    .bind(Uuid::now_v7())
    .fetch_one(&state.base.db)
    .await
    .expect("insert business record");
    (logicalname, record_id)
}

/// A server-persisted proposal to set the record to `closed`; returns its
/// `arguments_hash` (what the UI would display).
async fn propose(fx: &Fx, conversation: Uuid, tid: &str, entity: &str, record: Uuid) -> String {
    attome_ai::tool_call::propose(
        fx.db(),
        attome_ai::tool_call::NewToolCall {
            conversation_id: conversation,
            message_id: None,
            turn_id: Uuid::now_v7(),
            tool_call_id: Some(tid.into()),
            action_id: "record.update_field".into(),
            arguments: json!({
                "entity": entity, "record_id": record, "field": "status",
                "value": "closed", "row_version": 0,
            }),
            initiator_is_agent: true,
            gate_decision: None,
        },
    )
    .await
    .expect("propose")
    .arguments_hash
}

async fn business_row_version(fx: &Fx, entity: &str, record: Uuid) -> i64 {
    let table = attome_core::quote_ident(entity);
    sqlx::query_scalar(&format!("SELECT row_version FROM {table} WHERE id = $1"))
        .bind(record)
        .fetch_one(fx.db())
        .await
        .expect("read business row_version")
}

async fn proposal_status(fx: &Fx, conversation: Uuid, tid: &str) -> String {
    sqlx::query_scalar(
        "SELECT status FROM ai_tool_call WHERE conversation_id = $1 AND tool_call_id = $2",
    )
    .bind(conversation)
    .bind(tid)
    .fetch_one(fx.db())
    .await
    .expect("read proposal status")
}

fn confirm_uri(conversation: Uuid, tid: &str) -> String {
    format!("/api/v1/ai/conversations/{conversation}/tool-calls/{tid}/confirm")
}

// ---------------------------------------------------------------------------
// Start, list, get, authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_started_conversation_is_listed_and_shows_its_governance() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;

    let (status, list) = send(
        &fx.app,
        "GET",
        "/api/v1/ai/conversations",
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["page"], json!(1));
    assert!(
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == json!(conversation)),
        "{list}"
    );

    let (status, detail) = send(
        &fx.app,
        "GET",
        &format!("/api/v1/ai/conversations/{conversation}"),
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["governance"]["state"], json!("live"));
    assert_eq!(detail["governance"]["risk_ceiling"], json!("reversible"));
}

#[tokio::test]
async fn starting_a_conversation_requires_the_agent_privilege_and_a_known_body() {
    let fx = skip_if_no_db!(fixture().await);
    let definition = agent_definition(fx.db()).await;
    let (_, plain_cookie) = seed_user(fx.db(), false).await;

    let (status, _) = send(
        &fx.app,
        "POST",
        "/api/v1/ai/conversations",
        Some(&plain_cookie),
        Some(json!({"agent_definition_id": definition, "risk_ceiling": "read"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no ai_agent.update");

    let (status, _) = send(
        &fx.app,
        "POST",
        "/api/v1/ai/conversations",
        Some(&fx.owner_cookie),
        Some(json!({"agent_definition_id": definition, "risk_ceiling": "read", "extra": 1})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "an unknown field");
}

#[tokio::test]
async fn the_conversation_routes_require_authentication() {
    let fx = skip_if_no_db!(fixture().await);
    let (status, _) = send(&fx.app, "GET", "/api/v1/ai/conversations", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Rows A-38 / A-65 — another user's conversation is 404, on every C4 route
// ---------------------------------------------------------------------------

/// **Rows A-38 and A-65.** Every C4 route answers another user's conversation
/// with `404` — not `403` — and nothing is read or written: no message is
/// appended, the proposal is untouched, the conversation is not ended.
/// (`/stream` is C10's and is not mounted.)
#[tokio::test]
async fn another_users_conversation_is_not_found_on_every_route_and_nothing_changes() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    let hash = propose(&fx, conversation, "theirs", &entity, record).await;
    let (_, stranger) = seed_user(fx.db(), true).await;

    let routes: Vec<(&str, String, Option<Value>)> = vec![
        (
            "GET",
            format!("/api/v1/ai/conversations/{conversation}"),
            None,
        ),
        (
            "GET",
            format!("/api/v1/ai/conversations/{conversation}/messages"),
            None,
        ),
        (
            "POST",
            format!("/api/v1/ai/conversations/{conversation}/messages"),
            Some(json!({"text": "hello"})),
        ),
        (
            "POST",
            confirm_uri(conversation, "theirs"),
            Some(json!({"arguments_hash": hash})),
        ),
        (
            "DELETE",
            format!("/api/v1/ai/conversations/{conversation}/tool-calls/theirs"),
            None,
        ),
        (
            "DELETE",
            format!("/api/v1/ai/conversations/{conversation}"),
            None,
        ),
    ];
    for (method, uri, body) in routes {
        let (status, _) = send(&fx.app, method, &uri, Some(&stranger), body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }

    let (last_ordinal, ended): (i64, bool) = sqlx::query_as(
        "SELECT last_ordinal, ended_at IS NOT NULL FROM ai_conversation WHERE id = $1",
    )
    .bind(conversation)
    .fetch_one(fx.db())
    .await
    .unwrap();
    assert_eq!(last_ordinal, 0, "no message was appended");
    assert!(!ended, "the conversation was not ended");
    assert_eq!(
        proposal_status(&fx, conversation, "theirs").await,
        "proposed"
    );
    assert_eq!(business_row_version(&fx, &entity, record).await, 0);
}

// ---------------------------------------------------------------------------
// A turn
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_message_runs_a_turn_and_the_transcript_is_ordered() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    fx.model.push(says("Hello there."));

    let (status, turn) = send(
        &fx.app,
        "POST",
        &format!("/api/v1/ai/conversations/{conversation}/messages"),
        Some(&fx.owner_cookie),
        Some(json!({"text": "hi"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    assert_eq!(turn["terminal_state"], json!("completed"));
    assert_eq!(turn["text"], json!("Hello there."));
    assert!(turn["pending"].is_null());

    let (status, history) = send(
        &fx.app,
        "GET",
        &format!("/api/v1/ai/conversations/{conversation}/messages"),
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let roles: Vec<&str> = history["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["role"].as_str().unwrap())
        .collect();
    assert_eq!(roles, vec!["user", "assistant"]);
    assert_eq!(history["total"], json!(2));
}

#[tokio::test]
async fn an_empty_message_is_rejected_before_anything_is_written() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (status, _) = send(
        &fx.app,
        "POST",
        &format!("/api/v1/ai/conversations/{conversation}/messages"),
        Some(&fx.owner_cookie),
        Some(json!({"text": "   "})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let last: i64 = sqlx::query_scalar("SELECT last_ordinal FROM ai_conversation WHERE id = $1")
        .bind(conversation)
        .fetch_one(fx.db())
        .await
        .unwrap();
    assert_eq!(last, 0);
}

// ---------------------------------------------------------------------------
// The confirm round-trip over HTTP — rows A-08, A-09, A-13
// ---------------------------------------------------------------------------

/// **Row A-08.** The confirm body accepts no `arguments` field. A request
/// carrying one is rejected before the engine is reached: the proposal stays
/// `proposed` and the business record is untouched.
#[tokio::test]
async fn a_confirm_body_carrying_arguments_is_rejected() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    let hash = propose(&fx, conversation, "c1", &entity, record).await;

    let (status, _) = send(
        &fx.app,
        "POST",
        &confirm_uri(conversation, "c1"),
        Some(&fx.owner_cookie),
        Some(json!({
            "arguments_hash": hash,
            "arguments": {"entity": entity, "record_id": record, "field": "status",
                          "value": "hijacked", "row_version": 0},
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(proposal_status(&fx, conversation, "c1").await, "proposed");
    assert_eq!(business_row_version(&fx, &entity, record).await, 0);
}

/// **Row A-09.** A stale hash is a `409` with outcome `stale_hash`, and the
/// proposal is unchanged.
#[tokio::test]
async fn a_stale_hash_is_refused_over_http() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    propose(&fx, conversation, "c1", &entity, record).await;

    let (status, body) = send(
        &fx.app,
        "POST",
        &confirm_uri(conversation, "c1"),
        Some(&fx.owner_cookie),
        Some(json!({"arguments_hash": "not-what-was-shown"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], json!("conflict"));
    assert_eq!(body["outcome"], json!("stale_hash"));
    assert_eq!(proposal_status(&fx, conversation, "c1").await, "proposed");
    assert_eq!(business_row_version(&fx, &entity, record).await, 0);
}

/// **Row A-13 over HTTP.** A double-click: two confirms of one proposal in
/// flight at once. Exactly one `200`; the other is a `409` decided from the
/// persisted state (`in_progress` or `already_executed`, carrying the recorded
/// result) — and the business record changes exactly once.
#[tokio::test]
async fn a_double_confirm_over_http_mutates_exactly_once() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    let hash = propose(&fx, conversation, "dbl", &entity, record).await;
    let uri = confirm_uri(conversation, "dbl");
    let body = json!({"arguments_hash": hash});

    let (a, b) = tokio::join!(
        send(
            &fx.app,
            "POST",
            &uri,
            Some(&fx.owner_cookie),
            Some(body.clone())
        ),
        send(
            &fx.app,
            "POST",
            &uri,
            Some(&fx.owner_cookie),
            Some(body.clone())
        ),
    );
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::CONFLICT],
        "a: {} b: {}",
        a.1,
        b.1
    );
    let (ok, refused) = if a.0 == StatusCode::OK {
        (a.1, b.1)
    } else {
        (b.1, a.1)
    };
    assert_eq!(ok["outcome"], json!("executed"));
    let outcome = refused["outcome"].as_str().unwrap();
    assert!(
        outcome == "in_progress" || outcome == "already_executed",
        "{refused}"
    );
    assert_eq!(
        business_row_version(&fx, &entity, record).await,
        1,
        "exactly one business mutation"
    );

    // A later confirm is `already_executed`, carrying the recorded result.
    let (status, again) = send(&fx.app, "POST", &uri, Some(&fx.owner_cookie), Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(again["outcome"], json!("already_executed"));
    assert_eq!(again["result"]["new_value"], json!("closed"));
    assert_eq!(business_row_version(&fx, &entity, record).await, 1);
}

// ---------------------------------------------------------------------------
// Reject and end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_rejected_proposal_cannot_be_confirmed_or_rejected_again() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    let hash = propose(&fx, conversation, "no", &entity, record).await;
    let reject_uri = format!("/api/v1/ai/conversations/{conversation}/tool-calls/no");

    let (status, _) = send(&fx.app, "DELETE", &reject_uri, Some(&fx.owner_cookie), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(proposal_status(&fx, conversation, "no").await, "rejected");

    let (status, body) = send(
        &fx.app,
        "POST",
        &confirm_uri(conversation, "no"),
        Some(&fx.owner_cookie),
        Some(json!({"arguments_hash": hash})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["outcome"], json!("rejected"));

    let (status, body) = send(&fx.app, "DELETE", &reject_uri, Some(&fx.owner_cookie), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["outcome"], json!("rejected"));
    assert_eq!(business_row_version(&fx, &entity, record).await, 0);
}

#[tokio::test]
async fn ending_a_conversation_revokes_its_session_and_stops_further_turns() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, session) = fx.start("reversible").await;
    let uri = format!("/api/v1/ai/conversations/{conversation}");

    let (status, _) = send(&fx.app, "DELETE", &uri, Some(&fx.owner_cookie), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM agent_session WHERE id = $1")
            .bind(session)
            .fetch_one(fx.db())
            .await
            .unwrap();
    assert!(revoked, "the session is revoked with the conversation");

    let (status, _) = send(
        &fx.app,
        "POST",
        &format!("{uri}/messages"),
        Some(&fx.owner_cookie),
        Some(json!({"text": "still there?"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an ended conversation takes no turns"
    );

    let (status, detail) = send(&fx.app, "GET", &uri, Some(&fx.owner_cookie), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["governance"]["state"], json!("ended"));

    let (status, _) = send(&fx.app, "DELETE", &uri, Some(&fx.owner_cookie), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "ending twice is idempotent");
}

// ---------------------------------------------------------------------------
// Rows A-10 and A-15 — approvals raised from a conversation
// ---------------------------------------------------------------------------

/// A second session for `agent.pause` to target, as in
/// `approval_agent_action.rs`.
async fn target_session(fx: &Fx) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agent_session (owner_user_id, risk_ceiling, surface) \
         VALUES ($1, 2, 'test') RETURNING id",
    )
    .bind(fx.owner)
    .fetch_one(fx.db())
    .await
    .expect("open target session")
}

async fn paused(fx: &Fx, session: Uuid) -> bool {
    sqlx::query_scalar("SELECT paused_at IS NOT NULL FROM agent_session WHERE id = $1")
        .bind(session)
        .fetch_one(fx.db())
        .await
        .unwrap()
}

/// A turn in which the model asks for `agent.pause` — a `Consequential`
/// action — which the gate turns into a four-eyes request. Returns its id.
async fn approval_from_a_turn(fx: &Fx, conversation: Uuid, target: Uuid) -> Uuid {
    fx.model.push(wants_tool(
        "pause1",
        "agent.pause",
        &json!({"session_id": target, "reason": "runaway"}),
    ));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &format!("/api/v1/ai/conversations/{conversation}/messages"),
        Some(&fx.owner_cookie),
        Some(json!({"text": "pause that session"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    assert_eq!(turn["terminal_state"], json!("awaiting_approval"), "{turn}");
    assert_eq!(turn["pending"]["kind"], json!("approval"));
    Uuid::parse_str(turn["pending"]["approval_request_id"].as_str().unwrap()).unwrap()
}

async fn approve(fx: &Fx, approver_cookie: &str, approval: Uuid) -> StatusCode {
    send(
        &fx.app,
        "POST",
        &format!("/api/v1/admin/approvals/{approval}/decide"),
        Some(approver_cookie),
        Some(json!({"decision": "approve", "row_version": 0})),
    )
    .await
    .0
}

async fn approval_status(fx: &Fx, approval: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
        .bind(approval)
        .fetch_one(fx.db())
        .await
        .unwrap()
}

/// **Row A-10, from the conversation surface.** A turn raises an approval;
/// the requester then loses the privilege the action needs; a different admin
/// approves. Execution re-gates at resume and refuses — the action does not
/// run, and the request is `invalidated`.
#[tokio::test]
async fn an_approval_raised_in_a_conversation_is_regated_at_resume() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("consequential").await;
    let target = target_session(&fx).await;
    let approval = approval_from_a_turn(&fx, conversation, target).await;
    assert!(!paused(&fx, target).await, "nothing ran on the request");

    revoke(fx.db(), fx.owner, "system.admin").await;
    let (_, approver) = seed_user(fx.db(), true).await;

    assert_eq!(
        approve(&fx, &approver, approval).await,
        StatusCode::CONFLICT
    );
    assert!(
        !paused(&fx, target).await,
        "the re-gated action did not run"
    );
    assert_eq!(approval_status(&fx, approval).await, "invalidated");
}

/// **Row A-15, from the conversation surface.** The conversation's session is
/// paused when the approval is taken: execution is deferred, not run and not
/// invalidated — the request stays `approved`.
#[tokio::test]
async fn an_approval_raised_in_a_conversation_defers_while_its_session_is_paused() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, session) = fx.start("consequential").await;
    let target = target_session(&fx).await;
    let approval = approval_from_a_turn(&fx, conversation, target).await;

    attome_ai::session::pause(fx.db(), session, fx.owner, "test")
        .await
        .expect("pause the conversation's session");
    let (_, approver) = seed_user(fx.db(), true).await;

    assert_eq!(
        approve(&fx, &approver, approval).await,
        StatusCode::CONFLICT
    );
    assert!(!paused(&fx, target).await, "deferred, not run");
    assert_eq!(
        approval_status(&fx, approval).await,
        "approved",
        "not invalidated"
    );
}

// ---------------------------------------------------------------------------
// C7 — the panel's projections: provenance, tool calls, citations (A-56),
// and record context (A-66)
// ---------------------------------------------------------------------------

fn messages_uri(conversation: Uuid) -> String {
    format!("/api/v1/ai/conversations/{conversation}/messages")
}

async fn history(fx: &Fx, cookie: &str, conversation: Uuid) -> Vec<Value> {
    let (status, body) = send(
        &fx.app,
        "GET",
        &messages_uri(conversation),
        Some(cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["items"].as_array().expect("items").clone()
}

fn final_assistant(items: &[Value]) -> Value {
    items
        .iter()
        .rev()
        .find(|m| m["role"] == "assistant" && !m["terminal_state"].is_null())
        .cloned()
        .expect("a final assistant message")
}

/// Provenance rides the stored message; grounding and citations sit on a
/// turn's final assistant message only.
#[tokio::test]
async fn provenance_and_grounding_are_projected_on_the_final_assistant_message() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    fx.model.push(says("Hello there."));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "hi"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    assert_eq!(turn["grounding"], "none");
    assert_eq!(turn["citations"], json!([]));

    let items = history(&fx, &fx.owner_cookie, conversation).await;
    let user = &items[0];
    assert_eq!(user["role"], "user");
    assert!(
        user["model_id"].is_null() && user["grounding"].is_null(),
        "{user}"
    );
    assert_eq!(user["citations"], json!([]));
    let answer = final_assistant(&items);
    assert!(
        answer["model_id"].is_string(),
        "the model that wrote it: {answer}"
    );
    assert_eq!(answer["model_id"], turn["model_id"]);
    assert!(answer.get("prompt_version").is_some(), "{answer}");
    assert_eq!(answer["grounding"], "none");
}

/// **Row A-56.** A model that writes citation-shaped text without retrieving
/// anything produces no citation: `citations` is empty and grounding is
/// `none`, in the turn response and in the stored transcript alike.
#[tokio::test]
async fn citation_shaped_text_cannot_manufacture_a_citation() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    fx.model.push(says(
        "Refunds take 30 days [E1] (source: \"Refund policy\", article \
         01900000-0000-7000-8000-0000000000a1).",
    ));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "what is the refund policy?"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    assert_eq!(turn["citations"], json!([]), "{turn}");
    assert_eq!(turn["grounding"], "none");
    let answer = final_assistant(&history(&fx, &fx.owner_cookie, conversation).await);
    assert_eq!(answer["citations"], json!([]));
    assert_eq!(answer["grounding"], "none");
}

/// **Row A-56, `no_sources`.** A real `search.knowledge` call that retrieves
/// nothing makes the turn `no_sources`, and the answer's `[E1]` still cites
/// nothing.
#[tokio::test]
async fn an_empty_retrieval_is_no_sources_whatever_the_answer_claims() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    fx.model.push(wants_tool(
        "k1",
        "search.knowledge",
        &json!({"query": "c7 no such policy exists anywhere"}),
    ));
    fx.model.push(says("Per [E1], refunds take 30 days."));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "refund policy?"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    assert_eq!(proposal_status(&fx, conversation, "k1").await, "executed");
    assert_eq!(turn["grounding"], "no_sources", "{turn}");
    assert_eq!(turn["citations"], json!([]));
    let answer = final_assistant(&history(&fx, &fx.owner_cookie, conversation).await);
    assert_eq!(answer["grounding"], "no_sources");
}

fn stored_citation(item: Uuid, heading: &[&str]) -> Value {
    json!({
        "item_id": item,
        "data_source_id": Uuid::now_v7(),
        "title": "Refund policy",
        "heading_path": heading,
        "passage": "Refunds within 30 days.",
        "truncated": false,
        "fetched_at": null,
        "stale": false,
    })
}

async fn stored_tool_call(
    fx: &Fx,
    conversation: Uuid,
    turn: Uuid,
    tid: &str,
    action: &str,
    status: &str,
    outcome: Value,
) {
    let resolved = if status == "executed" {
        "NOW()"
    } else {
        "NULL"
    };
    sqlx::query(&format!(
        "INSERT INTO ai_tool_call \
            (conversation_id, turn_id, tool_call_id, action_id, arguments, arguments_hash, \
             status, outcome, initiator, resolved_at) \
         VALUES ($1, $2, $3, $4, '{{}}'::jsonb, 'h', $5, $6, 1, {resolved})"
    ))
    .bind(conversation)
    .bind(turn)
    .bind(tid)
    .bind(action)
    .bind(status)
    .bind(outcome)
    .execute(fx.db())
    .await
    .expect("store a tool call");
}

/// **Row A-56, `sourced`: provenance, not filtering.** The citations are
/// exactly those of the turn's **executed** knowledge outcomes, in order and
/// de-duplicated. A non-knowledge action's output, an unexecuted knowledge
/// proposal and the answer's own `[E…]` text contribute nothing. (The
/// executed rows are stored directly: a published corpus is C8's.)
#[tokio::test]
async fn citations_come_only_from_executed_knowledge_outcomes() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    fx.model.push(says("See [E1] and [E7]."));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "refund policy?"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    let turn_id = Uuid::parse_str(turn["turn_id"].as_str().unwrap()).unwrap();

    let (a, b, unrelated) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    stored_tool_call(
        &fx,
        conversation,
        turn_id,
        "s1",
        "search.knowledge",
        "executed",
        json!({"passages": [stored_citation(a, &["Scope"]), stored_citation(b, &[])],
               "abstained": false}),
    )
    .await;
    stored_tool_call(
        &fx,
        conversation,
        turn_id,
        "s2",
        "knowledge.answer",
        "executed",
        json!({"status": "answered", "answer": "x",
               "citations": [stored_citation(a, &["Scope"])]}),
    )
    .await;
    stored_tool_call(
        &fx,
        conversation,
        turn_id,
        "s3",
        "record.get",
        "executed",
        json!({"passages": [stored_citation(unrelated, &[])]}),
    )
    .await;
    stored_tool_call(
        &fx,
        conversation,
        turn_id,
        "s4",
        "search.knowledge",
        "proposed",
        json!({"passages": [stored_citation(unrelated, &[])]}),
    )
    .await;

    let answer = final_assistant(&history(&fx, &fx.owner_cookie, conversation).await);
    assert_eq!(answer["grounding"], "sourced", "{answer}");
    let cited: Vec<Value> = answer["citations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["item_id"].clone())
        .collect();
    assert_eq!(
        cited,
        vec![json!(a), json!(b)],
        "ordered, de-duplicated, executed only"
    );
    let keys: std::collections::BTreeSet<&str> = answer["citations"][0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "data_source_id",
            "fetched_at",
            "heading_path",
            "item_id",
            "stale",
            "title",
            "truncated"
        ]
        .into_iter()
        .collect(),
        "the CitationView contract, not the stored JSON"
    );
}

/// The tool-call projection: exactly the nine allow-listed fields, the
/// stored arguments for display, and the conversation-owner boundary (I-20).
#[tokio::test]
async fn tool_calls_are_an_allow_listed_owner_only_projection() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    let hash = propose(&fx, conversation, "p1", &entity, record).await;
    let uri = format!("/api/v1/ai/conversations/{conversation}/tool-calls");

    let (status, body) = send(&fx.app, "GET", &uri, Some(&fx.owner_cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["total"], json!(1));
    let item = &body["items"][0];
    let keys: std::collections::BTreeSet<&str> = item
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "action_id",
            "approval_request_id",
            "arguments",
            "arguments_hash",
            "created_at",
            "resolved_at",
            "status",
            "tool_call_id",
            "turn_id",
        ]
        .into_iter()
        .collect(),
        "no outcome, lease, gate decision or row version: {item}"
    );
    assert_eq!(item["arguments_hash"], json!(hash));
    assert_eq!(item["arguments"]["value"], json!("closed"));
    assert_eq!(item["status"], json!("proposed"));

    let (_, stranger) = seed_user(fx.db(), true).await;
    let (status, _) = send(&fx.app, "GET", &uri, Some(&stranger), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another user's conversation");
    let (status, _) = send(&fx.app, "GET", &uri, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A conversation owned by `user`, created directly (the start route's own
/// privilege is not what these tests measure; `turn::run` reads its model
/// from configuration, not the definition).
async fn conversation_for(fx: &Fx, user: Uuid) -> Uuid {
    let session = attome_ai::session::start(
        fx.db(),
        &attome_audit::audit_service(&fx.state),
        attome_ai::session::SessionStart {
            owner_user_id: user,
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
    attome_ai::conversation::create(
        fx.db(),
        attome_ai::conversation::NewConversation {
            agent_session_id: session.id,
            owner_user_id: user,
            agent_definition_ref: None,
            surface: attome_ai::conversation::Surface::Internal,
            title: None,
        },
    )
    .await
    .expect("conversation")
    .id
}

/// A record whose `status` is a unique marker, so any disclosure of it shows.
async fn secret_record(fx: &Fx) -> (String, Uuid, String) {
    let (entity, record) = writable_record(fx).await;
    let marker = format!("secret-{}", Uuid::now_v7().simple());
    let table = attome_core::quote_ident(&entity);
    sqlx::query(&format!("UPDATE {table} SET status = $1 WHERE id = $2"))
        .bind(&marker)
        .bind(record)
        .execute(fx.db())
        .await
        .expect("mark the record");
    (entity, record, marker)
}

/// Sends `record.get` on the context record through a turn; returns the
/// turn's HTTP status and the whole stored transcript as text.
async fn ask_about(
    fx: &Fx,
    cookie: &str,
    conversation: Uuid,
    entity: &str,
    record: Uuid,
) -> String {
    fx.model.push(wants_tool(
        "g1",
        "record.get",
        &json!({"entity": entity, "record_id": record}),
    ));
    fx.model.push(says("Done."));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(cookie),
        Some(json!({"text": "what is this record?",
                    "context": {"entity": entity, "record_id": record}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the context is accepted: {turn}");
    history(fx, cookie, conversation)
        .await
        .iter()
        .map(|m| m["content"].as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

/// **Row A-66.** A caller sends the id of a record they cannot read as
/// context. The message is accepted and stored with the context as one fixed
/// line; the server does not read the record for it; and when the model then
/// calls `record.get` on it, the ordinary action path refuses — the record's
/// data appears nowhere in the transcript. Control: the same flow for a
/// caller who **can** read it discloses the marker, so the test can see a
/// disclosure when there is one.
#[tokio::test]
async fn record_context_is_a_navigation_hint_never_authorization() {
    let fx = skip_if_no_db!(fixture().await);
    let (entity, record, marker) = secret_record(&fx).await;

    let (reader_less, cookie) = seed_user(fx.db(), false).await;
    let conversation = conversation_for(&fx, reader_less).await;
    let transcript = ask_about(&fx, &cookie, conversation, &entity, record).await;
    assert!(
        transcript.starts_with(&format!(
            "[record context: entity={entity} record_id={record}]\n\nwhat is this record?"
        )),
        "the context is stored as the fixed line: {transcript}"
    );
    assert!(
        !transcript.contains(&marker),
        "the unreadable record's data must appear nowhere: {transcript}"
    );
    assert_ne!(
        proposal_status(&fx, conversation, "g1").await,
        "executed",
        "record.get was refused by the ordinary action path"
    );

    // Control: a caller who can read it.
    let control = conversation_for(&fx, fx.owner).await;
    let transcript = ask_about(&fx, &fx.owner_cookie, control, &entity, record).await;
    assert!(
        transcript.contains(&marker),
        "control: a permitted record.get discloses it: {transcript}"
    );
}

/// Malformed record context is refused before anything is written, and an
/// unknown field inside it too.
#[tokio::test]
async fn malformed_record_context_is_refused_and_writes_nothing() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    for context in [
        json!({"entity": "Bad Name", "record_id": Uuid::now_v7()}),
        json!({"entity": "contact", "record_id": "not-a-uuid"}),
        json!({"entity": "contact", "record_id": Uuid::now_v7(), "grant": "system.admin"}),
    ] {
        let (status, body) = send(
            &fx.app,
            "POST",
            &messages_uri(conversation),
            Some(&fx.owner_cookie),
            Some(json!({"text": "hi", "context": context})),
        )
        .await;
        assert!(
            status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST,
            "{context}: {status} {body}"
        );
    }
    assert!(
        history(&fx, &fx.owner_cookie, conversation)
            .await
            .is_empty()
    );
}

/// **Regression (C7 browser pass).** A `RequiresKey` business write is offered
/// to the chat model and reaches the confirmation step. The tool list was once
/// built from a key-less context, so the gate's retry-safety refusal hid every
/// `RequiresKey` action and the model's `record.update` came back as "that tool
/// does not exist or is not available to you".
#[tokio::test]
async fn a_requires_key_write_is_offered_to_the_model_and_awaits_confirmation() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    fx.model.push(wants_tool(
        "u1",
        "record.update",
        &json!({"entity": entity, "record_id": record, "values": {"status": "closed"}, "row_version": 0}),
    ));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "close it"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    assert_eq!(turn["terminal_state"], "awaiting_confirmation", "{turn}");
    assert_eq!(turn["pending"]["kind"], "confirmation", "{turn}");
    assert_eq!(turn["pending"]["action_id"], "record.update", "{turn}");
    assert_eq!(proposal_status(&fx, conversation, "u1").await, "proposed");
    assert_eq!(
        business_row_version(&fx, &entity, record).await,
        0,
        "nothing written yet"
    );
}

// ---------------------------------------------------------------------------
// C8 — retrieval_mode end to end (D-561 §5)
// ---------------------------------------------------------------------------

/// A published article the fixture's (administrator) owner can read, in the
/// knowledge entities as the real `attome-webcrawl` platform bundle defines them.
async fn knowledge_article(fx: &Fx, marker: &str) -> Uuid {
    attome_api::bundle::apply_platform_bundle(
        &fx.state,
        "attome-webcrawl",
        include_str!("../../../../platform-bundles/attome-webcrawl.json"),
    )
    .await
    .expect("apply the knowledge bundle");
    let source = Uuid::now_v7();
    sqlx::query("INSERT INTO knowledge_data_source (id, name, is_active) VALUES ($1, $2, TRUE)")
        .bind(source)
        .bind(format!("KB {marker}"))
        .execute(fx.db())
        .await
        .expect("source");
    let item = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO knowledge_data_item (id, title, text, data_source_ref, lifecycle, is_active) \
         VALUES ($1, 'Refund policy', $2, $3, 'published', TRUE)",
    )
    .bind(item)
    .bind(format!(
        "# Refunds\n\nThe {marker} refund policy: refunds within thirty days."
    ))
    .bind(source)
    .execute(fx.db())
    .await
    .expect("article");
    attome_search::reindex_item(fx.db(), item)
        .await
        .expect("reindex");
    item
}

async fn start_from(fx: &Fx, definition: Uuid) -> Uuid {
    let (status, body) = send(
        &fx.app,
        "POST",
        "/api/v1/ai/conversations",
        Some(&fx.owner_cookie),
        Some(json!({"agent_definition_id": definition, "risk_ceiling": "reversible"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    Uuid::parse_str(body["conversation"]["id"].as_str().unwrap()).unwrap()
}

async fn ask(fx: &Fx, conversation: Uuid, text: &str) -> Value {
    fx.model.push(says("answered"));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": text})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    turn
}

async fn pre_retrieval_count(fx: &Fx, conversation: Uuid) -> usize {
    let (status, body) = send(
        &fx.app,
        "GET",
        &format!("/api/v1/ai/conversations/{conversation}/tool-calls"),
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["tool_call_id"]
                .as_str()
                .unwrap_or("")
                .starts_with("pre_retrieval_")
                && c["action_id"] == "search.knowledge"
                && c["status"] == "executed"
        })
        .count()
}

/// **D-561 §5, end to end over HTTP.** A definition set to `pre_retrieved`
/// starts a conversation whose every turn retrieves before the model is asked
/// — visible as an executed `search.knowledge` call and a `sourced` answer
/// citing the article (C7). Editing the definition to `tool_invoked` does not
/// reach that conversation's next turn; a conversation started after the edit
/// resolves the new mode and retrieves nothing up front.
#[tokio::test]
async fn retrieval_mode_holds_for_a_conversations_life_and_a_new_one_takes_the_edit() {
    let fx = skip_if_no_db!(fixture().await);
    let marker = format!("kbmarker{}", Uuid::now_v7().simple());
    let item = knowledge_article(&fx, &marker).await;
    let definition = agent_definition(fx.db()).await;
    sqlx::query("UPDATE ai_agent SET retrieval_mode = 'pre_retrieved' WHERE id = $1")
        .bind(definition)
        .execute(fx.db())
        .await
        .expect("pre_retrieved definition");

    let conversation = start_from(&fx, definition).await;
    for n in 1..=2 {
        let turn = ask(
            &fx,
            conversation,
            &format!("what is the {marker} refund policy?"),
        )
        .await;
        assert_eq!(turn["grounding"], "sourced", "turn {n}: {turn}");
        assert!(
            turn["citations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["item_id"] == json!(item)),
            "turn {n} cites the pre-retrieved article: {turn}"
        );
    }
    assert_eq!(pre_retrieval_count(&fx, conversation).await, 2);

    sqlx::query("UPDATE ai_agent SET retrieval_mode = 'tool_invoked' WHERE id = $1")
        .bind(definition)
        .execute(fx.db())
        .await
        .expect("edit the definition");
    let third = ask(
        &fx,
        conversation,
        &format!("and the {marker} refund policy again?"),
    )
    .await;
    assert_eq!(
        third["grounding"], "sourced",
        "the running conversation keeps its mode: {third}"
    );
    assert_eq!(pre_retrieval_count(&fx, conversation).await, 3);

    let fresh = start_from(&fx, definition).await;
    let turn = ask(&fx, fresh, &format!("what is the {marker} refund policy?")).await;
    assert_eq!(
        turn["grounding"], "none",
        "a new conversation takes the edited mode: {turn}"
    );
    assert_eq!(pre_retrieval_count(&fx, fresh).await, 0);
}

/// No client input selects the mode: the send route has no such field and
/// refuses one.
#[tokio::test]
async fn a_client_cannot_send_a_retrieval_mode() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (status, body) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "hi", "retrieval_mode": "tool_invoked"})),
    )
    .await;
    assert!(
        status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST,
        "{status} {body}"
    );
    assert!(
        history(&fx, &fx.owner_cookie, conversation)
            .await
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// C8 — the operator surface: the session's stored mode
// ---------------------------------------------------------------------------

/// The supervisor's session row for `session`, from the first page.
async fn supervised(fx: &Fx, session: Uuid) -> Value {
    let (status, body) = send(
        &fx.app,
        "GET",
        "/api/v1/admin/agents/sessions?page=1&page_size=200",
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == json!(session))
        .cloned()
        .unwrap_or_else(|| panic!("session {session} is not on the first page"))
}

/// **Configured vs stored (D-561 §5).** The supervisor list shows the mode the
/// session uses — stored at start — beside the mode its definition holds now.
/// After the definition is edited the two differ: the session keeps its own,
/// and the list says so rather than implying the edit reached it.
#[tokio::test]
async fn the_supervisor_shows_the_stored_mode_beside_the_configured_one() {
    let fx = skip_if_no_db!(fixture().await);
    let definition = agent_definition(fx.db()).await;
    sqlx::query("UPDATE ai_agent SET retrieval_mode = 'pre_retrieved' WHERE id = $1")
        .bind(definition)
        .execute(fx.db())
        .await
        .expect("pre_retrieved definition");
    let (status, body) = send(
        &fx.app,
        "POST",
        "/api/v1/ai/conversations",
        Some(&fx.owner_cookie),
        Some(json!({"agent_definition_id": definition, "risk_ceiling": "reversible"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start: {body}");
    let session =
        Uuid::parse_str(body["conversation"]["agent_session_id"].as_str().unwrap()).unwrap();

    let row = supervised(&fx, session).await;
    assert_eq!(row["retrieval_mode"], "pre_retrieved", "{row}");
    assert_eq!(row["agent_retrieval_mode"], "pre_retrieved", "{row}");

    sqlx::query("UPDATE ai_agent SET retrieval_mode = 'tool_invoked' WHERE id = $1")
        .bind(definition)
        .execute(fx.db())
        .await
        .expect("edit the definition");
    let row = supervised(&fx, session).await;
    assert_eq!(
        row["retrieval_mode"], "pre_retrieved",
        "the session keeps its own: {row}"
    );
    assert_eq!(
        row["agent_retrieval_mode"], "tool_invoked",
        "the definition now: {row}"
    );

    let (_, plain_session) = fx.start("reversible").await;
    let row = supervised(&fx, plain_session).await;
    assert_eq!(row["retrieval_mode"], "tool_invoked", "{row}");
}

// ---------------------------------------------------------------------------
// C9 B1 — the widget session: a configured definition, clamped (D-558)
// ---------------------------------------------------------------------------

fn widget_config(definition: Uuid) -> attome_config::WebchatSection {
    attome_config::WebchatSection {
        enabled: true,
        agent_definition_id: Some(definition),
        session_token_cap: Some(10_000),
        daily_token_cap: Some(50_000),
        deployment_daily_token_cap: Some(100_000),
    }
}

/// Sets the definition's policy: its ceiling, allow-list and knowledge scope
/// (`None` = the column NULL, i.e. no explicit scope).
async fn set_widget_policy(fx: &Fx, definition: Uuid, allowed: &[&str], scope: Option<&str>) {
    let policy: Uuid = sqlx::query_scalar("SELECT policy_ref FROM ai_agent WHERE id = $1")
        .bind(definition)
        .fetch_one(fx.db())
        .await
        .expect("policy_ref");
    sqlx::query(
        "UPDATE ai_agent_policy SET risk_ceiling = 'consequential', \
                allowed_action_ids = $2, knowledge_source_refs = $3, \
                max_tokens_per_session = 50000, row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(policy)
    .bind(
        allowed
            .iter()
            .map(|a| (*a).to_owned())
            .collect::<Vec<String>>(),
    )
    .bind(scope)
    .execute(fx.db())
    .await
    .expect("set the policy");
}

async fn sessions_from(fx: &Fx, definition: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM agent_session WHERE agent_definition_ref = $1")
        .bind(definition)
        .fetch_one(fx.db())
        .await
        .expect("count")
}

/// **Rows A-68 and A-39, and C9 invariant 1, against a real definition.** The
/// definition grants `query.execute`, a write and a `consequential` ceiling;
/// the widget session holds exactly `search.knowledge` + `bot.handoff` at
/// `Reversible`, the policy's explicit scope, the lower token limit, and reads
/// back from its row as an anonymous channel session.
#[tokio::test]
async fn the_widget_session_is_the_definitions_policy_clamped() {
    let fx = skip_if_no_db!(fixture().await);
    let definition = agent_definition(fx.db()).await;
    let collection = Uuid::now_v7();
    set_widget_policy(
        &fx,
        definition,
        &["search.knowledge", "query.execute", "record.update"],
        Some(&format!("[\"{collection}\"]")),
    )
    .await;
    let principal = fx
        .state
        .base
        .security
        .resolve(fx.owner)
        .await
        .expect("principal");

    let session = attome_ai::webchat::start_session_with(
        &fx.state,
        &principal,
        &widget_config(definition),
        Uuid::now_v7(),
    )
    .await
    .expect("start");
    assert_eq!(session.risk_ceiling, attome_ai::RiskTier::Reversible);
    assert_eq!(
        session.allowed_action_ids,
        Some(vec![
            "search.knowledge".to_owned(),
            "bot.handoff".to_owned()
        ])
    );
    assert_eq!(session.policy.knowledge_source_refs, Some(vec![collection]));
    assert_eq!(session.policy.max_tokens_per_session, Some(10_000));

    let stored = attome_ai::session::load_live(fx.db(), session.id)
        .await
        .expect("load")
        .expect("live");
    assert!(
        stored.anonymous_channel,
        "derived from the row, not a request"
    );
    assert_eq!(stored.allowed_action_ids, session.allowed_action_ids);
    for refused in ["query.execute", "record.update", "record.delete"] {
        assert!(
            !stored.permits(attome_ai::descriptor::ActionId(refused)),
            "{refused} must be outside the widget's allow-list"
        );
    }
}

/// **C9 invariant 1.** A policy with no explicit knowledge scope refuses the
/// widget session — it never falls back to every collection the service
/// principal can read — and nothing is started.
#[tokio::test]
async fn a_widget_policy_without_an_explicit_scope_starts_nothing() {
    let fx = skip_if_no_db!(fixture().await);
    let definition = agent_definition(fx.db()).await;
    set_widget_policy(&fx, definition, &["search.knowledge"], None).await;
    let principal = fx
        .state
        .base
        .security
        .resolve(fx.owner)
        .await
        .expect("principal");

    let refused = attome_ai::webchat::start_session_with(
        &fx.state,
        &principal,
        &widget_config(definition),
        Uuid::now_v7(),
    )
    .await;
    assert!(
        matches!(refused, Err(attome_types::AppError::Validation(_))),
        "{refused:?}"
    );
    assert_eq!(sessions_from(&fx, definition).await, 0);
}

/// An empty scope is no knowledge: the session holds the handoff alone and an
/// empty scope, never "all".
#[tokio::test]
async fn an_empty_widget_scope_is_no_knowledge() {
    let fx = skip_if_no_db!(fixture().await);
    let definition = agent_definition(fx.db()).await;
    set_widget_policy(
        &fx,
        definition,
        &["search.knowledge", "knowledge.answer"],
        Some("[]"),
    )
    .await;
    let principal = fx
        .state
        .base
        .security
        .resolve(fx.owner)
        .await
        .expect("principal");

    let session = attome_ai::webchat::start_session_with(
        &fx.state,
        &principal,
        &widget_config(definition),
        Uuid::now_v7(),
    )
    .await
    .expect("start");
    assert_eq!(
        session.allowed_action_ids,
        Some(vec!["bot.handoff".to_owned()])
    );
    assert_eq!(session.policy.knowledge_source_refs, Some(vec![]));
}

/// Disabled starts nothing, whatever else is configured.
#[tokio::test]
async fn a_disabled_widget_starts_no_governed_session() {
    let fx = skip_if_no_db!(fixture().await);
    let definition = agent_definition(fx.db()).await;
    set_widget_policy(&fx, definition, &["search.knowledge"], Some("[]")).await;
    let principal = fx
        .state
        .base
        .security
        .resolve(fx.owner)
        .await
        .expect("principal");

    let disabled = attome_ai::webchat::start_session_with(
        &fx.state,
        &principal,
        &attome_config::WebchatSection {
            enabled: false,
            ..widget_config(definition)
        },
        Uuid::now_v7(),
    )
    .await;
    assert!(
        matches!(
            disabled,
            Err(attome_types::AppError::CapabilityUnavailable(_))
        ),
        "{disabled:?}"
    );
    assert_eq!(sessions_from(&fx, definition).await, 0);
}

// ---------------------------------------------------------------------------
// C10-A — the conversation stream (I-14, rows A-12 and A-65's /stream half)
// ---------------------------------------------------------------------------

fn stream_uri(conversation: Uuid, after: Option<i64>) -> String {
    match after {
        Some(after) => format!("/api/v1/ai/conversations/{conversation}/stream?after={after}"),
        None => format!("/api/v1/ai/conversations/{conversation}/stream"),
    }
}

/// Opens the stream and reads frames until `want` have arrived or `wait`
/// passes. Returns the status, the content type and each frame's parsed
/// `data`, checking every frame's
/// SSE `id` and `event` agree with it. The connection is dropped on return —
/// a client disconnecting.
async fn stream_frames(
    app: &Router,
    cookie: Option<&str>,
    uri: &str,
    last_event_id: Option<i64>,
    want: usize,
    wait: std::time::Duration,
) -> (StatusCode, Option<String>, Vec<Value>) {
    let (status, content_type, frames, _) =
        stream_with_deltas(app, cookie, uri, last_event_id, want, wait).await;
    (status, content_type, frames)
}

/// [`stream_frames`], also returning the `message.delta` frames seen before
/// `want` durable frames arrived (C11 B3). A delta frame must carry **no**
/// SSE `id` — asserted here for every one, so no test can pass while a delta
/// moves the client's cursor (I-14, A-78).
async fn stream_with_deltas(
    app: &Router,
    cookie: Option<&str>,
    uri: &str,
    last_event_id: Option<i64>,
    want: usize,
    wait: std::time::Duration,
) -> (StatusCode, Option<String>, Vec<Value>, Vec<Value>) {
    use futures_util::StreamExt;
    let mut req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("origin", ORIGIN)
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    if let Some(id) = last_event_id {
        req = req.header("last-event-id", id.to_string());
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if status != StatusCode::OK {
        return (status, content_type, Vec::new(), Vec::new());
    }
    let mut body = resp.into_body().into_data_stream();
    let deadline = tokio::time::Instant::now() + wait;
    let mut buffer = String::new();
    let mut frames = Vec::new();
    let mut deltas = Vec::new();
    while frames.len() < want {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let Ok(Some(chunk)) = tokio::time::timeout(remaining, body.next()).await else {
            break;
        };
        buffer.push_str(&String::from_utf8_lossy(&chunk.expect("stream chunk")));
        while let Some(end) = buffer.find("\n\n") {
            let raw: String = buffer.drain(..end + 2).collect();
            let (mut id, mut event, mut data) = (None, None, None);
            for line in raw.lines() {
                if let Some(v) = line.strip_prefix("id:") {
                    id = Some(v.trim().to_owned());
                } else if let Some(v) = line.strip_prefix("event:") {
                    event = Some(v.trim().to_owned());
                } else if let Some(v) = line.strip_prefix("data:") {
                    data = Some(v.trim().to_owned());
                }
            }
            let Some(data) = data else { continue }; // a keep-alive comment
            let frame: Value = serde_json::from_str(&data).expect("frame data is JSON");
            if event.as_deref() == Some("message.delta") {
                assert_eq!(id, None, "a delta carries no cursor: {raw}");
                deltas.push(frame);
                continue;
            }
            assert_eq!(
                id,
                Some(frame["ordinal"].to_string()),
                "SSE id is the ordinal"
            );
            assert_eq!(
                event.as_deref(),
                frame["type"].as_str(),
                "SSE event is the type"
            );
            frames.push(frame);
            if frames.len() >= want {
                break;
            }
        }
    }
    (status, content_type, frames, deltas)
}

fn types(frames: &[Value]) -> Vec<String> {
    frames
        .iter()
        .map(|f| f["type"].as_str().unwrap().to_owned())
        .collect()
}

fn ordinals(frames: &[Value]) -> Vec<i64> {
    frames
        .iter()
        .map(|f| f["ordinal"].as_i64().unwrap())
        .collect()
}

async fn event_count(fx: &Fx, conversation: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM ai_conversation_event WHERE conversation_id = $1")
        .bind(conversation)
        .fetch_one(fx.db())
        .await
        .expect("count events")
}

const STREAM_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// A turn that proposes `record.update` and stops for confirmation. Returns
/// the displayed hash.
async fn turn_awaiting_confirmation(
    fx: &Fx,
    conversation: Uuid,
    tid: &str,
    entity: &str,
    record: Uuid,
) -> String {
    fx.model.push(wants_tool(
        tid,
        "record.update",
        &json!({"entity": entity, "record_id": record, "values": {"status": "closed"}, "row_version": 0}),
    ));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "close it"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    assert_eq!(turn["terminal_state"], "awaiting_confirmation", "{turn}");
    turn["pending"]["arguments_hash"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// **E5 — a confirmation cycle replays in order.** The turn's events, then the
/// confirm's, each exactly once and contiguous from 1.
#[tokio::test]
async fn a_confirmation_cycle_replays_in_order() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    let hash = turn_awaiting_confirmation(&fx, conversation, "c1", &entity, record).await;
    let (status, confirmed) = send(
        &fx.app,
        "POST",
        &confirm_uri(conversation, "c1"),
        Some(&fx.owner_cookie),
        Some(json!({"arguments_hash": hash})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");

    let (status, content_type, frames) = stream_frames(
        &fx.app,
        Some(&fx.owner_cookie),
        &stream_uri(conversation, None),
        None,
        6,
        STREAM_WAIT,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        content_type
            .unwrap_or_default()
            .starts_with("text/event-stream")
    );
    assert_eq!(
        types(&frames),
        [
            "turn.started",
            "tool.call.proposed",
            "message.completed",
            "turn.completed",
            "tool.call.started",
            "tool.call.completed",
        ],
        "{frames:?}"
    );
    assert_eq!(ordinals(&frames), (1..=6).collect::<Vec<_>>());
    assert_eq!(
        frames[3]["payload"]["terminal_state"],
        "awaiting_confirmation"
    );
    assert_eq!(frames[1]["payload"]["tool_call_id"], "c1");
    assert_eq!(frames[1]["payload"]["arguments_hash"], json!(hash));
    assert_eq!(
        event_count(&fx, conversation).await,
        6,
        "nothing else was recorded"
    );
}

/// **E1 — row A-12.** A client reads the first two events, disconnects, the
/// conversation carries on (the confirm, then a second turn), and the client
/// reconnects with its last ordinal via `Last-Event-ID`: it receives exactly
/// the events it missed, contiguous, and together they equal the full log.
#[tokio::test]
async fn a_reconnect_from_the_last_ordinal_misses_no_semantic_event() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    let hash = turn_awaiting_confirmation(&fx, conversation, "c2", &entity, record).await;

    let (_, _, first) = stream_frames(
        &fx.app,
        Some(&fx.owner_cookie),
        &stream_uri(conversation, None),
        None,
        2,
        STREAM_WAIT,
    )
    .await;
    assert_eq!(ordinals(&first), [1, 2]);

    let (status, _) = send(
        &fx.app,
        "POST",
        &confirm_uri(conversation, "c2"),
        Some(&fx.owner_cookie),
        Some(json!({"arguments_hash": hash})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    fx.model.push(says("All done."));
    let (status, _) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "thanks"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let total = event_count(&fx, conversation).await as usize;
    let (_, _, rest) = stream_frames(
        &fx.app,
        Some(&fx.owner_cookie),
        &stream_uri(conversation, None),
        Some(2),
        total - 2,
        STREAM_WAIT,
    )
    .await;
    assert_eq!(
        ordinals(&rest),
        (3..=total as i64).collect::<Vec<_>>(),
        "exactly what was missed"
    );
    let (_, _, all) = stream_frames(
        &fx.app,
        Some(&fx.owner_cookie),
        &stream_uri(conversation, Some(0)),
        None,
        total,
        STREAM_WAIT,
    )
    .await;
    let mut joined = first.clone();
    joined.extend(rest);
    assert_eq!(joined, all, "the two halves are the whole log");
    assert_eq!(
        types(&all).last().map(String::as_str),
        Some("turn.completed"),
        "the turn's state is unambiguous from the log alone"
    );
}

/// **E3 — replay hands over to live without a gap or a duplicate.** A stream
/// opened at the current end receives the next turn's events as they commit,
/// contiguous from `last + 1`.
#[tokio::test]
async fn a_stream_at_the_end_follows_the_next_turn() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    fx.model.push(says("First."));
    send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "one"})),
    )
    .await;
    let last = event_count(&fx, conversation).await;

    let app = fx.app.clone();
    let cookie = fx.owner_cookie.clone();
    let follower = tokio::spawn(async move {
        stream_frames(
            &app,
            Some(&cookie),
            &stream_uri(conversation, Some(last)),
            None,
            3,
            std::time::Duration::from_secs(10),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    fx.model.push(says("Second."));
    let (status, _) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "two"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, _, live) = follower.await.expect("follower");
    assert_eq!(
        ordinals(&live),
        (last + 1..=last + 3).collect::<Vec<_>>(),
        "contiguous from the cursor: {live:?}"
    );
    assert_eq!(
        types(&live),
        ["turn.started", "message.completed", "turn.completed"]
    );
}

/// **E4 — row A-65's `/stream` half (I-20).** Authorization happens before the
/// first frame: another user's conversation and an unknown one are a plain
/// 404 — not an event stream — and no credentials is 401.
#[tokio::test]
async fn the_stream_is_authorized_before_the_first_frame() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (_, stranger) = seed_user(fx.db(), true).await;
    for (cookie, uri, expected) in [
        (
            Some(stranger.as_str()),
            stream_uri(conversation, None),
            StatusCode::NOT_FOUND,
        ),
        (
            Some(fx.owner_cookie.as_str()),
            stream_uri(Uuid::now_v7(), None),
            StatusCode::NOT_FOUND,
        ),
        (
            None,
            stream_uri(conversation, None),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let (status, content_type, frames) =
            stream_frames(&fx.app, cookie, &uri, None, 1, STREAM_WAIT).await;
        assert_eq!(status, expected, "{uri}");
        assert!(
            !content_type
                .unwrap_or_default()
                .starts_with("text/event-stream"),
            "{uri}: no stream was started"
        );
        assert!(frames.is_empty());
    }
}

/// **E6 — one history.** A `message.completed` frame carries the message text
/// read from the ledger; the stored event holds only the ordinal.
#[tokio::test]
async fn message_content_comes_from_the_ledger_not_the_event() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let marker = format!("answer-{}", Uuid::now_v7().simple());
    fx.model.push(says(&marker));
    send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "hi"})),
    )
    .await;
    let (_, _, frames) = stream_frames(
        &fx.app,
        Some(&fx.owner_cookie),
        &stream_uri(conversation, None),
        None,
        3,
        STREAM_WAIT,
    )
    .await;
    let completed = frames
        .iter()
        .find(|f| f["type"] == "message.completed")
        .unwrap();
    assert_eq!(completed["content"], json!(marker));
    let stored: Value = sqlx::query_scalar(
        "SELECT payload FROM ai_conversation_event \
          WHERE conversation_id = $1 AND event_type = 'message.completed'",
    )
    .bind(conversation)
    .fetch_one(fx.db())
    .await
    .expect("stored event");
    assert_eq!(
        stored,
        json!({"message_ordinal": completed["payload"]["message_ordinal"]})
    );
    assert!(!stored.to_string().contains(&marker), "no copy of the text");
}

/// **E2 — a rolled-back change leaves no event and consumes no ordinal.** The
/// tool call's transition and its event are written in one transaction that is
/// then rolled back: the status, the log and the counter are all unchanged.
#[tokio::test]
async fn a_rolled_back_change_records_no_event() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    propose(&fx, conversation, "rb", &entity, record).await;
    let row: (Uuid, i64) = sqlx::query_as(
        "SELECT id, row_version FROM ai_tool_call WHERE conversation_id = $1 AND tool_call_id = 'rb'",
    )
    .bind(conversation)
    .fetch_one(fx.db())
    .await
    .unwrap();
    let before_events = event_count(&fx, conversation).await;
    let before_counter: i64 =
        sqlx::query_scalar("SELECT last_event_ordinal FROM ai_conversation WHERE id = $1")
            .bind(conversation)
            .fetch_one(fx.db())
            .await
            .unwrap();

    let mut tx = fx.db().begin().await.unwrap();
    let moved = attome_ai::tool_call::resolve_in(
        &mut tx,
        row.0,
        row.1,
        attome_ai::tool_call::Status::Rejected,
        None,
    )
    .await
    .expect("resolve in tx");
    assert!(moved);
    tx.rollback().await.unwrap();

    assert_eq!(proposal_status(&fx, conversation, "rb").await, "proposed");
    assert_eq!(event_count(&fx, conversation).await, before_events);
    let after_counter: i64 =
        sqlx::query_scalar("SELECT last_event_ordinal FROM ai_conversation WHERE id = $1")
            .bind(conversation)
            .fetch_one(fx.db())
            .await
            .unwrap();
    assert_eq!(after_counter, before_counter, "no ordinal consumed");
}

/// **E8 — message ordinals keep their meaning.** With events interleaved, the
/// messages are still numbered 1..m without a gap, and the events 1..n.
#[tokio::test]
async fn message_ordinals_stay_gapless_beside_events() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let (entity, record) = writable_record(&fx).await;
    turn_awaiting_confirmation(&fx, conversation, "g1", &entity, record).await;
    fx.model.push(says("ok"));
    send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "again"})),
    )
    .await;
    let messages: Vec<i64> = sqlx::query_scalar(
        "SELECT ordinal FROM ai_message WHERE conversation_id = $1 ORDER BY ordinal",
    )
    .bind(conversation)
    .fetch_all(fx.db())
    .await
    .unwrap();
    let events: Vec<i64> = sqlx::query_scalar(
        "SELECT ordinal FROM ai_conversation_event WHERE conversation_id = $1 ORDER BY ordinal",
    )
    .bind(conversation)
    .fetch_all(fx.db())
    .await
    .unwrap();
    assert_eq!(messages, (1..=messages.len() as i64).collect::<Vec<_>>());
    assert_eq!(events, (1..=events.len() as i64).collect::<Vec<_>>());
}

async fn approval_events(fx: &Fx, conversation: Uuid) -> Vec<(i64, String, Value)> {
    sqlx::query_as(
        "SELECT ordinal, event_type, payload FROM ai_conversation_event \
          WHERE conversation_id = $1 ORDER BY ordinal",
    )
    .bind(conversation)
    .fetch_all(fx.db())
    .await
    .unwrap()
}

/// **E7 — an approval resolves in its own transaction.** A turn's
/// `Consequential` action raises an approval (`approval.required`). An
/// approver approves: `approval.resolved{approved}` then, as it runs,
/// `tool.call.completed`. Recovery afterwards finds nothing to add.
#[tokio::test]
async fn an_approved_action_resolves_and_completes_its_tool_call() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("consequential").await;
    let target = target_session(&fx).await;
    let approval = approval_from_a_turn(&fx, conversation, target).await;
    let (_, approver) = seed_user(fx.db(), true).await;
    assert_eq!(approve(&fx, &approver, approval).await, StatusCode::OK);
    assert!(paused(&fx, target).await, "the approved action ran");

    let events = approval_events(&fx, conversation).await;
    let kinds: Vec<&str> = events.iter().map(|e| e.1.as_str()).collect();
    let required = kinds
        .iter()
        .position(|k| *k == "approval.required")
        .expect("required");
    let resolved = kinds
        .iter()
        .position(|k| *k == "approval.resolved")
        .expect("resolved");
    let completed = kinds
        .iter()
        .position(|k| *k == "tool.call.completed")
        .expect("completed");
    assert!(required < resolved && resolved < completed, "{kinds:?}");
    assert_eq!(events[resolved].2["decision"], "approved");
    assert_eq!(events[resolved].2["approval_request_id"], json!(approval));
    assert_eq!(
        kinds.iter().filter(|k| **k == "approval.resolved").count(),
        1
    );
    assert_eq!(
        proposal_status(&fx, conversation, "pause1").await,
        "executed"
    );

    let before = events.len();
    attome_ai::conversation_event::reconcile_approvals(fx.db())
        .await
        .unwrap();
    attome_ai::conversation_event::reconcile_approvals(fx.db())
        .await
        .unwrap();
    assert_eq!(
        approval_events(&fx, conversation).await.len(),
        before,
        "exactly once"
    );
}

/// **E7 — a rejection** is `approval.resolved{rejected}` and
/// `tool.call.failed{rejected}`, consecutive: one transaction with the
/// decision.
#[tokio::test]
async fn a_rejected_approval_fails_its_tool_call_in_the_same_transaction() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("consequential").await;
    let target = target_session(&fx).await;
    let approval = approval_from_a_turn(&fx, conversation, target).await;
    let (_, approver) = seed_user(fx.db(), true).await;
    let (status, body) = send(
        &fx.app,
        "POST",
        &format!("/api/v1/admin/approvals/{approval}/decide"),
        Some(&approver),
        Some(json!({"decision": "reject", "row_version": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!paused(&fx, target).await);

    let events = approval_events(&fx, conversation).await;
    let n = events.len();
    assert_eq!(events[n - 2].1, "approval.resolved");
    assert_eq!(events[n - 2].2["decision"], "rejected");
    assert_eq!(events[n - 1].1, "tool.call.failed");
    assert_eq!(events[n - 1].2["status"], "rejected");
    assert_eq!(
        events[n - 1].0,
        events[n - 2].0 + 1,
        "consecutive: one transaction"
    );
    assert_eq!(
        proposal_status(&fx, conversation, "pause1").await,
        "rejected"
    );
}

/// **E7 — an expiry** through the expiry sweep's transaction is
/// `approval.resolved{expired}` and `tool.call.failed{expired}`.
#[tokio::test]
async fn an_expired_approval_fails_its_tool_call() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("consequential").await;
    let target = target_session(&fx).await;
    let approval = approval_from_a_turn(&fx, conversation, target).await;
    sqlx::query(
        "UPDATE approval_request SET expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
    )
    .bind(approval)
    .execute(fx.db())
    .await
    .unwrap();
    attome_approval::sweep_expired_with(
        fx.db(),
        &attome_ai::conversation_event::ApprovalConversationHook,
    )
    .await
    .expect("expiry sweep");

    let events = approval_events(&fx, conversation).await;
    let n = events.len();
    assert_eq!(events[n - 2].1, "approval.resolved");
    assert_eq!(events[n - 2].2["decision"], "expired");
    assert_eq!(events[n - 1].1, "tool.call.failed");
    assert_eq!(events[n - 1].2["status"], "expired");
    assert_eq!(
        proposal_status(&fx, conversation, "pause1").await,
        "expired"
    );
}

/// **E7 — `approval.resolved{approved}` commits with the decision itself**, not
/// later with the execution. The conversation's session is paused, so the
/// approved action is deferred and nothing runs: the decision's transaction
/// alone must have written `approval.resolved{approved}`, while the tool call
/// is still `approval_pending` and there is no `tool.call.completed`.
#[tokio::test]
async fn an_approval_decision_records_resolved_before_anything_runs() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, session) = fx.start("consequential").await;
    let target = target_session(&fx).await;
    let approval = approval_from_a_turn(&fx, conversation, target).await;
    attome_ai::session::pause(fx.db(), session, fx.owner, "test")
        .await
        .expect("pause the conversation's session");
    let (_, approver) = seed_user(fx.db(), true).await;
    assert_eq!(
        approve(&fx, &approver, approval).await,
        StatusCode::CONFLICT,
        "deferred"
    );
    assert_eq!(approval_status(&fx, approval).await, "approved");
    assert!(!paused(&fx, target).await, "nothing ran");

    let events = approval_events(&fx, conversation).await;
    let kinds: Vec<&str> = events.iter().map(|e| e.1.as_str()).collect();
    let resolved: Vec<&(i64, String, Value)> = events
        .iter()
        .filter(|e| e.1 == "approval.resolved")
        .collect();
    assert_eq!(resolved.len(), 1, "{kinds:?}");
    assert_eq!(resolved[0].2["decision"], "approved");
    assert!(!kinds.contains(&"tool.call.completed"), "{kinds:?}");
    assert_eq!(
        proposal_status(&fx, conversation, "pause1").await,
        "approval_pending"
    );
}

/// **E7 — a withdrawal (contract amendment 2026-09-22).** The conversation's
/// owner is the request's `requested_by` and withdraws it: the cancellation's
/// own transaction writes `approval.resolved{cancelled}` and
/// `tool.call.failed{rejected}`, at consecutive ordinals, and the tool call is
/// `rejected` — never left `approval_pending`.
#[tokio::test]
async fn a_withdrawn_approval_resolves_as_cancelled() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("consequential").await;
    let target = target_session(&fx).await;
    let approval = approval_from_a_turn(&fx, conversation, target).await;
    let (status, body) = send(
        &fx.app,
        "POST",
        &format!("/api/v1/admin/approvals/{approval}/cancel"),
        Some(&fx.owner_cookie),
        Some(json!({"row_version": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(approval_status(&fx, approval).await, "cancelled");

    let events = approval_events(&fx, conversation).await;
    let n = events.len();
    assert_eq!(events[n - 2].1, "approval.resolved");
    assert_eq!(events[n - 2].2["decision"], "cancelled");
    assert_eq!(events[n - 1].1, "tool.call.failed");
    assert_eq!(events[n - 1].2["status"], "rejected");
    assert_eq!(events[n - 1].0, events[n - 2].0 + 1, "one transaction");
    assert_eq!(
        proposal_status(&fx, conversation, "pause1").await,
        "rejected"
    );
    assert!(!paused(&fx, target).await, "nothing ran");
}

/// **Concurrent writers get gapless ordinals, and a rollback consumes none.**
/// Twenty transactions write an event to one conversation at once; every
/// second one rolls back. The ten that commit hold exactly ordinals 1..10 —
/// no duplicate, no gap — and the counter stops at 10.
#[tokio::test]
async fn concurrent_writers_get_gapless_ordinals() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let before = event_count(&fx, conversation).await;
    assert_eq!(before, 0);

    let writers: Vec<_> = (0..20)
        .map(|i| {
            let db = fx.db().clone();
            tokio::spawn(async move {
                let mut tx = db.begin().await.expect("begin");
                attome_ai::conversation_event::record_in(
                    &mut tx,
                    conversation,
                    None,
                    attome_ai::conversation_event::EventType::TurnStarted,
                    json!({"message_ordinal": i}),
                )
                .await
                .expect("record");
                if i % 2 == 0 {
                    tx.commit().await.expect("commit");
                } else {
                    tx.rollback().await.expect("rollback");
                }
            })
        })
        .collect();
    for writer in writers {
        writer.await.expect("writer");
    }

    let ordinals: Vec<i64> = sqlx::query_scalar(
        "SELECT ordinal FROM ai_conversation_event WHERE conversation_id = $1 ORDER BY ordinal",
    )
    .bind(conversation)
    .fetch_all(fx.db())
    .await
    .unwrap();
    assert_eq!(
        ordinals,
        (1..=10).collect::<Vec<_>>(),
        "gapless, no duplicates"
    );
    let counter: i64 =
        sqlx::query_scalar("SELECT last_event_ordinal FROM ai_conversation WHERE id = $1")
            .bind(conversation)
            .fetch_one(fx.db())
            .await
            .unwrap();
    assert_eq!(counter, 10, "the rolled-back writers consumed nothing");
}

// ---------------------------------------------------------------------------
// C10-B — thumbs feedback and the bot analytics report
// (`01-architecture.md`, "C10-B: analytics and feedback")
// ---------------------------------------------------------------------------

fn feedback_uri(conversation: Uuid, message: Uuid) -> String {
    format!("/api/v1/ai/conversations/{conversation}/messages/{message}/feedback")
}

/// `Ai` + `Update` feedback events naming `message` as the record, on either
/// audit write path.
async fn feedback_audit_events(fx: &Fx, message: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header \
                  WHERE record_id = $1 AND event_name = 'ai_conversation.feedback') \
              + (SELECT COUNT(*) FROM audit_ingest \
                  WHERE payload->>'record_id' = $2 \
                    AND payload->>'event_name' = 'ai_conversation.feedback')",
    )
    .bind(message)
    .bind(message.to_string())
    .fetch_one(fx.db())
    .await
    .expect("count feedback audit events")
}

async fn feedback_rows(fx: &Fx, message: Uuid) -> Vec<(String, i64)> {
    sqlx::query_as("SELECT vote, row_version FROM ai_message_feedback WHERE message_id = $1")
        .bind(message)
        .fetch_all(fx.db())
        .await
        .unwrap()
}

/// A conversation with one real turn; returns `(conversation, answer, user
/// message)` ids.
async fn answered_conversation(fx: &Fx) -> (Uuid, Uuid, Uuid) {
    let (conversation, _) = fx.start("read").await;
    fx.model.push(says("Here is the answer."));
    let (status, body) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "a question"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = history(fx, &fx.owner_cookie, conversation).await;
    let answer = Uuid::parse_str(final_assistant(&items)["id"].as_str().unwrap()).unwrap();
    let question = items
        .iter()
        .find(|m| m["role"] == "user")
        .map(|m| Uuid::parse_str(m["id"].as_str().unwrap()).unwrap())
        .expect("the user's message");
    (conversation, answer, question)
}

/// **One current vote per user and answer, changed in place, every write
/// audited.** Up, then down, then down again: one row, holding `down`, updated
/// twice — never a second row — and three audit events in the writes' own
/// transactions. The transcript shows the caller's vote on the answer only.
#[tokio::test]
async fn a_vote_is_one_row_that_changes_in_place_and_is_audited() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, answer, question) = answered_conversation(&fx).await;
    assert_eq!(feedback_audit_events(&fx, answer).await, 0);

    for vote in ["up", "down", "down"] {
        let (status, body) = send(
            &fx.app,
            "PUT",
            &feedback_uri(conversation, answer),
            Some(&fx.owner_cookie),
            Some(json!({"vote": vote})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["vote"], vote);
        assert_eq!(body["message_id"], answer.to_string());
    }

    assert_eq!(
        feedback_rows(&fx, answer).await,
        vec![("down".to_owned(), 3)],
        "one row, updated in place"
    );
    assert_eq!(feedback_audit_events(&fx, answer).await, 3);

    let items = history(&fx, &fx.owner_cookie, conversation).await;
    for m in &items {
        let id = Uuid::parse_str(m["id"].as_str().unwrap()).unwrap();
        let expected = if id == answer {
            json!("down")
        } else {
            Value::Null
        };
        assert_eq!(m["feedback"], expected, "message {id}");
    }
    let _ = question;
}

/// **Owner-only, answers only, and a refused vote writes nothing.** Another
/// user's conversation and an unknown one are `404`; no credentials is `401`;
/// a message from a different conversation is `404`; a question (not an
/// answer) is `422`; a vote other than up/down, or an extra field, is `422`.
/// None of them leaves a feedback row or an audit event.
#[tokio::test]
async fn feedback_is_owner_only_answer_only_and_refusals_write_nothing() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, answer, question) = answered_conversation(&fx).await;
    let (other_conversation, other_answer, _) = answered_conversation(&fx).await;
    let (_, stranger) = seed_user(fx.db(), false).await;

    let cases: Vec<(&str, String, Option<&str>, Value, StatusCode)> = vec![
        (
            "another user",
            feedback_uri(conversation, answer),
            Some(stranger.as_str()),
            json!({"vote": "up"}),
            StatusCode::NOT_FOUND,
        ),
        (
            "unknown conversation",
            feedback_uri(Uuid::now_v7(), answer),
            Some(fx.owner_cookie.as_str()),
            json!({"vote": "up"}),
            StatusCode::NOT_FOUND,
        ),
        (
            "no credentials",
            feedback_uri(conversation, answer),
            None,
            json!({"vote": "up"}),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "a message of another conversation",
            feedback_uri(conversation, other_answer),
            Some(fx.owner_cookie.as_str()),
            json!({"vote": "up"}),
            StatusCode::NOT_FOUND,
        ),
        (
            "not an answer",
            feedback_uri(conversation, question),
            Some(fx.owner_cookie.as_str()),
            json!({"vote": "up"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "not up or down",
            feedback_uri(conversation, answer),
            Some(fx.owner_cookie.as_str()),
            json!({"vote": "sideways"}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "an extra field",
            feedback_uri(conversation, answer),
            Some(fx.owner_cookie.as_str()),
            json!({"vote": "up", "user_id": Uuid::now_v7()}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ];
    for (label, uri, cookie, body, expected) in cases {
        let (status, resp) = send(&fx.app, "PUT", &uri, cookie, Some(body)).await;
        assert_eq!(status, expected, "{label}: {resp}");
    }

    for message in [answer, question, other_answer] {
        assert!(feedback_rows(&fx, message).await.is_empty(), "{message}");
        assert_eq!(feedback_audit_events(&fx, message).await, 0, "{message}");
    }
    let _ = other_conversation;
}

// ── The analytics report ────────────────────────────────────────────────────

/// A `workflow`-surface conversation owned by the fixture's owner. No other
/// test in this binary uses that surface, so a report filtered to it over the
/// test's own window sees only what the test wrote.
async fn workflow_conversation(fx: &Fx) -> (Uuid, Uuid) {
    let session = attome_ai::session::start(
        fx.db(),
        &attome_audit::audit_service(&fx.state),
        attome_ai::session::SessionStart {
            owner_user_id: fx.owner,
            risk_ceiling: attome_ai::descriptor::RiskTier::Reversible,
            allowed_action_ids: None,
            surface: "workflow",
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: false,
            policy: attome_ai::session::PolicySnapshot::NONE,
        },
    )
    .await
    .expect("start session");
    let conversation = attome_ai::conversation::create(
        fx.db(),
        attome_ai::conversation::NewConversation {
            agent_session_id: session.id,
            owner_user_id: fx.owner,
            agent_definition_ref: None,
            surface: attome_ai::conversation::Surface::Workflow,
            title: None,
        },
    )
    .await
    .expect("conversation")
    .id;
    (conversation, session.id)
}

fn message(
    conversation: Uuid,
    turn: Uuid,
    role: attome_ai::conversation::Role,
    terminal: Option<attome_ai::conversation::TerminalState>,
) -> attome_ai::conversation::NewMessage {
    attome_ai::conversation::NewMessage {
        conversation_id: conversation,
        role,
        content: "text".into(),
        turn_id: turn,
        terminal_state: terminal,
        model_id: None,
        prompt_version: None,
        input_tokens: None,
        output_tokens: None,
    }
}

/// One turn through the ledger's own writers: the human message
/// (`turn.started`), then — when `ending` is given — the final assistant
/// message (`message.completed` + `turn.completed`). Returns `(turn, answer)`.
async fn seeded_turn(
    fx: &Fx,
    conversation: Uuid,
    ending: Option<attome_ai::conversation::TerminalState>,
) -> (Uuid, Option<Uuid>) {
    use attome_ai::conversation::Role;
    let turn = Uuid::now_v7();
    attome_ai::conversation::append_audited(
        &fx.state,
        message(conversation, turn, Role::User, None),
        fx.owner,
    )
    .await
    .expect("question");
    let answer = match ending {
        Some(state) => Some(
            attome_ai::conversation::append(
                fx.db(),
                message(conversation, turn, Role::Assistant, Some(state)),
            )
            .await
            .expect("answer")
            .id,
        ),
        None => None,
    };
    (turn, answer)
}

async fn seeded_call(
    fx: &Fx,
    conversation: Uuid,
    turn: Uuid,
    action: &str,
) -> attome_ai::tool_call::ToolCallRow {
    attome_ai::tool_call::propose(
        fx.db(),
        attome_ai::tool_call::NewToolCall {
            conversation_id: conversation,
            message_id: None,
            turn_id: turn,
            tool_call_id: Some(format!("c-{}", Uuid::now_v7().simple())),
            action_id: action.into(),
            arguments: json!({}),
            initiator_is_agent: true,
            gate_decision: None,
        },
    )
    .await
    .expect("propose")
}

/// Moves a seeded call through `statuses` the way the real paths do: a claim
/// (`tool_call::claim`, which takes the lease) for `Executing`, and a CAS'd
/// `resolve` on the last version for everything else.
async fn walk(
    fx: &Fx,
    call: &attome_ai::tool_call::ToolCallRow,
    statuses: &[attome_ai::tool_call::Status],
) {
    use attome_ai::tool_call::{Claim, Status};
    let mut version = call.row_version;
    for status in statuses {
        if *status == Status::Executing {
            match attome_ai::tool_call::claim(
                fx.db(),
                call.conversation_id,
                &call.tool_call_id,
                &call.arguments_hash,
            )
            .await
            .expect("claim")
            {
                Claim::Claimed(row) => version = row.row_version,
                _ => panic!("the seeded call could not be claimed"),
            }
            continue;
        }
        let approval = (*status == Status::ApprovalPending).then(Uuid::now_v7);
        assert!(
            attome_ai::tool_call::resolve(fx.db(), call.id, version, *status, None, approval)
                .await
                .expect("resolve"),
            "{status:?}"
        );
        version += 1;
    }
}

async fn seeded_invocation(fx: &Fx, session: Uuid, action: &str, outcome: &str, result: Value) {
    sqlx::query(
        "INSERT INTO action_invocation \
            (agent_session_id, tool_call_id, action_id, initiator, acting_user_id, outcome, result) \
         VALUES ($1, $2, $3, 1, $4, $5, $6)",
    )
    .bind(session)
    .bind(format!("inv-{}", Uuid::now_v7().simple()))
    .bind(action)
    .bind(fx.owner)
    .bind(outcome)
    .bind(result)
    .execute(fx.db())
    .await
    .expect("seed invocation");
}

async fn vote(fx: &Fx, conversation: Uuid, answer: Uuid, vote: &str) {
    let (status, body) = send(
        &fx.app,
        "PUT",
        &feedback_uri(conversation, answer),
        Some(&fx.owner_cookie),
        Some(json!({"vote": vote})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

fn analytics_uri(
    from: chrono::DateTime<chrono::Utc>,
    to: chrono::DateTime<chrono::Utc>,
    surface: &str,
) -> String {
    let fmt =
        |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    format!(
        "/api/v1/admin/ai/bot-analytics?from={}&to={}&surface={surface}",
        fmt(from),
        fmt(to)
    )
}

/// **Every C10-B formula, over a window holding a known mix.** Four
/// conversations and one session with no conversation, all on the
/// `workflow` surface, plus an `internal` conversation the filter must
/// exclude:
///
/// - **A** — a turn that ends `completed`, with a `search.knowledge` call
///   that is reopened once and completes; the answer voted up. Deflected.
/// - **B** — a turn ending `tool_failure`, with a `record.update_field` call
///   rejected and a `record.delete` call awaiting approval; a completed
///   `bot.handoff` for `refusal`; the answer voted down. Handed off.
/// - **C** — a turn ending `max_steps`, then one ending `awaiting_approval`;
///   a `bot.handoff` still only `claimed` (not a handoff). Unresolved.
/// - **D** — a question with no turn outcome yet. Not engaged.
/// - **E** — a session with no conversation and a completed handoff written
///   before `reason` existed. `unknown`, and outside the deflection cohort.
#[tokio::test]
async fn bot_analytics_follow_the_c10b_formulas() {
    use attome_ai::conversation::TerminalState as T;
    use attome_ai::tool_call::Status as S;
    let fx = skip_if_no_db!(fixture().await);
    let from = chrono::Utc::now() - chrono::Duration::seconds(2);

    let (a, _) = workflow_conversation(&fx).await;
    let (turn, _) = seeded_turn(&fx, a, None).await;
    let call = seeded_call(&fx, a, turn, "search.knowledge").await;
    walk(
        &fx,
        &call,
        &[S::Executing, S::Proposed, S::Executing, S::Executed],
    )
    .await;
    let answer_a = attome_ai::conversation::append(
        fx.db(),
        message(
            a,
            turn,
            attome_ai::conversation::Role::Assistant,
            Some(T::Completed),
        ),
    )
    .await
    .unwrap()
    .id;
    vote(&fx, a, answer_a, "up").await;

    let (b, session_b) = workflow_conversation(&fx).await;
    let (turn, _) = seeded_turn(&fx, b, None).await;
    let call = seeded_call(&fx, b, turn, "record.update_field").await;
    walk(&fx, &call, &[S::Rejected]).await;
    let call = seeded_call(&fx, b, turn, "record.delete").await;
    walk(&fx, &call, &[S::ApprovalPending]).await;
    let answer_b = attome_ai::conversation::append(
        fx.db(),
        message(
            b,
            turn,
            attome_ai::conversation::Role::Assistant,
            Some(T::ToolFailure),
        ),
    )
    .await
    .unwrap()
    .id;
    vote(&fx, b, answer_b, "down").await;
    seeded_invocation(
        &fx,
        session_b,
        "bot.handoff",
        "completed",
        json!({"reason": "refusal"}),
    )
    .await;

    let (c, session_c) = workflow_conversation(&fx).await;
    seeded_turn(&fx, c, Some(T::MaxSteps)).await;
    seeded_turn(&fx, c, Some(T::AwaitingApproval)).await;
    seeded_invocation(&fx, session_c, "bot.handoff", "claimed", Value::Null).await;
    seeded_invocation(
        &fx,
        session_c,
        "record.get",
        "completed",
        json!({"reason": "refusal"}),
    )
    .await;

    let (d, _) = workflow_conversation(&fx).await;
    seeded_turn(&fx, d, None).await;

    let (_, session_e) = workflow_conversation(&fx).await;
    sqlx::query("DELETE FROM ai_conversation WHERE agent_session_id = $1")
        .bind(session_e)
        .execute(fx.db())
        .await
        .unwrap();
    seeded_invocation(
        &fx,
        session_e,
        "bot.handoff",
        "completed",
        json!({"work_request_id": Uuid::now_v7()}),
    )
    .await;

    // Excluded by the surface filter.
    let internal = conversation_for(&fx, fx.owner).await;
    seeded_turn(&fx, internal, Some(T::Completed)).await;

    let to = chrono::Utc::now() + chrono::Duration::seconds(2);
    let (status, r) = send(
        &fx.app,
        "GET",
        &analytics_uri(from, to, "workflow"),
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["surface"], "workflow");

    // 1. Turns: A, B, C×2, D started; A, B, C×2 ended.
    let turns = &r["turns"];
    assert_eq!(turns["started"], 5, "{turns}");
    assert_eq!(turns["ended"], 4, "{turns}");
    assert_eq!(turns["completed"], 1);
    assert_eq!(turns["awaiting"], 1);
    assert_eq!(turns["failed"], 2);
    // C11 B4: a Stop is counted on its own, never as a failure.
    assert_eq!(turns["cancelled"], 0);
    assert_eq!(turns["completion_rate"], 0.25);
    let by_state = turns["by_terminal_state"].as_object().unwrap();
    assert_eq!(by_state.len(), 13, "every state, zero-filled");
    assert_eq!(by_state["cancelled"], 0);
    assert_eq!(by_state["completed"], 1);
    assert_eq!(by_state["tool_failure"], 1);
    assert_eq!(by_state["max_steps"], 1);
    assert_eq!(by_state["awaiting_approval"], 1);
    assert_eq!(by_state["model_failure"], 0);

    // 2. Tool calls: the reopened proposal is the same call.
    let tc = &r["tool_calls"];
    let by_action: Vec<&Value> = tc["by_action"].as_array().unwrap().iter().collect();
    let row = |id: &str| {
        by_action
            .iter()
            .find(|v| v["action_id"] == id)
            .copied()
            .unwrap_or_else(|| panic!("{id} in {tc}"))
    };
    assert_eq!(by_action.len(), 3, "{tc}");
    assert_eq!(row("search.knowledge")["proposed"], 1, "{tc}");
    assert_eq!(row("search.knowledge")["completed"], 1);
    assert_eq!(row("record.update_field")["proposed"], 1);
    assert_eq!(row("record.update_field")["rejected"], 1);
    assert_eq!(row("record.delete")["approval_required"], 1);
    assert_eq!(tc["total"]["proposed"], 3);
    assert_eq!(tc["total"]["completed"], 1);
    assert_eq!(tc["total"]["rejected"], 1);
    assert_eq!(tc["total"]["approval_required"], 1);
    assert_eq!(tc["total"]["expired"], 0);

    // 3. Handoffs: completed agent bot.handoff only.
    let h = &r["handoffs"];
    assert_eq!(h["total"], 2, "{h}");
    assert_eq!(h["by_reason"]["refusal"], 1);
    assert_eq!(h["by_reason"]["unknown"], 1);
    assert_eq!(h["by_reason"]["user_requested"], 0);
    assert_eq!(h["by_reason"].as_object().unwrap().len(), 5);

    // 4. Deflection: A deflected, B handed off, C unresolved, D not engaged.
    let df = &r["deflection"];
    assert_eq!(df["engaged"], 3, "{df}");
    assert_eq!(df["deflected"], 1);
    assert_eq!(df["handed_off"], 1);
    assert_eq!(df["unresolved"], 1);
    let third = 1.0 / 3.0;
    assert_eq!(df["deflection_rate"], third);
    assert_eq!(df["handoff_rate"], third);

    // 5. Thumbs: four answers (A, B, C×2), two rated.
    let fb = &r["feedback"];
    assert_eq!(fb["answers"], 4, "{fb}");
    assert_eq!(fb["rated_answers"], 2);
    assert_eq!(fb["up"], 1);
    assert_eq!(fb["down"], 1);
    assert_eq!(fb["up_rate"], 0.5);
    assert_eq!(fb["coverage"], 0.5);

    // A window after everything above is empty, and its rates are null.
    let later = to + chrono::Duration::hours(1);
    let (_, empty) = send(
        &fx.app,
        "GET",
        &analytics_uri(later, later + chrono::Duration::hours(1), "workflow"),
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(empty["turns"]["started"], 0, "{empty}");
    assert_eq!(empty["turns"]["completion_rate"], Value::Null);
    assert_eq!(empty["deflection"]["deflection_rate"], Value::Null);
    assert_eq!(empty["feedback"]["up_rate"], Value::Null);
}

/// **Administrators only, aggregates only.** No credentials is `401`; a
/// signed-in user without `system.admin` is `403`, even for their own
/// conversations' figures; a bad window is `422`. An administrator's report
/// names no conversation, user or message.
#[tokio::test]
async fn bot_analytics_are_admin_only_and_carry_no_identifiers() {
    let fx = skip_if_no_db!(fixture().await);
    let from = chrono::Utc::now() - chrono::Duration::seconds(2);
    let (conversation, answer, _) = answered_conversation(&fx).await;
    vote(&fx, conversation, answer, "up").await;
    let to = chrono::Utc::now() + chrono::Duration::seconds(2);
    let uri = analytics_uri(from, to, "internal");

    let (status, _) = send(&fx.app, "GET", &uri, None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (user, user_cookie) = seed_user(fx.db(), false).await;
    let own = conversation_for(&fx, user).await;
    seeded_turn(
        &fx,
        own,
        Some(attome_ai::conversation::TerminalState::Completed),
    )
    .await;
    let (status, body) = send(&fx.app, "GET", &uri, Some(&user_cookie), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body.get("turns").is_none(),
        "no figure on a refusal: {body}"
    );

    let (status, _) = send(
        &fx.app,
        "GET",
        &analytics_uri(to, from, "internal"),
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "reversed window");
    let (status, _) = send(
        &fx.app,
        "GET",
        &analytics_uri(from, to, "sms"),
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "unknown surface");

    let (status, body) = send(&fx.app, "GET", &uri, Some(&fx.owner_cookie), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["feedback"]["up"].as_i64().unwrap() >= 1, "{body}");
    let text = body.to_string();
    for id in [conversation, answer, own, fx.owner, user] {
        assert!(!text.contains(&id.to_string()), "{id} leaked: {text}");
    }
}

// ---------------------------------------------------------------------------
// C11 B3 — token deltas over the stream (P-3, rows A-78, A-81)
// ---------------------------------------------------------------------------

const LONG_ANSWER: &str = "This answer is long enough to arrive as several deltas, \
                           four characters at a time, before it is completed.";

/// **Row A-78.** A live stream receives `message.delta` frames for the turn,
/// each with no `id`; their text is the answer `message.completed` then
/// carries. A reconnect replays the durable events only — no delta is ever
/// replayed, and the cursor never moved on one.
#[tokio::test]
async fn deltas_stream_live_without_a_cursor_and_are_never_replayed() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;
    let before = event_count(&fx, conversation).await;

    let app = fx.app.clone();
    let cookie = fx.owner_cookie.clone();
    let follower = tokio::spawn(async move {
        stream_with_deltas(
            &app,
            Some(&cookie),
            &stream_uri(conversation, Some(before)),
            None,
            3,
            std::time::Duration::from_secs(15),
        )
        .await
    });
    // The follower subscribes after authorizing; give it that moment.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    fx.model.push(says(LONG_ANSWER));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "tell me something long"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");

    let (_, _, durable, deltas) = follower.await.expect("follower");
    assert_eq!(
        types(&durable),
        ["turn.started", "message.completed", "turn.completed"]
    );
    assert!(!deltas.is_empty(), "the answer streamed as deltas");
    let turn_id = durable[1]["turn_id"].clone();
    assert!(deltas.iter().all(|d| d["turn_id"] == turn_id));
    let streamed: String = deltas
        .iter()
        .map(|d| d["text"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        streamed,
        durable[1]["content"].as_str().unwrap_or(""),
        "the deltas are the answer the ledger holds"
    );

    // Reconnect from the start: the log replays, and no delta does.
    let total = event_count(&fx, conversation).await as usize;
    let (_, _, replayed, replayed_deltas) = stream_with_deltas(
        &fx.app,
        Some(&fx.owner_cookie),
        &stream_uri(conversation, Some(0)),
        None,
        total,
        STREAM_WAIT,
    )
    .await;
    assert_eq!(ordinals(&replayed), (1..=total as i64).collect::<Vec<_>>());
    assert!(replayed_deltas.is_empty(), "a delta is never replayed");
}

/// **Row A-81.** The turn runs on one application instance and the stream is
/// held by another — separate state, pools and routers over the same database
/// and Redis — and the deltas still arrive, because they travel through Redis
/// pub/sub rather than process memory. (Both instances share one test process,
/// so the in-process fan-out is shared too; the publish-to-subscribe hop is
/// the real one.)
#[tokio::test]
async fn deltas_reach_a_stream_held_by_another_instance() {
    let fx = skip_if_no_db!(fixture().await);
    let base_url = spawn_model(fx.model.clone()).await;
    let other = skip_if_no_db!(test_system(&base_url).await);
    let other_app = full_app(other);
    let (conversation, _) = fx.start("reversible").await;
    let before = event_count(&fx, conversation).await;

    let cookie = fx.owner_cookie.clone();
    let follower = tokio::spawn(async move {
        stream_with_deltas(
            &other_app,
            Some(&cookie),
            &stream_uri(conversation, Some(before)),
            None,
            3,
            std::time::Duration::from_secs(15),
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    fx.model.push(says(LONG_ANSWER));
    let (status, _) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "from the other node"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, _, durable, deltas) = follower.await.expect("follower");
    assert_eq!(durable.len(), 3, "{durable:?}");
    let streamed: String = deltas
        .iter()
        .map(|d| d["text"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(streamed, LONG_ANSWER, "every delta crossed instances");
}

// ---------------------------------------------------------------------------
// C11 B4 — Stop over HTTP (P-4, row A-84)
// ---------------------------------------------------------------------------

fn cancel_uri(conversation: Uuid, turn: Uuid) -> String {
    format!("/api/v1/ai/conversations/{conversation}/turns/{turn}/cancel")
}

async fn cancel_audit_events(fx: &Fx, conversation: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header \
                  WHERE record_id = $1 AND event_name = 'ai_conversation.turn_cancel') \
              + (SELECT COUNT(*) FROM audit_ingest \
                  WHERE payload->>'record_id' = $2 \
                    AND payload->>'event_name' = 'ai_conversation.turn_cancel')",
    )
    .bind(conversation)
    .bind(conversation.to_string())
    .fetch_one(fx.db())
    .await
    .expect("count cancel audit events")
}

/// **Row A-84 over HTTP.** A running turn's Stop is recorded once and audited
/// once, however often it is sent; a finished turn's Stop writes nothing; and
/// another user's conversation, an unknown turn and no credentials are
/// refused before anything is written (I-20).
#[tokio::test]
async fn stop_is_owner_only_idempotent_and_audited_once() {
    let fx = skip_if_no_db!(fixture().await);
    let (conversation, _) = fx.start("reversible").await;

    // A turn that has begun and not ended: its user message, no answer yet.
    let running = Uuid::now_v7();
    attome_ai::conversation::append(
        fx.db(),
        attome_ai::conversation::NewMessage {
            conversation_id: conversation,
            role: attome_ai::conversation::Role::User,
            content: "a long job".into(),
            turn_id: running,
            terminal_state: None,
            model_id: None,
            prompt_version: None,
            input_tokens: None,
            output_tokens: None,
        },
    )
    .await
    .expect("a running turn");

    let (_, stranger) = seed_user(fx.db(), true).await;
    for (cookie, uri, expected) in [
        (
            Some(stranger.as_str()),
            cancel_uri(conversation, running),
            StatusCode::NOT_FOUND,
        ),
        (
            Some(fx.owner_cookie.as_str()),
            cancel_uri(conversation, Uuid::now_v7()),
            StatusCode::NOT_FOUND,
        ),
        (
            None,
            cancel_uri(conversation, running),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        let (status, body) = send(&fx.app, "POST", &uri, cookie, Some(json!({}))).await;
        assert_eq!(status, expected, "{uri}: {body}");
    }
    assert_eq!(
        cancel_audit_events(&fx, conversation).await,
        0,
        "refusals write nothing"
    );

    for expected in ["requested", "already_requested"] {
        let (status, body) = send(
            &fx.app,
            "POST",
            &cancel_uri(conversation, running),
            Some(&fx.owner_cookie),
            Some(json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], expected);
        assert_eq!(body["turn_id"], json!(running));
    }
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ai_turn_cancel WHERE turn_id = $1")
        .bind(running)
        .fetch_one(fx.db())
        .await
        .unwrap();
    assert_eq!(rows, 1, "one row, however often Stop is sent");
    assert_eq!(
        cancel_audit_events(&fx, conversation).await,
        1,
        "audited once"
    );

    // A finished turn: nothing to stop, nothing written.
    fx.model.push(says("Done."));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "quick one"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    let finished = Uuid::parse_str(turn["turn_id"].as_str().unwrap()).unwrap();
    let (status, body) = send(
        &fx.app,
        "POST",
        &cancel_uri(conversation, finished),
        Some(&fx.owner_cookie),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], "already_ended");
    assert_eq!(cancel_audit_events(&fx, conversation).await, 1);
}

// ---------------------------------------------------------------------------
// C11 B5 — the runtime AI switch over HTTP (P-5, row A-85)
// ---------------------------------------------------------------------------

/// **Row A-85, the admin route.** Administrators only; an unknown surface is
/// 404; a change is audited as configuration and shows at once in the view,
/// which reports configuration and runtime apart; turning a surface back on
/// restores the configuration and nothing more.
#[tokio::test]
async fn the_runtime_switch_is_admin_only_audited_and_only_narrows() {
    let fx = skip_if_no_db!(fixture().await);
    sqlx::query("DELETE FROM ai_runtime_switch")
        .execute(fx.db())
        .await
        .unwrap();
    let (_, member) = seed_user(fx.db(), false).await;
    let uri = "/api/v1/admin/ai/runtime-switch";

    let (status, _) = send(&fx.app, "GET", uri, Some(&member), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "not for a non-administrator");
    let (status, _) = send(
        &fx.app,
        "PUT",
        &format!("{uri}/chat"),
        Some(&member),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &fx.app,
        "PUT",
        &format!("{uri}/everything"),
        Some(&fx.owner_cookie),
        Some(json!({"enabled": false})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an unknown surface");

    let (status, view) = send(
        &fx.app,
        "PUT",
        &format!("{uri}/chat"),
        Some(&fx.owner_cookie),
        Some(json!({"enabled": false, "reason": "incident drill"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    let row = |view: &Value, surface: &str| -> Value {
        view["surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["surface"] == surface)
            .cloned()
            .unwrap()
    };
    let chat = row(&view, "chat");
    assert_eq!(chat["configured"], true);
    assert_eq!(chat["runtime_enabled"], false);
    assert_eq!(chat["effective"], false);
    assert_eq!(chat["reason"], "incident drill");
    assert_eq!(row(&view, "fields")["effective"], true, "one surface only");

    // The test configuration has semantic search off: turning it "on" at
    // runtime changes nothing about what is in effect.
    let (_, view) = send(
        &fx.app,
        "PUT",
        &format!("{uri}/semantic_search"),
        Some(&fx.owner_cookie),
        Some(json!({"enabled": true})),
    )
    .await;
    let semantic = row(&view, "semantic_search");
    if semantic["configured"] == false {
        assert_eq!(
            semantic["effective"], false,
            "the runtime switch never enables"
        );
    }

    let audited: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE event_name = 'ai.runtime_switch') \
              + (SELECT COUNT(*) FROM audit_ingest \
                  WHERE payload->>'event_name' = 'ai.runtime_switch')",
    )
    .fetch_one(fx.db())
    .await
    .unwrap();
    assert!(audited >= 2, "each change is audited: {audited}");

    let (_, view) = send(
        &fx.app,
        "PUT",
        &format!("{uri}/chat"),
        Some(&fx.owner_cookie),
        Some(json!({"enabled": true})),
    )
    .await;
    assert_eq!(row(&view, "chat")["effective"], true, "restored");
    sqlx::query("DELETE FROM ai_runtime_switch")
        .execute(fx.db())
        .await
        .unwrap();
    attome_core::ai_runtime_switch::reload(fx.db()).await;
}

// ---------------------------------------------------------------------------
// C10 B2b — the assistant's analytics as metrics
// ---------------------------------------------------------------------------

/// **C10 B2b, the parity test.** The five shipped metrics are computed by
/// `attome-metric` from the shipped stored queries, and each equals the admin
/// analytics route's figure for the same seven days — so a dashboard's KPI
/// widget and the analytics screen can never tell an operator two different
/// stories. Activity comes through the real chat API: an answered turn, a
/// turn stopped for confirmation (one proposal), and a thumbs-up.
#[tokio::test]
async fn the_shipped_bot_metrics_equal_the_admin_route() {
    let fx = skip_if_no_db!(fixture().await);
    // Twice: boot re-applies both on every start, so a second apply must be
    // a no-op rather than a duplicate-key failure.
    for _ in 0..2 {
        // D-786: the `Metric Service` role the metric principal runs under.
        attome_api::bundle::apply_platform_bundle(
            &fx.state,
            "attome-metric",
            include_str!("../../../../platform-bundles/attome-metric.json"),
        )
        .await
        .expect("apply the metric bundle");
        attome_api::bundle::apply_platform_bundle(
            &fx.state,
            "attome-ai-bot-analytics",
            include_str!("../../../../platform-bundles/attome-ai-bot-analytics.json"),
        )
        .await
        .expect("apply the analytics queries");
        attome_api::bundle::apply_platform_bundle(
            &fx.state,
            "attome-ai-bot-analytics-data",
            include_str!("../../../../platform-bundles/attome-ai-bot-analytics-data.json"),
        )
        .await
        .expect("apply the metric definitions");
    }

    let (conversation, _) = fx.start("reversible").await;
    fx.model.push(says("An answer to rate."));
    let (status, turn) = send(
        &fx.app,
        "POST",
        &messages_uri(conversation),
        Some(&fx.owner_cookie),
        Some(json!({"text": "a question"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{turn}");
    let (entity, record) = writable_record(&fx).await;
    turn_awaiting_confirmation(&fx, conversation, "metric-p1", &entity, record).await;
    let answer: Uuid = sqlx::query_scalar(
        "SELECT id FROM ai_message WHERE conversation_id = $1 \
            AND role = 'assistant' AND terminal_state = 'completed' LIMIT 1",
    )
    .bind(conversation)
    .fetch_one(fx.db())
    .await
    .expect("the answer");
    let (status, _) = send(
        &fx.app,
        "PUT",
        &format!("/api/v1/ai/conversations/{conversation}/messages/{answer}/feedback"),
        Some(&fx.owner_cookie),
        Some(json!({"vote": "up"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, report) = send(
        &fx.app,
        "GET",
        "/api/v1/admin/ai/bot-analytics",
        Some(&fx.owner_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{report}");

    let metric = |key: &'static str| {
        let db = fx.db().clone();
        let state = fx.state.clone();
        async move {
            let id: Uuid =
                sqlx::query_scalar("SELECT id FROM dashboard_metric_definition WHERE key = $1")
                    .bind(key)
                    .fetch_one(&db)
                    .await
                    .unwrap_or_else(|e| panic!("metric {key} is shipped: {e}"));
            let outcome =
                attome_metric::metric::compute_and_record(&state, id, None, None, true, None)
                    .await
                    .unwrap_or_else(|e| panic!("compute {key}: {e:?}"));
            outcome
                .snapshot
                .actual
                .unwrap_or_else(|| panic!("{key} computed no value"))
        }
    };
    let close = |a: f64, b: f64, what: &str| {
        assert!((a - b).abs() < 1e-9, "{what}: metric {a} vs route {b}");
    };
    let n = |v: &Value| v.as_f64().unwrap_or(0.0);

    close(
        metric("ai.assistant.turns_7d").await,
        n(&report["turns"]["started"]),
        "turns started",
    );
    close(
        metric("ai.assistant.completion_rate_7d").await,
        n(&report["turns"]["completion_rate"]) * 100.0,
        "completion rate",
    );
    close(
        metric("ai.assistant.tool_calls_7d").await,
        n(&report["tool_calls"]["total"]["proposed"]),
        "tool calls",
    );
    close(
        metric("ai.assistant.handoffs_7d").await,
        n(&report["handoffs"]["total"]),
        "handoffs",
    );
    close(
        metric("ai.assistant.thumbs_up_share_7d").await,
        n(&report["feedback"]["up_rate"]) * 100.0,
        "thumbs-up share",
    );
    assert!(
        n(&report["turns"]["started"]) >= 2.0,
        "activity was counted: {report}"
    );
}

// ---------------------------------------------------------------------------
// A client that goes away (found by the A-87 browser pass)
// ---------------------------------------------------------------------------

/// Sends a request and drops it after `after` — a closed tab, a dropped
/// connection, the request timeout.
async fn send_and_drop(fx: &Fx, uri: &str, body: Value, after: std::time::Duration) {
    let _ = tokio::time::timeout(
        after,
        send(&fx.app, "POST", uri, Some(&fx.owner_cookie), Some(body)),
    )
    .await;
}

/// **A confirmation whose client goes away still finishes.** Dropped at
/// several points, a confirm either never started (`proposed`, the record
/// untouched) or ran to the end (`executed`, the record changed, the claim
/// completed) — never the old stuck state: the change made, the claim held,
/// the call `executing` forever. At least one attempt must have started, or
/// the test proves nothing.
#[tokio::test]
async fn a_confirmation_whose_client_goes_away_still_finishes() {
    let fx = skip_if_no_db!(fixture().await);
    let mut started = 0;
    for (i, after_ms) in [2u64, 10, 25, 60, 120].into_iter().enumerate() {
        let (conversation, _) = fx.start("reversible").await;
        let (entity, record) = writable_record(&fx).await;
        let tid = format!("gone-{i}");
        let hash = turn_awaiting_confirmation(&fx, conversation, &tid, &entity, record).await;
        send_and_drop(
            &fx,
            &confirm_uri(conversation, &tid),
            json!({"arguments_hash": hash}),
            std::time::Duration::from_millis(after_ms),
        )
        .await;
        let mut settled = None;
        for _ in 0..100 {
            let status: String = sqlx::query_scalar(
                "SELECT status FROM ai_tool_call WHERE conversation_id = $1 AND tool_call_id = $2",
            )
            .bind(conversation)
            .bind(&tid)
            .fetch_one(fx.db())
            .await
            .expect("the call");
            if status != "executing" {
                settled = Some(status);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let status =
            settled.unwrap_or_else(|| panic!("dropped after {after_ms} ms: stuck executing"));
        let closed: bool = sqlx::query_scalar(&format!(
            "SELECT status = 'closed' FROM {entity} WHERE id = $1"
        ))
        .bind(record)
        .fetch_one(fx.db())
        .await
        .expect("the record");
        match status.as_str() {
            "executed" => {
                assert!(
                    closed,
                    "dropped after {after_ms} ms: executed, but the record is unchanged"
                );
                started += 1;
            }
            "proposed" => assert!(
                !closed,
                "dropped after {after_ms} ms: the record changed but the call says proposed"
            ),
            other => panic!("dropped after {after_ms} ms: unexpected status {other}"),
        }
    }
    assert!(
        started > 0,
        "no attempt got far enough to start; the test proved nothing"
    );
}

/// **A turn whose client goes away still finishes.** Dropped at several
/// points, a turn either never started (no message recorded) or ended with a
/// terminal assistant message — never a question with no answer.
#[tokio::test]
async fn a_turn_whose_client_goes_away_still_finishes() {
    let fx = skip_if_no_db!(fixture().await);
    let mut started = 0;
    for after_ms in [2u64, 10, 25, 60, 120] {
        let (conversation, _) = fx.start("reversible").await;
        // Replies are identical, so one left queued by a turn that never
        // started is simply the next turn's.
        fx.model.push(says("An answer nobody waited for."));
        send_and_drop(
            &fx,
            &messages_uri(conversation),
            json!({"text": "are you there?"}),
            std::time::Duration::from_millis(after_ms),
        )
        .await;
        // A turn spawned just before the drop may not have recorded its
        // question yet, so settle on "every question has its answer" rather
        // than on the first empty read.
        let ledger = || async {
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT COUNT(*) FILTER (WHERE role = 'user'),                         COUNT(*) FILTER (WHERE role = 'assistant' AND terminal_state IS NOT NULL)                    FROM ai_message WHERE conversation_id = $1",
            )
            .bind(conversation)
            .fetch_one(fx.db())
            .await
            .expect("the ledger")
        };
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let mut counts = ledger().await;
        for _ in 0..300 {
            if counts.0 == counts.1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            counts = ledger().await;
        }
        let events: Vec<String> = sqlx::query_scalar(
            "SELECT event_type FROM ai_conversation_event WHERE conversation_id = $1 ORDER BY ordinal",
        )
        .bind(conversation)
        .fetch_all(fx.db())
        .await
        .expect("the events");
        assert_eq!(
            counts.0, counts.1,
            "dropped after {after_ms} ms: {} question(s), {} answer(s); events {events:?}",
            counts.0, counts.1
        );
        started += counts.1;
    }
    assert!(
        started > 0,
        "no attempt got far enough to start; the test proved nothing"
    );
}

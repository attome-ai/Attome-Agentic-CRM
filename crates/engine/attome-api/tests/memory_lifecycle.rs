//! M35 v1 Track A — `memory.remember`/`memory.forget` through the **full
//! assembled middleware stack** (`POST /api/v1/actions/{id}/invoke`), plus the
//! retention sweep. Each test asserts the consequence a user or auditor would
//! see, not the call that produced it:
//!
//! - a save persists the row and writes exactly one `Create` audit event that
//!   carries ids and scope, never the memory's content;
//! - a forget removes the row, recall stops returning it, and exactly one
//!   `HardDelete` audit event is written;
//! - forgetting another principal's memory is `404`, leaves it intact, and
//!   audits nothing;
//! - the HTTP idempotency middleware (`attome-server`, `x-idempotency-key`)
//!   deduplicates a replayed save, and — the other half of that contract — a
//!   save sent twice *without* a key is two saves. Agent/MCP invocation
//!   idempotency is a separate path owned by M31 and is not exercised here;
//! - the retention sweep deletes an expired memory and keeps a fresh one.
//!
//! `audit.chainer_enabled` is pinned false (D-316 made true the code default)
//! so the `audit_header` rows exist synchronously when asserted.
//! `inference.ai.enabled`/`fields` are on because `memory.*` are `MODULE_AI`
//! actions on the `Fields` surface, and the kill-switch default (every AI
//! surface off) makes the gate answer them `404`, same as unlicensed.
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test memory_lifecycle -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_modules::ModuleSet;
use attome_security::visibility::PolymorphicVisibility;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::point_config_at;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// `AuditOperation::Create` / `AuditOperation::HardDelete` as stored.
const AUDIT_OP_CREATE: i32 = 0;
const AUDIT_OP_HARD_DELETE: i32 = 3;

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
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// A plain (non-admin) user: `memory.remember`/`memory.forget` need no
/// privilege, and memory is per-principal for everyone (D-451).
async fn seed_user(db: &attome_db::DbPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("memory-lifecycle-{}", user_id.simple()))
        .execute(db)
        .await
        .expect("insert throwaway user");
    (user_id, session_cookie(user_id))
}

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
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }},
            "audit": {{ "chainer_enabled": false }},
            "inference": {{ "ai": {{ "enabled": true, "fields": true }} }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<(EngineSystem, attome_db::DbPool)> {
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

    let base = AppState::new(
        config,
        db.clone(),
        db.clone(),
        db.clone(),
        redis,
        redis_coordination,
        storage,
    );
    let state = EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_ai::ActionModel)
        .build()
        .await
        .expect("build EngineSystem");

    // Fully licensed: `memory.*` sit behind `MODULE_AI`, and the module gate
    // is not what this suite measures.
    //
    // Stored AFTER `build()`, as `action_routes.rs` does: `build()` loads the
    // deployment's own licence into `state.modules`, so a licence stored
    // before it was overwritten with the degraded one and every memory route
    // answered 403 `feature_hidden`.
    let license = ModuleSet::from_bits([u64::MAX; 4]);
    system.state().modules.store(Arc::new(license));
    Some((system, db))
}

/// An in-process `oneshot()` sends neither Sec-Fetch-Site nor Origin, which
/// `csrf_protect` correctly rejects for a cookie-authenticated POST — see
/// `action_routes.rs`'s identical helper.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    req
}

fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
}

async fn invoke(
    app: &axum::Router,
    action: &str,
    cookie: &str,
    idempotency_key: Option<&str>,
    args: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/actions/{action}/invoke"))
        .header("cookie", cookie)
        .header("content-type", "application/json");
    if let Some(key) = idempotency_key {
        builder = builder.header("x-idempotency-key", key);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(json!({ "args": args }).to_string()))
                .unwrap(),
        )
        .await
        .expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn remember_args(summary: &str) -> Value {
    json!({ "scope_kind": "user", "kind": "preference", "summary": summary })
}

/// The memory id out of a `completed` `memory.remember` outcome.
fn remembered_id(status: StatusCode, body: &Value) -> Uuid {
    assert_eq!(status, StatusCode::OK, "remember must succeed: {body}");
    assert_eq!(
        body["status"], "completed",
        "a user's own save executes: {body}"
    );
    body["result"]["memory_id"]
        .as_str()
        .expect("memory_id in the result")
        .parse()
        .expect("memory_id is a uuid")
}

async fn memory_audit_rows(
    db: &attome_db::DbPool,
    memory_id: Uuid,
) -> Vec<(Option<i32>, Option<String>, Option<String>)> {
    sqlx::query_as(
        "SELECT operation, event_name, event_comment FROM audit_header \
          WHERE entity_name = 'memory' AND record_id = $1 \
          ORDER BY changed_on",
    )
    .bind(memory_id)
    .fetch_all(db)
    .await
    .expect("read memory audit rows")
}

async fn memory_exists(db: &attome_db::DbPool, memory_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM memory WHERE id = $1)")
        .bind(memory_id)
        .fetch_one(db)
        .await
        .expect("query memory")
}

async fn recall_ids(db: &attome_db::DbPool, user_id: Uuid) -> Vec<Uuid> {
    let security = SecurityContext {
        user_id,
        is_admin: false,
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
    };
    let access = HashMap::new();
    let no_default_shares = HashSet::new();
    let records = PolymorphicVisibility::new(&security, &access, &no_default_shares, None);
    attome_search::recall(
        db,
        attome_search::RecallQuery {
            owner_principal: user_id,
            scope_kind: None,
            scope_ref: None,
            query_text: None,
            records: &records,
            limit: attome_search::corpus::memory::MAX_RECALL_LIMIT,
        },
    )
    .await
    .expect("recall")
    .into_iter()
    .map(|hit| hit.id)
    .collect()
}

async fn cleanup(db: &attome_db::DbPool, users: &[Uuid]) {
    let _ = sqlx::query("DELETE FROM memory WHERE owner_principal = ANY($1)")
        .bind(users)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM user_account WHERE id = ANY($1)")
        .bind(users)
        .execute(db)
        .await;
}

#[tokio::test]
async fn remembering_persists_the_row_and_writes_one_create_audit_event_without_content() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_id, cookie) = seed_user(&db).await;
    let summary = format!("prefers dark mode {}", Uuid::now_v7().simple());

    let (status, body) = invoke(
        &app,
        "memory.remember",
        &cookie,
        None,
        remember_args(&summary),
    )
    .await;
    let memory_id = remembered_id(status, &body);

    let (owner, stored_summary): (Uuid, String) =
        sqlx::query_as("SELECT owner_principal, summary FROM memory WHERE id = $1")
            .bind(memory_id)
            .fetch_one(&db)
            .await
            .expect("the saved memory row must exist");
    assert_eq!(owner, user_id, "the memory belongs to the caller");
    assert_eq!(stored_summary, summary);
    assert!(recall_ids(&db, user_id).await.contains(&memory_id));

    let audit = memory_audit_rows(&db, memory_id).await;
    assert_eq!(
        audit.len(),
        1,
        "exactly one audit event per save: {audit:?}"
    );
    let (operation, event_name, event_comment) = &audit[0];
    assert_eq!(*operation, Some(AUDIT_OP_CREATE));
    assert_eq!(event_name.as_deref(), Some("memory.remember"));
    assert_eq!(event_comment.as_deref(), Some("scope_kind=user"));
    assert!(
        !event_comment
            .as_deref()
            .unwrap_or_default()
            .contains("dark mode"),
        "the audit event must not carry the memory's content"
    );

    cleanup(&db, &[user_id]).await;
}

#[tokio::test]
async fn forgetting_removes_the_row_stops_recall_and_writes_one_delete_audit_event() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_id, cookie) = seed_user(&db).await;

    let (status, body) = invoke(
        &app,
        "memory.remember",
        &cookie,
        None,
        remember_args("a memory about to be forgotten"),
    )
    .await;
    let memory_id = remembered_id(status, &body);
    assert!(recall_ids(&db, user_id).await.contains(&memory_id));

    let (status, body) = invoke(
        &app,
        "memory.forget",
        &cookie,
        None,
        json!({ "memory_id": memory_id }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "forget must succeed: {body}");
    assert_eq!(body["status"], "completed", "{body}");
    assert_eq!(body["result"]["forgotten"], true);

    assert!(!memory_exists(&db, memory_id).await, "the row must be gone");
    assert!(
        !recall_ids(&db, user_id).await.contains(&memory_id),
        "a forgotten memory must never be recalled"
    );

    let audit = memory_audit_rows(&db, memory_id).await;
    let deletes: Vec<_> = audit
        .iter()
        .filter(|(op, _, _)| *op == Some(AUDIT_OP_HARD_DELETE))
        .collect();
    assert_eq!(
        deletes.len(),
        1,
        "exactly one delete audit event: {audit:?}"
    );
    assert_eq!(deletes[0].1.as_deref(), Some("memory.forget"));
    assert_eq!(deletes[0].2.as_deref(), Some("scope_kind=user"));

    cleanup(&db, &[user_id]).await;
}

#[tokio::test]
async fn forgetting_another_users_memory_is_not_found_leaves_it_intact_and_audits_nothing() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_a, cookie_a) = seed_user(&db).await;
    let (user_b, cookie_b) = seed_user(&db).await;

    let (status, body) = invoke(
        &app,
        "memory.remember",
        &cookie_a,
        None,
        remember_args("user A's private memory"),
    )
    .await;
    let memory_id = remembered_id(status, &body);

    let (status, body) = invoke(
        &app,
        "memory.forget",
        &cookie_b,
        None,
        json!({ "memory_id": memory_id }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "user B must not be able to forget user A's memory: {body}"
    );

    assert!(
        memory_exists(&db, memory_id).await,
        "user A's memory is intact"
    );
    assert!(recall_ids(&db, user_a).await.contains(&memory_id));
    let audit = memory_audit_rows(&db, memory_id).await;
    assert!(
        audit
            .iter()
            .all(|(op, _, _)| *op != Some(AUDIT_OP_HARD_DELETE)),
        "a refused forget must not write a delete audit event: {audit:?}"
    );

    cleanup(&db, &[user_a, user_b]).await;
}

/// The existing HTTP contract, verified for this route: a save replayed with
/// the same `x-idempotency-key` and body is answered from the middleware's
/// cache — same memory id, one row, one audit event.
#[tokio::test]
async fn a_remember_replayed_with_the_same_idempotency_key_writes_once() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_id, cookie) = seed_user(&db).await;
    let key = format!("memory-lifecycle-{}", Uuid::now_v7());
    let summary = format!("replayed save {}", Uuid::now_v7().simple());

    let (s1, b1) = invoke(
        &app,
        "memory.remember",
        &cookie,
        Some(&key),
        remember_args(&summary),
    )
    .await;
    let (s2, b2) = invoke(
        &app,
        "memory.remember",
        &cookie,
        Some(&key),
        remember_args(&summary),
    )
    .await;
    let first = remembered_id(s1, &b1);
    let second = remembered_id(s2, &b2);
    assert_eq!(
        first, second,
        "the replay must return the original save's result"
    );

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM memory WHERE owner_principal = $1 AND summary = $2",
    )
    .bind(user_id)
    .bind(&summary)
    .fetch_one(&db)
    .await
    .expect("count rows");
    assert_eq!(rows, 1, "a replayed save must not write a second row");
    assert_eq!(memory_audit_rows(&db, first).await.len(), 1);

    cleanup(&db, &[user_id]).await;
}

/// The other half of the same contract, stated so nobody reads more into it:
/// the middleware deduplicates only when the client sends a key. Two saves
/// with no key are two saves.
#[tokio::test]
async fn a_remember_sent_twice_without_an_idempotency_key_writes_twice() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_id, cookie) = seed_user(&db).await;
    let summary = format!("unkeyed save {}", Uuid::now_v7().simple());

    let (s1, b1) = invoke(
        &app,
        "memory.remember",
        &cookie,
        None,
        remember_args(&summary),
    )
    .await;
    let (s2, b2) = invoke(
        &app,
        "memory.remember",
        &cookie,
        None,
        remember_args(&summary),
    )
    .await;
    assert_ne!(remembered_id(s1, &b1), remembered_id(s2, &b2));

    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM memory WHERE owner_principal = $1 AND summary = $2",
    )
    .bind(user_id)
    .bind(&summary)
    .fetch_one(&db)
    .await
    .expect("count rows");
    assert_eq!(rows, 2);

    cleanup(&db, &[user_id]).await;
}

#[tokio::test]
async fn the_retention_sweep_purges_an_expired_memory_and_keeps_a_fresh_one() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let (user_id, _) = seed_user(&db).await;

    let store = |summary: &'static str| {
        let db = db.clone();
        async move {
            attome_search::store(
                &db,
                attome_search::NewMemory {
                    scope_kind: attome_search::MemoryScopeKind::User,
                    scope_ref: &user_id.to_string(),
                    owner_principal: user_id,
                    parent_entity: None,
                    parent_record_id: None,
                    kind: "fact",
                    summary,
                    facts: &[],
                    source_refs: &[],
                },
            )
            .await
            .expect("store")
        }
    };
    let expired = store("an old memory").await;
    let fresh = store("a recent memory").await;

    // Older than the setting's schema maximum (3650 days), so this row is
    // expired whatever `ai.memory_retention_days` this database resolves to.
    sqlx::query("UPDATE memory SET created_at = NOW() - INTERVAL '3651 days' WHERE id = $1")
        .bind(expired)
        .execute(&db)
        .await
        .expect("backdate the expired memory");

    attome_compliance::retention::prune_expired_memories(system.state())
        .await
        .expect("retention sweep");

    assert!(
        !memory_exists(&db, expired).await,
        "the expired memory is purged"
    );
    assert!(memory_exists(&db, fresh).await, "a fresh memory is kept");

    cleanup(&db, &[user_id]).await;
}

// ── M35 v1 C1–C6: an agent may propose a memory, only the human saves it ─────

/// One JSON-RPC call to `/api/v1/mcp`, optionally naming a session — the same
/// helper `action_routes.rs` uses.
async fn mcp(
    app: &axum::Router,
    cookie: &str,
    session: Option<Uuid>,
    method: &str,
    params: Value,
) -> Value {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/mcp")
        .header("cookie", cookie)
        .header("content-type", "application/json");
    if let Some(session) = session {
        request = request.header("mcp-session-id", session.to_string());
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(
                    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("JSON-RPC body")
}

async fn mcp_initialize(app: &axum::Router, cookie: &str) -> Uuid {
    let body = mcp(app, cookie, None, "initialize", json!({})).await;
    body["result"]["sessionId"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("initialize must return a session id: {body}"))
}

/// A `tools/call`'s decoded payload. Panics if the call was refused before
/// reaching a tool: every call in this section must reach the gate.
async fn propose_memory(app: &axum::Router, cookie: &str, session: Uuid, summary: &str) -> Value {
    let body = mcp(
        app,
        cookie,
        Some(session),
        "tools/call",
        json!({ "name": "memory.remember", "arguments": remember_args(summary) }),
    )
    .await;
    let result = body
        .get("result")
        .unwrap_or_else(|| panic!("tools/call must reach the gate: {body}"));
    assert_eq!(result["isError"], false, "{body}");
    let text = result["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("JSON payload")
}

/// MCP sessions start tainted. Clearing the flag with test-only SQL — the
/// same move `action_routes.rs` makes to narrow an allow-list — is how a test
/// reaches the no-retrieved-content path the unconditional rule exists to
/// close.
async fn untaint(db: &attome_db::DbPool, session: Uuid) {
    let tainted: bool = sqlx::query_scalar(
        "UPDATE agent_session SET tainted = false WHERE id = $1 RETURNING tainted",
    )
    .bind(session)
    .fetch_one(db)
    .await
    .expect("clear the session's taint");
    assert!(!tainted);
}

async fn count(db: &attome_db::DbPool, sql: &str, bind: impl ToString) -> i64 {
    sqlx::query_scalar(sql)
        .bind(bind.to_string())
        .fetch_one(db)
        .await
        .expect("count")
}

/// C1/C2/C3: a confirmation-required answer that echoes the proposal for
/// display and carries nothing that could be redeemed later.
fn assert_confirmation_only(payload: &Value, summary: &str) {
    assert_eq!(payload["status"], "confirmation_required", "{payload}");
    assert_eq!(
        payload["proposal"],
        json!({
            "scope_kind": "user",
            "kind": "preference",
            "summary": summary,
            "facts": [],
            "source_refs": [],
        }),
        "the proposal must echo exactly what a save would store: {payload}"
    );
    for key in [
        "id",
        "memory_id",
        "token",
        "handle",
        "approval_id",
        "result",
    ] {
        assert!(
            payload.get(key).is_none() && payload["proposal"].get(key).is_none(),
            "a confirmation must carry no redeemable `{key}`: {payload}"
        );
    }
}

/// C2: nothing was persisted for this proposal — no memory row, no approval
/// request, and no write invocation on the session.
async fn assert_nothing_persisted(db: &attome_db::DbPool, session: Uuid, summary: &str) {
    assert_eq!(
        count(
            db,
            "SELECT COUNT(*) FROM memory WHERE summary = $1",
            summary
        )
        .await,
        0,
        "no memory row may exist while a proposal awaits confirmation"
    );
    assert_eq!(
        count(
            db,
            "SELECT COUNT(*) FROM approval_request WHERE payload::text LIKE '%' || $1 || '%'",
            summary,
        )
        .await,
        0,
        "no approval request may be raised for an agent-proposed memory"
    );
    assert_eq!(
        count(
            db,
            "SELECT COUNT(*) FROM action_invocation WHERE agent_session_id::text = $1",
            session,
        )
        .await,
        0,
        "no write invocation may be recorded for an unconfirmed proposal"
    );
}

/// **MANDATORY REGRESSION (C1, C2, C3) — the no-retrieved-content bypass.**
/// An agent session whose context carries no retrieved content used to
/// auto-execute `memory.remember`. It must stop at confirmation, echo the
/// proposal with no handle, persist nothing, and stay that way when the same
/// tool call is repeated.
#[tokio::test]
async fn an_mcp_session_with_no_retrieved_content_cannot_save_a_memory_without_confirmation() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_id, cookie) = seed_user(&db).await;
    let session = mcp_initialize(&app, &cookie).await;
    untaint(&db, session).await;
    let summary = format!("clean-context proposal {}", Uuid::now_v7().simple());

    for _ in 0..2 {
        let payload = propose_memory(&app, &cookie, session, &summary).await;
        assert_confirmation_only(&payload, &summary);
    }
    assert_nothing_persisted(&db, session, &summary).await;

    cleanup(&db, &[user_id]).await;
}

/// C1: the tainted path confirms too (the existing I-10 behaviour still holds
/// for this action).
#[tokio::test]
async fn a_tainted_mcp_session_cannot_save_a_memory_without_confirmation() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_id, cookie) = seed_user(&db).await;
    let session = mcp_initialize(&app, &cookie).await;
    let summary = format!("tainted proposal {}", Uuid::now_v7().simple());

    let payload = propose_memory(&app, &cookie, session, &summary).await;
    assert_confirmation_only(&payload, &summary);
    assert_nothing_persisted(&db, session, &summary).await;

    cleanup(&db, &[user_id]).await;
}

/// **MANDATORY REGRESSION (C4, C6) — replay.** Accepting is an ordinary user
/// save built from the displayed proposal: one row owned by the acceptor, one
/// audit event, and a replay with the same idempotency key writes nothing
/// more. Re-sending the agent's tool call — in the same session or a new one —
/// never turns into a completed save.
#[tokio::test]
async fn accepting_a_proposal_is_an_ordinary_user_save_and_nothing_promotes_or_replays_it() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_id, cookie) = seed_user(&db).await;
    let session = mcp_initialize(&app, &cookie).await;
    untaint(&db, session).await;
    let summary = format!("accepted proposal {}", Uuid::now_v7().simple());

    let proposal = propose_memory(&app, &cookie, session, &summary).await["proposal"].clone();
    let key = format!("accept-{}", Uuid::now_v7());
    let (s1, b1) = invoke(
        &app,
        "memory.remember",
        &cookie,
        Some(&key),
        proposal.clone(),
    )
    .await;
    let (s2, b2) = invoke(&app, "memory.remember", &cookie, Some(&key), proposal).await;
    let memory_id = remembered_id(s1, &b1);
    assert_eq!(
        remembered_id(s2, &b2),
        memory_id,
        "the replayed accept is the same save"
    );

    let (owner, stored): (Uuid, String) =
        sqlx::query_as("SELECT owner_principal, summary FROM memory WHERE id = $1")
            .bind(memory_id)
            .fetch_one(&db)
            .await
            .expect("the accepted memory exists");
    assert_eq!(owner, user_id, "the accepting user owns the memory");
    assert_eq!(stored, summary, "what was displayed is what was saved");
    let audit = memory_audit_rows(&db, memory_id).await;
    assert_eq!(
        audit.len(),
        1,
        "an accept is audited like any save: {audit:?}"
    );
    assert_eq!(audit[0].1.as_deref(), Some("memory.remember"));

    let again = propose_memory(&app, &cookie, session, &summary).await;
    assert_eq!(again["status"], "confirmation_required", "{again}");
    let other_session = mcp_initialize(&app, &cookie).await;
    untaint(&db, other_session).await;
    let elsewhere = propose_memory(&app, &cookie, other_session, &summary).await;
    assert_eq!(elsewhere["status"], "confirmation_required", "{elsewhere}");
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) FROM memory WHERE summary = $1",
            &summary
        )
        .await,
        1,
        "only the human's accept ever wrote a row"
    );

    cleanup(&db, &[user_id]).await;
}

/// **MANDATORY REGRESSION (C6) — no transfer.** A proposal is not bound to
/// anyone: user B sending user A's displayed proposal is simply B saving a
/// memory of B's own. A gains nothing.
#[tokio::test]
async fn accepting_another_users_proposal_writes_only_the_acceptors_memory() {
    let (system, db) = skip_if_no_db!(test_system().await);
    let app = full_app(system);
    let (user_a, cookie_a) = seed_user(&db).await;
    let (user_b, cookie_b) = seed_user(&db).await;
    let session_a = mcp_initialize(&app, &cookie_a).await;
    untaint(&db, session_a).await;
    let summary = format!("cross-user proposal {}", Uuid::now_v7().simple());

    let proposal = propose_memory(&app, &cookie_a, session_a, &summary).await["proposal"].clone();
    let (status, body) = invoke(&app, "memory.remember", &cookie_b, None, proposal).await;
    let memory_id = remembered_id(status, &body);

    let owner: Uuid = sqlx::query_scalar("SELECT owner_principal FROM memory WHERE id = $1")
        .bind(memory_id)
        .fetch_one(&db)
        .await
        .expect("B's memory exists");
    assert_eq!(owner, user_b, "the acceptor owns what they save");
    let a_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM memory WHERE owner_principal = $1 AND summary = $2",
    )
    .bind(user_a)
    .bind(&summary)
    .fetch_one(&db)
    .await
    .expect("count A's rows");
    assert_eq!(
        a_rows, 0,
        "the proposer gains no memory from someone else's accept"
    );

    cleanup(&db, &[user_a, user_b]).await;
}

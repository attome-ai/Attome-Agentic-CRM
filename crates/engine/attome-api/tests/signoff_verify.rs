//! D-442 / M58 Phase 1 (Digital Signature, internal sign-off) —
//! `GET /api/v1/signoff/{decision_id}/verify`. Reuses `approval_lifecycle.rs`'s
//! exact harness shape (same throwaway config, same `assign_role_request`/
//! `decide_request` vehicle — `attome_security::admin::ACTION_ROLE_GRANT`,
//! already fully wired and proven by `approval_role_grant.rs`) rather than
//! inventing a second one, since this feature sits directly on top of
//! `decide_approval`, not beside it.
//!
//! **The single most important test in this file** (per the module's own
//! task scope) is `tampering_the_stored_decision_fails_verification` —
//! proves a decision mutated directly against the database (never possible
//! through this platform's own API — guidelines §4) is caught by the verify
//! endpoint, not silently accepted.
//!
//! Audit 10/10 plan item 1.7 adds the chain-evidence contract, every case
//! through this endpoint: pending evidence (the digest event still in
//! `audit_ingest`) is never reported verified; missing evidence fails; a
//! forged unsigned digest header, whether the only one or the newest of two,
//! is not verified; a second digest header for one decision is not verified;
//! authentic chained and signed sync-path decisions still verify. The harness
//! configures audit signing, as production requires.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `approval_lifecycle.rs`.
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic%20-c%20statement_timeout%3D60000"
//! $env:TEST_REDIS_HOST = "127.0.0.1"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test signoff_verify -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
    AuditUserContext,
};
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ROLE_GRANT_ACTION: &str = "security.role_grant";
const SIGNING_KEY_ID: &str = "signoff-verify-test-key";

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
            "approval": {{ "required_actions": ["{ROLE_GRANT_ACTION}"], "ttl_hours": 72 }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
    test_system_with(true).await
}

/// `chainer_enabled = true` is D-316's production default: a decision's
/// digest event waits in `audit_ingest` until the chainer batches it.
/// Audit signing is on in both modes, as production requires.
async fn test_system_with(chainer_enabled: bool) -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &url);
    config.audit.chainer_enabled = chainer_enabled;
    config.audit.signing_enabled = true;
    config.audit.signing_key_id = SIGNING_KEY_ID.to_owned();
    config.audit.signing_private_key = "5a".repeat(32);

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

    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        .build()
        .await
        .expect("build EngineSystem");
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
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

async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("signoff-verify-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

    if admin {
        let privilege_id: Uuid =
            sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
                .fetch_one(db)
                .await
                .expect("system.admin privilege must already be seeded by attome_security::seed");
        sqlx::query(
            "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
             VALUES ($1, $2, $3, true, NOW())",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("insert throwaway admin grant");
    }

    (user_id, session_cookie(user_id))
}

async fn seed_role(db: &attome_db::DbPool) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')",
    )
    .bind(role_id)
    .bind(format!("signoff-verify-test-role-{role_id}"))
    .bind("throwaway test role")
    .execute(db)
    .await
    .expect("insert throwaway role");
    role_id
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn assign_role_request(admin_cookie: &str, user_id: Uuid, role_id: Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/security/users/{user_id}/roles"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({ "role_id": role_id }).to_string(),
        ))
        .unwrap()
}

fn decide_request(
    admin_cookie: &str,
    request_id: Uuid,
    decision: &str,
    row_version: i64,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/approvals/{request_id}/decide"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({ "decision": decision, "row_version": row_version }).to_string(),
        ))
        .unwrap()
}

fn verify_request(cookie: &str, decision_id: Uuid) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!("/api/v1/signoff/{decision_id}/verify"))
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

async fn submit_role_grant_request(
    app: &axum::Router,
    requester_cookie: &str,
    user_id: Uuid,
    role_id: Uuid,
) -> Uuid {
    let resp = app
        .clone()
        .oneshot(assign_role_request(requester_cookie, user_id, role_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = body_json(resp).await;
    body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

async fn latest_grant_id(db: &attome_db::DbPool, request_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM approval_grant WHERE request_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(request_id)
    .fetch_one(db)
    .await
    .expect("query approval_grant for the just-decided grant row")
}

// ── Item 1.7 helpers ─────────────────────────────────────────────────────

/// One approved role-grant decision, made through the real decide route.
struct Decided {
    state: EngineState,
    app: axum::Router,
    db: attome_db::DbPool,
    approver_id: Uuid,
    approver_cookie: String,
    request_id: Uuid,
    decision_id: Uuid,
}

async fn decided_grant(chainer_enabled: bool) -> Option<Decided> {
    let system = test_system_with(chainer_enabled).await?;
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (approver_id, approver_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let state = system.state().clone();
    let db = state.base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;
    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let decision_id = latest_grant_id(&db, request_id).await;

    Some(Decided {
        state,
        app,
        db,
        approver_id,
        approver_cookie,
        request_id,
        decision_id,
    })
}

/// Calls `GET /api/v1/signoff/{decision_id}/verify` and returns its body.
async fn verify(d: &Decided) -> Value {
    let resp = d
        .app
        .clone()
        .oneshot(verify_request(&d.approver_cookie, d.decision_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    body_json(resp).await
}

async fn run_chainer(state: &EngineState) {
    attome_audit::chainer::run_once(&state.base.db, state.audit_signer.as_deref(), 1000, None)
        .await
        .expect("run the audit chainer");
}

async fn digest_ingest_rows(db: &attome_db::DbPool, decision_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_ingest \
         WHERE payload->>'record_id' = $1 AND payload->>'operation' = 'DecisionDigest'",
    )
    .bind(decision_id.to_string())
    .fetch_one(db)
    .await
    .expect("count DecisionDigest ingest rows")
}

async fn digest_header_rows(db: &attome_db::DbPool, decision_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_header WHERE record_id = $1 AND operation = $2")
        .bind(decision_id)
        .bind(AuditOperation::DecisionDigest as i32)
        .fetch_one(db)
        .await
        .expect("count DecisionDigest header rows")
}

/// Deletes the decision's pending digest event, as the runtime role still
/// can (`audit_ingest` DELETE is the documented Phase 9.8 exception).
/// Returns the event's `organization_ref`.
async fn delete_pending_digest_event(db: &attome_db::DbPool, decision_id: Uuid) -> Uuid {
    let org: Uuid = sqlx::query_scalar(
        "DELETE FROM audit_ingest \
         WHERE payload->>'record_id' = $1 AND payload->>'operation' = 'DecisionDigest' \
         RETURNING (payload->>'organization_ref')::uuid",
    )
    .bind(decision_id.to_string())
    .fetch_one(db)
    .await
    .expect("delete exactly the decision's pending digest event");
    org
}

async fn digest_event_org(db: &attome_db::DbPool, decision_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT (payload->>'organization_ref')::uuid FROM audit_ingest \
         WHERE payload->>'record_id' = $1 AND payload->>'operation' = 'DecisionDigest' \
         LIMIT 1",
    )
    .bind(decision_id.to_string())
    .fetch_one(db)
    .await
    .expect("read the digest event's organization")
}

/// A DB-level writer's forgery of the decision itself: approved becomes
/// rejected, and the stored digest is recomputed with the public formula so
/// the digest check still matches.
async fn rewrite_decision_and_digest(db: &attome_db::DbPool, decision_id: Uuid) {
    let (request_id, step, approver_id, decided_at): (Uuid, i32, Uuid, DateTime<Utc>) =
        sqlx::query_as(
            "SELECT request_id, step, approver_id, decided_at \
             FROM approval_grant WHERE id = $1",
        )
        .bind(decision_id)
        .fetch_one(db)
        .await
        .expect("read the grant");
    let forged_digest = attome_audit::signoff::compute_decision_digest(
        request_id,
        step,
        "rejected",
        approver_id,
        decided_at,
        None,
    );
    sqlx::query(
        "UPDATE approval_grant \
         SET decision = 'rejected', signature = jsonb_set(signature, '{digest}', to_jsonb($1::text)) \
         WHERE id = $2",
    )
    .bind(&forged_digest)
    .bind(decision_id)
    .execute(db)
    .await
    .expect("rewrite the decision and its stored digest");
}

/// Appends an unsigned `DecisionDigest` header for the decision with no batch
/// reference — what a DB-level writer produces with the public hash formula
/// and no signing key: the sync-path writer with no signer.
async fn append_unsigned_digest_header(db: &attome_db::DbPool, decision_id: Uuid, org: Uuid) {
    let (approver_id, decided_at, signature): (Uuid, DateTime<Utc>, Option<Value>) =
        sqlx::query_as(
            "SELECT approver_id, decided_at, signature FROM approval_grant WHERE id = $1",
        )
        .bind(decision_id)
        .fetch_one(db)
        .await
        .expect("read the grant");
    let event = AuditEvent {
        organization_ref: org,
        category: AuditCategory::Security,
        entity_name: Some("approval_grant".to_string()),
        record_id: Some(decision_id),
        operation: AuditOperation::DecisionDigest,
        version_before: None,
        version_after: None,
        user_context: AuditUserContext {
            user_id: approver_id,
            user_name: "forger".into(),
            user_display_name: "Forger".into(),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: decided_at,
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(ROLE_GRANT_ACTION.to_string()),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: signature,
    };
    AuditService::new(db, None)
        .write(event)
        .await
        .expect("append an unsigned digest header");
}

fn is_null(body: &Value, field: &str) -> bool {
    body[field].is_null()
}

// ── Happy path ───────────────────────────────────────────────────────────

/// A freshly decided request's digest verifies clean once its digest event
/// is chained: recorded, matching, and the chain row checks out.
#[tokio::test]
async fn freshly_decided_grant_verifies_clean() {
    let system = skip_if_no_db!(test_system().await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let decision_id = latest_grant_id(&db, request_id).await;

    // Item 1.7: under the chainer the digest event is pending until chained,
    // and pending is never reported verified.
    run_chainer(&state).await;

    let resp = app
        .clone()
        .oneshot(verify_request(&approver_cookie, decision_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["decision_id"], decision_id.to_string());
    assert_eq!(body["request_id"], request_id.to_string());
    assert_eq!(body["decision"], "approved");
    assert!(
        body["digest_recorded"].as_bool().unwrap(),
        "digest must have been recorded by decide_approval: {body:?}"
    );
    assert!(
        body["digest_matches"].as_bool().unwrap(),
        "an untampered decision's recomputed digest must match what was stored: {body:?}"
    );
    assert!(
        body["verified"].as_bool().unwrap(),
        "an untampered, freshly decided and chained grant must verify clean: {body:?}"
    );
}

/// The most important test in this file (per the module's own task scope):
/// a decision mutated directly against the database — something never
/// possible through this platform's own API (guidelines §4) — is caught by
/// the verify endpoint, not silently accepted as still valid.
#[tokio::test]
async fn tampering_the_stored_decision_fails_verification() {
    let system = skip_if_no_db!(test_system().await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let state = system.state().clone();
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let decision_id = latest_grant_id(&db, request_id).await;

    // Sanity: verifies clean before any tampering, once chained (item 1.7).
    run_chainer(&state).await;
    let resp = app
        .clone()
        .oneshot(verify_request(&approver_cookie, decision_id))
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert!(body["verified"].as_bool().unwrap(), "{body:?}");

    // Directly mutate the stored decision — simulating exactly the kind of
    // direct-DB tamper the platform's own API never permits (guidelines §4)
    // but that this endpoint exists to detect if it ever happens anyway.
    // The digest recorded at decision time still names the ORIGINAL
    // decided_by, so recomputing against this new one must not match it.
    let other_approver = Uuid::now_v7();
    sqlx::query("UPDATE approval_grant SET approver_id = $1, decided_by = $1 WHERE id = $2")
        .bind(other_approver)
        .bind(decision_id)
        .execute(&db)
        .await
        .expect("tamper the grant row's decided_by");

    let resp = app
        .clone()
        .oneshot(verify_request(&approver_cookie, decision_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(
        !body["digest_matches"].as_bool().unwrap(),
        "a decision tampered directly in the database must not match its recorded digest: {body:?}"
    );
    assert!(
        !body["verified"].as_bool().unwrap(),
        "a tampered decision must never report as verified: {body:?}"
    );

    // A second, independent tamper shape: the `decision` value itself
    // (approved -> rejected) rewritten in place.
    sqlx::query("UPDATE approval_grant SET decision = 'rejected' WHERE id = $1")
        .bind(decision_id)
        .execute(&db)
        .await
        .expect("tamper the grant row's decision");

    let resp = app
        .clone()
        .oneshot(verify_request(&approver_cookie, decision_id))
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert!(!body["digest_matches"].as_bool().unwrap());
    assert!(!body["verified"].as_bool().unwrap());
}

/// A decision that never had a digest recorded (simulated here by clearing
/// the `signature` column, standing in for a decision made before this
/// feature existed) reports `digest_recorded: false` and never `verified`,
/// rather than treating "nothing to compare" as a pass.
#[tokio::test]
async fn a_decision_with_no_recorded_digest_never_reports_verified() {
    let system = skip_if_no_db!(test_system().await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;
    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let decision_id = latest_grant_id(&db, request_id).await;

    sqlx::query("UPDATE approval_grant SET signature = NULL WHERE id = $1")
        .bind(decision_id)
        .execute(&db)
        .await
        .expect("clear the recorded digest");

    let resp = app
        .clone()
        .oneshot(verify_request(&approver_cookie, decision_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(!body["digest_recorded"].as_bool().unwrap());
    assert!(!body["digest_matches"].as_bool().unwrap());
    assert!(!body["verified"].as_bool().unwrap());
}

/// Unknown decision id -> 404, not a masked/internal error.
#[tokio::test]
async fn unknown_decision_id_is_not_found() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(verify_request(&admin_cookie, Uuid::now_v7()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A non-admin caller is refused, same coarse `system.admin` gate the rest
/// of the approval admin surface uses.
#[tokio::test]
async fn non_admin_cannot_call_verify() {
    let system = skip_if_no_db!(test_system().await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let (_, non_admin_cookie) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;
    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let decision_id = latest_grant_id(&db, request_id).await;

    let resp = app
        .clone()
        .oneshot(verify_request(&non_admin_cookie, decision_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Item 1.7: chain-evidence contract ────────────────────────────────────

/// Legitimate pending evidence is pending, never verified: the digest event
/// is still in `audit_ingest`. Once the chainer runs, the same decision
/// verifies.
#[tokio::test]
async fn pending_audit_evidence_is_not_verified_until_the_chainer_runs() {
    let d = skip_if_no_db!(decided_grant(true).await);

    assert_eq!(digest_ingest_rows(&d.db, d.decision_id).await, 1);
    assert_eq!(
        digest_header_rows(&d.db, d.decision_id).await,
        0,
        "precondition: the digest event is still pending"
    );

    let body = verify(&d).await;
    assert!(body["digest_recorded"].as_bool().unwrap(), "{body:?}");
    assert!(body["digest_matches"].as_bool().unwrap(), "{body:?}");
    assert!(
        !body["verified"].as_bool().unwrap(),
        "pending audit evidence must never be reported verified: {body}"
    );
    assert!(
        is_null(&body, "chain_row_hash_ok") && is_null(&body, "chain_row_signature_ok"),
        "pending evidence leaves both chain fields null: {body}"
    );

    run_chainer(&d.state).await;
    assert_eq!(digest_header_rows(&d.db, d.decision_id).await, 1);

    let body = verify(&d).await;
    assert!(
        body["verified"].as_bool().unwrap(),
        "once chained, the authentic decision verifies: {body}"
    );
    assert_eq!(body["chain_row_hash_ok"], true, "{body}");
}

/// Missing evidence fails: the digest event is in neither the header table
/// nor `audit_ingest`.
#[tokio::test]
async fn missing_audit_evidence_fails_verification() {
    let d = skip_if_no_db!(decided_grant(true).await);

    delete_pending_digest_event(&d.db, d.decision_id).await;
    assert_eq!(digest_ingest_rows(&d.db, d.decision_id).await, 0);
    assert_eq!(digest_header_rows(&d.db, d.decision_id).await, 0);

    let body = verify(&d).await;
    assert!(
        !body["verified"].as_bool().unwrap(),
        "missing audit evidence must never be reported verified: {body}"
    );
    assert_eq!(
        body["chain_row_hash_ok"], false,
        "missing evidence is a failure, not pending: {body}"
    );
}

/// A forged unsigned digest header that is the decision's only header: the
/// pending event was deleted and replaced, and the decision and its digest
/// rewritten consistently. Only the single-row signature rule catches this.
#[tokio::test]
async fn a_forged_unsigned_digest_header_replacing_pending_evidence_is_not_verified() {
    let d = skip_if_no_db!(decided_grant(true).await);

    let org = delete_pending_digest_event(&d.db, d.decision_id).await;
    rewrite_decision_and_digest(&d.db, d.decision_id).await;
    append_unsigned_digest_header(&d.db, d.decision_id, org).await;
    assert_eq!(digest_header_rows(&d.db, d.decision_id).await, 1);

    let body = verify(&d).await;
    assert_eq!(body["decision"], "rejected");
    assert!(
        body["digest_matches"].as_bool().unwrap(),
        "the forger recomputed the digest, so the digest check alone passes: {body}"
    );
    assert!(
        !body["verified"].as_bool().unwrap(),
        "a forged unsigned digest header must never verify: {body}"
    );
    assert_eq!(body["chain_row_signature_ok"], false, "{body}");
}

/// A forged unsigned digest header appended after the authentic chained one
/// becomes the newest header for the decision.
#[tokio::test]
async fn a_forged_unsigned_newest_digest_header_is_not_verified() {
    let d = skip_if_no_db!(decided_grant(true).await);

    run_chainer(&d.state).await;
    let body = verify(&d).await;
    assert!(
        body["verified"].as_bool().unwrap(),
        "sanity: authentic before forging: {body}"
    );

    let org = digest_event_org(&d.db, d.decision_id).await;
    rewrite_decision_and_digest(&d.db, d.decision_id).await;
    append_unsigned_digest_header(&d.db, d.decision_id, org).await;
    assert_eq!(digest_header_rows(&d.db, d.decision_id).await, 2);

    let body = verify(&d).await;
    assert_eq!(body["decision"], "rejected");
    assert!(body["digest_matches"].as_bool().unwrap(), "{body}");
    assert!(
        !body["verified"].as_bool().unwrap(),
        "a forged unsigned newest digest header must never verify: {body}"
    );
}

/// Two authentic, chained digest events for one decision are ambiguous
/// evidence, so the decision is not verified.
#[tokio::test]
async fn a_second_digest_header_for_the_same_decision_is_not_verified() {
    let d = skip_if_no_db!(decided_grant(true).await);

    run_chainer(&d.state).await;
    let body = verify(&d).await;
    assert!(body["verified"].as_bool().unwrap(), "sanity: {body}");

    attome_audit::signoff::record_decision_digest(
        &d.state,
        d.request_id,
        d.approver_id,
        attome_approval::Decision::Approve,
    )
    .await
    .expect("record a second digest event for the same decision");
    run_chainer(&d.state).await;
    assert_eq!(digest_header_rows(&d.db, d.decision_id).await, 2);

    let body = verify(&d).await;
    assert!(body["digest_matches"].as_bool().unwrap(), "{body}");
    assert!(
        !body["verified"].as_bool().unwrap(),
        "a decision with two digest headers must not verify: {body}"
    );
}

/// Authentic evidence on the sync path (no chainer): the digest header is
/// written signed at decision time and verifies immediately.
#[tokio::test]
async fn a_signed_sync_path_decision_verifies() {
    let d = skip_if_no_db!(decided_grant(false).await);

    assert_eq!(digest_header_rows(&d.db, d.decision_id).await, 1);
    let body = verify(&d).await;
    assert!(
        body["verified"].as_bool().unwrap(),
        "an authentic signed sync-path decision verifies: {body}"
    );
    assert_eq!(body["chain_row_hash_ok"], true, "{body}");
    assert_eq!(body["chain_row_signature_ok"], true, "{body}");
}

// ── A-2: the chain binds the decision digest (audit 10/10 plan Phase 2) ────

/// Register item A-2. A DB-level writer rewrites the decision and recomputes
/// the unkeyed stored digest with the public formula, leaving the authentic,
/// chained digest event untouched. Before hash v2 this verified: the digest
/// matched and the header row still checked out. Now the digest event carries
/// the original digest in `event_name`, which hash v2 covers, so the rewrite
/// no longer verifies — on the chainer path and on the signed sync path.
#[tokio::test]
async fn a_grant_rewritten_with_a_recomputed_digest_is_caught_by_the_chain_bound_digest() {
    for chainer_enabled in [true, false] {
        let d = skip_if_no_db!(decided_grant(chainer_enabled).await);
        if chainer_enabled {
            run_chainer(&d.state).await;
        }
        let body = verify(&d).await;
        assert!(
            body["verified"].as_bool().unwrap(),
            "sanity: authentic before forging (chainer_enabled = {chainer_enabled}): {body}"
        );

        rewrite_decision_and_digest(&d.db, d.decision_id).await;
        assert_eq!(digest_header_rows(&d.db, d.decision_id).await, 1);

        let body = verify(&d).await;
        assert_eq!(body["decision"], "rejected");
        assert!(
            body["digest_matches"].as_bool().unwrap(),
            "the forger recomputed the stored digest, so that check alone passes: {body}"
        );
        assert_eq!(
            body["chain_row_hash_ok"], true,
            "the authentic digest event itself is untouched: {body}"
        );
        assert!(
            !body["verified"].as_bool().unwrap(),
            "the chain-bound digest names the original decision, so the rewrite must not \
             verify (chainer_enabled = {chainer_enabled}): {body}"
        );
    }
}

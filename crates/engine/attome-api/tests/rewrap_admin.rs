//! Regression coverage for `rewrap_admin.rs` — the admin trigger for
//! `EngineJob::RewrapSecrets` (key/crypto rotation). This surface
//! previously had zero test coverage: the endpoint that rotates encryption
//! keys was completely unguarded, so a regression (wrong grant, a
//! duplicated/partial-state rewrap job, a trigger racing an in-progress
//! rewrap) would not have been caught by CI.
//!
//! Covers:
//! - non-admin rejection (`403`) — the "wrong grant" case,
//! - an unknown `domain` path segment (`422 Validation`),
//! - the ungated happy path — the triggered job actually lands in
//!   `apalis.jobs` with the expected `job_type`/`dedup_key`/`status`,
//! - a second trigger for the same domain before the first job has run does
//!   NOT enqueue a second row (the dedup key's whole job — partial/duplicate
//!   state protection),
//! - a trigger while a worker already holds the domain's advisory lock is
//!   rejected `409 Conflict` rather than queuing a redundant concurrent pass,
//!   and a subsequent trigger succeeds once that lock is released,
//! - the D-195 four-eyes approval gate: submit-without-enqueue, separation
//!   of duties (a requester cannot approve their own request), a different
//!   admin's approval actually enqueueing the job, and re-deciding an
//!   already-closed request (`409`).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `jobs_admin.rs`/
//! `approval_role_grant.rs`.
//! **Verified 2026-08-24 (MAINT-10): 8 passed, 0 failed, 141.64s** against a
//! real Postgres and Redis, retiring the "Not run in this session (code-only,
//! no DB/Redis access) — TODO: run against a throwaway database" note this
//! header carried. The **elapsed time** is the evidence, not the `ok`: this
//! suite reports green in ~0.01s when `DATABASE_URL` is absent, so a pass
//! alone does not distinguish a real run from a skipped one.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test rewrap_admin -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// `required_actions`: pass `&["security.rewrap"]` to gate the trigger
/// behind four-eyes approval, or `&[]` for today's default (ungated)
/// behavior — same knob `approval_role_grant.rs` uses.
fn test_config(required_actions: &[&str]) -> AppConfig {
    let required_actions_json = serde_json::to_string(required_actions).unwrap();
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
            "approval": {{ "required_actions": {required_actions_json} }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system(required_actions: &[&str]) -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config(required_actions);
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
        .bind(format!("rewrap-admin-test-{user_id}"))
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

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn trigger_request(cookie: &str, domain: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/security/rewrap/{domain}"))
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
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

// `Debug` is required by the `assert_eq!`/`assert!` calls below, which format
// a `Vec<QueuedJob>` with `{:?}` on failure. Safe to derive here despite the
// concurrent "redact secret Debug impls" work: this is a test-local row
// projection of exactly two non-sensitive columns (`status`, `job_type`) — it
// carries no key material, no credential, and no payload, so there is nothing
// for a Debug impl to leak.
#[derive(Debug, sqlx::FromRow)]
struct QueuedJob {
    status: String,
    job_type: String,
}

async fn queued_rewrap_jobs(db: &attome_db::DbPool, dedup_key: &str) -> Vec<QueuedJob> {
    sqlx::query_as("SELECT status, job_type FROM apalis.jobs WHERE dedup_key = $1")
        .bind(dedup_key)
        .fetch_all(db)
        .await
        .expect("query apalis.jobs for the rewrap dedup key")
}

/// Wrong-grant rejection: a non-admin session must never be able to trigger
/// a key rotation.
#[tokio::test]
async fn non_admin_gets_403() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, non_admin_cookie) = seed_user(&system, false).await;
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(trigger_request(&non_admin_cookie, "mfa"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A `domain` path segment that isn't `mfa`/`s2s`/`erasure` must be rejected
/// as a validation error before anything is enqueued or locked.
#[tokio::test]
async fn unknown_domain_is_a_validation_error() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(trigger_request(&admin_cookie, "not-a-real-domain"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// `approval.required_actions = []` (today's default): triggering a rewrap
/// directly enqueues the job — proving it actually lands in `apalis.jobs`
/// on the batch queue with the domain's dedup key, not just that the HTTP
/// call returns 202.
#[tokio::test]
async fn ungated_trigger_enqueues_a_batch_job_with_the_domain_dedup_key() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(trigger_request(&admin_cookie, "mfa"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = body_json(resp).await;
    assert_eq!(body["domain"], "mfa");
    assert_eq!(body["enqueued"], true);
    assert_eq!(body["approval_pending"], false);
    assert!(body["approval_request_id"].is_null());

    let jobs = queued_rewrap_jobs(&db, "rewrap:mfa").await;
    assert_eq!(jobs.len(), 1, "exactly one job must be queued: {jobs:?}");
    assert_eq!(jobs[0].job_type, "attome_job_batch");
    assert_eq!(jobs[0].status, "Pending");
}

/// Partial/duplicate-state protection: a second trigger for the same domain
/// before the first job has run must NOT queue a second concurrent rewrap —
/// the dedup key (`rewrap:{domain}`) collapses it to a no-op, even though
/// the HTTP response still reports success both times (matching
/// `do_trigger_rewrap`'s "the enqueue is best-effort dedup, not a client-
/// visible distinction" contract).
#[tokio::test]
async fn a_second_trigger_before_the_first_runs_does_not_duplicate_the_job() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let first = app
        .clone()
        .oneshot(trigger_request(&admin_cookie, "s2s"))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    let second = app
        .clone()
        .oneshot(trigger_request(&admin_cookie, "s2s"))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    let second_body = body_json(second).await;
    assert_eq!(second_body["enqueued"], true);

    let jobs = queued_rewrap_jobs(&db, "rewrap:s2s").await;
    assert_eq!(
        jobs.len(),
        1,
        "two triggers before the first job runs must still leave exactly one \
         queued row, not two concurrent rewraps: {jobs:?}"
    );
}

/// A trigger for a domain whose rewrap is already in progress (a worker
/// holding the same `pg_try_advisory_xact_lock` namespace `do_trigger_rewrap`
/// checks) must be rejected `409 Conflict` rather than silently queuing a
/// redundant concurrent pass — and must succeed again once that lock is
/// released.
#[tokio::test]
async fn trigger_conflicts_while_a_worker_already_holds_the_domain_lock() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let mut holder_tx = db.begin().await.expect("begin lock-holding tx");
    // Blocking form deliberately, and only here: this transaction must *hold*
    // the lock, not probe it. Namespace and key must match `do_trigger_rewrap`
    // exactly (L-1 / TODO-027) — a mismatch would take an unrelated lock and
    // the assertion below would silently stop testing contention.
    sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_auth::ADVISORY_LOCK_NAMESPACE)
        .bind("attome-auth/rewrap:erasure")
        .execute(&mut *holder_tx)
        .await
        .expect("acquire the erasure rewrap lock in the holding tx");

    let resp = app
        .clone()
        .oneshot(trigger_request(&admin_cookie, "erasure"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "a trigger must not queue a redundant rewrap while one is already running"
    );

    holder_tx.rollback().await.expect("release the held lock");

    let resp = app
        .clone()
        .oneshot(trigger_request(&admin_cookie, "erasure"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "once the lock is released, triggering the same domain must succeed"
    );
}

/// `approval.required_actions = ["security.rewrap"]`: the same trigger now
/// returns `202 approval_pending: true` and does NOT enqueue anything.
#[tokio::test]
async fn gated_trigger_submits_and_does_not_enqueue() {
    let system = skip_if_no_db!(test_system(&["security.rewrap"]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(trigger_request(&admin_cookie, "mfa"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = body_json(resp).await;
    assert_eq!(body["enqueued"], false);
    assert_eq!(body["approval_pending"], true);
    assert!(body["approval_request_id"].is_string());

    let jobs = queued_rewrap_jobs(&db, "rewrap:mfa").await;
    assert!(
        jobs.is_empty(),
        "a gated trigger must not enqueue anything until approved: {jobs:?}"
    );
}

/// Separation of duties: the admin who requested the rewrap cannot decide
/// their own approval request (`attome_approval::decide`'s core invariant).
#[tokio::test]
async fn requester_cannot_approve_own_rewrap_request() {
    let system = skip_if_no_db!(test_system(&["security.rewrap"]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(trigger_request(&admin_cookie, "mfa"))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let request_id: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let resp = app
        .clone()
        .oneshot(decide_request(&admin_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A different `system.admin` approving actually enqueues the rewrap job in
/// the same call, and re-deciding the now-closed request is a `409`, not a
/// silent no-op or a second enqueue.
#[tokio::test]
async fn different_admin_approving_enqueues_the_rewrap_and_a_second_decide_conflicts() {
    let system = skip_if_no_db!(test_system(&["security.rewrap"]).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(trigger_request(&requester_cookie, "erasure"))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let request_id: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    assert_eq!(body["executed"]["domain"], "erasure");
    assert_eq!(body["executed"]["enqueued"], true);

    let jobs = queued_rewrap_jobs(&db, "rewrap:erasure").await;
    assert_eq!(
        jobs.len(),
        1,
        "approval must actually enqueue exactly one rewrap job: {jobs:?}"
    );
    assert_eq!(jobs[0].job_type, "attome_job_batch");

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

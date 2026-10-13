//! D-195 / `document/detailed-plans/P-four-eyes-approval.md` §6/§10 — the
//! remaining approval-lifecycle coverage no wired-action test file exercises
//! yet: cancellation (the requester withdrawing their own request),
//! rejection, expiry, two concurrent `decide` calls racing the same
//! request, and (an audit finding) `retry-execution`'s recovery path for a
//! request stuck `approved` with no `executed_at` — see
//! `approval_admin::retry_execution`'s doc comment for why that state can
//! happen and what the endpoint does about it. Uses
//! `attome_security::admin::ACTION_ROLE_GRANT` (direct user->role assignment)
//! as the vehicle — already fully wired and proven by
//! `approval_role_grant.rs`, and the cheapest action to seed, so these
//! tests exercise `attome_approval`'s own lifecycle machinery rather than
//! re-proving any specific action's gate.
//!
//! **Verified 2026-08-12** — all 11 tests run green against the live
//! `attomedb_test` stack (Postgres 5556 / Redis 6380), which retires the
//! "NOT RUN in this session … treat as unverified until run" caveat this
//! header carried from the code-only session that wrote it.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `jobs_admin.rs`. Two env details
//! bite in setup, not at an assertion: `attome-api` suites reach the database
//! only through `attome_db::create_pool`'s `APP_ENV=debug` override (without it
//! the inline config's placeholder `"user": "unused"` is used and Postgres
//! rejects the password), and migration `0018`'s 500ms role-level
//! `statement_timeout` has to be raised in the URL or the per-binary database
//! clone is cancelled mid-`CREATE DATABASE`.
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic%20-c%20statement_timeout%3D60000"
//! $env:TEST_REDIS_HOST = "127.0.0.1"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test approval_lifecycle -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
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
const ROLE_GRANT_ACTION: &str = "security.role_grant";

fn test_config(ttl_hours: i64) -> AppConfig {
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
            "approval": {{ "required_actions": ["{ROLE_GRANT_ACTION}"], "ttl_hours": {ttl_hours} }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system(ttl_hours: i64) -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config(ttl_hours);
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
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("approval-lifecycle-test-{user_id}"))
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
    .bind(format!("approval-lifecycle-test-role-{role_id}"))
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

fn retry_execution_request(admin_cookie: &str, request_id: Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/admin/approvals/{request_id}/retry-execution"
        ))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

fn cancel_request(admin_cookie: &str, request_id: Uuid, row_version: i64) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/approvals/{request_id}/cancel"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({ "row_version": row_version }).to_string(),
        ))
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

// ── Cancellation ─────────────────────────────────────────────────────────

/// The original requester can withdraw their own pending request, and the
/// cancelled request can no longer be decided.
#[tokio::test]
async fn requester_can_cancel_own_pending_request() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    let resp = app
        .clone()
        .oneshot(cancel_request(&requester_cookie, request_id, 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "cancelled");

    // A cancelled request can no longer be decided.
    let resp = app
        .clone()
        .oneshot(decide_request(&requester_cookie, request_id, "approve", 1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// A different admin has no standing to cancel someone else's request — the
/// inverse of `decide()`'s separation-of-duties check.
#[tokio::test]
async fn non_requester_cannot_cancel_someone_elses_request() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, other_admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    let resp = app
        .clone()
        .oneshot(cancel_request(&other_admin_cookie, request_id, 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Rejection ────────────────────────────────────────────────────────────

/// A different admin's reject closes the request without assigning the
/// role, and a rejected request cannot later be approved.
#[tokio::test]
async fn different_admin_rejecting_closes_the_request_without_assigning() {
    let system = skip_if_no_db!(test_system(72).await);
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
        .oneshot(decide_request(&approver_cookie, request_id, "reject", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "rejected");
    assert!(body["executed"].is_null());

    let has_role: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
    )
    .bind(target_user_id)
    .bind(role_id)
    .fetch_one(&db)
    .await
    .expect("query user_account_mm_role");
    assert!(!has_role);

    // A rejected request cannot later be approved.
    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ── Expiry ───────────────────────────────────────────────────────────────

/// A request whose `expires_at` has already passed cannot be decided — the
/// decide call itself flips it to `expired` (`decide()`'s own doc comment)
/// rather than silently honoring a stale approval. Uses `approval.ttl_hours
/// = 0` semantics indirectly by directly backdating `expires_at` after
/// submit, since `ttl_hours` itself is validated `> 0` at boot (can't
/// configure an already-expired TTL).
#[tokio::test]
async fn decide_on_an_expired_request_fails_and_flips_it_to_expired() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    sqlx::query("UPDATE approval_request SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1")
        .bind(request_id)
        .execute(&db)
        .await
        .expect("backdate expires_at");

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let status: String = sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
        .bind(request_id)
        .fetch_one(&db)
        .await
        .expect("query approval_request");
    assert_eq!(status, "expired");
}

/// `attome_approval::sweep_expired` reaps a stale `pending` row directly (the
/// periodic-task path, `attome_api::spawn_approval_expiry_sweep` — this test
/// calls the underlying function rather than waiting on that task's
/// interval).
#[tokio::test]
async fn sweep_expired_reaps_a_backdated_pending_request() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    sqlx::query("UPDATE approval_request SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1")
        .bind(request_id)
        .execute(&db)
        .await
        .expect("backdate expires_at");

    // Deliberately no assertion on the return value: `sweep_expired` is one
    // unfiltered `UPDATE ... WHERE status = 'pending' AND expires_at <= NOW()`
    // over the whole table, so its count covers every expired request in the
    // database — including ones this test never created. `attome-workflow`'s
    // `execution.rs` alone leaves pending approvals behind with `ttl_hours: 1`
    // against this same shared throwaway database, so `== 1` would start
    // failing an hour after that suite last ran, and `>= 1` would still be
    // racy the other way (a concurrent sweep can reap this row first).
    // The per-request status below is the exact, order-independent proof
    // (F-006, TODO-008).
    attome_approval::sweep_expired(&db)
        .await
        .expect("sweep_expired");

    let status: String = sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
        .bind(request_id)
        .fetch_one(&db)
        .await
        .expect("query approval_request");
    assert_eq!(status, "expired");
}

// ── Concurrency ──────────────────────────────────────────────────────────

/// Two different admins deciding the same request at the same time: exactly
/// one wins (200, the grant executes), the other loses to the
/// `pg_try_advisory_xact_lock` (`decide()`'s doc comment) and observes a 409
/// or 403-shaped conflict — never both succeeding, never a double-assign.
#[tokio::test]
async fn concurrent_decisions_on_the_same_request_never_both_win() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_a_cookie) = seed_user(&system, true).await;
    let (_, approver_b_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    let app_a = app.clone();
    let app_b = app.clone();
    let req_a = decide_request(&approver_a_cookie, request_id, "approve", 0);
    let req_b = decide_request(&approver_b_cookie, request_id, "approve", 0);

    let (resp_a, resp_b) = tokio::join!(app_a.oneshot(req_a), app_b.oneshot(req_b));
    let status_a = resp_a.unwrap().status();
    let status_b = resp_b.unwrap().status();

    let ok_count = [status_a, status_b]
        .iter()
        .filter(|s| **s == StatusCode::OK)
        .count();
    assert_eq!(
        ok_count, 1,
        "exactly one of the two concurrent decisions must win (200), got {status_a}/{status_b}"
    );
    assert!(
        [status_a, status_b]
            .iter()
            .any(|s| *s == StatusCode::CONFLICT || *s == StatusCode::FORBIDDEN),
        "the losing decision must observe a conflict, got {status_a}/{status_b}"
    );

    let has_role: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
    )
    .bind(target_user_id)
    .bind(role_id)
    .fetch_one(&db)
    .await
    .expect("query user_account_mm_role");
    assert!(
        has_role,
        "the winning decision must have assigned the role exactly once"
    );
}

// ── Retry-execution recovery ────────────────────────────────────────────

/// The exact scenario `retry_execution`'s doc comment describes: a request
/// whose `decide()` committed `status = 'approved'` but whose
/// `execute_approved` never reached `mark_executed` — simulated directly
/// (there is no reachable failure-injection hook to make the real
/// `decide_approval` handler stop between those two steps) by backdating
/// the row's status without going through `/decide` at all. `retry-execution`
/// must actually perform the underlying role grant and leave the row
/// `executed` with a real `executed_at`, not just report success.
#[tokio::test]
async fn retry_execution_replays_a_stuck_approved_but_unexecuted_request() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, retrying_admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    sqlx::query("UPDATE approval_request SET status = 'approved' WHERE id = $1")
        .bind(request_id)
        .execute(&db)
        .await
        .expect("simulate a stuck approved-but-unexecuted request");

    let resp = app
        .clone()
        .oneshot(retry_execution_request(&retrying_admin_cookie, request_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(
        body["executed"].is_object(),
        "retry must return the executed action's result, got: {body:?}"
    );

    let has_role: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
    )
    .bind(target_user_id)
    .bind(role_id)
    .fetch_one(&db)
    .await
    .expect("query user_account_mm_role");
    assert!(has_role, "retry must actually perform the stuck action");

    let (status, executed_at): (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, executed_at FROM approval_request WHERE id = $1")
            .bind(request_id)
            .fetch_one(&db)
            .await
            .expect("query approval_request");
    assert_eq!(status, "executed");
    assert!(
        executed_at.is_some(),
        "mark_executed must have run as the last step of the retried execute_approved"
    );
}

/// A request still `pending` (never decided at all) has nothing to retry —
/// `retry-execution` must not be usable as a way to skip `decide()`.
#[tokio::test]
async fn retry_execution_rejects_a_request_that_is_still_pending() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    let resp = app
        .clone()
        .oneshot(retry_execution_request(&admin_cookie, request_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// A request the normal `/decide` path already fully executed must not be
/// retried a second time — `mark_executed`'s CAS would refuse it internally
/// either way, but this proves `retry-execution` itself refuses up front
/// rather than re-running `do_*` and relying on that inner guard alone.
#[tokio::test]
async fn retry_execution_rejects_an_already_executed_request() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(retry_execution_request(&approver_cookie, request_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// Same `system.admin` gate as every other endpoint in this file.
#[tokio::test]
async fn retry_execution_requires_admin() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, non_admin_cookie) = seed_user(&system, false).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;
    sqlx::query("UPDATE approval_request SET status = 'approved' WHERE id = $1")
        .bind(request_id)
        .execute(&db)
        .await
        .expect("simulate stuck state");

    let resp = app
        .clone()
        .oneshot(retry_execution_request(&non_admin_cookie, request_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── One execution per approval (D-518) ──────────────────────────────────

fn retry_execution_acknowledging_request(admin_cookie: &str, request_id: Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/admin/approvals/{request_id}/retry-execution?acknowledge_unknown_outcome=true"
        ))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

/// The stuck state `retry_execution_replays_a_stuck_approved_but_unexecuted_request`
/// simulates: approved, never executed.
async fn force_approved(db: &attome_db::DbPool, request_id: Uuid) {
    sqlx::query("UPDATE approval_request SET status = 'approved' WHERE id = $1")
        .bind(request_id)
        .execute(db)
        .await
        .expect("simulate a stuck approved-but-unexecuted request");
}

/// Simulates another call holding the execution claim, taken `minutes_ago`.
async fn hold_claim(db: &attome_db::DbPool, request_id: Uuid, claimant: Uuid, minutes_ago: i32) {
    sqlx::query(
        "UPDATE approval_request \
            SET status = 'executing', execution_claimed_by = $2, \
                execution_claimed_at = NOW() - make_interval(mins => $3), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(request_id)
    .bind(claimant)
    .bind(minutes_ago)
    .execute(db)
    .await
    .expect("simulate a held execution claim");
}

async fn status_and_claimant(db: &attome_db::DbPool, request_id: Uuid) -> (String, Option<Uuid>) {
    sqlx::query_as("SELECT status, execution_claimed_by FROM approval_request WHERE id = $1")
        .bind(request_id)
        .fetch_one(db)
        .await
        .expect("query approval_request")
}

/// The role grant upserts, so this proves "did not run" (0), not a count of
/// runs; how many calls ran it is shown by the responses and the claimant.
async fn role_assignments(db: &attome_db::DbPool, user_id: Uuid, role_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false",
    )
    .bind(user_id)
    .bind(role_id)
    .fetch_one(db)
    .await
    .expect("query user_account_mm_role")
}

/// Two admins retry the same stuck request at once: exactly one runs it, the
/// other gets `409`, and the request records the winner as its claimant.
#[tokio::test]
async fn concurrent_retries_of_a_stuck_request_execute_it_once() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (admin_a, cookie_a) = seed_user(&system, true).await;
    let (admin_b, cookie_b) = seed_user(&system, true).await;
    let mut targets = Vec::new();
    for _ in 0..3 {
        targets.push(seed_user(&system, false).await.0);
    }
    let db = system.state().base.db.clone();
    let role_id = seed_role(&db).await;
    let app = full_app(system);

    for target_user_id in targets {
        let request_id =
            submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;
        force_approved(&db, request_id).await;

        let (left, right) = tokio::join!(
            app.clone()
                .oneshot(retry_execution_request(&cookie_a, request_id)),
            app.clone()
                .oneshot(retry_execution_request(&cookie_b, request_id)),
        );
        let (left, right) = (left.unwrap().status(), right.unwrap().status());
        assert!(
            (left, right) == (StatusCode::OK, StatusCode::CONFLICT)
                || (left, right) == (StatusCode::CONFLICT, StatusCode::OK),
            "exactly one retry runs the action: {left} / {right}"
        );
        let winner = if left == StatusCode::OK {
            admin_a
        } else {
            admin_b
        };

        assert_eq!(
            status_and_claimant(&db, request_id).await,
            ("executed".to_string(), Some(winner))
        );
        assert_eq!(role_assignments(&db, target_user_id, role_id).await, 1);
    }
}

/// The deciding approval and a retry race: exactly one of them runs the
/// action, whichever claims first. The decision succeeds either way.
#[tokio::test]
async fn a_decision_racing_a_retry_executes_the_approval_once() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (approver, approver_cookie) = seed_user(&system, true).await;
    let (retrier, retrier_cookie) = seed_user(&system, true).await;
    let mut targets = Vec::new();
    for _ in 0..5 {
        targets.push(seed_user(&system, false).await.0);
    }
    let db = system.state().base.db.clone();
    let role_id = seed_role(&db).await;
    let app = full_app(system);

    for target_user_id in targets {
        let request_id =
            submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;

        let (decided, retried) = tokio::join!(
            app.clone()
                .oneshot(decide_request(&approver_cookie, request_id, "approve", 0)),
            app.clone()
                .oneshot(retry_execution_request(&retrier_cookie, request_id)),
        );
        let (decided, retried) = (decided.unwrap(), retried.unwrap());
        assert_eq!(decided.status(), StatusCode::OK);
        let retried = retried.status();
        assert!(
            retried == StatusCode::OK || retried == StatusCode::CONFLICT,
            "a losing retry is refused, not failed: {retried}"
        );
        let decide_ran_it = body_json(decided).await["executed"].is_object();
        let retry_ran_it = retried == StatusCode::OK;
        assert_eq!(
            usize::from(decide_ran_it) + usize::from(retry_ran_it),
            1,
            "exactly one call runs the action (decide: {decide_ran_it}, retry: {retried})"
        );

        let expected_claimant = if decide_ran_it { approver } else { retrier };
        assert_eq!(
            status_and_claimant(&db, request_id).await,
            ("executed".to_string(), Some(expected_claimant))
        );
        assert_eq!(role_assignments(&db, target_user_id, role_id).await, 1);
    }
}

/// A claim inside its lease belongs to a call that may still be running the
/// action: a retry is refused, even one that acknowledges an unknown outcome.
#[tokio::test]
async fn retry_refuses_a_request_another_call_is_executing() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let db = system.state().base.db.clone();
    let role_id = seed_role(&db).await;
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;
    let other_call = Uuid::now_v7();
    hold_claim(&db, request_id, other_call, 0).await;

    for request in [
        retry_execution_request(&admin_cookie, request_id),
        retry_execution_acknowledging_request(&admin_cookie, request_id),
    ] {
        let resp = app.clone().oneshot(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
    assert_eq!(
        status_and_claimant(&db, request_id).await,
        ("executing".to_string(), Some(other_call))
    );
    assert_eq!(role_assignments(&db, target_user_id, role_id).await, 0);
}

/// A claim past its lease has an unknown outcome. It is never re-run on a
/// plain retry; only an admin who acknowledges the unknown outcome takes it
/// over, and the action then runs under that admin's claim.
#[tokio::test]
async fn a_stale_claim_runs_again_only_when_the_unknown_outcome_is_acknowledged() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (admin, admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let db = system.state().base.db.clone();
    let role_id = seed_role(&db).await;
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;
    let hung_call = Uuid::now_v7();
    hold_claim(
        &db,
        request_id,
        hung_call,
        attome_approval::EXECUTION_CLAIM_LEASE_MINUTES + 1,
    )
    .await;

    let resp = app
        .clone()
        .oneshot(retry_execution_request(&admin_cookie, request_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        status_and_claimant(&db, request_id).await,
        ("executing".to_string(), Some(hung_call))
    );
    assert_eq!(role_assignments(&db, target_user_id, role_id).await, 0);

    let resp = app
        .clone()
        .oneshot(retry_execution_acknowledging_request(
            &admin_cookie,
            request_id,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(body_json(resp).await["executed"].is_object());
    assert_eq!(
        status_and_claimant(&db, request_id).await,
        ("executed".to_string(), Some(admin))
    );
    assert_eq!(role_assignments(&db, target_user_id, role_id).await, 1);
}

/// An executor error releases the claim: the request is `approved` again with
/// no claimant, and a later retry runs it.
#[tokio::test]
async fn an_executor_error_releases_the_claim_for_a_later_retry() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (admin, admin_cookie) = seed_user(&system, true).await;
    let (target_user_id, _) = seed_user(&system, false).await;
    let db = system.state().base.db.clone();
    let role_id = seed_role(&db).await;
    let app = full_app(system);

    let request_id =
        submit_role_grant_request(&app, &requester_cookie, target_user_id, role_id).await;
    force_approved(&db, request_id).await;
    let set_role = |role: Uuid| {
        sqlx::query(
            "UPDATE approval_request \
                SET payload = jsonb_set(payload::jsonb, '{role_id}', to_jsonb($2::text)) \
              WHERE id = $1",
        )
        .bind(request_id)
        .bind(role.to_string())
    };
    set_role(Uuid::now_v7())
        .execute(&db)
        .await
        .expect("point the grant at a role that does not exist");

    let resp = app
        .clone()
        .oneshot(retry_execution_request(&admin_cookie, request_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        status_and_claimant(&db, request_id).await,
        ("approved".to_string(), None)
    );

    set_role(role_id)
        .execute(&db)
        .await
        .expect("point the grant back at the real role");
    let resp = app
        .clone()
        .oneshot(retry_execution_request(&admin_cookie, request_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        status_and_claimant(&db, request_id).await,
        ("executed".to_string(), Some(admin))
    );
    assert_eq!(role_assignments(&db, target_user_id, role_id).await, 1);
}

// ── Pagination base ──────────────────────────────────────────────────────

/// Pins the *page base* of the one-based legacy shape (D-347, TODO-016).
///
/// `GET /api/v1/admin/approvals` numbers pages from 1 (`page.unwrap_or(1).max(1)`,
/// offset `(page - 1) * page_size`), the one base every offset list uses
/// (D-793) — `view_admin.rs`'s `admin_list_views_page_base_is_one` pins the
/// same base for the admin views list.
///
/// The discriminator is `page=0`: a zero-based handler serves it as the first
/// page and echoes `0`, whereas this one clamps it up and echoes `1`. That
/// clamp is also why the Angular walker's old zero-based arithmetic silently
/// truncated one-based lists rather than erroring — see `getAllPages`.
#[tokio::test]
async fn admin_list_approvals_page_base_is_one() {
    let system = skip_if_no_db!(test_system(72).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (target_a, _) = seed_user(&system, false).await;
    let (target_b, _) = seed_user(&system, false).await;
    let role_id = seed_role(&system.state().base.db).await;
    let app = full_app(system);

    // Two pending requests guarantee at least two rows in the queue, so
    // `page_size=1` makes pages 1 and 2 genuinely distinct windows.
    submit_role_grant_request(&app, &requester_cookie, target_a, role_id).await;
    submit_role_grant_request(&app, &requester_cookie, target_b, role_id).await;

    let list = |page: Option<i64>| {
        let app = app.clone();
        let cookie = requester_cookie.clone();
        async move {
            let uri = match page {
                Some(p) => format!("/api/v1/admin/approvals?page={p}&page_size=1"),
                None => "/api/v1/admin/approvals?page_size=1".to_string(),
            };
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            body_json(resp).await
        }
    };

    let p0 = list(Some(0)).await;
    let p1 = list(Some(1)).await;
    let p2 = list(Some(2)).await;
    let dflt = list(None).await;

    // The clamp is the whole tell: 0 is not a page on this shape.
    assert_eq!(
        p0["page"], 1,
        "one-based: page 0 must clamp up to 1, not be served as a first page"
    );
    assert_eq!(p1["page"], 1);
    assert_eq!(p2["page"], 2);
    assert_eq!(
        dflt["page"], 1,
        "omitting `page` must mean the first page, 1"
    );

    assert_eq!(p1["items"].as_array().unwrap().len(), 1);
    assert_eq!(p2["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        p0["items"][0]["id"], p1["items"][0]["id"],
        "page 0 and page 1 must be the same window — if they differ, offset is \
         being computed as page * page_size and the base has flipped"
    );
    assert_ne!(
        p1["items"][0]["id"], p2["items"][0]["id"],
        "pages 1 and 2 must be different windows"
    );
    assert_eq!(dflt["items"][0]["id"], p1["items"][0]["id"]);
}

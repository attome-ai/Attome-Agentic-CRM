//! D-421 / M10 (Approval & Governance) — live-database test for the policy
//! layer on top of D-195's `attome_approval` primitive: policy-driven gating
//! independent of `approval.required_actions`, the `/admin/approvals/{id}/
//! delegate` endpoint, and delegation's core self-approval invariant. Same
//! harness shape as `approval_role_grant.rs` (this repo's convention: each
//! `approval_*.rs` integration test builds its own `EngineSystem`, not a shared
//! helper module).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `approval_role_grant.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test approval_policy_governance -- --test-threads=1
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
            "approval": {{ "required_actions": [] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &url);
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

/// The system and router every test in this binary shares (build-loop plan,
/// Phase 3 task 4). Building a fresh `EngineSystem` per test cost ~0.3 s each;
/// the tests already share this binary's database, and each one provisions
/// its own uniquely named entities, users and roles, so sharing the in-memory
/// system adds no coupling the database did not already have. Tests run on
/// `attome_testkit::shared_runtime`, which keeps the pools' connections alive
/// between tests.
#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

impl TestSystem {
    fn state(&self) -> &EngineState {
        &self.state
    }
}

static SHARED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn test_system() -> Option<TestSystem> {
    SHARED
        .get_or_init(|| async {
            let system = build_test_system().await?;
            let state = system.state().clone();
            Some(TestSystem {
                state,
                app: build_app(system),
            })
        })
        .await
        .clone()
}

fn full_app(system: TestSystem) -> axum::Router {
    system.app
}

fn build_app(system: EngineSystem) -> axum::Router {
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

async fn seed_user(system: &TestSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("approval-policy-test-{user_id}"))
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
    .bind(format!("approval-policy-test-role-{role_id}"))
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

fn json_request(method: &str, uri: String, cookie: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Same Origin/Sec-Fetch-Site headers `json_request` sends — required for
/// every mutating (non-GET) cookie-authenticated call to pass CSRF
/// (guidelines §3), including a bodyless `DELETE`.
fn plain_request(method: &str, uri: String, cookie: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

fn assign_role_request(admin_cookie: &str, user_id: Uuid, role_id: Uuid) -> Request<Body> {
    json_request(
        "POST",
        format!("/api/v1/admin/security/users/{user_id}/roles"),
        admin_cookie,
        serde_json::json!({ "role_id": role_id }),
    )
}

/// A one-step, `any`-mode policy naming `approver_id` directly
/// (`"user:<uuid>"`) for `security.role_grant` — the smallest plan that can
/// exercise `find_matching_policy`/`gate` end to end.
async fn create_single_approver_policy(
    app: &axum::Router,
    db: &sqlx::PgPool,
    admin_cookie: &str,
    approver_id: Uuid,
) -> Uuid {
    // Every test in this file targets the same fixed action_type
    // (`security.role_grant`'s own gate() call site is hardcoded, not
    // test-controllable) against the same shared database — the partial
    // unique index on `approval_policy(action_type) WHERE
    // is_active AND NOT is_deleted` means only one test's policy can be
    // active for it at a time. Soft-delete (not hard-delete: a prior test's
    // request rows may still reference it via policy_id's FK, no ON DELETE
    // clause per this schema's no-cascade convention) any leftover from a
    // prior test in this same binary run rather than leaning on
    // `--test-threads=1` ordering alone.
    sqlx::query(
        "UPDATE approval_policy SET is_deleted = TRUE, is_active = FALSE \
         WHERE action_type = 'security.role_grant'",
    )
    .execute(db)
    .await
    .expect("clean up any pre-existing security.role_grant policy");

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/approval-policies".to_string(),
            admin_cookie,
            serde_json::json!({
                "name": format!("policy-test-{approver_id}"),
                "action_type": "security.role_grant",
                "plan": {
                    "steps": [{
                        "mode": "any",
                        "approvers": [format!("user:{approver_id}")],
                        "sla_minutes": 60,
                        "on_timeout": "escalate",
                    }]
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    Uuid::parse_str(body["id"].as_str().expect("policy id")).expect("policy id must be a uuid")
}

/// Soft-deletes any policy this file's tests left active for
/// `security.role_grant` — called at the end of every test that creates
/// one. Without this, a policy left active here would silently gate every
/// OTHER suite's plain (non-policy) role-grant flow the next time this
/// shared database is used (e.g. `approval_lifecycle.rs`,
/// `approval_role_grant.rs`) — not a bug in `gate()` (a policy widening
/// what gets gated is exactly D-421's point), just cross-suite test
/// isolation this file owes its neighbors.
async fn cleanup_role_grant_policy(db: &sqlx::PgPool) {
    sqlx::query(
        "UPDATE approval_policy SET is_deleted = TRUE, is_active = FALSE \
         WHERE action_type = 'security.role_grant'",
    )
    .execute(db)
    .await
    .expect("clean up the security.role_grant policy this test created");
}

/// A policy gates `security.role_grant` even though
/// `approval.required_actions` is empty — proves `gate()` now consults
/// `approval_policy` independently of the static config list
/// (D-421's whole point: a policy can turn gating on where the config list
/// never could).
#[test]
fn policy_gates_role_grant_even_when_not_in_required_actions() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_user(&system, true).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_single_approver_policy(&app, &db, &admin_cookie, admin_id).await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(&admin_cookie, target_user_id, role_id))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "a matching policy must gate this action even with an empty required_actions list"
        );
        let body = body_json(resp).await;
        assert_eq!(body["approval_pending"], true);
        let request_id: Uuid = body["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let role_assigned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
        )
        .bind(target_user_id)
        .bind(role_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(!role_assigned, "must not assign before the plan is decided");

        let plan_json: serde_json::Value =
            sqlx::query_scalar("SELECT plan FROM approval_request WHERE id = $1")
                .bind(request_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert!(
            !plan_json.is_null(),
            "the request created by a policy-matched gate() call must carry that policy's plan"
        );
        cleanup_role_grant_policy(&db).await;
    })
}

/// `/admin/approvals/{id}/delegate` lets the sole named approver on a
/// policy's step hand their standing to a third user, who can then decide
/// it — and the grant row records who actually clicked (`decided_by`) next
/// to whose authority they used (`on_behalf_of`).
#[test]
fn a_delegate_can_decide_and_the_grant_records_decided_by_and_on_behalf_of() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (requester_id, requester_cookie) = seed_user(&system, true).await;
        let (approver_id, _approver_cookie) = seed_user(&system, true).await;
        let (delegate_id, delegate_cookie) = seed_user(&system, true).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_single_approver_policy(&app, &db, &requester_cookie, approver_id).await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_json(resp).await;
        let request_id: Uuid = body["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        // The named approver delegates their standing to a third user. Their own
        // cookie authenticates the call, but the delegation is created via the
        // API using the approver's own identity as `from_user` — modeled here as
        // the approver themselves calling it (their session), matching how the
        // route is meant to be used: only a currently-eligible approver may
        // delegate their own standing.
        let approver_cookie2 = session_cookie(approver_id);
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/admin/approvals/{request_id}/delegate"),
                &approver_cookie2,
                serde_json::json!({ "to_user_id": delegate_id }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the named approver must be able to delegate their own standing"
        );

        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/admin/approvals/{request_id}/decide"),
                &delegate_cookie,
                serde_json::json!({ "decision": "approve", "row_version": 0 }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the delegate must be able to decide on the approver's behalf"
        );
        let body = body_json(resp).await;
        assert_eq!(body["status"], "approved");

        let role_assigned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
        )
        .bind(target_user_id)
        .bind(role_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            role_assigned,
            "the delegate's approval must have executed the grant"
        );

        let (grant_decided_by, grant_on_behalf_of): (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT decided_by, on_behalf_of FROM approval_grant WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(grant_decided_by, Some(delegate_id));
        assert_eq!(grant_on_behalf_of, Some(approver_id));
        let _ = requester_id;
        cleanup_role_grant_policy(&db).await;
    })
}

/// D-421's core invariant, exercised through the HTTP route: delegating
/// approval authority to the request's own requester must be refused, not
/// silently accepted as a path to self-approval.
#[test]
fn cannot_delegate_approval_authority_to_the_requester() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (requester_id, requester_cookie) = seed_user(&system, true).await;
        let (approver_id, _) = seed_user(&system, true).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_single_approver_policy(&app, &db, &requester_cookie, approver_id).await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        let body = body_json(resp).await;
        let request_id: Uuid = body["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let approver_cookie = session_cookie(approver_id);
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/admin/approvals/{request_id}/delegate"),
                &approver_cookie,
                serde_json::json!({ "to_user_id": requester_id }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "delegating to the request's own requester must be rejected, not accepted"
        );
        cleanup_role_grant_policy(&db).await;
    })
}

/// Smoke test for the policy admin CRUD surface itself: create, get, list,
/// update (row_version CAS), and delete.
#[test]
fn policy_crud_round_trips() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let policy_id = create_single_approver_policy(&app, &db, &admin_cookie, admin_id).await;

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                format!("/api/v1/admin/approval-policies/{policy_id}"),
                &admin_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["row_version"], 0);
        assert_eq!(body["is_active"], true);

        let resp = app
            .clone()
            .oneshot(json_request(
                "PUT",
                format!("/api/v1/admin/approval-policies/{policy_id}"),
                &admin_cookie,
                serde_json::json!({ "is_active": false, "row_version": 0 }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["is_active"], false);
        assert_eq!(body["row_version"], 1);

        // A stale row_version must be rejected.
        let resp = app
            .clone()
            .oneshot(json_request(
                "PUT",
                format!("/api/v1/admin/approval-policies/{policy_id}"),
                &admin_cookie,
                serde_json::json!({ "is_active": true, "row_version": 0 }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "DELETE",
                format!("/api/v1/admin/approval-policies/{policy_id}"),
                &admin_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        let resp = app
            .clone()
            .oneshot(plain_request(
                "GET",
                format!("/api/v1/admin/approval-policies/{policy_id}"),
                &admin_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    })
}

// ── Dashboard 10/10 Phase 6 prerequisites (D-551): the non-admin decide
// route, and team:/position:manager_of_requester approver token resolution.

async fn seed_team(db: &attome_db::DbPool) -> Uuid {
    let team_id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(team_id)
        .bind(format!("approval-policy-test-team-{team_id}"))
        .execute(db)
        .await
        .expect("insert throwaway team");
    team_id
}

async fn add_team_member(db: &attome_db::DbPool, team_id: Uuid, user_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_team (id, user_ref, team_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(team_id)
        .execute(db)
        .await
        .expect("insert throwaway team membership");
}

async fn seed_position(db: &attome_db::DbPool, parent: Option<Uuid>) -> Uuid {
    let position_id = Uuid::now_v7();
    sqlx::query("INSERT INTO position (id, name, parent_position_ref) VALUES ($1, $2, $3)")
        .bind(position_id)
        .bind(format!("approval-policy-test-position-{position_id}"))
        .bind(parent)
        .execute(db)
        .await
        .expect("insert throwaway position");
    position_id
}

async fn add_position_member(db: &attome_db::DbPool, position_id: Uuid, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO user_account_mm_position (id, user_ref, position_ref) \
         VALUES ($1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(position_id)
    .execute(db)
    .await
    .expect("insert throwaway position membership");
}

/// Same shape as [`create_single_approver_policy`], but for an arbitrary
/// approver token (`team:<uuid>`, `position:manager_of_requester`, …).
async fn create_policy_with_approver_token(
    app: &axum::Router,
    db: &sqlx::PgPool,
    admin_cookie: &str,
    token: &str,
) -> Uuid {
    sqlx::query(
        "UPDATE approval_policy SET is_deleted = TRUE, is_active = FALSE \
         WHERE action_type = 'security.role_grant'",
    )
    .execute(db)
    .await
    .expect("clean up any pre-existing security.role_grant policy");

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/approval-policies".to_string(),
            admin_cookie,
            serde_json::json!({
                "name": format!("policy-token-test-{}", Uuid::now_v7()),
                "action_type": "security.role_grant",
                "plan": {
                    "steps": [{
                        "mode": "any",
                        "approvers": [token],
                        "sla_minutes": 60,
                        "on_timeout": "escalate",
                    }]
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "policy create must succeed for token {token:?}"
    );
    let body = body_json(resp).await;
    Uuid::parse_str(body["id"].as_str().expect("policy id")).expect("policy id must be a uuid")
}

fn eligible_decide_request(cookie: &str, request_id: Uuid, row_version: i64) -> Request<Body> {
    json_request(
        "POST",
        format!("/api/v1/approvals/{request_id}/decide"),
        cookie,
        serde_json::json!({ "decision": "approve", "row_version": row_version }),
    )
}

/// D-551: a `team:<uuid>` approver token resolves to every active member of
/// that team, and the new non-admin route accepts a decision from one.
#[test]
fn team_member_can_decide_via_the_non_admin_route() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_requester_id, requester_cookie) = seed_user(&system, true).await;
        let (member_id, member_cookie) = seed_user(&system, false).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let team_id = seed_team(&db).await;
        add_team_member(&db, team_id, member_id).await;
        let app = full_app(system);

        create_policy_with_approver_token(&app, &db, &requester_cookie, &format!("team:{team_id}"))
            .await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_json(resp).await;
        let request_id: Uuid = body["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let resp = app
            .clone()
            .oneshot(eligible_decide_request(&member_cookie, request_id, 0))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a team member, though not an admin, must be able to decide through the non-admin route"
        );
        let body = body_json(resp).await;
        assert_eq!(body["status"], "approved");

        let role_assigned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
        )
        .bind(target_user_id)
        .bind(role_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(
            role_assigned,
            "the team member's approval must have executed the grant"
        );
        cleanup_role_grant_policy(&db).await;
    })
}

/// D-551: `position:manager_of_requester` resolves to whoever holds the
/// parent position of any position the requester holds — no `manager_id`
/// column needed, `position.parent_position_ref` already expresses
/// it.
#[test]
fn position_manager_of_requester_can_decide() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (requester_id, requester_cookie) = seed_user(&system, true).await;
        let (manager_id, manager_cookie) = seed_user(&system, false).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let manager_position = seed_position(&db, None).await;
        let requester_position = seed_position(&db, Some(manager_position)).await;
        add_position_member(&db, manager_position, manager_id).await;
        add_position_member(&db, requester_position, requester_id).await;
        let app = full_app(system);

        create_policy_with_approver_token(
            &app,
            &db,
            &requester_cookie,
            "position:manager_of_requester",
        )
        .await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_json(resp).await;
        let request_id: Uuid = body["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let resp = app
            .clone()
            .oneshot(eligible_decide_request(&manager_cookie, request_id, 0))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "the requester's position-hierarchy manager must be able to decide"
        );

        let role_assigned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
        )
        .bind(target_user_id)
        .bind(role_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert!(role_assigned);
        cleanup_role_grant_policy(&db).await;
    })
}

/// D-551: someone who is neither a named approver, nor a member of the
/// named team, nor the requester's position-hierarchy manager, gets 403 from
/// the non-admin route — `decide_step_with`'s own `allowed_decider_ids`
/// check, not a separate check this route would have to get right too.
#[test]
fn an_ineligible_caller_is_forbidden_on_the_non_admin_route() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_requester_id, requester_cookie) = seed_user(&system, true).await;
        let (approver_id, _) = seed_user(&system, true).await;
        let (bystander_id, bystander_cookie) = seed_user(&system, false).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        create_single_approver_policy(&app, &db, &requester_cookie, approver_id).await;

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_json(resp).await;
        let request_id: Uuid = body["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let resp = app
            .clone()
            .oneshot(eligible_decide_request(&bystander_cookie, request_id, 0))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let _ = bystander_id;
        cleanup_role_grant_policy(&db).await;
    })
}

/// D-551: a flat (non-plan) request has no eligible-approver concept other
/// than `system.admin`, so the non-admin route refuses it outright — even
/// for a caller who holds `system.admin` and would succeed on the admin
/// route.
#[test]
fn a_flat_request_is_forbidden_on_the_non_admin_route() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (requester_id, requester_cookie) = seed_user(&system, true).await;
        let (admin_id, _) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let submitted = attome_approval::submit(
            &db,
            &format!("policy_gov_flat.{}", Uuid::now_v7().simple()),
            serde_json::json!({}),
            requester_id,
            1,
            chrono::Duration::hours(1),
        )
        .await
        .expect("submit a flat approval request");

        let admin_cookie2 = session_cookie(admin_id);
        let resp = app
            .clone()
            .oneshot(eligible_decide_request(&admin_cookie2, submitted.id, 0))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a flat request must stay reachable only through the admin route"
        );
        let _ = requester_cookie;
    })
}

// ── BAP-12 / BAP-F7 (BAP-D4): the production floor means at least one human ──

/// `on_timeout: auto_approve` decides a step with no human behind it
/// (`decided_by = policy`). On a `PRODUCTION_MANDATORY_ACTIONS` type that
/// would turn the production floor — "a second person looked at this before
/// it ran" — into a timer, so the policy save refuses it. `escalate` and
/// `auto_reject` decide nothing and stay allowed.
#[test]
fn a_mandatory_action_policy_cannot_auto_approve_on_timeout() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        // `security.erasure` is on the production-mandatory floor
        // (`attome_api::PRODUCTION_MANDATORY_ACTIONS`).
        let cleanup = || async {
            sqlx::query(
                "UPDATE approval_policy SET is_deleted = TRUE, is_active = FALSE \
                 WHERE action_type = 'security.erasure'",
            )
            .execute(&db)
            .await
            .expect("clean up security.erasure policies");
        };
        cleanup().await;

        let plan = |on_timeout: &str| {
            serde_json::json!({
                "steps": [{
                    "mode": "any",
                    "approvers": [format!("user:{admin_id}")],
                    "sla_minutes": 60,
                    "on_timeout": on_timeout,
                }]
            })
        };

        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/v1/admin/approval-policies".to_string(),
                &admin_cookie,
                serde_json::json!({
                    "name": "mandatory-auto-approve-refused",
                    "action_type": "security.erasure",
                    "plan": plan("auto_approve"),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "auto_approve on a production-mandatory action must be a 422"
        );

        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/v1/admin/approval-policies".to_string(),
                &admin_cookie,
                serde_json::json!({
                    "name": "mandatory-escalate-allowed",
                    "action_type": "security.erasure",
                    "plan": plan("escalate"),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "escalate decides nothing and stays allowed on a mandatory action"
        );
        let body = body_json(resp).await;
        let policy_id = Uuid::parse_str(body["id"].as_str().expect("policy id"))
            .expect("policy id must be a uuid");
        let row_version = body["row_version"].as_i64().expect("row_version");

        // The same refusal covers an update that smuggles `auto_approve` in
        // through a plan replacement: `action_type` is immutable, so the
        // check runs against the row's own type, not the request body.
        let resp = app
            .clone()
            .oneshot(json_request(
                "PUT",
                format!("/api/v1/admin/approval-policies/{policy_id}"),
                &admin_cookie,
                serde_json::json!({
                    "plan": plan("auto_approve"),
                    "row_version": row_version,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "an update may not smuggle auto_approve onto a mandatory action either"
        );

        cleanup().await;
    })
}

// ── BAP-7 / BAP-D3: save-time threshold refusal only for all-`user:` steps ──

/// Owner ruling 2026-09-25: an `n_of_m` threshold above the token count is
/// refused at save time only when every token is `user:` (and then against
/// the *distinct* users). A `role:` token expands to many people, so a
/// 3-of-[role:x] policy saves; `required_count` refuses it at decide time
/// if the role turns out too small.
#[test]
fn n_of_m_threshold_is_refused_at_save_only_for_all_user_steps() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_admin_id, admin_cookie) = seed_user(&system, true).await;
        let (a_id, _) = seed_user(&system, false).await;
        let (b_id, _) = seed_user(&system, false).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        // A per-run action_type: no other test's active policy can collide
        // with it on the one-active-policy-per-action_type index.
        let action_type = format!("test.bap7_threshold.{}", Uuid::now_v7());
        let post = |name: &str, threshold: i32, approvers: Vec<String>| {
            json_request(
                "POST",
                "/api/v1/admin/approval-policies".to_string(),
                &admin_cookie,
                serde_json::json!({
                    "name": format!("{name}-{}", Uuid::now_v7()),
                    "action_type": action_type,
                    "is_active": false,
                    "plan": {
                        "steps": [{
                            "mode": "nof_m",
                            "threshold": threshold,
                            "approvers": approvers,
                            "sla_minutes": 60,
                            "on_timeout": "escalate",
                        }]
                    }
                }),
            )
        };

        let resp = app
            .clone()
            .oneshot(post(
                "bap7-role",
                3,
                vec![format!("role:{}", Uuid::now_v7())],
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "3-of-[role:x] must save: a role token's population is only known at decide time"
        );

        let resp = app
            .clone()
            .oneshot(post(
                "bap7-two-users",
                3,
                vec![format!("user:{a_id}"), format!("user:{b_id}")],
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "3-of-[user:a, user:b] can never be met and must be refused at save time"
        );

        let resp = app
            .clone()
            .oneshot(post(
                "bap7-repeated-user",
                2,
                vec![format!("user:{a_id}"), format!("user:{a_id}")],
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "2-of-[user:a, user:a] names one distinct user and must be refused"
        );

        sqlx::query(
            "UPDATE approval_policy SET is_deleted = TRUE, is_active = FALSE \
             WHERE action_type = $1",
        )
        .bind(&action_type)
        .execute(&db)
        .await
        .expect("clean up the bap7 threshold policies");
    })
}

// ── BAP-5 / BAP-D2: a principal who is also a delegate decides in their own slot ──

/// An `all` step over {A, B} where B has delegated to A. A's own approval
/// must fill A's slot (`on_behalf_of` NULL), not B's: were it stamped
/// `on_behalf_of = B`, B's own approval would then hit "slot filled", A could
/// not decide again, and the step could never close.
#[test]
fn a_principal_who_is_also_a_delegate_decides_in_their_own_slot() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_requester_id, requester_cookie) = seed_user(&system, true).await;
        let (a_id, a_cookie) = seed_user(&system, true).await;
        let (b_id, b_cookie) = seed_user(&system, true).await;
        let (target_user_id, _) = seed_user(&system, false).await;
        let role_id = seed_role(&system.state().base.db).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        cleanup_role_grant_policy(&db).await;
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/api/v1/admin/approval-policies".to_string(),
                &requester_cookie,
                serde_json::json!({
                    "name": format!("policy-all-slot-test-{}", Uuid::now_v7()),
                    "action_type": "security.role_grant",
                    "plan": {
                        "steps": [{
                            "mode": "all",
                            "approvers": [format!("user:{a_id}"), format!("user:{b_id}")],
                            "sla_minutes": 60,
                            "on_timeout": "escalate",
                        }]
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = app
            .clone()
            .oneshot(assign_role_request(
                &requester_cookie,
                target_user_id,
                role_id,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_json(resp).await;
        let request_id: Uuid = body["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        // B delegates their standing to A, a fellow principal of this step.
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                format!("/api/v1/admin/approvals/{request_id}/delegate"),
                &b_cookie,
                serde_json::json!({ "to_user_id": a_id }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "B delegates to A");

        let row_version = |db: sqlx::PgPool| async move {
            sqlx::query_scalar::<_, i64>("SELECT row_version FROM approval_request WHERE id = $1")
                .bind(request_id)
                .fetch_one(&db)
                .await
                .unwrap()
        };
        let decide = |cookie: String, rv: i64| {
            json_request(
                "POST",
                format!("/api/v1/admin/approvals/{request_id}/decide"),
                &cookie,
                serde_json::json!({ "decision": "approve", "row_version": rv }),
            )
        };

        let rv = row_version(db.clone()).await;
        let resp = app
            .clone()
            .oneshot(decide(a_cookie.clone(), rv))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "A approves");
        let body = body_json(resp).await;
        assert_eq!(body["status"], "pending", "B has not decided yet");

        let on_behalf_of: Option<Uuid> = sqlx::query_scalar(
            "SELECT on_behalf_of FROM approval_grant \
             WHERE request_id = $1 AND approver_id = $2",
        )
        .bind(request_id)
        .bind(a_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            on_behalf_of, None,
            "A is a principal of this step: A's own decision fills A's slot, not B's"
        );

        let rv = row_version(db.clone()).await;
        let resp = app
            .clone()
            .oneshot(decide(b_cookie.clone(), rv))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "B's own slot is still open, so B's approval must be accepted"
        );
        let body = body_json(resp).await;
        assert_eq!(
            body["status"], "approved",
            "both slots filled: the step closes"
        );

        cleanup_role_grant_policy(&db).await;
    })
}

// ── BAP-11b: an auto-approved gated action runs through a durable job ──

/// One auto-approved `security.role_grant` request, ready for the execution
/// job: a one-step `on_timeout: auto_approve` policy, a gated grant, the
/// step's SLA forced into the past, and one run of the real timeout sweep.
struct AutoApproved {
    request_id: Uuid,
    target_user_id: Uuid,
    role_id: Uuid,
    admin_cookie: String,
}

async fn auto_approved_role_grant(system: &TestSystem) -> AutoApproved {
    let (admin_id, admin_cookie) = seed_user(system, true).await;
    let (target_user_id, _) = seed_user(system, false).await;
    let db = system.state().base.db.clone();
    let role_id = seed_role(&db).await;
    let app = full_app(system.clone());

    cleanup_role_grant_policy(&db).await;
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/approval-policies".to_string(),
            &admin_cookie,
            serde_json::json!({
                "name": format!("auto-approve-{admin_id}"),
                "action_type": "security.role_grant",
                "plan": {
                    "steps": [{
                        "mode": "any",
                        "approvers": [format!("user:{admin_id}")],
                        "sla_minutes": 1,
                        "on_timeout": "auto_approve",
                    }]
                }
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = app
        .clone()
        .oneshot(assign_role_request(&admin_cookie, target_user_id, role_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let request_id: Uuid = body_json(resp).await["approval_request_id"]
        .as_str()
        .expect("approval_request_id")
        .parse()
        .expect("uuid");

    sqlx::query(
        "UPDATE approval_request \
         SET step_started_at = NOW() - INTERVAL '10 minutes' WHERE id = $1",
    )
    .bind(request_id)
    .execute(&db)
    .await
    .expect("force the step past its SLA");
    attome_notification::approval_timeouts::run_due_approval_timeouts(system.state(), 500).await;
    cleanup_role_grant_policy(&db).await;

    assert_eq!(
        request_status(&db, request_id).await,
        "approved",
        "the sweep must auto-approve the timed-out step"
    );
    AutoApproved {
        request_id,
        target_user_id,
        role_id,
        admin_cookie,
    }
}

async fn request_status(db: &sqlx::PgPool, request_id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
        .bind(request_id)
        .fetch_one(db)
        .await
        .expect("request status")
}

async fn execution_jobs(db: &sqlx::PgPool, request_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM apalis.jobs WHERE dedup_key = $1")
        .bind(attome_notification::approval_timeouts::execute_approved_dedup_key(request_id))
        .fetch_one(db)
        .await
        .expect("count execution jobs")
}

async fn role_granted(db: &sqlx::PgPool, user_id: Uuid, role_id: Uuid) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_account_mm_role \
         WHERE user_ref = $1 AND role_ref = $2 AND is_deleted = false)",
    )
    .bind(user_id)
    .bind(role_id)
    .fetch_one(db)
    .await
    .expect("role grant lookup")
}

/// The job rows this binary enqueued are removed so no later worker (or suite)
/// on the shared test database ever picks them up.
async fn drop_execution_jobs(db: &sqlx::PgPool, request_id: Uuid) {
    sqlx::query("DELETE FROM apalis.jobs WHERE dedup_key = $1")
        .bind(attome_notification::approval_timeouts::execute_approved_dedup_key(request_id))
        .execute(db)
        .await
        .expect("drop execution jobs");
}

#[test]
fn an_auto_approved_gated_action_dispatches_once_after_one_worker_tick() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let fixture = auto_approved_role_grant(&system).await;

        let (job_type, variant): (String, String) = sqlx::query_as(
            "SELECT job_type, job->>'variant' FROM apalis.jobs WHERE dedup_key = $1",
        )
        .bind(
            attome_notification::approval_timeouts::execute_approved_dedup_key(fixture.request_id),
        )
        .fetch_one(&db)
        .await
        .expect("the auto-approval commits its execution job in the same transaction");
        assert_eq!(
            (job_type.as_str(), variant.as_str()),
            ("attome_job", "ExecuteApprovedRequest")
        );
        assert!(
            !role_granted(&db, fixture.target_user_id, fixture.role_id).await,
            "nothing runs before the worker picks the job up"
        );

        let outcome = attome_api::execute_approved_request(system.state(), fixture.request_id)
            .await
            .expect("one worker tick");
        assert_eq!(outcome, attome_api::AutoExecution::Executed);
        assert!(role_granted(&db, fixture.target_user_id, fixture.role_id).await);
        assert_eq!(request_status(&db, fixture.request_id).await, "executed");

        drop_execution_jobs(&db, fixture.request_id).await;
    })
}

#[test]
fn a_duplicate_delivery_after_the_claim_dispatches_nothing_and_completes() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let fixture = auto_approved_role_grant(&system).await;

        // A live claim held by another delivery: this one completes and runs
        // nothing.
        let request = attome_approval::get(&db, fixture.request_id)
            .await
            .expect("request");
        let foreign = Uuid::now_v7();
        attome_approval::claim_execution(&db, request.id, request.row_version, foreign)
            .await
            .expect("another delivery claims first");
        let outcome = attome_api::execute_approved_request(system.state(), fixture.request_id)
            .await
            .expect("a duplicate delivery completes");
        assert_eq!(outcome, attome_api::AutoExecution::NotClaimed);
        assert!(!role_granted(&db, fixture.target_user_id, fixture.role_id).await);
        assert_eq!(request_status(&db, fixture.request_id).await, "executing");

        // And after the request has executed, a redelivery is a no-op too.
        let claimed = attome_approval::execution_claim(&db, request.id)
            .await
            .expect("claim lookup")
            .expect("the claim stands");
        assert_eq!(claimed.claimed_by, foreign);
        let current = attome_approval::get(&db, fixture.request_id)
            .await
            .expect("request");
        attome_approval::release_execution(&db, current.id, current.row_version)
            .await
            .expect("the holder releases");
        assert_eq!(
            attome_api::execute_approved_request(system.state(), fixture.request_id)
                .await
                .expect("delivery"),
            attome_api::AutoExecution::Executed
        );
        assert_eq!(
            attome_api::execute_approved_request(system.state(), fixture.request_id)
                .await
                .expect("redelivery"),
            attome_api::AutoExecution::NotClaimed
        );
        assert_eq!(request_status(&db, fixture.request_id).await, "executed");

        drop_execution_jobs(&db, fixture.request_id).await;
    })
}

#[test]
fn a_worker_that_dies_after_dispatch_leaves_the_request_executing_and_no_attempt_reclaims_it() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let fixture = auto_approved_role_grant(&system).await;

        // A worker claimed, dispatched and died before closing the claim.
        let request = attome_approval::get(&db, fixture.request_id)
            .await
            .expect("request");
        let dead_worker = Uuid::now_v7();
        attome_approval::claim_execution(&db, request.id, request.row_version, dead_worker)
            .await
            .expect("the dead worker's claim");
        sqlx::query(
            "UPDATE approval_request \
             SET execution_claimed_at = NOW() - INTERVAL '2 hours' WHERE id = $1",
        )
        .bind(fixture.request_id)
        .execute(&db)
        .await
        .expect("force the claim past its lease");
        let claim = attome_approval::execution_claim(&db, fixture.request_id)
            .await
            .expect("claim lookup")
            .expect("claim");
        assert!(
            claim.stale,
            "the claim must be past its lease for this case"
        );

        for _ in 0..3 {
            let outcome = attome_api::execute_approved_request(system.state(), fixture.request_id)
                .await
                .expect("a re-run completes");
            assert_eq!(outcome, attome_api::AutoExecution::NotClaimed);
        }
        assert_eq!(
            request_status(&db, fixture.request_id).await,
            "executing",
            "an unknown outcome waits for an admin's acknowledgement"
        );
        let claim = attome_approval::execution_claim(&db, fixture.request_id)
            .await
            .expect("claim lookup")
            .expect("claim");
        assert_eq!(
            claim.claimed_by, dead_worker,
            "no attempt took the claim over"
        );
        assert!(!role_granted(&db, fixture.target_user_id, fixture.role_id).await);

        drop_execution_jobs(&db, fixture.request_id).await;
    })
}

#[test]
fn an_executor_error_releases_the_claim_and_the_next_attempt_dispatches() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let fixture = auto_approved_role_grant(&system).await;

        // The role vanishes between approval and execution: the executor fails.
        sqlx::query("DELETE FROM role WHERE id = $1")
            .bind(fixture.role_id)
            .execute(&db)
            .await
            .expect("remove the role");
        let failed = attome_api::execute_approved_request(system.state(), fixture.request_id).await;
        assert!(
            failed.is_err(),
            "an executor error fails the attempt: {failed:?}"
        );
        assert_eq!(
            request_status(&db, fixture.request_id).await,
            "approved",
            "the claim is released so the next attempt may claim again"
        );

        sqlx::query(
            "INSERT INTO role (id, name, description, owner_layer) VALUES ($1, $2, $3, 'project')",
        )
        .bind(fixture.role_id)
        .bind(format!("approval-policy-test-role-{}", fixture.role_id))
        .bind("restored throwaway test role")
        .execute(&db)
        .await
        .expect("restore the role");
        let outcome = attome_api::execute_approved_request(system.state(), fixture.request_id)
            .await
            .expect("the next attempt");
        assert_eq!(outcome, attome_api::AutoExecution::Executed);
        assert!(role_granted(&db, fixture.target_user_id, fixture.role_id).await);
        assert_eq!(request_status(&db, fixture.request_id).await, "executed");

        drop_execution_jobs(&db, fixture.request_id).await;
    })
}

#[test]
fn an_auto_approval_racing_a_manual_retry_dispatches_once() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let fixture = auto_approved_role_grant(&system).await;
        let app = full_app(system.clone());

        let job = attome_api::execute_approved_request(system.state(), fixture.request_id);
        let retry = app.clone().oneshot(plain_request(
            "POST",
            format!(
                "/api/v1/admin/approvals/{}/retry-execution",
                fixture.request_id
            ),
            &fixture.admin_cookie,
        ));
        let (job, retry) = tokio::join!(job, retry);
        let job_ran = matches!(job, Ok(attome_api::AutoExecution::Executed));
        let retry_ran = retry.expect("retry response").status() == StatusCode::OK;
        assert!(
            job_ran ^ retry_ran,
            "exactly one of the job ({job:?}) and the manual retry (ran: {retry_ran}) dispatches"
        );
        assert_eq!(request_status(&db, fixture.request_id).await, "executed");
        assert!(role_granted(&db, fixture.target_user_id, fixture.role_id).await);

        drop_execution_jobs(&db, fixture.request_id).await;
    })
}

#[test]
fn a_repeated_timeout_sweep_enqueues_one_job() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let fixture = auto_approved_role_grant(&system).await;
        assert_eq!(execution_jobs(&db, fixture.request_id).await, 1);

        attome_notification::approval_timeouts::run_due_approval_timeouts(system.state(), 500)
            .await;
        attome_notification::approval_timeouts::run_due_approval_timeouts(system.state(), 500)
            .await;
        let again = attome_jobs::enqueue_dedup(
            &db,
            attome_core::jobs::EngineJob::ExecuteApprovedRequest {
                request_id: fixture.request_id,
            },
            &attome_notification::approval_timeouts::execute_approved_dedup_key(fixture.request_id),
        )
        .await
        .expect("enqueue_dedup");
        assert!(!again, "the live job holds the request's dedup slot");
        assert_eq!(execution_jobs(&db, fixture.request_id).await, 1);

        drop_execution_jobs(&db, fixture.request_id).await;
    })
}

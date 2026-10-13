//! D-195 / `document/detailed-plans/P-four-eyes-approval.md` — live-database
//! test for the four-eyes gate on `admin::attribute::create_attribute`
//! (`ACTION_SCHEMA_CHANGE`). Same shape as `approval_role_grant.rs`/
//! `approval_retention.rs`/`approval_erasure.rs`/`approval_query_publish.rs`:
//! default-off passthrough, gated submit-without-create, the
//! separation-of-duties Forbidden, a different admin's approve actually
//! creating the field, and (specific to this action) `dry_run` never being
//! gated regardless of `approval.required_actions`.
//!
//! **Verified 2026-08-24 (MAINT-10): 5 passed, 0 failed, 74.81s** against a
//! real Postgres and Redis, retiring the "NOT RUN in this session —
//! code-only sandbox … treat as unverified until run" caveat this header
//! carried from the session that wrote it.
//!
//! The **elapsed time** is the evidence, not the `ok`: these suites report
//! green in ~0.01s when `DATABASE_URL` is absent, so a pass alone does not
//! distinguish a real run from a skipped one.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `jobs_admin.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test approval_schema_change -- --test-threads=1
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
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

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
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    attome_testkit::migrated_db_url()?;

    let config = test_config(required_actions);
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
        .bind(format!("approval-schema-change-test-{user_id}"))
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

fn create_entity_request(admin_cookie: &str, logicalname: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({ "logicalname": logicalname, "name": "Approval Gate Test Entity" })
                .to_string(),
        ))
        .unwrap()
}

/// Seeds a throwaway entity through the real HTTP endpoint (never
/// gated — schema-change gating applies to fields, not entity creation
/// itself) so `create_attribute` below has a real `entity_id`/
/// `entity_logicalname` to target.
async fn seed_entity(app: &axum::Router, admin_cookie: &str) -> (Uuid, String) {
    // MAX_IDENTIFIER_LEN is 48; a 32-hex-char UUID plus this prefix must fit.
    let logicalname = format!("agt_{}", Uuid::now_v7().simple());
    let resp = app
        .clone()
        .oneshot(create_entity_request(admin_cookie, &logicalname))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let entity_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    (entity_id, logicalname)
}

fn create_field_request(admin_cookie: &str, entity_id: Uuid, dry_run: bool) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({
                "logicalname": "approval_gate_test_field",
                "name": "Approval Gate Test Field",
                "field_type": "text",
                "dry_run": dry_run
            })
            .to_string(),
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

async fn attribute_exists(db: &attome_db::DbPool, entity_id: Uuid, logicalname: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(entity_id)
    .bind(logicalname)
    .fetch_one(db)
    .await
    .expect("query attribute_info")
}

/// `approval.required_actions = []` (today's default): creating a field
/// still succeeds immediately — no behavior change for a deployment that
/// hasn't opted in.
#[tokio::test]
async fn ungated_create_succeeds_immediately() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity_id, _) = seed_entity(&app, &admin_cookie).await;

    let resp = app
        .clone()
        .oneshot(create_field_request(&admin_cookie, entity_id, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    assert!(attribute_exists(&db, entity_id, "approval_gate_test_field").await);
}

/// `dry_run: true` is never gated, even when `schema.attribute_change` is
/// listed — a read-only cost estimate has no side effect to protect.
#[tokio::test]
async fn dry_run_is_never_gated() {
    let system = skip_if_no_db!(test_system(&["schema.attribute_change"]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity_id, _) = seed_entity(&app, &admin_cookie).await;

    let resp = app
        .clone()
        .oneshot(create_field_request(&admin_cookie, entity_id, true))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["classification"].is_string());

    assert!(!attribute_exists(&db, entity_id, "approval_gate_test_field").await);
}

/// `approval.required_actions = ["schema.attribute_change"]`, `dry_run:
/// false`: the same call now returns `202 approval_pending: true` and does
/// NOT create the field.
#[tokio::test]
async fn gated_create_submits_and_does_not_create() {
    let system = skip_if_no_db!(test_system(&["schema.attribute_change"]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity_id, _) = seed_entity(&app, &admin_cookie).await;

    let resp = app
        .clone()
        .oneshot(create_field_request(&admin_cookie, entity_id, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = body_json(resp).await;
    assert_eq!(body["approval_pending"], true);
    assert!(body["approval_request_id"].is_string());

    assert!(!attribute_exists(&db, entity_id, "approval_gate_test_field").await);
}

/// Separation-of-duties: the requesting admin cannot decide their own
/// request.
#[tokio::test]
async fn requester_cannot_approve_own_schema_change_request() {
    let system = skip_if_no_db!(test_system(&["schema.attribute_change"]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity_id, _) = seed_entity(&app, &admin_cookie).await;

    let resp = app
        .clone()
        .oneshot(create_field_request(&admin_cookie, entity_id, false))
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

/// A different `system.admin` approving actually creates the field in the
/// same call, and a second decide on the same (now-closed) request is a 409.
#[tokio::test]
async fn different_admin_approving_creates_the_field_and_a_second_decide_conflicts() {
    let system = skip_if_no_db!(test_system(&["schema.attribute_change"]).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity_id, _) = seed_entity(&app, &requester_cookie).await;

    let resp = app
        .clone()
        .oneshot(create_field_request(&requester_cookie, entity_id, false))
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
    assert_eq!(body["executed"]["logicalname"], "approval_gate_test_field");

    assert!(attribute_exists(&db, entity_id, "approval_gate_test_field").await);

    let resp = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 1))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// L7.3: an approval-deferred structure change that ends **blocked** when it
/// runs (here `type_drift`: the conversion names a `from_type` the field does
/// not have) is an error to the approval dispatcher — the decide call fails,
/// and the request is not recorded `executed` (the claim is released, so it
/// stays `approved` for a retry).
#[tokio::test]
async fn approved_structure_change_that_ends_blocked_is_not_recorded_executed() {
    let system = skip_if_no_db!(test_system(&["schema.attribute_change"]).await);
    let (_, requester_cookie) = seed_user(&system, true).await;
    let (_, approver_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity_id, _) = seed_entity(&app, &requester_cookie).await;

    // Create the field through its own approval.
    let resp = app
        .clone()
        .oneshot(create_field_request(&requester_cookie, entity_id, false))
        .await
        .unwrap();
    let body = body_json(resp).await;
    let create_request: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let resp = app
        .clone()
        .oneshot(decide_request(
            &approver_cookie,
            create_request,
            "approve",
            0,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let field_id: Uuid = body["executed"]["id"].as_str().unwrap().parse().unwrap();

    // Request a type change whose conversion expects the wrong current type.
    let change_type = Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/change-type"
        ))
        .header("cookie", &requester_cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::from(
            serde_json::json!({
                "field_type": "number",
                "conversion": { "from_type": "date" }
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(change_type).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
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
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let (status, executed): (String, bool) = sqlx::query_as(
        "SELECT status, executed_at IS NOT NULL FROM approval_request WHERE id = $1",
    )
    .bind(request_id)
    .fetch_one(&db)
    .await
    .expect("read approval request");
    assert_eq!(
        status, "approved",
        "a blocked change must not close the request"
    );
    assert!(!executed, "a blocked change must not be recorded executed");
    assert!(attribute_exists(&db, entity_id, "approval_gate_test_field").await);
}

// ── Abandoning a failed field run (D-788 follow-up) ────────────────────────
// Lives here for the harness (a live system with an entity and a field); the
// route itself is not approval-gated.

fn abandon_request(
    admin_cookie: &str,
    entity_id: Uuid,
    field_id: Uuid,
    run_id: Uuid,
) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/runs/{run_id}/abandon"
        ))
        .header("cookie", admin_cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

/// Inserts a retype run for the field (as `change_field_type` would on a
/// large table) in `status`; returns its id.
async fn insert_retype_run(
    db: &attome_db::DbPool,
    entity: &str,
    entity_id: Uuid,
    field_id: Uuid,
    suffix: &str,
    status: &str,
) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO data_step_run (source, entity_logicalname, kind, spec, status) \
         VALUES ('admin', $1, 'retype', $2, $3) RETURNING id",
    )
    .bind(entity)
    .bind(serde_json::json!({
        "field": "approval_gate_test_field", "attribute_id": field_id,
        "entity_id": entity_id, "suffix": suffix,
        "conversion": { "from_type": "text", "to_type": "number" }
    }))
    .bind(status)
    .fetch_one(db)
    .await
    .expect("insert data-step run")
}

async fn column_exists(db: &attome_db::DbPool, table: &str, column: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(db)
    .await
    .expect("read information_schema.columns")
}

/// A failed retype run is abandoned: its shadow column is dropped, the run is
/// `abandoned` (so the field is no longer busy), and a second abandon is a
/// 409. A queued run is refused (409) and left alone.
#[tokio::test]
async fn a_failed_retype_run_is_abandoned_and_its_shadow_column_dropped() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity_id, entity) = seed_entity(&app, &admin_cookie).await;
    let resp = app
        .clone()
        .oneshot(create_field_request(&admin_cookie, entity_id, false))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let field_id: Uuid = body_json(resp).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let suffix = "0badc0de";
    let shadow = format!("__rt_{suffix}");
    sqlx::query(&format!(
        "ALTER TABLE \"{entity}\" ADD COLUMN \"{shadow}\" NUMERIC"
    ))
    .execute(&db)
    .await
    .expect("add the shadow column");
    let run_id = insert_retype_run(&db, &entity, entity_id, field_id, suffix, "failed").await;

    let resp = app
        .clone()
        .oneshot(abandon_request(&admin_cookie, entity_id, field_id, run_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "abandoned");
    assert_eq!(body["shadow_dropped"], true);
    assert_eq!(body["conversion_completed"], false);
    assert!(!column_exists(&db, &entity, &shadow).await);
    let status: String = sqlx::query_scalar("SELECT status FROM data_step_run WHERE id = $1")
        .bind(run_id)
        .fetch_one(&db)
        .await
        .expect("read run");
    assert_eq!(status, "abandoned");

    let resp = app
        .clone()
        .oneshot(abandon_request(&admin_cookie, entity_id, field_id, run_id))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let queued = insert_retype_run(&db, &entity, entity_id, field_id, "1badc0de", "queued").await;
    let resp = app
        .clone()
        .oneshot(abandon_request(&admin_cookie, entity_id, field_id, queued))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // A run of another field is not this field's run.
    let resp = app
        .clone()
        .oneshot(abandon_request(
            &admin_cookie,
            entity_id,
            Uuid::now_v7(),
            queued,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

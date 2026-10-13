//! M07 Phase 1 (D-405/D-406) — regression coverage for `attome-state`'s
//! enforcement of `state_model`/`state_transition` from
//! inside `attome-api::entity_mutation`, plus the admin CRUD and per-record
//! routes `attome-state` itself mounts.
//!
//! Covers:
//! - create: a record must land in the model's `initial_state` (submitted
//!   explicitly, or defaulted when the caller omits the field) — an explicit
//!   non-initial value is `422 transition_not_allowed`;
//! - update via a raw `PATCH`: an unconfigured (old -> new) edge is `422
//!   transition_not_allowed`; a configured one is `200`;
//! - `POST .../transition` is a thin caller of the `PATCH` path (M07 Phase
//!   A): legal, illegal, guarded-true, guarded-false and privilege-missing
//!   transitions give the same result on both; `If-Match` is optional there;
//! - a transition guard sees the acting principal as `current_user` (P0 0.7);
//! - `GET .../transitions` never lists a transition the caller lacks
//!   `required_privilege` for;
//! - the bulk surface (`attome_records::bulk::process`, driven directly per
//!   `bulk_mutation.rs`'s own convention) shares `entity_mutation.rs`'s
//!   enforcement — one item with a legal edge succeeds, one with an illegal
//!   edge is marked `'failed'`, proving the shared-path claim rather than
//!   assuming it;
//! - M07 Phase F (D-770), a transition with an approval plan: the record is
//!   parked in its pending state (via `/transition` and via PATCH); a two-step
//!   plan (2-of-3 named users, then any of a role) excludes the requester,
//!   opens step 2 after two approvals and moves the record to the target
//!   exactly once (a replayed execution changes nothing); rejection goes to
//!   `on_reject_state` (default: the origin); the requester's cancel returns
//!   it; fields and transitions are locked while pending; a record changed
//!   underneath invalidates the request and stays parked until released; the
//!   admin API validates the settings.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `bulk_mutation.rs`/`entity_round_trip.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test state_lifecycle -- --test-threads=1
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
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness (copied near-verbatim from bulk_mutation.rs / entity_round_trip.rs) ──

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4194304, "request_timeout_secs": 15,
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
            "security": {{ "bootstrap_admin_email": null }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
    let db_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &db_url);
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
        .register(attome_state::StateModel)
        .build()
        .await
        .expect("build EngineSystem");
    system
        .state()
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));
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

async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("state-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("state-test-{user_id}"))
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

    (user_id, email, session_cookie(user_id))
}

async fn seed_non_admin_user(db: &attome_db::DbPool) -> (Uuid, String, String) {
    let user_id = Uuid::now_v7();
    let email = format!("state-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("state-test-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email, session_cookie(user_id))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn req(method: &str, uri: &str, cookie: &str, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

/// A generic entity `PATCH` needs its `row_version` in the `if-match` header
/// (`entity_crud::row_version::expected_row_version`, F027/D-037/D-079), not
/// in the JSON body — `\"{row_version}\"`, quoted like an ETag, matching
/// `entity_round_trip.rs`'s own convention.
fn patch_req(uri: &str, cookie: &str, row_version: i64, body: &Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .header("if-match", format!("\"{row_version}\""))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn grant_privilege(
    app: &axum::Router,
    admin_cookie: &str,
    user_email: &str,
    privilege_key: &str,
) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/security/grants",
            admin_cookie,
            Some(&json!({ "user_email": user_email, "privilege_key": privilege_key })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "grant {privilege_key} to {user_email}"
    );
}

/// Provisions an entity with a `title` (text) field and a `status` (choice:
/// new/in_progress/closed) field — the "ticket"-shaped fixture every test
/// below governs with a state model.
async fn provision_governed_entity(
    app: &axum::Router,
    admin_cookie: &str,
    prefix: &str,
) -> (String, Uuid) {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({
                "logicalname": logicalname,
                "name": "State Lifecycle Test",
                "is_append_only": false,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity = body_json(res).await;
    let entity_id: Uuid = entity["id"].as_str().unwrap().parse().unwrap();

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin_cookie,
            Some(&json!({ "logicalname": "title", "name": "title", "field_type": "text" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create title field");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin_cookie,
            Some(&json!({
                "logicalname": "status", "name": "Status", "field_type": "choice",
                "options": { "choices": ["new", "in_progress", "closed"], "multi": false }
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create status field");

    (logicalname, entity_id)
}

/// Creates a state model (`status`, initial `new`) and two transitions
/// (`new -> in_progress`, `in_progress -> closed`) via `attome-state`'s own
/// admin API. Returns the model id.
async fn create_ticket_lifecycle(app: &axum::Router, admin_cookie: &str, entity: &str) -> Uuid {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/state-models",
            admin_cookie,
            Some(&json!({
                "entity_logicalname": entity,
                "name": "Ticket Lifecycle",
                "state_field": "status",
                "initial_state": "new",
                "is_active": true,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create state model");
    let model_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    for (from, to, name) in [
        ("new", "in_progress", "Start"),
        ("in_progress", "closed", "Close"),
    ] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/state-models/{model_id}/transitions"),
                admin_cookie,
                Some(&json!({ "from_state": from, "to_state": to, "name": name })),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "create transition {from}->{to}"
        );
    }
    model_id
}

async fn create_record(
    app: &axum::Router,
    cookie: &str,
    entity: &str,
    data: Value,
) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}"),
            cookie,
            Some(&data),
        ))
        .await
        .unwrap();
    let status = res.status();
    (status, body_json(res).await)
}

// ── create: initial_state ────────────────────────────────────────────────────

#[tokio::test]
async fn create_defaults_to_initial_state_when_status_is_omitted() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "createdefault").await;
    create_ticket_lifecycle(&app, &admin_cookie, &entity).await;

    let (status, body) =
        create_record(&app, &admin_cookie, &entity, json!({ "title": "t1" })).await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");
    assert_eq!(
        body["data"]["status"], "new",
        "status must default to initial_state"
    );
}

#[tokio::test]
async fn create_rejects_an_explicit_non_initial_state() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "createreject").await;
    create_ticket_lifecycle(&app, &admin_cookie, &entity).await;

    let (status, body) = create_record(
        &app,
        &admin_cookie,
        &entity,
        json!({ "title": "t1", "status": "closed" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");
    assert_eq!(body["error"], "transition_not_allowed");
}

// ── update via a raw PATCH ───────────────────────────────────────────────────

#[tokio::test]
async fn patch_rejects_an_unconfigured_transition() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "patchreject").await;
    create_ticket_lifecycle(&app, &admin_cookie, &entity).await;
    let (_, created) = create_record(&app, &admin_cookie, &entity, json!({ "title": "t1" })).await;
    let id = created["id"].as_str().unwrap();

    // new -> closed has no configured edge (only new -> in_progress does).
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            0,
            &json!({ "status": "closed" }),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");
    assert_eq!(body["error"], "transition_not_allowed");

    // attome-server hardening I4: the idempotency gate releases a key on a 4xx
    // on the strength of this contract, so prove the refused transition
    // changed nothing.
    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            None,
        ))
        .await
        .unwrap();
    let fetched = body_json(res).await;
    assert_eq!(fetched["data"]["status"], "new", "{fetched:?}");
    assert_eq!(fetched["row_version"].as_i64(), Some(0), "{fetched:?}");
}

#[tokio::test]
async fn patch_allows_a_configured_transition() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "patchallow").await;
    create_ticket_lifecycle(&app, &admin_cookie, &entity).await;
    let (_, created) = create_record(&app, &admin_cookie, &entity, json!({ "title": "t1" })).await;
    let id = created["id"].as_str().unwrap();

    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            0,
            &json!({ "status": "in_progress" }),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["data"]["status"], "in_progress");
}

// ── POST .../transition enforces identically to a raw PATCH ─────────────────

#[tokio::test]
async fn transition_endpoint_and_raw_patch_enforce_the_identical_illegal_edge() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "identical").await;
    create_ticket_lifecycle(&app, &admin_cookie, &entity).await;

    // Two identically-provisioned records, each still in `new`.
    let (_, rec_patch) = create_record(&app, &admin_cookie, &entity, json!({ "title": "a" })).await;
    let (_, rec_transition) =
        create_record(&app, &admin_cookie, &entity, json!({ "title": "b" })).await;
    let id_patch = rec_patch["id"].as_str().unwrap();
    let id_transition = rec_transition["id"].as_str().unwrap();

    let patch_res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id_patch}"),
            &admin_cookie,
            0,
            &json!({ "status": "closed" }),
        ))
        .await
        .unwrap();
    let patch_status = patch_res.status();
    let patch_body = body_json(patch_res).await;

    let transition_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}/{id_transition}/transition"),
            &admin_cookie,
            Some(&json!({ "to_state": "closed" })),
        ))
        .await
        .unwrap();
    let transition_status = transition_res.status();
    let transition_body = body_json(transition_res).await;

    assert_eq!(
        patch_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{patch_body:?}"
    );
    assert_eq!(
        transition_status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{transition_body:?}"
    );
    assert_eq!(patch_body["error"], "transition_not_allowed");
    assert_eq!(
        patch_body["error"], transition_body["error"],
        "a raw PATCH and POST .../transition must reject the identical illegal edge with the same code"
    );

    // And the legal edge succeeds through .../transition too.
    let ok_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}/{id_transition}/transition"),
            &admin_cookie,
            Some(&json!({ "to_state": "in_progress" })),
        ))
        .await
        .unwrap();
    assert_eq!(ok_res.status(), StatusCode::OK);
}

// ── GET .../transitions never lists a transition the caller lacks privilege for ──

#[tokio::test]
async fn available_transitions_never_lists_one_the_caller_lacks_privilege_for() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "privlist").await;
    let model_id = create_ticket_lifecycle(&app, &admin_cookie, &entity).await;

    // A third transition, gated on a privilege nobody but system.admin holds
    // yet: new -> in_progress (ungated, already exists) plus a privileged
    // new -> closed shortcut.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/state-models/{model_id}/transitions"),
            &admin_cookie,
            Some(&json!({
                "from_state": "new", "to_state": "closed", "name": "Force close",
                "required_privilege": format!("{entity}.close")
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);

    let (_, created) = create_record(&app, &admin_cookie, &entity, json!({ "title": "t1" })).await;
    let id = created["id"].as_str().unwrap();

    let (_, caller_email, caller_cookie) = seed_non_admin_user(&db).await;
    grant_privilege(
        &app,
        &admin_cookie,
        &caller_email,
        &format!("{entity}.read"),
    )
    .await;

    let list_res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/{entity}/{id}/transitions"),
            &caller_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(list_res.status(), StatusCode::OK);
    let list = body_json(list_res).await;
    let to_states: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["to_state"].as_str().unwrap())
        .collect();
    assert_eq!(
        to_states,
        vec!["in_progress"],
        "the privileged new->closed edge must not be listed for a caller without {entity}.close"
    );

    grant_privilege(
        &app,
        &admin_cookie,
        &caller_email,
        &format!("{entity}.close"),
    )
    .await;
    let list_res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/{entity}/{id}/transitions"),
            &caller_cookie,
            None,
        ))
        .await
        .unwrap();
    let list = body_json(list_res).await;
    let mut to_states: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["to_state"].as_str().unwrap())
        .collect();
    to_states.sort_unstable();
    assert_eq!(
        to_states,
        vec!["closed", "in_progress"],
        "once granted the privilege, the closed edge must appear too"
    );
}

// ── bulk shares entity_mutation.rs's enforcement ─────────────────────────────

/// The claim under test: bulk does not have its own copy of the transition
/// check, it inherits `entity_mutation::update_one`'s. One item in the batch
/// makes a legal edge (`new -> in_progress`), the other an illegal one
/// (`new -> closed`, no direct edge) — if bulk shared no code with the raw
/// PATCH path, this would either 500 or silently write the illegal value;
/// instead the legal item succeeds and the illegal one is marked `'failed'`
/// with the same `transition_not_allowed` reason, and the operation still
/// reaches `'completed'` (partial mode keeps going, same as
/// `bulk_mutation.rs`'s row_version-conflict test).
#[tokio::test]
async fn bulk_update_enforces_the_identical_transition_check_as_a_raw_patch() {
    let system = skip_if_no_db!(test_system().await);
    let (user_id, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let state = system.state().clone();
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "bulkstate").await;
    create_ticket_lifecycle(&app, &admin_cookie, &entity).await;

    let (_, rec_legal) =
        create_record(&app, &admin_cookie, &entity, json!({ "title": "legal" })).await;
    let (_, rec_illegal) =
        create_record(&app, &admin_cookie, &entity, json!({ "title": "illegal" })).await;
    let id_legal = rec_legal["id"].as_str().unwrap().to_owned();
    let id_illegal = rec_illegal["id"].as_str().unwrap().to_owned();

    let body = json!({
        "operation": "update",
        "records": [
            { "id": id_legal, "expected_row_version": 0, "data": { "status": "in_progress" } },
            { "id": id_illegal, "expected_row_version": 0, "data": { "status": "closed" } },
        ]
    });
    let enqueue_res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}/bulk"),
            &admin_cookie,
            Some(&body),
        ))
        .await
        .unwrap();
    assert_eq!(enqueue_res.status(), StatusCode::ACCEPTED);
    let bulk_op_id: Uuid = body_json(enqueue_res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    attome_records::bulk::process(&state, bulk_op_id, &entity, "update", Vec::new(), user_id)
        .await
        .expect("process must complete (partial mode keeps going past one failed item)");

    let (op_status, succeeded, failed): (String, i32, i32) = sqlx::query_as(
        "SELECT status, succeeded, failed FROM automation_bulk_operation WHERE id = $1",
    )
    .bind(bulk_op_id)
    .fetch_one(&db)
    .await
    .expect("bulk operation row");
    assert_eq!(op_status, "completed");
    assert_eq!(succeeded, 1, "the legal edge must succeed");
    assert_eq!(
        failed, 1,
        "the illegal edge must be rejected, not silently applied"
    );

    let item_rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT status, error FROM automation_bulk_operation_item \
         WHERE bulk_operation_id = $1 ORDER BY item_index",
    )
    .bind(bulk_op_id)
    .fetch_all(&db)
    .await
    .expect("item rows");
    assert_eq!(item_rows[0].0, "succeeded");
    assert_eq!(item_rows[1].0, "failed");
    assert!(
        item_rows[1]
            .1
            .as_deref()
            .is_some_and(|e| e.contains("transition")),
        "the failure reason must name the transition, not a generic error: {:?}",
        item_rows[1].1
    );

    let table = attome_core::quote_ident(&entity);
    let illegal_status: String =
        sqlx::query_scalar(&format!("SELECT status FROM {table} WHERE id = $1"))
            .bind(Uuid::parse_str(&id_illegal).unwrap())
            .fetch_one(&db)
            .await
            .expect("illegal record row");
    assert_eq!(
        illegal_status, "new",
        "the illegal item's row must be left in its pre-write state, not 'closed'"
    );
}

// ── M45 Phase 3 (REVIEW-2026-09-02 finding #8): guard_expression is now
// evaluated ────────────────────────────────────────────────────────────────

/// Same shape as `create_ticket_lifecycle`, but the `new -> in_progress`
/// transition carries a `guard_expression` referencing `title` — proves the
/// guard is actually compiled and evaluated against the record's effective
/// field state, not just stored inertly (D-472's original Phase 1 posture).
async fn create_guarded_lifecycle(app: &axum::Router, admin_cookie: &str, entity: &str) -> Uuid {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/state-models",
            admin_cookie,
            Some(&json!({
                "entity_logicalname": entity,
                "name": "Guarded Lifecycle",
                "state_field": "status",
                "initial_state": "new",
                "is_active": true,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create state model");
    let model_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/state-models/{model_id}/transitions"),
            admin_cookie,
            Some(&json!({
                "from_state": "new",
                "to_state": "in_progress",
                "name": "Start",
                "guard_expression": "title == \"ready\"",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "create guarded transition"
    );
    model_id
}

#[tokio::test]
async fn patch_blocks_a_transition_whose_guard_expression_evaluates_false() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "guardblock").await;
    create_guarded_lifecycle(&app, &admin_cookie, &entity).await;

    let (_, not_ready) = create_record(
        &app,
        &admin_cookie,
        &entity,
        json!({ "title": "not-ready" }),
    )
    .await;
    let blocked_id = not_ready["id"].as_str().unwrap();

    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{blocked_id}"),
            &admin_cookie,
            0,
            &json!({ "status": "in_progress" }),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");
    assert_eq!(body["error"], "transition_not_allowed");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("guard")),
        "the failure reason must name the guard condition, not a generic error: {body:?}"
    );
}

#[tokio::test]
async fn patch_allows_a_transition_whose_guard_expression_evaluates_true() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "guardallow").await;
    create_guarded_lifecycle(&app, &admin_cookie, &entity).await;

    let (_, ready) = create_record(&app, &admin_cookie, &entity, json!({ "title": "ready" })).await;
    let id = ready["id"].as_str().unwrap();

    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            0,
            &json!({ "status": "in_progress" }),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["data"]["status"], "in_progress");
}

// ── M07 Phase A (§4.1): POST .../transition is a thin caller of the PATCH path ──

/// `POST .../transition`, with an optional `If-Match`.
fn transition_req(uri: &str, cookie: &str, if_match: Option<i64>, body: &Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json");
    if let Some(v) = if_match {
        builder = builder.header("if-match", format!("\"{v}\""));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn record_state(app: &axum::Router, cookie: &str, entity: &str, id: &str) -> (Value, i64) {
    let res = app
        .clone()
        .oneshot(req("GET", &format!("/api/v1/{entity}/{id}"), cookie, None))
        .await
        .unwrap();
    let body = body_json(res).await;
    (
        body["data"]["status"].clone(),
        body["row_version"].as_i64().unwrap(),
    )
}

/// One case of the parity table: two identically prepared records, the same
/// state change through `PATCH` on one and `POST .../transition` on the
/// other, by the same caller. Status, error code and resulting record state
/// must match. Returns the shared status.
async fn assert_same_via_patch_and_transition(
    app: &axum::Router,
    cookie: &str,
    entity: &str,
    (id_patch, id_transition): (&str, &str),
    version: i64,
    to_state: &str,
) -> StatusCode {
    let patch = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id_patch}"),
            cookie,
            version,
            &json!({ "status": to_state }),
        ))
        .await
        .unwrap();
    let patch_status = patch.status();
    let patch_body = body_json(patch).await;

    let transition = app
        .clone()
        .oneshot(transition_req(
            &format!("/api/v1/{entity}/{id_transition}/transition"),
            cookie,
            None,
            &json!({ "to_state": to_state, "comment": "parity" }),
        ))
        .await
        .unwrap();
    let transition_status = transition.status();
    let transition_body = body_json(transition).await;

    assert_eq!(
        patch_status, transition_status,
        "-> {to_state}: PATCH {patch_body:?} vs /transition {transition_body:?}"
    );
    assert_eq!(
        patch_body["error"], transition_body["error"],
        "-> {to_state}: same error code"
    );
    if patch_status == StatusCode::OK {
        assert_eq!(transition_body["to_state"], to_state);
        assert_eq!(
            transition_body["row_version"].as_i64(),
            patch_body["row_version"].as_i64(),
            "-> {to_state}: both paths bump row_version once"
        );
    }
    let admin_view_patch = record_state(app, cookie, entity, id_patch).await;
    let admin_view_transition = record_state(app, cookie, entity, id_transition).await;
    assert_eq!(
        admin_view_patch, admin_view_transition,
        "-> {to_state}: both records end in the same state"
    );
    patch_status
}

/// The model the parity test governs with: `new -> in_progress` guarded on
/// `title == "ready"`, `in_progress -> new` open, `in_progress -> closed`
/// requiring `{entity}.close`. `new -> closed` is not configured.
async fn create_parity_lifecycle(app: &axum::Router, admin_cookie: &str, entity: &str) {
    let model_id = create_guarded_lifecycle(app, admin_cookie, entity).await;
    for body in [
        json!({ "from_state": "in_progress", "to_state": "new", "name": "Back" }),
        json!({
            "from_state": "in_progress", "to_state": "closed", "name": "Close",
            "required_privilege": format!("{entity}.close"),
        }),
    ] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/state-models/{model_id}/transitions"),
                admin_cookie,
                Some(&body),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "{body}");
    }
}

/// M07 Phase A acceptance: legal, illegal, guarded-true, guarded-false and
/// privilege-missing transitions give the same result through `PATCH` and
/// `POST .../transition` (the old route refused every guarded transition).
#[tokio::test]
async fn transition_endpoint_and_patch_agree_on_every_kind_of_transition() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "parity").await;
    create_parity_lifecycle(&app, &admin_cookie, &entity).await;

    let (_, caller_email, cookie) = seed_non_admin_user(&db).await;
    for action in ["read", "update"] {
        grant_privilege(
            &app,
            &admin_cookie,
            &caller_email,
            &format!("{entity}.{action}"),
        )
        .await;
    }

    async fn pair(app: &axum::Router, admin: &str, entity: &str, title: &str) -> (String, String) {
        let mut ids = Vec::new();
        for _ in 0..2 {
            let (status, rec) = create_record(app, admin, entity, json!({ "title": title })).await;
            assert_eq!(status, StatusCode::CREATED, "{rec:?}");
            ids.push(rec["id"].as_str().unwrap().to_owned());
        }
        (ids[0].clone(), ids[1].clone())
    }
    async fn to_in_progress(app: &axum::Router, admin: &str, entity: &str, ids: &(String, String)) {
        for id in [&ids.0, &ids.1] {
            let res = app
                .clone()
                .oneshot(patch_req(
                    &format!("/api/v1/{entity}/{id}"),
                    admin,
                    0,
                    &json!({ "status": "in_progress" }),
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK);
        }
    }

    // guarded, guard true: new -> in_progress on a "ready" record.
    let ready = pair(&app, &admin_cookie, &entity, "ready").await;
    let s = assert_same_via_patch_and_transition(
        &app,
        &cookie,
        &entity,
        (&ready.0, &ready.1),
        0,
        "in_progress",
    )
    .await;
    assert_eq!(s, StatusCode::OK, "guarded-true");

    // legal, unguarded: in_progress -> new.
    let s = assert_same_via_patch_and_transition(
        &app,
        &cookie,
        &entity,
        (&ready.0, &ready.1),
        1,
        "new",
    )
    .await;
    assert_eq!(s, StatusCode::OK, "legal");

    // guarded, guard false: new -> in_progress on a "not-ready" record.
    let not_ready = pair(&app, &admin_cookie, &entity, "not-ready").await;
    let s = assert_same_via_patch_and_transition(
        &app,
        &cookie,
        &entity,
        (&not_ready.0, &not_ready.1),
        0,
        "in_progress",
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "guarded-false");

    // illegal: new -> closed is not configured.
    let s = assert_same_via_patch_and_transition(
        &app,
        &cookie,
        &entity,
        (&not_ready.0, &not_ready.1),
        0,
        "closed",
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "illegal");

    // privilege missing: in_progress -> closed needs {entity}.close.
    let closable = pair(&app, &admin_cookie, &entity, "ready").await;
    to_in_progress(&app, &admin_cookie, &entity, &closable).await;
    let s = assert_same_via_patch_and_transition(
        &app,
        &cookie,
        &entity,
        (&closable.0, &closable.1),
        1,
        "closed",
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "privilege-missing");
}

/// §4.1: `If-Match` is optional on `/transition` (absent = current version);
/// a stale one is a 409 and writes nothing; a successful transition writes
/// exactly one change-feed row, like a PATCH.
#[tokio::test]
async fn transition_endpoint_honours_if_match_and_writes_one_change_feed_row() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "ifmatch").await;
    create_ticket_lifecycle(&app, &admin_cookie, &entity).await;
    let (_, created) = create_record(&app, &admin_cookie, &entity, json!({ "title": "t" })).await;
    let id = created["id"].as_str().unwrap().to_owned();
    let uri = format!("/api/v1/{entity}/{id}/transition");

    let stale = app
        .clone()
        .oneshot(transition_req(
            &uri,
            &admin_cookie,
            Some(5),
            &json!({ "to_state": "in_progress" }),
        ))
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    assert_eq!(
        record_state(&app, &admin_cookie, &entity, &id).await,
        (json!("new"), 0)
    );

    let feed_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM entity_change_event WHERE record_id = $1")
            .bind(Uuid::parse_str(&id).unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
    let ok = app
        .clone()
        .oneshot(transition_req(
            &uri,
            &admin_cookie,
            Some(0),
            &json!({ "to_state": "in_progress", "comment": "go" }),
        ))
        .await
        .unwrap();
    let status = ok.status();
    let body = body_json(ok).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["from_state"], "new");
    assert_eq!(body["to_state"], "in_progress");
    assert_eq!(body["row_version"].as_i64(), Some(1));
    let feed_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM entity_change_event WHERE record_id = $1")
            .bind(Uuid::parse_str(&id).unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(feed_after - feed_before, 1, "exactly one change-feed row");

    // No If-Match: transitions from the current version.
    let res = app
        .clone()
        .oneshot(transition_req(
            &uri,
            &admin_cookie,
            None,
            &json!({ "to_state": "closed" }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        record_state(&app, &admin_cookie, &entity, &id).await,
        (json!("closed"), 2)
    );
}

// ── P0 0.7: a transition guard sees the acting principal as `current_user` ──

/// The fixture entity plus a `submitted_by` lookup to `user_account`,
/// governed by `new -> in_progress` guarded on `current_user != submitted_by`.
async fn provision_four_eyes_entity(
    app: &axum::Router,
    admin_cookie: &str,
    db: &attome_db::DbPool,
) -> String {
    let (entity, entity_id) = provision_governed_entity(app, admin_cookie, "foureyes").await;
    let user_entity: Uuid =
        sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = 'user_account'")
            .fetch_one(db)
            .await
            .expect("user_account entity");
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin_cookie,
            Some(&json!({
                "logicalname": "submitted_by", "name": "Submitted By", "field_type": "lookup",
                "lookup_entity_ref": user_entity.to_string(),
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create submitted_by");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/state-models",
            admin_cookie,
            Some(&json!({
                "entity_logicalname": entity, "name": "Four Eyes", "state_field": "status",
                "initial_state": "new", "is_active": true,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let model_id = body_json(res).await["id"].as_str().unwrap().to_owned();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/state-models/{model_id}/transitions"),
            admin_cookie,
            Some(&json!({
                "from_state": "new", "to_state": "in_progress", "name": "Approve",
                "guard_expression": "current_user != submitted_by",
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    entity
}

#[tokio::test]
async fn a_current_user_guard_refuses_the_submitter_and_allows_another_user() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let app = full_app(system);
    let entity = provision_four_eyes_entity(&app, &admin_cookie, &db).await;

    let (submitter, submitter_email, submitter_cookie) = seed_non_admin_user(&db).await;
    let (other, other_email, other_cookie) = seed_non_admin_user(&db).await;
    for email in [&submitter_email, &other_email] {
        for action in ["read", "update"] {
            grant_privilege(&app, &admin_cookie, email, &format!("{entity}.{action}")).await;
        }
    }
    let (status, rec) = create_record(
        &app,
        &admin_cookie,
        &entity,
        json!({ "title": "t", "submitted_by": submitter }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{rec:?}");
    let id = rec["id"].as_str().unwrap().to_owned();

    // The submitter: refused through PATCH and through /transition.
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &submitter_cookie,
            0,
            &json!({ "status": "in_progress" }),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");
    assert_eq!(body["error"], "transition_not_allowed");
    let res = app
        .clone()
        .oneshot(transition_req(
            &format!("/api/v1/{entity}/{id}/transition"),
            &submitter_cookie,
            None,
            &json!({ "to_state": "in_progress" }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Nor by naming someone else as the submitter in the same write.
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &submitter_cookie,
            0,
            &json!({ "status": "in_progress", "submitted_by": other }),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.contains("same write")),
        "{body:?}"
    );
    assert_eq!(
        record_state(&app, &admin_cookie, &entity, &id).await,
        (json!("new"), 0)
    );

    // A different user: allowed.
    let res = app
        .clone()
        .oneshot(transition_req(
            &format!("/api/v1/{entity}/{id}/transition"),
            &other_cookie,
            None,
            &json!({ "to_state": "in_progress" }),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(body["to_state"], "in_progress");
}

// ── the real service_ticket built-in state model (attome-service::seed::seed_state_models) ──

/// Everything above governs a synthetic, per-test-provisioned entity. This
/// is the one direct check against the REAL `service_ticket` built-in state
/// model `attome-service::seed::seed_state_models` seeds (called from
/// `attome-api::system.rs` at boot, so it is already live by the time
/// `test_system()` finishes building). `service_ticket.status` is `is_required
/// = true` (unlike the synthetic fixture's `status`, which
/// `provision_governed_entity` leaves optional) — the exact edge case
/// REVIEW-2026-09-02 flagged as a real platform bug elsewhere (a required
/// state field can never be omitted, so `create_one`'s required-field check
/// at `validate_body` — which runs BEFORE `check_initial_state`'s
/// defaulting — would reject the create outright before the default ever
/// applies). Proves the actual behavior end-to-end against the live model
/// rather than reasoning about it from the code alone.
#[tokio::test]
async fn real_ticket_creates_at_new_and_transitions_to_resolved() {
    let system = skip_if_no_db!(test_system().await);
    let (admin_id, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    // `status` is required, so it must be submitted explicitly — this is
    // the only way any caller has ever been able to create a ticket, since
    // the field predates this state model. Submitting exactly the model's
    // `initial_state` ("new") must succeed.
    let (status, body) = create_record(
        &app,
        &admin_cookie,
        "service_ticket",
        json!({
            "ticket_number": format!("T-{}", Uuid::now_v7().simple()),
            "title": "state model smoke test",
            "requester_id": admin_id,
            "status": "new",
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create at initial state: {body:?}"
    );
    assert_eq!(body["data"]["status"], "new");
    let ticket_id = body["data"]["id"].as_str().unwrap().to_string();
    let row_version: i64 = body["data"]["row_version"].as_i64().unwrap();

    // A real transition real code performs: resolving a ticket. The seeded
    // model is fully connected, so new -> resolved is a configured edge.
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/service_ticket/{ticket_id}"),
            &admin_cookie,
            row_version,
            &json!({ "status": "resolved" }),
        ))
        .await
        .unwrap();
    let patch_status = res.status();
    let patch_body = body_json(res).await;
    assert_eq!(
        patch_status,
        StatusCode::OK,
        "resolve transition: {patch_body:?}"
    );
    assert_eq!(patch_body["data"]["status"], "resolved");
}

// ── Admin: moving a transition's edge in place ──────────────────────────────

/// basic-units-10-10 §8 P1 follow-up: `PATCH .../transitions/{id}` can move
/// an edge's `from_state`/`to_state` in place, under create's own rules — a
/// state that is not an option of the model's field is 422, an edge that
/// already exists is 409, a stale `row_version` is 409 — and the move is
/// enforced on the very next record write (the state-model cache is
/// invalidated the way create/delete invalidate it).
#[tokio::test]
async fn update_transition_moves_from_and_to_under_the_create_rules() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "edgemove").await;
    let model_id = create_ticket_lifecycle(&app, &admin_cookie, &entity).await;

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/admin/state-models/{model_id}"),
            &admin_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let detail = body_json(res).await;
    let start = detail["transitions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "Start")
        .cloned()
        .expect("the Start transition");
    let start_id = start["id"].as_str().unwrap().to_string();
    let start_version = start["row_version"].as_i64().unwrap();
    let uri = format!("/api/v1/admin/state-models/{model_id}/transitions/{start_id}");

    // Not an option of `status`: 422.
    let res = app
        .clone()
        .oneshot(req(
            "PATCH",
            &uri,
            &admin_cookie,
            Some(&json!({ "to_state": "bogus", "name": "Start", "row_version": start_version })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid state"
    );

    // A blank end is refused, not treated as "keep".
    let res = app
        .clone()
        .oneshot(req(
            "PATCH",
            &uri,
            &admin_cookie,
            Some(&json!({ "from_state": "  ", "name": "Start", "row_version": start_version })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "blank from_state"
    );

    // in_progress -> closed already exists (the Close edge): 409.
    let res = app
        .clone()
        .oneshot(req(
            "PATCH",
            &uri,
            &admin_cookie,
            Some(&json!({
                "from_state": "in_progress", "to_state": "closed",
                "name": "Start", "row_version": start_version
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "duplicate edge");

    // new -> closed is valid: moved in place, same id, version bumped.
    let res = app
        .clone()
        .oneshot(req(
            "PATCH",
            &uri,
            &admin_cookie,
            Some(
                &json!({ "to_state": "closed", "name": "Shortcut", "row_version": start_version }),
            ),
        ))
        .await
        .unwrap();
    let status = res.status();
    let moved = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "{moved:?}");
    assert_eq!(moved["id"], start_id.as_str());
    assert_eq!(moved["from_state"], "new", "an omitted end is kept");
    assert_eq!(moved["to_state"], "closed");
    assert_eq!(moved["name"], "Shortcut");
    assert_eq!(moved["row_version"].as_i64(), Some(start_version + 1));

    // The version the edit started from is stale now: 409.
    let res = app
        .clone()
        .oneshot(req(
            "PATCH",
            &uri,
            &admin_cookie,
            Some(&json!({ "to_state": "in_progress", "name": "Start", "row_version": start_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "stale row_version");

    // Enforcement follows the move at once: new -> in_progress is gone,
    // new -> closed is allowed.
    let (_, created) = create_record(&app, &admin_cookie, &entity, json!({ "title": "t1" })).await;
    let id = created["id"].as_str().unwrap();
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            0,
            &json!({ "status": "in_progress" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "the moved-away edge must no longer be allowed"
    );
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &admin_cookie,
            0,
            &json!({ "status": "closed" }),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the moved-to edge is allowed: {body:?}"
    );
}

/// Create applies the same option check the update does.
#[tokio::test]
async fn create_transition_rejects_a_state_that_is_not_an_option() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let (entity, _) = provision_governed_entity(&app, &admin_cookie, "edgecreate").await;
    let model_id = create_ticket_lifecycle(&app, &admin_cookie, &entity).await;

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/state-models/{model_id}/transitions"),
            &admin_cookie,
            Some(&json!({ "from_state": "new", "to_state": "archived", "name": "Archive" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ── M07 Phase F (D-770): multi-party approval on a transition ────────────────
//
// A transition carrying an `approval_plan` does not happen on write: the
// record moves to its `pending_state` and a `attome-approval` request is
// submitted in the same transaction. Approval moves it to the target exactly
// once, rejection to `on_reject_state`, cancel back to the origin; while
// pending the record is locked.

/// An entity with `title` (text) and `status` (choice: new, pending_approval,
/// approved, rejected).
async fn provision_approval_entity(app: &axum::Router, admin_cookie: &str, prefix: &str) -> String {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({
                "logicalname": logicalname,
                "name": "Approval Lifecycle Test",
                "is_append_only": false,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    for field in [
        json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
        json!({
            "logicalname": "status", "name": "Status", "field_type": "choice",
            "options": {
                "choices": ["new", "pending_approval", "approved", "rejected"],
                "multi": false
            }
        }),
    ] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                admin_cookie,
                Some(&field),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create field {field}");
    }
    logicalname
}

/// A model (initial `new`) with one transition `new -> approved` carrying
/// `plan`, parked in `pending_approval`. Returns the model id and the
/// transition response body.
async fn create_approval_model(
    app: &axum::Router,
    admin_cookie: &str,
    entity: &str,
    plan: Value,
    on_reject_state: Option<&str>,
) -> (Uuid, Value) {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/state-models",
            admin_cookie,
            Some(&json!({
                "entity_logicalname": entity,
                "name": "Approval Lifecycle",
                "state_field": "status",
                "initial_state": "new",
                "is_active": true,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create state model");
    let model_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let mut transition = json!({
        "from_state": "new",
        "to_state": "approved",
        "name": "Approve",
        "approval_plan": plan,
        "pending_state": "pending_approval",
    });
    if let Some(reject) = on_reject_state {
        transition["on_reject_state"] = json!(reject);
    }
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/state-models/{model_id}/transitions"),
            admin_cookie,
            Some(&transition),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create approval transition: {body:?}"
    );
    assert_eq!(body["pending_state"], "pending_approval", "{body:?}");
    (model_id, body)
}

/// A role holding `members`, for a `role:<uuid>` approver token.
async fn seed_role_with_members(db: &attome_db::DbPool, members: &[Uuid]) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("approval-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert throwaway role");
    for member in members {
        sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
            .bind(member)
            .bind(role_id)
            .execute(db)
            .await
            .expect("insert throwaway role membership");
    }
    role_id
}

/// The record's current `status` and `row_version`.
async fn record_status(app: &axum::Router, cookie: &str, entity: &str, id: &str) -> (Value, i64) {
    let res = app
        .clone()
        .oneshot(req("GET", &format!("/api/v1/{entity}/{id}"), cookie, None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    (
        body["data"]["status"].clone(),
        body["row_version"].as_i64().unwrap(),
    )
}

async fn decide(
    app: &axum::Router,
    db: &attome_db::DbPool,
    cookie: &str,
    request_id: Uuid,
    decision: &str,
    comment: Option<&str>,
) -> (StatusCode, Value) {
    let row_version = attome_approval::get(db, request_id)
        .await
        .expect("read approval request")
        .row_version;
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/approvals/{request_id}/decide"),
            cookie,
            Some(&json!({ "decision": decision, "row_version": row_version, "comment": comment })),
        ))
        .await
        .unwrap();
    let status = res.status();
    (status, body_json(res).await)
}

/// Asks for `new -> approved` through `/transition` and returns the approval
/// request it opened, asserting the record was parked instead.
async fn request_approval(app: &axum::Router, cookie: &str, entity: &str, id: &str) -> Uuid {
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}/{id}/transition"),
            cookie,
            Some(&json!({ "to_state": "approved", "comment": "please approve" })),
        ))
        .await
        .unwrap();
    let status = res.status();
    let body = body_json(res).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(
        body["to_state"], "pending_approval",
        "parked, not moved: {body:?}"
    );
    assert_eq!(body["requested_state"], "approved", "{body:?}");
    body["approval_request_id"]
        .as_str()
        .expect("the response names the approval request")
        .parse()
        .unwrap()
}

/// Whether an audit event naming both `record_id` and `request_id` exists, on
/// either audit path (the chainer's ingest queue or the synchronous header).
async fn audit_names_request(db: &attome_db::DbPool, record_id: &str, request_id: Uuid) -> bool {
    let request = request_id.to_string();
    let header: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_header \
         WHERE record_id = $1::uuid AND event_comment LIKE '%' || $2 || '%'",
    )
    .bind(record_id)
    .bind(&request)
    .fetch_one(db)
    .await
    .expect("read audit header");
    let ingest: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_ingest \
         WHERE payload::text LIKE '%' || $1 || '%' AND payload::text LIKE '%' || $2 || '%'",
    )
    .bind(record_id)
    .bind(&request)
    .fetch_one(db)
    .await
    .expect("read audit ingest");
    header + ingest > 0
}

/// The Phase F acceptance for the core flow: a two-step plan (step 1 `n_of_m`
/// 2-of-3 named users, step 2 `any` of a role) parks the record; the
/// requester can decide neither step; two approvals open step 2; the final
/// approval moves the record to the target exactly once, and a replayed
/// execution changes nothing. Fields and transitions are locked meanwhile.
#[tokio::test]
async fn a_two_step_approval_moves_the_record_to_its_target_exactly_once() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (requester, _, requester_cookie) = seed_user(&system, true).await;
    let (a1, _, a1_cookie) = seed_user(&system, true).await;
    let (a2, _, a2_cookie) = seed_user(&system, true).await;
    let (a3, _, _) = seed_user(&system, true).await;
    let (m, _, m_cookie) = seed_user(&system, true).await;
    // The requester also holds the step-2 role: attome-approval must still
    // exclude them.
    let role = seed_role_with_members(&db, &[m, requester]).await;
    let app = full_app(system);
    let entity = provision_approval_entity(&app, &requester_cookie, "apprtwostep").await;
    let plan = json!({ "steps": [
        { "mode": "nof_m", "threshold": 2, "approvers": [
            format!("user:{a1}"), format!("user:{a2}"), format!("user:{a3}")
        ], "sla_minutes": null },
        { "mode": "any", "approvers": [format!("role:{role}")], "sla_minutes": null },
    ]});
    create_approval_model(&app, &requester_cookie, &entity, plan, Some("rejected")).await;
    let (_, created) =
        create_record(&app, &requester_cookie, &entity, json!({ "title": "t" })).await;
    let id = created["id"].as_str().unwrap().to_owned();

    let request_id = request_approval(&app, &requester_cookie, &entity, &id).await;
    let (status, parked_version) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(status, "pending_approval");
    let request = attome_approval::get(&db, request_id).await.unwrap();
    assert_eq!(request.action_type, "state.transition");
    assert_eq!(request.requested_by, requester);
    assert_eq!(request.regarding_id, Some(id.parse().unwrap()));
    assert_eq!(request.payload["row_version"], parked_version);
    assert_eq!(request.payload["on_reject_state"], "rejected");

    // Locked while pending: a field edit, a transition, and no buttons.
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &requester_cookie,
            parked_version,
            &json!({ "title": "edited while pending" }),
        ))
        .await
        .unwrap();
    let code = res.status();
    let body = body_json(res).await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");
    assert_eq!(body["error"], "transition_not_allowed");
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}/{id}/transition"),
            &requester_cookie,
            Some(&json!({ "to_state": "approved" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/{entity}/{id}/transitions"),
            &requester_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(body_json(res).await["total"], 0, "no buttons while pending");

    // The requester cannot approve step 1.
    let (code, body) = decide(&app, &db, &requester_cookie, request_id, "approve", None).await;
    assert_eq!(code, StatusCode::FORBIDDEN, "{body:?}");

    // Two of three named approvers open step 2; the record stays parked.
    let (code, body) = decide(&app, &db, &a1_cookie, request_id, "approve", None).await;
    assert_eq!(code, StatusCode::OK, "{body:?}");
    assert_eq!(body["status"], "pending");
    assert_eq!(attome_approval::get(&db, request_id).await.unwrap().step, 0);
    let (code, body) = decide(&app, &db, &a2_cookie, request_id, "approve", None).await;
    assert_eq!(code, StatusCode::OK, "{body:?}");
    assert_eq!(body["status"], "pending");
    assert_eq!(
        attome_approval::get(&db, request_id).await.unwrap().step,
        1,
        "two approvals close the 2-of-3 step"
    );
    let (status, _) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(
        status, "pending_approval",
        "still parked until the last step"
    );

    // The requester holds the step-2 role and still cannot approve.
    let (code, body) = decide(&app, &db, &requester_cookie, request_id, "approve", None).await;
    assert_eq!(code, StatusCode::FORBIDDEN, "{body:?}");

    // The role member's approval closes the request and executes it.
    let (code, body) = decide(&app, &db, &m_cookie, request_id, "approve", None).await;
    assert_eq!(code, StatusCode::OK, "{body:?}");
    assert_eq!(body["executed"]["to_state"], "approved", "{body:?}");
    let (status, final_version) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(status, "approved");
    assert_eq!(final_version, parked_version + 1, "moved exactly once");
    let closed = attome_approval::get(&db, request_id).await.unwrap();
    assert_eq!(closed.status, attome_approval::ApprovalStatus::Executed);
    assert!(
        audit_names_request(&db, &id, request_id).await,
        "the record's audit trail names the approval request"
    );

    // A replayed execution changes nothing: the job path finds nothing to
    // claim, retry-execution refuses, and the record is untouched.
    let replay = attome_api::execute_approved_request(&state, request_id)
        .await
        .expect("replay");
    assert_eq!(replay, attome_api::AutoExecution::NotClaimed);
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/admin/approvals/{request_id}/retry-execution"),
            &a1_cookie,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
    let (status, version) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!((status, version), (json!("approved"), final_version));
}

/// A rejection moves the record to `on_reject_state`, and the rejection
/// comment reaches the record's audit trail.
#[tokio::test]
async fn a_rejection_moves_the_record_to_its_on_reject_state() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let (_, _, requester_cookie) = seed_user(&system, true).await;
    let (a1, _, a1_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let entity = provision_approval_entity(&app, &requester_cookie, "apprreject").await;
    let plan = json!({ "steps": [
        { "mode": "any", "approvers": [format!("user:{a1}")], "sla_minutes": null }
    ]});
    create_approval_model(&app, &requester_cookie, &entity, plan, Some("rejected")).await;
    let (_, created) =
        create_record(&app, &requester_cookie, &entity, json!({ "title": "t" })).await;
    let id = created["id"].as_str().unwrap().to_owned();
    let request_id = request_approval(&app, &requester_cookie, &entity, &id).await;

    let (code, body) = decide(
        &app,
        &db,
        &a1_cookie,
        request_id,
        "reject",
        Some("budget not available"),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body:?}");
    assert_eq!(body["status"], "rejected");
    let (status, _) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(status, "rejected");
    assert!(audit_names_request(&db, &id, request_id).await);
}

/// Without an `on_reject_state` a rejection returns the record to its origin.
#[tokio::test]
async fn a_rejection_without_on_reject_state_returns_to_the_origin() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let (_, _, requester_cookie) = seed_user(&system, true).await;
    let (a1, _, a1_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let entity = provision_approval_entity(&app, &requester_cookie, "apprrejorigin").await;
    let plan = json!({ "steps": [
        { "mode": "any", "approvers": [format!("user:{a1}")], "sla_minutes": null }
    ]});
    create_approval_model(&app, &requester_cookie, &entity, plan, None).await;
    let (_, created) =
        create_record(&app, &requester_cookie, &entity, json!({ "title": "t" })).await;
    let id = created["id"].as_str().unwrap().to_owned();
    let request_id = request_approval(&app, &requester_cookie, &entity, &id).await;
    let (code, _) = decide(&app, &db, &a1_cookie, request_id, "reject", None).await;
    assert_eq!(code, StatusCode::OK);
    let (status, _) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(status, "new");
}

/// Only the requester may cancel; cancelling returns the record to its
/// origin, where it is editable and transitionable again.
#[tokio::test]
async fn cancel_returns_the_record_to_its_origin() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state().clone();
    let db = state.base.db.clone();
    let (_, _, requester_cookie) = seed_user(&system, true).await;
    let (a1, _, a1_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let entity = provision_approval_entity(&app, &requester_cookie, "apprcancel").await;
    let plan = json!({ "steps": [
        { "mode": "any", "approvers": [format!("user:{a1}")], "sla_minutes": null }
    ]});
    create_approval_model(&app, &requester_cookie, &entity, plan, Some("rejected")).await;
    let (_, created) =
        create_record(&app, &requester_cookie, &entity, json!({ "title": "t" })).await;
    let id = created["id"].as_str().unwrap().to_owned();
    let request_id = request_approval(&app, &requester_cookie, &entity, &id).await;

    let cancel = |cookie: String| {
        let app = app.clone();
        let uri = format!("/api/v1/{entity}/{id}/transition/cancel");
        async move {
            let res = app
                .oneshot(req(
                    "POST",
                    &uri,
                    &cookie,
                    Some(&json!({ "comment": "withdrawn" })),
                ))
                .await
                .unwrap();
            let status = res.status();
            (status, body_json(res).await)
        }
    };
    let (code, body) = cancel(a1_cookie.clone()).await;
    assert_eq!(
        code,
        StatusCode::FORBIDDEN,
        "only the requester cancels: {body:?}"
    );
    let (code, body) = cancel(requester_cookie.clone()).await;
    assert_eq!(code, StatusCode::OK, "{body:?}");
    assert_eq!(body["to_state"], "new", "{body:?}");
    assert_eq!(
        attome_approval::get(&db, request_id).await.unwrap().status,
        attome_approval::ApprovalStatus::Cancelled
    );
    let (status, version) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(status, "new");
    // Unlocked again.
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &requester_cookie,
            version,
            &json!({ "title": "editable again" }),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // A second cancel has nothing to cancel.
    let (code, _) = cancel(requester_cookie.clone()).await;
    assert_eq!(code, StatusCode::CONFLICT);
    // And the stale request can no longer move the record.
    let (_, version) = record_status(&app, &requester_cookie, &entity, &id).await;
    let cancelled = attome_approval::get(&db, request_id).await.unwrap();
    assert!(
        attome_state::approval::settle_closed_request(&state, &cancelled, Uuid::nil(), None)
            .await
            .map(|moved| moved.is_none())
            .unwrap_or(true),
        "a settled request is a no-op"
    );
    let (_, after) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(after, version);
}

/// A record that changed underneath its open approval (a write that did not
/// go through the engine) is not moved on approval: the request is
/// invalidated and the record stays parked until it is released.
#[tokio::test]
async fn a_changed_record_invalidates_the_approval_and_stays_pending() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let (_, _, requester_cookie) = seed_user(&system, true).await;
    let (a1, _, a1_cookie) = seed_user(&system, true).await;
    let app = full_app(system);
    let entity = provision_approval_entity(&app, &requester_cookie, "apprinvalid").await;
    let plan = json!({ "steps": [
        { "mode": "any", "approvers": [format!("user:{a1}")], "sla_minutes": null }
    ]});
    create_approval_model(&app, &requester_cookie, &entity, plan, Some("rejected")).await;
    let (_, created) =
        create_record(&app, &requester_cookie, &entity, json!({ "title": "t" })).await;
    let id = created["id"].as_str().unwrap().to_owned();
    let request_id = request_approval(&app, &requester_cookie, &entity, &id).await;

    // Simulates a write outside the engine (the only way past the lock).
    sqlx::query(&format!(
        "UPDATE \"{entity}\" SET row_version = row_version + 1 WHERE id = $1::uuid"
    ))
    .bind(&id)
    .execute(&db)
    .await
    .unwrap();

    let (code, body) = decide(&app, &db, &a1_cookie, request_id, "approve", None).await;
    assert_eq!(code, StatusCode::CONFLICT, "{body:?}");
    assert_eq!(
        attome_approval::get(&db, request_id).await.unwrap().status,
        attome_approval::ApprovalStatus::Invalidated
    );
    let (status, _) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(
        status, "pending_approval",
        "left parked with a logged reason"
    );

    // The requester releases it back to the origin.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/{entity}/{id}/transition/cancel"),
            &requester_cookie,
            Some(&json!({})),
        ))
        .await
        .unwrap();
    let code = res.status();
    let body = body_json(res).await;
    assert_eq!(code, StatusCode::OK, "{body:?}");
    let (status, _) = record_status(&app, &requester_cookie, &entity, &id).await;
    assert_eq!(status, "new");
}

/// A raw PATCH asking for the gated state parks the record too, and names the
/// request on the record response.
#[tokio::test]
async fn a_patch_asking_for_a_gated_state_parks_the_record() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, requester_cookie) = seed_user(&system, true).await;
    let (a1, _, _) = seed_user(&system, true).await;
    let app = full_app(system);
    let entity = provision_approval_entity(&app, &requester_cookie, "apprpatch").await;
    let plan = json!({ "steps": [
        { "mode": "any", "approvers": [format!("user:{a1}")], "sla_minutes": null }
    ]});
    create_approval_model(&app, &requester_cookie, &entity, plan, None).await;
    let (_, created) =
        create_record(&app, &requester_cookie, &entity, json!({ "title": "t" })).await;
    let id = created["id"].as_str().unwrap();
    let res = app
        .clone()
        .oneshot(patch_req(
            &format!("/api/v1/{entity}/{id}"),
            &requester_cookie,
            0,
            &json!({ "status": "approved" }),
        ))
        .await
        .unwrap();
    let code = res.status();
    let body = body_json(res).await;
    assert_eq!(code, StatusCode::OK, "{body:?}");
    assert_eq!(body["data"]["status"], "pending_approval", "{body:?}");
    assert!(body["approval_request_id"].is_string(), "{body:?}");
}

/// The admin API validates the approval settings: a pending state that is
/// not an option, a plan without a pending state, a pending state equal to
/// an edge end, and a structurally invalid plan are all 422.
#[tokio::test]
async fn transition_approval_settings_are_validated() {
    let system = skip_if_no_db!(test_system().await);
    let (_, _, admin_cookie) = seed_user(&system, true).await;
    let (a1, _, _) = seed_user(&system, true).await;
    let app = full_app(system);
    let entity = provision_approval_entity(&app, &admin_cookie, "apprvalidate").await;
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/state-models",
            &admin_cookie,
            Some(&json!({
                "entity_logicalname": entity, "name": "V", "state_field": "status",
                "initial_state": "new", "is_active": true,
            })),
        ))
        .await
        .unwrap();
    let model_id = body_json(res).await["id"].as_str().unwrap().to_owned();
    let one_step = json!({ "steps": [
        { "mode": "any", "approvers": [format!("user:{a1}")], "sla_minutes": null }
    ]});
    let two_of_one = json!({ "steps": [
        { "mode": "nof_m", "threshold": 2, "approvers": [format!("user:{a1}")], "sla_minutes": null }
    ]});
    for (case, body) in [
        (
            "pending state is not an option",
            json!({ "approval_plan": one_step, "pending_state": "limbo" }),
        ),
        (
            "plan without a pending state",
            json!({ "approval_plan": one_step }),
        ),
        (
            "pending state without a plan",
            json!({ "pending_state": "pending_approval" }),
        ),
        (
            "pending state equals the target",
            json!({ "approval_plan": one_step, "pending_state": "approved" }),
        ),
        (
            "threshold above the named approvers",
            json!({ "approval_plan": two_of_one, "pending_state": "pending_approval" }),
        ),
        (
            "unsupported approver token",
            json!({
                "approval_plan": { "steps": [
                    { "mode": "any", "approvers": ["nobody:owner"], "sla_minutes": null }
                ]},
                "pending_state": "pending_approval"
            }),
        ),
    ] {
        let mut transition = json!({ "from_state": "new", "to_state": "approved", "name": "A" });
        for (k, v) in body.as_object().unwrap() {
            transition[k] = v.clone();
        }
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/state-models/{model_id}/transitions"),
                &admin_cookie,
                Some(&transition),
            ))
            .await
            .unwrap();
        let code = res.status();
        let body = body_json(res).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{case}: {body:?}");
    }
}

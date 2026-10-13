//! Web portal Phase 1 boundary, proven over HTTP through the full middleware
//! stack (D-576). `attome-portal`'s own tests prove the guard logic and the
//! provisioning functions; this file proves the claims that only hold if the
//! real routes actually invoke them:
//!
//! 1. Generic record CRUD (create, update, upsert) and the state-transition
//!    route refuse every protected portal field. The claim is not "the
//!    validator works" but "every generic mutation path reaches it".
//! 2. Ordinary profile edits still go through generic CRUD, and the portal
//!    admin API still works.
//! 3. The credential table is unreachable: it is not an entity, so generic
//!    CRUD, export and `query/execute` cannot name it; stored-query publishing
//!    refuses SQL that reads it; record reads and search never return its data.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"; $env:TEST_REDIS_HOST = "127.0.0.1"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<migrated template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p server --test portal_boundary -- --test-threads=1
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

use std::net::SocketAddr;

use attome::auth;
use attome_api::EngineSystem;
use attome_audit::security::SecurityAuditor;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ORIGIN: &str = "http://allowed.test";
/// The refusal message `attome_portal::guard` returns; asserting on it proves the
/// 422 came from the portal guard, not from some unrelated validation.
const GUARD_MESSAGE: &str = "web portal admin API";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 65536, "request_timeout_secs": 30,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 10, "timeout": 5.0
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
            "rate_limit": {{ "anonymous_rpm": 100000, "authenticated_rpm": 100000 }},
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
            "s2s": {{ "enabled": false, "key_encryption_key": "{s2s_key}" }},
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["{origin}"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        s2s_key = "cd".repeat(32),
        origin = ORIGIN,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

fn full_license() -> std::sync::Arc<attome_modules::ModuleSet> {
    std::sync::Arc::new(attome_modules::ModuleSet::from_bits([u64::MAX; 4]))
}

struct Fx {
    app: axum::Router,
    base: AppState,
    admin_token: String,
}

async fn fixture() -> Option<Fx> {
    let mut config = test_config();
    let throwaway_url = attome_testkit::migrated_db_url()?;
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
        config.clone(),
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    // The same model set `boot.rs` registers for the routes exercised here:
    // portal admin, state transitions, and search.
    let system = EngineSystem::builder(EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        .register(attome_portal::PortalModel)
        .register(attome_state::StateModel)
        .register(attome_search::SearchModel)
        .build()
        .await
        .expect("build EngineSystem");
    system.state().modules.store(full_license());

    let xrm = system.state().clone();
    let base_state = xrm.base.clone();
    let license = xrm.modules.clone();
    let public_bundle = attome_server::RouteBundle::new(
        auth::public_routes(license, SecurityAuditor::from_state(&xrm))
            .with_state(base_state.clone()),
    );
    let protected_bundle = attome_server::RouteBundle::new(
        auth::protected_routes(SecurityAuditor::from_state(&xrm)).with_state(base_state.clone()),
    );
    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(public_bundle)
        .add_bundle(protected_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    let admin_id = seed_admin(&base_state).await;
    let admin_token = session_token(&base_state, admin_id).await;
    Some(Fx {
        app,
        base: base_state,
        admin_token,
    })
}

async fn seed_admin(state: &AppState) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, email_verified) \
         VALUES ($1, $2, $3, true, true)",
    )
    .bind(user_id)
    .bind(format!("portal-boundary-{user_id}"))
    .bind(format!("portal-boundary-{user_id}@example.test"))
    .execute(&state.db)
    .await
    .expect("insert admin");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(&state.db)
            .await
            .expect("system.admin is seeded by attome_security::seed");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(&state.db)
    .await
    .expect("grant system.admin");
    user_id
}

async fn session_token(state: &AppState, user_id: Uuid) -> String {
    let issued = attome_auth::refresh::issue(
        &state.db,
        user_id,
        &attome_auth::auth_context::AuthContext::password(),
        attome_auth::refresh::RefreshLifetimes {
            idle_secs: state.config.refresh_token_expiry_secs(),
            absolute_secs: state.config.refresh_absolute_lifetime_secs(),
        },
        &state.pepper_ring(),
    )
    .await
    .expect("issue a refresh family");
    attome_auth::accounts::issue_access_token(
        &state.db,
        user_id,
        issued.family_id,
        &KeyRing::single(THROWAWAY_JWT_SECRET.to_string()),
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        3600,
    )
    .await
    .expect("issue a session token")
}

fn request(method: &str, uri: &str, token: &str, body: Option<Value>) -> Request<Body> {
    request_if_match(method, uri, token, body, None)
}

fn request_if_match(
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
    if_match: Option<i64>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", ORIGIN)
        .header(header::COOKIE, format!("__Host-session_token={token}"));
    if let Some(version) = if_match {
        builder = builder.header(header::IF_MATCH, version.to_string());
    }
    let mut req = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("build request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 9], 40_009))));
    req
}

/// Sends a request as the administrator and returns status and body text.
async fn send(fx: &Fx, method: &str, uri: &str, body: Option<Value>) -> (StatusCode, String) {
    send_req(fx, request(method, uri, &fx.admin_token, body)).await
}

/// A generic-CRUD `PATCH` as the administrator, carrying the mandatory
/// `If-Match` row version (D-079).
async fn patch(fx: &Fx, uri: &str, row_version: i64, body: Value) -> (StatusCode, String) {
    send_req(
        fx,
        request_if_match("PATCH", uri, &fx.admin_token, Some(body), Some(row_version)),
    )
    .await
}

async fn send_req(fx: &Fx, req: Request<Body>) -> (StatusCode, String) {
    let res = fx.app.clone().oneshot(req).await.expect("send");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn ok_json(fx: &Fx, method: &str, uri: &str, body: Option<Value>) -> Value {
    let (status, text) = send(fx, method, uri, body).await;
    assert!(status.is_success(), "{method} {uri}: {status} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

/// Asserts a 422 raised by the portal guard itself.
fn assert_guarded(what: &str, status: StatusCode, text: &str) {
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{what}: expected the portal guard's 422, got {status} {text}"
    );
    assert!(
        text.contains(GUARD_MESSAGE),
        "{what}: 422 did not come from the portal guard: {text}"
    );
}

fn id_of(v: &Value) -> Uuid {
    v["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("response has no id: {v}"))
}

fn keyword() -> String {
    format!("pb-{}", &Uuid::now_v7().simple().to_string()[20..])
}

async fn admin_portal(fx: &Fx) -> Value {
    ok_json(
        fx,
        "POST",
        "/api/v1/admin/webportals",
        Some(json!({
            "name": format!("Customers {}", keyword()),
            "keyword": keyword(),
            "portal_type": "authenticated",
        })),
    )
    .await
}

async fn admin_user(fx: &Fx, portal: Uuid) -> Value {
    ok_json(
        fx,
        "POST",
        &format!("/api/v1/admin/webportals/{portal}/users"),
        Some(json!({"name": "Ada", "email": format!("{}@example.com", keyword())})),
    )
    .await
}

async fn team_id(fx: &Fx) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(format!("portal-boundary-team-{id}"))
        .execute(&fx.base.db)
        .await
        .expect("insert team");
    id
}

async fn count_named(fx: &Fx, table: &str, name: &str) -> i64 {
    sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE name = $1"))
        .bind(name)
        .fetch_one(&fx.base.db)
        .await
        .unwrap()
}

/// Generic create: every body below is otherwise valid (all required fields
/// present, lookups real), so the only thing that can refuse it is the portal
/// guard. Required-field validation runs before the record validators, and
/// both protected entities have required protected fields, which is why a
/// partial body is not a useful probe.
#[tokio::test]
async fn generic_create_refuses_every_protected_field() {
    let fx = skip_if_no_db!(fixture().await);
    let team = team_id(&fx).await;
    let portal = id_of(&admin_portal(&fx).await);

    for (label, extra) in [
        ("keyword+portal_type", json!({})),
        ("is_enabled", json!({"is_enabled": true})),
        ("owning_team_ref", json!({"owning_team_ref": team})),
    ] {
        let name = format!("sneaky-{}", keyword());
        let mut body = json!({"name": name, "keyword": keyword(), "portal_type": "authenticated"});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let (status, text) = send(&fx, "POST", "/api/v1/webportal", Some(body)).await;
        assert_guarded(&format!("create webportal ({label})"), status, &text);
        assert_eq!(count_named(&fx, "webportal", &name).await, 0);
    }

    let name = format!("sneaky-{}", keyword());
    let (status, text) = send(
        &fx,
        "POST",
        "/api/v1/webportal_user",
        Some(json!({
            "name": name,
            "email": "sneaky@example.com",
            "webportal_ref": portal,
            "status": "active",
        })),
    )
    .await;
    assert_guarded("create webportal_user", status, &text);
    assert_eq!(count_named(&fx, "webportal_user", &name).await, 0);
}

/// Generic update: one protected field per request, each with the correct
/// `If-Match`, so nothing but the guard can refuse it.
#[tokio::test]
async fn generic_update_refuses_protected_fields_but_allows_profile_edits() {
    let fx = skip_if_no_db!(fixture().await);
    let team = team_id(&fx).await;
    let portal = admin_portal(&fx).await;
    let portal_id = id_of(&portal);
    let portal_version = portal["row_version"].as_i64().unwrap();
    let other_portal = id_of(&admin_portal(&fx).await);
    let user = admin_user(&fx, portal_id).await;
    let user_id = id_of(&user);
    let user_version = user["row_version"].as_i64().unwrap();

    for (field, value) in [
        ("keyword", json!(keyword())),
        ("portal_type", json!("anonymous")),
        ("is_enabled", json!(true)),
        ("owning_team_ref", json!(team)),
    ] {
        let (status, text) = patch(
            &fx,
            &format!("/api/v1/webportal/{portal_id}"),
            portal_version,
            json!({ field: value }),
        )
        .await;
        assert_guarded(&format!("update webportal.{field}"), status, &text);
    }
    for (field, value) in [
        ("webportal_ref", json!(other_portal)),
        ("email", json!("moved@example.com")),
        ("status", json!("active")),
    ] {
        let (status, text) = patch(
            &fx,
            &format!("/api/v1/webportal_user/{user_id}"),
            user_version,
            json!({ field: value }),
        )
        .await;
        assert_guarded(&format!("update webportal_user.{field}"), status, &text);
    }

    // Nothing moved.
    let (kw, enabled, version): (String, Option<bool>, i64) =
        sqlx::query_as("SELECT keyword, is_enabled, row_version FROM webportal WHERE id = $1")
            .bind(portal_id)
            .fetch_one(&fx.base.db)
            .await
            .unwrap();
    assert_eq!(kw, portal["keyword"].as_str().unwrap());
    assert_eq!(enabled, Some(false));
    assert_eq!(version, portal_version);
    let (ref_, status): (Option<Uuid>, String) =
        sqlx::query_as("SELECT webportal_ref, status FROM webportal_user WHERE id = $1")
            .bind(user_id)
            .fetch_one(&fx.base.db)
            .await
            .unwrap();
    assert_eq!(ref_, Some(portal_id));
    assert_eq!(status, "invited");

    // Profile fields still edit through generic CRUD.
    let (status, text) = patch(
        &fx,
        &format!("/api/v1/webportal/{portal_id}"),
        portal_version,
        json!({"name": "Renamed", "description": "Customer self-service"}),
    )
    .await;
    assert!(status.is_success(), "portal profile edit: {status} {text}");
    let (status, text) = patch(
        &fx,
        &format!("/api/v1/webportal_user/{user_id}"),
        user_version,
        json!({"name": "Grace"}),
    )
    .await;
    assert!(status.is_success(), "user profile edit: {status} {text}");
}

/// Upsert reaches both `create_one` (no match) and `update_one` (match); the
/// guard must fire on each.
#[tokio::test]
async fn upsert_refuses_protected_fields_on_create_and_update() {
    let fx = skip_if_no_db!(fixture().await);

    let name = format!("upsert-{}", keyword());
    let (status, text) = send(
        &fx,
        "POST",
        "/api/v1/webportal/upsert",
        Some(json!({
            "match": {"name": name},
            "data": {"keyword": keyword(), "portal_type": "authenticated"},
        })),
    )
    .await;
    assert_guarded("upsert (create branch)", status, &text);
    assert_eq!(count_named(&fx, "webportal", &name).await, 0);

    let portal = admin_portal(&fx).await;
    let (status, text) = send(
        &fx,
        "POST",
        "/api/v1/webportal/upsert",
        Some(json!({
            "match": {"name": portal["name"]},
            // Upsert validates match + data as a complete record before it
            // branches (upsert.rs), so required fields are sent even for an
            // update; the match names an existing record and row_version is
            // current, so this takes the update_one branch.
            "data": {"keyword": keyword(), "portal_type": "mixed"},
            "row_version": portal["row_version"],
        })),
    )
    .await;
    assert_guarded("upsert (update branch)", status, &text);
    let (kw, portal_type): (String, String) =
        sqlx::query_as("SELECT keyword, portal_type FROM webportal WHERE id = $1")
            .bind(id_of(&portal))
            .fetch_one(&fx.base.db)
            .await
            .unwrap();
    assert_eq!(kw, portal["keyword"].as_str().unwrap());
    assert_eq!(portal_type, "authenticated");
}

#[tokio::test]
async fn a_state_model_over_a_protected_field_cannot_bypass_the_guard() {
    let fx = skip_if_no_db!(fixture().await);
    let portal = id_of(&admin_portal(&fx).await);
    let user = id_of(&admin_user(&fx, portal).await);

    // An administrator puts a state model on `status`, with a path back to
    // `active` from `disabled`.
    let model = ok_json(
        &fx,
        "POST",
        "/api/v1/admin/state-models",
        Some(json!({
            "entity_logicalname": "webportal_user",
            "name": "Portal user lifecycle",
            "state_field": "status",
            "initial_state": "invited",
        })),
    )
    .await;
    ok_json(
        &fx,
        "POST",
        &format!("/api/v1/admin/state-models/{}/transitions", id_of(&model)),
        Some(json!({"from_state": "disabled", "to_state": "active", "name": "Reactivate"})),
    )
    .await;

    // The portal admin API disables the user (and ends their sessions).
    ok_json(
        &fx,
        "POST",
        &format!("/api/v1/admin/webportals/{portal}/users/{user}/disable"),
        None,
    )
    .await;

    // The transition route must not re-enable them around the admin API.
    let (status, text) = send(
        &fx,
        "POST",
        &format!("/api/v1/webportal_user/{user}/transition"),
        Some(json!({"to_state": "active"})),
    )
    .await;
    assert_guarded("transition webportal_user.status", status, &text);
    let status: String = sqlx::query_scalar("SELECT status FROM webportal_user WHERE id = $1")
        .bind(user)
        .fetch_one(&fx.base.db)
        .await
        .unwrap();
    assert_eq!(status, "disabled");
}

#[tokio::test]
async fn the_admin_api_still_drives_every_protected_field() {
    let fx = skip_if_no_db!(fixture().await);
    let team = team_id(&fx).await;
    let portal = admin_portal(&fx).await;
    let portal_id = id_of(&portal);
    let kw = keyword();

    let updated = ok_json(
        &fx,
        "PATCH",
        &format!("/api/v1/admin/webportals/{portal_id}/settings"),
        Some(json!({
            "row_version": portal["row_version"],
            "keyword": kw,
            "portal_type": "mixed",
            "is_enabled": true,
            "owning_team_ref": team,
        })),
    )
    .await;
    assert_eq!(updated["keyword"], kw);
    assert_eq!(updated["portal_type"], "mixed");
    assert_eq!(updated["is_enabled"], true);
    assert_eq!(updated["owning_team_ref"], json!(team));

    let user = id_of(&admin_user(&fx, portal_id).await);
    let disabled = ok_json(
        &fx,
        "POST",
        &format!("/api/v1/admin/webportals/{portal_id}/users/{user}/disable"),
        None,
    )
    .await;
    assert_eq!(disabled["status"], "disabled");
    let (status, _) = send(
        &fx,
        "DELETE",
        &format!("/api/v1/admin/webportals/{portal_id}/users/{user}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn credential_data_is_unreachable_through_every_generic_surface() {
    let fx = skip_if_no_db!(fixture().await);
    let portal = id_of(&admin_portal(&fx).await);
    let user = id_of(&admin_user(&fx, portal).await);
    // A marker where a hash would be, so any leak is detectable by value.
    let marker = format!("pbmarker{}", Uuid::now_v7().simple());
    sqlx::query("UPDATE webportal_credential SET password_hash = $2 WHERE webportal_user_id = $1")
        .bind(user)
        .bind(&marker)
        .execute(&fx.base.db)
        .await
        .unwrap();

    // Not an entity: every surface that resolves entities through the
    // metadata registry refuses it outright.
    let registered: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM entity_info WHERE logicalname = 'webportal_credential')",
    )
    .fetch_one(&fx.base.db)
    .await
    .unwrap();
    assert!(
        !registered,
        "the credential table must never be a metadata entity"
    );
    for (method, uri, body) in [
        ("GET", "/api/v1/webportal_credential".to_owned(), None),
        ("GET", format!("/api/v1/webportal_credential/{user}"), None),
        (
            "POST",
            "/api/v1/webportal_credential".to_owned(),
            Some(json!({"password_hash": "x"})),
        ),
        (
            "POST",
            "/api/v1/webportal_credential/export".to_owned(),
            Some(json!({})),
        ),
        (
            "POST",
            "/api/v1/query/execute".to_owned(),
            Some(json!({"entity": "webportal_credential"})),
        ),
    ] {
        let (status, text) = send(&fx, method, &uri, body).await;
        assert!(
            !status.is_success(),
            "{method} {uri} must be refused, got {status} {text}"
        );
        assert!(
            !text.contains(&marker),
            "{method} {uri} leaked the credential: {text}"
        );
    }

    // Stored-query publishing refuses SQL that reads the table.
    let (status, text) = send(
        &fx,
        "POST",
        "/api/v1/admin/queries",
        Some(json!({"sql_query": "SELECT webportal_user_id AS id, password_hash FROM webportal_credential"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
    assert!(text.contains("not a registered entity table"), "{text}");

    // The profile record never carries credential columns.
    let record = ok_json(&fx, "GET", &format!("/api/v1/webportal_user/{user}"), None).await;
    let text = record.to_string();
    for forbidden in [
        "password",
        "auth_epoch",
        "failed_login",
        "locked_until",
        &marker,
    ] {
        assert!(
            !text.contains(forbidden),
            "user record exposes {forbidden}: {text}"
        );
    }

    // Search indexes registered entities only; the marker never surfaces.
    let (status, text) = send(&fx, "GET", &format!("/api/v1/search?q={marker}"), None).await;
    assert!(status.is_success(), "search: {status} {text}");
    assert!(
        !text.contains(&marker),
        "search leaked the credential: {text}"
    );
}

//! Solution 7 Phase 1 (D-785), lane L5 — the engine admin routes record
//! changeset operations (design `document/general/SOLUTION-7-PHASE-1-DESIGN.md`
//! §1.1, §4.1–§4.5): security admin (roles, grants, grant conditions, role
//! entity access, bulk fields, entity default shares, field-security
//! profiles), state models and transitions, workflow definitions / versions /
//! publish, and stored queries.
//!
//! Proves, over HTTP against a real database:
//!
//! 1. **auto mode**: each hooked route yields exactly one operation (the
//!    role-grant route yields `ensure_privilege` + `grant_role_privilege` when
//!    it mints the privilege), with the expected op name and route, in an
//!    automatic changeset; new rows carry `owner_layer = 'project'`;
//! 2. **required mode**: a write with no open changeset is refused with 409
//!    `changeset_required` and writes nothing; with one open changeset the
//!    write is recorded into it;
//! 3. **layer rule**: updating, retiring or removing a row owned by another
//!    layer is refused with 409 `layer_mismatch` and records nothing.
//!
//! Case definitions (`attome-process`) are hooked too but not driven here:
//! `attome-process` is not a dev-dependency of `attome-api` (adding it is a
//! `Cargo.toml` change outside lane L5); `case_def_admin.rs`'s unit tests
//! cover their op shape.
//!
//! Needs a test database migrated through 0522 (`changeset_*`,
//! `owner_layer`). When the template predates it the tests say so and skip —
//! build a private template (see the `testing` skill); never migrate the
//! shared one.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test changeset_hooks_engines -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test inspects and seeds state on a raw pool; production code uses \
              attome_db::tx::begin"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::changeset::store::{self, NewChangeset};
use attome_core::changeset::{CHANGESET_HEADER, Layer};
use attome_core::{EngineState, build_registry};
use attome_server::AppState;
use attome_testkit::{point_config_at, skip_if_no_db};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config(mode: &str) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 15,
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
            "approval": {{ "required_actions": [] }},
            "metadata": {{ "changesets": {{ "mode": "{mode}" }} }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_system(mode: &str) -> Option<(EngineState, axum::Router)> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let mut config = test_config(mode);
    point_config_at(&mut config, &throwaway_url);
    let db = attome_db::create_pool(&config)
        .await
        .expect("connect DATABASE_URL");
    let present: bool = sqlx::query_scalar("SELECT to_regclass('changeset_operation') IS NOT NULL")
        .fetch_one(&db)
        .await
        .expect("probe for the changeset store");
    if !present {
        eprintln!(
            "the test database predates migration 0521 (no changeset_operation); \
             skipping — build a private template migrated through 0522"
        );
        return None;
    }
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
        .register(attome_state::StateModel)
        .register(attome_workflow::WorkflowModel)
        .build()
        .await
        .expect("build EngineSystem");
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    let state = system.state().clone();
    let base_state = state.base.clone();
    let app = attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    Some((state, app))
}

/// The `auto`-mode and `required`-mode systems every test shares (one
/// database; each test uses its own admin, so operations are counted per
/// actor without cross-test coupling).
#[derive(Clone)]
struct Fx {
    auto_state: EngineState,
    auto: axum::Router,
    required: axum::Router,
}

static SHARED: tokio::sync::OnceCell<Option<Fx>> = tokio::sync::OnceCell::const_new();

async fn fixture() -> Option<Fx> {
    SHARED
        .get_or_init(|| async {
            let (auto_state, auto) = build_system("auto").await?;
            let (_, required) = build_system("required").await?;
            Some(Fx {
                auto_state,
                auto,
                required,
            })
        })
        .await
        .clone()
}

impl Fx {
    fn db(&self) -> &attome_db::DbPool {
        &self.auto_state.base.db
    }
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
    let ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// An admin.
struct Admin {
    id: Uuid,
    email: String,
    cookie: String,
}

async fn seed_admin(db: &attome_db::DbPool) -> Admin {
    let id = Uuid::now_v7();
    let email = format!("cs-hooks-{}@test.local", id.simple());
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("cs-hooks-{id}"))
    .bind(&email)
    .execute(db)
    .await
    .expect("insert throwaway admin");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin is seeded by attome_security::seed");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant system.admin");
    Admin {
        id,
        email,
        cookie: session_cookie(id),
    }
}

fn suffix() -> String {
    let hex = Uuid::now_v7().simple().to_string();
    hex[hex.len() - 10..].to_owned()
}

async fn send(
    app: &axum::Router,
    admin: &Admin,
    method: &str,
    uri: &str,
    body: Option<Value>,
    changeset: Option<Uuid>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", &admin.cookie)
        .header("content-type", "application/json")
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(id) = changeset {
        builder = builder.header(CHANGESET_HEADER, id.to_string());
    }
    let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
    let resp = app
        .clone()
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("router");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.expect("body");
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn id_of(v: &Value) -> Uuid {
    v["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("response has no id: {v}"))
}

/// Every operation `actor` recorded, in recording order: (op, route,
/// target, changeset origin).
async fn ops_by(db: &attome_db::DbPool, actor: Uuid) -> Vec<(String, String, Value, String)> {
    sqlx::query_as(
        "SELECT o.op, o.route, o.target, c.origin \
         FROM changeset_operation o \
         JOIN changeset c ON c.id = o.changeset_ref \
         WHERE o.actor_ref = $1 ORDER BY o.recorded_at, o.seq",
    )
    .bind(actor)
    .fetch_all(db)
    .await
    .expect("read recorded operations")
}

/// Drives one hooked route in auto mode and asserts it succeeded and
/// recorded exactly `expected` (op names, in order) in one automatic
/// changeset, with this request's route.
#[allow(clippy::too_many_arguments)]
async fn expect_ops(
    fx: &Fx,
    admin: &Admin,
    method: &str,
    uri: &str,
    route: &str,
    body: Option<Value>,
    expected: &[&str],
) -> Value {
    let before = ops_by(fx.db(), admin.id).await.len();
    let (status, json) = send(&fx.auto, admin, method, uri, body, None).await;
    assert!(
        status.is_success(),
        "{method} {uri}: expected success, got {status}: {json}"
    );
    let ops = ops_by(fx.db(), admin.id).await;
    let new = &ops[before..];
    let names: Vec<&str> = new.iter().map(|(op, ..)| op.as_str()).collect();
    assert_eq!(names, expected, "{method} {uri}: recorded operations");
    for (op, recorded_route, target, origin) in new {
        assert_eq!(recorded_route, route, "{op}: route");
        assert_eq!(
            origin, "auto",
            "{op}: an auto-mode write records an automatic changeset"
        );
        assert!(target.is_object(), "{op}: target {target}");
    }
    json
}

fn conflict_code(json: &Value) -> String {
    let message = json["message"].as_str().unwrap_or_default();
    message
        .trim_start_matches("conflict: ")
        .split(':')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// A throwaway entity with a filterable `title` text field and a `status`
/// choice field, registered in the auto system's
/// metadata registry (grant conditions read it).
async fn seed_entity(fx: &Fx) -> String {
    let db = fx.db();
    let logicalname = format!("cs_hook_{}", suffix());
    let entity_id =
        attome_metadata::provision::ensure_entity(db, &logicalname, "Changeset Hooks", None, false)
            .await
            .expect("ensure_entity");
    attome_metadata::provision::ensure_attribute(
        db, entity_id, "title", "Title", "text", false, false, true, true, None, None,
    )
    .await
    .expect("ensure_attribute title");
    attome_metadata::provision::ensure_attribute(
        db, entity_id, "status", "Status", "choice", false, false, true, true, None,
        // No configured choices: a state model's transitions are then
        // unconstrained (the "no options set is a no-op" rule).
        None,
    )
    .await
    .expect("ensure_attribute status");
    let registry = build_registry(db).await.expect("build_registry");
    fx.auto_state.entities.swap(registry);
    logicalname
}

async fn create_role(fx: &Fx, admin: &Admin) -> (Uuid, String) {
    let name = format!("CS Hook Role {}", suffix());
    let json = expect_ops(
        fx,
        admin,
        "POST",
        "/api/v1/admin/security/roles",
        "POST /api/v1/admin/security/roles",
        Some(json!({ "name": name })),
        &["upsert_role"],
    )
    .await;
    assert_eq!(json["owner_layer"], "project");
    (id_of(&json), name)
}

async fn set_owner_layer(db: &attome_db::DbPool, table: &str, id: Uuid, layer: Layer) {
    // Test-only: `table` is a code literal from this file.
    sqlx::query(&format!(
        "UPDATE {table} SET owner_layer = $2 WHERE id = $1"
    ))
    .bind(id)
    .bind(layer.as_str())
    .execute(db)
    .await
    .expect("restamp owner_layer");
}

// ── 1. auto mode: exactly one operation per hooked route ───────────────────

#[test]
fn security_routes_record_one_operation_each() {
    attome_testkit::run_shared(async {
        let fx = skip_if_no_db!(fixture().await);
        let admin = seed_admin(fx.db()).await;
        let entity = seed_entity(&fx).await;
        let (role_id, _) = create_role(&fx, &admin).await;

        expect_ops(
            &fx,
            &admin,
            "PATCH",
            &format!("/api/v1/admin/security/roles/{role_id}"),
            "PATCH /api/v1/admin/security/roles/{id}",
            Some(json!({ "description": "changed" })),
            &["upsert_role"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "PUT",
            &format!("/api/v1/admin/security/roles/{role_id}/position-hierarchy"),
            "PUT /api/v1/admin/security/roles/{id}/position-hierarchy",
            Some(json!({ "position_hierarchy_enabled": true })),
            &["upsert_role"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "PUT",
            &format!("/api/v1/admin/security/roles/{role_id}/bulk-fields"),
            "PUT /api/v1/admin/security/roles/{id}/bulk-fields",
            Some(json!({ "mode": "listed", "fields": [] })),
            &["set_role_bulk_fields"],
        )
        .await;

        // A new privilege key: minted and granted in one request.
        let minted = format!("cs_hook_{}.approve", suffix());
        let grant = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/security/role-grants",
            "POST /api/v1/admin/security/role-grants",
            Some(json!({ "role_id": role_id, "privilege_key": minted })),
            &["ensure_privilege", "grant_role_privilege"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!("/api/v1/admin/security/role-grants/{}", id_of(&grant)),
            "DELETE /api/v1/admin/security/role-grants/{id}",
            None,
            &["revoke_role_privilege"],
        )
        .await;

        // An existing privilege: one grant operation.
        let read_key = format!("{entity}.read");
        attome_security::db::ensure_privilege(
            fx.db(),
            &read_key,
            &read_key,
            "test",
            Layer::Project,
        )
        .await
        .expect("ensure the entity's read privilege");
        let grant = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/security/role-grants",
            "POST /api/v1/admin/security/role-grants",
            Some(json!({ "role_id": role_id, "privilege_key": read_key })),
            &["grant_role_privilege"],
        )
        .await;
        let grant_id = id_of(&grant);
        let condition = expect_ops(
            &fx,
            &admin,
            "POST",
            &format!("/api/v1/admin/security/role-grants/{grant_id}/conditions"),
            "POST /api/v1/admin/security/role-grants/{grant_id}/conditions",
            Some(json!({ "field_logicalname": "title", "operator": 0, "value": "x" })),
            &["add_role_grant_condition"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!(
                "/api/v1/admin/security/role-grants/{grant_id}/conditions/{}",
                id_of(&condition)
            ),
            "DELETE /api/v1/admin/security/role-grants/{grant_id}/conditions/{condition_id}",
            None,
            &["remove_role_grant_condition"],
        )
        .await;

        let access = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/security/role-entity-access",
            "POST /api/v1/admin/security/role-entity-access",
            Some(json!({ "role_id": role_id, "entity": entity, "read_access_level": 1 })),
            &["set_role_entity_access"],
        )
        .await;
        assert_eq!(access["owner_layer"], "project");
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!(
                "/api/v1/admin/security/role-entity-access/{}",
                id_of(&access)
            ),
            "DELETE /api/v1/admin/security/role-entity-access/{id}",
            None,
            &["clear_role_entity_access"],
        )
        .await;

        let share = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/security/entity-default-shares",
            "POST /api/v1/admin/security/entity-default-shares",
            Some(json!({ "entity": entity, "capability": "view", "user_email": admin.email })),
            &["set_entity_default_share"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!(
                "/api/v1/admin/security/entity-default-shares/{}",
                id_of(&share)
            ),
            "DELETE /api/v1/admin/security/entity-default-shares/{id}",
            None,
            &["remove_entity_default_share"],
        )
        .await;

        let profile = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/security/field-profiles",
            "POST /api/v1/admin/security/field-profiles",
            Some(json!({ "name": format!("CS Hook Profile {}", suffix()) })),
            &["upsert_field_profile"],
        )
        .await;
        let profile_id = id_of(&profile);
        expect_ops(
            &fx,
            &admin,
            "POST",
            &format!("/api/v1/admin/security/field-profiles/{profile_id}/fields"),
            "POST /api/v1/admin/security/field-profiles/{id}/fields",
            Some(json!({ "entity_logicalname": entity, "field_logicalname": "title", "can_read": true })),
            &["set_field_profile_field"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "POST",
            &format!("/api/v1/admin/security/field-profiles/{profile_id}/assignments"),
            "POST /api/v1/admin/security/field-profiles/{id}/assignments",
            Some(json!({ "role_id": role_id })),
            &["assign_field_profile"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!("/api/v1/admin/security/field-profiles/{profile_id}/assignments/{role_id}"),
            "DELETE /api/v1/admin/security/field-profiles/{id}/assignments/{role_id}",
            None,
            &["unassign_field_profile"],
        )
        .await;

        // The share's logical key names no UUID (design §3; the lane's
        // natural-key choice for `entity_default_share`).
        let ops = ops_by(fx.db(), admin.id).await;
        let share_target = ops
            .iter()
            .find(|(op, ..)| op == "set_entity_default_share")
            .map(|(_, _, target, _)| target.clone())
            .expect("share op");
        assert_eq!(
            share_target,
            json!({ "entity": entity, "share": format!("user:{}:read", admin.email) })
        );
    });
}

#[test]
fn state_workflow_and_query_routes_record_one_operation_each() {
    attome_testkit::run_shared(async {
        let fx = skip_if_no_db!(fixture().await);
        let admin = seed_admin(fx.db()).await;
        let entity = seed_entity(&fx).await;

        // State models and transitions.
        let model = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/state-models",
            "POST /api/v1/admin/state-models",
            Some(json!({
                "entity_logicalname": entity, "name": "Lifecycle",
                "state_field": "status", "initial_state": "new",
            })),
            &["upsert_state_model"],
        )
        .await;
        let model_id = id_of(&model);
        let model = expect_ops(
            &fx,
            &admin,
            "PATCH",
            &format!("/api/v1/admin/state-models/{model_id}"),
            "PATCH /api/v1/admin/state-models/{id}",
            Some(json!({
                "name": "Lifecycle 2", "state_field": "status", "initial_state": "new",
                "is_active": true, "row_version": model["row_version"],
            })),
            &["upsert_state_model"],
        )
        .await;
        assert_eq!(model["owner_layer"], "project");
        let transition = expect_ops(
            &fx,
            &admin,
            "POST",
            &format!("/api/v1/admin/state-models/{model_id}/transitions"),
            "POST /api/v1/admin/state-models/{id}/transitions",
            Some(json!({ "from_state": "new", "to_state": "open", "name": "Open" })),
            &["upsert_state_transition"],
        )
        .await;
        let transition_id = id_of(&transition);
        expect_ops(
            &fx,
            &admin,
            "PATCH",
            &format!("/api/v1/admin/state-models/{model_id}/transitions/{transition_id}"),
            "PATCH /api/v1/admin/state-models/{id}/transitions/{transition_id}",
            Some(json!({ "name": "Open it", "row_version": transition["row_version"] })),
            &["upsert_state_transition"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!("/api/v1/admin/state-models/{model_id}/transitions/{transition_id}"),
            "DELETE /api/v1/admin/state-models/{id}/transitions/{transition_id}",
            None,
            &["retire_state_transition"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!("/api/v1/admin/state-models/{model_id}"),
            "DELETE /api/v1/admin/state-models/{id}",
            None,
            &["retire_state_model"],
        )
        .await;

        // Workflow definitions, versions and publish.
        let logicalname = format!("cs_hook_wf_{}", suffix());
        let definition = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/workflow/definitions",
            "POST /api/v1/workflow/definitions",
            Some(json!({ "logicalname": logicalname, "name": "Hooked" })),
            &["upsert_workflow"],
        )
        .await;
        let definition_id = id_of(&definition);
        expect_ops(
            &fx,
            &admin,
            "PATCH",
            &format!("/api/v1/workflow/definitions/{definition_id}"),
            "PATCH /api/v1/workflow/definitions/{id}",
            Some(json!({ "name": "Hooked 2", "row_version": definition["row_version"] })),
            &["upsert_workflow"],
        )
        .await;
        let trigger_only = json!({
            "nodes": [{ "id": "t", "type": "trigger", "config": { "trigger_type": "manual" } }],
            "edges": [],
        });
        let version = expect_ops(
            &fx,
            &admin,
            "POST",
            &format!("/api/v1/workflow/definitions/{definition_id}/versions"),
            "POST /api/v1/workflow/definitions/{id}/versions",
            Some(json!({ "graph": trigger_only })),
            &["set_workflow_draft"],
        )
        .await;
        let version_id = id_of(&version);
        expect_ops(
            &fx,
            &admin,
            "PATCH",
            &format!("/api/v1/workflow/definitions/{definition_id}/versions/{version_id}"),
            "PATCH /api/v1/workflow/definitions/{id}/versions/{version_id}",
            Some(json!({ "graph": trigger_only, "row_version": version["row_version"] })),
            &["set_workflow_draft"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "POST",
            &format!("/api/v1/workflow/definitions/{definition_id}/versions/{version_id}/publish"),
            "POST /api/v1/workflow/definitions/{id}/versions/{version_id}/publish",
            None,
            &["publish_workflow"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!("/api/v1/workflow/definitions/{definition_id}"),
            "DELETE /api/v1/workflow/definitions/{id}",
            None,
            &["retire_workflow"],
        )
        .await;

        // Stored queries (a named multi-entity query).
        let name = format!("cs_hook_query_{}", suffix());
        let query = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/queries",
            "POST /api/v1/admin/queries",
            Some(json!({ "name": name, "sql_query": "SELECT 1 AS id" })),
            &["upsert_query"],
        )
        .await;
        let query_id = id_of(&query);
        expect_ops(
            &fx,
            &admin,
            "PATCH",
            &format!("/api/v1/admin/queries/{query_id}"),
            "PATCH /api/v1/admin/queries/{id}",
            Some(json!({ "sql_query": "SELECT 2 AS id" })),
            &["upsert_query"],
        )
        .await;
        expect_ops(
            &fx,
            &admin,
            "DELETE",
            &format!("/api/v1/admin/queries/{query_id}"),
            "DELETE /api/v1/admin/queries/{id}",
            None,
            &["retire_query"],
        )
        .await;

        let ops = ops_by(fx.db(), admin.id).await;
        let transition_target = ops
            .iter()
            .find(|(op, ..)| op == "upsert_state_transition")
            .map(|(_, _, target, _)| target.clone())
            .expect("transition op");
        assert_eq!(
            transition_target,
            json!({ "entity": entity, "transition": "new->open" })
        );
        let workflow_target = ops
            .iter()
            .find(|(op, ..)| op == "publish_workflow")
            .map(|(_, _, target, _)| target.clone())
            .expect("publish op");
        assert_eq!(workflow_target, json!({ "workflow": logicalname }));
        // Every operation of one request shares one automatic changeset; no
        // request spilled into another's.
        let changesets: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT changeset_ref) FROM changeset_operation \
             WHERE actor_ref = $1",
        )
        .bind(admin.id)
        .fetch_one(fx.db())
        .await
        .expect("count changesets");
        assert_eq!(
            changesets as usize,
            ops.len(),
            "one automatic changeset per request"
        );
    });
}

// ── 2. required mode ───────────────────────────────────────────────────────

#[test]
fn required_mode_refuses_a_write_with_no_open_changeset() {
    attome_testkit::run_shared(async {
        let fx = skip_if_no_db!(fixture().await);
        let admin = seed_admin(fx.db()).await;
        let entity = seed_entity(&fx).await;
        let role_name = format!("CS Refused Role {}", suffix());

        for (method, uri, body) in [
            (
                "POST",
                "/api/v1/admin/security/roles".to_owned(),
                json!({ "name": role_name }),
            ),
            (
                "POST",
                "/api/v1/admin/security/field-profiles".to_owned(),
                json!({ "name": format!("CS Refused Profile {}", suffix()) }),
            ),
            (
                "POST",
                "/api/v1/admin/state-models".to_owned(),
                json!({
                    "entity_logicalname": entity, "name": "Refused",
                    "state_field": "status", "initial_state": "new",
                }),
            ),
            (
                "POST",
                "/api/v1/workflow/definitions".to_owned(),
                json!({ "logicalname": format!("cs_refused_{}", suffix()), "name": "Refused" }),
            ),
            (
                "POST",
                "/api/v1/admin/queries".to_owned(),
                json!({ "name": format!("cs_refused_{}", suffix()), "sql_query": "SELECT 1 AS id" }),
            ),
        ] {
            let (status, json) = send(&fx.required, &admin, method, &uri, Some(body), None).await;
            assert_eq!(status, StatusCode::CONFLICT, "{method} {uri}: {json}");
            assert_eq!(
                conflict_code(&json),
                "changeset_required",
                "{method} {uri}: {json}"
            );
        }
        let written: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM role WHERE name = $1)")
                .bind(&role_name)
                .fetch_one(fx.db())
                .await
                .expect("probe");
        assert!(!written, "a refused write writes nothing");
        assert!(ops_by(fx.db(), admin.id).await.is_empty());

        // With one open changeset, the same write is recorded into it — by
        // selection (no header) and by the header.
        let changeset = store::open(
            fx.db(),
            &NewChangeset {
                layer: Layer::Project,
                scope: "hooks-test".into(),
                name: format!("l5-{}", suffix()),
                title: "Lane 5 hooks".into(),
                description: String::new(),
                requires: json!({}),
                author_ref: Some(admin.id),
                author_label: format!("user:{}", admin.id),
            },
        )
        .await
        .expect("open a changeset");
        let (status, json) = send(
            &fx.required,
            &admin,
            "POST",
            "/api/v1/admin/security/roles",
            Some(json!({ "name": role_name })),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        let (status, json) = send(
            &fx.required,
            &admin,
            "PATCH",
            &format!("/api/v1/admin/security/roles/{}", id_of(&json)),
            Some(json!({ "description": "in the changeset" })),
            Some(changeset.id),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let recorded: Vec<(String, i32)> = sqlx::query_as(
            "SELECT op, seq FROM changeset_operation WHERE changeset_ref = $1 ORDER BY seq",
        )
        .bind(changeset.id)
        .fetch_all(fx.db())
        .await
        .expect("read the changeset's operations");
        assert_eq!(
            recorded,
            vec![("upsert_role".to_owned(), 1), ("upsert_role".to_owned(), 2)]
        );
    });
}

// ── 3. the layer rule ──────────────────────────────────────────────────────

#[test]
fn a_row_owned_by_another_layer_is_refused_and_nothing_is_recorded() {
    attome_testkit::run_shared(async {
        let fx = skip_if_no_db!(fixture().await);
        let admin = seed_admin(fx.db()).await;
        let entity = seed_entity(&fx).await;
        let db = fx.db();

        let (role_id, _) = create_role(&fx, &admin).await;
        let grant = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/security/role-grants",
            "POST /api/v1/admin/security/role-grants",
            Some(json!({ "role_id": role_id, "privilege_key": format!("cs_hook_{}.x", suffix()) })),
            &["ensure_privilege", "grant_role_privilege"],
        )
        .await;
        let model = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/state-models",
            "POST /api/v1/admin/state-models",
            Some(json!({
                "entity_logicalname": entity, "name": "Owned",
                "state_field": "status", "initial_state": "new",
            })),
            &["upsert_state_model"],
        )
        .await;
        let definition = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/workflow/definitions",
            "POST /api/v1/workflow/definitions",
            Some(json!({ "logicalname": format!("cs_owned_{}", suffix()), "name": "Owned" })),
            &["upsert_workflow"],
        )
        .await;
        let query = expect_ops(
            &fx,
            &admin,
            "POST",
            "/api/v1/admin/queries",
            "POST /api/v1/admin/queries",
            Some(
                json!({ "name": format!("cs_owned_{}", suffix()), "sql_query": "SELECT 1 AS id" }),
            ),
            &["upsert_query"],
        )
        .await;

        // The platform owns them now (as the boot stamp step would mark a
        // platform definition's rows).
        set_owner_layer(db, "role", role_id, Layer::Platform).await;
        set_owner_layer(db, "role_mm_privilege", id_of(&grant), Layer::Platform).await;
        set_owner_layer(db, "state_model", id_of(&model), Layer::Platform).await;
        set_owner_layer(
            db,
            "workflow_definition",
            id_of(&definition),
            Layer::Platform,
        )
        .await;
        set_owner_layer(db, "sql_query", id_of(&query), Layer::Platform).await;
        let before = ops_by(db, admin.id).await.len();

        for (method, uri, body) in [
            (
                "PATCH",
                format!("/api/v1/admin/security/roles/{role_id}"),
                Some(json!({ "description": "project edit of a platform role" })),
            ),
            (
                "PUT",
                format!("/api/v1/admin/security/roles/{role_id}/bulk-fields"),
                Some(json!({ "mode": "legacy", "fields": [] })),
            ),
            (
                "DELETE",
                format!("/api/v1/admin/security/role-grants/{}", id_of(&grant)),
                None,
            ),
            (
                "PATCH",
                format!("/api/v1/admin/state-models/{}", id_of(&model)),
                Some(json!({
                    "name": "Owned 2", "state_field": "status", "initial_state": "new",
                    "is_active": true, "row_version": model["row_version"],
                })),
            ),
            (
                "DELETE",
                format!("/api/v1/workflow/definitions/{}", id_of(&definition)),
                None,
            ),
            (
                "DELETE",
                format!("/api/v1/admin/queries/{}", id_of(&query)),
                None,
            ),
        ] {
            let (status, json) = send(&fx.auto, &admin, method, &uri, body, None).await;
            assert_eq!(status, StatusCode::CONFLICT, "{method} {uri}: {json}");
            assert_eq!(
                conflict_code(&json),
                "layer_mismatch",
                "{method} {uri}: {json}"
            );
        }
        assert_eq!(
            ops_by(db, admin.id).await.len(),
            before,
            "a refused write records nothing"
        );
        let description: Option<String> =
            sqlx::query_scalar("SELECT description FROM role WHERE id = $1")
                .bind(role_id)
                .fetch_one(db)
                .await
                .expect("read the role");
        assert_ne!(
            description.as_deref(),
            Some("project edit of a platform role"),
            "a refused write changes nothing"
        );

        // A project changeset may still add to a platform role: a new grant
        // row is the project's.
        let (status, json) = send(
            &fx.auto,
            &admin,
            "POST",
            "/api/v1/admin/security/role-grants",
            Some(json!({ "role_id": role_id, "privilege_key": format!("cs_hook_{}.y", suffix()) })),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        assert_eq!(json["owner_layer"], "project");
    });
}

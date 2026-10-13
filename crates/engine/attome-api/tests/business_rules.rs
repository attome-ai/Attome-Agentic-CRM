//! D-789 (amended by D-790, D-791) — the business-rule proof suite of
//! `document/general/BUSINESS-RULES-DESIGN.md` §11 (lane BR-E): the admin
//! family `/api/v1/admin/business-rules` and the write pipeline, end to end
//! through the real router.
//!
//! Covered here: admin CRUD with `If-Match`, idempotent create, validate,
//! test and the publish lock; auto-mode customer stamping (D-791 rule 2);
//! `hidden`/`disabled` locks for staff roles and for all users (admins
//! included), the one-request unlock, most-restrictive-wins,
//! required-but-locked; API keys exempt from locks but not from errors (D-791
//! rule 3); `warning` policies returned on create, update and upsert (D-791
//! rule 6); portal writes enforced for all-users and portal-role rules;
//! converted legacy validation/calculation/default rules (validation judges
//! the final record, D-789 ruling 5), including a legacy row still on disk;
//! `set_value` `default` vs `always`; unknown conditions failing closed; and
//! the `business_rules` field hook on rename, delete and retype (plus the
//! `record_baseline` hook of Solution 7 Phase 2 §9.1).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — skips (loudly) when `DATABASE_URL`
//! is unset, except under `CI`. Run against a throwaway database:
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test business_rules -- --test-threads=1
//! ```
//!
//! The harness is `rule_enforcement.rs`'s, unchanged in shape:
//! `cache.metadata_registry_enabled: false` (a freshly provisioned entity is
//! written in the same run), and the rule registry is swapped synchronously by
//! every admin write, so a rule is visible to the very next request. The test
//! config carries no `metadata` section, so changesets run in `auto` mode:
//! an admin rule write is a customer edit, stamped `customer` (design §7).
//! Fixture rows (users, roles, an API key, a legacy rule row, baseline rows)
//! are written with SQL into the throwaway database, as the sibling suites do.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_records::access_plan::{AccessPlan, PlanCondition, plan_create};
use attome_server::AppState;
use attome_server::security::{ConditionOperator, GrantCondition};
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// See `entity_round_trip.rs`'s identical helper for the shape this parses.
fn parse_test_database_url(url: &str) -> (String, String, String, u16, String) {
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .unwrap_or_else(|| panic!("test DATABASE_URL must be a postgres:// URL: {url}"));
    let (userinfo, hostpart) = rest
        .split_once('@')
        .unwrap_or_else(|| panic!("test DATABASE_URL must carry userinfo: {url}"));
    let (user, password) = match userinfo.split_once(':') {
        Some((u, p)) => (u.to_owned(), p.to_owned()),
        None => (userinfo.to_owned(), String::new()),
    };
    let hostpart = hostpart.split(['?', '#']).next().unwrap_or(hostpart);
    let (hostport, dbname) = hostpart
        .split_once('/')
        .unwrap_or_else(|| panic!("test DATABASE_URL must carry a database path: {url}"));
    let (host, port) = hostport
        .split_once(':')
        .unwrap_or_else(|| panic!("test DATABASE_URL must carry an explicit port: {url}"));
    (
        user,
        password,
        host.to_owned(),
        port.parse()
            .unwrap_or_else(|_| panic!("test DATABASE_URL port must be numeric: {url}")),
        dbname.to_owned(),
    )
}

fn test_config() -> AppConfig {
    let (db_user, db_password, db_host, db_port, db_name) =
        parse_test_database_url(&std::env::var("DATABASE_URL").expect(
            "DATABASE_URL must be set by attome_testkit::migrated_db_url() before test_config()",
        ));
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
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
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
            "cors": {{ "allowed_origins": ["http://test.local"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    attome_testkit::migrated_db_url()?;

    let config = test_config();
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

async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("http://test.local"),
    );
    req
}

/// The system and router every test in this binary shares (see
/// `rule_enforcement.rs`). Each test provisions its own uniquely named
/// entities, users and roles.
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

fn build_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
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

// ── Fixtures ────────────────────────────────────────────────────────────────

/// How a request authenticates: a cookie session (an interactive staff
/// user) or an API key (a service principal, D-791 rule 3).
#[derive(Clone)]
enum Auth {
    Cookie(String),
    ApiKey(String),
}

/// A `system.admin` holder (directly granted, no role). Returns its id and
/// cookie session.
async fn seed_admin(system: &TestSystem) -> (Uuid, Auth) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("business-rules-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must already be seeded by attome_security::seed::seed");

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

    (user_id, Auth::Cookie(session_cookie(user_id)))
}

/// A fresh staff role granting `"{entity}.{action}"` for each action (the
/// `record_level_security.rs` helper's shape).
async fn create_role_with_privileges(system: &TestSystem, entity: &str, actions: &[&str]) -> Uuid {
    let db = &system.state().base.db;
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("business-rules-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");

    for action in actions {
        let key = format!("{entity}.{action}");
        let privilege_id: Uuid = sqlx::query_scalar(
            "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
             VALUES ($1, $2, $3, $3, true, NOW(), 'project') \
             ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(&key)
        .bind(&key)
        .fetch_one(db)
        .await
        .expect("ensure privilege");

        sqlx::query(
            "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) \
             VALUES ($1, $2, $3, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("grant role privilege");
    }
    role_id
}

/// A non-admin user holding one fresh role that may create, read and update
/// `entity`. Returns (user, cookie, role).
async fn seed_role_user(system: &TestSystem, entity: &str) -> (Uuid, Auth, Uuid) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("business-rules-test-user-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway non-admin user");
    let role_id = create_role_with_privileges(system, entity, &["create", "read", "update"]).await;
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role to user");
    (user_id, Auth::Cookie(session_cookie(user_id)), role_id)
}

/// An API key for `user_id`, written with the deployment's own pepper (the
/// `pipeline_overhead.rs` helper: minting over HTTP needs a stepped-up
/// session, beside the point here). Returns the `ApiKey` credential.
async fn mint_api_key(system: &TestSystem, user_id: Uuid) -> Auth {
    let state = &system.state().base;
    let public_key = format!("atk_pub_br{}", Uuid::now_v7().simple());
    let secret = format!("atk_sec_br{}", Uuid::now_v7().simple());
    let secret_hash = state.pepper_ring().hash(&secret);
    sqlx::query(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(format!("business-rules-{}", Uuid::now_v7()))
    .bind(&public_key)
    .bind(&secret_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway api key");
    Auth::ApiKey(format!("{public_key}:{secret}"))
}

/// One request; returns the status and the JSON body (`Null` when empty).
async fn call(
    app: &axum::Router,
    method: &str,
    uri: &str,
    auth: &Auth,
    body: Option<Value>,
    if_match: Option<i64>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    builder = match auth {
        Auth::Cookie(cookie) => builder.header("cookie", cookie),
        Auth::ApiKey(key) => builder.header("authorization", format!("ApiKey {key}")),
    };
    if let Some(version) = if_match {
        builder = builder.header("if-match", format!("\"{version}\""));
    }
    let req = match body {
        Some(b) => builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("build request");
    let res = app.clone().oneshot(req).await.expect("response");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn id_of(body: &Value) -> Uuid {
    body["id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no id in {body}"))
}

/// Provisions an entity and its fields through the admin API. `fields` is
/// `(logicalname, field_type, is_required)`. Returns the entity id and the
/// field ids by name.
async fn provision(
    app: &axum::Router,
    admin: &Auth,
    logicalname: &str,
    fields: &[(&str, &str, bool)],
) -> (Uuid, HashMap<String, Uuid>) {
    let (status, body) = call(
        app,
        "POST",
        "/api/v1/admin/entities",
        admin,
        Some(json!({ "logicalname": logicalname, "name": "Business Rules Test" })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "entity create: {body}");
    let entity_id = id_of(&body);
    let mut ids = HashMap::new();
    for (name, field_type, required) in fields {
        let (status, body) = call(
            app,
            "POST",
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin,
            Some(json!({
                "logicalname": name,
                "name": name,
                "field_type": field_type,
                "is_required": required,
                // A portal grant condition needs an indexed field.
                "is_filterable": *name == "portal_tag",
            })),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "field '{name}' create: {body}");
        ids.insert((*name).to_owned(), id_of(&body));
    }
    (entity_id, ids)
}

fn unique(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::now_v7().simple())
}

/// `POST /api/v1/admin/business-rules`, asserting 201.
async fn create_rule(app: &axum::Router, admin: &Auth, body: Value) -> Value {
    let (status, rule) = call(
        app,
        "POST",
        "/api/v1/admin/business-rules",
        admin,
        Some(body),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "rule create: {rule}");
    rule
}

async fn create_record(
    app: &axum::Router,
    auth: &Auth,
    entity: &str,
    body: Value,
) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        &format!("/api/v1/{entity}"),
        auth,
        Some(body),
        None,
    )
    .await
}

async fn update_record(
    app: &axum::Router,
    auth: &Auth,
    entity: &str,
    record: &Value,
    body: Value,
) -> (StatusCode, Value) {
    let id = id_of(record);
    let version = record["row_version"].as_i64().expect("row_version");
    call(
        app,
        "PATCH",
        &format!("/api/v1/{entity}/{id}"),
        auth,
        Some(body),
        Some(version),
    )
    .await
}

fn always() -> Value {
    json!({ "all": [] })
}

fn warning_codes(rule: &Value) -> Vec<String> {
    rule["warnings"]
        .as_array()
        .map(|w| {
            w.iter()
                .filter_map(|x| x["code"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn assert_locked(status: StatusCode, body: &Value, field: &str, effect: &str, rule_id: &str) {
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "field_locked", "{body}");
    assert_eq!(body["field"], field, "{body}");
    assert_eq!(body["effect"], effect, "{body}");
    assert_eq!(body["rule_id"], rule_id, "{body}");
    assert!(body["details"]["fields"].is_array(), "{body}");
}

// ── Admin CRUD, If-Match, validate, test, publish ───────────────────────────

/// Design §6.1–§6.4: CRUD with `If-Match`, idempotent create by (entity,
/// name), warnings, validate and test (no write), publish and its advisory
/// lock; an `auto`-mode write is a customer edit, stamped `customer`
/// (design §7, D-791 rule 2).
#[test]
fn admin_crud_if_match_validate_test_and_publish_lock() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = system.app.clone();
        let entity = unique("br_admin");
        provision(
            &app,
            &admin,
            &entity,
            &[("note", "text", false), ("amount", "number", false)],
        )
        .await;

        let body = json!({
            "entity": entity,
            "name": "lock_note",
            "condition": always(),
            "policies": [{ "type": "disabled", "field": "note" }],
        });
        let rule = create_rule(&app, &admin, body.clone()).await;
        let rule_id = rule["id"].as_str().expect("rule id").to_owned();
        assert_eq!(rule["kind"], "business");
        assert_eq!(rule["applies_to"], "all");
        assert_eq!(
            rule["owner_layer"], "customer",
            "auto mode stamps customer: {rule}"
        );
        assert_eq!(rule["version"], 1);
        let codes = warning_codes(&rule);
        assert!(codes.iter().any(|c| c == "locks_everyone"), "{rule}");
        assert!(
            codes.iter().any(|c| c == "rule_applies_to_admins"),
            "{rule}"
        );

        // Idempotent create: the same body answers 200 with the same rule; a
        // different body under the same name is 409.
        let (status, again) = call(
            &app,
            "POST",
            "/api/v1/admin/business-rules",
            &admin,
            Some(body),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["id"], rule_id.as_str());
        let (status, clash) = call(
            &app,
            "POST",
            "/api/v1/admin/business-rules",
            &admin,
            Some(json!({
                "entity": entity,
                "name": "lock_note",
                "condition": always(),
                "policies": [{ "type": "hidden", "field": "note" }],
            })),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{clash}");

        // List and get.
        let (status, list) = call(
            &app,
            "GET",
            &format!("/api/v1/admin/business-rules?entity={entity}"),
            &admin,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert_eq!(list["total"], 1, "{list}");
        assert_eq!(list["page"], 1, "{list}");

        // Validate writes nothing: a lock policy with an advanced leaf is an
        // issue; a sound body is valid.
        let (status, verdict) = call(
            &app,
            "POST",
            "/api/v1/admin/business-rules/validate",
            &admin,
            Some(json!({
                "entity": entity,
                "name": "advanced_lock",
                "condition": { "expression": "amount > 10" },
                "policies": [{ "type": "hidden", "field": "note" }],
            })),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{verdict}");
        assert_eq!(verdict["valid"], false, "{verdict}");
        assert!(!verdict["issues"].as_array().expect("issues").is_empty());
        let (status, verdict) = call(
            &app,
            "POST",
            "/api/v1/admin/business-rules/validate",
            &admin,
            Some(json!({
                "entity": entity,
                "name": "advanced_error",
                "condition": { "expression": "amount > 10" },
                "policies": [{ "type": "error", "message": "too big", "severity": "error" }],
            })),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{verdict}");
        assert_eq!(verdict["valid"], true, "{verdict}");
        let stored: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rule WHERE entity_logicalname = $1 AND is_deleted = false",
        )
        .bind(&entity)
        .fetch_one(&db)
        .await
        .expect("count rules");
        assert_eq!(stored, 1, "validate must not write");

        // Test: the lock applies to a staff writer, not to a system context
        // nor to an API-key principal (D-791 rule 3).
        let test_uri = format!("/api/v1/admin/business-rules/{rule_id}/test");
        // The test endpoint reads the in-memory entity registry, which catches
        // up from the metadata change log asynchronously; wait for it, bounded.
        let mut attempt = 0;
        let (status, out) = loop {
            let (status, out) = call(
                &app,
                "POST",
                &test_uri,
                &admin,
                Some(json!({ "record": { "note": "x" } })),
                None,
            )
            .await;
            attempt += 1;
            if status == StatusCode::UNPROCESSABLE_ENTITY
                && out.to_string().contains("no registered entity found")
                && attempt < 50
            {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            break (status, out);
        };
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["condition"], "true", "{out}");
        assert_eq!(out["locks"][0]["field"], "note", "{out}");
        assert_eq!(out["locks"][0]["effect"], "disabled", "{out}");
        for audience in [json!({ "system": true }), json!({ "interactive": false })] {
            let (status, out) = call(
                &app,
                "POST",
                &test_uri,
                &admin,
                Some(json!({ "record": { "note": "x" }, "as": audience })),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{out}");
            assert!(
                out["locks"].as_array().is_some_and(Vec::is_empty),
                "no lock for {audience}: {out}"
            );
        }

        // PATCH needs If-Match: missing is 422, stale is 409, current is 200.
        let rule_uri = format!("/api/v1/admin/business-rules/{rule_id}");
        let version = rule["row_version"].as_i64().expect("row_version");
        let patch = json!({ "display_name": "Lock the note" });
        let (status, out) = call(&app, "PATCH", &rule_uri, &admin, Some(patch.clone()), None).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{out}");
        let (status, out) = call(
            &app,
            "PATCH",
            &rule_uri,
            &admin,
            Some(patch.clone()),
            Some(version + 5),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{out}");
        assert_eq!(out["error"], "version_conflict", "{out}");
        let (status, patched) =
            call(&app, "PATCH", &rule_uri, &admin, Some(patch), Some(version)).await;
        assert_eq!(status, StatusCode::OK, "{patched}");
        assert_eq!(patched["display_name"], "Lock the note");
        assert!(patched["row_version"].as_i64().expect("row_version") > version);

        // Publish bumps `version`; a publish that cannot take the per-rule
        // advisory lock (D-351 two-argument form) is refused with 409.
        let publish_uri = format!("/api/v1/admin/business-rules/{rule_id}/publish");
        let (status, published) = call(&app, "POST", &publish_uri, &admin, None, None).await;
        assert_eq!(status, StatusCode::OK, "{published}");
        assert_eq!(published["version"], 2, "{published}");
        let mut held = attome_db::tx::begin(&db).await.expect("begin holder");
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(attome_api::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-api/rule-publish:{rule_id}"))
            .fetch_one(&mut *held)
            .await
            .expect("take the publish lock");
        assert!(got, "the test must hold the publish lock");
        let (status, busy) = call(&app, "POST", &publish_uri, &admin, None, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{busy}");
        held.rollback().await.expect("release the publish lock");
        let (status, published) = call(&app, "POST", &publish_uri, &admin, None, None).await;
        assert_eq!(status, StatusCode::OK, "{published}");
        assert_eq!(published["version"], 3, "{published}");

        // DELETE retires (If-Match optional; stale is 409).
        let current = published["row_version"].as_i64().expect("row_version");
        let (status, out) = call(&app, "DELETE", &rule_uri, &admin, None, Some(current + 9)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{out}");
        let (status, out) = call(&app, "DELETE", &rule_uri, &admin, None, Some(current)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{out}");
        let (status, retired) = call(&app, "GET", &rule_uri, &admin, None, None).await;
        assert_eq!(status, StatusCode::OK, "{retired}");
        assert_eq!(retired["is_active"], false, "{retired}");
        let (status, out) = call(&app, "DELETE", &rule_uri, &admin, None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{out}");
    })
}

// ── Locks ───────────────────────────────────────────────────────────────────

/// Design §3.1, §3.5: a role-scoped lock binds only holders of the role; an
/// all-users lock binds everyone, administrators included; an unchanged
/// value is accepted; the condition is judged on the record as it will be
/// saved, so one request may unlock a field.
#[test]
fn locks_bind_staff_roles_and_all_users() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let app = system.app.clone();
        let entity = unique("br_locks");
        provision(
            &app,
            &admin,
            &entity,
            &[
                ("title", "text", false),
                ("priority", "text", false),
                ("note", "text", false),
            ],
        )
        .await;
        let (_, user1, role1) = seed_role_user(&system, &entity).await;
        let (_, user2, _) = seed_role_user(&system, &entity).await;

        let role_rule = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "role1_locks_priority",
                "applies_to": "roles",
                "role_ids": [role1],
                "condition": always(),
                "policies": [{ "type": "disabled", "field": "priority" }],
            }),
        )
        .await;
        let role_rule_id = role_rule["id"].as_str().expect("id").to_owned();
        let all_rule = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "secret_titles_hide_note",
                "condition": { "field": "title", "op": "eq", "value": "secret" },
                "policies": [{ "type": "hidden", "field": "note" }],
            }),
        )
        .await;
        let all_rule_id = all_rule["id"].as_str().expect("id").to_owned();

        // Role-scoped: user1 holds role1, user2 does not.
        let (status, body) = create_record(
            &app,
            &user1,
            &entity,
            json!({ "title": "a", "priority": "high" }),
        )
        .await;
        assert_locked(status, &body, "priority", "disabled", &role_rule_id);
        let (status, mine) = create_record(&app, &user1, &entity, json!({ "title": "a" })).await;
        assert_eq!(status, StatusCode::CREATED, "{mine}");
        // Re-sending the stored (empty) value is not a change.
        let (status, updated) = update_record(
            &app,
            &user1,
            &entity,
            &mine,
            json!({ "title": "b", "priority": null }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        let (status, body) =
            update_record(&app, &user1, &entity, &updated, json!({ "priority": "x" })).await;
        assert_locked(status, &body, "priority", "disabled", &role_rule_id);
        let (status, body) = create_record(
            &app,
            &user2,
            &entity,
            json!({ "title": "a", "priority": "high" }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "a role-scoped rule binds only its roles: {body}"
        );

        // All users, administrators included, and only while the condition
        // holds on the final record.
        for writer in [&admin, &user2] {
            let (status, body) = create_record(
                &app,
                writer,
                &entity,
                json!({ "title": "secret", "note": "n" }),
            )
            .await;
            assert_locked(status, &body, "note", "hidden", &all_rule_id);
        }
        let (status, body) = create_record(
            &app,
            &admin,
            &entity,
            json!({ "title": "public", "note": "n" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, secret) =
            create_record(&app, &admin, &entity, json!({ "title": "secret" })).await;
        assert_eq!(status, StatusCode::CREATED, "{secret}");
        let (status, body) = update_record(
            &app,
            &admin,
            &entity,
            &secret,
            json!({ "title": "public", "note": "now visible" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "one request may unlock: {body}");
        assert_eq!(body["data"]["note"], "now visible");
    })
}

/// Design §3.3: per field, `hidden` > `disabled` > none across every rule
/// whose condition holds and every role the writer holds.
#[test]
fn the_most_restrictive_lock_wins() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let app = system.app.clone();
        let entity = unique("br_strict");
        provision(&app, &admin, &entity, &[("priority", "text", false)]).await;
        let (_, user1, role1) = seed_role_user(&system, &entity).await;
        let (_, user2, _) = seed_role_user(&system, &entity).await;

        let everyone = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "everyone_disabled",
                "condition": always(),
                "policies": [{ "type": "disabled", "field": "priority" }],
            }),
        )
        .await;
        let role_rule = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "role1_hidden",
                "applies_to": "roles",
                "role_ids": [role1],
                "condition": always(),
                "policies": [{ "type": "hidden", "field": "priority" }],
            }),
        )
        .await;

        let body = json!({ "priority": "high" });
        let (status, out) = create_record(&app, &user1, &entity, body.clone()).await;
        assert_locked(
            status,
            &out,
            "priority",
            "hidden",
            role_rule["id"].as_str().expect("id"),
        );
        assert_eq!(
            out["details"]["fields"].as_array().map(Vec::len),
            Some(1),
            "{out}"
        );
        for writer in [&user2, &admin] {
            let (status, out) = create_record(&app, writer, &entity, body.clone()).await;
            assert_locked(
                status,
                &out,
                "priority",
                "disabled",
                everyone["id"].as_str().expect("id"),
            );
        }
    })
}

/// Design §3.4: a required field that is locked for the writer and empty in
/// the final record fails the save, naming the field and the rule.
#[test]
fn a_required_field_locked_and_left_empty_fails_the_save() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let app = system.app.clone();
        let entity = unique("br_required");
        provision(
            &app,
            &admin,
            &entity,
            &[("code", "text", true), ("status", "text", false)],
        )
        .await;
        let locked_status = json!({ "field": "status", "op": "eq", "value": "locked" });

        create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "blank_code_when_locked",
                "condition": locked_status,
                "policies": [{ "type": "set_value", "field": "code", "value": "", "mode": "always" }],
            }),
        )
        .await;
        let lock = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "lock_code_when_locked",
                "condition": locked_status,
                "policies": [{ "type": "disabled", "field": "code" }],
            }),
        )
        .await;
        assert!(
            warning_codes(&lock)
                .iter()
                .any(|c| c == "required_field_locked"),
            "{lock}"
        );

        let (status, record) = create_record(
            &app,
            &admin,
            &entity,
            json!({ "code": "A", "status": "open" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
        let (status, body) = update_record(
            &app,
            &admin,
            &entity,
            &record,
            json!({ "status": "locked" }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "field_locked_required", "{body}");
        assert_eq!(body["field"], "code", "{body}");
        assert_eq!(body["rule_id"], lock["id"], "{body}");
        assert_eq!(body["rule_name"], "lock_code_when_locked", "{body}");
    })
}

/// D-791 rule 3: an API-key principal skips `hidden`/`disabled`; `error`
/// policies still apply to it.
#[test]
fn api_keys_skip_locks_but_not_errors() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (admin_id, admin) = seed_admin(&system).await;
        let api_key = mint_api_key(&system, admin_id).await;
        let app = system.app.clone();
        let entity = unique("br_apikey");
        provision(
            &app,
            &admin,
            &entity,
            &[("priority", "text", false), ("amount", "number", false)],
        )
        .await;

        let lock = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "lock_priority",
                "condition": always(),
                "policies": [{ "type": "disabled", "field": "priority" }],
            }),
        )
        .await;
        let error = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "no_negative_amounts",
                "condition": { "field": "amount", "op": "lt", "value": 0 },
                "policies": [{
                    "type": "error",
                    "field": "amount",
                    "message": "amount must not be negative",
                    "severity": "error",
                }],
            }),
        )
        .await;

        let (status, body) =
            create_record(&app, &admin, &entity, json!({ "priority": "high" })).await;
        assert_locked(
            status,
            &body,
            "priority",
            "disabled",
            lock["id"].as_str().expect("id"),
        );
        let (status, body) =
            create_record(&app, &api_key, &entity, json!({ "priority": "high" })).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "an API key skips locks: {body}"
        );
        assert_eq!(body["data"]["priority"], "high");

        let (status, body) = create_record(&app, &api_key, &entity, json!({ "amount": -1 })).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "rule_violation", "{body}");
        assert_eq!(body["rule_id"], error["id"], "{body}");
        assert_eq!(
            body["message"],
            "rule violation: amount must not be negative"
        );
        assert_eq!(body["details"]["field"], "amount", "{body}");
    })
}

/// D-791 rule 6: a `warning`-severity error policy never blocks; the write
/// response carries it in `warnings` on create, update and upsert, and omits
/// the list when none fired.
#[test]
fn warnings_reach_create_update_and_upsert() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let app = system.app.clone();
        let entity = unique("br_warn");
        provision(
            &app,
            &admin,
            &entity,
            &[("code", "text", false), ("amount", "number", false)],
        )
        .await;
        let rule = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "large_amount",
                "condition": { "field": "amount", "op": "gt", "value": 100 },
                "policies": [{
                    "type": "error",
                    "field": "amount",
                    "message": "large amount",
                    "severity": "warning",
                }],
            }),
        )
        .await;
        let check = |body: &Value| {
            assert_eq!(body["warnings"].as_array().map(Vec::len), Some(1), "{body}");
            assert_eq!(body["warnings"][0]["rule_id"], rule["id"], "{body}");
            assert_eq!(body["warnings"][0]["field"], "amount", "{body}");
            assert_eq!(body["warnings"][0]["message"], "large amount", "{body}");
        };

        let (status, created) = create_record(
            &app,
            &admin,
            &entity,
            json!({ "code": "c1", "amount": 500 }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        check(&created);

        let (status, quiet) =
            create_record(&app, &admin, &entity, json!({ "code": "c2", "amount": 5 })).await;
        assert_eq!(status, StatusCode::CREATED, "{quiet}");
        assert!(
            quiet.get("warnings").is_none(),
            "no warning, no list: {quiet}"
        );

        let (status, updated) =
            update_record(&app, &admin, &entity, &quiet, json!({ "amount": 700 })).await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        check(&updated);

        let (status, upserted) = call(
            &app,
            "POST",
            &format!("/api/v1/{entity}/upsert"),
            &admin,
            Some(json!({ "match": { "code": "c3" }, "data": { "amount": 900 } })),
            None,
        )
        .await;
        assert!(
            status == StatusCode::CREATED || status == StatusCode::OK,
            "{status}: {upserted}"
        );
        check(&upserted);
    })
}

// ── Portal ──────────────────────────────────────────────────────────────────

/// A portal plan on `entity` whose one grant condition is `portal_tag = 'p'`
/// (so the created record is in scope), writing `fields`.
async fn portal_plan(system: &TestSystem, entity: &str, fields: &[&str], role: Uuid) -> AccessPlan {
    let org: Option<Uuid> = sqlx::query_scalar("SELECT id FROM organization LIMIT 1")
        .fetch_optional(&system.state().base.db)
        .await
        .expect("read an organization");
    let names: BTreeSet<String> = fields.iter().map(|f| (*f).to_owned()).collect();
    AccessPlan {
        portal_user_id: Uuid::now_v7(),
        portal_user_label: "business-rules-portal-user".to_owned(),
        webportal_id: Uuid::now_v7(),
        entity: entity.to_owned(),
        can_read: true,
        can_create: true,
        can_update: true,
        can_delete: false,
        conditions: vec![PlanCondition::Match(GrantCondition {
            field_logicalname: "portal_tag".to_owned(),
            operator: ConditionOperator::Eq,
            value: json!("p"),
        })],
        readable: names.clone(),
        writable: names.clone(),
        filterable: names,
        owner_team_ref: Uuid::now_v7(),
        owner_org_ref: org.unwrap_or_else(Uuid::now_v7),
        portal_user_field: None,
        lookup_scopes: BTreeMap::new(),
        request_context: Default::default(),
        role_id: Some(role),
    }
}

async fn portal_role(system: &TestSystem) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO webportal_role (id, webportal_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(Uuid::now_v7())
        .bind(format!("business-rules-portal-role-{id}"))
        .execute(&system.state().base.db)
        .await
        .expect("insert portal role");
    id
}

/// D-789 ruling 6: portal writes go through the same pipeline
/// (`Principal::Portal`): all-users rules bind them, and a portal-role rule
/// binds only holders of that portal role.
#[test]
fn portal_writes_are_enforced() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let app = system.app.clone();
        let entity = unique("br_portal");
        provision(
            &app,
            &admin,
            &entity,
            &[
                ("portal_tag", "text", false),
                ("priority", "text", false),
                ("note", "text", false),
            ],
        )
        .await;
        let role_a = portal_role(&system).await;
        let role_b = portal_role(&system).await;

        let everyone = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "lock_priority_everyone",
                "condition": always(),
                "policies": [{ "type": "disabled", "field": "priority" }],
            }),
        )
        .await;
        let portal_rule = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "hide_note_for_portal_role_a",
                "applies_to": "roles",
                "portal_role_ids": [role_a],
                "condition": always(),
                "policies": [{ "type": "hidden", "field": "note" }],
            }),
        )
        .await;
        let fields = ["portal_tag", "priority", "note"];
        let state = system.state();
        let plan_a = portal_plan(&system, &entity, &fields, role_a).await;
        let plan_b = portal_plan(&system, &entity, &fields, role_b).await;

        let locked =
            |result: Result<_, AppError>, field: &str, effect: &str, rule: &Value| match result {
                Err(AppError::FieldLocked { locks, required }) => {
                    assert!(!required);
                    assert_eq!(locks[0].field, field);
                    assert_eq!(locks[0].effect, effect);
                    assert_eq!(
                        Some(locks[0].rule_id.to_string().as_str()),
                        rule["id"].as_str()
                    );
                }
                Err(other) => panic!("expected field_locked on {field}, got {other:?}"),
                Ok(_) => panic!("expected field_locked on {field}, the write succeeded"),
            };

        let result = plan_create(
            state,
            &plan_b,
            json!({ "portal_tag": "p", "priority": "high" }),
        )
        .await;
        locked(result, "priority", "disabled", &everyone);
        let result = plan_create(state, &plan_a, json!({ "portal_tag": "p", "note": "n" })).await;
        locked(result, "note", "hidden", &portal_rule);
        let record = plan_create(state, &plan_b, json!({ "portal_tag": "p", "note": "n" }))
            .await
            .expect("a portal-role rule binds only its role");
        assert_eq!(record.data.get("note"), Some(&json!("n")));
        plan_create(state, &plan_a, json!({ "portal_tag": "p" }))
            .await
            .expect("no locked field written");
    })
}

// ── Set-value policies ──────────────────────────────────────────────────────

/// Design §3.3: `set_value` `default` fills a field left empty on create
/// only; `always` writes on every write whose condition holds.
#[test]
fn set_value_default_fills_gaps_on_create_and_always_overrides() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let app = system.app.clone();
        let entity = unique("br_setvalue");
        provision(
            &app,
            &admin,
            &entity,
            &[
                ("currency", "text", false),
                ("stamp", "text", false),
                ("amount", "number", false),
            ],
        )
        .await;
        create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "currency_default",
                "condition": always(),
                "policies": [{ "type": "set_value", "field": "currency", "value": "USD", "mode": "default" }],
            }),
        )
        .await;
        create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "stamp_positive",
                "condition": { "field": "amount", "op": "gt", "value": 0 },
                "policies": [{ "type": "set_value", "field": "stamp", "value": "positive", "mode": "always" }],
            }),
        )
        .await;

        let (status, empty) = create_record(&app, &admin, &entity, json!({})).await;
        assert_eq!(status, StatusCode::CREATED, "{empty}");
        assert_eq!(empty["data"]["currency"], "USD", "{empty}");
        assert!(
            empty["data"]["stamp"].is_null(),
            "a null-safe leaf is false: {empty}"
        );

        let (status, mine) = create_record(
            &app,
            &admin,
            &entity,
            json!({ "currency": "EUR", "amount": 3, "stamp": "mine" }),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{mine}");
        assert_eq!(mine["data"]["currency"], "EUR", "{mine}");
        assert_eq!(mine["data"]["stamp"], "positive", "{mine}");

        let (status, again) =
            update_record(&app, &admin, &entity, &mine, json!({ "stamp": "again" })).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(
            again["data"]["stamp"], "positive",
            "always applies on update: {again}"
        );
        let (status, cleared) =
            update_record(&app, &admin, &entity, &again, json!({ "currency": null })).await;
        assert_eq!(status, StatusCode::OK, "{cleared}");
        assert!(
            cleared["data"]["currency"].is_null(),
            "default is create-only: {cleared}"
        );
    })
}

/// Design §3.2: an unknown condition (here a null operand in an advanced
/// leaf) counts as holding for `error` (fail closed) and refuses a
/// `set_value` whose value cannot be decided.
#[test]
fn unknown_conditions_fail_closed() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let app = system.app.clone();

        let errors = unique("br_unknown_err");
        provision(&app, &admin, &errors, &[("amount", "number", false)]).await;
        let error = create_rule(
            &app,
            &admin,
            json!({
                "entity": errors,
                "name": "big_amounts_refused",
                "condition": { "expression": "amount > 10" },
                "policies": [{ "type": "error", "message": "amount too big", "severity": "error" }],
            }),
        )
        .await;
        let (status, body) = create_record(&app, &admin, &errors, json!({ "amount": 5 })).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) = create_record(&app, &admin, &errors, json!({})).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "unknown fails closed: {body}"
        );
        assert_eq!(body["error"], "rule_violation", "{body}");
        assert_eq!(body["rule_id"], error["id"], "{body}");

        let sets = unique("br_unknown_set");
        provision(
            &app,
            &admin,
            &sets,
            &[("amount", "number", false), ("flag", "text", false)],
        )
        .await;
        let set = create_rule(
            &app,
            &admin,
            json!({
                "entity": sets,
                "name": "flag_big_amounts",
                "condition": { "expression": "amount > 10" },
                "policies": [{ "type": "set_value", "field": "flag", "value": "big", "mode": "always" }],
            }),
        )
        .await;
        let (status, body) = create_record(&app, &admin, &sets, json!({ "amount": 50 })).await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["data"]["flag"], "big", "{body}");
        let (status, body) = create_record(&app, &admin, &sets, json!({})).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body["error"], "rule_violation", "{body}");
        assert_eq!(body["rule_id"], set["id"], "{body}");
    })
}

// ── Solution 7 field hooks ──────────────────────────────────────────────────

async fn get_rule(app: &axum::Router, admin: &Auth, rule: &Value) -> (StatusCode, Value) {
    let id = id_of(rule);
    call(
        app,
        "GET",
        &format!("/api/v1/admin/business-rules/{id}"),
        admin,
        None,
        None,
    )
    .await
}

async fn baseline_fields(system: &TestSystem, entity: &str, record: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT field_logicalname FROM record_baseline \
         WHERE entity_logicalname = $1 AND record_id = $2 ORDER BY field_logicalname",
    )
    .bind(entity)
    .bind(record)
    .fetch_all(&system.state().base.db)
    .await
    .expect("read baselines")
}

/// D-789 §8 (the `business_rules` hook) and Solution 7 Phase 2 §9.1 (the
/// `record_baseline` hook): a rename rewrites a customer rule's condition
/// leaf and policy field and moves baseline rows; a delete deletes a
/// policy on the field, turns off a rule whose condition used it, removes a
/// rule left with no policy, and removes baseline rows; one of our rules
/// referencing the field blocks the delete; a retype that invalidates a
/// customer rule turns it off.
#[test]
fn the_field_hook_follows_rename_delete_and_retype() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, admin) = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = system.app.clone();
        let entity = unique("br_hooks");
        let (entity_id, fields) = provision(
            &app,
            &admin,
            &entity,
            &[
                ("status", "text", false),
                ("note", "text", false),
                ("gone", "text", false),
                ("kept", "text", false),
                ("only", "text", false),
                ("ours", "text", false),
                ("amount", "number", false),
                ("ref_code", "text", false),
            ],
        )
        .await;
        let field_uri =
            |name: &str| format!("/api/v1/admin/entities/{entity_id}/fields/{}", fields[name]);

        let renamed = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "open_locks_note",
                "condition": { "field": "status", "op": "eq", "value": "open" },
                "policies": [{ "type": "disabled", "field": "note" }],
            }),
        )
        .await;
        let uses_gone = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "gone_locks_kept",
                "condition": { "field": "gone", "op": "is_not_empty" },
                "policies": [{ "type": "disabled", "field": "kept" }],
            }),
        )
        .await;
        let only_gone = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "locks_only_gone",
                "condition": always(),
                "policies": [{ "type": "disabled", "field": "gone" }],
            }),
        )
        .await;
        let retyped = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "big_amount_locks_kept",
                "condition": { "field": "amount", "op": "gt", "value": 10 },
                "policies": [{ "type": "disabled", "field": "kept" }],
            }),
        )
        .await;
        let ours = create_rule(
            &app,
            &admin,
            json!({
                "entity": entity,
                "name": "ours_locks_ours",
                "condition": always(),
                "policies": [{ "type": "disabled", "field": "ours" }],
            }),
        )
        .await;
        // Our layer: fixture SQL on the throwaway database (the admin route in
        // auto mode only ever writes customer rules).
        sqlx::query("UPDATE rule SET owner_layer = 'project' WHERE id = $1")
            .bind(id_of(&ours))
            .execute(&db)
            .await
            .expect("make the rule ours");

        // Baseline rows of a reference record's field (design §9.1).
        let record = Uuid::now_v7();
        let hash = format!("sha256:{}", "a".repeat(64));
        sqlx::query(
            "INSERT INTO record_baseline \
                 (entity_logicalname, record_id, field_logicalname, value_hash, live_hash, \
                  changeset_id, op_seq) \
             VALUES ($1, $2, 'ref_code', $3, $3, $4, 1)",
        )
        .bind(&entity)
        .bind(record)
        .bind(&hash)
        .bind(Uuid::now_v7())
        .execute(&db)
        .await
        .expect("insert a baseline row");

        // Rename: condition leaf, policy field, baseline rows follow.
        for (field, new_name) in [
            ("status", "phase"),
            ("note", "memo"),
            ("ref_code", "ref_key"),
        ] {
            let (status, body) = call(
                &app,
                "POST",
                &format!("{}/rename", field_uri(field)),
                &admin,
                Some(json!({ "new_name": new_name })),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "rename {field}: {body}");
        }
        let (status, rule) = get_rule(&app, &admin, &renamed).await;
        assert_eq!(status, StatusCode::OK, "{rule}");
        assert_eq!(rule["condition"]["field"], "phase", "{rule}");
        assert_eq!(rule["policies"][0]["field"], "memo", "{rule}");
        assert_eq!(rule["is_active"], true, "{rule}");
        assert_eq!(
            baseline_fields(&system, &entity, record).await,
            vec!["ref_key".to_owned()]
        );

        // Our rule blocks the delete of its field.
        let (status, body) = call(&app, "DELETE", &field_uri("ours"), &admin, None, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["blockers"]
                .as_array()
                .is_some_and(|b| b.iter().any(|x| x["hook"] == "business_rules")),
            "{body}"
        );

        // Delete: a condition use turns the rule off; a rule left with no
        // policy is removed.
        let (status, body) = call(&app, "DELETE", &field_uri("gone"), &admin, None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, rule) = get_rule(&app, &admin, &uses_gone).await;
        assert_eq!(status, StatusCode::OK, "{rule}");
        assert_eq!(rule["is_active"], false, "{rule}");
        assert_eq!(rule["disabled_reason"], "field_deleted:gone", "{rule}");
        let (status, rule) = get_rule(&app, &admin, &only_gone).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a rule with no policy left is removed: {rule}"
        );

        // Delete removes the field's baseline rows.
        let (status, body) = call(&app, "DELETE", &field_uri("ref_code"), &admin, None, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(baseline_fields(&system, &entity, record).await.is_empty());

        // Retype: `gt` does not apply to text, so the customer rule is off.
        let (status, body) = call(
            &app,
            "POST",
            &format!("{}/change-type", field_uri("amount")),
            &admin,
            Some(json!({ "field_type": "text" })),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, rule) = get_rule(&app, &admin, &retyped).await;
        assert_eq!(status, StatusCode::OK, "{rule}");
        assert_eq!(rule["is_active"], false, "{rule}");
        assert_eq!(rule["disabled_reason"], "field_retyped:amount", "{rule}");
    })
}

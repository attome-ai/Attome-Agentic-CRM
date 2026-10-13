//! M45 Phase 2 (D-472) — HTTP-level contract tests for the `entity_mutation.rs`
//! validation/calculation/default retrofit: provision an entity + fields
//! through the admin API, author a rule through `/api/v1/admin/business-rules`, then
//! prove the rule actually fires on a real `POST /api/v1/{entity}` create —
//! the same "real contract test" shape `entity_round_trip.rs` uses for the
//! generic-CRUD path, applied to this module's own new enforcement point.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — skips (loudly) when `DATABASE_URL`
//! is unset, except under `CI`. Run manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test rule_enforcement -- --test-threads=1
//! ```
//!
//! `cache.metadata_registry_enabled: false` mirrors `entity_round_trip.rs`'s
//! own reasoning exactly: this test provisions a brand-new entity and writes
//! a record to it in the same process run, which races the arc-swap entity
//! registry's ~250ms pub/sub catch-up. `attome_core::rule_registry`
//! carries no such race for THIS test's purposes — `rule_admin`'s
//! `invalidate()` swaps this same process's `state.rules` synchronously
//! before the create/update/publish HTTP response returns, so a rule is
//! visible to the very next request with no reload delay to wait out.

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
use axum::http::{Request, StatusCode};
use serde_json::Value;
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

async fn seed_admin(system: &TestSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("rule-enforcement-test-admin-{user_id}"))
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

    session_cookie(user_id)
}

async fn body_json(res: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

async fn provision_entity_with_fields(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    fields: &[(&str, &str)],
) -> String {
    let create_entity_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"Rule Enforcement Test"}}"#
        )))
        .unwrap();
    let res = app
        .clone()
        .oneshot(create_entity_req)
        .await
        .expect("create entity");
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "entity create must succeed"
    );
    let entity = body_json(res).await;
    let entity_id = entity["id"].as_str().expect("entity id").to_owned();

    for (field_name, field_type) in fields {
        let create_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{field_name}","name":"{field_name}","field_type":"{field_type}"}}"#
            )))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create field");
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "field '{field_name}' create must succeed"
        );
    }
    entity_id
}

async fn create_rule(app: &axum::Router, cookie: &str, body: Value) -> Value {
    // The in-memory entity registry catches up from the metadata change log
    // asynchronously (pub/sub doorbell), so a rule authored right after its
    // entity may briefly see `entity_unknown`; wait for the registry, bounded.
    for attempt in 0..50 {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/business-rules")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let res = app.clone().oneshot(req).await.expect("create rule");
        let status = res.status();
        let out = body_json(res).await;
        if status == StatusCode::UNPROCESSABLE_ENTITY
            && out.to_string().contains("no registered entity found")
            && attempt < 49
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }
        assert_eq!(
            status,
            StatusCode::CREATED,
            "rule create must succeed: {out}"
        );
        return out;
    }
    unreachable!("the loop returns or asserts on its last attempt")
}

/// The task's own required proof: a `kind = validation` rule violation
/// returns the existing 422 validation-error contract shape WITH a
/// structured `rule_id` field identifying exactly which rule fired.
#[test]
fn validation_rule_violation_returns_422_with_rule_id() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        let logicalname = format!("rule_val_{}", Uuid::now_v7().simple());
        provision_entity_with_fields(&app, &admin_cookie, &logicalname, &[("amount", "number")])
            .await;

        let rule = create_rule(
            &app,
            &admin_cookie,
            serde_json::json!({
                "entity_logicalname": logicalname,
                "name": "amount_must_be_positive",
                "condition": { "expression": "not (amount > 0)" },
                "policies": [
                    { "type": "error", "message": "amount must be positive", "severity": "error" }
                ],
            }),
        )
        .await;
        let rule_id = rule["id"].as_str().expect("rule id").to_owned();

        // A violating create is rejected before any row is written.
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"amount": -5}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("violating create");
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = body_json(res).await;
        assert_eq!(body["error"], "rule_violation");
        assert_eq!(
            body["rule_id"], rule_id,
            "rule_id must identify exactly which rule fired"
        );
        assert_eq!(body["message"], "rule violation: amount must be positive");
        // attome-server hardening I4: the idempotency gate releases a key on a 4xx
        // on the strength of this contract, so prove the rejected create wrote
        // nothing (the entity was provisioned fresh by this test).
        let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM \"{logicalname}\""))
            .fetch_one(&db)
            .await
            .expect("count rows");
        assert_eq!(rows, 0, "a rule_violation must not leave a row behind");

        // A passing create succeeds normally.
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"amount": 5}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("passing create");
        assert_eq!(res.status(), StatusCode::CREATED);
    })
}

/// `kind = calculation`: the derived field is stored on the row (not a
/// virtual/computed-on-read value), recomputed from the caller's own body —
/// M45 plan §5.
#[test]
fn calculation_rule_computes_and_stores_derived_field() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = format!("rule_calc_{}", Uuid::now_v7().simple());
        provision_entity_with_fields(
            &app,
            &admin_cookie,
            &logicalname,
            &[("amount", "number"), ("total_with_tax", "number")],
        )
        .await;

        create_rule(
            &app,
            &admin_cookie,
            serde_json::json!({
                "entity_logicalname": logicalname,
                "name": "compute_total_with_tax",
                "condition": { "all": [] },
                "policies": [
                    { "type": "set_value", "field": "total_with_tax",
                      "expression": "amount * 1.1", "mode": "always" }
                ],
            }),
        )
        .await;

        // The caller supplies a (wrong) value for total_with_tax — the
        // calculation rule must overwrite it unconditionally.
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"amount": 100, "total_with_tax": 0}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create with calculation rule");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        let total = created["data"]["total_with_tax"]
            .as_f64()
            .expect("total_with_tax must be a stored number");
        assert!(
            (total - 110.0).abs() < 0.001,
            "calculation rule must overwrite the caller's own value: got {total}"
        );
    })
}

/// `kind = default`: fills a field ONLY when the caller left it empty —
/// never overrides a caller-supplied value (contrast the calculation rule
/// above, which always overrides).
#[test]
fn default_rule_fills_only_the_gap_the_caller_left() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);

        let logicalname = format!("rule_default_{}", Uuid::now_v7().simple());
        provision_entity_with_fields(&app, &admin_cookie, &logicalname, &[("currency", "text")])
            .await;

        create_rule(
            &app,
            &admin_cookie,
            serde_json::json!({
                "entity_logicalname": logicalname,
                "name": "default_currency",
                "condition": { "all": [] },
                "policies": [
                    { "type": "set_value", "field": "currency",
                      "expression": "\"USD\"", "mode": "default" }
                ],
            }),
        )
        .await;

        // Caller leaves currency unset -> the default rule fills it.
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create with default rule, gap left");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        assert_eq!(created["data"]["currency"], "USD");

        // Caller supplies their own value -> the default rule does not override it.
        let create_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"currency": "EUR"}"#))
            .unwrap();
        let res = app
            .clone()
            .oneshot(create_req)
            .await
            .expect("create with default rule, caller supplied");
        assert_eq!(res.status(), StatusCode::CREATED);
        let created = body_json(res).await;
        assert_eq!(
            created["data"]["currency"], "EUR",
            "a default rule must never override a caller-supplied value"
        );
    })
}

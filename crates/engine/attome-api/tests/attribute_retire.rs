//! Regression coverage for `admin::attribute::delete_attribute` relaxing a
//! retired attribute's physical `NOT NULL` contract.
//!
//! Found live on `ai_agent`: its persona/model-config redesign retired
//! the old governance schema's `is_template` (`required: true`), but
//! `delete_attribute` only ever flipped `attribute_info.is_active`
//! (`reconcile.rs`'s documented "retire is `is_active = false`, never a
//! drop" contract) and never touched the physical column. The generic
//! entity engine never writes a value for a retired attribute again, so the
//! leftover `NOT NULL` permanently blocked every future insert on the
//! entity with `internal_error` (`null value in column "is_template" ...
//! violates not-null constraint`), for anyone, regardless of body — not a
//! validation error a caller could work around.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `approval_schema_change.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-api --test attribute_retire -- --test-threads=1
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

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
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

async fn seed_user(system: &TestSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("attribute-retire-test-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway user_account");

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

    session_cookie(user_id)
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

async fn seed_entity(app: &axum::Router, admin_cookie: &str) -> (Uuid, String) {
    // MAX_IDENTIFIER_LEN is 48; a 32-hex-char UUID plus this prefix must fit.
    let logicalname = format!("agt_{}", Uuid::now_v7().simple());
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/admin/entities".to_string(),
            admin_cookie,
            serde_json::json!({ "logicalname": logicalname, "name": "Attribute Retire Test Entity" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let entity_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    (entity_id, logicalname)
}

/// Mirrors the pre-redesign `ai_agent.is_template` shape: a required
/// boolean field, so its physical column is `NOT NULL`.
async fn create_required_field(app: &axum::Router, admin_cookie: &str, entity_id: Uuid) -> Uuid {
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin_cookie,
            serde_json::json!({
                "logicalname": "was_required",
                "name": "Was Required",
                "field_type": "bool",
                "is_required": true
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "{:?}", resp.status());
    let body = body_json(resp).await;
    body["id"].as_str().unwrap().parse().unwrap()
}

/// An optional text field, so a record can still carry a value once the
/// required field is deleted (an empty body is refused: no recognised fields).
async fn create_optional_field(app: &axum::Router, admin_cookie: &str, entity_id: Uuid) {
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin_cookie,
            serde_json::json!({ "logicalname": "note", "name": "Note", "field_type": "text" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "{:?}", resp.status());
}

async fn delete_field(
    app: &axum::Router,
    admin_cookie: &str,
    entity_id: Uuid,
    field_id: Uuid,
) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/api/v1/admin/entities/{entity_id}/fields/{field_id}"
                ))
                .header("cookie", admin_cookie)
                .header("origin", "http://localhost:4200")
                .header("sec-fetch-site", "same-origin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

async fn create_record(
    app: &axum::Router,
    admin_cookie: &str,
    entity: &str,
    body: Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(json_request(
            "POST",
            format!("/api/v1/{entity}"),
            admin_cookie,
            body,
        ))
        .await
        .unwrap()
}

/// The regression: retiring a `required: true` attribute must relax its
/// physical `NOT NULL` so the entity stays writable afterward. Before the
/// fix, the second `create_record` below 500s with `AppError::internal`
/// wrapping a raw Postgres not-null-violation — exactly what
/// `ai_agent`/`is_template` did live.
#[test]
fn retiring_a_required_attribute_relaxes_not_null_for_future_inserts() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_user(&system).await;
        let app = full_app(system);
        let (entity_id, entity_logicalname) = seed_entity(&app, &admin_cookie).await;
        let field_id = create_required_field(&app, &admin_cookie, entity_id).await;
        create_optional_field(&app, &admin_cookie, entity_id).await;

        // Baseline: the field is genuinely enforced while active.
        let resp = create_record(
            &app,
            &admin_cookie,
            &entity_logicalname,
            serde_json::json!({ "note": "x" }),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a required field must reject a record that omits it while still active"
        );

        // D-788: the DELETE is a real delete now (200 with the result; the
        // column goes with the attribute), so a later insert cannot trip over
        // it either.
        let status = delete_field(&app, &admin_cookie, entity_id, field_id).await;
        assert_eq!(status, StatusCode::OK);

        // The regression: a record with no value for the now-retired field must
        // succeed, not 500 on the leftover NOT NULL.
        let resp = create_record(
            &app,
            &admin_cookie,
            &entity_logicalname,
            serde_json::json!({ "note": "x" }),
        )
        .await;
        let status = resp.status();
        let body = body_json(resp).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "retiring a required attribute must relax its physical NOT NULL, not just its metadata: {body:?}"
        );
    })
}

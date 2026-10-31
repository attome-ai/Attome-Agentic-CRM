//! A1-T4: entity inheritance by copy-down. An entity created with
//! `extends_entity_id` gets copies of its base's fields, a field later added
//! to the base appears on it, a base field's rename and delete follow on the
//! copy, and a copy's type is the base's to change.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `attribute_retire.rs`.
//!
//! ```powershell
//! cargo test -p attome-api --test entity_inheritance -- --test-threads=1
//! ```

#![recursion_limit = "512"]
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

    let mut config = test_config();
    // Deleting a field that holds values archives them sealed under this
    // ring; without one the delete is refused (`archive_key_missing`).
    config.metadata.recovery_archive_key_encryption_key = KeyRing::single("12".repeat(32));
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
        .bind(format!("entity-inheritance-test-{user_id}"))
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

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// Creates an entity, extending `base` when given.
async fn create_entity(app: &axum::Router, cookie: &str, base: Option<Uuid>) -> (Uuid, String) {
    let logicalname = format!("inh_{}", Uuid::now_v7().simple());
    let mut body = serde_json::json!({ "logicalname": logicalname, "name": "Inheritance Test" });
    if let Some(base) = base {
        body["extends_entity_id"] = Value::String(base.to_string());
    }
    let (status, body) = send(
        app,
        json_request("POST", "/api/v1/admin/entities".into(), cookie, body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");
    (body["id"].as_str().unwrap().parse().unwrap(), logicalname)
}

async fn create_field(app: &axum::Router, cookie: &str, entity_id: Uuid, name: &str) -> Uuid {
    let (status, body) = send(
        app,
        json_request(
            "POST",
            format!("/api/v1/admin/entities/{entity_id}/fields"),
            cookie,
            serde_json::json!({ "logicalname": name, "name": name, "field_type": "text" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body:?}");
    body["id"].as_str().unwrap().parse().unwrap()
}

/// The entity's detail: `extends_entity_id` and its fields by logical name.
async fn entity_detail(app: &axum::Router, cookie: &str, entity_id: Uuid) -> Value {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/admin/entities/{entity_id}"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(app, req).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    body
}

fn field<'a>(detail: &'a Value, name: &str) -> Option<&'a Value> {
    detail["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["logicalname"] == name)
}

async fn write_record(app: &axum::Router, cookie: &str, entity: &str, body: Value) -> StatusCode {
    send(
        app,
        json_request("POST", format!("/api/v1/{entity}"), cookie, body),
    )
    .await
    .0
}

#[test]
fn child_gets_base_columns() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let cookie = seed_user(&system).await;
        let app = system.app.clone();
        let (base_id, _) = create_entity(&app, &cookie, None).await;
        create_field(&app, &cookie, base_id, "plate").await;

        let (child_id, child) = create_entity(&app, &cookie, Some(base_id)).await;
        let detail = entity_detail(&app, &cookie, child_id).await;
        assert_eq!(detail["extends_entity_id"], base_id.to_string());
        assert!(field(&detail, "plate").is_some(), "{detail:?}");
        // The copy is a real column of the child's own table.
        assert_eq!(
            write_record(
                &app,
                &cookie,
                &child,
                serde_json::json!({ "plate": "AB-123" })
            )
            .await,
            StatusCode::CREATED
        );

        // A base that does not exist is refused before anything is written.
        let (status, _) = send(
            &app,
            json_request(
                "POST",
                "/api/v1/admin/entities".into(),
                &cookie,
                serde_json::json!({
                    "logicalname": format!("inh_{}", Uuid::now_v7().simple()),
                    "name": "Orphan",
                    "extends_entity_id": Uuid::now_v7(),
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    })
}

#[test]
fn base_attribute_copied_down() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let cookie = seed_user(&system).await;
        let app = system.app.clone();
        let (base_id, _) = create_entity(&app, &cookie, None).await;
        let (child_id, child) = create_entity(&app, &cookie, Some(base_id)).await;
        let (grandchild_id, _) = create_entity(&app, &cookie, Some(child_id)).await;

        // A field added to the base appears on every entity below it.
        let tier = create_field(&app, &cookie, base_id, "tier").await;
        let detail = entity_detail(&app, &cookie, child_id).await;
        let copy: Uuid = field(&detail, "tier").expect("copied to the child")["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(field(&entity_detail(&app, &cookie, grandchild_id).await, "tier").is_some());
        assert_eq!(
            write_record(&app, &cookie, &child, serde_json::json!({ "tier": "gold" })).await,
            StatusCode::CREATED
        );

        // A name a child already uses is refused on the base up front.
        create_field(&app, &cookie, child_id, "nickname").await;
        let (status, _) = send(
            &app,
            json_request(
                "POST",
                format!("/api/v1/admin/entities/{base_id}/fields"),
                &cookie,
                serde_json::json!({ "logicalname": "nickname", "name": "Nickname", "field_type": "text" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // The copy's type is the base's to change.
        let (status, body) = send(
            &app,
            json_request(
                "POST",
                format!("/api/v1/admin/entities/{child_id}/fields/{copy}/change-type"),
                &cookie,
                serde_json::json!({ "field_type": "number" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body:?}");

        // A rename of the base field follows on the copies.
        let (status, body) = send(
            &app,
            json_request(
                "POST",
                format!("/api/v1/admin/entities/{base_id}/fields/{tier}/rename"),
                &cookie,
                serde_json::json!({ "new_name": "level" }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        let detail = entity_detail(&app, &cookie, child_id).await;
        assert!(
            field(&detail, "level").is_some() && field(&detail, "tier").is_none(),
            "{detail:?}"
        );
        assert!(field(&entity_detail(&app, &cookie, grandchild_id).await, "level").is_some());

        // And so does its delete.
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/api/v1/admin/entities/{base_id}/fields/{tier}"))
            .header("cookie", &cookie)
            .header("origin", "http://localhost:4200")
            .header("sec-fetch-site", "same-origin")
            .body(Body::empty())
            .unwrap();
        let (status, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert!(field(&entity_detail(&app, &cookie, child_id).await, "level").is_none());
        assert!(field(&entity_detail(&app, &cookie, grandchild_id).await, "level").is_none());
    })
}

//! M9-T2 — approval on change: a process that starts on `change` holds an
//! update of a watched attribute (here `discount > 20`) until a second
//! person approves it, writes the rest of the update at once, refuses a
//! second change while one waits, and writes the held value on approval.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis, as `jobs_admin.rs`.
//!
//! ```powershell
//! cargo test -p attome-api --test approval_on_change -- --test-threads=1
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
use axum::http::{Request, StatusCode};
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
            "security": {{ "bootstrap_admin_email": null }}
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

async fn seed_user(system: &TestSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("approval-on-change-test-{user_id}"))
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

fn post(uri: &str, cookie: &str, body: Option<serde_json::Value>) -> Request<Body> {
    let builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

fn get(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

async fn json_of(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn patch(uri: &str, cookie: &str, row_version: i64, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("if-match", format!("\"{row_version}\""))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A throwaway entity with a `title` (text) and `discount` (number) field.
async fn provision_entity(app: &axum::Router, admin_cookie: &str) -> String {
    let logicalname = format!("aoc_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(post(
            "/api/v1/admin/entities",
            admin_cookie,
            Some(serde_json::json!({ "logicalname": logicalname, "name": "Approval On Change" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity_id = json_of(res).await["id"].as_str().unwrap().to_owned();
    for (ln, ft) in [("title", "text"), ("discount", "number")] {
        let res = app
            .clone()
            .oneshot(post(
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                admin_cookie,
                Some(serde_json::json!({ "logicalname": ln, "name": ln, "field_type": ft })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create field {ln}");
    }
    logicalname
}

fn as_number(v: &serde_json::Value) -> f64 {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(f64::NAN)
}

#[test]
fn approval_on_change_holds_a_discount_above_twenty_until_approved() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let db = system.state().base.db.clone();
        let (_requester, requester_cookie) = seed_user(&system, true).await;
        let (approver, approver_cookie) = seed_user(&system, true).await;
        let app = full_app(system);
        let entity = provision_entity(&app, &requester_cookie).await;

        let res = app
            .clone()
            .oneshot(post(
                "/api/v1/admin/approval-processes",
                &requester_cookie,
                Some(serde_json::json!({
                    "name": "Discount above 20%",
                    "entity_logicalname": entity,
                    "entry_condition": "discount > 20",
                    "plan": { "steps": [{
                        "mode": "any",
                        "approvers": [format!("user:{approver}")],
                        "sla_minutes": 60,
                        "on_timeout": "escalate",
                    }] },
                    "lock_record": false,
                    "starts_on": "change",
                    "watched_attributes": ["discount"],
                })),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "create the change process"
        );

        let res = app
            .clone()
            .oneshot(post(
                &format!("/api/v1/{entity}"),
                &requester_cookie,
                Some(serde_json::json!({ "title": "deal", "discount": 10 })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create the record");
        let record = json_of(res).await;
        let record_id = record["id"].as_str().unwrap().to_owned();
        let row_version = record["row_version"].as_i64().unwrap();

        // A discount within the limit is written at once.
        let res = app
            .clone()
            .oneshot(patch(
                &format!("/api/v1/{entity}/{record_id}"),
                &requester_cookie,
                row_version,
                serde_json::json!({ "discount": 15 }),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::OK,
            "a 15% discount needs no approval"
        );
        let updated = json_of(res).await;
        assert!(updated.get("held_attributes").is_none());
        assert_eq!(as_number(&updated["data"]["discount"]), 15.0);
        let row_version = updated["row_version"].as_i64().unwrap();

        // Above the limit: the discount is held, the title is written.
        let res = app
            .clone()
            .oneshot(patch(
                &format!("/api/v1/{entity}/{record_id}"),
                &requester_cookie,
                row_version,
                serde_json::json!({ "discount": 25, "title": "deal, revised" }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let held = json_of(res).await;
        assert_eq!(held["held_attributes"], serde_json::json!(["discount"]));
        assert_eq!(
            as_number(&held["data"]["discount"]),
            15.0,
            "the stored value stays"
        );
        assert_eq!(held["data"]["title"], "deal, revised");
        let request_id: Uuid = held["approval_request_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let row_version = held["row_version"].as_i64().unwrap();

        // A second change while the first waits is refused.
        let res = app
            .clone()
            .oneshot(patch(
                &format!("/api/v1/{entity}/{record_id}"),
                &requester_cookie,
                row_version,
                serde_json::json!({ "discount": 30 }),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);

        // The approver approves; the held discount is written.
        let request_version: i64 =
            sqlx::query_scalar("SELECT row_version FROM approval_request WHERE id = $1")
                .bind(request_id)
                .fetch_one(&db)
                .await
                .unwrap();
        let res = app
            .clone()
            .oneshot(post(
                &format!("/api/v1/admin/approvals/{request_id}/decide"),
                &approver_cookie,
                Some(serde_json::json!({ "decision": "approve", "row_version": request_version })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{:?}", json_of(res).await);

        let res = app
            .clone()
            .oneshot(get(
                &format!("/api/v1/{entity}/{record_id}"),
                &requester_cookie,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let after = json_of(res).await;
        assert_eq!(
            as_number(&after["data"]["discount"]),
            25.0,
            "approval writes the held value"
        );
        assert_eq!(after["data"]["title"], "deal, revised");
        let status: String =
            sqlx::query_scalar("SELECT status FROM approval_request WHERE id = $1")
                .bind(request_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(status, "executed");
    });
}

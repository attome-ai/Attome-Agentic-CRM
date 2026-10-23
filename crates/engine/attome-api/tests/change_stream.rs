//! L7-T3: an S2S identity reads its change-stream subscription in commit
//! order, filtered by operation and by what its service user may read;
//! nobody else reads it, and an ended subscription answers 410.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), as `attribute_retire.rs`.
//!
//! ```powershell
//! cargo test -p attome-api --test change_stream -- --test-threads=1
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

async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

fn get(uri: String, cookie: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

async fn entity_with_title(app: &axum::Router, admin: &str, prefix: &str) -> String {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let (status, body) = send(
        app,
        json_request(
            "POST",
            "/api/v1/admin/entities".into(),
            admin,
            serde_json::json!({ "logicalname": logicalname, "name": "Change Stream Test" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let entity_id = body["id"].as_str().unwrap().to_owned();
    let (status, body) = send(
        app,
        json_request(
            "POST",
            format!("/api/v1/admin/entities/{entity_id}/fields"),
            admin,
            serde_json::json!({ "logicalname": "title", "name": "Title", "field_type": "text" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    logicalname
}

async fn create(app: &axum::Router, admin: &str, entity: &str, title: &str) -> Value {
    let (status, body) = send(
        app,
        json_request(
            "POST",
            format!("/api/v1/{entity}"),
            admin,
            serde_json::json!({ "title": title }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

#[test]
fn subscriber_reads_in_order_filtered_by_permission() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_user(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let readable = entity_with_title(&app, &admin_cookie, "csa").await;
        let hidden = entity_with_title(&app, &admin_cookie, "csb").await;

        // The S2S identity's service user may read the first entity only.
        let service_user = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO user_account (id, user_name, email, is_active) \
             VALUES ($1, $2, $2 || '@test.invalid', true)",
        )
        .bind(service_user)
        .bind(format!("change-stream-{service_user}"))
        .execute(&db)
        .await
        .unwrap();
        let granted = sqlx::query(
            "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
             SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
        )
        .bind(service_user)
        .bind(format!("{readable}.read"))
        .execute(&db)
        .await
        .unwrap();
        assert_eq!(
            granted.rows_affected(),
            1,
            "the entity has a read privilege"
        );
        let (status, client) = send(
            &app,
            json_request(
                "POST",
                "/api/v1/admin/s2s/clients".into(),
                &admin_cookie,
                serde_json::json!({
                    "client_id": format!("cs-{}", Uuid::now_v7().simple()),
                    "name": "change stream client",
                    "service_user_ref": service_user,
                }),
            ),
        )
        .await;
        assert!(status.is_success(), "{status} {client}");
        let (status, sub) = send(
            &app,
            json_request(
                "POST",
                "/api/v1/change-stream/subscriptions".into(),
                &admin_cookie,
                serde_json::json!({
                    "name": "erp feed",
                    "client_ref": client["id"],
                    "entities": [readable, hidden],
                    "operations": ["create", "update"],
                    "payload": "changes",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{sub}");
        let sub_id = sub["id"].as_str().unwrap().to_owned();
        let identity = session_cookie(service_user);

        // Start from now.
        let (status, start) = send(
            &app,
            get(format!("/api/v1/change-stream/{sub_id}/events"), &identity),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{start}");
        assert_eq!(start["events"], serde_json::json!([]));
        let cursor = start["next_cursor"].as_str().unwrap().to_owned();

        let first = create(&app, &admin_cookie, &readable, "one").await;
        create(&app, &admin_cookie, &hidden, "not for this identity").await;
        let second = create(&app, &admin_cookie, &readable, "two").await;
        let first_id = first["id"].as_str().unwrap().to_owned();
        let (status, body) = send(
            &app,
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/v1/{readable}/{first_id}"))
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .header("origin", "http://localhost:4200")
                .header("sec-fetch-site", "same-origin")
                .header("if-match", format!("\"{}\"", first["row_version"]))
                .body(Body::from(
                    serde_json::json!({ "title": "one, edited" }).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // The feed shows an event once every earlier transaction finished.
        let mut events = Vec::new();
        for _ in 0..20 {
            let (status, page) = send(
                &app,
                get(
                    format!(
                        "/api/v1/change-stream/{sub_id}/events?cursor={}&limit=50",
                        urlencode(&cursor)
                    ),
                    &identity,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{page}");
            events = page["events"].as_array().unwrap().clone();
            if events.len() >= 3 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        let seen: Vec<(String, String)> = events
            .iter()
            .map(|e| {
                (
                    e["record_id"].as_str().unwrap().to_owned(),
                    e["operation"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                (first_id.clone(), "create".to_owned()),
                (
                    second["id"].as_str().unwrap().to_owned(),
                    "create".to_owned()
                ),
                (first_id, "update".to_owned()),
            ],
            "in commit order, and nothing of the entity it may not read"
        );
        assert!(events.iter().all(|e| e["entity"] == readable.as_str()));
        assert!(
            events[2]["changed_attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a == "title"),
            "{events:?}"
        );

        // Nobody but the identity reads it.
        let (status, _) = send(
            &app,
            get(
                format!("/api/v1/change-stream/{sub_id}/events"),
                &admin_cookie,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // An ended subscription asks for a resync.
        let (status, body) = send(
            &app,
            json_request(
                "PATCH",
                format!("/api/v1/change-stream/subscriptions/{sub_id}"),
                &admin_cookie,
                serde_json::json!({ "row_version": sub["row_version"], "is_active": false }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = send(
            &app,
            get(
                format!(
                    "/api/v1/change-stream/{sub_id}/events?cursor={}",
                    urlencode(&cursor)
                ),
                &identity,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::GONE, "{body}");
        assert_eq!(body["error"], "resync_needed");
    })
}

fn urlencode(raw: &str) -> String {
    raw.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

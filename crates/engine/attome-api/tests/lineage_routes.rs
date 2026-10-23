//! L5-T4: the lineage graph routes walk down and up, compare two graph
//! versions, and count the nodes a caller may not see.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), as `attribute_retire.rs`.
//!
//! ```powershell
//! cargo test -p attome-api --test lineage_routes -- --test-threads=1
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

async fn get_json(app: &axum::Router, uri: String, cookie: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    (status, body_json(resp).await)
}

fn keys(graph: &Value) -> Vec<String> {
    graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["key"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn downstream_upstream_compare_and_hidden_counts() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_user(&system).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);

        // A metric reads invoice-like data; a dashboard shows the metric.
        let entity = format!("lrt_{}", Uuid::now_v7().simple());
        let metric = Uuid::now_v7();
        let dashboard = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO metadata_reference \
                 (from_kind, from_ref, from_label, to_entity, to_attribute, edge_kind, confidence) \
             VALUES ('metric', $1, 'Routes revenue', $2, 'amount', 'reads', 'parsed')",
        )
        .bind(metric)
        .bind(&entity)
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO metadata_reference \
                 (from_kind, from_ref, from_label, to_entity, to_attribute, to_kind, to_ref) \
             VALUES ('dashboard', $1, 'Routes board', $2, '', 'metric', $3)",
        )
        .bind(dashboard)
        .bind(format!("metric:{metric}"))
        .bind(metric)
        .execute(&db)
        .await
        .unwrap();
        // An edge the metric had before a publish replaced it (valid 0..5).
        sqlx::query(
            "INSERT INTO lineage_edge_history \
                 (from_kind, from_ref, from_label, to_entity, to_attribute, edge_kind, \
                  confidence, valid_from, valid_to) \
             VALUES ('metric', $1, 'Routes revenue', $2, 'old_amount', 'reads', 'parsed', 0, 5)",
        )
        .bind(metric)
        .bind(&entity)
        .execute(&db)
        .await
        .unwrap();

        // Downstream of the attribute: the metric, then the dashboard.
        let (status, down) = get_json(
            &app,
            format!("/api/v1/lineage/entity/{entity}.amount?direction=down&depth=3"),
            &admin_cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{down}");
        let found = keys(&down);
        assert!(found.contains(&format!("metric:{metric}")), "{down}");
        assert!(found.contains(&format!("dashboard:{dashboard}")), "{down}");
        assert_eq!(down["hidden"], 0);

        // Only dashboards: the metric is not walked through.
        let (_, only) = get_json(
            &app,
            format!("/api/v1/lineage/entity/{entity}.amount?kinds=dashboard"),
            &admin_cookie,
        )
        .await;
        assert_eq!(keys(&only).len(), 1, "{only}");

        // Upstream of the dashboard: the metric, then the data it reads.
        let (status, up) = get_json(
            &app,
            format!("/api/v1/lineage/dashboard/{dashboard}?direction=up&depth=3"),
            &admin_cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{up}");
        let found = keys(&up);
        assert!(found.contains(&format!("metric:{metric}")), "{up}");
        assert!(found.contains(&format!("entity:{entity}.amount")), "{up}");

        // As of version 1 the metric also read the replaced attribute.
        let (_, then) = get_json(
            &app,
            format!("/api/v1/lineage/metric/{metric}?direction=up&version=1"),
            &admin_cookie,
        )
        .await;
        assert!(
            keys(&then).contains(&format!("entity:{entity}.old_amount")),
            "{then}"
        );
        let (status, diff) = get_json(
            &app,
            "/api/v1/lineage/compare?from=1&to=10".into(),
            &admin_cookie,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{diff}");
        assert!(
            diff["removed"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["to"] == format!("entity:{entity}.old_amount")),
            "{diff}"
        );

        // A person who may read nothing here sees counts only.
        let plain = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO user_account (id, user_name, email, is_active) \
             VALUES ($1, $2, $2 || '@test.invalid', true)",
        )
        .bind(plain)
        .bind(format!("lineage-plain-{plain}"))
        .execute(&db)
        .await
        .unwrap();
        let (status, seen) = get_json(
            &app,
            format!("/api/v1/lineage/entity/{entity}.amount?depth=3"),
            &session_cookie(plain),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{seen}");
        assert_eq!(keys(&seen).len(), 1, "only the start: {seen}");
        assert_eq!(
            seen["hidden"], 1,
            "the metric is counted; the dashboard is behind it"
        );
        let (status, _) = get_json(
            &app,
            "/api/v1/lineage/cleanup".into(),
            &session_cookie(plain),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    })
}

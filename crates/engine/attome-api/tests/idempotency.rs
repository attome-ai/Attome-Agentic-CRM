//! Enterprise-audit remediation (Phase 2.4): integration coverage for
//! `attome_server::middleware::idempotency`'s method+path scoping fix — proves
//! a client-supplied `X-Idempotency-Key` reused across two different
//! endpoints no longer replays the first endpoint's cached response against
//! the second (the audit's core complaint: the digest used to be
//! `user_id:key` only), while same-endpoint replay still works as before.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as
//! `entity_round_trip.rs`. Run manually against a throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test idempotency -- --test-threads=1
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
use attome_testkit::point_config_at;
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
        .build()
        .await
        .expect("build EngineSystem");
    // D-143: entity_crud/bulk routes are now license-gated (now MODULE_CORE, was MODULE_ENTITY pre-D-222) —
    // grant every module so this suite exercises them the same way a fully
    // licensed deployment would.
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));
    Some(system)
}

/// See `entity_round_trip.rs`'s identical helper: `oneshot()` requests carry
/// no `Sec-Fetch-Site`/`Origin`, which `csrf_protect` fails closed on for
/// cookie-authenticated unsafe methods by design.
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
        .bind(format!("idem-test-admin-{user_id}"))
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

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Same idempotency key, same endpoint, same body — the second request must
/// replay the first's cached response (same created entity id, no second
/// entity actually created) rather than erroring or creating a duplicate.
/// This is the behavior the fix must NOT change.
#[test]
fn same_key_same_endpoint_replays_the_cached_response() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);
        let idem_key = format!("idem-{}", Uuid::now_v7());
        let logicalname = format!("idem_same_{}", Uuid::now_v7().simple());

        let build_req = || {
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/entities")
                .header("cookie", &admin_cookie)
                .header("content-type", "application/json")
                .header("x-idempotency-key", &idem_key)
                .body(Body::from(format!(
                    r#"{{"logicalname":"{logicalname}","name":"Idem Same Endpoint"}}"#
                )))
                .unwrap()
        };

        let res1 = app
            .clone()
            .oneshot(build_req())
            .await
            .expect("first request");
        assert_eq!(res1.status(), StatusCode::CREATED);
        let body1 = body_json(res1).await;
        let id1 = body1["id"].as_str().expect("entity id").to_owned();

        let res2 = app
            .clone()
            .oneshot(build_req())
            .await
            .expect("second request");
        assert_eq!(
            res2.status(),
            StatusCode::CREATED,
            "the replayed response must carry the same cached status"
        );
        let body2 = body_json(res2).await;
        assert_eq!(
            body2["id"].as_str().unwrap(),
            id1,
            "the second request must replay the first's cached response \
         (same entity id), not create a second entity"
        );
    })
}

/// The same idempotency key cannot be reused for a different payload.  The
/// middleware must reject the request instead of replaying the original
/// response or running a second operation.
#[test]
fn same_key_with_a_different_body_is_rejected() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let admin_cookie = seed_admin(&system).await;
        let app = full_app(system);
        let idem_key = format!("idem-{}", Uuid::now_v7());
        let logicalname_a = format!("idem_cross_a_{}", Uuid::now_v7().simple());
        let logicalname_b = format!("idem_cross_b_{}", Uuid::now_v7().simple());

        let req_a = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("x-idempotency-key", &idem_key)
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname_a}","name":"Idem Cross A"}}"#
            )))
            .unwrap();
        let res_a = app
            .clone()
            .oneshot(req_a)
            .await
            .expect("first entity create");
        assert_eq!(res_a.status(), StatusCode::CREATED);
        let body_a = body_json(res_a).await;
        let id_a = body_a["id"].as_str().expect("entity id").to_owned();

        // Same idempotency key, same method, but a different logical resource
        // (a different entity being created) — must be treated as a genuinely
        // new request, not a replay of the first.
        let req_b = Request::builder()
            .method("POST")
            .uri("/api/v1/admin/entities")
            .header("cookie", &admin_cookie)
            .header("content-type", "application/json")
            .header("x-idempotency-key", &idem_key)
            .body(Body::from(format!(
                r#"{{"logicalname":"{logicalname_b}","name":"Idem Cross B"}}"#
            )))
            .unwrap();
        let res_b = app
            .clone()
            .oneshot(req_b)
            .await
            .expect("second entity create");

        // A client key denotes one operation.  A different body with the same
        // key and route must therefore fail before the entity-create handler
        // executes, rather than replaying entity A or creating entity B.
        assert_eq!(res_b.status(), StatusCode::CONFLICT);

        // A GET is outside the idempotency gate, regardless of any client key.
        let req_get = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/admin/entities/{id_a}"))
            .header("cookie", &admin_cookie)
            .header("x-idempotency-key", &idem_key)
            .body(Body::empty())
            .unwrap();
        let res_get = app.clone().oneshot(req_get).await.expect("get entity");
        assert_eq!(
            res_get.status(),
            StatusCode::OK,
            "a GET is never idempotency-gated (only mutating verbs are), so this \
         must succeed as an ordinary read regardless of the reused key"
        );
    })
}

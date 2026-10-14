//! P-health-readiness — `GET /health/dependencies`.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same convention as `authz.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test system_health -- --test-threads=1
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
use tower::ServiceExt;
use uuid::Uuid;

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
    let ring = KeyRing::single("test-only-throwaway-secret-do-not-use-in-prod".to_string());
    let token = attome_auth::create_token(&claims, &ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

/// A user holding `system.admin`, and a session cookie for them.
async fn seed_admin(db: &attome_db::DbPool) -> String {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("system-health-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin");
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin is seeded");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(privilege_id)
    .execute(db)
    .await
    .expect("grant system.admin");
    session_cookie(user_id)
}

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
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "enabled": false, "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "test@test.local",
                "smtp_from_name": "test", "smtp_use_tls": false
            }},
            "google_ai": {{
                "api_key": "", "base_url": "https://example.invalid",
                "default_model": "none", "timeout_seconds": 1
            }},
            "llm_api": {{}},
            "external_api": {{}},
            "s2s": {{ "enabled": false }},
            "security": {{ "bootstrap_admin_email": null }},
            "audit": {{ "chainer_enabled": false }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );

    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

async fn test_system() -> Option<EngineSystem> {
    attome_testkit::migrated_db_url()?;

    let config = test_config();
    // Pinned false in `test_config`, not inherited: D-316 flipped the code
    // default to true, and this suite asserts the `"enabled": false` branch of
    // `/health/dependencies`'s `audit_chainer` block below.
    assert!(
        !config.audit.chainer_enabled,
        "test config must pin chainer_enabled to false"
    );
    assert!(
        !config.email.enabled,
        "test config must keep email disabled for this suite"
    );

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

fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        // `/health/ready` is NOT part of `core_routes()`/`add_bundle` — it moved
        // into `attome_server::liveness_routes()`, which is opt-in via this
        // builder method so the probe is merged AFTER the Redis/state-dependent
        // layers and a Redis blip can never turn it into a 500. Without this
        // line the route simply is not mounted, and
        // `dependencies_endpoint_never_affects_health_ready` below asserts 200
        // against a 404. Mirrors `crates/server/src/main.rs` and
        // `attome-server/tests/health.rs`, which both already do this.
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
}

/// U9-T2: the dependency report is for administrators. Without a session it
/// is refused; with an administrator's it answers 200, and it no longer names
/// the modules this deployment has on.
#[tokio::test]
async fn dependencies_endpoint_answers_administrators_only() {
    let system = skip_if_no_db!(test_system().await);
    let cookie = seed_admin(&system.state().base.db).await;
    let app = full_app(system);

    let anonymous = Request::builder()
        .method("GET")
        .uri("/health/dependencies")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(anonymous).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method("GET")
        .uri("/health/dependencies")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(body["audit_chainer"]["enabled"], false);
    assert_eq!(body["email"]["enabled"], false);
    assert_eq!(body["email"]["reachable"], serde_json::Value::Null);
    assert!(body["storage"]["reachable"].is_boolean());
    // test_config() never sets storage.clamd_address, so it defaults to ""
    // (StorageSection::clamd_address's #[serde(default)]) — the disabled
    // shape, no TCP connection attempted.
    assert_eq!(body["clamav"]["enabled"], false);
    assert!(body["jobs"]["fast"].is_object());
    assert!(body["jobs"]["batch"].is_object());
    assert!(body.get("modules").is_none(), "no licence or module state");
}

/// This endpoint must never affect `/health/ready`'s own status code —
/// hitting it (even repeatedly) must not change readiness.
#[tokio::test]
async fn dependencies_endpoint_never_affects_health_ready() {
    let system = skip_if_no_db!(test_system().await);
    let cookie = seed_admin(&system.state().base.db).await;
    let app = full_app(system);

    for _ in 0..3 {
        let req = Request::builder()
            .method("GET")
            .uri("/health/dependencies")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // /health/ready's own gate (DB/Redis/registry) is unaffected by any of
    // the calls above -- still reachable and still evaluating the same
    // three things it always has, regardless of storage/email/jobs/audit.
    // `EngineSystem::builder(...).build()` (in `test_system()`) already runs
    // the metadata-registry pre-warm step, so `registry_ready` is true and
    // DB/Redis are live against the test stack -- 200 is the correct, fully
    // healthy reading here.
    let ready_req = Request::builder()
        .method("GET")
        .uri("/health/ready")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(ready_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["db"], true);
    assert_eq!(body["redis"], true);
    assert_eq!(body["registry"], true);
}

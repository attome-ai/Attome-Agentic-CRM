//! Integration test for the Plan 1.2 metadata registry cache + Redis pub/sub
//! invalidation: an entity/attribute created via one node's admin API must
//! become usable on a second, independent node after the pub/sub round-trip
//! — without that second node ever querying Postgres for the schema itself.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`REDIS_URL` or
//! `TEST_REDIS_HOST`/`TEST_REDIS_PORT`, defaulting to `localhost:6379`) —
//! skips (loudly) when `DATABASE_URL` is unset, except under `CI`, per the P1.8
//! testing-baseline convention. NOT wired into any CI run yet (no
//! `attomedb_test` harness exists — see P1.8); run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test metadata_cache -- --test-threads=1
//! ```
//!
//! Note on scope: this test exercises the on-message pub/sub path (the load-
//! bearing correctness property — a write becomes visible cross-node without
//! a per-request Postgres query). The on-reconnect self-heal path shares the
//! same re-check-then-rebuild code (`build_registry` + a `meta_version`
//! re-read) exercised here and by `attome-core`'s `build_registry` test;
//! actually forcing a live Redis disconnect/reconnect is exercised manually
//! (`docker compose up --scale server=N`, kill the Redis link, per
//! `/release-and-deploy`) rather than faked with test-only hooks that don't
//! exist on `EngineSystem` today.

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
use std::time::Duration;
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
                "metadata_registry_enabled": true
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

/// Builds one independent "node" — its own `EngineState`/registry/subscriber —
/// sharing the same Postgres + Redis as every other node built this way.
async fn test_node() -> Option<EngineSystem> {
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

/// csrf_protect (P-cookie-csrf-hardening) rejects a cookie-authenticated
/// unsafe-method request with neither a safe Sec-Fetch-Site nor an allow-
/// listed Origin — a real browser always sends the former, an in-process
/// `oneshot()` call sends neither. This file's `test_config()` has no `cors`
/// section (so no Origin would ever be allow-listed), so Sec-Fetch-Site is
/// the only viable signal — same fix a legitimate non-browser caller would
/// need in production, not a bypass of the check.
async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::HeaderName::from_static("sec-fetch-site"),
        axum::http::HeaderValue::from_static("same-origin"),
    );
    req
}

/// Builds the full assembled app the same way `main.rs` does (Plan 1.3):
/// inner (authn/authz/RateLimit/Idempotency) → s2s_authn → outer
/// (RequestId..BodyLimit). `core_routes()` alone is bare, middleware-free
/// routes as of this plan — using it directly would silently skip auth.
fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
}

/// Seeds a throwaway admin user on the given node. Returns the session cookie.
async fn seed_admin(system: &EngineSystem) -> String {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("metadata-cache-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let key = "system.admin";
    let privilege_id: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
        .bind(key)
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

#[tokio::test]
async fn write_on_one_node_becomes_visible_on_another_via_pubsub() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_b = skip_if_no_db!(test_node().await);

    let cookie_a = seed_admin(&node_a).await;
    let cookie_b = seed_admin(&node_b).await;

    let app_a = full_app(node_a);
    let app_b = full_app(node_b);

    let logicalname = format!("mc_test_{}", Uuid::now_v7().simple());

    // Create the entity on node A.
    let create_entity_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", &cookie_a)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"Metadata Cache Test"}}"#
        )))
        .unwrap();
    let res = app_a
        .clone()
        .oneshot(create_entity_req)
        .await
        .expect("create entity request");
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "entity creation on node A must succeed"
    );

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let entity: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entity_id = entity["id"].as_str().unwrap();

    // Add a text attribute on node A.
    let create_field_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", &cookie_a)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"note","name":"Note","field_type":"text"}"#,
        ))
        .unwrap();
    let res = app_a
        .clone()
        .oneshot(create_field_req)
        .await
        .expect("create field request");
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "field creation on node A must succeed"
    );

    // Node B has never queried Postgres for this schema — it only learns
    // about it via the meta_version pub/sub round-trip. Poll bounded: a
    // 404 means node B's registry doesn't know the entity yet; a 201 means
    // it rebuilt and the create succeeded end-to-end.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let last_status = loop {
        let create_record_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &cookie_b)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"note":"hello from node B"}"#))
            .unwrap();
        let res = app_b
            .clone()
            .oneshot(create_record_req)
            .await
            .expect("create record request on node B");
        let status = res.status();
        if status == StatusCode::CREATED || tokio::time::Instant::now() >= deadline {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    assert_eq!(
        last_status,
        StatusCode::CREATED,
        "node B must pick up the entity created on node A after the meta_version pub/sub round-trip"
    );
}

/// Plan 1.14: a burst of writes touching the same entity (a bulk field
/// import is the motivating case) must still leave node B with the full,
/// final state after catch-up — exercising `apply_change_log`'s dedupe-by-
/// `entity_ref` path, not just a single-row catch-up.
#[tokio::test]
async fn bulk_attribute_writes_on_one_entity_all_land_on_another_node() {
    let node_a = skip_if_no_db!(test_node().await);
    let node_b = skip_if_no_db!(test_node().await);

    let cookie_a = seed_admin(&node_a).await;
    let cookie_b = seed_admin(&node_b).await;

    let app_a = full_app(node_a);
    let app_b = full_app(node_b);

    let logicalname = format!("mc_bulk_test_{}", Uuid::now_v7().simple());

    let create_entity_req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", &cookie_a)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"Bulk Metadata Cache Test"}}"#
        )))
        .unwrap();
    let res = app_a
        .clone()
        .oneshot(create_entity_req)
        .await
        .expect("create entity request");
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "entity creation on node A must succeed"
    );

    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let entity: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entity_id = entity["id"].as_str().unwrap().to_owned();

    // Five attribute creates back-to-back on the same entity — each appends
    // its own change-log row, but they all patch the same registry key.
    let field_names = ["alpha", "beta", "gamma", "delta", "epsilon"];
    for field in field_names {
        let create_field_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
            .header("cookie", &cookie_a)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"logicalname":"{field}","name":"{field}","field_type":"text"}}"#
            )))
            .unwrap();
        let res = app_a
            .clone()
            .oneshot(create_field_req)
            .await
            .expect("create field request");
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "field '{field}' creation on node A must succeed"
        );
    }

    // Node B only learns of the entity and all five fields via catch-up.
    // Poll until a record carrying every field is accepted (a field missing
    // from node B's registry would 422/be silently dropped by the generic
    // CRUD dispatcher's column binding, so a CREATED response here is proof
    // every attribute — not just the entity — made it across).
    let record_json = r#"{"alpha":"a","beta":"b","gamma":"c","delta":"d","epsilon":"e"}"#;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let last_status = loop {
        let create_record_req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/{logicalname}"))
            .header("cookie", &cookie_b)
            .header("content-type", "application/json")
            .body(Body::from(record_json))
            .unwrap();
        let res = app_b
            .clone()
            .oneshot(create_record_req)
            .await
            .expect("create record request on node B");
        let status = res.status();
        if status == StatusCode::CREATED || tokio::time::Instant::now() >= deadline {
            break status;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };

    assert_eq!(
        last_status,
        StatusCode::CREATED,
        "node B must pick up the entity and all five attributes from the bulk write via incremental catch-up"
    );
}

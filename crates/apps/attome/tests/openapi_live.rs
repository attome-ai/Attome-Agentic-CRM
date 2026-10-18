//! S2-T14: `GET /api/v1/openapi.json` is filtered per caller. Drives the
//! fully composed router (the harness of `admin_routes_forbid_non_admin.rs`)
//! with the `project` module switched off: a non-admin caller sees no
//! `/api/v1/admin` path and no `project` operation, an administrator sees the
//! admin paths, and a repeat call with the ETag in `If-None-Match` is a 304.
//!
//! Requires a throwaway Postgres (`DATABASE_URL`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`); skips without them.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use rand::distributions::{Alphanumeric, DistString};
use tower::ServiceExt;
use uuid::Uuid;

/// Every module but `project`.
fn all_but_project() -> attome_modules::ModuleBits {
    let mut bits = [u64::MAX; 4];
    bits[attome_modules::MODULE_PROJECT.word] &= !attome_modules::MODULE_PROJECT.mask;
    bits
}

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const THROWAWAY_PEPPER: &str = "test-only-throwaway-pepper-32-bytes-min";
const ALLOWED_ORIGIN: &str = "http://allowed.test";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 10,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5556, "dbname": "unused_overridden_by_env",
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
                "apikey_hash_pepper": "{pepper}",
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 100000, "authenticated_rpm": 100000 }},
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
            "cors": {{ "allowed_origins": ["{allowed_origin}"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        pepper = THROWAWAY_PEPPER,
        allowed_origin = ALLOWED_ORIGIN,
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

async fn test_app(config: AppConfig) -> Option<(axum::Router, AppState)> {
    attome_testkit::migrated_db_url()?;

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

    let base = AppState::new(
        config.clone(),
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    let state = EngineState::new(base);

    let system = attome::boot::register_engines(EngineSystem::builder(state))
        .build()
        .await
        .expect("build EngineSystem");
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            all_but_project(),
        )));

    let base_state = system.state().base.clone();
    let license = system.state().modules.clone();
    let auth_bundle = attome_server::RouteBundle::new(
        attome::auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );

    let openapi_bundle = attome_server::RouteBundle::new(
        attome::openapi::routes().with_state(system.state().clone()),
    );
    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle)
        .add_bundle(openapi_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

/// Creates a throwaway user plus an API key, returning the `Authorization`
/// header value. `admin` grants the reserved `system.admin` privilege.
async fn seed_principal(state: &AppState, admin: bool) -> String {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, created_at)
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(user_id)
    .bind(format!("authz-probe-{user_id}"))
    .bind(format!("authz-probe-{user_id}@example.invalid"))
    .execute(&state.db)
    .await
    .expect("insert throwaway user");

    if admin {
        let privilege_id: Uuid = sqlx::query_scalar(
            "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer)
             VALUES ($1, 'system.admin', 'System Admin', 'test', true, NOW(), 'project')
             ON CONFLICT (key) DO UPDATE SET is_active = true
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .fetch_one(&state.db)
        .await
        .expect("ensure system.admin privilege");

        sqlx::query(
            "INSERT INTO user_account_mm_privilege
                 (id, user_ref, privilege_ref, is_active, created_at)
             VALUES ($1, $2, $3, true, NOW())",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(privilege_id)
        .execute(&state.db)
        .await
        .expect("grant system.admin");
    }

    let public_key = format!(
        "atk_pub_{}",
        Alphanumeric.sample_string(&mut rand::thread_rng(), 20)
    );
    let secret = format!(
        "atk_sec_{}",
        Alphanumeric.sample_string(&mut rand::thread_rng(), 20)
    );
    let ring = attome_auth::PepperRing::new(0, THROWAWAY_PEPPER, &[]);
    sqlx::query(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash)
         VALUES ($1, 'authz-probe', $2, $3)",
    )
    .bind(user_id)
    .bind(&public_key)
    .bind(ring.hash(&secret))
    .execute(&state.db)
    .await
    .expect("insert throwaway api key");

    format!("ApiKey {public_key}:{secret}")
}

async fn get_doc(app: &axum::Router, auth: &str, etag: Option<&str>) -> axum::response::Response {
    let mut request = Request::builder()
        .method("GET")
        .uri("/api/v1/openapi.json")
        .header("authorization", auth);
    if let Some(etag) = etag {
        request = request.header(header::IF_NONE_MATCH, etag);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).expect("a JSON document")
}

fn modules_of(doc: &serde_json::Value) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for item in doc["paths"].as_object().expect("paths").values() {
        for operation in item.as_object().expect("path item").values() {
            if let Some(module) = operation.get("x-module").and_then(|m| m.as_str()) {
                out.insert(module.to_owned());
            }
        }
    }
    out
}

#[tokio::test]
async fn openapi_json_hides_admin_paths_from_non_admin() {
    let (app, state) = skip_if_no_db!(test_app(test_config()).await);
    let staff = seed_principal(&state, false).await;
    let admin = seed_principal(&state, true).await;

    let response = get_doc(&app, &staff, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get(header::ETAG)
        .expect("an ETag")
        .to_str()
        .unwrap()
        .to_owned();
    let doc = json_body(response).await;
    let paths = doc["paths"].as_object().expect("paths");
    assert!(paths.len() > 10, "the caller still sees the API");
    let admin_paths: Vec<&String> = paths
        .keys()
        .filter(|p| p.starts_with("/api/v1/admin"))
        .collect();
    assert!(admin_paths.is_empty(), "{admin_paths:?}");
    let modules = modules_of(&doc);
    assert!(!modules.contains("project"), "{modules:?}");

    // The same caller's repeat call with the ETag is a bodyless 304.
    let again = get_doc(&app, &staff, Some(&etag)).await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);

    // An administrator gets the admin paths, under another ETag.
    let response = get_doc(&app, &admin, Some(&etag)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let doc = json_body(response).await;
    assert!(
        doc["paths"]
            .as_object()
            .expect("paths")
            .keys()
            .any(|p| p.starts_with("/api/v1/admin")),
        "an administrator sees the admin paths"
    );
    assert!(
        !modules_of(&doc).contains("project"),
        "the module is still off"
    );
}

//! Q1-T4: sign-in providers over the admin API. A client secret goes in and
//! never comes back out; a configured provider is listed but cannot be
//! changed; only `system.admin` reaches the routes.
//!
//! ```powershell
//! cargo test -p attome-api --test oidc_providers_admin -- --test-threads=1
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
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
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
            "oidc": {{
                "providers": {{
                    "configured": {{
                        "display_name": "Configured", "issuer": "https://config.example",
                        "client_id": "configured", "client_secret": "configured-secret-value"
                    }}
                }},
                "client_secret_encryption_key": "{oidc_key}"
            }},
            "approval": {{ "required_actions": [] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        oidc_key = "ab".repeat(32),
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let mut config = test_config();
    point_config_at(&mut config, &throwaway_url);
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

async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(user_id)
        .bind(format!("oidc-admin-test-{user_id}"))
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

fn request(method: &str, cookie: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    let body = match body {
        Some(json) => {
            builder = builder.header("content-type", "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

async fn call(
    app: &axum::Router,
    cookie: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(request(method, cookie, uri, body))
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

const SECRET: &str = "never-shown-client-secret";

fn new_provider() -> Value {
    json!({
        "key": format!("screen-{}", &Uuid::now_v7().simple().to_string()[20..]),
        "display_name": "On screen",
        "issuer": "https://idp.example",
        "client_id": "client",
        "client_secret": SECRET,
        "preset": "okta",
    })
}

#[tokio::test]
async fn create_never_returns_secret() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin) = seed_user(&system, true).await;
    let base = system.state().base.clone();
    let app = full_app(system);

    let body = new_provider();
    let (status, created) = call(
        &app,
        &admin,
        "POST",
        "/api/v1/admin/security/oidc-providers",
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let text = created.to_string();
    assert!(!text.contains(SECRET), "{text}");
    assert!(created.get("client_secret").is_none());
    assert!(created.get("client_secret_enc").is_none());
    assert_eq!(created["secret_set"], json!(true));
    assert_eq!(created["secret_fingerprint"].as_str().unwrap().len(), 8);

    let (status, list) = call(
        &app,
        &admin,
        "GET",
        "/api/v1/admin/security/oidc-providers?page=1&page_size=200",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!list.to_string().contains(SECRET));
    let keys: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["key"].as_str())
        .collect();
    assert!(keys.contains(&body["key"].as_str().unwrap()));
    assert!(keys.contains(&"configured"));

    // The sign-in list (what /api/v1/auth/oidc/providers and every sign-in
    // read) follows at once on this node.
    let key = body["key"].as_str().unwrap();
    let entry = base
        .oidc_providers
        .get(key)
        .expect("the new provider signs in");
    assert_eq!(entry.config.client_secret.expose(), SECRET);

    // A new secret is accepted and still not shown; the fingerprint moves.
    let id = created["id"].as_str().unwrap();
    let (status, changed) = call(
        &app,
        &admin,
        "PATCH",
        &format!("/api/v1/admin/security/oidc-providers/{id}"),
        Some(json!({ "client_secret": "a-second-secret-value" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{changed}");
    assert!(!changed.to_string().contains("a-second-secret-value"));
    assert_ne!(changed["secret_fingerprint"], created["secret_fingerprint"]);
}

#[tokio::test]
async fn config_provider_cannot_be_patched() {
    let system = skip_if_no_db!(test_system().await);
    let (_, admin) = seed_user(&system, true).await;
    let app = full_app(system);

    for (method, body) in [
        ("PATCH", Some(json!({ "display_name": "Mine" }))),
        ("DELETE", None),
    ] {
        let (status, error) = call(
            &app,
            &admin,
            method,
            "/api/v1/admin/security/oidc-providers/configured",
            body,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{method} {error}");
        assert!(
            error.to_string().contains("provider_is_config_managed"),
            "{error}"
        );
    }
    let mut taken = new_provider();
    taken["key"] = json!("configured");
    let (status, _) = call(
        &app,
        &admin,
        "POST",
        "/api/v1/admin/security/oidc-providers",
        Some(taken),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn non_admin_gets_403() {
    let system = skip_if_no_db!(test_system().await);
    let (_, user) = seed_user(&system, false).await;
    let app = full_app(system);

    for (method, uri, body) in [
        ("GET", "/api/v1/admin/security/oidc-providers", None),
        ("GET", "/api/v1/admin/security/oidc-presets", None),
        (
            "POST",
            "/api/v1/admin/security/oidc-providers",
            Some(new_provider()),
        ),
    ] {
        let (status, _) = call(&app, &user, method, uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
}

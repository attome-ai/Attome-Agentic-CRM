//! Q10-T11: the screen and the API come from one decision. The menu
//! (`GET /api/v1/sidebar/get`) shows an item exactly when the API behind its
//! page admits the caller (an entity list needs `{entity}.read`, an admin page
//! its administration area), and a form's schema carries the operations the
//! record routes would admit (`allowed_actions`).
//!
//! ```powershell
//! cargo test -p attome-api --test screen_api_parity -- --test-threads=1
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
            "approval": {{ "required_actions": [] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
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
        .bind(format!("screen-parity-test-{user_id}"))
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

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn get_request(cookie: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap()
}

/// Holds exactly `privilege_keys`, granted directly (a direct grant reaches
/// every record of its entity).
async fn grant(system: &EngineSystem, user_id: Uuid, privilege_keys: &[&str]) {
    let db = &system.state().base.db;
    for key in privilege_keys {
        sqlx::query(
            "INSERT INTO privilege (id, key, name, is_active, created_at, owner_layer)              VALUES ($1, $2, $2, true, NOW(), 'project') ON CONFLICT (key) DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(key)
        .execute(db)
        .await
        .expect("ensure privilege");
        sqlx::query(
            "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at)              SELECT $1, $2, id, true, NOW() FROM privilege WHERE key = $3",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(key)
        .execute(db)
        .await
        .expect("grant privilege");
    }
}

/// Every route in a `GET /api/v1/sidebar/get` tree.
fn routes_in(nodes: &[Value], out: &mut Vec<String>) {
    for node in nodes {
        if let Some(route) = node["route"].as_str()
            && !route.is_empty()
        {
            out.push(route.to_owned());
        }
        if let Some(children) = node["child"].as_array() {
            routes_in(children, out);
        }
    }
}

async fn menu_routes(app: &axum::Router, cookie: &str) -> Vec<String> {
    let resp = app
        .clone()
        .oneshot(get_request(cookie, "/api/v1/sidebar/get"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let tree = body_json(resp).await;
    let mut routes = Vec::new();
    routes_in(tree.as_array().expect("sidebar tree"), &mut routes);
    routes
}

async fn status_of(app: &axum::Router, cookie: &str, uri: &str) -> StatusCode {
    app.clone()
        .oneshot(get_request(cookie, uri))
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn sidebar_hides_entity_without_read() {
    let system = skip_if_no_db!(test_system().await);
    let (user, cookie) = seed_user(&system, false).await;
    grant(&system, user, &["team.read"]).await;
    let app = full_app(system);

    let routes = menu_routes(&app, &cookie).await;
    assert!(
        routes.iter().any(|r| r == "/xrm/entity/team/list"),
        "team.read shows the Teams list: {routes:?}"
    );
    assert!(
        !routes.iter().any(|r| r == "/xrm/entity/role/list"),
        "no role.read hides the Roles list: {routes:?}"
    );
}

#[tokio::test]
async fn api_refuses_entity_hidden_in_sidebar() {
    let system = skip_if_no_db!(test_system().await);
    let (user, cookie) = seed_user(&system, false).await;
    grant(&system, user, &["team.read"]).await;
    let app = full_app(system);

    assert_eq!(
        status_of(&app, &cookie, "/api/v1/team").await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&app, &cookie, "/api/v1/role").await,
        StatusCode::FORBIDDEN,
        "the entity the menu hides is refused by the API"
    );
}

#[tokio::test]
async fn admin_menu_follows_the_area_its_api_requires() {
    let system = skip_if_no_db!(test_system().await);
    let (user, cookie) = seed_user(&system, false).await;
    grant(&system, user, &["admin.data_model"]).await;
    let app = full_app(system);

    let routes = menu_routes(&app, &cookie).await;
    assert!(
        routes.iter().any(|r| r == "/xrm/admin/entities"),
        "the DataModel area shows Entities: {routes:?}"
    );
    assert!(
        !routes.iter().any(|r| r == "/xrm/admin/settings"),
        "Settings needs the Deployment area: {routes:?}"
    );
    assert!(
        !routes.iter().any(|r| r.starts_with("/xrm/admin/metadata/")),
        "bundles stay system.admin: {routes:?}"
    );
    assert_eq!(
        status_of(&app, &cookie, "/api/v1/admin/entities").await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&app, &cookie, "/api/v1/admin/settings").await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn schema_carries_the_actions_the_api_admits() {
    let system = skip_if_no_db!(test_system().await);
    let (user, cookie) = seed_user(&system, false).await;
    grant(&system, user, &["team.read"]).await;
    let app = full_app(system);

    let resp = app
        .clone()
        .oneshot(get_request(&cookie, "/api/v1/schema/team"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let schema = body_json(resp).await;
    // Export runs on the read privilege, and with the default bulk-field
    // mode its level falls back to the read level, so a reader may export.
    assert_eq!(
        schema["allowed_actions"],
        json!(["read", "export"]),
        "{schema}"
    );
    assert_eq!(
        status_of(&app, &cookie, "/api/v1/schema/role").await,
        StatusCode::FORBIDDEN
    );
}

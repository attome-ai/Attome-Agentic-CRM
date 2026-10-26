//! Y4-T2: switching a module off in Module Management hides it at runtime:
//! its routes answer 403 `feature_hidden` (D-279's choice for an off module), its agent tools leave the MCP listing, and its
//! schedules stop ticking; switching it back on restores all three without
//! a restart. The module is Ops (drills, its tools and its schedules).
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database) and Redis.
//!
//! ```powershell
//! cargo test -p attome --test module_off -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;

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
const ALLOWED_ORIGIN: &str = "http://allowed.test";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 65536, "request_timeout_secs": 15,
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
                "oauth_google_client_id": "", "oauth_google_client_secret": "",
                "secure_cookies": true
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000 }},
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
        allowed_origin = ALLOWED_ORIGIN,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn app() -> Option<(axum::Router, EngineState, Uuid, String)> {
    let mut config = test_config();
    point_config_at(&mut config, &attome_testkit::migrated_db_url()?);
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
    let system = attome::boot::register_engines(EngineSystem::builder(EngineState::new(base)))
        .build()
        .await
        .expect("build EngineSystem");
    let state = system.state().clone();
    let base_state = state.base.clone();
    let app = attome_server::ServerBuilder::new(base_state.clone(), config)
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    let (admin, cookie) = admin_cookie(&base_state).await;
    Some((app, state, admin, cookie))
}

async fn admin_cookie(state: &AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $2 || '@test.invalid', true)",
    )
    .bind(user_id)
    .bind(format!("module-off-{user_id}"))
    .execute(&state.db)
    .await
    .expect("insert user_account");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT $1, $2, id, true, NOW() FROM privilege WHERE key = 'system.admin'",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .execute(&state.db)
    .await
    .expect("grant system.admin");
    let now = chrono::Utc::now().timestamp();
    let claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 3600,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: state.config.auth.jwt_issuer.clone(),
        aud: state.config.jwt_audience().to_owned(),
        typ: attome_auth::TokenType::Session,
    };
    let token = attome_auth::create_token(&claims, &KeyRing::single(THROWAWAY_JWT_SECRET.into()))
        .expect("encode jwt");
    (
        user_id,
        format!("{}={token}", attome_auth::cookie::session_cookie_name(true)),
    )
}

async fn send(
    app: &axum::Router,
    cookie: &str,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> StatusCode {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", ALLOWED_ORIGIN)
        .header("sec-fetch-site", "same-origin");
    let body = match body {
        Some(json) => {
            builder = builder.header("content-type", "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
        .status()
}

/// Every module but `off` on, through Module Management.
async fn configure(app: &axum::Router, cookie: &str, off: Option<&str>) {
    let modules: Vec<&str> = attome_modules::MODULE_MAP
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| Some(*name) != off)
        .collect();
    let status = send(
        app,
        cookie,
        "PUT",
        "/api/v1/admin/license/modules",
        Some(serde_json::json!({ "enabled": true, "modules": modules })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "module configuration saved");
    attome::jobs::forget_schedule_modules();
}

async fn ops_tool_listed(
    state: &EngineState,
    security: Arc<attome_server::security::SecurityContext>,
) -> bool {
    attome_ai::mcp::visible_tool_names(state, security)
        .await
        .iter()
        // The Ops module's own tools; `ops.slo_health` is a core tool.
        .any(|t| t == "ops.upgrade_status" || t == "ops.drill_freshness")
}

#[tokio::test]
async fn an_off_module_mounts_no_routes_tools_or_schedules() {
    let (app, state, admin, cookie) = skip_if_no_db!(app().await);
    let security = Arc::new(
        attome_security::resolve_uncached(&state.base.db, admin)
            .await
            .expect("security"),
    );
    configure(&app, &cookie, None).await;
    assert_ne!(
        send(&app, &cookie, "GET", "/api/v1/ops/drills", None).await,
        StatusCode::FORBIDDEN
    );
    assert!(
        ops_tool_listed(&state, security.clone()).await,
        "ops tools listed while on"
    );
    assert!(attome::jobs::schedule_allowed(&state.base.db, "ops-drill-freshness").await);

    configure(&app, &cookie, Some("ops")).await;
    assert_eq!(
        send(&app, &cookie, "GET", "/api/v1/ops/drills", None).await,
        StatusCode::FORBIDDEN
    );
    assert!(
        !ops_tool_listed(&state, security.clone()).await,
        "no ops tool while off"
    );
    assert!(
        !attome::jobs::schedule_allowed(&state.base.db, "ops-drill-freshness").await,
        "an ops schedule does not tick while ops is off"
    );
    assert!(
        attome::jobs::schedule_allowed(&state.base.db, "audit-chain-verify").await,
        "platform schedules keep running"
    );

    // Back on, without a restart.
    configure(&app, &cookie, None).await;
    assert_ne!(
        send(&app, &cookie, "GET", "/api/v1/ops/drills", None).await,
        StatusCode::FORBIDDEN
    );
    assert!(ops_tool_listed(&state, security).await);
    assert!(attome::jobs::schedule_allowed(&state.base.db, "ops-drill-freshness").await);
}

//! S11-T4: every S2S client is a service account. A client created without
//! a service user gets one of its own that holds nothing, so it can do
//! nothing until granted; a role granted to it allows exactly what the role
//! holds. The daily sweep reminds the owner once 14 days before expiry and
//! suspends an expired client.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database) and Redis.
//!
//! ```powershell
//! cargo test -p attome --test s2s_service_account -- --test-threads=1
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
    .bind(format!("s2s-sa-admin-{user_id}"))
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

async fn call(
    app: &axum::Router,
    cookie: &str,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
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
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn uuid_of(value: &serde_json::Value, field: &str) -> Uuid {
    value[field]
        .as_str()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("{field} in {value}"))
}

async fn privileges(state: &EngineState, user: Uuid) -> Vec<String> {
    let mut held: Vec<String> = attome_security::resolve_uncached(&state.base.db, user)
        .await
        .expect("resolve")
        .privileges
        .into_iter()
        .collect();
    held.sort();
    held
}

#[tokio::test]
async fn service_account_new_client_holds_nothing_until_granted() {
    let (app, state, admin, cookie) = skip_if_no_db!(app().await);
    let slug = format!("sa-{}", Uuid::now_v7().simple());
    let (status, client) = call(
        &app,
        &cookie,
        "POST",
        "/api/v1/admin/s2s/clients",
        Some(serde_json::json!({
            "client_id": slug, "name": "ERP sync",
            "purpose": "nightly ledger export", "environment": "production",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    assert_eq!(
        uuid_of(&client, "owner_user_ref"),
        admin,
        "the creator owns it"
    );
    assert_eq!(client["purpose"], "nightly ledger export");
    assert_eq!(client["environment"], "production");
    let service_user = uuid_of(&client, "service_user_ref");
    assert_ne!(service_user, admin, "a service user of its own");
    assert!(
        privileges(&state, service_user).await.is_empty(),
        "a new client can do nothing"
    );

    // Grant it a role holding one entity's read privilege.
    let keys: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, key FROM privilege WHERE key LIKE '%.read' AND key <> 'system.admin'          ORDER BY key LIMIT 2",
    )
    .fetch_all(&state.base.db)
    .await
    .unwrap();
    assert_eq!(keys.len(), 2, "two read privileges to tell apart");
    let role: Uuid = sqlx::query_scalar(
        "INSERT INTO role (name, owner_layer) VALUES ($1, 'customer') RETURNING id",
    )
    .bind(format!("sa-role-{slug}"))
    .fetch_one(&state.base.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO role_mm_privilege (role_ref, privilege_ref, owner_layer) VALUES ($1, $2, 'customer')",
    )
    .bind(role)
    .bind(keys[0].0)
    .execute(&state.base.db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2)")
        .bind(service_user)
        .bind(role)
        .execute(&state.base.db)
        .await
        .unwrap();
    let held = privileges(&state, service_user).await;
    assert!(held.contains(&keys[0].1), "{held:?}");
    assert!(
        !held.contains(&keys[1].1),
        "only what the role holds: {held:?}"
    );

    // Bad fields are refused.
    for bad in [
        serde_json::json!({"client_id": format!("{slug}-x"), "name": "x", "environment": "prod"}),
        serde_json::json!({"client_id": format!("{slug}-y"), "name": "y", "expires_at": "2020-01-01T00:00:00Z"}),
    ] {
        let (status, body) = call(
            &app,
            &cookie,
            "POST",
            "/api/v1/admin/s2s/clients",
            Some(bad),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }
}

#[tokio::test]
async fn service_account_expiry_reminds_once_then_suspends() {
    let (app, state, _admin, cookie) = skip_if_no_db!(app().await);
    let slug = format!("sa-exp-{}", Uuid::now_v7().simple());
    let (status, client) = call(
        &app,
        &cookie,
        "POST",
        "/api/v1/admin/s2s/clients",
        Some(serde_json::json!({"client_id": slug, "name": "Expiring"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{client}");
    let id = uuid_of(&client, "id");
    let soon = chrono::Utc::now() + chrono::Duration::days(10);
    let (status, patched) = call(
        &app,
        &cookie,
        "PATCH",
        &format!("/api/v1/admin/s2s/clients/{id}"),
        Some(serde_json::json!({"expires_at": soon, "row_version": client["row_version"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");

    let mine = |notices: &[attome_s2s::service_account::ExpiryNotice]| {
        notices
            .iter()
            .filter(|n| n.client_db_id == id)
            .map(|n| n.action)
            .collect::<Vec<_>>()
    };
    use attome_s2s::service_account::{ExpiryAction, expiry_sweep};
    assert_eq!(
        mine(&expiry_sweep(&state).await.unwrap()),
        [ExpiryAction::Remind]
    );
    assert!(
        mine(&expiry_sweep(&state).await.unwrap()).is_empty(),
        "reminded once"
    );

    // Time passes (the API refuses a past expiry).
    sqlx::query("UPDATE s2s_client SET expires_at = NOW() - interval '1 minute' WHERE id = $1")
        .bind(id)
        .execute(&state.base.db)
        .await
        .unwrap();
    assert_eq!(
        mine(&expiry_sweep(&state).await.unwrap()),
        [ExpiryAction::Suspend]
    );
    let (_, after) = call(
        &app,
        &cookie,
        "GET",
        &format!("/api/v1/admin/s2s/clients/{id}"),
        None,
    )
    .await;
    assert_eq!(after["status"], "suspended");
    assert!(
        mine(&expiry_sweep(&state).await.unwrap()).is_empty(),
        "suspended once"
    );
}

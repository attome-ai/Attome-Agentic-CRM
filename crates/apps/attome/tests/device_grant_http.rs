//! C7-T1 / T4-T1 (V2-D1415): the RFC 8628 device grant over HTTP. A device
//! asks for a grant, polls while it is pending (and is told to slow down when
//! it polls too fast), a signed-in browser sees and approves it, and the
//! device receives a session it uses as a bearer and refreshes; the grant
//! works once, a bearer session cannot approve another device, a denied grant
//! says so, and only the known clients may ask.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis, like `passkey_http`,
//! whose harness this copies.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome::auth;
use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "device-grant-password-1";
const SESSION_COOKIE: &str = "__Host-session_token";
const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4096, "request_timeout_secs": 5,
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
            "rate_limit": {{
                "anonymous_rpm": 1000, "authenticated_rpm": 1000
            }},
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

/// The full `main.rs` stack around both auth bundles.
async fn test_app() -> Option<(axum::Router, AppState)> {
    let mut config = test_config();
    let throwaway_url = attome_testkit::migrated_db_url()?;
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
        config.clone(),
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

    let base_state = system.state().base.clone();
    let license = system.state().modules.clone();
    let public_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );
    let protected_bundle = attome_server::RouteBundle::new(
        auth::protected_routes(attome_audit::security::SecurityAuditor::from_state(
            system.state(),
        ))
        .with_state(base_state.clone()),
    );

    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(public_bundle)
        .add_bundle(protected_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

async fn seed_user(state: &AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let email = format!("device-grant-{user_id}@example.test");
    let password_hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(PASSWORD))
            .await
            .expect("hash throwaway password");
    sqlx::query(
        "INSERT INTO user_account \
         (id, user_name, email, password_hash, is_active, email_verified) \
         VALUES ($1, $2, $3, $4, true, true)",
    )
    .bind(user_id)
    .bind(format!("device-grant-{user_id}"))
    .bind(&email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email)
}

/// One sign-in's cookies.
struct Signed {
    session: String,
}

impl Signed {
    fn session_cookie(&self) -> String {
        format!("{SESSION_COOKIE}={}", self.session)
    }
}

fn cookie_value(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<String>,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", ALLOWED_ORIGIN)
        .header(header::USER_AGENT, BROWSER);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let body = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .expect("request")
}

async fn sign_in(app: &axum::Router, email: &str) -> Signed {
    let res = send(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(serde_json::json!({ "email": email, "password": PASSWORD })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "password sign-in succeeds");
    Signed {
        session: cookie_value(&res, SESSION_COOKIE).expect("session cookie"),
    }
}

/// Mandatory events of `category`/`operation` written so far.
async fn events(state: &AppState, category: &str, operation: &str) -> i64 {
    let c: attome_audit::AuditCategory =
        serde_json::from_value(serde_json::json!(category)).expect("known category");
    let o: attome_audit::AuditOperation =
        serde_json::from_value(serde_json::json!(operation)).expect("known operation");
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE category = $1 AND operation = $2) \
              + (SELECT COUNT(*) FROM audit_ingest \
                 WHERE payload->>'category' = $3 AND payload->>'operation' = $4)",
    )
    .bind(c as i32)
    .bind(o as i32)
    .bind(category)
    .bind(operation)
    .fetch_one(&state.db)
    .await
    .expect("count audit events")
}

/// The `amr` the newest live family of `user_id` was signed in with.
async fn amr_of(state: &AppState, user_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT amr FROM refresh_token WHERE user_ref = $1 AND revoked_at IS NULL \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .expect("the newest session")
}

fn form(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::USER_AGENT, BROWSER)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn call(app: &axum::Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let res = app.clone().oneshot(req).await.expect("request");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn ask(app: &axum::Router) -> serde_json::Value {
    let (status, grant) = call(
        app,
        form("/api/v1/oauth/device_authorization", "client_id=attome-cli"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{grant}");
    grant
}

async fn poll(app: &axum::Router, grant: &serde_json::Value) -> (StatusCode, serde_json::Value) {
    let body = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=attome-cli&device_code={}",
        grant["device_code"].as_str().unwrap()
    );
    call(app, form("/api/v1/oauth/device/token", &body)).await
}

async fn decide(
    app: &axum::Router,
    credential: (&str, String),
    grant: &serde_json::Value,
    approve: bool,
) -> StatusCode {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/oauth/device/approve")
                .header("origin", ALLOWED_ORIGIN)
                .header(header::USER_AGENT, BROWSER)
                .header(credential.0, credential.1)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "user_code": grant["user_code"], "approve": approve })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("request");
    res.status()
}

#[tokio::test]
async fn a_device_signs_in_through_an_approving_browser() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let browser = sign_in(&app, &email).await;
    let cookie = (header::COOKIE.as_str(), browser.session_cookie());

    let grant = ask(&app).await;
    let user_code = grant["user_code"].as_str().unwrap().to_owned();
    assert_eq!(user_code.len(), 9, "XXXX-XXXX: {user_code}");
    assert!(
        grant["verification_uri_complete"]
            .as_str()
            .unwrap()
            .ends_with(&user_code)
    );

    // Pending, then too fast.
    let (status, answer) = poll(&app, &grant).await;
    assert_eq!(
        (status, answer["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("authorization_pending"))
    );
    let (_, answer) = poll(&app, &grant).await;
    assert_eq!(answer["error"], "slow_down");

    // The browser sees which application asks, then approves it.
    let (status, pending) = call(
        &app,
        Request::builder()
            .uri(format!(
                "/api/v1/oauth/device?user_code={}",
                user_code.to_lowercase()
            ))
            .header(header::COOKIE, browser.session_cookie())
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["client_name"], "Attome CLI");
    let approvals = events(&state, "Credential", "Create").await;
    let logins = events(&state, "Security", "Login").await;
    assert_eq!(
        decide(&app, cookie.clone(), &grant, true).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(events(&state, "Credential", "Create").await, approvals + 1);

    let (status, tokens) = poll(&app, &grant).await;
    assert_eq!(status, StatusCode::OK, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(amr_of(&state, user_id).await, vec!["dev"]);
    assert_eq!(events(&state, "Security", "Login").await, logins + 1);
    let (_, again) = poll(&app, &grant).await;
    assert_eq!(again["error"], "invalid_grant", "a grant works once");

    // The session works as a bearer.
    let access = tokens["access_token"].as_str().unwrap().to_owned();
    let bearer = (header::AUTHORIZATION.as_str(), format!("Bearer {access}"));
    let (status, me) = call(
        &app,
        Request::builder()
            .uri("/api/v1/auth/session")
            .header(header::AUTHORIZATION, format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{me}");
    assert_eq!(me["user_id"], user_id.to_string());

    // A device session cannot approve another device.
    let second = ask(&app).await;
    assert_eq!(
        decide(&app, bearer, &second, true).await,
        StatusCode::FORBIDDEN
    );

    // The refresh token gives the next pair once.
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    let body = format!("grant_type=refresh_token&client_id=attome-cli&refresh_token={refresh}");
    let (status, next) = call(&app, form("/api/v1/oauth/device/token", &body)).await;
    assert_eq!(status, StatusCode::OK, "{next}");
    assert_ne!(next["refresh_token"], tokens["refresh_token"]);
    let (status, _) = call(&app, form("/api/v1/oauth/device/token", &body)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a rotated refresh token is spent"
    );

    // A denied grant says so; an unknown client cannot ask.
    let third = ask(&app).await;
    assert_eq!(
        decide(&app, cookie, &third, false).await,
        StatusCode::NO_CONTENT
    );
    let (_, denied) = poll(&app, &third).await;
    assert_eq!(denied["error"], "access_denied");
    let (status, refused) = call(
        &app,
        form("/api/v1/oauth/device_authorization", "client_id=somebody"),
    )
    .await;
    assert_eq!(
        (status, refused["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_client"))
    );
}

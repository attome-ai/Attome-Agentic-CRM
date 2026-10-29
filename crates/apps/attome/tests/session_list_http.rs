//! Q8-T4: a person's own session list through the assembled HTTP stack.
//!
//! A person signs in twice with a password. `GET /api/v1/auth/sessions` lists
//! both sign-ins, marks the one the request came with, records the browser
//! and the sign-in method, and never carries a token or secret. Ending the
//! others keeps the current session and stops the other one refreshing, and
//! another person's session cannot be ended (404, untouched).
//!
//! Q8-T8: a refresh from another browser family is refused with
//! `reauth_required` and does not rotate; a browser update rotates as before.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database — attome-testkit
//! clones it per binary) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`).
//! Skips cleanly when `DATABASE_URL` is unset. Run manually:
//!
//! ```powershell
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome --test session_list_http -- --test-threads=1
//! ```

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
const PASSWORD: &str = "session-list-http-password-1";
const SESSION_COOKIE: &str = "__Host-session_token";
const REFRESH_COOKIE: &str = "__Secure-refresh_token";
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

async fn seed_user(state: &AppState) -> String {
    let user_id = Uuid::now_v7();
    let email = format!("session-list-http-{user_id}@example.test");
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
    .bind(format!("session-list-http-{user_id}"))
    .bind(&email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    email
}

/// One sign-in's cookies.
struct Signed {
    session: String,
    refresh: String,
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
        refresh: cookie_value(&res, REFRESH_COOKIE).expect("refresh cookie"),
    }
}

async fn json_of(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("JSON body")
}

async fn sessions(app: &axum::Router, signed: &Signed) -> Vec<serde_json::Value> {
    let res = send(
        app,
        "GET",
        "/api/v1/auth/sessions",
        Some(signed.session_cookie()),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "the session list answers");
    let body = json_of(res).await;
    assert_eq!(body["page"], 1, "a one-based list");
    body["items"].as_array().expect("items").clone()
}

async fn refresh_status(app: &axum::Router, signed: &Signed) -> StatusCode {
    send(
        app,
        "POST",
        "/api/v1/auth/refresh",
        Some(format!("{REFRESH_COOKIE}={}", signed.refresh)),
        Some(serde_json::json!({})),
    )
    .await
    .status()
}

/// The family a session token names, as authn reads it.
fn family_of(state: &AppState, signed: &Signed) -> Uuid {
    attome_auth::validate_session_token(
        &signed.session,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .expect("a valid session token")
    .1
    .0
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn user_sees_own_sessions_only() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let email = seed_user(&state).await;
    let first = sign_in(&app, &email).await;
    let second = sign_in(&app, &email).await;
    let stranger = sign_in(&app, &seed_user(&state).await).await;

    let items = sessions(&app, &second).await;
    assert_eq!(
        items.len(),
        2,
        "both of the person's sign-ins, nobody else's"
    );
    let ids: Vec<Uuid> = items
        .iter()
        .map(|s| s["id"].as_str().unwrap().parse().unwrap())
        .collect();
    assert!(ids.contains(&family_of(&state, &first)));
    assert!(ids.contains(&family_of(&state, &second)));
    assert!(!ids.contains(&family_of(&state, &stranger)));

    let current: Vec<&serde_json::Value> =
        items.iter().filter(|s| s["is_current"] == true).collect();
    assert_eq!(current.len(), 1, "exactly one session is the caller's");
    assert_eq!(
        current[0]["id"].as_str().unwrap(),
        family_of(&state, &second).to_string()
    );
    for item in &items {
        assert_eq!(item["user_agent"], BROWSER, "the browser is recorded");
        assert_eq!(item["sign_in_method"], "password");
        assert_eq!(item["client_kind"], "web");
        assert!(item["device_label"].is_string(), "a browser family");
        // No `auth.geoip_database` here: the country is listed, unknown.
        assert!(item["sign_in_country"].is_null());
        for hidden in ["secret_hash", "public_id", "jti", "ip_address", "token"] {
            assert!(item.get(hidden).is_none(), "{hidden} is never listed");
        }
    }
}

#[tokio::test]
async fn end_other_sessions_keeps_current() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let email = seed_user(&state).await;
    let other = sign_in(&app, &email).await;
    let current = sign_in(&app, &email).await;

    let res = send(
        &app,
        "POST",
        "/api/v1/auth/sessions/end-others",
        Some(current.session_cookie()),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);

    let items = sessions(&app, &current).await;
    assert_eq!(items.len(), 1, "only the current session is left");
    assert_eq!(items[0]["is_current"], true);
    assert_eq!(
        refresh_status(&app, &other).await,
        StatusCode::UNAUTHORIZED,
        "the ended session can no longer refresh"
    );
    assert_eq!(
        refresh_status(&app, &current).await,
        StatusCode::OK,
        "the current session still refreshes"
    );
}

#[tokio::test]
async fn cannot_end_another_users_session() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let mine = sign_in(&app, &seed_user(&state).await).await;
    let theirs = sign_in(&app, &seed_user(&state).await).await;
    let their_family = family_of(&state, &theirs);

    let res = send(
        &app,
        "DELETE",
        &format!("/api/v1/auth/sessions/{their_family}"),
        Some(mine.session_cookie()),
        None,
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "not the caller's session"
    );
    assert_eq!(
        refresh_status(&app, &theirs).await,
        StatusCode::OK,
        "their session is untouched"
    );

    // The caller's own session ends through the same route.
    let mine_family = family_of(&state, &mine);
    let res = send(
        &app,
        "DELETE",
        &format!("/api/v1/auth/sessions/{mine_family}"),
        Some(mine.session_cookie()),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(refresh_status(&app, &mine).await, StatusCode::UNAUTHORIZED);
}

/// Q8-T8: a refresh with `cookie` sent from `user_agent`.
async fn refresh_from(
    app: &axum::Router,
    signed: &Signed,
    user_agent: &str,
) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/refresh")
        .header("origin", ALLOWED_ORIGIN)
        .header(header::USER_AGENT, user_agent)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            format!("{REFRESH_COOKIE}={}", signed.refresh),
        )
        .body(Body::from("{}"))
        .unwrap();
    app.clone().oneshot(req).await.expect("refresh request")
}

#[tokio::test]
async fn refresh_from_new_browser_requires_reauth() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let signed = sign_in(&app, &seed_user(&state).await).await;
    let firefox =
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:121.0) Gecko/20100101 Firefox/121.0";
    let res = refresh_from(&app, &signed, firefox).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_of(res).await["code"], "reauth_required");
    // Not rotated: the token still refreshes from the browser that signed in.
    assert_eq!(
        refresh_from(&app, &signed, BROWSER).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn refresh_from_same_browser_rotates() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let signed = sign_in(&app, &seed_user(&state).await).await;
    // A browser update changes the version, not the family.
    let updated = BROWSER.replace("Chrome/120.0", "Chrome/131.0");
    let res = refresh_from(&app, &signed, &updated).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        cookie_value(&res, REFRESH_COOKIE).is_some(),
        "the refresh cookie rotated"
    );
}

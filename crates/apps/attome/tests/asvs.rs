//! Q21-T5: OWASP ASVS 4.0.3 level 2 requirements proved through the whole
//! composed stack (`ServerBuilder` with the auth routes, as `main.rs` builds
//! it). Each test is named after the requirement it proves; the map of every
//! level 2 requirement to its test, its gap or why it does not apply is
//! `docs/security/asvs-l2.md`. Requirements an existing suite already proves
//! (rate limits, body limits, idempotency, record access) are cited there,
//! not repeated here.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`); skips when `DATABASE_URL` is unset.
//!
//! ```powershell
//! cargo test -p attome --test asvs -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::net::SocketAddr;

use attome::auth;
use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, Response, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "asvs-l2-password-1";

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

/// The app `main.rs` assembles: liveness, the engine routes and the auth
/// routes through one `ServerBuilder`.
async fn test_app() -> Option<(axum::Router, AppState)> {
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
    let system = EngineSystem::builder(EngineState::new(base))
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
    let auth_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            system.state().modules.clone(),
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );
    let app = attome_server::ServerBuilder::new(base_state.clone(), config)
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    Some((app, base_state))
}

/// A verified password account; returns its email.
async fn seed_password_user(state: &AppState) -> String {
    let user_id = Uuid::now_v7();
    let email = format!("asvs-{user_id}@example.test");
    let hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(PASSWORD))
            .await
            .expect("hash password");
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, password_hash, is_active, email_verified) \
         VALUES ($1, $2, $3, $4, true, true)",
    )
    .bind(user_id)
    .bind(format!("asvs-{user_id}"))
    .bind(&email)
    .bind(hash)
    .execute(&state.db)
    .await
    .expect("insert user_account");
    email
}

/// A distinct peer per request, so no test shares a rate-limit bucket.
fn from_new_peer(mut req: Request<Body>) -> Request<Body> {
    let n = Uuid::now_v7().as_u128();
    let peer = SocketAddr::from((
        [10, (n >> 16) as u8, (n >> 8) as u8, n as u8],
        40_000 + (n as u16 % 1000),
    ));
    req.extensions_mut().insert(ConnectInfo(peer));
    req
}

/// Signs in and returns the response.
async fn login(app: &axum::Router, email: &str) -> Response<Body> {
    let body = serde_json::json!({ "email": email, "password": PASSWORD }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .header("origin", ALLOWED_ORIGIN)
        .body(Body::from(body))
        .unwrap();
    app.clone().oneshot(from_new_peer(req)).await.unwrap()
}

/// The `Set-Cookie` value whose name starts with `prefix`.
fn set_cookie<'a>(res: &'a Response<Body>, prefix: &str) -> &'a str {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix} cookie in {:?}", res.headers()))
}

fn header<'a>(res: &'a Response<Body>, name: &str) -> Option<&'a str> {
    res.headers().get(name).and_then(|v| v.to_str().ok())
}

// ── V3 Session management ───────────────────────────────────────────────────

/// V3.4.1, V3.4.2, V3.4.3, V3.4.4: the session cookie a sign-in sets is
/// `Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-` with `Path=/` and no
/// `Domain`; the refresh cookie is `__Secure-` and as strict.
#[tokio::test]
async fn v3_4_session_cookie_flags() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let email = seed_password_user(&state).await;
    let res = login(&app, &email).await;
    assert_eq!(res.status(), StatusCode::OK);
    for prefix in ["__Host-session_token=", "__Secure-refresh_token="] {
        let cookie = set_cookie(&res, prefix);
        assert!(cookie.contains("; Secure"), "{cookie}");
        assert!(cookie.contains("; HttpOnly"), "{cookie}");
        assert!(cookie.contains("; SameSite=Strict"), "{cookie}");
        assert!(!cookie.to_ascii_lowercase().contains("domain="), "{cookie}");
    }
    assert!(set_cookie(&res, "__Host-session_token=").contains("; Path=/;"));
}

/// V3.1.1, V13.1.3: no session token in the response body or a redirect
/// URL; the token only travels in the cookie.
#[tokio::test]
async fn v3_1_1_session_token_never_in_a_url() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let email = seed_password_user(&state).await;
    let res = login(&app, &email).await;
    assert_eq!(res.status(), StatusCode::OK);
    let cookie = set_cookie(&res, "__Host-session_token=");
    let token = cookie
        .trim_start_matches("__Host-session_token=")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(header(&res, "location").is_none_or(|l| !l.contains(&token)));
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&body).contains(&token),
        "the session token must not be echoed in the body"
    );
}

/// V3.2.1: every sign-in mints a new session token.
#[tokio::test]
async fn v3_2_1_new_session_token_per_sign_in() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let email = seed_password_user(&state).await;
    let first = login(&app, &email).await;
    let second = login(&app, &email).await;
    assert_ne!(
        set_cookie(&first, "__Host-session_token="),
        set_cookie(&second, "__Host-session_token=")
    );
}

/// V2.2.1 (anti-automation), V7.4.1 (generic message): a wrong password is
/// a plain 401 that does not say which part was wrong.
#[tokio::test]
async fn v2_wrong_password_is_generic() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let email = seed_password_user(&state).await;
    let body = serde_json::json!({ "email": email, "password": "not-the-password" }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "application/json")
        .header("origin", ALLOWED_ORIGIN)
        .body(Body::from(body))
        .unwrap();
    let res = app.clone().oneshot(from_new_peer(req)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body).to_ascii_lowercase();
    assert!(
        !text.contains("password is") && !text.contains("no such user"),
        "{text}"
    );
}

// ── V4 Access control ───────────────────────────────────────────────────────

/// V4.2.2, V13.2.3: a cookie-authenticated mutation from another site is
/// refused.
#[tokio::test]
async fn v4_2_2_cross_site_mutation_is_refused() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let email = seed_password_user(&state).await;
    let res = login(&app, &email).await;
    let cookie = set_cookie(&res, "__Host-session_token=")
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("cookie", cookie)
        .header("origin", "http://evil.example")
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(from_new_peer(req)).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// V4.1.1, V13.1.4: an API route without credentials is refused at the
/// server, whatever the client hides.
#[tokio::test]
async fn v4_1_1_unauthenticated_api_is_refused() {
    let (app, _) = skip_if_no_db!(test_app().await);
    let req = Request::builder()
        .uri("/api/v1/admin/entities")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(from_new_peer(req)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

// ── V14 Configuration ───────────────────────────────────────────────────────

/// V14.5.3: a preflight from an origin not on the allow list gets no
/// `Access-Control-Allow-Origin`; an allowed one is echoed exactly.
#[tokio::test]
async fn v14_5_3_cors_allow_list() {
    let (app, _) = skip_if_no_db!(test_app().await);
    for (origin, echoed) in [("http://evil.example", false), (ALLOWED_ORIGIN, true)] {
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/v1/auth/login")
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap();
        let res = app.clone().oneshot(from_new_peer(req)).await.unwrap();
        let allow = header(&res, "access-control-allow-origin");
        if echoed {
            assert_eq!(allow, Some(origin));
        } else {
            assert!(allow.is_none(), "{origin} must not be echoed");
        }
    }
}

/// V14.4.3, V14.4.7: a page carries a Content Security Policy that forbids
/// framing (`frame-ancestors`) and plugins (`object-src 'none'`).
#[tokio::test]
async fn v14_4_3_page_has_csp() {
    let (app, _) = skip_if_no_db!(test_app().await);
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let res = app.clone().oneshot(from_new_peer(req)).await.unwrap();
    let csp = header(&res, "content-security-policy")
        .or_else(|| header(&res, "content-security-policy-report-only"))
        .expect("a page response carries a CSP");
    assert!(csp.contains("default-src"), "{csp}");
    assert!(csp.contains("object-src 'none'"), "{csp}");
    assert!(
        csp.contains("frame-ancestors") || header(&res, "x-frame-options") == Some("DENY"),
        "{csp}"
    );
}

/// V14.4.1, V14.4.4, V14.4.5, V14.4.6, V8.1.1, V8.2.1: an API response names
/// its content type and carries `nosniff`, HSTS, a referrer policy and a
/// private, revalidated `Cache-Control`.
#[tokio::test]
async fn v14_4_api_response_headers() {
    let (app, _) = skip_if_no_db!(test_app().await);
    let req = Request::builder()
        .uri("/api/v1/admin/entities")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(from_new_peer(req)).await.unwrap();
    assert!(
        header(&res, "content-type").is_some_and(
            |t| t.starts_with("application/json") || t.starts_with("application/problem+json")
        ),
        "{:?}",
        res.headers()
    );
    assert_eq!(header(&res, "x-content-type-options"), Some("nosniff"));
    // V8.1.1, V8.2.1: an API answer is never stored by a shared cache.
    assert!(
        header(&res, "cache-control").is_some_and(
            |c| c.contains("private") && (c.contains("no-cache") || c.contains("no-store"))
        ),
        "{:?}",
        res.headers()
    );
    assert!(
        header(&res, "strict-transport-security").is_some_and(|h| h.contains("max-age=")),
        "{:?}",
        res.headers()
    );
    assert_eq!(
        header(&res, "referrer-policy"),
        Some("strict-origin-when-cross-origin")
    );
}

/// V14.3.3: no response names the server software or its version.
#[tokio::test]
async fn v14_3_3_no_version_in_headers() {
    let (app, _) = skip_if_no_db!(test_app().await);
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(from_new_peer(req)).await.unwrap();
    assert!(header(&res, "x-powered-by").is_none());
    if let Some(server) = header(&res, "server") {
        assert!(
            !server.chars().any(|c| c.is_ascii_digit()),
            "Server header names a version: {server}"
        );
    }
}

/// V13.1.5, V13.2.5: a JSON route refuses a body of another content type.
#[tokio::test]
async fn v13_2_5_unexpected_content_type_is_refused() {
    let (app, _) = skip_if_no_db!(test_app().await);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("content-type", "text/plain")
        .header("origin", ALLOWED_ORIGIN)
        .body(Body::from("email=a&password=b"))
        .unwrap();
    let res = app.clone().oneshot(from_new_peer(req)).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

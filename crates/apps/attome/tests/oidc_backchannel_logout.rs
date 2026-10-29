//! Q1-T10: OIDC sign-out through the assembled HTTP stack, against a local
//! mock provider.
//!
//! A person signs in through the provider (its ID token carries a `sid`).
//! The provider's back-channel logout naming that `sid` ends the session at
//! once: the access token stops (the epoch moved) and the refresh token is
//! revoked. A replayed logout token, and one carrying a `nonce`, change
//! nothing and answer 400. Sign-out of an OIDC session answers the provider's
//! end-session URL.
//!
//! Each test uses its own provider key: discovery documents and JWKS are cached
//! in Redis per provider key, and each test runs its own mock provider.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database — attome-testkit
//! clones it per binary) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`).
//! Skips cleanly when `DATABASE_URL` is unset. Run manually:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome --test oidc_backchannel_logout -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::{Arc, Mutex, OnceLock};

use attome::auth;
use attome_api::EngineSystem;
use attome_config::{AppConfig, OidcProviderConfig};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const CLIENT_ID: &str = "oidc-backchannel-logout-client";
const KID: &str = "oidc-backchannel-logout-kid";
const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
const SESSION_COOKIE: &str = "__Host-session_token";
const REFRESH_COOKIE: &str = "__Secure-refresh_token";

fn unique_provider() -> String {
    format!("mock-oidc-{}", Uuid::now_v7())
}

// ── Mock OIDC provider ───────────────────────────────────────────────────────

fn signing_key() -> &'static rsa::RsaPrivateKey {
    static KEY: OnceLock<rsa::RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("generate a test RSA key")
    })
}

fn sign(claims: &serde_json::Value) -> String {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let pem = signing_key()
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("pem");
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    jsonwebtoken::encode(&header, claims, &key).expect("sign the token")
}

fn jwks() -> serde_json::Value {
    use rsa::traits::PublicKeyParts;
    let key = signing_key();
    serde_json::json!({
        "keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
            "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        }]
    })
}

#[derive(Clone)]
struct MockIdp {
    issuer: String,
    next_id_token: Arc<Mutex<Option<String>>>,
}

async fn read_request_path(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    head.lines()
        .next()?
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
}

async fn mock_idp() -> MockIdp {
    // Q21-T1: the identity-provider client refuses a private host unless
    // boot lists its issuer; this provider listens on loopback. The first
    // call in the binary wins, and every test builds the provider first.
    let _ = attome_auth::oidc::configure_identity_providers(["http://127.0.0.1"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp = MockIdp {
        issuer: format!("http://{}", listener.local_addr().unwrap()),
        next_id_token: Arc::new(Mutex::new(None)),
    };
    let served = idp.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let idp = served.clone();
            tokio::spawn(async move {
                let Some(path) = read_request_path(&mut socket).await else {
                    return;
                };
                let (status, body) = if path.starts_with("/.well-known/openid-configuration") {
                    (
                        200,
                        serde_json::json!({
                            "issuer": idp.issuer,
                            "authorization_endpoint": format!("{}/authorize", idp.issuer),
                            "token_endpoint": format!("{}/token", idp.issuer),
                            "jwks_uri": format!("{}/jwks", idp.issuer),
                            "end_session_endpoint": format!("{}/logout", idp.issuer),
                        })
                        .to_string(),
                    )
                } else if path.starts_with("/jwks") {
                    (200, jwks().to_string())
                } else if path.starts_with("/token") {
                    match idp.next_id_token.lock().unwrap().take() {
                        Some(id_token) => (
                            200,
                            serde_json::json!({ "id_token": id_token, "token_type": "Bearer" })
                                .to_string(),
                        ),
                        None => (500, "{}".to_owned()),
                    }
                } else {
                    (404, "{}".to_owned())
                };
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    _ => "Internal Server Error",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    idp
}

impl MockIdp {
    fn issue_id_token(&self, subject: &str, nonce: &str, sid: &str) {
        let now = Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": self.issuer,
            "aud": CLIENT_ID,
            "sub": subject,
            "email": format!("{subject}@idp.example"),
            "email_verified": true,
            "nonce": nonce,
            "sid": sid,
            "iat": now,
            "exp": now + 300,
        });
        *self.next_id_token.lock().unwrap() = Some(sign(&claims));
    }

    fn logout_token(&self, sid: &str, jti: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": self.issuer,
            "aud": CLIENT_ID,
            "iat": Utc::now().timestamp(),
            "jti": jti,
            "sid": sid,
            "events": { LOGOUT_EVENT: {} },
        })
    }
}

// ── App ──────────────────────────────────────────────────────────────────────

fn test_config(issuer: &str, provider: &str) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 8192, "request_timeout_secs": 10,
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
    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    config.oidc.providers.insert(
        provider.to_owned(),
        OidcProviderConfig {
            display_name: "Mock IdP".into(),
            issuer: issuer.to_owned(),
            client_id: CLIENT_ID.into(),
            client_secret: "mock-client-secret".into(),
            scopes: vec!["openid".into(), "email".into()],
            email_claim: "email".into(),
            require_email_verified_claim: false,
            mfa_acr_values: Vec::new(),
            trust_idp_mfa: true,
        },
    );
    config
}

async fn test_app(issuer: &str, provider: &str) -> Option<(axum::Router, AppState)> {
    let mut config = test_config(issuer, provider);
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

// ── Helpers ──────────────────────────────────────────────────────────────────

/// A person signed in through the provider, with the provider session `sid`.
struct Signed {
    session: String,
    refresh: String,
}

fn cookie_value(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

fn query_param(url: &str, name: &str) -> String {
    url.split_once('?')
        .expect("a query")
        .1
        .split('&')
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.to_owned())
        })
        .unwrap_or_else(|| panic!("no {name} in {url}"))
}

async fn get(app: &axum::Router, uri: &str, cookies: &[String]) -> axum::response::Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    if !cookies.is_empty() {
        builder = builder.header(header::COOKIE, cookies.join("; "));
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .expect("request")
}

/// Links a new person to `provider` and signs them in through it, the ID
/// token carrying `sid`.
async fn sign_in(
    app: &axum::Router,
    state: &AppState,
    idp: &MockIdp,
    provider: &str,
    sid: &str,
) -> Signed {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, email_verified) \
         VALUES ($1, $2, $3, true, true)",
    )
    .bind(user_id)
    .bind(format!("oidc-backchannel-{user_id}"))
    .bind(format!("oidc-backchannel-{user_id}@example.test"))
    .execute(&state.db)
    .await
    .expect("insert user");
    let subject = format!("subject-{user_id}");
    sqlx::query(
        "INSERT INTO user_identity (user_ref, provider_key, provider_sub, email)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(provider)
    .bind(&subject)
    .bind(format!("{subject}@idp.example"))
    .execute(&state.db)
    .await
    .expect("link identity");

    let start = get(app, &format!("/api/v1/auth/oidc/{provider}/login"), &[]).await;
    assert!(
        start.status().is_redirection(),
        "login redirects to the provider"
    );
    let authorize = start
        .headers()
        .get(header::LOCATION)
        .expect("a redirect to the provider")
        .to_str()
        .unwrap()
        .to_owned();
    let state_id = query_param(&authorize, "state");
    let nonce = query_param(&authorize, "nonce");
    let binding = cookie_value(&start, "__Host-oidc_login").expect("binding cookie");
    idp.issue_id_token(&subject, &nonce, sid);

    let callback = get(
        app,
        &format!("/api/v1/auth/oidc/{provider}/callback?code=c&state={state_id}"),
        &[format!("__Host-oidc_login={binding}")],
    )
    .await;
    assert_eq!(callback.status(), StatusCode::FOUND, "callback redirects");
    Signed {
        session: cookie_value(&callback, SESSION_COOKIE).expect("session cookie"),
        refresh: cookie_value(&callback, REFRESH_COOKIE).expect("refresh cookie"),
    }
}

async fn session_status(app: &axum::Router, signed: &Signed) -> StatusCode {
    get(
        app,
        "/api/v1/auth/session",
        &[format!("{SESSION_COOKIE}={}", signed.session)],
    )
    .await
    .status()
}

async fn live_families(state: &AppState, provider: &str, sid: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM refresh_token
          WHERE oidc_provider = $1 AND oidc_sid = $2 AND revoked_at IS NULL",
    )
    .bind(provider)
    .bind(sid)
    .fetch_one(&state.db)
    .await
    .expect("count families")
}

async fn backchannel(
    app: &axum::Router,
    provider: &str,
    logout_token: &str,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/auth/oidc/{provider}/backchannel-logout"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!("logout_token={logout_token}")))
                .unwrap(),
        )
        .await
        .expect("backchannel request")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn valid_logout_token_ends_sessions() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let sid = format!("op-session-{}", Uuid::now_v7());
    let signed = sign_in(&app, &state, &idp, &provider, &sid).await;
    let other = sign_in(&app, &state, &idp, &provider, "another-op-session").await;
    assert_eq!(session_status(&app, &signed).await, StatusCode::OK);
    assert_eq!(live_families(&state, &provider, &sid).await, 1);

    let token = sign(&idp.logout_token(&sid, &Uuid::now_v7().to_string()));
    let res = backchannel(&app, &provider, &token).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );

    assert_eq!(live_families(&state, &provider, &sid).await, 0);
    // The access token stops at once: the person's epoch moved.
    assert_eq!(
        session_status(&app, &signed).await,
        StatusCode::UNAUTHORIZED
    );
    // The refresh token cannot mint a new session.
    let refreshed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("origin", ALLOWED_ORIGIN)
                .header(
                    header::COOKIE,
                    format!("{REFRESH_COOKIE}={}", signed.refresh),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.status(), StatusCode::UNAUTHORIZED);
    // Another provider session is untouched.
    assert_eq!(session_status(&app, &other).await, StatusCode::OK);
}

#[tokio::test]
async fn replayed_logout_token_is_refused() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let sid = format!("op-session-{}", Uuid::now_v7());
    let token = sign(&idp.logout_token(&sid, &Uuid::now_v7().to_string()));
    assert_eq!(
        backchannel(&app, &provider, &token).await.status(),
        StatusCode::OK
    );

    // The same token again, after the person signed in under that session.
    let signed = sign_in(&app, &state, &idp, &provider, &sid).await;
    let replay = backchannel(&app, &provider, &token).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        replay.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(live_families(&state, &provider, &sid).await, 1);
    assert_eq!(session_status(&app, &signed).await, StatusCode::OK);
}

#[tokio::test]
async fn logout_token_with_nonce_is_refused() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let sid = format!("op-session-{}", Uuid::now_v7());
    let signed = sign_in(&app, &state, &idp, &provider, &sid).await;

    let mut claims = idp.logout_token(&sid, &Uuid::now_v7().to_string());
    claims["nonce"] = serde_json::json!("an-id-token-nonce");
    let res = backchannel(&app, &provider, &sign(&claims)).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(live_families(&state, &provider, &sid).await, 1);
    assert_eq!(session_status(&app, &signed).await, StatusCode::OK);
}

#[tokio::test]
async fn sign_out_of_an_oidc_session_answers_the_provider_sign_out() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let signed = sign_in(&app, &state, &idp, &provider, "op-session-x").await;

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/logout")
                .header("origin", ALLOWED_ORIGIN)
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    format!(
                        "{SESSION_COOKIE}={}; {REFRESH_COOKIE}={}",
                        signed.session, signed.refresh
                    ),
                )
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let redirect = body["redirect"].as_str().expect("a provider sign-out URL");
    assert!(
        redirect.starts_with(&format!("{}/logout?", idp.issuer)),
        "{redirect}"
    );
    assert_eq!(query_param(redirect, "client_id"), CLIENT_ID);
    assert!(redirect.contains("post_logout_redirect_uri="), "{redirect}");
}

//! Base-auth hardening 2.1c (D-510 rule 5), end to end through the assembled
//! HTTP stack: federated step-up over OIDC against a local mock provider.
//!
//! Proves that the start route sends `prompt=login` and `max_age` and binds the
//! flow to the browser; that the bypass-listed callback refuses a request
//! without that binding and a stale or missing authentication time; and that a
//! fresh provider authentication elevates only the session cookie's own
//! family, with the provider's `auth_time`.
//!
//! Since 2.1d the guard is wired onto the protected routes: identity linking
//! redirects an unelevated session to re-authenticate, and returns through a
//! federated step-up's callback to the link it asked for.
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
//! cargo test -p server --test step_up_federated_http -- --test-threads=1
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
use attome_auth::validate_session_token;
use attome_config::{AppConfig, OidcProviderConfig};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "step-up-federated-http-password-1";
const CLIENT_ID: &str = "step-up-federated-http-client";
const KID: &str = "step-up-federated-http-kid";

/// A provider key no other test or run shares, so the Redis-cached discovery
/// document and JWKS always belong to this test's mock provider.
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
    jsonwebtoken::encode(&header, claims, &key).expect("sign the ID token")
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
                        })
                        .to_string(),
                    )
                } else if path.starts_with("/jwks") {
                    (200, jwks().to_string())
                } else if path.starts_with("/token") {
                    let queued = idp.next_id_token.lock().unwrap().take();
                    match queued {
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
    fn issue(&self, subject: &str, nonce: &str, auth_time: Option<i64>) {
        let now = Utc::now().timestamp();
        let mut claims = serde_json::json!({
            "iss": self.issuer,
            "aud": CLIENT_ID,
            "sub": subject,
            "email": format!("{subject}@idp.example"),
            "email_verified": true,
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        });
        if let Some(auth_time) = auth_time {
            claims["auth_time"] = serde_json::json!(auth_time);
        }
        *self.next_id_token.lock().unwrap() = Some(sign(&claims));
    }
}

// ── App ──────────────────────────────────────────────────────────────────────

fn test_config(issuer: &str, provider: &str) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4096, "request_timeout_secs": 10,
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

/// A password account, linked to the test's mock provider, signed in over HTTP.
struct Account {
    subject: String,
    provider: String,
    session_token: String,
}

async fn linked_account(app: &axum::Router, state: &AppState, provider: &str) -> Account {
    let user_id = Uuid::now_v7();
    let email = format!("step-up-federated-http-{user_id}@example.test");
    let password_hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(PASSWORD))
            .await
            .expect("hash");
    sqlx::query(
        "INSERT INTO user_account \
         (id, user_name, email, password_hash, is_active, email_verified) \
         VALUES ($1, $2, $3, $4, true, true)",
    )
    .bind(user_id)
    .bind(format!("step-up-federated-http-{user_id}"))
    .bind(&email)
    .bind(password_hash)
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

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .header("origin", ALLOWED_ORIGIN)
                .body(Body::from(
                    serde_json::json!({ "email": email, "password": PASSWORD }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("login");
    assert_eq!(res.status(), StatusCode::OK, "password login");
    let session_token = cookie_value(&res, "__Host-session_token").expect("session cookie");
    Account {
        subject,
        provider: provider.to_owned(),
        session_token,
    }
}

fn cookie_value(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

fn location(res: &axum::response::Response) -> String {
    res.headers()
        .get(header::LOCATION)
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_owned()
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

fn family_of(state: &AppState, session_token: &str) -> Uuid {
    let (_, sid) = validate_session_token(
        session_token,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .expect("valid session token");
    sid.0
}

async fn live_elevation(
    state: &AppState,
    family_id: Uuid,
) -> (Option<DateTime<Utc>>, Option<DateTime<Utc>>) {
    sqlx::query_as(
        "SELECT elevated_until, auth_time FROM refresh_token
         WHERE family_id = $1 AND used_at IS NULL AND revoked_at IS NULL
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(family_id)
    .fetch_one(&state.db)
    .await
    .expect("live row")
}

async fn db_now(state: &AppState) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT NOW()")
        .fetch_one(&state.db)
        .await
        .expect("database clock")
}

async fn start_challenge(app: &axum::Router, account: &Account, operation: &str) -> String {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/auth/step-up/{operation}"))
                .header("content-type", "application/json")
                .header("origin", ALLOWED_ORIGIN)
                .header(
                    header::COOKIE,
                    format!("__Host-session_token={}", account.session_token),
                )
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .expect("start challenge");
    assert_eq!(res.status(), StatusCode::CREATED);
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        body["acceptable_factors"],
        serde_json::json!(["password", "federated"])
    );
    body["challenge_id"].as_str().unwrap().to_owned()
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

/// Starts the federated half for `operation`; returns the authorize URL and
/// the binding cookie the start route set.
async fn start_federated(
    app: &axum::Router,
    account: &Account,
    operation: &str,
    challenge_id: &str,
) -> (String, String) {
    let provider = &account.provider;
    let res = get(
        app,
        &format!("/api/v1/auth/step-up/{operation}/oidc/{provider}?challenge_id={challenge_id}"),
        &[format!("__Host-session_token={}", account.session_token)],
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::SEE_OTHER,
        "the start route redirects to the provider"
    );
    let binding = cookie_value(&res, "__Host-step_up_oidc").expect("a binding cookie");
    (location(&res), binding)
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// A fresh provider authentication, completed in the starting browser,
/// elevates the session cookie's own family with the provider's `auth_time`.
#[tokio::test]
async fn a_fresh_federated_step_up_over_http_elevates_the_sessions_family() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let account = linked_account(&app, &state, &provider).await;
    let family = family_of(&state, &account.session_token);

    let challenge_id = start_challenge(&app, &account, "identity_link").await;
    let (authorize_url, binding) =
        start_federated(&app, &account, "identity_link", &challenge_id).await;
    assert!(authorize_url.starts_with(&format!("{}/authorize?", idp.issuer)));
    assert_eq!(query_param(&authorize_url, "prompt"), "login");
    assert_eq!(query_param(&authorize_url, "max_age"), "300");
    let oauth_state = query_param(&authorize_url, "state");
    assert_eq!(binding, oauth_state, "the binding cookie carries the state");

    let authenticated = db_now(&state).await.timestamp() - 45;
    idp.issue(
        &account.subject,
        &query_param(&authorize_url, "nonce"),
        Some(authenticated),
    );
    let res = get(
        &app,
        &format!("/api/v1/auth/step-up-callback/oidc/{provider}?code=abc&state={oauth_state}"),
        &[format!("__Host-step_up_oidc={binding}")],
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(
        location(&res).ends_with("/settings/security?step_up=identity_link"),
        "success redirect, got {}",
        location(&res)
    );

    let authenticated_at = DateTime::<Utc>::from_timestamp(authenticated, 0).unwrap();
    let (elevated_until, auth_time) = live_elevation(&state, family).await;
    assert_eq!(auth_time, Some(authenticated_at));
    assert_eq!(
        elevated_until,
        Some(authenticated_at + Duration::minutes(15))
    );
}

/// A callback from another browser, a stale provider authentication, a missing
/// one, and start requests the account or route cannot make all fail closed.
#[tokio::test]
async fn federated_step_up_over_http_fails_closed() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let account = linked_account(&app, &state, &provider).await;
    let family = family_of(&state, &account.session_token);
    let cookie = format!("__Host-session_token={}", account.session_token);

    // Start refusals: not a step-up operation, no such provider, no challenge.
    let challenge_id = start_challenge(&app, &account, "identity_link").await;
    assert_eq!(
        get(
            &app,
            &format!(
                "/api/v1/auth/step-up/mfa_disable/oidc/{provider}?challenge_id={challenge_id}"
            ),
            std::slice::from_ref(&cookie),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(
            &app,
            &format!("/api/v1/auth/step-up/identity_link/oidc/unknown?challenge_id={challenge_id}"),
            std::slice::from_ref(&cookie),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(
            &app,
            &format!(
                "/api/v1/auth/step-up/identity_link/oidc/{provider}?challenge_id={}",
                Uuid::now_v7()
            ),
            std::slice::from_ref(&cookie),
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED,
        "an unknown challenge is reauth_required"
    );

    // A callback without the starting browser's binding cookie.
    let (authorize_url, binding) =
        start_federated(&app, &account, "identity_link", &challenge_id).await;
    let oauth_state = query_param(&authorize_url, "state");
    let fresh = db_now(&state).await.timestamp() - 30;
    idp.issue(
        &account.subject,
        &query_param(&authorize_url, "nonce"),
        Some(fresh),
    );
    let callback =
        format!("/api/v1/auth/step-up-callback/oidc/{provider}?code=abc&state={oauth_state}");
    let res = get(&app, &callback, &[]).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(location(&res).ends_with("/settings/security?step_up_error=1"));
    let res = get(
        &app,
        &callback,
        &["__Host-step_up_oidc=someone-elses-state".into()],
    )
    .await;
    assert!(location(&res).ends_with("/settings/security?step_up_error=1"));
    assert_eq!(live_elevation(&state, family).await.0, None);
    // The genuine browser can still finish: a binding failure consumed nothing.
    let res = get(&app, &callback, &[format!("__Host-step_up_oidc={binding}")]).await;
    assert!(
        location(&res).ends_with("/settings/security?step_up=identity_link"),
        "the starting browser completes the flow, got {}",
        location(&res)
    );
    let elevated = live_elevation(&state, family).await.0;
    assert!(elevated.is_some());

    // A stale and a missing provider authentication time.
    for (case, auth_time) in [
        ("stale", Some(db_now(&state).await.timestamp() - 301)),
        ("missing", None),
    ] {
        let challenge_id = start_challenge(&app, &account, "identity_link").await;
        let (authorize_url, binding) =
            start_federated(&app, &account, "identity_link", &challenge_id).await;
        idp.issue(
            &account.subject,
            &query_param(&authorize_url, "nonce"),
            auth_time,
        );
        let res = get(
            &app,
            &format!(
                "/api/v1/auth/step-up-callback/oidc/{provider}?code=abc&state={}",
                query_param(&authorize_url, "state")
            ),
            &[format!("__Host-step_up_oidc={binding}")],
        )
        .await;
        assert!(
            location(&res).ends_with("/settings/security?step_up_error=1"),
            "{case} authentication time must be refused, got {}",
            location(&res)
        );
        assert_eq!(
            live_elevation(&state, family).await.0,
            elevated,
            "{case}: the earlier elevation is neither extended nor replaced"
        );
    }
}

/// The re-authentication marker the identity-link start routes redirect to
/// (attome-auth hardening 2.1d), with no binding cookie set.
fn is_link_marker(res: &axum::response::Response) -> bool {
    res.status() == StatusCode::SEE_OTHER
        && location(res).ends_with("/settings/security?reauth_required=identity_link")
        && cookie_value(res, "__Host-identity_link_oidc").is_none()
}

async fn json_of(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn link_status(app: &axum::Router, session: &str) -> serde_json::Value {
    let res = get(
        app,
        "/api/v1/auth/step-up/identity_link",
        &[session.to_owned()],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "the step-up status read");
    json_of(res).await
}

/// Base-auth hardening 2.1d (D-510 rules 7 and 9), identity linking over HTTP.
/// A link start without a fresh step-up sends the browser to re-authenticate and
/// creates no provider state. A cancelled or failed provider round trip, an
/// expired challenge and replays leave it so. A completed federated step-up
/// returns through its callback, and the same link start then proceeds to the
/// provider.
#[tokio::test]
async fn identity_linking_returns_through_a_federated_step_up_to_the_link() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let account = linked_account(&app, &state, &provider).await;
    let family = family_of(&state, &account.session_token);
    let session = format!("__Host-session_token={}", account.session_token);
    let link_start = format!("/api/v1/auth/identity-link/oidc/{provider}");
    let callback = |oauth_state: &str, query: &str| {
        format!("/api/v1/auth/step-up-callback/oidc/{provider}?{query}&state={oauth_state}")
    };

    let res = get(&app, &link_start, std::slice::from_ref(&session)).await;
    assert!(
        is_link_marker(&res),
        "an unelevated link start asks for a step-up, got {} {:?}",
        res.status(),
        res.headers().get(header::LOCATION)
    );
    let status = link_status(&app, &session).await;
    assert_eq!(status["elevated"], false);
    assert_eq!(
        status["acceptable_factors"],
        serde_json::json!(["password", "federated"])
    );

    // Cancelled at the provider: it redirects back with an error and no code.
    let challenge_id = start_challenge(&app, &account, "identity_link").await;
    let (authorize_url, binding) =
        start_federated(&app, &account, "identity_link", &challenge_id).await;
    let oauth_state = query_param(&authorize_url, "state");
    let binding_cookie = format!("__Host-step_up_oidc={binding}");
    let res = get(
        &app,
        &callback(&oauth_state, "error=access_denied"),
        std::slice::from_ref(&binding_cookie),
    )
    .await;
    let cancelled_location = res
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        !res.status().is_success() && !cancelled_location.contains("step_up=identity_link"),
        "a cancelled provider round trip is not a step-up, got {} {cancelled_location}",
        res.status()
    );
    assert_eq!(live_elevation(&state, family).await.0, None);
    assert!(is_link_marker(
        &get(&app, &link_start, std::slice::from_ref(&session)).await
    ));

    // A provider that fails the code exchange: the mock has no ID token queued.
    let res = get(
        &app,
        &callback(&oauth_state, "code=abc"),
        std::slice::from_ref(&binding_cookie),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(
        location(&res).ends_with("/settings/security?step_up_error=1"),
        "a failed provider round trip, got {}",
        location(&res)
    );
    assert_eq!(live_elevation(&state, family).await.0, None);
    assert!(is_link_marker(
        &get(&app, &link_start, std::slice::from_ref(&session)).await
    ));

    // An expired challenge cannot start a provider round trip.
    let expired = start_challenge(&app, &account, "identity_link").await;
    let _: i64 = state
        .redis_coordination
        .del(format!("auth:step_up:{expired}"))
        .await
        .expect("expire the challenge");
    let res = get(
        &app,
        &format!("/api/v1/auth/step-up/identity_link/oidc/{provider}?challenge_id={expired}"),
        std::slice::from_ref(&session),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body = json_of(res).await;
    assert_eq!(body["error"], "reauth_required", "an expired challenge");
    assert_eq!(body["operation"], "identity_link");

    // A fresh provider authentication, completed in the starting browser.
    let challenge_id = start_challenge(&app, &account, "identity_link").await;
    let (authorize_url, binding) =
        start_federated(&app, &account, "identity_link", &challenge_id).await;
    let oauth_state = query_param(&authorize_url, "state");
    let binding_cookie = format!("__Host-step_up_oidc={binding}");
    let nonce = query_param(&authorize_url, "nonce");
    let authenticated = db_now(&state).await.timestamp() - 30;
    idp.issue(&account.subject, &nonce, Some(authenticated));
    let completed = callback(&oauth_state, "code=abc");
    let res = get(&app, &completed, std::slice::from_ref(&binding_cookie)).await;
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(
        location(&res).ends_with("/settings/security?step_up=identity_link"),
        "the callback returns to the operation that asked, got {}",
        location(&res)
    );
    assert!(
        cookie_value(&res, "__Host-session_token").is_none(),
        "a step-up never issues a session"
    );
    let elevated = live_elevation(&state, family).await.0;
    assert!(elevated.is_some());

    // Replays: the same callback, with a token the provider would still hand
    // out, and the consumed challenge.
    idp.issue(&account.subject, &nonce, Some(authenticated));
    let res = get(&app, &completed, std::slice::from_ref(&binding_cookie)).await;
    assert!(
        location(&res).ends_with("/settings/security?step_up_error=1"),
        "a replayed callback is refused, got {}",
        location(&res)
    );
    let res = get(
        &app,
        &format!("/api/v1/auth/step-up/identity_link/oidc/{provider}?challenge_id={challenge_id}"),
        std::slice::from_ref(&session),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "a consumed challenge"
    );
    assert_eq!(live_elevation(&state, family).await.0, elevated);

    // Back to the operation that asked for the step-up.
    let status = link_status(&app, &session).await;
    assert_eq!(status["elevated"], true);
    let res = get(&app, &link_start, std::slice::from_ref(&session)).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    let link_authorize = location(&res);
    assert!(
        link_authorize.starts_with(&format!("{}/authorize?", idp.issuer)),
        "the elevated link start proceeds to the provider, got {link_authorize}"
    );
    assert!(query_param(&link_authorize, "redirect_uri").contains("identity-link-callback"));
    assert_eq!(
        cookie_value(&res, "__Host-identity_link_oidc"),
        Some(query_param(&link_authorize, "state")),
        "the link flow gets its own browser binding"
    );
}
// ── BAU-25 (finding BAU-F20): a provider that refuses or is cancelled ─────

/// Every callback must survive a provider that redirects back with `error`
/// and **no** code — RFC 6749 §4.1.2.1, and what a user pressing "cancel" at
/// the consent screen produces. Before BAU-25 the required `code`/`state`
/// query extraction answered axum's bare 400 before any handler ran, so the
/// browser stopped on a blank page instead of the error page each route
/// already knows how to render.
#[tokio::test]
async fn a_cancelled_provider_redirects_to_the_error_page() {
    let idp = mock_idp().await;
    // A unique provider key, like every other test here: the discovery document
    // is cached per provider for an hour in the shared Redis, and this mock's
    // port is different every run — a fixed key would read a stale document
    // whose issuer no longer matches, which validate_discovery correctly
    // refuses (BAU-7).
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let provider = provider.as_str();
    let account = linked_account(&app, &state, provider).await;
    let family = family_of(&state, &account.session_token);
    let challenge_id = start_challenge(&app, &account, "identity_link").await;
    let (authorize_url, binding) =
        start_federated(&app, &account, "identity_link", &challenge_id).await;
    let oauth_state = query_param(&authorize_url, "state");

    // Three ways back without a code: a refusal that echoes the state, an
    // error with no state at all, and a callback with nothing in it.
    let queries = [
        format!("error=access_denied&state={oauth_state}"),
        "error=consent_required".to_string(),
        String::new(),
    ];
    for query in &queries {
        let res = get(
            &app,
            &format!("/api/v1/auth/step-up-callback/oidc/{provider}?{query}"),
            &[format!("__Host-step_up_oidc={binding}")],
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::FOUND,
            "query {query:?} must redirect, not answer a bare 400"
        );
        assert!(
            location(&res).ends_with("/settings/security?step_up_error=1"),
            "query {query:?} must land on the step-up error page, got {}",
            location(&res)
        );
        assert_eq!(
            live_elevation(&state, family).await.0,
            None,
            "a cancelled step-up must elevate nothing"
        );
        assert!(
            cookie_value(&res, "__Host-step_up_oidc").is_none(),
            "a cancelled step-up must not clear the binding cookie: the genuine browser \
             may still be finishing this flow"
        );
    }

    // The challenge is untouched — the genuine browser can still complete it.
    idp.issue(
        &account.subject,
        &query_param(&authorize_url, "nonce"),
        Some(db_now(&state).await.timestamp()),
    );
    let res = get(
        &app,
        &format!("/api/v1/auth/step-up-callback/oidc/{provider}?code=abc&state={oauth_state}"),
        &[format!("__Host-step_up_oidc={binding}")],
    )
    .await;
    assert!(
        location(&res).ends_with("/settings/security?step_up=identity_link"),
        "the cancelled callbacks consumed nothing, so the same state still completes: got {}",
        location(&res)
    );
    assert!(live_elevation(&state, family).await.0.is_some());
}

/// The same defect on the ordinary sign-in route. It lives here because this
/// suite already assembles the full app (`auth::public_routes()` mounts
/// `/api/v1/auth/oidc/{provider}/callback`) and configures a provider; the
/// BAU-25 branch runs before the provider lookup, so this asserts on the real
/// route rather than a stub.
#[tokio::test]
async fn a_cancelled_sign_in_redirects_to_the_login_error_page() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, _state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let provider = provider.as_str();

    for query in ["error=access_denied", "state=only", ""] {
        let res = get(
            &app,
            &format!("/api/v1/auth/oidc/{provider}/callback?{query}"),
            &[],
        )
        .await;
        assert_eq!(
            res.status(),
            StatusCode::FOUND,
            "query {query:?} must redirect, not answer a bare 400"
        );
        assert!(
            location(&res).ends_with("/login?oidc_error=1"),
            "query {query:?} must land on the login error page, got {}",
            location(&res)
        );
        assert!(
            cookie_value(&res, "__Host-oidc_login").is_none(),
            "a cancelled sign-in must not clear a genuine in-flight flow's binding cookie"
        );
    }
}
// ── BAU-26 (finding BAU-F19): the GET callbacks must audit too ────────────

/// The ingest payloads one operation wrote for `record`, in order.
///
/// `audit.chainer_enabled` keeps its default (true), so every event these
/// routes write is in `audit_ingest` — the same read
/// `auth_audit_events.rs` makes. It lives in this suite because this is the
/// one that already assembles the federated driver the two tests below need
/// (a real mock IdP, a linked account and the step-up challenge); the
/// assertions themselves belong to BAU-26, whose row names
/// `auth_audit_events.rs`. Moving them there needs only this helper plus a
/// mock IdP in that suite.
async fn ingest_payloads(
    state: &AppState,
    operation: &str,
    record: Uuid,
) -> Vec<serde_json::Value> {
    let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
        "SELECT payload FROM audit_ingest \
         WHERE payload->>'operation' = $1 \
           AND (payload->>'record_id') IS NOT DISTINCT FROM $2 \
         ORDER BY id",
    )
    .bind(operation)
    .bind(Some(record.to_string()))
    .fetch_all(&state.db)
    .await
    .expect("read ingest payloads");
    rows.into_iter().map(|(payload,)| payload).collect()
}

/// The user a linked account belongs to — the record every one of these hooks
/// names.
async fn linked_user_id(state: &AppState, provider: &str, subject: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT user_ref FROM user_identity \
         WHERE provider_key = $1 AND provider_sub = $2",
    )
    .bind(provider)
    .bind(subject)
    .fetch_one(&state.db)
    .await
    .expect("the account is linked")
}

/// BAU-26 — a federated elevation is a re-authentication and commits the same
/// `Security`/`Login` event the local half does, inside the elevation's own
/// transaction. Before this the callback hard-coded `NoHook`, so a federated
/// elevation appeared in no audit trail at all.
#[tokio::test]
async fn a_federated_step_up_writes_one_security_event() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let account = linked_account(&app, &state, &provider).await;
    let family = family_of(&state, &account.session_token);
    let user_id = linked_user_id(&state, &provider, &account.subject).await;

    let challenge_id = start_challenge(&app, &account, "identity_link").await;
    let (authorize_url, binding) =
        start_federated(&app, &account, "identity_link", &challenge_id).await;
    let oauth_state = query_param(&authorize_url, "state");
    idp.issue(
        &account.subject,
        &query_param(&authorize_url, "nonce"),
        Some(db_now(&state).await.timestamp() - 45),
    );
    let res = get(
        &app,
        &format!("/api/v1/auth/step-up-callback/oidc/{provider}?code=abc&state={oauth_state}"),
        &[format!("__Host-step_up_oidc={binding}")],
    )
    .await;
    assert!(location(&res).ends_with("/settings/security?step_up=identity_link"));
    assert!(live_elevation(&state, family).await.0.is_some());

    // The account signed in first, so `Login` for this user also carries that
    // sign-in's own event; the assertion is that the *elevation* wrote exactly
    // one, named as such.
    let events = ingest_payloads(&state, "Login", user_id).await;
    let elevations: Vec<_> = events
        .iter()
        .filter(|event| {
            event["event_name"]
                .as_str()
                .is_some_and(|name| name.starts_with("step_up_federated"))
        })
        .collect();
    assert_eq!(
        elevations.len(),
        1,
        "a federated elevation writes exactly one event: {events:?}"
    );
    assert_eq!(elevations[0]["category"], "Security");
    assert!(
        elevations[0]["event_name"]
            .as_str()
            .unwrap_or_default()
            .contains("identity_link"),
        "the event names the stepped-up operation, got {:?}",
        elevations[0]["event_name"]
    );
}

/// BAU-26 — linking a federated identity is a credential change and must
/// commit its `Credential`/`Create` event with the link. The callback used
/// the `_with`-less variant, so it wrote nothing. The identity linked here is
/// a *new* subject for the same provider, which is the branch that creates a
/// row and therefore the one a hook must cover.
#[tokio::test]
async fn an_oidc_identity_link_writes_one_credential_event() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let account = linked_account(&app, &state, &provider).await;
    let user_id = linked_user_id(&state, &provider, &account.subject).await;

    // The link start route is guarded by a step-up for `identity_link`
    // (D-510), so elevate the session's family through the federated flow
    // first — exactly what the UI does.
    let challenge_id = start_challenge(&app, &account, "identity_link").await;
    let (authorize_url, binding) =
        start_federated(&app, &account, "identity_link", &challenge_id).await;
    let step_up_state = query_param(&authorize_url, "state");
    idp.issue(
        &account.subject,
        &query_param(&authorize_url, "nonce"),
        Some(db_now(&state).await.timestamp() - 45),
    );
    let res = get(
        &app,
        &format!("/api/v1/auth/step-up-callback/oidc/{provider}?code=abc&state={step_up_state}"),
        &[format!("__Host-step_up_oidc={binding}")],
    )
    .await;
    assert!(location(&res).ends_with("/settings/security?step_up=identity_link"));

    // The link itself: a second, different subject for the same provider.
    let new_subject = format!("linked-{user_id}");
    let session = format!("__Host-session_token={}", account.session_token);
    let res = get(
        &app,
        &format!("/api/v1/auth/identity-link/oidc/{provider}"),
        std::slice::from_ref(&session),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::SEE_OTHER,
        "the link start proceeds"
    );
    let link_authorize = location(&res);
    let link_state = query_param(&link_authorize, "state");
    assert_eq!(
        cookie_value(&res, "__Host-identity_link_oidc"),
        Some(link_state.clone()),
        "the link flow gets its own browser binding"
    );
    idp.issue(&new_subject, &query_param(&link_authorize, "nonce"), None);
    let res = get(
        &app,
        &format!("/api/v1/auth/identity-link-callback/oidc/{provider}?code=abc&state={link_state}"),
        &[format!("__Host-identity_link_oidc={link_state}")],
    )
    .await;
    assert!(
        location(&res).ends_with("/settings/security?identity_linked=1"),
        "the link completes, got {}",
        location(&res)
    );

    let events = ingest_payloads(&state, "Create", user_id).await;
    assert_eq!(
        events.len(),
        1,
        "the link writes exactly one event: {events:?}"
    );
    assert_eq!(events[0]["category"], "Credential");
    let name = events[0]["event_name"].as_str().unwrap_or_default();
    assert!(
        name.contains("identity_link:oidc"),
        "the event names the linked identity, got {name:?}"
    );
}

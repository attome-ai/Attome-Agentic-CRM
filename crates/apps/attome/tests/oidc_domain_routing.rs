//! Q1-T6: email-first sign-in and the checks a provider added on screen
//! makes, through the assembled HTTP stack against a local mock provider.
//!
//! `POST /api/v1/auth/oidc/discover` answers the provider of an email's
//! verified domain, and `null` for an unverified or unknown one, in the same
//! shape. A provider added on screen signs in only people whose email domain
//! is verified for it, and, with a tenant allow-list, only tokens from those
//! tenants.
//!
//! Each test uses its own provider key and domain. Requires a live Postgres
//! (`DATABASE_URL`, a throwaway database — attome-testkit clones it per binary)
//! and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`). Skips cleanly when
//! `DATABASE_URL` is unset. Run manually:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome --test oidc_domain_routing -- --test-threads=1
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
use attome_config::AppConfig;
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
const CLIENT_ID: &str = "oidc-domain-routing-client";
const KID: &str = "oidc-domain-routing-kid";
const SESSION_COOKIE: &str = "__Host-session_token";
/// The key provider client secrets are sealed under in this test.
const SEAL_KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";

/// A provider key no other test or run shares (at most 40 characters, the
/// `oidc_provider.key` rule).
fn unique_provider() -> String {
    format!("mock-{}", &Uuid::now_v7().simple().to_string()[12..])
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
    fn issue_id_token(&self, subject: &str, email: &str, nonce: &str, tid: Option<&str>) {
        let now = Utc::now().timestamp();
        let mut claims = serde_json::json!({
            "iss": self.issuer,
            "aud": CLIENT_ID,
            "sub": subject,
            "email": email,
            "email_verified": true,
            "nonce": nonce,
            "iat": now,
            "exp": now + 300,
        });
        if let Some(tid) = tid {
            claims["tid"] = serde_json::json!(tid);
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
    config.oidc.client_secret_encryption_key =
        serde_json::from_value(serde_json::json!(SEAL_KEY_HEX)).expect("seal key");
    let _ = (issuer, provider);
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

fn location(res: &axum::response::Response) -> String {
    res.headers()
        .get(header::LOCATION)
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_owned()
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

fn unique_domain() -> String {
    format!(
        "d{}.example.test",
        &Uuid::now_v7().simple().to_string()[16..]
    )
}

fn unique_local_part() -> String {
    format!("p{}", &Uuid::now_v7().simple().to_string()[20..])
}

/// A provider added on screen for the mock IdP, its client secret sealed as
/// the admin route seals it, then loaded into the registry.
async fn add_provider(state: &AppState, issuer: &str, key: &str, tenants: &[&str]) -> Uuid {
    let id = Uuid::now_v7();
    let sealed = attome_auth::oidc_registry::seal_secret(
        &state.config.oidc.client_secret_encryption_key,
        id,
        "mock-client-secret",
    )
    .expect("seal the client secret");
    sqlx::query(
        "INSERT INTO oidc_provider \
             (id, key, display_name, issuer, client_id, client_secret_enc, scopes, \
              link_mode, tenant_allowlist) \
         VALUES ($1, $2, 'Mock IdP', $3, $4, $5, ARRAY['openid', 'email'], 'link_only', $6)",
    )
    .bind(id)
    .bind(key)
    .bind(issuer)
    .bind(CLIENT_ID)
    .bind(sealed)
    .bind(tenants.iter().map(|t| (*t).to_owned()).collect::<Vec<_>>())
    .execute(&state.db)
    .await
    .expect("insert provider");
    state
        .oidc_providers
        .reload(
            &state.db,
            &state.config.oidc.providers,
            &state.secrets.load().oidc_client_secrets,
            &state.config.oidc.client_secret_encryption_key,
        )
        .await
        .expect("reload providers");
    assert!(state.oidc_providers.get(key).is_some(), "provider loaded");
    id
}

async fn add_domain(state: &AppState, provider_id: Uuid, domain: &str, verified: bool) {
    sqlx::query(
        "INSERT INTO oidc_domain (domain, provider_ref, verification_token, verified_at) \
         VALUES ($1, $2, 'token', CASE WHEN $3 THEN now() END)",
    )
    .bind(domain)
    .bind(provider_id)
    .bind(verified)
    .execute(&state.db)
    .await
    .expect("insert domain");
}

async fn discover(app: &axum::Router, email: &str) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/oidc/discover")
                .header(header::CONTENT_TYPE, "application/json")
                .header("origin", ALLOWED_ORIGIN)
                .body(Body::from(
                    serde_json::json!({ "email": email }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .expect("discover");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).expect("a JSON body"))
}

/// A person linked to `provider` as `email` signs in through it, the token
/// carrying `tid`. Answers the callback's response.
async fn sign_in(
    app: &axum::Router,
    state: &AppState,
    idp: &MockIdp,
    provider: &str,
    email: &str,
    tid: Option<&str>,
) -> axum::response::Response {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, email_verified) \
         VALUES ($1, $2, $3, true, true)",
    )
    .bind(user_id)
    .bind(format!("oidc-domain-{user_id}"))
    .bind(email)
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
    .bind(email)
    .execute(&state.db)
    .await
    .expect("link identity");

    let start = get(app, &format!("/api/v1/auth/oidc/{provider}/login"), &[]).await;
    assert!(
        start.status().is_redirection(),
        "login redirects to the provider"
    );
    let authorize = location(&start);
    let state_id = query_param(&authorize, "state");
    let nonce = query_param(&authorize, "nonce");
    let binding = cookie_value(&start, "__Host-oidc_login").expect("binding cookie");
    idp.issue_id_token(&subject, email, &nonce, tid);
    get(
        app,
        &format!("/api/v1/auth/oidc/{provider}/callback?code=c&state={state_id}"),
        &[format!("__Host-oidc_login={binding}")],
    )
    .await
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn discover_returns_provider_for_verified_domain() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let id = add_provider(&state, &idp.issuer, &provider, &[]).await;
    let domain = unique_domain();
    add_domain(&state, id, &domain, true).await;

    let (status, body) = discover(&app, &format!("Someone@{}", domain.to_uppercase())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["provider"], provider.as_str());
}

#[tokio::test]
async fn discover_returns_null_for_unverified_domain() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let id = add_provider(&state, &idp.issuer, &provider, &[]).await;
    let domain = unique_domain();
    add_domain(&state, id, &domain, false).await;

    // Unverified, unknown and malformed all answer the same way.
    for email in [
        format!("someone@{domain}"),
        format!("someone@{}", unique_domain()),
        "not-an-email".to_owned(),
    ] {
        let (status, body) = discover(&app, &email).await;
        assert_eq!(status, StatusCode::OK, "{email}");
        assert!(body["provider"].is_null(), "{email}: {body}");
    }
}

#[tokio::test]
async fn tenant_outside_allowlist_is_refused() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let id = add_provider(&state, &idp.issuer, &provider, &["tenant-a"]).await;
    let domain = unique_domain();
    add_domain(&state, id, &domain, true).await;

    for tid in [Some("tenant-b"), None] {
        let email = format!("{}@{domain}", unique_local_part());
        let res = sign_in(&app, &state, &idp, &provider, &email, tid).await;
        assert!(
            location(&res).ends_with("/login?tenant_not_allowed=1"),
            "{tid:?}: {}",
            location(&res)
        );
        assert!(
            cookie_value(&res, SESSION_COOKIE).is_none(),
            "no session for {tid:?}"
        );
    }
    let email = format!("{}@{domain}", unique_local_part());
    let res = sign_in(&app, &state, &idp, &provider, &email, Some("tenant-a")).await;
    assert!(
        cookie_value(&res, SESSION_COOKIE).is_some(),
        "an allowed tenant signs in"
    );
}

#[tokio::test]
async fn a_provider_added_on_screen_signs_in_only_verified_domains() {
    let idp = mock_idp().await;
    let provider = unique_provider();
    let (app, state) = skip_if_no_db!(test_app(&idp.issuer, &provider).await);
    let id = add_provider(&state, &idp.issuer, &provider, &[]).await;
    let verified = unique_domain();
    add_domain(&state, id, &verified, true).await;
    let pending = unique_domain();
    add_domain(&state, id, &pending, false).await;

    for domain in [pending, unique_domain()] {
        let email = format!("{}@{domain}", unique_local_part());
        let res = sign_in(&app, &state, &idp, &provider, &email, None).await;
        assert!(
            location(&res).ends_with("/login?domain_not_verified=1"),
            "{domain}: {}",
            location(&res)
        );
        assert!(cookie_value(&res, SESSION_COOKIE).is_none());
    }
    let email = format!("{}@{verified}", unique_local_part());
    let res = sign_in(&app, &state, &idp, &provider, &email, None).await;
    assert!(
        cookie_value(&res, SESSION_COOKIE).is_some(),
        "a verified domain signs in"
    );
}

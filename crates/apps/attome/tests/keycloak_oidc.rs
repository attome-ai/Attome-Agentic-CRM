//! D-108 — live OIDC verification against a real IdP (Keycloak), closing the
//! P2.8 gap this repo's docs have flagged since D-065/D-072: `verify_claims`
//! has unit coverage against a throwaway RSA key, but `oidc::complete_login`
//! had never run against a real IdP issuing real signed tokens. This drives
//! the actual `/api/v1/auth/oidc/{provider}/login|callback` routes end to
//! end against a real Keycloak container, the same way a browser would.
//!
//! Gated behind the `keycloak-tests` marker feature (`required-features` in
//! `Cargo.toml`) rather than this repo's usual env-var-panic convention — a
//! plain `cargo test --workspace` must never even attempt to collect this
//! binary, since an ordinary test run never brings up Keycloak.
//!
//! Requires:
//! - A live Postgres (`DATABASE_URL`, throwaway `attomedb_test` — NEVER
//!   `attome_dev`) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`, default
//!   `localhost:6379`), same convention as every other integration test here.
//! - Keycloak running with the `attome-test` realm imported:
//!   ```powershell
//!   docker compose -f crates/server/tests/keycloak/docker-compose.yml up -d
//!   ```
//!   `KEYCLOAK_BASE_URL` overrides the default `http://localhost:8090`.
//!
//! ```powershell
//! # NOTE the `?options=-c search_path=...` suffix — `create_pool` uses
//! # $env:DATABASE_URL verbatim when it's set (bypassing
//! # `AppConfig::database_url()`, which is what normally embeds this), so a
//! # bare `postgres://.../attomedb_test` with no role-level default
//! # search_path will 42P01 on the very first query ("relation ... does not
//! # exist") even though the tables are there, just in the `attome_dev`
//! # schema rather than `public`.
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! docker compose -f crates/server/tests/keycloak/docker-compose.yml up -d
//! cargo test -p server --features keycloak-tests --test keycloak_oidc -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;
use std::time::Duration;

use attome::auth;
use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
/// Fixed, never-bound placeholder — `frontend_url()` only needs to produce a
/// stable string the Keycloak client's registered redirect URI matches; the
/// backend under test is reached entirely via in-process `oneshot`, never a
/// real socket on this port.
const FIXED_FRONTEND_PORT: u16 = 9999;
const OIDC_PROVIDER_KEY: &str = "keycloak";
const OIDC_CLIENT_ID: &str = "attome-oidc-test";
const OIDC_CLIENT_SECRET: &str = "oidc-test-client-secret-throwaway";
const TEST_USERNAME: &str = "attome-test-user";
const TEST_PASSWORD: &str = "attome-test-Passw0rd!";
const TEST_EMAIL: &str = "attome-test-user@attome-test.invalid";
/// Q1-T15: the provider added through the admin API, signing in through the
/// same Keycloak client (its redirect and back-channel URLs name this key).
const DB_PROVIDER_KEY: &str = "keycloak-db";
const SALES_USERNAME: &str = "attome-sales-user";
const SALES_PASSWORD: &str = "attome-sales-Passw0rd!";
const SALES_EMAIL: &str = "attome-sales-user@attome-test.invalid";
const SEAL_KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";
/// Where the realm's back-channel logout URL points (`host.docker.internal`).
const BACKCHANNEL_PORT: u16 = 9998;

fn keycloak_base_url() -> String {
    std::env::var("KEYCLOAK_BASE_URL").unwrap_or_else(|_| "http://localhost:8090".into())
}

fn oidc_issuer() -> String {
    format!("{}/realms/attome-test", keycloak_base_url())
}

/// Polls the realm's own discovery endpoint — this only ever returns 200
/// once Keycloak has finished booting AND the `--import-realm` pass has
/// completed, which is exactly the readiness signal these tests need (unlike
/// Keycloak's generic `/health/ready`, which can report UP before the import
/// finishes).
async fn wait_for_keycloak_ready() {
    let url = format!("{}/.well-known/openid-configuration", oidc_issuer());
    let client = reqwest::Client::new();
    for _ in 0..30 {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    panic!(
        "Keycloak's attome-test realm never became ready at {url} — \
         is `docker compose -f crates/server/tests/keycloak/docker-compose.yml up -d` running? \
         See tests/keycloak_oidc.rs's header for the full local-run recipe."
    );
}

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": {frontend_port}, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 10,
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
                "secure_cookies": false,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{
                "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}}
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
            "cors": {{ "allowed_origins": ["http://allowed.test"] }},
            "oidc": {{
                "providers": {{
                    "{provider_key}": {{
                        "display_name": "Keycloak (test)",
                        "issuer": "{issuer}",
                        "client_id": "{client_id}",
                        "client_secret": "{client_secret}",
                        "scopes": ["openid", "email", "profile"],
                        "email_claim": "email"
                    }}
                }}
            }}
        }}"#,
        frontend_port = FIXED_FRONTEND_PORT,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        provider_key = OIDC_PROVIDER_KEY,
        issuer = oidc_issuer(),
        client_id = OIDC_CLIENT_ID,
        client_secret = OIDC_CLIENT_SECRET,
    );

    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    // Q1-T15: a provider added through the admin API has its secret sealed.
    config.oidc.client_secret_encryption_key =
        serde_json::from_value(serde_json::json!(SEAL_KEY_HEX)).expect("seal key");
    config
}

/// Same harness shape as `middleware_pipeline.rs`/`audit_throughput_load.rs`
/// — a real Postgres/Redis, the real `auth::public_routes()` + `EngineSystem`
/// composition, no real TCP listener (`tower::ServiceExt::oneshot` instead).
async fn test_app() -> Option<(axum::Router, AppState)> {
    // Q21-T1: the identity-provider client refuses a private host unless
    // boot lists its issuer; the test Keycloak is on localhost.
    let issuer = oidc_issuer();
    attome_auth::oidc::configure_identity_providers([issuer.as_str()]);
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
    // D-143: entity_crud/bulk routes are now license-gated (now MODULE_CORE, was MODULE_ENTITY pre-D-222) —
    // grant every module so this suite exercises them the same way a fully
    // licensed deployment would.
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));

    let base_state = system.state().base.clone();
    // P-license-enforcement-hardening Phase 5 (d): public_routes now needs
    // the live license handle for seat enforcement.
    let license = system.state().modules.clone();
    let auth_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );
    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
        out
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Scrapes Keycloak's `kc-form-login` action URL out of its login page HTML.
/// Fragile by nature (coupled to Keycloak's login-page markup for the pinned
/// image tag in `tests/keycloak/docker-compose.yml`) — if this ever breaks,
/// check Keycloak's release notes for a login-page/theme change before
/// assuming this repo's own code regressed.
fn extract_login_form_action(html: &str) -> String {
    let marker = "id=\"kc-form-login\"";
    let form_start = html
        .find(marker)
        .expect("Keycloak login page did not contain the expected kc-form-login element");
    let action_marker = "action=\"";
    let action_start = html[form_start..]
        .find(action_marker)
        .map(|i| form_start + i + action_marker.len())
        .expect("kc-form-login element had no action attribute");
    let action_end = html[action_start..]
        .find('"')
        .map(|i| action_start + i)
        .expect("unterminated action attribute");
    html[action_start..action_end].replace("&amp;", "&")
}

/// Extracts `code`/`state` off a redirected response's `Location` header —
/// the target of the redirect from our own OIDC callback route pattern.
fn extract_code_and_state(location: &str) -> (String, String) {
    let url = reqwest::Url::parse(location).expect("Location header must be a valid URL");
    let mut code = None;
    let mut state = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            _ => {}
        }
    }
    (
        code.expect("redirect Location must carry a code param"),
        state.expect("redirect Location must carry a state param"),
    )
}

/// Drives one full OIDC login against the real Keycloak container: fetches
/// the real authorize URL from our own `/oidc/{provider}/login` route (via
/// `oneshot`), follows it to Keycloak's login page (or straight through, if
/// this `client`'s cookie jar already has a live Keycloak SSO session from an
/// earlier call in the same test), submits the test user's credentials, and
/// returns the `code`/`state` our own callback route needs next, signing in
/// through `provider` as `username`.
///
/// Also returns the `Set-Cookie` pair the `/login` response issued — the
/// BAU-4a browser-binding cookie. A real browser stores it and replays it on
/// the cross-site redirect back, which is the whole point of the binding; a
/// harness that drops it is not modelling a browser, and without the cookie
/// the callback is (correctly) refused.
async fn drive_login_to_code_as(
    app: &axum::Router,
    client: &reqwest::Client,
    provider: &str,
    username: &str,
    password: &str,
) -> (String, String, String) {
    let login_req = Request::builder()
        .uri(format!("/api/v1/auth/oidc/{provider}/login"))
        .body(Body::empty())
        .unwrap();
    let login_res = app
        .clone()
        .oneshot(login_req)
        .await
        .expect("oidc login request");
    assert!(
        login_res.status().is_redirection(),
        "expected a redirect to Keycloak's authorize endpoint, got {}",
        login_res.status()
    );
    let authorize_url = login_res
        .headers()
        .get(header::LOCATION)
        .expect("oidc login response must carry a Location header")
        .to_str()
        .unwrap()
        .to_string();
    // What the browser jars on the way out (BAU-4a), replayed on the way back.
    // `secure_cookies = false` in this suite's config, so the bare name.
    let binding_cookie = login_res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|line| line.starts_with("oidc_login="))
        .expect("the sign-in start must set the oidc_login binding cookie")
        .split(';')
        .next()
        .unwrap_or_default()
        .to_owned();

    let resp = client
        .get(&authorize_url)
        .send()
        .await
        .expect("GET the Keycloak authorize URL");

    if let Some(location) = resp.headers().get(reqwest::header::LOCATION) {
        // Already-authenticated SSO session — Keycloak redirected straight back.
        let (code, state) = extract_code_and_state(location.to_str().unwrap());
        return (code, state, binding_cookie);
    }

    let html = resp.text().await.expect("read Keycloak login page body");
    let action = extract_login_form_action(&html);
    let body = form_urlencode(&[
        ("username", username),
        ("password", password),
        ("credentialId", ""),
    ]);
    let login_submit = client
        .post(&action)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .expect("POST credentials to Keycloak's login form");
    let location = login_submit
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("Keycloak must redirect back after a successful login")
        .to_str()
        .unwrap()
        .to_string();
    let (code, state) = extract_code_and_state(&location);
    (code, state, binding_cookie)
}

async fn drive_full_oidc_login(
    app: &axum::Router,
    client: &reqwest::Client,
) -> axum::http::Response<Body> {
    drive_full_login_as(app, client, OIDC_PROVIDER_KEY, TEST_USERNAME, TEST_PASSWORD).await
}

/// [`drive_full_oidc_login`] through `provider` as `username`.
async fn drive_full_login_as(
    app: &axum::Router,
    client: &reqwest::Client,
    provider: &str,
    username: &str,
    password: &str,
) -> axum::http::Response<Body> {
    let (code, state, binding_cookie) =
        drive_login_to_code_as(app, client, provider, username, password).await;
    let callback_req = Request::builder()
        .uri(format!(
            "/api/v1/auth/oidc/{provider}/callback?code={code}&state={state}"
        ))
        // The browser replays the binding cookie the start route set (BAU-4a).
        // Without it the callback is refused before the single-use state is
        // consumed or the IdP is contacted, which is the point of the binding.
        .header(header::COOKIE, binding_cookie)
        .body(Body::empty())
        .unwrap();
    app.clone()
        .oneshot(callback_req)
        .await
        .expect("oidc callback request")
}

fn reqwest_client_with_cookies() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client")
}

/// The Keycloak realm defines exactly one test user (`TEST_EMAIL`), shared by
/// every test in this file — unlike this repo's usual per-test throwaway-UUID
/// rows, there is no way to mint a second one without editing
/// `tests/keycloak/realm-export.json`. `oidc_login_after_account_disabled_is_rejected`
/// deliberately disables this shared account; call this at the start of any
/// test that expects a normal, successful login so it self-heals regardless
/// of what a previous test (or a previous crashed run) left behind — a
/// no-op if the row doesn't exist yet (first login of a fresh database).
async fn ensure_test_account_active(db: &attome_db::DbPool) {
    let _ = sqlx::query("UPDATE user_account SET is_active = true WHERE email = $1")
        .bind(TEST_EMAIL)
        .execute(db)
        .await;
}

#[tokio::test]
async fn oidc_login_against_real_keycloak_links_and_issues_a_session() {
    wait_for_keycloak_ready().await;
    let (app, state) = skip_if_no_db!(test_app().await);
    ensure_test_account_active(&state.db).await;
    let client = reqwest_client_with_cookies();

    let res = drive_full_oidc_login(&app, &client).await;
    assert!(
        res.status().is_redirection(),
        "expected a redirect back to the frontend, got {}",
        res.status()
    );
    let location = res
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        !location.contains("oidc_error"),
        "callback redirected to an error location: {location}"
    );
    let has_session_cookie = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or_default().starts_with("session_token="));
    assert!(
        has_session_cookie,
        "callback must set a session_token cookie"
    );

    let (provider_sub, email): (String, String) = sqlx::query_as(
        "SELECT provider_sub, email FROM user_identity WHERE provider_key = $1 AND email = $2",
    )
    .bind(OIDC_PROVIDER_KEY)
    .bind(TEST_EMAIL)
    .fetch_one(&state.db)
    .await
    .expect("user_identity row must exist after a successful OIDC login");
    assert_eq!(email, TEST_EMAIL);
    assert!(!provider_sub.is_empty());
}

#[tokio::test]
async fn oidc_login_twice_links_to_the_same_user_not_a_duplicate() {
    wait_for_keycloak_ready().await;
    let (app, state) = skip_if_no_db!(test_app().await);
    ensure_test_account_active(&state.db).await;

    // Two independent login rounds, each with its own cookie jar — mirrors
    // two separate browser sessions logging in as the same Keycloak user,
    // rather than reusing one single-use code/state twice.
    let client1 = reqwest_client_with_cookies();
    drive_full_oidc_login(&app, &client1).await;
    let client2 = reqwest_client_with_cookies();
    drive_full_oidc_login(&app, &client2).await;

    let (provider_sub,): (String,) = sqlx::query_as(
        "SELECT provider_sub FROM user_identity WHERE provider_key = $1 AND email = $2",
    )
    .bind(OIDC_PROVIDER_KEY)
    .bind(TEST_EMAIL)
    .fetch_one(&state.db)
    .await
    .expect("user_identity row must exist");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_identity WHERE provider_key = $1 AND provider_sub = $2",
    )
    .bind(OIDC_PROVIDER_KEY)
    .bind(&provider_sub)
    .fetch_one(&state.db)
    .await
    .expect("count user_identity rows");
    assert_eq!(
        count, 1,
        "a second login for the same (provider_key, provider_sub) must upsert, not duplicate"
    );
}

#[tokio::test]
async fn oidc_callback_with_a_stale_state_redirects_to_the_error_page() {
    wait_for_keycloak_ready().await;
    let (app, _state) = skip_if_no_db!(test_app().await);

    let callback_req = Request::builder()
        .uri(format!(
            "/api/v1/auth/oidc/{OIDC_PROVIDER_KEY}/callback?code=irrelevant&state={}",
            Uuid::now_v7()
        ))
        .body(Body::empty())
        .unwrap();
    let res = app
        .oneshot(callback_req)
        .await
        .expect("oidc callback request");

    assert_eq!(res.status(), StatusCode::FOUND);
    let location = res
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.contains("oidc_error=1"),
        "a state never issued by start_login must redirect to the error page, got {location}"
    );
}

/// D-113/P-account-state-enforcement's still-open item: a disabled account
/// must not be resurrected or re-linked via a federation login mid-flow.
/// `attome_security::accounts::link_external_identity` (called from
/// `attome_auth::oidc::complete_login`'s JIT-link step) returns
/// `AppError::Forbidden` for an existing identity whose `user_account` row
/// is disabled — this drives that path against a REAL Keycloak login (a
/// live, freshly-issued code, not a synthetic request), proving the full
/// `/api/v1/auth/oidc/{provider}/login|callback` round trip rejects it, not
/// just the library function in isolation.
#[tokio::test]
async fn oidc_login_after_account_disabled_is_rejected() {
    wait_for_keycloak_ready().await;
    let (app, state) = skip_if_no_db!(test_app().await);
    ensure_test_account_active(&state.db).await;

    // First login: creates + links the account normally (same shape as
    // `oidc_login_against_real_keycloak_links_and_issues_a_session`).
    let client1 = reqwest_client_with_cookies();
    let first = drive_full_oidc_login(&app, &client1).await;
    assert!(
        first.status().is_redirection(),
        "first login must succeed, got {}",
        first.status()
    );
    let has_session_cookie = first
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or_default().starts_with("session_token="));
    assert!(
        has_session_cookie,
        "first login must issue a session cookie"
    );

    let user_id: Uuid = sqlx::query_scalar("SELECT id FROM user_account WHERE email = $1")
        .bind(TEST_EMAIL)
        .fetch_one(&state.db)
        .await
        .expect("user_account row must exist after the first login");

    sqlx::query("UPDATE user_account SET is_active = false WHERE id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .expect("disable the account directly, same as the admin disable endpoint would");

    // Second login: a genuinely fresh Keycloak authorization code/assertion
    // for the SAME user — not a replay of the first one.
    let client2 = reqwest_client_with_cookies();
    let second = drive_full_oidc_login(&app, &client2).await;

    assert_eq!(
        second.status(),
        StatusCode::FOUND,
        "a disabled account's login must redirect to the error page, not succeed"
    );
    let location = second
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        location.contains("oidc_error=1"),
        "a disabled account's login must redirect with oidc_error=1, got {location}"
    );
    let has_session_cookie = second
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap_or_default().starts_with("session_token="));
    assert!(
        !has_session_cookie,
        "a disabled account's login must NOT issue a session cookie"
    );

    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(user_id)
            .fetch_one(&state.db)
            .await
            .expect("user_account row must still exist");
    assert_eq!(
        is_active,
        Some(false),
        "the login attempt must not resurrect the disabled account"
    );

    // Restore the shared test account for every other test in this file (and
    // any future run) — see `ensure_test_account_active`'s doc comment.
    ensure_test_account_active(&state.db).await;
}

// ── Q1-T15: a provider added through the admin API ───────────────────────────

/// A `system.admin` and their session cookie (`secure_cookies = false`).
async fn seed_admin_cookie(state: &AppState) -> String {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $2 || '@admin.invalid', true)",
    )
    .bind(user_id)
    .bind(format!("keycloak-admin-{user_id}"))
    .execute(&state.db)
    .await
    .expect("insert admin");
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
        aud: state.config.jwt_audience().to_string(),
        typ: attome_auth::TokenType::Session,
    };
    let token = attome_auth::create_token(&claims, &state.secrets.load().jwt_secret)
        .expect("encode admin token");
    format!(
        "{}={token}",
        attome_auth::cookie::session_cookie_name(false)
    )
}

async fn admin_call(
    app: &axum::Router,
    cookie: &str,
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::COOKIE, cookie)
                .header("origin", "http://allowed.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .expect("admin request");
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// Adds the Keycloak client as a provider through the admin API (sign-ups
/// allowed, the `groups` claim read), verifies the realm's email domain for
/// it, and loads it into the sign-in list. Returns its id.
async fn add_db_provider(app: &axum::Router, state: &AppState, admin: &str) -> Uuid {
    let (status, created) = admin_call(
        app,
        admin,
        "POST",
        "/api/v1/admin/security/oidc-providers",
        serde_json::json!({
            "key": DB_PROVIDER_KEY,
            "display_name": "Keycloak (database)",
            "issuer": oidc_issuer(),
            "client_id": OIDC_CLIENT_ID,
            "client_secret": OIDC_CLIENT_SECRET,
            "scopes": ["openid", "email", "profile"],
            "claim_map": { "groups": "groups" },
            "link_mode": "create",
        }),
    )
    .await;
    // Both tests in this binary add it; the second finds it there.
    let provider_id: Uuid = if status == StatusCode::CONFLICT {
        sqlx::query_scalar("SELECT id FROM oidc_provider WHERE key = $1 AND NOT is_deleted")
            .bind(DB_PROVIDER_KEY)
            .fetch_one(&state.db)
            .await
            .expect("the provider an earlier test added")
    } else {
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create the provider: {created}"
        );
        created["id"].as_str().unwrap().parse().unwrap()
    };
    // The domain proof is DNS, out of a test's reach; the row it leaves.
    sqlx::query(
        "INSERT INTO oidc_domain (domain, provider_ref, verification_token, verified_at) \
         VALUES ('attome-test.invalid', $1, 'token', now()) \
         ON CONFLICT (domain) DO UPDATE SET provider_ref = EXCLUDED.provider_ref, verified_at = now()",
    )
    .bind(provider_id)
    .execute(&state.db)
    .await
    .expect("verify the realm's domain");
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
    assert!(state.oidc_providers.get(DB_PROVIDER_KEY).is_some());
    provider_id
}

fn cookie_named(res: &axum::http::Response<Body>, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

#[tokio::test]
async fn db_provider_login_applies_group_mapping() {
    wait_for_keycloak_ready().await;
    let (app, state) = skip_if_no_db!(test_app().await);
    let admin = seed_admin_cookie(&state).await;
    let provider_id = add_db_provider(&app, &state, &admin).await;

    let team_id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(team_id)
        .bind(format!("keycloak-sales-{team_id}"))
        .execute(&state.db)
        .await
        .expect("insert team");
    let (status, mapping) = admin_call(
        &app,
        &admin,
        "POST",
        &format!("/api/v1/admin/security/oidc-providers/{provider_id}/group-mappings"),
        serde_json::json!({ "claim_value": "sales", "team_id": team_id }),
    )
    .await;
    assert!(
        status.is_success(),
        "create the mapping: {status} {mapping}"
    );

    let client = reqwest_client_with_cookies();
    let res = drive_full_login_as(
        &app,
        &client,
        DB_PROVIDER_KEY,
        SALES_USERNAME,
        SALES_PASSWORD,
    )
    .await;
    let location = res
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert_eq!(res.status(), StatusCode::FOUND);
    assert!(
        !location.contains("oidc_error"),
        "sign-in failed: {location}"
    );
    assert!(
        cookie_named(&res, "session_token").is_some(),
        "a session was issued"
    );

    let in_team: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_account_mm_team ut \
                          JOIN user_account u ON u.id = ut.user_ref \
                         WHERE u.email = $1 AND ut.team_ref = $2 AND NOT ut.is_deleted)",
    )
    .bind(SALES_EMAIL)
    .bind(team_id)
    .fetch_one(&state.db)
    .await
    .expect("read team membership");
    assert!(
        in_team,
        "the Keycloak group `sales` put the person in the mapped team"
    );
}

/// A Keycloak administrator's admin token (the master realm's `admin-cli`).
async fn keycloak_admin_token(client: &reqwest::Client) -> String {
    let res = client
        .post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            keycloak_base_url()
        ))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_urlencode(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "admin"),
            ("password", "admin-throwaway-pw"),
        ]))
        .send()
        .await
        .expect("Keycloak admin token request");
    let body: serde_json::Value = res.json().await.expect("admin token JSON");
    body["access_token"]
        .as_str()
        .expect("an admin access token")
        .to_owned()
}

#[tokio::test]
async fn keycloak_backchannel_logout_ends_session() {
    wait_for_keycloak_ready().await;
    let (app, state) = skip_if_no_db!(test_app().await);
    let admin = seed_admin_cookie(&state).await;
    add_db_provider(&app, &state, &admin).await;

    // Keycloak posts the logout token to this listener (the realm's
    // back-channel URL), from inside its container.
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", BACKCHANNEL_PORT))
        .await
        .expect("bind the back-channel listener");
    let served = app.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, served).await;
    });

    let client = reqwest_client_with_cookies();
    let res = drive_full_login_as(
        &app,
        &client,
        DB_PROVIDER_KEY,
        SALES_USERNAME,
        SALES_PASSWORD,
    )
    .await;
    assert_eq!(res.status(), StatusCode::FOUND);
    let refresh = cookie_named(&res, "refresh_token").expect("a refresh cookie");
    let user_id: Uuid = sqlx::query_scalar("SELECT id FROM user_account WHERE email = $1")
        .bind(SALES_EMAIL)
        .fetch_one(&state.db)
        .await
        .expect("the signed-in person");
    // This sign-in's family only: an earlier test may have left the same
    // person signed in through the same provider.
    let public_id: Uuid = refresh
        .split_once('.')
        .and_then(|(id, _)| id.parse().ok())
        .expect("the refresh token's public id");
    let live = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM refresh_token \
              WHERE user_ref = $1 AND oidc_provider = $2 AND revoked_at IS NULL \
                AND family_id = (SELECT family_id FROM refresh_token WHERE public_id = $3)",
        )
        .bind(user_id)
        .bind(DB_PROVIDER_KEY)
        .bind(public_id)
        .fetch_one(&state.db)
        .await
        .expect("count live families")
    };
    assert!(live().await > 0, "the sign-in left a live session");

    // Sign the person out in Keycloak: it ends their session there and
    // posts a logout token to every client's back-channel URL.
    let kc = reqwest::Client::new();
    let token = keycloak_admin_token(&kc).await;
    let users: serde_json::Value = kc
        .get(format!(
            "{}/admin/realms/attome-test/users?username={SALES_USERNAME}&exact=true",
            keycloak_base_url()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("find the Keycloak user")
        .json()
        .await
        .expect("users JSON");
    let kc_user = users[0]["id"].as_str().expect("the Keycloak user id");
    let logout = kc
        .post(format!(
            "{}/admin/realms/attome-test/users/{kc_user}/logout",
            keycloak_base_url()
        ))
        .bearer_auth(&token)
        .send()
        .await
        .expect("sign the user out in Keycloak");
    assert!(
        logout.status().is_success(),
        "Keycloak logout: {}",
        logout.status()
    );

    let mut ended = false;
    for _ in 0..40 {
        if live().await == 0 {
            ended = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    server.abort();
    assert!(
        ended,
        "the provider's back-channel logout ended the session"
    );

    let refreshed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header(header::COOKIE, format!("refresh_token={refresh}"))
                .header("origin", "http://allowed.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .expect("refresh request");
    assert_eq!(
        refreshed.status(),
        StatusCode::UNAUTHORIZED,
        "the next refresh is refused"
    );
}

//! Q2-T3: a person from a SAML identity provider signs in to Attome
//! through Keycloak, which speaks OIDC to Attome (V2-D471: Attome itself
//! has no SAML). The `attome-test` realm brokers the `saml-idp` realm
//! (`tests/keycloak/saml-idp-realm.json`) as identity provider `saml-idp`:
//! AuthnRequest and Response by HTTP-Redirect, unsigned (a test IdP),
//! email as the NameID, and email, names and a `groups` attribute passed
//! through. Keycloak's first-broker-login creates the brokered user, and an
//! `Advanced Attribute to Group` mapper puts them in the realm's `sales`
//! group when the SAML `groups` attribute says `sales`, so the OIDC client's
//! `groups` claim carries it.
//!
//! Run like `keycloak_oidc.rs` (live Keycloak, `--features keycloak-tests`):
//!
//! ```powershell
//! docker compose -f crates/apps/attome/tests/keycloak/docker-compose.yml up -d
//! cargo test -p attome --features keycloak-tests --test keycloak_saml_broker -- q2_ --test-threads=1
//! ```
//!
//! The harness (configuration, app, form and redirect helpers) is copied
//! from `keycloak_oidc.rs`; the sign-in walk adds `kc_idp_hint=saml-idp` to
//! Keycloak's authorize URL, as a sign-in button for that IdP would, and
//! follows the broker's redirects and any auto-posted SAML form.

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
/// Fixed, never-bound placeholder: the Keycloak client's redirect URIs name
/// it; the app is reached in process.
const FIXED_FRONTEND_PORT: u16 = 9999;
const OIDC_PROVIDER_KEY: &str = "keycloak";
const OIDC_CLIENT_ID: &str = "attome-oidc-test";
const OIDC_CLIENT_SECRET: &str = "oidc-test-client-secret-throwaway";
/// The provider added through the admin API (its redirect URI is registered).
const DB_PROVIDER_KEY: &str = "keycloak-db";
const SEAL_KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";
/// The `attome-test` realm's identity provider for the SAML realm.
const SAML_IDP_ALIAS: &str = "saml-idp";
const SAML_USERNAME: &str = "saml.user";
const SAML_PASSWORD: &str = "saml-user-Passw0rd!";
const SAML_EMAIL: &str = "saml.user@example.test";
/// Most hops the walk follows before giving up.
const MAX_HOPS: usize = 20;

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

fn reqwest_client_with_cookies() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build reqwest client")
}

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

fn cookie_named(res: &axum::http::Response<Body>, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

/// The value of the hidden input `name` in `html` (Keycloak's auto-post
/// form writes its tags upper case). Pure.
fn hidden_input(html: &str, name: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let at = lower.find(&format!("name=\"{}\"", name.to_ascii_lowercase()))?;
    let tag_start = lower[..at].rfind('<')?;
    let tag_end = at + lower[at..].find('>')?;
    let tag = &lower[tag_start..tag_end];
    let v = tag.find("value=\"")? + "value=\"".len();
    let start = tag_start + v;
    let end = start + html[start..].find('"')?;
    Some(html[start..end].replace("&amp;", "&"))
}

/// The `action` of the first form in `html`, resolved against `base`. Pure.
fn form_action(html: &str, base: &reqwest::Url) -> Option<reqwest::Url> {
    let lower = html.to_ascii_lowercase();
    let form = lower.find("<form")?;
    let a = form + lower[form..].find("action=\"")? + "action=\"".len();
    let end = a + html[a..].find('"')?;
    base.join(&html[a..end].replace("&amp;", "&")).ok()
}

/// Follows `res` through redirects and auto-posted SAML forms until Keycloak
/// sends the browser back to Attome's callback with a code, or shows a page
/// that is neither (returned for the caller to act on).
async fn walk(
    client: &reqwest::Client,
    mut res: reqwest::Response,
) -> Result<(String, String), (reqwest::Url, String)> {
    for _ in 0..MAX_HOPS {
        let here = res.url().clone();
        if let Some(location) = res.headers().get(reqwest::header::LOCATION) {
            let next = here
                .join(location.to_str().expect("a Location header"))
                .expect("a Location URL");
            if next.port() == Some(FIXED_FRONTEND_PORT) && next.path().ends_with("/callback") {
                return Ok(extract_code_and_state(next.as_str()));
            }
            res = client.get(next).send().await.expect("follow a redirect");
            continue;
        }
        let html = res.text().await.expect("read a Keycloak page");
        if let Some(response) = hidden_input(&html, "SAMLResponse") {
            let action = form_action(&html, &here).expect("the SAML form's action");
            let mut pairs = vec![("SAMLResponse", response.clone())];
            if let Some(relay) = hidden_input(&html, "RelayState") {
                pairs.push(("RelayState", relay));
            }
            let body = form_urlencode(
                &pairs
                    .iter()
                    .map(|(k, v)| (*k, v.as_str()))
                    .collect::<Vec<_>>(),
            );
            res = client
                .post(action)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-www-form-urlencoded",
                )
                .body(body)
                .send()
                .await
                .expect("post the SAML response");
            continue;
        }
        return Err((here, html));
    }
    panic!("the sign-in did not come back to Attome within {MAX_HOPS} hops");
}

/// Signs in through `provider` with Keycloak sent straight to the SAML IdP,
/// as `saml.user`. Returns the code, state and Attome's binding cookie.
async fn saml_login_to_code(
    app: &axum::Router,
    client: &reqwest::Client,
    provider: &str,
) -> (String, String, String) {
    let login_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/auth/oidc/{provider}/login"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oidc login request");
    assert!(login_res.status().is_redirection());
    let authorize_url = login_res
        .headers()
        .get(header::LOCATION)
        .expect("a redirect to Keycloak")
        .to_str()
        .unwrap()
        .to_owned();
    let binding_cookie = login_res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|line| line.starts_with("oidc_login="))
        .expect("the oidc_login binding cookie")
        .split(';')
        .next()
        .unwrap_or_default()
        .to_owned();

    // A sign-in button for this IdP sends the hint; Keycloak then skips its
    // own login page and redirects to the SAML IdP.
    let hinted = format!("{authorize_url}&kc_idp_hint={SAML_IDP_ALIAS}");
    let first = client
        .get(&hinted)
        .send()
        .await
        .expect("GET the authorize URL");
    let (page, html) = match walk(client, first).await {
        Ok((code, state)) => return (code, state, binding_cookie),
        Err(page) => page,
    };
    assert!(
        page.path().starts_with("/realms/saml-idp/"),
        "expected the SAML IdP's login page, got {page}"
    );
    let action = extract_login_form_action(&html);
    let submitted = client
        .post(&action)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(form_urlencode(&[
            ("username", SAML_USERNAME),
            ("password", SAML_PASSWORD),
            ("credentialId", ""),
        ]))
        .send()
        .await
        .expect("POST credentials to the SAML IdP");
    match walk(client, submitted).await {
        Ok((code, state)) => (code, state, binding_cookie),
        Err((page, html)) => panic!(
            "the broker stopped at {page} instead of returning to Attome: {}",
            html.chars().take(400).collect::<String>()
        ),
    }
}

/// The callback for a code [`saml_login_to_code`] obtained.
async fn saml_login(
    app: &axum::Router,
    client: &reqwest::Client,
    provider: &str,
) -> axum::http::Response<Body> {
    let (code, state, binding_cookie) = saml_login_to_code(app, client, provider).await;
    app.clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/auth/oidc/{provider}/callback?code={code}&state={state}"
                ))
                .header(header::COOKIE, binding_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oidc callback request")
}

/// The brokered user's own row may be disabled by an earlier run's test of
/// another file; keep it usable.
async fn ensure_saml_account_active(db: &attome_db::DbPool) {
    let _ = sqlx::query("UPDATE user_account SET is_active = true WHERE email = $1")
        .bind(SAML_EMAIL)
        .execute(db)
        .await;
}

#[tokio::test]
async fn q2_saml_brokered_login_creates_session() {
    wait_for_keycloak_ready().await;
    let (app, state) = skip_if_no_db!(test_app().await);
    ensure_saml_account_active(&state.db).await;
    let client = reqwest_client_with_cookies();

    let res = saml_login(&app, &client, OIDC_PROVIDER_KEY).await;
    let location = res
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(res.status().is_redirection(), "got {}", res.status());
    assert!(
        !location.contains("oidc_error"),
        "the callback failed: {location}"
    );
    assert!(
        cookie_named(&res, "session_token").is_some(),
        "the callback sets a session"
    );
    let email: String = sqlx::query_scalar(
        "SELECT email FROM user_identity WHERE provider_key = $1 AND email = $2",
    )
    .bind(OIDC_PROVIDER_KEY)
    .bind(SAML_EMAIL)
    .fetch_one(&state.db)
    .await
    .expect("the brokered person is linked by their SAML email");
    assert_eq!(email, SAML_EMAIL);
}

#[tokio::test]
async fn q2_saml_groups_reach_group_mapping() {
    wait_for_keycloak_ready().await;
    let (app, state) = skip_if_no_db!(test_app().await);
    ensure_saml_account_active(&state.db).await;
    let admin = seed_admin_cookie(&state).await;

    // The provider added through the admin API reads the `groups` claim.
    let (status, created) = admin_call(
        &app,
        &admin,
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
    let provider_id: Uuid = if status == StatusCode::CONFLICT {
        sqlx::query_scalar("SELECT id FROM oidc_provider WHERE key = $1 AND NOT is_deleted")
            .bind(DB_PROVIDER_KEY)
            .fetch_one(&state.db)
            .await
            .expect("the provider an earlier run added")
    } else {
        assert_eq!(
            status,
            StatusCode::CREATED,
            "create the provider: {created}"
        );
        created["id"].as_str().unwrap().parse().unwrap()
    };
    // The SAML user's domain, verified for this provider (the DNS proof is
    // out of a test's reach; this is the row it leaves).
    sqlx::query(
        "INSERT INTO oidc_domain (domain, provider_ref, verification_token, verified_at) \
         VALUES ('example.test', $1, 'token', now()) \
         ON CONFLICT (domain) DO UPDATE SET provider_ref = EXCLUDED.provider_ref, verified_at = now()",
    )
    .bind(provider_id)
    .execute(&state.db)
    .await
    .expect("verify the SAML realm's domain");
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

    let team_id = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(team_id)
        .bind(format!("saml-sales-{team_id}"))
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
    let res = saml_login(&app, &client, DB_PROVIDER_KEY).await;
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

    let in_team: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_account_mm_team ut \
                          JOIN user_account u ON u.id = ut.user_ref \
                         WHERE u.email = $1 AND ut.team_ref = $2 AND NOT ut.is_deleted)",
    )
    .bind(SAML_EMAIL)
    .bind(team_id)
    .fetch_one(&state.db)
    .await
    .expect("read team membership");
    assert!(
        in_team,
        "the SAML `groups` attribute reached the groups claim and the mapped team"
    );
}

#[test]
fn q2_hidden_inputs_are_read_from_keycloaks_upper_case_form() {
    let html = r#"<HTML><BODY Onload="document.forms[0].submit()"><FORM METHOD="POST" ACTION="http://kc/realms/attome-test/broker/saml-idp/endpoint?a=1&amp;b=2"><INPUT TYPE="HIDDEN" NAME="SAMLResponse" VALUE="PHNhbWw+"/><INPUT TYPE="HIDDEN" NAME="RelayState" VALUE="r-1"/></FORM></BODY></HTML>"#;
    assert_eq!(
        hidden_input(html, "SAMLResponse").as_deref(),
        Some("PHNhbWw+")
    );
    assert_eq!(hidden_input(html, "RelayState").as_deref(), Some("r-1"));
    assert_eq!(hidden_input(html, "Missing"), None);
    let base = reqwest::Url::parse("http://kc/realms/saml-idp/login").unwrap();
    assert_eq!(
        form_action(html, &base).unwrap().as_str(),
        "http://kc/realms/attome-test/broker/saml-idp/endpoint?a=1&b=2"
    );
}

//! BAU-F1 / P0.1 (G-10) — the staff OIDC **sign-in** callback must arrive in
//! the browser that started the sign-in.
//!
//! Before this test's fix, `oidc_login` set no binding cookie and
//! `oidc_callback` trusted `state` alone: an attacker starts a sign-in, signs
//! in at the IdP as themselves, and hands the victim the callback URL. The
//! victim's browser completes it and is signed in to the *attacker's* account
//! (login CSRF). Link and step-up flows already carry the binding
//! (`identity_link_binding.rs`); this file is the sign-in flow's half.
//!
//! No IdP is needed. The start route is driven fully offline by priming the
//! provider's discovery-document cache (`oidc:discovery:{provider}`, the same
//! key `attome_auth::oidc::fetch_discovery` reads first), and the callback's
//! binding check runs before any IdP contact, so the negative cases never
//! leave the process. The positive case proves it got *past* the check by
//! observing the single-use state being consumed — the only step that follows
//! the check and precedes the (unreachable) token exchange.
//!
//! Same harness shape as `identity_link_binding.rs`: real Postgres/Redis, the
//! real `auth::public_routes()`/`protected_routes()` composition, in-process
//! `oneshot` instead of a socket. Needs `DATABASE_URL` (throwaway — NEVER
//! `attome_dev`), `APP_ENV=debug`, and `TEST_REDIS_HOST`/`TEST_REDIS_PORT`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

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
const PROVIDER_KEY: &str = "signin-binding-test";
/// Nothing listens here. The start route never reaches it (discovery is
/// primed into Redis below); the positive callback case's token exchange
/// hits it and fails fast, which is exactly what that case wants.
const UNREACHABLE_IDP: &str = "http://127.0.0.1:1";
/// `secure_cookies = false` in the config below, so the bare name applies —
/// the `__Host-` half of the naming is covered by the unit tests in `oidc.rs`.
const BINDING_COOKIE: &str = "oidc_login";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
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
                        "display_name": "Sign-in binding test IdP",
                        "issuer": "{issuer}",
                        "client_id": "signin-binding-test-client",
                        "client_secret": "signin-binding-test-client-secret-throwaway",
                        "scopes": ["openid", "email"],
                        "email_claim": "email"
                    }}
                }}
            }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        provider_key = PROVIDER_KEY,
        issuer = UNREACHABLE_IDP,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_app() -> Option<(axum::Router, AppState)> {
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
        .add_bundle(system.core_routes())
        .add_bundle(public_bundle)
        .add_bundle(protected_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

/// Lets `attome_auth::oidc::start_login` build the authorize URL without an
/// IdP: `fetch_discovery` serves this cached document and never fetches.
async fn prime_discovery_cache(state: &AppState) {
    let doc = format!(
        r#"{{"authorization_endpoint":"{UNREACHABLE_IDP}/authorize","token_endpoint":"{UNREACHABLE_IDP}/token","jwks_uri":"{UNREACHABLE_IDP}/jwks"}}"#
    );
    state
        .redis
        .set(
            &format!("oidc:discovery:{PROVIDER_KEY}"),
            &(doc).to_string(),
            Some(std::time::Duration::from_secs(120)),
        )
        .await
        .expect("prime oidc discovery cache");
}

fn query_param(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

fn header_str(res: &axum::response::Response, name: header::HeaderName) -> Option<&str> {
    res.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Drives the bypass-listed sign-in start route and returns the `state` it
/// minted plus the raw `Set-Cookie` line it issued.
async fn start_sign_in(app: &axum::Router) -> (String, String) {
    let req = Request::builder()
        .uri(format!("/api/v1/auth/oidc/{PROVIDER_KEY}/login"))
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("login request");
    assert!(
        res.status().is_redirection(),
        "sign-in start must redirect to the IdP, got {}",
        res.status()
    );
    let location = header_str(&res, header::LOCATION)
        .expect("sign-in start must carry a Location header")
        .to_owned();
    assert!(
        location.starts_with(&format!("{UNREACHABLE_IDP}/authorize?")),
        "sign-in start must redirect to the primed authorization_endpoint, got {location}"
    );
    let state_id = query_param(&location, "state").expect("authorize URL must carry a state");
    let set_cookie = header_str(&res, header::SET_COOKIE)
        .expect("sign-in start must set the browser-binding cookie")
        .to_owned();
    (state_id, set_cookie)
}

async fn callback(
    app: &axum::Router,
    state_id: &str,
    binding_cookie: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().uri(format!(
        "/api/v1/auth/oidc/{PROVIDER_KEY}/callback?code=throwaway&state={state_id}"
    ));
    if let Some(cookie) = binding_cookie {
        builder = builder.header(header::COOKIE, format!("{BINDING_COOKIE}={cookie}"));
    }
    app.clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .expect("callback request")
}

async fn pending_state_exists(state: &AppState, state_id: &str) -> bool {
    let n: i64 = state
        .redis_coordination
        .exists(format!("oidc:state:{state_id}"))
        .await
        .expect("EXISTS oidc:state");
    n == 1
}

/// Every `Set-Cookie` line on a response, in order.
fn set_cookies(res: &axum::response::Response) -> Vec<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect()
}

/// No session was issued: neither session cookie name appears on the response.
fn assert_no_session_cookie(res: &axum::response::Response) {
    for line in set_cookies(res) {
        assert!(
            !line.starts_with("session_token=")
                && !line.starts_with("__Host-session_token=")
                && !line.starts_with("refresh_token=")
                && !line.starts_with("__Secure-refresh_token="),
            "a refused sign-in callback must not issue a session, got {line}"
        );
    }
}

#[tokio::test]
async fn login_start_sets_a_binding_cookie_carrying_the_flow_state() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;

    let (state_id, set_cookie) = start_sign_in(&app).await;

    assert_eq!(
        set_cookie,
        format!("{BINDING_COOKIE}={state_id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600"),
        "the sign-in start must bind the flow to this browser: a cookie \
         carrying exactly the state the IdP will echo back, HttpOnly, Lax (a \
         Strict cookie is withheld on the redirect back from the IdP), Path=/, \
         and living no longer than ten minutes"
    );
    assert!(
        pending_state_exists(&state, &state_id).await,
        "start must have written the single-use state the callback consumes"
    );
}

#[tokio::test]
async fn a_sign_in_callback_from_another_browser_signs_nobody_in() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;
    let (state_id, _) = start_sign_in(&app).await;

    // The victim's browser: a valid state (handed over by the attacker) but no
    // binding cookie, because it never started this sign-in.
    let res = callback(&app, &state_id, None).await;

    assert_no_session_cookie(&res);
    assert!(
        pending_state_exists(&state, &state_id).await,
        "the sign-in callback must refuse BEFORE the single-use state is \
         consumed — otherwise the genuine flow the attacker hijacked is dead"
    );
    assert_eq!(res.status(), StatusCode::FOUND);
    let location = header_str(&res, header::LOCATION).expect("callback must redirect");
    assert!(
        location.ends_with("/login?oidc_error=1"),
        "a refused callback redirects to the login error page, got {location}"
    );
}

#[tokio::test]
async fn a_sign_in_callback_with_a_mismatched_cookie_signs_nobody_in() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;
    let (state_id, _) = start_sign_in(&app).await;

    // A browser holding a binding cookie for some OTHER flow it started.
    let other_state = Uuid::now_v7().to_string();
    let res = callback(&app, &state_id, Some(&other_state)).await;

    assert_no_session_cookie(&res);
    assert!(pending_state_exists(&state, &state_id).await);
}

#[tokio::test]
async fn the_genuine_browser_completes_the_round_trip() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;
    let (state_id, _) = start_sign_in(&app).await;

    // The same browser that started the sign-in: the cookie equals the state.
    let res = callback(&app, &state_id, Some(&state_id)).await;

    // The check passed, so `complete_login` ran: the single-use state is
    // consumed (the step right after the check), and only then does the token
    // exchange fail against the unreachable IdP — which is as far as this
    // harness can go without a real IdP (`keycloak_oidc.rs` covers the
    // exchange itself).
    assert!(
        !pending_state_exists(&state, &state_id).await,
        "a matching cookie must let the callback proceed to consume the state"
    );
    assert_no_session_cookie(&res);
    assert_eq!(res.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn the_binding_cookie_is_cleared_once_its_flow_has_run() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;
    let (state_id, _) = start_sign_in(&app).await;

    let res = callback(&app, &state_id, Some(&state_id)).await;

    assert!(
        set_cookies(&res)
            .iter()
            .any(|line| line
                == &format!("{BINDING_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")),
        "the binding cookie is cleared once its flow has run, got {:?}",
        set_cookies(&res)
    );
}

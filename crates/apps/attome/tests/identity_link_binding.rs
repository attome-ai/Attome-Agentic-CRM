//! B3 — the self-service identity-link callback must arrive in the browser
//! that started the link. `identity_link_oidc_start` sets a binding cookie
//! carrying the flow's `state`; `identity_link_oidc_callback` refuses to
//! consume the single-use state, contact the IdP, or link anything unless
//! that cookie is presented and equals the echoed `state`. See the "Browser
//! binding for self-service identity linking" section of
//! `crates/server/src/auth/oidc.rs` for the attack this closes.
//!
//! No IdP is needed. The start route is driven fully offline by priming the
//! provider's discovery-document cache (`oidc:discovery:{provider}`, the
//! same key `attome_auth::oidc::fetch_discovery` reads first), and the
//! callback's binding check runs before any IdP contact, so the negative
//! cases never leave the process. The positive case proves it got *past* the
//! check by observing the single-use state being consumed — the only step
//! that follows the check and precedes the (unreachable) token exchange.
//!
//! Same harness shape as `middleware_pipeline.rs`: real Postgres/Redis, the
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
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use fred::prelude::*;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const PROVIDER_KEY: &str = "binding-test";
/// Nothing listens here. The start route never reaches it (discovery is
/// primed into Redis below); the positive callback case's token exchange
/// hits it and fails fast, which is exactly what that case wants.
const UNREACHABLE_IDP: &str = "http://127.0.0.1:1";
/// `secure_cookies = false` in the config below, so the bare name applies —
/// the `__Host-` half of the naming is covered by the unit tests in `oidc.rs`.
const BINDING_COOKIE: &str = "identity_link_oidc";

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
                        "display_name": "Binding test IdP",
                        "issuer": "{issuer}",
                        "client_id": "binding-test-client",
                        "client_secret": "binding-test-client-secret-throwaway",
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
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));

    let base_state = system.state().base.clone();
    let license = system.state().license.clone();
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
/// Same key shape as that module's `discovery_key`, on the general cache
/// pool it reads from (`AppState.redis`, not the coordination pool).
async fn prime_discovery_cache(state: &AppState) {
    let doc = format!(
        r#"{{"authorization_endpoint":"{UNREACHABLE_IDP}/authorize","token_endpoint":"{UNREACHABLE_IDP}/token","jwks_uri":"{UNREACHABLE_IDP}/jwks"}}"#
    );
    state
        .redis
        .set::<(), _, _>(
            format!("oidc:discovery:{PROVIDER_KEY}"),
            doc,
            Some(Expiration::EX(120)),
            None,
            false,
        )
        .await
        .expect("prime oidc discovery cache");
}

/// A password account with a real refresh family and a session token naming it
/// (`sid`), whose family already holds a step-up for `identity_link`. Since
/// attome-auth hardening 2.1d (D-510), the start route only proceeds for such a
/// session. The step-up itself is written straight to the throwaway database,
/// with the values a verified password step-up writes; the step-up routes are
/// covered by `step_up_http.rs` and the enforcement by
/// `step_up_enforcement_http.rs`.
async fn seed_user_and_session_cookie(state: &AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let password_hash = attome_auth::hash_password_async(
        attome_auth::NewPassword::platform_generated("identity-link-binding-password-1"),
    )
    .await
    .expect("hash throwaway password");
    sqlx::query(
        "INSERT INTO user_account (id, user_name, password_hash, is_active) \
         VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("identity-link-binding-{user_id}"))
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");

    let issued = attome_auth::refresh::issue(
        &state.db,
        user_id,
        &attome_auth::auth_context::AuthContext::password(),
        attome_auth::refresh::RefreshLifetimes {
            idle_secs: state.config.refresh_token_expiry_secs(),
            absolute_secs: state.config.refresh_absolute_lifetime_secs(),
        },
        &state.pepper_ring(),
    )
    .await
    .expect("issue a refresh family");
    sqlx::query(
        "UPDATE refresh_token
         SET auth_time = NOW(), amr = ARRAY['pwd'], elevated_until = NOW() + INTERVAL '15 minutes'
         WHERE family_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(issued.family_id)
    .execute(&state.db)
    .await
    .expect("record a password step-up on the family");
    let token = attome_auth::accounts::issue_access_token(
        &state.db,
        user_id,
        issued.family_id,
        &KeyRing::single(THROWAWAY_JWT_SECRET.to_string()),
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        3600,
    )
    .await
    .expect("issue a session token naming the family");
    (user_id, format!("session_token={token}"))
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

/// Drives the protected start route as the seeded user and returns the
/// `state` it minted plus the raw `Set-Cookie` line it issued.
async fn start_link(app: &axum::Router, session_cookie: &str) -> (String, String) {
    let req = Request::builder()
        .uri(format!("/api/v1/auth/identity-link/oidc/{PROVIDER_KEY}"))
        .header(header::COOKIE, session_cookie)
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("start request");
    assert!(
        res.status().is_redirection(),
        "start must redirect to the IdP, got {}",
        res.status()
    );
    let location = header_str(&res, header::LOCATION)
        .expect("start must carry a Location header")
        .to_owned();
    assert!(
        location.starts_with(&format!("{UNREACHABLE_IDP}/authorize?")),
        "start must redirect to the primed authorization_endpoint, got {location}"
    );
    let state_id = query_param(&location, "state").expect("authorize URL must carry a state");
    let set_cookie = header_str(&res, header::SET_COOKIE)
        .expect("start must set the binding cookie")
        .to_owned();
    (state_id, set_cookie)
}

async fn callback(
    app: &axum::Router,
    state_id: &str,
    binding_cookie: Option<&str>,
) -> axum::response::Response {
    let mut builder = Request::builder().uri(format!(
        "/api/v1/auth/identity-link-callback/oidc/{PROVIDER_KEY}?code=throwaway&state={state_id}"
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

async fn linked_identity_count(state: &AppState, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM user_identity WHERE user_ref = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .expect("count user_identity")
}

fn assert_rejected_to_error_page(res: &axum::response::Response) {
    assert_eq!(res.status(), StatusCode::FOUND);
    let location = header_str(res, header::LOCATION).expect("callback must redirect");
    assert!(
        location.ends_with("/settings/security?identity_link_error=1"),
        "a rejected callback redirects to the settings error page, got {location}"
    );
}

#[tokio::test]
async fn start_sets_a_binding_cookie_carrying_the_flow_state() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;
    let (_user_id, session_cookie) = seed_user_and_session_cookie(&state).await;

    let (state_id, set_cookie) = start_link(&app, &session_cookie).await;

    assert_eq!(
        set_cookie,
        format!("{BINDING_COOKIE}={state_id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600"),
        "binding cookie must carry exactly the state the IdP will echo back, \
         HttpOnly, Lax (a Strict cookie is withheld on the redirect back from \
         the IdP), Path=/, and live no longer than ten minutes"
    );
    assert!(
        pending_state_exists(&state, &state_id).await,
        "start must have written the single-use state the callback consumes"
    );
}

#[tokio::test]
async fn callback_without_the_binding_cookie_is_rejected_and_links_nothing() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;
    let (user_id, session_cookie) = seed_user_and_session_cookie(&state).await;
    let (state_id, _) = start_link(&app, &session_cookie).await;

    // The victim's browser: a valid state (handed over by the attacker) but
    // no binding cookie, because it never started this flow.
    let res = callback(&app, &state_id, None).await;

    assert_rejected_to_error_page(&res);
    assert!(
        header_str(&res, header::SET_COOKIE).is_none(),
        "a binding failure must not touch the cookie jar (nothing to clear, \
         and a genuine in-flight flow's cookie is not this request's to discard)"
    );
    assert!(
        pending_state_exists(&state, &state_id).await,
        "rejection must happen BEFORE the single-use state is consumed — \
         the callback never got as far as complete_login"
    );
    assert_eq!(linked_identity_count(&state, user_id).await, 0);
}

#[tokio::test]
async fn callback_with_a_mismatched_binding_cookie_is_rejected_and_links_nothing() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;
    let (user_id, session_cookie) = seed_user_and_session_cookie(&state).await;
    let (state_id, _) = start_link(&app, &session_cookie).await;

    // A browser holding a binding cookie for some OTHER flow it started.
    let other_state = Uuid::now_v7().to_string();
    let res = callback(&app, &state_id, Some(&other_state)).await;

    assert_rejected_to_error_page(&res);
    assert!(header_str(&res, header::SET_COOKIE).is_none());
    assert!(pending_state_exists(&state, &state_id).await);
    assert_eq!(linked_identity_count(&state, user_id).await, 0);
}

#[tokio::test]
async fn callback_with_the_matching_binding_cookie_proceeds_past_the_check() {
    let (app, state) = skip_if_no_db!(test_app().await);
    prime_discovery_cache(&state).await;
    let (user_id, session_cookie) = seed_user_and_session_cookie(&state).await;
    let (state_id, _) = start_link(&app, &session_cookie).await;

    // The same browser that started the link: the cookie equals the state.
    let res = callback(&app, &state_id, Some(&state_id)).await;

    // The check passed, so `complete_login` ran: the single-use state is
    // consumed (the step right after the check), and only then does the
    // token exchange fail against the unreachable IdP — which is as far as
    // this harness can go without a real IdP (`keycloak_oidc.rs` covers the
    // exchange itself).
    assert!(
        !pending_state_exists(&state, &state_id).await,
        "a matching cookie must let the callback proceed to consume the state"
    );
    assert_rejected_to_error_page(&res);
    assert_eq!(
        header_str(&res, header::SET_COOKIE),
        Some(format!("{BINDING_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0").as_str()),
        "the binding cookie is cleared once its flow has run"
    );
    assert_eq!(
        linked_identity_count(&state, user_id).await,
        0,
        "no IdP was reached, so nothing may have been linked"
    );
}

#[tokio::test]
async fn start_requires_a_session() {
    let (app, _state) = skip_if_no_db!(test_app().await);
    let req = Request::builder()
        .uri(format!("/api/v1/auth/identity-link/oidc/{PROVIDER_KEY}"))
        .body(Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.expect("start request");
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "the start route stays session-gated — the binding cookie is issued \
         only to an authenticated browser"
    );
    assert!(header_str(&res, header::SET_COOKIE).is_none());
}

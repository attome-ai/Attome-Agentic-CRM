//! Base-auth hardening 2.1d (D-510 rules 3, 7, 8 and 9), end to end through
//! the assembled HTTP stack: the step-up guard on the protected operations.
//!
//! Proves:
//! - API-key creation and identity linking need a fresh step-up on the
//!   session cookie's own family, answered with `reauth_required` (or, for
//!   the browser-navigation link starts, a redirect to the settings page);
//! - a stale or expired elevation is refused, and an elevation old enough for
//!   `api_key_create` (15 min) never satisfies `identity_link` (5 min);
//! - another family of the same user, and a later sign-in, stay unelevated,
//!   while a refresh of the elevated session keeps its elevation;
//! - the MFA disable and recovery-code routes take their step-up from the code
//!   in the request (rule 8);
//! - an API-key caller is refused with 403 on every guarded route (rule 7);
//! - the read endpoint reports exactly what the guard decides (rule 9).
//!
//! The federated step-up round trips back to identity linking live in
//! `step_up_federated_http.rs`.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database — attome-testkit
//! clones it per binary) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`).
//! Skips cleanly when `DATABASE_URL` is unset. Run manually:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p server --test step_up_enforcement_http -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome::auth;
use attome_api::EngineSystem;
use attome_auth::validate_session_token;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use attome_types::ReauthRequiredResponse;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, Utc};
use totp_rs::{Algorithm, Builder, Secret, Totp};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "step-up-enforcement-password-1";
const PROVIDER_KEY: &str = "enforcement-idp";
/// Nothing listens here: the link start reads the primed discovery document
/// and never contacts the IdP.
const UNREACHABLE_IDP: &str = "http://127.0.0.1:1";

// ── App ──────────────────────────────────────────────────────────────────────

fn test_config() -> AppConfig {
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
            "cors": {{ "allowed_origins": ["{allowed_origin}"] }},
            "oidc": {{
                "providers": {{
                    "{provider_key}": {{
                        "display_name": "Enforcement test IdP",
                        "issuer": "{issuer}",
                        "client_id": "enforcement-client",
                        "client_secret": "enforcement-client-secret-throwaway",
                        "scopes": ["openid", "email"],
                        "email_claim": "email"
                    }}
                }}
            }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        allowed_origin = ALLOWED_ORIGIN,
        provider_key = PROVIDER_KEY,
        issuer = UNREACHABLE_IDP,
    );
    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    config.auth.mfa_policy = "optional".into();
    config.auth.mfa_encryption_key = KeyRing::single("ab".repeat(32));
    config
}

/// The full `main.rs` stack around the public and protected auth bundles and
/// the core routes (which mount the MFA and API-key routes).
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

    // The identity-link start builds its authorize URL from the cached
    // discovery document (general cache pool) and never fetches.
    let doc = format!(
        r#"{{"authorization_endpoint":"{UNREACHABLE_IDP}/authorize","token_endpoint":"{UNREACHABLE_IDP}/token","jwks_uri":"{UNREACHABLE_IDP}/jwks"}}"#
    );
    base_state
        .redis
        .set(
            &format!("oidc:discovery:{PROVIDER_KEY}"),
            &(doc).to_string(),
            Some(std::time::Duration::from_secs(600)),
        )
        .await
        .expect("prime oidc discovery cache");

    Some((app, base_state))
}

// ── Accounts and sessions ────────────────────────────────────────────────────

async fn seed_user(state: &AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let email = format!("step-up-enforcement-{user_id}@example.test");
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
    .bind(format!("step-up-enforcement-{user_id}"))
    .bind(&email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email)
}

fn post_json(uri: &str, session_token: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("origin", ALLOWED_ORIGIN);
    if let Some(token) = session_token {
        builder = builder.header(header::COOKIE, format!("__Host-session_token={token}"));
    }
    builder
        .body(Body::from(body.to_string()))
        .expect("build request")
}

fn get(uri: &str, session_token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(token) = session_token {
        builder = builder.header(header::COOKIE, format!("__Host-session_token={token}"));
    }
    builder.body(Body::empty()).expect("build request")
}

fn cookie_value(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

async fn json_of(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// A password sign-in: `(session token, refresh token)`.
async fn password_login(app: &axum::Router, email: &str) -> (String, String) {
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/login",
            None,
            serde_json::json!({ "email": email, "password": PASSWORD }),
        ))
        .await
        .expect("login");
    assert_eq!(res.status(), StatusCode::OK, "password login");
    (
        cookie_value(&res, "__Host-session_token").expect("a session cookie"),
        cookie_value(&res, attome_auth::cookie::refresh_cookie_name(true))
            .expect("a refresh cookie"),
    )
}

/// Rotates the refresh token: the new `(session token, refresh token)`.
async fn refresh(app: &axum::Router, refresh_token: &str) -> (String, String) {
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/refresh")
                .header("origin", ALLOWED_ORIGIN)
                .header(
                    header::COOKIE,
                    format!(
                        "{}={refresh_token}",
                        attome_auth::cookie::refresh_cookie_name(true)
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("refresh");
    assert_eq!(res.status(), StatusCode::OK, "refresh");
    (
        cookie_value(&res, "__Host-session_token").expect("a new session cookie"),
        cookie_value(&res, attome_auth::cookie::refresh_cookie_name(true))
            .expect("a new refresh cookie"),
    )
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

/// A password step-up on the session's own family, through the real routes.
async fn step_up_with_password(app: &axum::Router, token: &str, operation: &str) {
    let res = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/auth/step-up/{operation}"),
            Some(token),
            serde_json::json!({}),
        ))
        .await
        .expect("start");
    assert_eq!(res.status(), StatusCode::CREATED, "start a challenge");
    let challenge_id = json_of(res).await["challenge_id"]
        .as_str()
        .expect("challenge id")
        .to_owned();
    let res = app
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/auth/step-up/{operation}/verify"),
            Some(token),
            serde_json::json!({
                "challenge_id": challenge_id,
                "factor": "password",
                "credential": PASSWORD,
            }),
        ))
        .await
        .expect("verify");
    assert_eq!(res.status(), StatusCode::OK, "a correct password elevates");
}

/// Moves a family's step-up into the past: authenticated `auth_secs_ago`
/// seconds ago, elevated until `until_secs_from_now` from now.
async fn age_elevation(
    state: &AppState,
    family_id: Uuid,
    auth_secs_ago: i64,
    until_secs_from_now: i64,
) {
    sqlx::query(
        "UPDATE refresh_token
         SET auth_time = NOW() - make_interval(secs => $2::float8),
             elevated_until = NOW() + make_interval(secs => $3::float8)
         WHERE family_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(auth_secs_ago)
    .bind(until_secs_from_now)
    .execute(&state.db)
    .await
    .expect("age the elevation");
}

async fn api_key_count(state: &AppState, user_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM api_key WHERE user_ref = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .expect("count api keys")
}

async fn create_api_key(app: &axum::Router, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(post_json(
            "/api/v1/auth/api-keys",
            Some(token),
            serde_json::json!({ "name": format!("enforcement-{}", Uuid::now_v7()) }),
        ))
        .await
        .expect("create api key")
}

async fn link_start(app: &axum::Router, token: &str) -> axum::response::Response {
    app.clone()
        .oneshot(get(
            &format!("/api/v1/auth/identity-link/oidc/{PROVIDER_KEY}"),
            Some(token),
        ))
        .await
        .expect("link start")
}

async fn status_of(app: &axum::Router, token: &str, operation: &str) -> serde_json::Value {
    let res = app
        .clone()
        .oneshot(get(
            &format!("/api/v1/auth/step-up/{operation}"),
            Some(token),
        ))
        .await
        .expect("step-up status");
    assert_eq!(res.status(), StatusCode::OK, "status for {operation}");
    json_of(res).await
}

/// A `reauth_required` answer that parses as the documented schema, for
/// `operation` with `factors`.
async fn assert_reauth_required(res: axum::response::Response, operation: &str, factors: &[&str]) {
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body = json_of(res).await;
    let parsed: ReauthRequiredResponse = serde_json::from_value(body.clone())
        .unwrap_or_else(|e| panic!("reauth_required body must match its schema ({e}): {body}"));
    assert_eq!(parsed.error, "reauth_required");
    assert_eq!(parsed.operation, operation);
    assert_eq!(parsed.acceptable_factors, factors);
}

fn location(res: &axum::response::Response) -> String {
    res.headers()
        .get(header::LOCATION)
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_owned()
}

fn assert_link_needs_step_up(res: &axum::response::Response) {
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        location(res).ends_with("/settings/security?reauth_required=identity_link"),
        "an unelevated link start goes back to the settings page, got {}",
        location(res)
    );
    assert!(
        res.headers().get(header::SET_COOKIE).is_none(),
        "no binding cookie and no provider flow without a step-up"
    );
}

fn assert_link_proceeds(res: &axum::response::Response) {
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(
        location(res).starts_with(&format!("{UNREACHABLE_IDP}/authorize?")),
        "an elevated link start continues to the IdP, got {}",
        location(res)
    );
    assert!(cookie_value(res, "__Host-identity_link_oidc").is_some());
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// API-key creation needs a step-up on the cookie's own family; the read
/// endpoint agrees with the guard; a refresh keeps the elevation; another
/// family of the same user, and a later sign-in, do not share it.
#[tokio::test]
async fn api_key_creation_needs_a_step_up_on_the_sessions_own_family() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let (token, refresh_token) = password_login(&app, &email).await;
    let (sibling, _) = password_login(&app, &email).await;

    assert_reauth_required(
        create_api_key(&app, &token).await,
        "api_key_create",
        &["password"],
    )
    .await;
    assert_eq!(api_key_count(&state, user_id).await, 0);
    let status = status_of(&app, &token, "api_key_create").await;
    assert_eq!(status["elevated"], false);
    assert_eq!(status["elevated_until"], serde_json::Value::Null);
    assert_eq!(
        status["acceptable_factors"],
        serde_json::json!(["password"])
    );

    step_up_with_password(&app, &token, "api_key_create").await;
    let status = status_of(&app, &token, "api_key_create").await;
    assert_eq!(status["elevated"], true);
    assert!(status["elevated_until"].is_string());

    let res = create_api_key(&app, &token).await;
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "a stepped-up session mints"
    );
    let created = json_of(res).await;
    assert!(created["secret"].is_string(), "the secret is shown once");
    assert_eq!(api_key_count(&state, user_id).await, 1);

    assert_reauth_required(
        create_api_key(&app, &sibling).await,
        "api_key_create",
        &["password"],
    )
    .await;
    assert_eq!(
        status_of(&app, &sibling, "api_key_create").await["elevated"],
        false
    );

    let (rotated, _) = refresh(&app, &refresh_token).await;
    assert_eq!(family_of(&state, &rotated), family_of(&state, &token));
    assert_eq!(
        create_api_key(&app, &rotated).await.status(),
        StatusCode::CREATED,
        "a refresh keeps the family's elevation"
    );

    let (later, _) = password_login(&app, &email).await;
    assert_reauth_required(
        create_api_key(&app, &later).await,
        "api_key_create",
        &["password"],
    )
    .await;
    assert_eq!(api_key_count(&state, user_id).await, 2);
}

/// A stale or expired elevation is refused, and an elevation old enough for
/// `api_key_create` never satisfies `identity_link`.
#[tokio::test]
async fn stale_and_expired_elevation_is_refused_per_operation() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let (token, _) = password_login(&app, &email).await;
    let family = family_of(&state, &token);

    step_up_with_password(&app, &token, "identity_link").await;
    assert_link_proceeds(&link_start(&app, &token).await);

    // Authenticated 6 minutes ago: inside api_key_create's 15, outside
    // identity_link's 5.
    age_elevation(&state, family, 6 * 60, 9 * 60).await;
    assert_link_needs_step_up(&link_start(&app, &token).await);
    assert_eq!(
        status_of(&app, &token, "identity_link").await["elevated"],
        false
    );
    assert_eq!(
        status_of(&app, &token, "api_key_create").await["elevated"],
        true
    );
    assert_eq!(
        create_api_key(&app, &token).await.status(),
        StatusCode::CREATED
    );

    // Authenticated 16 minutes ago: stale for both.
    age_elevation(&state, family, 16 * 60, 60).await;
    assert_reauth_required(
        create_api_key(&app, &token).await,
        "api_key_create",
        &["password"],
    )
    .await;

    // A fresh authentication time, but the elevation itself has lapsed.
    age_elevation(&state, family, 30, -1).await;
    assert_reauth_required(
        create_api_key(&app, &token).await,
        "api_key_create",
        &["password"],
    )
    .await;
    assert_link_needs_step_up(&link_start(&app, &token).await);
    assert_eq!(api_key_count(&state, user_id).await, 1);
}

/// Identity linking: a browser start without a step-up returns to the settings
/// page and starts nothing; with one it continues to the IdP. The Google link
/// answers `reauth_required`. The MFA operations have no status to read.
#[tokio::test]
async fn identity_linking_checks_the_step_up_before_any_provider_flow() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (_user_id, email) = seed_user(&state).await;
    let (token, _) = password_login(&app, &email).await;

    assert_link_needs_step_up(&link_start(&app, &token).await);
    assert_reauth_required(
        app.clone()
            .oneshot(post_json(
                "/api/v1/auth/identity-link/google",
                Some(&token),
                serde_json::json!({ "credential": "not-a-google-token" }),
            ))
            .await
            .expect("google link"),
        "identity_link",
        &["password"],
    )
    .await;
    let status = status_of(&app, &token, "identity_link").await;
    assert_eq!(status["elevated"], false);
    assert_eq!(status["operation"], "identity_link");

    for not_step_up in ["mfa_disable", "recovery_codes_regenerate", "admin"] {
        let res = app
            .clone()
            .oneshot(get(
                &format!("/api/v1/auth/step-up/{not_step_up}"),
                Some(&token),
            ))
            .await
            .expect("status");
        assert_eq!(res.status(), StatusCode::NOT_FOUND, "{not_step_up}");
    }

    step_up_with_password(&app, &token, "identity_link").await;
    assert_link_proceeds(&link_start(&app, &token).await);
}

/// The MFA routes take their step-up from the code in the request (rule 8):
/// no elevation needed, and a wrong or replayed code changes nothing.
#[tokio::test]
async fn mfa_routes_take_their_step_up_from_the_code_in_the_request() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let ring = state.secrets.load().mfa_encryption_key.clone();
    let enrolled = attome_auth::mfa::enroll(&state.db, &ring, user_id)
        .await
        .expect("enroll");
    let totp: Totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(&enrolled.secret_base32).expect("base32 secret"))
        .with_account_name("test".to_string())
        .build()
        .expect("build totp");
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let recovery_codes = attome_auth::mfa::confirm_enrollment(
        &state.db,
        &ring,
        &state.pepper_ring(),
        user_id,
        &totp.generate(now()).to_string(),
    )
    .await
    .expect("confirm enrollment");

    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/login",
            None,
            serde_json::json!({ "email": email, "password": PASSWORD }),
        ))
        .await
        .expect("login");
    let pending = json_of(res).await["pending_token"]
        .as_str()
        .expect("pending token")
        .to_owned();
    // Sign in with a recovery code, so no TOTP step is spent before the
    // regeneration below (the verifier accepts one step of skew and never the
    // same step twice).
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/mfa/verify-recovery",
            None,
            serde_json::json!({ "pending_token": pending, "code": recovery_codes[1] }),
        ))
        .await
        .expect("mfa verify-recovery");
    assert_eq!(res.status(), StatusCode::OK);
    let token = cookie_value(&res, "__Host-session_token").expect("session cookie");
    let family = family_of(&state, &token);

    // A valid code regenerates without any elevation on the family.
    let code = totp.generate(now() + 30).to_string();
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/mfa/recovery-codes/regenerate",
            Some(&token),
            serde_json::json!({ "code": code }),
        ))
        .await
        .expect("regenerate");
    assert_eq!(res.status(), StatusCode::OK, "the code is the step-up");
    let new_codes: Vec<String> = json_of(res).await["recovery_codes"]
        .as_array()
        .expect("fresh recovery codes")
        .iter()
        .map(|code| code.as_str().expect("a code").to_owned())
        .collect();
    let elevated: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT elevated_until FROM refresh_token
         WHERE family_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
    )
    .bind(family)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(elevated, None, "rule 8 writes no elevation");

    // The same code again is a replay.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/mfa/recovery-codes/regenerate",
            Some(&token),
            serde_json::json!({ "code": code }),
        ))
        .await
        .expect("replayed regenerate");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(json_of(res).await["error"], "reauth_required");

    // A wrong code does not disable MFA, and is not a step-up prompt.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/mfa/disable",
            Some(&token),
            serde_json::json!({ "code": "000000" }),
        ))
        .await
        .expect("disable with a wrong code");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(json_of(res).await["error"], "reauth_required");
    assert!(
        attome_auth::mfa::is_enrolled(&state.db, user_id)
            .await
            .unwrap()
    );

    // A recovery code from before the regeneration no longer works; one of the
    // freshly issued codes is this request's step-up and disables.
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/mfa/disable",
            Some(&token),
            serde_json::json!({ "code": recovery_codes[0] }),
        ))
        .await
        .expect("disable with a regenerated-away recovery code");
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/mfa/disable",
            Some(&token),
            serde_json::json!({ "code": new_codes[0] }),
        ))
        .await
        .expect("disable");
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a fresh recovery code disables"
    );
    assert!(
        !attome_auth::mfa::is_enrolled(&state.db, user_id)
            .await
            .unwrap()
    );
}

/// An API-key caller can never step up (rule 7): every guarded route, and the
/// read endpoint, refuse it with 403 and write nothing.
#[tokio::test]
async fn an_api_key_caller_is_refused_on_every_guarded_route() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, _email) = seed_user(&state).await;
    let public_key = format!("atk_pub_enforce{}", Uuid::now_v7().simple());
    let secret = format!("atk_sec_enforce{}", Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO api_key (user_ref, name, public_key, secret_hash)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind("enforcement caller")
    .bind(&public_key)
    .bind(state.pepper_ring().hash(&secret))
    .execute(&state.db)
    .await
    .expect("insert api key");
    let authorization = format!("ApiKey {public_key}:{secret}");

    let requests: Vec<(&str, Request<Body>)> = vec![
        (
            "POST /api/v1/auth/api-keys",
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/api-keys")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::from(r#"{"name":"never-created"}"#))
                .unwrap(),
        ),
        (
            "POST /api/v1/auth/mfa/disable",
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/mfa/disable")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::from(r#"{"code":"123456"}"#))
                .unwrap(),
        ),
        (
            "POST /api/v1/auth/mfa/recovery-codes/regenerate",
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/mfa/recovery-codes/regenerate")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::from(r#"{"code":"123456"}"#))
                .unwrap(),
        ),
        (
            "POST /api/v1/auth/identity-link/google",
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/identity-link/google")
                .header("content-type", "application/json")
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::from(r#"{"credential":"x"}"#))
                .unwrap(),
        ),
        (
            "GET /api/v1/auth/identity-link/oidc/{provider}",
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/auth/identity-link/oidc/{PROVIDER_KEY}"))
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
        ),
        (
            "GET /api/v1/auth/step-up/api_key_create",
            Request::builder()
                .method("GET")
                .uri("/api/v1/auth/step-up/api_key_create")
                .header(header::AUTHORIZATION, &authorization)
                .body(Body::empty())
                .unwrap(),
        ),
    ];
    for (route, request) in requests {
        let res = app.clone().oneshot(request).await.expect(route);
        let status = res.status();
        let body = json_of(res).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{route}: {body}");
        assert_eq!(body["error"], "forbidden", "{route}");
    }
    assert_eq!(
        api_key_count(&state, user_id).await,
        1,
        "only the seeded key exists"
    );
}

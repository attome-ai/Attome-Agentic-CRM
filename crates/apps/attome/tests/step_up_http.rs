//! Base-auth hardening 2.1b (D-510 rule 6), end to end through the assembled
//! HTTP stack: the step-up routes.
//!
//! Proves the family comes from the session cookie's validated `sid` and the
//! operation from the route, even when the body names others; that wrong
//! credentials, route mismatches, non-step-up operations and legacy sessions
//! are refused; and that a TOTP-enrolled account cannot step up with its
//! password. Wiring the guard onto the protected routes is 2.1d.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database — attome-testkit
//! clones it per binary) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`).
//! Skips cleanly when `DATABASE_URL` is unset. Run manually:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p server --test step_up_http -- --test-threads=1
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
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, Utc};
use totp_rs::{Algorithm, Builder, Secret, Totp};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "step-up-http-password-1";

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
    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    config.auth.mfa_policy = "optional".into();
    config.auth.mfa_encryption_key = KeyRing::single("ab".repeat(32));
    config
}

/// The full `main.rs` stack around the public and protected auth bundles.
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

async fn seed_user(state: &AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let email = format!("step-up-http-{user_id}@example.test");
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
    .bind(format!("step-up-http-{user_id}"))
    .bind(&email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email)
}

async fn enroll_totp(state: &AppState, user_id: Uuid) -> (Totp, Vec<String>) {
    let ring = state.secrets.load().mfa_encryption_key.clone();
    let enrolled = attome_auth::mfa::enroll(&state.db, &ring, user_id)
        .await
        .expect("enroll");
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(Secret::try_from_base32(&enrolled.secret_base32).expect("base32 secret"))
        .with_account_name("test".to_string())
        .build()
        .expect("build totp");
    let code = totp.generate_current().to_string();
    let recovery_codes = attome_auth::mfa::confirm_enrollment(
        &state.db,
        &ring,
        &state.pepper_ring(),
        user_id,
        &code,
    )
    .await
    .expect("confirm enrollment");
    (totp, recovery_codes)
}

fn next_code(totp: &Totp) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    totp.generate(now + 30).to_string()
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

fn session_cookie_of(res: &axum::response::Response) -> String {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| {
            pair.strip_prefix("__Host-session_token=")
                .map(str::to_owned)
        })
        .expect("a session cookie")
}

async fn json_of(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("JSON body")
}

async fn password_login(app: &axum::Router, email: &str) -> String {
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
    session_cookie_of(&res)
}

fn sid_of(state: &AppState, session_token: &str) -> Uuid {
    let (_, sid) = validate_session_token(
        session_token,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .expect("valid session token");
    sid.0
}

async fn live_elevation(state: &AppState, family_id: Uuid) -> Option<DateTime<Utc>> {
    sqlx::query_scalar(
        "SELECT elevated_until FROM refresh_token
         WHERE family_id = $1 AND used_at IS NULL AND revoked_at IS NULL
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(family_id)
    .fetch_one(&state.db)
    .await
    .expect("live row")
}

async fn start(app: &axum::Router, token: &str, operation: &str) -> axum::response::Response {
    app.clone()
        .oneshot(post_json(
            &format!("/api/v1/auth/step-up/{operation}"),
            Some(token),
            serde_json::json!({}),
        ))
        .await
        .expect("start request")
}

async fn verify(
    app: &axum::Router,
    token: &str,
    operation: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    app.clone()
        .oneshot(post_json(
            &format!("/api/v1/auth/step-up/{operation}/verify"),
            Some(token),
            body,
        ))
        .await
        .expect("verify request")
}

async fn assert_reauth_required(res: axum::response::Response, operation: &str, factors: &[&str]) {
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let body = json_of(res).await;
    assert_eq!(body["error"], "reauth_required");
    assert_eq!(body["operation"], operation);
    assert_eq!(body["acceptable_factors"], serde_json::json!(factors));
}

/// The family is the session cookie's, and the operation is the route's, even
/// when the body names another family, user and operation.
#[tokio::test]
async fn a_password_step_up_elevates_the_sessions_own_family_whatever_the_body_says() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let (other_user, _) = seed_user(&state).await;
    let mine = password_login(&app, &email).await;
    let other_session = password_login(&app, &email).await;
    let my_family = sid_of(&state, &mine);
    let other_family = sid_of(&state, &other_session);
    assert_ne!(my_family, other_family);

    let res = start(&app, &mine, "identity_link").await;
    assert_eq!(res.status(), StatusCode::CREATED, "start a challenge");
    let started = json_of(res).await;
    assert_eq!(started["operation"], "identity_link");
    assert_eq!(
        started["acceptable_factors"],
        serde_json::json!(["password"])
    );
    assert_eq!(started["expires_in_secs"], 300);
    let challenge_id = started["challenge_id"].as_str().expect("challenge id");

    let res = verify(
        &app,
        &mine,
        "identity_link",
        serde_json::json!({
            "challenge_id": challenge_id,
            "factor": "password",
            "credential": PASSWORD,
            "sid": other_family,
            "family_id": other_family,
            "user_id": other_user,
            "operation": "api_key_create",
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "a correct password elevates");
    let elevated = json_of(res).await;
    assert_eq!(elevated["operation"], "identity_link");
    let until: DateTime<Utc> = elevated["elevated_until"]
        .as_str()
        .expect("elevated_until")
        .parse()
        .expect("RFC 3339");

    assert_eq!(live_elevation(&state, my_family).await, Some(until));
    assert_eq!(
        live_elevation(&state, other_family).await,
        None,
        "the family named in the body is untouched"
    );
    let _ = user_id;
}

/// BAU-8c: the Google step-up route is session-gated and refuses an account
/// with no Google link before any Google credential is verified, so an
/// ineligible session contacts nothing and elevates nothing.
#[tokio::test]
async fn the_google_step_up_route_refuses_before_contacting_google() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (_, email) = seed_user(&state).await;
    let token = password_login(&app, &email).await;
    let family = sid_of(&state, &token);
    let google = |token: Option<String>, operation: &'static str, challenge: String| {
        let app = app.clone();
        async move {
            app.oneshot(post_json(
                &format!("/api/v1/auth/step-up/{operation}/google"),
                token.as_deref(),
                serde_json::json!({ "challenge_id": challenge, "credential": "not-a-google-token" }),
            ))
            .await
            .expect("google step-up request")
        }
    };

    let res = start(&app, &token, "identity_link").await;
    assert_eq!(res.status(), StatusCode::CREATED);
    let challenge = json_of(res).await["challenge_id"]
        .as_str()
        .expect("challenge id")
        .to_owned();

    assert_reauth_required(
        google(Some(token.clone()), "identity_link", challenge.clone()).await,
        "identity_link",
        &["password"],
    )
    .await;
    assert_eq!(live_elevation(&state, family).await, None);

    let res = google(Some(token.clone()), "not_an_operation", challenge.clone()).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let res = google(None, "identity_link", challenge).await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
}

/// Non-step-up operations, wrong credentials, route mismatches, replays and
/// sessions without `sid` are all refused.
#[tokio::test]
async fn step_up_routes_refuse_what_they_must() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let token = password_login(&app, &email).await;
    let family = sid_of(&state, &token);

    for not_step_up in ["mfa_disable", "recovery_codes_regenerate", "admin"] {
        assert_eq!(
            start(&app, &token, not_step_up).await.status(),
            StatusCode::NOT_FOUND,
            "{not_step_up} is not a step-up operation"
        );
    }

    let started = json_of(start(&app, &token, "identity_link").await).await;
    let challenge_id = started["challenge_id"]
        .as_str()
        .expect("challenge id")
        .to_owned();
    let answer = |credential: &str| {
        serde_json::json!({
            "challenge_id": challenge_id,
            "factor": "password",
            "credential": credential,
        })
    };

    assert_reauth_required(
        verify(&app, &token, "identity_link", answer("wrong-password")).await,
        "identity_link",
        &["password"],
    )
    .await;
    assert_reauth_required(
        verify(&app, &token, "api_key_create", answer(PASSWORD)).await,
        "api_key_create",
        &["password"],
    )
    .await;
    assert_eq!(live_elevation(&state, family).await, None);

    assert_eq!(
        verify(&app, &token, "identity_link", answer(PASSWORD))
            .await
            .status(),
        StatusCode::OK,
        "the challenge survived a wrong password and a route mismatch"
    );
    assert_reauth_required(
        verify(&app, &token, "identity_link", answer(PASSWORD)).await,
        "identity_link",
        &["password"],
    )
    .await;

    // A cookie session minted before 2.1a carries no sid: refused with a plain
    // 401 so the client refreshes, never elevated.
    let now = Utc::now().timestamp();
    let legacy_claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 600,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: state.config.auth.jwt_issuer.clone(),
        aud: state.config.jwt_audience().to_owned(),
        typ: attome_auth::TokenType::Session,
    };
    let legacy = attome_auth::create_token(
        &legacy_claims,
        &KeyRing::single(THROWAWAY_JWT_SECRET.to_string()),
    )
    .expect("legacy token");
    let res = start(&app, &legacy, "identity_link").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_of(res).await["error"], "unauthorized");
}

/// A TOTP-enrolled account is offered TOTP or a recovery code and refused its
/// password.
#[tokio::test]
async fn a_totp_account_steps_up_with_a_second_factor_not_its_password() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let (totp, recovery_codes) = enroll_totp(&state, user_id).await;

    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/login",
            None,
            serde_json::json!({ "email": email, "password": PASSWORD }),
        ))
        .await
        .expect("login");
    let pending_token = json_of(res).await["pending_token"]
        .as_str()
        .expect("pending token")
        .to_owned();
    let res = app
        .clone()
        .oneshot(post_json(
            "/api/v1/auth/mfa/verify",
            None,
            serde_json::json!({ "pending_token": pending_token, "code": next_code(&totp) }),
        ))
        .await
        .expect("mfa verify");
    assert_eq!(res.status(), StatusCode::OK);
    let token = session_cookie_of(&res);
    let family = sid_of(&state, &token);

    let started = json_of(start(&app, &token, "api_key_create").await).await;
    assert_eq!(
        started["acceptable_factors"],
        serde_json::json!(["totp", "recovery_code"])
    );
    let challenge_id = started["challenge_id"].as_str().expect("challenge id");

    assert_reauth_required(
        verify(
            &app,
            &token,
            "api_key_create",
            serde_json::json!({
                "challenge_id": challenge_id,
                "factor": "password",
                "credential": PASSWORD,
            }),
        )
        .await,
        "api_key_create",
        &["totp", "recovery_code"],
    )
    .await;
    assert_eq!(live_elevation(&state, family).await, None);

    let res = verify(
        &app,
        &token,
        "api_key_create",
        serde_json::json!({
            "challenge_id": challenge_id,
            "factor": "recovery_code",
            "credential": recovery_codes[0],
        }),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "a recovery code steps up");
    assert!(live_elevation(&state, family).await.is_some());
}

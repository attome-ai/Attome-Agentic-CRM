//! Base-auth hardening 2.1a (D-510 rule 2), end to end through the assembled
//! HTTP stack: a real sign-in → refresh flow for the password, TOTP and
//! recovery-code paths.
//!
//! Each flow proves three things:
//! - the session token's `sid` names the refresh family its refresh cookie
//!   belongs to, for the signed-in user;
//! - that family records a server-derived `auth_time` and exactly the verified
//!   methods, unelevated;
//! - `POST /api/v1/auth/refresh` keeps the family and copies the context
//!   unchanged, rather than advancing it.
//!
//! Federated sign-ins are not covered here: OIDC and Google evidence
//! belongs to 2.1c and 2.6.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database — attome-testkit
//! clones it per binary) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`).
//! Skips cleanly when `DATABASE_URL` is unset. Run manually:
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p server --test session_context_http -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome::auth;
use attome_api::EngineSystem;
use attome_auth::{SessionId, validate_session_token};
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
const PASSWORD: &str = "session-context-http-password-1";

/// `mfa_policy = "optional"` so an enrolled account is challenged and an
/// unenrolled one gets a plain session. `secure_cookies` stays at its default
/// (true), so the cookies are the prefixed production names.
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

/// Same assembly as `account_throttle.rs::test_app`: the full `main.rs` stack
/// around the auth bundle.
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
        .license
        .store(std::sync::Arc::new(attome_modules::ModuleSet {
            module_bits: [u64::MAX; 4],
            max_users: u32::MAX,
            expires: chrono::Utc::now() + chrono::Duration::days(365),
        }));

    let base_state = system.state().base.clone();
    let license = system.state().license.clone();
    let auth_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );

    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    Some((app, base_state))
}

async fn seed_user(state: &AppState) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    let email = format!("session-context-http-{user_id}@example.test");
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
    .bind(format!("session-context-http-{user_id}"))
    .bind(&email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email)
}

/// Enrolls TOTP through the engine and returns the generator and the recovery
/// codes, as `attome-auth/tests/login_mfa.rs` does.
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

/// A code for the next TOTP step, so it is never a replay of the step that
/// confirmed enrollment (the verifier's skew still accepts it).
fn next_code(totp: &Totp) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    totp.generate(now + 30).to_string()
}

fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("origin", ALLOWED_ORIGIN)
        .body(Body::from(body.to_string()))
        .expect("build request")
}

/// The session token and refresh token a response sets.
struct Cookies {
    session: String,
    refresh: String,
}

fn cookies_of(res: &axum::response::Response) -> Cookies {
    let mut session = None;
    let mut refresh = None;
    for value in res.headers().get_all(header::SET_COOKIE) {
        let pair = value
            .to_str()
            .expect("ascii cookie")
            .split(';')
            .next()
            .unwrap_or_default();
        match pair.split_once('=') {
            Some(("__Host-session_token", v)) => session = Some(v.to_owned()),
            Some(("__Secure-refresh_token", v)) => refresh = Some(v.to_owned()),
            _ => {}
        }
    }
    Cookies {
        session: session.expect("a session cookie"),
        refresh: refresh.expect("a refresh cookie"),
    }
}

async fn json_of(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("JSON body")
}

async fn db_now(state: &AppState) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT NOW()")
        .fetch_one(&state.db)
        .await
        .expect("database clock")
}

/// Validates the session token exactly as authn does and returns its `sid`.
fn sid_of(state: &AppState, user_id: Uuid, session_token: &str) -> Uuid {
    let (claims, sid) = validate_session_token(
        session_token,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .expect("a valid session token");
    assert_eq!(
        claims.sub, user_id,
        "the token belongs to the signed-in user"
    );
    sid.0
}

/// `(user_ref, family_id, auth_time, amr, elevated_until, used_at)` of the row a
/// refresh cookie names.
type RefreshRow = (
    Uuid,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<Vec<String>>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

async fn row_of(state: &AppState, refresh_token: &str) -> RefreshRow {
    let public_id: Uuid = refresh_token
        .split_once('.')
        .expect("refresh token shape")
        .0
        .parse()
        .expect("public_id is a uuid");
    sqlx::query_as(
        "SELECT user_ref, family_id, auth_time, amr, elevated_until, used_at
         FROM refresh_token WHERE public_id = $1",
    )
    .bind(public_id)
    .fetch_one(&state.db)
    .await
    .expect("the refresh cookie's row")
}

/// Asserts a freshly signed-in session: `sid` names the refresh cookie's
/// family for `user_id`, `auth_time` is the database clock inside
/// `[before, after]`, `amr` is exactly `expected_amr`, and it is unelevated.
/// Returns the family id and the recorded `auth_time`.
async fn assert_fresh_session(
    state: &AppState,
    user_id: Uuid,
    cookies: &Cookies,
    before: DateTime<Utc>,
    after: DateTime<Utc>,
    expected_amr: &[&str],
) -> (Uuid, DateTime<Utc>) {
    let sid = sid_of(state, user_id, &cookies.session);
    let (user_ref, family_id, auth_time, amr, elevated_until, used_at) =
        row_of(state, &cookies.refresh).await;
    assert_eq!(user_ref, user_id, "the refresh row belongs to the user");
    assert_eq!(
        family_id,
        Some(sid),
        "sid names the refresh cookie's family"
    );
    let auth_time = auth_time.expect("a local sign-in records auth_time");
    assert!(
        before <= auth_time && auth_time <= after,
        "auth_time {auth_time} must be the database clock at sign-in ({before}..{after})"
    );
    assert_eq!(
        amr,
        Some(expected_amr.iter().map(|m| (*m).to_owned()).collect()),
        "amr holds exactly the verified methods"
    );
    assert_eq!(elevated_until, None, "a new sign-in is unelevated");
    assert_eq!(used_at, None, "the new refresh token is unused");
    (sid, auth_time)
}

/// Refreshes with `cookies` and asserts the rotation stayed in `family_id`
/// and copied the context unchanged. Returns the rotated cookies.
async fn refresh_and_assert_unchanged(
    app: &axum::Router,
    state: &AppState,
    user_id: Uuid,
    cookies: &Cookies,
    family_id: Uuid,
    auth_time: DateTime<Utc>,
    expected_amr: &[&str],
) -> Cookies {
    // Let the database clock move past the sign-in, so an advanced auth_time
    // would be visible.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let refreshed_at = db_now(state).await;
    assert!(refreshed_at > auth_time);

    let mut req = post_json("/api/v1/auth/refresh", serde_json::json!({}));
    req.headers_mut().insert(
        header::COOKIE,
        format!("__Secure-refresh_token={}", cookies.refresh)
            .parse()
            .expect("cookie header"),
    );
    let res = app.clone().oneshot(req).await.expect("refresh request");
    assert_eq!(res.status(), StatusCode::OK, "refresh must succeed");
    let rotated = cookies_of(&res);
    assert_ne!(
        rotated.refresh, cookies.refresh,
        "refresh rotates the token"
    );

    assert_eq!(
        sid_of(state, user_id, &rotated.session),
        family_id,
        "the refreshed session token names the same family"
    );
    let (user_ref, new_family, new_auth_time, new_amr, new_elevated, new_used) =
        row_of(state, &rotated.refresh).await;
    assert_eq!(user_ref, user_id);
    assert_eq!(new_family, Some(family_id), "rotation stays in the family");
    assert_eq!(
        new_auth_time,
        Some(auth_time),
        "refresh must copy auth_time, never advance it"
    );
    assert_eq!(
        new_amr,
        Some(expected_amr.iter().map(|m| (*m).to_owned()).collect()),
        "refresh must copy amr unchanged"
    );
    assert_eq!(new_elevated, None, "refresh must not create elevation");
    assert_eq!(new_used, None);
    assert!(
        row_of(state, &cookies.refresh).await.5.is_some(),
        "the presented refresh token is now used"
    );

    let context = attome_auth::refresh::session_context(
        &state.db,
        user_id,
        SessionId(family_id),
        state.config.refresh_absolute_lifetime_secs(),
    )
    .await
    .expect("read session context")
    .expect("the family is live after refresh");
    assert_eq!(context.auth_time, Some(auth_time));
    assert_eq!(context.amr, expected_amr);
    assert_eq!(context.elevated_until, None);
    rotated
}

/// Password sign-in → refresh → a second sign-in, which starts a new family.
#[tokio::test]
async fn a_password_sign_in_names_its_family_and_refresh_keeps_its_context() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let login = serde_json::json!({ "email": email, "password": PASSWORD });

    let before = db_now(&state).await;
    let res = app
        .clone()
        .oneshot(post_json("/api/v1/auth/login", login.clone()))
        .await
        .expect("login request");
    assert_eq!(res.status(), StatusCode::OK, "password login must succeed");
    let cookies = cookies_of(&res);
    let after = db_now(&state).await;
    let (family_id, auth_time) =
        assert_fresh_session(&state, user_id, &cookies, before, after, &["pwd"]).await;

    let rotated = refresh_and_assert_unchanged(
        &app,
        &state,
        user_id,
        &cookies,
        family_id,
        auth_time,
        &["pwd"],
    )
    .await;
    // A second rotation copies from a replacement row, not the original.
    refresh_and_assert_unchanged(
        &app,
        &state,
        user_id,
        &rotated,
        family_id,
        auth_time,
        &["pwd"],
    )
    .await;

    let before = db_now(&state).await;
    let res = app
        .clone()
        .oneshot(post_json("/api/v1/auth/login", login))
        .await
        .expect("second login request");
    assert_eq!(res.status(), StatusCode::OK);
    let second = cookies_of(&res);
    let after = db_now(&state).await;
    let (second_family, second_auth_time) =
        assert_fresh_session(&state, user_id, &second, before, after, &["pwd"]).await;
    assert_ne!(
        second_family, family_id,
        "a new sign-in starts a new family"
    );
    assert!(second_auth_time > auth_time);
}

/// TOTP and recovery-code sign-ins record `pwd` plus the second factor, and
/// refresh keeps it.
#[tokio::test]
async fn mfa_sign_ins_record_the_second_factor_and_refresh_keeps_it() {
    let (app, state) = skip_if_no_db!(test_app().await);

    for (route, expected_amr) in [
        ("/api/v1/auth/mfa/verify", ["pwd", "otp"]),
        ("/api/v1/auth/mfa/verify-recovery", ["pwd", "rcode"]),
    ] {
        let (user_id, email) = seed_user(&state).await;
        let (totp, recovery_codes) = enroll_totp(&state, user_id).await;

        let res = app
            .clone()
            .oneshot(post_json(
                "/api/v1/auth/login",
                serde_json::json!({ "email": email, "password": PASSWORD }),
            ))
            .await
            .expect("login request");
        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            res.headers().get(header::SET_COOKIE).is_none(),
            "an MFA challenge sets no session cookie"
        );
        let pending_token = json_of(res).await["pending_token"]
            .as_str()
            .expect("an enrolled account gets a pending token")
            .to_owned();

        let code = if route.ends_with("verify-recovery") {
            recovery_codes[0].clone()
        } else {
            next_code(&totp)
        };
        let before = db_now(&state).await;
        let res = app
            .clone()
            .oneshot(post_json(
                route,
                serde_json::json!({ "pending_token": pending_token, "code": code }),
            ))
            .await
            .expect("mfa request");
        assert_eq!(res.status(), StatusCode::OK, "{route} must succeed");
        let cookies = cookies_of(&res);
        let after = db_now(&state).await;
        let (family_id, auth_time) =
            assert_fresh_session(&state, user_id, &cookies, before, after, &expected_amr).await;

        refresh_and_assert_unchanged(
            &app,
            &state,
            user_id,
            &cookies,
            family_id,
            auth_time,
            &expected_amr,
        )
        .await;
    }
}

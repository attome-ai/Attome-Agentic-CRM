//! Q6-T1: passkeys through the assembled HTTP stack, with a software
//! authenticator (`attome_testkit::passkey`).
//!
//! A person adds a passkey only after a step-up, signs in with it alone only
//! once a role allows that, uses it as the second factor of a password
//! sign-in, steps up with it and removes it. Each mutation's audit event is
//! checked here, since `audit_coverage_emission` cannot sign a ceremony.
//!
//! Requires a live Postgres (`DATABASE_URL`, a throwaway database) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`). Skips cleanly when `DATABASE_URL`
//! is unset.
//!
//! ```powershell
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome --test passkey_http -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome::auth;
use attome_api::EngineSystem;
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ALLOWED_ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "passkey-http-password-1";
const SESSION_COOKIE: &str = "__Host-session_token";
const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36";

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
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

/// The full `main.rs` stack around both auth bundles.
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
    let email = format!("passkey-http-{user_id}@example.test");
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
    .bind(format!("passkey-http-{user_id}"))
    .bind(&email)
    .bind(password_hash)
    .execute(&state.db)
    .await
    .expect("insert throwaway user_account");
    (user_id, email)
}

/// One sign-in's cookies.
struct Signed {
    session: String,
}

impl Signed {
    fn session_cookie(&self) -> String {
        format!("{SESSION_COOKIE}={}", self.session)
    }
}

fn cookie_value(res: &axum::response::Response, name: &str) -> Option<String> {
    res.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next())
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<String>,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", ALLOWED_ORIGIN)
        .header(header::USER_AGENT, BROWSER);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let body = match body {
        Some(json) => {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .expect("request")
}

async fn sign_in(app: &axum::Router, email: &str) -> Signed {
    let res = send(
        app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(serde_json::json!({ "email": email, "password": PASSWORD })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "password sign-in succeeds");
    Signed {
        session: cookie_value(&res, SESSION_COOKIE).expect("session cookie"),
    }
}

async fn json_of(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("JSON body")
}

/// The relying party the test config gives: the frontend URL's host.
const RP_ID: &str = "localhost";
const RP_ORIGIN: &str = "http://localhost:4200";

fn authenticator(seed: u8) -> attome_testkit::passkey::Authenticator {
    attome_testkit::passkey::Authenticator::new(seed, RP_ID, RP_ORIGIN)
}

/// Mandatory events of `category`/`operation` written so far.
async fn events(state: &AppState, category: &str, operation: &str) -> i64 {
    let c: attome_audit::AuditCategory =
        serde_json::from_value(serde_json::json!(category)).expect("known category");
    let o: attome_audit::AuditOperation =
        serde_json::from_value(serde_json::json!(operation)).expect("known operation");
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE category = $1 AND operation = $2) \
              + (SELECT COUNT(*) FROM audit_ingest \
                 WHERE payload->>'category' = $3 AND payload->>'operation' = $4)",
    )
    .bind(c as i32)
    .bind(o as i32)
    .bind(category)
    .bind(operation)
    .fetch_one(&state.db)
    .await
    .expect("count audit events")
}

/// The `amr` the newest live family of `user_id` was signed in with.
async fn amr_of(state: &AppState, user_id: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT amr FROM refresh_token WHERE user_ref = $1 AND revoked_at IS NULL \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .expect("the newest session")
}

/// Gives `user_id` a new role whose sign-in policy sets `column` to the SQL
/// literal `value`.
async fn grant_role_with_policy(state: &AppState, user_id: Uuid, column: &str, value: &str) {
    let role = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'customer')")
        .bind(role)
        .bind(format!("passkey-http-{role}"))
        .execute(&state.db)
        .await
        .expect("insert a role");
    sqlx::query(&format!(
        "INSERT INTO role_auth_policy (role_ref, {column}) VALUES ($1, {value})"
    ))
    .bind(role)
    .execute(&state.db)
    .await
    .expect("set the role's sign-in policy");
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role)
        .execute(&state.db)
        .await
        .expect("grant the role");
}

/// Steps the session up for `passkey_manage` with the password.
async fn step_up_with_password(app: &axum::Router, signed: &Signed) {
    let started = send(
        app,
        "POST",
        "/api/v1/auth/step-up/passkey_manage",
        Some(signed.session_cookie()),
        None,
    )
    .await;
    assert_eq!(started.status(), StatusCode::CREATED, "the step-up starts");
    let challenge = json_of(started).await["challenge_id"]
        .as_str()
        .expect("a challenge id")
        .to_owned();
    let verified = send(
        app,
        "POST",
        "/api/v1/auth/step-up/passkey_manage/verify",
        Some(signed.session_cookie()),
        Some(serde_json::json!({
            "challenge_id": challenge, "factor": "password", "credential": PASSWORD,
        })),
    )
    .await;
    assert_eq!(
        verified.status(),
        StatusCode::OK,
        "the password step-up verifies"
    );
}

/// Adds a passkey through the routes; returns its id.
async fn add_passkey(
    app: &axum::Router,
    signed: &Signed,
    authenticator: &attome_testkit::passkey::Authenticator,
) -> Uuid {
    let started = send(
        app,
        "POST",
        "/api/v1/auth/passkeys/register/start",
        Some(signed.session_cookie()),
        None,
    )
    .await;
    assert_eq!(started.status(), StatusCode::OK, "registration starts");
    let options = json_of(started).await["options"].clone();
    assert_eq!(options["rp"]["id"], RP_ID, "the frontend host is the RP id");
    let finished = send(
        app,
        "POST",
        "/api/v1/auth/passkeys/register/finish",
        Some(signed.session_cookie()),
        Some(serde_json::json!({
            "label": "Work laptop", "response": authenticator.register(&options),
        })),
    )
    .await;
    assert_eq!(
        finished.status(),
        StatusCode::CREATED,
        "registration finishes"
    );
    json_of(finished).await["id"]
        .as_str()
        .expect("the passkey id")
        .parse()
        .expect("a uuid")
}

/// A passkey sign-in naming no one; the response as it came.
async fn passkey_sign_in(
    app: &axum::Router,
    authenticator: &mut attome_testkit::passkey::Authenticator,
    user_id: Uuid,
) -> axum::response::Response {
    let started = send(app, "POST", "/api/v1/auth/passkey/start", None, None).await;
    assert_eq!(started.status(), StatusCode::OK, "a passkey sign-in starts");
    let options = json_of(started).await["options"].clone();
    send(
        app,
        "POST",
        "/api/v1/auth/passkey/verify",
        None,
        Some(serde_json::json!({ "response": authenticator.assert(&options, user_id) })),
    )
    .await
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn passkey_added_after_step_up_signs_in_once_a_role_allows_it() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let signed = sign_in(&app, &email).await;
    let mut key = authenticator(31);

    // A session alone cannot add a passkey.
    let refused = send(
        &app,
        "POST",
        "/api/v1/auth/passkeys/register/start",
        Some(signed.session_cookie()),
        None,
    )
    .await;
    assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_of(refused).await["code"], "reauth_required");

    step_up_with_password(&app, &signed).await;
    let created = events(&state, "Credential", "Create").await;
    let passkey = add_passkey(&app, &signed, &key).await;
    assert_eq!(
        events(&state, "Credential", "Create").await,
        created + 1,
        "adding a passkey is audited"
    );
    let listed = json_of(
        send(
            &app,
            "GET",
            "/api/v1/auth/passkeys",
            Some(signed.session_cookie()),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(listed["total"], 1);
    assert_eq!(listed["items"][0]["id"], passkey.to_string());
    assert_eq!(listed["items"][0]["label"], "Work laptop");
    assert!(
        listed["items"][0].get("public_key").is_none(),
        "the key never leaves the server"
    );

    // No role allows a passkey alone yet: refused, and audited.
    let failed = events(&state, "Security", "FailedLogin").await;
    let res = passkey_sign_in(&app, &mut key, user_id).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(events(&state, "Security", "FailedLogin").await, failed + 1);

    grant_role_with_policy(&state, user_id, "passkey_sign_in", "true").await;
    let logins = events(&state, "Security", "Login").await;
    let res = passkey_sign_in(&app, &mut key, user_id).await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a role allows a passkey alone"
    );
    assert!(
        cookie_value(&res, SESSION_COOKIE).is_some(),
        "a session is issued"
    );
    assert_eq!(events(&state, "Security", "Login").await, logins + 1);
    assert_eq!(amr_of(&state, user_id).await, vec!["hwk"]);

    // A single sign-on rule still wins over the role.
    grant_role_with_policy(&state, user_id, "sso_only", "true").await;
    let res = passkey_sign_in(&app, &mut key, user_id).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn passkey_is_a_second_factor_and_a_step_up() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (user_id, email) = seed_user(&state).await;
    let mut key = authenticator(32);
    let signed = sign_in(&app, &email).await;
    step_up_with_password(&app, &signed).await;
    let passkey = add_passkey(&app, &signed, &key).await;

    // Now a role requires a second factor; the passkey is one.
    grant_role_with_policy(&state, user_id, "mfa_mode", "'required'").await;
    let res = send(
        &app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(serde_json::json!({ "email": email, "password": PASSWORD })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let challenge = json_of(res).await;
    assert_eq!(challenge["mfa"], "required", "a passkey counts as enrolled");
    assert_eq!(challenge["passkey"], true, "the page may offer the passkey");
    let pending = challenge["pending_token"]
        .as_str()
        .expect("pending token")
        .to_owned();

    let started = send(
        &app,
        "POST",
        "/api/v1/auth/mfa/passkey/start",
        None,
        Some(serde_json::json!({ "pending_token": pending })),
    )
    .await;
    assert_eq!(started.status(), StatusCode::OK);
    let options = json_of(started).await["options"].clone();
    let response = key.assert(&options, user_id);
    let logins = events(&state, "Security", "Login").await;
    let res = send(
        &app,
        "POST",
        "/api/v1/auth/mfa/passkey/verify",
        None,
        Some(serde_json::json!({ "pending_token": pending, "response": response })),
    )
    .await;
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the passkey finishes the sign-in"
    );
    let second = Signed {
        session: cookie_value(&res, SESSION_COOKIE).expect("session cookie"),
    };
    assert_eq!(events(&state, "Security", "Login").await, logins + 1);
    assert_eq!(amr_of(&state, user_id).await, vec!["pwd", "hwk"]);

    // The pending token is spent.
    let replay = send(
        &app,
        "POST",
        "/api/v1/auth/mfa/passkey/start",
        None,
        Some(serde_json::json!({ "pending_token": pending })),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    // A passkey step-up elevates the new session, which may then remove it.
    let started = send(
        &app,
        "POST",
        "/api/v1/auth/step-up/passkey_manage/passkey",
        Some(second.session_cookie()),
        None,
    )
    .await;
    assert_eq!(started.status(), StatusCode::OK);
    let options = json_of(started).await["options"].clone();
    let res = send(
        &app,
        "POST",
        "/api/v1/auth/step-up/passkey_manage/passkey/verify",
        Some(second.session_cookie()),
        Some(serde_json::json!({ "response": key.assert(&options, user_id) })),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK, "the passkey step-up verifies");
    assert_eq!(json_of(res).await["operation"], "passkey_manage");

    let deleted = events(&state, "Credential", "SoftDelete").await;
    let res = send(
        &app,
        "DELETE",
        &format!("/api/v1/auth/passkeys/{passkey}"),
        Some(second.session_cookie()),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        events(&state, "Credential", "SoftDelete").await,
        deleted + 1
    );
    let listed = send(
        &app,
        "GET",
        "/api/v1/auth/passkeys",
        Some(second.session_cookie()),
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(
        json_of(listed).await["total"],
        0,
        "a removed passkey is gone"
    );

    // The passkey elevation no longer counts once the account has none.
    let again = send(
        &app,
        "DELETE",
        &format!("/api/v1/auth/passkeys/{passkey}"),
        Some(second.session_cookie()),
        None,
    )
    .await;
    assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(json_of(again).await["error"], "reauth_required");
}

#[tokio::test]
async fn another_persons_passkey_is_never_theirs() {
    let (app, state) = skip_if_no_db!(test_app().await);
    let (_, owner_email) = seed_user(&state).await;
    let owner = sign_in(&app, &owner_email).await;
    step_up_with_password(&app, &owner).await;
    let passkey = add_passkey(&app, &owner, &authenticator(33)).await;

    let (_, other_email) = seed_user(&state).await;
    let other = sign_in(&app, &other_email).await;
    step_up_with_password(&app, &other).await;
    let res = send(
        &app,
        "DELETE",
        &format!("/api/v1/auth/passkeys/{passkey}"),
        Some(other.session_cookie()),
        None,
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let listed = json_of(
        send(
            &app,
            "GET",
            "/api/v1/auth/passkeys",
            Some(other.session_cookie()),
            None,
        )
        .await,
    )
    .await;
    assert_eq!(listed["total"], 0, "the other person sees none");
}

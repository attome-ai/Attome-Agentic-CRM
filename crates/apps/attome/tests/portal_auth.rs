//! Web portal Phase 2: authentication, proven over HTTP through the full
//! middleware stack with the portal router mounted exactly as `main.rs`
//! mounts it (`ServerBuilder::add_audience_bundle`).
//!
//! `token_isolation_matrix` is the Phase 2 gate (plan §5): staff and portal
//! sessions, and sessions of two portals, must never authenticate each other,
//! and wrong audience, wrong type, expiry, a disabled user, a deactivated
//! portal and a bumped epoch must each be refused. The other tests cover the
//! flows D-573 lists: invitation, login, lockout, refresh rotation and reuse,
//! logout, reset, MFA, per-portal cookies, anonymous portals, and the staff
//! bypass lists staying as they were.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"; $env:TEST_REDIS_HOST = "127.0.0.1"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<migrated template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p server --test portal_auth -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test seeds fixtures on the raw pool; production code uses attome_db::tx::begin"
)]

use std::net::SocketAddr;

use attome::auth;
use attome_api::EngineSystem;
use attome_audit::security::SecurityAuditor;
use attome_auth::session::TokenType;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_portal::provision::{self, MfaPolicy, NewPortal, NewPortalUser, PortalType};
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";
const ORIGIN: &str = "http://allowed.test";
const PASSWORD: &str = "portal-auth-password-1";

fn test_config() -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 65536, "request_timeout_secs": 30,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 10, "timeout": 5.0
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
            "rate_limit": {{ "anonymous_rpm": 100000, "authenticated_rpm": 100000 }},
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
            "s2s": {{ "enabled": false, "key_encryption_key": "{s2s_key}" }},
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["{origin}"] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        s2s_key = "cd".repeat(32),
        origin = ORIGIN,
    );
    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    // Portal MFA secrets are envelope-encrypted under this ring.
    config.auth.mfa_encryption_key = KeyRing::single("ab".repeat(32));
    // The reset-request route only issues a link when email is on.
    config.email.enabled = true;
    config
}

fn full_license() -> std::sync::Arc<attome_modules::ModuleSet> {
    std::sync::Arc::new(attome_modules::ModuleSet::from_bits([u64::MAX; 4]))
}

struct Fx {
    app: axum::Router,
    base: AppState,
    /// A real staff session (with a refresh family), for the staff rows.
    staff_token: String,
}

async fn fixture() -> Option<Fx> {
    fixture_with(|_| {}).await
}

async fn fixture_with(tweak: impl FnOnce(&mut AppConfig)) -> Option<Fx> {
    let mut config = test_config();
    tweak(&mut config);
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
    let base = AppState::new(
        config.clone(),
        db.clone(),
        db.clone(),
        db,
        redis,
        redis_coordination,
        storage,
    );
    let system = EngineSystem::builder(EngineState::new(base))
        .register(attome_security::model::SecurityModel)
        .register(attome_portal::PortalModel)
        .build()
        .await
        .expect("build EngineSystem");
    system.state().modules.store(full_license());

    let xrm = system.state().clone();
    let base_state = xrm.base.clone();
    let license = xrm.modules.clone();
    let public_bundle = attome_server::RouteBundle::new(
        auth::public_routes(license, SecurityAuditor::from_state(&xrm))
            .with_state(base_state.clone()),
    );
    let protected_bundle = attome_server::RouteBundle::new(
        auth::protected_routes(SecurityAuditor::from_state(&xrm)).with_state(base_state.clone()),
    );
    // Exactly as `main.rs` mounts it.
    let portal_bundle = attome_server::RouteBundle::new(attome_portal::router::app(xrm.clone()));
    let app = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(public_bundle)
        .add_bundle(protected_bundle)
        .add_audience_bundle(portal_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));

    let staff_id = seed_staff(&base_state).await;
    let staff_token = staff_session(&base_state, staff_id).await;
    Some(Fx {
        app,
        base: base_state,
        staff_token,
    })
}

async fn seed_staff(state: &AppState) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active, email_verified) \
         VALUES ($1, $2, $3, true, true)",
    )
    .bind(user_id)
    .bind(format!("portal-auth-staff-{user_id}"))
    .bind(format!("portal-auth-staff-{user_id}@example.test"))
    .execute(&state.db)
    .await
    .expect("insert staff user");
    user_id
}

async fn staff_session(state: &AppState, user_id: Uuid) -> String {
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
    attome_auth::accounts::issue_access_token(
        &state.db,
        user_id,
        issued.family_id,
        &KeyRing::single(THROWAWAY_JWT_SECRET.to_string()),
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        3600,
    )
    .await
    .expect("issue a staff session token")
}

// ── Portal fixtures ───────────────────────────────────────────────────────────

struct Portal {
    id: Uuid,
    keyword: String,
}

async fn portal(fx: &Fx, portal_type: PortalType, mfa_policy: MfaPolicy) -> Portal {
    let mut tx = fx.base.db.begin().await.unwrap();
    let p = provision::create_portal(
        &mut tx,
        Uuid::now_v7(),
        NewPortal {
            name: "Customers".into(),
            description: None,
            keyword: format!("pa-{}", &Uuid::now_v7().simple().to_string()[20..]),
            portal_type,
            is_enabled: true,
            owning_team_ref: None,
            mfa_policy,
        },
    )
    .await
    .expect("create portal");
    tx.commit().await.unwrap();
    Portal {
        id: p.id,
        keyword: p.keyword,
    }
}

/// A portal user who has accepted their invitation over HTTP (so the
/// invitation route is exercised by every test) and can log in.
async fn active_user(fx: &Fx, p: &Portal) -> (Uuid, String) {
    let email = format!("{}@example.com", Uuid::now_v7().simple());
    let mut tx = fx.base.db.begin().await.unwrap();
    let user = provision::create_user(
        &mut tx,
        Uuid::now_v7(),
        p.id,
        NewPortalUser {
            name: "Ada".into(),
            email: Some(email.clone()),
            username: None,
        },
    )
    .await
    .expect("create user");
    let (_, invitation) =
        attome_portal::auth::issue_invitation(&mut tx, &fx.base.pepper_ring(), p.id, user.id)
            .await
            .unwrap()
            .expect("invitation");
    tx.commit().await.unwrap();

    // On a portal host: required once D-585 host sets are configured, and
    // harmless without them (every host then serves portals outside
    // production).
    let res = send(
        fx,
        on_host(
            portal_req(
                "POST",
                &format!("/{}/api/v1/auth/invitation/accept", p.keyword),
                &[],
                Some(json!({"token": invitation.bearer, "password": PASSWORD})),
            ),
            "portal.test",
        ),
    )
    .await;
    assert_eq!(
        res.0,
        StatusCode::NO_CONTENT,
        "accept invitation: {}",
        res.2
    );
    (user.id, email)
}

/// Logs in over HTTP; returns the `name=value` cookie pairs it set.
async fn login(fx: &Fx, p: &Portal, email: &str, code: Option<String>) -> Vec<String> {
    let (status, cookies, body) = send(
        fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD, "code": code})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login: {body}");
    assert_eq!(cookies.len(), 2, "session and refresh cookies: {cookies:?}");
    cookies
}

fn cookie_value<'a>(cookies: &'a [String], suffix: &str) -> &'a str {
    cookies
        .iter()
        .find_map(|c| {
            let (name, value) = c.split_once('=')?;
            name.ends_with(suffix).then_some(value)
        })
        .unwrap_or_else(|| panic!("no *{suffix} cookie in {cookies:?}"))
}

fn session_of(cookies: &[String]) -> String {
    cookie_value(cookies, "_session").to_owned()
}

fn refresh_of(cookies: &[String]) -> String {
    cookie_value(cookies, "_refresh").to_owned()
}

fn names(p: &Portal) -> attome_portal::session::CookieNames {
    // The test config leaves `auth.secure_cookies` at its default (true).
    attome_portal::session::cookie_names(&p.keyword, true)
}

/// A request from the allowed origin, carrying `cookies` (`name=value`).
fn portal_req(method: &str, uri: &str, cookies: &[String], body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", ORIGIN);
    if !cookies.is_empty() {
        builder = builder.header(header::COOKIE, cookies.join("; "));
    }
    let mut req = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("build request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 40_007))));
    req
}

/// Status, `name=value` pairs of every non-empty `Set-Cookie`, and body text.
async fn send(fx: &Fx, req: Request<Body>) -> (StatusCode, Vec<String>, String) {
    let res = fx.app.clone().oneshot(req).await.expect("send");
    let status = res.status();
    let cookies = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|v| v.split(';').next().map(str::to_owned))
        .filter(|pair| !pair.ends_with('='))
        .collect();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        cookies,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn me(fx: &Fx, p: &Portal, session_cookie: &str) -> StatusCode {
    let cookie = format!("{}={session_cookie}", names(p).session);
    send(
        fx,
        portal_req("GET", &format!("/{}/api/v1/me", p.keyword), &[cookie], None),
    )
    .await
    .0
}

async fn refresh(fx: &Fx, p: &Portal, refresh_cookie: &str) -> (StatusCode, Vec<String>) {
    let cookie = format!("{}={refresh_cookie}", names(p).refresh);
    let (status, cookies, _) = send(
        fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/refresh", p.keyword),
            &[cookie],
            None,
        ),
    )
    .await;
    (status, cookies)
}

/// A staff route every authenticated staff user may call.
const STAFF_ROUTE: &str = "/api/v1/auth/mfa/status";

async fn staff_route_with(fx: &Fx, cookie: String) -> StatusCode {
    send(fx, portal_req("GET", STAFF_ROUTE, &[cookie], None))
        .await
        .0
}

/// A session-shaped token with arbitrary claims, signed with the deployment
/// key, for the forged-token rows of the matrix.
fn forge(fx: &Fx, sub: Uuid, typ: TokenType, aud: String, exp_offset: i64, family: Uuid) -> String {
    let now = chrono::Utc::now().timestamp();
    attome_auth::jwt::create_session_token(
        &attome_auth::session::SessionClaims {
            sub,
            iat: now,
            exp: now + exp_offset,
            jti: Uuid::now_v7(),
            epoch: 0,
            iss: fx.base.config.auth.jwt_issuer.clone(),
            aud,
            typ,
        },
        family,
        &fx.base.secrets.load().jwt_secret,
    )
    .expect("forge token")
}

/// The family id a portal access token names.
fn family_of(fx: &Fx, p: &Portal, token: &str) -> Uuid {
    attome_portal::session::validate_access(
        token,
        &fx.base.secrets.load().jwt_secret,
        &fx.base.config.auth.jwt_issuer,
        p.id,
    )
    .expect("a valid portal token")
    .1
    .0
}

// ── The isolation matrix (plan §5, the Phase 2 gate) ──────────────────────────

#[tokio::test]
async fn token_isolation_matrix() {
    let fx = skip_if_no_db!(fixture().await);
    let a = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let b = portal(&fx, PortalType::Mixed, MfaPolicy::Optional).await;
    let (user_a, email_a) = active_user(&fx, &a).await;
    let (_, email_b) = active_user(&fx, &b).await;
    let session_a = session_of(&login(&fx, &a, &email_a, None).await);
    let session_b = session_of(&login(&fx, &b, &email_b, None).await);
    let family_a = family_of(&fx, &a, &session_a);

    // Allowed: staff session on a staff route, portal session on its portal.
    assert_eq!(
        staff_route_with(&fx, format!("__Host-session_token={}", fx.staff_token)).await,
        StatusCode::OK,
        "staff session -> staff route"
    );
    assert_eq!(
        me(&fx, &a, &session_a).await,
        StatusCode::OK,
        "portal A -> portal A"
    );

    // Staff session -> portal route: under the portal's cookie name, and as
    // the staff cookie on the portal path.
    assert_eq!(
        me(&fx, &a, &fx.staff_token).await,
        StatusCode::UNAUTHORIZED,
        "staff session -> portal route"
    );
    let (status, _, _) = send(
        &fx,
        portal_req(
            "GET",
            &format!("/{}/api/v1/me", a.keyword),
            &[format!("__Host-session_token={}", fx.staff_token)],
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "staff cookie -> portal route"
    );

    // Portal A -> staff route, under the staff cookie name and its own.
    assert_eq!(
        staff_route_with(&fx, format!("__Host-session_token={session_a}")).await,
        StatusCode::UNAUTHORIZED,
        "portal A token as staff cookie -> staff route"
    );
    assert_eq!(
        staff_route_with(&fx, format!("{}={session_a}", names(&a).session)).await,
        StatusCode::UNAUTHORIZED,
        "portal A cookie -> staff route"
    );

    // Cross-portal, both directions.
    assert_eq!(
        me(&fx, &a, &session_b).await,
        StatusCode::UNAUTHORIZED,
        "portal B -> portal A"
    );
    assert_eq!(
        me(&fx, &b, &session_a).await,
        StatusCode::UNAUTHORIZED,
        "portal A -> portal B"
    );

    // Forged tokens signed with the real key, each one claim off.
    let wrong_aud = forge(
        &fx,
        user_a,
        TokenType::PortalSession,
        format!("portal:{}", b.id),
        600,
        family_a,
    );
    assert_eq!(
        me(&fx, &a, &wrong_aud).await,
        StatusCode::UNAUTHORIZED,
        "wrong aud"
    );
    let wrong_typ = forge(
        &fx,
        user_a,
        TokenType::Session,
        format!("portal:{}", a.id),
        600,
        family_a,
    );
    assert_eq!(
        me(&fx, &a, &wrong_typ).await,
        StatusCode::UNAUTHORIZED,
        "wrong typ"
    );
    let expired = forge(
        &fx,
        user_a,
        TokenType::PortalSession,
        format!("portal:{}", a.id),
        -60,
        family_a,
    );
    assert_eq!(
        me(&fx, &a, &expired).await,
        StatusCode::UNAUTHORIZED,
        "expired"
    );
    let unknown_family = forge(
        &fx,
        user_a,
        TokenType::PortalSession,
        format!("portal:{}", a.id),
        600,
        Uuid::now_v7(),
    );
    assert_eq!(
        me(&fx, &a, &unknown_family).await,
        StatusCode::UNAUTHORIZED,
        "unknown family"
    );

    // Epoch-invalidated session.
    sqlx::query(
        "UPDATE webportal_credential SET auth_epoch = auth_epoch + 1 WHERE webportal_user_id = $1",
    )
    .bind(user_a)
    .execute(&fx.base.db)
    .await
    .unwrap();
    assert_eq!(
        me(&fx, &a, &session_a).await,
        StatusCode::UNAUTHORIZED,
        "epoch bumped"
    );

    // Disabled user (through the admin engine path, which also bumps the epoch;
    // a fresh session proves the status check on its own).
    let (user_c, email_c) = active_user(&fx, &a).await;
    let session_c = session_of(&login(&fx, &a, &email_c, None).await);
    sqlx::query("UPDATE webportal_user SET status = 'disabled' WHERE id = $1")
        .bind(user_c)
        .execute(&fx.base.db)
        .await
        .unwrap();
    assert_eq!(
        me(&fx, &a, &session_c).await,
        StatusCode::UNAUTHORIZED,
        "disabled user"
    );

    // Deactivated portal: its routes disappear.
    let session_b2 = session_of(&login(&fx, &b, &email_b, None).await);
    sqlx::query("UPDATE webportal SET is_enabled = FALSE WHERE id = $1")
        .bind(b.id)
        .execute(&fx.base.db)
        .await
        .unwrap();
    assert_eq!(
        me(&fx, &b, &session_b2).await,
        StatusCode::NOT_FOUND,
        "deactivated portal"
    );
    let _ = session_b;
}

#[tokio::test]
async fn admin_disable_and_portal_deactivation_revoke_sessions_through_the_real_paths() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (user, email) = active_user(&fx, &p).await;
    let session = session_of(&login(&fx, &p, &email, None).await);
    assert_eq!(me(&fx, &p, &session).await, StatusCode::OK);

    let mut tx = fx.base.db.begin().await.unwrap();
    provision::set_user_enabled(&mut tx, Uuid::now_v7(), p.id, user, false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(me(&fx, &p, &session).await, StatusCode::UNAUTHORIZED);
    // Re-enabling does not resurrect the old session: its epoch is stale.
    let mut tx = fx.base.db.begin().await.unwrap();
    provision::set_user_enabled(&mut tx, Uuid::now_v7(), p.id, user, true)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(me(&fx, &p, &session).await, StatusCode::UNAUTHORIZED);
    // A new login works, and disabling the portal ends it too.
    let session = session_of(&login(&fx, &p, &email, None).await);
    let row_version: i64 = sqlx::query_scalar("SELECT row_version FROM webportal WHERE id = $1")
        .bind(p.id)
        .fetch_one(&fx.base.db)
        .await
        .unwrap();
    let mut tx = fx.base.db.begin().await.unwrap();
    provision::update_portal_settings(
        &mut tx,
        Uuid::now_v7(),
        p.id,
        attome_portal::provision::PortalSettingsPatch {
            row_version,
            keyword: None,
            portal_type: None,
            is_enabled: Some(false),
            owning_team_ref: None,
            mfa_policy: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(me(&fx, &p, &session).await, StatusCode::NOT_FOUND);
    // Re-enabled, the old session is still dead (epoch bumped on disable).
    sqlx::query("UPDATE webportal SET is_enabled = TRUE WHERE id = $1")
        .bind(p.id)
        .execute(&fx.base.db)
        .await
        .unwrap();
    assert_eq!(me(&fx, &p, &session).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_rotates_and_reuse_revokes_the_family() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    let first = login(&fx, &p, &email, None).await;
    let r1 = refresh_of(&first);

    let (status, second) = refresh(&fx, &p, &r1).await;
    assert_eq!(status, StatusCode::OK);
    let r2 = refresh_of(&second);
    let s2 = session_of(&second);
    assert_ne!(r1, r2);
    assert_eq!(me(&fx, &p, &s2).await, StatusCode::OK);

    // r1 again: reuse. The family dies, taking r2 and every access token.
    assert_eq!(refresh(&fx, &p, &r1).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(refresh(&fx, &p, &r2).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(me(&fx, &p, &s2).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        me(&fx, &p, &session_of(&first)).await,
        StatusCode::UNAUTHORIZED
    );

    // A refresh token is bound to its portal.
    let other = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email2) = active_user(&fx, &p).await;
    let fresh = login(&fx, &p, &email2, None).await;
    assert_eq!(
        refresh(&fx, &other, &refresh_of(&fresh)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_ends_the_session_and_clears_cookies() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    let cookies = login(&fx, &p, &email, None).await;
    let session_cookie = format!("{}={}", names(&p).session, session_of(&cookies));
    let res = fx
        .app
        .clone()
        .oneshot(portal_req(
            "POST",
            &format!("/{}/api/v1/auth/logout", p.keyword),
            &[session_cookie],
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    let cleared: Vec<_> = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|v| v.contains("Max-Age=0"))
        .collect();
    assert_eq!(cleared.len(), 2, "both cookies cleared: {cleared:?}");
    assert!(
        cleared
            .iter()
            .any(|c| c.contains(&format!("Path=/{}/", p.keyword)))
    );
    assert_eq!(
        me(&fx, &p, &session_of(&cookies)).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh(&fx, &p, &refresh_of(&cookies)).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn cookies_are_named_and_scoped_per_portal() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    let res = fx
        .app
        .clone()
        .oneshot(portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD})),
        ))
        .await
        .unwrap();
    let set: Vec<String> = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_owned))
        .collect();
    let session = set
        .iter()
        .find(|c| c.starts_with(&format!("__Secure-wp_{}_session=", p.keyword)))
        .expect("session cookie");
    assert!(
        session.contains(&format!("Path=/{}/", p.keyword)),
        "{session}"
    );
    for flag in ["HttpOnly", "Secure", "SameSite=Strict"] {
        assert!(session.contains(flag), "{flag} missing: {session}");
    }
    let refresh = set
        .iter()
        .find(|c| c.starts_with(&format!("__Secure-wp_{}_refresh=", p.keyword)))
        .expect("refresh cookie");
    assert!(
        refresh.contains(&format!("Path=/{}/api/v1/auth/", p.keyword)),
        "{refresh}"
    );
    assert!(
        !set.iter().any(|c| c.starts_with("__Host-session_token")),
        "no staff cookie"
    );
}

#[tokio::test]
async fn anonymous_disabled_and_unknown_portals_have_no_auth_routes() {
    let fx = skip_if_no_db!(fixture().await);
    let anonymous = portal(&fx, PortalType::Anonymous, MfaPolicy::Optional).await;
    let body = json!({"email": "x@example.com", "password": PASSWORD});
    for kw in [
        anonymous.keyword.as_str(),
        "no-such-portal-kw",
        "xrm",
        "api",
    ] {
        for (method, path, body) in [
            ("POST", "auth/login", Some(body.clone())),
            ("POST", "auth/refresh", None),
            (
                "POST",
                "auth/reset-request",
                Some(json!({"email": "x@example.com"})),
            ),
            ("GET", "me", None),
        ] {
            let (status, _, text) = send(
                &fx,
                portal_req(method, &format!("/{kw}/api/v1/{path}"), &[], body),
            )
            .await;
            // `xrm` and `api` are reserved keywords: `/api/api/v1/auth/login`
            // is keyword `api` plus a portal route, so the portal router
            // answers it with the same uniform 404 as any unknown portal.
            // (Unmatched *staff* paths are a different case: they still go
            // through staff authn and answer 401; see portal_isolation T-6.)
            assert_eq!(status, StatusCode::NOT_FOUND, "/{kw}/api/v1/{path}: {text}");
        }
    }
}

#[tokio::test]
async fn repeated_failures_lock_the_account_without_revealing_it() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (user, email) = active_user(&fx, &p).await;
    for _ in 0..attome_portal::auth::LOCKOUT_THRESHOLD {
        let (status, _, _) = send(
            &fx,
            portal_req(
                "POST",
                &format!("/{}/api/v1/auth/login", p.keyword),
                &[],
                Some(json!({"email": email, "password": "wrong-password-123"})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let locked: bool = sqlx::query_scalar(
        "SELECT locked_until > NOW() FROM webportal_credential WHERE webportal_user_id = $1",
    )
    .bind(user)
    .fetch_one(&fx.base.db)
    .await
    .unwrap();
    assert!(locked);
    // The right password is refused while locked, with the same response.
    let (status, _, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{text}");
    // An unknown email gets exactly that response too.
    let (status2, _, text2) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": "nobody@example.com", "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status2, status);
    let strip = |t: &str| {
        let mut v: Value = serde_json::from_str(t).unwrap();
        v.as_object_mut().unwrap().remove("request_id");
        v
    };
    assert_eq!(strip(&text), strip(&text2));
}

#[tokio::test]
async fn reset_ends_every_session_and_sets_the_new_password() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (user, email) = active_user(&fx, &p).await;
    let cookies = login(&fx, &p, &email, None).await;

    // The request route answers the same for known and unknown addresses.
    for addr in [email.as_str(), "nobody@example.com"] {
        let (status, _, text) = send(
            &fx,
            portal_req(
                "POST",
                &format!("/{}/api/v1/auth/reset-request", p.keyword),
                &[],
                Some(json!({"email": addr})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
    }
    let issued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webportal_token WHERE webportal_user_id = $1 AND kind = 'reset'",
    )
    .bind(user)
    .fetch_one(&fx.base.db)
    .await
    .unwrap();
    assert_eq!(issued, 1, "the known address got exactly one link");

    // The emailed bearer is not observable here; issue a fresh one the same
    // way and confirm it over HTTP.
    let mut tx = fx.base.db.begin().await.unwrap();
    let token = attome_portal::onetime::issue(
        &mut tx,
        &fx.base.pepper_ring(),
        attome_portal::onetime::Kind::Reset,
        p.id,
        user,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let new_password = "a-brand-new-password-2026";
    let (status, _, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/reset-confirm", p.keyword),
            &[],
            Some(json!({"token": token.bearer, "password": new_password})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    // Single use.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/reset-confirm", p.keyword),
            &[],
            Some(json!({"token": token.bearer, "password": new_password})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    assert_eq!(
        me(&fx, &p, &session_of(&cookies)).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        refresh(&fx, &p, &refresh_of(&cookies)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": new_password})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn an_invitation_works_once_and_only_on_its_own_portal() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let other = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let mut tx = fx.base.db.begin().await.unwrap();
    let user = provision::create_user(
        &mut tx,
        Uuid::now_v7(),
        p.id,
        NewPortalUser {
            name: "Grace".into(),
            email: Some(format!("{}@example.com", Uuid::now_v7().simple())),
            username: None,
        },
    )
    .await
    .unwrap();
    let (_, invitation) =
        attome_portal::auth::issue_invitation(&mut tx, &fx.base.pepper_ring(), p.id, user.id)
            .await
            .unwrap()
            .unwrap();
    tx.commit().await.unwrap();
    let accept = |kw: &str| {
        portal_req(
            "POST",
            &format!("/{kw}/api/v1/auth/invitation/accept"),
            &[],
            Some(json!({"token": invitation.bearer, "password": PASSWORD})),
        )
    };
    assert_eq!(
        send(&fx, accept(&other.keyword)).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        send(&fx, accept(&p.keyword)).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        send(&fx, accept(&p.keyword)).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (status, verified): (String, bool) = sqlx::query_as(
        "SELECT u.status, c.email_verified FROM webportal_user u \
         JOIN webportal_credential c ON c.webportal_user_id = u.id WHERE u.id = $1",
    )
    .bind(user.id)
    .fetch_one(&fx.base.db)
    .await
    .unwrap();
    assert_eq!(status, "active");
    assert!(verified, "accepting the emailed link verifies the address");
}

#[tokio::test]
async fn an_invited_user_cannot_log_in_before_accepting() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let email = format!("{}@example.com", Uuid::now_v7().simple());
    let mut tx = fx.base.db.begin().await.unwrap();
    provision::create_user(
        &mut tx,
        Uuid::now_v7(),
        p.id,
        NewPortalUser {
            name: "Pending".into(),
            email: Some(email.clone()),
            username: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mfa_enrollment_then_login_requires_a_fresh_code() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    let cookies = login(&fx, &p, &email, None).await;
    let session_cookie = format!("{}={}", names(&p).session, session_of(&cookies));

    let (status, _, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/enroll", p.keyword),
            std::slice::from_ref(&session_cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let secret = serde_json::from_str::<Value>(&text).unwrap()["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    let code = attome_portal::mfa::code_at(&secret, now).unwrap();
    let (status, _, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/confirm", p.keyword),
            &[session_cookie],
            Some(json!({"code": code})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let codes = serde_json::from_str::<Value>(&text).unwrap()["recovery_codes"]
        .as_array()
        .map(Vec::len);
    assert_eq!(codes, Some(10), "confirm returns ten recovery codes");

    // Password alone is no longer enough.
    let (status, cookies, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(text.contains("mfa_required"), "{text}");
    assert!(cookies.is_empty());
    // The confirming code is a replay; the next step's code works.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD, "code": code})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "replayed code");
    let next = attome_portal::mfa::code_at(&secret, now + 30).unwrap();
    login(&fx, &p, &email, Some(next)).await;
}

#[tokio::test]
async fn a_required_mfa_portal_serves_only_enrollment_until_enrolled() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Required).await;
    let (_, email) = active_user(&fx, &p).await;
    let (status, cookies, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["mfa_enrollment_required"],
        true
    );
    let session = session_of(&cookies);
    assert_eq!(me(&fx, &p, &session).await, StatusCode::FORBIDDEN);

    let session_cookie = format!("{}={session}", names(&p).session);
    let (_, _, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/enroll", p.keyword),
            std::slice::from_ref(&session_cookie),
            None,
        ),
    )
    .await;
    let secret = serde_json::from_str::<Value>(&text).unwrap()["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/confirm", p.keyword),
            std::slice::from_ref(&session_cookie),
            Some(json!({"code": attome_portal::mfa::code_at(&secret, now).unwrap()})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me(&fx, &p, &session).await, StatusCode::OK);
    // And it cannot be switched off while the portal requires it.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/disable", p.keyword),
            &[session_cookie],
            Some(json!({"code": attome_portal::mfa::code_at(&secret, now + 30).unwrap()})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn a_cross_site_request_with_a_portal_cookie_is_refused() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    let session = session_of(&login(&fx, &p, &email, None).await);
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/{}/api/v1/me", p.keyword))
        .header("origin", "https://evil.example")
        .header("sec-fetch-site", "cross-site")
        .header(header::COOKIE, format!("{}={session}", names(&p).session))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 40_007))));
    assert_eq!(send(&fx, req).await.0, StatusCode::FORBIDDEN);
}

/// The audience bundle must not have widened the staff bypass lists, and a
/// staff route must still demand a staff session.
#[tokio::test]
async fn staff_bypass_lists_are_unchanged_and_staff_routes_still_need_a_session() {
    for path in attome_server::middleware::bypass::EXACT_BYPASS_PATHS
        .iter()
        .chain(attome_server::middleware::bypass::BYPASS_SUBTREE_PREFIXES)
    {
        assert!(!path.contains("{keyword}"), "{path}");
        assert!(!path.contains("webportal"), "{path}");
        assert!(
            path.starts_with("/api/")
                || path.starts_with("/health")
                || *path == "/version"
                // Z4-T4: the public signing keys, at the standard well-known path.
                || *path == "/.well-known/jwks.json"
                // Q3-T1: SCIM's own tree; its bearer token is the credential.
                || *path == "/scim/v2/",
            "a bypass outside the staff tree: {path}"
        );
    }
    let fx = skip_if_no_db!(fixture().await);
    let (status, _, _) = send(&fx, portal_req("GET", STAFF_ROUTE, &[], None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = send(&fx, portal_req("GET", "/api/v1/webportal", &[], None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A path no staff route matches still passes staff authn: 401, never a
    // 404 that would tell an unauthenticated caller which paths exist. (The
    // audience bundle is merged after the staff layers; the builder gives the
    // staff router an explicit fallback so this stays true.)
    for path in [
        "/api/v1/no-such-route",
        "/api/v1/no/such/route/at/all",
        "/nothing-here",
    ] {
        let (status, _, _) = send(&fx, portal_req("GET", path, &[], None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }
}

fn on_host(mut req: Request<Body>, host: &str) -> Request<Body> {
    req.headers_mut()
        .insert(header::HOST, host.parse().expect("host header"));
    req
}

/// D-585: with host sets configured, the staff API answers only on staff
/// hosts and portals only on portal hosts (404 before any authentication),
/// and a same-site request from a portal origin can't make a staff
/// state change with the staff cookie.
#[tokio::test]
async fn staff_and_portals_answer_only_on_their_own_hosts() {
    const STAFF_HOST: &str = "app.test";
    const PORTAL_HOST: &str = "portal.test";
    let fx = skip_if_no_db!(
        fixture_with(|c| {
            c.deployment.staff_hosts = vec![STAFF_HOST.into()];
            c.deployment.portal_hosts = vec![PORTAL_HOST.into()];
        })
        .await
    );
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    // Log in on the portal host.
    let login_req = on_host(
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({ "email": email, "password": PASSWORD })),
        ),
        PORTAL_HOST,
    );
    let (status, cookies, body) = send(&fx, login_req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "portal login on the portal host: {body}"
    );
    let session = session_of(&cookies);
    let portal_cookie = format!("{}={session}", names(&p).session);
    let staff_cookie = format!("__Host-session_token={}", fx.staff_token);

    let me_uri = format!("/{}/api/v1/me", p.keyword);
    let cases = [
        (STAFF_ROUTE, &staff_cookie, STAFF_HOST, StatusCode::OK),
        (
            STAFF_ROUTE,
            &staff_cookie,
            PORTAL_HOST,
            StatusCode::NOT_FOUND,
        ),
        (me_uri.as_str(), &portal_cookie, PORTAL_HOST, StatusCode::OK),
        (
            me_uri.as_str(),
            &portal_cookie,
            STAFF_HOST,
            StatusCode::NOT_FOUND,
        ),
        // An unmatched path on a portal host ends at the staff fallback,
        // behind the staff host gate: 404, not a staff 401.
        (
            "/api/v1/nope",
            &staff_cookie,
            PORTAL_HOST,
            StatusCode::NOT_FOUND,
        ),
    ];
    for (uri, cookie, host, expected) in cases {
        let mut req = on_host(
            portal_req("GET", uri, std::slice::from_ref(cookie), None),
            host,
        );
        if host == PORTAL_HOST {
            // A portal page's own origin: once portal hosts are configured, a
            // portal cookie is accepted only from one (G-10).
            req.headers_mut().insert(
                "origin",
                format!("https://{PORTAL_HOST}").parse().expect("origin"),
            );
        }
        assert_eq!(send(&fx, req).await.0, expected, "GET {uri} on {host}");
    }

    // The portal login route doesn't exist on the staff host.
    let req = on_host(
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({ "email": email, "password": PASSWORD })),
        ),
        STAFF_HOST,
    );
    assert_eq!(send(&fx, req).await.0, StatusCode::NOT_FOUND);

    // Same-site from a portal origin, riding the staff cookie: refused.
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header(header::HOST, STAFF_HOST)
        .header("origin", format!("https://{PORTAL_HOST}"))
        .header("sec-fetch-site", "same-site")
        .header(header::COOKIE, staff_cookie.clone())
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([203, 0, 113, 7], 40_007))));
    assert_eq!(
        send(&fx, req).await.0,
        StatusCode::FORBIDDEN,
        "same-site alone must not pass staff CSRF"
    );
    // The staff session still works (the refused logout did nothing).
    let req = on_host(
        portal_req("GET", STAFF_ROUTE, &[staff_cookie], None),
        STAFF_HOST,
    );
    assert_eq!(send(&fx, req).await.0, StatusCode::OK);
}

/// Enrols and confirms MFA on a signed-in session; returns the secret, the
/// time the confirming code was made for, and the recovery codes.
async fn enrol_mfa(fx: &Fx, p: &Portal, session_cookie: &str) -> (String, u64, Vec<String>) {
    let (status, _, text) = send(
        fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/enroll", p.keyword),
            &[session_cookie.to_owned()],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "enroll: {text}");
    let secret = serde_json::from_str::<Value>(&text).unwrap()["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap();
    let (status, _, text) = send(
        fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/confirm", p.keyword),
            &[session_cookie.to_owned()],
            Some(json!({"code": attome_portal::mfa::code_at(&secret, now).unwrap()})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "confirm: {text}");
    let codes = serde_json::from_str::<Value>(&text).unwrap()["recovery_codes"]
        .as_array()
        .expect("recovery_codes")
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    (secret, now, codes)
}

async fn login_with_code(
    fx: &Fx,
    p: &Portal,
    email: &str,
    code: &str,
) -> (StatusCode, Vec<String>, String) {
    send(
        fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD, "code": code})),
        ),
    )
    .await
}

/// D-588 item 1: a recovery code signs in once, in place of the TOTP code;
/// the use is audited and emailed; a regenerated set voids the old one and
/// needs a real TOTP code, never a recovery code.
#[tokio::test]
async fn a_recovery_code_signs_in_once_and_regeneration_voids_the_old_set() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (user_id, email) = active_user(&fx, &p).await;
    let cookies = login(&fx, &p, &email, None).await;
    let session_cookie = format!("{}={}", names(&p).session, session_of(&cookies));
    let (secret, confirmed_at, codes) = enrol_mfa(&fx, &p, &session_cookie).await;
    assert_eq!(codes.len(), 10);
    let distinct: std::collections::HashSet<_> = codes.iter().collect();
    assert_eq!(distinct.len(), 10, "codes are distinct");

    // Upper-case and without the dash: still the same code.
    let presented = codes[0].replace('-', "").to_uppercase();
    let (status, _, text) = login_with_code(&fx, &p, &email, &presented).await;
    assert_eq!(status, StatusCode::OK, "recovery login: {text}");
    let body: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["recovery_code_used"], true);
    assert_eq!(body["mfa_enrollment_required"], false, "optional portal");
    // Spent.
    let (status, _, _) = login_with_code(&fx, &p, &email, &codes[0]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a recovery code works once"
    );

    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_ingest WHERE payload->>'event_name' = 'portal login with an MFA recovery code' AND payload->>'record_id' = $1::text",
    )
    .bind(user_id)
    .fetch_one(&fx.base.db)
    .await
    .expect("count recovery-login events");
    assert_eq!(
        events, 1,
        "the recovery login is audited under its own name"
    );
    let mails: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_delivery WHERE recipient = $1 AND subject LIKE '%recovery code was used'",
    )
    .bind(&email)
    .fetch_one(&fx.base.db)
    .await
    .expect("count notices");
    assert_eq!(mails, 1, "the owner is told");

    // Regenerating refuses a recovery code and accepts a fresh TOTP code.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/recovery-codes", p.keyword),
            std::slice::from_ref(&session_cookie),
            Some(json!({"code": codes[1]})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let totp = attome_portal::mfa::code_at(&secret, confirmed_at + 30).unwrap();
    let (status, _, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/mfa/recovery-codes", p.keyword),
            std::slice::from_ref(&session_cookie),
            Some(json!({"code": totp})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "regenerate: {text}");
    let fresh = serde_json::from_str::<Value>(&text).unwrap()["recovery_codes"]
        .as_array()
        .unwrap()[0]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _, _) = login_with_code(&fx, &p, &email, &codes[1]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old set is void");
    let (status, _, _) = login_with_code(&fx, &p, &email, &fresh).await;
    assert_eq!(status, StatusCode::OK, "the new set works");
}

/// D-588 item 1 on an MFA-required portal: a recovery code only buys
/// re-enrolment, and the restriction survives a refresh until a new
/// authenticator is confirmed.
#[tokio::test]
async fn on_a_required_portal_a_recovery_code_forces_re_enrolment() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Required).await;
    let (_, email) = active_user(&fx, &p).await;
    let first = login(&fx, &p, &email, None).await;
    let first_cookie = format!("{}={}", names(&p).session, session_of(&first));
    let (_, _, codes) = enrol_mfa(&fx, &p, &first_cookie).await;

    let (status, cookies, text) = login_with_code(&fx, &p, &email, &codes[0]).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["mfa_enrollment_required"],
        true
    );
    let session = session_of(&cookies);
    assert_eq!(me(&fx, &p, &session).await, StatusCode::FORBIDDEN);
    // A refresh doesn't lift it.
    let (status, refreshed) = refresh(&fx, &p, &refresh_of(&cookies)).await;
    assert_eq!(status, StatusCode::OK);
    let refreshed_session = session_of(&refreshed);
    assert_eq!(me(&fx, &p, &refreshed_session).await, StatusCode::FORBIDDEN);
    // Nor does the earlier, pre-recovery session: the requirement is on the
    // account, not the token.
    assert_eq!(
        me(&fx, &p, &session_of(&first)).await,
        StatusCode::FORBIDDEN
    );

    // Confirming a new authenticator lifts it.
    let cookie = format!("{}={refreshed_session}", names(&p).session);
    enrol_mfa(&fx, &p, &cookie).await;
    assert_eq!(me(&fx, &p, &refreshed_session).await, StatusCode::OK);
}

/// D-588 item 4: the database refuses a second credential with the same
/// login email in one portal, even written past the provisioning lock.
#[tokio::test]
async fn the_login_email_is_unique_per_portal_in_the_database() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    let err = sqlx::query(
        "INSERT INTO webportal_credential (webportal_user_id, webportal_id, login_email_lower) \
         VALUES ($1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(p.id)
    .bind(email.to_lowercase())
    .execute(&fx.base.db)
    .await
    .expect_err("duplicate login email");
    assert_eq!(
        err.as_database_error().and_then(|d| d.code()).as_deref(),
        Some("23505")
    );
    // Another portal may hold the same address.
    let other = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    sqlx::query(
        "INSERT INTO webportal_credential (webportal_user_id, webportal_id, login_email_lower) \
         VALUES ($1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(other.id)
    .bind(email.to_lowercase())
    .execute(&fx.base.db)
    .await
    .expect("same address, other portal");
}

// ── Phase 11: accounts (D-588 items 2-3, G-11) ──────────────────────────────

async fn set_policy(fx: &Fx, p: &Portal, policy: attome_portal::policy::AuthPolicy) {
    let mut tx = fx.base.db.begin().await.unwrap();
    let current = attome_portal::policy::load(&mut tx, p.id).await.unwrap();
    attome_portal::policy::save(
        &mut tx,
        p.id,
        &attome_portal::policy::AuthPolicy {
            row_version: current.row_version,
            ..policy
        },
        &[],
        &[],
    )
    .await
    .expect("save policy");
    tx.commit().await.unwrap();
    // As the admin route does after its commit (G-9).
    attome_portal::cache::bump_version(&fx.base.redis)
        .await
        .expect("bump the portal access version");
}

async fn signup_role(fx: &Fx, p: &Portal) -> Uuid {
    let mut tx = fx.base.db.begin().await.unwrap();
    let role = attome_portal::roles::create_role(&mut tx, p.id, "self-registered")
        .await
        .expect("create role");
    tx.commit().await.unwrap();
    role.id
}

/// The token in the newest queued email to `email` that links to `page`.
async fn emailed_token(fx: &Fx, email: &str, page: &str) -> Option<String> {
    let jobs: Vec<String> = sqlx::query_scalar(
        "SELECT job::text FROM apalis.jobs WHERE job::text LIKE $1 AND job::text LIKE $2 \
         ORDER BY run_at DESC",
    )
    .bind(format!("%{email}%"))
    .bind(format!("%/{page}?token=%"))
    .fetch_all(&fx.base.db)
    .await
    .unwrap();
    let job = jobs.first()?;
    let start = job.find(&format!("/{page}?token="))? + page.len() + 8;
    Some(
        job[start..]
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == '-' || *c == '.')
            .collect(),
    )
}

async fn user_count(fx: &Fx, p: &Portal, email: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM webportal_user WHERE webportal_ref = $1 AND lower(email) = $2",
    )
    .bind(p.id)
    .bind(email.to_lowercase())
    .fetch_one(&fx.base.db)
    .await
    .unwrap()
}

async fn signup(fx: &Fx, p: &Portal, email: &str, extra: Value) -> (StatusCode, String) {
    let mut body = json!({"name": "New User", "email": email, "password": PASSWORD});
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    let (status, _, text) = send(
        fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/signup", p.keyword),
            &[],
            Some(body),
        ),
    )
    .await;
    (status, text)
}

/// D-588 item 2: signup creates nothing before verification; an existing
/// address gets the same answer (and a notice, not a link); the link works
/// once; an invite-only portal creates nothing.
#[tokio::test]
async fn signup_creates_nothing_before_verification_and_reveals_nothing() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;

    // Invite-only (the default): accepted, nothing sent, nothing created.
    let email = format!("{}@example.com", Uuid::now_v7().simple());
    let (status, _) = signup(&fx, &p, &email, json!({})).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(user_count(&fx, &p, &email).await, 0);
    assert!(emailed_token(&fx, &email, "verify-signup").await.is_none());

    let role = signup_role(&fx, &p).await;
    set_policy(
        &fx,
        &p,
        attome_portal::policy::AuthPolicy {
            signup_mode: attome_portal::policy::SignupMode::SelfService,
            signup_role_ref: Some(role),
            ..Default::default()
        },
    )
    .await;

    let (status, _) = signup(&fx, &p, &email, json!({})).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        user_count(&fx, &p, &email).await,
        0,
        "nothing before verification"
    );
    let token = emailed_token(&fx, &email, "verify-signup")
        .await
        .expect("a verification link was emailed");

    // An existing address: the same answer, and no link.
    let (_, existing) = active_user(&fx, &p).await;
    let (status, _) = signup(&fx, &p, &existing, json!({})).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(
        emailed_token(&fx, &existing, "verify-signup")
            .await
            .is_none()
    );

    let verify = |token: String| {
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/signup/verify", p.keyword),
            &[],
            Some(json!({"token": token})),
        )
    };
    let (status, _, text) = send(&fx, verify(token.clone())).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "verify: {text}");
    assert_eq!(user_count(&fx, &p, &email).await, 1);
    let role_of: Option<Uuid> = sqlx::query_scalar(
        "SELECT ur.role_id FROM webportal_user_role ur \
         JOIN webportal_user u ON u.id = ur.webportal_user_id \
         WHERE u.webportal_ref = $1 AND lower(u.email) = $2",
    )
    .bind(p.id)
    .bind(email.to_lowercase())
    .fetch_optional(&fx.base.db)
    .await
    .unwrap();
    assert_eq!(role_of, Some(role), "the signup role is assigned");
    login(&fx, &p, &email, None).await;

    // Single use.
    let (status, _, _) = send(&fx, verify(token)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

/// G-11: while the portal requires consent, records are refused until the
/// user accepts the current versions; a signup must carry them.
#[tokio::test]
async fn records_wait_for_consent_to_the_current_terms() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    set_policy(
        &fx,
        &p,
        attome_portal::policy::AuthPolicy {
            terms_version: Some("2026-09".into()),
            ..Default::default()
        },
    )
    .await;
    let cookie = format!(
        "{}={}",
        names(&p).session,
        session_of(&login(&fx, &p, &email, None).await)
    );
    let records = |c: &str| {
        portal_req(
            "GET",
            &format!("/{}/api/v1/records/no_such_entity", p.keyword),
            &[c.to_owned()],
            None,
        )
    };
    assert_eq!(send(&fx, records(&cookie)).await.0, StatusCode::FORBIDDEN);
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/me/consent", p.keyword),
            std::slice::from_ref(&cookie),
            Some(json!({"terms_version": "2025-01"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "an old version");
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/me/consent", p.keyword),
            std::slice::from_ref(&cookie),
            Some(json!({"terms_version": "2026-09"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Past the consent gate: the entity has no grant, so the usual 404.
    assert_eq!(send(&fx, records(&cookie)).await.0, StatusCode::NOT_FOUND);
}

/// G-11: changing the password needs the current one, ends every other
/// session and every old access token, and keeps this session working.
#[tokio::test]
async fn a_password_change_ends_other_sessions_and_keeps_this_one() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    let other = login(&fx, &p, &email, None).await;
    let mine = login(&fx, &p, &email, None).await;
    let cookie = format!("{}={}", names(&p).session, session_of(&mine));
    let change = |current: &str| {
        portal_req(
            "POST",
            &format!("/{}/api/v1/me/password", p.keyword),
            std::slice::from_ref(&cookie),
            Some(json!({"current_password": current, "new_password": "a-new-portal-password-2"})),
        )
    };
    assert_eq!(
        send(&fx, change("wrong-password-1")).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (status, cookies, text) = send(&fx, change(PASSWORD)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    let reissued = cookie_value(&cookies, "_session").to_owned();
    assert_eq!(
        me(&fx, &p, &reissued).await,
        StatusCode::OK,
        "this session, re-issued"
    );
    assert_eq!(
        me(&fx, &p, &session_of(&mine)).await,
        StatusCode::UNAUTHORIZED,
        "the old access token is dead (epoch)"
    );
    assert_eq!(
        refresh(&fx, &p, &refresh_of(&other)).await.0,
        StatusCode::UNAUTHORIZED,
        "the other session ended"
    );
    // The new password signs in.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": "a-new-portal-password-2"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// G-11: a user lists their sessions, ends one or all others; an erasure
/// request is idempotent.
#[tokio::test]
async fn users_manage_their_own_sessions_and_request_erasure() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, email) = active_user(&fx, &p).await;
    let other = login(&fx, &p, &email, None).await;
    let _third = login(&fx, &p, &email, None).await;
    let mine = login(&fx, &p, &email, None).await;
    let cookie = format!("{}={}", names(&p).session, session_of(&mine));
    let list = || async {
        let (status, _, text) = send(
            &fx,
            portal_req(
                "GET",
                &format!("/{}/api/v1/me/sessions", p.keyword),
                std::slice::from_ref(&cookie),
                None,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        serde_json::from_str::<Value>(&text).unwrap()
    };
    let sessions = list().await;
    let sessions = sessions.as_array().unwrap();
    assert_eq!(sessions.len(), 3);
    assert_eq!(sessions.iter().filter(|s| s["current"] == true).count(), 1);

    let other_family = family_of(&fx, &p, &session_of(&other));
    let (status, _, _) = send(
        &fx,
        portal_req(
            "DELETE",
            &format!("/{}/api/v1/me/sessions/{other_family}", p.keyword),
            std::slice::from_ref(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        me(&fx, &p, &session_of(&other)).await,
        StatusCode::UNAUTHORIZED
    );
    // Someone else's (or an unknown) session is a 404.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "DELETE",
            &format!("/{}/api/v1/me/sessions/{}", p.keyword, Uuid::now_v7()),
            std::slice::from_ref(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/me/sessions/end-others", p.keyword),
            std::slice::from_ref(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(list().await.as_array().unwrap().len(), 1);
    assert_eq!(me(&fx, &p, &session_of(&mine)).await, StatusCode::OK);

    let erase = || {
        portal_req(
            "POST",
            &format!("/{}/api/v1/me/erasure-request", p.keyword),
            std::slice::from_ref(&cookie),
            None,
        )
    };
    let (status, _, first) = send(&fx, erase()).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, _, second) = send(&fx, erase()).await;
    assert_eq!(
        serde_json::from_str::<Value>(&first).unwrap()["request_id"],
        serde_json::from_str::<Value>(&second).unwrap()["request_id"],
        "one open request, not two"
    );
}

/// D-588 item 3: a pending OIDC link needs proof of the existing account; a
/// pending step is single-use and bound to its portal.
#[tokio::test]
async fn an_oidc_link_needs_proof_of_the_account_and_is_single_use() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let other_portal = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (user, _) = active_user(&fx, &p).await;
    let stage = || async {
        attome_portal::oidc::store_pending(
            &fx.base.redis_coordination,
            &attome_portal::oidc::Pending {
                kind: attome_portal::oidc::PendingKind::Link,
                webportal_id: p.id,
                user_id: user,
                provider: "entra".into(),
                issuer: "https://idp.test".into(),
                subject: "subject-1".into(),
            },
        )
        .await
        .unwrap()
    };
    let link = |portal: &Portal, pending: Uuid, password: &str| {
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/oidc/link", portal.keyword),
            &[],
            Some(json!({"pending": pending, "password": password})),
        )
    };

    // Wrong password: refused, and the pending step is spent.
    let pending = stage().await;
    assert_eq!(
        send(&fx, link(&p, pending, "wrong-password-1")).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&fx, link(&p, pending, PASSWORD)).await.0,
        StatusCode::UNAUTHORIZED,
        "single use"
    );
    // Another portal can't use it.
    let pending = stage().await;
    assert_eq!(
        send(&fx, link(&other_portal, pending, PASSWORD)).await.0,
        StatusCode::UNAUTHORIZED
    );
    // With the account's password: linked and signed in.
    let pending = stage().await;
    let (status, cookies, text) = send(&fx, link(&p, pending, PASSWORD)).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(me(&fx, &p, &session_of(&cookies)).await, StatusCode::OK);
    let linked: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webportal_identity \
         WHERE webportal_id = $1 AND webportal_user_id = $2 AND subject = 'subject-1'",
    )
    .bind(p.id)
    .bind(user)
    .fetch_one(&fx.base.db)
    .await
    .unwrap();
    assert_eq!(linked, 1);
}

// ── Phase 13 step 4: T-34, T-35 (G-11, G-12, D-585) ─────────────────────────

/// A staff session holding `system.admin`, for the portal admin API.
async fn admin_session(fx: &Fx) -> String {
    let admin = seed_staff(&fx.base).await;
    let privilege: Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
        .fetch_one(&fx.base.db)
        .await
        .expect("system.admin is seeded by attome_security::seed");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(admin)
    .bind(privilege)
    .execute(&fx.base.db)
    .await
    .expect("grant system.admin");
    staff_session(&fx.base, admin).await
}

/// Every queued email job that mentions `email`.
async fn emails_to(fx: &Fx, email: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT job::text FROM apalis.jobs WHERE job::text LIKE $1")
        .bind(format!("%{email}%"))
        .fetch_all(&fx.base.db)
        .await
        .unwrap()
}

/// T-34 (G-12, D-585): every emailed portal link (the admin invitation, a
/// password reset, a signup verification) is built on a portal host, never
/// on the staff host or the staff frontend, and the emailed invitation link
/// works on the portal host.
#[tokio::test]
async fn t34_emailed_links_are_built_on_a_portal_host() {
    const STAFF_HOST: &str = "app.test";
    const PORTAL_HOST: &str = "portal.test";
    let fx = skip_if_no_db!(
        fixture_with(|c| {
            c.deployment.staff_hosts = vec![STAFF_HOST.into()];
            c.deployment.portal_hosts = vec![PORTAL_HOST.into()];
        })
        .await
    );
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    // `secure_cookies` is on in the test config, so links are https.
    let portal_base = format!("https://{PORTAL_HOST}/{}/", p.keyword);
    let staff_frontend = fx.base.config.frontend_url();
    let admin_cookie = format!("__Host-session_token={}", admin_session(&fx).await);

    // 1. Invitation, sent by a staff admin from the staff host.
    let invited = format!("{}@example.com", Uuid::now_v7().simple());
    let mut tx = fx.base.db.begin().await.unwrap();
    let user = provision::create_user(
        &mut tx,
        Uuid::now_v7(),
        p.id,
        NewPortalUser {
            name: "Invited".into(),
            email: Some(invited.clone()),
            username: None,
        },
    )
    .await
    .expect("create user");
    tx.commit().await.unwrap();
    let invite = on_host(
        portal_req(
            "POST",
            &format!("/api/v1/admin/webportals/{}/users/{}/invite", p.id, user.id),
            &[admin_cookie],
            None,
        ),
        STAFF_HOST,
    );
    let (status, _, text) = send(&fx, invite).await;
    assert!(status.is_success(), "admin invite: {status} {text}");
    let token = emailed_token(&fx, &invited, "accept-invitation")
        .await
        .expect("an invitation link was emailed");
    // The link works where it points: accept it on the portal host.
    let (status, _, text) = send(
        &fx,
        on_host(
            portal_req(
                "POST",
                &format!("/{}/api/v1/auth/invitation/accept", p.keyword),
                &[],
                Some(json!({"token": token, "password": PASSWORD})),
            ),
            PORTAL_HOST,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "accept on the portal host: {text}"
    );

    // 2. Password reset for the (now active) user, on the portal host.
    let (status, _, text) = send(
        &fx,
        on_host(
            portal_req(
                "POST",
                &format!("/{}/api/v1/auth/reset-request", p.keyword),
                &[],
                Some(json!({"email": invited})),
            ),
            PORTAL_HOST,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reset request: {text}");
    assert!(
        emailed_token(&fx, &invited, "reset-password")
            .await
            .is_some(),
        "a reset link was emailed"
    );

    // 3. Signup verification, on a self-service portal.
    let role = signup_role(&fx, &p).await;
    set_policy(
        &fx,
        &p,
        attome_portal::policy::AuthPolicy {
            signup_mode: attome_portal::policy::SignupMode::SelfService,
            signup_role_ref: Some(role),
            ..Default::default()
        },
    )
    .await;
    let signed_up = format!("{}@example.com", Uuid::now_v7().simple());
    let (status, _, text) = send(
        &fx,
        on_host(
            portal_req(
                "POST",
                &format!("/{}/api/v1/auth/signup", p.keyword),
                &[],
                Some(json!({"name": "New User", "email": signed_up, "password": PASSWORD})),
            ),
            PORTAL_HOST,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "signup: {text}");
    assert!(
        emailed_token(&fx, &signed_up, "verify-signup")
            .await
            .is_some(),
        "a verification link was emailed"
    );

    // Every link in every one of those emails is on the portal host.
    for (email, pages) in [
        (&invited, &["accept-invitation", "reset-password"][..]),
        (&signed_up, &["verify-signup"][..]),
    ] {
        let jobs = emails_to(&fx, email).await;
        for page in pages {
            let expected = format!("{portal_base}{page}?token=");
            assert!(
                jobs.iter().any(|j| j.contains(&expected)),
                "no {page} link on {portal_base} to {email}: {jobs:?}"
            );
        }
        for job in &jobs {
            assert!(!job.contains(STAFF_HOST), "a staff-host link: {job}");
            assert!(
                !job.contains(&staff_frontend),
                "a staff-frontend link ({staff_frontend}): {job}"
            );
        }
    }
}

/// The session list a portal session sees.
async fn sessions_of(fx: &Fx, p: &Portal, cookie: &str) -> Vec<Uuid> {
    let (status, _, text) = send(
        fx,
        portal_req(
            "GET",
            &format!("/{}/api/v1/me/sessions", p.keyword),
            &[cookie.to_owned()],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// T-35 (G-11): a portal user can neither read nor end another user's
/// sessions, in the same portal or in another portal: the list shows only
/// their own, ending someone else's session is the same 404 as an unknown
/// one, "end others" ends only their own, and the victim's sessions keep
/// working throughout.
#[tokio::test]
async fn t35_a_user_cannot_read_or_end_another_users_sessions() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let q = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (_, attacker_email) = active_user(&fx, &p).await;
    let (_, victim_email) = active_user(&fx, &p).await;
    let (_, far_email) = active_user(&fx, &q).await;
    let attacker = login(&fx, &p, &attacker_email, None).await;
    let victim = login(&fx, &p, &victim_email, None).await;
    let far = login(&fx, &q, &far_email, None).await;
    let cookie = format!("{}={}", names(&p).session, session_of(&attacker));
    let victim_family = family_of(&fx, &p, &session_of(&victim));
    let far_family = family_of(&fx, &q, &session_of(&far));
    let own_family = family_of(&fx, &p, &session_of(&attacker));

    // Reading: only the caller's own session is listed.
    assert_eq!(sessions_of(&fx, &p, &cookie).await, vec![own_family]);

    // Ending someone else's session, in this portal or another one, is the
    // same 404 as an unknown id, and changes nothing.
    let end = |family: Uuid| {
        portal_req(
            "DELETE",
            &format!("/{}/api/v1/me/sessions/{family}", p.keyword),
            std::slice::from_ref(&cookie),
            None,
        )
    };
    let (unknown_status, _, unknown_body) = send(&fx, end(Uuid::now_v7())).await;
    assert_eq!(unknown_status, StatusCode::NOT_FOUND);
    for family in [victim_family, far_family] {
        let (status, _, body) = send(&fx, end(family)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{family}");
        let strip = |b: &str| {
            let mut v: Value = serde_json::from_str(b).unwrap_or(Value::Null);
            if let Some(o) = v.as_object_mut() {
                o.remove("request_id");
                // Z14-T1: `instance` echoes the path the caller sent, so it
                // differs by the id asked for and discloses nothing.
                o.remove("instance");
            }
            v
        };
        assert_eq!(strip(&body), strip(&unknown_body), "indistinguishable");
    }

    // The attacker's session can't reach the other portal's session routes.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "GET",
            &format!("/{}/api/v1/me/sessions", q.keyword),
            &[format!("{}={}", names(&q).session, session_of(&attacker))],
            None,
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a portal-A token on portal B"
    );
    let (status, _, _) = send(
        &fx,
        portal_req(
            "DELETE",
            &format!("/{}/api/v1/me/sessions/{far_family}", q.keyword),
            &[format!("{}={}", names(&q).session, session_of(&attacker))],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // "End others" ends only the caller's own other sessions.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/me/sessions/end-others", p.keyword),
            std::slice::from_ref(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The victims are untouched: their access tokens and refresh families live.
    assert_eq!(me(&fx, &p, &session_of(&victim)).await, StatusCode::OK);
    assert_eq!(me(&fx, &q, &session_of(&far)).await, StatusCode::OK);
    let victim_cookie = format!("{}={}", names(&p).session, session_of(&victim));
    assert_eq!(
        sessions_of(&fx, &p, &victim_cookie).await,
        vec![victim_family]
    );
    assert_eq!(
        refresh(&fx, &p, &refresh_of(&victim)).await.0,
        StatusCode::OK
    );
    assert_eq!(refresh(&fx, &q, &refresh_of(&far)).await.0, StatusCode::OK);
}

// ── D-777: username login ─────────────────────────────────────────────────────

/// An active account with a username and no email, and a password.
async fn username_user(fx: &Fx, p: &Portal) -> (Uuid, String) {
    let username = format!("u{}", &Uuid::new_v4().simple().to_string()[..10]);
    let hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::validate(PASSWORD).unwrap())
            .await
            .unwrap();
    let mut tx = fx.base.db.begin().await.unwrap();
    let id = provision::create_verified_account(
        &mut tx,
        p.id,
        "Zezima",
        None,
        Some(&username),
        Some(&hash),
    )
    .await
    .unwrap()
    .expect("username account created");
    tx.commit().await.unwrap();
    (id, username)
}

async fn login_with(fx: &Fx, p: &Portal, body: Value) -> (StatusCode, Vec<String>, String) {
    send(
        fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(body),
        ),
    )
    .await
}

#[tokio::test]
async fn d777_a_web_user_signs_in_with_a_username_or_an_email() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;

    // A username-only account, in any case, through `login`.
    let (user, username) = username_user(&fx, &p).await;
    let (status, cookies, body) = login_with(
        &fx,
        &p,
        json!({"login": username.to_uppercase(), "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "username login: {body}");
    let session = cookie_value(&cookies, names(&p).session.as_str()).to_owned();
    let (status, _, me) = send(
        &fx,
        portal_req(
            "GET",
            &format!("/{}/api/v1/me", p.keyword),
            &[format!("{}={session}", names(&p).session)],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{me}");
    let me: Value = serde_json::from_str(&me).unwrap();
    assert_eq!(me["id"], user.to_string());
    assert_eq!(me["username"], username.as_str());
    assert!(me["email"].is_null(), "{me}");

    // Wrong password: the same refusal as an unknown name.
    let (wrong, _, _) = login_with(
        &fx,
        &p,
        json!({"login": username, "password": "not the password"}),
    )
    .await;
    let (unknown, _, _) = login_with(
        &fx,
        &p,
        json!({"login": format!("{username}x"), "password": PASSWORD}),
    )
    .await;
    assert_eq!(wrong, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown, StatusCode::UNAUTHORIZED);

    // An email account through `login`, and through the old `email` field.
    let (_, email) = active_user(&fx, &p).await;
    let (status, _, body) = login_with(
        &fx,
        &p,
        json!({"login": email.to_uppercase(), "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "email via login: {body}");
    let (status, _, body) =
        login_with(&fx, &p, json!({"email": email, "password": PASSWORD})).await;
    assert_eq!(status, StatusCode::OK, "email via the old field: {body}");

    // Neither field.
    let (status, _, _) = login_with(&fx, &p, json!({"password": PASSWORD})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // A username belongs to its portal.
    let other = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (status, _, _) = login_with(
        &fx,
        &other,
        json!({"login": username, "password": PASSWORD}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn d777_a_user_without_an_email_cannot_be_invited() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let mut tx = fx.base.db.begin().await.unwrap();
    let user = provision::create_user(
        &mut tx,
        Uuid::now_v7(),
        p.id,
        NewPortalUser {
            name: "No Mail".into(),
            email: None,
            username: Some(format!("u{}", &Uuid::new_v4().simple().to_string()[..10])),
        },
    )
    .await
    .expect("create user");
    let r =
        attome_portal::auth::issue_invitation(&mut tx, &fx.base.pepper_ring(), p.id, user.id).await;
    assert!(
        matches!(r, Err(attome_types::AppError::Validation(_))),
        "{:?}",
        r.map(|o| o.is_some())
    );
}

// ── D-779: trusted server login (S2S) ─────────────────────────────────────────

/// An S2S client (with a primary key) whose service user is a fresh staff
/// user, optionally granted `webportal.trusted_login`.
struct S2sKey {
    client_id: String,
    key_id: String,
    secret: String,
}

async fn trusted_client(fx: &Fx, admin_cookie: &str, privileged: bool) -> S2sKey {
    let service_user = seed_staff(&fx.base).await;
    let slug = format!("game-{}", Uuid::now_v7().simple());
    let (status, _, body) = send(
        fx,
        portal_req(
            "POST",
            "/api/v1/admin/s2s/clients",
            &[admin_cookie.to_owned()],
            Some(
                json!({"client_id": slug, "name": "Game login", "service_user_ref": service_user}),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create client: {body}");
    let client: Value = serde_json::from_str(&body).unwrap();
    let (status, _, body) = send(
        fx,
        portal_req(
            "POST",
            &format!(
                "/api/v1/admin/s2s/clients/{}/keys",
                client["id"].as_str().unwrap()
            ),
            &[admin_cookie.to_owned()],
            Some(json!({"slot": "primary"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create key: {body}");
    let key: Value = serde_json::from_str(&body).unwrap();
    if privileged {
        let (status, _, body) = send(
            fx,
            portal_req(
                "POST",
                "/api/v1/admin/security/grants",
                &[admin_cookie.to_owned()],
                Some(json!({
                    "user_email": format!("portal-auth-staff-{service_user}@example.test"),
                    "privilege_key": "webportal.trusted_login",
                })),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "grant: {body}");
    }
    S2sKey {
        client_id: slug,
        key_id: key["public_id"].as_str().unwrap().to_owned(),
        secret: key["secret"].as_str().unwrap().to_owned(),
    }
}

/// A trusted-login request signed as the S2S middleware checks it.
fn signed_login(key: &S2sKey, p: &Portal, body: Value) -> Request<Body> {
    let path = format!("/api/v1/s2s/webportals/{}/login", p.keyword);
    let raw = body.to_string();
    let ts = chrono::Utc::now().timestamp_millis().to_string();
    let nonce = Uuid::now_v7().simple().to_string();
    let message = attome_s2s::crypto::canonical_message(
        "POST",
        &path,
        &attome_s2s::crypto::sha256_hex(raw.as_bytes()),
        &ts,
        &nonce,
    );
    let signature = attome_s2s::crypto::sign_hmac(&key.secret, &message).expect("hex secret");
    let mut req = portal_req("POST", &path, &[], None);
    *req.body_mut() = Body::from(raw);
    let h = req.headers_mut();
    for (name, value) in [
        ("x-s2s-client-id", key.client_id.as_str()),
        ("x-s2s-key-id", key.key_id.as_str()),
        ("x-s2s-timestamp", ts.as_str()),
        ("x-s2s-nonce", nonce.as_str()),
        ("x-s2s-signature", signature.as_str()),
    ] {
        h.insert(name, value.parse().unwrap());
    }
    h.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    req
}

async fn set_trusted(fx: &Fx, p: &Portal, on: bool) {
    sqlx::query(
        "INSERT INTO webportal_auth_policy (webportal_id, trusted_server_login) VALUES ($1, $2) \
         ON CONFLICT (webportal_id) DO UPDATE SET trusted_server_login = EXCLUDED.trusted_server_login",
    )
    .bind(p.id)
    .bind(on)
    .execute(&fx.base.db)
    .await
    .unwrap();
}

async fn trusted(fx: &Fx, key: &S2sKey, p: &Portal, body: Value) -> (StatusCode, Value) {
    let (status, _, text) = send(fx, signed_login(key, p, body)).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

fn new_name() -> String {
    format!("p{}", &Uuid::new_v4().simple().to_string()[..10])
}

#[tokio::test]
async fn d779_a_trusted_server_creates_and_signs_in_players() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    set_trusted(&fx, &p, true).await;
    let admin_cookie = format!("__Host-session_token={}", admin_session(&fx).await);
    let key = trusted_client(&fx, &admin_cookie, true).await;
    let name = new_name();
    let body = |password: &str| json!({"login": name, "password": password, "client_ip": "203.0.113.7", "create_if_missing": true});

    let (status, created) = trusted(&fx, &key, &p, body(PASSWORD)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(created["outcome"], "created");
    assert_eq!(created["username"], name.as_str());
    assert_eq!(created["auth_epoch"], 0);
    let user = created["user_id"].as_str().unwrap().to_owned();

    let (_, again) = trusted(&fx, &key, &p, body(PASSWORD)).await;
    assert_eq!(again["outcome"], "ok");
    assert_eq!(again["user_id"], user.as_str());

    let (_, wrong) = trusted(&fx, &key, &p, body("not the password")).await;
    assert_eq!(wrong["outcome"], "bad_credentials");
    assert!(wrong["user_id"].is_null(), "no id on a refusal: {wrong}");

    // The account signs in on the portal's own web login too.
    let (status, _, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"login": name, "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");

    // Security events about the account (create, login, and the failure,
    // which names the account in the event though not in the reply), through
    // either write path: the synchronous header or the chainer's ingest queue.
    let events: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM audit_header WHERE record_id = $1) \
              + (SELECT count(*) FROM audit_ingest WHERE payload->>'record_id' = $1::text)",
    )
    .bind(Uuid::parse_str(&user).unwrap())
    .fetch_one(&fx.base.db)
    .await
    .unwrap();
    assert!(events >= 3, "security events about the account: {events}");
}

#[tokio::test]
async fn d779_only_a_privileged_s2s_client_on_an_opted_in_portal_may_call_it() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let admin_cookie = format!("__Host-session_token={}", admin_session(&fx).await);
    let key = trusted_client(&fx, &admin_cookie, true).await;
    let body = json!({"login": new_name(), "password": PASSWORD, "client_ip": "203.0.113.8", "create_if_missing": true});

    // The portal hasn't opted in.
    let (status, _) = trusted(&fx, &key, &p, body.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    set_trusted(&fx, &p, true).await;

    // An S2S client without the privilege.
    let unprivileged = trusted_client(&fx, &admin_cookie, false).await;
    let (status, _) = trusted(&fx, &unprivileged, &p, body.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A staff admin session (no S2S signature) passes the privilege check
    // but is refused.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/api/v1/s2s/webportals/{}/login", p.keyword),
            std::slice::from_ref(&admin_cookie),
            Some(body.clone()),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A bad client_ip is refused before anything happens.
    let mut bad = body.clone();
    bad["client_ip"] = json!("not-an-ip");
    let (status, _) = trusted(&fx, &key, &p, bad).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // The privileged client succeeds.
    let (status, ok) = trusted(&fx, &key, &p, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ok["outcome"], "created");
}

async fn changes(fx: &Fx, key: &S2sKey, p: &Portal, since: i64) -> Value {
    let path = format!(
        "/api/v1/s2s/webportals/{}/accounts/changes?since={since}",
        p.keyword
    );
    let ts = chrono::Utc::now().timestamp_millis().to_string();
    let nonce = Uuid::now_v7().simple().to_string();
    let message = attome_s2s::crypto::canonical_message(
        "GET",
        &path,
        &attome_s2s::crypto::sha256_hex(b""),
        &ts,
        &nonce,
    );
    let signature = attome_s2s::crypto::sign_hmac(&key.secret, &message).expect("hex secret");
    let mut req = portal_req("GET", &path, &[], None);
    let h = req.headers_mut();
    for (name, value) in [
        ("x-s2s-client-id", key.client_id.as_str()),
        ("x-s2s-key-id", key.key_id.as_str()),
        ("x-s2s-timestamp", ts.as_str()),
        ("x-s2s-nonce", nonce.as_str()),
        ("x-s2s-signature", signature.as_str()),
    ] {
        h.insert(name, value.parse().unwrap());
    }
    let (status, _, text) = send(fx, req).await;
    assert_eq!(status, StatusCode::OK, "changes: {text}");
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn d779_account_changes_report_disables_and_epoch_bumps() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    set_trusted(&fx, &p, true).await;
    let admin_cookie = format!("__Host-session_token={}", admin_session(&fx).await);
    let key = trusted_client(&fx, &admin_cookie, true).await;
    let name = new_name();
    let (_, created) = trusted(
        &fx,
        &key,
        &p,
        json!({"login": name, "password": PASSWORD, "client_ip": "203.0.113.9", "create_if_missing": true}),
    )
    .await;
    let user = Uuid::parse_str(created["user_id"].as_str().unwrap()).unwrap();

    let all = changes(&fx, &key, &p, 0).await;
    let row = all["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["user_id"] == user.to_string())
        .cloned()
        .expect("the new account");
    assert_eq!(row["status"], "active");
    assert_eq!(row["username"], name.as_str());
    let epoch = row["auth_epoch"].as_i64().unwrap();
    let since = row["changed_at"].as_i64().unwrap() - 1;

    // Disable it: status and epoch change, and it shows up after `since`.
    let mut tx = fx.base.db.begin().await.unwrap();
    provision::set_user_enabled(&mut tx, Uuid::now_v7(), p.id, user, false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let later = changes(&fx, &key, &p, since).await;
    let row = later["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["user_id"] == user.to_string())
        .cloned()
        .expect("the disabled account");
    assert_eq!(row["status"], "disabled");
    assert!(row["auth_epoch"].as_i64().unwrap() > epoch);

    // Nothing newer than the newest change.
    let next = later["next_since"].as_i64().unwrap();
    let none = changes(&fx, &key, &p, next).await;
    assert!(
        none["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["user_id"] != user.to_string()),
        "{none}"
    );
}

#[tokio::test]
async fn d779_failures_and_creations_are_limited_per_address() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    set_trusted(&fx, &p, true).await;
    let admin_cookie = format!("__Host-session_token={}", admin_session(&fx).await);
    let key = trusted_client(&fx, &admin_cookie, true).await;

    // Three creations per address per hour.
    for _ in 0..3 {
        let (_, r) = trusted(
            &fx,
            &key,
            &p,
            json!({"login": new_name(), "password": PASSWORD, "client_ip": "198.51.100.1", "create_if_missing": true}),
        )
        .await;
        assert_eq!(r["outcome"], "created", "{r}");
    }
    let (_, r) = trusted(
        &fx,
        &key,
        &p,
        json!({"login": new_name(), "password": PASSWORD, "client_ip": "198.51.100.1", "create_if_missing": true}),
    )
    .await;
    assert_eq!(r["outcome"], "rate_limited", "{r}");
    assert!(r["retry_after_secs"].as_i64().unwrap() > 0);
    // Another address still can.
    let (_, r) = trusted(
        &fx,
        &key,
        &p,
        json!({"login": new_name(), "password": PASSWORD, "client_ip": "198.51.100.2", "create_if_missing": true}),
    )
    .await;
    assert_eq!(r["outcome"], "created", "{r}");

    // Twenty failed logins per address per 10 minutes (unknown emails, so
    // no account delay gets in the way).
    for i in 0..20 {
        let (_, r) = trusted(
            &fx,
            &key,
            &p,
            json!({"login": format!("nobody{i}-{}@example.com", Uuid::now_v7().simple()), "password": PASSWORD, "client_ip": "198.51.100.3"}),
        )
        .await;
        assert_eq!(r["outcome"], "bad_credentials", "attempt {i}: {r}");
    }
    let (_, r) = trusted(
        &fx,
        &key,
        &p,
        json!({"login": "someone@example.com", "password": PASSWORD, "client_ip": "198.51.100.3"}),
    )
    .await;
    assert_eq!(r["outcome"], "rate_limited", "{r}");
}

// ── D-780: second factor and account self-service through a trusted server ──

/// Any S2S request, signed as the middleware checks it.
fn signed_s2s(key: &S2sKey, method: &str, path: &str, body: Option<Value>) -> Request<Body> {
    let raw = body.map(|b| b.to_string()).unwrap_or_default();
    let ts = chrono::Utc::now().timestamp_millis().to_string();
    let nonce = Uuid::now_v7().simple().to_string();
    let message = attome_s2s::crypto::canonical_message(
        method,
        path,
        &attome_s2s::crypto::sha256_hex(raw.as_bytes()),
        &ts,
        &nonce,
    );
    let signature = attome_s2s::crypto::sign_hmac(&key.secret, &message).expect("hex secret");
    let mut req = portal_req(method, path, &[], None);
    *req.body_mut() = Body::from(raw);
    let h = req.headers_mut();
    for (name, value) in [
        ("x-s2s-client-id", key.client_id.as_str()),
        ("x-s2s-key-id", key.key_id.as_str()),
        ("x-s2s-timestamp", ts.as_str()),
        ("x-s2s-nonce", nonce.as_str()),
        ("x-s2s-signature", signature.as_str()),
    ] {
        h.insert(name, value.parse().unwrap());
    }
    h.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    req
}

async fn account_call(
    fx: &Fx,
    key: &S2sKey,
    p: &Portal,
    user: &str,
    method: &str,
    rest: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let path = format!("/api/v1/s2s/webportals/{}/accounts/{user}{rest}", p.keyword);
    let (status, _, text) = send(fx, signed_s2s(key, method, &path, body)).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// A new player through trusted login: (key, user id, username).
async fn trusted_player(fx: &Fx, p: &Portal) -> (S2sKey, String, String) {
    set_trusted(fx, p, true).await;
    let admin_cookie = format!("__Host-session_token={}", admin_session(fx).await);
    let key = trusted_client(fx, &admin_cookie, true).await;
    let name = new_name();
    let (_, created) = trusted(
        fx,
        &key,
        p,
        json!({"login": name, "password": PASSWORD, "client_ip": "203.0.113.20", "create_if_missing": true}),
    )
    .await;
    assert_eq!(created["outcome"], "created", "{created}");
    (key, created["user_id"].as_str().unwrap().to_owned(), name)
}

fn now_secs() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap()
}

#[tokio::test]
async fn d780_mfa_is_turned_on_and_off_and_asked_for_at_sign_in() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (key, user, name) = trusted_player(&fx, &p).await;
    let ip = "203.0.113.21";

    let (status, info) = account_call(&fx, &key, &p, &user, "GET", "", None).await;
    assert_eq!(status, StatusCode::OK, "{info}");
    assert_eq!(info["mfa_enabled"], false);
    assert_eq!(info["username"], name.as_str());
    assert!(info["email"].is_null());

    // Enroll: the password again, then a code from the app.
    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/mfa/enroll",
        Some(json!({"password": "not it", "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "bad_credentials", "{r}");
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await; // the 1 s delay
    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/mfa/enroll",
        Some(json!({"password": PASSWORD, "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "ok", "{r}");
    let secret = r["secret"].as_str().unwrap().to_owned();
    assert!(
        r["otpauth_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
    let now = now_secs();
    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/mfa/confirm",
        Some(json!({"code": "000000", "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "wrong_code", "{r}");
    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/mfa/confirm",
        Some(
            json!({"code": attome_portal::mfa::code_at(&secret, now - 30).unwrap(), "client_ip": ip}),
        ),
    )
    .await;
    assert_eq!(r["outcome"], "ok", "{r}");
    let recovery: Vec<String> = r["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(recovery.len(), 10);
    let (_, info) = account_call(&fx, &key, &p, &user, "GET", "", None).await;
    assert_eq!(info["mfa_enabled"], true);
    assert_eq!(info["recovery_codes_left"], 10);

    let login = |code: Option<String>| {
        let mut b = json!({"login": name, "password": PASSWORD, "client_ip": ip});
        if let Some(c) = code {
            b["code"] = json!(c);
        }
        b
    };
    // No code: asked for one (not a failure: the password was right).
    let (_, r) = trusted(&fx, &key, &p, login(None)).await;
    assert_eq!(r["outcome"], "mfa_required", "{r}");
    // A wrong code: a failure like a wrong password.
    let (_, r) = trusted(&fx, &key, &p, login(Some("123456".into()))).await;
    assert_eq!(r["outcome"], "mfa_failed", "{r}");
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    // The current code signs in, once.
    let code = attome_portal::mfa::code_at(&secret, now).unwrap();
    let (_, r) = trusted(&fx, &key, &p, login(Some(code.clone()))).await;
    assert_eq!(r["outcome"], "ok", "{r}");
    assert!(r["recovery_code_used"].is_null());
    let (_, r) = trusted(&fx, &key, &p, login(Some(code))).await;
    assert_eq!(r["outcome"], "mfa_failed", "a replayed code: {r}");
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    // A recovery code works once.
    let (_, r) = trusted(&fx, &key, &p, login(Some(recovery[0].clone()))).await;
    assert_eq!(r["outcome"], "ok", "{r}");
    assert_eq!(r["recovery_code_used"], true);
    let (_, info) = account_call(&fx, &key, &p, &user, "GET", "", None).await;
    assert_eq!(info["recovery_codes_left"], 9);

    // Off: the password and a current code.
    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/mfa/disable",
        Some(json!({"password": PASSWORD, "code": "000000", "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "wrong_code", "{r}");
    let (_, r) = account_call(&fx, &key, &p, &user, "POST", "/mfa/disable",
        Some(json!({"password": PASSWORD, "code": attome_portal::mfa::code_at(&secret, now + 30).unwrap(), "client_ip": ip}))).await;
    assert_eq!(r["outcome"], "ok", "{r}");
    let (_, r) = trusted(&fx, &key, &p, login(None)).await;
    assert_eq!(r["outcome"], "ok", "no code needed any more: {r}");
}

#[tokio::test]
async fn d780_an_email_is_added_only_once_its_link_is_opened() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (key, user, name) = trusted_player(&fx, &p).await;
    let ip = "203.0.113.22";
    let email = format!("{name}@example.test");

    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/email",
        Some(json!({"password": PASSWORD, "email": "not an address", "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "invalid_email", "{r}");
    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/email",
        Some(json!({"password": "wrong!", "email": email, "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "bad_credentials", "{r}");
    assert!(emailed_token(&fx, &email, "verify-email").await.is_none());
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/email",
        Some(json!({"password": PASSWORD, "email": email.to_uppercase(), "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "sent", "{r}");
    let token = emailed_token(&fx, &email, "verify-email")
        .await
        .expect("a link was emailed");
    // Nothing on the account until the link is opened.
    let (_, info) = account_call(&fx, &key, &p, &user, "GET", "", None).await;
    assert!(info["email"].is_null(), "{info}");
    assert_eq!(
        info["pending_email"],
        format!("{}***@example.test", &name[..1])
    );

    let verify = |token: &str| {
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/email/verify", p.keyword),
            &[],
            Some(json!({"token": token})),
        )
    };
    let (status, _, text) = send(&fx, verify(&token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
    let (status, _, _) = send(&fx, verify(&token)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "single use");
    let (_, info) = account_call(&fx, &key, &p, &user, "GET", "", None).await;
    assert_eq!(info["email"], format!("{}***@example.test", &name[..1]));
    assert!(info["pending_email"].is_null());

    // The player now signs in with the email too, and can reset the password.
    let (_, r) = trusted(
        &fx,
        &key,
        &p,
        json!({"login": email, "password": PASSWORD, "client_ip": ip}),
    )
    .await;
    assert_eq!(r["outcome"], "ok", "{r}");
    assert_eq!(r["user_id"], user.as_str());
    let (status, _, text) = send(
        &fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/reset-request", p.keyword),
            &[],
            Some(json!({"email": email})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(emailed_token(&fx, &email, "reset-password").await.is_some());

    // Another player asking for the same address: the same answer, no link;
    // the owner gets a notice instead.
    let (key2, user2, _) = trusted_player(&fx, &p).await;
    let (_, r) = account_call(
        &fx,
        &key2,
        &p,
        &user2,
        "POST",
        "/email",
        Some(json!({"password": PASSWORD, "email": email, "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "sent", "{r}");
    let notices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM email_delivery \
         WHERE recipient = $1 AND subject LIKE '%someone tried to add this email'",
    )
    .bind(&email)
    .fetch_one(&fx.base.db)
    .await
    .unwrap();
    assert_eq!(notices, 1);
    let (_, info2) = account_call(&fx, &key2, &p, &user2, "GET", "", None).await;
    assert!(info2["pending_email"].is_null(), "{info2}");

    // The same address again: unchanged.
    let (_, r) = account_call(
        &fx,
        &key,
        &p,
        &user,
        "POST",
        "/email",
        Some(json!({"password": PASSWORD, "email": email, "client_ip": ip})),
    )
    .await;
    assert_eq!(r["outcome"], "unchanged", "{r}");
}

#[tokio::test]
async fn d780_account_routes_follow_the_trusted_login_caller_rules() {
    let fx = skip_if_no_db!(fixture().await);
    let p = portal(&fx, PortalType::Authenticated, MfaPolicy::Optional).await;
    let (key, user, _) = trusted_player(&fx, &p).await;
    // A client without the privilege.
    let admin_cookie = format!("__Host-session_token={}", admin_session(&fx).await);
    let plain = trusted_client(&fx, &admin_cookie, false).await;
    let (status, _) = account_call(&fx, &plain, &p, &user, "GET", "", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A staff session, even an admin's.
    let (status, _, _) = send(
        &fx,
        portal_req(
            "GET",
            &format!("/api/v1/s2s/webportals/{}/accounts/{user}", p.keyword),
            std::slice::from_ref(&admin_cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Trusted login turned off.
    set_trusted(&fx, &p, false).await;
    let (status, _) = account_call(&fx, &key, &p, &user, "GET", "", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    set_trusted(&fx, &p, true).await;
    // Another portal's account is not found.
    let (status, _) =
        account_call(&fx, &key, &p, &Uuid::now_v7().to_string(), "GET", "", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

//! Web portal Phase 3: the isolation suite (plan §5, T-1 to T-15), the gate
//! before Phase 4 or 5 (D-574, D-575, D-576, D-579), plus the Phase 13
//! security closure (plan §9.4, T-22 to T-25: lookup scope, write-bound
//! grants, drifted conditions, owning-team liveness).
//!
//! Every test builds a world of two portals, a case entity with a scope
//! field, a hidden field, a sensitive field, a file field and a lookup to
//! staff, and portal users on different roles, then drives the real routes
//! (`/{keyword}/api/v1/records/...`, the staff API, the admin API) through the
//! full middleware stack, with the portal router mounted exactly as `main.rs`
//! mounts it. Staff widening data (record shares, team shares, entity default
//! shares) is seeded so any widening arm that fired would leak.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"; $env:TEST_REDIS_HOST = "127.0.0.1"
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<migrated template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p server --test portal_isolation -- --test-threads=1
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
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_portal::provision::{self, NewPortalUser};
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
                "s3_region": "us-east-1", "s3_access_key": "{s3_access_key}", "s3_secret_key": "{s3_secret_key}",
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
        // Only the G-14 export test uploads; it skips without a real
        // credential (the ones `scripts/run-integration-tests.ps1` exports).
        s3_access_key = std::env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "test".into()),
        s3_secret_key = std::env::var("S3_SECRET_KEY").unwrap_or_else(|_| "test".into()),
    );
    let mut config: AppConfig =
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig");
    // T-6 sweeps ~1,100 staff routes from one test address; the IP-only
    // pre-auth limit would otherwise (correctly) throttle every later test.
    config.rate_limit.pre_auth_rpm = 100_000;
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
    xrm: EngineState,
    base: AppState,
    /// A staff administrator's session, for the admin API.
    admin_token: String,
}

async fn fixture() -> Option<Fx> {
    // Server-side errors behind a masked 500 (the staff admin API has
    // intermittently answered 500 while a world is built) are logged, so a
    // failing run says why instead of only "internal_error".
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .try_init();
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

    let admin_id = seed_staff(&base_state).await;
    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(&base_state.db)
            .await
            .expect("system.admin is seeded by attome_security::seed");
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) VALUES ($1, $2, $3, true, NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(admin_id)
    .bind(privilege_id)
    .execute(&base_state.db)
    .await
    .expect("grant system.admin");
    let admin_token = staff_session(&base_state, admin_id).await;
    Some(Fx {
        app,
        xrm,
        base: base_state,
        admin_token,
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

/// An admin request; returns status and body text.
async fn admin_status(
    fx: &Fx,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, String) {
    let cookie = format!("__Host-session_token={}", fx.admin_token);
    let (status, _, text) = send(fx, portal_req(method, uri, &[cookie], body)).await;
    (status, text)
}

/// An admin request that must succeed; returns its JSON body.
async fn admin(fx: &Fx, method: &str, uri: &str, body: Option<Value>) -> Value {
    let (status, text) = admin_status(fx, method, uri, body).await;
    assert!(status.is_success(), "{method} {uri}: {status} {text}");
    serde_json::from_str(&text).unwrap_or(Value::Null)
}

fn id_of(v: &Value) -> Uuid {
    v["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(|| panic!("response has no id: {v}"))
}

// ── The world every test runs in ──────────────────────────────────────────────

/// Two portals (A, B), a staff team that owns portal-created records, a case
/// entity and a company entity, roles, and portal users:
///
/// - `a1`, `a2`: portal A, role "mine" (`portal_user_ref = @portal_user.id`),
///   which can also read its own company (`id = @portal_user.company_ref`).
/// - `a3`: portal A, role "company" (`company_ref = @portal_user.company_ref`),
///   company set to `acme`.
/// - `a4`: portal A, role "company", **no** company (null `value_ref`).
/// - `b1`: portal B, role "mine".
struct World {
    fx: Fx,
    a: Portal,
    b: Portal,
    team: Uuid,
    case: String,
    company: String,
    acme: Uuid,
    role_mine_a: Uuid,
    role_company_a: Uuid,
    a1: Session,
    a2: Session,
    a3: Session,
    a4: Session,
    b1: Session,
}

struct Portal {
    id: Uuid,
    keyword: String,
}

struct Session {
    user: Uuid,
    email: String,
    cookie: String,
}

fn short() -> String {
    Uuid::now_v7().simple().to_string()[20..].to_owned()
}

async fn entity_id(fx: &Fx, logicalname: &str) -> Uuid {
    sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
        .bind(logicalname)
        .fetch_one(&fx.base.db)
        .await
        .unwrap_or_else(|e| panic!("{logicalname} registered: {e}"))
}

async fn add_field(fx: &Fx, entity: Uuid, body: Value) {
    admin(
        fx,
        "POST",
        &format!("/api/v1/admin/entities/{entity}/fields"),
        Some(body),
    )
    .await;
}

async fn add_field_once(fx: &Fx, entity: Uuid, body: Value) {
    let (status, text) = admin_status(
        fx,
        "POST",
        &format!("/api/v1/admin/entities/{entity}/fields"),
        Some(body),
    )
    .await;
    assert!(
        status.is_success() || status == StatusCode::CONFLICT,
        "{status} {text}"
    );
}

async fn portal_user(fx: &Fx, p: &Portal, role: Uuid, company: Option<Uuid>) -> Session {
    let email = format!("{}@example.com", Uuid::now_v7().simple());
    let mut tx = fx.base.db.begin().await.unwrap();
    let user = provision::create_user(
        &mut tx,
        Uuid::now_v7(),
        p.id,
        NewPortalUser {
            name: format!("user-{}", short()),
            email: Some(email.clone()),
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
    let portal = attome_portal::auth::resolve_portal_with_users(&mut tx, &p.keyword)
        .await
        .unwrap()
        .unwrap();
    let hash =
        attome_auth::hash_password_async(attome_auth::NewPassword::platform_generated(PASSWORD))
            .await
            .unwrap();
    attome_portal::auth::accept_invitation(
        &mut tx,
        &fx.base.pepper_ring(),
        &portal,
        &invitation.bearer,
        &hash,
    )
    .await
    .unwrap()
    .unwrap();
    if let Some(company) = company {
        sqlx::query("UPDATE webportal_user SET company_ref = $2 WHERE id = $1")
            .bind(user.id)
            .bind(company)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    admin(
        fx,
        "PUT",
        &format!("/api/v1/admin/webportals/{}/users/{}/role", p.id, user.id),
        Some(json!({"role_id": role})),
    )
    .await;

    let (status, cookies, body) = send(
        fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", p.keyword),
            &[],
            Some(json!({"email": email, "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login: {body}");
    let session = cookies
        .into_iter()
        .find(|c| c.contains("_session="))
        .expect("session cookie");
    Session {
        user: user.id,
        email,
        cookie: session,
    }
}

/// Builds a world with no other world being built in this process.
///
/// Phase 13 step 3 (the "fixture 500"): building one runs runtime DDL twice —
/// `EngineSystem::build` re-applies platform bundles, then the admin API
/// provisions the entities and fields below. Two builds racing in one
/// database fail inside that DDL: `GRANT SELECT … TO attome_readonly` on the
/// same table answers `tuple concurrently updated`, index builds hit the
/// statement timeout, bundle plans see `basis changed since plan`, and the
/// staff admin API masks any of those as a 500. Measured 2026-09-28: three
/// `--test-threads=1` runs 27/27; one run with libtest's default parallelism
/// 2/27, all 25 failures in that DDL. Each binary already gets its own
/// database clone (`attome_testkit::test_db_url`), so serializing the builds
/// inside the process removes the race even when `--test-threads=1` is
/// forgotten.
async fn world() -> Option<World> {
    static BUILDING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _one_at_a_time = BUILDING.lock().await;
    build_world().await
}

async fn build_world() -> Option<World> {
    let fx = fixture().await?;
    let team = Uuid::now_v7();
    sqlx::query("INSERT INTO team (id, name) VALUES ($1, $2)")
        .bind(team)
        .bind(format!("portal-iso-team-{team}"))
        .execute(&fx.base.db)
        .await
        .unwrap();

    let s = short();
    let company = format!("pic_{s}");
    let case = format!("pie_{s}");
    let company_id = id_of(
        &admin(
            &fx,
            "POST",
            "/api/v1/admin/entities",
            Some(json!({"logicalname": company, "name": "Company"})),
        )
        .await,
    );
    add_field(
        &fx,
        company_id,
        json!({"logicalname": "name", "name": "Name", "field_type": "text"}),
    )
    .await;
    let case_id = id_of(
        &admin(
            &fx,
            "POST",
            "/api/v1/admin/entities",
            Some(json!({"logicalname": case, "name": "Case"})),
        )
        .await,
    );
    let systemuser = entity_id(&fx, "user_account").await;
    let portal_user_entity = entity_id(&fx, "webportal_user").await;
    for body in [
        json!({"logicalname": "title", "name": "Title", "field_type": "text", "is_filterable": true, "is_sortable": true}),
        json!({"logicalname": "internal_note", "name": "Internal note", "field_type": "text", "is_filterable": true}),
        json!({"logicalname": "secret", "name": "Secret", "field_type": "text", "is_sensitive": true}),
        json!({"logicalname": "attachment", "name": "Attachment", "field_type": "file"}),
        json!({"logicalname": "staff_ref", "name": "Staff", "field_type": "lookup", "lookup_entity_ref": systemuser}),
        json!({"logicalname": "portal_user_ref", "name": "Portal user", "field_type": "lookup", "lookup_entity_ref": portal_user_entity, "is_filterable": true}),
        json!({"logicalname": "company_ref", "name": "Company", "field_type": "lookup", "lookup_entity_ref": company_id, "is_filterable": true}),
    ] {
        add_field(&fx, case_id, body).await;
    }
    // An admin-added custom field on the portal user (D-576 item 1). The
    // entity is shared by every test in this binary, so the second world
    // finds it already there.
    add_field_once(
        &fx,
        portal_user_entity,
        json!({"logicalname": "company_ref", "name": "Company", "field_type": "lookup", "lookup_entity_ref": company_id, "is_filterable": true}),
    )
    .await;
    let registry = attome_core::build_registry(&fx.base.db).await.unwrap();
    fx.xrm.entities.swap(registry);

    let acme = id_of(
        &admin(
            &fx,
            "POST",
            &format!("/api/v1/{company}"),
            Some(json!({"name": "Acme"})),
        )
        .await,
    );

    let mut portals = Vec::new();
    for label in ["a", "b"] {
        let p = admin(
            &fx,
            "POST",
            "/api/v1/admin/webportals",
            Some(json!({
                "name": format!("Portal {label}"),
                "keyword": format!("pi{label}-{}", short()),
                "portal_type": "authenticated",
                "is_enabled": true,
                "owning_team_ref": team,
            })),
        )
        .await;
        let portal = Portal {
            id: id_of(&p),
            keyword: p["keyword"].as_str().unwrap().to_owned(),
        };
        admin(
            &fx,
            "PUT",
            &format!("/api/v1/admin/webportals/{}/entities/{case}", portal.id),
            Some(json!({"portal_user_field": "portal_user_ref"})),
        )
        .await;
        portals.push(portal);
    }
    let b = portals.pop().unwrap();
    let a = portals.pop().unwrap();

    let role = |p: &Portal, name: &str| {
        let fx = &fx;
        let url = format!("/api/v1/admin/webportals/{}/roles", p.id);
        let name = name.to_owned();
        async move { id_of(&admin(fx, "POST", &url, Some(json!({"name": name}))).await) }
    };
    let mine_grant = json!({
        "can_read": true, "can_create": true, "can_update": true, "can_delete": true,
        "conditions": [{"field": "portal_user_ref", "operator": "eq", "value_ref": "@portal_user.id"}],
        "fields": [
            {"field": "title", "can_read": true, "can_write": true, "can_filter": true},
            {"field": "company_ref", "can_read": true, "can_write": true},
            {"field": "portal_user_ref", "can_read": true},
        ],
    });
    let role_mine_a = role(&a, "mine").await;
    let role_company_a = role(&a, "company").await;
    let role_mine_b = role(&b, "mine").await;
    // The case's `company_ref` lookup is readable and writable, so the role
    // must be able to read the company it points at (I-8).
    let own_company_grant = json!({
        "can_read": true,
        "conditions": [{"field": "id", "operator": "eq", "value_ref": "@portal_user.company_ref"}],
        "fields": [{"field": "name", "can_read": true}],
    });
    for (p, r) in [(&a, role_mine_a), (&b, role_mine_b)] {
        admin(
            &fx,
            "PUT",
            &format!(
                "/api/v1/admin/webportals/{}/roles/{r}/grants/{company}",
                p.id
            ),
            Some(own_company_grant.clone()),
        )
        .await;
    }
    for (p, r) in [(&a, role_mine_a), (&b, role_mine_b)] {
        admin(
            &fx,
            "PUT",
            &format!("/api/v1/admin/webportals/{}/roles/{r}/grants/{case}", p.id),
            Some(mine_grant.clone()),
        )
        .await;
    }
    admin(
        &fx,
        "PUT",
        &format!("/api/v1/admin/webportals/{}/roles/{role_company_a}/grants/{case}", a.id),
        Some(json!({
            "can_read": true,
            "conditions": [{"field": "company_ref", "operator": "eq", "value_ref": "@portal_user.company_ref"}],
            "fields": [{"field": "title", "can_read": true, "can_filter": true}],
        })),
    )
    .await;

    let a1 = portal_user(&fx, &a, role_mine_a, Some(acme)).await;
    let a2 = portal_user(&fx, &a, role_mine_a, Some(acme)).await;
    let a3 = portal_user(&fx, &a, role_company_a, Some(acme)).await;
    let a4 = portal_user(&fx, &a, role_company_a, None).await;
    let b1 = portal_user(&fx, &b, role_mine_b, Some(acme)).await;
    Some(World {
        fx,
        a,
        b,
        team,
        case,
        company,
        acme,
        role_mine_a,
        role_company_a,
        a1,
        a2,
        a3,
        a4,
        b1,
    })
}

fn records(p: &Portal, entity: &str) -> String {
    format!("/{}/api/v1/records/{entity}", p.keyword)
}

async fn as_user(
    w: &World,
    who: &Session,
    method: &str,
    uri: &str,
    body: Option<Value>,
    if_match: Option<i64>,
) -> (StatusCode, Value) {
    let mut req = portal_req(method, uri, std::slice::from_ref(&who.cookie), body);
    if let Some(v) = if_match {
        req.headers_mut()
            .insert(header::IF_MATCH, v.to_string().parse().unwrap());
    }
    let (status, _, text) = send(&w.fx, req).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn create_case(w: &World, who: &Session, p: &Portal, title: &str) -> Value {
    let (status, body) = as_user(
        w,
        who,
        "POST",
        &records(p, &w.case),
        Some(json!({"title": title, "company_ref": w.acme})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {body}");
    body
}

fn titles(list: &Value) -> Vec<String> {
    let mut t: Vec<String> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["data"]["title"].as_str().unwrap_or_default().to_owned())
        .collect();
    t.sort();
    t
}

fn without_request_id(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.remove("request_id");
    }
    v
}

// ── T-1 … T-15 ────────────────────────────────────────────────────────────────

/// T-1: a portal user never sees another portal user's records in the same
/// portal, through any read path.
#[tokio::test]
async fn t01_same_portal_users_are_isolated() {
    let w = skip_if_no_db!(world().await);
    let mine = create_case(&w, &w.a1, &w.a, "a1-only").await;
    create_case(&w, &w.a2, &w.a, "a2-only").await;
    let id = mine["id"].as_str().unwrap();
    let rv = mine["row_version"].as_i64().unwrap();

    let (_, list) = as_user(&w, &w.a2, "GET", &records(&w.a, &w.case), None, None).await;
    assert_eq!(titles(&list), vec!["a2-only"]);
    assert_eq!(list["total"], 1, "count must not include other users' rows");
    for q in [
        "?title=a1-only",
        "?order_by=title&order=desc",
        "?page=1&page_size=100",
    ] {
        let (_, l) = as_user(
            &w,
            &w.a2,
            "GET",
            &format!("{}{q}", records(&w.a, &w.case)),
            None,
            None,
        )
        .await;
        assert!(!titles(&l).contains(&"a1-only".to_owned()), "{q}: {l}");
    }
    let one = format!("{}/{id}", records(&w.a, &w.case));
    assert_eq!(
        as_user(&w, &w.a2, "GET", &one, None, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        as_user(
            &w,
            &w.a2,
            "PATCH",
            &one,
            Some(json!({"title": "x"})),
            Some(rv)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // G-5: a delete carries `If-Match` (without it, a uniform 422, T-27).
    assert_eq!(
        as_user(&w, &w.a2, "DELETE", &one, None, Some(rv)).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        as_user(&w, &w.a1, "GET", &one, None, None).await.0,
        StatusCode::OK
    );
}

/// T-2: portal B never sees portal A's records, even with the same grant
/// shape on the same entity.
#[tokio::test]
async fn t02_portals_are_isolated() {
    let w = skip_if_no_db!(world().await);
    let a_case = create_case(&w, &w.a1, &w.a, "in-portal-a").await;
    create_case(&w, &w.b1, &w.b, "in-portal-b").await;
    let (_, list) = as_user(&w, &w.b1, "GET", &records(&w.b, &w.case), None, None).await;
    assert_eq!(titles(&list), vec!["in-portal-b"]);
    let id = a_case["id"].as_str().unwrap();
    assert_eq!(
        as_user(
            &w,
            &w.b1,
            "GET",
            &format!("{}/{id}", records(&w.b, &w.case)),
            None,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // B's session on A's routes: no session at all there.
    assert_eq!(
        as_user(&w, &w.b1, "GET", &records(&w.a, &w.case), None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

/// T-3: staff sharing (record shares, team shares, entity default shares)
/// never widens portal visibility; an unconditioned grant is refused.
#[tokio::test]
async fn t03_staff_sharing_never_widens_portal_scope() {
    let w = skip_if_no_db!(world().await);
    create_case(&w, &w.a1, &w.a, "mine").await;
    // A staff-created record, shared to the portal's own owning team and
    // default-shared to everyone: rows that WOULD leak if any widening arm fired.
    let staff_case = admin(
        &w.fx,
        "POST",
        &format!("/api/v1/{}", w.case),
        Some(json!({"title": "staff-only"})),
    )
    .await;
    let staff_id = id_of(&staff_case);
    let entity_ref = entity_id(&w.fx, &w.case).await;
    sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 1, $3, 1)",
    )
    .bind(staff_id)
    .bind(entity_ref)
    .bind(w.team)
    .execute(&w.fx.base.db)
    .await
    .unwrap();
    let _ = sqlx::query(
        "INSERT INTO entity_default_share (entity_ref, principal_type, principal_id, capability, owner_layer) \
         VALUES ($1, 1, $2, 1, 'project')",
    )
    .bind(entity_ref)
    .bind(w.team)
    .execute(&w.fx.base.db)
    .await;

    for who in [&w.a1, &w.a2] {
        let (_, list) = as_user(&w, who, "GET", &records(&w.a, &w.case), None, None).await;
        assert!(!titles(&list).contains(&"staff-only".to_owned()), "{list}");
    }
    assert_eq!(
        as_user(
            &w,
            &w.a1,
            "GET",
            &format!("{}/{staff_id}", records(&w.a, &w.case)),
            None,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    // No unconditioned grant.
    let (status, text) = admin_status(
        &w.fx,
        "PUT",
        &format!("/api/v1/admin/webportals/{}/roles/{}/grants/{}", w.a.id, w.role_mine_a, w.case),
        Some(json!({"can_read": true, "conditions": [], "fields": [{"field": "title", "can_read": true}]})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
}

/// T-4: a field outside the profile does not exist for the portal user:
/// never returned, never writable, never filterable or sortable.
#[tokio::test]
async fn t04_fields_outside_the_profile_do_not_exist() {
    let w = skip_if_no_db!(world().await);
    let created = create_case(&w, &w.a1, &w.a, "fields").await;
    let id = created["id"].as_str().unwrap();
    sqlx::query(&format!(
        "UPDATE \"{}\" SET internal_note = 'staff eyes only', secret = 'top secret' WHERE id = $1",
        w.case
    ))
    .bind(Uuid::parse_str(id).unwrap())
    .execute(&w.fx.base.db)
    .await
    .unwrap();

    let (_, one) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{}/{id}", records(&w.a, &w.case)),
        None,
        None,
    )
    .await;
    let mut keys: Vec<&str> = one["data"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["company_ref", "portal_user_ref", "title"],
        "{one}"
    );
    let text = one.to_string();
    assert!(!text.contains("staff eyes only") && !text.contains("top secret"));

    let (status, _) = as_user(
        &w,
        &w.a1,
        "POST",
        &records(&w.a, &w.case),
        Some(json!({"title": "x", "internal_note": "n"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "write a hidden field");
    let rv = one["row_version"].as_i64().unwrap();
    let (status, _) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &format!("{}/{id}", records(&w.a, &w.case)),
        Some(json!({"secret": "x"})),
        Some(rv),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "write a sensitive hidden field"
    );
    for q in [
        "?internal_note=staff%20eyes%20only",
        "?secret=top%20secret",
        "?order_by=internal_note",
        "?order_by=secret",
    ] {
        let (status, body) = as_user(
            &w,
            &w.a1,
            "GET",
            &format!("{}{q}", records(&w.a, &w.case)),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{q}: {body}");
    }
    // The same message for a hidden field and one that does not exist.
    let (_, hidden) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{}?internal_note=x", records(&w.a, &w.case)),
        None,
        None,
    )
    .await;
    let (_, missing) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{}?no_such_field=x", records(&w.a, &w.case)),
        None,
        None,
    )
    .await;
    assert_eq!(
        hidden["message"]
            .as_str()
            .unwrap()
            .replace("internal_note", "F"),
        missing["message"]
            .as_str()
            .unwrap()
            .replace("no_such_field", "F")
    );
}

/// T-5: a portal user never learns a staff user's id or name.
#[tokio::test]
async fn t05_no_staff_identity_reaches_the_portal() {
    let w = skip_if_no_db!(world().await);
    let created = create_case(&w, &w.a1, &w.a, "who").await;
    let text = created.to_string();
    for forbidden in [
        "created_by",
        "modified_by",
        "owner_ref",
        "owner_type",
        "organization_ref",
        "staff_ref",
    ] {
        assert!(!text.contains(forbidden), "{forbidden} in {text}");
    }
    // A lookup to staff can never be allowlisted.
    let (status, body) = admin_status(
        &w.fx,
        "PUT",
        &format!("/api/v1/admin/webportals/{}/roles/{}/grants/{}", w.a.id, w.role_mine_a, w.case),
        Some(json!({
            "can_read": true,
            "conditions": [{"field": "portal_user_ref", "operator": "eq", "value_ref": "@portal_user.id"}],
            "fields": [{"field": "staff_ref", "can_read": true}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    // Nor can a staff or portal-identity entity be granted at all.
    for entity in [
        "user_account",
        "team",
        "webportal_user",
        "webportal_credential",
    ] {
        let (status, _) = admin_status(
            &w.fx,
            "PUT",
            &format!(
                "/api/v1/admin/webportals/{}/roles/{}/grants/{entity}",
                w.a.id, w.role_mine_a
            ),
            Some(json!({
                "can_read": true,
                "conditions": [{"field": "id", "operator": "eq", "value_ref": "@portal_user.id"}],
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{entity}");
    }
}

/// T-6: a portal session reaches no staff route. Generated from
/// `openapi.json`, so every new staff route joins the sweep automatically.
#[tokio::test]
async fn t06_no_staff_route_accepts_a_portal_session() {
    let w = skip_if_no_db!(world().await);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../openapi.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let token = w.a1.cookie.split_once('=').unwrap().1.to_owned();
    let bypass = |p: &str| {
        // The public routes the middleware itself bypasses, the
        // segment-shaped ones (the payment page, webhooks) included.
        attome_server::middleware::bypass::is_bypass(p)
            || attome_server::middleware::bypass::EXACT_BYPASS_PATHS.contains(&p)
            || attome_server::middleware::bypass::BYPASS_SUBTREE_PREFIXES
                .iter()
                .any(|prefix| p.starts_with(prefix))
            || p.contains("/webhook")
            || p.starts_with("/health")
            || p == "/version"
    };
    let mut failures = Vec::new();
    let mut checked = 0;
    for (route, item) in doc["paths"].as_object().unwrap() {
        if route.starts_with("/{keyword}") {
            continue;
        }
        for method in item.as_object().unwrap().keys() {
            let concrete: String = route
                .split('/')
                .map(|seg| {
                    if seg.starts_with('{') {
                        Uuid::nil().to_string()
                    } else {
                        seg.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("/");
            if bypass(&concrete) || bypass(route) {
                continue;
            }
            for cookie in [format!("__Host-session_token={token}"), w.a1.cookie.clone()] {
                let body = (method != "get" && method != "delete").then(|| json!({}));
                let (status, _, _) = send(
                    &w.fx,
                    portal_req(&method.to_uppercase(), &concrete, &[cookie], body),
                )
                .await;
                checked += 1;
                if status != StatusCode::UNAUTHORIZED {
                    failures.push(format!("{} {route}: {status}", method.to_uppercase()));
                }
            }
        }
    }
    assert!(
        checked > 500,
        "the sweep must cover the staff API ({checked})"
    );
    assert!(
        failures.is_empty(),
        "staff routes answered a portal session:\n{}",
        failures.join("\n")
    );
}

/// T-7: "not in scope" and "does not exist" are indistinguishable.
#[tokio::test]
async fn t07_out_of_scope_and_missing_look_the_same() {
    let w = skip_if_no_db!(world().await);
    let other = create_case(&w, &w.a1, &w.a, "other").await;
    let other_id = other["id"].as_str().unwrap();
    let missing_id = Uuid::now_v7();
    for (method, body, if_match) in [
        ("GET", None, None),
        ("PATCH", Some(json!({"title": "x"})), Some(1)),
        // G-5: a delete needs `If-Match` (without it, a uniform 422 for
        // any id, T-27), so the scope check is reached only with one.
        ("DELETE", None, Some(1)),
    ] {
        let a = as_user(
            &w,
            &w.a2,
            method,
            &format!("{}/{other_id}", records(&w.a, &w.case)),
            body.clone(),
            if_match,
        )
        .await;
        let b = as_user(
            &w,
            &w.a2,
            method,
            &format!("{}/{missing_id}", records(&w.a, &w.case)),
            body,
            if_match,
        )
        .await;
        assert_eq!(a.0, StatusCode::NOT_FOUND, "{method}");
        assert_eq!(a.0, b.0, "{method}");
        assert_eq!(without_request_id(a.1), without_request_id(b.1), "{method}");
    }
    // No grant on an entity is the same 404 as an unknown entity (role
    // "company" has no grant on the company entity).
    let a = as_user(&w, &w.a3, "GET", &records(&w.a, &w.company), None, None).await;
    let b = as_user(
        &w,
        &w.a3,
        "GET",
        &records(&w.a, "no_such_entity"),
        None,
        None,
    )
    .await;
    assert_eq!(a.0, StatusCode::NOT_FOUND);
    assert_eq!(without_request_id(a.1), without_request_id(b.1));
}

/// T-8: access follows the user's role and state immediately: a role change
/// or a removed grant applies on the next request, and a disabled user is out.
#[tokio::test]
async fn t08_role_changes_and_revocation_apply_at_once() {
    let w = skip_if_no_db!(world().await);
    create_case(&w, &w.a1, &w.a, "before").await;
    admin(
        &w.fx,
        "PUT",
        &format!(
            "/api/v1/admin/webportals/{}/users/{}/role",
            w.a.id, w.a1.user
        ),
        Some(json!({"role_id": w.role_company_a})),
    )
    .await;
    let (_, list) = as_user(&w, &w.a1, "GET", &records(&w.a, &w.case), None, None).await;
    // Company scope now, not "mine": a1's own case is also acme's, so it shows,
    // but a1 can no longer create.
    assert_eq!(
        as_user(
            &w,
            &w.a1,
            "POST",
            &records(&w.a, &w.case),
            Some(json!({"title": "no"})),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "{list}"
    );
    let (status, _) = admin_status(
        &w.fx,
        "DELETE",
        &format!(
            "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
            w.a.id, w.role_company_a, w.case
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        as_user(&w, &w.a1, "GET", &records(&w.a, &w.case), None, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let mut tx = w.fx.base.db.begin().await.unwrap();
    provision::set_user_enabled(&mut tx, Uuid::now_v7(), w.a.id, w.a2.user, false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        as_user(&w, &w.a2, "GET", &records(&w.a, &w.case), None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

/// T-9: no escalation through the stamp field, through scope-moving writes,
/// or through staff-only operations (bulk, merge, import, share, assign).
#[tokio::test]
async fn t09_no_escalation_through_writes() {
    let w = skip_if_no_db!(world().await);
    // The portal user field is the engine's stamp, never the client's.
    let (status, _) = as_user(
        &w,
        &w.a1,
        "POST",
        &records(&w.a, &w.case),
        Some(json!({"title": "spoof", "portal_user_ref": w.a2.user})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let created = create_case(&w, &w.a1, &w.a, "stamped").await;
    assert_eq!(
        created["data"]["portal_user_ref"],
        json!(w.a1.user.to_string())
    );
    let (status, _) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &format!(
            "{}/{}",
            records(&w.a, &w.case),
            created["id"].as_str().unwrap()
        ),
        Some(json!({"portal_user_ref": w.a2.user})),
        Some(created["row_version"].as_i64().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "re-stamp to another user");
    // There is no portal route for bulk, merge, import, share or assign; the
    // staff routes for them refuse a portal session (T-6 covers every one).
    for (method, path) in [
        ("POST", format!("/api/v1/{}/bulk", w.case)),
        ("POST", format!("/api/v1/{}/{}/merge", w.case, Uuid::nil())),
        ("POST", format!("/api/v1/{}/staged-import", w.case)),
        (
            "POST",
            format!("/{}/api/v1/records/{}/bulk", w.a.keyword, w.case),
        ),
        (
            "POST",
            format!(
                "/{}/api/v1/records/{}/{}/merge",
                w.a.keyword,
                w.case,
                Uuid::nil()
            ),
        ),
    ] {
        let (status, _) = as_user(&w, &w.a1, method, &path, Some(json!({})), None).await;
        assert!(
            matches!(
                status,
                StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{method} {path}: {status}"
        );
    }
}

/// T-10: a `value_ref` that resolves to nothing matches nothing.
#[tokio::test]
async fn t10_null_value_ref_matches_nothing() {
    let w = skip_if_no_db!(world().await);
    create_case(&w, &w.a1, &w.a, "acme-case").await;
    let (_, with_company) = as_user(&w, &w.a3, "GET", &records(&w.a, &w.case), None, None).await;
    assert!(
        titles(&with_company).contains(&"acme-case".to_owned()),
        "company scope works: {with_company}"
    );
    let (status, without) = as_user(&w, &w.a4, "GET", &records(&w.a, &w.case), None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        without["total"], 0,
        "a null company must see nothing: {without}"
    );
    // An invalid value_ref is refused at write time.
    let (status, _) = admin_status(
        &w.fx,
        "PUT",
        &format!("/api/v1/admin/webportals/{}/roles/{}/grants/{}", w.a.id, w.role_company_a, w.case),
        Some(json!({"can_read": true, "conditions": [{"field": "company_ref", "operator": "eq", "value_ref": "@portal_user.password_hash"}]})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

/// T-11: a portal-created record is owned by the portal's staff team, with
/// that team's share, and staff can see it through the ordinary API.
#[tokio::test]
async fn t11_portal_created_records_are_owned_by_the_team() {
    let w = skip_if_no_db!(world().await);
    let created = create_case(&w, &w.a1, &w.a, "owned").await;
    let id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    let (owner_ref, owner_type): (Option<Uuid>, i16) = sqlx::query_as(&format!(
        "SELECT owner_ref, owner_type FROM \"{}\" WHERE id = $1",
        w.case
    ))
    .bind(id)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!((owner_ref, owner_type), (Some(w.team), 1));
    let shares: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM record_share WHERE record_id = $1 AND principal_type = 1 AND principal_id = $2",
    )
    .bind(id)
    .bind(w.team)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(shares, 1);
    let user_shares: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM record_share WHERE record_id = $1 AND principal_type = 0",
    )
    .bind(id)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(user_shares, 0, "a portal user is never a share principal");
    let staff_view = admin(&w.fx, "GET", &format!("/api/v1/{}/{id}", w.case), None).await;
    assert_eq!(staff_view["data"]["title"], "owned");
}

/// T-12: portal credentials stay unreachable (the full proof is in
/// `portal_boundary.rs`); here, through the portal's own records route.
#[tokio::test]
async fn t12_credentials_are_unreachable_from_the_portal() {
    let w = skip_if_no_db!(world().await);
    for entity in ["webportal_credential", "webportal_user", "user_account"] {
        assert_eq!(
            as_user(&w, &w.a1, "GET", &records(&w.a, entity), None, None)
                .await
                .0,
            StatusCode::NOT_FOUND,
            "{entity}"
        );
    }
}

/// T-13: portal writes are attributed to the portal user and never to a
/// staff id: `created_by`/`modified_by` stay NULL (D-579) and the audit event
/// carries the portal user with `Initiator::PortalUser` (hashed).
#[tokio::test]
async fn t13_portal_writes_are_attributed_to_the_portal_user() {
    let w = skip_if_no_db!(world().await);
    let created = create_case(&w, &w.a1, &w.a, "attributed").await;
    let id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    let (status, _) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &format!("{}/{id}", records(&w.a, &w.case)),
        Some(json!({"title": "attributed-2"})),
        Some(created["row_version"].as_i64().unwrap()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (created_by, modified_by): (Option<Uuid>, Option<Uuid>) = sqlx::query_as(&format!(
        "SELECT created_by, modified_by FROM \"{}\" WHERE id = $1",
        w.case
    ))
    .bind(id)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!((created_by, modified_by), (None, None));
    // Either write path: the synchronous header (initiator 3) or the chainer's
    // ingest payload (`attribution.initiator = "portal_user"`).
    let portal_attributed: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM audit_header \
                 WHERE record_id = $1 AND user_id = $2 AND initiator = 3) \
              + (SELECT count(*) FROM audit_ingest \
                 WHERE payload->>'record_id' = $1::text \
                   AND payload->'user_context'->>'user_id' = $2::text \
                   AND payload->'attribution'->>'initiator' = 'portal_user')",
    )
    .bind(id)
    .bind(w.a1.user)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert!(
        portal_attributed >= 2,
        "create and update as the portal user ({portal_attributed})"
    );
    let not_portal: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM audit_header WHERE record_id = $1 AND initiator <> 3) \
              + (SELECT count(*) FROM audit_ingest \
                 WHERE payload->>'record_id' = $1::text \
                   AND COALESCE(payload->'attribution'->>'initiator', 'user') <> 'portal_user')",
    )
    .bind(id)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(
        not_portal, 0,
        "no event on a portal write may read as staff"
    );
}

/// T-14 (Phase 5): a portal user downloads a file of a record in their scope
/// through a short-lived URL; a file on another user's record, a field they
/// can't read, a non-file field and an empty field are all the same 404; a
/// file field is never filterable, and with a read-only grant a record write
/// can't set it (uploads: `u1_…`).
#[tokio::test]
async fn t14_file_fields_are_download_only_and_scoped() {
    let w = skip_if_no_db!(world().await);
    let grant_url = format!(
        "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
        w.a.id, w.role_mine_a, w.case
    );
    let grant = |attachment: Value| {
        json!({
            "can_read": true, "can_create": true, "can_update": true, "can_delete": true,
            "conditions": [{"field": "portal_user_ref", "operator": "eq", "value_ref": "@portal_user.id"}],
            "fields": [
                {"field": "title", "can_read": true, "can_write": true, "can_filter": true},
                {"field": "company_ref", "can_read": true, "can_write": true},
                {"field": "portal_user_ref", "can_read": true},
                attachment,
            ],
        })
    };
    let filterable_file = json!({"field": "attachment", "can_read": true, "can_filter": true});
    let (status, text) = admin_status(&w.fx, "PUT", &grant_url, Some(grant(filterable_file))).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a file field is never filterable: {text}"
    );
    admin(
        &w.fx,
        "PUT",
        &grant_url,
        Some(grant(json!({"field": "attachment", "can_read": true}))),
    )
    .await;

    // A staff-attached file on a1's case (set directly in this throwaway
    // database, as the upload pipeline's promotion would).
    let mine = create_case(&w, &w.a1, &w.a, "with file").await;
    let mine_id = mine["id"].as_str().unwrap().to_owned();
    let key = format!(
        "{}/{mine_id}/attachment/{}-report.pdf",
        w.case,
        Uuid::now_v7()
    );
    sqlx::query(&format!(
        "UPDATE {} SET attachment = $2 WHERE id = $1",
        attome_core::quote_ident(&w.case)
    ))
    .bind(Uuid::parse_str(&mine_id).unwrap())
    .bind(&key)
    .execute(&w.fx.base.db)
    .await
    .unwrap();
    let empty = create_case(&w, &w.a1, &w.a, "no file").await;

    let record = format!("{}/{mine_id}", records(&w.a, &w.case));
    let (status, shown) = as_user(&w, &w.a1, "GET", &record, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(shown["data"]["attachment"], key.as_str(), "{shown}");

    let (status, url) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{record}/files/attachment"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{url}");
    assert!(
        url["download_url"]
            .as_str()
            .is_some_and(|u| u.contains("report.pdf")),
        "{url}"
    );
    assert_eq!(url["expires_in_secs"], 900);

    // All the same 404: another user's record, a non-file field, an
    // unreadable field, an empty field, a wrong key.
    let missing = without_request_id(
        as_user(
            &w,
            &w.a2,
            "GET",
            &format!("{record}/files/attachment"),
            None,
            None,
        )
        .await
        .1,
    );
    for (who, uri) in [
        (&w.a1, format!("{record}/files/title")),
        (&w.a1, format!("{record}/files/secret")),
        (&w.a1, format!("{record}/files/internal_note")),
        (
            &w.a1,
            format!(
                "{}/{}/files/attachment",
                records(&w.a, &w.case),
                empty["id"].as_str().unwrap()
            ),
        ),
        (
            &w.a1,
            format!("{record}/files/attachment?key=someone-elses"),
        ),
        (&w.a3, format!("{record}/files/attachment")),
    ] {
        let (status, body) = as_user(&w, who, "GET", &uri, None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
        assert_eq!(without_request_id(body), missing, "{uri}");
    }

    // Read only: no upload through a record write, no filter.
    let (status, _) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &record,
        Some(json!({"attachment": "k"})),
        shown["row_version"].as_i64(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, view) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("/{}/api/v1/metadata/{}", w.a.keyword, w.case),
        None,
        None,
    )
    .await;
    let attachment = field(&view, "attachment");
    assert_eq!(attachment["readable"], true, "{view}");
    assert_eq!(attachment["writable"], false);
    assert_eq!(attachment["filterable"], false);
    assert_eq!(attachment["field_type"], "file");
}

/// T-15: no code on the portal path builds a staff `SecurityContext`.
#[test]
fn t15_no_security_context_is_built_on_the_portal_path() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut files = vec![root.join("crates/engine/attome-records/src/access_plan.rs")];
    // Every file under attome-portal/src, subdirectories included.
    let mut dirs = vec![root.join("crates/engine/attome-portal/src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else {
                files.push(path);
            }
        }
    }
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for pattern in [
            "SecurityContext {",
            "SecurityContext::",
            "admin_security_context",
            "Principal::Staff",
        ] {
            assert!(
                !text.contains(pattern),
                "{} contains `{pattern}`: the portal path must never build or borrow a staff context",
                file.display()
            );
        }
    }
}

/// T-15, metadata half (plan Phase 5, I-18): portal route code never reads
/// entity metadata by hand. What a portal may see of an entity comes only
/// from `access_plan::describe` over the caller's plan; the one label read
/// (`router/metadata.rs`) asks for exactly the plan's field names.
#[test]
fn t15_portal_routes_describe_entities_only_through_the_plan() {
    let src =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../engine/attome-portal/src");
    let mut files = vec![src.join("router.rs")];
    for entry in std::fs::read_dir(src.join("router")).unwrap() {
        files.push(entry.unwrap().path());
    }
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for pattern in ["resolve_entity", ".attrs", "EntityMeta {"] {
            assert!(
                !text.contains(pattern),
                "{} contains `{pattern}`: portal routes describe entities only through \
                 access_plan::describe",
                file.display()
            );
        }
        if !file.ends_with("metadata.rs") {
            assert!(
                !text.contains("attribute_info") && !text.contains("entity_info"),
                "{} reads staff metadata tables; only router/metadata.rs reads labels",
                file.display()
            );
        }
    }
}

// ── T-22 … T-25 (Phase 13, plan §9.4) ─────────────────────────────────────────

/// A second company, which no portal user in the world belongs to.
async fn other_company(w: &World) -> Uuid {
    id_of(
        &admin(
            &w.fx,
            "POST",
            &format!("/api/v1/{}", w.company),
            Some(json!({"name": format!("Globex {}", short())})),
        )
        .await,
    )
}

/// T-22 (G-1): a lookup written to a target outside the caller's scope is
/// refused exactly as a nonexistent id is, on create and on update, and
/// nothing is written.
#[tokio::test]
async fn t22_lookup_writes_respect_the_target_scope() {
    let w = skip_if_no_db!(world().await);
    let globex = other_company(&w).await;
    let missing = Uuid::now_v7();
    let url = records(&w.a, &w.case);

    let create = |company: Uuid| {
        let w = &w;
        let url = url.clone();
        async move {
            as_user(
                w,
                &w.a1,
                "POST",
                &url,
                Some(json!({"title": "probe", "company_ref": company})),
                None,
            )
            .await
        }
    };
    let out_of_scope = create(globex).await;
    let nonexistent = create(missing).await;
    assert_eq!(
        out_of_scope.0,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        out_of_scope.1
    );
    assert_eq!(out_of_scope.0, nonexistent.0);
    assert_eq!(
        without_request_id(out_of_scope.1),
        without_request_id(nonexistent.1),
        "an out-of-scope target must read exactly like a missing one"
    );
    let (_, list) = as_user(&w, &w.a1, "GET", &url, None, None).await;
    assert_eq!(list["total"], 0, "nothing was created: {list}");

    // Update: the same refusal, and the record keeps its company.
    let mine = create_case(&w, &w.a1, &w.a, "mine").await;
    let id = mine["id"].as_str().unwrap();
    let rv = mine["row_version"].as_i64().unwrap();
    let moved = as_user(
        &w,
        &w.a1,
        "PATCH",
        &format!("{url}/{id}"),
        Some(json!({"company_ref": globex})),
        Some(rv),
    )
    .await;
    let missing_update = as_user(
        &w,
        &w.a1,
        "PATCH",
        &format!("{url}/{id}"),
        Some(json!({"company_ref": missing})),
        Some(rv),
    )
    .await;
    assert_eq!(moved.0, StatusCode::UNPROCESSABLE_ENTITY, "{}", moved.1);
    assert_eq!(
        without_request_id(moved.1),
        without_request_id(missing_update.1)
    );
    let (_, after) = as_user(&w, &w.a1, "GET", &format!("{url}/{id}"), None, None).await;
    assert_eq!(
        after["data"]["company_ref"],
        json!(w.acme.to_string()),
        "{after}"
    );

    // Its own company is still writable.
    let ok = as_user(
        &w,
        &w.a1,
        "PATCH",
        &format!("{url}/{id}"),
        Some(json!({"company_ref": w.acme, "title": "still mine"})),
        Some(rv),
    )
    .await;
    assert_eq!(ok.0, StatusCode::OK, "{}", ok.1);
}

/// T-23 (G-2): a readable lookup whose target is out of scope reads as
/// `null`, in get and in list; one in scope reads as its id. The caller can
/// read their own company record and no other.
#[tokio::test]
async fn t23_lookup_reads_respect_the_target_scope() {
    let w = skip_if_no_db!(world().await);
    let globex = other_company(&w).await;
    let url = records(&w.a, &w.case);
    let visible = create_case(&w, &w.a1, &w.a, "visible target").await;
    let hidden = create_case(&w, &w.a1, &w.a, "hidden target").await;
    let hidden_id: Uuid = hidden["id"].as_str().unwrap().parse().unwrap();
    // Staff move one case to a company the portal user can't see.
    sqlx::query(&format!(
        "UPDATE {} SET company_ref = $2 WHERE id = $1",
        w.case
    ))
    .bind(hidden_id)
    .bind(globex)
    .execute(&w.fx.base.db)
    .await
    .unwrap();

    let (_, got) = as_user(&w, &w.a1, "GET", &format!("{url}/{hidden_id}"), None, None).await;
    assert_eq!(got["data"]["company_ref"], Value::Null, "{got}");
    assert_eq!(
        got["data"]["portal_user_ref"],
        json!(w.a1.user.to_string()),
        "the caller's own id is visible through a portal-user lookup"
    );
    let (_, list) = as_user(&w, &w.a1, "GET", &url, None, None).await;
    for item in list["items"].as_array().unwrap() {
        let expected = if item["id"] == visible["id"] {
            json!(w.acme.to_string())
        } else {
            Value::Null
        };
        assert_eq!(item["data"]["company_ref"], expected, "{item}");
    }

    // The caller's own company is readable; another company is the same 404
    // as a missing record.
    let companies = records(&w.a, &w.company);
    let (status, own) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{companies}/{}", w.acme),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{own}");
    let (_, all) = as_user(&w, &w.a1, "GET", &companies, None, None).await;
    assert_eq!(all["total"], 1, "only the caller's company: {all}");
    let (status, _) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{companies}/{globex}"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // A lookup can't be granted without a read grant on its target: role
    // "company" has none on the company entity.
    let (status, text) = admin_status(
        &w.fx,
        "PUT",
        &format!(
            "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
            w.a.id, w.role_company_a, w.case
        ),
        Some(json!({
            "can_read": true,
            "conditions": [{"field": "company_ref", "operator": "eq", "value_ref": "@portal_user.company_ref"}],
            "fields": [{"field": "company_ref", "can_read": true}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{text}");
}

/// T-24 (G-3): a grant that can write needs a condition bound to the portal
/// user; a literal-only grant is accepted only read-only.
#[tokio::test]
async fn t24_writable_grants_need_a_caller_bound_condition() {
    let w = skip_if_no_db!(world().await);
    let url = format!(
        "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
        w.a.id, w.role_company_a, w.case
    );
    let literal = json!([{"field": "title", "operator": "ne", "value": "nothing matches this"}]);
    for action in ["can_create", "can_update", "can_delete"] {
        let mut body = json!({"can_read": true, "conditions": literal.clone(), "fields": [{"field": "title", "can_read": true}]});
        body[action] = json!(true);
        let (status, text) = admin_status(&w.fx, "PUT", &url, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{action}: {text}");
    }
    // Read-only reference data is allowed.
    let (status, text) = admin_status(
        &w.fx,
        "PUT",
        &url,
        Some(json!({"can_read": true, "conditions": literal, "fields": [{"field": "title", "can_read": true}]})),
    )
    .await;
    assert!(status.is_success(), "{status} {text}");
    // `id` conditions: `eq` only.
    let (status, _) = admin_status(
        &w.fx,
        "PUT",
        &url,
        Some(json!({"can_read": true, "conditions": [{"field": "id", "operator": "ne", "value_ref": "@portal_user.company_ref"}]})),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

/// T-25 (G-6, G-15): a condition that no longer renders matches nothing
/// (200, empty) rather than failing every request, and an owning team that
/// is gone refuses creation while reads keep working.
#[tokio::test]
async fn t25_drift_fails_closed_without_a_500() {
    let w = skip_if_no_db!(world().await);
    create_case(&w, &w.a1, &w.a, "acme-case").await;
    let url = records(&w.a, &w.case);

    // G-6: the company role's condition now names a field that doesn't exist.
    sqlx::query(
        "UPDATE webportal_grant_condition c SET field_logicalname = 'gone_field' \
         FROM webportal_grant g \
         WHERE g.id = c.grant_id AND g.role_id = $1 AND g.entity_logicalname = $2",
    )
    .bind(w.role_company_a)
    .bind(&w.case)
    .execute(&w.fx.base.db)
    .await
    .unwrap();
    let (status, list) = as_user(&w, &w.a3, "GET", &url, None, None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(
        list["total"], 0,
        "a drifted condition matches nothing: {list}"
    );

    // G-15: the owning team is deleted.
    sqlx::query("UPDATE team SET is_deleted = TRUE WHERE id = $1")
        .bind(w.team)
        .execute(&w.fx.base.db)
        .await
        .unwrap();
    let (status, body) = as_user(
        &w,
        &w.a1,
        "POST",
        &url,
        Some(json!({"title": "orphan"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, list) = as_user(&w, &w.a1, "GET", &url, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(titles(&list), vec!["acme-case"]);
}

// ── T-26 … T-30 (Phase 13, plan §9.4: G-4, G-5, G-7, G-8, G-13, G-14) ─────────

/// Reads the portal's auth policy, lets `edit` change it, and writes it back.
async fn edit_policy(fx: &Fx, p: &Portal, edit: impl FnOnce(&mut Value)) -> (StatusCode, String) {
    let url = format!("/api/v1/admin/webportals/{}/auth-policy", p.id);
    let mut policy = admin(fx, "GET", &url, None).await;
    edit(&mut policy);
    admin_status(fx, "PUT", &url, Some(policy)).await
}

/// T-26 (G-14): erasing a portal user scrubs their profile in place, ends
/// every session and credential, completes their erasure request, and leaves
/// their records pointing at the (now anonymous) id.
#[tokio::test]
async fn t26_erasure_scrubs_the_profile_and_keeps_records_resolvable() {
    let w = skip_if_no_db!(world().await);
    let created = create_case(&w, &w.a1, &w.a, "before erasure").await;
    let case_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    let (status, _) = as_user(
        &w,
        &w.a1,
        "POST",
        &format!("/{}/api/v1/me/erasure-request", w.a.keyword),
        None,
        None,
    )
    .await;
    assert!(status.is_success(), "erasure request: {status}");

    let done = admin(
        &w.fx,
        "POST",
        &format!(
            "/api/v1/admin/webportals/{}/users/{}/erase",
            w.a.id, w.a1.user
        ),
        None,
    )
    .await;
    let request_id: Uuid = done["erasure_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // The session is dead: the credential is gone.
    let (status, _) = as_user(&w, &w.a1, "GET", &records(&w.a, &w.case), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (name, email, company, active): (String, String, Option<Uuid>, Option<bool>) =
        sqlx::query_as(
            "SELECT name, email, company_ref, is_active FROM webportal_user WHERE id = $1",
        )
        .bind(w.a1.user)
        .fetch_one(&w.fx.base.db)
        .await
        .unwrap();
    assert_eq!(name, "Erased user");
    assert!(email.ends_with("@erased.invalid"), "{email}");
    assert_eq!(company, None, "admin-added personal fields are blanked");
    assert_eq!(active, Some(false));
    let leftovers: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM webportal_credential WHERE webportal_user_id = $1) \
              + (SELECT count(*) FROM webportal_refresh_token WHERE webportal_user_id = $1) \
              + (SELECT count(*) FROM webportal_user_role WHERE webportal_user_id = $1)",
    )
    .bind(w.a1.user)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(leftovers, 0);

    // The record still names the (anonymous) portal user.
    let owner: Option<Uuid> = sqlx::query_scalar(&format!(
        "SELECT portal_user_ref FROM \"{}\" WHERE id = $1",
        w.case
    ))
    .bind(case_id)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(owner, Some(w.a1.user));

    // The request the user opened is the one completed.
    let requests = admin(
        &w.fx,
        "GET",
        &format!("/api/v1/admin/webportals/{}/erasure-requests", w.a.id),
        None,
    )
    .await;
    let mine = requests["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == json!(request_id.to_string()))
        .unwrap_or_else(|| panic!("request listed: {requests}"));
    assert_eq!(mine["status"], "completed");
}

/// T-27 (G-4, G-5): record routes are budgeted per account; a repeated
/// idempotency key creates once; delete needs `If-Match`.
#[tokio::test]
async fn t27_record_budgets_idempotency_and_if_match() {
    let w = skip_if_no_db!(world().await);
    let url = records(&w.a, &w.case);

    // G-5: the same key twice creates one record and replays the first result.
    let mut first = portal_req(
        "POST",
        &url,
        std::slice::from_ref(&w.a2.cookie),
        Some(json!({"title": "once", "company_ref": w.acme})),
    );
    first
        .headers_mut()
        .insert("x-idempotency-key", "k-once".parse().unwrap());
    let (status_1, _, body_1) = send(&w.fx, first).await;
    let mut again = portal_req(
        "POST",
        &url,
        std::slice::from_ref(&w.a2.cookie),
        Some(json!({"title": "once", "company_ref": w.acme})),
    );
    again
        .headers_mut()
        .insert("x-idempotency-key", "k-once".parse().unwrap());
    let (status_2, _, body_2) = send(&w.fx, again).await;
    assert_eq!(status_1, StatusCode::CREATED, "{body_1}");
    assert_eq!(status_2, StatusCode::CREATED, "{body_2}");
    let id_1 = serde_json::from_str::<Value>(&body_1).unwrap()["id"].clone();
    let id_2 = serde_json::from_str::<Value>(&body_2).unwrap()["id"].clone();
    assert_eq!(id_1, id_2, "replayed, not created twice");
    let (_, list) = as_user(&w, &w.a2, "GET", &url, None, None).await;
    assert_eq!(list["total"], 1, "{list}");

    // G-5: delete without If-Match is refused, with it succeeds.
    let id = id_1.as_str().unwrap();
    let (status, _) = as_user(&w, &w.a2, "DELETE", &format!("{url}/{id}"), None, None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // G-4: 30 writes a minute per account; the 31st is refused. Two writes
    // are spent above (the replay short-circuits before the handler).
    let mut last = StatusCode::CREATED;
    let mut writes = 1;
    while writes < 31 {
        let (status, _) = as_user(
            &w,
            &w.a2,
            "POST",
            &url,
            Some(json!({"title": format!("w{writes}"), "company_ref": w.acme})),
            None,
        )
        .await;
        last = status;
        writes += 1;
        if status == StatusCode::TOO_MANY_REQUESTS {
            break;
        }
    }
    assert_eq!(
        last,
        StatusCode::TOO_MANY_REQUESTS,
        "the account's write budget ends at 30 a minute ({writes} writes)"
    );
    // Reads have their own budget: still allowed.
    let (status, _) = as_user(&w, &w.a2, "GET", &url, None, None).await;
    assert_eq!(status, StatusCode::OK);
}

/// T-28 (G-13): the portal's client-address allowlist refuses outsiders with
/// the unknown-portal 404 on every route; the page-size cap bounds lists.
#[tokio::test]
async fn t28_address_allowlist_and_page_cap() {
    let w = skip_if_no_db!(world().await);
    create_case(&w, &w.a1, &w.a, "one").await;
    create_case(&w, &w.a1, &w.a, "two").await;
    create_case(&w, &w.a1, &w.a, "three").await;
    let url = records(&w.a, &w.case);

    // The harness connects from 203.0.113.7.
    let (status, text) = edit_policy(&w.fx, &w.a, |p| {
        p["allowed_cidrs"] = json!(["198.51.100.0/24"]);
    })
    .await;
    assert!(status.is_success(), "{status} {text}");
    let refused = as_user(&w, &w.a1, "GET", &url, None, None).await;
    let unknown = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("/no-such-portal-{}/api/v1/records/{}", short(), w.case),
        None,
        None,
    )
    .await;
    assert_eq!(refused.0, StatusCode::NOT_FOUND);
    assert_eq!(
        without_request_id(refused.1),
        without_request_id(unknown.1),
        "an outside address sees the unknown-portal 404"
    );
    let (status, _, _) = send(
        &w.fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", w.a.keyword),
            &[],
            Some(json!({"email": "x@example.com", "password": "x"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "login is gated too");
    // The keyword resolves case-insensitively, so the allowlist must too: a
    // differently-cased keyword once skipped it and reached the login (401).
    let (status, _, _) = send(
        &w.fx,
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", w.a.keyword.to_uppercase()),
            &[],
            Some(json!({"email": "x@example.com", "password": "x"})),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a re-cased keyword is gated too"
    );
    // Portal B has no allowlist and is unaffected.
    let (status, _) = as_user(&w, &w.b1, "GET", &records(&w.b, &w.case), None, None).await;
    assert_eq!(status, StatusCode::OK);

    // Inside the allowlist, with a page cap of 2.
    let (status, text) = edit_policy(&w.fx, &w.a, |p| {
        p["allowed_cidrs"] = json!(["203.0.113.0/24"]);
        p["page_size_cap"] = json!(2);
    })
    .await;
    assert!(status.is_success(), "{status} {text}");
    let (status, list) =
        as_user(&w, &w.a1, "GET", &format!("{url}?page_size=50"), None, None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["page_size"], 2);
    assert_eq!(list["items"].as_array().unwrap().len(), 2);
    assert_eq!(list["total"], 3);

    // A bad CIDR or cap is refused at write time.
    let (status, _) =
        edit_policy(&w.fx, &w.a, |p| p["allowed_cidrs"] = json!(["10.0.0.0/33"])).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = edit_policy(&w.fx, &w.a, |p| p["page_size_cap"] = json!(101)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

/// T-29 (G-8): the admin API reads back what it writes, labels public
/// grants, and manages the role lifecycle without stranding users.
#[tokio::test]
async fn t29_admin_reads_and_role_lifecycle() {
    let w = skip_if_no_db!(world().await);
    let base = format!("/api/v1/admin/webportals/{}", w.a.id);

    let portals = admin(&w.fx, "GET", "/api/v1/admin/webportals?page_size=200", None).await;
    assert!(
        portals["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == json!(w.a.id.to_string())),
        "{portals}"
    );
    let users = admin(&w.fx, "GET", &format!("{base}/users"), None).await;
    assert_eq!(users["total"], 4, "a1..a4: {users}");
    let roles = admin(&w.fx, "GET", &format!("{base}/roles"), None).await;
    let mine = roles["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "mine")
        .unwrap_or_else(|| panic!("{roles}"));
    assert_eq!(mine["user_count"], 2);

    let role = admin(
        &w.fx,
        "GET",
        &format!("{base}/roles/{}", w.role_mine_a),
        None,
    )
    .await;
    let case_grant = role["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["entity"] == json!(w.case))
        .unwrap_or_else(|| panic!("{role}"));
    assert_eq!(case_grant["public"], false);
    assert_eq!(case_grant["conditions"][0]["value_ref"], "@portal_user.id");

    // A read-only literal grant reads back as public.
    admin(
        &w.fx,
        "PUT",
        &format!("{base}/roles/{}/grants/{}", w.role_company_a, w.case),
        Some(json!({
            "can_read": true,
            "conditions": [{"field": "title", "operator": "eq", "value": "catalogue"}],
            "fields": [{"field": "title", "can_read": true}],
        })),
    )
    .await;
    let role = admin(
        &w.fx,
        "GET",
        &format!("{base}/roles/{}", w.role_company_a),
        None,
    )
    .await;
    assert_eq!(role["grants"][0]["public"], true, "{role}");

    let configs = admin(&w.fx, "GET", &format!("{base}/entities"), None).await;
    assert_eq!(configs["items"][0]["portal_user_field"], "portal_user_ref");

    // Rename; a held role can't be deleted; unassigning ends record access.
    let (status, _) = admin_status(
        &w.fx,
        "PATCH",
        &format!("{base}/roles/{}", w.role_mine_a),
        Some(json!({"name": "my own"})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = admin_status(
        &w.fx,
        "DELETE",
        &format!("{base}/roles/{}", w.role_mine_a),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = admin_status(
        &w.fx,
        "DELETE",
        &format!("{base}/users/{}/role", w.a2.user),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = as_user(&w, &w.a2, "GET", &records(&w.a, &w.case), None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "no role, no records");
}

/// T-30 (G-7): portal audit rows carry the client address.
#[tokio::test]
async fn t30_portal_audit_rows_carry_the_client_address() {
    let w = skip_if_no_db!(world().await);
    let created = create_case(&w, &w.a1, &w.a, "with an address").await;
    let id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
    let with_ip: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM audit_header \
                 WHERE record_id = $1 AND ip_address = '203.0.113.7') \
              + (SELECT count(*) FROM audit_ingest \
                 WHERE payload->>'record_id' = $1::text \
                   AND payload->'request_context'->>'ip_address' = '203.0.113.7')",
    )
    .bind(id)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert!(with_ip >= 1, "the create's audit row names 203.0.113.7");
}

// ── T-31 … T-33 (Phase 13 step 4: G-4, G-5, G-8; I-10, I-17) ─────────────────

/// A record create carrying `key` as its idempotency key.
fn keyed_create(w: &World, who: &Session, p: &Portal, key: &str) -> Request<Body> {
    let mut req = portal_req(
        "POST",
        &records(p, &w.case),
        std::slice::from_ref(&who.cookie),
        Some(json!({"title": "same", "company_ref": w.acme})),
    );
    req.headers_mut()
        .insert("x-idempotency-key", key.parse().unwrap());
    req
}

fn id_in(text: &str) -> String {
    serde_json::from_str::<Value>(text).unwrap()["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no id in {text}"))
        .to_owned()
}

/// T-31 (G-5, I-17): an idempotency key is scoped to the portal user and the
/// portal. The same key, with the same body, from another user of the same
/// portal or from a user of another portal creates that caller's own record;
/// it never replays the first user's result.
#[tokio::test]
async fn t31_an_idempotency_key_never_replays_across_users_or_portals() {
    let w = skip_if_no_db!(world().await);
    let key = format!("t31-{}", short());

    let (status, _, first) = send(&w.fx, keyed_create(&w, &w.a1, &w.a, &key)).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let a1_id = id_in(&first);
    // The first user's own repeat is a replay: the key is live.
    let (status, _, replay) = send(&w.fx, keyed_create(&w, &w.a1, &w.a, &key)).await;
    assert_eq!(status, StatusCode::CREATED, "{replay}");
    assert_eq!(id_in(&replay), a1_id, "the key is live for a1");

    // Another user of the same portal: same route, key and body.
    let (status, _, other_user) = send(&w.fx, keyed_create(&w, &w.a2, &w.a, &key)).await;
    assert_eq!(status, StatusCode::CREATED, "{other_user}");
    let a2_id = id_in(&other_user);
    assert_ne!(a2_id, a1_id, "a2 was replayed a1's result");

    // A user of another portal: same key and body.
    let (status, _, other_portal) = send(&w.fx, keyed_create(&w, &w.b1, &w.b, &key)).await;
    assert_eq!(status, StatusCode::CREATED, "{other_portal}");
    let b1_id = id_in(&other_portal);
    assert_ne!(b1_id, a1_id, "portal B was replayed portal A's result");
    assert_ne!(b1_id, a2_id);

    // Each record belongs to its own caller, and each caller sees only it.
    for (who, p, id) in [
        (&w.a1, &w.a, &a1_id),
        (&w.a2, &w.a, &a2_id),
        (&w.b1, &w.b, &b1_id),
    ] {
        let owner: Option<Uuid> = sqlx::query_scalar(&format!(
            "SELECT portal_user_ref FROM \"{}\" WHERE id = $1",
            w.case
        ))
        .bind(Uuid::parse_str(id).unwrap())
        .fetch_one(&w.fx.base.db)
        .await
        .unwrap();
        assert_eq!(owner, Some(who.user));
        let (status, list) = as_user(&w, who, "GET", &records(p, &w.case), None, None).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert_eq!(list["total"], 1, "{list}");
        assert_eq!(list["items"][0]["id"], json!(id), "{list}");
    }
}

/// A pool that can never reach Redis: never initialized and pointed at a
/// closed port, so every command errors (the outage path).
fn unreachable_redis() -> fred::clients::RedisPool {
    let config = fred::types::RedisConfig {
        server: fred::types::ServerConfig::new_centralized("127.0.0.1", 1),
        ..Default::default()
    };
    fred::clients::RedisPool::new(config, None, None, None, 1).expect("build pool")
}

/// A refusal a failed budget check produces (never a 2xx, 401 or 404).
fn refused(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::TOO_MANY_REQUESTS
    )
}

/// T-32 (G-4, I-10): with the coordination Redis unavailable, the portal's
/// auth and record budgets refuse the request (fail closed): a correct login
/// gets no session, a reset request issues no link, and a valid session
/// neither reads nor writes records. The same requests succeed with Redis
/// up, so the refusal is the budget's, not the fixture's.
#[tokio::test]
async fn t32_budgets_fail_closed_when_redis_is_unavailable() {
    let w = skip_if_no_db!(world().await);
    let mut dead = w.fx.xrm.clone();
    dead.base.redis_coordination = unreachable_redis().into();
    // The portal router exactly as `router::app` builds it, on the outage state.
    let outage = attome_portal::router::app(dead);
    let send_outage = |req: Request<Body>| {
        let app = outage.clone();
        async move {
            let res = app.oneshot(req).await.expect("send");
            (res.status(), res.headers().contains_key(header::SET_COOKIE))
        }
    };
    let login = |who: &Session| {
        portal_req(
            "POST",
            &format!("/{}/api/v1/auth/login", w.a.keyword),
            &[],
            Some(json!({"email": who.email, "password": PASSWORD})),
        )
    };
    let url = records(&w.a, &w.case);
    let create = || {
        portal_req(
            "POST",
            &url,
            std::slice::from_ref(&w.a1.cookie),
            Some(json!({"title": "during the outage", "company_ref": w.acme})),
        )
    };

    // Auth: the correct password, and no session.
    let (status, sets_cookie) = send_outage(login(&w.a2)).await;
    assert!(refused(status), "login during an outage: {status}");
    assert!(!sets_cookie, "no session cookie during an outage");
    // Reset request: refused before any link is issued.
    let (status, _) = send_outage(portal_req(
        "POST",
        &format!("/{}/api/v1/auth/reset-request", w.a.keyword),
        &[],
        Some(json!({"email": w.a2.email})),
    ))
    .await;
    assert!(refused(status), "reset request during an outage: {status}");
    let resets: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webportal_token WHERE webportal_user_id = $1 AND kind = 'reset'",
    )
    .bind(w.a2.user)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(resets, 0, "no reset link issued during an outage");

    // Records: a valid session is refused on read and on write.
    let (status, _) = send_outage(portal_req(
        "GET",
        &url,
        std::slice::from_ref(&w.a1.cookie),
        None,
    ))
    .await;
    assert!(refused(status), "record read during an outage: {status}");
    let (status, _) = send_outage(create()).await;
    assert!(refused(status), "record write during an outage: {status}");
    let written: i64 = sqlx::query_scalar(&format!(
        "SELECT count(*) FROM \"{}\" WHERE portal_user_ref = $1",
        w.case
    ))
    .bind(w.a1.user)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(written, 0, "nothing written during an outage");

    // Control: the same requests pass with Redis up.
    let (status, _, body) = send(&w.fx, login(&w.a2)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = send(&w.fx, create()).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

/// T-33 (G-8): a staff session without `system.admin` gets 403 on every
/// `/api/v1/admin/webportals/*` operation. Generated from `openapi.json`, so
/// a new admin route joins the sweep, and aimed at real ids, so a missing
/// gate would reach real rows. Nothing changes.
#[tokio::test]
async fn t33_a_non_admin_staff_session_is_refused_every_portal_admin_route() {
    let w = skip_if_no_db!(world().await);
    let staff = seed_staff(&w.fx.base).await;
    let cookie = format!(
        "__Host-session_token={}",
        staff_session(&w.fx.base, staff).await
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../openapi.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let concrete = |seg: &str| -> String {
        match seg {
            "{id}" => w.a.id.to_string(),
            "{user_id}" => w.a2.user.to_string(),
            "{role_id}" => w.role_mine_a.to_string(),
            "{entity}" => w.case.clone(),
            "{request_id}" => Uuid::now_v7().to_string(),
            other if other.starts_with('{') => panic!("unmapped path parameter {other}"),
            other => other.to_owned(),
        }
    };
    let mut failures = Vec::new();
    let mut checked = 0;
    for (route, item) in doc["paths"].as_object().unwrap() {
        if !route.starts_with("/api/v1/admin/webportals") {
            continue;
        }
        let uri = route.split('/').map(concrete).collect::<Vec<_>>().join("/");
        for method in item.as_object().unwrap().keys() {
            let body = (method != "get" && method != "delete").then(|| {
                json!({
                    "name": "hijack", "keyword": format!("hj-{}", short()),
                    "portal_type": "authenticated", "is_enabled": true,
                    "email": "hijack@example.com", "role_id": w.role_company_a,
                    "can_read": true, "portal_user_field": "portal_user_ref",
                })
            });
            let (status, _, text) = send(
                &w.fx,
                portal_req(
                    &method.to_uppercase(),
                    &uri,
                    std::slice::from_ref(&cookie),
                    body,
                ),
            )
            .await;
            checked += 1;
            if status != StatusCode::FORBIDDEN {
                failures.push(format!(
                    "{} {route}: {status} {text}",
                    method.to_uppercase()
                ));
            }
        }
    }
    assert!(
        checked >= 26,
        "the sweep must cover the portal admin API ({checked})"
    );
    assert!(
        failures.is_empty(),
        "portal admin routes answered a non-admin staff session:\n{}",
        failures.join("\n")
    );
    // Nothing changed: a2 still holds "mine" and still reads records.
    let role: Option<Uuid> =
        sqlx::query_scalar("SELECT role_id FROM webportal_user_role WHERE webportal_user_id = $1")
            .bind(w.a2.user)
            .fetch_optional(&w.fx.base.db)
            .await
            .unwrap();
    assert_eq!(role, Some(w.role_mine_a));
    let (status, _) = as_user(&w, &w.a2, "GET", &records(&w.a, &w.case), None, None).await;
    assert_eq!(status, StatusCode::OK);
}

// ── C7: record latency and SQL statements per request (Phase 13 step 5) ──────

/// Counts sqlx's per-statement `sqlx::query` event while `on` is set. Scoped to
/// the test's own thread (`tracing::dispatcher::set_default`), so the global
/// `fmt` subscriber the fixture installs is untouched.
#[derive(Clone, Default)]
struct SqlCount {
    on: std::sync::Arc<std::sync::atomic::AtomicBool>,
    statements: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SqlCount {
    fn register_callsite(
        &self,
        metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        if metadata.target() == "sqlx::query" {
            tracing::subscriber::Interest::sometimes()
        } else {
            tracing::subscriber::Interest::never()
        }
    }

    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        metadata.target() == "sqlx::query" && self.on.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        /// sqlx's `summary` (the first words) and, when the statement is
        /// longer, its full text in `db.statement`: kept as
        /// `"{summary} :: {statement}"` so a test can match on table names.
        #[derive(Default)]
        struct Summary(String, String);
        impl tracing::field::Visit for Summary {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                match field.name() {
                    "summary" => value.clone_into(&mut self.0),
                    "db.statement" => {
                        self.1 = value.split_whitespace().collect::<Vec<_>>().join(" ")
                    }
                    _ => {}
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                match field.name() {
                    "summary" => self.0 = format!("{value:?}"),
                    "db.statement" => {
                        self.1 = format!("{value:?}")
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ");
                    }
                    _ => {}
                }
            }
        }
        let mut summary = Summary::default();
        event.record(&mut summary);
        self.statements
            .lock()
            .unwrap()
            .push(format!("{} :: {}", summary.0, summary.1));
    }
}

fn p95(samples: &mut [std::time::Duration]) -> std::time::Duration {
    samples.sort();
    samples[(samples.len() * 95).div_ceil(100) - 1]
}

/// C7 (plan §1; Phase 13 step 5): p95 of a record `GET` and of a 25-row list,
/// measured in-process through the full middleware stack (host gate, portal
/// gate, session, budgets, plan, engine), and the SQL statements each issues.
/// Server-side only: no network hop. The numbers are printed (`C7:` lines)
/// for the plan; the statement count is asserted, since it is deterministic.
/// Latency is not asserted (a debug build on a shared machine is noisy); the
/// recorded run in the plan is the evidence.
#[tokio::test]
async fn c7_record_latency_and_statements_per_request() {
    use tracing_subscriber::layer::SubscriberExt;

    let w = skip_if_no_db!(world().await);
    let mut ids = Vec::new();
    for n in 0..25 {
        let c = create_case(&w, &w.a1, &w.a, &format!("c7-{n:02}")).await;
        ids.push(c["id"].as_str().unwrap().to_owned());
    }
    let list_uri = format!("{}?page_size=25", records(&w.a, &w.case));
    let get_uri = |i: usize| format!("{}/{}", records(&w.a, &w.case), ids[i % ids.len()]);
    // Measuring needs more reads than the per-account read budget (120/min,
    // G-4) admits in a minute. Clearing the counter between requests keeps the
    // budget check itself (one Redis round trip) inside every measured call.
    let read_key = attome_cache::rate_limit::storage_key(&format!(
        "attome-portal:rl:rec-read:{}:{}",
        w.a.id, w.a1.user
    ));
    let reset_budget = || async {
        let _: i64 = w.fx.base.redis_coordination.del(&read_key).await.unwrap();
    };

    let capture = SqlCount::default();
    let _guard = tracing::dispatcher::set_default(&tracing::Dispatch::new(
        tracing_subscriber::registry().with(capture.clone()),
    ));
    let count_one = |uri: String| {
        let capture = capture.clone();
        let w = &w;
        async move {
            capture.statements.lock().unwrap().clear();
            capture.on.store(true, std::sync::atomic::Ordering::Relaxed);
            let (status, _) = as_user(w, &w.a1, "GET", &uri, None, None).await;
            capture
                .on
                .store(false, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(status, StatusCode::OK, "{uri}");
            capture.statements.lock().unwrap().clone()
        }
    };
    // G-9: C7 is the warm path. After a cold start the first request only
    // starts the access version and the second fills the portal cache.
    for _ in 0..2 {
        assert_eq!(
            as_user(&w, &w.a1, "GET", &get_uri(0), None, None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            as_user(&w, &w.a1, "GET", &list_uri, None, None).await.0,
            StatusCode::OK
        );
    }
    reset_budget().await;
    let get_statements = count_one(get_uri(0)).await;
    let list_statements = count_one(list_uri.clone()).await;
    eprintln!(
        "C7: record GET issues {} SQL statements: {:#?}",
        get_statements.len(),
        get_statements
    );
    eprintln!(
        "C7: 25-row list issues {} SQL statements: {:#?}",
        list_statements.len(),
        list_statements
    );

    const WARMUP: usize = 20;
    const SAMPLES: usize = 200;
    let mut get_times = Vec::with_capacity(SAMPLES);
    let mut list_times = Vec::with_capacity(SAMPLES);
    for i in 0..WARMUP + SAMPLES {
        reset_budget().await;
        let started = std::time::Instant::now();
        let (status, _) = as_user(&w, &w.a1, "GET", &get_uri(i), None, None).await;
        let get_elapsed = started.elapsed();
        assert_eq!(status, StatusCode::OK);
        let started = std::time::Instant::now();
        let (status, list) = as_user(&w, &w.a1, "GET", &list_uri, None, None).await;
        let list_elapsed = started.elapsed();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list["items"].as_array().map(Vec::len), Some(25));
        if i >= WARMUP {
            get_times.push(get_elapsed);
            list_times.push(list_elapsed);
        }
    }
    eprintln!(
        "C7: record GET p95 {:?} (median {:?}); 25-row list p95 {:?} (median {:?}); {SAMPLES} samples each, {} build",
        p95(&mut get_times),
        get_times[SAMPLES / 2],
        p95(&mut list_times),
        list_times[SAMPLES / 2],
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    );
    assert!(
        get_statements.len() <= RECORD_GET_STATEMENTS_WARM,
        "record GET: {} statements, more than the {RECORD_GET_STATEMENTS_WARM} measured \
         with the G-9 cache warm (C7 budget {C7_MAX_STATEMENTS_PER_RECORD_REQUEST})",
        get_statements.len()
    );
    assert!(
        list_statements.len() <= RECORD_GET_STATEMENTS_WARM + 1,
        "25-row list: {} statements",
        list_statements.len()
    );
}

/// C7's statement budget for one record request (plan §1).
const C7_MAX_STATEMENTS_PER_RECORD_REQUEST: usize = 8;
/// What a warm record `GET` issues (world role "mine": one readable lookup).
/// 18 before the G-9 cache (2026-09-28); 5 with it: the session check
/// (account, epoch, refresh family, role and portal liveness in one
/// statement), the user's `value_ref` row and label, the engine's entity
/// metadata (2) and the record. A regression guard below C7's budget; the
/// 25-row list issues one more (its count).
const RECORD_GET_STATEMENTS_WARM: usize = 5;

// ── G-9: the portal cache (plan §4.2) ────────────────────────────────────────

/// A statement capture scoped to the calling test's thread.
fn capture_sql() -> (SqlCount, tracing::dispatcher::DefaultGuard) {
    use tracing_subscriber::layer::SubscriberExt;
    let capture = SqlCount::default();
    let guard = tracing::dispatcher::set_default(&tracing::Dispatch::new(
        tracing_subscriber::registry().with(capture.clone()),
    ));
    (capture, guard)
}

/// The statements `request` issues, and its status.
async fn statements_of(
    capture: &SqlCount,
    request: impl std::future::Future<Output = StatusCode>,
) -> (StatusCode, Vec<String>) {
    capture.statements.lock().unwrap().clear();
    capture.on.store(true, std::sync::atomic::Ordering::Relaxed);
    let status = request.await;
    capture
        .on
        .store(false, std::sync::atomic::Ordering::Relaxed);
    (status, capture.statements.lock().unwrap().clone())
}

/// Starts a new access version, as a portal-admin write does: nothing cached
/// so far is served again.
async fn new_access_version(w: &World) -> String {
    let version = Uuid::now_v7().to_string();
    w.fx.base
        .redis
        .set(
            attome_portal::cache::ACCESS_VERSION_KEY,
            &version,
            Some(std::time::Duration::from_secs(3600)),
        )
        .await
        .unwrap();
    version
}

async fn access_version(w: &World) -> Option<String> {
    w.fx.base
        .redis
        .get(attome_portal::cache::ACCESS_VERSION_KEY)
        .await
        .unwrap()
}

/// What only the cache may answer on a warm request: the portal by keyword,
/// its policy, the grant, its conditions and field profile, the entity config.
const CACHED_READS: &[&str] = &[
    "FROM webportal WHERE",
    "webportal_auth_policy",
    "webportal_grant",
    "webportal_entity",
];

fn reads_any_cached(statements: &[String]) -> Vec<&str> {
    CACHED_READS
        .iter()
        .copied()
        .filter(|t| statements.iter().any(|s| s.contains(t)))
        .collect()
}

/// G-9: a warm portal cache answers the portal, policy and grant reads; only
/// the per-request reads remain (the session check, the user's `value_ref`
/// row, the engine's metadata and the record), within C7's budget.
#[tokio::test]
async fn g9_a_warm_cache_skips_the_portal_policy_and_grant_reads() {
    let w = skip_if_no_db!(world().await);
    let case = create_case(&w, &w.a1, &w.a, "g9 warm").await;
    let uri = format!(
        "{}/{}",
        records(&w.a, &w.case),
        case["id"].as_str().unwrap()
    );
    let get = || async { as_user(&w, &w.a1, "GET", &uri, None, None).await.0 };
    let (capture, _guard) = capture_sql();

    new_access_version(&w).await;
    let (status, cold) = statements_of(&capture, get()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, warm) = statements_of(&capture, get()).await;
    assert_eq!(status, StatusCode::OK);
    eprintln!(
        "G-9: cold GET {} statements, warm GET {}: {warm:#?}",
        cold.len(),
        warm.len()
    );
    assert_eq!(
        reads_any_cached(&cold),
        CACHED_READS.to_vec(),
        "a cold request reads everything from PostgreSQL: {cold:#?}"
    );
    assert!(
        reads_any_cached(&warm).is_empty(),
        "a warm request read {:?}: {warm:#?}",
        reads_any_cached(&warm)
    );
    assert!(warm.len() < cold.len());
    assert!(warm.len() <= C7_MAX_STATEMENTS_PER_RECORD_REQUEST);
    // The session and the user's own row are read on every request.
    assert!(warm.iter().any(|s| s.contains("webportal_credential")));
    assert!(warm.iter().any(|s| s.contains("FROM webportal_user WHERE")));
}

/// G-9: every portal-admin write replaces the access version after it
/// commits, so a narrowed grant applies on the very next request, even with
/// the old grant cached.
#[tokio::test]
async fn g9_an_admin_grant_change_applies_on_the_next_request() {
    let w = skip_if_no_db!(world().await);
    let case = create_case(&w, &w.a1, &w.a, "g9 narrowed").await;
    let uri = format!(
        "{}/{}",
        records(&w.a, &w.case),
        case["id"].as_str().unwrap()
    );
    for _ in 0..3 {
        let (status, record) = as_user(&w, &w.a1, "GET", &uri, None, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(record["data"]["title"], "g9 narrowed", "{record}");
    }
    let before = access_version(&w).await;
    assert!(before.is_some(), "the cache is warm under a version");

    // Narrow "mine": `title` leaves the field profile.
    admin(
        &w.fx,
        "PUT",
        &format!(
            "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
            w.a.id, w.role_mine_a, w.case
        ),
        Some(json!({
            "can_read": true, "can_create": true, "can_update": true, "can_delete": true,
            "conditions": [{"field": "portal_user_ref", "operator": "eq", "value_ref": "@portal_user.id"}],
            "fields": [
                {"field": "company_ref", "can_read": true, "can_write": true},
                {"field": "portal_user_ref", "can_read": true},
            ],
        })),
    )
    .await;
    assert_ne!(
        access_version(&w).await,
        before,
        "the write replaced the version"
    );

    let (status, record) = as_user(&w, &w.a1, "GET", &uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        record["data"].get("title").is_none(),
        "the removed field is gone at once: {record}"
    );
    let (status, _) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{}?title=x", records(&w.a, &w.case)),
        None,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "and no longer filterable"
    );

    // Removing the grant: the next request is the uniform 404.
    let (status, _) = admin_status(
        &w.fx,
        "DELETE",
        &format!(
            "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
            w.a.id, w.role_mine_a, w.case
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        as_user(&w, &w.a1, "GET", &uri, None, None).await.0,
        StatusCode::NOT_FOUND
    );
}

/// G-9: with the cache Redis unreachable, the portal serves from PostgreSQL
/// on every request (never from a stale entry) and stays correct: scope,
/// field profile and admin changes all hold. The coordination Redis (budgets)
/// stays up; its outage fails closed instead (T-32).
#[tokio::test]
async fn g9_a_cache_redis_outage_serves_the_source_of_truth() {
    let w = skip_if_no_db!(world().await);
    let mine = create_case(&w, &w.a1, &w.a, "g9 outage").await;
    let theirs = create_case(&w, &w.a2, &w.a, "g9 not mine").await;
    let url = |c: &Value| format!("{}/{}", records(&w.a, &w.case), c["id"].as_str().unwrap());
    let mut dead = w.fx.xrm.clone();
    dead.base.redis = unreachable_redis().into();
    let outage = attome_portal::router::app(dead);
    let get = |uri: String| {
        let app = outage.clone();
        let cookie = w.a1.cookie.clone();
        async move {
            let res = app
                .oneshot(portal_req("GET", &uri, &[cookie], None))
                .await
                .expect("send");
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };

    let (capture, _guard) = capture_sql();
    for _ in 0..2 {
        let (status, statements) = statements_of(&capture, async {
            let (status, record) = get(url(&mine)).await;
            assert_eq!(record["data"]["title"], "g9 outage", "{record}");
            status
        })
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            reads_any_cached(&statements),
            CACHED_READS.to_vec(),
            "every outage request reads PostgreSQL: {statements:#?}"
        );
    }
    assert_eq!(
        get(url(&theirs)).await.0,
        StatusCode::NOT_FOUND,
        "scope holds"
    );

    // An admin change (through the live stack) applies at once on the
    // outage router too: nothing there was cached.
    admin(
        &w.fx,
        "PUT",
        &format!(
            "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
            w.a.id, w.role_mine_a, w.case
        ),
        Some(json!({
            "can_read": true,
            "conditions": [{"field": "portal_user_ref", "operator": "eq", "value_ref": "@portal_user.id"}],
            "fields": [{"field": "portal_user_ref", "can_read": true}],
        })),
    )
    .await;
    let (status, record) = get(url(&mine)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(record["data"].get("title").is_none(), "{record}");
}

// ── G-14: the portal user data export (Phase 13 step 6) ──────────────────────

/// G-14: the admin export is the DSR access fulfillment, not a second
/// exporter: it records an `access` request under the user's email, exports
/// the profile and the consent history (a supplement, since
/// `webportal_consent` is an infrastructure table) as checksummed NDJSON,
/// marks the request fulfilled and writes one `Security`/`Export` event. A
/// user of another portal is a uniform 404, and so is an erased user.
#[tokio::test]
async fn g14_admin_export_is_the_dsr_access_fulfillment() {
    if std::env::var("S3_ACCESS_KEY").is_err() || std::env::var("S3_SECRET_KEY").is_err() {
        eprintln!("SKIP g14: set S3_ACCESS_KEY/S3_SECRET_KEY to a live RustFS credential");
        return;
    }
    let w = skip_if_no_db!(world().await);
    sqlx::query(
        "INSERT INTO webportal_consent (id, webportal_id, webportal_user_id, terms_version, privacy_version) VALUES ($1, $2, $3, 'terms-1', 'privacy-1')",
    )
    .bind(Uuid::now_v7())
    .bind(w.a.id)
    .bind(w.a1.user)
    .execute(&w.fx.base.db)
    .await
    .unwrap();

    let uri =
        |portal: Uuid, user: Uuid| format!("/api/v1/admin/webportals/{portal}/users/{user}/export");
    // Another portal's user, through this portal's id: the uniform 404.
    let (status, _) = admin_status(&w.fx, "POST", &uri(w.a.id, w.b1.user), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let result = admin(&w.fx, "POST", &uri(w.a.id, w.a1.user), None).await;
    assert_eq!(result["status"], "fulfilled", "{result}");
    let scope = |name: &str| {
        result["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["entity_logicalname"] == name)
            .unwrap_or_else(|| panic!("no {name} scope in {result}"))
            .clone()
    };
    let profile = scope("webportal_user");
    assert_eq!(profile["exported_rows"], 1, "{profile}");
    assert_eq!(profile["checksum"].as_str().map(str::len), Some(64));
    let consent = scope("webportal_consent");
    assert_eq!(consent["exported_rows"], 1, "{consent}");
    assert!(
        consent["object_key"]
            .as_str()
            .unwrap()
            .ends_with("/webportal_consent.ndjson")
    );

    // The DSR request is the evidence: fulfilled, subject = the user's email.
    let request_id = Uuid::parse_str(result["id"].as_str().unwrap()).unwrap();
    let (subject, status, kind): (String, String, String) = sqlx::query_as(
        "SELECT subject_reference, status, request_type FROM dsr_request WHERE id = $1",
    )
    .bind(request_id)
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(
        (subject.as_str(), status.as_str(), kind.as_str()),
        (w.a1.email.as_str(), "fulfilled", "access")
    );

    // Erased users are gone from the export too.
    admin(
        &w.fx,
        "POST",
        &format!(
            "/api/v1/admin/webportals/{}/users/{}/erase",
            w.a.id, w.a2.user
        ),
        None,
    )
    .await;
    let (status, _) = admin_status(&w.fx, "POST", &uri(w.a.id, w.a2.user), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── C9: the staff task walk (Phase 13 step 6) ────────────────────────────────

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

/// C9 (plan §1): staff run a portal without hand-written API calls — create
/// portal → role → grant → invite. Every staff request below is the exact
/// request (method, path, body shape, and the reloads it triggers) that one
/// control of `@attome/xrm/portal`'s `PortalAdminComponent` sends through
/// `PortalAdminService`; the walk then proves the result works end to end
/// for the invited person (emailed link → accept → login → create → list).
/// The entity and the owning team exist beforehand (the world's case entity,
/// built through the staff entity admin API): C9's task starts at "create
/// portal". The human-time half of C9 (≤ 5 minutes in a browser) is an owner
/// walk; this pins the request sequence those screens depend on.
#[tokio::test]
async fn c9_staff_create_portal_role_grant_invite_walk() {
    let w = skip_if_no_db!(world().await);
    let fx = &w.fx;
    let base = "/api/v1/admin/webportals";
    let started = std::time::Instant::now();
    let reload = |id: Uuid| async move {
        // `refreshPortal()`: the four lists the screen reloads after each save.
        for tail in [
            "users?page=1&page_size=200",
            "roles",
            "entities",
            "erasure-requests?page=1&page_size=200",
        ] {
            admin(fx, "GET", &format!("{base}/{id}/{tail}"), None).await;
        }
    };

    // Open the screen: `listPortals()`.
    admin(fx, "GET", &format!("{base}?page=1&page_size=200"), None).await;

    // 1. "Create portal" form (`createPortal()`), then `select()`.
    let keyword = format!("c9-{}", short());
    let portal = admin(
        fx,
        "POST",
        base,
        Some(json!({
            "name": "C9 customers",
            "keyword": keyword,
            "portal_type": "authenticated",
            "is_enabled": true,
            "owning_team_ref": w.team,
        })),
    )
    .await;
    let pid = id_of(&portal);
    assert_eq!(portal["keyword"], keyword);
    reload(pid).await;

    // Entity settings form (`saveEntityConfig()`): portal creates stamp the
    // portal user on `portal_user_ref`.
    admin(
        fx,
        "PUT",
        &format!("{base}/{pid}/entities/{}", w.case),
        Some(json!({"portal_user_field": "portal_user_ref"})),
    )
    .await;
    reload(pid).await;

    // 2. "Create role" (`createRole()`), which opens the role (`getRole()`).
    let role = admin(
        fx,
        "POST",
        &format!("{base}/{pid}/roles"),
        Some(json!({"name": "customers"})),
    )
    .await;
    let rid = id_of(&role);
    reload(pid).await;
    let opened = admin(fx, "GET", &format!("{base}/{pid}/roles/{rid}"), None).await;
    assert_eq!(opened["grants"], json!([]));

    // 3. Grant editor (`saveGrant()`), in `grantBody()`'s shape: one
    // condition whose value starts `@portal_user.` (a bound reference) and
    // the field-profile grid rows.
    admin(
        fx,
        "PUT",
        &format!("{base}/{pid}/roles/{rid}/grants/{}", w.case),
        Some(json!({
            "can_read": true, "can_create": true, "can_update": true, "can_delete": false,
            "conditions": [{"field": "portal_user_ref", "operator": "eq", "value_ref": "@portal_user.id"}],
            "fields": [
                {"field": "title", "can_read": true, "can_write": true, "can_filter": true},
                {"field": "portal_user_ref", "can_read": true, "can_write": false, "can_filter": false},
            ],
        })),
    )
    .await;
    let opened = admin(fx, "GET", &format!("{base}/{pid}/roles/{rid}"), None).await;
    let grants = opened["grants"].as_array().expect("grants");
    assert_eq!(grants.len(), 1, "{opened}");
    assert_eq!(grants[0]["entity"], w.case.as_str());
    assert_eq!(grants[0]["public"], false);

    // 4. "Add user" (`createUser()`), role picker (`assignRole()`), then
    // "Invite" (`invite()`).
    let email = format!("c9-{}@example.com", Uuid::now_v7().simple());
    let user = admin(
        fx,
        "POST",
        &format!("{base}/{pid}/users"),
        Some(json!({"name": "C9 Customer", "email": email})),
    )
    .await;
    let uid = id_of(&user);
    assert_eq!(user["status"], "invited");
    admin(
        fx,
        "PUT",
        &format!("{base}/{pid}/users/{uid}/role"),
        Some(json!({"role_id": rid})),
    )
    .await;
    reload(pid).await;
    let cookie = format!("__Host-session_token={}", fx.admin_token);
    let (status, _, text) = send(
        fx,
        portal_req(
            "POST",
            &format!("{base}/{pid}/users/{uid}/invite"),
            &[cookie],
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "invite: {text}");
    let sent: Value = serde_json::from_str(&text).unwrap();
    assert!(sent["expires_at"].is_string(), "{sent}");
    let staff_elapsed = started.elapsed();
    eprintln!(
        "C9 walk: staff side (26 admin requests) took {} ms",
        staff_elapsed.as_millis()
    );
    assert!(staff_elapsed < std::time::Duration::from_secs(300));

    // The invited person: emailed link → accept → login → first record.
    let token = emailed_token(fx, &email, "accept-invitation")
        .await
        .expect("an invitation link was emailed");
    let (status, _, text) = send(
        fx,
        portal_req(
            "POST",
            &format!("/{keyword}/api/v1/auth/invitation/accept"),
            &[],
            Some(json!({"token": token, "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "accept: {text}");
    let (status, cookies, text) = send(
        fx,
        portal_req(
            "POST",
            &format!("/{keyword}/api/v1/auth/login"),
            &[],
            Some(json!({"email": email, "password": PASSWORD})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login: {text}");
    let session = cookies
        .into_iter()
        .find(|c| c.contains("_session="))
        .expect("session cookie");
    let me = Session {
        user: uid,
        email: email.clone(),
        cookie: session,
    };
    let p = Portal {
        id: pid,
        keyword: keyword.clone(),
    };
    let (status, created) = as_user(
        &w,
        &me,
        "POST",
        &records(&p, &w.case),
        Some(json!({"title": "c9 first case"})),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create: {created}");
    assert_eq!(created["data"]["portal_user_ref"], me.user.to_string());
    let (status, list) = as_user(&w, &me, "GET", &records(&p, &w.case), None, None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(titles(&list), vec!["c9 first case".to_owned()]);

    // The users list the screen shows now reads "active".
    let users = admin(
        fx,
        "GET",
        &format!("{base}/{pid}/users?page=1&page_size=200"),
        None,
    )
    .await;
    assert_eq!(users["items"][0]["status"], "active", "{users}");
    assert_eq!(users["items"][0]["email"], me.email.as_str());
}

// ── T-36: revocation races (plan §6.1, C5) ────────────────────────────────────

/// Waits until some statement in this database is waiting on a lock, i.e. the
/// parked write has passed authentication and plan building and is blocked on
/// the held row.
async fn wait_for_a_lock_waiter(fx: &Fx) -> bool {
    for _ in 0..400 {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid \
             WHERE NOT l.granted AND a.datname = current_database()",
        )
        .fetch_one(&fx.base.db)
        .await
        .unwrap();
        if waiting > 0 {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    false
}

/// Parks a `PATCH` by `who` on their own new case inside its write
/// transaction (a held `FOR UPDATE` on the row: the request is already past
/// `auth::resolve_principal` and has its plan), runs `revoke` to completion,
/// releases the row and returns the parked request's status and the case's
/// record URI.
///
/// The window is short on purpose: every pool connection carries the 500 ms
/// role-level `statement_timeout` (`attome_db::pool`), so a write parked longer
/// is cancelled. `revoke` is timed and the time is in any failure message.
async fn patch_across_a_revocation(
    w: &World,
    who: &Session,
    p: &Portal,
    revoke: impl std::future::Future<Output = ()>,
) -> (StatusCode, String, String) {
    let case = create_case(w, who, p, "t36 before").await;
    let id = case["id"].as_str().unwrap().to_owned();
    let uri = format!("{}/{id}", records(p, &w.case));

    let mut hold = w.fx.base.db.begin().await.unwrap();
    sqlx::query(&format!(
        "SELECT 1 FROM {} WHERE id = $1 FOR UPDATE",
        attome_core::quote_ident(&w.case)
    ))
    .bind(Uuid::parse_str(&id).unwrap())
    .execute(&mut *hold)
    .await
    .unwrap();

    let mut req = portal_req(
        "PATCH",
        &uri,
        std::slice::from_ref(&who.cookie),
        Some(json!({"title": "t36 in flight"})),
    );
    req.headers_mut().insert(
        header::IF_MATCH,
        case["row_version"].to_string().parse().unwrap(),
    );
    let app = w.fx.app.clone();
    let parked = tokio::spawn(async move {
        let res = app.oneshot(req).await.expect("send");
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .expect("body");
        (status, String::from_utf8_lossy(&bytes).into_owned())
    });
    assert!(
        wait_for_a_lock_waiter(&w.fx).await,
        "the PATCH never reached the held row"
    );

    let started = std::time::Instant::now();
    revoke.await;
    let revoke_took = started.elapsed();
    hold.commit().await.unwrap();

    let (status, body) = parked.await.unwrap();
    assert_ne!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "the parked write failed (revoke took {revoke_took:?}; over ~500 ms means the \
         statement_timeout, not the portal): {body}"
    );
    (status, uri, body)
}

/// C5 as a guarantee, not a happy path: a revocation that commits while one
/// of the user's writes is already inside its transaction lets that write
/// finish or refuses it (never a 500, never a partial write), and **every
/// request started after the commit is refused**. Three revocations: disable
/// the user (401 after), unassign the role (404), remove the grant (404).
/// Disable, role assignment and portal liveness are read live on every
/// request, so "after the commit" holds on every node at once; the grant is
/// covered on other nodes by the access-version bump (G-9, and
/// `t36_a_failed_cache_bump_serves_a_removed_field_for_at_most_the_ttl`).
#[tokio::test]
async fn t36_a_revocation_racing_an_in_flight_write() {
    let w = skip_if_no_db!(world().await);
    // A write in flight may complete (C5); a refusal must be a uniform one.
    let in_flight_ok = [
        StatusCode::OK,
        StatusCode::UNAUTHORIZED,
        StatusCode::NOT_FOUND,
    ];

    // Disable a2.
    let (status, uri, body) = patch_across_a_revocation(&w, &w.a2, &w.a, async {
        let mut tx = w.fx.base.db.begin().await.unwrap();
        provision::set_user_enabled(&mut tx, Uuid::now_v7(), w.a.id, w.a2.user, false)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    })
    .await;
    eprintln!("T-36 disable: the in-flight PATCH answered {status}");
    assert!(in_flight_ok.contains(&status), "{status} {body}");
    for (method, body) in [
        ("GET", None),
        ("PATCH", Some(json!({"title": "after disable"}))),
    ] {
        assert_eq!(
            as_user(
                &w,
                &w.a2,
                method,
                &uri,
                body.clone(),
                body.as_ref().map(|_| 1)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED,
            "{method} after the disable committed"
        );
    }

    // Unassign b1's role (portal B).
    let (status, uri, body) = patch_across_a_revocation(&w, &w.b1, &w.b, async {
        let (status, text) = admin_status(
            &w.fx,
            "DELETE",
            &format!(
                "/api/v1/admin/webportals/{}/users/{}/role",
                w.b.id, w.b1.user
            ),
            None,
        )
        .await;
        assert!(status.is_success(), "unassign: {status} {text}");
    })
    .await;
    eprintln!("T-36 unassign: the in-flight PATCH answered {status}");
    assert!(in_flight_ok.contains(&status), "{status} {body}");
    for (method, body) in [
        ("GET", None),
        ("PATCH", Some(json!({"title": "after unassign"}))),
    ] {
        assert_eq!(
            as_user(
                &w,
                &w.b1,
                method,
                &uri,
                body.clone(),
                body.as_ref().map(|_| 1)
            )
            .await
            .0,
            StatusCode::NOT_FOUND,
            "{method} after the unassign committed"
        );
    }

    // Remove role "mine"'s grant on the case entity, under a1.
    let (status, uri, body) = patch_across_a_revocation(&w, &w.a1, &w.a, async {
        let (status, text) = admin_status(
            &w.fx,
            "DELETE",
            &format!(
                "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
                w.a.id, w.role_mine_a, w.case
            ),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "grant removal: {text}");
    })
    .await;
    eprintln!("T-36 grant removal: the in-flight PATCH answered {status}");
    assert!(in_flight_ok.contains(&status), "{status} {body}");
    for (method, body) in [
        ("GET", None),
        ("PATCH", Some(json!({"title": "after grant removal"}))),
    ] {
        assert_eq!(
            as_user(
                &w,
                &w.a1,
                method,
                &uri,
                body.clone(),
                body.as_ref().map(|_| 1)
            )
            .await
            .0,
            StatusCode::NOT_FOUND,
            "{method} after the grant removal committed"
        );
    }
    assert_eq!(
        as_user(
            &w,
            &w.a1,
            "POST",
            &records(&w.a, &w.case),
            Some(json!({"title": "after grant removal"})),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND,
        "and no create either"
    );
}

async fn set_access_version(w: &World, version: &str) {
    w.fx.base
        .redis
        .set(
            attome_portal::cache::ACCESS_VERSION_KEY,
            version,
            Some(std::time::Duration::from_secs(3600)),
        )
        .await
        .unwrap();
}

/// C5's degraded case (§4.2 "Failure"): when the access-version bump after an
/// admin grant change fails, another node may keep serving the old grant from
/// its L1, but for no longer than `cache::TTL_SECS` after the entry was
/// cached. Simulated in-process by putting the old version back after the
/// admin write, which is exactly the state a failed bump leaves in Redis.
#[tokio::test]
async fn t36_a_failed_cache_bump_serves_a_removed_field_for_at_most_the_ttl() {
    let w = skip_if_no_db!(world().await);
    // a1's case is acme's, so a3 (role "company") reads it.
    let case = create_case(&w, &w.a1, &w.a, "t36 cached").await;
    let uri = format!(
        "{}/{}",
        records(&w.a, &w.case),
        case["id"].as_str().unwrap()
    );

    let version = new_access_version(&w).await;
    let cached_at = std::time::Instant::now();
    let (status, record) = as_user(&w, &w.a3, "GET", &uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(record["data"]["title"], "t36 cached", "{record}");

    // Narrow "company": `title` leaves the field profile.
    admin(
        &w.fx,
        "PUT",
        &format!(
            "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
            w.a.id, w.role_company_a, w.case
        ),
        Some(json!({
            "can_read": true,
            "conditions": [{"field": "company_ref", "operator": "eq", "value_ref": "@portal_user.company_ref"}],
            "fields": [{"field": "internal_note", "can_read": true}],
        })),
    )
    .await;
    set_access_version(&w, &version).await;

    let (status, record) = as_user(&w, &w.a3, "GET", &uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    eprintln!(
        "T-36 failed bump: right after the change the removed field is {}",
        if record["data"].get("title").is_some() {
            "still served (stale L1, allowed until the TTL)"
        } else {
            "already gone"
        }
    );

    let ttl = std::time::Duration::from_secs(attome_portal::cache::TTL_SECS + 1);
    if let Some(left) = ttl.checked_sub(cached_at.elapsed()) {
        tokio::time::sleep(left).await;
    }
    let (status, record) = as_user(&w, &w.a3, "GET", &uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        record["data"].get("title").is_none(),
        "the removed field is still served {:?} after it was cached: {record}",
        cached_at.elapsed()
    );
}

// ── Phase 5 metadata and Phase 11 profile edit ────────────────────────────────

fn field_names(view: &Value) -> Vec<String> {
    let mut names: Vec<String> = view["fields"]
        .as_array()
        .unwrap_or_else(|| panic!("no fields: {view}"))
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_owned())
        .collect();
    names.sort();
    names
}

fn field<'a>(view: &'a Value, name: &str) -> &'a Value {
    view["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("no field {name}: {view}"))
}

/// Phase 5 (I-18, C3, C4): portal metadata is built from the caller's plan.
/// The index lists only the entities the role has a grant on; an entity view
/// names only the grant's fields, offers a pick list only onto a target the
/// role reads, and never names a staff, sensitive, file or unlisted field; an
/// entity the caller can't reach is the same 404 as one that doesn't exist.
#[tokio::test]
async fn p5_metadata_is_built_from_the_callers_plan() {
    let w = skip_if_no_db!(world().await);
    let base = format!("/{}/api/v1/metadata", w.a.keyword);

    let (status, index) = as_user(&w, &w.a1, "GET", &base, None, None).await;
    assert_eq!(status, StatusCode::OK, "{index}");
    assert_eq!(index["total"], 2, "{index}");
    assert_eq!(
        (&index["page"], &index["page_size"]),
        (&json!(1), &json!(100))
    );
    let items = index["items"].as_array().unwrap();
    let mut listed: Vec<&str> = items
        .iter()
        .map(|e| e["entity"].as_str().unwrap())
        .collect();
    listed.sort_unstable();
    let mut expected = vec![w.case.as_str(), w.company.as_str()];
    expected.sort_unstable();
    assert_eq!(
        listed, expected,
        "role \"mine\" has grants on these two only"
    );
    let case_entry = items
        .iter()
        .find(|e| e["entity"] == w.case.as_str())
        .unwrap();
    assert_eq!(case_entry["label"], "Case");

    let (status, case) = as_user(&w, &w.a1, "GET", &format!("{base}/{}", w.case), None, None).await;
    assert_eq!(status, StatusCode::OK, "{case}");
    assert_eq!(case["label"], "Case");
    assert_eq!(case["can_create"], true);
    assert_eq!(
        field_names(&case),
        vec!["company_ref", "portal_user_ref", "title"],
        "internal_note, secret, attachment and staff_ref are not in the grant"
    );
    let title = field(&case, "title");
    assert_eq!(title["label"], "Title");
    assert_eq!(title["field_type"], "text");
    assert_eq!(
        (&title["readable"], &title["writable"], &title["filterable"]),
        (&json!(true), &json!(true), &json!(true))
    );
    assert_eq!(
        field(&case, "company_ref")["lookup_entity"],
        w.company.as_str()
    );
    let stamp = field(&case, "portal_user_ref");
    assert_eq!(stamp["writable"], false, "the engine stamps it");
    assert!(stamp["lookup_entity"].is_null(), "{stamp}");

    // Unreachable and missing look the same (C4).
    let (s1, staff) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{base}/user_account"),
        None,
        None,
    )
    .await;
    let (s2, missing) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{base}/no_such_entity"),
        None,
        None,
    )
    .await;
    assert_eq!((s1, s2), (StatusCode::NOT_FOUND, StatusCode::NOT_FOUND));
    assert_eq!(without_request_id(staff), without_request_id(missing));
    // Role "company" has no grant on the company entity.
    assert_eq!(
        as_user(
            &w,
            &w.a3,
            "GET",
            &format!("{base}/{}", w.company),
            None,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // Another portal's session is not a session here.
    assert_eq!(
        as_user(&w, &w.b1, "GET", &base, None, None).await.0,
        StatusCode::UNAUTHORIZED
    );
}

/// Phase 11 (D-588): `PATCH /me` edits only the fields the portal's policy
/// lists, through the engine (row version, audit); identity fields (the name
/// too: owner decision 2026-09-28) and lookups can never be made
/// self-editable, a user edits only their own row, and staff with update
/// rights rename a portal user through the generic entity API.
#[tokio::test]
async fn p11_patch_me_edits_only_the_policy_fields() {
    let w = skip_if_no_db!(world().await);
    let me = format!("/{}/api/v1/me", w.a.keyword);

    let (status, before) = as_user(&w, &w.a1, "GET", &me, None, None).await;
    assert_eq!(status, StatusCode::OK, "{before}");
    assert_eq!(
        before["profile"],
        json!({}),
        "nothing is editable by default"
    );
    let rv = before["row_version"].as_i64().expect("row_version");
    assert_eq!(
        as_user(
            &w,
            &w.a1,
            "PATCH",
            &me,
            Some(json!({"name": "x"})),
            Some(rv)
        )
        .await
        .0,
        StatusCode::FORBIDDEN,
        "no editable field, no edit"
    );

    // A plain custom field on the portal user (shared by the binary's
    // worlds, hence "once").
    add_field_once(
        &w.fx,
        entity_id(&w.fx, "webportal_user").await,
        json!({"logicalname": "phone", "name": "Phone", "field_type": "text"}),
    )
    .await;
    let registry = attome_core::build_registry(&w.fx.base.db).await.unwrap();
    w.fx.xrm.entities.swap(registry);

    // The policy refuses identity (name included: staff rename a portal
    // user), lookup (a scope source) and unknown fields.
    for refused in ["name", "email", "status", "company_ref", "ghost"] {
        let (status, text) = edit_policy(&w.fx, &w.a, |p| {
            p["editable_profile_fields"] = json!([refused]);
        })
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{refused}: {text}"
        );
    }
    let (status, text) = edit_policy(&w.fx, &w.a, |p| {
        p["editable_profile_fields"] = json!(["phone"]);
    })
    .await;
    assert!(status.is_success(), "{status} {text}");

    let (_, before) = as_user(&w, &w.a1, "GET", &me, None, None).await;
    let rv = before["row_version"].as_i64().unwrap();
    assert_eq!(before["profile"], json!({"phone": null}), "{before}");
    assert_eq!(
        as_user(&w, &w.a1, "PATCH", &me, Some(json!({"phone": "1"})), None)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY,
        "If-Match is required"
    );
    for body in [
        json!({"name": "Renamed by me"}),
        json!({"email": "someone.else@example.com"}),
        json!({"company_ref": w.acme}),
        json!({"phone": "1", "status": 2}),
    ] {
        assert_eq!(
            as_user(&w, &w.a1, "PATCH", &me, Some(body.clone()), Some(rv))
                .await
                .0,
            StatusCode::FORBIDDEN,
            "{body}"
        );
    }
    let (status, after) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &me,
        Some(json!({"phone": "+44 20 7946 0000"})),
        Some(rv),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{after}");
    assert_eq!(after["profile"]["phone"], "+44 20 7946 0000");
    assert_eq!(after["name"], before["name"], "name untouched");
    assert_eq!(after["email"], w.a1.email.as_str(), "email untouched");
    let rv2 = after["row_version"].as_i64().unwrap();
    assert!(rv2 > rv);
    assert_eq!(
        as_user(
            &w,
            &w.a1,
            "PATCH",
            &me,
            Some(json!({"phone": "stale"})),
            Some(rv)
        )
        .await
        .0,
        StatusCode::CONFLICT,
        "a stale row_version"
    );
    // Only a1's own row changed.
    let (_, other) = as_user(&w, &w.a2, "GET", &me, None, None).await;
    assert!(other["profile"]["phone"].is_null(), "{other}");

    // Staff with update rights (here a system admin) rename a portal user
    // through the generic entity API; the portal shows the new name.
    let cookie = format!("__Host-session_token={}", w.fx.admin_token);
    let mut req = portal_req(
        "PATCH",
        &format!("/api/v1/webportal_user/{}", w.a1.user),
        &[cookie],
        Some(json!({"name": "Renamed by staff"})),
    );
    req.headers_mut()
        .insert(header::IF_MATCH, format!("\"{rv2}\"").parse().unwrap());
    let (status, _, text) = send(&w.fx, req).await;
    assert!(status.is_success(), "staff rename: {status} {text}");
    let (_, renamed) = as_user(&w, &w.a1, "GET", &me, None, None).await;
    assert_eq!(renamed["name"], "Renamed by staff", "{renamed}");
}

// ── D-774: portal uploads through the shared file pipeline ────────────────────

/// D-774 (Phase 5): a portal user uploads to a file field their role can
/// write, on a record in their scope, through the staff pipeline with
/// themselves as the session's owner. Another user, a read-only role, a
/// non-file field and a disallowed type are refused; a session can't be
/// finalized or polled by someone else; the record can name only a clean
/// session this portal user owns (never an unscanned one, never a staff one);
/// and the file version records the portal user as the uploader. The scan
/// job's promotion is simulated in this throwaway database (no clamd here).
#[tokio::test]
async fn u1_portal_upload_through_the_shared_pipeline() {
    let w = skip_if_no_db!(world().await);
    admin(
        &w.fx,
        "PUT",
        &format!(
            "/api/v1/admin/webportals/{}/roles/{}/grants/{}",
            w.a.id, w.role_mine_a, w.case
        ),
        Some(json!({
            "can_read": true, "can_create": true, "can_update": true, "can_delete": true,
            "conditions": [{"field": "portal_user_ref", "operator": "eq", "value_ref": "@portal_user.id"}],
            "fields": [
                {"field": "title", "can_read": true, "can_write": true, "can_filter": true},
                {"field": "company_ref", "can_read": true, "can_write": true},
                {"field": "portal_user_ref", "can_read": true},
                {"field": "attachment", "can_read": true, "can_write": true},
            ],
        })),
    )
    .await;
    let mine = create_case(&w, &w.a1, &w.a, "upload here").await;
    let id = mine["id"].as_str().unwrap().to_owned();
    let record = format!("{}/{id}", records(&w.a, &w.case));
    let start = format!("{record}/files/attachment/upload-session");
    let pdf = json!({"filename": "report.pdf", "content_type": "application/pdf", "declared_size_bytes": 10});

    // Who may start an upload.
    for (who, uri, body, expected) in [
        (&w.a2, start.clone(), pdf.clone(), StatusCode::NOT_FOUND),
        (&w.a3, start.clone(), pdf.clone(), StatusCode::NOT_FOUND),
        (
            &w.a1,
            format!("{record}/files/title/upload-session"),
            pdf.clone(),
            StatusCode::NOT_FOUND,
        ),
        (
            &w.a1,
            start.clone(),
            json!({"filename": "x.html", "content_type": "text/html", "declared_size_bytes": 10}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let (status, text) = as_user(&w, who, "POST", &uri, Some(body), None).await;
        assert_eq!(status, expected, "{uri}: {text}");
    }
    let (status, session) = as_user(&w, &w.a1, "POST", &start, Some(pdf.clone()), None).await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let session_id = session["session_id"].as_str().unwrap().to_owned();
    assert!(
        session["upload_url"]
            .as_str()
            .is_some_and(|u| u.contains("_quarantine")),
        "{session}"
    );
    let owners: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT owner_user_ref, owner_portal_user_ref FROM upload_session WHERE id = $1",
    )
    .bind(Uuid::parse_str(&session_id).unwrap())
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(
        owners,
        (None, Some(w.a1.user)),
        "owned by the portal user alone"
    );

    // Polling and finalizing are the owner's own.
    let status_uri = format!("{start}/{session_id}");
    let (status, polled) = as_user(&w, &w.a1, "GET", &status_uri, None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(polled["status"], "pending");
    assert_eq!(
        as_user(&w, &w.a2, "GET", &status_uri, None, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        as_user(
            &w,
            &w.a2,
            "POST",
            &format!("{status_uri}/finalize"),
            None,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    // An unscanned session can't reach the record.
    let quarantine: String =
        sqlx::query_scalar("SELECT quarantine_key FROM upload_session WHERE id = $1")
            .bind(Uuid::parse_str(&session_id).unwrap())
            .fetch_one(&w.fx.base.db)
            .await
            .unwrap();
    let rv = mine["row_version"].as_i64();
    let (status, _) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &record,
        Some(json!({"attachment": quarantine})),
        rv,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "not clean yet");

    // What the scan job does on a clean result.
    let final_key = quarantine.trim_start_matches("_quarantine/").to_owned();
    sqlx::query(
        "UPDATE upload_session SET status = 'clean', final_key = $2, \
         actual_size_bytes = 10, actual_content_type = 'application/pdf' WHERE id = $1",
    )
    .bind(Uuid::parse_str(&session_id).unwrap())
    .bind(&final_key)
    .execute(&w.fx.base.db)
    .await
    .unwrap();
    let (_, polled) = as_user(&w, &w.a1, "GET", &status_uri, None, None).await;
    assert_eq!(polled["final_key"], final_key.as_str(), "{polled}");
    // Even clean, the quarantine key (the user's PUT target, re-PUTtable
    // until it expires) never reaches the record: only the promoted key.
    let (status, _) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &record,
        Some(json!({"attachment": quarantine})),
        rv,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "quarantine key refused"
    );

    // A clean staff-owned session for the same field is not the portal's.
    let staff: Uuid = sqlx::query_scalar("SELECT id FROM user_account LIMIT 1")
        .fetch_one(&w.fx.base.db)
        .await
        .unwrap();
    let staff_key = format!("{}/{id}/attachment/{}-staff.pdf", w.case, Uuid::now_v7());
    sqlx::query(
        "INSERT INTO upload_session (entity_logicalname, record_id, field_logicalname, \
         owner_user_ref, quarantine_key, final_key, declared_filename, declared_content_type, \
         declared_max_size_bytes, actual_size_bytes, status) \
         VALUES ($1, $2, 'attachment', $3, $4, $4, 'staff.pdf', 'application/pdf', 10, 10, 'clean')",
    )
    .bind(&w.case)
    .bind(Uuid::parse_str(&id).unwrap())
    .bind(staff)
    .bind(&staff_key)
    .execute(&w.fx.base.db)
    .await
    .unwrap();
    let (status, _) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &record,
        Some(json!({"attachment": staff_key})),
        rv,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a staff upload is not the portal user's"
    );

    // The portal user's own clean upload goes onto the record.
    let (status, updated) = as_user(
        &w,
        &w.a1,
        "PATCH",
        &record,
        Some(json!({"attachment": final_key})),
        rv,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["data"]["attachment"], final_key.as_str());
    let version: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
        "SELECT uploaded_by, uploaded_by_portal_user FROM file_version \
         WHERE record_id = $1 AND field = 'attachment' AND is_current",
    )
    .bind(Uuid::parse_str(&id).unwrap())
    .fetch_one(&w.fx.base.db)
    .await
    .unwrap();
    assert_eq!(
        version,
        (None, Some(w.a1.user)),
        "the version names the portal uploader"
    );
    let (status, url) = as_user(
        &w,
        &w.a1,
        "GET",
        &format!("{record}/files/attachment"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{url}");

    // Finalizing a session whose bytes never arrived rejects it.
    let (_, second) = as_user(&w, &w.a1, "POST", &start, Some(pdf), None).await;
    let second_id = second["session_id"].as_str().unwrap();
    let (status, finalized) = as_user(
        &w,
        &w.a1,
        "POST",
        &format!("{start}/{second_id}/finalize"),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{finalized}");
    assert_eq!(finalized["status"], "rejected");
}

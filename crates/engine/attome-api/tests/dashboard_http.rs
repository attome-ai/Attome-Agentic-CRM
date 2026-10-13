//! R-16 (`document/module-master-plans/M26-dashboard-remediation.md`) — HTTP
//! coverage for every bespoke `attome-dashboard` route: 401 (no credentials),
//! 403 (credentials but lacking the route's compile-time privilege), 404
//! (R-04 record-level denial), and a real 200/201/202/204 happy path, plus
//! the D-195 four-eyes gate on `publish`.
//!
//! Harness copied near-verbatim from `dashboard_access.rs` (this crate's
//! established per-test-file convention for exercising `attome-dashboard`
//! through the real HTTP stack) — `parse_db_url`/`test_config` resolve real
//! throwaway-clone credentials (not the `"unused"`/`5555` placeholder
//! `dashboard_migration.rs` used to carry, see that file's own comment on why
//! that broke `sync_attribute_index`'s migrator connection), and
//! `create_role`/`grant_privileges`/`scope_role_for_entity`/
//! `share_record_with_owner` reproduce D-133's real role/privilege/
//! entity-access-depth/record-share plumbing rather than trusting an
//! all-privileged `SecurityContext`.
//!
//! **Coverage strategy, not "one test per route".** Every bespoke route in
//! this crate authorizes with exactly one of two shapes: a compile-time
//! `Authorized<Privilege<X>>` extractor (checked BEFORE the handler body, and
//! therefore before any path/body parsing — see each handler's argument
//! order in `attome-dashboard/src`), and then, for routes that resolve a
//! specific record, one of two record-level checks — `access::
//! require_dashboard_access`/`require_entity_access` (R-04). That means:
//!
//! - **401** is identical for every route (the auth extractor rejects
//!   before anything else runs) — one table-driven test covers all 25.
//! - **403** is identical for every route sharing a privilege type — one
//!   table-driven test, keyed by `(method, uri)`, covers all 25 with one
//!   privilege-less caller.
//! - **404** is the SAME function call for every route in a given group
//!   (`require_dashboard_access` for every `attome-dashboard/{id}/...` route,
//!   `require_entity_access(.., "dashboard_decision", ..)` for decision approve,
//!   `require_entity_access(.., "dashboard_scenario", ..)` for scenario routes) —
//!   `dashboard_access.rs` already proves this for `publish` and
//!   `widget/duplicate`; this file adds one representative test per
//!   remaining group (dashboard-Update via `archive`, dashboard-Read via
//!   `health-check`, decision via
//!   `decisions/{id}/approve`, scenario via `scenario/evaluate` and
//!   `scenario/compare`) rather than repeating the same assertion 21 times.
//! - **200/201/202/204** happy paths are grouped by natural sequence
//!   (lifecycle state machine, widget duplicate, decision +
//!   scenario, health/context, create-from-layout) as an admin caller, who
//!   bypasses record-level scoping — this proves the real HTTP wiring calls
//!   into the same `do_*` functions `dashboard_crud.rs`/`widget_actions.rs`/
//!   `scenario.rs`'s own direct-call suites already exercise in depth.
//!
//! The freeform-only `widget/{group,ungroup,align}` routes (M26 R-15) were
//! deleted outright (D-790), so they are no longer in the route table.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test dashboard_http -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_server::AppState;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness (see `dashboard_access.rs`'s identical helpers for the doc
// comments this file omits to avoid repeating them) ─────────────────────────

/// `required_actions` — same D-195 knob `approval_query_publish.rs` exposes,
/// empty by default (ungated).
fn test_config(db: &DbUrlParts, required_actions: &[&str]) -> AppConfig {
    let required_actions_json = serde_json::to_string(required_actions).unwrap();
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 4194304, "request_timeout_secs": 15,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0,
                "migrator": {{ "user": "{db_user}", "password": "{db_password}" }}
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
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}} }},
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
            "approval": {{ "required_actions": {required_actions_json} }}
        }}"#,
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system(required_actions: &[&str]) -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let db_parts = DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse");

    let config = test_config(&db_parts, required_actions);
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
        config,
        db,
        db_readonly,
        db_migrator,
        redis,
        redis_coordination,
        storage,
    );
    let state = attome_core::EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        .register(attome_dashboard::DashboardModel)
        .build()
        .await
        .expect("build EngineSystem");
    system
        .state()
        .modules
        .store(std::sync::Arc::new(attome_modules::ModuleSet::from_bits(
            [u64::MAX; 4],
        )));

    Some(system)
}

fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
}

fn session_cookie(user_id: Uuid) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = attome_auth::SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + 3600,
        jti: Uuid::now_v7(),
        epoch: 0,
        iss: "attome-test".into(),
        aud: "attome-test".into(),
        typ: attome_auth::TokenType::Session,
    };
    let signing_ring = KeyRing::single(THROWAWAY_JWT_SECRET.to_string());
    let token = attome_auth::create_token(&claims, &signing_ring).expect("encode throwaway jwt");
    format!("{}={token}", attome_auth::cookie::session_cookie_name(true))
}

async fn seed_user(system: &EngineSystem, admin: bool) -> (Uuid, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("dashhttp-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("dashhttp-test-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");

    if admin {
        let privilege_id: Uuid =
            sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
                .fetch_one(db)
                .await
                .expect("system.admin privilege must already be seeded by attome_security::seed");
        sqlx::query(
            "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
             VALUES ($1, $2, $3, true, NOW())",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("insert throwaway admin grant");
    }

    (user_id, session_cookie(user_id))
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 16 * 1024 * 1024).await.unwrap();
    serde_json::from_slice(&bytes).expect("response body must be JSON")
}

fn req(method: &str, uri: &str, cookie: Option<&str>, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

async fn create_role(db: &PgPool) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("dashhttp-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");
    role_id
}

async fn grant_privileges(db: &PgPool, role_id: Uuid, logicalname: &str, actions: &[&str]) {
    for action in actions {
        let key = format!("{logicalname}.{action}");
        let privilege_id: Uuid = sqlx::query_scalar(
            "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
             VALUES ($1, $2, $3, $3, true, NOW(), 'project') \
             ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(&key)
        .bind(&key)
        .fetch_one(db)
        .await
        .expect("ensure privilege");

        sqlx::query(
            "INSERT INTO role_mm_privilege (id, role_ref, privilege_ref, owner_layer) VALUES ($1, $2, $3, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(role_id)
        .bind(privilege_id)
        .execute(db)
        .await
        .expect("grant role privilege");
    }
}

async fn assign_role_to_user(db: &PgPool, user_id: Uuid, role_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role to user");
}

async fn scope_role_for_entity(
    db: &PgPool,
    security: &attome_server::security::SecurityResolverHandle,
    role_id: Uuid,
    user_id: Uuid,
    entity_id: Uuid,
    access_level: i16,
) {
    sqlx::query(
        r#"
        INSERT INTO role_mm_entity_access
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer)
        VALUES ($1, $2, $3, $4, $4, $4, 'project')
        ON CONFLICT (role_ref, entity_ref) DO UPDATE SET
            read_access_level = EXCLUDED.read_access_level,
            write_access_level = EXCLUDED.write_access_level,
            delete_access_level = EXCLUDED.delete_access_level,
            is_deleted = false,
            updated_at = NOW()
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_id)
    .bind(access_level)
    .execute(db)
    .await
    .expect("upsert role entity-access grant");

    security.invalidate(user_id).await;
}

async fn entity_id_for(db: &PgPool, logicalname: &str) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .expect("entity must already be provisioned by attome_dashboard::seed")
}

async fn share_record_with_owner(db: &PgPool, entity_ref: Uuid, record_id: Uuid, owner_id: Uuid) {
    sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 1)",
    )
    .bind(record_id)
    .bind(entity_ref)
    .bind(owner_id)
    .execute(db)
    .await
    .expect("insert owner record share");
}

// ── Fixture data helpers ────────────────────────────────────────────────────

async fn insert_dashboard(db: &PgPool, owner_id: Uuid, name: &str) -> (Uuid, i64) {
    let id = Uuid::now_v7();
    let (row_version,): (i64,) = sqlx::query_as(
        "INSERT INTO attome_dashboard (id, name, dashboard_type, owner_id, is_active) \
         VALUES ($1, $2, 'personal', $3, true) RETURNING row_version",
    )
    .bind(id)
    .bind(name)
    .bind(owner_id)
    .fetch_one(db)
    .await
    .expect("insert test attome_dashboard row");
    (id, row_version)
}

async fn insert_page(db: &PgPool, dashboard_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO dashboard_page (id, dashboard_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(dashboard_id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert test dashboard_page row");
    id
}

async fn insert_section(db: &PgPool, page_id: Uuid, layout_mode: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_section (id, page_id, section_type, layout_mode) \
         VALUES ($1, $2, 'container', $3)",
    )
    .bind(id)
    .bind(page_id)
    .bind(layout_mode)
    .execute(db)
    .await
    .expect("insert test dashboard_section row");
    id
}

#[allow(clippy::too_many_arguments)]
async fn insert_widget(
    db: &PgPool,
    section_id: Uuid,
    name: &str,
    x: Option<f64>,
    y: Option<f64>,
    width: Option<f64>,
    height: Option<f64>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_widget \
         (id, section_id, widget_type, name, freeform_x, freeform_y, freeform_width, freeform_height) \
         VALUES ($1, $2, 'rich_text', $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(section_id)
    .bind(name)
    .bind(x)
    .bind(y)
    .bind(width)
    .bind(height)
    .execute(db)
    .await
    .expect("insert test dashboard_widget row");
    id
}

/// Bare `dashboard_decision` row — `status` defaults NULL/`"proposed"` per
/// `decision.rs::load_decision_state`.
async fn insert_decision(db: &PgPool, title: &str) -> (Uuid, i64) {
    let id = Uuid::now_v7();
    let (row_version,): (i64,) = sqlx::query_as(
        "INSERT INTO dashboard_decision (id, title, status) VALUES ($1, $2, 'proposed') \
         RETURNING row_version",
    )
    .bind(id)
    .bind(title)
    .fetch_one(db)
    .await
    .expect("insert test dashboard_decision row");
    (id, row_version)
}

async fn insert_decision_option(db: &PgPool, decision_id: Uuid, label: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_decision_option (id, decision_ref, label) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(decision_id)
    .bind(label)
    .execute(db)
    .await
    .expect("insert test dashboard_decision_option row");
    id
}

async fn get_published(app: &axum::Router, cookie: &str, dashboard_id: Uuid) -> Value {
    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/published"),
            Some(cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    body_json(res).await
}

async fn live_version(db: &PgPool, dashboard_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT published_version_id FROM attome_dashboard WHERE id = $1")
        .bind(dashboard_id)
        .fetch_one(db)
        .await
        .expect("read published_version_id")
}

async fn insert_scenario(db: &PgPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO dashboard_scenario (id, name, status) VALUES ($1, $2, 'draft')")
        .bind(id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert test dashboard_scenario row");
    id
}

/// One dashboard fixture, deep enough for the whole HTTP surface: a page, a
/// freeform section with two positioned widgets (group/ungroup/align need a
/// non-empty selection; align needs >= 2 with a set freeform position), owned
/// by `owner_id` and shared with them (D-133's implicit creator-share,
/// reproduced by hand since these rows bypass the generic entity API — same
/// convention `dashboard_access.rs::share_record_with_owner`'s own doc
/// comment documents).
// `#[allow(dead_code)]` — not every field this fixture builds is read by
// every test that constructs one (`section_id`/`widget_b` are read by some
// call sites, e.g. a future widget-scoped 404 test, but not the ones in this
// file today) — same "shared fixture, partial per-test use" shape
// `attome-dashboard/tests/common/mod.rs`'s own `#[allow(dead_code)]` helpers
// document.
#[allow(dead_code)]
struct DashboardFixture {
    dashboard_id: Uuid,
    row_version: i64,
    section_id: Uuid,
    widget_a: Uuid,
    widget_b: Uuid,
}

async fn build_dashboard_fixture(
    db: &PgPool,
    dashboard_entity_id: Uuid,
    owner_id: Uuid,
    name: &str,
) -> DashboardFixture {
    let (dashboard_id, row_version) = insert_dashboard(db, owner_id, name).await;
    share_record_with_owner(db, dashboard_entity_id, dashboard_id, owner_id).await;
    let page_id = insert_page(db, dashboard_id, "Overview").await;
    let section_id = insert_section(db, page_id, "freeform").await;
    let widget_a = insert_widget(
        db,
        section_id,
        "Widget A",
        Some(0.0),
        Some(0.0),
        Some(100.0),
        Some(50.0),
    )
    .await;
    let widget_b = insert_widget(
        db,
        section_id,
        "Widget B",
        Some(200.0),
        Some(0.0),
        Some(100.0),
        Some(50.0),
    )
    .await;
    DashboardFixture {
        dashboard_id,
        row_version,
        section_id,
        widget_a,
        widget_b,
    }
}

/// A fully-privileged (create/read/update on every entity this crate's
/// bespoke routes touch), `User`-depth ("own records only") role, assigned to
/// two callers `A`/`B` — same shape as `dashboard_access.rs::build_fixture`.
#[allow(dead_code)]
struct Fixture {
    db: PgPool,
    cookie_a: String,
    user_a: Uuid,
    cookie_b: String,
    user_b: Uuid,
    admin_cookie: String,
    dashboard_entity_id: Uuid,
    decision_entity_id: Uuid,
    scenario_entity_id: Uuid,
}

async fn build_fixture(system: &EngineSystem) -> Fixture {
    let db = system.state().base.db.clone();
    let security = system.state().base.security.clone();

    let (_admin_id, admin_cookie) = seed_user(system, true).await;
    let (user_a, cookie_a) = seed_user(system, false).await;
    let (user_b, cookie_b) = seed_user(system, false).await;

    let role_id = create_role(&db).await;
    grant_privileges(
        &db,
        role_id,
        "attome_dashboard",
        &["create", "read", "update"],
    )
    .await;
    grant_privileges(&db, role_id, "dashboard_page", &["create", "read"]).await;
    grant_privileges(&db, role_id, "dashboard_section", &["create", "read"]).await;
    grant_privileges(
        &db,
        role_id,
        "dashboard_widget",
        &["create", "read", "update"],
    )
    .await;
    grant_privileges(
        &db,
        role_id,
        "dashboard_decision",
        &["create", "read", "update"],
    )
    .await;
    grant_privileges(
        &db,
        role_id,
        "dashboard_scenario",
        &["create", "read", "update"],
    )
    .await;
    assign_role_to_user(&db, user_a, role_id).await;
    assign_role_to_user(&db, user_b, role_id).await;

    let dashboard_entity_id = entity_id_for(&db, "attome_dashboard").await;
    let decision_entity_id = entity_id_for(&db, "dashboard_decision").await;
    let scenario_entity_id = entity_id_for(&db, "dashboard_scenario").await;
    for entity_id in [dashboard_entity_id, decision_entity_id, scenario_entity_id] {
        scope_role_for_entity(&db, &security, role_id, user_a, entity_id, 0).await;
        scope_role_for_entity(&db, &security, role_id, user_b, entity_id, 0).await;
    }

    Fixture {
        db,
        cookie_a,
        user_a,
        cookie_b,
        user_b,
        admin_cookie,
        dashboard_entity_id,
        decision_entity_id,
        scenario_entity_id,
    }
}

// ── 401: every bespoke route requires authentication ────────────────────────

/// `(method, uri)` for all 25 bespoke `attome-dashboard` routes. Real-looking
/// but nonexistent ids are fine — the `Authorized<...>` extractor rejects
/// before the handler ever parses `Path`/`Json` (see this file's module doc
/// comment), so the same table drives both the 401 and 403 tests below.
fn all_bespoke_routes() -> Vec<(&'static str, String)> {
    let id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    vec![
        (
            "POST",
            format!("/api/v1/attome-dashboard/{id}/submit-review"),
        ),
        ("POST", format!("/api/v1/attome-dashboard/{id}/approve")),
        ("POST", format!("/api/v1/attome-dashboard/{id}/reject")),
        ("POST", format!("/api/v1/attome-dashboard/{id}/publish")),
        ("POST", format!("/api/v1/attome-dashboard/{id}/unpublish")),
        ("POST", format!("/api/v1/attome-dashboard/{id}/archive")),
        ("POST", format!("/api/v1/attome-dashboard/{id}/clone")),
        (
            "POST",
            format!("/api/v1/attome-dashboard/{id}/versions/{version_id}/restore"),
        ),
        ("POST", "/api/v1/attome-dashboard/from-layout".to_string()),
        ("GET", "/api/v1/attome-dashboard/widget-types".to_string()),
        (
            "POST",
            "/api/v1/attome-dashboard/widget/duplicate".to_string(),
        ),
        (
            "POST",
            "/api/v1/attome-dashboard/widget/validate-config".to_string(),
        ),
        (
            "POST",
            format!("/api/v1/attome-dashboard/{id}/resolve-variables"),
        ),
        ("GET", format!("/api/v1/attome-dashboard/{id}/health-check")),
        // Dashboard 10/10 plan Phase 1 (D-520, D-521, D-527).
        ("POST", format!("/api/v1/attome-dashboard/{id}/pages")),
        (
            "POST",
            format!("/api/v1/attome-dashboard/{id}/pages/{version_id}/root-section"),
        ),
        ("GET", format!("/api/v1/attome-dashboard/{id}/tree")),
        (
            "POST",
            format!("/api/v1/attome-dashboard/{id}/start-revision"),
        ),
        (
            "POST",
            format!("/api/v1/attome-dashboard/{id}/versions/{version_id}/activate"),
        ),
        ("GET", format!("/api/v1/attome-dashboard/{id}/published")),
        (
            "POST",
            format!("/api/v1/attome-dashboard/{id}/widgets/{version_id}/data"),
        ),
        ("POST", format!("/api/v1/decisions/{id}/approve")),
        ("POST", format!("/api/v1/scenarios/{id}/evaluate")),
        ("GET", format!("/api/v1/scenarios/{id}/compare")),
        ("POST", format!("/api/v1/scenarios/{id}/clone")),
    ]
}

#[tokio::test]
async fn every_bespoke_route_requires_authentication() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let app = full_app(system);

    for (method, uri) in all_bespoke_routes() {
        let res = app
            .clone()
            .oneshot(req(method, &uri, None, None))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri} must 401 with no credentials"
        );
    }
}

/// Same table, minus `widget-types` (`SelfService` — authenticated-only, no
/// further privilege, so it has no 403 case): an authenticated caller
/// assigned to a role with ZERO privileges must be refused before the
/// handler ever resolves a record.
#[tokio::test]
async fn every_bespoke_route_requires_its_privilege() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let db = system.state().base.db.clone();
    let (user_id, cookie) = seed_user(&system, false).await;
    let role_id = create_role(&db).await;
    assign_role_to_user(&db, user_id, role_id).await;
    let app = full_app(system);

    for (method, uri) in all_bespoke_routes() {
        if uri == "/api/v1/attome-dashboard/widget-types" {
            continue;
        }
        let res = app
            .clone()
            .oneshot(req(method, &uri, Some(&cookie), None))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must 403 for a caller with no privileges at all"
        );
    }
}

#[tokio::test]
async fn widget_types_only_requires_authentication_not_a_specific_privilege() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let db = system.state().base.db.clone();
    let (user_id, cookie) = seed_user(&system, false).await;
    let role_id = create_role(&db).await;
    assign_role_to_user(&db, user_id, role_id).await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            "/api/v1/attome-dashboard/widget-types",
            Some(&cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ── 404: representative record-level denial per access-check group ─────────
// (`publish` and `widget/duplicate` are already covered in `dashboard_access.rs`.)

#[tokio::test]
async fn archive_denies_a_dashboard_the_caller_cannot_see() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let fx = build_fixture(&system).await;
    let dash =
        build_dashboard_fixture(&fx.db, fx.dashboard_entity_id, fx.user_a, "A's dashboard").await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{}/archive", dash.dashboard_id),
            Some(&fx.cookie_b),
            Some(&json!({ "row_version": dash.row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_check_denies_a_dashboard_the_caller_cannot_see() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let fx = build_fixture(&system).await;
    let dash =
        build_dashboard_fixture(&fx.db, fx.dashboard_entity_id, fx.user_a, "A's dashboard").await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!(
                "/api/v1/attome-dashboard/{}/health-check",
                dash.dashboard_id
            ),
            Some(&fx.cookie_b),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn decision_approve_denies_a_decision_the_caller_cannot_see() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let fx = build_fixture(&system).await;
    let (decision_id, row_version) = insert_decision(&fx.db, "A's decision").await;
    share_record_with_owner(&fx.db, fx.decision_entity_id, decision_id, fx.user_a).await;
    let option_id = insert_decision_option(&fx.db, decision_id, "Option 1").await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/decisions/{decision_id}/approve"),
            Some(&fx.cookie_b),
            Some(&json!({ "chosen_option_id": option_id, "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn scenario_evaluate_denies_a_scenario_the_caller_cannot_see() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let fx = build_fixture(&system).await;
    let scenario_id = insert_scenario(&fx.db, "A's scenario").await;
    share_record_with_owner(&fx.db, fx.scenario_entity_id, scenario_id, fx.user_a).await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/scenarios/{scenario_id}/evaluate"),
            Some(&fx.cookie_b),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

/// `compare`'s own record-level check (`scenario.rs::do_compare`) runs on
/// EVERY scenario named — the anchor `{id}` and everything in `?with=` —
/// independently, not just the entity-level `dashboard_scenario.read` its
/// compile-time policy already verified.
#[tokio::test]
async fn scenario_compare_denies_when_the_anchor_scenario_is_unreadable() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let fx = build_fixture(&system).await;
    let scenario_id = insert_scenario(&fx.db, "A's scenario").await;
    share_record_with_owner(&fx.db, fx.scenario_entity_id, scenario_id, fx.user_a).await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/scenarios/{scenario_id}/compare"),
            Some(&fx.cookie_b),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

// ── Happy paths (admin, so record-level scoping never blocks) ──────────────

#[tokio::test]
async fn lifecycle_happy_path_through_publish_unpublish_archive_clone_and_restore() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let dashboard_entity_id = entity_id_for(&db, "attome_dashboard").await;
    let (dashboard_id, row_version) =
        insert_dashboard(&db, Uuid::now_v7(), "Lifecycle HTTP Test").await;
    let _ = dashboard_entity_id; // admin bypasses record-level scoping entirely
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/submit-review"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let row_version = body_json(res).await["row_version"].as_i64().unwrap();

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/approve"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let row_version = body_json(res).await["row_version"].as_i64().unwrap();

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/publish"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "ungated publish must be 200");
    let body = body_json(res).await;
    assert_eq!(body["approval_pending"], false);
    let row_version = body["row_version"].as_i64().unwrap();
    let version_id: Uuid = body["version_id"].as_str().unwrap().parse().unwrap();

    // D-521 (Phase 1.3): viewers read the immutable version publish made live.
    let live = get_published(&app, &admin_cookie, dashboard_id).await;
    assert_eq!(live["state"], "published");
    assert_eq!(live["version_id"], version_id.to_string());

    // A new revision returns the working copy to draft; the live version stays.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/start-revision"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["lifecycle_status"], "draft");
    let row_version = body["row_version"].as_i64().unwrap();
    assert_eq!(
        get_published(&app, &admin_cookie, dashboard_id).await["state"],
        "published",
        "start-revision must not take the live version offline"
    );

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/unpublish"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    // Not read again before `restore_version` (which carries no
    // `row_version` guard of its own — see below) supersedes it.
    let body = body_json(res).await;
    assert_eq!(body["lifecycle_status"], "draft");
    let _row_version = body["row_version"].as_i64().unwrap();
    assert_eq!(
        get_published(&app, &admin_cookie, dashboard_id).await["state"],
        "none",
        "unpublish takes the live version offline"
    );

    // `restore_version` is not gated by lifecycle status — exercise it here,
    // still in draft.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/versions/{version_id}/restore"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["restored_from_version"], version_id.to_string());

    // `restore_version`'s response carries no `row_version` (see its own doc
    // comment: deliberately no caller-supplied `expected_row_version` guard
    // either) but it still bumps the real column by one — re-read it before
    // the next transition, or the subsequent `archive` call below stales out
    // with a spurious Conflict.
    let row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM attome_dashboard WHERE id = $1")
            .bind(dashboard_id)
            .fetch_one(&db)
            .await
            .expect("read row_version after restore");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/reject"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": 999 })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CONFLICT,
        "reject only applies from review — draft must Conflict, proving the real state machine ran"
    );

    // Rolling back makes a stored version live again without touching the
    // working copy.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/versions/{version_id}/activate"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "ungated activate must be 200");
    let body = body_json(res).await;
    assert_eq!(body["approval_pending"], false);
    assert_eq!(body["live_version_number"], 1);
    let row_version = body["row_version"].as_i64().unwrap();
    let live = get_published(&app, &admin_cookie, dashboard_id).await;
    assert_eq!(live["state"], "published");
    assert_eq!(live["version_id"], version_id.to_string());

    // `do_clone`'s source fetch only matches an ACTIVE row (`is_active IS
    // NULL OR is_active = true`) — clone while still active, archive last,
    // so this doesn't collide with `archive`'s own "also deactivate" step
    // (`lifecycle.rs`'s doc comment).
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/clone"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = body_json(res).await;
    assert!(body["id"].as_str().is_some());

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/archive"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn widget_actions_happy_path_duplicate() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (dashboard_id, _) = insert_dashboard(&db, Uuid::now_v7(), "Widget HTTP Test").await;
    let page_id = insert_page(&db, dashboard_id, "Page").await;
    let section_id = insert_section(&db, page_id, "freeform").await;
    let widget_a = insert_widget(
        &db,
        section_id,
        "A",
        Some(0.0),
        Some(0.0),
        Some(10.0),
        Some(10.0),
    )
    .await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/attome-dashboard/widget/duplicate",
            Some(&admin_cookie),
            Some(&json!({ "widget_id": widget_a })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn validate_config_happy_path_reports_a_well_formed_config_as_valid() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    // `default_config()` is deliberately an EMPTY starting point for the
    // widget config editor (`query_ref: ""`, no columns), not itself a valid
    // config — `validate_config` requires `query_ref` to parse as a UUID
    // AND at least one column (`declarative_widget.rs` ~213 and its own
    // "columns must declare at least one column" check). A well-formed
    // config needs both, same shape as that module's own
    // `tests::valid_config` fixture.
    let config = json!({
        "query_ref": Uuid::now_v7().to_string(),
        "columns": [{ "field": "amount", "label": "Amount" }],
        "actions": []
    });
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/attome-dashboard/widget/validate-config",
            Some(&admin_cookie),
            Some(&json!({ "config": config })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["valid"], true, "expected valid, got errors: {body:?}");
}

#[tokio::test]
async fn create_from_layout_happy_path() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/attome-dashboard/from-layout",
            Some(&admin_cookie),
            Some(&json!({
                "name": "HTTP From-Layout Test",
                "dashboard_type": "team",
                "pages": [{ "name": "Overview", "sections": [] }]
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = body_json(res).await;
    assert!(body["id"].as_str().is_some());
    assert_eq!(body["pages_created"], 1);
}

#[tokio::test]
async fn health_check_and_resolve_variables_happy_path() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (dashboard_id, _) = insert_dashboard(&db, Uuid::now_v7(), "Context HTTP Test").await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/health-check"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(
        body["checked"], 0,
        "a dashboard with no widgets checks none"
    );
    assert_eq!(body["broken"], json!([]));

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/resolve-variables"),
            Some(&admin_cookie),
            Some(&json!({})),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert!(
        body["variables"]["@current_user"].is_string(),
        "the built-in @current_user variable must always resolve"
    );
}

#[tokio::test]
async fn decision_and_scenario_happy_path() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (decision_id, row_version) = insert_decision(&db, "HTTP Test Decision").await;
    let option_id = insert_decision_option(&db, decision_id, "Option 1").await;
    let scenario_id = insert_scenario(&db, "HTTP Test Scenario").await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/decisions/{decision_id}/approve"),
            Some(&admin_cookie),
            Some(&json!({ "chosen_option_id": option_id, "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["status"], "approved");

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/scenarios/{scenario_id}/evaluate"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["scenario_id"], scenario_id.to_string());

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/scenarios/{scenario_id}/compare"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/scenarios/{scenario_id}/clone"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

// ── D-195 four-eyes gate on publish ──────────────────────────────────────
// Same shape as `approval_query_publish.rs` (that file's own doc comment is
// the fuller reference); `ACTION_DASHBOARD_PUBLISH` ("dashboard.publish") is
// already wired into `approval_admin::{KNOWN_ACTION_TYPES, execute_approved}`.

fn decide_request(
    admin_cookie: &str,
    request_id: Uuid,
    decision: &str,
    row_version: i64,
) -> Request<Body> {
    req(
        "POST",
        &format!("/api/v1/admin/approvals/{request_id}/decide"),
        Some(admin_cookie),
        Some(&json!({ "decision": decision, "row_version": row_version })),
    )
}

#[tokio::test]
async fn gated_publish_submits_a_pending_request_and_does_not_publish() {
    let system = skip_if_no_db!(test_system(&["dashboard.publish"]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (dashboard_id, row_version) =
        insert_dashboard(&db, Uuid::now_v7(), "Gated Publish Test").await;
    let app = full_app(system);

    let row_version = {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/submit-review"),
                Some(&admin_cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        body_json(res).await["row_version"].as_i64().unwrap()
    };
    let row_version = {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/approve"),
                Some(&admin_cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        body_json(res).await["row_version"].as_i64().unwrap()
    };

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/publish"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let body = body_json(res).await;
    assert_eq!(body["approval_pending"], true);
    assert!(body["approval_request_id"].as_str().is_some());
    assert_eq!(
        body["lifecycle_status"], "approved",
        "the dashboard must stay approved, not fabricate a published status"
    );

    let (lifecycle_status,): (Option<String>,) =
        sqlx::query_as("SELECT lifecycle_status FROM attome_dashboard WHERE id = $1")
            .bind(dashboard_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        lifecycle_status.as_deref(),
        Some("approved"),
        "a gated publish must not flip lifecycle_status"
    );
    let version_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dashboard_version WHERE dashboard_id = $1")
            .bind(dashboard_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(
        version_count, 0,
        "a gated publish must not write a version row"
    );
}

/// A second, different `system.admin` deciding the pending request actually
/// publishes (`execute_approved`'s `ACTION_DASHBOARD_PUBLISH` arm dispatches
/// into the same `do_publish_dashboard` the ungated path calls).
#[tokio::test]
async fn a_different_admin_approving_the_pending_request_actually_publishes() {
    let system = skip_if_no_db!(test_system(&["dashboard.publish"]).await);
    let (_requester_id, requester_cookie) = seed_user(&system, true).await;
    let (_approver_id, approver_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (dashboard_id, row_version) =
        insert_dashboard(&db, Uuid::now_v7(), "Gated Publish Approve Test").await;
    let app = full_app(system);

    let row_version = {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/submit-review"),
                Some(&requester_cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        body_json(res).await["row_version"].as_i64().unwrap()
    };
    let row_version = {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/approve"),
                Some(&requester_cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        body_json(res).await["row_version"].as_i64().unwrap()
    };

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/publish"),
            Some(&requester_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    let body = body_json(res).await;
    let request_id: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let res = app
        .clone()
        .oneshot(decide_request(&approver_cookie, request_id, "approve", 0))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["executed"]["dashboard_id"], dashboard_id.to_string());

    let (lifecycle_status,): (Option<String>,) =
        sqlx::query_as("SELECT lifecycle_status FROM attome_dashboard WHERE id = $1")
            .bind(dashboard_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(lifecycle_status.as_deref(), Some("published"));
    let version_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dashboard_version WHERE dashboard_id = $1")
            .bind(dashboard_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(version_count, 1);
}

// ── D-520/D-527: pages route and draft tree ─────────────────────────────────

#[tokio::test]
async fn pages_route_creates_a_page_with_its_root_section_and_the_tree_reads_it() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (dashboard_id, _) = insert_dashboard(&db, Uuid::now_v7(), "Pages Route HTTP").await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/pages"),
            Some(&admin_cookie),
            Some(&json!({ "name": "Created Page", "sequence": 1 })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let body = body_json(res).await;
    let page_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    let root_section_id = body["root_section_id"].as_str().unwrap().to_string();

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/tree"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let tree = body_json(res).await;
    assert_eq!(tree["dashboard"]["id"], dashboard_id.to_string());
    assert_eq!(tree["pages"].as_array().unwrap().len(), 1);
    assert_eq!(tree["pages"][0]["id"], page_id.to_string());
    assert_eq!(
        tree["pages"][0]["data"]["dashboard_id"],
        dashboard_id.to_string()
    );
    assert!(tree["pages"][0]["row_version"].is_i64());
    assert_eq!(tree["sections"][0]["id"], root_section_id);
    assert_eq!(tree["pages_needing_root_section"], json!([]));

    // A second root section is refused.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/pages/{page_id}/root-section"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);

    // A page from before the route existed is reported, then repaired explicitly.
    let bare_page = insert_page(&db, dashboard_id, "Bare Page").await;
    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/tree"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(
        body_json(res).await["pages_needing_root_section"],
        json!([bare_page.to_string()])
    );
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/pages/{bare_page}/root-section"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// The new dashboard-scoped routes run the same record-level check as every
/// other `attome-dashboard/{id}/...` route: a caller who cannot see the dashboard
/// gets 404, its owner gets through.
#[tokio::test]
async fn tree_pages_and_published_are_404_for_a_caller_without_record_access() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let fx = build_fixture(&system).await;
    let dashboard =
        build_dashboard_fixture(&fx.db, fx.dashboard_entity_id, fx.user_a, "Scoped Tree").await;
    let id = dashboard.dashboard_id;
    let app = full_app(system);

    for (method, uri, body) in [
        ("GET", format!("/api/v1/attome-dashboard/{id}/tree"), None),
        (
            "GET",
            format!("/api/v1/attome-dashboard/{id}/published"),
            None,
        ),
        (
            "POST",
            format!("/api/v1/attome-dashboard/{id}/pages"),
            Some(json!({ "name": "Intruder Page" })),
        ),
    ] {
        let res = app
            .clone()
            .oneshot(req(method, &uri, Some(&fx.cookie_b), body.as_ref()))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "{method} {uri} for a non-owner"
        );
    }

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/attome-dashboard/{id}/published"),
            Some(&fx.cookie_a),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["state"], "none");
    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/attome-dashboard/{id}/tree"),
            Some(&fx.cookie_a),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ── D-521: four-eyes gate on activating a version ───────────────────────────

/// D-521: rollback rides the publish gate. With `dashboard.publish` required,
/// both publishing v1 and later re-activating it wait for a different admin.
#[tokio::test]
async fn gated_activate_rides_the_publish_gate_and_waits_for_a_different_admin() {
    let system = skip_if_no_db!(test_system(&["dashboard.publish"]).await);
    let (_requester_id, requester_cookie) = seed_user(&system, true).await;
    let (_approver_id, approver_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (dashboard_id, row_version) =
        insert_dashboard(&db, Uuid::now_v7(), "Gated Activate Test").await;
    let app = full_app(system);

    let mut row_version = row_version;
    for step in ["submit-review", "approve"] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/{step}"),
                Some(&requester_cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{step}");
        row_version = body_json(res).await["row_version"].as_i64().unwrap();
    }

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/publish"),
            Some(&requester_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let publish_request: Uuid = body_json(res).await["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let res = app
        .clone()
        .oneshot(decide_request(
            &approver_cookie,
            publish_request,
            "approve",
            0,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let executed = body_json(res).await["executed"].clone();
    let version_id: Uuid = executed["version_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(live_version(&db, dashboard_id).await, Some(version_id));

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/unpublish"),
            Some(&requester_cookie),
            Some(&json!({ "row_version": executed["row_version"] })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let row_version = body_json(res).await["row_version"].as_i64().unwrap();
    assert_eq!(live_version(&db, dashboard_id).await, None);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/versions/{version_id}/activate"),
            Some(&requester_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let body = body_json(res).await;
    assert_eq!(body["approval_pending"], true);
    let activate_request: Uuid = body["approval_request_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        live_version(&db, dashboard_id).await,
        None,
        "a gated activate must not move the live version"
    );

    let res = app
        .clone()
        .oneshot(decide_request(
            &approver_cookie,
            activate_request,
            "approve",
            0,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = body_json(res).await;
    assert_eq!(body["executed"]["dashboard_id"], dashboard_id.to_string());
    assert_eq!(body["executed"]["live_version_number"], 1);
    assert_eq!(live_version(&db, dashboard_id).await, Some(version_id));
}

/// D-520 (Phase 1.1): a page created through the pages route — never raw SQL —
/// is seen by publish, health, restore and clone.
#[tokio::test]
async fn a_page_created_through_the_pages_route_is_published_health_checked_restored_and_cloned() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (dashboard_id, _) = insert_dashboard(&db, Uuid::now_v7(), "Built In The Editor").await;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/pages"),
            Some(&admin_cookie),
            Some(&json!({ "name": "Revenue" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let root_section_id: Uuid = body_json(res).await["root_section_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    insert_widget(
        &db,
        root_section_id,
        "Notes",
        Some(0.0),
        Some(0.0),
        Some(100.0),
        Some(50.0),
    )
    .await;

    let mut row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM attome_dashboard WHERE id = $1")
            .bind(dashboard_id)
            .fetch_one(&db)
            .await
            .unwrap();
    let mut version_id = String::new();
    for step in ["submit-review", "approve", "publish"] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/{step}"),
                Some(&admin_cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{step}");
        let body = body_json(res).await;
        row_version = body["row_version"].as_i64().unwrap();
        if step == "publish" {
            version_id = body["version_id"].as_str().unwrap().to_string();
        }
    }

    let live = get_published(&app, &admin_cookie, dashboard_id).await;
    assert_eq!(live["state"], "published");
    assert_eq!(live["snapshot"]["pages"][0]["name"], "Revenue");
    assert_eq!(
        live["snapshot"]["pages"][0]["sections"][0]["widgets"][0]["name"],
        "Notes"
    );

    let res = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/health-check"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body_json(res).await["broken"], json!([]));

    sqlx::query("UPDATE dashboard_page SET name = 'Renamed' WHERE dashboard_id = $1")
        .bind(dashboard_id)
        .execute(&db)
        .await
        .unwrap();
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/versions/{version_id}/restore"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let restored: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM dashboard_page \
         WHERE dashboard_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(dashboard_id)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(restored, vec!["Revenue".to_string()]);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/clone"),
            Some(&admin_cookie),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let clone_id: Uuid = body_json(res).await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let cloned_pages: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dashboard_page \
         WHERE dashboard_id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(clone_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(cloned_pages, 1);
}

/// D-543 — a published widget executes the definition captured at publish.
/// Editing the view it was published from changes neither the columns nor the
/// chart settings a viewer receives; republishing adopts them.
#[tokio::test]
async fn a_published_widget_executes_its_captured_definition_not_the_live_view() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let (_admin_id, admin_cookie) = seed_user(&system, true).await;
    let db = system.state().base.db.clone();
    let (dashboard_id, _) = insert_dashboard(&db, Uuid::now_v7(), "Captured Definition").await;
    let app = full_app(system);

    // A page through the pages route, then a widget bound to a view.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/pages"),
            Some(&admin_cookie),
            Some(&json!({ "name": "Revenue" })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED);
    let root_section_id: Uuid = body_json(res).await["root_section_id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let query_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query (id, sql_query, table_definition, is_active, created_at, owner_layer) \
         VALUES ($1, 'SELECT 1 AS id, 2 AS amount', '[]', true, NOW(), 'project')",
    )
    .bind(query_id)
    .execute(&db)
    .await
    .expect("insert query");
    sqlx::query(
        "INSERT INTO sql_query_version (id, query_id, sql_query, cost_estimate) \
         VALUES ($1, $2, 'SELECT 1 AS id, 2 AS amount', 1.0)",
    )
    .bind(Uuid::now_v7())
    .bind(query_id)
    .execute(&db)
    .await
    .expect("insert query version");
    let entity_id = entity_id_for(&db, "attome_dashboard").await;
    let view_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO view \
             (id, name, entity_logical_name, sql_query_ref, is_default, is_active, kind, view_metadata, owner_layer) \
         VALUES ($1, $2, $3, $4, false, true, 'chart', '{\"chart_type\":\"line\"}'::jsonb, 'project')",
    )
    .bind(view_id)
    .bind(format!("captured view {view_id}"))
    .bind(entity_id)
    .bind(query_id)
    .execute(&db)
    .await
    .expect("insert view");
    let widget_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_widget (id, section_id, widget_type, name, view_id) \
         VALUES ($1, $2, 'line_chart', 'Revenue', $3)",
    )
    .bind(widget_id)
    .bind(root_section_id)
    .bind(view_id.to_string())
    .execute(&db)
    .await
    .expect("insert widget");

    let mut row_version: i64 =
        sqlx::query_scalar("SELECT row_version FROM attome_dashboard WHERE id = $1")
            .bind(dashboard_id)
            .fetch_one(&db)
            .await
            .unwrap();
    for step in ["submit-review", "approve", "publish"] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/{step}"),
                Some(&admin_cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "{step}");
        row_version = body_json(res).await["row_version"].as_i64().unwrap();
    }

    let widget_data = |cookie: String| {
        let app = app.clone();
        async move {
            app.oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/widgets/{widget_id}/data"),
                Some(&cookie),
                Some(&json!({})),
            ))
            .await
            .unwrap()
        }
    };

    let res = widget_data(admin_cookie.clone()).await;
    assert_eq!(res.status(), StatusCode::OK);
    let before = body_json(res).await;
    assert_eq!(
        before["query"]["metadata"]["view_metadata"]["chart_type"],
        "line"
    );

    // Edit the view after publication: chart settings and columns both change.
    sqlx::query(
        "UPDATE view SET view_metadata = '{\"chart_type\":\"bar\"}'::jsonb, \
             table_definition = '[{\"logicalName\":\"amount\",\"displayName\":\"Late\"}]'::jsonb \
         WHERE id = $1",
    )
    .bind(view_id)
    .execute(&db)
    .await
    .expect("edit the view");

    let res = widget_data(admin_cookie.clone()).await;
    assert_eq!(res.status(), StatusCode::OK);
    let after = body_json(res).await;
    assert_eq!(
        after["query"]["metadata"]["view_metadata"], before["query"]["metadata"]["view_metadata"],
        "a view edit must not change a published widget's chart settings"
    );
    assert_eq!(
        after["query"]["data"]["columns"], before["query"]["data"]["columns"],
        "a view edit must not change a published widget's columns"
    );

    // Republishing adopts the edit.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{dashboard_id}/start-revision"),
            Some(&admin_cookie),
            Some(&json!({ "row_version": row_version })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let mut row_version = body_json(res).await["row_version"].as_i64().unwrap();
    for step in ["submit-review", "approve", "publish"] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/attome-dashboard/{dashboard_id}/{step}"),
                Some(&admin_cookie),
                Some(&json!({ "row_version": row_version })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK, "republish {step}");
        row_version = body_json(res).await["row_version"].as_i64().unwrap();
    }
    let res = widget_data(admin_cookie).await;
    let republished = body_json(res).await;
    assert_eq!(
        republished["query"]["metadata"]["view_metadata"]["chart_type"],
        "bar"
    );
}

/// D-543 — the data route is record-scoped like every other dashboard route,
/// and a widget with no published data source is a 422, never an empty 200.
#[tokio::test]
async fn widget_data_denies_a_hidden_dashboard_and_refuses_a_widget_with_no_data_source() {
    let system = skip_if_no_db!(test_system(&[]).await);
    let fx = build_fixture(&system).await;
    let dashboard =
        build_dashboard_fixture(&fx.db, fx.dashboard_entity_id, fx.user_a, "Scoped Data").await;
    let id = dashboard.dashboard_id;
    let widget = dashboard.widget_a;
    let app = full_app(system);

    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{id}/widgets/{widget}/data"),
            Some(&fx.cookie_b),
            Some(&json!({})),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "a caller who cannot see the dashboard cannot read its widget data"
    );

    // The owner can reach it, but nothing is published yet.
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/api/v1/attome-dashboard/{id}/widgets/{widget}/data"),
            Some(&fx.cookie_a),
            Some(&json!({})),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND, "nothing is live");
}

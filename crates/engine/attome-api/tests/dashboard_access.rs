//! R-04 regression coverage: every bespoke `attome-dashboard` business-action
//! route (`lifecycle.rs`, `widget_actions.rs`, …) used to authorize with
//! only a global `Authorized<Privilege<X>>` compile-time policy and then
//! read `WHERE id = $1` — any holder of `attome_dashboard.update` could
//! publish/archive/restore any private dashboard, and `widget/duplicate`
//! could copy a widget into an arbitrary `target_section_id`, including one
//! on a dashboard the caller cannot otherwise see. `attome-dashboard/src/
//! access.rs` closes that gap by calling `attome_records::entity_crud::
//! require_record_access` (D-133) before every such transition.
//!
//! Harness copied near-verbatim from `dashboard_migration.rs` (this crate's
//! established per-test-file convention) plus the role/privilege/
//! entity-access-depth seeding helpers from `record_level_security.rs`
//! (D-133/D-136's own test file) — same shapes, not re-derived.
//!
//! "`User`-depth" in this file's test names is Dynamics/XRM terminology for
//! "own records only," which this codebase's `AccessLevel` enum spells
//! `None` (0) — `role_mm_entity_access.read_access_level = 0` with
//! no team/BU widening, so only an explicit share (here, the creator's own)
//! makes a record visible at all.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test dashboard_access -- --test-threads=1
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

// ── Harness ──────────────────────────────────────────────────────────────

/// Unlike `dashboard_migration.rs`/`record_level_security.rs`'s own
/// `test_config()`, `database.{host,port,dbname,user,password}` here are the
/// REAL resolved per-binary throwaway-clone values (`db`, from
/// `attome_testkit::migrated_db_url()`), not the `"unused"`/`APP_ENV=debug`
/// placeholder those two files rely on — and `database.migrator` is set
/// (same credentials as `database.user`, which on this harness's Postgres
/// role already carries full DDL rights) rather than left `null`.
///
/// This is NOT cosmetic: `attome_config::AppConfig::migrator_database_url()`
/// (`attome_db::create_migrator_connection`'s target, used by
/// `attome_metadata::provision::attribute::sync_attribute_index` for any
/// sortable/filterable/lookup attribute) is built from `database.host`/
/// `.port`/`.dbname` DIRECTLY — it does not consult `DATABASE_URL` or
/// `APP_ENV` at all (see that method's own doc comment; only
/// `attome_db::create_pool`'s DML-only `runtime_database_url()` path has the
/// debug override). `attome_dashboard::seed::seed`'s `widget_type` choice-list
/// resync (`ensure_attribute(.., is_sortable = true, is_filterable = true,
/// ..)`, ordinary EngineSystem::build() plumbing, unrelated to this file's own
/// R-04 assertions) triggers exactly that path on a schema-only database
/// with no entities provisioned yet — this harness's `attomedb_test`
/// throwaway clones. Leaving `database.{host,port,dbname}` as the
/// `"unused"`/`5555` placeholder (byte-identical to `dashboard_migration.rs`)
/// makes `migrator_database_url()` dial a database that isn't the clone at
/// all — confirmed live 2026-09-06: the SAME failure
/// (`password authentication failed for user "unused"`) reproduces on the
/// unmodified `dashboard_migration.rs` file under this exact environment, so
/// it is a pre-existing gap in that shared test-harness pattern (migration
/// `0042_migrator_runtime_roles.sql`'s own doc comment already flags
/// `database.migrator`-configured provisioning as "still only exercised by
/// Rust integration tests... not run this session, still open"), not
/// something introduced here — this file just needs a real result and works
/// around it locally rather than leaving a broken database.migrator = null
/// placeholder that happens not to matter for `dashboard_migration.rs`'s own
/// narrower assertions.
fn test_config(db: &DbUrlParts) -> AppConfig {
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
            "security": {{ "bootstrap_admin_email": null }}
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

async fn test_system() -> Option<EngineSystem> {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let db_parts = DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse");

    let config = test_config(&db_parts);
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
    let email = format!("dashaccess-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("dashaccess-test-{user_id}"))
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

fn req(method: &str, uri: &str, cookie: &str, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin");
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match body {
        Some(v) => Body::from(v.to_string()),
        None => Body::empty(),
    };
    builder.body(body).unwrap()
}

/// Creates a fresh, privilege-less `role` — the caller layers
/// privileges (`grant_privileges`) and an entity-access depth
/// (`scope_role_for_entity`) onto it afterward.
async fn create_role(db: &PgPool) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("dashaccess-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");
    role_id
}

/// Grants `role_id` the `"{logicalname}.{action}"` privilege for each of
/// `actions`, via `role_mm_privilege`/`privilege` — same
/// plumbing as `record_level_security.rs::create_role_with_privileges`, but
/// factored so ONE role can accumulate privileges across several entities
/// (`attome_dashboard`, `dashboard_page`, …) rather than only one.
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

/// Upserts one `role_mm_entity_access` row for `(role_id,
/// entity_id)`, uniform across read/write/delete — same helper shape as
/// `record_level_security.rs::scope_role_for_entity`. `access_level = 0`
/// (`None`, this file's "`User`-depth") means only an explicit share (here,
/// each owner's own record share, inserted by `insert_dashboard`) makes a
/// record visible at all — no team/BU/Global widening.
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

/// Mirrors `entity_crud::create_record`'s D-133 (2) implicit creator-share
/// (view+action, i.e. `capability = 1`) — this file's fixtures insert
/// `attome_dashboard*` rows directly rather than through the generic entity
/// API (same convention `attome-dashboard/tests/dashboard_crud.rs` already
/// uses), so a real create's automatic self-share has to be recreated by
/// hand for the owner to see their own dashboard once the role's depth is
/// narrowed below `Global`.
async fn share_record_with_owner(db: &PgPool, entity_ref: Uuid, record_id: Uuid, owner_id: Uuid) {
    sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, 1)", // principal_type=user, capability=action (covers read too)
    )
    .bind(record_id)
    .bind(entity_ref)
    .bind(owner_id)
    .execute(db)
    .await
    .expect("insert owner record share");
}

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

async fn insert_section(db: &PgPool, page_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_section (id, page_id, section_type, layout_mode) \
         VALUES ($1, $2, 'container', 'grid')",
    )
    .bind(id)
    .bind(page_id)
    .execute(db)
    .await
    .expect("insert test dashboard_section row");
    id
}

async fn insert_widget(db: &PgPool, section_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_widget (id, section_id, widget_type, name) \
         VALUES ($1, $2, 'rich_text', $3)",
    )
    .bind(id)
    .bind(section_id)
    .bind(name)
    .execute(db)
    .await
    .expect("insert test dashboard_widget row");
    id
}

/// Sets up two non-admin users (`A`, `B`) sharing ONE role that grants
/// `attome_dashboard{,_page,_section,_widget}` create/read/update, then narrows
/// that role's `attome_dashboard` depth to `None` ("`User`"-depth, own records
/// only) for both. Returns `(db, security, app, cookie_a, user_a, cookie_b,
/// user_b, dashboard_entity_id)`.
struct Fixture {
    db: PgPool,
    cookie_a: String,
    user_a: Uuid,
    cookie_b: String,
    user_b: Uuid,
    admin_cookie: String,
    dashboard_entity_id: Uuid,
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
    assign_role_to_user(&db, user_a, role_id).await;
    assign_role_to_user(&db, user_b, role_id).await;

    let dashboard_entity_id = entity_id_for(&db, "attome_dashboard").await;
    scope_role_for_entity(&db, &security, role_id, user_a, dashboard_entity_id, 0).await;
    scope_role_for_entity(&db, &security, role_id, user_b, dashboard_entity_id, 0).await;

    Fixture {
        db,
        cookie_a,
        user_a,
        cookie_b,
        user_b,
        admin_cookie,
        dashboard_entity_id,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

/// The exact scenario R-04 was written against: a `User`-depth ("own
/// records only") role holder who is NOT the dashboard's owner must not be
/// able to drive its lifecycle at all — the caller must not even learn the
/// dashboard exists (`NotFound`, not `Forbidden`). The owner and an admin
/// both reach past the access gate to the real state machine — proven here
/// by both getting `Conflict` (the dashboard is still `draft`, and
/// `/publish` only accepts `approved`), not `NotFound`: the access check
/// let them through, and it is the lifecycle rule, not authorization, that
/// stops the transition.
///
/// **Known pre-existing blocker (2026-09-06), unrelated to R-04/this file's
/// own logic**: on a genuinely fresh, entity-empty database, this test's own
/// `test_system()` call — building a full `EngineSystem`, which every test in
/// this file does — can fail before reaching any of this test's assertions,
/// with `column "status" does not exist` while `attome_api::bundle::apply`
/// provisions `user_account.status` (the `attome-security` platform
/// bundle, nothing dashboard-specific). Root cause: `attome_metadata::provision::
/// attribute::sync_attribute_index`'s `CREATE INDEX CONCURRENTLY` opens its
/// own physical connection (`attome_db::create_migrator_connection`), which
/// cannot see the `ADD COLUMN` the enclosing bundle-apply transaction added
/// moments earlier and has not yet committed — a genuine transaction-
/// visibility bug in `attome-api::bundle::apply` vs.
/// `attome-metadata::provision::attribute`, confirmed live and reproducible on an
/// UNMODIFIED `dashboard_migration.rs` (same harness pattern, same failure)
/// once that file's own `database.migrator` gap (see `test_config`'s doc
/// comment above) is worked around the same way this file's is. Migration
/// `0042_migrator_runtime_roles.sql`'s own comment already flags this exact
/// class of path ("exercised by Rust integration tests against a
/// DATABASE_URL test database — not run this session, still open") as
/// never verified before. Out of scope for R-04 to fix (deep, unrelated
/// platform boot-sequencing code) — tracked here so it isn't mistaken for a
/// defect in `access.rs`. In practice this only bites the FIRST
/// `EngineSystem::build()` against a given throwaway clone; this file's other
/// two tests build fine because they run after this one (attribute already
/// reconciled) whenever the whole file runs together.
#[tokio::test]
async fn non_owner_cannot_publish_a_private_dashboard_but_owner_and_admin_reach_the_state_machine()
{
    let system = skip_if_no_db!(test_system().await);
    let fx = build_fixture(&system).await;

    let (dashboard_id, row_version) =
        insert_dashboard(&fx.db, fx.user_a, "A's private dashboard").await;
    share_record_with_owner(&fx.db, fx.dashboard_entity_id, dashboard_id, fx.user_a).await;

    let app = full_app(system);
    let uri = format!("/api/v1/attome-dashboard/{dashboard_id}/publish");
    let publish_body = json!({ "row_version": row_version });

    let res_b = app
        .clone()
        .oneshot(req("POST", &uri, &fx.cookie_b, Some(&publish_body)))
        .await
        .unwrap();
    assert_eq!(
        res_b.status(),
        StatusCode::NOT_FOUND,
        "a User-depth caller with no share on this dashboard must get 404, \
         not 403 — the record must not be observably distinguishable from \
         one that doesn't exist"
    );

    let res_a = app
        .clone()
        .oneshot(req("POST", &uri, &fx.cookie_a, Some(&publish_body)))
        .await
        .unwrap();
    assert_eq!(
        res_a.status(),
        StatusCode::CONFLICT,
        "the owner must pass the access gate and reach the real lifecycle \
         rule (only an approved dashboard can publish) — Conflict, not \
         NotFound, proves the access check did not block a legitimate caller"
    );

    let res_admin = app
        .clone()
        .oneshot(req("POST", &uri, &fx.admin_cookie, Some(&publish_body)))
        .await
        .unwrap();
    assert_eq!(
        res_admin.status(),
        StatusCode::CONFLICT,
        "an admin bypasses record-level scoping entirely and also reaches \
         the same lifecycle rule"
    );
}

/// `widget/duplicate`'s `target_section_id` must be checked against the
/// TARGET dashboard's own access, independent of whether the caller may act
/// on the source widget's dashboard. `B` legitimately owns the source
/// widget (on `B`'s own dashboard) but has no share on `A`'s dashboard,
/// which owns the target section — must 404, not silently place a copy of
/// `B`'s widget inside `A`'s private dashboard.
#[tokio::test]
async fn widget_duplicate_denies_a_target_section_inside_another_users_private_dashboard() {
    let system = skip_if_no_db!(test_system().await);
    let fx = build_fixture(&system).await;

    let (dashboard_a, _) = insert_dashboard(&fx.db, fx.user_a, "A's private dashboard").await;
    share_record_with_owner(&fx.db, fx.dashboard_entity_id, dashboard_a, fx.user_a).await;
    let page_a = insert_page(&fx.db, dashboard_a, "Page A").await;
    let section_a = insert_section(&fx.db, page_a).await;

    let (dashboard_b, _) = insert_dashboard(&fx.db, fx.user_b, "B's private dashboard").await;
    share_record_with_owner(&fx.db, fx.dashboard_entity_id, dashboard_b, fx.user_b).await;
    let page_b = insert_page(&fx.db, dashboard_b, "Page B").await;
    let section_b = insert_section(&fx.db, page_b).await;
    let widget_b = insert_widget(&fx.db, section_b, "B's widget").await;

    let app = full_app(system);
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/attome-dashboard/widget/duplicate",
            &fx.cookie_b,
            Some(&json!({ "widget_id": widget_b, "target_section_id": section_a })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "B holds Update access on the source widget's own dashboard (B's), \
         but not on A's dashboard, which owns target_section_id — must 404, \
         not copy B's widget into A's private dashboard"
    );
}

/// Regression guard for the fix above: the SAME caller duplicating a widget
/// within their OWN dashboard (no cross-dashboard target) must still
/// succeed — the new access check must not have broken the ordinary,
/// same-dashboard case.
#[tokio::test]
async fn widget_duplicate_succeeds_within_the_callers_own_dashboard() {
    let system = skip_if_no_db!(test_system().await);
    let fx = build_fixture(&system).await;

    let (dashboard_a, _) = insert_dashboard(&fx.db, fx.user_a, "A's own dashboard").await;
    share_record_with_owner(&fx.db, fx.dashboard_entity_id, dashboard_a, fx.user_a).await;
    let page_a = insert_page(&fx.db, dashboard_a, "Page A").await;
    let section_a = insert_section(&fx.db, page_a).await;
    let widget_a = insert_widget(&fx.db, section_a, "A's widget").await;

    let app = full_app(system);
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/attome-dashboard/widget/duplicate",
            &fx.cookie_a,
            Some(&json!({ "widget_id": widget_a, "target_section_id": section_a })),
        ))
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::CREATED,
        "duplicating within one's own dashboard must still work after R-04"
    );
    let body = body_json(res).await;
    assert!(body["id"].as_str().is_some());
}

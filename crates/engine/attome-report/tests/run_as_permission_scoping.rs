//! M25 Phase 1 (Report, D-440) — the money-path security test this decision
//! exists to make true: **a scheduled report never surfaces a row its
//! `run_as` user cannot see, even though the admin who created the schedule
//! can see it.**
//!
//! Builds a real `EngineSystem`/`EngineState` + HTTP router in-process (same
//! pattern as `attome-api/tests/record_level_security.rs`, whose
//! `test_config`/`test_system`/`full_app`/`seed_admin`/
//! `seed_user_with_privileges`/`create_role_with_privileges`/
//! `assign_role_to_user`/`scope_role_for_entity`/`create_record_as` helpers
//! this file duplicates locally — same convention every DB-backed test file
//! in this repo follows, see that file's own header) and drives the whole
//! path for real:
//!
//! 1. An admin provisions a throwaway entity and two rows: one created by a
//!    restricted, None-tier-scoped user (`run_as`, visible to them via the
//!    implicit D-133 creator-share) and one created by the admin (invisible
//!    to `run_as`, since their role's access to this entity is scoped to
//!    `None` with no share).
//! 2. The admin creates an `attome_report` over a stored query against that
//!    entity, and an `report_schedule` naming `run_as` as the restricted
//!    user — proving D-440's `validate_run_as` accepts a genuinely
//!    non-admin, active user.
//! 3. The schedule is forced due (`next_run_at` backdated) and
//!    `attome_report::scheduler::sweep` dispatches it, exactly as the real
//!    `EngineJob::ReportScheduleSweep` scheduler would.
//! 4. `attome_report::run::process` — the same function
//!    `EngineJob::ReportRun`'s worker calls — is invoked directly (bypassing
//!    the apalis queue for a deterministic test) for the dispatched run.
//! 5. The uploaded CSV is read back from `attome-storage` and asserted to
//!    contain ONLY the row `run_as` can see — never the admin-only row —
//!    while a parallel manual run as the admin (who created both) contains
//!    both, proving the scheduled run is genuinely narrower, not just
//!    coincidentally short.
//!
//! Requires a live Postgres (`DATABASE_URL`), Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) and the test RustFS/S3-compatible
//! storage backend (`http://localhost:9000`, same endpoint
//! `record_level_security.rs`'s `test_config()` points at) — run manually
//! against a throwaway database/bucket:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-report --test run_as_permission_scoping -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_config::{AppConfig, KeyRing};
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

fn test_config(db: &DbUrlParts) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
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
            "cors": {{ "allowed_origins": ["http://test.local"] }}
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

/// Registers `SecurityModel` (so `user_account` exists for `owner`/
/// `run_as` lookups, same fresh-database ordering `seed.rs::seed_reports`'s
/// doc comment describes) and `ReportModel` (so `/api/v1/reports*` is
/// mounted — `ReportModel::tier()` is `Paid`, so the license grant below must
/// cover `MODULE_REPORT`), then runs `attome_report::seed::seed_reports` +
/// re-runs `entity_privileges::seed_all` exactly the way
/// `crates/server/src/boot.rs` does after `.build()` returns.
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
    let state = EngineState::new(base);

    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        .register(attome_report::ReportModel)
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

    let db = system.state().base.db.clone();
    attome_report::seed::seed_reports(&db)
        .await
        .expect("seed attome_report/report_schedule (post-.build(), see seed.rs doc)");
    attome_security::entity_privileges::seed_all(&db)
        .await
        .expect("mint attome_report{,_schedule} privilege rows after their late registration");

    Some(system)
}

async fn stamp_test_origin(mut req: axum::extract::Request) -> axum::extract::Request {
    req.headers_mut().insert(
        axum::http::header::ORIGIN,
        axum::http::HeaderValue::from_static("http://test.local"),
    );
    req
}

fn full_app(system: EngineSystem) -> axum::Router {
    let base_state = system.state().base.clone();
    attome_server::ServerBuilder::new(base_state.clone(), (*base_state.config).clone())
        .add_bundle(system.core_routes())
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()))
        .layer(axum::middleware::map_request(stamp_test_origin))
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

async fn seed_admin(db: &PgPool) -> (Uuid, String) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("report-rls-test-admin-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway admin user_account");

    let privilege_id: Uuid =
        sqlx::query_scalar("SELECT id FROM privilege WHERE key = 'system.admin'")
            .fetch_one(db)
            .await
            .expect("system.admin privilege must already be seeded by attome_security::seed::seed");

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

    (user_id, session_cookie(user_id))
}

/// See `record_level_security.rs`'s identical helper for the full D-136
/// rationale: a fresh role, holding `"{logicalname}.{action}"` for each of
/// `actions`, is what `scope_role_for_entity` narrows afterward.
async fn create_role_with_privileges(db: &PgPool, logicalname: &str, actions: &[&str]) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("report-rls-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");

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

    role_id
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

async fn seed_user_with_privileges(
    db: &PgPool,
    logicalname: &str,
    actions: &[&str],
) -> (Uuid, String, Uuid) {
    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, is_active) VALUES ($1, $2, true)")
        .bind(user_id)
        .bind(format!("report-rls-test-user-{user_id}"))
        .execute(db)
        .await
        .expect("insert throwaway non-admin user");

    let role_id = create_role_with_privileges(db, logicalname, actions).await;
    assign_role_to_user(db, user_id, role_id).await;

    (user_id, session_cookie(user_id), role_id)
}

/// See `record_level_security.rs`'s identical helper. `access_level`:
/// 0=None, 1=Team, 2=BusinessUnit, 3=Global.
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

async fn body_json(res: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

/// Tests disable the background metadata registry subscriber, so a
/// dynamically-provisioned entity/field needs an explicit refresh before
/// generic CRUD will recognize it.
async fn sync_registry(state: &EngineState) {
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build metadata registry");
    state.entities.swap(registry);
}

async fn provision_entity(app: &axum::Router, admin_cookie: &str, logicalname: &str) -> Uuid {
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/entities")
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"logicalname":"{logicalname}","name":"Report RLS Test"}}"#
        )))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create entity");
    let status = res.status();
    let entity = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "create entity failed: {entity:?}"
    );
    Uuid::parse_str(entity["id"].as_str().expect("entity id")).expect("entity id is a uuid")
}

async fn provision_text_field(app: &axum::Router, admin_cookie: &str, entity_id: Uuid) {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/admin/entities/{entity_id}/fields"))
        .header("cookie", admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"logicalname":"title","name":"Title","field_type":"text"}"#,
        ))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create field");
    assert_eq!(res.status(), StatusCode::CREATED);
}

/// Implicit-creator-share write (D-133 (2)): the creator always has `action`
/// access to what they just made, regardless of any access_level scoping.
async fn create_record_as(
    app: &axum::Router,
    creator_cookie: &str,
    logicalname: &str,
    title: &str,
) -> String {
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/{logicalname}"))
        .header("cookie", creator_cookie)
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"title":"{title}"}}"#)))
        .unwrap();
    let res = app.clone().oneshot(req).await.expect("create record");
    assert_eq!(res.status(), StatusCode::CREATED, "creating {title} failed");
    let created = body_json(res).await;
    created["id"].as_str().expect("record id").to_owned()
}

/// Same misleadingly-named-but-UUID-typed `entity_logical_name` column
/// `attome-api/tests/query_exec.rs::seed_entity_query` binds (D-133 metadata
/// natural-keys migration 0133's own comment: "entity_logical_name is the
/// entity's UUID").
async fn seed_entity_query(db: &PgPool, sql: &str, entity_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query (id, sql_query, table_definition, entity_logical_name, is_active, created_at, owner_layer) \
         VALUES ($1, $2, '[]', $3, true, NOW(), 'project')",
    )
    .bind(id)
    .bind(sql)
    .bind(entity_id)
    .execute(db)
    .await
    .expect("insert throwaway entity-scoped sql_query");
    id
}

#[tokio::test]
async fn scheduled_run_never_surfaces_a_row_run_as_cannot_see() {
    let system = skip_if_no_db!(test_system().await);
    let db = system.state().base.db.clone();
    let security = system.state().base.security.clone();
    let state = system.state().clone();
    let app = full_app(system);

    let (admin_id, admin_cookie) = seed_admin(&db).await;

    // ── A throwaway entity with two rows: one restricted-user-owned
    //    ("Visible Row", via implicit creator-share), one admin-owned
    //    ("Hidden Row", never shared with the restricted user). ────────────
    let logicalname = format!("report_rls_widget_{}", Uuid::now_v7().simple());
    let entity_id = provision_entity(&app, &admin_cookie, &logicalname).await;
    provision_text_field(&app, &admin_cookie, entity_id).await;
    sync_registry(&state).await;

    // The `run_as` user: `{logicalname}.read` scoped to None-tier (sees only
    // records they created or were explicitly shared) PLUS `attome_report.read`
    // (unscoped is fine — `run::process`'s `security.require("attome_report",
    // "read")` is a flat table-level privilege check, not a per-record one;
    // record-level scope for the underlying data is what `{logicalname}`'s
    // None-tier role enforces).
    let (restricted_id, restricted_cookie, widget_role_id) =
        seed_user_with_privileges(&db, &logicalname, &["read"]).await;
    scope_role_for_entity(
        &db,
        &security,
        widget_role_id,
        restricted_id,
        entity_id,
        0, // None
    )
    .await;
    let report_read_role = create_role_with_privileges(&db, "attome_report", &["read"]).await;
    assign_role_to_user(&db, restricted_id, report_read_role).await;

    let visible_id = create_record_as(&app, &restricted_cookie, &logicalname, "Visible Row").await;
    let hidden_id = create_record_as(&app, &admin_cookie, &logicalname, "Hidden Row").await;

    // Sanity check the RLS setup itself before trusting anything downstream:
    // the restricted user must see their own row and not the admin's.
    assert_eq!(
        get_record_as(&app, &restricted_cookie, &logicalname, &visible_id).await,
        StatusCode::OK,
        "sanity: run_as must see the row they created"
    );
    assert_eq!(
        get_record_as(&app, &restricted_cookie, &logicalname, &hidden_id).await,
        StatusCode::NOT_FOUND,
        "sanity: run_as must NOT see the admin-only row before any report runs"
    );

    // ── The stored query, the report definition, and the schedule. ────────
    let query_id = seed_entity_query(
        &db,
        &format!("SELECT id, title FROM \"{logicalname}\" WHERE is_active = true"),
        entity_id,
    )
    .await;

    let create_report_req = Request::builder()
        .method("POST")
        .uri("/api/v1/reports")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "Widget Report",
                "query_ref": query_id,
                "format": "csv",
                "is_template": false,
            })
            .to_string(),
        ))
        .unwrap();
    let res = app
        .clone()
        .oneshot(create_report_req)
        .await
        .expect("create report");
    let report = body_json(res).await;
    let report_id =
        Uuid::parse_str(report["id"].as_str().expect("report id")).expect("report id is a uuid");

    let create_schedule_req = Request::builder()
        .method("POST")
        .uri("/api/v1/reports/schedules")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "report_ref": report_id,
                "rrule": "FREQ=DAILY",
                "run_as": restricted_id,
                "recipients": [],
                "delivery": "in_app",
                "skip_if_empty": false,
            })
            .to_string(),
        ))
        .unwrap();
    let res = app
        .clone()
        .oneshot(create_schedule_req)
        .await
        .expect("create schedule");
    let status = res.status();
    let schedule = body_json(res).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "creating a schedule with a genuine non-admin run_as must succeed: {schedule:?}"
    );
    let schedule_id = Uuid::parse_str(schedule["id"].as_str().expect("schedule id"))
        .expect("schedule id is a uuid");

    // D-440's other half: an admin `run_as` must be rejected outright.
    let admin_run_as_req = Request::builder()
        .method("POST")
        .uri("/api/v1/reports/schedules")
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "report_ref": report_id,
                "rrule": "FREQ=DAILY",
                "run_as": admin_id,
                "recipients": [],
                "delivery": "in_app",
                "skip_if_empty": false,
            })
            .to_string(),
        ))
        .unwrap();
    let res = app
        .clone()
        .oneshot(admin_run_as_req)
        .await
        .expect("attempt schedule with admin run_as");
    assert_eq!(
        res.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a schedule naming an admin/system.admin-holding run_as must be rejected (D-440)"
    );

    // ── Force the schedule due, sweep it (the real scheduler's job), then
    //    run the worker directly (bypassing apalis for a deterministic
    //    test — the enqueued EngineJob::ReportRun would call the exact
    //    same function). ─────────────────────────────────────────────────
    sqlx::query(
        "UPDATE report_schedule SET next_run_at = NOW() - INTERVAL '1 minute' WHERE id = $1",
    )
    .bind(schedule_id)
    .execute(&db)
    .await
    .expect("backdate next_run_at to force the schedule due");

    let stats = attome_report::scheduler::sweep(&state)
        .await
        .expect("sweep due schedules");
    assert_eq!(
        stats.dispatched, 1,
        "the due schedule must be dispatched exactly once"
    );

    let scheduled_run_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM report_run WHERE schedule_ref = $1 ORDER BY requested_at DESC LIMIT 1",
    )
    .bind(schedule_id)
    .fetch_one(&db)
    .await
    .expect("the sweep must have created a run row");

    let scheduled_requested_by: Uuid =
        sqlx::query_scalar("SELECT requested_by FROM report_run WHERE id = $1")
            .bind(scheduled_run_id)
            .fetch_one(&db)
            .await
            .expect("read requested_by");
    assert_eq!(
        scheduled_requested_by, restricted_id,
        "D-440's core property: the dispatched run's requested_by must be the \
         schedule's run_as, never the admin who created the schedule"
    );

    attome_report::run::process(&state, scheduled_run_id)
        .await
        .expect("process the scheduled run");

    let (scheduled_status, scheduled_object_key, scheduled_row_count, scheduled_error): (
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
    ) = sqlx::query_as("SELECT status, object_key, row_count, error FROM report_run WHERE id = $1")
        .bind(scheduled_run_id)
        .fetch_one(&db)
        .await
        .expect("read scheduled run row");
    assert_eq!(
        scheduled_status, "completed",
        "scheduled run must complete (error: {scheduled_error:?})"
    );
    assert_eq!(
        scheduled_row_count,
        Some(1),
        "run_as must see exactly the one row they have access to"
    );

    let scheduled_csv = download_report_object(
        &state,
        &format!(
            "report-runs/{report_id}/{scheduled_run_id}.csv",
            scheduled_run_id = scheduled_run_id
        ),
        scheduled_object_key.as_deref(),
    )
    .await;
    assert!(
        scheduled_csv.contains("Visible Row"),
        "the run_as-scoped export must contain the row run_as can see:\n{scheduled_csv}"
    );
    assert!(
        !scheduled_csv.contains("Hidden Row"),
        "SECURITY: the run_as-scoped export must NEVER contain a row run_as \
         cannot see, even though the schedule's creator (admin) can see it:\n{scheduled_csv}"
    );

    // ── Contrast: the same report run manually as the admin (who created
    //    both rows) must contain BOTH — proving the scheduled run above was
    //    genuinely narrowed by run_as's permissions, not coincidentally
    //    short for some unrelated reason. ───────────────────────────────
    let manual_run_req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/reports/{report_id}/run"))
        .header("cookie", &admin_cookie)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let res = app
        .clone()
        .oneshot(manual_run_req)
        .await
        .expect("trigger manual run as admin");
    assert_eq!(res.status(), StatusCode::ACCEPTED);
    let manual_run = body_json(res).await;
    let manual_run_id = Uuid::parse_str(manual_run["id"].as_str().expect("manual run id"))
        .expect("manual run id is a uuid");

    attome_report::run::process(&state, manual_run_id)
        .await
        .expect("process the manual admin run");

    let (manual_status, manual_object_key, manual_row_count): (
        String,
        Option<String>,
        Option<i64>,
    ) = sqlx::query_as("SELECT status, object_key, row_count FROM report_run WHERE id = $1")
        .bind(manual_run_id)
        .fetch_one(&db)
        .await
        .expect("read manual run row");
    assert_eq!(manual_status, "completed", "manual admin run must complete");
    assert_eq!(
        manual_row_count,
        Some(2),
        "the admin, who created both rows, must see both when running manually"
    );

    let manual_csv = download_report_object(
        &state,
        &format!("report-runs/{report_id}/{manual_run_id}.csv"),
        manual_object_key.as_deref(),
    )
    .await;
    assert!(manual_csv.contains("Visible Row"));
    assert!(
        manual_csv.contains("Hidden Row"),
        "the admin's own manual run must contain the row only the admin created:\n{manual_csv}"
    );
}

async fn get_record_as(
    app: &axum::Router,
    cookie: &str,
    logicalname: &str,
    record_id: &str,
) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/{logicalname}/{record_id}"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    app.clone().oneshot(req).await.expect("get record").status()
}

async fn download_report_object(
    state: &EngineState,
    expected_key: &str,
    object_key: Option<&str>,
) -> String {
    let key = object_key.unwrap_or(expected_key);
    let path = ObjectPath::parse(key).expect("valid object key");
    let result = state
        .base
        .storage
        .store()
        .get(&path)
        .await
        .expect("download report object from storage");
    let bytes = result.bytes().await.expect("read report object bytes");
    String::from_utf8(bytes.to_vec()).expect("report object is valid utf-8 csv")
}

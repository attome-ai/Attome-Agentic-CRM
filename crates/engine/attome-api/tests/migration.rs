//! Regression coverage for `migration.rs` (M17 data migration, D-433) —
//! `migration_project`/`migration_run` admin CRUD, built on top of
//! `bulk.rs`'s staged-import mechanism.
//!
//! Covers the three properties the module plan calls out explicitly:
//! - `mode: "dry_run"` writes nothing to the database and can never be
//!   approved,
//! - rollback refuses an item whose record has a later edit (D-433) and
//!   reports it, rather than skipping it silently or forcing the revert,
//! - an incremental re-run of the same source (resolve the natural key,
//!   update the existing record instead of blindly re-creating) is
//!   idempotent — no duplicate record, same underlying row.
//!
//! Harness copied near-verbatim from `bulk_mutation.rs` (itself copied from
//! `rewrap_admin.rs`/`entity_round_trip.rs` — this repo's established
//! per-test-file convention, not shared, so each suite can evolve its harness
//! independently).
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test migration -- --test-threads=1
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
use axum::body::to_bytes;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

// ── Harness ──────────────────────────────────────────────────────────────────

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
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
        db_host = db.host,
        db_port = db.port,
        db_name = db.dbname,
        db_user = db.user,
        db_password = db.password,
    );

    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn build_test_system() -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;

    let config = test_config(&DbUrlParts::parse(&throwaway_url).expect("DATABASE_URL must parse"));
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

/// The system and router every test in this binary shares (build-loop plan,
/// Phase 3 task 4). Building a fresh `EngineSystem` per test cost ~0.3 s each;
/// the tests already share this binary's database, and each one provisions
/// its own uniquely named entities, users and roles, so sharing the in-memory
/// system adds no coupling the database did not already have. Tests run on
/// `attome_testkit::shared_runtime`, which keeps the pools' connections alive
/// between tests.
#[derive(Clone)]
struct TestSystem {
    state: EngineState,
    app: axum::Router,
}

impl TestSystem {
    fn state(&self) -> &EngineState {
        &self.state
    }
}

static SHARED: tokio::sync::OnceCell<Option<TestSystem>> = tokio::sync::OnceCell::const_new();

async fn test_system() -> Option<TestSystem> {
    SHARED
        .get_or_init(|| async {
            let system = build_test_system().await?;
            let state = system.state().clone();
            Some(TestSystem {
                state,
                app: build_app(system),
            })
        })
        .await
        .clone()
}

fn full_app(system: TestSystem) -> axum::Router {
    system.app
}

fn build_app(system: EngineSystem) -> axum::Router {
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

async fn seed_user(system: &TestSystem, admin: bool) -> (Uuid, String, String) {
    let db = &system.state().base.db;
    let user_id = Uuid::now_v7();
    let email = format!("migration-test-{user_id}@test.local");
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(format!("migration-test-{user_id}"))
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

    (user_id, email, session_cookie(user_id))
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

/// Same shape as `req`, but for a `PATCH` that needs an `if-match` header
/// (`bulk_mutation.rs`'s `req` helper has no header-injection point).
fn patch_req(uri: &str, cookie: &str, if_match_row_version: i64, body: &Value) -> Request<Body> {
    Request::builder()
        .method("PATCH")
        .uri(uri)
        .header("cookie", cookie)
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .header("if-match", format!("\"{if_match_row_version}\""))
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Provisions a throwaway entity with a `title` (text) and `amount` (number)
/// field — mirrors `bulk_mutation.rs`'s helper of the same name.
async fn provision_entity(app: &axum::Router, admin_cookie: &str, prefix: &str) -> String {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let res = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/admin/entities",
            admin_cookie,
            Some(&json!({
                "logicalname": logicalname,
                "name": "Migration Test",
                "is_append_only": false,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "create entity");
    let entity = body_json(res).await;
    let entity_id: Uuid = entity["id"].as_str().unwrap().parse().unwrap();

    for (ln, ft) in [("title", "text"), ("amount", "number")] {
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                admin_cookie,
                Some(&json!({ "logicalname": ln, "name": ln, "field_type": ft })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create field {ln}");
    }

    logicalname
}

fn bulk_body(operation: &str, records: Vec<Value>) -> Value {
    json!({ "operation": operation, "records": records })
}

async fn row_count(db: &attome_db::DbPool, logicalname: &str) -> i64 {
    let table = attome_core::quote_ident(logicalname);
    sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) FROM {table}"))
        .fetch_one(db)
        .await
        .expect("count entity rows")
}

async fn find_by_title(
    db: &attome_db::DbPool,
    logicalname: &str,
    title: &str,
) -> Option<(Uuid, i64)> {
    let table = attome_core::quote_ident(logicalname);
    sqlx::query_as::<_, (Uuid, i64)>(&format!(
        "SELECT id, row_version FROM {table} WHERE title = $1 AND is_active = true"
    ))
    .bind(title)
    .fetch_optional(db)
    .await
    .expect("lookup by natural key")
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// `mode: "dry_run"` on `POST .../staged-import` never writes a real row (the
/// same property every staged import already has before approval), and
/// additionally can never be approved at all — `POST .../approve` on a
/// dry-run import must 422, not silently no-op or succeed.
#[test]
fn dry_run_mode_writes_nothing_and_refuses_approval() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (_, _, admin_cookie) = seed_user(&system, true).await;
        let db = system.state().base.db.clone();
        let app = full_app(system);
        let logicalname = provision_entity(&app, &admin_cookie, "dryrunmig").await;

        let mut body = bulk_body(
            "create",
            vec![json!({ "data": { "title": "would-create" } })],
        );
        body["mode"] = json!("dry_run");

        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import"),
                &admin_cookie,
                Some(&body),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let staged = body_json(res).await;
        assert_eq!(staged["passed"], 1);
        let import_id: Uuid = staged["id"].as_str().unwrap().parse().unwrap();

        assert_eq!(
            row_count(&db, &logicalname).await,
            0,
            "mode: dry_run must write nothing to the database"
        );

        let approve_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import/{import_id}/approve"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            approve_res.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a dry-run staged import must never be approvable"
        );

        assert_eq!(
            row_count(&db, &logicalname).await,
            0,
            "still nothing written after the refused approval attempt"
        );
    })
}

/// D-433: a migration run's rollback refuses an item whose record was edited
/// after the migration applied — it reports the conflict on that item and
/// leaves the record exactly as the later edit left it, rather than
/// overwriting it or silently skipping the item without a trace.
#[test]
fn rollback_refuses_when_a_later_edit_exists() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, _, admin_cookie) = seed_user(&system, true).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let logicalname = provision_entity(&app, &admin_cookie, "rollbackrefuse").await;

        let create_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}"),
                &admin_cookie,
                Some(&json!({ "title": "original" })),
            ))
            .await
            .unwrap();
        assert_eq!(create_res.status(), StatusCode::CREATED);
        let created = body_json(create_res).await;
        let record_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        let project_res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/admin/migration-projects",
                &admin_cookie,
                Some(&json!({
                    "name": format!("proj-{record_id}"),
                    "source_kind": "json",
                    "target_entity": logicalname,
                })),
            ))
            .await
            .unwrap();
        assert_eq!(project_res.status(), StatusCode::CREATED);
        let project_id: Uuid = body_json(project_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let stage_body = bulk_body(
            "update",
            vec![json!({
                "id": record_id, "expected_row_version": 0,
                "data": { "title": "migrated" }
            })],
        );
        let stage_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import"),
                &admin_cookie,
                Some(&stage_body),
            ))
            .await
            .unwrap();
        assert_eq!(stage_res.status(), StatusCode::ACCEPTED);
        let import_id: Uuid = body_json(stage_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        // Link BEFORE approval, so `apply_staged_one` sees `migration_run_id`
        // and writes the rollback ledger while it applies.
        let run_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/migration-projects/{project_id}/runs"),
                &admin_cookie,
                Some(&json!({ "staged_import_id": import_id })),
            ))
            .await
            .unwrap();
        assert_eq!(run_res.status(), StatusCode::CREATED);
        let run_id: Uuid = body_json(run_res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let approve_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import/{import_id}/approve"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(approve_res.status(), StatusCode::ACCEPTED);

        attome_records::bulk::process_staged_import(
            &state,
            import_id,
            &logicalname,
            "update",
            Vec::new(),
            user_id,
        )
        .await
        .expect("process_staged_import must succeed");

        let get_res = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v1/{logicalname}/{record_id}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        let after_migration = body_json(get_res).await;
        assert_eq!(after_migration["data"]["title"], "migrated");
        assert_eq!(after_migration["row_version"], 1);

        // A LATER edit — bumps row_version to 2, independent of the migration.
        let patch_res = app
            .clone()
            .oneshot(patch_req(
                &format!("/api/v1/{logicalname}/{record_id}"),
                &admin_cookie,
                1,
                &json!({ "title": "edited-after-migration" }),
            ))
            .await
            .unwrap();
        assert_eq!(patch_res.status(), StatusCode::OK, "the later edit itself");

        let rollback_res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/migration-projects/{project_id}/runs/{run_id}/rollback"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(rollback_res.status(), StatusCode::ACCEPTED);

        attome_api::migration::process_rollback(&state, run_id, user_id)
            .await
            .expect("process_rollback must not itself error for a refused item");

        let (run_rollback_status,): (String,) =
            sqlx::query_as("SELECT rollback_status FROM migration_run WHERE id = $1")
                .bind(run_id)
                .fetch_one(&db)
                .await
                .expect("run row");
        assert_eq!(
            run_rollback_status, "refused",
            "the run must land on refused, not completed, when any item was refused"
        );

        let (item_status, item_error): (String, Option<String>) = sqlx::query_as(
            "SELECT rollback_status, rollback_error FROM migration_run_item \
         WHERE migration_run_id = $1 AND item_index = 0",
        )
        .bind(run_id)
        .fetch_one(&db)
        .await
        .expect("run item row");
        assert_eq!(item_status, "refused");
        assert!(
            item_error.is_some(),
            "the refusal must report why, not just that it happened"
        );

        // The later edit must survive completely untouched.
        let get_res = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v1/{logicalname}/{record_id}"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        let final_record = body_json(get_res).await;
        assert_eq!(
            final_record["data"]["title"], "edited-after-migration",
            "a refused rollback must never overwrite the later edit"
        );
    })
}

/// An "incremental" re-run of the same source is idempotent: the caller
/// resolves the source's natural key against the target entity first (as any
/// real incremental-migration tool must — this platform does not guess which
/// records are new vs. existing on the server's behalf), so re-submitting the
/// identical source data a second time updates the record run 1 created
/// instead of creating a duplicate.
#[test]
fn incremental_rerun_of_same_source_is_idempotent() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, _, admin_cookie) = seed_user(&system, true).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let logicalname = provision_entity(&app, &admin_cookie, "increrun").await;

        assert!(
            find_by_title(&db, &logicalname, "acme-corp")
                .await
                .is_none()
        );

        // Run 1: the natural key isn't present yet -> create.
        let stage1 = bulk_body(
            "create",
            vec![json!({ "data": { "title": "acme-corp", "amount": 100 } })],
        );
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import"),
                &admin_cookie,
                Some(&stage1),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let import_id_1: Uuid = body_json(res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let approve1 = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import/{import_id_1}/approve"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(approve1.status(), StatusCode::ACCEPTED);
        attome_records::bulk::process_staged_import(
            &state,
            import_id_1,
            &logicalname,
            "create",
            Vec::new(),
            user_id,
        )
        .await
        .expect("run 1 must succeed");

        assert_eq!(row_count(&db, &logicalname).await, 1);

        // Run 2 ("incremental re-run of the same source"): resolve the natural
        // key first, find the record run 1 created, and submit an UPDATE against
        // its current id/row_version instead of blindly creating again.
        let (existing_id, existing_version) = find_by_title(&db, &logicalname, "acme-corp")
            .await
            .expect("run 1 must have created the record");

        let stage2 = bulk_body(
            "update",
            vec![json!({
                "id": existing_id, "expected_row_version": existing_version,
                "data": { "title": "acme-corp", "amount": 100 }
            })],
        );
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import"),
                &admin_cookie,
                Some(&stage2),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        let import_id_2: Uuid = body_json(res).await["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let approve2 = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import/{import_id_2}/approve"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(approve2.status(), StatusCode::ACCEPTED);
        attome_records::bulk::process_staged_import(
            &state,
            import_id_2,
            &logicalname,
            "update",
            Vec::new(),
            user_id,
        )
        .await
        .expect("incremental re-run must succeed");

        assert_eq!(
            row_count(&db, &logicalname).await,
            1,
            "an incremental re-run of the same source must not create a duplicate"
        );
        let (final_id, final_version) = find_by_title(&db, &logicalname, "acme-corp")
            .await
            .expect("record still present after the re-run");
        assert_eq!(
            final_id, existing_id,
            "the same underlying record must have been updated, not replaced"
        );
        assert_eq!(final_version, existing_version + 1);
    })
}

/// D-606 (CSV import resume): the wizard stages a file as one staged import
/// per ≤500-row chunk and links each to the project as a run, in chunk order.
/// A resumed import re-reads the project's runs and never applies a chunk
/// twice. That rests on three server guarantees this test pins:
/// linking the same staged import a second time is a 409 (unique
/// `staged_import_id`), approving an already-approved import is a 404 (the
/// `status = 'pending_review'` claim), and the run list reports each chunk's
/// staged import with its status. The records exist exactly once afterwards.
#[test]
fn resumed_csv_import_cannot_link_or_apply_a_chunk_twice() {
    attome_testkit::run_shared(async {
        let system = skip_if_no_db!(test_system().await);
        let (user_id, _, admin_cookie) = seed_user(&system, true).await;
        let state = system.state().clone();
        let db = state.base.db.clone();
        let app = full_app(system);
        let logicalname = provision_entity(&app, &admin_cookie, "csvresume").await;

        let res = app
            .clone()
            .oneshot(req(
                "POST",
                "/api/v1/admin/migration-projects",
                &admin_cookie,
                Some(&json!({
                    "name": format!("csv-resume-{}", Uuid::now_v7()),
                    "source_kind": "csv",
                    "source_ref": "csv-import:v1;rows=3",
                    "target_entity": logicalname,
                })),
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED, "create project");
        let project_id = body_json(res).await["id"].as_str().unwrap().to_string();

        // Two chunks, staged and linked in order.
        let mut import_ids = Vec::new();
        for chunk in [vec!["a", "b"], vec!["c"]] {
            let records = chunk
                .iter()
                .map(|t| json!({ "data": { "title": t } }))
                .collect();
            let res = app
                .clone()
                .oneshot(req(
                    "POST",
                    &format!("/api/v1/{logicalname}/staged-import"),
                    &admin_cookie,
                    Some(&bulk_body("create", records)),
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::ACCEPTED);
            let import_id: Uuid = body_json(res).await["id"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let res = app
                .clone()
                .oneshot(req(
                    "POST",
                    &format!("/api/v1/admin/migration-projects/{project_id}/runs"),
                    &admin_cookie,
                    Some(&json!({ "staged_import_id": import_id })),
                ))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::CREATED, "link chunk run");
            import_ids.push(import_id);
        }

        // A resumed attempt that re-links chunk 0 is refused.
        let res = app
            .clone()
            .oneshot(req(
                "POST",
                &format!("/api/v1/admin/migration-projects/{project_id}/runs"),
                &admin_cookie,
                Some(&json!({ "staged_import_id": import_ids[0] })),
            ))
            .await
            .unwrap();
        assert_eq!(
            res.status(),
            StatusCode::CONFLICT,
            "a staged import can be linked to one run only"
        );

        // Approve chunk 0 only (the "mid-import failure"), and apply it.
        let approve = |id: Uuid| {
            req(
                "POST",
                &format!("/api/v1/{logicalname}/staged-import/{id}/approve"),
                &admin_cookie,
                None,
            )
        };
        let res = app.clone().oneshot(approve(import_ids[0])).await.unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        attome_records::bulk::process_staged_import(
            &state,
            import_ids[0],
            &logicalname,
            "create",
            Vec::new(),
            user_id,
        )
        .await
        .expect("chunk 0 applies");

        // The resume reads the run list: chunk 0 is no longer pending review,
        // chunk 1 still is.
        let res = app
            .clone()
            .oneshot(req(
                "GET",
                &format!("/api/v1/admin/migration-projects/{project_id}/runs?page_size=200"),
                &admin_cookie,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let runs = body_json(res).await;
        let status_of = |id: Uuid| {
            runs["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["staged_import_id"] == json!(id))
                .map(|r| r["import_status"].as_str().unwrap().to_string())
                .expect("run listed")
        };
        assert_ne!(status_of(import_ids[0]), "pending_review");
        assert_eq!(status_of(import_ids[1]), "pending_review");

        // Re-approving chunk 0 is refused; chunk 1 approves normally.
        let res = app.clone().oneshot(approve(import_ids[0])).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::NOT_FOUND,
            "an already-approved chunk cannot be approved again"
        );
        let res = app.clone().oneshot(approve(import_ids[1])).await.unwrap();
        assert_eq!(res.status(), StatusCode::ACCEPTED);
        attome_records::bulk::process_staged_import(
            &state,
            import_ids[1],
            &logicalname,
            "create",
            Vec::new(),
            user_id,
        )
        .await
        .expect("chunk 1 applies");

        assert_eq!(
            row_count(&db, &logicalname).await,
            3,
            "every CSV row exists exactly once after the resumed import"
        );
    })
}

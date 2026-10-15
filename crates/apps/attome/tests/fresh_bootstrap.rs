//! End-to-end proof of the fresh-database bootstrap sequence this platform
//! actually ships: an empty database -> `attome_db::ensure_schema` -> every
//! migration compiled into this binary (`attome_db::run_migrations` against
//! the real `sqlx::migrate!("./migrations")` `Migrator`, not `sqlx-cli`) ->
//! the same `attome_auth::accounts::bootstrap_admin` + privilege-grant
//! primitives `main.rs`'s `--bootstrap-admin` mode calls -> a full,
//! idempotent second pass through `attome::boot::init` (schema/migration
//! re-check, role/pepper seed, the whole `EngineSystem` build) ->
//! `/health/ready` reporting 200. See `db-and-migrations` skill's
//! "Fresh-database bootstrap" section for the sequence this proves matches.
//!
//! No other integration suite in this repo calls `attome_db::ensure_schema`/
//! `run_migrations`/`attome::boot::init` directly against a database that
//! starts out with zero tables — every other test (`db_role_seed.rs`,
//! `bootstrap_admin_flow.rs`, `middleware_pipeline.rs`, `attome-server/tests/
//! health.rs`, ...) assumes migrations are already applied to a
//! long-lived `attome_dev` schema. This file is the one that proves the
//! *bootstrap* path itself, matching a brand-new per-customer database's
//! actual starting condition (D-002).
//!
//! **Isolation: a whole empty database, not a schema** (TODO-006, D-349).
//! `attome_testkit::empty_database` allocates one with nothing in it at all —
//! no `attome_dev`, no `_sqlx_migrations`, no `apalis` — and drops it when
//! the guard falls out of scope. That is what a new customer deployment
//! (D-002: one database per customer) actually starts from, and it is the
//! only boundary that contains migration `0014_apalis_jobs.sql`'s hardcoded
//! **global** `apalis` schema, which no `search_path` can redirect. The
//! earlier per-schema strategy (`fresh_boot_<uuid>` inside the shared test
//! database) is what kept this test `#[ignore]`d until 2026-08-12: replaying
//! `0014` where `apalis` already existed died on `42710 trigger
//! "notify_workers" for relation "jobs" already exists`, and its fix-forward
//! `0090_apalis_trigger_idempotent.sql` is unreachable from version 14.
//! `0014` is checksum-frozen (D-127/D-306) and was not touched; only the
//! harness changed.
//!
//! `attome_db::create_direct_pool` builds its connection URL from
//! `AppConfig::database`'s fields directly and never reads `DATABASE_URL`
//! (see its own doc comment) — only `attome_db::create_pool` honors
//! `DATABASE_URL` under `APP_ENV=debug`. To keep both pools pointed at the
//! same fresh database, this test extracts host/port/user/password/dbname
//! from the guard's URL into the config it builds, then **unsets**
//! `DATABASE_URL` for the duration of the test (restored on drop) so
//! `create_pool` falls back to that same config instead of the ambient URL,
//! which still names the shared, already-migrated template.
//!
//! That last point is the one safety-critical wire in this file: every write
//! below (`bootstrap_admin`, the privilege grant, `boot::init`'s seeds) must
//! land in the throwaway database and nowhere else. `assert_connected_to`
//! checks `current_database()` against the guard's own name before the first
//! write rather than trusting the plumbing.
//!
//! Requires a live Postgres (`DATABASE_URL`, e.g.
//! `postgres://postgres:postgres@localhost:5432/attomedb_test`) and Redis
//! (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`, default `localhost:6379`), plus
//! `APP_ENV=debug` in the environment — same convention as every other
//! integration test in this repo that drives `attome_db::create_pool`'s
//! debug-only fallback path (`database.runtime`/`.migrator`/`.readonly` are
//! deliberately left unconfigured here, exactly like `db_role_seed.rs`'s
//! own template). Skips (loudly) when `DATABASE_URL` is unset, except under `CI` —
//! see `attome_testkit`.
//! Run manually:
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p server --test fresh_bootstrap
//! ```
//!
//! The `DATABASE_URL` role needs `CREATEDB` (the `postgres` superuser both
//! `docker-compose.yml`'s test profile runs as already has it). This test never writes to the database that URL names.

#![recursion_limit = "512"]
#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::accounts::{BootstrapOutcome, bootstrap_admin};
use attome_config::AppConfig;
use attome_testkit::DbUrlParts;
use attome_testkit::skip_if_no_db;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use sqlx::PgPool;
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
static MIGRATION_CHECKSUM_BASELINE: &str = include_str!("../migrations/checksums.sha256");

/// Restores `DATABASE_URL` on drop regardless of panic, so unsetting it for
/// this test's isolation (see module doc) never leaks into whatever runs
/// next in the same process.
struct DatabaseUrlGuard {
    original: Option<String>,
}

impl DatabaseUrlGuard {
    /// SAFETY: this file has exactly one `#[tokio::test]`, so there is no
    /// concurrent mutator of `DATABASE_URL` within this test binary's
    /// process.
    fn unset() -> Self {
        let original = std::env::var("DATABASE_URL").ok();
        unsafe {
            std::env::remove_var("DATABASE_URL");
        }
        Self { original }
    }
}

impl Drop for DatabaseUrlGuard {
    fn drop(&mut self) {
        // SAFETY: see `unset`'s comment.
        unsafe {
            match &self.original {
                Some(v) => std::env::set_var("DATABASE_URL", v),
                None => std::env::remove_var("DATABASE_URL"),
            }
        }
    }
}

/// The schema a real deployment configures (`config.example.json`,
/// `docker-compose.yml`). The isolation boundary is
/// the throwaway database, so there is nothing left for a randomized schema
/// name to protect — and using the real one means `ensure_schema` is exercised
/// on exactly the identifier a customer deployment creates on day one.
const DEPLOYMENT_SCHEMA: &str = "attome_dev";

/// Fails before the first write if the pool is not connected to the throwaway
/// database this test allocated. The whole file is one long sequence of writes
/// against a config assembled from a parsed URL with `DATABASE_URL` unset
/// underneath it; if any of that plumbing regresses, the writes land in the
/// shared, already-migrated template that every other suite clones from. This
/// is one round trip to make that unrepresentable rather than merely unlikely.
async fn assert_connected_to(pool: &PgPool, expected_dbname: &str) {
    let (current,): (String,) = sqlx::query_as("SELECT current_database()")
        .fetch_one(pool)
        .await
        .expect("SELECT current_database() must succeed on a connected pool");
    assert_eq!(
        current, expected_dbname,
        "this test must only ever write to its own throwaway database — refusing to \
         bootstrap into '{current}'"
    );
}

/// `database.runtime`/`.migrator`/`.readonly` deliberately absent — same
/// "APP_ENV=debug fallback" shape as `db_role_seed.rs`'s own template.
/// `security.bootstrap_admin_email: null` so `attome_security::seed` never
/// fails boot looking for a configured email that doesn't match anything
/// yet (this test grants `system.admin` directly, the same way
/// `run_bootstrap_admin` does, not via that seed path).
fn test_config(db: &DbUrlParts, schema: &str) -> AppConfig {
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
                "host": "{host}", "port": {port}, "dbname": "{dbname}",
                "user": "{user}", "password": "{password}", "schema": "{schema}",
                "connection_number": 5, "timeout": 5.0, "migrate_on_boot": true,
                "runtime": {{ "user": "attome_runtime", "password": "boot-test-runtime-pw" }},
                "migrator": {{ "user": "attome_migrator", "password": "boot-test-migrator-pw" }},
                "readonly": {{ "user": "attome_readonly", "password": "boot-test-readonly-pw" }}
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 0, "connection_pool_size": 4, "timeout": 2000,
                "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
                "metadata_registry_enabled": true
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
                "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
                "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
                "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{
                "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {{}}
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
            "cors": {{ "allowed_origins": ["http://allowed.test"] }}
        }}"#,
        host = db.host,
        port = db.port,
        dbname = db.dbname,
        user = db.user,
        password = db.password,
        schema = schema,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    serde_json::from_str(&json).expect("test config JSON must deserialize into AppConfig")
}

// No longer `#[ignore]`d (TODO-006, 2026-08-12). This runs in the ordinary
// `cargo test --workspace` pass, which is the point: it is the only automated
// check that exercises the empty-database bootstrap path every new customer
// deployment (D-002: one database per customer) runs on day one.
// `scripts/backup/restore-drill.sh` boots a *restored* database for real,
// which is a different path with different failure modes — not a substitute.
#[tokio::test]
async fn fresh_database_bootstraps_end_to_end() {
    // A database with nothing in it — not `attome_testkit::migrated_db_url()`'s
    // clone of the migrated template, which would already have every migration
    // applied and the global `apalis` schema present. Dropped when this guard
    // falls out of scope, `WITH (FORCE)`, so the pools `boot::init` opens below
    // need no teardown.
    let fresh_db = skip_if_no_db!(attome_testkit::empty_database("fresh_bootstrap").await);
    let db_parts = DbUrlParts::parse(fresh_db.url()).expect("DATABASE_URL must parse");
    assert_eq!(
        db_parts.dbname,
        fresh_db.name(),
        "the config below must be built from the throwaway database's own URL"
    );
    // Isolation: force `attome_db::create_pool` (used inside `attome::boot::init`)
    // to fall back to the config below — which points at the fresh database —
    // instead of preferring the ambient `DATABASE_URL`, which still names the
    // shared migrated template. See module doc.
    let _database_url_guard = DatabaseUrlGuard::unset();

    let config = test_config(&db_parts, DEPLOYMENT_SCHEMA);

    // ── Step 1: the exact sequence `main.rs`'s `--bootstrap-admin` mode runs ──

    attome_db::verify_migration_checksums(&MIGRATOR, MIGRATION_CHECKSUM_BASELINE)
        .expect("this build's compiled migrations must match the frozen checksum baseline");

    let migration_db = attome_db::create_direct_pool(&config)
        .await
        .expect("create_direct_pool must connect against a genuinely fresh database");
    assert_connected_to(&migration_db, fresh_db.name()).await;

    attome_db::ensure_schema(&migration_db, &config)
        .await
        .expect("ensure_schema must CREATE SCHEMA IF NOT EXISTS for the fresh database");

    attome_db::run_migrations(&migration_db, &MIGRATOR)
        .await
        .expect("run_migrations must apply every compiled migration to the fresh database");

    // Prove every compiled migration actually landed, not just that
    // `run_migrations` returned `Ok` — `applied_max_version` must equal the
    // highest version compiled into this binary, and the run must not be
    // `dirty` (an interrupted/partially-applied run, D-038).
    let expected_max_version = MIGRATOR
        .migrations
        .iter()
        .map(|m| m.version)
        .max()
        .expect("MIGRATOR must contain at least one migration");
    let post_migration_state = attome_db::schema_state(&migration_db)
        .await
        .expect("schema_state must succeed once _sqlx_migrations exists");
    assert_eq!(
        post_migration_state.applied_max_version,
        Some(expected_max_version),
        "every migration compiled into this binary must have applied to the fresh database"
    );
    assert!(
        !post_migration_state.dirty,
        "a fresh-database bootstrap must never leave a dirty (interrupted) migration row"
    );

    let email = format!("fresh-boot-admin-{}@example.invalid", Uuid::now_v7());
    let user_id = match bootstrap_admin(&migration_db, &email)
        .await
        .expect("bootstrap_admin must succeed against a freshly-migrated, empty systemuser table")
    {
        BootstrapOutcome::Created { user_id, password } => {
            assert_eq!(
                password.len(),
                24,
                "the very first bootstrap on a fresh database must generate a one-time password"
            );
            user_id
        }
        other => panic!(
            "expected BootstrapOutcome::Created for a brand-new email against a fresh \
             database, got {other:?}"
        ),
    };

    let privilege_id = attome_security::db::ensure_privilege(
        &migration_db,
        attome_security::context::ADMIN_PRIVILEGE_KEY,
        "System Admin",
        "Full administrative access to every gated route",
        attome_core::changeset::Layer::Platform,
    )
    .await
    .expect("ensure_privilege must create the system.admin privilege row");
    attome_security::db::ensure_user_privilege_grant(&migration_db, user_id, privilege_id)
        .await
        .expect("ensure_user_privilege_grant must grant system.admin to the bootstrap admin");

    migration_db.close().await;

    // ── Step 2: a real second boot — `attome::boot::init`, the exact sequence ──
    // `main.rs`/`bin/worker.rs` run on every normal (non-bootstrap-admin) start.
    // Re-runs `ensure_schema`/`run_migrations` idempotently, seeds migrator/
    // runtime role passwords + the pepper registry, then builds the full
    // `EngineSystem` (license load, metadata registry pre-warm — this is what
    // flips `registry_ready`, the flag `/health/ready` gates on).
    let boot = attome::boot::init(&config)
        .await
        .expect("attome::boot::init must succeed on the database this test just bootstrapped");
    let base_state = boot.system.state().base.clone();
    assert_connected_to(&base_state.db, fresh_db.name()).await;

    // ── Step 3: /health/ready must report 200 ──
    let (status, Json(ready_body)) =
        attome_server::health::health_ready(State(base_state.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "/health/ready must return 200 after a real fresh-database bootstrap; body: {ready_body}"
    );
    assert_eq!(ready_body["status"], "ready");
    assert_eq!(ready_body["db"], true);
    assert_eq!(ready_body["registry"], true);
    assert_eq!(ready_body["schema"], true);

    // Cross-check against `/health/version`'s independent `schema_state`
    // read: same fresh schema, same expected max version, still not dirty.
    let Json(version_body) = attome_server::health::version(State(base_state.clone())).await;
    assert_eq!(version_body["schema_version"], expected_max_version);
    assert_eq!(version_body["schema_dirty"], false);
    // P-environment-promotion §5 step 20: `EngineSystem::build()` (which
    // `attome::boot::init` just ran) computes the configuration hash at the
    // end of boot, so a real fresh bootstrap must report a real hash, not
    // the pre-this-feature fallback to `application_version`.
    assert!(version_body["configuration_version"].is_string());
    assert_ne!(
        version_body["configuration_version"],
        version_body["application_version"]
    );

    // AF3-T1: a fresh install needs no licence or module configuration and
    // runs with every module on, core included (V2-D473: no licences).
    let modules = boot.system.state().modules.load();
    let off: Vec<&str> = attome_modules::MODULE_MAP
        .iter()
        .filter(|(_, id)| !modules.has(*id))
        .map(|(name, _)| *name)
        .collect();
    assert!(
        off.is_empty(),
        "a fresh install must run every module; off: {off:?}"
    );
    let configured: i64 = sqlx::query_scalar("SELECT count(*) FROM module_configuration")
        .fetch_one(&base_state.db)
        .await
        .expect("read module_configuration");
    assert_eq!(
        configured, 0,
        "a fresh install writes no module configuration"
    );

    // ── Step 4: the seeds actually produced a usable deployment ──────────────
    // `/health/ready` only proves the process booted; it says nothing about
    // whether the built-in features have their metadata. That is precisely the
    // gap that shipped broken three times (D-363's Knowledge Base entities,
    // D-364's `attome_document` and its sidebar row): each was created by a
    // one-off admin API call against the authoring database, so it worked
    // there forever and existed on no other deployment. A fresh boot is the
    // only place that is visible. Before `attome_core::seed_gate` this was
    // also only true on the *first* boot, since every later boot re-ran every
    // seed unconditionally and papered over what an earlier boot skipped —
    // Step 5 below proves that is no longer required: a boot where every
    // module hits the watermark skip path must leave the same usable state.
    assert_seeds_produced_a_usable_deployment(&base_state.db).await;

    // ── Step 5: a THIRD boot — proves the seed watermark gate's skip path ────
    // leaves a still-usable deployment, not just a fast one. Once a module's
    // `seed_watermark` row matches, `run_if_stale` makes its second
    // call a pure watermark-table read with no `ensure_entity`/
    // `ensure_attribute` calls at all. Re-running every Step 3/4 assertion
    // here is the regression guard for the gate's one
    // correctness-critical detail: the watermark is written only after a
    // module's body returns `Ok`, so a module that skips must have left
    // correct state behind on the call that actually ran it.
    let boot_again = attome::boot::init(&config)
        .await
        .expect("attome::boot::init must succeed on a boot that hits every seed's skip path");
    let base_state_again = boot_again.system.state().base.clone();
    assert_connected_to(&base_state_again.db, fresh_db.name()).await;

    let (status, Json(ready_body)) =
        attome_server::health::health_ready(State(base_state_again.clone())).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "/health/ready must still return 200 after a boot where every seed module skipped; \
         body: {ready_body}"
    );
    assert_eq!(ready_body["status"], "ready");
    assert_eq!(ready_body["db"], true);
    assert_eq!(ready_body["registry"], true);
    assert_eq!(ready_body["schema"], true);

    assert_seeds_produced_a_usable_deployment(&base_state_again.db).await;
}

/// Invariants every seeded entity must satisfy on a database that has never
/// seen this codebase. Deliberately mostly *generic* — the two loops below
/// catch a future engine's missing view or privilege with no edit here — plus
/// one small explicit list for the "the seed does not exist at all" case,
/// which no generic rule can detect.
async fn assert_seeds_produced_a_usable_deployment(db: &PgPool) {
    // Entities whose absence is a broken feature, not a missing nice-to-have.
    // Add a line when a feature becomes built-in; that one line is the whole
    // cost of never shipping this class of bug again.
    const REQUIRED_ENTITIES: &[&str] = &[
        "user_account",
        "team",
        "organization",
        "api_key",
        "license",
        "audit_header",
        "s2s_client",
        "notification_template",
        "workflow_definition",
        // D-363 / D-365 — Knowledge Base + Web Crawling.
        "knowledge_data_source",
        "knowledge_data_item",
        // D-364 — Documents. `/api/v1/documents/tree` selects straight from
        // this table, so without it every level of the folder browser 500s.
        "attome_document",
        // Project Management — attome-project's core entity; its child entities
        // (work item, deliverable, issue, change request, project team, …)
        // are covered by the generic view/privilege loops below, same as
        // every other engine.
        "attome_project",
        // Work Intake & Service Management — attome-service's core entity;
        // service_work_request is covered by the same generic loops.
        "service_ticket",
        // Decision Intelligence Platform, Phase 1 (attome-dashboard) —
        // `attome_dashboard`, the platform's one dashboard product. D-479 (M26
        // R-09) retired the legacy `dashboard` entity (attome-report) this list
        // used to also require — a fresh boot no longer provisions it at
        // all.
        "attome_dashboard",
        // M27 Phase 1 (KPI & Metrics) — split out of attome-dashboard into its
        // own `attome-metric` crate (D-480, M26 R-14); still seeded from inside
        // `attome_dashboard::seed::seed_body` (`attome_metric::metric::seed`).
        "dashboard_metric_definition",
        // M25 Phase 1 (Report, D-440) — `attome_report::seed::seed_reports`,
        // called *after* `.build()` returns (see that function's doc
        // comment); this is exactly the kind of post-build, second-seed-call
        // registration a fresh-database check exists to catch.
        "attome_report",
        // M59 Phase 1 (attome-integration) — the external-system registry.
        "integration_system",
        // D-576 — web portals (`platform-bundles/attome-portal.json`).
        "webportal",
        "webportal_user",
        // M20 Phase 1 (attome-grc, D-427) — Governance, Risk & Compliance's
        // core entity.
        "grc_control",
        // M11 Search gap list — saved searches (`saved_search::seed`).
        "saved_search",
        // M57 Phase 1 (Document Generation, D-463) — the `attome-docgen` platform
        // bundle, applied pre-`.build()` from `boot.rs` same as `workflow_definition`
        // above.
        "docgen_template",
    ];

    let registered: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
         WHERE (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .expect("read registered entities");

    let missing: Vec<&str> = REQUIRED_ENTITIES
        .iter()
        .copied()
        .filter(|want| !registered.iter().any(|got| got == want))
        .collect();
    assert!(
        missing.is_empty(),
        "built-in entities absent after a fresh boot: {missing:?}. Each one is a feature \
         that works on its author's database and nowhere else — it was created through \
         the admin API and never given an idempotent seed() called from \
         EngineSystem::build(). See .claude/commands/xrm-api-first.md, \"The other half\"."
    );

    // Every registered entity needs a default view, or its admin list 404s
    // (D-036 — the view carries the `{logicalname}.read` required privilege).
    //
    // Three audit internals are exempt by design, not by omission: they are
    // written by `AuditService` and read through the audit APIs, never browsed
    // as an entity list, so `attome_audit::seed` deliberately gives them no view.
    // Verified against the dev database 2026-08-16 — they are the only three.
    // Do not add to this list to make a new failure go away; a missing view on
    // anything else is the bug this loop is looking for.
    const NO_LIST_VIEW: &[&str] = &["audit_config", "audit_detail", "audit_snapshot"];

    for logicalname in registered
        .iter()
        .filter(|n| !NO_LIST_VIEW.contains(&n.as_str()))
    {
        let has_view: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sql_query q \
               JOIN entity_info e ON e.id = q.entity_logical_name \
              WHERE e.logicalname = $1 AND q.required_privilege IS NOT NULL \
                AND (q.is_active IS NULL OR q.is_active = true))",
        )
        .bind(logicalname)
        .fetch_one(db)
        .await
        .expect("read default views");
        assert!(
            has_view,
            "entity {logicalname} has no default view after a fresh boot — its seed is \
             missing an ensure_default_query/ensure_entity_list_views call, so its admin \
             list will 404"
        );
    }

    // …and its four CRUD privilege rows plus the bulk one. This is what breaks
    // when an entity-registering seed is wired *below*
    // `entity_privileges::seed_all` in `EngineSystem::build()`: seed_all sweeps
    // whatever is registered at the moment it runs, so a late seed's entity is
    // invisible to it and only picks up privileges on the second boot.
    for logicalname in &registered {
        for action in ["read", "create", "update", "delete", "bulk"] {
            let key = format!("{logicalname}.{action}");
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM privilege WHERE key = $1)")
                    .bind(&key)
                    .fetch_one(db)
                    .await
                    .expect("read privileges");
            assert!(
                exists,
                "privilege {key} missing after a fresh boot — register this entity's \
                 seed above the entity_privileges::seed_all call in EngineSystem::build()"
            );
        }
    }

    // D-364's sidebar promotion, the half that is easiest to forget: the
    // entity can be perfectly seeded and the feature still unreachable because
    // nothing links to it. `sidebar_seed.rs` owns every built-in row.
    let documents_nav: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sidebar WHERE route = '/documents' \
           AND (is_active IS NULL OR is_active = true))",
    )
    .fetch_one(db)
    .await
    .expect("read sidebar");
    assert!(
        documents_nav,
        "the Documents sidebar row is missing after a fresh boot — a built-in page with \
         no navigation is unreachable; seed it in attome-api/src/sidebar_seed.rs"
    );
}

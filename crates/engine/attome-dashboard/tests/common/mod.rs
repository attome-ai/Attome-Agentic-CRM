//! Shared test infrastructure for this crate's DB-backed suites.
//!
//! R-07 (`document/xrm/module/M26-dashboard/remediation.md`) routed
//! several `do_*` functions (`widget_actions::do_duplicate_widget`,
//! `scenario::do_clone`) through the generic entity engine
//! (`attome_records::entity_crud::{create_record_for, update_record_for}`)
//! and made `layout::apply_pages_snapshot` (and therefore
//! `lifecycle::do_clone`/`do_restore_version`/`layout::do_create_from_layout`)
//! take `&EngineState` instead of a bare `&DbPool`, to resolve each written
//! entity's live `AttrInfo` for `validate_body`. Exercising any of those
//! directly against a real database — same "call the `pub` `do_*` function,
//! skip the HTTP layer" convention every suite in this crate already uses —
//! therefore needs a real (if mostly bare) `EngineState`, not just a `DbPool`.
//! `test_state` builds one the same way `attome-workflow/tests/execution.rs`
//! does.
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use uuid::Uuid;

/// Minimal `AppConfig` JSON good enough to construct an `AppState` — no HTTP
/// server is ever bound from a test, so most of this is inert. `direct_url`
/// mirrors `database`'s own throwaway URL: `attome_db::create_direct_pool` and
/// `attome_db::create_runtime_session` (outside a debug `DATABASE_URL`
/// override) take their endpoint from `database.direct_url`, and this
/// crate's code never uses those paths today, but keeping the two in sync
/// costs nothing and avoids a future trap.
fn test_config(direct_url: &str) -> AppConfig {
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
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "public",
                "connection_number": 5, "timeout": 5.0,
                "direct_url": "{direct_url}"
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
                "jwt_secret": "test-only-throwaway-secret", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
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
        direct_url = direct_url,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

// SAFETY: `std::env::set_var` is unsafe in edition 2024 — concurrent mutation
// from other threads is a real data race, not just a logical one (same
// hazard `attome-workflow/tests/execution.rs::ENV_LOCK` guards against). Every
// `#[tokio::test]` in this crate's suites that calls `test_state()` runs
// concurrently by default; this lock serializes those mutations with the
// synchronous env reads inside `attome_db::create_pool` that consume them.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `None` when there is no throwaway database configured — unwrap with
/// `attome_testkit::skip_if_no_db!`.
pub async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let _env_guard = ENV_LOCK.lock().await;
    // SAFETY: serialized by ENV_LOCK above — no other thread mutates or
    // reads these vars while this guard is held.
    unsafe {
        std::env::set_var("DATABASE_URL", &db_url);
        std::env::set_var("APP_ENV", "debug");
    }
    let config = test_config(&db_url);
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
    Some(EngineState::new(base))
}

/// This crate's own DB pool, out of an already-built `EngineState` — every
/// existing `test_db()` helper in this crate's suites returns this same
/// `attome_db::DbPool` shape, so call sites that only need the pool (most of
/// this crate's own raw-SQL fixtures) don't have to change.
pub fn pool(state: &EngineState) -> &DbPool {
    &state.base.db
}

/// Idempotent — safe to call at the top of every test in this file, same as
/// every other `seed()` in this workspace. Identical to each suite's own
/// former `seed_once`, kept here so every `tests/*.rs` in this crate shares
/// one copy (M26 R-15 finished what R-07 started: `context_engine.rs`/
/// `seed.rs` route through `test_state`/`pool` now too, though `seed.rs`
/// calls `attome_dashboard::seed`'s pieces directly to test idempotency and so
/// doesn't call this).
///
/// Takes `&EngineState` (not a bare `&DbPool`) and refreshes `state.entities`
/// from the freshly-seeded metadata afterward — R-07's Tier 1 conversions
/// (`widget_actions::do_duplicate_widget` and friends) go through
/// `attome_records::entity_crud::create_record_for`/`update_record_for`,
/// whose `validate_lookup_targets`/`lock_lookup_targets` read
/// `state.entities.load()` directly (unlike `resolve_entity`, that path does
/// NOT fall back to a live DB query regardless of
/// `cache.metadata_registry_enabled`) — a bare `EngineState::new(base)` starts
/// with an empty registry, so every lookup-typed field write would 404 as
/// "lookup target does not exist" without this.
// `#[allow(dead_code)]` — same "shared module, partial per-binary use" shape
// `admin_ctx` below documents: `seed.rs`'s own binary doesn't call this one.
#[allow(dead_code)]
pub async fn seed_once(state: &EngineState) {
    let db = &state.base.db;
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    // `attome-metric`'s bundle first: the decision/scenario entities in
    // attome-dashboard.json look up `dashboard_metric_definition`.
    attome_metric::metric::seed_for_tests(db)
        .await
        .expect("attome_metric::metric::seed_for_tests");
    attome_dashboard::seed::seed_for_tests(db)
        .await
        .expect("attome_dashboard::seed::seed_for_tests");
    // `seed_body`, not `seed`: `seed_for_tests` above rewrites
    // `dashboard_widget.widget_type`'s choice list to the bundle's
    // placeholder on every call, while `seed()` is gated by
    // `seed_gate::run_if_stale`, whose in-process stamp snapshot skips the
    // resync after the first test in a binary. Calling `seed()` here left every
    // later test with `["__PLACEHOLDER_SEE_RESIDUAL_CODE__"]` as the only valid
    // widget type (dashboard 10/10 plan, Phase 0 baseline).
    attome_dashboard::seed::seed_body(db)
        .await
        .expect("attome_dashboard::seed::seed_body");
    // R-07: `widget_actions::do_duplicate_widget` (and friends) now
    // go through `attome_records::entity_crud::create_record_for`, whose
    // `entity_mutation::create_one` reads auto-value rules from
    // `autovalue` — itself a metadata-defined entity migrations
    // don't create (only the real boot path's `attome_metadata::autovalue::seed`
    // does). Same fix `attome-workflow/tests/execution.rs::seed_platform`
    // documents for the identical gap.
    attome_metadata::autovalue::seed_for_tests(db)
        .await
        .expect("attome_metadata::autovalue::seed_for_tests");
    let registry = attome_core::meta_registry::build_registry(db)
        .await
        .expect("build_registry after seeding");
    state.entities.swap(registry);
}

/// A synthetic, fully-privileged `SecurityContext` for exercising a `do_*`
/// function directly against a live database, bypassing the HTTP
/// authorization layer these suites already don't stand up (same posture as
/// every other `pub async fn do_*` in this crate — see e.g. `tests/
/// dashboard_crud.rs`'s module doc comment). Re-exports
/// `attome_records::entity_crud::admin_security_context`, the same
/// synthetic-admin-context constructor `attome_workflow::scheduler::
/// system_security_context` and the duplicates-admin/auto-merge callback
/// already use for a platform-initiated write with no live HTTP caller.
// `#[allow(dead_code)]` — this shared module is compiled once per
// integration-test binary (`mod common;` in each), and not every binary uses
// every helper here (only `widget_actions.rs`'s `do_*` calls need a
// `SecurityContext`, `dashboard_crud.rs`'s don't) — the same "shared test
// helper, partial per-binary use" shape as every other `tests/common/mod.rs`
// in this workspace.
#[allow(dead_code)]
pub fn admin_ctx(user_id: Uuid) -> SecurityContext {
    attome_records::entity_crud::admin_security_context(user_id)
}

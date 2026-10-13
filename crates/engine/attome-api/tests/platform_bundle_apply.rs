//! REVIEW-2026-09-02 item 11 (seeds-to-bundles, D-478) — each
//! `platform-bundles/<module>.json` replaced that module's imperative
//! `ensure_entity`/`ensure_attribute`/`ensure_default_query`/
//! `ensure_secondary_view` seed calls (the pilot was `attome-s2s`).
//!
//! The equivalence proof this test relies on: `test_system()` boots a real
//! `EngineSystem`, which applies the platform bundles `build()` owns. Planning
//! a bundle against that already-provisioned database must then be a pure
//! no-op. Where a module's old seed function still exists it was the
//! oracle; where D-478 deleted it, the test applies the bundle to a database
//! that never had it and re-plans. Any field-type, required-ness, or shape
//! mismatch between the bundle and what boots would show up as a `create`,
//! `update`, or `blocked` plan entry instead. This is a stronger check than hand-diffing JSON against Rust: it
//! proves the bundle reproduces exactly what boots today, not what the
//! bundle's author believes the old code does.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test platform_bundle_apply -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::{Bundle, PlanOptions, apply_platform_bundle, derived_id, plan_bundle};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// The pieces of the throwaway database's URL the config's own
/// `database.*` fields must agree with. `bundle::apply` reaches
/// `provision::sync_attribute_index(config, ..)` when it creates a
/// sortable/filterable attribute, and that opens a *fresh* migrator
/// connection built from `config.database` (`migrator_database_url()`),
/// not from the `DATABASE_URL` env override `create_pool` honours — so a
/// placeholder identity here fails with "password authentication failed"
/// the moment a bundle provisions its first indexed attribute against the
/// per-binary clone `attome_testkit::test_db_url` allocates.
struct DbParts {
    host: String,
    port: String,
    name: String,
    user: String,
    password: String,
}

fn db_parts() -> DbParts {
    let url = attome_testkit::migrated_db_url().expect("test_system checks DATABASE_URL first");
    let rest = url
        .strip_prefix("postgres://")
        .or_else(|| url.strip_prefix("postgresql://"))
        .expect("postgres:// DATABASE_URL");
    let (userinfo, rest) = rest.split_once('@').expect("user@host in DATABASE_URL");
    let (user, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let (hostport, rest) = rest.split_once('/').expect("host/db in DATABASE_URL");
    let (host, port) = hostport.split_once(':').unwrap_or((hostport, "5432"));
    let name = rest.split('?').next().unwrap_or(rest);
    DbParts {
        host: host.to_owned(),
        port: port.to_owned(),
        name: name.to_owned(),
        user: user.to_owned(),
        password: password.to_owned(),
    }
}

fn test_config() -> AppConfig {
    let db = db_parts();
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 16777216, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "use_gzip": false,
                "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 30, "keepalive_requests": 100,
                "static_files_cache_time": 0, "server_header_field": "attome-test"
            }},
            "database": {{
                "host": "{db_host}", "port": {db_port}, "dbname": "{db_name}",
                "user": "{db_user}", "password": "{db_password}", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
            }},
            "cache": {{
                "host": "{redis_host}", "port": {redis_port}, "password": "",
                "db": 9, "connection_pool_size": 4, "timeout": 2000,
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
            "approval": {{ "required_actions": [] }}
        }}"#,
        db_host = db.host,
        db_port = db.port,
        db_name = db.name,
        db_user = db.user,
        db_password = db.password,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
    attome_testkit::migrated_db_url()?;

    let config = test_config();
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

fn load_platform_bundle(module: &str) -> Bundle {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../platform-bundles")
        .join(format!("{module}.json"));
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Shared assertion every platform-bundle pilot test below uses: planning
/// `module`'s bundle against a database the OLD seed function already ran
/// against must be a pure no-op. See this file's module doc for why that's
/// a stronger proof than hand-diffing JSON against Rust.
async fn assert_platform_bundle_is_pure_noop(state: &EngineState, module: &str) {
    let bundle = load_platform_bundle(module);
    let license = state.modules.load_full();

    let plan = plan_bundle(
        &state.base.db,
        &license,
        &bundle,
        PlanOptions {
            allow_retire: false,
            additive_only: true,
        },
    )
    .await
    .unwrap_or_else(|e| panic!("{module}: plan_bundle failed: {e}"));

    assert!(
        plan.blocked.is_empty(),
        "{module} platform bundle disagrees with the live schema the old seed produced: {:#?}",
        plan.blocked
    );
    assert!(
        plan.retires.is_empty(),
        "{module} platform bundle would retire something the old seed created: {:#?}",
        plan.retires
    );
    let non_noop: Vec<_> = plan
        .entries
        .iter()
        .filter(|e| e.action != attome_api::bundle::plan::PlanAction::Noop)
        .collect();
    assert!(
        non_noop.is_empty(),
        "{module} platform bundle is not a pure no-op against what the old seed already \
         produced -- every non-noop entry below is a real behavioral difference between the \
         bundle and the code it's meant to replace: {non_noop:#?}"
    );
}

#[tokio::test]
async fn s2s_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-s2s").await;
}

#[tokio::test]
async fn server_license_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-license").await;
}

#[tokio::test]
async fn audit_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-audit").await;
}

#[tokio::test]
async fn compliance_consent_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-compliance-consent").await;
}

#[tokio::test]
async fn compliance_legal_matter_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-compliance-legal-matter").await;
}

// D-479 (M26 R-09) deleted `attome_report::seed::seed` (the legacy `dashboard`
// entity) and gutted `platform-bundles/attome-report.json` to `entities: []` —
// the test that used to live here proved the bundle reproduced that seed's
// output, and neither side of that comparison exists any more. There is
// nothing left for a "pure no-op against the old seed" check to verify for
// this module (an empty bundle is trivially a no-op against anything).

/// `attome_report::seed::seed_reports` runs from `crates/server/src/boot.rs`
/// AFTER `.build()` returns (it needs `user_account` already
/// registered, which `.build()`'s `attome_security::seed::seed` provides) --
/// replicated here the same way as the dashboard seed above.
#[tokio::test]
async fn report_reports_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    attome_report::seed::seed_reports(&system.state().base.db_migrator)
        .await
        .expect("attome_report::seed::seed_reports");
    assert_platform_bundle_is_pure_noop(system.state(), "attome-report-reports").await;
}

/// `attome-dashboard`'s bundle covers the 8 entities `seed.rs` itself owns
/// (dashboard/version/page/section/breakpoint/widget/variable/parameter),
/// their views, and (since M26 R-05) 7 developer-authored "General:" report
/// queries that used to be raw-`INSERT`ed by the now-deleted
/// `general_seed.rs` — see `dashboard_general_report_queries_are_live_
/// and_executable_after_apply` below for the query-specific assertions
/// (version rows, executability) this pure-noop check doesn't cover.
/// `widget_type`'s choice list is deliberately NOT asserted here: it is
/// derived at runtime from `widget_registry::registry().type_ids()`, a
/// genuinely dynamic source of truth, and the bundle ships only a
/// placeholder for it — the residual `attome_dashboard::seed()` re-syncs that
/// one attribute's choices after applying the bundle, so plan_bundle alone
/// would see a mismatch there by design. `metric_seed.rs`/`decision_seed.rs`/
/// `scenario_seed.rs` are separate, out of scope here.
#[tokio::test]
async fn dashboard_platform_bundle_is_a_pure_noop_against_the_old_seed_except_widget_type() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    let state = system.state();
    let bundle = load_platform_bundle("attome-dashboard");
    let license = state.modules.load_full();

    let plan = plan_bundle(
        &state.base.db,
        &license,
        &bundle,
        PlanOptions {
            allow_retire: false,
            additive_only: true,
        },
    )
    .await
    .expect("plan_bundle");

    assert!(
        plan.blocked.is_empty(),
        "attome-dashboard platform bundle disagrees with the live schema the old seed produced: {:#?}",
        plan.blocked
    );
    assert!(
        plan.retires.is_empty(),
        "attome-dashboard platform bundle would retire something the old seed created: {:#?}",
        plan.retires
    );
    let non_noop: Vec<_> = plan
        .entries
        .iter()
        .filter(|e| e.action != attome_api::bundle::plan::PlanAction::Noop)
        .filter(|e| !e.key.contains("widget_type"))
        .collect();
    assert!(
        non_noop.is_empty(),
        "attome-dashboard platform bundle is not a pure no-op (excluding the known widget_type \
         placeholder) against what the old seed already produced: {non_noop:#?}"
    );
}

/// M26 R-05: `general_seed.rs` used to raw-`INSERT` 8 report queries
/// straight into `sql_query`, bypassing `query_admin.rs`'s publish
/// pipeline entirely — so none of them ever got an
/// `sql_query_version` row, and `execute_stored_query` rejected
/// every one (`query_exec.rs`'s "any `sql_query` row with no
/// `sql_query_version` entry" fallback comment names this exact
/// class of bug). 7 of the 8 now live in the bundle's `queries[]` instead
/// (the 8th, "Team Members Breakdown", needs a `JOIN` across
/// `team`/`user_account_mm_team`/`user_account` that
/// a platform bundle's query containment check structurally cannot admit —
/// see `seed.rs`'s module doc), reconciled through the same
/// `attome_records::query_admin::reconcile_query` path every other
/// bundled query already uses. This test proves both halves of the fix: a
/// version row exists for every one of the 7, and at least one is genuinely
/// executable end to end, through the same `execute_stored_query` function
/// `POST /api/v1/query/execute` calls — not just "a row exists".
#[tokio::test]
async fn dashboard_general_report_queries_are_live_and_executable_after_apply() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    let state = system.state();
    let db = &state.base.db;

    let rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, record_no FROM sql_query \
         WHERE record_no LIKE 'General:%' AND (is_active IS NULL OR is_active = true)",
    )
    .fetch_all(db)
    .await
    .expect("query sql_query for 'General:' rows");
    assert_eq!(
        rows.len(),
        7,
        "expected 7 'General:' report queries live after the attome-dashboard platform bundle \
         applies (8 minus 'Team Members Breakdown', which cannot be bundled — see seed.rs's \
         module doc): {rows:?}"
    );

    for (query_id, name) in &rows {
        let version_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sql_query_version WHERE query_id = $1")
                .bind(query_id)
                .fetch_one(db)
                .await
                .expect("count sql_query_version rows");
        assert!(
            version_count >= 1,
            "{name} (query_id {query_id}) has no sql_query_version row — the exact \
             general_seed.rs gap R-05 fixed"
        );
    }

    // Executability: run one representative query end to end through the
    // same function the HTTP handler calls, not just an existence check.
    let (active_users_id, _) = rows
        .iter()
        .find(|(_, name)| name == "General: Active Users Count")
        .expect("'General: Active Users Count' is one of the 7 bundled queries");

    let security = attome_server::security::SecurityContext {
        user_id: uuid::Uuid::now_v7(),
        is_admin: true,
        privileges: std::collections::HashSet::new(),
        field_grants: std::collections::HashSet::new(),
        field_write_grants: std::collections::HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: std::collections::HashMap::new(),
        role_ids: None,
        service_principal: false,
    };
    let body: attome_records::query_exec::ExecuteQueryRequest =
        serde_json::from_value(serde_json::json!({ "query_id": active_users_id }))
            .expect("ExecuteQueryRequest deserializes from a bare query_id");

    let response = attome_records::query_exec::execute_stored_query(state, &security, body)
        .await
        .expect("General: Active Users Count must execute now that it has a version row");
    let response_json = serde_json::to_value(&response).expect("ExecResponse serializes");
    assert!(
        response_json["data"]["records"].is_array(),
        "execute_stored_query response has no records array: {response_json:#?}"
    );
}

#[tokio::test]
async fn project_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-project").await;
}

// attome-ai's three `_seed.rs` files are called from `crates/server/src/
// boot.rs` BEFORE `EngineSystem::builder(..).build()` (a real, non-dev
// dependency on attome-api forces this placement — see each seed file's own
// doc comment), so `test_system()` above never runs them. Each test below
// calls the old seed directly first to establish the "already seeded"
// baseline the equivalence proof depends on, exactly matching what boot.rs
// does before `.build()` runs.

// `ai_agent`'s equivalence-with-the-old-seed proof was retired here: the
// agent redesign (persona/model-config schema — name, status, icon, color,
// model lookups, system_instructions, personality/tone relationships —
// replacing the old governance schema of purpose/risk_ceiling/
// restrict_actions/allowed_action_ids/system_prompt_version/
// knowledge_collection_refs/schedule_trigger_ref/is_template) is a
// deliberate, permanent divergence from `agent_seed::seed`'s output, not a
// mechanical bundle-format migration — so "pure noop against the old seed"
// is no longer the right property to assert. `agent_seed.rs` itself is
// removed alongside this test; see `platform-bundles/attome-ai-agent.json` for
// the current schema.
//
// The governance follow-up this redesign left open is being closed by later
// decisions:
// - D-503 moved session constraints off the definition and onto the starting
//   surface (`attome_ai::agent::SessionConstraints`); `start_session` no longer
//   reads any governance field from an `ai_agent` record.
// - D-505 adds the reusable `ai_agent_policy` entity, which a definition
//   references through `policy_ref`. Both are in the same bundle.
//   `start_session` resolving and combining that policy is a later change.

// `ai_model_registry`'s equivalence-with-the-old-seed proof was retired
// here: D-491 removed the `ai_model_approval` entity and its bundle
// (`platform-bundles/attome-ai-model-registry.json`) entirely — model approval
// is now `ai_model.approval_status`, a field on the AI Model catalog
// bundle (`attome-ai-model-catalog`, no Rust seed of its own, so it was never
// one of this section's "old seed" equivalence proofs to begin with). There
// is no bundle left for this test to compare against.

#[tokio::test]
async fn ai_quality_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    let state = system.state();
    // `quality_seed::seed` is gone (D-478 second pass) — apply the bundle
    // once, then prove a second plan is a pure no-op (idempotency).
    apply_platform_bundle(
        state,
        "attome-ai-quality",
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../platform-bundles/attome-ai-quality.json"),
        )
        .expect("read attome-ai-quality.json"),
    )
    .await
    .expect("apply attome-ai-quality");
    assert_platform_bundle_is_pure_noop(state, "attome-ai-quality").await;
}

#[tokio::test]
async fn server_communication_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-communication").await;
}

#[tokio::test]
async fn server_communication_event_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-communication-event").await;
}

#[tokio::test]
async fn server_document_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-document").await;
}

#[tokio::test]
async fn server_follow_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-follow").await;
}

/// D-602 — a bundle with no old seed: once `EngineSystem::build` has applied
/// it, planning it again must be a pure no-op (it applies cleanly and is
/// idempotent).
#[tokio::test]
async fn reminder_platform_bundle_is_a_pure_noop_once_applied() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "xrm-reminder").await;
}

#[tokio::test]
async fn server_glossary_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-glossary").await;
}

/// attome-grc's old seed also patches an additive `risk_ref` attribute onto
/// `project_issue` (a different crate's entity) — the bundle carries
/// that as an `attribute_patches` entry, and the no-op proof below covers
/// it the same way it covers every entity: a patch that already matches the
/// live attribute plans as `Noop`, not `Update`/`Blocked`.
#[tokio::test]
async fn grc_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-grc").await;
}

/// `attome_notification::seed::seed` runs inside `EngineSystem::build()`
/// (`attome-api/src/system.rs`), so `test_system()` already triggers it.
#[tokio::test]
async fn notification_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-notification").await;
}

/// `attome_webcrawl::seed::seed` runs inside `EngineSystem::build()`
/// (`attome-api/src/system.rs`), so `test_system()` already triggers it.
#[tokio::test]
async fn webcrawl_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-webcrawl").await;
}

/// `attome-docgen`, `attome-integration` and `attome-workflow` apply their bundles
/// from `crates/server/src/boot.rs`, before `EngineSystem::builder(...).build()`
/// (each crate depends on `attome-api`, so `build()` cannot call back into
/// it). `test_system()` only replicates `build()`, so these tests apply the
/// bundle themselves. Their old seed functions are deleted (D-478), so the
/// proof is the `quality_seed` one above: the bundle applies cleanly to a
/// database that never had it, and a second plan is a pure no-op.
async fn assert_boot_applied_bundle_applies_then_replans_as_noop(
    state: &EngineState,
    module: &str,
) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../platform-bundles")
        .join(format!("{module}.json"));
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    apply_platform_bundle(state, module, &raw)
        .await
        .unwrap_or_else(|e| panic!("apply {module}: {e:?}"));
    assert_platform_bundle_is_pure_noop(state, module).await;
}

#[tokio::test]
async fn docgen_platform_bundle_applies_then_replans_as_noop() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_boot_applied_bundle_applies_then_replans_as_noop(system.state(), "attome-docgen").await;
}

#[tokio::test]
async fn integration_platform_bundle_applies_then_replans_as_noop() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_boot_applied_bundle_applies_then_replans_as_noop(system.state(), "attome-integration")
        .await;
}

#[tokio::test]
async fn workflow_platform_bundle_applies_then_replans_as_noop() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_boot_applied_bundle_applies_then_replans_as_noop(system.state(), "attome-workflow")
        .await;
}

#[tokio::test]
async fn server_note_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-note").await;
}

/// Basic-units U2 (D-600): no old seed ever existed for `activity`, so
/// this proves the boot apply (`EngineSystem::build`) landed the whole bundle,
/// seeded state model included: re-planning it is a pure no-op.
#[tokio::test]
async fn server_activity_platform_bundle_applies_at_boot_and_replans_as_a_noop() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-activity").await;
    let (initial_state, transitions): (String, i64) = sqlx::query_as(
        "SELECT m.initial_state, \
                (SELECT COUNT(*) FROM state_transition t \
                  WHERE t.model_ref = m.id AND t.is_deleted = false) \
           FROM state_model m \
          WHERE m.entity_logicalname = 'activity' AND m.is_deleted = false",
    )
    .fetch_one(&system.state().base.db)
    .await
    .expect("activity state model seeded at boot");
    assert_eq!(initial_state, "open");
    assert_eq!(transitions, 4);
}

#[tokio::test]
async fn server_resource_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-resource").await;
}

/// `tag_item`'s free-text `name` field an old seed revision created is
/// retired by a small residual function (`crate::tag_seed::retire_legacy_name`
/// in production, not this test) that still runs after the bundle — a fresh
/// database never provisions `name` in the first place, so the bundle's
/// no-op proof below doesn't need to know about it either way.
#[tokio::test]
async fn server_tag_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-tag").await;
}

#[tokio::test]
async fn server_relationship_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-relationship").await;
}

/// `attome-security/src/seed.rs` split: `platform-bundles/attome-security.json`
/// covers only `register_readonly_entities_body`'s static entity/attribute/
/// query/view registrations plus the two `ensure_privilege` calls
/// (`sidebar.manage`, `system.admin`). The bootstrap-admin grant (resolves
/// `config.security.bootstrap_admin_email` against a live `
/// systemuser` row, hard-fails boot if it doesn't resolve) reads runtime
/// config and branches on live data — not expressible as a static bundle —
/// and stays a residual Rust function, `attome_security::seed::grant_bootstrap_admin`.
#[tokio::test]
async fn security_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-security").await;
}

// `attome_service::analytics_seed::seed` took a prior seed's resolved
// `service_ticket` entity id as a parameter, which is why D-478 originally
// deferred it: every ensure_report_query call inside it only ever used that
// id to scope a query to service_ticket by uuid, exactly the "which entity does
// this query belong to" shape `QueryDef.entity` (a logical name string,
// resolved at apply time) already handles — no genuinely id-shaped value
// escapes the function. `platform-bundles/attome-service.json` now carries its
// three SLA analytics queries directly. `test_system()`'s `.build()` chain
// still runs attome-service's bundle AND (until the call site below is
// updated) the old analytics_seed::seed, so this proves the bundle's new
// entries exactly match what that old code already produces.
#[tokio::test]
async fn service_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-service").await;
}

/// `authentication_type`/`ai_provider` are brand new (no prior
/// imperative seed), so there is nothing to prove a no-op against — this
/// instead proves the three bundles actually apply end to end against a
/// bare test database, in the same order `boot.rs` applies them:
/// entity-defining bundle, then its `record_sets` sibling (split out because
/// a bundle's plan is computed against live metadata as of that one
/// `apply_platform_bundle` call — `record_sets` for an entity the SAME
/// bundle also defines always comes back "not live", the exact failure this
/// test guards against regressing), then `attome-ai-provider`.
#[tokio::test]
async fn ai_provider_and_authentication_type_bundles_apply_end_to_end() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    let state = system.state();

    apply_platform_bundle(
        state,
        "xrm-core-authentication-type",
        include_str!("../../../../platform-bundles/xrm-core-authentication-type.json"),
    )
    .await
    .expect("xrm-core-authentication-type applies");
    apply_platform_bundle(
        state,
        "xrm-core-authentication-type-data",
        include_str!("../../../../platform-bundles/xrm-core-authentication-type-data.json"),
    )
    .await
    .expect("xrm-core-authentication-type-data applies");
    apply_platform_bundle(
        state,
        "attome-ai-provider",
        include_str!("../../../../platform-bundles/attome-ai-provider.json"),
    )
    .await
    .expect("attome-ai-provider applies");

    let auth_type_count: i64 = sqlx::query_scalar("SELECT count(*) FROM authentication_type")
        .fetch_one(&state.base.db)
        .await
        .expect("count authentication types");
    assert_eq!(
        auth_type_count, 8,
        "all 8 seeded authentication types landed"
    );

    // Re-applying all three (the shape every real boot repeats) must be a
    // pure no-op the second time — the watermark hash short-circuits it
    // before even reaching `plan_bundle`, but this also catches a hash that
    // isn't stable across identical re-applies.
    apply_platform_bundle(
        state,
        "xrm-core-authentication-type",
        include_str!("../../../../platform-bundles/xrm-core-authentication-type.json"),
    )
    .await
    .expect("xrm-core-authentication-type re-applies idempotently");
    apply_platform_bundle(
        state,
        "xrm-core-authentication-type-data",
        include_str!("../../../../platform-bundles/xrm-core-authentication-type-data.json"),
    )
    .await
    .expect("xrm-core-authentication-type-data re-applies idempotently");
    apply_platform_bundle(
        state,
        "attome-ai-provider",
        include_str!("../../../../platform-bundles/attome-ai-provider.json"),
    )
    .await
    .expect("attome-ai-provider re-applies idempotently");

    let auth_type_count_after: i64 = sqlx::query_scalar("SELECT count(*) FROM authentication_type")
        .fetch_one(&state.base.db)
        .await
        .expect("count authentication types after re-apply");
    assert_eq!(
        auth_type_count_after, 8,
        "re-applying record_sets does not duplicate rows"
    );
}

/// The "Example Provider" -> "Example Model" -> "Example Agent" inactive
/// scaffold `boot.rs` seeds so a fresh deployment has something to look at
/// and edit, without any real provider/API key. The model and agent chain
/// onto the scaffold's own rows by `derived_id` literal (see `boot.rs`'s
/// comment on the `attome-ai-provider-data` call) — this test is the proof that
/// the chain lands the expected ids on a genuinely fresh database, applying
/// every bundle in the exact order/names `boot.rs` does.
/// `bundle_record_key_reference.rs` covers business-key lookups in `record_sets`.
#[tokio::test]
async fn ai_scaffold_records_chain_by_derived_id_on_a_fresh_database() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    let state = system.state();

    for (name, bytes) in [
        (
            "attome-ai-personality",
            include_str!("../../../../platform-bundles/attome-ai-personality.json"),
        ),
        (
            "attome-ai-tone",
            include_str!("../../../../platform-bundles/attome-ai-tone.json"),
        ),
        (
            "attome-ai-tone-data",
            include_str!("../../../../platform-bundles/attome-ai-tone-data.json"),
        ),
        (
            "xrm-core-authentication-type",
            include_str!("../../../../platform-bundles/xrm-core-authentication-type.json"),
        ),
        (
            "xrm-core-authentication-type-data",
            include_str!("../../../../platform-bundles/xrm-core-authentication-type-data.json"),
        ),
        (
            "attome-ai-provider",
            include_str!("../../../../platform-bundles/attome-ai-provider.json"),
        ),
        (
            "attome-ai-provider-data",
            include_str!("../../../../platform-bundles/attome-ai-provider-data.json"),
        ),
        (
            "attome-ai-model-catalog",
            include_str!("../../../../platform-bundles/attome-ai-model-catalog.json"),
        ),
        (
            "attome-ai-model-catalog-data",
            include_str!("../../../../platform-bundles/attome-ai-model-catalog-data.json"),
        ),
        (
            "attome-ai-agent",
            include_str!("../../../../platform-bundles/attome-ai-agent.json"),
        ),
        (
            "attome-ai-agent-data",
            include_str!("../../../../platform-bundles/attome-ai-agent-data.json"),
        ),
    ] {
        apply_platform_bundle(state, name, bytes)
            .await
            .unwrap_or_else(|e| panic!("{name} applies: {e}"));
    }

    let expected_provider = derived_id("record", "ai_provider[name=Example Provider]");
    let expected_model = derived_id("record", "ai_model[name=Example Model]");
    let expected_agent = derived_id("record", "ai_agent[name=Example Agent]");

    let (provider_id, provider_type, status): (uuid::Uuid, String, String) = sqlx::query_as(
        "SELECT id, provider_type, status FROM ai_provider WHERE name = 'Example Provider'",
    )
    .fetch_one(&state.base.db)
    .await
    .expect("Example Provider row exists");
    assert_eq!(
        provider_id, expected_provider,
        "provider gets its derived id"
    );
    assert_eq!(provider_type, "custom");
    assert_eq!(status, "closed", "scaffold provider ships inactive");

    let (model_id, provider_ref, approval_status): (uuid::Uuid, uuid::Uuid, String) =
        sqlx::query_as(
            "SELECT id, provider_ref, approval_status FROM ai_model WHERE name = 'Example Model'",
        )
        .fetch_one(&state.base.db)
        .await
        .expect("Example Model row exists");
    assert_eq!(model_id, expected_model, "model gets its derived id");
    assert_eq!(
        provider_ref, expected_provider,
        "chains onto Example Provider"
    );
    assert_eq!(
        approval_status, "pending",
        "scaffold model ships unapproved, so require_approved_model refuses it"
    );

    let (agent_id, primary_model_ref, agent_status): (uuid::Uuid, uuid::Uuid, String) =
        sqlx::query_as(
            "SELECT id, primary_model_ref, status FROM ai_agent WHERE name = 'Example Agent'",
        )
        .fetch_one(&state.base.db)
        .await
        .expect("Example Agent row exists");
    assert_eq!(agent_id, expected_agent, "agent gets its derived id");
    assert_eq!(
        primary_model_ref, expected_model,
        "chains onto Example Model"
    );
    assert_eq!(agent_status, "draft", "scaffold agent ships as a draft");

    // Re-applying the whole chain (the shape every real boot repeats) must
    // stay a pure no-op -- same regression `ai_provider_and_
    // authentication_type_bundles_apply_end_to_end` guards for the schema
    // bundles, extended here to the record-set data bundles.
    for (name, bytes) in [
        (
            "attome-ai-provider-data",
            include_str!("../../../../platform-bundles/attome-ai-provider-data.json"),
        ),
        (
            "attome-ai-model-catalog-data",
            include_str!("../../../../platform-bundles/attome-ai-model-catalog-data.json"),
        ),
        (
            "attome-ai-agent-data",
            include_str!("../../../../platform-bundles/attome-ai-agent-data.json"),
        ),
    ] {
        apply_platform_bundle(state, name, bytes)
            .await
            .unwrap_or_else(|e| panic!("{name} re-applies idempotently: {e}"));
    }
    let provider_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ai_provider WHERE name = 'Example Provider'")
            .fetch_one(&state.base.db)
            .await
            .expect("count Example Provider rows");
    assert_eq!(
        provider_count, 1,
        "re-applying record_sets does not duplicate rows"
    );
}

// ── Seeds-to-bundles, second pass (D-478) ────────────────────────────────
// The remaining `db: &DbPool`-only seeds: `attome_metadata::autovalue::seed`,
// `attome_api::profiler_finding_seed::seed`, `attome_metric::metric::seed` +
// `attome_dashboard::{decision,scenario}_seed::seed` (their `Uuid` parameters
// were only ever lookup targets — `AttributeDef.lookup_entity` by
// logicalname), `attome_project::seed::seed_utilization` +
// `attome_service::queue_analytics_seed::seed` (entity-scoped `is_report`
// queries), the two `seed_state_models` (`StateModelDef`), and the two
// boot.rs-only seeds `server::apikey_seed` / `attome_search::saved_search`.

#[tokio::test]
async fn entity_autovalue_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-metadata-autovalue").await;
}

#[tokio::test]
async fn server_profiler_finding_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-api-profiler-finding").await;
}

#[tokio::test]
async fn metric_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    assert_platform_bundle_is_pure_noop(system.state(), "attome-metric").await;
}

// `attome-search-saved-search` applies from `crates/server/src/boot.rs` before
// `.build()`, so `test_system()` never applies it — apply it here first,
// then prove a second plan is a pure no-op (idempotency; the equivalence
// proof against the old `saved_search::seed` ran before that seed was
// deleted).
#[tokio::test]
async fn search_saved_search_platform_bundle_is_a_pure_noop_against_the_old_seed() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    let state = system.state();
    apply_platform_bundle(
        state,
        "attome-search-saved-search",
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../platform-bundles/attome-search-saved-search.json"),
        )
        .expect("read attome-search-saved-search.json"),
    )
    .await
    .expect("apply attome-search-saved-search");
    assert_platform_bundle_is_pure_noop(state, "attome-search-saved-search").await;
}

// `api_key` applies from `crates/server/src/boot.rs` before `.build()`, so
// `test_system()` never applies it — apply it here first, then prove a
// second plan is a pure no-op (idempotency; the equivalence proof against
// the old `server::apikey_seed::seed` body ran before that seed was
// deleted — `crates/server` is not reachable from an `xrm-*` test).
#[tokio::test]
async fn apikey_platform_bundle_is_a_pure_noop_after_apply() {
    let Some(system) = test_system().await else {
        eprintln!("skipping: no DATABASE_URL");
        return;
    };
    let state = system.state();
    apply_platform_bundle(
        state,
        "api_key",
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../platform-bundles/xrm-core-api_key.json"),
        )
        .expect("read xrm-core-api_key.json"),
    )
    .await
    .expect("apply api_key");
    assert_platform_bundle_is_pure_noop(state, "xrm-core-api_key").await;
}

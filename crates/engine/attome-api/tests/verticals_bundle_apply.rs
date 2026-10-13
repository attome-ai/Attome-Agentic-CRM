//! REVIEW-2026-09-02 finding #6 — proves what no test in this workspace
//! proved before: that every vertical bundle under `verticals/*/bundle.json`
//! actually applies to a **fresh** deployment. Before this file, "validated"
//! meant a `bundle-tool plan` run against the shared dev database, which
//! already had every entity these bundles reference — so a bundle missing a
//! cross-module field (an `attribute_patches` gap) or an undeclared
//! `depends_on_bundles` edge would `plan` clean there and still fail on a
//! real customer deployment.
//!
//! This binary gets its own throwaway database (D-343, one per test
//! binary), seeded only by the platform's own boot-time seeds — the closest
//! thing to "a fresh deployment" a test can stand up without a running
//! server process. It applies each bundle directly through the same
//! `plan_bundle`/`run_apply_job` functions the HTTP admin API and
//! `bundle-tool` call, in dependency order (crm and contract-management
//! before sales and vendor-supplier, which patch/reference their entities),
//! and asserts:
//!   1. the plan has zero `blocked` entries (the exact failure mode a
//!      missing field or an unmet `depends_on_bundles` produces);
//!   2. the apply is reported `succeeded`;
//!   3. every entity the bundle defines is live and active afterward.
//!
//! `field-service` has no bundle (D-475 — back-office fields ride
//! `attribute_patches` on other verticals' bundles, not a bundle of its
//! own) and is correctly absent from the list below.
//!
//! Requires a live Postgres (`DATABASE_URL`) and Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`) — same convention as `bundle_apply.rs`. Run with
//! `--test-threads=1`: applies share one throwaway database.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test verticals_bundle_apply -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::{Bundle, PlanOptions, canonical_json, ledger, plan_bundle, run_apply_job};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_server::AppState;
use attome_testkit::skip_if_no_db;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

/// The throwaway database's connection identity, parsed from the URL
/// `attome_testkit::test_db_url` allocates. The config's own `database.*`
/// fields must agree with it: boot-time bundle applies reach
/// `provision::sync_attribute_index(config, ..)` whenever they create a
/// sortable/filterable attribute, and that opens a fresh migrator connection
/// from `config.database`, not from the `DATABASE_URL` override
/// `create_pool` honours. With placeholder values that connection fails with
/// "password authentication failed for user \"unused\"" the first time a
/// platform bundle provisions an indexed attribute on the clone (the same fix
/// `platform_bundle_apply.rs` carries).
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

    // Same registration chain `crates/server/src/boot.rs` uses in
    // production, minus `attome_process`/`attome_predict` — neither is a
    // dependency of this crate (dev or otherwise) and none of the nine
    // vertical bundles' `requires.modules` names `process` or `predict`.
    let system = EngineSystem::builder(state)
        .register(attome_security::model::SecurityModel)
        .register(attome_notification::NotificationModel)
        .register(attome_workflow::WorkflowModel)
        .register(attome_project::ProjectModel)
        .register(attome_service::ServiceModel)
        .register(attome_grc::GrcModel)
        .register(attome_dashboard::DashboardModel)
        .register(attome_compliance::model::ComplianceModel)
        .register(attome_ai::ActionModel)
        .register(attome_ai::DecisionExecutionModel)
        .register(attome_ai::OutcomeModel)
        .register(attome_search::SearchModel)
        .register(attome_report::ReportModel)
        .register(attome_docgen::DocgenModel)
        .register(attome_state::StateModel)
        .register(attome_integration::IntegrationModel)
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
    Some(system)
}

fn load_bundle(vertical: &str) -> Bundle {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../verticals")
        .join(vertical)
        .join("bundle.json");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Plans, persists, queues, and runs `bundle`'s apply inline (no worker),
/// same shape `bundle_apply.rs::plan_queue_apply` uses. Asserts the plan has
/// no `blocked` entries — the exact failure mode a missing cross-module
/// field or an unmet `depends_on_bundles` edge would produce — before
/// applying, so a failure here names the specific blocked component instead
/// of surfacing as an opaque apply error.
async fn apply_bundle_to_fresh_deployment(state: &EngineState, vertical: &str) {
    apply_loaded_bundle(state, vertical, load_bundle(vertical)).await;
}

/// [`apply_bundle_to_fresh_deployment`]'s body, for a bundle the caller has
/// already loaded (and possibly narrowed).
async fn apply_loaded_bundle(state: &EngineState, vertical: &str, bundle: Bundle) {
    let license = state.license.load_full();
    // `additive_only`: a vertical bundle is a slice of the deployment, not a
    // whole-deployment snapshot, so the platform's own entities, queries and
    // state models are outside its scope. Without it every one of them reads
    // as "live but absent from the bundle" and comes back `Blocked: retire
    // requires allow_retire` (hundreds of entries on a freshly booted
    // deployment), which hides the blocked entries this test exists to find.
    // Real blockers (a missing cross-module field, an unmet
    // `depends_on_bundles`) are still reported under this option.
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
    .unwrap_or_else(|e| panic!("{vertical}: plan_bundle failed: {e}"));
    assert!(
        plan.blocked.is_empty(),
        "{vertical}: bundle would not apply cleanly to a fresh deployment — blocked: {:#?}",
        plan.blocked
    );

    let bundle_json = serde_json::to_value(
        serde_json::from_slice::<serde_json::Value>(&canonical_json(&bundle)).unwrap(),
    )
    .unwrap();
    let plan_json = serde_json::to_value(&plan).unwrap();
    let plan_id = ledger::insert_plan(
        &state.base.db,
        &bundle_json,
        &plan_json,
        &plan.bundle_hash,
        &plan.basis_hash,
        attome_api::bundle::BUNDLE_FORMAT,
        attome_api::bundle::PLATFORM_VERSION,
        false,
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("{vertical}: insert_plan failed: {e}"));

    assert!(
        ledger::mark_queued(&state.base.db, plan_id, None)
            .await
            .unwrap_or_else(|e| panic!("{vertical}: mark_queued failed: {e}")),
        "{vertical}: plan must move planned -> queued"
    );
    run_apply_job(state, plan_id)
        .await
        .unwrap_or_else(|e| panic!("{vertical}: run_apply_job failed: {e}"));

    let row = ledger::get_plan(&state.base.db, plan_id)
        .await
        .unwrap()
        .expect("plan row exists");
    assert_eq!(
        row.status,
        ledger::PlanStatus::Succeeded,
        "{vertical}: apply did not report succeeded"
    );

    // Round-trip: every entity this bundle defines must be live and active
    // now — proves the apply actually landed schema, not just that the job
    // reported success.
    for entity in &bundle.entities {
        let is_active: Option<bool> =
            sqlx::query_scalar("SELECT is_active FROM entity_info WHERE logicalname = $1")
                .bind(&entity.logicalname)
                .fetch_optional(&state.base.db)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "{vertical}: query entity_info for {}: {e}",
                        entity.logicalname
                    )
                });
        assert_eq!(
            is_active,
            Some(true),
            "{vertical}: entity '{}' is not live+active after apply",
            entity.logicalname
        );
    }
}

/// Dependency order: `crm` and `contract-management` are applied before
/// `sales` (patches `account`, needs `crm` live) and `vendor-supplier`
/// (patches `account`, needs both `crm` and `contract-management` live) —
/// exactly the order their `requires.depends_on_bundles` now declares.
/// Every other vertical is independent of the rest.
const APPLY_ORDER: &[&str] = &[
    "crm",
    "contract-management",
    "asset-management",
    "customer-service",
    "enterprise-architecture",
    "finance",
    "human-resources",
    "sales",
    "vendor-supplier",
    "game-ops",
];

#[tokio::test]
async fn every_vertical_bundle_applies_cleanly_to_a_fresh_deployment() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();

    for vertical in APPLY_ORDER {
        apply_bundle_to_fresh_deployment(state, vertical).await;
    }
}

/// `game-ops` (Attome Online world servers: worlds, players, bans, server
/// commands) on its own, so it stays proven while the whole-catalogue test
/// above is red for the `dashboard` and finance reasons noted below. Its
/// only cross-module edge is `game_player.portal_user_ref` ->
/// `webportal_user`, a platform entity, so it needs no other vertical.
#[tokio::test]
async fn game_ops_bundle_applies_cleanly_to_a_fresh_deployment() {
    let system = skip_if_no_db!(test_system().await);
    apply_bundle_to_fresh_deployment(system.state(), "game-ops").await;
}

/// Basic-units U8 (2026-09-23): the lifecycle models seeded into the finance
/// (`invoice`) and human-resources (`performance_review`) vertical bundles
/// land on a fresh deployment, and an illegal transition is refused.
///
/// Separate from the whole-catalogue test above, which is red for reasons no
/// state model causes (found 2026-09-23): six vertical bundles carry a
/// `record_sets` entry for the pre-rename `dashboard` entity, which no longer
/// exists, so `crm` is blocked with "entity 'dashboard' is not live"; and the
/// finance apply fails on its "Finance: Budget vs Actual" query. So this test
/// narrows each bundle to its schema and its lifecycle (entities, attribute
/// patches, privileges, state models) and proves the state models alone.
#[tokio::test]
async fn seeded_vertical_state_models_apply_and_are_enforced() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();

    for vertical in ["finance", "human-resources"] {
        let full = load_bundle(vertical);
        let mut bundle = load_bundle(vertical);
        bundle.queries.clear();
        bundle.calendars.clear();
        bundle.views.clear();
        bundle.sidebar.clear();
        bundle.roles.clear();
        bundle.field_security_profiles.clear();
        bundle.record_sets.clear();
        bundle.settings.clear();
        bundle.labels.clear();
        bundle.relationships.clear();
        bundle.apps.clear();
        bundle.rules.clear();
        assert_eq!(bundle.state_models, full.state_models);
        apply_loaded_bundle(state, vertical, bundle).await;
    }

    for (entity, initial, transitions) in [
        ("invoice", "draft", 7_i64),
        ("performance_review", "draft", 3),
    ] {
        let (initial_state, count): (String, i64) = sqlx::query_as(
            "SELECT m.initial_state,                     (SELECT COUNT(*) FROM state_transition t                       WHERE t.model_ref = m.id AND t.is_deleted = false)                FROM state_model m               WHERE m.entity_logicalname = $1 AND m.is_deleted = false AND m.is_active = true",
        )
        .bind(entity)
        .fetch_one(&state.base.db)
        .await
        .unwrap_or_else(|e| panic!("{entity}: seeded state model missing: {e}"));
        assert_eq!(initial_state, initial, "{entity}");
        assert_eq!(count, transitions, "{entity}");
    }

    // The enforcement primitive a generic PATCH goes through, over a
    // registry freshly loaded from what the apply wrote.
    let registry = attome_core::state_registry::load(&state.base.db)
        .await
        .expect("load state model registry");
    let invoice = registry.get("invoice").expect("invoice is governed");
    let anyone = |_: &str| true;
    assert!(
        attome_core::check_transition_with(invoice, anyone, Some("paid"), "draft").is_err(),
        "paid -> draft is not a seeded invoice transition"
    );
    assert!(
        attome_core::check_transition_with(invoice, anyone, Some("draft"), "sent").is_ok(),
        "draft -> sent is a seeded invoice transition"
    );
}

// ── P0 0.7: approval privileges and separation of duties (M69 S3, M81 S2, M82 S2) ──

/// A throwaway staff user (the approver/submitter identities below).
async fn seed_staff_user(state: &EngineState) -> uuid::Uuid {
    let id = uuid::Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(id)
    .bind(format!("sod-{id}@test.local"))
    .bind(format!("sod-{id}"))
    .execute(&state.base.db)
    .await
    .expect("insert throwaway user_account");
    id
}

/// Assigns the bundle role `role` to `user` (its record-level reach comes
/// from the role's access level, as for a real user).
async fn assign_role(state: &EngineState, user: uuid::Uuid, role: &str) {
    let role_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM role WHERE name = $1 AND is_deleted = false")
            .bind(role)
            .fetch_one(&state.base.db)
            .await
            .unwrap_or_else(|e| panic!("role {role}: {e}"));
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(uuid::Uuid::now_v7())
        .bind(user)
        .bind(role_id)
        .execute(&state.base.db)
        .await
        .expect("assign role");
}

/// Direct grants of `keys` to `user` (the plain `.update` holder).
async fn grant_direct(state: &EngineState, user: uuid::Uuid, keys: &[&str]) {
    for key in keys {
        let privilege: uuid::Uuid = sqlx::query_scalar("SELECT id FROM privilege WHERE key = $1")
            .bind(key)
            .fetch_one(&state.base.db)
            .await
            .unwrap_or_else(|e| panic!("privilege {key}: {e}"));
        sqlx::query(
            "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at)              VALUES ($1, $2, $3, true, NOW())",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(user)
        .bind(privilege)
        .execute(&state.base.db)
        .await
        .expect("direct grant");
    }
}

/// A non-admin caller holding exactly `privileges` — what the resolver
/// produces for a user granted them (directly or through a role).
fn staff_ctx(user_id: uuid::Uuid, privileges: &[&str]) -> attome_server::security::SecurityContext {
    attome_server::security::SecurityContext {
        is_admin: false,
        privileges: privileges.iter().map(|p| (*p).to_owned()).collect(),
        ..attome_records::entity_crud::admin_security_context(user_id)
    }
}

async fn create_as_admin(
    state: &EngineState,
    admin: uuid::Uuid,
    entity: &str,
    body: serde_json::Value,
) -> uuid::Uuid {
    let ctx = attome_records::entity_crud::admin_security_context(admin);
    let (id, _) = attome_records::entity_crud::create_record_for(state, &ctx, admin, entity, body)
        .await
        .unwrap_or_else(|e| panic!("create {entity}: {e:?}"));
    id
}

/// The generic PATCH path (`update_record_for` is exactly what the `PATCH
/// /{entity}/{id}` handler calls) moving `status`, plus any `extra` fields.
async fn set_status(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    target: (&str, uuid::Uuid, i64),
    status: &str,
    extra: serde_json::Value,
) -> Result<i64, attome_types::AppError> {
    let (entity, id, version) = target;
    let mut body = serde_json::json!({ "status": status });
    if let (Some(b), Some(x)) = (body.as_object_mut(), extra.as_object()) {
        b.extend(x.clone());
    }
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        entity,
        id,
        version,
        body,
    )
    .await
    .map(|r| r.row_version())
}

async fn reload_state_models(state: &EngineState) {
    let fresh = attome_core::state_registry::load(&state.base.db)
        .await
        .expect("load state model registry");
    state.state_models.swap(fresh);
}

async fn role_grants(state: &EngineState, role: &str) -> Vec<String> {
    let mut grants: Vec<String> = sqlx::query_scalar(
        "SELECT p.key FROM role r \
           JOIN role_mm_privilege rp ON rp.role_ref = r.id \
           JOIN privilege p ON p.id = rp.privilege_ref \
          WHERE r.name = $1",
    )
    .bind(role)
    .fetch_all(&state.base.db)
    .await
    .unwrap_or_else(|e| panic!("role {role} grants: {e}"));
    grants.sort();
    grants
}

/// The two vertical bundles narrowed as in
/// `seeded_vertical_state_models_apply_and_are_enforced`, but keeping their
/// privileges and roles (the approve privilege and approver roles are what
/// P0 0.7 adds).
async fn apply_finance_and_hr_with_roles(state: &EngineState) {
    for vertical in ["finance", "human-resources"] {
        let mut bundle = load_bundle(vertical);
        bundle.queries.clear();
        bundle.calendars.clear();
        bundle.views.clear();
        bundle.sidebar.clear();
        bundle.field_security_profiles.clear();
        bundle.record_sets.clear();
        bundle.settings.clear();
        bundle.labels.clear();
        bundle.relationships.clear();
        bundle.apps.clear();
        bundle.rules.clear();
        apply_loaded_bundle(state, vertical, bundle).await;
    }
    reload_state_models(state).await;
}

fn assert_forbidden(result: Result<i64, attome_types::AppError>, what: &str) {
    assert!(
        matches!(result, Err(attome_types::AppError::Forbidden)),
        "{what}: expected Forbidden, got {result:?}"
    );
}

fn assert_guard_refused(result: Result<i64, attome_types::AppError>, what: &str) {
    assert!(
        matches!(
            &result,
            Err(attome_types::AppError::TransitionNotAllowed(m))
                if m.contains("guard") || m.contains("same write")
        ),
        "{what}: expected the guard to refuse, got {result:?}"
    );
}

fn privs<'a>(entity: &str, actions: &[&str], buf: &'a mut Vec<String>) -> Vec<&'a str> {
    *buf = actions.iter().map(|a| format!("{entity}.{a}")).collect();
    buf.iter().map(String::as_str).collect()
}

/// M81 S2: an `expense.update` holder cannot approve; the submitter cannot
/// approve or reject their own even with `expense.approve`, nor by rewriting
/// `submitted_by` in the same write; another `expense.approve` holder can.
#[tokio::test]
async fn expense_approval_needs_the_approve_privilege_and_a_different_user() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    apply_finance_and_hr_with_roles(state).await;

    assert_eq!(
        role_grants(state, "Finance Approver").await,
        vec!["expense.approve", "expense.read", "expense.update"]
    );

    let admin = seed_staff_user(state).await;
    let submitter = seed_staff_user(state).await;
    let approver = seed_staff_user(state).await;
    let plain = seed_staff_user(state).await;
    assign_role(state, submitter, "Finance Approver").await;
    assign_role(state, approver, "Finance Approver").await;
    grant_direct(state, plain, &["expense.read", "expense.update"]).await;
    let id = create_as_admin(
        state,
        admin,
        "expense",
        serde_json::json!({
            "amount": 120.0, "description": "taxi", "expense_date": "2026-09-01T00:00:00Z",
            "submitted_by": submitter,
        }),
    )
    .await;
    let admin_ctx = attome_records::entity_crud::admin_security_context(admin);
    let v = set_status(
        state,
        &admin_ctx,
        ("expense", id, 0),
        "manager_review",
        serde_json::json!({}),
    )
    .await
    .expect("submitted -> manager_review needs no approve privilege");
    let at = ("expense", id, v);

    let updater = staff_ctx(plain, &["expense.read", "expense.update"]);
    assert_forbidden(
        set_status(state, &updater, at, "approved", serde_json::json!({})).await,
        "an expense.update holder approving",
    );

    let own = staff_ctx(
        submitter,
        &["expense.read", "expense.update", "expense.approve"],
    );
    assert_guard_refused(
        set_status(state, &own, at, "approved", serde_json::json!({})).await,
        "the submitter approving their own expense",
    );
    assert_guard_refused(
        set_status(state, &own, at, "rejected", serde_json::json!({})).await,
        "the submitter rejecting their own expense",
    );
    assert_guard_refused(
        set_status(
            state,
            &own,
            at,
            "approved",
            serde_json::json!({ "submitted_by": approver }),
        )
        .await,
        "the submitter rewriting submitted_by in the approving write",
    );

    let other = staff_ctx(
        approver,
        &["expense.read", "expense.update", "expense.approve"],
    );
    set_status(state, &other, at, "approved", serde_json::json!({}))
        .await
        .expect("a different expense.approve holder approves");
}

/// M82 S2: a `leave_request.update` holder cannot approve; the requester
/// (`requested_by`) cannot approve or reject their own leave even as a People
/// Manager, nor by rewriting `requested_by` in the same write; another People
/// Manager can.
#[tokio::test]
async fn leave_approval_needs_the_approve_privilege_and_a_different_user() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    apply_finance_and_hr_with_roles(state).await;

    for role in ["People Manager", "HR Specialist"] {
        assert_eq!(
            role_grants(state, role).await,
            vec![
                "leave_request.approve",
                "leave_request.read",
                "leave_request.update"
            ],
            "{role}"
        );
    }

    let admin = seed_staff_user(state).await;
    let manager = seed_staff_user(state).await;
    let requester = seed_staff_user(state).await;
    let plain = seed_staff_user(state).await;
    assign_role(state, manager, "People Manager").await;
    assign_role(state, requester, "People Manager").await;
    grant_direct(
        state,
        plain,
        &["leave_request.read", "leave_request.update"],
    )
    .await;
    let employee = create_as_admin(
        state,
        admin,
        "employee",
        serde_json::json!({ "full_name": "Test Employee" }),
    )
    .await;
    let id = create_as_admin(
        state,
        admin,
        "leave_request",
        serde_json::json!({
            "employee_ref": employee, "leave_type": "annual",
            "start_date": "2026-10-01T00:00:00Z", "end_date": "2026-10-03T00:00:00Z",
            "requested_by": requester,
        }),
    )
    .await;
    let admin_ctx = attome_records::entity_crud::admin_security_context(admin);
    let v = set_status(
        state,
        &admin_ctx,
        ("leave_request", id, 0),
        "manager_review",
        serde_json::json!({}),
    )
    .await
    .expect("requested -> manager_review needs no approve privilege");
    let at = ("leave_request", id, v);

    let mut buf = Vec::new();
    let updater = staff_ctx(
        plain,
        &privs("leave_request", &["read", "update"], &mut buf),
    );
    assert_forbidden(
        set_status(state, &updater, at, "approved", serde_json::json!({})).await,
        "a leave_request.update holder approving",
    );
    let own = staff_ctx(
        requester,
        &privs("leave_request", &["read", "update", "approve"], &mut buf),
    );
    assert_guard_refused(
        set_status(state, &own, at, "approved", serde_json::json!({})).await,
        "the requester approving their own leave",
    );
    assert_guard_refused(
        set_status(state, &own, at, "rejected", serde_json::json!({})).await,
        "the requester rejecting their own leave",
    );
    assert_guard_refused(
        set_status(
            state,
            &own,
            at,
            "approved",
            serde_json::json!({ "requested_by": manager }),
        )
        .await,
        "the requester rewriting requested_by in the approving write",
    );
    let approver = staff_ctx(
        manager,
        &privs("leave_request", &["read", "update", "approve"], &mut buf),
    );
    set_status(state, &approver, at, "approved", serde_json::json!({}))
        .await
        .expect("another People Manager approves");
}

/// M69 S3 (generic path): an `.update` holder cannot approve a timesheet or a
/// change request; the timesheet's own user cannot approve it and the
/// requester cannot approve their change request; a Project Approver can.
/// The attome-project platform bundle is applied at boot (`ProjectModel`).
#[tokio::test]
async fn project_approvals_need_the_approve_privilege_and_a_different_user() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    reload_state_models(state).await;

    assert_eq!(
        role_grants(state, "Project Approver").await,
        vec![
            "project_change_request.approve",
            "project_change_request.read",
            "project_change_request.update",
            "project_timesheet.approve",
            "project_timesheet.read",
            "project_timesheet.update",
        ]
    );

    let admin = seed_staff_user(state).await;
    let submitter = seed_staff_user(state).await;
    let approver = seed_staff_user(state).await;
    let plain = seed_staff_user(state).await;
    assign_role(state, submitter, "Project Approver").await;
    assign_role(state, approver, "Project Approver").await;
    grant_direct(
        state,
        plain,
        &[
            "project_timesheet.read",
            "project_timesheet.update",
            "project_change_request.read",
            "project_change_request.update",
        ],
    )
    .await;
    let (ts_e, cr_e) = ("project_timesheet", "project_change_request");
    let mut buf = Vec::new();

    // Timesheet: its own user submits (no privilege on submit), then approval.
    let ts = create_as_admin(
        state,
        admin,
        ts_e,
        serde_json::json!({ "user_id": submitter, "week_start_date": "2026-09-21T00:00:00Z", "status": "draft" }),
    )
    .await;
    let own = staff_ctx(
        submitter,
        &privs(ts_e, &["read", "update", "approve"], &mut buf),
    );
    let v = set_status(
        state,
        &own,
        (ts_e, ts, 0),
        "submitted",
        serde_json::json!({}),
    )
    .await
    .expect("draft -> submitted needs no approve privilege");
    assert_guard_refused(
        set_status(
            state,
            &own,
            (ts_e, ts, v),
            "approved",
            serde_json::json!({}),
        )
        .await,
        "a user approving their own timesheet",
    );
    let updater = staff_ctx(plain, &privs(ts_e, &["read", "update"], &mut buf));
    assert_forbidden(
        set_status(
            state,
            &updater,
            (ts_e, ts, v),
            "approved",
            serde_json::json!({}),
        )
        .await,
        "an project_timesheet.update holder approving",
    );
    let other = staff_ctx(
        approver,
        &privs(ts_e, &["read", "update", "approve"], &mut buf),
    );
    set_status(
        state,
        &other,
        (ts_e, ts, v),
        "approved",
        serde_json::json!({}),
    )
    .await
    .expect("a Project Approver approves someone else's timesheet");

    // Change request: needs a project, which needs an organization.
    let org = uuid::Uuid::now_v7();
    sqlx::query("INSERT INTO organization (id, name) VALUES ($1, $2)")
        .bind(org)
        .bind(format!("sod-org-{org}"))
        .execute(&state.base.db)
        .await
        .expect("insert throwaway organization");
    let project = create_as_admin(
        state,
        admin,
        "attome_project",
        serde_json::json!({
            "name": "SoD project",
            "project_code": format!("SOD-{}", org.simple()),
            "organization_id": org,
        }),
    )
    .await;
    let cr = create_as_admin(
        state,
        admin,
        cr_e,
        serde_json::json!({ "title": "scope", "project_id": project, "requested_by": submitter, "status": "pending" }),
    )
    .await;
    let updater = staff_ctx(plain, &privs(cr_e, &["read", "update"], &mut buf));
    assert_forbidden(
        set_status(
            state,
            &updater,
            (cr_e, cr, 0),
            "approved",
            serde_json::json!({}),
        )
        .await,
        "an project_change_request.update holder approving",
    );
    let own = staff_ctx(
        submitter,
        &privs(cr_e, &["read", "update", "approve"], &mut buf),
    );
    assert_guard_refused(
        set_status(
            state,
            &own,
            (cr_e, cr, 0),
            "approved",
            serde_json::json!({}),
        )
        .await,
        "the requester approving their own change request",
    );
    let other = staff_ctx(
        approver,
        &privs(cr_e, &["read", "update", "approve"], &mut buf),
    );
    set_status(
        state,
        &other,
        (cr_e, cr, 0),
        "approved",
        serde_json::json!({}),
    )
    .await
    .expect("a Project Approver approves someone else's change request");
}

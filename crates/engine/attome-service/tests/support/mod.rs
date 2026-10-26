//! Shared harness for the intake tests (`convert.rs`, `offering.rs`) — M70
//! Phase 1 routes every intake write through the entity engine, which needs
//! a full `EngineState` rather than a bare pool. Same `EngineState` construction
//! `tests/timeline.rs`/`tests/queue.rs` already use, plus the two things the
//! engine consults that those tests never needed:
//!
//! - **State models from the shipped bundles.** `seed_for_tests` provisions
//!   entities only and never loads `state_models`, so without this the engine
//!   would skip every lifecycle check and a conversion to a status the bundle
//!   forbids would pass here and fail in production. [`register_bundle_state_models`]
//!   parses `platform-bundles/attome-service.json` and `attome-project.json`
//!   (compiled in, so an edit to either is what the tests see) into
//!   `state.state_models`, exactly the snapshot boot builds from the
//!   reconciled rows.
//! - **Audit and change-feed probes** that read both audit write paths
//!   (`audit_header`, or `audit_ingest` when the chainer is on).

#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_core::state_registry::{
    StateModelDef, StateModelEntry, StateModelRegistry, TransitionDef,
};
use attome_db::DbPool;
use attome_server::AppState;
use attome_server::security::SecurityContext;
use uuid::Uuid;

fn test_config() -> AppConfig {
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
            "host": "localhost", "port": 5555, "dbname": "unused",
            "user": "unused", "password": "unused", "schema": "attome_dev",
            "connection_number": 5, "timeout": 5.0
        }},
        "cache": {{
            "host": "{redis_host}", "port": {redis_port}, "password": "", "db": 0,
            "connection_pool_size": 4, "timeout": 2000,
            "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
            "metadata_registry_enabled": false
        }},
        "storage": {{
            "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
            "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
            "s3_bucket": "test", "s3_use_path_style": true, "s3_verify_ssl": false
        }},
        "auth": {{
            "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
            "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
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
        "cors": {{ "allowed_origins": ["http://allowed.test"] }}
    }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
}

/// `attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV` synchronously, and
/// `cargo test` runs a file's tests concurrently.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A full `EngineState` over the throwaway test database, entities seeded and
/// the bundles' state models loaded. `None` when no test database is set.
pub async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
    let state = {
        let _env_guard = ENV_LOCK.lock().await;
        // SAFETY: serialized by ENV_LOCK above — no other thread mutates or
        // reads these vars while this guard is held.
        unsafe {
            std::env::set_var("DATABASE_URL", &db_url);
            std::env::set_var("APP_ENV", "debug");
        }
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
        EngineState::new(base)
    };
    ensure_seeded(&state.base.db).await;
    // The engine resolves a lookup's target entity through the metadata
    // registry snapshot, which boot pre-warms and this harness must too.
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build metadata registry");
    state.entities.swap(registry);
    register_bundle_state_models(&state);
    Some(state)
}

async fn ensure_seeded(db: &DbPool) {
    // `create_one_as` reads `autovalue` on every create; that table
    // is itself a platform-bundle entity, not a migration.
    attome_metadata::autovalue::seed_for_tests(db)
        .await
        .expect("attome_metadata::autovalue::seed_for_tests");
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    attome_project::seed::seed_for_tests(db)
        .await
        .expect("attome_project::seed::seed_for_tests");
    attome_service::seed::seed_for_tests(db)
        .await
        .expect("attome_service::seed::seed_for_tests");
}

/// Every `state_models[]` entry of the two shipped bundles, as the engine's
/// state-model snapshot. See this module's doc comment.
pub fn register_bundle_state_models(state: &EngineState) {
    let mut entries = Vec::new();
    for bundle in [
        include_str!("../../../../../platform-bundles/attome-service.json"),
        include_str!("../../../../../platform-bundles/attome-project.json"),
    ] {
        let bundle: serde_json::Value = serde_json::from_str(bundle).expect("bundle is JSON");
        for model in bundle["state_models"].as_array().into_iter().flatten() {
            let model_id = Uuid::now_v7();
            let text = |v: &serde_json::Value, key: &str| {
                v[key].as_str().map(str::to_owned).unwrap_or_default()
            };
            let entity = text(model, "entity_logicalname");
            let transitions = model["transitions"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| TransitionDef {
                    id: Uuid::now_v7(),
                    model_ref: model_id,
                    from_state: text(t, "from_state"),
                    to_state: text(t, "to_state"),
                    name: text(t, "name"),
                    required_privilege: t["required_privilege"].as_str().map(str::to_owned),
                    guard_expression: t["guard_expression"].as_str().map(str::to_owned),
                    entry_actions: Vec::new(),
                    exit_actions: Vec::new(),
                    display_order: t["display_order"].as_i64().unwrap_or(0) as i32,
                    row_version: 0,
                    approval_plan: None,
                    pending_state: None,
                    on_reject_state: None,
                    auto_condition: t["auto_condition"].as_str().map(str::to_owned),
                })
                .collect();
            entries.push((
                entity.clone(),
                StateModelEntry {
                    model: Some(StateModelDef {
                        id: model_id,
                        entity_logicalname: entity,
                        name: text(model, "name"),
                        state_field: text(model, "state_field"),
                        initial_state: text(model, "initial_state"),
                        is_active: true,
                        row_version: 0,
                        rules: Default::default(),
                    }),
                    transitions,
                },
            ));
        }
    }
    state
        .state_models
        .swap(StateModelRegistry::from_entries(entries));
}

/// A non-admin context holding exactly `privileges`.
pub fn ctx_for(user_id: Uuid, privileges: &[&str]) -> SecurityContext {
    SecurityContext {
        user_id,
        is_admin: false,
        privileges: privileges.iter().map(|s| s.to_string()).collect(),
        field_grants: HashSet::new(),
        field_write_grants: HashSet::new(),
        bulk_fields: Default::default(),
        epoch: 0,
        accessible_org_ids: Vec::new(),
        team_ids: Vec::new(),
        position_hierarchy_enabled: false,
        subordinate_user_ids: Vec::new(),
        condition_grants: HashMap::new(),
        role_ids: None,
        service_principal: false,
    }
}

/// An administrator context (`system.admin`).
pub fn admin_ctx(user_id: Uuid) -> SecurityContext {
    SecurityContext {
        is_admin: true,
        ..ctx_for(user_id, &["system.admin"])
    }
}

pub async fn insert_systemuser(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, email, is_active) VALUES ($1, $2, TRUE)")
        .bind(id)
        .bind(format!("intake-test-{id}@example.invalid"))
        .execute(db)
        .await
        .expect("insert user_account");
    id
}

/// Change-feed rows (`entity_change_event`) for one record.
pub async fn change_events(db: &DbPool, entity: &str, record_id: Uuid, operation: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM entity_change_event \
         WHERE entity_logicalname = $1 AND record_id = $2 AND operation = $3",
    )
    .bind(entity)
    .bind(record_id)
    .bind(operation)
    .fetch_one(db)
    .await
    .expect("count change events")
}

/// Audit rows for one record in one `(category, operation)`, on either write
/// path.
pub async fn audit_events(
    db: &DbPool,
    record_id: Uuid,
    category: attome_audit::AuditCategory,
    operation: attome_audit::AuditOperation,
) -> i64 {
    let pascal = |v: serde_json::Value| v.as_str().unwrap_or_default().to_owned();
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header \
                 WHERE record_id = $1 AND category = $2 AND operation = $3) \
              + (SELECT COUNT(*) FROM audit_ingest \
                 WHERE payload->>'record_id' = $4 AND payload->>'category' = $5 \
                   AND payload->>'operation' = $6)",
    )
    .bind(record_id)
    .bind(category as i32)
    .bind(operation as i32)
    .bind(record_id.to_string())
    .bind(pascal(serde_json::to_value(category).expect("category")))
    .bind(pascal(serde_json::to_value(operation).expect("operation")))
    .fetch_one(db)
    .await
    .expect("count audit events")
}

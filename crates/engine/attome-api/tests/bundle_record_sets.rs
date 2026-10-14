//! P-environment-promotion §3 Phase 3 / §5 step 24 — record sets against a
//! live, seeded database:
//!
//! - a record set naming a brand-new key plans `create`, applies
//!   (`ReconcileOutcome::Created`), and re-planning/re-applying the same
//!   bundle is `noop`/`Unchanged` — the create-then-noop-on-re-apply
//!   acceptance bar;
//! - changing one field and re-planning finds the row by its key and plans
//!   `update` (with the changed field named), applies
//!   (`ReconcileOutcome::Updated`), and the live row reflects the change;
//! - a row missing a declared key field plans `blocked`, never reaching the
//!   database.
//!
//! Requires a live Postgres (`DATABASE_URL`, cloned per binary by
//! `attome_testkit`) and Redis (`TEST_REDIS_HOST`/`TEST_REDIS_PORT`) — same
//! convention as `bundle_export.rs`.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; $env:TEST_REDIS_PORT = "6380"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-api --test bundle_record_sets -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_api::bundle::{
    Bundle, PlanAction, RecordSet, Requires, apply_record, export_bundle, plan_record_sets,
};
use attome_config::AppConfig;
use attome_core::EngineState;
use attome_metadata::provision::{
    AttributeDesc, EntityDesc, ReconcileOutcome, ReconcilePolicy, reconcile_attribute,
    reconcile_entity,
};
use attome_server::AppState;
use attome_testkit::skip_if_no_db;
use serde_json::{Map, Value, json};
use uuid::Uuid;

const THROWAWAY_JWT_SECRET: &str = "test-only-throwaway-secret-do-not-use-in-prod";

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
                "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
                "user": "unused", "password": "unused", "schema": "attome_dev",
                "connection_number": 5, "timeout": 5.0
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
            "approval": {{ "required_actions": [] }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        jwt_secret = THROWAWAY_JWT_SECRET,
    );
    attome_testkit::with_test_database(
        serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    )
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

fn text_attr(logicalname: &str, display_name: &str) -> AttributeDesc {
    AttributeDesc {
        logicalname: logicalname.to_owned(),
        display_name: display_name.to_owned(),
        field_type: "text".to_owned(),
        is_required: false,
        is_sensitive: false,
        is_write_restricted: None,
        is_sortable: false,
        is_filterable: false,
        lookup_entity: None,
        options: None,
        max_length: None,
        on_target_delete: None,
        data_classification: None,
        purpose: None,
    }
}

/// Provisions a throwaway entity (`name`, `subject` — both `text`) directly
/// through the reconcile primitives, so it is "live" before any bundle
/// touches it — record sets are only planned against an already-live entity
/// (`plan_record_sets`'s doc comment).
async fn provision_test_entity(state: &EngineState) -> String {
    let logicalname = attome_testkit::unique_logicalname("bndl_rec");
    let db = &state.base.db;
    let (entity_id, _) = reconcile_entity(
        db,
        &EntityDesc {
            logicalname: logicalname.clone(),
            display_name: "Bundle Record Set Test".to_owned(),
            primary_name_attribute: Some("name".to_owned()),
            is_append_only: false,
            is_audited: false,
            category: None,
        },
        ReconcilePolicy::Seed,
    )
    .await
    .expect("provision test entity");
    reconcile_attribute(
        db,
        entity_id,
        &text_attr("name", "Name"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("provision name attribute");
    reconcile_attribute(
        db,
        entity_id,
        &text_attr("subject", "Subject"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("provision subject attribute");
    logicalname
}

fn row(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn bundle_with(entity: &str, key_fields: &[&str], rows: Vec<Map<String, Value>>) -> Bundle {
    let mut b = Bundle::empty(Requires {
        platform_version: ">=0.0.0".to_owned(),
        schema_version: 0,
        modules: vec!["core".to_owned()],
        depends_on_bundles: vec![],
    });
    b.record_sets.push(RecordSet {
        entity: entity.to_owned(),
        key_fields: key_fields.iter().map(|s| (*s).to_owned()).collect(),
        rows,
    });
    b
}

fn find<'a>(
    entries: &'a [attome_api::bundle::PlanEntry],
    key: &str,
) -> &'a attome_api::bundle::PlanEntry {
    entries
        .iter()
        .find(|e| e.key == key)
        .unwrap_or_else(|| panic!("no plan entry with key {key:?} in {entries:#?}"))
}

#[tokio::test]
async fn create_then_noop_on_reapply() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    let entity = provision_test_entity(state).await;
    let key = format!("{entity}[name=welcome]");

    let welcome_row = row(&[("name", json!("welcome")), ("subject", json!("Welcome!"))]);
    let bundle = bundle_with(&entity, &["name"], vec![welcome_row.clone()]);

    let live = export_bundle(&state.base.db).await.expect("export live");
    let diff = plan_record_sets(&state.base.db, &live, &bundle)
        .await
        .expect("plan record sets");
    assert!(diff.blocked.is_empty(), "{:#?}", diff.blocked);
    assert_eq!(find(&diff.entries, &key).action, PlanAction::Create);

    let outcome = apply_record(
        state,
        Uuid::nil(),
        &entity,
        &["name".to_owned()],
        &welcome_row,
    )
    .await
    .expect("apply create");
    assert_eq!(outcome, ReconcileOutcome::Created);

    // Re-plan against the same bundle: the row now exists and is identical,
    // so it must be Noop, never Create/Update.
    let live2 = export_bundle(&state.base.db).await.expect("export live 2");
    let diff2 = plan_record_sets(&state.base.db, &live2, &bundle)
        .await
        .expect("plan record sets again");
    assert_eq!(find(&diff2.entries, &key).action, PlanAction::Noop);

    // Re-apply: compare-first means no write, Unchanged.
    let outcome2 = apply_record(
        state,
        Uuid::nil(),
        &entity,
        &["name".to_owned()],
        &welcome_row,
    )
    .await
    .expect("re-apply");
    assert_eq!(outcome2, ReconcileOutcome::Unchanged);
}

#[tokio::test]
async fn update_by_key_finds_the_row_and_writes_only_the_changed_field() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    let entity = provision_test_entity(state).await;
    let key = format!("{entity}[name=digest]");

    let original = row(&[("name", json!("digest")), ("subject", json!("Old subject"))]);
    apply_record(state, Uuid::nil(), &entity, &["name".to_owned()], &original)
        .await
        .expect("seed the row");

    let updated = row(&[("name", json!("digest")), ("subject", json!("New subject"))]);
    let bundle = bundle_with(&entity, &["name"], vec![updated.clone()]);
    let live = export_bundle(&state.base.db).await.expect("export live");
    let diff = plan_record_sets(&state.base.db, &live, &bundle)
        .await
        .expect("plan update");
    assert!(diff.blocked.is_empty(), "{:#?}", diff.blocked);
    let entry = find(&diff.entries, &key);
    assert_eq!(entry.action, PlanAction::Update);
    assert_eq!(
        entry.changes,
        vec!["subject: \"Old subject\" -> \"New subject\"".to_owned()]
    );

    let outcome = apply_record(state, Uuid::nil(), &entity, &["name".to_owned()], &updated)
        .await
        .expect("apply update");
    assert_eq!(outcome, ReconcileOutcome::Updated);

    let live_subject: String = sqlx::query_scalar(&format!(
        "SELECT subject FROM {} WHERE name = 'digest'",
        attome_core::quote_ident(&entity)
    ))
    .fetch_one(&state.base.db)
    .await
    .expect("read back the updated row");
    assert_eq!(live_subject, "New subject");
}

#[tokio::test]
async fn missing_key_field_is_blocked_at_plan_and_never_reaches_the_database() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    let entity = provision_test_entity(state).await;

    // "name" is the declared key field but this row never sets it.
    let incomplete = row(&[("subject", json!("No key here"))]);
    let bundle = bundle_with(&entity, &["name"], vec![incomplete]);

    let live = export_bundle(&state.base.db).await.expect("export live");
    let diff = plan_record_sets(&state.base.db, &live, &bundle)
        .await
        .expect("plan with a missing key field");
    assert!(diff.entries.is_empty(), "{:#?}", diff.entries);
    assert_eq!(diff.blocked.len(), 1, "{:#?}", diff.blocked);
    assert!(
        diff.blocked[0]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("missing key field"),
        "{:?}",
        diff.blocked[0]
    );

    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {}",
        attome_core::quote_ident(&entity)
    ))
    .fetch_one(&state.base.db)
    .await
    .expect("count rows");
    assert_eq!(count, 0, "a blocked row must never reach the database");
}

//! DB-backed regression test for module-master-plans/M01-core.md §7 C-02:
//! `GET /api/v1/predictions` (`predictions::list_predictions_impl`) must not
//! return scores/explanations for a `regarding_id` record the caller cannot
//! see, even when the caller holds the blanket `{regarding_entity}.read`
//! entity-level privilege `ctx.require` alone used to treat as sufficient.
//!
//! Harness shape follows `attome-service/tests/timeline.rs` (same constraint:
//! this crate has no dependency on `attome-api`'s test tree, so the
//! role/entity-access/record-share seeding helpers are reimplemented here
//! rather than imported). The "regarding" entity is a throwaway inline
//! registration (`predict_test_target`) rather than the real
//! `service_ticket` this endpoint serves in production, because provisioning
//! `service_ticket` pulls in `attome-service`'s seed, which this crate has no
//! production dependency on (see `predictions.rs`'s module doc for why) —
//! `record_visible`'s logic is entity-name-generic, so any provisioned
//! entity exercises the exact same code path `service_ticket` would.

#![allow(
    unsafe_code,
    reason = "the test sets process environment variables (std::env::set_var) before any thread reads them"
)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_predict::predictions::{PredictionListQuery, list_predictions_impl};
use attome_server::AppState;
use attome_server::security::SecurityContext;
use attome_testkit::skip_if_no_db;
use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};
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

/// Same env-var-mutation serialization `attome-service/tests/timeline.rs`
/// documents (`attome_db::create_pool` reads `DATABASE_URL`/`APP_ENV`
/// synchronously, and `cargo test` runs this file's tests concurrently).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn test_state() -> Option<EngineState> {
    let db_url = attome_testkit::migrated_db_url()?;
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
    Some(EngineState::new(base))
}

const TARGET_ENTITY: &str = "predict_test_target";

/// Inlined — see this file's module doc for why `predictions.rs`'s own
/// production dependencies (no `attome-metadata`) can't provision this.
async fn ensure_target_entity(db: &DbPool) {
    use attome_metadata::provision::ensure_entity;
    ensure_entity(db, TARGET_ENTITY, "Predict Test Target", None, true)
        .await
        .expect("ensure predict_test_target entity");
}

async fn ensure_seeded(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    ensure_target_entity(db).await;
}

async fn sync_registry(state: &EngineState) {
    let registry = attome_core::build_registry(&state.base.db)
        .await
        .expect("build metadata registry");
    state.entities.swap(registry);
}

async fn entity_id_by_logicalname(db: &DbPool, logicalname: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_info WHERE logicalname = $1 \
         AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .expect("resolve entity id")
}

async fn insert_target_record(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(&format!(
        r#"INSERT INTO "{TARGET_ENTITY}" (id, is_active) VALUES ($1, true)"#
    ))
    .bind(id)
    .execute(db)
    .await
    .expect("insert target record");
    id
}

async fn insert_model(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO prediction_model (id, name, target, entity, status) \
         VALUES ($1, $2, 'sla_breach', $3, 'active')",
    )
    .bind(id)
    .bind(format!("predict-test-model-{id}"))
    .bind(TARGET_ENTITY)
    .execute(db)
    .await
    .expect("insert prediction_model");
    id
}

async fn insert_prediction(db: &DbPool, model_ref: Uuid, regarding_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO prediction \
            (id, model_ref, regarding_entity, regarding_id, score, label, horizon_at) \
         VALUES ($1, $2, $3, $4, 0.9, 'breach', $5)",
    )
    .bind(id)
    .bind(model_ref)
    .bind(TARGET_ENTITY)
    .bind(regarding_id)
    .bind(Utc::now() + Duration::days(1))
    .execute(db)
    .await
    .expect("insert prediction");
    id
}

async fn insert_user(db: &DbPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO user_account (id, user_name, email, is_active) VALUES ($1, $2, $2 || '@test.invalid', true)")
        .bind(id)
        .bind(format!("predict-test-{id}"))
        .execute(db)
        .await
        .expect("insert user_account");
    id
}

/// A fresh `role` granting `"{logicalname}.read"` — same shape
/// `attome-api/tests/record_level_security.rs::create_role_with_privileges`
/// establishes, reimplemented here (this crate cannot depend on
/// `attome-api`'s test tree — see this crate's own layering).
async fn create_read_role(db: &DbPool, logicalname: &str) -> Uuid {
    let role_id = Uuid::now_v7();
    sqlx::query("INSERT INTO role (id, name, owner_layer) VALUES ($1, $2, 'project')")
        .bind(role_id)
        .bind(format!("predict-test-role-{role_id}"))
        .execute(db)
        .await
        .expect("insert test role");

    let key = format!("{logicalname}.read");
    let privilege_id: Uuid = sqlx::query_scalar(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, owner_layer) \
         VALUES ($1, $2, $2, $2, true, NOW(), 'project') \
         ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
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

    role_id
}

async fn assign_role(db: &DbPool, user_id: Uuid, role_id: Uuid) {
    sqlx::query("INSERT INTO user_account_mm_role (id, user_ref, role_ref) VALUES ($1, $2, $3)")
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role_id)
        .execute(db)
        .await
        .expect("assign role to user");
}

/// `access_level`: 0=None, 1=Team, 2=BusinessUnit, 3=Global
/// (`attome_server::security::AccessLevel`).
async fn scope_role(db: &DbPool, role_id: Uuid, entity_id: Uuid, access_level: i16) {
    sqlx::query(
        "INSERT INTO role_mm_entity_access \
            (id, role_ref, entity_ref, read_access_level, write_access_level, delete_access_level, owner_layer) \
         VALUES ($1, $2, $3, $4, $4, $4, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(role_id)
    .bind(entity_id)
    .bind(access_level)
    .execute(db)
    .await
    .expect("upsert role entity-access grant");
}

/// capability: 0=View, 1=Action (`attome_security::rls::Capability`).
async fn share_record(
    db: &DbPool,
    record_id: Uuid,
    entity_id: Uuid,
    user_id: Uuid,
    capability: i16,
) {
    sqlx::query(
        "INSERT INTO record_share (record_id, entity_ref, principal_type, principal_id, capability) \
         VALUES ($1, $2, 0, $3, $4)",
    )
    .bind(record_id)
    .bind(entity_id)
    .bind(user_id)
    .bind(capability)
    .execute(db)
    .await
    .expect("insert record share");
}

fn ctx_for(user_id: Uuid, privileges: &[&str]) -> SecurityContext {
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
        unit_scope: Default::default(),
        field_masks: Default::default(),
        service_principal: false,
    }
}

fn query_for(regarding_id: Uuid) -> PredictionListQuery {
    PredictionListQuery {
        regarding_entity: TARGET_ENTITY.to_string(),
        regarding_id,
        page: None,
        page_size: None,
    }
}

/// C-02's proof requirement: a scoped user who holds the blanket
/// `{regarding_entity}.read` privilege but no record-level visibility of
/// this specific `regarding_id` (`None`-tier access, no explicit share) gets
/// an empty page — never the other record's scores/explanations.
#[tokio::test]
async fn predictions_list_is_empty_for_a_record_the_caller_cannot_see() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;
    sync_registry(&state).await;

    let target_entity_id = entity_id_by_logicalname(db, TARGET_ENTITY).await;
    let hidden_record = insert_target_record(db).await;
    let model_id = insert_model(db).await;
    insert_prediction(db, model_id, hidden_record).await;

    let user_id = insert_user(db).await;
    let role = create_read_role(db, TARGET_ENTITY).await;
    assign_role(db, user_id, role).await;
    scope_role(db, role, target_entity_id, 0).await; // None — no share granted at all

    let read_priv = format!("{TARGET_ENTITY}.read");
    let ctx = ctx_for(user_id, &[read_priv.as_str()]);
    let q = query_for(hidden_record);

    let page = list_predictions_impl(&state, &ctx, &q)
        .await
        .expect("list_predictions_impl");

    assert_eq!(
        page.items.len(),
        0,
        "a caller without record-level visibility of the regarding record must see no predictions"
    );
    assert_eq!(page.total, 0);
}

/// Positive-path counterpart: a caller explicitly shared the regarding
/// record (View capability) sees its prediction(s), proving the new gate
/// doesn't accidentally hide a record the caller genuinely can see.
#[tokio::test]
async fn predictions_list_returns_rows_for_a_shared_record() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;
    sync_registry(&state).await;

    let target_entity_id = entity_id_by_logicalname(db, TARGET_ENTITY).await;
    let visible_record = insert_target_record(db).await;
    let model_id = insert_model(db).await;
    let prediction_id = insert_prediction(db, model_id, visible_record).await;

    let user_id = insert_user(db).await;
    let role = create_read_role(db, TARGET_ENTITY).await;
    assign_role(db, user_id, role).await;
    scope_role(db, role, target_entity_id, 0).await; // None-tier by default...

    // ...except this one record is explicitly shared (View capability).
    share_record(db, visible_record, target_entity_id, user_id, 0).await;

    let read_priv = format!("{TARGET_ENTITY}.read");
    let ctx = ctx_for(user_id, &[read_priv.as_str()]);
    let q = query_for(visible_record);

    let page = list_predictions_impl(&state, &ctx, &q)
        .await
        .expect("list_predictions_impl");

    let ids: Vec<Uuid> = page.items.iter().map(|p| p.id).collect();
    assert!(
        ids.contains(&prediction_id),
        "an explicitly-shared regarding record's predictions must still be returned"
    );
    assert_eq!(page.total, 1);
}

/// A caller who lacks the entity-level `{regarding_entity}.read` privilege
/// altogether must still get the existing 403 — the new record-level gate
/// must not change or bypass that pre-existing check.
#[tokio::test]
async fn predictions_list_403s_without_the_entity_level_privilege() {
    let state = skip_if_no_db!(test_state().await);
    let db = &state.base.db;
    ensure_seeded(db).await;
    sync_registry(&state).await;

    let record = insert_target_record(db).await;
    let user_id = insert_user(db).await;
    let ctx = ctx_for(user_id, &[]); // no privileges at all
    let q = query_for(record);

    let result = list_predictions_impl(&state, &ctx, &q).await;
    assert!(matches!(result, Err(attome_types::AppError::Forbidden)));
}

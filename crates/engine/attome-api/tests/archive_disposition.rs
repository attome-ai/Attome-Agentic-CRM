//! M23 Records Management (D-456) — live-verified against a real Postgres +
//! object store: the `archive` disposition's interplay with per-record legal
//! holds, and the archive -> restore round trip. Same harness shape as
//! `retention.rs` (this crate's existing `entity_purge`/`partition_archive`
//! DB-backed suite) — a separate file rather than adding to that one so its
//! existing tests stay untouched; the JSON `test_config` helper below is a
//! near-duplicate of that file's own for the same reason.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-api --test archive_disposition -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::EngineSystem;
use attome_compliance::archive::restore_archived_record;
use attome_compliance::retention::{execute_action, propose_retention_actions};
use attome_config::AppConfig;
use attome_core::{EngineState, build_registry};
use attome_metadata::provision::{ensure_attribute, ensure_entity};
use attome_server::AppState;
use attome_testkit::point_config_at;
use attome_testkit::skip_if_no_db;
use chrono::{Duration as ChronoDuration, Utc};
use uuid::Uuid;

fn test_config(entity_purge_grace_days: Option<u32>, disposition_action: &str) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 15,
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
                "s3_region": "us-east-1", "s3_access_key": "{s3_access_key}", "s3_secret_key": "{s3_secret_key}",
                "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod", "jwt_issuer": "attome-test",
                "jwt_expiry_hours": 1, "oauth_google_client_id": "", "oauth_google_client_secret": ""
            }},
            "rate_limit": {{ "anonymous_rpm": 1000, "authenticated_rpm": 1000, "categories": {{}} }},
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
            "s2s": {{ "enabled": false, "key_encryption_key": "test-only-throwaway-s2s-key-32-bytes-min" }},
            "security": {{ "bootstrap_admin_email": null }},
            "cors": {{ "allowed_origins": ["http://test.local"] }},
            "retention": {{
                "audit_days": null, "s2s_access_log_days": null,
                "entity_purge_grace_days": {entity_purge_grace_days},
                "legal_hold": false, "dry_run": false,
                "disposition_action": "{disposition_action}"
            }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        s3_access_key = std::env::var("S3_ACCESS_KEY")
            .expect("set S3_ACCESS_KEY to a real RustFS/MinIO credential to run archive tests"),
        s3_secret_key = std::env::var("S3_SECRET_KEY")
            .expect("set S3_SECRET_KEY to a real RustFS/MinIO credential to run archive tests"),
        entity_purge_grace_days = entity_purge_grace_days
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".to_string()),
        disposition_action = disposition_action,
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system(mut config: AppConfig) -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    point_config_at(&mut config, &throwaway_url);
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

    Some(
        EngineSystem::builder(state)
            .register(attome_security::model::SecurityModel)
            .build()
            .await
            .expect("build EngineSystem"),
    )
}

async fn provision_test_entity(db: &attome_db::DbPool) -> String {
    let logicalname = format!("test_archive_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(db, &logicalname, "Test Archive Entity", None, false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        db, entity_id, "ssn", "SSN", "text", false, true, false, false, None, None,
    )
    .await
    .expect("ensure_attribute ssn");
    logicalname
}

async fn seed_soft_deleted_record(
    db: &attome_db::DbPool,
    logicalname: &str,
    days_ago: i64,
) -> Uuid {
    let record_id = Uuid::now_v7();
    let backdated = Utc::now() - ChronoDuration::days(days_ago);
    sqlx::query(&format!(
        "INSERT INTO \"{logicalname}\" (id, ssn, is_active, created_at, modified_at) \
         VALUES ($1, 'the-original-ssn', false, $2, $2)"
    ))
    .bind(record_id)
    .bind(backdated)
    .execute(db)
    .await
    .expect("seed a soft-deleted test record");
    record_id
}

async fn propose_and_approve_archive(
    db: &attome_db::DbPool,
    state: &EngineState,
    logicalname: &str,
    record_id: Uuid,
    approver: Uuid,
) -> Uuid {
    propose_retention_actions(state)
        .await
        .expect("propose_retention_actions");

    let target = format!("{logicalname}:{record_id}");
    let action_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_retention_action WHERE action_type = 'archive' AND target = $1",
    )
    .bind(&target)
    .fetch_one(db)
    .await
    .expect(
        "proposed 'archive' action row must exist when retention.disposition_action = \"archive\"",
    );

    sqlx::query(
        "UPDATE audit_retention_action SET status = 'approved', approved_by = $2, approved_at = NOW() \
          WHERE id = $1",
    )
    .bind(action_id)
    .bind(approver)
    .execute(db)
    .await
    .expect("simulate approval");

    action_id
}

/// Verification requirement: the round trip. `propose_retention_actions`
/// (with `retention.disposition_action = "archive"`) proposes an `archive`
/// action for the seeded soft-deleted record instead of `entity_purge`,
/// `execute_action` archives it (exports, scrubs the row), and
/// `restore_archived_record` brings the exact original field values back —
/// same `ssn`, `is_active = true` again.
#[tokio::test]
async fn archive_then_restore_round_trip_produces_the_same_data() {
    let config = test_config(Some(90), "archive");
    let system = skip_if_no_db!(test_system(config).await);
    let state = system.state();
    let db = &state.base.db;

    let logicalname = provision_test_entity(db).await;
    let record_id = seed_soft_deleted_record(db, &logicalname, 400).await;
    let approver = Uuid::now_v7();

    // Force a synchronous registry rebuild — same reasoning as
    // retention.rs's identical call: the entity was provisioned after
    // `EngineSystem::build()` already ran.
    let fresh_registry = build_registry(db).await.expect("build_registry");
    state.entities.swap(fresh_registry);

    let action_id = propose_and_approve_archive(db, state, &logicalname, record_id, approver).await;

    execute_action(state, action_id)
        .await
        .expect("execute_action (archive)");

    let (status, evidence_ref): (String, Option<String>) =
        sqlx::query_as("SELECT status, evidence_ref FROM audit_retention_action WHERE id = $1")
            .bind(action_id)
            .fetch_one(db)
            .await
            .expect("action row must still exist");
    assert_eq!(status, "completed");
    assert!(evidence_ref.is_some());

    let (ssn, is_active): (Option<String>, bool) = sqlx::query_as(&format!(
        "SELECT ssn, is_active FROM \"{logicalname}\" WHERE id = $1"
    ))
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("record must still exist (archive scrubs, never hard-deletes)");
    assert_eq!(ssn, None, "the live row must be scrubbed after archiving");
    assert!(!is_active);

    let archive_record_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM archive_record WHERE entity_logicalname = $1 AND record_id = $2 \
          AND restored_at IS NULL",
    )
    .bind(&logicalname)
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("execute_entity_archive must have written an archive_record row");

    let restored_by = Uuid::now_v7();
    restore_archived_record(state, archive_record_id, restored_by)
        .await
        .expect("restore_archived_record");

    let (ssn_after, is_active_after): (Option<String>, bool) = sqlx::query_as(&format!(
        "SELECT ssn, is_active FROM \"{logicalname}\" WHERE id = $1"
    ))
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("record must still exist after restore");
    assert_eq!(
        ssn_after,
        Some("the-original-ssn".to_string()),
        "restore must bring back the exact original field value"
    );
    assert!(is_active_after, "restore must reactivate the record");

    let restored_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT restored_at FROM archive_record WHERE id = $1")
            .bind(archive_record_id)
            .fetch_one(db)
            .await
            .expect("archive record row must still exist");
    assert!(restored_at.is_some());
}

/// Verification requirement: a legal hold blocks archival. Places a
/// per-record hold (`legal_hold`, the same table
/// `legal_hold_admin::place_hold` writes to) directly, mirroring how this
/// crate's existing retention tests simulate an admin approval step by SQL
/// rather than standing up an HTTP harness.
#[tokio::test]
async fn execute_entity_archive_refuses_a_record_under_an_active_legal_hold() {
    let config = test_config(Some(90), "archive");
    let system = skip_if_no_db!(test_system(config).await);
    let state = system.state();
    let db = &state.base.db;

    let logicalname = provision_test_entity(db).await;
    let record_id = seed_soft_deleted_record(db, &logicalname, 400).await;
    let approver = Uuid::now_v7();

    let fresh_registry = build_registry(db).await.expect("build_registry");
    state.entities.swap(fresh_registry);

    let hold_id: Uuid = sqlx::query_scalar(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ($1, $2, 'test-matter-001', $3) RETURNING id",
    )
    .bind(&logicalname)
    .bind(record_id)
    .bind(Uuid::now_v7())
    .fetch_one(db)
    .await
    .expect("place a per-record legal hold");

    let action_id = propose_and_approve_archive(db, state, &logicalname, record_id, approver).await;

    let result = execute_action(state, action_id).await;
    assert!(
        result.is_err(),
        "execute_action must refuse to archive a record under an active per-record legal hold"
    );

    let (status,): (String,) =
        sqlx::query_as("SELECT status FROM audit_retention_action WHERE id = $1")
            .bind(action_id)
            .fetch_one(db)
            .await
            .expect("action row must still exist");
    assert_eq!(
        status, "failed",
        "a hold-blocked execution must mark the action failed, not silently vanish"
    );

    let no_archive_row: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM archive_record WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(&logicalname)
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("count query");
    assert_eq!(
        no_archive_row, 0,
        "a refused archive must never leave an archive_record row behind"
    );

    // Release the hold, then retry the same action (an operator's manual
    // retry — same "flip status back to approved directly" convention this
    // crate's existing retention tests use to simulate the admin surface)
    // and confirm archival now succeeds.
    sqlx::query("UPDATE legal_hold SET released_at = NOW() WHERE id = $1")
        .bind(hold_id)
        .execute(db)
        .await
        .expect("release the hold");

    sqlx::query(
        "UPDATE audit_retention_action SET status = 'approved', approved_at = NOW() WHERE id = $1",
    )
    .bind(action_id)
    .execute(db)
    .await
    .expect("re-approve for retry");

    execute_action(state, action_id)
        .await
        .expect("execute_action must succeed once the hold is released");

    let (status_after,): (String,) =
        sqlx::query_as("SELECT status FROM audit_retention_action WHERE id = $1")
            .bind(action_id)
            .fetch_one(db)
            .await
            .expect("action row must still exist");
    assert_eq!(status_after, "completed");

    let archived: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM archive_record WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(&logicalname)
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("count query");
    assert_eq!(
        archived, 1,
        "releasing the hold must let the retry archive the record"
    );
}

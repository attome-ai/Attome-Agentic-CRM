//! Audit 10/10 plan item 3.6 (side-path atomicity, D-062): a background job's
//! state change and its audit event share one transaction, so a failed audit
//! write rolls the change back and the job returns `Err` instead of
//! completing without evidence — and the job is still safe to run again.
//!
//! Technique: in this binary's throwaway database (D-343), a `BEFORE INSERT`
//! trigger scoped to one event (by `event_name` + `record_id`, or by
//! `batch_id`) raises on both audit storage paths — `audit_ingest`
//! (`audit.chainer_enabled`, the default) and `audit_header` (the
//! synchronous path) — so the test holds whichever path the config selects.
//! Each test then drops its trigger and re-runs the job to prove retry safety.
//!
//! Harness copied from `archive_disposition.rs`/`data_management.rs` (same
//! per-file convention every integration suite in this crate follows).
//! Requires Postgres (`DATABASE_URL`), Redis (`TEST_REDIS_HOST`/
//! `TEST_REDIS_PORT`), and, for the export and archive tests, the object
//! store at `localhost:9000` (`S3_ACCESS_KEY`/`S3_SECRET_KEY`, default `test`).
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5556/attomedb_test"
//! $env:TEST_REDIS_PORT = "6380"
//! cargo test -p attome-api --test side_path_atomicity
//! ```

#![recursion_limit = "512"]
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

// ── Harness ─────────────────────────────────────────────────────────────────

fn test_config() -> AppConfig {
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
                "entity_purge_grace_days": 90,
                "legal_hold": false, "dry_run": false,
                "disposition_action": "archive"
            }}
        }}"#,
        redis_host = std::env::var("TEST_REDIS_HOST").unwrap_or_else(|_| "localhost".into()),
        redis_port = std::env::var("TEST_REDIS_PORT").unwrap_or_else(|_| "6379".into()),
        s3_access_key = std::env::var("S3_ACCESS_KEY").unwrap_or_else(|_| "test".into()),
        s3_secret_key = std::env::var("S3_SECRET_KEY").unwrap_or_else(|_| "test".into()),
    );
    serde_json::from_str(&json).expect("test_config JSON must deserialize into AppConfig")
}

async fn test_system() -> Option<EngineSystem> {
    let throwaway_url = attome_testkit::migrated_db_url()?;
    let mut config = test_config();
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

/// Which audit event a forced failure targets.
enum AuditMatch<'a> {
    /// `event_name` + `record_id` (the legal-matter and archive events).
    NamedRecord(&'a str, Uuid),
    /// `batch_id` (the data export event, which has no `event_name`).
    Batch(Uuid),
}

impl AuditMatch<'_> {
    fn ingest_predicate(&self) -> String {
        match self {
            Self::NamedRecord(name, record_id) => format!(
                "(NEW.payload->>'event_name') = '{name}' AND (NEW.payload->>'record_id') = '{record_id}'"
            ),
            Self::Batch(batch_id) => format!("(NEW.payload->>'batch_id') = '{batch_id}'"),
        }
    }

    fn header_predicate(&self) -> String {
        match self {
            Self::NamedRecord(name, record_id) => {
                format!("NEW.event_name = '{name}' AND NEW.record_id::text = '{record_id}'")
            }
            Self::Batch(batch_id) => format!("NEW.batch_id::text = '{batch_id}'"),
        }
    }

    async fn count(&self, db: &attome_db::DbPool) -> i64 {
        let sql = format!(
            "SELECT (SELECT COUNT(*) FROM audit_ingest WHERE {ingest}) \
                  + (SELECT COUNT(*) FROM audit_header WHERE {header})",
            ingest = self.ingest_predicate().replace("NEW.", ""),
            header = self.header_predicate().replace("NEW.", ""),
        );
        sqlx::query_scalar::<_, i64>(&sql)
            .fetch_one(db)
            .await
            .expect("count audit rows")
    }
}

/// Installs a trigger pair that makes exactly the matched audit insert fail.
/// Every name/literal interpolated here is a test-generated UUID or a
/// constant event name — never external input. Returns the suffix
/// [`remove_audit_failure`] needs.
async fn force_audit_failure(db: &attome_db::DbPool, matcher: &AuditMatch<'_>) -> String {
    let suffix = Uuid::now_v7().simple().to_string();
    let statements = [
        format!(
            "CREATE FUNCTION test_fail_audit_{suffix}() RETURNS trigger LANGUAGE plpgsql AS \
             $$ BEGIN RAISE EXCEPTION 'forced audit failure'; END $$"
        ),
        format!(
            "CREATE TRIGGER test_fail_audit_ingest_{suffix} BEFORE INSERT ON audit_ingest \
             FOR EACH ROW WHEN ({}) EXECUTE FUNCTION test_fail_audit_{suffix}()",
            matcher.ingest_predicate()
        ),
        format!(
            "CREATE TRIGGER test_fail_audit_header_{suffix} BEFORE INSERT ON audit_header \
             FOR EACH ROW WHEN ({}) EXECUTE FUNCTION test_fail_audit_{suffix}()",
            matcher.header_predicate()
        ),
    ];
    for sql in statements {
        sqlx::query(&sql)
            .execute(db)
            .await
            .unwrap_or_else(|e| panic!("install forced audit failure ({sql}): {e}"));
    }
    suffix
}

async fn remove_audit_failure(db: &attome_db::DbPool, suffix: &str) {
    let statements = [
        format!("DROP TRIGGER IF EXISTS test_fail_audit_ingest_{suffix} ON audit_ingest"),
        format!("DROP TRIGGER IF EXISTS test_fail_audit_header_{suffix} ON audit_header"),
        format!("DROP FUNCTION IF EXISTS test_fail_audit_{suffix}()"),
    ];
    for sql in statements {
        sqlx::query(&sql)
            .execute(db)
            .await
            .unwrap_or_else(|e| panic!("remove forced audit failure ({sql}): {e}"));
    }
}

async fn seed_admin_user(db: &attome_db::DbPool) -> Uuid {
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, email, user_name, is_active) VALUES ($1, $2, $3, true)",
    )
    .bind(user_id)
    .bind(format!("spa-test-{user_id}@test.local"))
    .bind(format!("spa-test-{user_id}"))
    .execute(db)
    .await
    .expect("insert throwaway user_account");

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
    user_id
}

/// Provisions an entity with one plain `title` and one sensitive `ssn` text
/// field, then refreshes the registry (the background subscriber is off).
async fn provision_test_entity(state: &EngineState, prefix: &str) -> String {
    let db = &state.base.db;
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let entity_id = ensure_entity(db, &logicalname, "Side Path Atomicity Test", None, false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        db, entity_id, "title", "Title", "text", false, false, false, false, None, None,
    )
    .await
    .expect("ensure_attribute title");
    ensure_attribute(
        db, entity_id, "ssn", "SSN", "text", false, true, false, false, None, None,
    )
    .await
    .expect("ensure_attribute ssn");
    let fresh_registry = build_registry(db).await.expect("build_registry");
    state.entities.swap(fresh_registry);
    logicalname
}

// ── Legal matter release ────────────────────────────────────────────────────

#[tokio::test]
async fn a_failed_audit_write_rolls_back_the_legal_matter_release() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    let db = &state.base.db;
    let released_by = Uuid::now_v7();

    let reference = format!("spa-matter-{}", Uuid::now_v7().simple());
    let matter_id: Uuid = sqlx::query_scalar(
        "INSERT INTO audit_legal_matter (reference, custodian, scope_entity, status) \
         VALUES ($1, 'test custodian', 'user_account', 'releasing') RETURNING id",
    )
    .bind(&reference)
    .fetch_one(db)
    .await
    .expect("seed a releasing legal matter");
    sqlx::query(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ('user_account', $1, $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(&reference)
    .bind(released_by)
    .execute(db)
    .await
    .expect("seed a hold under the matter");

    let matcher = AuditMatch::NamedRecord("legal_matter_release", matter_id);
    let suffix = force_audit_failure(db, &matcher).await;

    let result =
        attome_compliance::legal_matter_admin::run_release_job(state, matter_id, released_by).await;
    assert!(
        result.is_err(),
        "a failed audit write must fail the release job, not complete it silently"
    );

    let (status, released_at): (String, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT status, released_at FROM audit_legal_matter WHERE id = $1")
            .bind(matter_id)
            .fetch_one(db)
            .await
            .expect("matter row");
    assert_eq!(
        status, "releasing",
        "the released transition must roll back with the failed audit write"
    );
    assert!(released_at.is_none());
    assert_eq!(matcher.count(db).await, 0, "no audit row may exist");

    // Retry safety: the matter is still `releasing`, so a re-delivered job
    // passes the status guard, finds no holds left, and completes.
    remove_audit_failure(db, &suffix).await;
    attome_compliance::legal_matter_admin::run_release_job(state, matter_id, released_by)
        .await
        .expect("the retried release job must complete once the audit write succeeds");

    let status_after: String =
        sqlx::query_scalar("SELECT status FROM audit_legal_matter WHERE id = $1")
            .bind(matter_id)
            .fetch_one(db)
            .await
            .expect("matter row");
    assert_eq!(status_after, "released");
    let active_holds: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM legal_hold WHERE matter_reference = $1 AND released_at IS NULL",
    )
    .bind(&reference)
    .fetch_one(db)
    .await
    .expect("count holds");
    assert_eq!(active_holds, 0);
    assert_eq!(matcher.count(db).await, 1, "exactly one release event");
}

// ── Data export ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_failed_audit_write_rolls_back_the_data_export_completion() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    let db = &state.base.db;
    let user_id = seed_admin_user(db).await;
    let logicalname = provision_test_entity(state, "spa_exp").await;

    sqlx::query(&format!(
        "INSERT INTO \"{logicalname}\" (title) VALUES ('exported value')"
    ))
    .execute(db)
    .await
    .expect("insert fixture record");

    let export_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO data_export (id, entity_logicalname, format, status, created_by) \
         VALUES ($1, $2, 'json', 'pending', $3)",
    )
    .bind(export_id)
    .bind(&logicalname)
    .bind(user_id)
    .execute(db)
    .await
    .expect("seed a pending export row");

    let payload = || attome_core::jobs::DataExportPayload {
        export_id,
        entity_logicalname: logicalname.clone(),
        format: "json".to_string(),
        columns: vec![],
        filters: vec![],
        user_id,
    };

    let matcher = AuditMatch::Batch(export_id);
    let suffix = force_audit_failure(db, &matcher).await;

    let result = attome_api::data_export::process(state, payload()).await;
    assert!(
        result.is_err(),
        "a failed audit write must fail the export job, not complete it silently"
    );

    let (status, completed_at): (String, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT status, completed_at FROM data_export WHERE id = $1")
            .bind(export_id)
            .fetch_one(db)
            .await
            .expect("export row");
    assert_ne!(
        status, "completed",
        "the completed transition must roll back with the failed audit write"
    );
    assert_eq!(
        status, "failed",
        "the rolled-back export must not stay 'running' holding a concurrency slot"
    );
    assert!(completed_at.is_none());
    assert_eq!(matcher.count(db).await, 0, "no audit row may exist");

    // Retry safety: this worker has no status guard, so a re-delivered job
    // re-streams to the same object key and completes the same row.
    remove_audit_failure(db, &suffix).await;
    attome_api::data_export::process(state, payload())
        .await
        .expect("the retried export job must complete once the audit write succeeds");

    let (status_after, object_key): (String, Option<String>) =
        sqlx::query_as("SELECT status, object_key FROM data_export WHERE id = $1")
            .bind(export_id)
            .fetch_one(db)
            .await
            .expect("export row");
    assert_eq!(status_after, "completed");
    assert!(object_key.is_some());
    assert_eq!(matcher.count(db).await, 1, "exactly one export event");
}

// ── Archive disposition and restore ─────────────────────────────────────────

async fn seed_soft_deleted_record(db: &attome_db::DbPool, logicalname: &str) -> Uuid {
    let record_id = Uuid::now_v7();
    let backdated = Utc::now() - ChronoDuration::days(400);
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

async fn record_ssn(db: &attome_db::DbPool, logicalname: &str, record_id: Uuid) -> Option<String> {
    sqlx::query_scalar(&format!("SELECT ssn FROM \"{logicalname}\" WHERE id = $1"))
        .bind(record_id)
        .fetch_one(db)
        .await
        .expect("record row")
}

async fn set_action_approved(db: &attome_db::DbPool, action_id: Uuid, approver: Uuid) {
    sqlx::query(
        "UPDATE audit_retention_action SET status = 'approved', approved_by = $2, approved_at = NOW() \
          WHERE id = $1",
    )
    .bind(action_id)
    .bind(approver)
    .execute(db)
    .await
    .expect("simulate approval");
}

#[tokio::test]
async fn a_failed_audit_write_rolls_back_the_archive_scrub_and_the_restore() {
    let system = skip_if_no_db!(test_system().await);
    let state = system.state();
    let db = &state.base.db;
    let logicalname = provision_test_entity(state, "spa_arc").await;
    let record_id = seed_soft_deleted_record(db, &logicalname).await;
    let approver = Uuid::now_v7();

    propose_retention_actions(state)
        .await
        .expect("propose_retention_actions");
    let action_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_retention_action WHERE action_type = 'archive' AND target = $1",
    )
    .bind(format!("{logicalname}:{record_id}"))
    .fetch_one(db)
    .await
    .expect("proposed 'archive' action row");
    set_action_approved(db, action_id, approver).await;

    // Archive: the scrub, the evidence row and the event are one transaction.
    let archive_match = AuditMatch::NamedRecord("retention_archive", record_id);
    let suffix = force_audit_failure(db, &archive_match).await;
    assert!(
        execute_action(state, action_id).await.is_err(),
        "a failed audit write must fail the archive disposition"
    );
    assert_eq!(
        record_ssn(db, &logicalname, record_id).await.as_deref(),
        Some("the-original-ssn"),
        "the scrub must roll back with the failed audit write"
    );
    let archive_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM archive_record WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(&logicalname)
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("count archive rows");
    assert_eq!(archive_rows, 0, "no evidence row without its audit event");
    assert_eq!(archive_match.count(db).await, 0);

    // Retry: the action was marked failed; an operator re-approves it (the
    // same simulation archive_disposition.rs uses) and the whole disposition
    // re-runs against the still-unscrubbed record.
    remove_audit_failure(db, &suffix).await;
    set_action_approved(db, action_id, approver).await;
    execute_action(state, action_id)
        .await
        .expect("the retried archive must complete once the audit write succeeds");
    assert_eq!(record_ssn(db, &logicalname, record_id).await, None);
    assert_eq!(archive_match.count(db).await, 1);

    let archive_record_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM archive_record WHERE entity_logicalname = $1 AND record_id = $2 \
          AND restored_at IS NULL",
    )
    .bind(&logicalname)
    .bind(record_id)
    .fetch_one(db)
    .await
    .expect("archive record row");

    // Restore: the row restore, `restored_at`, and the event are one
    // transaction.
    let restore_match = AuditMatch::NamedRecord("retention_archive_restore", record_id);
    let suffix = force_audit_failure(db, &restore_match).await;
    let restored_by = Uuid::now_v7();
    assert!(
        restore_archived_record(state, archive_record_id, restored_by)
            .await
            .is_err(),
        "a failed audit write must fail the restore"
    );
    assert_eq!(
        record_ssn(db, &logicalname, record_id).await,
        None,
        "the restore must roll back with the failed audit write"
    );
    let restored_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT restored_at FROM archive_record WHERE id = $1")
            .bind(archive_record_id)
            .fetch_one(db)
            .await
            .expect("archive record row");
    assert!(restored_at.is_none());
    assert_eq!(restore_match.count(db).await, 0);

    remove_audit_failure(db, &suffix).await;
    restore_archived_record(state, archive_record_id, restored_by)
        .await
        .expect("the retried restore must complete once the audit write succeeds");
    assert_eq!(
        record_ssn(db, &logicalname, record_id).await.as_deref(),
        Some("the-original-ssn")
    );
    assert_eq!(restore_match.count(db).await, 1);
}

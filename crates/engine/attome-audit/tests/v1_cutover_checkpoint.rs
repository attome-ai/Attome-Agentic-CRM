//! Audit 10/10 plan item 2.6 (D-539 ruling 6): the v1 cutover checkpoint.
//!
//! Hash version 1 never covered an event's content, so these tests prove what
//! the checkpoint adds: after the cutover, an edit of pre-cutover (v1) detail,
//! snapshot or header content fails verification; a v1 row appended after the
//! checkpoint fails verification; and the checkpoint job is idempotent,
//! retry-safe and defers while pre-v2 payloads are still pending.
//!
//! Every chain here is written through the production chainer path, with
//! batches signed by a key registered in `audit_signing_key` (as boot does),
//! so "signing configured" holds for the whole binary.
//!
//! The anchored case needs a live S3-compatible store: `S3_ACCESS_KEY` and
//! `S3_SECRET_KEY` (the repo-root `.env`), optionally `S3_ENDPOINT` and
//! `S3_BUCKET` — the same convention as `anchor.rs` and `epoch_boundary.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-audit --test v1_cutover_checkpoint -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Duration;

use attome_audit::checkpoint::{self, CheckpointOutcome, V1ContentProtection};
use attome_audit::{
    AuditCategory, AuditEvent, AuditFieldChange, AuditOperation, AuditRequestContext, AuditService,
    AuditSigner, AuditSource, AuditUserContext, chainer, verify,
};
use attome_config::AppConfig;
use attome_db::DbPool;
use attome_storage::{StorageClient, create_storage_client};
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const KEY_ID: &str = "v1-cutover-checkpoint-test-key";

fn signer() -> AuditSigner {
    AuditSigner::from_config(KEY_ID, &"3c".repeat(32)).expect("test signing key")
}

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await
        .expect("failed to connect to DATABASE_URL");
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");
    let signer = signer();
    attome_core::audit_signing::upsert_signing_key(&db, KEY_ID, &signer.verifying_key_b64())
        .await
        .expect("register the test signing key, as boot does");
    Some(db)
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// Same throwaway-config shape as `tests/anchor.rs::test_storage_client`.
async fn test_storage_client() -> StorageClient {
    let json = format!(
        r#"{{
            "app": {{ "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
                "frontend_port": 4200, "log_level": "error", "threads": 1,
                "max_body_size_bytes": 1048576, "request_timeout_secs": 5,
                "enable_session": true, "max_connection_num": 8, "max_connection_num_per_ip": 8,
                "use_gzip": false, "enable_compression": false, "gzip_level": 1, "br_level": 1,
                "idle_connection_timeout": 10, "keepalive_requests": 10,
                "static_files_cache_time": 0, "server_header_field": "test" }},
            "database": {{ "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
                "password": "test", "schema": "test", "connection_number": 1, "timeout": 5.0 }},
            "cache": {{ "host": "localhost", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60 }},
            "storage": {{ "s3_endpoint": "{endpoint}", "s3_region": "us-east-1",
                "s3_access_key": "{access_key}", "s3_secret_key": "{secret_key}",
                "s3_bucket": "{bucket}", "s3_use_path_style": true, "s3_verify_ssl": false }},
            "auth": {{ "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
                "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min" }},
            "rate_limit": {{ "anonymous_rpm": 100, "authenticated_rpm": 1000 }},
            "observability": {{ "metrics_port": 0, "log_sampling_rate": 1.0,
                "trace_sampling_rate": 1.0, "enable_distributed_tracing": false }},
            "email": {{ "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "a@b.c", "smtp_from_name": "t",
                "smtp_use_tls": false, "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5 }},
            "google_ai": {{ "api_key": "test", "base_url": "http://localhost",
                "default_model": "test", "timeout_seconds": 5 }}
        }}"#,
        endpoint = env_or("S3_ENDPOINT", "http://127.0.0.1:9000"),
        access_key = env_or("S3_ACCESS_KEY", ""),
        secret_key = env_or("S3_SECRET_KEY", ""),
        bucket = env_or("S3_BUCKET", "attomebase"),
    );
    let config: AppConfig = serde_json::from_str(&json).expect("parse throwaway storage config");
    create_storage_client(&config)
        .await
        .expect("connect to the configured S3-compatible store")
}

fn field(name: &str, old: &str, new: &str) -> AuditFieldChange {
    AuditFieldChange {
        field_name: name.into(),
        display_name: Some(format!("{name} (display)")),
        data_type: Some(0),
        old_value: Some(old.into()),
        new_value: Some(new.into()),
        old_display_value: None,
        new_display_value: None,
        old_lookup_entity: None,
        old_lookup_name: None,
        new_lookup_entity: None,
        new_lookup_name: None,
        is_sensitive: false,
    }
}

fn full_event(org: Uuid, i: usize) -> AuditEvent {
    AuditEvent {
        organization_ref: org,
        category: AuditCategory::Entity,
        entity_name: Some("v1_checkpoint_test_entity".into()),
        record_id: Some(Uuid::now_v7()),
        operation: AuditOperation::Update,
        version_before: Some(i as i64),
        version_after: Some(i as i64 + 1),
        user_context: AuditUserContext {
            user_id: Uuid::now_v7(),
            user_name: format!("v1-checkpoint-user-{i}"),
            user_display_name: format!("V1 Checkpoint User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext {
            ip_address: Some(format!("10.1.0.{i}")),
            browser: Some("v1-checkpoint-agent".into()),
            device_type: Some(0),
        },
        correlation_id: Some(Uuid::now_v7()),
        batch_id: None,
        event_name: Some(format!("v1-checkpoint-event-{i}")),
        event_comment: Some(format!("remark {i}")),
        changed_fields: vec![
            field("status", "draft", &format!("approved-{i}")),
            field("amount", "10", &format!("{}", 20 + i)),
        ],
        snapshot_json: Some(
            serde_json::json!({"status": format!("approved-{i}"), "amount": 20 + i}),
        ),
    }
}

/// A pre-v2 ingest payload — what an old-binary writer captured. The chainer
/// writes it as a hash-version-1 row.
async fn insert_legacy_ingest_row(db: &DbPool, event: &AuditEvent) {
    let payload = serde_json::to_value(event).expect("serialize AuditEvent");
    sqlx::query("INSERT INTO audit_ingest (organization_ref, payload) VALUES ($1, $2)")
        .bind(event.organization_ref)
        .bind(payload)
        .execute(db)
        .await
        .expect("insert legacy ingest row");
}

/// Three v1 rows (pre-cutover history), then two v2 rows (the cutover
/// happened), all drained into signed batches. Returns the v1 header ids.
async fn upgraded_chain(db: &DbPool, org: Uuid, store: Option<&StorageClient>) -> Vec<Uuid> {
    let signer = signer();
    for i in 0..3 {
        insert_legacy_ingest_row(db, &full_event(org, i)).await;
    }
    chainer::run_once(db, Some(&signer), 1000, store)
        .await
        .expect("chainer run (v1 history)");
    for i in 3..5 {
        AuditService::new(db, None)
            .with_chainer_enabled(true)
            .write(full_event(org, i))
            .await
            .expect("v2 write");
    }
    chainer::run_once(db, Some(&signer), 1000, store)
        .await
        .expect("chainer run (v2)");

    sqlx::query_scalar(
        "SELECT id FROM audit_header WHERE organization_ref = $1 AND hash_version = 1 ORDER BY id",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .expect("v1 header ids")
}

async fn verify(db: &DbPool, org: Uuid) -> verify::VerificationReport {
    let signer = signer();
    verify::verify_chain(db, Some(&signer), org)
        .await
        .expect("verify_chain")
}

async fn checkpoint(db: &DbPool, org: Uuid) -> CheckpointOutcome {
    let signer = signer();
    checkpoint::create_v1_cutover_checkpoint(db, Some(&signer), None, org, Duration::ZERO)
        .await
        .expect("create_v1_cutover_checkpoint")
}

async fn exec(db: &DbPool, sql: &str, id: Uuid) {
    let affected = sqlx::query(sql)
        .bind(id)
        .execute(db)
        .await
        .unwrap_or_else(|e| panic!("tamper statement failed: {sql}: {e}"))
        .rows_affected();
    assert!(affected > 0, "tamper statement changed nothing: {sql}");
}

fn assert_v1_content_change_reported(report: &verify::VerificationReport) {
    assert!(
        !report.is_ok(),
        "a post-cutover v1 edit must fail verification"
    );
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("v1 content changed after the cutover checkpoint")),
        "expected a v1 checkpoint mismatch, got: {:?}",
        report.errors
    );
}

/// Plan Phase 2 fixture: "the checkpoint detects a post-cutover v1 edit".
#[tokio::test]
async fn checkpoint_detects_a_post_cutover_v1_detail_edit() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let v1 = upgraded_chain(&db, org, None).await;

    let before = verify(&db, org).await;
    assert!(before.is_ok(), "{:?}", before.errors);
    assert_eq!(
        before.v1_content_protection,
        V1ContentProtection::NotCheckpointed
    );

    // Without a checkpoint, a v1 detail edit is invisible (the v1 hash never
    // covered content) — which is exactly what the checkpoint closes.
    assert_eq!(
        checkpoint(&db, org).await,
        CheckpointOutcome::Created {
            v1_headers: 3,
            partitions: 1
        }
    );
    let frozen = verify(&db, org).await;
    assert!(frozen.is_ok(), "{:?}", frozen.errors);
    assert_eq!(
        frozen.v1_content_protection,
        V1ContentProtection::CheckpointedDatabaseOnly
    );

    exec(
        &db,
        "UPDATE audit_detail SET new_value = 'edited after cutover'
         WHERE audit_ref = $1 AND field_name = 'status'",
        v1[1],
    )
    .await;
    assert_v1_content_change_reported(&verify(&db, org).await);
}

#[tokio::test]
async fn checkpoint_detects_a_post_cutover_v1_snapshot_edit() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let v1 = upgraded_chain(&db, org, None).await;
    checkpoint(&db, org).await;
    assert!(verify(&db, org).await.is_ok());

    exec(
        &db,
        "UPDATE audit_snapshot SET snapshot_json = '{\"status\": \"forged\"}'::jsonb
         WHERE audit_ref = $1",
        v1[0],
    )
    .await;
    assert_v1_content_change_reported(&verify(&db, org).await);
}

#[tokio::test]
async fn checkpoint_detects_a_post_cutover_v1_remark_edit_and_a_deleted_detail_row() {
    let db = skip_if_no_db!(test_db().await);

    let org = Uuid::now_v7();
    let v1 = upgraded_chain(&db, org, None).await;
    checkpoint(&db, org).await;
    exec(
        &db,
        "UPDATE audit_header SET event_comment = 'rewritten remark' WHERE id = $1",
        v1[2],
    )
    .await;
    assert_v1_content_change_reported(&verify(&db, org).await);

    let org = Uuid::now_v7();
    let v1 = upgraded_chain(&db, org, None).await;
    checkpoint(&db, org).await;
    exec(
        &db,
        "DELETE FROM audit_detail WHERE audit_ref = $1 AND field_name = 'amount'",
        v1[0],
    )
    .await;
    assert_v1_content_change_reported(&verify(&db, org).await);
}

#[tokio::test]
async fn a_v1_row_after_the_checkpoint_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    upgraded_chain(&db, org, None).await;
    checkpoint(&db, org).await;
    assert!(verify(&db, org).await.is_ok());

    // A straggling old-binary writer after the v1 set was frozen.
    insert_legacy_ingest_row(&db, &full_event(org, 9)).await;
    chainer::run_once(&db, Some(&signer()), 1000, None)
        .await
        .expect("chainer run (late v1)");

    let report = verify(&db, org).await;
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("hash_version 1 row after the v1 cutover checkpoint")),
        "expected the late v1 row to be reported, got: {:?}",
        report.errors
    );
}

#[tokio::test]
async fn checkpoint_job_is_idempotent_and_retry_safe() {
    let db = skip_if_no_db!(test_db().await);
    let signer = signer();

    // Sequential retry: the second call changes nothing.
    let org = Uuid::now_v7();
    upgraded_chain(&db, org, None).await;
    assert!(matches!(
        checkpoint(&db, org).await,
        CheckpointOutcome::Created { .. }
    ));
    let stored: (String, String) = sqlx::query_as(
        "SELECT record, signature FROM audit_v1_checkpoint WHERE organization_ref = $1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("stored checkpoint");
    assert_eq!(checkpoint(&db, org).await, CheckpointOutcome::AlreadyExists);
    let again: (String, String) = sqlx::query_as(
        "SELECT record, signature FROM audit_v1_checkpoint WHERE organization_ref = $1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("stored checkpoint after retry");
    assert_eq!(stored, again, "a retry must not rewrite the checkpoint");

    // The scheduled sweep skips an organization that already has one.
    let swept = checkpoint::run_v1_cutover_checkpoints(&db, Some(&signer), None, Duration::ZERO)
        .await
        .expect("sweep");
    assert!(swept.iter().all(|(o, _)| *o != org));

    // Two concurrent runs: exactly one writes, the other backs off.
    let org = Uuid::now_v7();
    upgraded_chain(&db, org, None).await;
    let (a, b) = tokio::join!(
        checkpoint::create_v1_cutover_checkpoint(&db, Some(&signer), None, org, Duration::ZERO),
        checkpoint::create_v1_cutover_checkpoint(&db, Some(&signer), None, org, Duration::ZERO),
    );
    let outcomes = [a.expect("run a"), b.expect("run b")];
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, CheckpointOutcome::Created { .. }))
            .count(),
        1,
        "exactly one concurrent run creates the checkpoint: {outcomes:?}"
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_v1_checkpoint WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count checkpoints");
    assert_eq!(rows, 1);
    assert!(verify(&db, org).await.is_ok());
}

#[tokio::test]
async fn checkpoint_defers_while_pre_v2_payloads_are_pending() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    upgraded_chain(&db, org, None).await;

    // An old-binary node captured one more event that is not chained yet.
    insert_legacy_ingest_row(&db, &full_event(org, 7)).await;
    assert!(matches!(
        checkpoint(&db, org).await,
        CheckpointOutcome::Deferred(_)
    ));

    // A quiet period also defers while the newest pre-v2 capture is recent.
    chainer::run_once(&db, Some(&signer()), 1000, None)
        .await
        .expect("chainer run (drain the straggler)");
    let signer = signer();
    assert!(matches!(
        checkpoint::create_v1_cutover_checkpoint(
            &db,
            Some(&signer),
            None,
            org,
            Duration::from_secs(3600)
        )
        .await
        .expect("create with a quiet period"),
        CheckpointOutcome::Deferred(_)
    ));

    assert_eq!(
        checkpoint(&db, org).await,
        CheckpointOutcome::Created {
            v1_headers: 4,
            partitions: 1
        }
    );
    assert!(verify(&db, org).await.is_ok());

    // An organization with no v1 history has nothing to freeze.
    let fresh = Uuid::now_v7();
    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .write(full_event(fresh, 0))
        .await
        .expect("v2 write");
    chainer::run_once(&db, Some(&signer), 1000, None)
        .await
        .expect("chainer run (v2 only)");
    assert_eq!(checkpoint(&db, fresh).await, CheckpointOutcome::NoV1History);
    assert_eq!(
        verify(&db, fresh).await.v1_content_protection,
        V1ContentProtection::NoV1History
    );
}

#[tokio::test]
async fn a_tampered_or_forged_checkpoint_fails_verification() {
    let db = skip_if_no_db!(test_db().await);

    // Signature no longer matches the record.
    let org = Uuid::now_v7();
    upgraded_chain(&db, org, None).await;
    checkpoint(&db, org).await;
    exec(
        &db,
        "UPDATE audit_v1_checkpoint
         SET record = replace(record, '\"v1_header_count\":3', '\"v1_header_count\":4'),
             record_sha256 = encode(sha256(convert_to(replace(record, '\"v1_header_count\":3', '\"v1_header_count\":4'), 'UTF8')), 'hex')
         WHERE organization_ref = $1",
        org,
    )
    .await;
    let report = verify(&db, org).await;
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("v1 cutover checkpoint: signature does not verify")),
        "got: {:?}",
        report.errors
    );

    // Signature stripped while signing is configured.
    let org = Uuid::now_v7();
    upgraded_chain(&db, org, None).await;
    checkpoint(&db, org).await;
    exec(
        &db,
        "UPDATE audit_v1_checkpoint SET signature = NULL WHERE organization_ref = $1",
        org,
    )
    .await;
    let report = verify(&db, org).await;
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("unsigned while audit signing is configured")),
        "got: {:?}",
        report.errors
    );
}

/// With an anchor store, the anchored object is the reference: a database copy
/// rewritten afterwards is reported, and the job refuses to overwrite the anchor.
#[tokio::test]
async fn the_anchored_checkpoint_wins_over_a_rewritten_database_copy() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let signer = signer();
    let org = Uuid::now_v7();
    let v1 = upgraded_chain(&db, org, Some(&store)).await;

    let outcome = checkpoint::create_v1_cutover_checkpoint(
        &db,
        Some(&signer),
        Some(&store),
        org,
        Duration::ZERO,
    )
    .await
    .expect("create anchored checkpoint");
    assert!(matches!(outcome, CheckpointOutcome::Created { .. }));
    assert!(
        checkpoint::fetch_anchored_checkpoint(&store, org)
            .await
            .expect("read anchor")
            .is_some()
    );

    let report = verify::verify_chain_with_anchors(&db, Some(&signer), Some(&store), org)
        .await
        .expect("verify with anchors");
    assert!(report.is_ok(), "{:?}", report.errors);
    assert_eq!(
        report.v1_content_protection,
        V1ContentProtection::CheckpointedAnchored
    );

    // A DB-level writer edits v1 content and re-freezes it: deletes nothing
    // (runtime cannot), but rewrites the database copy by recomputing it.
    exec(
        &db,
        "UPDATE audit_detail SET new_value = 'rewritten' WHERE audit_ref = $1 AND field_name = 'status'",
        v1[0],
    )
    .await;
    exec(
        &db,
        "DELETE FROM audit_v1_checkpoint WHERE organization_ref = $1",
        org,
    )
    .await;
    assert!(matches!(
        checkpoint::create_v1_cutover_checkpoint(&db, Some(&signer), None, org, Duration::ZERO)
            .await
            .expect("re-create database copy"),
        CheckpointOutcome::Created { .. }
    ));

    let report = verify::verify_chain_with_anchors(&db, Some(&signer), Some(&store), org)
        .await
        .expect("verify with anchors after the rewrite");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("differs from the externally anchored object")),
        "got: {:?}",
        report.errors
    );
    assert_v1_content_change_reported(&report);

    // The job's anchor retry refuses to replace the anchored object.
    assert!(
        checkpoint::create_v1_cutover_checkpoint(
            &db,
            Some(&signer),
            Some(&store),
            org,
            Duration::ZERO
        )
        .await
        .is_err(),
        "an anchored checkpoint must never be overwritten with a different database copy"
    );
}

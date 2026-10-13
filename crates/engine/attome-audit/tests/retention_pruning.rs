//! Integration tests for `attome_audit::chainer::prune_ingest` — P1.13 step 6,
//! rewritten for audit 10/10 plan item 2.8: pruning never breaks verification,
//! and only ingest ranges whose covering batches are sealed (signed) and
//! externally anchored are pruned.
//!
//! `prune_ingest` has no per-organization filter (it is a global retention
//! sweep by design), so these tests must run single-threaded, and each asserts
//! on its own organization's rows rather than the returned global count.
//!
//! Needs a live S3-compatible store for the anchors: `S3_ACCESS_KEY` and
//! `S3_SECRET_KEY` (the repo-root `.env`), optionally `S3_ENDPOINT` and
//! `S3_BUCKET` — the same convention as `anchor.rs` and `epoch_boundary.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-audit --test retention_pruning -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSigner,
    AuditSource, AuditUserContext, chainer, verify,
};
use attome_config::AppConfig;
use attome_db::DbPool;
use attome_storage::{StorageClient, create_storage_client};
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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
    Some(db)
}

fn signer() -> AuditSigner {
    AuditSigner::from_config("retention-pruning-test-key", &"7a".repeat(32))
        .expect("test signing key")
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

fn make_event(organization_ref: Uuid, i: usize) -> AuditEvent {
    AuditEvent {
        organization_ref,
        category: AuditCategory::BusinessEvent,
        entity_name: Some("test_entity".into()),
        record_id: Some(Uuid::now_v7()),
        operation: AuditOperation::Submitted,
        version_before: None,
        version_after: None,
        user_context: AuditUserContext {
            user_id: Uuid::now_v7(),
            user_name: format!("prune-test-user-{i}"),
            user_display_name: format!("Prune Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("prune-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

/// A pre-v2 payload (no hash version): the chainer writes it as a v1 row.
async fn insert_ingest_row(db: &DbPool, event: &AuditEvent) {
    let payload = serde_json::to_value(event).expect("serialize AuditEvent");
    sqlx::query("INSERT INTO audit_ingest (organization_ref, payload) VALUES ($1, $2)")
        .bind(event.organization_ref)
        .bind(payload)
        .execute(db)
        .await
        .expect("insert ingest row");
}

/// Captures a v2 event through the production chainer path.
async fn write_v2(db: &DbPool, event: AuditEvent) {
    AuditService::new(db, None)
        .with_chainer_enabled(true)
        .write(event)
        .await
        .expect("audit write (chainer path)");
}

async fn backdate_ingest_rows(db: &DbPool, organization_ref: Uuid, days: i64) {
    sqlx::query(
        "UPDATE audit_ingest SET created_at = NOW() - make_interval(days => $1)
         WHERE organization_ref = $2",
    )
    .bind(days as i32)
    .bind(organization_ref)
    .execute(db)
    .await
    .expect("backdate ingest rows");
}

async fn ingest_count(db: &DbPool, organization_ref: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_ingest WHERE organization_ref = $1")
        .bind(organization_ref)
        .fetch_one(db)
        .await
        .expect("count ingest rows")
}

async fn watermark_rows(db: &DbPool, organization_ref: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_ingest_prune WHERE organization_ref = $1")
        .bind(organization_ref)
        .fetch_one(db)
        .await
        .expect("count watermark rows")
}

/// Three v1 events then two v2 events for `org`, drained into two batches,
/// signed with `signer` and anchored in `anchor` when those are given.
async fn chained(
    db: &DbPool,
    org: Uuid,
    signer: Option<&AuditSigner>,
    anchor: Option<&StorageClient>,
) {
    for i in 0..3 {
        insert_ingest_row(db, &make_event(org, i)).await;
    }
    chainer::run_once(db, signer, 100, anchor)
        .await
        .expect("chainer run_once (v1)");
    for i in 3..5 {
        write_v2(db, make_event(org, i)).await;
    }
    chainer::run_once(db, signer, 100, anchor)
        .await
        .expect("chainer run_once (v2)");
}

#[tokio::test]
async fn retention_days_zero_is_a_no_op_without_querying() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let deleted = chainer::prune_ingest(&db, Some(&store), 0)
        .await
        .expect("prune_ingest");
    assert_eq!(deleted, 0);
}

#[tokio::test]
async fn already_chained_but_recent_rows_are_not_pruned() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let signer = signer();
    let org = Uuid::now_v7();
    chained(&db, org, Some(&signer), Some(&store)).await;
    assert_eq!(
        ingest_count(&db, org).await,
        5,
        "draining a batch does not itself delete the ingest rows"
    );

    // Chained, signed and anchored, but created "now" — well inside any sane
    // retention window.
    chainer::prune_ingest(&db, Some(&store), 30)
        .await
        .expect("prune_ingest");
    assert_eq!(
        ingest_count(&db, org).await,
        5,
        "a chained-but-recent row must survive a 30-day retention prune"
    );
    assert_eq!(watermark_rows(&db, org).await, 0);
}

#[tokio::test]
async fn already_chained_and_aged_past_retention_rows_are_pruned() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let signer = signer();
    let org = Uuid::now_v7();
    chained(&db, org, Some(&signer), Some(&store)).await;
    backdate_ingest_rows(&db, org, 100).await;

    chainer::prune_ingest(&db, Some(&store), 30)
        .await
        .expect("prune_ingest");
    assert_eq!(
        ingest_count(&db, org).await,
        0,
        "signed, anchored, chained rows older than the retention window must be pruned"
    );
    assert_eq!(watermark_rows(&db, org).await, 1);
}

/// Plan Phase 2, "must still verify: a pruned ingest range".
#[tokio::test]
async fn a_pruned_ingest_range_still_verifies() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let signer = signer();
    let org = Uuid::now_v7();
    chained(&db, org, Some(&signer), Some(&store)).await;
    backdate_ingest_rows(&db, org, 100).await;

    let before = verify::verify_chain_with_anchors(&db, Some(&signer), Some(&store), org)
        .await
        .expect("verify before pruning");
    assert!(before.is_ok(), "unpruned chain: {:?}", before.errors);
    assert_eq!(before.ingest_pruned_through, None);

    chainer::prune_ingest(&db, Some(&store), 30)
        .await
        .expect("prune_ingest");
    assert_eq!(ingest_count(&db, org).await, 0);

    let last_ingest_id: Uuid = sqlx::query_scalar(
        "SELECT last_ingest_id FROM audit_chain_batch
         WHERE organization_ref = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("last batch");

    for report in [
        verify::verify_chain_with_anchors(&db, Some(&signer), Some(&store), org)
            .await
            .expect("verify with anchors after pruning"),
        verify::verify_chain(&db, Some(&signer), org)
            .await
            .expect("verify without anchors after pruning"),
    ] {
        assert!(
            report.is_ok(),
            "a pruned ingest range must still verify: {:?}",
            report.errors
        );
        assert_eq!(report.ingest_pruned_through, Some(last_ingest_id));
        assert_eq!(report.ingest_pruned_batches, 2);
        assert_eq!((report.v1_headers, report.v2_headers), (3, 2));
    }

    // A second run finds nothing left to do and records no further watermark.
    chainer::prune_ingest(&db, Some(&store), 30)
        .await
        .expect("prune_ingest (repeat)");
    assert_eq!(watermark_rows(&db, org).await, 1);
}

#[tokio::test]
async fn unanchored_batches_are_not_pruned() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let signer = signer();
    let org = Uuid::now_v7();
    // Signed but never anchored.
    chained(&db, org, Some(&signer), None).await;
    backdate_ingest_rows(&db, org, 100).await;

    chainer::prune_ingest(&db, Some(&store), 30)
        .await
        .expect("prune_ingest");
    assert_eq!(
        ingest_count(&db, org).await,
        5,
        "an ingest range whose batch has no external anchor must never be pruned"
    );
    assert_eq!(watermark_rows(&db, org).await, 0);

    // And without an anchor store nothing is pruned at all.
    let deleted = chainer::prune_ingest(&db, None, 30)
        .await
        .expect("prune_ingest without a store");
    assert_eq!(deleted, 0);
    assert_eq!(ingest_count(&db, org).await, 5);
}

#[tokio::test]
async fn unsigned_batches_are_not_pruned() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let org = Uuid::now_v7();
    // Anchored but never signed: not sealed.
    chained(&db, org, None, Some(&store)).await;
    backdate_ingest_rows(&db, org, 100).await;

    chainer::prune_ingest(&db, Some(&store), 30)
        .await
        .expect("prune_ingest");
    assert_eq!(ingest_count(&db, org).await, 5);
    assert_eq!(watermark_rows(&db, org).await, 0);
}

#[tokio::test]
async fn a_forged_prune_watermark_fails_verification() {
    let db = skip_if_no_db!(test_db().await);
    let signer = signer();
    let org = Uuid::now_v7();
    chained(&db, org, Some(&signer), None).await;

    // A DB-level writer records a watermark no batch ends at, to hide missing
    // ingest rows.
    sqlx::query(
        "INSERT INTO audit_ingest_prune
             (organization_ref, through_batch_id, through_ingest_id, rows_deleted)
         VALUES ($1, $2, $3, 0)",
    )
    .bind(org)
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .execute(&db)
    .await
    .expect("insert forged watermark");

    let report = verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains("pruned watermark") && e.contains("forged or stale")),
        "expected the forged watermark to be reported, got: {:?}",
        report.errors
    );
}

#[tokio::test]
async fn unchained_rows_are_never_pruned_regardless_of_age() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let org = Uuid::now_v7();

    // Insert but deliberately never drain — no batch exists for this org, so
    // there is nothing sealed or anchored to prune under.
    for i in 0..3 {
        insert_ingest_row(&db, &make_event(org, i)).await;
    }
    backdate_ingest_rows(&db, org, 365).await;

    chainer::prune_ingest(&db, Some(&store), 30)
        .await
        .expect("prune_ingest");
    assert_eq!(
        ingest_count(&db, org).await,
        3,
        "an ingest row with no draining batch yet must never be pruned, no matter how old"
    );

    // Cleanup: `chainer::run_once` drains *every* organization with pending
    // rows, not just the caller's — leaving these undrained would silently
    // change the batch count another test's `run_once` call observes later
    // in the same shared database (found by actually running the suite).
    sqlx::query("DELETE FROM audit_ingest WHERE organization_ref = $1")
        .bind(org)
        .execute(&db)
        .await
        .expect("cleanup: delete this test's undrained ingest rows");
}

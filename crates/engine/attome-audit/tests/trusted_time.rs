//! Audit 10/10 plan Phase 2.9 (contract C14, D-539 ruling 5): the canonical
//! v2 event time is the database transaction clock at capture, the anchor
//! object's storage-assigned `Last-Modified` is an upper bound on every event
//! in its batch, and v1 rows are reported as application time.
//!
//! The anchor case needs a live S3-compatible store: `S3_ACCESS_KEY` and
//! `S3_SECRET_KEY` (the repo-root `.env`), optionally `S3_ENDPOINT` and
//! `S3_BUCKET` — the same convention as `anchor.rs` and `epoch_boundary.rs`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-audit --test trusted_time -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
    AuditUserContext, chainer, verify,
};
use attome_config::AppConfig;
use attome_db::DbPool;
use attome_storage::{StorageClient, create_storage_client};
use attome_testkit::skip_if_no_db;
use chrono::{DateTime, Duration, Utc};
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

fn event_at(org: Uuid, changed_on: DateTime<Utc>) -> AuditEvent {
    AuditEvent {
        organization_ref: org,
        category: AuditCategory::BusinessEvent,
        entity_name: Some("trusted_time_entity".into()),
        record_id: Some(Uuid::now_v7()),
        operation: AuditOperation::Submitted,
        version_before: None,
        version_after: None,
        user_context: AuditUserContext {
            user_id: Uuid::now_v7(),
            user_name: "trusted-time-user".into(),
            user_display_name: "Trusted Time User".into(),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on,
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some("trusted-time".into()),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

async fn db_now(db: &DbPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(db)
        .await
        .expect("read the database clock")
}

#[tokio::test]
async fn db_clock_wins_over_skewed_app_clock() {
    let db = skip_if_no_db!(test_db().await);
    let skewed = Utc::now() - Duration::days(3);

    // Chainer path: the stored time is the ingest row's own transaction clock,
    // not the application's, and not the (later) chaining time.
    let org = Uuid::now_v7();
    let before = db_now(&db).await;
    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .write(event_at(org, skewed))
        .await
        .expect("audit write (chainer path)");
    let after = db_now(&db).await;
    let captured_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT created_at FROM audit_ingest WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("read the ingest row");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run");

    let (stored, version): (DateTime<Utc>, i16) = sqlx::query_as(
        "SELECT changed_on, hash_version FROM audit_header WHERE organization_ref = $1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("read the chained header");
    assert_eq!(version, 2);
    assert_eq!(
        stored, captured_at,
        "v2 event time is the capturing transaction's clock, identical to ingest.created_at"
    );
    assert!(
        stored >= before && stored <= after,
        "{before} <= {stored} <= {after}"
    );
    assert_ne!(stored, skewed.trunc_subsecs_micros());

    // Synchronous path: the header insert's own transaction clock.
    let org_sync = Uuid::now_v7();
    let before = db_now(&db).await;
    AuditService::new(&db, None)
        .write(event_at(org_sync, skewed))
        .await
        .expect("audit write (sync path)");
    let after = db_now(&db).await;
    let (stored, created): (DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "SELECT changed_on, created_at FROM audit_header WHERE organization_ref = $1",
    )
    .bind(org_sync)
    .fetch_one(&db)
    .await
    .expect("read the synchronous header");
    assert!(
        stored >= before && stored <= after,
        "{before} <= {stored} <= {after}"
    );
    assert_eq!(
        stored, created,
        "the header's changed_on equals its created_at (both the transaction clock)"
    );

    // Both chains verify with the database time in their digests.
    for o in [org, org_sync] {
        let report = verify::verify_chain(&db, None, o).await.expect("verify");
        assert!(report.is_ok(), "{:?}", report.errors);
        assert_eq!((report.v1_headers, report.v2_headers), (0, 1));
    }
}

trait TruncMicros {
    fn trunc_subsecs_micros(self) -> Self;
}

impl TruncMicros for DateTime<Utc> {
    fn trunc_subsecs_micros(self) -> Self {
        chrono::SubsecRound::trunc_subsecs(self, 6)
    }
}

#[tokio::test]
async fn event_after_anchor_bound_is_reported() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let org = Uuid::now_v7();

    for _ in 0..2 {
        AuditService::new(&db, None)
            .with_chainer_enabled(true)
            .write(event_at(org, Utc::now()))
            .await
            .expect("audit write (chainer path)");
    }
    let batches = chainer::run_once(&db, None, 1000, Some(&store))
        .await
        .expect("chainer run with anchoring");
    let batch = batches
        .iter()
        .find(|b| b.organization_ref == org)
        .expect("a batch for this organization")
        .batch_id;
    assert!(
        attome_audit::anchor::fetch_anchor_bound(&store, org, batch)
            .await
            .expect("HEAD the anchor")
            .is_some(),
        "the chainer anchored the batch"
    );

    let baseline = verify::verify_chain_with_anchors(&db, None, Some(&store), org)
        .await
        .expect("verify with anchors");
    assert!(baseline.is_ok(), "{:?}", baseline.errors);
    assert_eq!(baseline.anchor_time_checked_batches, 1);
    assert!(baseline.anchor_time_unknown_batches.is_empty());

    // Postdate one event past its anchor.
    let header: Uuid = sqlx::query_scalar(
        "SELECT id FROM audit_header WHERE organization_ref = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("read a header");
    sqlx::query(
        "UPDATE audit_header SET changed_on = changed_on + interval '1 hour' WHERE id = $1",
    )
    .bind(header)
    .execute(&db)
    .await
    .expect("postdate the event");

    let report = verify::verify_chain_with_anchors(&db, None, Some(&store), org)
        .await
        .expect("verify with anchors (postdated)");
    assert!(
        report
            .errors
            .iter()
            .any(|e| e.contains(&header.to_string()) && e.contains("later than its batch")),
        "an event time after its anchor bound must be reported: {:?}",
        report.errors
    );

    // Without an anchor store the time bound is not checked at all — and is
    // never claimed as checked.
    let unanchored = verify::verify_chain(&db, None, org).await.expect("verify");
    assert_eq!(unanchored.anchor_time_checked_batches, 0);
    assert!(
        !unanchored
            .errors
            .iter()
            .any(|e| e.contains("later than its batch")),
        "the bound check only runs against the anchor store"
    );
}

#[tokio::test]
async fn an_unanchored_batch_reports_the_time_bound_as_unknown() {
    let db = skip_if_no_db!(test_db().await);
    let store = test_storage_client().await;
    let org = Uuid::now_v7();

    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .write(event_at(org, Utc::now()))
        .await
        .expect("audit write (chainer path)");
    // Chained without anchoring (as if the anchor write had failed).
    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run without anchoring");

    let report = verify::verify_chain_with_anchors(&db, None, Some(&store), org)
        .await
        .expect("verify with anchors");
    assert!(report.is_ok(), "{:?}", report.errors);
    assert_eq!(report.anchor_time_checked_batches, 0);
    assert_eq!(
        report.anchor_time_unknown_batches.len(),
        1,
        "a missing anchor is an unknown time bound, never a pass"
    );
}

#[tokio::test]
async fn v1_rows_are_reported_as_application_time() {
    let db = skip_if_no_db!(test_db().await);
    let org = Uuid::now_v7();
    let app_time = Utc::now() - Duration::days(1);

    // A pre-v2 ingest payload keeps its application clock and hash version 1.
    let payload = serde_json::to_value(event_at(org, app_time)).expect("serialize");
    sqlx::query("INSERT INTO audit_ingest (organization_ref, payload) VALUES ($1, $2)")
        .bind(org)
        .bind(payload)
        .execute(&db)
        .await
        .expect("insert legacy ingest row");
    chainer::run_once(&db, None, 1000, None)
        .await
        .expect("chainer run");

    let (stored, version): (DateTime<Utc>, i16) = sqlx::query_as(
        "SELECT changed_on, hash_version FROM audit_header WHERE organization_ref = $1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("read header");
    assert_eq!(version, 1);
    assert_eq!(stored, app_time.trunc_subsecs_micros());

    let report = verify::verify_chain(&db, None, org).await.expect("verify");
    assert!(report.is_ok(), "{:?}", report.errors);
    assert_eq!(
        (report.v1_headers, report.v2_headers),
        (1, 0),
        "v1 rows are counted separately as application-time rows"
    );
}

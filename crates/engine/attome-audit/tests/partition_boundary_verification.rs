//! P-db-maintenance item (b) — proves `verify_chain` (`attome-audit/src/verify.rs`)
//! is unaffected by `audit_header` being `PARTITION BY RANGE (created_at)`
//! (migrations/0026_audit_partitioning.sql), including a batch whose rows end up
//! spread across more than one partition. Complements `chainer_end_to_end.rs` —
//! same `DATABASE_URL` convention (see that file's header), and assumes migration
//! 0026 has already been applied to the target test database (this test does not
//! run migrations itself, same assumption every other file in this suite makes).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5599/attome_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-audit --test partition_boundary_verification
//! ```
//!
//! `audit_header.created_at` is normally DB-defaulted (never written by the
//! generic insert path — see attome-metadata::provision's comment on why), so getting
//! rows into a *different* partition than "now" means moving them there with a
//! direct UPDATE after the fact, same as `chainer_end_to_end.rs`'s tamper test
//! updates `event_hash` directly. Postgres moves a row to the matching partition
//! automatically when an UPDATE changes its partition-key value (`created_at` is
//! part of the composite PK here) — this test exercises that cross-partition
//! move for real, not just a same-partition happy path.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSigner,
    AuditSource, AuditUserContext,
};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::{Duration, Utc};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(10)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
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
            user_name: format!("partition-test-user-{i}"),
            user_display_name: format!("Partition Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("partition-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

#[tokio::test]
async fn verify_chain_passes_when_rows_span_more_than_one_partition() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("test-key", &"77".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    const N: usize = 10;
    let mut ids = Vec::with_capacity(N);
    for i in 0..N {
        let id = AuditService::new(&db, Some(&signer))
            .write(make_event(org, i))
            .await
            .expect("audit write (sync path)");
        ids.push(id);
    }

    // Move the second half of the chain (in `id`/insertion order — id is
    // uuidv7, time-ordered) two months into the future. Migration 0026 always
    // creates the current month + 2 months ahead, so this partition already
    // exists and the UPDATE below needs no extra setup.
    let moved_createdon = Utc::now() + Duration::days(62);
    for id in &ids[N / 2..] {
        let result = sqlx::query("UPDATE audit_header SET created_at = $1 WHERE id = $2")
            .bind(moved_createdon)
            .bind(id)
            .execute(&db)
            .await
            .expect("move row to a future partition");
        assert_eq!(
            result.rows_affected(),
            1,
            "each row must exist and be movable exactly once"
        );
    }

    // Confirm the moved rows actually landed on a different physical partition
    // than the untouched ones — proving this test exercises real cross-partition
    // movement, not a no-op UPDATE.
    let distinct_partitions: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tableoid) FROM audit_header WHERE organization_ref = $1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("count distinct partitions");
    assert!(
        distinct_partitions >= 2,
        "expected this org's rows to span at least 2 partitions after the move, got {distinct_partitions}"
    );

    // The actual proof: chain verification (ORDER BY id, filtered by
    // organization_ref — see verify.rs's module doc) must still pass cleanly,
    // and must still see every row, regardless of which partition each one now
    // physically lives in.
    let report = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "verification must pass across a partition boundary, got errors: {:?}",
        report.errors
    );
    assert_eq!(report.headers_checked, N);
}

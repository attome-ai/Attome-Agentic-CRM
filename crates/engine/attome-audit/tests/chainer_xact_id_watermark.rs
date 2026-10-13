//! Audit 10/10 plan Phase 1.5: the chainer's in-flight watermark compares
//! 64-bit transaction ids (`audit_ingest.xact_id`, migration 0471) instead
//! of the raw 32-bit `xmin`. The epoch-boundary arithmetic is unit-tested in
//! `chainer.rs`; these tests prove the column is populated by real inserts and
//! that rows written before 0471 (NULL `xact_id`) still drain.
//!
//! The out-of-order commit race itself stays covered by
//! `chainer_race_and_leader_election.rs`, which must keep passing.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-audit --test chainer_xact_id_watermark -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
    AuditUserContext, chainer,
};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
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
            user_name: format!("xact-id-test-user-{i}"),
            user_display_name: format!("Xact Id Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("xact-id-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

#[tokio::test]
async fn an_ingest_write_records_its_64_bit_transaction_id() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");
    let org = Uuid::now_v7();

    AuditService::new(&db, None)
        .with_chainer_enabled(true)
        .write(make_event(org, 0))
        .await
        .expect("audit write (chainer path)");

    let (xact_id, xmin): (Option<String>, String) = sqlx::query_as(
        "SELECT xact_id::text, xmin::text FROM audit_ingest WHERE organization_ref = $1",
    )
    .bind(org)
    .fetch_one(&db)
    .await
    .expect("read the ingest row");

    let xact_id: u64 = xact_id
        .expect("a row inserted after migration 0471 must carry xact_id")
        .parse()
        .expect("xact_id is an unsigned integer");
    let xmin: u64 = xmin.parse().expect("xmin is an unsigned integer");
    assert_eq!(
        xact_id & 0xFFFF_FFFF,
        xmin,
        "xact_id is the epoch-extended form of the row's own xmin"
    );
}

#[tokio::test]
async fn a_legacy_ingest_row_without_xact_id_still_drains() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");
    let org = Uuid::now_v7();

    // Exactly what a row written before migration 0471 looks like.
    let payload = serde_json::to_value(make_event(org, 0)).expect("serialize event");
    sqlx::query(
        "INSERT INTO audit_ingest (organization_ref, payload, xact_id) VALUES ($1, $2, NULL)",
    )
    .bind(org)
    .bind(payload)
    .execute(&db)
    .await
    .expect("insert a legacy ingest row");

    let batches = chainer::run_once(&db, None, 100, None)
        .await
        .expect("chainer run");
    let ours: Vec<_> = batches
        .iter()
        .filter(|b| b.organization_ref == org)
        .collect();
    assert_eq!(ours.len(), 1, "the legacy row must be drained into a batch");
    assert_eq!(ours[0].event_count, 1);

    let headers: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_header WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count headers");
    assert_eq!(headers, 1, "the legacy row must become a chained header");
}

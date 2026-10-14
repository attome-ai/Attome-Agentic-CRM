//! P1.13 §6 leftover gaps, closed against a live Postgres instead of left as
//! "reasoned about, not watched happen" (see `chainer.rs`'s module doc and
//! the plan's progress notes):
//!
//! 1. The actual out-of-order-commit race the xmin-watermark prefix-stop
//!    logic exists to handle — two genuinely concurrent transactions racing
//!    so a higher-`id` ingest row commits before a lower-`id` one.
//! 2. Leader election under real lock contention — a second chainer must
//!    skip (not block or error) when another instance already holds the
//!    per-organization chain lock, and a genuine concurrent race must never
//!    double-process the same events.
//!
//! Same `DATABASE_URL` convention as `concurrency.rs`/`chainer_end_to_end.rs`
//! — a throwaway database, never `attome_dev`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres@localhost:<port>/attomedb_test?options=-c%20search_path%3Dattome_dev"
//! cargo test -p attome-audit --test chainer_race_and_leader_election -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSigner, AuditSource,
    AuditUserContext,
};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use sqlx::{Connection, PgConnection, postgres::PgPoolOptions};
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

/// A connection outside the pool, so its transaction boundaries (`BEGIN`/
/// `COMMIT`/`ROLLBACK`) are under this test's direct control — the pool's
/// `db.begin()` API ties a transaction's lifetime to a Rust borrow, which
/// can't be held open across a separate connection's work the way these
/// tests need.
async fn raw_conn() -> Option<PgConnection> {
    let url = attome_testkit::migrated_db_url()?;
    Some(PgConnection::connect(&url).await.expect("raw connection"))
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
            user_name: format!("race-test-user-{i}"),
            user_display_name: format!("Race Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("race-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

/// Inserts a `audit_ingest` row on a *specific* connection (pool or raw)
/// so callers can control exactly which transaction it lands in — mirrors
/// `AuditService::write_ingest`'s statement exactly.
async fn insert_ingest_row_on<'c, E>(executor: E, event: &AuditEvent) -> Uuid
where
    E: sqlx::Executor<'c, Database = sqlx::Postgres>,
{
    let payload = serde_json::to_value(event).expect("serialize AuditEvent");
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO audit_ingest (organization_ref, payload) VALUES ($1, $2) RETURNING id",
    )
    .bind(event.organization_ref)
    .bind(payload)
    .fetch_one(executor)
    .await
    .expect("insert ingest row")
}

/// Gap 1 — the commit-visibility race `chainer.rs`'s module doc names by
/// hand but had never been reproduced: transaction A inserts an ingest row
/// (getting the lower `id`, since it executes first) and stays open;
/// transaction B then inserts a *later* row (higher `id`) and commits
/// immediately, so B is fully durable and visible while A — the
/// chronologically-and-id-earlier row — is still unresolved.
///
/// A naive `WHERE id > checkpoint ORDER BY id` drain would see only B (A is
/// invisible under MVCC until it commits), drain it, and advance its
/// checkpoint past B's id — permanently losing A once A does commit, since a
/// future `WHERE id > checkpoint` would then exclude it forever. The
/// watermark must instead withhold B too, until A resolves.
#[tokio::test]
async fn chainer_withholds_a_committed_row_while_an_older_transaction_is_still_open() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("test-key", &"77".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    let mut conn_a = skip_if_no_db!(raw_conn().await);
    let mut conn_b = skip_if_no_db!(raw_conn().await);

    sqlx::query("BEGIN")
        .execute(&mut conn_a)
        .await
        .expect("begin A");
    let id_a = insert_ingest_row_on(&mut conn_a, &make_event(org, 0)).await;
    // conn_a deliberately stays open — not committed yet.

    sqlx::query("BEGIN")
        .execute(&mut conn_b)
        .await
        .expect("begin B");
    let id_b = insert_ingest_row_on(&mut conn_b, &make_event(org, 1)).await;
    sqlx::query("COMMIT")
        .execute(&mut conn_b)
        .await
        .expect("commit B");

    assert!(
        id_a < id_b,
        "test setup requires A's row (inserted first) to sort before B's — got A={id_a} B={id_b}"
    );

    // While A is still open, nothing for this org may be drained yet.
    let batches_while_a_open = attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("run_once while A is open");
    assert!(
        batches_while_a_open.is_empty(),
        "the watermark must withhold B while A's older transaction is still unresolved, \
         got: {batches_while_a_open:?}"
    );

    // Only B is visible here (A's own transaction hasn't committed, so under
    // MVCC no other connection — including this count query — can see its
    // row yet); the point of the assertion above is that even the *visible*
    // row (B) was correctly withheld from the batch.
    let visible: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_ingest WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count visible rows");
    assert_eq!(
        visible, 1,
        "only B should be visible to other connections while A is still open"
    );

    sqlx::query("COMMIT")
        .execute(&mut conn_a)
        .await
        .expect("commit A");

    let visible_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_ingest WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count visible rows after A commits");
    assert_eq!(visible_after, 2, "both rows are now durably visible");

    let batches = attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("run_once after A commits");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].event_count, 2);
    assert_eq!(
        batches[0].first_ingest_id, id_a,
        "A must chain before B despite committing second"
    );
    assert_eq!(batches[0].last_ingest_id, id_b);

    let report = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "chain must verify cleanly: {:?}",
        report.errors
    );
    assert_eq!(report.pending_ingest, 0);
}

/// Gap 2a — deterministic leader-election proof: hold the exact lock
/// namespace `run_batch_for_org` acquires ("attome-audit/chain:{org}") open on
/// another connection, simulating a second chainer instance already
/// mid-batch, and confirm this one skips (never blocks, never errors, never
/// double-processes) rather than contending for it.
#[tokio::test]
async fn chainer_skips_a_batch_when_another_leader_already_holds_the_chain_lock() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("test-key", &"88".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    for i in 0..5 {
        insert_ingest_row_on(&db, &make_event(org, i)).await;
    }

    let mut holder = skip_if_no_db!(raw_conn().await);
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("begin holder");
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_audit::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-audit/chain:{org}"))
        .fetch_one(&mut holder)
        .await
        .expect("acquire lock");
    assert!(acquired, "test setup must actually hold the lock");

    let batches = attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("run_once while locked");
    assert!(
        batches.is_empty(),
        "a chainer must skip (not block or error) when another leader holds the lock, got: {batches:?}"
    );

    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_ingest WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count pending");
    assert_eq!(
        pending, 5,
        "nothing should be drained while the lock is held elsewhere"
    );

    sqlx::query("COMMIT")
        .execute(&mut holder)
        .await
        .expect("release holder lock");

    let batches = attome_audit::chainer::run_once(&db, Some(&signer), 100, None)
        .await
        .expect("run_once after release");
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].event_count, 5);
}

/// Gap 2b — a genuine concurrent race between two `run_once` calls sharing
/// the same pool. Not timing-controlled (unlike 2a), so it doesn't prove the
/// two calls truly overlapped inside Postgres, but the assertion holds
/// exactly once either way: no duplicate headers, no lost events, regardless
/// of how the two polls happened to interleave.
#[tokio::test]
async fn two_concurrent_chainer_polls_never_double_process_the_same_batch() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("test-key", &"99".repeat(32)).expect("signer");
    let org = Uuid::now_v7();

    const N: usize = 20;
    for i in 0..N {
        insert_ingest_row_on(&db, &make_event(org, i)).await;
    }

    let (r1, r2) = tokio::join!(
        attome_audit::chainer::run_once(&db, Some(&signer), 100, None),
        attome_audit::chainer::run_once(&db, Some(&signer), 100, None),
    );
    r1.expect("run_once #1");
    r2.expect("run_once #2");

    let header_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_header WHERE organization_ref = $1")
            .bind(org)
            .fetch_one(&db)
            .await
            .expect("count headers");
    assert_eq!(
        header_count, N as i64,
        "two racing polls must land exactly N header rows total — not fewer (lost) or more (duplicated)"
    );

    let report = attome_audit::verify::verify_chain(&db, Some(&signer), org)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "chain must verify cleanly: {:?}",
        report.errors
    );
    assert_eq!(report.pending_ingest, 0);
}

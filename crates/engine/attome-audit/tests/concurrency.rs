//! Integration test for P1.8 money-path #3 — audit chain integrity under
//! concurrency. ~50 concurrent appends to the same organization's hash chain,
//! then walk `audit_header` (ordered by `id`) and assert every row's
//! `prev_hash` equals the previous row's `event_hash`.
//!
//! **Two tests, one invariant, two paths (D-316), plus one T2-14 regression
//! test.** The chain must never fork whichever path wrote it, so both paths
//! are exercised here:
//!
//! - `audit_chain_has_no_fork_under_concurrent_appends` — the pre-P1.13
//!   synchronous path, now supported only for single-writer development. It
//!   takes a per-organization advisory lock inside each writer's own
//!   transaction with a single non-blocking `pg_try_advisory_xact_lock`
//!   attempt (T2-14: no retry loop — a retry would sleep with that
//!   transaction, and its pooled connection, held open) and sheds a losing
//!   writer immediately with `Conflict`; the 2026-08-10 engineering review's
//!   F-001 is exactly that shedding behavior, and this test now records it
//!   rather than failing on it (see the comment at the join loop).
//! - `no_conflicts_and_no_fork_on_the_chainer_path` — the cutover path, which
//!   `audit.chainer_enabled` selects and which D-316 made the default and a
//!   production requirement. No lock, so no shed writes: this one asserts all
//!   50 land, drain, and verify.
//!
//! A third test, `losing_writer_gets_immediate_conflict_not_a_retry_sleep`,
//! targets T2-14 (TECHNICAL-DUE-DILIGENCE-2026-08-24 finding 3.5) directly:
//! it deterministically holds the sync path's advisory lock open on one
//! connection and proves a second writer racing for the same organization's
//! lock loses immediately (`Conflict`, well under the old worst case of
//! `LOCK_MAX_ATTEMPTS` x `LOCK_RETRY_DELAY_MS` = 1s of sleeping inside an
//! open transaction), rather than retrying.
//!
//! **Un-ignored by Plan 1.5a+d.** `AuditService::write` now wraps
//! `fetch_last_hash` + the header insert + detail inserts in one transaction
//! guarded by `pg_try_advisory_xact_lock("attome-audit/append:{organization_ref}")`
//! (see `attome-audit/src/service.rs`), so concurrent writers to the same
//! organization's chain serialize instead of forking. This was previously
//! `#[ignore]`d as an expected-fail test — removing the ignore was P1.5a's
//! acceptance test ("the test that proves the moat", P1.8 plan money-path #3).
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when it is
//! unset, except under `CI` (see `attome_testkit`). Run manually against a
//! throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-audit --test concurrency -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSigner,
    AuditSource, AuditUserContext,
};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const CONCURRENT_WRITERS: usize = 50;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            // More than CONCURRENT_WRITERS so every concurrent append gets its
            // own connection — the point is to race Postgres, not the pool.
            .max_connections((CONCURRENT_WRITERS as u32) + 5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn make_event(organization_ref: Uuid, i: usize) -> AuditEvent {
    AuditEvent {
        organization_ref,
        category: AuditCategory::BusinessEvent,
        entity_name: None,
        record_id: None,
        operation: AuditOperation::Submitted,
        version_before: None,
        version_after: None,
        user_context: AuditUserContext {
            user_id: Uuid::now_v7(),
            user_name: format!("concurrency-test-user-{i}"),
            user_display_name: format!("Concurrency Test User {i}"),
            user_email: String::new(),
            user_job_ref: None,
            user_job_name: None,
        },
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(format!("concurrency-test-{i}")),
        event_comment: None,
        changed_fields: vec![],
        snapshot_json: None,
    }
}

#[tokio::test]
async fn audit_chain_has_no_fork_under_concurrent_appends() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let organization_ref = Uuid::now_v7();

    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..CONCURRENT_WRITERS {
        let db = db.clone();
        tasks.spawn(async move {
            AuditService::new(&db, None)
                .write(make_event(organization_ref, i))
                .await
        });
    }

    // Counted, not `.expect()`ed — and this is a deliberate change of what
    // this test claims, not a relaxation to make it pass. A single
    // non-blocking `pg_try_advisory_xact_lock` attempt (T2-14 — no retry
    // loop; see `AuditService::acquire_chain_lock`'s doc) is the sync path's
    // *documented* contract: lose the race once and the write is shed with
    // `Conflict` immediately, no waiting. Asserting all 50 writers succeed
    // therefore asserted a throughput property this path never promised —
    // and the 2026-08-10 engineering review's F-001 is precisely that the
    // promise is missing: reproduced here as `Conflict("audit chain append
    // lock is held by a concurrent writer for this organization")` for every
    // writer that loses the race (this test still passes standalone against
    // an idle instance and typically accepts only one or a few of the 50,
    // since — unlike the old retry loop — a loser gets no second attempt).
    //
    // What this test guards is the P1.5a **fork** invariant, and that is
    // asserted below over exactly the writes that were accepted. The
    // "every writer succeeds" half now lives where it can actually hold —
    // `no_conflicts_and_no_fork_on_the_chainer_path` below, which is the
    // acceptance test P1.13 §6 specified ("zero Conflict from audit on the
    // chainer path") and D-316 made the default.
    let mut accepted = 0usize;
    let mut conflicts = 0usize;
    while let Some(joined) = tasks.join_next().await {
        match joined.expect("audit write task panicked") {
            Ok(_) => accepted += 1,
            Err(e) => {
                conflicts += 1;
                eprintln!("sync-path audit write shed under contention (F-001): {e}");
            }
        }
    }
    assert!(
        accepted > 0,
        "the sync path must accept at least some concurrent writes, got {conflicts} conflicts \
         out of {CONCURRENT_WRITERS}"
    );

    // Ordered by `id` (uuidv7, monotonic at actual insert time), not
    // `created_at` (SQL `NOW()`, frozen at transaction start — see the P1.8
    // finding documented in `attome-audit/src/service.rs::fetch_last_hash`).
    // Ordering this verification query by the same wrong column the service
    // used to use would make the assertion unsound: it could report a fork
    // that is only an artifact of `created_at` not tracking commit order.
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT COALESCE(prev_hash, ''), COALESCE(event_hash, '')
           FROM audit_header
           WHERE organization_ref = $1
           ORDER BY id ASC"#,
    )
    .bind(organization_ref)
    .fetch_all(&db)
    .await
    .expect("query audit_header");

    assert_eq!(
        rows.len(),
        accepted,
        "every write the sync path ACCEPTED must have landed exactly one row — a shed write \
         (Conflict) rolls its whole transaction back and must leave nothing behind, and an \
         accepted one must never be lost"
    );

    for i in 1..rows.len() {
        let (prev_hash_of_this_row, _) = &rows[i];
        let (_, event_hash_of_previous_row) = &rows[i - 1];
        assert_eq!(
            prev_hash_of_this_row, event_hash_of_previous_row,
            "chain link broken at position {i}: row's prev_hash must equal the prior row's event_hash \
             — a mismatch here means two writers read the same prev_hash and forked the chain"
        );
    }
}

/// D-316 / P1.13 §6's own acceptance criterion, which had never been written:
/// "N concurrent writers — zero `Conflict` from audit on the chainer path;
/// resulting chain verifies with no forks, no gaps, no orphans."
///
/// This is the test that actually carries TODO-006's claim. The sibling test
/// above cannot: it drives `AuditService` directly, so no config flag reaches
/// it, and it exercises the very lock the chainer path exists to remove.
///
/// Same 50 writers, same organization, same chain — the only difference is
/// `with_chainer_enabled(true)`, so a failure here is unambiguously about the
/// cutover path rather than about test scaffolding.
#[tokio::test]
async fn no_conflicts_and_no_fork_on_the_chainer_path() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let signer = AuditSigner::from_config("concurrency-test-key", &"44".repeat(32))
        .expect("build test signer");
    let organization_ref = Uuid::now_v7();

    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..CONCURRENT_WRITERS {
        let db = db.clone();
        tasks.spawn(async move {
            AuditService::new(&db, None)
                .with_chainer_enabled(true)
                .write(make_event(organization_ref, i))
                .await
        });
    }

    let mut errors = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Err(e) = joined.expect("audit write task panicked") {
            errors.push(e.to_string());
        }
    }
    assert!(
        errors.is_empty(),
        "the chainer path must never shed a concurrent write — it takes no chain lock at all. \
         Got {} failure(s): {errors:?}",
        errors.len()
    );

    // Drain the way the `audit_chainer` process does. Looped, not a single
    // call: `chainer::run_once` stops at the xmin safe-harbor watermark, so
    // rows whose transactions committed while an older one was still open are
    // deliberately withheld until a later poll (see chainer.rs's module doc,
    // and chainer_race_and_leader_election.rs, which tests that behavior
    // directly). A bounded budget rather than an unbounded loop so a genuine
    // stall fails the test instead of hanging it.
    const MAX_DRAIN_POLLS: usize = 40;
    let mut pending = i64::MAX;
    for _ in 0..MAX_DRAIN_POLLS {
        attome_audit::chainer::run_once(&db, Some(&signer), 500, None)
            .await
            .expect("chainer run_once");
        pending = attome_audit::verify::lag(&db, organization_ref)
            .await
            .expect("chain lag")
            .0;
        if pending == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        pending, 0,
        "the chainer must drain every ingest row within {MAX_DRAIN_POLLS} polls"
    );

    // No gaps, no orphans, no forged/mismatched batch signature — verify_chain
    // recomputes every event_hash and every batch Merkle root for this org.
    let report = attome_audit::verify::verify_chain(&db, Some(&signer), organization_ref)
        .await
        .expect("verify_chain");
    assert!(
        report.is_ok(),
        "the chain the chainer produced must verify, got errors: {:?}",
        report.errors
    );
    assert_eq!(
        report.headers_checked, CONCURRENT_WRITERS,
        "every concurrent write must appear exactly once in the chained history"
    );
    assert_eq!(report.pending_ingest, 0);

    // And the same fork assertion the sync-path test makes, over the rows the
    // chainer wrote — the invariant is a property of the chain, not of which
    // path produced it.
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"SELECT COALESCE(prev_hash, ''), COALESCE(event_hash, '')
           FROM audit_header
           WHERE organization_ref = $1
           ORDER BY id ASC"#,
    )
    .bind(organization_ref)
    .fetch_all(&db)
    .await
    .expect("query audit_header");

    assert_eq!(rows.len(), CONCURRENT_WRITERS);
    for i in 1..rows.len() {
        let (prev_hash_of_this_row, _) = &rows[i];
        let (_, event_hash_of_previous_row) = &rows[i - 1];
        assert_eq!(
            prev_hash_of_this_row, event_hash_of_previous_row,
            "chain link broken at position {i} on the chainer path"
        );
    }
}

/// T2-14 regression test (TECHNICAL-DUE-DILIGENCE-2026-08-24 finding 3.5):
/// the sync path's advisory-lock acquisition is now exactly one non-blocking
/// `pg_try_advisory_xact_lock` attempt — no sleep-retry loop that would hold
/// the caller's transaction (and its pooled connection) open while it spins.
///
/// The two `CONCURRENT_WRITERS`-scale tests above prove the invariant that
/// matters (no fork) but, being genuinely racy, can't pin down *how fast* a
/// losing writer fails. This test makes the race deterministic instead: it
/// takes the exact lock `AuditService` takes — same namespace, same key
/// format — on a connection it holds open itself, so a second writer via
/// `AuditService::write` is guaranteed to lose. That writer must come back
/// with `Conflict` almost immediately, not after spinning for up to
/// `LOCK_MAX_ATTEMPTS` x `LOCK_RETRY_DELAY_MS` (the old sync path's worst
/// case, 200 x 5ms = 1s). Releasing the held lock afterward then proves nothing
/// else broke: a normal write against the same organization still succeeds.
#[tokio::test]
async fn losing_writer_gets_immediate_conflict_not_a_retry_sleep() {
    let db = skip_if_no_db!(test_db().await);
    attome_audit::seed(&db)
        .await
        .expect("seed audit entities (idempotent)");

    let organization_ref = Uuid::now_v7();

    // Hold the exact same lock `acquire_chain_lock` takes, on our own
    // connection, in an open (uncommitted) transaction — simulating a
    // concurrent in-flight append that has the lock and hasn't released it
    // yet.
    let mut lock_holder = db.begin().await.expect("begin lock-holder tx");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_audit::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-audit/append:{organization_ref}"))
        .fetch_one(&mut *lock_holder)
        .await
        .expect("acquire the lock for the test's own holder");
    assert!(
        locked,
        "test setup: the holder must win the lock uncontested"
    );

    // Race a real `AuditService::write` against that held lock. It must lose
    // (the holder above still has it) and come back fast.
    let start = std::time::Instant::now();
    let result = AuditService::new(&db, None)
        .write(make_event(organization_ref, 1))
        .await;
    let elapsed = start.elapsed();

    match result {
        Err(attome_types::AppError::Conflict(msg)) => {
            assert!(
                msg.contains("held by a concurrent writer"),
                "unexpected Conflict message: {msg}"
            );
        }
        other => panic!("expected AppError::Conflict from the losing writer, got {other:?}"),
    }
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "a losing writer must fail on its first attempt (no retry-sleep loop) — took {elapsed:?}, \
         which is in the range the old LOCK_MAX_ATTEMPTS x LOCK_RETRY_DELAY_MS retry loop could \
         have produced (up to ~1s)"
    );

    // Release the held lock and confirm a subsequent write succeeds normally
    // — the fix didn't just make losing writers fail, it left the winning
    // path intact.
    lock_holder
        .rollback()
        .await
        .expect("release the held lock (rollback, wrote nothing)");

    let after_release = AuditService::new(&db, None)
        .write(make_event(organization_ref, 2))
        .await;
    assert!(
        after_release.is_ok(),
        "after the lock is released, a normal write must succeed: {after_release:?}"
    );
}

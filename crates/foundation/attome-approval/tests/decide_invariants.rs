//! Proves the two invariants `lib.rs`'s own module doc claims for `decide()`
//! (guidelines §2, D-195/`P-four-eyes-approval.md` §6's test matrix) but that,
//! until this file, no test anywhere actually exercised for `attome-approval`
//! itself — only downstream integration suites for two of the eight wired
//! action classes (`xrm-server/tests/approval_role_grant.rs`,
//! `xrm-server/tests/approval_retention.rs`, per D-199) touch `decide()`, and
//! neither races it or drives it through a stale-`row_version` retry.
//!
//! 1. `approver_id != requested_by` — separation-of-duties
//!    (`self_approval_is_rejected_for_both_decisions`).
//! 2. The `pg_try_advisory_xact_lock` + `row_version` CAS around every state
//!    transition, so two concurrent decisions on the same request can never
//!    both "win" (`concurrent_decide_calls_on_same_request_never_both_win`),
//!    and a caller racing in with a `row_version` it read before another
//!    decision already landed gets a clean `VersionConflict` instead of a
//!    lost update (`decide_rejects_a_stale_row_version_even_while_still_pending`).
//!
//! `approval_request`/`approval_grant` (migration
//! `0070_core_approval_request.sql`) take raw `UUID` for `requested_by`/
//! `approver_id` with no FK to a users table, so these tests need no fixture
//! rows beyond what `submit()` itself creates.
//!
//! **Live-verified against a real Postgres (2026-08-03):** all 4 tests pass,
//! including the concurrent-decide race and the stale-`row_version` CAS
//! rejection.
//!
//! Skips (loudly) when `DATABASE_URL` is unset, except under `CI` where a
//! skip means the service wiring broke — see `attome_testkit` (F-008/TODO-008).
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-approval --test decide_invariants -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_approval::{ApprovalStatus, Decision, cancel, decide, get, submit};
use attome_testkit::migrated_pool_or_skip;
use attome_types::AppError;
use chrono::Duration;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn grant_count(pool: &PgPool, request_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM approval_grant WHERE request_id = $1")
        .bind(request_id)
        .fetch_one(pool)
        .await
        .expect("count approval_grant rows")
}

/// `decide()`'s core correctness test, per this crate's own module doc and
/// `P-four-eyes-approval.md` §6's framing: the requester can never approve —
/// or reject — their own request. Checked before the `row_version` CAS in
/// `decide()`, so it must fail as `Forbidden` regardless of whether the
/// caller also passed a correct `expected_row_version`.
#[tokio::test]
async fn self_approval_is_rejected_for_both_decisions() {
    // 10 connections: `concurrent_decide_calls_…` races two decisions at once.
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();

    for decision in [Decision::Approve, Decision::Reject] {
        let request = submit(
            &pool,
            "test.self_approval",
            json!({"decision": format!("{decision:?}")}),
            requested_by,
            1,
            Duration::hours(1),
        )
        .await
        .expect("submit");

        let result = decide(
            &pool,
            request.id,
            requested_by,
            decision,
            request.row_version,
        )
        .await;
        assert!(
            matches!(result, Err(AppError::Forbidden)),
            "requester deciding ({decision:?}) their own request must be Forbidden, got {result:?}"
        );

        // The request must be left exactly as submitted — no grant row, no
        // row_version bump, still pending — a rejected self-decide is not
        // merely reported as an error, it must have no side effect at all.
        let after = get(&pool, request.id).await.expect("get");
        assert_eq!(after.status, ApprovalStatus::Pending);
        assert_eq!(after.row_version, request.row_version);
        assert_eq!(
            grant_count(&pool, request.id).await,
            0,
            "a Forbidden self-decide must never insert a approval_grant row"
        );
    }
}

/// The same separation-of-duties check applies to `cancel()`'s inverse rule
/// (only the requester may withdraw): a different admin cannot cancel
/// someone else's request, and confirms `cancel()` doesn't accidentally
/// share `decide()`'s "not the requester" gate instead of its own "must BE
/// the requester" one.
#[tokio::test]
async fn cancel_by_a_non_requester_is_forbidden() {
    // 10 connections: `concurrent_decide_calls_…` races two decisions at once.
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let someone_else = Uuid::now_v7();

    let request = submit(
        &pool,
        "test.cancel_forbidden",
        json!({}),
        requested_by,
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");

    let result = cancel(&pool, request.id, someone_else, request.row_version).await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "a non-requester cancelling someone else's request must be Forbidden, got {result:?}"
    );

    let after = get(&pool, request.id).await.expect("get");
    assert_eq!(after.status, ApprovalStatus::Pending);
    assert_eq!(after.row_version, request.row_version);
}

/// The advisory-lock invariant, proven by actually racing it rather than
/// reading the code: two different, valid (non-requester) approvers calling
/// `decide()` on the same `required_approvals = 1` request at the same
/// instant must never both land — exactly one must close the request, the
/// other must observe a clean `Conflict` (either "another decision ...
/// already in progress" from losing the `pg_try_advisory_xact_lock` race, or
/// "already been decided" if it acquires the lock only after the winner
/// committed), and the grant table must end up with exactly one row, never
/// two and never zero.
#[tokio::test]
async fn concurrent_decide_calls_on_same_request_never_both_win() {
    // 10 connections: `concurrent_decide_calls_…` races two decisions at once.
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let approver_a = Uuid::now_v7();
    let approver_b = Uuid::now_v7();

    let request = submit(
        &pool,
        "test.concurrent_decide",
        json!({}),
        requested_by,
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");

    let (result_a, result_b) = tokio::join!(
        decide(
            &pool,
            request.id,
            approver_a,
            Decision::Approve,
            request.row_version,
        ),
        decide(
            &pool,
            request.id,
            approver_b,
            Decision::Approve,
            request.row_version,
        ),
    );

    let outcomes = [&result_a, &result_b];
    let successes = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes, 1,
        "exactly one of two concurrent decide() calls on the same request must win, \
         got a={result_a:?} b={result_b:?}"
    );
    let loser = outcomes
        .iter()
        .find(|r| r.is_err())
        .expect("the other concurrent call must have lost the race");
    assert!(
        matches!(loser, Err(AppError::Conflict(_))),
        "the losing concurrent decide() call must surface as Conflict, got {loser:?}"
    );

    let final_state = get(&pool, request.id).await.expect("get");
    assert_eq!(
        final_state.status,
        ApprovalStatus::Approved,
        "the winning decide() call must have closed the request"
    );
    assert_eq!(
        final_state.row_version,
        request.row_version + 1,
        "row_version must have advanced exactly once despite two concurrent attempts \
         — a second, unguarded bump would mean the loser also wrote"
    );
    assert_eq!(
        grant_count(&pool, request.id).await,
        1,
        "exactly one approval_grant row must exist — the loser must never have \
         inserted a duplicate grant alongside the winner"
    );
}

/// The `row_version` CAS half of the same invariant, isolated from the
/// advisory-lock/status-check paths above: with `required_approvals = 2` the
/// request stays `Pending` after the first Approve (unlike the
/// `required_approvals = 1` case above, where a second call would instead
/// be bounced by the "already decided" status check before ever reaching the
/// CAS). A second approver racing in with the `row_version` it read *before*
/// the first approval landed must be rejected as `VersionConflict` — not
/// silently applied as a lost update — and only succeed once retried with
/// the now-current `row_version`.
#[tokio::test]
async fn decide_rejects_a_stale_row_version_even_while_still_pending() {
    // 10 connections: `concurrent_decide_calls_…` races two decisions at once.
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let approver_a = Uuid::now_v7();
    let approver_b = Uuid::now_v7();

    let request = submit(
        &pool,
        "test.stale_row_version",
        json!({}),
        requested_by,
        2,
        Duration::hours(1),
    )
    .await
    .expect("submit");
    let stale_version = request.row_version;

    decide(
        &pool,
        request.id,
        approver_a,
        Decision::Approve,
        stale_version,
    )
    .await
    .expect("first approval must succeed and bump row_version");

    let result = decide(
        &pool,
        request.id,
        approver_b,
        Decision::Approve,
        stale_version,
    )
    .await;
    assert!(
        matches!(result, Err(AppError::VersionConflict)),
        "a decide() call racing in with a row_version read before another decision landed \
         must be rejected as VersionConflict, got {result:?}"
    );

    let after = get(&pool, request.id).await.expect("get");
    assert_eq!(
        after.status,
        ApprovalStatus::Pending,
        "still pending — only one of the two required approvals has been recorded"
    );
    assert_eq!(
        after.row_version,
        stale_version + 1,
        "only the winning decide() call may have bumped row_version"
    );
    assert_eq!(
        grant_count(&pool, request.id).await,
        1,
        "the VersionConflict call must never have inserted a grant row"
    );

    let final_state = decide(
        &pool,
        request.id,
        approver_b,
        Decision::Approve,
        after.row_version,
    )
    .await
    .expect("retrying with the current row_version must succeed");
    assert_eq!(
        final_state.status,
        ApprovalStatus::Approved,
        "the second, distinct approver's retry must close the request"
    );
    assert_eq!(grant_count(&pool, request.id).await, 2);
}

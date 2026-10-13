//! D-518 — proves `attome_approval`'s claim-before-execute primitives directly,
//! with no HTTP router, session or RBAC in the way:
//!
//! 1. Of any number of concurrent `claim_execution` calls on one approved
//!    request, exactly one wins, and the losers see the claim
//!    (`concurrent_claims_on_one_request_never_both_win`).
//! 2. Only an approved, unexecuted request can be claimed
//!    (`only_an_approved_unexecuted_request_can_be_claimed`).
//! 3. A released claim returns the request to `approved`
//!    (`a_released_claim_returns_the_request_to_approved`).
//! 4. A claimed request closes only through its own claim
//!    (`a_claimed_request_closes_only_through_its_claim`).
//! 5. A stale claim is taken over only after the lease, and the takeover
//!    fences the earlier holder out
//!    (`a_stale_claim_is_taken_over_only_after_the_lease_and_fences_the_old_holder`).
//! 6. Callers that never claim keep `mark_executed` as before
//!    (`an_unclaimed_caller_still_marks_an_approved_request_executed`).
//!
//! Needs migrations 0468/0469 in the template `DATABASE_URL` names. Skips
//! (loudly) when `DATABASE_URL` is unset, except under `CI` — see
//! `attome_testkit`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-approval --test execution_claim -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_approval::{
    ApprovalRequest, ApprovalStatus, Decision, EXECUTION_CLAIM_LEASE_MINUTES, claim_execution,
    complete_execution, decide, execution_claim, get, invalidate_execution, mark_executed,
    release_execution, submit, take_over_stale_execution,
};
use attome_testkit::migrated_pool_or_skip;
use attome_types::AppError;
use chrono::Duration;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn approved(pool: &PgPool) -> ApprovalRequest {
    let request = submit(
        pool,
        "test.execution_claim",
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");
    let approved = decide(
        pool,
        request.id,
        Uuid::now_v7(),
        Decision::Approve,
        request.row_version,
    )
    .await
    .expect("decide");
    assert_eq!(approved.status, ApprovalStatus::Approved);
    approved
}

async fn backdate_claim(pool: &PgPool, request_id: Uuid, minutes: i32) {
    sqlx::query(
        "UPDATE approval_request \
            SET execution_claimed_at = NOW() - make_interval(mins => $2) \
          WHERE id = $1",
    )
    .bind(request_id)
    .bind(minutes)
    .execute(pool)
    .await
    .expect("backdate the claim");
}

async fn claim_columns(pool: &PgPool, request_id: Uuid) -> (Option<Uuid>, bool) {
    let (claimed_by, has_claimed_at): (Option<Uuid>, bool) = sqlx::query_as(
        "SELECT execution_claimed_by, execution_claimed_at IS NOT NULL \
           FROM approval_request WHERE id = $1",
    )
    .bind(request_id)
    .fetch_one(pool)
    .await
    .expect("read claim columns");
    (claimed_by, has_claimed_at)
}

/// The invariant D-518 exists for. Repeated so both loser paths get a chance
/// to occur: blocked on the winner's row lock, or arriving after it committed.
#[tokio::test]
async fn concurrent_claims_on_one_request_never_both_win() {
    let pool: PgPool = migrated_pool_or_skip!(10);

    for _ in 0..10 {
        let request = approved(&pool).await;
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let (left, right) = tokio::join!(
            claim_execution(&pool, request.id, request.row_version, a),
            claim_execution(&pool, request.id, request.row_version, b),
        );

        assert_eq!(
            usize::from(left.is_ok()) + usize::from(right.is_ok()),
            1,
            "exactly one claim wins: {:?} / {:?}",
            left.as_ref().err(),
            right.as_ref().err()
        );
        let (winner, loser) = if left.is_ok() {
            (a, right.as_ref().err())
        } else {
            (b, left.as_ref().err())
        };
        assert!(
            matches!(loser, Some(AppError::Conflict(_))),
            "the loser must see the claim: {loser:?}"
        );

        let claim = execution_claim(&pool, request.id)
            .await
            .expect("read claim")
            .expect("the request is executing");
        assert_eq!(claim.claimed_by, winner);
        assert!(!claim.stale);
        assert_eq!(
            get(&pool, request.id).await.expect("get").status,
            ApprovalStatus::Executing
        );
    }
}

#[tokio::test]
async fn only_an_approved_unexecuted_request_can_be_claimed() {
    let pool: PgPool = migrated_pool_or_skip!(4);

    let pending = submit(
        &pool,
        "test.execution_claim",
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");
    assert!(matches!(
        claim_execution(&pool, pending.id, pending.row_version, Uuid::now_v7()).await,
        Err(AppError::Conflict(_))
    ));

    let request = approved(&pool).await;
    assert!(matches!(
        claim_execution(&pool, request.id, request.row_version - 1, Uuid::now_v7()).await,
        Err(AppError::VersionConflict)
    ));

    let claimed = claim_execution(&pool, request.id, request.row_version, Uuid::now_v7())
        .await
        .expect("claim");
    let executed = complete_execution(&pool, claimed.id, claimed.row_version)
        .await
        .expect("complete");
    assert!(matches!(
        claim_execution(&pool, executed.id, executed.row_version, Uuid::now_v7()).await,
        Err(AppError::Conflict(_))
    ));
    assert!(
        execution_claim(&pool, executed.id)
            .await
            .expect("read")
            .is_none()
    );
}

#[tokio::test]
async fn a_released_claim_returns_the_request_to_approved() {
    let pool: PgPool = migrated_pool_or_skip!(4);
    let request = approved(&pool).await;

    let claimed = claim_execution(&pool, request.id, request.row_version, Uuid::now_v7())
        .await
        .expect("claim");
    let released = release_execution(&pool, claimed.id, claimed.row_version)
        .await
        .expect("release");
    assert_eq!(released.status, ApprovalStatus::Approved);
    assert!(released.executed_at.is_none());
    assert_eq!(claim_columns(&pool, request.id).await, (None, false));
    assert!(
        execution_claim(&pool, request.id)
            .await
            .expect("read")
            .is_none()
    );

    let again = Uuid::now_v7();
    let reclaimed = claim_execution(&pool, released.id, released.row_version, again)
        .await
        .expect("a released request can be claimed again");
    assert_eq!(reclaimed.status, ApprovalStatus::Executing);
    assert!(
        matches!(
            release_execution(&pool, claimed.id, claimed.row_version).await,
            Err(AppError::VersionConflict)
        ),
        "the earlier claim's row_version no longer releases anything"
    );
    assert_eq!(claim_columns(&pool, request.id).await, (Some(again), true));
}

#[tokio::test]
async fn a_claimed_request_closes_only_through_its_claim() {
    let pool: PgPool = migrated_pool_or_skip!(4);

    let request = approved(&pool).await;
    assert!(
        matches!(
            complete_execution(&pool, request.id, request.row_version).await,
            Err(AppError::VersionConflict)
        ),
        "an unclaimed request cannot be completed through the claim path"
    );
    let claimant = Uuid::now_v7();
    let claimed = claim_execution(&pool, request.id, request.row_version, claimant)
        .await
        .expect("claim");
    assert!(
        matches!(
            mark_executed(&pool, claimed.id, claimed.row_version).await,
            Err(AppError::VersionConflict)
        ),
        "the unclaimed close-out refuses a claimed request"
    );
    let executed = complete_execution(&pool, claimed.id, claimed.row_version)
        .await
        .expect("complete");
    assert_eq!(executed.status, ApprovalStatus::Executed);
    assert!(executed.executed_at.is_some());
    assert_eq!(
        claim_columns(&pool, request.id).await,
        (Some(claimant), true),
        "the claim stays as the record of who ran it"
    );
    assert!(matches!(
        complete_execution(&pool, claimed.id, claimed.row_version).await,
        Err(AppError::VersionConflict)
    ));

    let refused = approved(&pool).await;
    let claimed = claim_execution(&pool, refused.id, refused.row_version, Uuid::now_v7())
        .await
        .expect("claim");
    let invalidated = invalidate_execution(&pool, claimed.id, claimed.row_version)
        .await
        .expect("invalidate");
    assert_eq!(invalidated.status, ApprovalStatus::Invalidated);
    assert!(invalidated.executed_at.is_none());
    assert!(matches!(
        claim_execution(
            &pool,
            invalidated.id,
            invalidated.row_version,
            Uuid::now_v7()
        )
        .await,
        Err(AppError::Conflict(_))
    ));
}

#[tokio::test]
async fn a_stale_claim_is_taken_over_only_after_the_lease_and_fences_the_old_holder() {
    let pool: PgPool = migrated_pool_or_skip!(4);
    let request = approved(&pool).await;
    let (first, second) = (Uuid::now_v7(), Uuid::now_v7());

    let held = claim_execution(&pool, request.id, request.row_version, first)
        .await
        .expect("claim");
    assert!(
        matches!(
            take_over_stale_execution(&pool, held.id, held.row_version, second).await,
            Err(AppError::Conflict(_))
        ),
        "a claim inside its lease is never taken over"
    );

    backdate_claim(&pool, request.id, EXECUTION_CLAIM_LEASE_MINUTES + 1).await;
    let claim = execution_claim(&pool, request.id)
        .await
        .expect("read")
        .expect("executing");
    assert!(claim.stale);
    assert_eq!(claim.claimed_by, first);

    let taken = take_over_stale_execution(&pool, held.id, held.row_version, second)
        .await
        .expect("take over a stale claim");
    assert_eq!(taken.status, ApprovalStatus::Executing);
    assert!(taken.row_version > held.row_version);
    let claim = execution_claim(&pool, request.id)
        .await
        .expect("read")
        .expect("executing");
    assert_eq!(claim.claimed_by, second);
    assert!(!claim.stale, "the takeover restarts the lease");

    for (label, outcome) in [
        (
            "complete",
            complete_execution(&pool, held.id, held.row_version).await,
        ),
        (
            "invalidate",
            invalidate_execution(&pool, held.id, held.row_version).await,
        ),
        (
            "release",
            release_execution(&pool, held.id, held.row_version).await,
        ),
    ] {
        assert!(
            matches!(outcome, Err(AppError::VersionConflict)),
            "the earlier holder can no longer {label} the claim"
        );
    }
    assert!(
        matches!(
            take_over_stale_execution(&pool, held.id, held.row_version, first).await,
            Err(AppError::Conflict(_) | AppError::VersionConflict)
        ),
        "a second takeover with the old row_version is refused"
    );

    let executed = complete_execution(&pool, taken.id, taken.row_version)
        .await
        .expect("the new holder completes");
    assert_eq!(executed.status, ApprovalStatus::Executed);
}

/// `trd-engine` and `xrm-ai`'s policy auto-approval execute without claiming
/// (out of D-518's scope); their close-out must keep working unchanged.
#[tokio::test]
async fn an_unclaimed_caller_still_marks_an_approved_request_executed() {
    let pool: PgPool = migrated_pool_or_skip!(4);
    let request = approved(&pool).await;

    let executed = mark_executed(&pool, request.id, request.row_version)
        .await
        .expect("mark executed");
    assert_eq!(executed.status, ApprovalStatus::Executed);
    assert_eq!(claim_columns(&pool, request.id).await, (None, false));
}

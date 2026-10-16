//! BAP-14 (Phase 5) — the crate-level cases P-four-eyes-approval §6 left
//! open: `mark_invalidated`'s CAS/terminal/hook-rollback contract, the
//! `list_pending` filter/paging/total shape, the `regarding` pointer and the
//! plan round-tripping through `submit_regarding_with`/
//! `submit_with_plan_regarding_with`, `sweep_expired` on a backdated row, and the
//! second `mark_executed` that must be a `VersionConflict` rather than a
//! second side effect.
//!
//! Skips (loudly) when `DATABASE_URL` is unset, except under
//! `ATTOME_TEST_REQUIRE_DB` — see `attome_testkit`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-approval --test lifecycle -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashSet;
use std::sync::Mutex;

use attome_approval::{
    ApprovalPlan, ApprovalRequest, ApprovalStatus, ApprovalStep, Decision, OnTimeout, StepMode,
    decide, get, list_pending, mark_executed, mark_invalidated, mark_invalidated_with, submit,
    submit_regarding_with, submit_with_plan_regarding_with, sweep_expired,
};
use attome_db::{BeforeCommit, HookFuture, Tx};
use attome_testkit::migrated_pool_or_skip;
use attome_types::AppError;
use chrono::Duration;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Fails after writing nothing, so a rollback is the only way the mutation
/// can be absent.
struct FailingHook;

impl BeforeCommit<ApprovalRequest> for FailingHook {
    fn before_commit<'a>(
        &'a self,
        _tx: &'a mut Tx<'_>,
        _request: &'a ApprovalRequest,
    ) -> HookFuture<'a> {
        Box::pin(async { Err(AppError::internal("forced hook failure")) })
    }
}

/// Records what a hook saw, so a test can prove it ran inside the mutation's
/// transaction.
#[derive(Default)]
struct RecordingHook(Mutex<Vec<ApprovalStatus>>);

impl BeforeCommit<ApprovalRequest> for RecordingHook {
    fn before_commit<'a>(
        &'a self,
        _tx: &'a mut Tx<'_>,
        request: &'a ApprovalRequest,
    ) -> HookFuture<'a> {
        self.0.lock().expect("lock").push(request.status);
        Box::pin(async { Ok(()) })
    }
}

async fn pending(pool: &PgPool, action_type: &str) -> ApprovalRequest {
    submit(
        pool,
        action_type,
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit")
}

async fn approved(pool: &PgPool, action_type: &str) -> ApprovalRequest {
    let request = pending(pool, action_type).await;
    decide(
        pool,
        request.id,
        Uuid::now_v7(),
        Decision::Approve,
        request.row_version,
    )
    .await
    .expect("decide")
}

async fn status(pool: &PgPool, id: Uuid) -> ApprovalStatus {
    get(pool, id).await.expect("get").status
}

/// `mark_invalidated` is a status-guarded CAS: it takes only a request that
/// is still `approved`, and the result is terminal.
#[tokio::test]
async fn mark_invalidated_is_a_terminal_cas_from_approved_only() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let request = pending(&pool, "test.lifecycle.invalidate").await;

    // Still pending: not a legal source state.
    let err = mark_invalidated(&pool, request.id, request.row_version)
        .await
        .expect_err("a pending request cannot be invalidated");
    assert!(matches!(err, AppError::VersionConflict));
    assert_eq!(status(&pool, request.id).await, ApprovalStatus::Pending);

    let approved = approved(&pool, "test.lifecycle.invalidate").await;
    let invalidated = mark_invalidated(&pool, approved.id, approved.row_version)
        .await
        .expect("an approved request can be invalidated");
    assert_eq!(invalidated.status, ApprovalStatus::Invalidated);
    assert_eq!(invalidated.row_version, approved.row_version + 1);

    // Terminal: nothing, not even a retry of the mark, moves it again.
    let err = mark_invalidated(&pool, invalidated.id, invalidated.row_version)
        .await
        .expect_err("an invalidated request stays invalidated");
    assert!(matches!(err, AppError::VersionConflict));
    assert_eq!(
        status(&pool, invalidated.id).await,
        ApprovalStatus::Invalidated
    );
}

/// A failing hook rolls the invalidation back, and a succeeding one sees the
/// invalidated request.
#[tokio::test]
async fn mark_invalidated_honours_its_hook() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let request = approved(&pool, "test.lifecycle.invalidate_hook").await;

    mark_invalidated_with(&pool, request.id, request.row_version, &FailingHook)
        .await
        .expect_err("a failing hook fails the invalidation");
    assert_eq!(status(&pool, request.id).await, ApprovalStatus::Approved);

    let hook = RecordingHook::default();
    let invalidated = mark_invalidated_with(&pool, request.id, request.row_version, &hook)
        .await
        .expect("mark_invalidated_with");
    assert_eq!(invalidated.status, ApprovalStatus::Invalidated);
    assert_eq!(
        *hook.0.lock().expect("lock"),
        vec![ApprovalStatus::Invalidated]
    );
}

/// `list_pending` filters by action type, pages without repeating a row, and
/// reports the total of the whole filtered set (not of the page).
#[tokio::test]
async fn list_pending_filters_pages_and_totals() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let action_type = format!("test.lifecycle.list.{}", Uuid::now_v7());
    let mut ids = HashSet::new();
    for _ in 0..3 {
        // `ORDER BY requested_at DESC` needs distinct timestamps to page
        // deterministically; the default is the transaction clock.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        ids.insert(pending(&pool, &action_type).await.id);
    }
    // A pending request of another action type must not appear.
    pending(&pool, "test.lifecycle.list.other").await;

    let (first, total) = list_pending(&pool, Some(&action_type), 1, 2)
        .await
        .expect("list_pending page 1");
    assert_eq!(total, 3, "the total counts the whole filtered set");
    assert_eq!(first.len(), 2);
    let (second, _) = list_pending(&pool, Some(&action_type), 2, 2)
        .await
        .expect("list_pending page 2");
    assert_eq!(second.len(), 1);

    let seen: HashSet<Uuid> = first.iter().chain(second.iter()).map(|r| r.id).collect();
    assert_eq!(seen, ids, "every row appears exactly once across the pages");

    // A decided request leaves the pending list.
    let first_row = first.first().expect("a row").clone();
    decide(
        &pool,
        first_row.id,
        Uuid::now_v7(),
        Decision::Approve,
        first_row.row_version,
    )
    .await
    .expect("decide");
    let (_, total) = list_pending(&pool, Some(&action_type), 1, 50)
        .await
        .expect("list_pending after a decision");
    assert_eq!(total, 2);
}

/// The `regarding` pointer and the opaque payload survive a submit/get round
/// trip, and a plain `submit` leaves the pointer unset.
#[tokio::test]
async fn submit_regarding_round_trips_its_pointer() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let record_id = Uuid::now_v7();
    let request = submit_regarding_with(
        &pool,
        "test.lifecycle.regarding",
        json!({ "amount": 10 }),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
        Some(("account", record_id)),
        &attome_db::NoHook,
    )
    .await
    .expect("submit_regarding_with");

    let fetched = get(&pool, request.id).await.expect("get");
    assert_eq!(fetched.regarding_entity.as_deref(), Some("account"));
    assert_eq!(fetched.regarding_id, Some(record_id));
    assert_eq!(fetched.payload, json!({ "amount": 10 }));
    assert!(fetched.plan.is_none());
    assert_eq!(fetched.required_approvals, 1);

    let plain = pending(&pool, "test.lifecycle.regarding").await;
    assert!(plain.regarding_entity.is_none());
    assert!(plain.regarding_id.is_none());
}

/// `submit_with_plan_regarding_with` stores the plan verbatim, starts at step 0,
/// records the policy id and the pointer, and keeps `required_approvals` at
/// the column's minimum (it is not read once a request has a plan).
#[tokio::test]
async fn submit_with_plan_regarding_round_trips_the_plan() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let plan = ApprovalPlan {
        steps: vec![
            ApprovalStep {
                mode: StepMode::NofM,
                threshold: Some(2),
                approvers: vec![
                    "user:a".to_string(),
                    "user:b".to_string(),
                    "user:c".to_string(),
                ],
                sla_minutes: Some(60),
                on_timeout: OnTimeout::Escalate,
                extras: Default::default(),
            },
            ApprovalStep {
                mode: StepMode::Any,
                threshold: None,
                approvers: vec!["role:manager".to_string()],
                sla_minutes: None,
                on_timeout: OnTimeout::AutoReject,
                extras: Default::default(),
            },
        ],
    };
    // `policy_id` is an opaque provenance pointer: the policy table belongs
    // to the engine, so any id round-trips.
    let policy_id = Uuid::now_v7();

    let record_id = Uuid::now_v7();
    let request = submit_with_plan_regarding_with(
        &pool,
        "test.lifecycle.plan_regarding",
        json!({ "reason": "audit" }),
        Uuid::now_v7(),
        plan.clone(),
        Duration::hours(48),
        Some(policy_id),
        Some(("invoice", record_id)),
        &attome_db::NoHook,
    )
    .await
    .expect("submit_with_plan_regarding_with");

    let fetched = get(&pool, request.id).await.expect("get");
    assert_eq!(fetched.plan.as_ref(), Some(&plan));
    assert_eq!(fetched.policy_id, Some(policy_id));
    assert_eq!(fetched.step, 0);
    assert!(
        fetched.step_started_at.is_some(),
        "step 0's SLA clock started"
    );
    assert!(fetched.escalated_at.is_none());
    assert_eq!(fetched.required_approvals, 1);
    assert_eq!(fetched.regarding_entity.as_deref(), Some("invoice"));
    assert_eq!(fetched.regarding_id, Some(record_id));
}

/// `sweep_expired` reaps a backdated pending row, and only a pending one.
#[tokio::test]
async fn sweep_expired_reaps_a_backdated_row() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let stale = pending(&pool, "test.lifecycle.sweep").await;
    let fresh = pending(&pool, "test.lifecycle.sweep").await;
    sqlx::query(
        "UPDATE approval_request SET expires_at = NOW() - INTERVAL '1 minute' \
          WHERE id = $1",
    )
    .bind(stale.id)
    .execute(&pool)
    .await
    .expect("backdate expires_at");

    let expired = sweep_expired(&pool).await.expect("sweep_expired");
    assert!(expired >= 1, "the backdated row is reaped");
    assert_eq!(status(&pool, stale.id).await, ApprovalStatus::Expired);
    assert_eq!(
        status(&pool, fresh.id).await,
        ApprovalStatus::Pending,
        "a row inside its TTL is untouched"
    );
}

/// P-four-eyes-approval §6: a second `mark_executed` is a `VersionConflict`,
/// not a second execution record — the CAS is what makes the retry safe.
#[tokio::test]
async fn mark_executed_twice_is_a_version_conflict() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let request = approved(&pool, "test.lifecycle.mark_executed").await;

    let executed = mark_executed(&pool, request.id, request.row_version)
        .await
        .expect("mark_executed");
    assert_eq!(executed.status, ApprovalStatus::Executed);
    assert!(executed.executed_at.is_some());

    let err = mark_executed(&pool, executed.id, executed.row_version)
        .await
        .expect_err("a second mark is refused");
    assert!(matches!(err, AppError::VersionConflict));
    let after = get(&pool, executed.id).await.expect("get");
    assert_eq!(after.status, ApprovalStatus::Executed);
    assert_eq!(
        after.row_version, executed.row_version,
        "the refused mark changed nothing"
    );
}

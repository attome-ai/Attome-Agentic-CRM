//! Audit plan 3.6 / D-062: a `attome_db::BeforeCommit` hook runs inside the
//! base-layer transaction, so a failing hook (in production, a failed audit
//! write) rolls the decision, the cancellation or the execution mark back
//! instead of leaving a change with no event; a succeeding hook sees the
//! request exactly as it is returned.
//!
//! BAP-15 extends the same rule to the expiry a decision discovers, and
//! BAP-6a/6b to the per-step timeout: both now take a hook, so an expiry or
//! an automatic decision carries its event, or neither commits. BAP-19a/19b
//! extend it to `submit` itself, which is what makes `gate()`'s `Submitted`
//! event atomic with the request it describes.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-approval --test before_commit_hook -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Mutex;

use attome_approval::{
    ADVISORY_LOCK_NAMESPACE, ApprovalPlan, ApprovalRequest, ApprovalStatus, ApprovalStep, Decision,
    OnTimeout, StepMode, TimeoutOutcome, apply_step_timeout_with, cancel_with, decide_with, get,
    mark_executed_with, submit, submit_regarding_with, submit_with_plan,
    submit_with_plan_regarding_with,
};
use attome_db::{BeforeCommit, HookFuture, Tx};
use attome_testkit::migrated_pool_or_skip;
use attome_types::AppError;
use chrono::Duration;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Fails after writing a row of its own, so the test also proves the hook's
/// own writes roll back with the base mutation.
struct FailingHook;

impl BeforeCommit<ApprovalRequest> for FailingHook {
    fn before_commit<'a>(
        &'a self,
        tx: &'a mut Tx<'_>,
        request: &'a ApprovalRequest,
    ) -> HookFuture<'a> {
        Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock($1, hashtext($2))")
                .bind(ADVISORY_LOCK_NAMESPACE)
                .bind(request.id.to_string())
                .execute(&mut **tx)
                .await
                .map_err(AppError::internal)?;
            Err(AppError::internal("forced hook failure"))
        })
    }
}

/// Records the status each call saw.
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

async fn grant_count(pool: &PgPool, request_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM approval_grant WHERE request_id = $1")
        .bind(request_id)
        .fetch_one(pool)
        .await
        .expect("count grants")
}

async fn pending(pool: &PgPool, requested_by: Uuid) -> ApprovalRequest {
    submit(
        pool,
        "test.before_commit_hook",
        json!({}),
        requested_by,
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit")
}

#[tokio::test]
async fn a_failing_hook_rolls_the_decision_back() {
    let pool: PgPool = migrated_pool_or_skip!(5);
    let request = pending(&pool, Uuid::now_v7()).await;

    let err = decide_with(
        &pool,
        request.id,
        Uuid::now_v7(),
        Decision::Approve,
        request.row_version,
        None,
        &FailingHook,
    )
    .await
    .expect_err("a failing hook fails the decision");
    assert!(matches!(err, AppError::Internal(_)));

    let after = get(&pool, request.id).await.expect("get");
    assert_eq!(after.status, ApprovalStatus::Pending);
    assert_eq!(after.row_version, request.row_version);
    assert_eq!(
        grant_count(&pool, request.id).await,
        0,
        "no grant row survives"
    );

    // The same decision then succeeds, and its hook sees the returned state.
    let hook = RecordingHook::default();
    let decided = decide_with(
        &pool,
        request.id,
        Uuid::now_v7(),
        Decision::Approve,
        request.row_version,
        None,
        &hook,
    )
    .await
    .expect("decide");
    assert_eq!(decided.status, ApprovalStatus::Approved);
    assert_eq!(
        *hook.0.lock().expect("lock"),
        vec![ApprovalStatus::Approved]
    );
}

#[tokio::test]
async fn a_failing_hook_rolls_back_cancel_and_mark_executed() {
    let pool: PgPool = migrated_pool_or_skip!(5);
    let requester = Uuid::now_v7();

    let request = pending(&pool, requester).await;
    cancel_with(
        &pool,
        request.id,
        requester,
        request.row_version,
        &FailingHook,
    )
    .await
    .expect_err("a failing hook fails the cancellation");
    assert_eq!(
        get(&pool, request.id).await.expect("get").status,
        ApprovalStatus::Pending
    );

    let approved = decide_with(
        &pool,
        request.id,
        Uuid::now_v7(),
        Decision::Approve,
        request.row_version,
        None,
        &attome_db::NoHook,
    )
    .await
    .expect("decide");
    mark_executed_with(&pool, approved.id, approved.row_version, &FailingHook)
        .await
        .expect_err("a failing hook fails the execution mark");
    let after = get(&pool, approved.id).await.expect("get");
    assert_eq!(after.status, ApprovalStatus::Approved);
    assert!(after.executed_at.is_none());
}

/// Fails a step-timeout hook, whose value is the request *and* the outcome
/// that was applied (BAP-6a/6b).
struct FailingTimeoutHook;

impl BeforeCommit<(ApprovalRequest, TimeoutOutcome)> for FailingTimeoutHook {
    fn before_commit<'a>(
        &'a self,
        _tx: &'a mut Tx<'_>,
        _committed: &'a (ApprovalRequest, TimeoutOutcome),
    ) -> HookFuture<'a> {
        Box::pin(async { Err(AppError::internal("forced timeout-hook failure")) })
    }
}

/// Records the status a step-timeout hook saw.
#[derive(Default)]
struct RecordingTimeoutHook(Mutex<Vec<ApprovalStatus>>);

impl BeforeCommit<(ApprovalRequest, TimeoutOutcome)> for RecordingTimeoutHook {
    fn before_commit<'a>(
        &'a self,
        _tx: &'a mut Tx<'_>,
        committed: &'a (ApprovalRequest, TimeoutOutcome),
    ) -> HookFuture<'a> {
        self.0.lock().expect("lock").push(committed.0.status);
        Box::pin(async { Ok(()) })
    }
}

async fn backdate_expiry(pool: &PgPool, request_id: Uuid) {
    sqlx::query(
        "UPDATE approval_request SET expires_at = NOW() - INTERVAL '1 minute' \
         WHERE id = $1",
    )
    .bind(request_id)
    .execute(pool)
    .await
    .expect("move the backstop into the past");
}

/// A pending, plan-bearing request whose `auto_approve` step SLA has already
/// elapsed, so `apply_step_timeout_with` acts on it.
async fn due_auto_approve_timeout(pool: &PgPool, requested_by: Uuid) -> ApprovalRequest {
    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:a".to_string()],
            sla_minutes: Some(1),
            on_timeout: OnTimeout::AutoApprove,
        }],
    };
    let request = submit_with_plan(
        pool,
        "test.before_commit_hook.timeout",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");
    sqlx::query(
        "UPDATE approval_request \
             SET step_started_at = NOW() - INTERVAL '10 minutes' \
          WHERE id = $1",
    )
    .bind(request.id)
    .execute(pool)
    .await
    .expect("backdate step_started_at");
    get(pool, request.id).await.expect("get")
}

/// BAP-15 / BAP-F11 (D-545): a decision that finds the request already past
/// its backstop flips it to `expired` and runs the caller\'s hook with the
/// expired request *before* committing — so the expiry carries an event like
/// any other transition — and a hook failure rolls the expiry back.
#[tokio::test]
async fn deciding_an_expired_request_commits_the_expiry_with_the_hook() {
    let pool: PgPool = migrated_pool_or_skip!(5);
    let request = pending(&pool, Uuid::now_v7()).await;
    backdate_expiry(&pool, request.id).await;

    let hook = RecordingHook::default();
    let err = decide_with(
        &pool,
        request.id,
        Uuid::now_v7(),
        Decision::Approve,
        request.row_version,
        None,
        &hook,
    )
    .await
    .expect_err("an expired request cannot be decided");
    assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");
    assert_eq!(
        *hook.0.lock().expect("lock"),
        vec![ApprovalStatus::Expired],
        "the hook ran with the expired request before the expiry committed"
    );
    assert_eq!(
        get(&pool, request.id).await.expect("get").status,
        ApprovalStatus::Expired
    );

    // A failing hook rolls the expiry back: the request stays pending, so a
    // later sweep expires it with its own event.
    let second = pending(&pool, Uuid::now_v7()).await;
    backdate_expiry(&pool, second.id).await;
    decide_with(
        &pool,
        second.id,
        Uuid::now_v7(),
        Decision::Approve,
        second.row_version,
        None,
        &FailingHook,
    )
    .await
    .expect_err("a failing hook fails the expiry too");
    assert_eq!(
        get(&pool, second.id).await.expect("get").status,
        ApprovalStatus::Pending,
        "the expiry rolled back with its failed event"
    );
}

/// BAP-6a/BAP-6b (D-545): the step-timeout transition commits with the
/// caller\'s hook, so a hook error rolls the whole timeout back — no
/// automatic approval without its event.
#[tokio::test]
async fn a_failing_timeout_hook_rolls_the_step_timeout_back() {
    let pool: PgPool = migrated_pool_or_skip!(5);
    let request = due_auto_approve_timeout(&pool, Uuid::now_v7()).await;

    let err = apply_step_timeout_with(&pool, request.id, &FailingTimeoutHook)
        .await
        .expect_err("a failing hook fails the timeout");
    assert!(matches!(err, AppError::Internal(_)), "got {err:?}");

    let after = get(&pool, request.id).await.expect("get");
    assert_eq!(after.status, ApprovalStatus::Pending);
    assert_eq!(after.row_version, request.row_version);
    assert_eq!(
        grant_count(&pool, request.id).await,
        0,
        "the automatic grant rolled back too"
    );

    let hook = RecordingTimeoutHook::default();
    let (after, outcome) = apply_step_timeout_with(&pool, request.id, &hook)
        .await
        .expect("apply_step_timeout_with")
        .expect("the step is due");
    assert_eq!(outcome, TimeoutOutcome::AutoApproved);
    assert_eq!(after.status, ApprovalStatus::Approved);
    assert_eq!(
        *hook.0.lock().expect("lock"),
        vec![ApprovalStatus::Approved]
    );
}

/// BAP-19a / BAP-F14: the submit's hook runs inside the insert's own
/// transaction, so a failing hook leaves no request row at all — never the
/// real, approvable request with no event that `gate()` used to risk.
#[tokio::test]
async fn a_failing_submit_hook_leaves_no_request_row() {
    let pool: PgPool = migrated_pool_or_skip!(5);
    let action_type = format!("test.before_commit_hook.submit.{}", Uuid::now_v7());

    submit_regarding_with(
        &pool,
        &action_type,
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
        None,
        &FailingHook,
    )
    .await
    .expect_err("a failing hook fails the submit");

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approval_request WHERE action_type = $1")
            .bind(&action_type)
            .fetch_one(&pool)
            .await
            .expect("count rows");
    assert_eq!(rows, 0, "the request rolled back with its failed event");

    let request = submit_regarding_with(
        &pool,
        &action_type,
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
        None,
        &attome_db::NoHook,
    )
    .await
    .expect("submit_regarding_with");
    assert_eq!(request.status, ApprovalStatus::Pending);
}

/// The plan-bearing twin of the same contract.
#[tokio::test]
async fn a_failing_plan_submit_hook_leaves_no_request_row() {
    let pool: PgPool = migrated_pool_or_skip!(5);
    let action_type = format!("test.before_commit_hook.plan_submit.{}", Uuid::now_v7());
    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:a".to_string()],
            sla_minutes: Some(60),
            on_timeout: OnTimeout::Escalate,
        }],
    };

    submit_with_plan_regarding_with(
        &pool,
        &action_type,
        json!({}),
        Uuid::now_v7(),
        plan.clone(),
        Duration::hours(1),
        None,
        None,
        &FailingHook,
    )
    .await
    .expect_err("a failing hook fails the plan-bearing submit");

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approval_request WHERE action_type = $1")
            .bind(&action_type)
            .fetch_one(&pool)
            .await
            .expect("count rows");
    assert_eq!(rows, 0);

    let request = submit_with_plan_regarding_with(
        &pool,
        &action_type,
        json!({}),
        Uuid::now_v7(),
        plan,
        Duration::hours(1),
        None,
        None,
        &attome_db::NoHook,
    )
    .await
    .expect("submit_with_plan_regarding_with");
    assert!(request.plan.is_some());
    assert_eq!(request.status, ApprovalStatus::Pending);
}

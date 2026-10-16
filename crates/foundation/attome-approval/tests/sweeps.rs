//! attome-approval plan Phase 0 (BAP-P0.5, BAP-P0.6): the two periodic sweeps
//! must be poison-proof and starvation-free (invariant A9).
//!
//! BAP-P0.5/P0.6 were `#[ignore]`d while they failed against the old
//! implementations; BAP-8 (due-ness in SQL) and BAP-9 (one short transaction
//! per row) landed, so both run unconditionally now. Skips (loudly) when
//! `DATABASE_URL` is unset, except under `ATTOME_TEST_REQUIRE_DB` — see
//! `attome_testkit`.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/<private template>?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-approval --test sweeps -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_approval::{
    ApprovalPlan, ApprovalRequest, ApprovalStatus, ApprovalStep, Decision, EXPIRY_SWEEP_BATCH,
    OnTimeout, StepMode, claim_execution, decide, get, list_by_status, list_due_step_timeouts,
    list_pending, oldest_pending_age_seconds, stale_executing_count, status_counts, submit,
    submit_with_plan, sweep_expired_report_with, sweep_expired_with,
};
use attome_db::{BeforeCommit, HookFuture, Tx};
use attome_testkit::migrated_pool_or_skip;
use attome_types::AppError;
use chrono::Duration;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Fails the hook for exactly one request, standing in for an agent-action
/// request whose conversation hook errors, or any other poison row.
struct FailsFor(Uuid);

impl BeforeCommit<ApprovalRequest> for FailsFor {
    fn before_commit<'a>(
        &'a self,
        _tx: &'a mut Tx<'_>,
        request: &'a ApprovalRequest,
    ) -> HookFuture<'a> {
        let poisoned = request.id == self.0;
        Box::pin(async move {
            if poisoned {
                Err(AppError::internal("forced hook failure for one row"))
            } else {
                Ok(())
            }
        })
    }
}

async fn submit_already_expired(pool: &PgPool, label: &str) -> Uuid {
    let request = submit(
        pool,
        label,
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");
    sqlx::query(
        "UPDATE approval_request SET expires_at = NOW() - INTERVAL '1 minute' \
         WHERE id = $1",
    )
    .bind(request.id)
    .execute(pool)
    .await
    .expect("move expires_at into the past");
    request.id
}

/// BAP-P0.5 / BAP-F5: one row whose hook fails must not stop every other
/// due row from expiring. Today the sweep is one all-or-nothing transaction,
/// so the poisoned row rolls back all three.
#[tokio::test]
async fn one_failing_hook_does_not_block_other_expiries() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let first = submit_already_expired(&pool, "test.sweep.first").await;
    let poisoned = submit_already_expired(&pool, "test.sweep.poisoned").await;
    let third = submit_already_expired(&pool, "test.sweep.third").await;

    let result = sweep_expired_with(&pool, &FailsFor(poisoned)).await;

    let first_status = get(&pool, first).await.expect("get first").status;
    let third_status = get(&pool, third).await.expect("get third").status;
    assert_eq!(
        (first_status, third_status),
        (ApprovalStatus::Expired, ApprovalStatus::Expired),
        "the two healthy rows must expire even though another row's hook failed \
         (sweep returned {result:?})"
    );
    assert_eq!(
        get(&pool, poisoned).await.expect("get poisoned").status,
        ApprovalStatus::Pending,
        "the poisoned row stays pending for a later sweep"
    );
}

fn plan_with_sla(sla_minutes: Option<i64>) -> ApprovalPlan {
    ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:a".to_string()],
            sla_minutes,
            on_timeout: OnTimeout::Escalate,
            extras: Default::default(),
        }],
    }
}

async fn submit_plan_started_minutes_ago(
    pool: &PgPool,
    plan: ApprovalPlan,
    minutes_ago: i64,
) -> Uuid {
    let request = submit_with_plan(
        pool,
        "test.sweep.timeout_window",
        json!({}),
        Uuid::now_v7(),
        plan,
        Duration::hours(24),
        None,
    )
    .await
    .expect("submit_with_plan");
    sqlx::query(
        "UPDATE approval_request \
            SET step_started_at = NOW() - make_interval(mins => $2) \
          WHERE id = $1",
    )
    .bind(request.id)
    .bind(i32::try_from(minutes_ago).expect("minutes fit i32"))
    .execute(pool)
    .await
    .expect("backdate step_started_at");
    request.id
}

/// BAP-P0.6 / BAP-F4: 30 older pending plan requests with no SLA sit ahead of
/// one request whose step SLA has elapsed. `list_due_step_timeouts(25)` must
/// still return the due one. Today it reads the oldest 25 candidates and
/// filters them in Rust, so the due row never reaches the window.
#[tokio::test]
async fn a_due_timeout_is_not_starved_by_rows_that_are_not_due() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    for _ in 0..30 {
        submit_plan_started_minutes_ago(&pool, plan_with_sla(None), 24 * 60).await;
    }
    let due = submit_plan_started_minutes_ago(&pool, plan_with_sla(Some(1)), 10).await;

    let listed = list_due_step_timeouts(&pool, 25)
        .await
        .expect("list_due_step_timeouts");
    assert!(
        listed.contains(&due),
        "a due step timeout must be listed even when 30 older rows that are not due exist \
         ({} ids listed)",
        listed.len()
    );
}

/// BAP-9: the sweep is bounded and reports its own progress, and running it
/// again finds nothing left to do for a row it already expired.
#[tokio::test]
async fn a_bounded_sweep_reports_its_own_progress() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let id = submit_already_expired(&pool, "test.sweep.report").await;

    let outcome = sweep_expired_report_with(&pool, &attome_db::NoHook, EXPIRY_SWEEP_BATCH)
        .await
        .expect("sweep_expired_report_with");
    assert!(outcome.expired >= 1, "expired the backdated row");
    assert_eq!(outcome.failed, 0);
    assert_eq!(
        get(&pool, id).await.expect("get").status,
        ApprovalStatus::Expired
    );

    let again = sweep_expired_report_with(&pool, &attome_db::NoHook, EXPIRY_SWEEP_BATCH)
        .await
        .expect("second sweep");
    assert_eq!(again.expired, 0, "a second sweep does no double work");
}

/// BAP-17 / BAP-F12: a page far past the end of any result set is an empty
/// page, not an overflow. Before the checked arithmetic inside
/// `list_by_status`, `(page - 1) * page_size` wrapped in a release build (a
/// negative `OFFSET` Postgres rejects with a 500) and panicked in a debug
/// one.
#[tokio::test]
async fn an_absurd_page_returns_an_empty_page() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    submit(
        &pool,
        "test.sweeps.absurd_page",
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");

    let (items, total) = list_pending(&pool, Some("test.sweeps.absurd_page"), i64::MAX, 50)
        .await
        .expect("an absurd page must not error");
    assert!(items.is_empty(), "past the end of the result set");
    assert!(total >= 1, "the total still reports what exists");
}

/// BAP-10 / BAP-F8: approved-but-unexecuted and claimed requests are
/// listable by status, not only by id — the operability listing the plan
/// asks for.
#[tokio::test]
async fn list_by_status_lists_approved_and_claimed_requests() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let approved = submit(
        &pool,
        "test.sweeps.listing",
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");
    decide(
        &pool,
        approved.id,
        Uuid::now_v7(),
        Decision::Approve,
        approved.row_version,
    )
    .await
    .expect("decide");

    let claimed_request = submit(
        &pool,
        "test.sweeps.listing",
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");
    let approved_to_claim = decide(
        &pool,
        claimed_request.id,
        Uuid::now_v7(),
        Decision::Approve,
        claimed_request.row_version,
    )
    .await
    .expect("decide");
    claim_execution(
        &pool,
        approved_to_claim.id,
        approved_to_claim.row_version,
        Uuid::now_v7(),
    )
    .await
    .expect("claim_execution");

    let (items, total) = list_by_status(
        &pool,
        &[ApprovalStatus::Approved, ApprovalStatus::Executing],
        Some("test.sweeps.listing"),
        1,
        50,
    )
    .await
    .expect("list_by_status");
    let ids: Vec<Uuid> = items.iter().map(|r| r.id).collect();
    assert!(
        ids.contains(&approved.id),
        "an approved-unexecuted request is listed"
    );
    assert!(
        ids.contains(&approved_to_claim.id),
        "a claimed request is listed"
    );
    assert_eq!(total, 2);

    let (pending, _) = list_by_status(
        &pool,
        &[ApprovalStatus::Pending],
        Some("test.sweeps.listing"),
        1,
        50,
    )
    .await
    .expect("list_by_status");
    assert!(pending.is_empty(), "neither request is pending");
}

/// BAP-13 / BAP-F8: the counts an operator needs — status buckets, the
/// oldest pending age, and stale claims.
#[tokio::test]
async fn status_counts_and_ages_report_the_current_queue() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    submit(
        &pool,
        "test.sweeps.counts",
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::hours(1),
    )
    .await
    .expect("submit");

    let counts = status_counts(&pool).await.expect("status_counts");
    let bucket = counts
        .iter()
        .find(|c| c.status == "pending" && c.action_type == "test.sweeps.counts")
        .expect("pending bucket");
    assert_eq!(bucket.count, 1);

    let ages = oldest_pending_age_seconds(&pool).await.expect("ages");
    let (action_type, seconds) = ages
        .iter()
        .find(|(a, _)| a == "test.sweeps.counts")
        .expect("age bucket");
    assert_eq!(action_type, "test.sweeps.counts");
    assert!(*seconds >= 0.0);

    // Fresh claims (the listing test\'s, if it ran first) are not stale.
    assert_eq!(stale_executing_count(&pool).await.expect("stale count"), 0);
}

/// BAP-16: a `ttl` outside `DateTime`\'s range is a 422, not a panic —
/// chrono\'s `DateTime + TimeDelta` panics out of range.
#[tokio::test]
async fn an_out_of_range_ttl_is_a_validation_error() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let err = submit(
        &pool,
        "test.sweeps.ttl_overflow",
        json!({}),
        Uuid::now_v7(),
        1,
        Duration::MAX,
    )
    .await
    .expect_err("an out-of-range ttl must be refused");
    assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
}

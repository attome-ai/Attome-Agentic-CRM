//! D-421 / M10 (Approval & Governance) — proves the plan-aware half of
//! `attome-approval` (`submit_with_plan`/`decide_step`/`list_due_step_timeouts`/
//! `apply_step_timeout_with`) alongside `decide_invariants.rs`'s pre-D-421 tests,
//! which this file leaves completely untouched: every test there still
//! exercises `submit`/`decide` exactly as before, proving the flat
//! `required_approvals` model kept working unchanged.
//!
//! Covers this module's own three named test targets:
//! - `n_of_m_step_closes_only_once_the_threshold_is_reached` /
//!   `all_step_requires_every_named_principal` — n-of-m/all semantics.
//! - `decide_step_rejects_a_delegation_that_would_reach_the_requester` —
//!   delegation cannot manufacture a path to self-approval.
//! - `auto_approve_timeout_is_recorded_as_decided_by_policy` /
//!   `auto_reject_timeout_is_recorded_as_decided_by_policy` — timeout
//!   auto-decide audited as `decided_by = POLICY_ACTOR_ID` ("policy").
//!
//! Skips (loudly) when `DATABASE_URL` is unset, except under `CI` — see
//! `attome_testkit` (F-008/TODO-008), same convention `decide_invariants.rs`
//! uses.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://attome:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-approval --test plan_step_invariants -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_approval::{
    ApprovalPlan, ApprovalStatus, ApprovalStep, Decision, OnTimeout, POLICY_ACTOR_ID, StepMode,
    TimeoutOutcome, apply_step_timeout_with, decide_step, get, list_due_step_timeouts,
    submit_with_plan,
};
use attome_testkit::migrated_pool_or_skip;
use attome_types::AppError;
use chrono::Duration;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct GrantRow {
    approver_id: Uuid,
    decided_by: Option<Uuid>,
    on_behalf_of: Option<Uuid>,
    decision: String,
    step: i32,
}

/// Backdates `step_started_at` so a step's `sla_minutes` (which
/// `ApprovalPlan::validate()` requires to be `>= 1`) is already elapsed —
/// lets these tests exercise "due now" deterministically instead of
/// actually sleeping a real minute.
async fn backdate_step_started_at(pool: &PgPool, request_id: Uuid) {
    sqlx::query(
        "UPDATE approval_request SET step_started_at = NOW() - INTERVAL '10 minutes' \
         WHERE id = $1",
    )
    .bind(request_id)
    .execute(pool)
    .await
    .expect("backdate step_started_at");
}

async fn grants(pool: &PgPool, request_id: Uuid) -> Vec<GrantRow> {
    sqlx::query_as(
        "SELECT approver_id, decided_by, on_behalf_of, decision, step \
         FROM approval_grant WHERE request_id = $1 ORDER BY decided_at",
    )
    .bind(request_id)
    .fetch_all(pool)
    .await
    .expect("select approval_grant rows")
}

fn n_of_m_plan(n: i32, approvers: usize) -> ApprovalPlan {
    ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::NofM,
            threshold: Some(n),
            approvers: (0..approvers).map(|i| format!("user:{i}")).collect(),
            sla_minutes: Some(60),
            on_timeout: OnTimeout::Escalate,
        }],
    }
}

/// n-of-m: with a 2-of-3 step, the first Approve leaves the request
/// `Pending`; only the second distinct approver's Approve closes it. A third
/// eligible approver deciding afterward gets a clean `Conflict` — the
/// request is no longer `Pending` — not a silent extra grant.
#[tokio::test]
async fn n_of_m_step_closes_only_once_the_threshold_is_reached() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let c = Uuid::now_v7();

    let plan = n_of_m_plan(2, 3);
    let request = submit_with_plan(
        &pool,
        "test.n_of_m",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");

    let after_a = decide_step(
        &pool,
        request.id,
        a,
        None,
        &[a, b, c],
        3,
        Decision::Approve,
        request.row_version,
    )
    .await
    .expect("first of two required approvals must succeed");
    assert_eq!(
        after_a.status,
        ApprovalStatus::Pending,
        "2-of-3 must not close after only one distinct approval"
    );

    let after_b = decide_step(
        &pool,
        request.id,
        b,
        None,
        &[a, b, c],
        3,
        Decision::Approve,
        after_a.row_version,
    )
    .await
    .expect("second, distinct approval must close a single-step plan");
    assert_eq!(
        after_b.status,
        ApprovalStatus::Approved,
        "2-of-3 threshold reached on a single-step plan must approve the whole request"
    );

    let result = decide_step(
        &pool,
        request.id,
        c,
        None,
        &[a, b, c],
        3,
        Decision::Approve,
        after_b.row_version,
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Conflict(_))),
        "a third eligible approver deciding an already-closed request must be Conflict, got {result:?}"
    );

    let recorded = grants(&pool, request.id).await;
    assert_eq!(
        recorded.len(),
        2,
        "exactly the two decisions that actually closed the step, never the rejected third"
    );
}

/// `all` mode: every named principal (after the requester is removed) must
/// decide before the step closes — population here is 2, so a single
/// approval must leave it `Pending`.
#[tokio::test]
async fn all_step_requires_every_named_principal() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();

    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::All,
            threshold: None,
            approvers: vec!["user:0".to_string(), "user:1".to_string()],
            sla_minutes: Some(60),
            on_timeout: OnTimeout::Escalate,
            extras: Default::default(),
        }],
    };
    let request = submit_with_plan(
        &pool,
        "test.all_mode",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");

    let after_a = decide_step(
        &pool,
        request.id,
        a,
        None,
        &[a, b],
        2,
        Decision::Approve,
        request.row_version,
    )
    .await
    .expect("first of two named principals must succeed");
    assert_eq!(after_a.status, ApprovalStatus::Pending);

    let after_b = decide_step(
        &pool,
        request.id,
        b,
        None,
        &[a, b],
        2,
        Decision::Approve,
        after_a.row_version,
    )
    .await
    .expect("second named principal must close it");
    assert_eq!(after_b.status, ApprovalStatus::Approved);
}

/// A two-step plan: closing step 0 must advance to step 1, not approve the
/// whole request — and a distinct step-0 approver's grant must not count
/// toward step 1's own threshold.
#[tokio::test]
async fn approving_one_step_advances_to_the_next_without_closing_the_request() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let step0_approver = Uuid::now_v7();
    let step1_approver = Uuid::now_v7();

    let plan = ApprovalPlan {
        steps: vec![
            ApprovalStep {
                mode: StepMode::Any,
                threshold: None,
                approvers: vec!["user:0".to_string()],
                sla_minutes: Some(60),
                on_timeout: OnTimeout::Escalate,
                extras: Default::default(),
            },
            ApprovalStep {
                mode: StepMode::Any,
                threshold: None,
                approvers: vec!["user:1".to_string()],
                sla_minutes: Some(60),
                on_timeout: OnTimeout::Escalate,
                extras: Default::default(),
            },
        ],
    };
    let request = submit_with_plan(
        &pool,
        "test.two_step",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");
    assert_eq!(request.step, 0);

    let after_step0 = decide_step(
        &pool,
        request.id,
        step0_approver,
        None,
        &[step0_approver],
        1,
        Decision::Approve,
        request.row_version,
    )
    .await
    .expect("step 0's any-mode approval must succeed");
    assert_eq!(
        after_step0.status,
        ApprovalStatus::Pending,
        "closing step 0 of a 2-step plan must not approve the whole request"
    );
    assert_eq!(after_step0.step, 1, "must have advanced to step 1");

    // The step-0 approver is not eligible on step 1 — same separation this
    // crate has always enforced, now scoped per step via the caller-supplied
    // allowed-id list (xrm_audit::approval::resolve_step_approvers would
    // never include them here either).
    let wrong_step_attempt = decide_step(
        &pool,
        request.id,
        step0_approver,
        None,
        &[step1_approver],
        1,
        Decision::Approve,
        after_step0.row_version,
    )
    .await;
    assert!(
        matches!(wrong_step_attempt, Err(AppError::Forbidden)),
        "the step-0 approver is not in step 1's allowed set, got {wrong_step_attempt:?}"
    );

    let after_step1 = decide_step(
        &pool,
        request.id,
        step1_approver,
        None,
        &[step1_approver],
        1,
        Decision::Approve,
        after_step0.row_version,
    )
    .await
    .expect("step 1's own approver must be able to close the last step");
    assert_eq!(after_step1.status, ApprovalStatus::Approved);

    let recorded = grants(&pool, request.id).await;
    assert_eq!(
        recorded.len(),
        2,
        "one grant per step, never the rejected attempt"
    );
    assert_eq!(recorded[0].step, 0);
    assert_eq!(recorded[1].step, 1);
}

/// D-421's core delegation invariant: `on_behalf_of` naming the request's
/// own requester must be refused, even when the actual clicker
/// (`decider_id`) is a legitimately allowed delegate and is not themselves
/// the requester — delegation must never manufacture a path to
/// self-approval.
#[tokio::test]
async fn decide_step_rejects_a_delegation_that_would_reach_the_requester() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let delegate = Uuid::now_v7();

    let plan = n_of_m_plan(1, 1);
    let request = submit_with_plan(
        &pool,
        "test.delegation_self_approval",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");

    // xrm_audit::approval::resolve_step_approvers would never let this
    // delegation reach `allowed_decider_ids` in the first place (it drops
    // any delegation whose to_user is the requester) — this asserts
    // decide_step ALSO refuses it directly, so a bug in that filtering can
    // never turn into an actual self-approval path.
    let result = decide_step(
        &pool,
        request.id,
        delegate,
        Some(requested_by),
        &[delegate],
        1,
        Decision::Approve,
        request.row_version,
    )
    .await;
    assert!(
        matches!(result, Err(AppError::Forbidden)),
        "on_behalf_of == requested_by must be Forbidden regardless of who actually clicked, \
         got {result:?}"
    );

    let after = get(&pool, request.id).await.expect("get");
    assert_eq!(after.status, ApprovalStatus::Pending);
    assert_eq!(
        grants(&pool, request.id).await.len(),
        0,
        "a Forbidden delegated decision must never insert a grant row"
    );
}

/// `on_timeout: auto_approve` records `decided_by = POLICY_ACTOR_ID` (the
/// "policy" sentinel), not a real user id — there was no human decider.
#[tokio::test]
async fn auto_approve_timeout_is_recorded_as_decided_by_policy() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();

    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:0".to_string()],
            sla_minutes: Some(1),
            on_timeout: OnTimeout::AutoApprove,
            extras: Default::default(),
        }],
    };
    let request = submit_with_plan(
        &pool,
        "test.auto_approve_timeout",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");
    backdate_step_started_at(&pool, request.id).await;

    let due = list_due_step_timeouts(&pool, 10)
        .await
        .expect("list_due_step_timeouts");
    assert!(
        due.contains(&request.id),
        "a step whose sla_minutes has already elapsed must be immediately due"
    );

    let (updated, outcome) = apply_step_timeout_with(&pool, request.id, &attome_db::NoHook)
        .await
        .expect("apply_step_timeout_with")
        .expect("this request's due step must have been applied");
    assert_eq!(outcome, TimeoutOutcome::AutoApproved);
    assert_eq!(updated.status, ApprovalStatus::Approved);

    let recorded = grants(&pool, request.id).await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].decision, "approved");
    assert_eq!(
        recorded[0].decided_by,
        Some(POLICY_ACTOR_ID),
        "an auto-approved timeout must record decided_by = the policy sentinel, not a human id"
    );
    assert_eq!(recorded[0].approver_id, POLICY_ACTOR_ID);
    assert_eq!(recorded[0].on_behalf_of, None);

    // Idempotent against a second tick: no longer pending, so nothing left
    // to apply.
    let second = apply_step_timeout_with(&pool, request.id, &attome_db::NoHook)
        .await
        .expect("apply_step_timeout_with");
    assert!(second.is_none());
}

/// Same `decided_by = policy` bookkeeping for `on_timeout: auto_reject`.
#[tokio::test]
async fn auto_reject_timeout_is_recorded_as_decided_by_policy() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();

    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:0".to_string()],
            sla_minutes: Some(1),
            on_timeout: OnTimeout::AutoReject,
            extras: Default::default(),
        }],
    };
    let request = submit_with_plan(
        &pool,
        "test.auto_reject_timeout",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");
    backdate_step_started_at(&pool, request.id).await;

    let (updated, outcome) = apply_step_timeout_with(&pool, request.id, &attome_db::NoHook)
        .await
        .expect("apply_step_timeout_with")
        .expect("this request's due step must have been applied");
    assert_eq!(outcome, TimeoutOutcome::AutoRejected);
    assert_eq!(updated.status, ApprovalStatus::Rejected);

    let recorded = grants(&pool, request.id).await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].decision, "rejected");
    assert_eq!(recorded[0].decided_by, Some(POLICY_ACTOR_ID));
}

/// `on_timeout: escalate` never decides anything by itself, and only fires
/// once — a second tick after `escalated_at` is already set must be a
/// no-op, so the notification sweep that consumes `Escalated` never resends
/// forever.
#[tokio::test]
async fn escalate_timeout_fires_once_and_decides_nothing() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();

    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:0".to_string()],
            sla_minutes: Some(1),
            on_timeout: OnTimeout::Escalate,
            extras: Default::default(),
        }],
    };
    let request = submit_with_plan(
        &pool,
        "test.escalate_timeout",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");
    backdate_step_started_at(&pool, request.id).await;

    let (updated, outcome) = apply_step_timeout_with(&pool, request.id, &attome_db::NoHook)
        .await
        .expect("apply_step_timeout_with")
        .expect("the due step must have been escalated");
    assert_eq!(outcome, TimeoutOutcome::Escalated);
    assert_eq!(
        updated.status,
        ApprovalStatus::Pending,
        "escalation must never decide the request"
    );
    assert!(updated.escalated_at.is_some());
    assert_eq!(
        grants(&pool, request.id).await.len(),
        0,
        "escalation must never insert a grant row"
    );

    let second = apply_step_timeout_with(&pool, request.id, &attome_db::NoHook)
        .await
        .expect("apply_step_timeout_with");
    assert!(
        second.is_none(),
        "a step already escalated must not escalate again on a later tick"
    );

    let due_after = list_due_step_timeouts(&pool, 10)
        .await
        .expect("list_due_step_timeouts");
    assert!(
        !due_after.contains(&request.id),
        "an already-escalated step must not keep showing up as due"
    );
}

fn all_of_two_plan() -> ApprovalPlan {
    ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::All,
            threshold: None,
            approvers: vec!["user:a".to_string(), "user:b".to_string()],
            sla_minutes: Some(60),
            on_timeout: OnTimeout::Escalate,
            extras: Default::default(),
        }],
    }
}

/// BAP-P0.3 / BAP-F2 (invariant A4): a step counts principals, not
/// identities. On an `all` step over {A, B}, A approving and then A's
/// delegate D approving on A's behalf fills A's slot twice; B has not
/// decided, so the request must stay `Pending`. Today `decide_step_with`
/// counts `DISTINCT approver_id`, sees 2 and approves without B.
///
/// Encodes owner decision BAP-D2 as recommended ("a principal and their
/// delegate fill one slot").
#[tokio::test]
async fn a_principal_and_their_delegate_fill_one_slot() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let delegate_of_a = Uuid::now_v7();

    let request = submit_with_plan(
        &pool,
        "test.delegate_fills_one_slot",
        json!({}),
        requested_by,
        all_of_two_plan(),
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");

    let allowed = [a, b, delegate_of_a];
    let after_a = decide_step(
        &pool,
        request.id,
        a,
        None,
        &allowed,
        2,
        Decision::Approve,
        request.row_version,
    )
    .await
    .expect("A approves");
    assert_eq!(after_a.status, ApprovalStatus::Pending);

    // The delegate acting for A must not count as a second principal. Either
    // refusing the decision or recording it without closing the step is
    // acceptable; approving the request is not.
    let after_delegate = decide_step(
        &pool,
        request.id,
        delegate_of_a,
        Some(a),
        &allowed,
        2,
        Decision::Approve,
        after_a.row_version,
    )
    .await;
    let status = get(&pool, request.id).await.expect("get").status;
    assert_eq!(
        status,
        ApprovalStatus::Pending,
        "A and A's delegate filled one slot; B has not decided, so an `all` step must stay \
         pending (delegate decision returned {after_delegate:?})"
    );
}

/// BAP-P0.4 / BAP-F3 (invariant A5): nothing is decided past `expires_at`.
/// A request whose backstop has passed, with a step SLA that has also
/// elapsed under `auto_approve`, must end `expired` with no grant row — a
/// policy timeout must never approve a request that should already have
/// died. Today `apply_step_timeout_with` never reads `expires_at` and approves it.
#[tokio::test]
async fn an_expired_request_is_not_auto_approved_by_a_step_timeout() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();

    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:a".to_string()],
            sla_minutes: Some(1),
            on_timeout: OnTimeout::AutoApprove,
            extras: Default::default(),
        }],
    };
    let request = submit_with_plan(
        &pool,
        "test.expired_not_auto_approved",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");

    backdate_step_started_at(&pool, request.id).await;
    sqlx::query(
        "UPDATE approval_request SET expires_at = NOW() - INTERVAL '1 minute' \
         WHERE id = $1",
    )
    .bind(request.id)
    .execute(&pool)
    .await
    .expect("move the backstop into the past");

    let outcome = apply_step_timeout_with(&pool, request.id, &attome_db::NoHook)
        .await
        .expect("apply_step_timeout_with must not error");
    let after = get(&pool, request.id).await.expect("get");
    assert_eq!(
        after.status,
        ApprovalStatus::Expired,
        "a request past its backstop must end expired, not be decided by a step timeout \
         (outcome was {outcome:?})"
    );
    assert!(
        grants(&pool, request.id).await.is_empty(),
        "an expired request must carry no grant row"
    );
}

/// BAP-5 (second half) / BAP-D2: the refusal is explicit. Once principal A
/// has approved, a delegate acting for A is refused with `Conflict` — not
/// recorded as a second slot, and never able to close the step.
#[tokio::test]
async fn a_delegate_cannot_refill_a_principals_slot() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let delegate_of_a = Uuid::now_v7();

    let request = submit_with_plan(
        &pool,
        "test.delegate_cannot_refill",
        json!({}),
        requested_by,
        all_of_two_plan(),
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");

    let allowed = [a, b, delegate_of_a];
    let after_a = decide_step(
        &pool,
        request.id,
        a,
        None,
        &allowed,
        2,
        Decision::Approve,
        request.row_version,
    )
    .await
    .expect("A approves");
    assert_eq!(after_a.status, ApprovalStatus::Pending);

    let err = decide_step(
        &pool,
        request.id,
        delegate_of_a,
        Some(a),
        &allowed,
        2,
        Decision::Approve,
        after_a.row_version,
    )
    .await
    .expect_err("A\'s slot is already filled");
    assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");

    assert_eq!(
        get(&pool, request.id).await.expect("get").status,
        ApprovalStatus::Pending,
        "B has still not decided"
    );
    assert_eq!(
        grants(&pool, request.id).await.len(),
        1,
        "the refused decision wrote no grant row"
    );
}

/// BAP-7 / BAP-D3: an `n_of_m` whose threshold exceeds the population the
/// step resolved to refuses every approval (`Conflict`) instead of closing
/// at the population's lower bar — a \"3 of finance\" policy is never
/// silently satisfied by 2 approvers.
#[tokio::test]
async fn an_n_of_m_above_its_population_refuses_every_approval() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();

    // A role token: its population is only known at decide time, so
    // `validate` accepts the plan and this exercises the decide-time refusal
    // (an all-`user:` 3-of-2 is refused at save time instead).
    let plan = ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::NofM,
            threshold: Some(3),
            approvers: vec!["role:finance".to_string()],
            sla_minutes: Some(60),
            on_timeout: OnTimeout::Escalate,
            extras: Default::default(),
        }],
    };
    let request = submit_with_plan(
        &pool,
        "test.n_of_m_unreachable",
        json!({}),
        requested_by,
        plan,
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");

    let allowed = [a, b];
    for decider in [a, b] {
        let current = get(&pool, request.id).await.expect("get");
        let err = decide_step(
            &pool,
            request.id,
            decider,
            None,
            &allowed,
            2,
            Decision::Approve,
            current.row_version,
        )
        .await
        .expect_err("a 3-of-2 step can never be satisfied");
        assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");
    }

    assert_eq!(
        get(&pool, request.id).await.expect("get").status,
        ApprovalStatus::Pending,
        "the step never closes at a lower bar"
    );
    assert!(grants(&pool, request.id).await.is_empty());
}

/// BAP-5 / BAP-D2 (invariant A4), the reject half: once principal A has
/// approved, A's delegate rejecting on A's behalf would spend A's authority a
/// second time and close the whole request `Rejected`. The slot check covers
/// both decisions, so it is refused with `Conflict` and nothing is recorded.
#[tokio::test]
async fn a_delegate_cannot_reject_in_a_slot_its_principal_already_approved() {
    let pool: PgPool = migrated_pool_or_skip!(10);
    let requested_by = Uuid::now_v7();
    let a = Uuid::now_v7();
    let b = Uuid::now_v7();
    let delegate_of_a = Uuid::now_v7();

    let request = submit_with_plan(
        &pool,
        "test.delegate_cannot_reject_filled_slot",
        json!({}),
        requested_by,
        all_of_two_plan(),
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan");

    let allowed = [a, b, delegate_of_a];
    let after_a = decide_step(
        &pool,
        request.id,
        a,
        None,
        &allowed,
        2,
        Decision::Approve,
        request.row_version,
    )
    .await
    .expect("A approves");
    assert_eq!(after_a.status, ApprovalStatus::Pending);

    let err = decide_step(
        &pool,
        request.id,
        delegate_of_a,
        Some(a),
        &allowed,
        2,
        Decision::Reject,
        after_a.row_version,
    )
    .await
    .expect_err("A's slot already holds A's approval");
    assert!(matches!(err, AppError::Conflict(_)), "got {err:?}");

    assert_eq!(
        get(&pool, request.id).await.expect("get").status,
        ApprovalStatus::Pending,
        "the delegate's reject must not close the request"
    );
    assert_eq!(
        grants(&pool, request.id).await.len(),
        1,
        "the refused reject wrote no grant row"
    );
}

/// BAP-8 / A9: one legacy row whose `sla_minutes` is a digit string beyond
/// `int4` (saved before `MAX_SLA_MINUTES` existed) must be skipped, not raise
/// "integer out of range" for the whole due-timeout query — every other
/// due step still fires.
#[tokio::test]
async fn an_out_of_range_sla_does_not_stop_other_timeouts_firing() {
    let pool: PgPool = migrated_pool_or_skip!(10);

    let plan = || ApprovalPlan {
        steps: vec![ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:a".to_string()],
            sla_minutes: Some(1),
            on_timeout: OnTimeout::Escalate,
            extras: Default::default(),
        }],
    };
    let bad = submit_with_plan(
        &pool,
        "test.sla_out_of_range",
        json!({}),
        Uuid::now_v7(),
        plan(),
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan (bad)");
    let good = submit_with_plan(
        &pool,
        "test.sla_out_of_range",
        json!({}),
        Uuid::now_v7(),
        plan(),
        Duration::hours(1),
        None,
    )
    .await
    .expect("submit_with_plan (good)");
    backdate_step_started_at(&pool, bad.id).await;
    backdate_step_started_at(&pool, good.id).await;
    // Simulates a legacy row directly, as no save path can produce it now.
    sqlx::query(
        "UPDATE approval_request \
         SET plan = jsonb_set(plan, '{steps,0,sla_minutes}', '99999999999'::jsonb) \
         WHERE id = $1",
    )
    .bind(bad.id)
    .execute(&pool)
    .await
    .expect("corrupt sla_minutes");

    let due = list_due_step_timeouts(&pool, 100_000).await;
    // Retire the corrupted row whatever happened, so it cannot affect a
    // later test sharing this database.
    sqlx::query("UPDATE approval_request SET status = 'expired' WHERE id = $1")
        .bind(bad.id)
        .execute(&pool)
        .await
        .expect("retire corrupted row");
    let due = due.expect("an out-of-range sla_minutes must not fail the whole query");
    assert!(
        due.contains(&good.id),
        "the well-formed due step still fires"
    );
    assert!(!due.contains(&bad.id), "the out-of-range row is skipped");
}

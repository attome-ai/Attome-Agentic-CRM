//! `attome-approval` — the generic four-eyes / dual-control primitive (D-195),
//! with its plan and step extension (D-421) and the execution claim (D-518).
//! Plan, findings and invariants: `document/base/approval/plans/attome-approval-plan.md`.
//!
//! **What it is.** The request lifecycle over `approval_request` and
//! `approval_grant`:
//! - submit: `submit`, `submit_regarding_with`, `submit_with_plan`(`_regarding_with`),
//!   and `submit_with_plan_regarding_in_tx` inside a caller's transaction
//!   (the state engine's transition approvals, D-770);
//! - decide: `decide`(`_with`) for a flat `required_approvals` request, or
//!   `decide_step`(`_with`) for a request running an ordered [`ApprovalPlan`]
//!   of `any`/`all`/`n_of_m` steps, each with an SLA and a timeout behaviour;
//! - close: `cancel`, `mark_executed`, `mark_invalidated`, `sweep_expired`,
//!   and the step timeouts `list_due_step_timeouts` / `apply_step_timeout_with`;
//! - execute exactly one caller's dispatch (D-518): `claim_execution` moves an
//!   approved request to `executing`, and only that claim closes it
//!   (`complete_execution`, `invalidate_execution`, `release_execution`). A
//!   claim past [`EXECUTION_CLAIM_LEASE_MINUTES`] has an unknown outcome and is
//!   taken over only explicitly (`take_over_stale_execution`).
//!
//! A plan-bearing request is the same row running through the same
//! lifecycle; `ApprovalRequest::plan` is `None` for a flat request. Approver
//! *resolution* (turning `"role:…"` into user ids) never happens here; it
//! lives in `xrm-audit` (see [`ApprovalPlan`]).
//!
//! **Invariants it enforces:**
//! 1. `approver != requested_by`, including through a delegation;
//! 2. every transition takes the per-request advisory lock and a `row_version`
//!    CAS, so two concurrent decisions never both win;
//! 3. automatic dispatch is at most once for callers that claim: while a claim
//!    stands, no other caller can claim, and a stale claim is never re-run
//!    without an explicit takeover.
//!
//! Every transition has a `_with` variant taking a [`attome_db::BeforeCommit`]
//! hook, so a caller's audit event commits in the same transaction (D-545).
//!
//! **What it deliberately does not do.** It never executes an action: `payload`
//! is opaque, and only the submitting flow knows how to run it. It knows no
//! `action_type`. Exactly-once *side effects* are each executor's own
//! idempotency contract; the claim only guarantees one dispatch.
//!
//! **Who calls it.** Many flows, on both sides of the base/xrm boundary, which
//! is why it lives in the base layer:
//! - `xrm-server`: the admin and eligible-approver routes and their dispatcher
//!   (`approval_admin`, which claims before running any of the action types in
//!   its `has_execution_handler`), approval policies, My Work providers,
//!   sign-off, duplicates, and the expiry metrics sweep;
//! - `xrm-audit` (the gate and approver resolution), `xrm-ai` (agent actions and
//!   the conversation event log), `xrm-workflow` (approval nodes and the SLA
//!   sweep), `xrm-notification` (the step-timeout poller), `xrm-security`,
//!   `xrm-content`, `xrm-project`, `xrm-state` and `xrm-entity-engine` (state
//!   transition approvals, D-770), and `trd-engine` (promotion and kill-switch
//!   release, which close through `mark_executed` without claiming).

use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

/// Advisory-lock namespace for every key this crate takes under the
/// `"attome-approval/…"` prefix (guidelines §2's
/// `"{crate}/{operation}:{resource}"` convention). Bound as the first
/// argument of the two-argument `pg_try_advisory_xact_lock($1, hashtext($2))`
/// so a `hashtext` collision between two unrelated keys can only happen
/// *within* this subsystem, never across subsystems — before this existed,
/// `hashtext`'s single `int4` space was shared by every lock in the
/// workspace, so a per-record approval key could collide with, say, a
/// registration's email key and bounce an unrelated request with a spurious
/// `Conflict` (L-1 / TODO-027).
///
/// The workspace-wide assignment table, and the test that proves the ids stay
/// distinct, live in `crates/server/tests/advisory_lock_namespaces.rs`. Never
/// reuse or renumber an id.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Executed,
    /// The original requester withdrew this request while it was still
    /// `Pending` — added by migration `0073_approval_request_cancelled_
    /// status.sql` (0070 itself is immutable, guidelines §4). Distinct from
    /// `Rejected`: a rejection is a different admin's decision; a
    /// cancellation is the requester's own, and never counts as anyone
    /// else's decision (`cancel()` does not touch `approval_grant`).
    Cancelled,
    /// Approved, but the caller's execution-time revalidation refused to run
    /// it — the requester's authorization, or the conditions the action
    /// depends on, changed between the request and its execution (see
    /// [`mark_invalidated`]). Terminal: an invalidated request never becomes
    /// executable again, even if the condition that invalidated it is later
    /// restored. Added by migration `0458`.
    Invalidated,
    /// Approved, and one caller has claimed it to run its action (D-518,
    /// migration `0468`): [`claim_execution`] moved it here from `Approved`,
    /// and only that claim can close it — as `Executed`, as `Invalidated`, or
    /// released back to `Approved`. A claim past
    /// [`EXECUTION_CLAIM_LEASE_MINUTES`] has an unknown outcome and is only
    /// ever taken over explicitly ([`take_over_stale_execution`]).
    Executing,
}

impl ApprovalStatus {
    /// The wire name this status is stored under in
    /// `approval_request.status` and returns to a caller. Public so
    /// an HTTP layer can build a status filter from the same vocabulary the
    /// database uses instead of a hand-maintained copy.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Invalidated => "invalidated",
            Self::Executing => "executing",
        }
    }

    /// Parses a status wire name as *caller input*, so an unknown one is a
    /// `422 Validation` naming it rather than `FromStr`'s masked `Internal`
    /// (which is for a corrupt stored row). Used by the admin list filter.
    pub fn parse_wire(s: &str) -> Result<Self, AppError> {
        <Self as std::str::FromStr>::from_str(s)
            .map_err(|_| AppError::Validation(format!("unknown approval status {s:?}")))
    }
}

impl std::str::FromStr for ApprovalStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "expired" => Ok(Self::Expired),
            "executed" => Ok(Self::Executed),
            "cancelled" => Ok(Self::Cancelled),
            "invalidated" => Ok(Self::Invalidated),
            "executing" => Ok(Self::Executing),
            other => Err(AppError::internal(format!(
                "corrupt approval_request.status: {other:?}"
            ))),
        }
    }
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One approver's decision on a request. Distinct from `ApprovalStatus`:
/// this is what a single `approval_grant` row records, not what the
/// parent request's aggregate state is (a `Decision::Approve` under an
/// `required_approvals > 1` policy doesn't necessarily flip the request to
/// `ApprovalStatus::Approved` by itself — see `decide()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Reject,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approved",
            Self::Reject => "rejected",
        }
    }
}

/// Longest decision comment [`decide_with`]/[`decide_step_with`] accept, in
/// characters (not bytes). Mirrored by migration 0498's CHECK on
/// `approval_grant.comment`, which is only the backstop.
pub const MAX_DECISION_COMMENT_CHARS: usize = 2000;

/// Normalizes an approver's optional decision comment: surrounding
/// whitespace is trimmed, an empty or whitespace-only comment is no comment
/// (`None`), and one longer than [`MAX_DECISION_COMMENT_CHARS`] characters
/// is a `422 Validation`. Public so an HTTP layer can reject a bad comment
/// before it reads anything, with the same rule the decision path applies.
pub fn normalize_decision_comment(comment: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(trimmed) = comment.map(str::trim).filter(|c| !c.is_empty()) else {
        return Ok(None);
    };
    if trimmed.chars().count() > MAX_DECISION_COMMENT_CHARS {
        return Err(AppError::Validation(format!(
            "comment must be at most {MAX_DECISION_COMMENT_CHARS} characters"
        )));
    }
    Ok(Some(trimmed.to_owned()))
}

/// D-421 / M10 (Approval & Governance) — an ordered set of approval steps,
/// persisted on the request as `plan JSONB` (migration
/// `0185_approval_request_plan_step.sql`). This is a **pure extension** of
/// D-195's primitive, not a second one (guidelines §13): a plan-bearing
/// request is still one `approval_request` row running through
/// `submit`/`decide`/`sweep_expired`'s same lifecycle machinery — a plan just
/// tells `decide_step` how many steps there are and what each one requires,
/// instead of the flat `required_approvals` count every pre-D-421 caller
/// still uses unchanged.
///
/// `mode`/`approvers` (`any`/`all`/`n_of_m` over a list of opaque tokens) is
/// generic dual-control sequencing — this crate owns it because it never has
/// to interpret a token to run the math. **What it must never do** is turn a
/// token like `"role:finance_manager"` or `"position:manager_of_requester"`
/// into an actual user id — that resolution is XRM metadata knowledge
/// (roles, teams, org structure) this crate has none of (guidelines §1), so
/// it stays in `xrm_audit::approval::resolve_step_approvers` (ARCH-5's same
/// split: attome-approval runs the lifecycle, the engine layer resolves what
/// its own tokens mean). Every function below that needs "who may decide
/// this step" therefore takes an already-resolved `&[Uuid]`/`usize` from the
/// caller — it never touches `approvers` itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ApprovalPlan {
    pub steps: Vec<ApprovalStep>,
}

/// BAP-16 / BAP-D6 — the upper bounds `ApprovalPlan::validate` enforces.
/// An approval policy is configuration an admin saves once and every later
/// submission of its `action_type` replays; an unbounded step count, an
/// unbounded approver list, or an `sla_minutes` near `i64::MAX` is not a
/// heavier plan, it is a plan that panics (chrono's `TimeDelta::minutes`
/// and `DateTime + TimeDelta` both panic out of range) on every gated
/// submission until someone edits the policy. These caps are far above any
/// real policy and far below chrono's limits.
pub const MAX_PLAN_STEPS: usize = 10;
/// See [`MAX_PLAN_STEPS`].
pub const MAX_STEP_APPROVERS: usize = 50;
/// One year, in minutes — see [`MAX_PLAN_STEPS`].
pub const MAX_SLA_MINUTES: i64 = 525_600;

impl ApprovalPlan {
    /// Structural validation only — never evaluates `approvers` tokens
    /// (that needs XRM metadata this crate doesn't have) or anything about
    /// the M45 `condition` a policy might carry (that lives on
    /// `xrm_core_approval_policy`, one layer up, and is itself unevaluated
    /// until M45 Phase 2 ships). Called by the admin handler that saves a
    /// policy's plan, and by `submit_with_plan` as a last line of defense
    /// against a caller that built one by hand.
    ///
    /// Bounds both ends of every input (BAP-16): at least one step, at most
    /// [`MAX_PLAN_STEPS`]; at least one approver token per step, at most
    /// [`MAX_STEP_APPROVERS`]; an `sla_minutes`, when set, between 1 and
    /// [`MAX_SLA_MINUTES`].
    pub fn validate(&self) -> Result<(), AppError> {
        if self.steps.is_empty() {
            return Err(AppError::Validation(
                "an approval plan must have at least one step".to_string(),
            ));
        }
        if self.steps.len() > MAX_PLAN_STEPS {
            return Err(AppError::Validation(format!(
                "an approval plan must have at most {MAX_PLAN_STEPS} steps (it has {})",
                self.steps.len()
            )));
        }
        for (i, step) in self.steps.iter().enumerate() {
            if step.approvers.is_empty() {
                return Err(AppError::Validation(format!(
                    "plan step {i} has no approvers"
                )));
            }
            if step.approvers.len() > MAX_STEP_APPROVERS {
                return Err(AppError::Validation(format!(
                    "plan step {i} has {} approvers; the maximum is {MAX_STEP_APPROVERS}",
                    step.approvers.len()
                )));
            }
            if step.mode == StepMode::NofM {
                match step.threshold {
                    Some(n) if n >= 1 => {
                        // BAP-7 / BAP-D3: when every token names one user,
                        // the step's population is known at save time, so a
                        // threshold above it can never be met — and saving
                        // it would leave the step to its `on_timeout`
                        // (possibly `auto_approve`, with no human at all).
                        // Role, team and position tokens resolve at decide
                        // time instead, where `required_count` refuses the
                        // same case. Distinct tokens: a repeated `user:` token
                        // is still one principal.
                        if step.approvers.iter().all(|t| t.starts_with("user:")) {
                            let named: std::collections::HashSet<&str> =
                                step.approvers.iter().map(String::as_str).collect();
                            if usize::try_from(n).unwrap_or(usize::MAX) > named.len() {
                                return Err(AppError::Validation(format!(
                                    "plan step {i} needs {n} approvals but names only {} \
                                     distinct approver(s)",
                                    named.len()
                                )));
                            }
                        }
                    }
                    _ => {
                        return Err(AppError::Validation(format!(
                            "plan step {i} uses n_of_m and needs threshold >= 1"
                        )));
                    }
                }
            }
            let extras = &step.extras;
            if extras
                .skip_unless
                .as_ref()
                .is_some_and(|e| e.chars().count() > MAX_SKIP_UNLESS_CHARS)
            {
                return Err(AppError::Validation(format!(
                    "plan step {i} skip_unless is longer than {MAX_SKIP_UNLESS_CHARS} characters"
                )));
            }
            if let Some(reminder) = extras.reminder_minutes {
                if !(1..=MAX_SLA_MINUTES).contains(&reminder) {
                    return Err(AppError::Validation(format!(
                        "plan step {i} reminder_minutes must be between 1 and {MAX_SLA_MINUTES}"
                    )));
                }
                if step.sla_minutes.is_some_and(|sla| reminder >= sla) {
                    return Err(AppError::Validation(format!(
                        "plan step {i} reminder_minutes must come before sla_minutes"
                    )));
                }
            }
            if extras.requires_signature && !extras.requires_human {
                return Err(AppError::Validation(format!(
                    "plan step {i} needs a signature, so a person must decide it"
                )));
            }
            if let Some(sla) = step.sla_minutes {
                if sla < 1 {
                    return Err(AppError::Validation(format!(
                        "plan step {i} sla_minutes must be >= 1 when set"
                    )));
                }
                if sla > MAX_SLA_MINUTES {
                    return Err(AppError::Validation(format!(
                        "plan step {i} sla_minutes must be at most {MAX_SLA_MINUTES} (one year)"
                    )));
                }
            }
        }
        self.validate_groups()
    }

    /// Z10-T2: a group's steps are consecutive and time out the same way.
    fn validate_groups(&self) -> Result<(), AppError> {
        let mut closed: std::collections::HashSet<u16> = std::collections::HashSet::new();
        let mut current: Option<u16> = None;
        for (i, step) in self.steps.iter().enumerate() {
            let group = step.extras.group;
            if group != current {
                if let Some(done) = current {
                    closed.insert(done);
                }
                if let Some(g) = group
                    && closed.contains(&g)
                {
                    return Err(AppError::Validation(format!(
                        "plan step {i} rejoins group {g}; a group's steps must be consecutive"
                    )));
                }
                current = group;
            } else if group.is_some() && self.steps[i - 1].on_timeout != step.on_timeout {
                return Err(AppError::Validation(format!(
                    "plan step {i} times out differently from the rest of its group"
                )));
            }
        }
        Ok(())
    }

    /// Z10-T2: the steps that run together with `step` — the consecutive
    /// steps sharing its group, or just itself.
    pub fn stage_of(&self, step: usize) -> std::ops::Range<usize> {
        let Some(group) = self.steps.get(step).and_then(|s| s.extras.group) else {
            return step..step + 1;
        };
        let mut start = step;
        while start > 0 && self.steps[start - 1].extras.group == Some(group) {
            start -= 1;
        }
        let mut end = step + 1;
        while end < self.steps.len() && self.steps[end].extras.group == Some(group) {
            end += 1;
        }
        start..end
    }
}

/// One step of an [`ApprovalPlan`]. Parallel = a step with `mode: all`;
/// sequential = multiple steps — `decide_step` only advances to `steps[n+1]`
/// once `steps[n]` itself is satisfied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ApprovalStep {
    pub mode: StepMode,
    /// Required only when `mode == NofM` — how many of this step's *named*
    /// approvers (not counting any delegate standing in for one of them,
    /// see `ApprovalStep::required_count`'s doc comment) must decide before
    /// the step closes. Ignored for `Any`/`All`.
    #[serde(default)]
    pub threshold: Option<i32>,
    /// Opaque tokens this crate never parses — e.g. `"user:<uuid>"`,
    /// `"role:<uuid>"`. See the module-level doc comment above.
    pub approvers: Vec<String>,
    /// `None` means this step never times out on its own — it waits
    /// indefinitely for a human decision (still subject to the request's
    /// overall backstop `expires_at`/`sweep_expired`, see
    /// `submit_with_plan`'s doc comment).
    pub sla_minutes: Option<i64>,
    #[serde(default)]
    pub on_timeout: OnTimeout,
    /// Z10-T2: conditions, grouping, evidence and reminders. Flattened, so
    /// the JSON keys sit on the step itself and a plan stored before them
    /// reads with every default.
    #[serde(flatten)]
    pub extras: StepExtras,
}

/// Z10-T2: what a step may add to who decides it and how.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct StepExtras {
    /// A rules expression; the step runs only when it is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_unless: Option<String>,
    /// Consecutive steps with the same group run together, in parallel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<u16>,
    /// The decider confirms with a fresh sign-in or second factor.
    #[serde(default, skip_serializing_if = "is_false")]
    pub requires_step_up: bool,
    /// The decision is signed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub requires_signature: bool,
    /// A person decides, never an agent.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub requires_human: bool,
    /// Remind the approvers this long after the step started waiting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reminder_minutes: Option<i64>,
    /// Who an escalation goes to (an approver token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalate_to: Option<String>,
    /// SLA and reminder minutes count business hours only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub business_hours: bool,
}

fn default_true() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Default for StepExtras {
    fn default() -> Self {
        Self {
            skip_unless: None,
            group: None,
            requires_step_up: false,
            requires_signature: false,
            requires_human: true,
            reminder_minutes: None,
            escalate_to: None,
            business_hours: false,
        }
    }
}

/// The longest `skip_unless` expression a step takes.
pub const MAX_SKIP_UNLESS_CHARS: usize = 2000;

impl ApprovalStep {
    /// How many *distinct decisions* this step needs before it closes,
    /// given `population` — the number of distinct named principals this
    /// step's `approvers` tokens resolved to (after removing the request's
    /// own `requested_by`, per `xrm_audit::approval::resolve_step_approvers`).
    ///
    /// A delegate standing in for one of those principals still only ever
    /// contributes one distinct decision under that principal's slot — this
    /// deliberately does not let one person holding two delegations satisfy
    /// two of an `All` step's slots by clicking once each under a different
    /// identity than the principal (there is only one identity: theirs).
    /// `decide_step_with` counts `COALESCE(on_behalf_of, approver_id)` — the
    /// same slot rule — so the count this returns and the count it compares
    /// against always agree (BAP-5, BAP-D2).
    ///
    /// **Fails closed** (BAP-7, BAP-D3). A step that resolves to nobody
    /// (`population == 0`), or an `n_of_m` whose `threshold` exceeds the
    /// population it may draw from, is not silently clamped down to what
    /// today's eligible approvers can reach: lowering the bar a policy states
    /// is an audited policy edit, never a side effect of who happens to hold
    /// the roles at this instant. The caller surfaces this as a `Conflict`.
    pub fn required_count(&self, population: usize) -> Result<i32, AppError> {
        if population == 0 {
            return Err(AppError::Conflict(
                "this step cannot be satisfied by the currently eligible approvers",
            ));
        }
        let population = i32::try_from(population).unwrap_or(i32::MAX);
        match self.mode {
            StepMode::Any => Ok(1),
            StepMode::All => Ok(population),
            StepMode::NofM => {
                let n = self.threshold.ok_or_else(|| {
                    AppError::internal("n_of_m step reached decide_step with no threshold")
                })?;
                if n < 1 || n > population {
                    return Err(AppError::Conflict(
                        "this step cannot be satisfied by the currently eligible approvers",
                    ));
                }
                Ok(n)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepMode {
    /// One decision from any named approver closes the step.
    Any,
    /// Every named approver (after removing the requester) must decide.
    All,
    /// `threshold` distinct decisions out of the named approvers.
    NofM,
}

/// What happens when a step's `sla_minutes` elapses with nobody having
/// decided it yet — applied by `apply_step_timeout_with`, driven by the sweep
/// that reuses M51's notification-escalation poller
/// (`xrm_notification::poller`; see that crate's `approval_timeouts` module).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnTimeout {
    /// Fires a notification to the step's eligible approvers once (tracked
    /// by `escalated_at` so the sweep never resends it every tick) and
    /// otherwise leaves the request exactly as it was — still waiting for a
    /// human. The only outcome that does not itself decide anything.
    #[default]
    Escalate,
    /// The step (and, if it was the last one, the whole request) is decided
    /// as if it had just received its required approvals — but by policy,
    /// not a human. Recorded with `decided_by = attome_approval::POLICY_ACTOR_ID`.
    AutoApprove,
    /// The whole request is rejected, same `decided_by = POLICY_ACTOR_ID`
    /// bookkeeping as `AutoApprove`.
    AutoReject,
}

/// What `apply_step_timeout_with` actually did — returned so the caller (the
/// notification-poller sweep) knows whether to send an escalation
/// notification (`Escalated`) or nothing further (the others are already
/// terminal/advanced and their own audit event is the caller's job either
/// way).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutOutcome {
    Escalated,
    AutoApproved,
    AutoRejected,
    /// BAP-6a / BAP-F3 (invariant A5): the request was already past its
    /// overall `expires_at` backstop when the step SLA elapsed, so it was
    /// set `expired` instead of being auto-decided. A policy timeout must
    /// never decide a request that should already have died.
    Expired,
}

/// Sentinel `approval_grant.approver_id`/`decided_by` for a decision
/// `apply_step_timeout_with` recorded automatically — there is no real human
/// decider to name. Not a valid `xrm_core_systemuser` row; a caller building
/// an audit event or display label for this actor uses a synthetic one
/// (`"policy"`), never a user lookup.
pub const POLICY_ACTOR_ID: Uuid = Uuid::nil();

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub action_type: String,
    pub payload: Value,
    pub requested_by: Uuid,
    pub requested_at: DateTime<Utc>,
    pub status: ApprovalStatus,
    pub required_approvals: i32,
    pub row_version: i64,
    pub expires_at: DateTime<Utc>,
    pub executed_at: Option<DateTime<Utc>>,
    /// `Some` only for a request submitted via `submit_with_plan` (D-421).
    /// `None` means this request runs the original flat
    /// `required_approvals` model unchanged — every pre-D-421 caller keeps
    /// working exactly as before.
    pub plan: Option<ApprovalPlan>,
    /// Index into `plan.steps` of the step currently awaiting decisions.
    /// Meaningless (always `0`) when `plan` is `None`.
    pub step: i32,
    /// When the current step started waiting — the base its `sla_minutes`
    /// counts from. `None` when `plan` is `None`.
    pub step_started_at: Option<DateTime<Utc>>,
    /// Set once the current step's `on_timeout: escalate` has actually
    /// fired, so the sweep never re-escalates the same step every tick.
    /// Cleared back to `None` whenever the step advances.
    pub escalated_at: Option<DateTime<Utc>>,
    /// The `xrm_core_approval_policy` id that supplied `plan`, when any did.
    /// Carried opaquely — see `submit_with_plan`'s doc comment.
    pub policy_id: Option<Uuid>,
    /// Dashboard 10/10 Phase 6 prerequisite (migration 0477) — the record
    /// this request is *about*, so a caller can run record-level access
    /// checks against it before showing the request as actionable. `None`
    /// for every `gate()` caller that has not opted in yet (an
    /// unpopulated pointer, not an error — see the migration's own doc
    /// comment). Same polymorphic-target shape as `xrm_core_outcome`'s and
    /// `xrm_dashboard_decision`'s own `regarding_entity`/`regarding_id`.
    pub regarding_entity: Option<String>,
    pub regarding_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct ApprovalRequestRow {
    id: Uuid,
    action_type: String,
    payload: Value,
    requested_by: Uuid,
    requested_at: DateTime<Utc>,
    status: String,
    required_approvals: i32,
    row_version: i64,
    expires_at: DateTime<Utc>,
    executed_at: Option<DateTime<Utc>>,
    plan: Option<Value>,
    step: i32,
    step_started_at: Option<DateTime<Utc>>,
    escalated_at: Option<DateTime<Utc>>,
    policy_id: Option<Uuid>,
    regarding_entity: Option<String>,
    regarding_id: Option<Uuid>,
}

impl TryFrom<ApprovalRequestRow> for ApprovalRequest {
    type Error = AppError;

    fn try_from(row: ApprovalRequestRow) -> Result<Self, AppError> {
        let plan = row
            .plan
            .map(serde_json::from_value::<ApprovalPlan>)
            .transpose()
            .map_err(|e| AppError::internal(format!("corrupt approval_request.plan: {e}")))?;
        Ok(Self {
            id: row.id,
            action_type: row.action_type,
            payload: row.payload,
            requested_by: row.requested_by,
            requested_at: row.requested_at,
            status: row.status.parse()?,
            required_approvals: row.required_approvals,
            row_version: row.row_version,
            expires_at: row.expires_at,
            executed_at: row.executed_at,
            plan,
            step: row.step,
            step_started_at: row.step_started_at,
            escalated_at: row.escalated_at,
            policy_id: row.policy_id,
            regarding_entity: row.regarding_entity,
            regarding_id: row.regarding_id,
        })
    }
}

const REQUEST_COLUMNS: &str = "id, action_type, payload, requested_by, requested_at, status, \
     required_approvals, row_version, expires_at, executed_at, plan, step, step_started_at, \
     escalated_at, policy_id, regarding_entity, regarding_id";

/// Enqueues a new pending approval request instead of the caller executing
/// its mutation inline. `required_approvals` lets a future N-of-M policy
/// raise the bar above plain two-person dual control — every caller wired
/// today passes `1` (the same distinct approver reaching the count once is
/// enough to close it). `ttl` bounds how long the request stays decidable;
/// `sweep_expired` reaps anything still `pending` past `expires_at` so a
/// forgotten request never becomes a silent standing approval.
pub async fn submit(
    pool: &PgPool,
    action_type: &str,
    payload: Value,
    requested_by: Uuid,
    required_approvals: i32,
    ttl: Duration,
) -> Result<ApprovalRequest, AppError> {
    submit_regarding_with(
        pool,
        action_type,
        payload,
        requested_by,
        required_approvals,
        ttl,
        None,
        &attome_db::NoHook,
    )
    .await
}

/// [`submit`] with a "regarding" record pointer (migration 0477) — the
/// caller's own choice of which record, if any, this request is about —
/// and a [`attome_db::BeforeCommit`] hook, which runs
/// inside the insert's own transaction with the request as it will be
/// returned (BAP-19a, D-545). A caller whose request needs an audit event
/// (`xrm_audit::approval::gate`'s `Submitted`) hands it here, so a crash or a
/// failed audit write between the insert and the event leaves *neither* —
/// before this, the event was a separate transaction after the request had
/// already committed.
#[allow(clippy::too_many_arguments)]
pub async fn submit_regarding_with(
    pool: &PgPool,
    action_type: &str,
    payload: Value,
    requested_by: Uuid,
    required_approvals: i32,
    ttl: Duration,
    regarding: Option<(&str, Uuid)>,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    if required_approvals < 1 {
        return Err(AppError::Validation(
            "required_approvals must be at least 1".to_string(),
        ));
    }
    let id = Uuid::now_v7();
    // BAP-16: a `ttl` far enough out to overflow `DateTime` is a 422, not a
    // panic — `DateTime + TimeDelta` panics out of range (chrono 0.4.45).
    let expires_at = Utc::now()
        .checked_add_signed(ttl)
        .ok_or_else(|| AppError::Validation("ttl is out of range".to_string()))?;
    let (regarding_entity, regarding_id) = match regarding {
        Some((entity, record_id)) => (Some(entity), Some(record_id)),
        None => (None, None),
    };
    let mut tx = attome_db::tx::begin(pool).await?;
    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "INSERT INTO approval_request \
             (id, action_type, payload, requested_by, status, required_approvals, row_version, \
              expires_at, regarding_entity, regarding_id) \
         VALUES ($1, $2, $3, $4, 'pending', $5, 0, $6, $7, $8) \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(id)
    .bind(action_type)
    .bind(&payload)
    .bind(requested_by)
    .bind(required_approvals)
    .bind(expires_at)
    .bind(regarding_entity)
    .bind(regarding_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let request: ApprovalRequest = row.try_into()?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(
        request_id = %request.id,
        action_type = %request.action_type,
        to = %request.status,
        "approval request submitted",
    );
    Ok(request)
}

/// D-421's plan-aware sibling of [`submit`] — same insert, but the request
/// carries an [`ApprovalPlan`] and starts at step 0 instead of the flat
/// `required_approvals` model (`required_approvals` is still stored as `1`,
/// purely to satisfy that column's own `CHECK (>= 1)`; it is not read once a
/// request has a plan — see `decide_step`).
///
/// `backstop_ttl` is deliberately **not** the same thing as any one step's
/// `sla_minutes` — those are handled by `apply_step_timeout_with`'s per-step
/// on_timeout logic, independent of this. It is the same safety net
/// `submit`'s `ttl` always was: `sweep_expired` still reaps this request
/// (regardless of what step it's on) if it is ever left `pending` past
/// `expires_at`, so a plan whose per-step SLAs are misconfigured (or whose
/// timeout sweep stops running) cannot become a silent standing approval
/// forever. The caller (`xrm_audit::approval::gate`/the workflow approval
/// node) picks a generous value — e.g. the sum of every step's
/// `sla_minutes`, plus slack — not a tight one.
///
/// `policy_id` names the `xrm_core_approval_policy` row (if any) that
/// supplied `plan` — carried opaquely (this crate never reads it back), same
/// as `action_type` itself, purely so the caller doesn't need a second round
/// trip to stamp provenance on the row it just created.
#[allow(clippy::too_many_arguments)]
pub async fn submit_with_plan(
    pool: &PgPool,
    action_type: &str,
    payload: Value,
    requested_by: Uuid,
    plan: ApprovalPlan,
    backstop_ttl: Duration,
    policy_id: Option<Uuid>,
) -> Result<ApprovalRequest, AppError> {
    submit_with_plan_regarding_with(
        pool,
        action_type,
        payload,
        requested_by,
        plan,
        backstop_ttl,
        policy_id,
        None,
        &attome_db::NoHook,
    )
    .await
}

/// [`submit_with_plan`] with a "regarding" record pointer and a
/// [`attome_db::BeforeCommit`] hook — the plan-bearing twin of
/// [`submit_regarding_with`], same atomicity contract (BAP-19a).
#[allow(clippy::too_many_arguments)]
pub async fn submit_with_plan_regarding_with(
    pool: &PgPool,
    action_type: &str,
    payload: Value,
    requested_by: Uuid,
    plan: ApprovalPlan,
    backstop_ttl: Duration,
    policy_id: Option<Uuid>,
    regarding: Option<(&str, Uuid)>,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let mut tx = attome_db::tx::begin(pool).await?;
    let request = submit_with_plan_regarding_in_tx(
        &mut tx,
        action_type,
        payload,
        requested_by,
        plan,
        backstop_ttl,
        policy_id,
        regarding,
    )
    .await?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(
        request_id = %request.id,
        action_type = %request.action_type,
        to = %request.status,
        "approval request submitted",
    );
    Ok(request)
}

/// [`submit_with_plan_regarding_with`]'s insert, inside the **caller's**
/// transaction (M07 Phase F, D-770). For a flow whose own write and the
/// request that gates its next step must commit together or not at all — the
/// state engine moves a record into its transition's `pending_state` and
/// submits the approval regarding that record in one transaction, so a
/// record can never sit pending with no request, nor a request exist for a
/// move that rolled back. The caller owns the commit and any audit event;
/// the plan is validated here exactly as on the pool-owning path.
#[allow(clippy::too_many_arguments)]
pub async fn submit_with_plan_regarding_in_tx(
    tx: &mut attome_db::Tx<'_>,
    action_type: &str,
    payload: Value,
    requested_by: Uuid,
    plan: ApprovalPlan,
    backstop_ttl: Duration,
    policy_id: Option<Uuid>,
    regarding: Option<(&str, Uuid)>,
) -> Result<ApprovalRequest, AppError> {
    plan.validate()?;
    let id = Uuid::now_v7();
    // BAP-16: same checked arithmetic as `submit_regarding_with` — a backstop TTL
    // that overflows `DateTime` (a plan whose steps each carry a legal but
    // enormous SLA, summed by the caller) is a 422, never a panic.
    let expires_at = Utc::now()
        .checked_add_signed(backstop_ttl)
        .ok_or_else(|| AppError::Validation("backstop ttl is out of range".to_string()))?;
    let plan_json = serde_json::to_value(&plan).map_err(AppError::internal)?;
    let (regarding_entity, regarding_id) = match regarding {
        Some((entity, record_id)) => (Some(entity), Some(record_id)),
        None => (None, None),
    };
    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "INSERT INTO approval_request \
             (id, action_type, payload, requested_by, status, required_approvals, row_version, \
              expires_at, plan, step, step_started_at, policy_id, regarding_entity, regarding_id) \
         VALUES ($1, $2, $3, $4, 'pending', 1, 0, $5, $6, 0, NOW(), $7, $8, $9) \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(id)
    .bind(action_type)
    .bind(&payload)
    .bind(requested_by)
    .bind(expires_at)
    .bind(&plan_json)
    .bind(policy_id)
    .bind(regarding_entity)
    .bind(regarding_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    row.try_into()
}

pub async fn get(pool: &PgPool, id: Uuid) -> Result<ApprovalRequest, AppError> {
    get_with(pool, id).await
}

/// [`get`] on any executor — a pool, or a caller's open transaction so the
/// read sees that transaction's own view (M07 Phase F: the state engine
/// checks, inside the record write that settles a request, that the request
/// is in the status the move claims).
pub async fn get_with<'e, E>(executor: E, id: Uuid) -> Result<ApprovalRequest, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM approval_request WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    row.try_into()
}

/// The newest request of `action_type` regarding `(entity, record_id)`, in
/// any status — `None` when there is none. Ids are UUIDv7, so the highest id
/// is the latest submission. M07 Phase F uses it to tell which request a
/// record's pending state belongs to: only the latest one may move the
/// record, so a stale request from an earlier round can never act on it.
/// Served by `approval_request_regarding_idx` (migration 0477).
pub async fn latest_regarding_with<'e, E>(
    executor: E,
    action_type: &str,
    entity: &str,
    record_id: Uuid,
) -> Result<Option<ApprovalRequest>, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let row: Option<ApprovalRequestRow> = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM approval_request \
         WHERE regarding_entity = $1 AND regarding_id = $2 AND action_type = $3 \
         ORDER BY id DESC LIMIT 1"
    ))
    .bind(entity)
    .bind(record_id)
    .bind(action_type)
    .fetch_optional(executor)
    .await
    .map_err(AppError::internal)?;
    row.map(TryInto::try_into).transpose()
}

/// Lists requests in any of `statuses`, newest-first, optionally filtered to
/// one `action_type`. Returns `(items, total)` — callers wrap this into
/// `attome_types::PaginatedResponse` (guidelines §12) at the HTTP boundary;
/// this crate has no HTTP-shape knowledge of its own.
///
/// BAP-10 / BAP-F8: the operability listing the plan asks for —
/// approved-but-unexecuted (`&[ApprovalStatus::Approved]`) and claimed
/// (`&[ApprovalStatus::Executing]`) requests were previously visible only by
/// id. `statuses` is matched with `= ANY`, so a slice matching nothing
/// returns an empty page rather than every row; pass the statuses you mean.
pub async fn list_by_status(
    pool: &PgPool,
    statuses: &[ApprovalStatus],
    action_type: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<(Vec<ApprovalRequest>, i64), AppError> {
    let page = page.max(1);
    let page_size = page_size.max(0);
    // BAP-17 / BAP-F12: `(page - 1) * page_size` overflows i64 for an absurd
    // `page` (a release build wraps to a negative `OFFSET` Postgres rejects as
    // a 500; a debug build panics). Overflow means "past the end of the
    // result set", so it answers an empty page — with the real total — never
    // an error the caller cannot act on.
    let offset = page
        .checked_sub(1)
        .and_then(|before| before.checked_mul(page_size));
    let statuses: Vec<&str> = statuses.iter().map(|s| s.as_str()).collect();

    let rows: Vec<ApprovalRequestRow> = match offset {
        Some(offset) => sqlx::query_as(&format!(
            "SELECT {REQUEST_COLUMNS} FROM approval_request \
             WHERE status = ANY($1) AND ($2::text IS NULL OR action_type = $2) \
             ORDER BY requested_at DESC OFFSET $3 LIMIT $4"
        ))
        .bind(&statuses)
        .bind(action_type)
        .bind(offset)
        .bind(page_size)
        .fetch_all(pool)
        .await
        .map_err(AppError::internal)?,
        None => Vec::new(),
    };

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_request \
         WHERE status = ANY($1) AND ($2::text IS NULL OR action_type = $2)",
    )
    .bind(&statuses)
    .bind(action_type)
    .fetch_one(pool)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(TryInto::try_into)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((items, total))
}

/// Lists `pending` requests — [`list_by_status`] with exactly that one
/// status, so every existing caller keeps its behavior (and its BAP-17
/// overflow handling) unchanged.
pub async fn list_pending(
    pool: &PgPool,
    action_type: Option<&str>,
    page: i64,
    page_size: i64,
) -> Result<(Vec<ApprovalRequest>, i64), AppError> {
    list_by_status(
        pool,
        &[ApprovalStatus::Pending],
        action_type,
        page,
        page_size,
    )
    .await
}

/// Records one approver's decision. Inside a single transaction guarded by
/// `pg_try_advisory_xact_lock` (guidelines §2 Layer 2, namespace
/// `"attome-approval/decide:{request_id}"`) plus `SELECT ... FOR UPDATE` and a
/// `row_version` CAS (guidelines §2's optimistic-concurrency rule), this
/// enforces:
///
/// - the request is still `pending` and not past `expires_at` (a request
///   that has just expired is bounced back as `Conflict` — and flipped to
///   `Expired` in the same transaction — rather than silently decided),
/// - `approver_id != requested_by` — the separation-of-duties check this
///   whole crate exists for; a caller can never approve its own request,
/// - `expected_row_version` matches the current row.
///
/// A `Reject` always immediately closes the request — one rejection is
/// enough to kill it, there is no "N distinct rejecters" threshold. An
/// `Approve` only flips the request to `Approved` once the number of
/// *distinct* approvers who have approved it reaches `required_approvals`.
pub async fn decide(
    pool: &PgPool,
    request_id: Uuid,
    approver_id: Uuid,
    decision: Decision,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    decide_with(
        pool,
        request_id,
        approver_id,
        decision,
        expected_row_version,
        None,
        &attome_db::NoHook,
    )
    .await
}

/// [`decide`], plus the approver's optional `comment` (normalized by
/// [`normalize_decision_comment`] and stored on the grant row) and a hook
/// that runs inside the decision's transaction just before it commits, with
/// the request as it will be returned ([`attome_db::BeforeCommit`]). An `Err`
/// from the hook rolls the decision back. The hook does not run on any
/// refusal, including the expired path.
pub async fn decide_with(
    pool: &PgPool,
    request_id: Uuid,
    approver_id: Uuid,
    decision: Decision,
    expected_row_version: i64,
    comment: Option<&str>,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let comment = normalize_decision_comment(comment)?;
    let mut tx = attome_db::tx::begin(pool).await?;

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-approval/decide:{request_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another decision on this approval request is already in progress",
        ));
    }

    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM approval_request WHERE id = $1 FOR UPDATE"
    ))
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let current: ApprovalRequest = row.try_into()?;

    if current.status != ApprovalStatus::Pending {
        return Err(AppError::Conflict(
            "this approval request has already been decided",
        ));
    }
    if current.expires_at <= Utc::now() {
        let row: ApprovalRequestRow = sqlx::query_as(&format!(
            "UPDATE approval_request SET status = 'expired', row_version = row_version + 1 \
             WHERE id = $1 AND row_version = $2 \
             RETURNING {REQUEST_COLUMNS}"
        ))
        .bind(request_id)
        .bind(current.row_version)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let expired: ApprovalRequest = row.try_into()?;
        // BAP-15 / BAP-F11 (D-545): the expiry this decision noticed is a
        // state change like any other, so it commits with the caller's hook
        // (its own `Expired`/`Closed` event, or a conversation tool call's
        // failure) instead of leaving the request pending-then-expired with
        // no event at all. A hook error rolls the expiry back too.
        hook.before_commit(&mut tx, &expired).await?;
        tx.commit().await.map_err(AppError::internal)?;
        log_transition(&expired, ApprovalStatus::Pending);
        return Err(AppError::Conflict("this approval request has expired"));
    }
    // Separation-of-duties: the one check this crate exists to make
    // impossible to skip. Checked before the row_version CAS so a
    // same-user attempt is always rejected as Forbidden rather than
    // sometimes surfacing as a version conflict depending on request body.
    if approver_id == current.requested_by {
        return Err(AppError::Forbidden);
    }
    if current.row_version != expected_row_version {
        return Err(AppError::VersionConflict);
    }
    // Only reachable when required_approvals > 1 keeps the request Pending
    // after an earlier Approve — with today's callers (required_approvals
    // always 1) a first Approve already closes the request, so this guard
    // only matters for a future N-of-M caller. Checked explicitly (rather
    // than relying on the grant table's UNIQUE(request_id, approver_id) and
    // mapping its violation) so a duplicate click surfaces as a clean
    // Conflict instead of a masked internal error.
    let already_decided: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM approval_grant WHERE request_id = $1 AND approver_id = $2)",
    )
    .bind(request_id)
    .bind(approver_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if already_decided {
        return Err(AppError::Conflict(
            "this approver has already recorded a decision on this request",
        ));
    }

    sqlx::query(
        "INSERT INTO approval_grant \
             (id, request_id, approver_id, decision, decided_at, comment) \
         VALUES ($1, $2, $3, $4, NOW(), $5)",
    )
    .bind(Uuid::now_v7())
    .bind(request_id)
    .bind(approver_id)
    .bind(decision.as_str())
    .bind(comment.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let new_status = match decision {
        Decision::Reject => ApprovalStatus::Rejected,
        Decision::Approve => {
            let approvals: i64 = sqlx::query_scalar(
                "SELECT COUNT(DISTINCT approver_id) FROM approval_grant \
                 WHERE request_id = $1 AND decision = 'approved'",
            )
            .bind(request_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if approvals >= i64::from(current.required_approvals) {
                ApprovalStatus::Approved
            } else {
                ApprovalStatus::Pending
            }
        }
    };

    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "UPDATE approval_request SET status = $3, row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .bind(new_status.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let request: ApprovalRequest = row.try_into()?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    log_transition(&request, ApprovalStatus::Pending);
    Ok(request)
}

/// D-421's plan-aware sibling of [`decide`] — used instead of it whenever
/// `ApprovalRequest::plan` is `Some`. Same shape (advisory lock + `FOR
/// UPDATE` + row_version CAS + separation-of-duties), extended for a
/// multi-step plan instead of the flat `required_approvals` count:
///
/// - `allowed_decider_ids` is the caller-resolved (`xrm_audit::approval::
///   resolve_step_approvers`) set of user ids who may decide the *current*
///   step right now — every step's named approver plus any delegate
///   currently standing in for one of them. `decider_id` must be in it or
///   this returns `Forbidden`, same as an unresolvable/ineligible approver
///   always has been.
/// - `on_behalf_of`, when `Some`, names the principal `decider_id` is
///   deciding as a delegate for — recorded on the grant row so the audit
///   trail always shows both who actually clicked (`decided_by`) and whose
///   authority they used (`on_behalf_of`). The caller must never pass a
///   principal equal to the request's own `requested_by` (this function
///   checks it anyway, and refuses with `Forbidden` — a delegation can
///   never manufacture a path to self-approval, D-421).
/// - `step_population` is the number of distinct *named* principals this
///   step resolved to (after the caller has already removed
///   `requested_by`) — see `ApprovalStep::required_count`'s doc comment for
///   why a delegate doesn't inflate it.
///
/// A `Reject` still always closes the whole request immediately, same as
/// `decide()` — there is no "N distinct rejections" threshold, on a plan any
/// more than there was before one. An `Approve` that reaches this step's
/// required count either advances to `step + 1` (resetting `step_started_at`
/// and clearing `escalated_at` for the new step's own SLA clock) or, if this
/// was the last step, closes the request as `Approved`.
#[allow(clippy::too_many_arguments)]
pub async fn decide_step(
    pool: &PgPool,
    request_id: Uuid,
    decider_id: Uuid,
    on_behalf_of: Option<Uuid>,
    allowed_decider_ids: &[Uuid],
    step_population: usize,
    decision: Decision,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    decide_step_with(
        pool,
        request_id,
        decider_id,
        on_behalf_of,
        allowed_decider_ids,
        step_population,
        decision,
        expected_row_version,
        None,
        &attome_db::NoHook,
    )
    .await
}

/// [`decide_step`] with the approver's optional `comment` and a
/// [`attome_db::BeforeCommit`] hook, exactly as [`decide_with`] is to
/// [`decide`].
#[allow(clippy::too_many_arguments)]
pub async fn decide_step_with(
    pool: &PgPool,
    request_id: Uuid,
    decider_id: Uuid,
    on_behalf_of: Option<Uuid>,
    allowed_decider_ids: &[Uuid],
    step_population: usize,
    decision: Decision,
    expected_row_version: i64,
    comment: Option<&str>,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let comment = normalize_decision_comment(comment)?;
    let mut tx = attome_db::tx::begin(pool).await?;

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-approval/decide:{request_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another decision on this approval request is already in progress",
        ));
    }

    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM approval_request WHERE id = $1 FOR UPDATE"
    ))
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let current: ApprovalRequest = row.try_into()?;

    if current.status != ApprovalStatus::Pending {
        return Err(AppError::Conflict(
            "this approval request has already been decided",
        ));
    }
    if current.expires_at <= Utc::now() {
        let row: ApprovalRequestRow = sqlx::query_as(&format!(
            "UPDATE approval_request SET status = 'expired', row_version = row_version + 1 \
             WHERE id = $1 AND row_version = $2 \
             RETURNING {REQUEST_COLUMNS}"
        ))
        .bind(request_id)
        .bind(current.row_version)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let expired: ApprovalRequest = row.try_into()?;
        // BAP-15 / BAP-F11 (D-545): identical to `decide_with`'s expiry flip.
        hook.before_commit(&mut tx, &expired).await?;
        tx.commit().await.map_err(AppError::internal)?;
        log_transition(&expired, ApprovalStatus::Pending);
        return Err(AppError::Conflict(
            "this approval request has expired (its overall backstop TTL, not a step SLA)",
        ));
    }

    let plan = current.plan.clone().ok_or_else(|| {
        AppError::internal("decide_step called on an approval request with no plan")
    })?;
    let step_index = usize::try_from(current.step).map_err(AppError::internal)?;
    let step = plan.steps.get(step_index).ok_or_else(|| {
        AppError::internal("approval request step index out of range for its own plan")
    })?;

    // Separation-of-duties, widened for delegation (D-421): neither the
    // person who actually clicked nor whoever they clicked *for* may be the
    // request's own requester. Checked before the row_version CAS, same
    // ordering rationale as decide()'s own version of this check.
    if decider_id == current.requested_by {
        return Err(AppError::Forbidden);
    }
    if let Some(principal) = on_behalf_of
        && principal == current.requested_by
    {
        return Err(AppError::Forbidden);
    }
    if !allowed_decider_ids.contains(&decider_id) {
        return Err(AppError::Forbidden);
    }
    if current.row_version != expected_row_version {
        return Err(AppError::VersionConflict);
    }
    let already_decided: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM approval_grant \
             WHERE request_id = $1 AND approver_id = $2 AND step = $3)",
    )
    .bind(request_id)
    .bind(decider_id)
    .bind(current.step)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if already_decided {
        return Err(AppError::Conflict(
            "this approver has already recorded a decision on this request's current step",
        ));
    }

    // BAP-5 / BAP-F2 (invariant A4) and BAP-7 / BAP-F6, both evaluated
    // *before* the grant is written, so a decision that would fill a slot
    // twice, or that could never satisfy this step, is refused with nothing
    // recorded:
    // - a step counts *principal slots*, not identities (BAP-D2). A
    //   delegate fills the slot of the principal they stand in for, so
    //   `COALESCE(on_behalf_of, decider_id)` is the slot key: a principal
    //   who has already decided, and a delegate acting for them afterward
    //   (or the reverse), are one slot, never two.
    // - a step that resolves to nobody, or an `n_of_m` whose threshold
    //   exceeds the population, refuses the approval rather than silently
    //   closing at a lower bar (BAP-D3, fail closed).
    //
    // The slot check runs for *both* decisions and matches any recorded
    // decision: a principal who approved must not have their delegate then
    // reject on their behalf (or the reverse) — that would spend one
    // principal's authority twice (A4).
    let slot = on_behalf_of.unwrap_or(decider_id);
    let slot_filled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM approval_grant \
             WHERE request_id = $1 AND step = $2 \
               AND COALESCE(on_behalf_of, approver_id) = $3)",
    )
    .bind(request_id)
    .bind(current.step)
    .bind(slot)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if slot_filled {
        return Err(AppError::Conflict(
            "this principal's slot on the current step has already recorded a decision",
        ));
    }
    if decision == Decision::Approve {
        step.required_count(step_population)?;
    }

    sqlx::query(
        "INSERT INTO approval_grant \
             (id, request_id, approver_id, decision, decided_at, step, decided_by, on_behalf_of, \
              comment) \
         VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8)",
    )
    .bind(Uuid::now_v7())
    .bind(request_id)
    .bind(decider_id)
    .bind(decision.as_str())
    .bind(current.step)
    .bind(decider_id)
    .bind(on_behalf_of)
    .bind(comment.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let (new_status, new_step, new_step_started_at, advanced) = match decision {
        Decision::Reject => (
            ApprovalStatus::Rejected,
            current.step,
            current.step_started_at,
            false,
        ),
        Decision::Approve => {
            // BAP-5: count principal slots, not identities — the same
            // `COALESCE(on_behalf_of, approver_id)` key the refusal above
            // uses, so the count and the guard can never disagree.
            let approvals: i64 = sqlx::query_scalar(
                "SELECT COUNT(DISTINCT COALESCE(on_behalf_of, approver_id)) \
                   FROM approval_grant \
                 WHERE request_id = $1 AND step = $2 AND decision = 'approved'",
            )
            .bind(request_id)
            .bind(current.step)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            let required = step.required_count(step_population)?;
            if approvals >= i64::from(required) {
                if step_index + 1 < plan.steps.len() {
                    (
                        ApprovalStatus::Pending,
                        current.step + 1,
                        Some(Utc::now()),
                        true,
                    )
                } else {
                    (
                        ApprovalStatus::Approved,
                        current.step,
                        current.step_started_at,
                        false,
                    )
                }
            } else {
                (
                    ApprovalStatus::Pending,
                    current.step,
                    current.step_started_at,
                    false,
                )
            }
        }
    };

    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "UPDATE approval_request \
         SET status = $3, step = $4, step_started_at = $5, \
             escalated_at = CASE WHEN $6 THEN NULL ELSE escalated_at END, \
             row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .bind(new_status.to_string())
    .bind(new_step)
    .bind(new_step_started_at)
    .bind(advanced)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let request: ApprovalRequest = row.try_into()?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    log_transition(&request, ApprovalStatus::Pending);
    Ok(request)
}

/// Lets the original requester withdraw their own request while it is still
/// `Pending` — the third terminal outcome alongside `decide()`'s
/// `Approved`/`Rejected`, and `sweep_expired`'s `Expired`. Same
/// advisory-lock namespace as `decide()` (`"attome-approval/decide:{request_id}"`)
/// so a cancel racing a concurrent `decide` call is serialized against it,
/// not a separate uncoordinated write path — whichever call actually wins
/// the lock observes the current row and the other gets a clean `Conflict`
/// once it re-checks `status`, never a lost update.
///
/// Unlike `decide()`, this requires the caller to BE `requested_by` (the
/// inverse of `decide()`'s separation-of-duties check, which requires the
/// caller NOT be `requested_by`) — a different admin has no standing to
/// withdraw someone else's request; they can only `Reject` it.
pub async fn cancel(
    pool: &PgPool,
    request_id: Uuid,
    requester_id: Uuid,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    cancel_with(
        pool,
        request_id,
        requester_id,
        expected_row_version,
        &attome_db::NoHook,
    )
    .await
}

/// [`cancel`] with a [`attome_db::BeforeCommit`] hook that runs inside the
/// cancellation's transaction just before it commits.
pub async fn cancel_with(
    pool: &PgPool,
    request_id: Uuid,
    requester_id: Uuid,
    expected_row_version: i64,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let mut tx = attome_db::tx::begin(pool).await?;

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-approval/decide:{request_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another decision on this approval request is already in progress",
        ));
    }

    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM approval_request WHERE id = $1 FOR UPDATE"
    ))
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let current: ApprovalRequest = row.try_into()?;

    if current.requested_by != requester_id {
        return Err(AppError::Forbidden);
    }
    if current.status != ApprovalStatus::Pending {
        return Err(AppError::Conflict(
            "this approval request has already been decided",
        ));
    }
    if current.row_version != expected_row_version {
        return Err(AppError::VersionConflict);
    }

    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "UPDATE approval_request SET status = 'cancelled', row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let request: ApprovalRequest = row.try_into()?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    log_transition(&request, ApprovalStatus::Pending);
    Ok(request)
}

/// Closes the loop after the caller has actually re-run the approved
/// mutation. `decide()` only ever gets a request to `Approved` — this crate
/// never executes anything itself (see the module doc); the caller must
/// call this once its own execution of the payload has succeeded.
/// CAS-guarded (`status = 'approved' AND row_version = $2`) so a retried
/// "mark executed" call after a crash can't double-apply: the second call's
/// `expected_row_version` is already stale and it returns `VersionConflict`
/// instead of updating again.
///
/// This is for callers that execute an `Approved` request **without claiming
/// it first**: `trd-engine`'s promotion and kill-switch release, and
/// `xrm-ai`'s policy auto-approval close-out. The CAS does not stop two such
/// callers from both running the action before either marks it. The admin
/// execution path claims instead ([`claim_execution`], then
/// [`complete_execution`], D-518), and this refuses a claimed (`executing`)
/// request.
pub async fn mark_executed(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    mark_executed_with(pool, request_id, expected_row_version, &attome_db::NoHook).await
}

/// [`mark_executed`] with a [`attome_db::BeforeCommit`] hook: the status change
/// and whatever the hook writes (the caller's `Execute` audit event) commit
/// together, or neither does.
pub async fn mark_executed_with(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let mut tx = attome_db::tx::begin(pool).await?;
    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "UPDATE approval_request \
             SET status = 'executed', executed_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'approved' \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::VersionConflict)?;
    let request: ApprovalRequest = row.try_into()?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    log_transition(&request, ApprovalStatus::Approved);
    Ok(request)
}

/// Closes the loop the other way: the caller revalidated an `Approved`
/// request immediately before executing it, and refused. Moves it to the
/// terminal `invalidated` status so no later call — `retry-execution`
/// included — can run it once whatever invalidated it is undone; the
/// requester must ask again, against the world as it is now.
///
/// Same CAS shape as [`mark_executed`] (`status = 'approved' AND row_version
/// = $2`), so an invalidation racing a concurrent execution of the same
/// request resolves to exactly one terminal state and the loser gets
/// `VersionConflict`.
pub async fn mark_invalidated(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    mark_invalidated_with(pool, request_id, expected_row_version, &attome_db::NoHook).await
}

/// [`mark_invalidated`] with a [`attome_db::BeforeCommit`] hook: the status
/// change and whatever the hook writes commit together, or neither does —
/// the same shape as [`mark_executed_with`].
pub async fn mark_invalidated_with(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let mut tx = attome_db::tx::begin(pool).await?;
    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "UPDATE approval_request \
             SET status = 'invalidated', row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'approved' \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::VersionConflict)?;
    let request: ApprovalRequest = row.try_into()?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    log_transition(&request, ApprovalStatus::Approved);
    Ok(request)
}

/// How long a claim from [`claim_execution`] may stand before it counts as
/// stale (D-518). Every normal path completes, invalidates or releases a claim
/// within the request that took it, so a claim older than this means its
/// holder died or hung, and whether the action ran is unknown. A stale claim
/// is never taken over automatically; [`take_over_stale_execution`] is the
/// explicit path for an admin who has acknowledged that.
pub const EXECUTION_CLAIM_LEASE_MINUTES: i32 = 15;

/// Who holds an `executing` request's claim, and whether it is stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionClaim {
    pub claimed_by: Uuid,
    pub claimed_at: DateTime<Utc>,
    /// `claimed_at` is at least [`EXECUTION_CLAIM_LEASE_MINUTES`] old, by the
    /// database clock.
    pub stale: bool,
}

/// D-518 — the only way a caller may start executing an approved request.
///
/// Moves it `approved -> executing` in one CAS (`status = 'approved' AND
/// executed_at IS NULL AND row_version = $2`) and records `claimant`. Of any
/// number of concurrent callers presenting the same `row_version`, exactly one
/// gets `Ok`. The claimed request it returns carries the new `row_version`
/// that [`complete_execution`], [`invalidate_execution`] and
/// [`release_execution`] require.
///
/// A caller that gets `Err` must not run the action. `Conflict` means the
/// request is already being executed, has been executed, or is not approved;
/// `VersionConflict` means it is still approved but changed since it was read.
pub async fn claim_execution(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
    claimant: Uuid,
) -> Result<ApprovalRequest, AppError> {
    let claimed: Option<ApprovalRequestRow> = sqlx::query_as(&format!(
        "UPDATE approval_request \
             SET status = 'executing', execution_claimed_at = NOW(), \
                 execution_claimed_by = $3, row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'approved' \
           AND executed_at IS NULL \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .bind(claimant)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?;
    if let Some(row) = claimed {
        let request: ApprovalRequest = row.try_into()?;
        log_transition(&request, ApprovalStatus::Approved);
        return Ok(request);
    }

    // Nothing was claimed. Only the refusal's wording is left to choose, and
    // every branch refuses.
    Err(match get(pool, request_id).await?.status {
        ApprovalStatus::Executing => {
            AppError::Conflict("this approval request is already being executed")
        }
        ApprovalStatus::Executed => {
            AppError::Conflict("this approval request has already been executed")
        }
        ApprovalStatus::Approved => AppError::VersionConflict,
        _ => AppError::Conflict("this approval request is not approved, so it cannot be executed"),
    })
}

/// D-518 — closes a claimed request as `executed` once its action has run.
///
/// CAS on `status = 'executing' AND row_version = $2`. A claim taken over
/// since ([`take_over_stale_execution`]) carries a newer `row_version`, so a
/// late finish by the original, hung holder gets `VersionConflict`. The claim
/// columns stay set as the record of who ran it.
pub async fn complete_execution(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    complete_execution_with(pool, request_id, expected_row_version, &attome_db::NoHook).await
}

/// [`complete_execution`] with a [`attome_db::BeforeCommit`] hook: the
/// `executing -> executed` transition and whatever the hook writes (the
/// caller's D-541/D-062 `Execute` audit event) commit together, or neither
/// does — the same atomicity `mark_executed_with` gives the unclaimed path.
pub async fn complete_execution_with(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let mut tx = attome_db::tx::begin(pool).await?;
    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "UPDATE approval_request \
             SET status = 'executed', executed_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'executing' \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::VersionConflict)?;
    let request: ApprovalRequest = row.try_into()?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    log_transition(&request, ApprovalStatus::Executing);
    Ok(request)
}

/// D-518 — closes a claimed request as `invalidated`: execution-time
/// revalidation refused its action (see [`mark_invalidated`] for what that
/// means). Same CAS as [`complete_execution`].
pub async fn invalidate_execution(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    invalidate_execution_with(pool, request_id, expected_row_version, &attome_db::NoHook).await
}

/// [`invalidate_execution`] with a [`attome_db::BeforeCommit`] hook: the
/// `executing -> invalidated` transition and whatever the hook writes (an
/// agent conversation's `tool.call.failed{invalidated}`, C10-A) commit
/// together, or neither does — the claimed counterpart of
/// [`mark_invalidated_with`].
pub async fn invalidate_execution_with(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let mut tx = attome_db::tx::begin(pool).await?;
    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "UPDATE approval_request \
             SET status = 'invalidated', row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'executing' \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::VersionConflict)?;
    let request: ApprovalRequest = row.try_into()?;
    hook.before_commit(&mut tx, &request).await?;
    tx.commit().await.map_err(AppError::internal)?;
    log_transition(&request, ApprovalStatus::Executing);
    Ok(request)
}

/// D-518 — returns a claimed request to `approved` and clears its claim, so it
/// can be claimed again.
///
/// For a holder whose attempt applied nothing it can vouch for: the action was
/// deferred, or the executor returned an error. CAS on `status = 'executing'
/// AND row_version = $2`, so only the current holder can release it.
pub async fn release_execution(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "UPDATE approval_request \
             SET status = 'approved', execution_claimed_at = NULL, \
                 execution_claimed_by = NULL, row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'executing' \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::VersionConflict)?;
    let request: ApprovalRequest = row.try_into()?;
    log_transition(&request, ApprovalStatus::Executing);
    Ok(request)
}

/// D-518 — the claim on an `executing` request; `None` when the request is not
/// `executing`.
pub async fn execution_claim(
    pool: &PgPool,
    request_id: Uuid,
) -> Result<Option<ExecutionClaim>, AppError> {
    // Migration 0468's claim CHECK keeps both columns set on every
    // `executing` row, so they decode as non-null here.
    let row: Option<(Uuid, DateTime<Utc>, bool)> = sqlx::query_as(
        "SELECT execution_claimed_by, execution_claimed_at, \
                execution_claimed_at <= NOW() - make_interval(mins => $2) \
           FROM approval_request \
          WHERE id = $1 AND status = 'executing'",
    )
    .bind(request_id)
    .bind(EXECUTION_CLAIM_LEASE_MINUTES)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(row.map(|(claimed_by, claimed_at, stale)| ExecutionClaim {
        claimed_by,
        claimed_at,
        stale,
    }))
}

/// D-518 — hands a stale claim to `claimant`, who will run the action again.
///
/// Only for a human who has acknowledged that the earlier attempt's outcome is
/// unknown and it may already have run; nothing calls this automatically. CAS
/// on `status = 'executing' AND row_version = $2` plus the lease check, all by
/// the database clock. The takeover bumps `row_version`, so the earlier holder
/// can no longer complete, invalidate or release the claim.
///
/// `Conflict` when the claim has not passed its lease; `VersionConflict` when
/// the request changed since it was read or is no longer `executing`.
pub async fn take_over_stale_execution(
    pool: &PgPool,
    request_id: Uuid,
    expected_row_version: i64,
    claimant: Uuid,
) -> Result<ApprovalRequest, AppError> {
    let taken: Option<ApprovalRequestRow> = sqlx::query_as(&format!(
        "UPDATE approval_request \
             SET execution_claimed_at = NOW(), execution_claimed_by = $3, \
                 row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status = 'executing' \
           AND execution_claimed_at <= NOW() - make_interval(mins => $4) \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(expected_row_version)
    .bind(claimant)
    .bind(EXECUTION_CLAIM_LEASE_MINUTES)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?;
    if let Some(row) = taken {
        // Still `executing`, but under a new claimant: the transition this
        // logs is the takeover, not a status change.
        let request: ApprovalRequest = row.try_into()?;
        log_transition(&request, ApprovalStatus::Executing);
        return Ok(request);
    }

    Err(match execution_claim(pool, request_id).await? {
        Some(claim) if !claim.stale => AppError::Conflict(
            "this approval request's execution claim has not passed its lease yet",
        ),
        _ => AppError::VersionConflict,
    })
}

/// BAP-9 / BAP-F5 — what one bounded expiry sweep did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SweepOutcome {
    /// Rows this sweep moved `pending -> expired`.
    pub expired: u64,
    /// Rows it tried and skipped: a hook error, or a row that no longer
    /// decodes. Each is left `pending` (its own transaction rolled back) and
    /// reported to the caller; the sweep carries on with the rest.
    pub failed: u64,
}

/// The largest batch one sweep will process, and the default the
/// unparameterized [`sweep_expired_with`] uses. Bounded so one sweep is a
/// short, interruptible piece of work, never an unbounded table scan.
pub const EXPIRY_SWEEP_BATCH: i64 = 500;

/// Reaps stale `pending` requests past `expires_at`. Not wired to run
/// itself — the caller owns the periodic-task lifecycle (see
/// `xrm-server::spawn_approval_expiry_sweep` in `metrics.rs`), same split as
/// every other periodic sweep in this codebase; `base-*` has no
/// background-task-runtime opinions of its own.
pub async fn sweep_expired(pool: &PgPool) -> Result<u64, AppError> {
    sweep_expired_with(pool, &attome_db::NoHook).await
}

/// [`sweep_expired`] with a [`attome_db::BeforeCommit`] hook run once per
/// expired request, and the number expired as its return.
///
/// BAP-9 / BAP-F5: the sweep is **bounded and poison-proof**. It takes at
/// most [`EXPIRY_SWEEP_BATCH`] rows and gives each one its own short
/// transaction (`SELECT ... FOR UPDATE SKIP LOCKED`, CAS, hook, commit), so
/// a hook that errors — or a `plan` that no longer decodes — rolls back only
/// that row: the sweep logs it by id, skips it, and expires the rest. Before
/// this, one bad row aborted every expiry in the deployment, every hour.
pub async fn sweep_expired_with(
    pool: &PgPool,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<u64, AppError> {
    Ok(sweep_expired_report_with(pool, hook, EXPIRY_SWEEP_BATCH)
        .await?
        .expired)
}

/// [`sweep_expired_with`] with the `{expired, failed}` breakdown (BAP-9)
/// over at most `batch` rows, so a caller can report a poisoned row rather
/// than only guess from a count that came up short.
pub async fn sweep_expired_report_with(
    pool: &PgPool,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
    batch: i64,
) -> Result<SweepOutcome, AppError> {
    let batch = batch.clamp(1, EXPIRY_SWEEP_BATCH);
    let mut outcome = SweepOutcome::default();
    // Ids this sweep has already refused: excluded from the next candidate
    // select so a poisoned row cannot be retried in a loop and eat the batch.
    let mut skipped: Vec<Uuid> = Vec::new();

    for _ in 0..batch {
        match expire_one(pool, hook, &skipped).await? {
            SweepStep::Expired(_request) => outcome.expired += 1,
            SweepStep::Done => break,
            SweepStep::Failed(id, error) => {
                tracing::warn!(
                    request_id = %id,
                    error = %error,
                    "approval expiry sweep: one pending request could not be expired and was skipped; the rest of the batch continues",
                );
                outcome.failed += 1;
                skipped.push(id);
            }
        }
    }
    Ok(outcome)
}

/// One row's worth of [`sweep_expired_report_with`].
enum SweepStep {
    Expired(ApprovalRequest),
    /// No more due rows (or the row was taken by a concurrent sweep).
    Done,
    /// This row could not be expired; everything it wrote is rolled back.
    Failed(Uuid, AppError),
}

/// Expires exactly the next due row in its own short transaction.
///
/// `FOR UPDATE SKIP LOCKED` so two sweeps running at once never wait on each
/// other and never expire the same row twice; the `status`/`row_version` CAS
/// keeps that true even against a concurrent sweep that read the row first.
async fn expire_one(
    pool: &PgPool,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
    skipped: &[Uuid],
) -> Result<SweepStep, AppError> {
    let mut tx = attome_db::tx::begin(pool).await?;
    let row: Option<ApprovalRequestRow> = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM approval_request \
          WHERE status = 'pending' AND expires_at <= NOW() AND NOT (id = ANY($1)) \
          ORDER BY expires_at ASC LIMIT 1 \
          FOR UPDATE SKIP LOCKED"
    ))
    .bind(skipped)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(SweepStep::Done);
    };
    let id = row.id;
    let current: ApprovalRequest = match row.try_into() {
        Ok(current) => current,
        Err(error) => {
            let _ = tx.rollback().await;
            return Ok(SweepStep::Failed(id, error));
        }
    };

    let updated: Option<ApprovalRequestRow> = sqlx::query_as(&format!(
        "UPDATE approval_request \
             SET status = 'expired', row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 AND status = 'pending' \
          RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(current.id)
    .bind(current.row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(updated) = updated else {
        // A concurrent sweep got there first; nothing to do.
        let _ = tx.rollback().await;
        return Ok(SweepStep::Done);
    };
    let expired: ApprovalRequest = match updated.try_into() {
        Ok(expired) => expired,
        Err(error) => {
            let _ = tx.rollback().await;
            return Ok(SweepStep::Failed(id, error));
        }
    };

    // The expiry and whatever the hook writes commit together, or neither
    // does — for this row alone.
    if let Err(error) = hook.before_commit(&mut tx, &expired).await {
        let _ = tx.rollback().await;
        return Ok(SweepStep::Failed(id, error));
    }
    if let Err(e) = tx.commit().await {
        return Ok(SweepStep::Failed(id, AppError::internal(e)));
    }
    log_transition(&expired, ApprovalStatus::Pending);
    Ok(SweepStep::Expired(expired))
}

/// D-421 — the read half of the per-step timeout sweep: the ids of pending,
/// plan-bearing requests whose current step's `sla_minutes` has elapsed and
/// whose timeout still has something to do.
///
/// BAP-8 / BAP-F4: **due-ness is decided in SQL**, not by reading the oldest
/// `limit` candidates and filtering them in Rust. The old shape let 25
/// long-lived no-SLA or already-escalated requests sit at the front of
/// `ORDER BY step_started_at` forever, so a newer request's SLA never fired.
/// The predicate is now the whole filter:
/// - `plan->'steps'->step` projects this request's *current* step;
/// - its `sla_minutes` is present, so a no-SLA step is never due;
/// - `step_started_at + sla <= NOW()`;
/// - an `on_timeout: escalate` step that already has `escalated_at` is not
///   due again (there is nothing left for it to do).
///
/// The `CASE WHEN … ~ '^[0-9]{1,9}$' THEN … ::int END` guard keeps one bad
/// `sla_minutes` from making the whole query fail: a non-numeric value, or a
/// digit string too long for `int4` (a legacy row saved before
/// [`MAX_SLA_MINUTES`] existed), yields `NULL` and is simply not due — skipped
/// here, exactly as the old Rust filter skipped an undecodable plan — instead
/// of raising "integer out of range" and taking the poller's whole tick down.
/// The guard sits inside one `CASE` because PostgreSQL does not promise to
/// evaluate a separate `AND` regex before the cast; nine digits is always
/// inside `int4` and far above `MAX_SLA_MINUTES`.
/// `apply_step_timeout_with` re-checks due-ness itself under the row lock before
/// acting, so a race against a human deciding the same step in between this
/// call and that one is still safe — this function only ever narrows what
/// gets attempted.
pub async fn list_due_step_timeouts(pool: &PgPool, limit: i64) -> Result<Vec<Uuid>, AppError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM approval_request \
         WHERE status = 'pending' AND plan IS NOT NULL AND step_started_at IS NOT NULL \
           AND step_started_at \
                 + CASE WHEN (plan->'steps'->step->>'sla_minutes') ~ '^[0-9]{1,9}$' \
                        THEN make_interval(mins => (plan->'steps'->step->>'sla_minutes')::int) \
                   END <= NOW() \
           AND NOT (COALESCE(plan->'steps'->step->>'on_timeout', 'escalate') = 'escalate' \
                    AND escalated_at IS NOT NULL) \
         ORDER BY step_started_at ASC LIMIT $1",
    )
    .bind(limit.clamp(1, i64::MAX))
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// D-421 — applies exactly one step's timeout outcome, under the same
/// advisory lock + `FOR UPDATE` a concurrent human `decide_step` call would
/// take, so the two can never race each other into inconsistent state. If
/// another decision is in flight right now (lock held), or the row no
/// longer needs a timeout applied by the time this actually reads it (a
/// human decided it first, it already escalated, it isn't `pending`
/// anymore, etc.), this is a clean no-op — `Ok(None)` — never an error; the
/// caller just tries again on a later tick.
///
/// Returns the outcome so the caller (the notification-poller sweep,
/// reusing M51's escalation machinery) knows what audit event and, for
/// `Escalated`, what notification to send — this function itself has no
/// notification or audit knowledge (guidelines §1: base layer).
///
/// Takes a [`attome_db::BeforeCommit`] hook, which runs
/// inside the timeout's own transaction (BAP-6a/6b, D-545): a caller's audit
/// event — or an agent conversation's tool-call projection — commits with
/// the timeout, or neither does. An error from the hook rolls the timeout
/// back and is returned to the caller.
///
/// The hook's value is `(ApprovalRequest, TimeoutOutcome)`, not just the
/// request, because the event an `Escalated` step needs is a different
/// operation from the one `AutoApproved`/`AutoRejected`/`Expired` needs, and
/// only this function knows which branch ran.
pub async fn apply_step_timeout_with(
    pool: &PgPool,
    request_id: Uuid,
    hook: &dyn attome_db::BeforeCommit<(ApprovalRequest, TimeoutOutcome)>,
) -> Result<Option<(ApprovalRequest, TimeoutOutcome)>, AppError> {
    let mut tx = attome_db::tx::begin(pool).await?;

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-approval/decide:{request_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(None);
    }

    let row: ApprovalRequestRow = sqlx::query_as(&format!(
        "SELECT {REQUEST_COLUMNS} FROM approval_request WHERE id = $1 FOR UPDATE"
    ))
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let current: ApprovalRequest = row.try_into()?;

    if current.status != ApprovalStatus::Pending {
        return Ok(None);
    }
    // BAP-6a / BAP-F3 (invariant A5): the request's own backstop wins over
    // any step SLA. A request already past `expires_at` is expired here —
    // never auto-approved or auto-rejected — so a policy timeout can no
    // longer decide something that should already have died (the hourly
    // expiry sweep may simply not have run yet). The expiry commits with
    // the hook, exactly as the sweep's own expiries do (BAP-15's rule).
    if current.expires_at <= Utc::now() {
        let row: ApprovalRequestRow = sqlx::query_as(&format!(
            "UPDATE approval_request \
                 SET status = 'expired', row_version = row_version + 1 \
             WHERE id = $1 AND row_version = $2 \
             RETURNING {REQUEST_COLUMNS}"
        ))
        .bind(request_id)
        .bind(current.row_version)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let expired: ApprovalRequest = row.try_into()?;
        hook.before_commit(&mut tx, &(expired.clone(), TimeoutOutcome::Expired))
            .await?;
        tx.commit().await.map_err(AppError::internal)?;
        log_transition(&expired, ApprovalStatus::Pending);
        return Ok(Some((expired, TimeoutOutcome::Expired)));
    }
    let Some(plan) = current.plan.clone() else {
        return Ok(None);
    };
    let step_index = match usize::try_from(current.step) {
        Ok(i) => i,
        Err(_) => return Ok(None),
    };
    let Some(step) = plan.steps.get(step_index) else {
        return Ok(None);
    };
    let Some(sla) = step.sla_minutes else {
        return Ok(None);
    };
    let Some(started) = current.step_started_at else {
        return Ok(None);
    };
    if Utc::now() < started + Duration::minutes(sla) {
        return Ok(None);
    }

    let on_timeout = step.on_timeout;
    let (new_status, new_step, new_step_started_at, new_escalated_at, record_decision) =
        match on_timeout {
            OnTimeout::Escalate => {
                if current.escalated_at.is_some() {
                    return Ok(None);
                }
                (
                    current.status,
                    current.step,
                    current.step_started_at,
                    Some(Utc::now()),
                    None,
                )
            }
            OnTimeout::AutoApprove => {
                if step_index + 1 < plan.steps.len() {
                    (
                        ApprovalStatus::Pending,
                        current.step + 1,
                        Some(Utc::now()),
                        None,
                        Some(Decision::Approve),
                    )
                } else {
                    (
                        ApprovalStatus::Approved,
                        current.step,
                        current.step_started_at,
                        current.escalated_at,
                        Some(Decision::Approve),
                    )
                }
            }
            OnTimeout::AutoReject => (
                ApprovalStatus::Rejected,
                current.step,
                current.step_started_at,
                current.escalated_at,
                Some(Decision::Reject),
            ),
        };

    if let Some(decision) = record_decision {
        sqlx::query(
            "INSERT INTO approval_grant \
                 (id, request_id, approver_id, decision, decided_at, step, decided_by, on_behalf_of) \
             VALUES ($1, $2, $3, $4, NOW(), $5, $6, NULL)",
        )
        .bind(Uuid::now_v7())
        .bind(request_id)
        .bind(POLICY_ACTOR_ID)
        .bind(decision.as_str())
        .bind(current.step)
        .bind(POLICY_ACTOR_ID)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    // BAP-6a: the CAS this transition was missing. The `FOR UPDATE` above
    // already held the row, so it cannot lose today; the predicate makes the
    // update safe on its own terms rather than by that lock.
    let row: Option<ApprovalRequestRow> = sqlx::query_as(&format!(
        "UPDATE approval_request \
         SET status = $2, step = $3, step_started_at = $4, escalated_at = $5, \
             row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $6 \
         RETURNING {REQUEST_COLUMNS}"
    ))
    .bind(request_id)
    .bind(new_status.to_string())
    .bind(new_step)
    .bind(new_step_started_at)
    .bind(new_escalated_at)
    .bind(current.row_version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        // The request moved under us; roll the grant (if any) back and let a
        // later tick see the new state.
        return Ok(None);
    };

    let updated: ApprovalRequest = row.try_into()?;
    let outcome = match on_timeout {
        OnTimeout::Escalate => TimeoutOutcome::Escalated,
        OnTimeout::AutoApprove => TimeoutOutcome::AutoApproved,
        OnTimeout::AutoReject => TimeoutOutcome::AutoRejected,
    };
    // BAP-6b: the timeout's audit event (or any other caller obligation)
    // commits with the transition, or neither does.
    hook.before_commit(&mut tx, &(updated.clone(), outcome))
        .await?;
    tx.commit().await.map_err(AppError::internal)?;
    log_transition(&updated, ApprovalStatus::Pending);
    Ok(Some((updated, outcome)))
}

/// BAP-13 / BAP-F8 — one structured line per state transition: the request
/// id, its action type, the step, and `from -> to`. Never the payload or a
/// decision comment: those can carry customer data, and this is an
/// operational signal, not an audit record.
fn log_transition(request: &ApprovalRequest, from: ApprovalStatus) {
    tracing::info!(
        request_id = %request.id,
        action_type = %request.action_type,
        step = request.step,
        from = %from,
        to = %request.status,
        "approval request transition",
    );
}

/// BAP-13 / BAP-F8 — how many requests sit in each
/// `(status, action_type)` bucket. The base-layer half of the hourly loop's
/// `approval_requests{status,action_type}` gauge; this crate has no metrics
/// dependency of its own (guidelines §1).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StatusCount {
    pub status: String,
    pub action_type: String,
    pub count: i64,
}

/// See [`StatusCount`].
pub async fn status_counts(pool: &PgPool) -> Result<Vec<StatusCount>, AppError> {
    sqlx::query_as(
        "SELECT status, action_type, COUNT(*)::bigint AS count \
           FROM approval_request \
          GROUP BY status, action_type \
          ORDER BY status ASC, action_type ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)
}

/// BAP-13 / BAP-F8 — the age in seconds of the oldest still-`pending`
/// request for each action type (the base half of
/// `approval_oldest_pending_age_seconds{action_type}`). A type with no
/// pending request is absent, not zero: "never asked" and "asked a moment
/// ago" are different signals.
pub async fn oldest_pending_age_seconds(pool: &PgPool) -> Result<Vec<(String, f64)>, AppError> {
    sqlx::query_as(
        "SELECT action_type, EXTRACT(EPOCH FROM (NOW() - MIN(requested_at)))::float8 \
           FROM approval_request \
          WHERE status = 'pending' \
          GROUP BY action_type \
          ORDER BY action_type ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(AppError::internal)
}

/// BAP-13 / BAP-F8 — claims past [`EXECUTION_CLAIM_LEASE_MINUTES`]: an
/// approved action whose holder died or hung, so whether it ran is unknown.
/// Nothing retries these automatically (D-518); this count (the base half of
/// `approval_executing_stale`) is how an operator finds them.
pub async fn stale_executing_count(pool: &PgPool) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_request \
          WHERE status = 'executing' \
            AND execution_claimed_at <= NOW() - make_interval(mins => $1)",
    )
    .bind(EXECUTION_CLAIM_LEASE_MINUTES)
    .fetch_one(pool)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_comment_is_trimmed_and_blank_is_none() {
        assert_eq!(normalize_decision_comment(None).unwrap(), None);
        assert_eq!(normalize_decision_comment(Some("   ")).unwrap(), None);
        assert_eq!(
            normalize_decision_comment(Some("  looks right \n")).unwrap(),
            Some("looks right".to_owned())
        );
    }

    #[test]
    fn decision_comment_is_bounded_in_characters_not_bytes() {
        // Multi-byte characters: 2000 of them is 4000+ bytes, still allowed.
        let at_limit = "\u{0639}".repeat(MAX_DECISION_COMMENT_CHARS);
        assert!(
            normalize_decision_comment(Some(&at_limit))
                .unwrap()
                .is_some()
        );
        let over = "x".repeat(MAX_DECISION_COMMENT_CHARS + 1);
        assert!(matches!(
            normalize_decision_comment(Some(&over)),
            Err(AppError::Validation(_))
        ));
    }

    fn any_step() -> ApprovalStep {
        ApprovalStep {
            mode: StepMode::Any,
            threshold: None,
            approvers: vec!["user:a".to_string()],
            sla_minutes: Some(60),
            on_timeout: OnTimeout::Escalate,
            extras: Default::default(),
        }
    }

    fn grouped(group: Option<u16>) -> ApprovalStep {
        let mut step = any_step();
        step.extras.group = group;
        step
    }

    #[test]
    fn validate_rejects_non_consecutive_group() {
        let ok = ApprovalPlan {
            steps: vec![grouped(Some(1)), grouped(Some(1)), grouped(None)],
        };
        assert!(ok.validate().is_ok());
        let split = ApprovalPlan {
            steps: vec![grouped(Some(1)), grouped(None), grouped(Some(1))],
        };
        assert!(split.validate().is_err());
        let mut mixed = vec![grouped(Some(2)), grouped(Some(2))];
        mixed[1].on_timeout = OnTimeout::AutoReject;
        assert!(ApprovalPlan { steps: mixed }.validate().is_err());
    }

    #[test]
    fn validate_rejects_reminder_after_sla() {
        let mut step = any_step();
        step.extras.reminder_minutes = Some(60);
        assert!(
            ApprovalPlan {
                steps: vec![step.clone()]
            }
            .validate()
            .is_err()
        );
        step.extras.reminder_minutes = Some(30);
        assert!(
            ApprovalPlan {
                steps: vec![step.clone()]
            }
            .validate()
            .is_ok()
        );
        step.extras.requires_signature = true;
        step.extras.requires_human = false;
        assert!(ApprovalPlan { steps: vec![step] }.validate().is_err());
    }

    #[test]
    fn stage_of_groups_consecutive_steps() {
        let plan = ApprovalPlan {
            steps: vec![
                grouped(None),
                grouped(Some(1)),
                grouped(Some(1)),
                grouped(None),
            ],
        };
        assert_eq!(plan.stage_of(0), 0..1);
        assert_eq!(plan.stage_of(1), 1..3);
        assert_eq!(plan.stage_of(2), 1..3);
        assert_eq!(plan.stage_of(3), 3..4);
    }

    #[test]
    fn old_plan_json_deserializes_with_defaults() {
        let plan: ApprovalPlan = serde_json::from_value(serde_json::json!({
            "steps": [{"mode": "any", "approvers": ["user:a"], "sla_minutes": 60}]
        }))
        .expect("an old plan reads");
        assert_eq!(plan.steps[0].extras, StepExtras::default());
        assert!(plan.steps[0].extras.requires_human);
        let back = serde_json::to_value(&plan).expect("writes");
        assert!(
            back["steps"][0].get("group").is_none(),
            "absent keys stay absent: {back}"
        );
    }

    /// BAP-7 / BAP-F6 (BAP-D3): `required_count` counts principal slots and
    /// refuses — never clamps — a step that the currently eligible approvers
    /// cannot satisfy.
    #[test]
    fn required_count_never_lowers_the_bar_a_policy_states() {
        assert_eq!(any_step().required_count(1).expect("any"), 1);
        assert_eq!(any_step().required_count(25).expect("any"), 1);

        let all = ApprovalStep {
            mode: StepMode::All,
            ..any_step()
        };
        assert_eq!(all.required_count(3).expect("all"), 3);

        let n_of_m = ApprovalStep {
            mode: StepMode::NofM,
            threshold: Some(2),
            ..any_step()
        };
        assert_eq!(n_of_m.required_count(3).expect("2 of 3"), 2);
        assert_eq!(n_of_m.required_count(2).expect("2 of 2"), 2);

        let too_high = ApprovalStep {
            mode: StepMode::NofM,
            threshold: Some(3),
            ..any_step()
        };
        assert!(matches!(
            too_high.required_count(2),
            Err(AppError::Conflict(_))
        ));

        // Nobody is eligible: the step cannot close at a silent bar of 1.
        assert!(matches!(
            any_step().required_count(0),
            Err(AppError::Conflict(_))
        ));
    }

    fn n_of_m(n: i32, approvers: &[&str]) -> ApprovalStep {
        ApprovalStep {
            mode: StepMode::NofM,
            threshold: Some(n),
            approvers: approvers.iter().map(|t| (*t).to_string()).collect(),
            ..any_step()
        }
    }

    /// BAP-7 / BAP-D3, save-time half: an `n_of_m` over only `user:` tokens
    /// has a population known at save time, so a threshold above it is
    /// refused rather than left to its `on_timeout` (possibly auto_approve).
    #[test]
    fn validate_refuses_a_static_threshold_above_the_named_users() {
        let plan = ApprovalPlan {
            steps: vec![n_of_m(3, &["user:a", "user:b"])],
        };
        assert!(matches!(plan.validate(), Err(AppError::Validation(_))));
        let plan = ApprovalPlan {
            steps: vec![n_of_m(2, &["user:a", "user:b"])],
        };
        assert!(plan.validate().is_ok());
        // A repeated token is still one principal.
        let plan = ApprovalPlan {
            steps: vec![n_of_m(2, &["user:a", "user:a"])],
        };
        assert!(matches!(plan.validate(), Err(AppError::Validation(_))));
        // A role token resolves at decide time, so save cannot know its size.
        let plan = ApprovalPlan {
            steps: vec![n_of_m(3, &["user:a", "role:reviewers"])],
        };
        assert!(plan.validate().is_ok());
    }

    /// BAP-16 / BAP-D6: every plan input is bounded at both ends, exactly at
    /// the cap and one past it.
    #[test]
    fn plan_validation_caps_steps_approvers_and_sla() {
        let step = any_step();

        let at_cap = ApprovalPlan {
            steps: vec![step.clone(); MAX_PLAN_STEPS],
        };
        assert!(
            at_cap.validate().is_ok(),
            "{MAX_PLAN_STEPS} steps is allowed"
        );
        let over = ApprovalPlan {
            steps: vec![step.clone(); MAX_PLAN_STEPS + 1],
        };
        assert!(matches!(over.validate(), Err(AppError::Validation(_))));

        let at_cap = ApprovalStep {
            approvers: vec!["user:a".to_string(); MAX_STEP_APPROVERS],
            ..step.clone()
        };
        assert!(
            ApprovalPlan {
                steps: vec![at_cap]
            }
            .validate()
            .is_ok()
        );
        let over = ApprovalStep {
            approvers: vec!["user:a".to_string(); MAX_STEP_APPROVERS + 1],
            ..step.clone()
        };
        assert!(matches!(
            ApprovalPlan { steps: vec![over] }.validate(),
            Err(AppError::Validation(_))
        ));

        let at_limit = ApprovalStep {
            sla_minutes: Some(MAX_SLA_MINUTES),
            ..step.clone()
        };
        assert!(
            ApprovalPlan {
                steps: vec![at_limit]
            }
            .validate()
            .is_ok()
        );
        let past = ApprovalStep {
            sla_minutes: Some(MAX_SLA_MINUTES + 1),
            ..step
        };
        assert!(matches!(
            ApprovalPlan { steps: vec![past] }.validate(),
            Err(AppError::Validation(_))
        ));
    }
}

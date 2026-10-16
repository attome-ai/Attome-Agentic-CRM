//! The XRM half of D-195's four-eyes gate: `attome_approval::submit` plus the
//! `Submitted` audit event that `attome-approval` (base layer, zero `xrm-*`
//! knowledge) cannot write itself.
//!
//! Lived in `attome-server::approval_admin` until ARCH-5
//! (PLATFORM-REVIEW-2026-08-24). Two things forced it down the stack:
//!
//! - the compliance route bundles that call it at the top of every gated
//!   handler (`dsr_admin`, `retention_admin`, `erasure_admin`,
//!   `rewrap_admin`) moved into `attome-compliance`, which may not depend on
//!   `attome-server`;
//! - `attome-security::admin::user_roles` had already been carrying a
//!   line-for-line **duplicate** (`gate_role_grant`) for the same reason —
//!   an engine crate cannot reach `attome-server` — which is the clearest
//!   possible sign that the function was filed in the wrong crate.
//!
//! It lives here rather than in `attome-core` because the only
//! XRM-specific work it does *is* the audit write, and `AuditService`/
//! `AuditEvent` are this crate's. The dispatch side (`execute_approved`, the
//! approve/reject endpoints, `KNOWN_ACTION_TYPES`) deliberately stays in
//! `attome-server::approval_admin`: it has to name every gated flow's `do_*`
//! across every engine, which only the composition layer can.

use std::collections::{HashMap, HashSet};

use attome_approval::{ApprovalPlan, ApprovalRequest, ApprovalStep, Decision};
use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::security::{AuditHook, HookEvent, MandatoryCategory, SecurityEvent};
use crate::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, audit_service,
    fetch_audit_ctx,
};

/// Checked at the top of every gated handler, before it does anything else.
/// Returns `Ok(None)` when `action_type` is neither in
/// `approval.required_actions` (attome-config; empty/off by default) NOR
/// matched by an active `approval_policy` (D-421) — the caller
/// proceeds exactly as it always has, no behavior change.
///
/// Returns `Ok(Some(request))` when the action IS gated: this has already
/// submitted a pending `approval_request` row and written its
/// `Submitted` audit event in that same transaction. The caller MUST NOT execute its
/// mutation in this case — it should return the submitted request's id to
/// the client (see `attome-compliance`'s `rewrap_admin` or `attome-server`'s
/// `license_admin` for the response shape) so a different `system.admin`
/// can later decide it.
///
/// D-421 — when a policy matches `action_type`, the request is submitted
/// through `attome_approval::submit_with_plan` (its `ApprovalPlan`, sequenced
/// steps and all) instead of the original flat `attome_approval::submit`. This
/// is the one hook that makes every existing `gate()` caller (retention,
/// stored-query publish, dashboard publish, metadata bundle apply/break-
/// glass, schema change, role grant, erasure, DSR erasure) policy-aware
/// automatically, with no change to any of their own call sites — a policy
/// can require approval for an `action_type` even when it is not also
/// listed in `approval.required_actions` (the reverse of the old rule, where
/// that list was the only thing that could ever turn gating on).
///
/// BAP-19b (this function's former "known gap"): the `Submitted` audit
/// event is now written through `attome_approval::submit_*_with`'s
/// `BeforeCommit` hook, inside the insert's own transaction (D-062, D-545).
/// The request and the one event that names who asked for a sensitive
/// action commit together, or neither does; before this, the event was a
/// second round-trip after `submit` had already committed, and a crash
/// between the two left a real, still-approvable request with no
/// `Submitted` trail.
pub async fn gate(
    state: &EngineState,
    action_type: &str,
    payload: Value,
    requester: Uuid,
) -> Result<Option<ApprovalRequest>, AppError> {
    gate_inner(state, action_type, payload, requester, None, false).await
}

/// [`gate`], with `required` forcing approval even when no policy and no
/// `approval.required_actions` entry asks for it (a per-record setting, such
/// as an entity whose bin setting wants a second person for permanent
/// deletes, A18-T6).
pub async fn gate_required(
    state: &EngineState,
    action_type: &str,
    payload: Value,
    requester: Uuid,
    required: bool,
) -> Result<Option<ApprovalRequest>, AppError> {
    gate_inner(state, action_type, payload, requester, None, required).await
}

/// [`gate`] with a "regarding" record pointer (Dashboard 10/10 Phase 6
/// prerequisite, migration 0477): the specific record `action_type`'s
/// mutation is about, so a My-Work-style caller can run
/// `require_record_access` against it before ever showing the request as
/// actionable. `None` (what every existing `gate()` call site still gets)
/// leaves the request exactly as record-unfilterable as it is today —
/// wiring a specific `action_type` caller (`rewrap_admin`, `retention_admin`,
/// dashboard publish, …) to pass its own regarding record is each caller's
/// own follow-up, not done wholesale here.
pub async fn gate_regarding(
    state: &EngineState,
    action_type: &str,
    payload: Value,
    requester: Uuid,
    regarding: Option<(&str, Uuid)>,
) -> Result<Option<ApprovalRequest>, AppError> {
    gate_inner(state, action_type, payload, requester, regarding, false).await
}

/// An approval that is always required, regarding a record (F10-T7's
/// period close): unlike [`gate`], it never answers "no approval needed".
pub async fn gate_regarding_required(
    state: &EngineState,
    action_type: &str,
    payload: Value,
    requester: Uuid,
    regarding: Option<(&str, Uuid)>,
) -> Result<ApprovalRequest, AppError> {
    gate_inner(state, action_type, payload, requester, regarding, true)
        .await?
        .ok_or_else(|| AppError::internal("a required approval was not opened"))
}

async fn gate_inner(
    state: &EngineState,
    action_type: &str,
    payload: Value,
    requester: Uuid,
    regarding: Option<(&str, Uuid)>,
    required: bool,
) -> Result<Option<ApprovalRequest>, AppError> {
    // M45 Phase 3 (REVIEW-2026-09-02 finding #8): a policy that matched by
    // `action_type` is dropped back to "no policy" when its `condition`
    // does not permit this specific payload — the fallback below (the flat
    // `config_required` gate) still applies exactly as if no policy had
    // matched at all.
    let policy = find_matching_policy(&state.base.db, action_type)
        .await?
        .filter(|p| condition_permits(p.condition.as_deref(), &payload));
    let config_required = state
        .base
        .config
        .approval
        .required_actions
        .iter()
        .any(|a| a == action_type);
    if !config_required && !required && policy.is_none() {
        return Ok(None);
    }

    // BAP-19b: read the actor and organization *before* the submit opens its
    // transaction — a `BeforeCommit` hook runs on that transaction's own
    // connection and must do database work only (guidelines §4) — then hand
    // the event to whichever submit runs, so the request and its `Submitted`
    // trail commit together.
    let (user_ctx, organization_ref) = fetch_audit_ctx(state, requester).await;
    let submitted = SubmittedAudit {
        state,
        action_type,
        organization_ref,
        user_ctx,
    };

    let request = if let Some(policy) = policy {
        let backstop_ttl = plan_backstop_ttl(&policy.plan);
        attome_approval::submit_with_plan_regarding_with(
            &state.base.db,
            action_type,
            payload,
            requester,
            policy.plan,
            backstop_ttl,
            Some(policy.id),
            regarding,
            &submitted,
        )
        .await?
    } else {
        let ttl = chrono::Duration::hours(state.base.config.approval.ttl_hours);
        attome_approval::submit_regarding_with(
            &state.base.db,
            action_type,
            payload,
            requester,
            1,
            ttl,
            regarding,
            &submitted,
        )
        .await?
    };

    Ok(Some(request))
}

/// Writes `gate`'s `Submitted` event inside the submit's own transaction
/// (BAP-19b, D-062/D-545). Every field it needs is read *before* the submit
/// opens that transaction, so the hook itself does one insert and nothing
/// else. The event's shape is exactly what the old after-commit write
/// produced (Security category, `Submitted` operation, no entity name), so
/// existing audit rows and readers are unaffected.
struct SubmittedAudit<'s> {
    state: &'s EngineState,
    action_type: &'s str,
    organization_ref: Uuid,
    user_ctx: crate::AuditUserContext,
}

impl attome_db::BeforeCommit<ApprovalRequest> for SubmittedAudit<'_> {
    fn before_commit<'a>(
        &'a self,
        tx: &'a mut attome_db::Tx<'_>,
        request: &'a ApprovalRequest,
    ) -> attome_db::HookFuture<'a> {
        Box::pin(async move {
            let event = AuditEvent {
                organization_ref: self.organization_ref,
                category: AuditCategory::Security,
                entity_name: None,
                record_id: Some(request.id),
                operation: AuditOperation::Submitted,
                version_before: None,
                version_after: None,
                user_context: self.user_ctx.clone(),
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some(self.action_type.to_string()),
                event_comment: Some(format!(
                    "four-eyes approval request {} submitted for {}",
                    request.id, self.action_type
                )),
                changed_fields: vec![],
                snapshot_json: None,
            };
            audit_service(self.state).write_in_tx(tx, event).await?;
            Ok(())
        })
    }
}

// ── D-421 / M10 (Approval & Governance) — policy lookup, approver
// resolution, and delegation. All below is the "approver *resolution* stays
// in attome-audit" half of D-421's split with `attome-approval` (see that
// crate's `ApprovalPlan` doc comment for the other half). ──────────────────

/// One active `approval_policy` row, resolved down to just what
/// `gate`/the workflow approval node need.
pub struct ResolvedPolicy {
    pub id: Uuid,
    pub plan: ApprovalPlan,
    pub condition: Option<String>,
}

impl std::fmt::Debug for ResolvedPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedPolicy").finish_non_exhaustive()
    }
}

/// Looks up the single active, non-deleted policy for `action_type` — the
/// partial unique index on `approval_policy(action_type) WHERE
/// is_active AND NOT is_deleted` (migration `0183_xrm_core_approval_policy.sql`)
/// guarantees there is at most one, so "which policy applies" never needs
/// tie-breaking today, condition evaluation included: `condition_permits`
/// only ever decides "does the one candidate policy apply", never has to
/// choose among several.
///
/// Returns the raw `condition` text unevaluated — the caller (`gate`, the
/// workflow approval node) is the one with a `payload` to check it against,
/// via `condition_permits`.
pub async fn find_matching_policy(
    db: &PgPool,
    action_type: &str,
) -> Result<Option<ResolvedPolicy>, AppError> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        plan: Value,
        condition: Option<String>,
    }
    let row: Option<Row> = sqlx::query_as(
        "SELECT id, plan, condition FROM approval_policy \
         WHERE action_type = $1 AND is_active AND NOT is_deleted",
    )
    .bind(action_type)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let plan: ApprovalPlan = serde_json::from_value(row.plan)
        .map_err(|e| AppError::internal(format!("corrupt approval_policy.plan: {e}")))?;
    Ok(Some(ResolvedPolicy {
        id: row.id,
        plan,
        condition: row.condition,
    }))
}

/// Builds a `attome_rules` `Schema`/`Context` pair from `payload`'s top-level
/// object entries. A policy condition has no fixed entity to type-check
/// against — `action_type` varies (retention, role grant, schema change,
/// erasure, dashboard publish, ...), each with its own payload shape — so
/// field types come from the JSON values actually present rather than a
/// declared schema. Only scalar JSON types (number/string/bool) map to a
/// `attome_rules::Type`; a nested object/array field is skipped, so a
/// condition referencing one is rejected at compile time as `UnknownField`,
/// same as referencing any other absent field.
fn schema_and_context_for_payload(
    payload: &Value,
) -> (attome_rules::Schema, attome_rules::Context) {
    let mut schema = attome_rules::Schema::new();
    let mut ctx = attome_rules::Context::new(Utc::now());
    let Some(obj) = payload.as_object() else {
        return (schema, ctx);
    };
    for (k, v) in obj {
        let field = match v {
            Value::Number(n) => n
                .as_f64()
                .map(|f| (attome_rules::Type::Number, attome_rules::Value::Number(f))),
            Value::String(s) => Some((
                attome_rules::Type::Text,
                attome_rules::Value::Text(s.clone()),
            )),
            Value::Bool(b) => Some((attome_rules::Type::Bool, attome_rules::Value::Bool(*b))),
            _ => None,
        };
        if let Some((ty, val)) = field {
            schema = schema.with_field(k.clone(), ty);
            ctx = ctx.with_field(k.clone(), val);
        }
    }
    (schema, ctx)
}

/// Evaluates `condition` (an M45/attome-rules expression, `
/// approval_policy.condition`) against `payload` — M45 Phase 3
/// (REVIEW-2026-09-02 finding #8). `None` (no condition set) always
/// permits, the same unconditional-match posture Phase 1/2 had for every
/// policy. **Fails closed**: a condition that fails to compile or evaluate,
/// or evaluates to anything other than a clean `Value::Bool`, is treated as
/// satisfied (the stricter policy still applies, approval is still
/// required) — a malformed or unresolvable condition must never be the
/// reason a gated action skips its approval policy. Only a condition that
/// compiles and evaluates cleanly to `Bool(false)` genuinely means "this
/// policy does not apply to this payload".
pub fn condition_permits(condition: Option<&str>, payload: &Value) -> bool {
    let Some(expr) = condition else {
        return true;
    };
    let (schema, ctx) = schema_and_context_for_payload(payload);
    let compiled = match attome_rules::compile(expr, &schema) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                condition = expr,
                error = %e,
                "approval policy condition failed to compile; failing closed (approval still required)"
            );
            return true;
        }
    };
    match compiled.eval(&ctx) {
        Ok(attome_rules::Value::Bool(b)) => b,
        other => {
            tracing::warn!(
                condition = expr,
                result = ?other,
                "approval policy condition did not evaluate to a plain bool; failing closed (approval still required)"
            );
            true
        }
    }
}

/// The overall backstop TTL `gate`/the workflow approval node passes to
/// `attome_approval::submit_with_plan` — deliberately generous, and
/// deliberately not any one step's own SLA (see that function's doc
/// comment). Sums every step's `sla_minutes`, defaulting a step with none to
/// 7 days (same "a request can never live forever, even loosely
/// configured" posture the pre-D-421 fixed `approval.ttl_hours` already
/// had), plus a day of slack.
pub fn plan_backstop_ttl(plan: &ApprovalPlan) -> chrono::Duration {
    const DEFAULT_STEP_MINUTES: i64 = 7 * 24 * 60;
    const SLACK_MINUTES: i64 = 24 * 60;
    // BAP-16: a plan saved through the admin API is bounded by
    // `attome_approval::{MAX_PLAN_STEPS, MAX_SLA_MINUTES}` before it is ever
    // stored, so this sum is tiny for any real policy. A plan read back from
    // a row written before those caps existed — or edited by hand — must
    // still not panic here: the old `sum::<i64>()` overflowed and
    // `Duration::minutes` panicked on the wrapping value. Saturate instead,
    // and fall back to chrono's own maximum if even that is out of range;
    // the `submit_*` call this feeds maps the result through
    // `checked_add_signed`, so an unusable TTL is a 422, never a panic.
    let total = plan.steps.iter().fold(SLACK_MINUTES, |acc: i64, step| {
        acc.saturating_add(step.sla_minutes.unwrap_or(DEFAULT_STEP_MINUTES))
    });
    chrono::Duration::try_minutes(total).unwrap_or(chrono::Duration::MAX)
}

/// The literal `position:` token this release resolves — `position`
/// has no other well-known role to name generically (unlike `team:<uuid>`,
/// a position's *meaning* is relative to a request's requester, not a fixed
/// id), so this is the one accepted `position:` shape.
pub const POSITION_MANAGER_OF_REQUESTER: &str = "position:manager_of_requester";

/// Rejects an `approvers` token this workspace cannot resolve, *before* it
/// is ever saved into a policy — the strict counterpart of
/// `resolve_step_approvers`'s best-effort-skip-unknown-tokens behavior at
/// decide time. Supported today: `"user:<uuid>"`, `"role:<uuid>"`,
/// `"team:<uuid>"` (`team` membership, `user_account_mm_team`)
/// and the literal `"position:manager_of_requester"` (`position`'s
/// `parent_position_ref` hierarchy via `user_account_mm_position`) —
/// rejecting anything else here means an operator finds out at policy-save
/// time, not the first time a request against it can never be decided.
pub fn validate_approver_token(token: &str) -> Result<(), AppError> {
    for prefix in ["user:", "role:", "team:"] {
        if let Some(rest) = token.strip_prefix(prefix) {
            return Uuid::parse_str(rest).map(|_| ()).map_err(|_| {
                AppError::Validation(format!(
                    "invalid approver token {token:?}: {prefix} must be followed by a uuid"
                ))
            });
        }
    }
    if token == POSITION_MANAGER_OF_REQUESTER {
        return Ok(());
    }
    Err(AppError::Validation(format!(
        "unsupported approver token {token:?} — only \"user:<uuid>\", \"role:<uuid>\", \
         \"team:<uuid>\" and \"{POSITION_MANAGER_OF_REQUESTER}\" are resolvable in this release"
    )))
}

/// Runs [`validate_approver_token`] over every step of a plan — called by
/// attome-server's policy admin handler before insert/update, alongside
/// `ApprovalPlan::validate()`'s own structural checks.
pub fn validate_plan_approvers(plan: &ApprovalPlan) -> Result<(), AppError> {
    for step in &plan.steps {
        for token in &step.approvers {
            validate_approver_token(token)?;
        }
    }
    Ok(())
}

/// D-421 — turns one plan step's opaque `approvers` tokens into concrete
/// user ids, expands active delegation, and excludes the request's own
/// requester (self-approval is never eligible, delegated or not).
///
/// Returns `(step_population, principals, allowed_decider_ids, delegate_of)`:
/// - `step_population` / `principals` — the distinct named principals this
///   step resolved to, after removing the requester. `step_population` is
///   the basis `ApprovalStep::required_count` uses for `all`/`n_of_m`;
///   `principals` is who is allowed to *create* a delegation for this step
///   (`create_request_delegation`) — a delegate may not re-delegate further.
/// - `allowed_decider_ids` — `principals` plus every delegate currently
///   standing in for one of them. A delegation whose `to_user` would be the
///   requester is dropped before it ever reaches this set — D-421's core
///   invariant: delegation must never manufacture a path to self-approval.
/// - `delegate_of` — maps a delegate's id back to the principal they are
///   deputizing for, so the caller can pass the right `on_behalf_of` to
///   `attome_approval::decide_step`.
pub async fn resolve_step_approvers(
    state: &EngineState,
    step: &ApprovalStep,
    action_type: &str,
    requested_by: Uuid,
) -> Result<(usize, Vec<Uuid>, Vec<Uuid>, HashMap<Uuid, Uuid>), AppError> {
    let mut principals: HashSet<Uuid> = HashSet::new();
    for token in &step.approvers {
        if let Some(id) = token.strip_prefix("user:")
            && let Ok(id) = Uuid::parse_str(id)
        {
            principals.insert(id);
        } else if let Some(role_id) = token.strip_prefix("role:")
            && let Ok(role_id) = Uuid::parse_str(role_id)
        {
            let rows: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT ur.user_ref FROM user_account_mm_role ur \
                     JOIN user_account u ON u.id = ur.user_ref \
                     WHERE ur.role_ref = $1 AND ur.is_deleted = false \
                       AND (u.is_active IS NULL OR u.is_active = TRUE)",
            )
            .bind(role_id)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            principals.extend(rows.into_iter().map(|(id,)| id));
        } else if let Some(team_id) = token.strip_prefix("team:")
            && let Ok(team_id) = Uuid::parse_str(team_id)
        {
            let rows: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT tm.user_ref FROM user_account_mm_team tm \
                     JOIN user_account u ON u.id = tm.user_ref \
                     WHERE tm.team_ref = $1 AND tm.is_deleted = false \
                       AND (u.is_active IS NULL OR u.is_active = TRUE)",
            )
            .bind(team_id)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            principals.extend(rows.into_iter().map(|(id,)| id));
        } else if token == POSITION_MANAGER_OF_REQUESTER {
            // Every user holding the parent position of any position
            // `requested_by` holds — dual-hatting means more than one such
            // user is possible, same as `role:`'s "every member" semantics.
            // A requester holding no position, or holding only root
            // positions (no `parent_position_ref`), resolves to no one —
            // this step then falls back on whatever other tokens it names,
            // same as an empty `role:` membership does today.
            let rows: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT DISTINCT mgr.user_ref \
                 FROM user_account_mm_position req_pos \
                 JOIN position pos \
                     ON pos.id = req_pos.position_ref AND pos.is_deleted = false \
                 JOIN user_account_mm_position mgr \
                     ON mgr.position_ref = pos.parent_position_ref AND mgr.is_deleted = false \
                 JOIN user_account u ON u.id = mgr.user_ref \
                 WHERE req_pos.user_ref = $1 AND req_pos.is_deleted = false \
                   AND pos.parent_position_ref IS NOT NULL \
                   AND (u.is_active IS NULL OR u.is_active = TRUE)",
            )
            .bind(requested_by)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            principals.extend(rows.into_iter().map(|(id,)| id));
        }
        // Any other token shape is skipped here (best-effort at decide
        // time) — validate_approver_token/validate_plan_approvers is what
        // actually stops one being saved into a policy in the first place.
    }
    principals.remove(&requested_by);

    let principals: Vec<Uuid> = principals.into_iter().collect();
    let mut allowed: Vec<Uuid> = principals.clone();
    let mut delegate_of: HashMap<Uuid, Uuid> = HashMap::new();
    for &principal in &principals {
        let delegates: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT to_user FROM approval_delegation \
             WHERE from_user = $1 AND NOT is_deleted \
               AND valid_from <= NOW() AND valid_to > NOW() \
               AND (scope = 'all' OR scope = $2)",
        )
        .bind(principal)
        .bind(action_type)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        for (delegate,) in delegates {
            if delegate == requested_by {
                // D-421: never let a delegation reach the requester — the
                // eligible set stays exactly as if this delegation didn't
                // exist, rather than silently widening self-approval.
                continue;
            }
            delegate_of.entry(delegate).or_insert(principal);
            if !allowed.contains(&delegate) {
                allowed.push(delegate);
            }
        }
    }

    Ok((principals.len(), principals, allowed, delegate_of))
}

/// The slot a decider fills (BAP-D2): a named principal of the step always
/// decides in their *own* slot, even when another principal has also
/// delegated to them — only a decider who is not themselves a principal
/// stands in for someone (`on_behalf_of`). Stamping a principal's own
/// decision into the delegating principal's slot would leave their own slot
/// unfillable and an `all` step unable to ever close.
fn decider_on_behalf_of(
    decider_id: Uuid,
    principals: &[Uuid],
    delegate_of: &HashMap<Uuid, Uuid>,
) -> Option<Uuid> {
    if principals.contains(&decider_id) {
        None
    } else {
        delegate_of.get(&decider_id).copied()
    }
}

/// The plan-aware counterpart of a caller invoking `attome_approval::decide`
/// directly: resolves `request`'s *current* step's eligible approvers
/// (including delegation) and calls `attome_approval::decide_step` with them.
/// Only valid when `request.plan` is `Some` — `attome-server`'s decide handler
/// is the one that already branched on that before calling this.
pub async fn decide_request_step(
    state: &EngineState,
    request: &ApprovalRequest,
    decider_id: Uuid,
    decision: Decision,
    expected_row_version: i64,
) -> Result<ApprovalRequest, AppError> {
    decide_request_step_with(
        state,
        request,
        decider_id,
        decision,
        expected_row_version,
        None,
        &attome_db::NoHook,
    )
    .await
}

/// [`decide_request_step`] with the approver's optional decision `comment`
/// and a [`attome_db::BeforeCommit`] hook, both passed through to
/// `attome_approval::decide_step_with` (audit plan 3.6).
pub async fn decide_request_step_with(
    state: &EngineState,
    request: &ApprovalRequest,
    decider_id: Uuid,
    decision: Decision,
    expected_row_version: i64,
    comment: Option<&str>,
    hook: &dyn attome_db::BeforeCommit<ApprovalRequest>,
) -> Result<ApprovalRequest, AppError> {
    let plan = request.plan.as_ref().ok_or_else(|| {
        AppError::internal("decide_request_step called on a request with no plan")
    })?;
    let step_index = usize::try_from(request.step).map_err(AppError::internal)?;
    let step = plan.steps.get(step_index).ok_or_else(|| {
        AppError::internal("approval request step index out of range for its own plan")
    })?;
    let (population, principals, allowed, delegate_of) =
        resolve_step_approvers(state, step, &request.action_type, request.requested_by).await?;
    let on_behalf_of = decider_on_behalf_of(decider_id, &principals, &delegate_of);
    attome_approval::decide_step_with(
        &state.base.db,
        request.id,
        decider_id,
        on_behalf_of,
        &allowed,
        population,
        decision,
        expected_row_version,
        comment,
        hook,
    )
    .await
}

/// Backs `POST /api/v1/admin/approvals/{id}/delegate` — lets `from_user`
/// (who must actually be a *named* approver on `request`'s current step, not
/// merely a delegate themselves — delegation is one hop, not a chain) hand
/// their standing on this one request's `action_type` to `to_user`, for the
/// rest of this request's window unless `valid_to` narrows it. Returns the
/// new `approval_delegation` row's id.
pub async fn create_request_delegation(
    state: &EngineState,
    request: &ApprovalRequest,
    from_user: Uuid,
    to_user: Uuid,
    valid_to: Option<DateTime<Utc>>,
) -> Result<Uuid, AppError> {
    if from_user == to_user {
        return Err(AppError::Validation(
            "cannot delegate to yourself".to_string(),
        ));
    }
    if to_user == request.requested_by {
        return Err(AppError::Validation(
            "cannot delegate approval authority to this request's own requester".to_string(),
        ));
    }
    let plan = request.plan.as_ref().ok_or_else(|| {
        AppError::Validation("this request has no policy plan to delegate on".to_string())
    })?;
    let step_index = usize::try_from(request.step).map_err(AppError::internal)?;
    let step = plan.steps.get(step_index).ok_or_else(|| {
        AppError::internal("approval request step index out of range for its own plan")
    })?;
    let (_population, principals, _allowed, _delegate_of) =
        resolve_step_approvers(state, step, &request.action_type, request.requested_by).await?;
    if !principals.contains(&from_user) {
        return Err(AppError::Forbidden);
    }

    let valid_to = valid_to.unwrap_or(request.expires_at);
    let id = Uuid::now_v7();
    // D-541 rule 4 / D-062: delegating approval standing changes who may
    // authorize an action, so the grant and its `Access` + `Grant` event
    // commit together.
    let mut tx = crate::security::SecurityTx::begin(
        state,
        crate::security::SecurityEvent::new(
            crate::security::MandatoryCategory::Access,
            AuditOperation::Grant,
            from_user,
            "approval_delegation",
            Some(id),
        )
        .named(request.action_type.clone())
        .comment(format!(
            "approval standing on request {} delegated by {from_user} to {to_user} until {valid_to}",
            request.id
        )),
    )
    .await?;
    sqlx::query(
        "INSERT INTO approval_delegation \
             (id, from_user, to_user, valid_from, valid_to, scope, created_by) \
         VALUES ($1, $2, $3, NOW(), $4, $5, $2)",
    )
    .bind(id)
    .bind(from_user)
    .bind(to_user)
    .bind(valid_to)
    .bind(&request.action_type)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(id)
}

/// Z10-T7: hands all of `from_user`'s approval standing to `to_user` for an
/// absence, from `valid_from` to `valid_to`. `source` is `out_of_office` (the
/// signed-in user's own `PUT /api/v1/approvals/out-of-office`) or `leave`:
/// W6 calls this with `leave` when a leave request is approved, so
/// approvals keep moving while the approver is away. An earlier delegation
/// of the same user and source that overlaps the new window is ended
/// (soft-deleted) in the same transaction as the insert and the `Access` +
/// `Grant` event. Returns the new delegation's id.
pub async fn upsert_absence_delegation(
    state: &EngineState,
    from_user: Uuid,
    to_user: Uuid,
    valid_from: DateTime<Utc>,
    valid_to: DateTime<Utc>,
    source: &str,
) -> Result<Uuid, AppError> {
    if from_user == to_user {
        return Err(AppError::Validation(
            "cannot delegate to yourself".to_string(),
        ));
    }
    if valid_to <= valid_from {
        return Err(AppError::Validation(
            "valid_to must be after valid_from".to_string(),
        ));
    }
    if !matches!(source, "leave" | "out_of_office") {
        return Err(AppError::Validation(format!(
            "unknown delegation source {source:?}"
        )));
    }
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_account          WHERE id = $1 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(to_user)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !live {
        return Err(AppError::Validation(
            "the delegate is not an active user".to_string(),
        ));
    }

    let id = Uuid::now_v7();
    let mut tx = crate::security::SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Grant,
            from_user,
            "approval_delegation",
            Some(id),
        )
        .named(format!("absence:{source}"))
        .comment(format!(
            "approval standing of {from_user} delegated to {to_user} from {valid_from} to              {valid_to} ({source})"
        )),
    )
    .await?;
    sqlx::query(
        "UPDATE approval_delegation SET is_deleted = true          WHERE from_user = $1 AND source = $2 AND NOT is_deleted            AND valid_from < $4 AND valid_to > $3",
    )
    .bind(from_user)
    .bind(source)
    .bind(valid_from)
    .bind(valid_to)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO approval_delegation              (id, from_user, to_user, valid_from, valid_to, scope, created_by, source)          VALUES ($1, $2, $3, $4, $5, 'all', $2, $6)",
    )
    .bind(id)
    .bind(from_user)
    .bind(to_user)
    .bind(valid_from)
    .bind(valid_to)
    .bind(source)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(id)
}

/// Z10-T7: ends `from_user`'s current and future absence delegations of
/// `source`, with an `Access` + `Revoke` event in the same transaction.
/// Returns how many were ended.
pub async fn end_absence_delegation(
    state: &EngineState,
    from_user: Uuid,
    source: &str,
) -> Result<u64, AppError> {
    let mut tx = crate::security::SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Revoke,
            from_user,
            "approval_delegation",
            None,
        )
        .named(format!("absence:{source}"))
        .comment(format!(
            "absence delegation ({source}) of {from_user} ended"
        )),
    )
    .await?;
    let ended = sqlx::query(
        "UPDATE approval_delegation SET is_deleted = true          WHERE from_user = $1 AND source = $2 AND NOT is_deleted AND valid_to > NOW()",
    )
    .bind(from_user)
    .bind(source)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    tx.commit().await?;
    Ok(ended)
}

/// Applies one due step timeout and writes the matching audit event — the
/// audit-aware wrapper around `attome_approval::apply_step_timeout_with`, which
/// has no audit-writing capability of its own (base layer, guidelines §1).
/// Reused by `attome_notification::poller`'s tick (M51's escalation sweep) so
/// approval-plan timeouts ride the same periodic scanner notification
/// escalation already does, rather than a second background-task system
/// (guidelines §13).
///
/// D-545 / BAP-6b: the event is written through a `BeforeCommit` hook, so it
/// commits **inside** the timeout's own transaction or not at all (D-062).
/// Before this, the event was written after the timeout committed and a
/// failure was only logged, leaving an automatic approval with no audit
/// trail.
///
/// Returns `Ok(None)` when nothing was due (already covered by
/// `attome_approval::apply_step_timeout`'s own doc comment). On `Escalated`,
/// also returns the resolved ids of the step's eligible approvers so the
/// caller — which actually owns a notification-send API, this crate
/// deliberately does not — knows who to notify. An `Expired` outcome (BAP-6a)
/// is reported the same way any automatic decision is: nothing to send, its
/// event already written.
pub async fn apply_and_audit_step_timeout(
    state: &EngineState,
    request_id: Uuid,
) -> Result<Option<(ApprovalRequest, attome_approval::TimeoutOutcome, Vec<Uuid>)>, AppError> {
    apply_and_audit_step_timeout_with(state, request_id, &attome_db::NoHook).await
}

/// [`apply_and_audit_step_timeout`] with a caller-owned hook that runs in the
/// same transaction, after the audit event. BAP-11b: the sweep enqueues the
/// auto-approved request's execution job here, so the approval and the job
/// that carries it out commit together or not at all — this crate cannot
/// enqueue it itself without a attome-jobs dependency it has no other use for.
pub async fn apply_and_audit_step_timeout_with(
    state: &EngineState,
    request_id: Uuid,
    extra: &dyn attome_db::BeforeCommit<(ApprovalRequest, attome_approval::TimeoutOutcome)>,
) -> Result<Option<(ApprovalRequest, attome_approval::TimeoutOutcome, Vec<Uuid>)>, AppError> {
    // The event names the request's organization, and the hook cannot look
    // it up itself: it runs on the timeout's own connection, inside its
    // transaction (guidelines §4). One cheap read before that transaction
    // opens, exactly as the old after-the-fact write did.
    let existing = attome_approval::get(&state.base.db, request_id).await?;
    let (_discarded_ctx, organization_ref) = fetch_audit_ctx(state, existing.requested_by).await;

    // D-545 / BAP-6b: the timeout's audit event goes through a
    // `BeforeCommit` hook, so it commits with the status change or not at
    // all. It used to be written after the timeout committed, with a failure
    // only logged — an automatic approval (or an escalation) with no audit
    // trail. The hook's value carries the outcome as well as the request,
    // because an escalated step and an auto-decided one are different
    // operations.
    //
    // The actor stays `POLICY_ACTOR_ID` (nil), this crate's sentinel for a
    // decision with no human behind it; a reader shows it as "policy".
    let audit = AuditHook::new(
        audit_service(state),
        move |committed: &(ApprovalRequest, attome_approval::TimeoutOutcome)| {
            let (request, outcome) = committed;
            let (operation, outcome_word) = match outcome {
                attome_approval::TimeoutOutcome::Escalated => {
                    (AuditOperation::Escalated, "escalated")
                }
                attome_approval::TimeoutOutcome::AutoApproved => {
                    (AuditOperation::Approved, "auto-approved")
                }
                attome_approval::TimeoutOutcome::AutoRejected => {
                    (AuditOperation::Rejected, "auto-rejected")
                }
                // BAP-6a: the request was past its backstop, so the timeout
                // expired it instead of deciding it.
                attome_approval::TimeoutOutcome::Expired => (AuditOperation::Closed, "expired"),
            };
            vec![HookEvent::Security(
                SecurityEvent::new(
                    MandatoryCategory::Security,
                    operation,
                    attome_approval::POLICY_ACTOR_ID,
                    "approval_request",
                    Some(request.id),
                )
                .named(request.action_type.clone())
                .comment(format!(
                    "four-eyes approval request {} step {} {outcome_word} on SLA timeout \
                     (decided_by=policy)",
                    request.id, request.step
                ))
                .source(AuditSource::BackgroundJob)
                .organization(organization_ref),
            )]
        },
    );

    let Some((request, outcome)) = attome_approval::apply_step_timeout_with(
        &state.base.db,
        request_id,
        &attome_db::Chain(&audit, extra),
    )
    .await?
    else {
        return Ok(None);
    };

    // BAP-13 / BAP-F8: one point per automatic decision, labelled by
    // outcome. A policy timeout is the only automatic decider in the
    // platform, so this is the one place the counter can be incremented;
    // `Escalated` decides nothing and is deliberately not counted. A
    // decision the hook rolled back never reaches here, so the counter
    // tracks decisions that actually committed.
    match outcome {
        attome_approval::TimeoutOutcome::Escalated => {}
        attome_approval::TimeoutOutcome::AutoApproved => {
            metrics::counter!("approval_auto_decisions_total", "outcome" => "auto_approved")
                .increment(1);
        }
        attome_approval::TimeoutOutcome::AutoRejected => {
            metrics::counter!("approval_auto_decisions_total", "outcome" => "auto_rejected")
                .increment(1);
        }
        attome_approval::TimeoutOutcome::Expired => {
            metrics::counter!("approval_auto_decisions_total", "outcome" => "expired").increment(1);
        }
    }

    // Only an `Escalated` outcome has someone to notify, and only this
    // function can resolve who they are (approver resolution is this
    // crate's half of D-421's split). The audit event is already written —
    // inside the timeout's transaction — by the hook above.
    let mut notify_ids = Vec::new();
    if outcome == attome_approval::TimeoutOutcome::Escalated
        && let Some(plan) = &request.plan
    {
        let step_index = usize::try_from(request.step).unwrap_or(0);
        if let Some(step) = plan.steps.get(step_index)
            && let Ok((_pop, _principals, allowed, _delegate_of)) =
                resolve_step_approvers(state, step, &request.action_type, request.requested_by)
                    .await
        {
            notify_ids = allowed;
        }
    }

    Ok(Some((request, outcome, notify_ids)))
}

#[cfg(test)]
mod condition_permits_tests {
    use super::*;

    #[test]
    fn no_condition_always_permits() {
        assert!(condition_permits(None, &serde_json::json!({})));
    }

    #[test]
    fn a_true_condition_permits() {
        let payload = serde_json::json!({ "amount": 15000.0 });
        assert!(condition_permits(Some("amount > 10000"), &payload));
    }

    #[test]
    fn a_false_condition_does_not_permit() {
        let payload = serde_json::json!({ "amount": 500.0 });
        assert!(!condition_permits(Some("amount > 10000"), &payload));
    }

    #[test]
    fn a_condition_referencing_a_missing_field_fails_closed_to_permit() {
        // `amount` is absent from the payload -> compile fails
        // (`UnknownField`) -> fail closed -> still gated.
        let payload = serde_json::json!({ "other_field": "x" });
        assert!(condition_permits(Some("amount > 10000"), &payload));
    }

    #[test]
    fn a_syntactically_invalid_condition_fails_closed_to_permit() {
        let payload = serde_json::json!({});
        assert!(condition_permits(Some("amount >>> 10000"), &payload));
    }

    #[test]
    fn a_non_bool_condition_result_fails_closed_to_permit() {
        let payload = serde_json::json!({ "amount": 42.0 });
        assert!(condition_permits(Some("amount"), &payload));
    }

    #[test]
    fn string_and_bool_payload_fields_are_usable_too() {
        let payload = serde_json::json!({ "kind": "erasure", "urgent": true });
        assert!(condition_permits(
            Some("kind == \"erasure\" and urgent"),
            &payload
        ));
        assert!(!condition_permits(
            Some("kind == \"erasure\" and urgent"),
            &serde_json::json!({ "kind": "erasure", "urgent": false })
        ));
    }
}

#[cfg(test)]
mod decider_slot_tests {
    use super::*;

    /// BAP-D2: on an `all` step {A, B} where B delegated to A, A's own
    /// decision fills A's slot, never B's.
    #[test]
    fn a_principal_who_is_also_a_delegate_decides_in_their_own_slot() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        let d = Uuid::now_v7();
        let principals = [a, b];
        let delegate_of = HashMap::from([(a, b), (d, b)]);
        assert_eq!(decider_on_behalf_of(a, &principals, &delegate_of), None);
        assert_eq!(decider_on_behalf_of(b, &principals, &delegate_of), None);
        // A non-principal delegate still stands in for their principal.
        assert_eq!(decider_on_behalf_of(d, &principals, &delegate_of), Some(b));
        // Someone neither: no slot of their own to stand in for.
        assert_eq!(
            decider_on_behalf_of(Uuid::now_v7(), &principals, &delegate_of),
            None
        );
    }
}

#[cfg(test)]
mod backstop_ttl_tests {
    use super::*;

    fn step(sla_minutes: Option<i64>) -> ApprovalStep {
        ApprovalStep {
            mode: attome_approval::StepMode::Any,
            threshold: None,
            approvers: vec!["user:a".to_string()],
            sla_minutes,
            on_timeout: attome_approval::OnTimeout::Escalate,
            extras: Default::default(),
        }
    }

    #[test]
    fn a_normal_plan_sums_its_steps_and_the_default_and_slack() {
        const DEFAULT_STEP_MINUTES: i64 = 7 * 24 * 60;
        const SLACK_MINUTES: i64 = 24 * 60;
        let plan = ApprovalPlan {
            steps: vec![step(Some(60)), step(None)],
        };
        assert_eq!(
            plan_backstop_ttl(&plan),
            chrono::Duration::minutes(60 + DEFAULT_STEP_MINUTES + SLACK_MINUTES)
        );
    }

    /// BAP-16: a plan whose SLAs sum past chrono's range saturates instead of
    /// panicking (the old `sum::<i64>()` + `Duration::minutes` did both).
    /// `submit_with_plan` then maps the result through `checked_add_signed`,
    /// so the caller sees a 422, never a 500 from a `CatchPanic`.
    #[test]
    fn an_enormous_plan_saturates_instead_of_panicking() {
        let plan = ApprovalPlan {
            steps: (0..attome_approval::MAX_PLAN_STEPS + 4)
                .map(|_| step(Some(i64::MAX)))
                .collect(),
        };
        assert_eq!(plan_backstop_ttl(&plan), chrono::Duration::MAX);
    }
}

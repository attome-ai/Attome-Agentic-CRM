//! `POST /api/v1/decisions/{id}/execute` — M28 Phase 1 (Decision
//! Intelligence, `document/module-master-plans/M28-decision-intelligence.md`).
//!
//! Ordinary field CRUD on `dashboard_decision`/`dashboard_decision_option`/
//! `dashboard_decision_dependency`, and the `proposed -> approved` transition
//! (`/api/v1/decisions/{id}/approve`), live in `attome_dashboard::decision` —
//! that crate owns the entities (`DashboardModel::owned_entities`). This
//! module owns only `execute` (`approved -> executed`), and it lives here
//! instead, deliberately: `execute` has to call [`crate::execute::dispatch`],
//! and `attome-dashboard` cannot depend on `attome-ai` without closing a cycle
//! — `attome-api` depends on `attome-dashboard` for real (`approval_admin.rs`'s
//! `do_publish_dashboard` dispatch), and (M98) `attome-api` now also depends
//! on `attome-ai` for real (`approval_admin.rs`'s
//! `dispatch_approved_agent_action` call), so `attome-dashboard -> attome-ai`
//! would still close a cycle through `attome-api` even though D-477 (T3-2)
//! removed the older, narrower `attome-ai -> attome-api` edge this comment
//! used to cite. `attome_dashboard::decision`'s own module doc carries the same
//! reasoning from the other side.
//!
//! So this route reads/writes `dashboard_decision`/`dashboard_decision_option` by bound
//! SQL, the same way `attome_metric::metric` reads tables (`sql_query`)
//! it does not own the seed of. It is mounted as its own [`EngineModel`]
//! ([`DecisionExecutionModel`]), gated by `MODULE_DASHBOARD` — a decision is a
//! dashboard concept even though *running* its chosen option goes through the
//! action registry — and it owns no entities of its own (`attome_dashboard`
//! already claims the three `dashboard_decision*` tables; see that crate's
//! `model.rs` comment).
//!
//! ## The Consequential contract (plan §7)
//!
//! *A `Consequential` option cannot execute without an approval request id.*
//! [`crate::gate::evaluate`] does not enforce this for a human caller —
//! `(RiskTier::Consequential, Initiator::User) => GateDecision::Execute`,
//! see that match arm's own comment: a human invoking a Consequential action
//! through the UI is answered by the deployment's `approval.required_actions`
//! four-eyes policy, not by the per-invocation gate. Wiring the *generic*
//! `attome_audit::approval::gate`/`execute_approved` admin surface
//! (`attome-api::approval_admin`) for this route is no longer blocked by a
//! cycle the way it was before M98 — `attome-api` now has a real dependency
//! on `attome-ai` (`execute_approved`'s `attome-ai/invoke` arm) — but
//! migrating decision-option execution onto that generic surface is a
//! separate, unstarted change (it would mean `attome_dashboard::decision`
//! submitting the approval with an `execute_approved`-recognized
//! `action_type`, and this route's own gate check going away in favor of the
//! admin surface's). Until that migration happens, this route enforces the
//! narrower, plan-stated contract itself: a `Consequential` option may
//! run only when `dashboard_decision.approval_request_ref` already names an
//! **Approved** `approval_request` row — created through the
//! ordinary `attome_approval::submit`/`decide` flow by whichever process
//! decided this decision needed four-eyes. No action registered today is
//! `Consequential` (see `actions/mod.rs`), so this path is defensive and
//! future-proofed rather than exercised by a real action yet; `mod tests`
//! below exercises the pure gate function directly, without a database.
//!
//! ## A known Phase-1 gap: double-execute is not fully closed
//!
//! Unlike `attome_dashboard::decision::do_approve`, this handler does not take
//! an advisory lock across the whole request. It cannot: [`dispatch`] does
//! real work (today, database reads/writes through other engines; once
//! `Effect::External` actions exist, outbound HTTP), and guidelines §4/§13
//! forbid holding a database transaction across that. Instead it reads the
//! decision, validates, dispatches, then finalizes with a `row_version` CAS
//! (guidelines §2's optimistic-concurrency rule) — so two concurrent
//! `execute` calls can both pass validation and both dispatch, and only one
//! finalizing `UPDATE` wins; the other logs an error and reports a conflict
//! **after the action has already run**. This mirrors the platform's existing,
//! stated posture for direct invocation (`gate.rs`: "a human clicking twice is
//! a human's decision, not a retry loop") rather than inventing a stronger
//! guarantee for decisions specifically. Closing it for real needs either an
//! idempotency key on this route or a short-lived "claim" write before
//! dispatch — left as follow-up, not hidden.

use attome_approval::ApprovalStatus;
use attome_audit::AuditOperation;
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_DASHBOARD, ModuleId};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::RiskTier;
use crate::execute::{ActionOutcome, dispatch};
use crate::session::{self, InvocationRecord};

/// `dashboard_decision.update` — same key `attome_dashboard::auth::DecisionUpdate`
/// declares for the sibling `approve` route. Duplicated rather than shared:
/// this crate cannot depend on `attome-dashboard` for one marker type without
/// the same cycle risk this module's own doc comment describes for
/// `dispatch` (`attome-dashboard` does not currently depend on `attome-ai` or
/// `attome-api`, so today this would not literally cycle — but a marker-type
/// dependency invites a real one to follow it later, and a duplicated
/// `&'static str` costs nothing to keep the boundary clean).
struct DecisionExecute;

impl PrivilegeKey for DecisionExecute {
    const KEY: &'static str = "dashboard_decision.update";
}

/// Thin wrapper over the shared `attome_audit::write_business_event` (M26 R-15
/// dedup — see `attome_dashboard::lifecycle::write_lifecycle_audit`'s own
/// comment). No `Executed` discriminant exists on `AuditOperation` — this is
/// a field-level state transition, same category the generic `Update`
/// already covers for `lifecycle.rs`'s non-milestone transitions; the
/// specific semantics ride in the fixed `event_name`/caller-supplied
/// `comment`.
async fn write_decision_audit(
    state: &EngineState,
    decision_id: Uuid,
    actor_id: Uuid,
    version_before: Option<i64>,
    version_after: Option<i64>,
    comment: String,
) {
    attome_audit::write_business_event(
        state,
        "dashboard_decision",
        decision_id,
        AuditOperation::Update,
        "decision.execute",
        actor_id,
        version_before,
        version_after,
        comment,
    )
    .await;
}

/// Best-effort: records why an option could not run. Never escalates its own
/// failure into the response — the caller already has the real reason as the
/// returned `AppError`; this is bookkeeping, not the primary answer.
async fn set_refusal_reason(
    state: &EngineState,
    decision_id: Uuid,
    reason: &str,
    expected_row_version: i64,
) {
    let result = sqlx::query(
        "UPDATE dashboard_decision SET refusal_reason = $2, modified_at = NOW(), \
         row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $3",
    )
    .bind(decision_id)
    .bind(reason)
    .bind(expected_row_version)
    .execute(&state.base.db)
    .await;
    match result {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => tracing::warn!(
            decision_id = %decision_id,
            "refusal_reason write lost a concurrency race — the decision changed \
             before its refusal could be recorded",
        ),
        Err(e) => tracing::error!(
            decision_id = %decision_id,
            error = %e,
            "failed to write decision refusal_reason",
        ),
    }
}

struct DecisionRow {
    status: String,
    chosen_option_ref: Option<Uuid>,
    approval_request_ref: Option<String>,
    row_version: i64,
}

/// `(status, chosen_option_ref, approval_request_ref, row_version)`.
type DecisionRowTuple = (Option<String>, Option<Uuid>, Option<String>, i64);

async fn load_decision(state: &EngineState, decision_id: Uuid) -> Result<DecisionRow, AppError> {
    let row: Option<DecisionRowTuple> = sqlx::query_as(
        "SELECT status, chosen_option_ref, approval_request_ref, row_version \
           FROM dashboard_decision \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(decision_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (status, chosen_option_ref, approval_request_ref, row_version) =
        row.ok_or(AppError::NotFound)?;
    Ok(DecisionRow {
        status: status.unwrap_or_else(|| "proposed".to_string()),
        chosen_option_ref,
        approval_request_ref,
        row_version,
    })
}

struct OptionRow {
    action_id: String,
    args: Option<String>,
}

async fn load_option(
    state: &EngineState,
    decision_id: Uuid,
    option_id: Uuid,
) -> Result<OptionRow, AppError> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT action_id, args FROM dashboard_decision_option \
          WHERE id = $1 AND decision_ref = $2",
    )
    .bind(option_id)
    .bind(decision_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (action_id, args) = row.ok_or(AppError::NotFound)?;
    Ok(OptionRow { action_id, args })
}

fn parse_args(args: Option<&str>) -> Result<Value, AppError> {
    match args {
        None => Ok(Value::Null),
        Some(s) if s.trim().is_empty() => Ok(Value::Null),
        Some(s) => serde_json::from_str(s).map_err(|_| {
            AppError::Validation("the chosen option's stored arguments are not valid JSON".into())
        }),
    }
}

/// The plan §7 contract, decided without touching the database: a
/// `Consequential` option needs an `approval_request_ref` to even consider —
/// returns the id to look up when one is required, or `None` when the risk
/// tier doesn't require this check at all.
fn approval_ref_to_check(
    risk: RiskTier,
    approval_request_ref: Option<&str>,
) -> Result<Option<Uuid>, &'static str> {
    if risk != RiskTier::Consequential {
        return Ok(None);
    }
    let raw = approval_request_ref.ok_or(
        "this option's action is Consequential and requires an approved \
         approval_request_ref before it can execute",
    )?;
    let id = Uuid::parse_str(raw)
        .map_err(|_| "approval_request_ref does not name a valid approval request id")?;
    Ok(Some(id))
}

#[derive(Deserialize, ToSchema)]
struct ExecuteBody {
    row_version: i64,
}

#[derive(Serialize, ToSchema)]
struct ExecuteResponse {
    id: Uuid,
    status: String,
    row_version: i64,
    outcome: ActionOutcome,
}

/// `POST /api/v1/decisions/{id}/execute` — runs the decision's chosen
/// option through [`dispatch`], the platform's one execution path (I-2), and
/// records the invocation id + result status on the decision.
#[utoipa::path(
    post,
    path = "/api/v1/decisions/{id}/execute",
    tag = "dashboard",
    params(("id" = Uuid, Path)),
    request_body = ExecuteBody,
    responses(
        (status = 200, description = "Success", body = ExecuteResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege, or the option's action requires an approved approval request", body = ErrorResponse),
        (status = 404, description = "No such decision, option, or action", body = ErrorResponse),
        (status = 409, description = "Not approved, or row_version is stale", body = ErrorResponse),
        (status = 422, description = "The option's stored arguments failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
// Named `execute_decision`, not `execute`: utoipa derives the operationId
// from the function name, and `attome_records::query_exec::execute` already owns
// `execute` (same collision-avoidance convention `engine.rs`'s own
// `list_invocable_actions` doc comment documents for `list_actions`). Two
// operations sharing an id generate a duplicate TypeScript identifier and
// break the Angular build.
async fn execute_decision(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DecisionExecute>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ExecuteBody>,
) -> Result<Json<ExecuteResponse>, AppError> {
    let decision = load_decision(&state, id).await?;
    if decision.row_version != body.row_version {
        return Err(AppError::Conflict(
            "row_version does not match the decision's current state — reload and retry",
        ));
    }
    if decision.status != "approved" {
        return Err(AppError::Conflict(
            "only an approved decision can be executed",
        ));
    }
    let Some(option_id) = decision.chosen_option_ref else {
        // Data-integrity failure, not a caller error: `approve` always sets
        // `chosen_option_ref` in the same transaction that flips the status.
        tracing::error!(decision_id = %id, "decision is approved but has no chosen_option_ref");
        return Err(AppError::internal(
            "decision is approved but has no chosen option",
        ));
    };
    let option = load_option(&state, id, option_id).await?;

    let Some(descriptor) = crate::engine::REGISTRY.resolve(&option.action_id) else {
        return Err(AppError::NotFound);
    };

    match approval_ref_to_check(descriptor.risk, decision.approval_request_ref.as_deref()) {
        Ok(None) => {}
        Ok(Some(approval_id)) => match attome_approval::get(&state.base.db, approval_id).await {
            Ok(request) if request.status == ApprovalStatus::Approved => {}
            Ok(_) => {
                let reason = "approval_request_ref does not name an Approved request";
                set_refusal_reason(&state, id, reason, body.row_version).await;
                return Err(AppError::Forbidden);
            }
            Err(_) => {
                let reason = "approval_request_ref does not name an existing approval request";
                set_refusal_reason(&state, id, reason, body.row_version).await;
                return Err(AppError::Validation(reason.to_string()));
            }
        },
        Err(reason) => {
            set_refusal_reason(&state, id, reason, body.row_version).await;
            return Err(AppError::Forbidden);
        }
    }

    let args = parse_args(option.args.as_deref())?;
    let action_ctx = ActionContext::user(ctx.into_inner());
    let user_id = action_ctx.security.user_id;
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let gate_inputs = crate::engine::gate_inputs(&state, descriptor.module);

    let outcome = dispatch(
        &state,
        &crate::engine::REGISTRY,
        &crate::engine::EXECUTORS,
        &option.action_id,
        &action_ctx,
        &gate_inputs,
        &args,
    )
    .await;

    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(e) => {
            // A safe, canned message — never the raw `AppError` (guidelines
            // §6/§7: no internal detail in a field a caller can read back).
            let reason = match &e {
                AppError::NotFound => "action not found, unlicensed, or disabled",
                AppError::Forbidden => "caller lacks the required privilege for this action",
                AppError::Validation(_) | AppError::FieldValidation(_) => {
                    "the option's arguments failed validation"
                }
                AppError::Conflict(_) => "conflict while executing this action",
                _ => "action execution failed",
            };
            set_refusal_reason(&state, id, reason, body.row_version).await;
            return Err(e);
        }
    };

    let (result, provenance) = match outcome {
        ActionOutcome::Completed { result, provenance } => (result, provenance),
        // Unreachable in practice: `action_ctx` is always `Initiator::User`
        // here, and `gate::evaluate`'s matrix never returns either of these
        // for a user-initiated call. Handled anyway because `ActionOutcome`
        // is exhaustively matched, and because "unreachable" is a claim about
        // today's gate matrix, not a guarantee.
        ActionOutcome::ConfirmationRequired { .. }
        | ActionOutcome::ApprovalRequired { .. }
        | ActionOutcome::Scheduled { .. } => {
            tracing::error!(
                decision_id = %id,
                "dispatch returned a confirmation/approval outcome for a \
                 user-initiated decision execute — this should be unreachable",
            );
            let reason = "the action requires confirmation or approval and cannot run through decision execution";
            set_refusal_reason(&state, id, reason, body.row_version).await;
            return Err(AppError::Conflict(reason));
        }
    };

    let invocation_id = session::record_invocation_returning_id(
        &state.base.db,
        InvocationRecord {
            session_id: None,
            tool_call_id: None,
            action_id: descriptor.id,
            is_agent: false,
            acting_user_id: user_id,
            outcome: "completed",
            result: Some(&result),
        },
    )
    .await?;

    let rows_affected = sqlx::query(
        "UPDATE dashboard_decision SET status = 'executed', action_invocation_ref = $2, \
         refusal_reason = NULL, modified_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $3",
    )
    .bind(id)
    .bind(invocation_id.map(|u| u.to_string()))
    .bind(body.row_version)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if rows_affected != 1 {
        // See this module's doc comment ("A known Phase-1 gap"): the action
        // already ran by this point. Logged loudly because this is the one
        // place that gap actually surfaces.
        tracing::error!(
            decision_id = %id,
            invocation_id = ?invocation_id,
            "action executed but the decision's row_version changed before its \
             status could be updated to 'executed' — a concurrent request won \
             the race",
        );
        return Err(AppError::Conflict(
            "the action ran, but the decision's row_version changed before its \
             status could be updated — reload and check action_invocation_ref",
        ));
    }

    let row_version = body.row_version + 1;
    write_decision_audit(
        &state,
        id,
        user_id,
        Some(body.row_version),
        Some(row_version),
        format!("decision {id} executed, action {}", option.action_id),
    )
    .await;

    Ok(Json(ExecuteResponse {
        id,
        status: "executed".to_string(),
        row_version,
        outcome: ActionOutcome::Completed { result, provenance },
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/decisions/{id}/execute", post(execute_decision))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(execute_decision))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

/// Registered via `EngineSystem::builder(state).register(DecisionExecutionModel)`
/// — mounted only when `dashboard` is a licensed module bit (D-010), same gate
/// `attome_dashboard::DashboardModel` uses. Owns no entities of its own: the
/// three `dashboard_decision*` tables stay claimed by `DashboardModel` (see that
/// crate's `model.rs` comment).
#[derive(Debug)]
pub struct DecisionExecutionModel;

impl EngineModel for DecisionExecutionModel {
    fn name(&self) -> &'static str {
        "attome-ai-decision"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_DASHBOARD
    }

    fn routes(&self) -> Router<EngineState> {
        routes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plan §7 contract, exercised without a database: Read/Reversible
    /// options never need an approval_request_ref.
    #[test]
    fn a_non_consequential_option_needs_no_approval_ref() {
        assert_eq!(approval_ref_to_check(RiskTier::Read, None), Ok(None));
        assert_eq!(approval_ref_to_check(RiskTier::Reversible, None), Ok(None));
    }

    /// A `Consequential` option with no `approval_request_ref` at all is
    /// refused before any database lookup happens.
    #[test]
    fn a_consequential_option_is_refused_with_no_approval_ref() {
        assert!(approval_ref_to_check(RiskTier::Consequential, None).is_err());
    }

    /// A malformed `approval_request_ref` is refused rather than silently
    /// treated as "no approval" or panicking on the `Uuid::parse_str`.
    #[test]
    fn a_consequential_option_is_refused_with_a_malformed_approval_ref() {
        assert!(approval_ref_to_check(RiskTier::Consequential, Some("not-a-uuid")).is_err());
    }

    /// A `Consequential` option with a well-formed ref is handed back for the
    /// caller to look up and check the request's status.
    #[test]
    fn a_consequential_option_with_a_valid_ref_is_returned_for_lookup() {
        let id = Uuid::now_v7();
        assert_eq!(
            approval_ref_to_check(RiskTier::Consequential, Some(&id.to_string())),
            Ok(Some(id))
        );
    }

    /// Empty and whitespace-only stored arguments both parse as `Value::Null`
    /// rather than a JSON error — the common case for an option whose action
    /// takes no arguments.
    #[test]
    fn empty_args_parse_as_null() {
        assert_eq!(parse_args(None).unwrap(), Value::Null);
        assert_eq!(parse_args(Some("")).unwrap(), Value::Null);
        assert_eq!(parse_args(Some("   ")).unwrap(), Value::Null);
    }

    /// Well-formed JSON arguments parse through unchanged.
    #[test]
    fn well_formed_args_parse() {
        let v = parse_args(Some(r#"{"a":1}"#)).unwrap();
        assert_eq!(v, serde_json::json!({"a": 1}));
    }

    /// Malformed stored arguments are a validation error, not a panic or a
    /// silent `Value::Null` — a corrupted `args` column must not make an
    /// action run with different arguments than an admin actually configured.
    #[test]
    fn malformed_args_are_refused() {
        assert!(parse_args(Some("{not json")).is_err());
    }
}

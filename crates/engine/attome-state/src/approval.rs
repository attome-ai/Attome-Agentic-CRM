//! M07 Phase F (D-770) — a state transition that requires a multi-party
//! approval, run by `attome-approval`.
//!
//! **The request** is not here: a write asking for a plan-bearing transition
//! goes through the one write path (`entity_mutation::update_one`), which
//! checks privilege and guard as for any transition, writes the transition's
//! `pending_state` instead of the target, and submits the
//! `state.transition` request regarding the record in the same transaction.
//!
//! **This module moves a record out of its pending state**, always through
//! that same write path with `MutationMode::ApprovalFlow(request_id)`, which
//! the mutation engine checks against the request itself (latest request for
//! the record, record still in the pending state, only the state field, the
//! target the request's status allows):
//!
//! - [`execute_approved_transition`] — the executor. The approval dispatcher
//!   (`attome_api::approval_admin::dispatch_approved`) calls it holding the
//!   request's execution claim (D-518). It moves `pending_state -> to` as the
//!   policy actor (`attome_approval::POLICY_ACTOR_ID`), with the request id and
//!   the final approver on the audit event; the dispatcher then completes the
//!   claim. A record whose `row_version` is no longer the one the request
//!   froze (it changed underneath) is not moved: the executor answers
//!   [`ExecutedTransition::Invalidated`], the dispatcher invalidates the
//!   request, and the record stays pending with a `warn!` naming both
//!   versions — releasing it is then an explicit act ([`cancel_or_release`]).
//!   A replayed execution changes nothing: the claim cannot be taken twice,
//!   and the mutation check refuses any request that is not `executing`.
//! - [`settle_closed_request`] — a request closed without executing moves the
//!   record on: rejected to `on_reject_state` (with the rejection comment on
//!   the audit event, which the timeline shows), cancelled / expired /
//!   invalidated back to the origin.
//! - [`cancel_or_release`] — `POST /{entity}/{id}/transition/cancel`: the
//!   requester withdraws an open request (`attome_approval::cancel`, audited in
//!   its transaction) and the record returns to the origin; or, when the
//!   request already closed without executing but the record is still parked
//!   (a rejection whose settle failed, an expiry, an invalidation), the
//!   requester or an administrator finishes returning it.
//!
//! Every move is a separate transaction after the request's own transition
//! (attome-approval owns that transaction), so a crash between the two leaves a
//! closed request and a parked record; [`cancel_or_release`] is the recovery
//! path, and a rejection or cancel logs an `error!` when its settle fails.

use attome_approval::{ApprovalRequest, ApprovalStatus};
use attome_audit::security::{AuditHook, HookEvent, MandatoryCategory, SecurityEvent};
use attome_audit::{AuditOperation, audit_service};
use attome_core::{ACTION_STATE_TRANSITION, EngineState, TransitionApprovalPayload, quote_ident};
use attome_records::entity_crud::{
    admin_security_context, require_record_access, update_record_for_outcome,
};
use attome_records::entity_mutation::MutationMode;
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::model::TransitionResult;

/// Validates a transition's approval configuration (admin API and bundle
/// reconcile alike): `approval_plan` and `pending_state` come together, and
/// `on_reject_state` only with them; the plan passes attome-approval's own
/// structural validator and attome-audit's approver-token check; the pending
/// state is a state of its own (not the edge's ends, nor the model's initial
/// state, which a new record could otherwise be created in), and a rejection
/// does not land back in it. Whether each state is an option of the state
/// field is checked by the caller that can see the field
/// (`admin::validate_transition_states`).
pub(crate) fn validate_transition_approval(
    from_state: &str,
    to_state: &str,
    approval_plan: Option<&attome_approval::ApprovalPlan>,
    pending_state: Option<&str>,
    on_reject_state: Option<&str>,
    initial_state: Option<&str>,
) -> Result<(), AppError> {
    let Some(plan) = approval_plan else {
        if pending_state.is_some() || on_reject_state.is_some() {
            return Err(AppError::Validation(
                "pending_state and on_reject_state are only allowed with an approval_plan".into(),
            ));
        }
        return Ok(());
    };
    let pending = pending_state
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| {
            AppError::Validation("a transition with an approval_plan needs a pending_state".into())
        })?;
    plan.validate()?;
    attome_audit::approval::validate_plan_approvers(plan)?;
    if pending == from_state || pending == to_state {
        return Err(AppError::Validation(format!(
            "pending_state '{pending}' must differ from the transition's from_state and to_state"
        )));
    }
    if initial_state == Some(pending) {
        return Err(AppError::Validation(format!(
            "pending_state '{pending}' must not be the model's initial state"
        )));
    }
    if let Some(reject) = on_reject_state
        && reject.trim() == pending
    {
        return Err(AppError::Validation(format!(
            "on_reject_state must not be the pending_state '{pending}'"
        )));
    }
    Ok(())
}

/// What [`execute_approved_transition`] did with a claimed request.
#[derive(Debug)]
pub enum ExecutedTransition {
    /// The record moved to the requested state; a summary of the move.
    Executed(Value),
    /// The move was refused at execution time; the reason is logged and the
    /// caller invalidates the request. The record is left where it is.
    Invalidated(&'static str),
}

/// The request's frozen payload and the record it is about.
fn payload_of(request: &ApprovalRequest) -> Result<(TransitionApprovalPayload, Uuid), AppError> {
    if request.action_type != ACTION_STATE_TRANSITION {
        return Err(AppError::internal(format!(
            "approval request {} is not a state transition request",
            request.id
        )));
    }
    let payload: TransitionApprovalPayload = serde_json::from_value(request.payload.clone())
        .map_err(|e| AppError::internal(format!("corrupt state.transition payload: {e}")))?;
    let record_id = request
        .regarding_id
        .filter(|_| request.regarding_entity.as_deref() == Some(payload.entity.as_str()))
        .ok_or_else(|| {
            AppError::internal(format!(
                "state.transition request {} has no matching regarding record",
                request.id
            ))
        })?;
    Ok((payload, record_id))
}

/// The record's live state-field value and `row_version`, or `None` when it
/// no longer exists. A read only; every write goes through the update path.
async fn current_state(
    state: &EngineState,
    payload: &TransitionApprovalPayload,
    record_id: Uuid,
) -> Result<Option<(Option<String>, i64)>, AppError> {
    let table = quote_ident(&payload.entity);
    let field = quote_ident(&payload.state_field);
    sqlx::query_as::<_, (Option<String>, i64)>(&format!(
        "SELECT {field}, row_version FROM {table} WHERE id = $1 AND is_active = true"
    ))
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The executor for an `executing` [`ACTION_STATE_TRANSITION`] request (see
/// the module doc). `approver_id` is whoever closed the request (a human's
/// final approval, or `POLICY_ACTOR_ID` for a policy auto-approval); it is
/// named on the audit event, while the write itself is the policy actor's.
///
/// `Err` is a transient failure the dispatcher releases the claim for (the
/// request stays `approved` for `retry-execution`); every refusal that will
/// not change on retry is [`ExecutedTransition::Invalidated`].
pub async fn execute_approved_transition(
    state: &EngineState,
    request: &ApprovalRequest,
    approver_id: Uuid,
) -> Result<ExecutedTransition, AppError> {
    if request.status != ApprovalStatus::Executing {
        return Err(AppError::internal(format!(
            "state.transition request {} executed without its claim (status {})",
            request.id, request.status
        )));
    }
    let (payload, record_id) = payload_of(request)?;
    let Some((current, row_version)) = current_state(state, &payload, record_id).await? else {
        tracing::warn!(
            request_id = %request.id,
            entity = %payload.entity,
            %record_id,
            "approved state transition not executed: the record no longer exists"
        );
        return Ok(ExecutedTransition::Invalidated(
            "the record no longer exists",
        ));
    };
    if current.as_deref() != Some(payload.pending_state.as_str())
        || row_version != payload.row_version
    {
        tracing::warn!(
            request_id = %request.id,
            entity = %payload.entity,
            %record_id,
            expected_state = %payload.pending_state,
            actual_state = current.as_deref().unwrap_or(""),
            expected_row_version = payload.row_version,
            actual_row_version = row_version,
            "approved state transition not executed: the record changed while its approval \
             was open; the request is invalidated and the record stays where it is (release it \
             with POST /api/v1/{{entity}}/{{id}}/transition/cancel)"
        );
        return Ok(ExecutedTransition::Invalidated(
            "the record changed while its transition approval was open",
        ));
    }

    let actor = attome_approval::POLICY_ACTOR_ID;
    let decided_by = if approver_id == attome_approval::POLICY_ACTOR_ID {
        "by policy".to_owned()
    } else {
        format!("with final approval by {approver_id}")
    };
    let comment = format!(
        "approval request {} approved {decided_by}: '{}' -> '{}' (requested by {})",
        request.id, payload.pending_state, payload.to, payload.requested_by
    );
    let mut body = serde_json::Map::new();
    body.insert(
        payload.state_field.clone(),
        Value::String(payload.to.clone()),
    );
    let outcome = update_record_for_outcome(
        state,
        &admin_security_context(actor),
        actor,
        &payload.entity,
        record_id,
        payload.row_version,
        Value::Object(body),
        Some(comment),
        MutationMode::ApprovalFlow(request.id),
    )
    .await;
    match outcome {
        Ok(outcome) => {
            tracing::info!(
                request_id = %request.id,
                entity = %payload.entity,
                %record_id,
                to = %payload.to,
                "approved state transition executed"
            );
            Ok(ExecutedTransition::Executed(json!({
                "entity": payload.entity,
                "record_id": record_id,
                "from_state": payload.pending_state,
                "to_state": payload.to,
                "row_version": outcome.response.row_version(),
            })))
        }
        Err(AppError::VersionConflict | AppError::NotFound) => {
            tracing::warn!(
                request_id = %request.id,
                entity = %payload.entity,
                %record_id,
                "approved state transition not executed: the record changed or vanished at \
                 execution time; the request is invalidated"
            );
            Ok(ExecutedTransition::Invalidated(
                "the record changed while its transition approval was open",
            ))
        }
        Err(AppError::TransitionNotAllowed(why) | AppError::Validation(why)) => {
            tracing::warn!(
                request_id = %request.id,
                entity = %payload.entity,
                %record_id,
                reason = %why,
                "approved state transition refused by the record's rules at execution time; \
                 the request is invalidated"
            );
            Ok(ExecutedTransition::Invalidated(
                "the record's rules refused the approved transition",
            ))
        }
        Err(e) => Err(e),
    }
}

/// Moves a record out of its pending state after its request closed without
/// executing: `rejected` to the frozen `on_reject_state`, `cancelled` /
/// `expired` / `invalidated` back to the origin. `actor_id` is who closed it
/// (the rejecting approver, the cancelling requester, the releasing admin);
/// `comment` (a rejection's reason, say) goes on the audit event.
///
/// `Ok(None)` when there is nothing to do: not a state-transition request, or
/// the record already left the pending state (a second settle is a no-op).
/// A request that is still open or was executed is `409`.
pub async fn settle_closed_request(
    state: &EngineState,
    request: &ApprovalRequest,
    actor_id: Uuid,
    comment: Option<&str>,
) -> Result<Option<TransitionResult>, AppError> {
    if request.action_type != ACTION_STATE_TRANSITION {
        return Ok(None);
    }
    let (payload, record_id) = payload_of(request)?;
    let (target, verb) = match request.status {
        ApprovalStatus::Rejected => (payload.on_reject_state.clone(), "rejected"),
        ApprovalStatus::Cancelled => (payload.from.clone(), "cancelled"),
        ApprovalStatus::Recalled => (payload.from.clone(), "recalled"),
        ApprovalStatus::Expired => (payload.from.clone(), "expired"),
        ApprovalStatus::Invalidated => (payload.from.clone(), "invalidated"),
        ApprovalStatus::Pending | ApprovalStatus::Approved | ApprovalStatus::Executing => {
            return Err(AppError::Conflict(
                "the record's transition approval is still open",
            ));
        }
        ApprovalStatus::Executed => {
            return Err(AppError::Conflict(
                "the record's transition approval was already carried out",
            ));
        }
    };
    let Some((current, row_version)) = current_state(state, &payload, record_id).await? else {
        return Ok(None);
    };
    if current.as_deref() != Some(payload.pending_state.as_str()) {
        return Ok(None);
    }
    let note = match comment.map(str::trim).filter(|c| !c.is_empty()) {
        Some(c) => format!(
            "approval request {} {verb}: '{}' -> '{target}'; comment: {c}",
            request.id, payload.pending_state
        ),
        None => format!(
            "approval request {} {verb}: '{}' -> '{target}'",
            request.id, payload.pending_state
        ),
    };
    let mut body = serde_json::Map::new();
    body.insert(payload.state_field.clone(), Value::String(target.clone()));
    let outcome = update_record_for_outcome(
        state,
        &admin_security_context(actor_id),
        actor_id,
        &payload.entity,
        record_id,
        row_version,
        Value::Object(body),
        Some(note),
        MutationMode::ApprovalFlow(request.id),
    )
    .await?;
    tracing::info!(
        request_id = %request.id,
        entity = %payload.entity,
        %record_id,
        status = %request.status,
        to = %target,
        "state transition approval settled"
    );
    Ok(Some(TransitionResult {
        record_id,
        from_state: Some(payload.pending_state),
        to_state: target,
        row_version: outcome.response.row_version(),
        approval_request_id: None,
        requested_state: None,
    }))
}

/// Settles after a decision or cancellation that another surface already
/// committed (the approval admin routes). The decision stands whatever
/// happens here, so a failure is logged, not returned: the record stays
/// parked and [`cancel_or_release`] finishes it.
pub async fn settle_after_close(
    state: &EngineState,
    request: &ApprovalRequest,
    actor_id: Uuid,
    comment: Option<&str>,
) {
    if request.action_type != ACTION_STATE_TRANSITION {
        return;
    }
    if let Err(e) = settle_closed_request(state, request, actor_id, comment).await {
        tracing::error!(
            request_id = %request.id,
            status = %request.status,
            error = %e,
            "state transition approval closed but its record could not be moved out of the \
             pending state; release it with POST /api/v1/{{entity}}/{{id}}/transition/cancel"
        );
    }
}

/// `POST /api/v1/{entity}/{id}/transition/cancel` (see the module doc). The
/// caller has already passed the entity-level `{entity}.update` check; the
/// record-level check runs here.
pub async fn cancel_or_release(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    record_id: Uuid,
    comment: Option<String>,
) -> Result<TransitionResult, AppError> {
    let entity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    require_record_access(
        state,
        ctx,
        entity_id,
        entity,
        record_id,
        RecordAction::Update,
    )
    .await?;
    let comment = attome_approval::normalize_decision_comment(comment.as_deref())?;

    let request = attome_approval::latest_regarding_with(
        &state.base.db,
        ACTION_STATE_TRANSITION,
        entity,
        record_id,
    )
    .await?
    .ok_or(AppError::Conflict(
        "this record has no transition approval to cancel",
    ))?;
    let (payload, _) = payload_of(&request)?;
    let parked = current_state(state, &payload, record_id)
        .await?
        .ok_or(AppError::NotFound)?
        .0
        .as_deref()
        == Some(payload.pending_state.as_str());
    if !parked {
        return Err(AppError::Conflict(
            "this record is not waiting on a transition approval",
        ));
    }

    let closed = match request.status {
        ApprovalStatus::Pending => {
            // attome-approval enforces requester-only (403 otherwise) and the
            // request's row_version CAS; the Cancelled event commits with it.
            let note = comment.clone();
            let hook = AuditHook::new(audit_service(state), move |cancelled: &ApprovalRequest| {
                let mut event = SecurityEvent::new(
                    MandatoryCategory::Security,
                    AuditOperation::Cancelled,
                    ctx.user_id,
                    "approval_request",
                    Some(cancelled.id),
                )
                .named(ACTION_STATE_TRANSITION);
                event = event.comment(match &note {
                    Some(c) => format!(
                        "state transition approval {} cancelled by its requester; comment: {c}",
                        cancelled.id
                    ),
                    None => format!(
                        "state transition approval {} cancelled by its requester",
                        cancelled.id
                    ),
                });
                vec![HookEvent::Security(event)]
            });
            attome_approval::cancel_with(
                &state.base.db,
                request.id,
                ctx.user_id,
                request.row_version,
                &hook,
            )
            .await?
        }
        ApprovalStatus::Rejected
        | ApprovalStatus::Cancelled
        | ApprovalStatus::Recalled
        | ApprovalStatus::Expired
        | ApprovalStatus::Invalidated => {
            if ctx.user_id != request.requested_by && !ctx.is_admin {
                return Err(AppError::Forbidden);
            }
            request
        }
        ApprovalStatus::Approved | ApprovalStatus::Executing => {
            return Err(AppError::Conflict(
                "the transition approval has been granted and is being carried out",
            ));
        }
        ApprovalStatus::Executed => {
            return Err(AppError::Conflict(
                "the transition approval was already carried out",
            ));
        }
    };

    settle_closed_request(state, &closed, ctx.user_id, comment.as_deref())
        .await?
        .ok_or(AppError::Conflict(
            "this record is not waiting on a transition approval",
        ))
}

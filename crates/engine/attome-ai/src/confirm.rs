//! The confirm round-trip (C4, `POST …/tool-calls/{tid}/confirm`).
//!
//! > **The client confirms a server-persisted proposal; it does not submit a
//! > new one** (I-13).
//!
//! The request carries the tool-call id and the `arguments_hash` the UI
//! displayed — nothing else. The arguments that run are the ones the server
//! stored when the model proposed them.
//!
//! **A human confirmation authorizes execution of the agent action that was
//! proposed; it is not a conversion of that action into a user-initiated
//! one.** The action runs under the session's own agent context, with the
//! persisted `tool_call_id` as its D-502 idempotency key, through
//! [`crate::execute::dispatch_confirmed_agent_action`].
//!
//! ## The transaction map (row A-41)
//!
//! 1. **Claim (tx C, [`tool_call::claim_reclaiming`]).** Reclaim this row's
//!    lease if it has expired, then `proposed → executing` conditional on the
//!    displayed hash. A failed claim is classified from the state actually
//!    persisted, read in the same transaction.
//! 2. **Privilege snapshot**, on its own connection
//!    (`attome_security::resolve_uncached`). A point-in-time snapshot: **not**
//!    protected by the transaction below or by the session-row lock.
//! 3. **Check transaction T.** In the canonical lock order — the session row,
//!    then the account row, both `FOR SHARE` — read the transactionally
//!    lockable state; then evaluate the point-in-time checks (registry
//!    resolution, licence, AI surface, air-gap, allow-list, privilege,
//!    ceiling — `gate::admissible`) for this claimant; write any resulting
//!    transition conditional on the claimed `row_version`; commit. **T's
//!    commit is the authorization point.**
//! 4. **Execution** under the D-502 claim, then the final conditional write.
//!
//! State that changes after its check has completed — privilege, licence,
//! action registration, AI switch, air-gap, session or account — does not
//! cancel the execution already admitted; it applies to the next admission.
//! Session and account state get the stronger guarantee: a change committed
//! before T's read is seen, and one committed concurrently waits for T.
//!
//! Every write to the proposal after the claim is conditional on the claimed
//! `row_version`; zero rows means the claim was lost and the writer does not
//! clobber. No normal path leaves the row `executing`. A database failure
//! after the claim is answered with a best-effort return to `proposed`, and
//! the lease sweep is the backstop for a failure of that too — a re-confirm
//! then meets the D-502 ledger and cannot execute twice.

use std::sync::Arc;

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::conversation::{self, Access, Conversation};
use crate::descriptor::ActionDescriptor;
use crate::execute::{ConfirmedExecution, Executors};
use crate::registry::ActionRegistry;
use crate::session::{self, AgentSession, SessionForExecution};
use crate::tool_call::{self, Claim, Status, ToolCallRow};

/// One confirm request, as the route parses it.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmRequest<'a> {
    /// The authenticated human confirming.
    pub caller: Uuid,
    pub conversation_id: Uuid,
    pub tool_call_id: &'a str,
    /// The `arguments_hash` the UI displayed — a staleness check, never the
    /// source of the payload.
    pub displayed_hash: &'a str,
}

/// What a confirm produced.
#[derive(Debug)]
pub enum ConfirmOutcome {
    /// The action ran now; its result.
    Executed { result: Value },
    /// A `Consequential` action was submitted for four-eyes approval.
    ApprovalRequested { approval_request_id: Uuid },
    /// Nothing ran on this request.
    Refused(ConfirmRefusal),
}

/// Why a confirm did not run the action. Every variant is decided from the
/// state actually persisted — the proposal row or the invocation ledger —
/// never from a failed update alone.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfirmRefusal {
    /// No such conversation for this caller, or no such tool call in it. One
    /// answer for both (I-20).
    NotFound,
    /// The displayed hash no longer matches: the human was not shown this.
    /// The proposal is unchanged.
    StaleHash,
    /// The proposal moved underneath this request (a lost race, or this
    /// request's claim was reclaimed). Nothing ran; the human may retry.
    Conflict,
    /// Another confirm of this proposal is executing it, or an earlier one
    /// crashed holding its execution claim.
    InProgress,
    /// Another confirm already executed it; its recorded result, from
    /// `action_invocation`.
    AlreadyExecuted { result: Option<Value> },
    /// It is waiting on a four-eyes approval.
    ApprovalPending { approval_request_id: Option<Uuid> },
    /// It is `rejected`, `expired` or `invalidated`.
    Terminal { status: Status },
    /// This confirm's checks refused it; the proposal is now `invalidated`.
    Invalidated { reason: &'static str },
    /// The session is paused. The proposal is back to `proposed` and may be
    /// confirmed once the session resumes.
    SessionPaused,
    /// The session's daily write total is spent. Back to `proposed`.
    WriteLimitReached,
    /// The action ran and failed; nothing committed. Back to `proposed` when
    /// the failure was transient (see [`is_transient`]); otherwise
    /// `invalidated`, because a proposal's arguments cannot change, so a
    /// refusal of them — a rejected argument, a record that is gone, a
    /// `row_version` that moved, a write the caller may no longer make — is
    /// refused identically on every retry.
    ActionFailed { invalidated: bool },
    /// The side effect may have committed but its completion was not
    /// recorded; the execution claim is still held, so it never runs again.
    /// Back to `proposed`, where every retry meets "in progress".
    OutcomeUnrecorded,
}

/// Runs the confirm round-trip. See the module doc for the transaction map.
///
/// `Err` is an infrastructure failure (the database), answered as retryable;
/// every business outcome is `Ok`.
pub async fn confirm_tool_call(
    state: &EngineState,
    registry: &ActionRegistry,
    executors: &Executors,
    request: ConfirmRequest<'_>,
) -> Result<ConfirmOutcome, AppError> {
    let db = &state.base.db;

    // Authorize the conversation before anything else (I-20, rows A-38/A-65).
    let Some(conversation) =
        conversation::load_for(db, request.conversation_id, Access::Owner(request.caller)).await?
    else {
        return Ok(ConfirmOutcome::Refused(ConfirmRefusal::NotFound));
    };

    // 1. The claim (tx C).
    let row = match tool_call::claim_reclaiming(
        db,
        conversation.id,
        request.tool_call_id,
        request.displayed_hash,
        tool_call::CONFIRM_LEASE,
    )
    .await?
    {
        Claim::Claimed(row) => *row,
        other => {
            return Ok(ConfirmOutcome::Refused(
                classify_failed_claim(state, &conversation, request.tool_call_id, other).await?,
            ));
        }
    };

    match admit_and_execute(state, registry, executors, &conversation, &row).await {
        Ok(outcome) => Ok(outcome),
        Err(e) => {
            // A database failure after the claim — including a deadlock that
            // rolled T back before the executor was reached. Return the row to
            // `proposed` if nothing has moved it since; the lease sweep is the
            // backstop if this write fails too.
            if let Err(release) =
                tool_call::resolve(db, row.id, row.row_version, Status::Proposed, None, None).await
            {
                tracing::error!(
                    tool_call = %row.id,
                    error = %release,
                    "confirm: could not return a claimed proposal to proposed after a failure; \
                     the lease sweep will"
                );
            }
            Err(e)
        }
    }
}

/// The answer to a claim that did not take the row, from the state the claim
/// transaction read.
async fn classify_failed_claim(
    state: &EngineState,
    conversation: &Conversation,
    tool_call_id: &str,
    claim: Claim,
) -> Result<ConfirmRefusal, AppError> {
    Ok(match claim {
        Claim::Claimed(_) => unreachable!("classify_failed_claim is only called on a failed claim"),
        Claim::Gone => ConfirmRefusal::NotFound,
        Claim::StaleHash => ConfirmRefusal::StaleHash,
        Claim::LostRace => ConfirmRefusal::Conflict,
        Claim::NotProposed {
            status,
            approval_request_id,
        } => match status {
            Status::Executing => ConfirmRefusal::InProgress,
            Status::Executed => ConfirmRefusal::AlreadyExecuted {
                // The invocation ledger is authoritative for what ran.
                result: session::prior_invocation(
                    &state.base.db,
                    conversation.agent_session_id,
                    tool_call_id,
                )
                .await?
                .and_then(|prior| prior.result),
            },
            Status::ApprovalPending => ConfirmRefusal::ApprovalPending {
                approval_request_id,
            },
            Status::Proposed => ConfirmRefusal::Conflict,
            status => ConfirmRefusal::Terminal { status },
        },
    })
}

/// What the check transaction decided.
enum Admission<'r> {
    Admitted {
        descriptor: &'r ActionDescriptor,
        ctx: ActionContext,
    },
    Refused(ConfirmRefusal),
}

/// Steps 2–4 of the module doc, for a row this request has claimed.
async fn admit_and_execute(
    state: &EngineState,
    registry: &ActionRegistry,
    executors: &Executors,
    conversation: &Conversation,
    row: &ToolCallRow,
) -> Result<ConfirmOutcome, AppError> {
    let db = &state.base.db;

    // 2. The privilege snapshot, on its own connection, before T — so T holds
    //    its locks only briefly. Point-in-time; not protected by T.
    //    `resolve_uncached` itself refuses a missing or disabled account
    //    (`require_active_user`) with `Forbidden`. That is the account check,
    //    taken unlocked; T takes it again under the lock and records the
    //    verdict, so it is carried into T as "no snapshot" rather than
    //    escaping as an error.
    let security = match attome_security::resolve_uncached(db, conversation.owner_user_id).await {
        Ok(security) => Some(Arc::new(security)),
        Err(attome_types::AppError::Forbidden) => None,
        Err(e) => return Err(e),
    };

    // 3. The check transaction.
    let admission = check_transaction(state, registry, conversation, row, security).await?;
    let (descriptor, ctx) = match admission {
        Admission::Admitted { descriptor, ctx } => (descriptor, ctx),
        Admission::Refused(refusal) => return Ok(ConfirmOutcome::Refused(refusal)),
    };

    // 4. Execution, under the D-502 claim.
    let execution = crate::execute::dispatch_confirmed_agent_action(
        state,
        executors,
        descriptor,
        &ctx,
        &row.arguments,
    )
    .await?;

    let (status, recorded, approval_request_id, answer) = match execution {
        ConfirmedExecution::Executed(result) => (
            Status::Executed,
            Some(result.clone()),
            None,
            ConfirmOutcome::Executed { result },
        ),
        ConfirmedExecution::AlreadyExecuted(result) => (
            Status::Executed,
            Some(result.clone()),
            None,
            ConfirmOutcome::Refused(ConfirmRefusal::AlreadyExecuted {
                result: Some(result),
            }),
        ),
        ConfirmedExecution::InProgress => (
            Status::Proposed,
            None,
            None,
            ConfirmOutcome::Refused(ConfirmRefusal::InProgress),
        ),
        ConfirmedExecution::ApprovalRequired { approval_id } => (
            Status::ApprovalPending,
            None,
            Some(approval_id),
            ConfirmOutcome::ApprovalRequested {
                approval_request_id: approval_id,
            },
        ),
        ConfirmedExecution::WriteLimitReached => (
            Status::Proposed,
            None,
            None,
            ConfirmOutcome::Refused(ConfirmRefusal::WriteLimitReached),
        ),
        ConfirmedExecution::Failed(e) => {
            let invalidated = !is_transient(&e);
            tracing::warn!(
                error = %e,
                action = %descriptor.id,
                tool_call = %row.id,
                "confirm: the confirmed action failed"
            );
            (
                if invalidated {
                    Status::Invalidated
                } else {
                    Status::Proposed
                },
                invalidated.then(|| json!({ "reason": "the action refused these arguments" })),
                None,
                ConfirmOutcome::Refused(ConfirmRefusal::ActionFailed { invalidated }),
            )
        }
        ConfirmedExecution::OutcomeUnrecorded(e) => {
            tracing::error!(
                error = %e,
                action = %descriptor.id,
                tool_call = %row.id,
                "confirm: the side effect may have committed but its completion was not \
                 recorded; the execution claim is held, so it will not run again"
            );
            (
                Status::Proposed,
                None,
                None,
                ConfirmOutcome::Refused(ConfirmRefusal::OutcomeUnrecorded),
            )
        }
    };

    let landed = tool_call::resolve(
        db,
        row.id,
        row.row_version,
        status,
        recorded.as_ref(),
        approval_request_id,
    )
    .await?;
    if landed {
        return Ok(answer);
    }

    // 7. The claim was lost mid-dispatch (the lease was reclaimed). Do not
    //    clobber the reclaimed row; answer from the ledger, which this
    //    request's execution claim — if it took one — still owns.
    if let ConfirmOutcome::Executed { .. } = answer {
        // The mutation is this request's own and it happened; the reclaimed
        // row is reconciled by the ledger on the next confirm.
        return Ok(answer);
    }
    let prior =
        session::prior_invocation(db, conversation.agent_session_id, &row.tool_call_id).await?;
    Ok(ConfirmOutcome::Refused(match prior {
        Some(prior) if prior.outcome == session::OUTCOME_COMPLETED => {
            ConfirmRefusal::AlreadyExecuted {
                result: prior.result,
            }
        }
        Some(prior) if prior.outcome == session::OUTCOME_CLAIMED => ConfirmRefusal::InProgress,
        _ => ConfirmRefusal::Conflict,
    }))
}

/// The check transaction T (row A-41): lockable state read under `FOR SHARE`
/// in the canonical order, point-in-time admission checks, and the resulting
/// transition — all committed together.
async fn check_transaction<'r>(
    state: &EngineState,
    registry: &'r ActionRegistry,
    conversation: &Conversation,
    row: &ToolCallRow,
    security: Option<Arc<attome_server::security::SecurityContext>>,
) -> Result<Admission<'r>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    let refusal = match evaluate(state, registry, conversation, row, security, &mut tx).await? {
        Ok(admitted) => {
            tx.commit().await.map_err(AppError::internal)?;
            return Ok(admitted);
        }
        Err(refusal) => refusal,
    };

    let (status, reason, answer) = match refusal {
        Refusal::Invalidate(reason) => (
            Status::Invalidated,
            Some(json!({ "reason": reason })),
            ConfirmRefusal::Invalidated { reason },
        ),
        Refusal::Paused => (Status::Proposed, None, ConfirmRefusal::SessionPaused),
        Refusal::Retry => (Status::Proposed, None, ConfirmRefusal::Conflict),
    };
    let landed =
        tool_call::resolve_in(&mut tx, row.id, row.row_version, status, reason.as_ref()).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Admission::Refused(if landed {
        answer
    } else {
        // The claim was lost before T could record its verdict; the row is
        // whatever the reclaimer left, and nothing ran.
        ConfirmRefusal::Conflict
    }))
}

/// A refusal T writes, and to which state.
enum Refusal {
    Invalidate(&'static str),
    Paused,
    /// The unlocked snapshot and the locked read disagreed about the account
    /// (it was reactivated in between). Nothing ran; back to `proposed`.
    Retry,
}

/// The checks inside T, in the canonical lock order. `Ok(Err(_))` is a
/// refusal to record; `Err(_)` is a database failure that rolls T back.
async fn evaluate<'r>(
    state: &EngineState,
    registry: &'r ActionRegistry,
    conversation: &Conversation,
    row: &ToolCallRow,
    security: Option<Arc<attome_server::security::SecurityContext>>,
    tx: &mut sqlx::PgConnection,
) -> Result<Result<Admission<'r>, Refusal>, AppError> {
    // Lock order, first: the session row.
    let session: AgentSession =
        match session::lock_for_confirmation(tx, conversation.agent_session_id).await? {
            SessionForExecution::Live(session) => session,
            SessionForExecution::Paused => return Ok(Err(Refusal::Paused)),
            SessionForExecution::Gone => {
                return Ok(Err(Refusal::Invalidate(
                    "the agent session has been revoked or has ended",
                )));
            }
        };

    // Lock order, second: the account row.
    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1 FOR SHARE")
            .bind(session.owner_user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if is_active != Some(true) {
        return Ok(Err(Refusal::Invalidate(
            "the requesting account is no longer active",
        )));
    }
    let Some(security) = security else {
        return Ok(Err(Refusal::Retry));
    };
    if session.owner_user_id != conversation.owner_user_id {
        return Ok(Err(Refusal::Invalidate(
            "the agent session no longer belongs to this conversation's owner",
        )));
    }

    // Point-in-time admission checks, for this claimant.
    let Some(descriptor) = registry.resolve(&row.action_id) else {
        return Ok(Err(Refusal::Invalidate("the action no longer exists")));
    };
    // Through the one construction seam every conversational path uses (C3,
    // `turn::context_for`), so D-529's identity change lands in one place.
    let mut ctx = crate::turn::context_for(security, &session);
    ctx.idempotency_key = Some(row.tool_call_id.clone());
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, descriptor.module);
    if let Err(refusal) = crate::gate::admissible(descriptor, &ctx, &inputs) {
        crate::turn_metrics::gate_refused(refusal);
        tracing::info!(
            action = %descriptor.id,
            tool_call = %row.id,
            ?refusal,
            "confirm: the proposal is no longer admissible"
        );
        return Ok(Err(Refusal::Invalidate(
            "the action is no longer permitted for this session",
        )));
    }
    Ok(Ok(Admission::Admitted { descriptor, ctx }))
}

/// Whether an executor failure might not recur on a retry of the **same**
/// arguments: the infrastructure was busy, slow or briefly unavailable, or a
/// rate limit that will lift. Everything else is the action refusing these
/// immutable arguments against the world as it is, which a retry repeats.
pub fn is_transient(error: &AppError) -> bool {
    matches!(
        error,
        AppError::Internal(_)
            | AppError::Overloaded(_)
            | AppError::ServerTimeout
            | AppError::CapabilityUnavailable(_)
            | AppError::FeatureUnavailable
            | AppError::TooManyRequests {
                retry_after_secs: None
            }
    )
}

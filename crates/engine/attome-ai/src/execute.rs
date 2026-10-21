//! Executing an action — the half that runs *after* the gate has decided.
//!
//! The split is the whole design. [`crate::gate::evaluate`] answers "may this
//! happen, and under what condition", in Rust, before any action code is
//! reached. This module answers "do it". [`dispatch`] is the only thing that
//! calls both, in that order, and no consumer may call an executor directly —
//! which is what makes invariant I-4 ("risk gating happens before dispatch")
//! a property of the code rather than a rule in a document.

use attome_core::EngineState;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect};
use crate::gate::{self, ConfirmReason, GateDecision, GateInputs};
use crate::registry::ActionRegistry;
use crate::session::{
    self, Claim, InvocationAdmission, InvocationKey, InvocationRecord, PriorInvocation,
    WriteReservation,
};

/// What an invocation produced.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ActionOutcome {
    /// The action ran. `result` is the action's own payload.
    Completed {
        result: Value,
        /// Present only for actions that reach a model. `model_id` and
        /// `prompt_version` ride here so the caller can log the outcome
        /// against them (TODO-054) — provenance is not optional and cannot be
        /// reconstructed later.
        #[serde(skip_serializing_if = "Option::is_none")]
        provenance: Option<Provenance>,
    },
    /// The gate requires a human to confirm this specific invocation before it
    /// runs. **Nothing has executed and no side effect has occurred.**
    ConfirmationRequired {
        reason: &'static str,
        /// M35 v1 C3 — present only for an action that declares one
        /// ([`Action::confirmation_proposal`]): the normalized proposal, for
        /// display only. Model-authored, so render it as untrusted plain
        /// text. It carries no id, token or handle and authorizes nothing:
        /// confirming means the human invoking the action themselves.
        #[serde(skip_serializing_if = "Option::is_none")]
        proposal: Option<Value>,
    },
    /// The gate requires four-eyes approval (D-195). Nothing has executed;
    /// `dispatch` has already raised the `attome_approval` request itself (the
    /// gate decision's own doc comment always said this — closing the gap
    /// where nothing actually did it). `approval_id` is the handle a caller
    /// polls or an approver UI lists.
    ApprovalRequired { approval_id: Uuid },
    /// AH8: held for its undo window. Nothing has executed yet; it runs at
    /// `run_at` unless cancelled (`POST /api/v1/ai/deferred-actions/{id}/cancel`)
    /// and is re-checked first.
    Scheduled {
        deferred_action_id: Uuid,
        run_at: chrono::DateTime<chrono::Utc>,
    },
    /// V2-D702: staged for the person's review with the session's other
    /// staged actions. Nothing has executed, and nothing will until they
    /// apply it (`POST /api/v1/ai/deferred-actions/apply`).
    AwaitingReview { deferred_action_id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Provenance {
    pub model_id: String,
    pub prompt_version: String,
    /// The row in `ai_suggestion_outcome` this suggestion was logged as.
    /// The caller reports the human's decision against it.
    pub suggestion_id: Option<Uuid>,
}

impl ActionOutcome {
    /// A held action reported as a completed tool call, for a tool loop
    /// that has no "held" state of its own: the model reads that it is held,
    /// when it runs and that nothing ran yet (AH8).
    #[must_use]
    pub fn scheduled_as_completed(self) -> Self {
        match self {
            Self::Scheduled {
                deferred_action_id,
                run_at,
            } => Self::Completed {
                result: serde_json::json!({
                    "status": "scheduled",
                    "deferred_action_id": deferred_action_id,
                    "run_at": run_at,
                    "detail": "Held for its undo window: it runs at run_at unless the \
                               person cancels it. Nothing has run yet.",
                }),
                provenance: None,
            },
            Self::AwaitingReview { deferred_action_id } => Self::Completed {
                result: serde_json::json!({
                    "status": "awaiting_review",
                    "deferred_action_id": deferred_action_id,
                    "detail": "Staged for the person's review: it has NOT run and runs only \
                               if they apply it. Do not act as if it happened; tell the \
                               person what is waiting for them.",
                }),
                provenance: None,
            },
            other => other,
        }
    }
}

/// One executable capability.
///
/// Deliberately object-safe and deliberately narrow: an executor receives the
/// caller's context and its own arguments, and returns a value. It does **not**
/// receive the gate decision, cannot inspect the risk tier, and has no way to
/// ask whether it was approved — because an executor that could reason about
/// its own authorization is an executor that can be argued into skipping it.
#[allow(async_fn_in_trait)]
pub trait Action: Send + Sync {
    fn id(&self) -> ActionId;

    /// Runs. By the time this is called the gate has already returned
    /// [`GateDecision::Execute`].
    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ActionResult, AppError>> + Send + 'a>,
    >;

    /// M35 v1 C3 — what may be shown to a human when this invocation stops at
    /// `ConfirmationRequired`: the normalized proposal, for display only.
    /// `None` (the default) for every action that declares none.
    ///
    /// Pure: called by [`dispatch`] only after the gate has decided
    /// `ConfirmFirst`, never persisted, and never a handle a later call could
    /// redeem. Confirming means the human invoking the action themselves.
    fn confirmation_proposal(&self, _args: &Value) -> Option<Value> {
        None
    }
}

/// An executor's own return: the payload, plus provenance when a model was
/// involved.
pub struct ActionResult {
    pub value: Value,
    pub provenance: Option<Provenance>,
}

impl std::fmt::Debug for ActionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionResult").finish_non_exhaustive()
    }
}

impl ActionResult {
    pub fn plain(value: Value) -> Self {
        Self {
            value,
            provenance: None,
        }
    }
}

/// The **only** way to invoke an action.
///
/// Gate first, always, and unconditionally. There is no `dispatch_unchecked`,
/// no `bypass` flag, and no service-principal overload — the three shapes that
/// would each, in their own plausible-looking way, undo the entire risk model.
///
/// A refusal short-circuits before the executor is looked up, so an unlicensed
/// or switched-off action cannot even be observed to exist by timing the call
/// differently.
pub async fn dispatch(
    state: &EngineState,
    registry: &ActionRegistry,
    executors: &Executors,
    action_id: &str,
    ctx: &ActionContext,
    inputs: &GateInputs<'_>,
    args: &Value,
) -> Result<ActionOutcome, AppError> {
    // Resolving against the closed set is where a model-named tool stops being
    // a string and becomes a capability — or does not (I-9). Unknown resolves
    // to NotFound, identical to an unlicensed one, so probing for which
    // actions exist tells a caller nothing.
    let descriptor: &ActionDescriptor = registry.resolve(action_id).ok_or(AppError::NotFound)?;

    // AH8: an agent asks for an undo window with a reserved argument, taken
    // out before anything reads the arguments; the autonomy level comes from
    // the stored row only — whatever a caller put on the context is replaced.
    let (cleaned_args, asked_window) = crate::deferred::take_undo_window(args);
    let args = &cleaned_args;
    let mut gated_ctx = ctx.clone();
    if let Some(seconds) = asked_window {
        gated_ctx = gated_ctx.with_undo_window(seconds);
    }
    let autonomy = crate::autonomy::resolve(state, &gated_ctx, descriptor, args).await;
    gated_ctx.autonomy = autonomy.grant;
    let ctx = &gated_ctx;

    // D-512 §4: a call that reaches a live session and names a registered
    // action consumes one unit of that session's invocation budget here,
    // BEFORE the gate decides anything — so reads, refusals, confirmations,
    // approval submissions and retries all count. An unknown action returned
    // above and a dead session is refused here; neither consumes budget.
    // Counting changes no outcome the gate reaches afterwards.
    if let Some(session_id) = ctx.agent_session_id.filter(|_| ctx.is_agent()) {
        match session::consume_invocation(&state.base.db, session_id).await? {
            InvocationAdmission::Admitted => {}
            InvocationAdmission::NotLive => {
                return Err(AppError::Validation(
                    "this agent session is no longer live".into(),
                ));
            }
            InvocationAdmission::LimitReached => {
                return Err(AppError::TooManyRequests {
                    retry_after_secs: None,
                });
            }
        }
    }

    // N31-T1: a switched-off tool or agent is refused before anything else
    // runs; an unreadable switch table refuses (fails closed).
    crate::scope_switch::check(
        &state.base.db,
        descriptor.id.0,
        ctx.agent_session_id.filter(|_| ctx.is_agent()),
    )
    .await?;

    // C11 B5 (P-5, row A-85): the runtime AI switch narrows whatever the
    // caller passed — `caller AND runtime` — here, at the one entry every
    // action takes, so no caller can skip it. A stale or unreadable switch
    // reads as all-off: an AI surface fails closed, and a non-AI caller
    // (`surface: None`) is untouched, exactly as with the configuration.
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let narrowed = GateInputs {
        ai: attome_core::ai_runtime_switch::effective(inputs.ai),
        ..*inputs
    };
    let inputs = &narrowed;

    // M3.4 (MI-3): an MCP agent's `record.*` call on an entity that is not
    // admitted is refused darkly here, BEFORE the gate — so no confirmation
    // proposal and no four-eyes request is ever raised for it. A no-op for
    // every non-MCP caller. The caller's own privileges still apply after.
    crate::mcp::admission::check(state, ctx, descriptor.id, args)?;

    // AH8 level 3: run now, then tell the person the agent acts for.
    let mut report_to_owner = false;

    // C13.1: every dispatch-time refusal is counted before it is masked.
    let decision = gate::evaluate(descriptor, ctx, inputs)
        .inspect_err(|r| crate::turn_metrics::gate_refused(*r))?;

    // AH6-T2: a trial session (a `testing` definition) records every write or
    // outside call it is allowed to make instead of running it, and never
    // raises a confirmation or an approval for one. Reads run for real.
    if ctx.is_agent() && ctx.session_trial && descriptor.effect != Effect::Read {
        let id = crate::trial::record(state, ctx, descriptor, args).await?;
        return Ok(ActionOutcome::Completed {
            result: serde_json::json!({
                "status": "recorded_in_trial",
                "trial_decision_id": id,
                "detail": "Trial mode: this was recorded, not done. Carry on as if it had \
                           been done; a person compares it with what they did.",
            }),
            provenance: None,
        });
    }

    match decision {
        GateDecision::ConfirmFirst { reason } => {
            return Ok(ActionOutcome::ConfirmationRequired {
                reason: match reason {
                    ConfirmReason::RetrievedContentInContext => {
                        "this action was proposed from retrieved content and needs confirmation"
                    }
                    ConfirmReason::AgentProposalNeedsConfirmation => {
                        "an agent proposed this action; it runs only when the human invokes it"
                    }
                    ConfirmReason::AutonomyAskFirst => autonomy
                        .limit_exceeded
                        .unwrap_or("this agent's autonomy level for this action asks first"),
                },
                // Display data only (C3). Nothing ran, nothing was stored, and
                // no handle is issued — see `ActionOutcome::ConfirmationRequired`.
                proposal: executors
                    .get(descriptor.id)
                    .and_then(|executor| executor.confirmation_proposal(args)),
            });
        }
        GateDecision::RequiresApproval => {
            // (RiskTier::Consequential, Initiator::Agent) is the only arm
            // `gate::evaluate` returns this decision for — an agent
            // invocation always carries a session by the time it reaches a
            // Consequential action (the same "no session -> refused"
            // posture `record_update_field.rs`'s write cap already takes),
            // so a missing one here is a caller bug, not a policy question.
            let Some(agent_session_id) = ctx.agent_session_id else {
                return Err(AppError::internal(
                    "a Consequential agent action requires an agent session id to submit for approval",
                ));
            };
            let request = crate::approval::AgentActionRequest {
                action_id: action_id.to_string(),
                args: args.clone(),
                agent_session_id,
                acting_user_id: ctx.security.user_id,
                agent_rationale: None,
                target: capture_target(state, ctx, args).await,
            };
            // D-502: a retried tool call must not raise a second four-eyes
            // request for one intent — an approver seeing two identical
            // requests cannot tell which is real, or whether approving both
            // does the thing twice.
            let claim = match claim_key(state, descriptor, ctx).await? {
                Some(Claim::Existing(prior)) => return replay(prior),
                Some(Claim::Acquired(id)) => Some(id),
                None => None,
            };
            let pending =
                match crate::approval::request_approval(&state.base.db, descriptor.id, &request)
                    .await
                {
                    Ok(pending) => pending,
                    Err(e) => {
                        release_claim(state, claim).await;
                        return Err(e);
                    }
                };
            if let Some(id) = claim {
                let recorded = serde_json::json!({ "approval_id": pending.approval_id });
                finish_claim(state, id, session::OUTCOME_REQUIRES_APPROVAL, &recorded).await;
            }
            return Ok(ActionOutcome::ApprovalRequired {
                approval_id: pending.approval_id,
            });
        }
        GateDecision::ExecuteAfterDelay { seconds, report } => {
            let held =
                crate::deferred::enqueue(state, descriptor, ctx, args, seconds, report).await?;
            return Ok(ActionOutcome::Scheduled {
                deferred_action_id: held.id,
                run_at: held.run_at,
            });
        }
        GateDecision::Stage => {
            let staged = crate::deferred::stage(state, descriptor, ctx, args).await?;
            return Ok(ActionOutcome::AwaitingReview {
                deferred_action_id: staged,
            });
        }
        GateDecision::ExecuteAndReport => report_to_owner = true,
        GateDecision::Execute => {}
    }

    // D-502: only a write has a side effect worth claiming. A read, or a
    // confirmation (nothing ran), is safe to repeat.
    let claim = if descriptor.effect == Effect::Write {
        match claim_write(state, descriptor, ctx).await? {
            Some(Claim::Existing(prior)) => return replay(prior),
            Some(Claim::Acquired(id)) => Some(id),
            None => None,
        }
    } else {
        None
    };

    let outcome = run_executor(state, executors, descriptor, ctx, args, claim).await?;
    // AH8-T8: an action the agent ran on its own feeds the daily summary.
    crate::autonomy::record_autonomous_run(state, ctx, descriptor).await;
    if report_to_owner {
        crate::deferred::notify(
            state,
            ctx.security.user_id,
            format!("An agent ran {}", descriptor.id),
            "It ran on its own under the autonomy level set for it.".to_owned(),
        )
        .await;
    }
    Ok(outcome)
}

/// Runs one held action whose undo window ended (AH8), re-checking it first.
///
/// An agent's action goes back through the gate with today's autonomy level
/// (an administrator may have lowered it during the window): one that would
/// still run is executed through [`dispatch_approved_agent_action_under`],
/// which re-checks the session, the account, admissibility, MCP admission and
/// the record; one that now needs approval raises the request instead; one
/// that now needs a person's confirmation ends without running.
///
/// A person's own action is re-checked the same way against their freshly
/// resolved security context.
pub async fn run_deferred(
    state: &EngineState,
    row: &crate::deferred::DueAction,
) -> Result<crate::deferred::DeferredRun, AppError> {
    use crate::deferred::DeferredRun;

    let Some(descriptor) = crate::engine::REGISTRY.resolve(&row.action_id) else {
        return Ok(DeferredRun::Invalidated("the action no longer exists"));
    };
    let target: Option<crate::approval::ApprovalTarget> = row
        .target
        .clone()
        .and_then(|t| serde_json::from_value(t).ok());

    if row.initiator == "agent" {
        let Some(agent_session_id) = row.agent_session_id else {
            return Ok(DeferredRun::Invalidated("the agent session is gone"));
        };
        let session = match session::load_for_execution(&state.base.db, agent_session_id).await? {
            session::SessionForExecution::Live(session) => session,
            session::SessionForExecution::Paused => {
                return Ok(DeferredRun::NotNow("the agent session is paused"));
            }
            session::SessionForExecution::Gone => {
                return Ok(DeferredRun::Invalidated(
                    "the agent session has been revoked or has ended",
                ));
            }
        };
        let security =
            attome_security::resolve_uncached(&state.base.db, row.acting_user_id).await?;
        let mut ctx = ActionContext::for_session(std::sync::Arc::new(security), &session);
        ctx.idempotency_key = row.tool_call_id.clone();
        ctx.autonomy = crate::autonomy::resolve(state, &ctx, descriptor, &row.args)
            .await
            .grant;
        attome_core::ai_runtime_switch::refresh(&state.base.db).await;
        let inputs = crate::engine::gate_inputs(state, descriptor.module);
        let request = crate::approval::AgentActionRequest {
            action_id: row.action_id.clone(),
            args: row.args.clone(),
            agent_session_id,
            acting_user_id: row.acting_user_id,
            agent_rationale: None,
            target,
        };
        return match gate::evaluate(descriptor, &ctx, &inputs) {
            Err(refusal) => {
                crate::turn_metrics::gate_refused(refusal);
                Ok(DeferredRun::Invalidated(
                    "the action is no longer permitted for the requesting user",
                ))
            }
            Ok(GateDecision::RequiresApproval) => {
                let pending =
                    crate::approval::request_approval(&state.base.db, descriptor.id, &request)
                        .await?;
                Ok(DeferredRun::ApprovalRequired(pending.approval_id))
            }
            Ok(GateDecision::ConfirmFirst { .. }) => Ok(DeferredRun::Invalidated(
                "it now needs the person's confirmation; the agent can propose it again",
            )),
            Ok(
                GateDecision::Execute
                | GateDecision::ExecuteAndReport
                | GateDecision::ExecuteAfterDelay { .. }
                // The person applied it: that is the review.
                | GateDecision::Stage,
            ) => match dispatch_approved_agent_action_under(state, &request, None).await? {
                ApprovedExecution::Executed(result) => Ok(DeferredRun::Executed(result)),
                ApprovedExecution::Invalidated { reason } => Ok(DeferredRun::Invalidated(reason)),
                ApprovedExecution::Deferred { reason } => Ok(DeferredRun::NotNow(reason)),
            },
        };
    }

    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(row.acting_user_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if is_active != Some(true) {
        return Ok(DeferredRun::Invalidated(
            "the requesting account is no longer active",
        ));
    }
    let security = attome_security::resolve_uncached(&state.base.db, row.acting_user_id).await?;
    let ctx = ActionContext::user(std::sync::Arc::new(security));
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, descriptor.module);
    if let Err(refusal) = gate::admissible(descriptor, &ctx, &inputs) {
        crate::turn_metrics::gate_refused(refusal);
        return Ok(DeferredRun::Invalidated(
            "the action is no longer permitted for the requesting user",
        ));
    }
    if let Some(target) = &target
        && !target_unchanged(state, target).await?
    {
        return Ok(DeferredRun::Invalidated(
            "the record changed during the undo window",
        ));
    }
    match run_executor(
        state,
        &crate::engine::EXECUTORS,
        descriptor,
        &ctx,
        &row.args,
        None,
    )
    .await?
    {
        ActionOutcome::Completed { result, .. } => Ok(DeferredRun::Executed(result)),
        _ => Err(AppError::internal(
            "run_executor returned a gate-only outcome unreachable from this path",
        )),
    }
}

/// The claim for an agent write that is about to run.
///
/// A session with a policy `max_writes_per_day` reserves the write against the
/// session-wide daily total first (D-512 §3), atomically, and that reservation
/// is the write's claim. A session without one takes the ordinary D-502 path
/// ([`claim_key`]) exactly as before.
async fn claim_write(
    state: &EngineState,
    descriptor: &ActionDescriptor,
    ctx: &ActionContext,
) -> Result<Option<Claim>, AppError> {
    if let Some(session_id) = ctx.agent_session_id.filter(|_| ctx.is_agent()) {
        match session::reserve_session_write(
            &state.base.db,
            session_id,
            ctx.idempotency_key.as_deref(),
            descriptor.id,
            ctx.security.user_id,
        )
        .await?
        {
            WriteReservation::Unlimited => {}
            WriteReservation::Reserved(id) => return Ok(Some(Claim::Acquired(id))),
            WriteReservation::Existing(prior) => return Ok(Some(Claim::Existing(prior))),
            WriteReservation::LimitReached => {
                return Err(AppError::TooManyRequests {
                    retry_after_secs: None,
                });
            }
        }
    }
    claim_key(state, descriptor, ctx).await
}

/// Claims this invocation's idempotency key, when it has one (D-502).
///
/// `None` when the invocation is not keyed: a direct human invocation (its
/// idempotency is the HTTP layer's `X-Idempotency-Key`, see D-502), or an agent
/// invocation that carries no session or no key (the gate already refused
/// the `RequiresKey` actions that must have one).
async fn claim_key(
    state: &EngineState,
    descriptor: &ActionDescriptor,
    ctx: &ActionContext,
) -> Result<Option<Claim>, AppError> {
    let (Some(session_id), Some(tool_call_id)) =
        (ctx.agent_session_id, ctx.idempotency_key.as_deref())
    else {
        return Ok(None);
    };
    if !ctx.is_agent() {
        return Ok(None);
    }
    session::claim_invocation(
        &state.base.db,
        InvocationKey {
            session_id,
            tool_call_id,
            action_id: descriptor.id,
            acting_user_id: ctx.security.user_id,
        },
    )
    .await
    .map(Some)
}

/// What a retry of an already-claimed tool call returns instead of running it.
///
/// A completed invocation replays its recorded result, marked `replayed`. A
/// pending approval returns the same approval id. A claim still in flight — or
/// one whose executor crashed before recording its result — is reported as in
/// progress and never re-run: running it again could repeat a side effect
/// that already committed, which is the one thing this mechanism exists to
/// prevent. A stuck claim blocks only that exact tool call; the model's next
/// call carries a new `tool_call_id`.
fn replay(prior: PriorInvocation) -> Result<ActionOutcome, AppError> {
    match prior.outcome.as_str() {
        session::OUTCOME_COMPLETED => {
            let mut result = prior.result.unwrap_or(Value::Null);
            if let Value::Object(map) = &mut result {
                map.insert("replayed".to_string(), Value::Bool(true));
                // A completed ledger row is what makes a write revertible.
                map.insert("revertible".to_string(), Value::Bool(true));
            }
            Ok(ActionOutcome::Completed {
                result,
                provenance: None,
            })
        }
        session::OUTCOME_REQUIRES_APPROVAL => {
            let approval_id = prior
                .result
                .as_ref()
                .and_then(|r| r.get("approval_id"))
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| {
                    AppError::internal("a requires_approval invocation has no recorded approval_id")
                })?;
            Ok(ActionOutcome::ApprovalRequired { approval_id })
        }
        session::OUTCOME_CLAIMED => Err(AppError::Conflict(
            "an identical invocation of this tool call is already in progress",
        )),
        other => Err(AppError::internal(format!(
            "unrecognized invocation ledger outcome {other:?}"
        ))),
    }
}

/// Records a claimed invocation's outcome. Returns whether it landed. A
/// failure is logged, not raised: the side effect already committed, so the
/// request must not be reported as failed — but the key stays `claimed`, so a
/// retry is told "in progress" rather than running the write a second time.
async fn finish_claim(state: &EngineState, id: Uuid, outcome: &str, result: &Value) -> bool {
    match session::complete_invocation(&state.base.db, id, outcome, Some(result)).await {
        Ok(recorded) => recorded,
        Err(e) => {
            tracing::error!(
                invocation_id = %id,
                error = %e,
                "side effect committed but its idempotency claim could not be completed — \
                 retries of this tool call will be refused as in progress"
            );
            false
        }
    }
}

/// Releases a claim whose side effect failed, so the tool call can be retried.
async fn release_claim(state: &EngineState, claim: Option<Uuid>) {
    let Some(id) = claim else { return };
    if let Err(e) = session::release_invocation(&state.base.db, id).await {
        tracing::error!(
            invocation_id = %id,
            error = %e,
            "failed to release an idempotency claim after a failed invocation — \
             retries of this tool call will be refused as in progress"
        );
    }
}

/// The half of dispatch that runs *after* the gate has already said yes —
/// executor lookup, the executor call itself, and the invocation-ledger
/// write. Shared by [`dispatch`]'s own `GateDecision::Execute` arm and
/// [`dispatch_approved_agent_action`]: the latter's whole reason to exist is
/// that a human has already made the gate's decision (via `attome_approval`),
/// so it must reach this same tail without re-asking the gate — re-asking
/// would just raise a second, redundant approval request for an action that
/// was already approved. Nothing else may call an executor directly (I-4);
/// this function and `dispatch` are the two gated entry points to it.
///
/// `claim` is the invocation's idempotency claim, when [`dispatch`] took one
/// (D-502): released if the executor fails, completed with its result if it
/// succeeds.
async fn run_executor(
    state: &EngineState,
    executors: &Executors,
    descriptor: &ActionDescriptor,
    ctx: &ActionContext,
    args: &Value,
    claim: Option<Uuid>,
) -> Result<ActionOutcome, AppError> {
    // M3.4: the shared tail re-checks MCP entity admission, so the confirmed
    // path reaches no unadmitted entity either. A refusal frees the claim.
    if let Err(refusal) = crate::mcp::admission::check(state, ctx, descriptor.id, args) {
        release_claim(state, claim).await;
        return Err(refusal);
    }

    let executor = executors
        .get(descriptor.id)
        // A registered descriptor with no executor is a programming error, not
        // a caller error: the registry would be offering a tool that cannot
        // run. `actions::read::descriptors` and `Executors::new` are asserted
        // to agree in `executors_cover_every_registered_action`.
        .ok_or_else(|| {
            tracing::error!(
                action = %descriptor.id,
                "action is registered but has no executor — the registry is offering a tool that cannot run"
            );
            AppError::internal("action has no executor")
        })?;

    // AH4-T1: the money rule, before the step runs.
    if let Err(refusal) = crate::discount_rule::check(state, ctx, args).await {
        release_claim(state, claim).await;
        return Err(refusal);
    }

    // AK3-T1: the engine writes an agent's action makes (record audit
    // headers, change events) name the agent and its session.
    let run = executor.execute(state, ctx, args);
    let outcome = match ctx.agent_session_id.filter(|_| ctx.is_agent()) {
        Some(session_id) => {
            let agent = attome_core::agent_scope::AgentScope {
                session_id,
                action_id: descriptor.id.to_string(),
            };
            attome_core::agent_scope::scope(agent, run).await
        }
        None => run.await,
    };
    let mut result = match outcome {
        Ok(result) => result,
        Err(e) => {
            // Retryability (D-502): a failed attempt must not occupy the key.
            release_claim(state, claim).await;
            return Err(e);
        }
    };

    // C19 / D-541 rule 4 (G3-2a): an agent-driven action that changes
    // anything, or that a human approved, writes one mandatory `Ai` +
    // `Execute` event naming the agent session, the action, the model and the
    // approval request, attributed to the human it ran for. The executor has
    // already committed its own transaction (and its own entity events), so
    // this cannot join it; a failed write fails the call instead of being
    // swallowed, and the claim is deliberately left `claimed` (the side
    // effect happened), so a retry is refused as in progress rather than run
    // twice. Recorded as register entry A-10.
    if ctx.is_agent() && (descriptor.effect != Effect::Read || ctx.approval_request_id.is_some()) {
        write_agent_action_event(state, descriptor, ctx, result.provenance.as_ref()).await?;
    }

    // REVIEW-2026-09-02 finding #9 (M98): the invocation ledger, made
    // structural rather than opt-in. Every completed `Effect::Write` action
    // gets a row here, in the one chokepoint every invocation passes
    // through — a future write action gets this by construction, not by its
    // author remembering to copy `record.update_field`'s own bookkeeping.
    // Best-effort, after the write already committed inside `execute()`: a
    // logging failure here must not be reported as this request having
    // failed, only that this particular write is not revertible from the
    // ledger — which `revertible` in the result tells the caller.
    if descriptor.effect == Effect::Write {
        let revertible = match claim {
            Some(id) => finish_claim(state, id, session::OUTCOME_COMPLETED, &result.value).await,
            None => record_write_invocation(state, descriptor.id, ctx, &result.value).await,
        };
        if let Value::Object(map) = &mut result.value {
            map.insert("revertible".to_string(), Value::Bool(revertible));
        }
    }

    Ok(ActionOutcome::Completed {
        result: result.value,
        provenance: result.provenance,
    })
}

/// The mandatory `Ai` + `Execute` event for one agent-driven action (C19).
///
/// Model id: the action's own provenance when it called a model, otherwise
/// the provider model of the agent definition the session was started from.
/// A session with no definition (MCP, where the model runs on the external
/// host, or a webchat conversation) records none.
async fn write_agent_action_event(
    state: &EngineState,
    descriptor: &ActionDescriptor,
    ctx: &ActionContext,
    provenance: Option<&Provenance>,
) -> Result<(), AppError> {
    let session_id = ctx.agent_session_id;
    let ai_model_id = match (provenance, session_id) {
        (Some(p), _) => Some(p.model_id.clone()),
        (None, Some(session_id)) => session_model_id(state, session_id).await?,
        (None, None) => None,
    };
    let acting_user_id = ctx.security.user_id;
    let attribution = match session_id {
        Some(session_id) => {
            attome_audit::Attribution::agent(acting_user_id, session_id, descriptor.id.to_string())
        }
        None => {
            let mut a = attome_audit::Attribution::user(acting_user_id);
            a.initiator = attome_audit::Initiator::Agent;
            a.agent_action_id = Some(descriptor.id.to_string());
            a
        }
    };
    let mut event = attome_audit::security::SecurityEvent::new(
        attome_audit::security::MandatoryCategory::Ai,
        attome_audit::AuditOperation::Execute,
        acting_user_id,
        "agent_session",
        session_id,
    )
    .named(descriptor.id.to_string())
    .attributed(attribution)
    .comment(format!(
        "agent action {} ({:?}, {:?}) executed{}",
        descriptor.id,
        descriptor.risk,
        descriptor.effect,
        ctx.approval_request_id
            .map_or_else(String::new, |id| format!(" under approval request {id}"))
    ));
    if let Some(model) = ai_model_id {
        event = event.ai_model(model);
    }
    if let Some(approval) = ctx.approval_request_id {
        event = event.approval_request(approval);
    }
    attome_audit::security::SecurityAuditor::from_state(state)
        .write(event)
        .await
        .map(|_| ())
}

/// The provider model id of the agent definition `session_id` was started
/// from, when it was started from one.
async fn session_model_id(
    state: &EngineState,
    session_id: Uuid,
) -> Result<Option<String>, AppError> {
    let definition: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT agent_definition_ref FROM agent_session WHERE id = $1")
            .bind(session_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some(definition) = definition.flatten() else {
        return Ok(None);
    };
    let model: Option<Option<String>> = sqlx::query_scalar(
        // `::text` on both sides: the lookup column is a uuid in the shipped
        // bundle and plain text in some test harnesses.
        "SELECT m.provider_model_id::text FROM ai_agent a \
         JOIN ai_model m ON m.id::text = a.primary_model_ref::text \
         WHERE a.id = $1",
    )
    .bind(definition)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(model.flatten())
}

/// Runs an agent action that has already cleared `attome_approval` — the
/// callback `crates/engine/attome-api/src/approval_admin.rs::execute_approved`
/// makes for every `attome-ai/invoke:*` approval once a second admin
/// decides `Approve`. Closes the gap where `ActionOutcome::ApprovalRequired`
/// existed and a request could be approved, but nothing ever executed it.
///
/// Deliberately bypasses `gate::evaluate` entirely rather than calling
/// [`dispatch`] again: the gate's `(Consequential, Agent)` arm always
/// returns `RequiresApproval`, so a second pass through it would submit a
/// second approval request instead of running the action a human already
/// approved. This function is the one sanctioned bypass — reached only from
/// the approval-execution callback, never from a model-facing entry point,
/// and it still goes through [`run_executor`] (the same ledger-writing tail
/// `dispatch` uses), never the executor directly (I-4).
///
/// **Revalidates immediately before running** (M98/M101 P0 authorization
/// hardening). An approval authorizes one action; it does not freeze the
/// security state the action was requested under. So, fresh at execution
/// time and in this order, the action must still:
///
/// 1. exist in this build's registry,
/// 2. belong to an agent session that has not been revoked or ended — a
///    killed agent's queued actions die with it,
/// 3. be requested by an account that is still active,
/// 4. pass [`crate::gate::admissible`] against the acting user's freshly
///    resolved `SecurityContext` and the session's own ceiling and
///    allow-list — licence, kill-switch, air-gap, allow-list, privilege.
///
/// Any failure is [`ApprovedExecution::Invalidated`], which the approval
/// callback records as the request's terminal `invalidated` status so it can
/// never run later, even once the condition that invalidated it is undone.
///
/// **A paused session is "not now", not "never"** (D-502): it returns
/// [`ApprovedExecution::Deferred`] and the request stays `approved`, so
/// `retry-execution` runs it once the session is resumed. Invalidating it
/// would turn a supervisor's pause into the permanent loss of every pending
/// approval.
///
/// **Never reopens confirmation.** `admissible` deliberately excludes the
/// gate's risk/initiator/taint matrix: the human approval this path runs
/// behind already is that decision, and a tainted session is not a reason to
/// ask the approver again.
///
/// An `Err` is a transient failure (the database, the executor itself) and
/// leaves the request `approved`, for `retry-execution` to pick up.
pub async fn dispatch_approved_agent_action(
    state: &EngineState,
    request: &crate::approval::AgentActionRequest,
) -> Result<ApprovedExecution, AppError> {
    dispatch_approved_agent_action_under(state, request, None).await
}

/// [`dispatch_approved_agent_action`], naming the `attome_approval` request it
/// runs under, so the mandatory `Ai` + `Execute` event records it as
/// `approval_request_ref` (C19). `approval_admin::execute_approved` calls
/// this.
pub async fn dispatch_approved_agent_action_under(
    state: &EngineState,
    request: &crate::approval::AgentActionRequest,
    approval_request_id: Option<Uuid>,
) -> Result<ApprovedExecution, AppError> {
    let Some(descriptor) = crate::engine::REGISTRY.resolve(&request.action_id) else {
        return Ok(invalidated(request, "the action no longer exists"));
    };

    let session =
        match session::load_for_execution(&state.base.db, request.agent_session_id).await? {
            session::SessionForExecution::Live(session) => session,
            session::SessionForExecution::Paused => {
                tracing::info!(
                    action_id = %request.action_id,
                    agent_session_id = %request.agent_session_id,
                    "approved agent action deferred: its session is paused"
                );
                return Ok(ApprovedExecution::Deferred {
                    reason: "the agent session is paused",
                });
            }
            session::SessionForExecution::Gone => {
                return Ok(invalidated(
                    request,
                    "the agent session has been revoked or has ended",
                ));
            }
        };

    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(request.acting_user_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if is_active != Some(true) {
        return Ok(invalidated(
            request,
            "the requesting account is no longer active",
        ));
    }

    let security =
        attome_security::resolve_uncached(&state.base.db, request.acting_user_id).await?;
    let mut ctx = ActionContext::for_session(std::sync::Arc::new(security), &session);
    ctx.approval_request_id = approval_request_id;
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, descriptor.module);
    if let Err(refusal) = gate::admissible(descriptor, &ctx, &inputs) {
        crate::turn_metrics::gate_refused(refusal);
        tracing::warn!(
            action_id = %request.action_id,
            agent_session_id = %request.agent_session_id,
            acting_user_id = %request.acting_user_id,
            ?refusal,
            "approved agent action refused at execution time"
        );
        return Ok(invalidated(
            request,
            "the action is no longer permitted for the requesting user",
        ));
    }

    // M3.4: an approval does not freeze MCP entity admission either. An
    // entity whose admission was withdrawn after the request was raised is
    // terminal, like any other revalidation failure above — never retried.
    if crate::mcp::admission::check(state, &ctx, descriptor.id, &request.args).is_err() {
        tracing::warn!(
            action_id = %request.action_id,
            agent_session_id = %request.agent_session_id,
            "approved MCP agent action refused at execution time: entity not admitted"
        );
        return Ok(invalidated(
            request,
            "the entity is not admitted for MCP agents",
        ));
    }

    // N30-T2: an approval covers the record as it stood when it was asked
    // for. Changed since (or gone) is terminal: the approver approved a
    // different record, and the agent can ask again against the world as it
    // is now.
    if let Some(target) = &request.target
        && !target_unchanged(state, target).await?
    {
        return Ok(invalidated(
            request,
            "the record changed after the request was made",
        ));
    }

    // D-512 §3: an approved write still counts against the session-wide daily
    // write total. Used up is "not now", not "never": the request stays
    // approved and runs on a later retry, once the day rolls over.
    let claim = if descriptor.effect == Effect::Write {
        match session::reserve_session_write(
            &state.base.db,
            session.id,
            None,
            descriptor.id,
            request.acting_user_id,
        )
        .await?
        {
            WriteReservation::Unlimited => None,
            WriteReservation::Reserved(id) => Some(id),
            WriteReservation::Existing(_) => {
                return Err(AppError::internal(
                    "an unkeyed write reservation matched a prior invocation",
                ));
            }
            WriteReservation::LimitReached => {
                return Ok(ApprovedExecution::Deferred {
                    reason: "the agent session has reached its daily write limit",
                });
            }
        }
    } else {
        None
    };

    let outcome = run_executor(
        state,
        &crate::engine::EXECUTORS,
        descriptor,
        &ctx,
        &request.args,
        claim,
    )
    .await?;
    match outcome {
        ActionOutcome::Completed { result, .. } => Ok(ApprovedExecution::Executed(result)),
        // `run_executor` cannot itself produce these — they belong to the
        // gate path this function deliberately does not call.
        ActionOutcome::ConfirmationRequired { .. }
        | ActionOutcome::ApprovalRequired { .. }
        | ActionOutcome::Scheduled { .. }
        | ActionOutcome::AwaitingReview { .. } => Err(AppError::internal(
            "run_executor returned a gate-only outcome unreachable from this path",
        )),
    }
}

/// Runs a proposal a human has just confirmed (C4, `POST …/confirm`).
///
/// **A confirmation authorizes execution of the agent action that was
/// proposed; it does not turn it into a user-initiated action.** So `ctx` is
/// the session's own agent context (`ActionContext::for_session`, carrying
/// its ceiling, allow-list and taint) with `idempotency_key` set to the
/// persisted `tool_call_id` — never `ActionContext::user`, under which
/// [`dispatch`] would take no D-502 claim at all (`claim_key` requires an
/// agent), and a confirm reclaimed after its lease expired could execute a
/// second time.
///
/// **The caller has already admitted the call** — `gate::admissible` inside
/// the confirm path's check transaction (row A-41) — exactly as
/// [`dispatch_approved_agent_action_under`] admits before reaching the same
/// tail. What is *not* re-asked is the risk/initiator/taint matrix's
/// `ConfirmFirst`: this human act is that confirmation. Its approval half
/// still holds: a `Consequential` action is submitted for four-eyes approval
/// through the same code [`dispatch`] uses, never executed on a confirm.
///
/// Consumes no invocation unit: the turn that produced the proposal already
/// did (D-512 §4), and the approval path takes none either. The daily write
/// reservation still applies.
pub async fn dispatch_confirmed_agent_action(
    state: &EngineState,
    executors: &Executors,
    descriptor: &ActionDescriptor,
    ctx: &ActionContext,
    args: &Value,
) -> Result<ConfirmedExecution, AppError> {
    let (Some(agent_session_id), Some(_)) = (ctx.agent_session_id, ctx.idempotency_key.as_deref())
    else {
        return Err(AppError::internal(
            "a confirmed agent action must carry its session and its tool_call_id",
        ));
    };
    if !ctx.is_agent() {
        return Err(AppError::internal(
            "a confirmed agent action must run under the session's agent context",
        ));
    }

    // N30-T4: a consequential action always goes to approval; a reversible
    // write does too when an administrator's per-write policy names it.
    let needs_approval = descriptor.risk == crate::descriptor::RiskTier::Consequential
        || (descriptor.effect == Effect::Write
            && crate::write_policy::requires_approval(&state.base.db, descriptor.id.0, args)
                .await?);
    if needs_approval {
        let claim = match claim_key(state, descriptor, ctx).await? {
            Some(Claim::Existing(prior)) => return from_prior(prior),
            Some(Claim::Acquired(id)) => Some(id),
            None => None,
        };
        let request = crate::approval::AgentActionRequest {
            action_id: descriptor.id.to_string(),
            args: args.clone(),
            agent_session_id,
            acting_user_id: ctx.security.user_id,
            agent_rationale: None,
            target: capture_target(state, ctx, args).await,
        };
        let pending = match crate::approval::request_approval(
            &state.base.db,
            descriptor.id,
            &request,
        )
        .await
        {
            Ok(pending) => pending,
            Err(e) => {
                release_claim(state, claim).await;
                return Err(e);
            }
        };
        if let Some(id) = claim {
            let recorded = serde_json::json!({ "approval_id": pending.approval_id });
            finish_claim(state, id, session::OUTCOME_REQUIRES_APPROVAL, &recorded).await;
        }
        return Ok(ConfirmedExecution::ApprovalRequired {
            approval_id: pending.approval_id,
        });
    }

    let claim = if descriptor.effect == Effect::Write {
        match claim_write(state, descriptor, ctx).await {
            Ok(Some(Claim::Existing(prior))) => return from_prior(prior),
            Ok(Some(Claim::Acquired(id))) => Some(id),
            Ok(None) => None,
            Err(AppError::TooManyRequests {
                retry_after_secs: None,
            }) => return Ok(ConfirmedExecution::WriteLimitReached),
            Err(e) => return Err(e),
        }
    } else {
        None
    };

    match run_executor(state, executors, descriptor, ctx, args, claim).await {
        Ok(ActionOutcome::Completed { result, .. }) => Ok(ConfirmedExecution::Executed(result)),
        Ok(
            ActionOutcome::ConfirmationRequired { .. }
            | ActionOutcome::ApprovalRequired { .. }
            | ActionOutcome::Scheduled { .. }
            | ActionOutcome::AwaitingReview { .. },
        ) => Err(AppError::internal(
            "run_executor returned a gate-only outcome unreachable from this path",
        )),
        Err(e) => {
            // `run_executor` releases the claim when the executor itself
            // failed, and deliberately keeps it when the side effect may have
            // committed (the mandatory audit write failed after it). The
            // ledger row therefore says which one this was.
            let still_claimed = match claim {
                Some(id) => {
                    let outcome: Option<String> =
                        sqlx::query_scalar("SELECT outcome FROM action_invocation WHERE id = $1")
                            .bind(id)
                            .fetch_optional(&state.base.db)
                            .await
                            .map_err(AppError::internal)?;
                    outcome.as_deref() == Some(session::OUTCOME_CLAIMED)
                }
                None => false,
            };
            Ok(if still_claimed {
                ConfirmedExecution::OutcomeUnrecorded(e)
            } else {
                ConfirmedExecution::Failed(e)
            })
        }
    }
}

/// A prior invocation of the same `(session, tool_call_id)`: the executor
/// must not run (D-502). Mirrors [`replay`], but tells "completed" apart from
/// "in progress" by value rather than by error, because the confirm path
/// answers each differently.
fn from_prior(prior: PriorInvocation) -> Result<ConfirmedExecution, AppError> {
    match prior.outcome.as_str() {
        session::OUTCOME_COMPLETED => Ok(ConfirmedExecution::AlreadyExecuted(
            prior.result.unwrap_or(Value::Null),
        )),
        session::OUTCOME_REQUIRES_APPROVAL => {
            let approval_id = prior
                .result
                .as_ref()
                .and_then(|r| r.get("approval_id"))
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| {
                    AppError::internal("a requires_approval invocation has no recorded approval_id")
                })?;
            Ok(ConfirmedExecution::ApprovalRequired { approval_id })
        }
        session::OUTCOME_CLAIMED => Ok(ConfirmedExecution::InProgress),
        other => Err(AppError::internal(format!(
            "unrecognized invocation ledger outcome {other:?}"
        ))),
    }
}

/// What running a confirmed proposal produced.
#[derive(Debug)]
pub enum ConfirmedExecution {
    /// The executor ran now and completed; its payload.
    Executed(Value),
    /// An earlier attempt under the same `(session, tool_call_id)` already
    /// completed; its recorded result. The executor did not run.
    AlreadyExecuted(Value),
    /// An attempt under the same key still holds the execution claim — in
    /// flight, or crashed before recording. The executor did not run.
    InProgress,
    /// A `Consequential` action, submitted for four-eyes approval.
    ApprovalRequired { approval_id: Uuid },
    /// The session's daily write total is spent. Nothing ran.
    WriteLimitReached,
    /// The executor ran and failed; its claim was released and nothing
    /// committed.
    Failed(AppError),
    /// The side effect may have committed but its completion was not
    /// recorded, so the claim is still held: every retry meets "in progress"
    /// and the executor never runs again (the D-502 stuck-claim condition).
    OutcomeUnrecorded(AppError),
}

/// What running an approved agent action produced.
#[derive(Debug)]
pub enum ApprovedExecution {
    /// The action ran; the executor's own payload.
    Executed(Value),
    /// Revalidation refused it permanently: a condition checked at execution
    /// time no longer holds and never will again for this request. Nothing
    /// ran. `reason` is safe to show the approver: it names which condition
    /// changed, never internal state.
    Invalidated { reason: &'static str },
    /// Not runnable right now, but may be later (a paused session). Nothing
    /// ran, and the request must stay `approved` so it can be retried.
    Deferred { reason: &'static str },
}

/// The record an approval request is about, read as the requesting caller
/// reads it (N30-T1). `None` when the arguments name no single record or the
/// caller cannot read it: the request still goes ahead, without a diff.
pub(crate) async fn capture_target(
    state: &EngineState,
    ctx: &ActionContext,
    args: &serde_json::Value,
) -> Option<crate::approval::ApprovalTarget> {
    let (entity, record_id) = crate::approval::target_of(args)?;
    let record =
        attome_records::entity_crud::read_record_bulk(state, &ctx.security, &entity, record_id)
            .await
            .ok()?;
    let state_field = state
        .state_models
        .load()
        .get(&entity)
        .and_then(|entry| entry.model.as_ref())
        .map(|model| model.state_field.clone());
    let (before, after) = crate::approval::diff(record.data(), args, state_field.as_deref());
    Some(crate::approval::ApprovalTarget {
        entity,
        record_id,
        row_version: record.row_version(),
        before,
        after,
    })
}

/// Whether the target record still exists at the version the request saw.
/// An append-only entity has no versions to compare, so it always matches.
async fn target_unchanged(
    state: &EngineState,
    target: &crate::approval::ApprovalTarget,
) -> Result<bool, AppError> {
    let append_only = {
        let registry = state.entities.load();
        match registry.get(&target.entity) {
            Some(meta) => meta.is_append_only,
            None => return Ok(false),
        }
    };
    if append_only {
        return Ok(true);
    }
    let table = attome_core::quote_ident(&target.entity);
    let live = attome_core::live_row_predicate("t", false)
        .map(|p| format!("AND {p}"))
        .unwrap_or_default();
    let current: Option<i64> = sqlx::query_scalar(&format!(
        "SELECT t.row_version::bigint FROM {table} t WHERE t.id = $1 {live}"
    ))
    .bind(target.record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(current == Some(target.row_version))
}

fn invalidated(
    request: &crate::approval::AgentActionRequest,
    reason: &'static str,
) -> ApprovedExecution {
    tracing::warn!(
        action_id = %request.action_id,
        agent_session_id = %request.agent_session_id,
        acting_user_id = %request.acting_user_id,
        reason,
        "approved agent action invalidated before execution"
    );
    ApprovedExecution::Invalidated { reason }
}

/// Writes one `action_invocation` row for a completed `Effect::
/// Write` action. Returns whether the row was actually inserted — `false`
/// on a logged failure, so the caller can tell an operator "this write
/// cannot be reverted from the ledger" rather than silently claim it can.
async fn record_write_invocation(
    state: &EngineState,
    action_id: ActionId,
    ctx: &ActionContext,
    result_value: &Value,
) -> bool {
    match session::record_invocation(
        &state.base.db,
        InvocationRecord {
            session_id: ctx.agent_session_id,
            tool_call_id: ctx.idempotency_key.as_deref(),
            action_id,
            is_agent: ctx.is_agent(),
            acting_user_id: ctx.security.user_id,
            outcome: "completed",
            result: Some(result_value),
        },
    )
    .await
    {
        Ok(inserted) => inserted,
        Err(e) => {
            tracing::error!(
                action_id = %action_id,
                error = %e,
                "action completed but failed to log its invocation — \
                 this write is not revertible from the ledger"
            );
            false
        }
    }
}

/// The executor table. Built once at startup, alongside the registry.
pub struct Executors {
    inner: Vec<Box<dyn Action>>,
}

impl std::fmt::Debug for Executors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Executors").finish_non_exhaustive()
    }
}

impl Executors {
    pub fn new() -> Self {
        Self {
            inner: crate::actions::all_executors(),
        }
    }

    fn get(&self, id: ActionId) -> Option<&dyn Action> {
        self.inner.iter().find(|a| a.id() == id).map(|a| a.as_ref())
    }
}

impl Default for Executors {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every registered descriptor must have an executor, and every executor
    /// must have a descriptor.
    ///
    /// A descriptor without an executor is a tool the registry offers and
    /// `dispatch` then 500s on — for a model, an unexplainable failure it will
    /// retry. An executor without a descriptor is a capability that never
    /// passes through the gate, because the gate reads descriptors. Both
    /// directions matter, so both are asserted.
    #[test]
    fn executors_cover_every_registered_action() {
        let registry = ActionRegistry::new();
        let executors = Executors::new();

        for descriptor in registry.all() {
            assert!(
                executors.get(descriptor.id).is_some(),
                "{} is registered but has no executor",
                descriptor.id
            );
        }
        for action in &executors.inner {
            assert!(
                registry.get(action.id()).is_some(),
                "{} has an executor but no descriptor — it would never be \
                 risk-gated, because the gate reads descriptors",
                action.id()
            );
        }
    }
}

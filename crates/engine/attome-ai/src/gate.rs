//! Risk gating — the decision that happens **before** dispatch, never during
//! it, and never by prompt or UI (invariant I-4).
//!
//! A prompt is not a control. An LLM can be argued out of an instruction; a
//! match on `(risk, initiator, tainted, ceiling)` evaluated in Rust before the
//! action function is reached cannot. Everything in this file exists to keep
//! that decision on the Rust side of the boundary.
//!
//! This is also the one enforcement point for the kill-switch (TODO-055) and
//! the license gate, so "AI is off", "the module is unlicensed", and "you
//! cannot do that" all produce one consistent shape instead of three.

use attome_config::{AiEnablement, AiSurface};
use attome_types::AppError;

use crate::autonomy::AutonomyLevel;
use crate::context::{ActionContext, Initiator};
use crate::descriptor::{ActionDescriptor, Effect, RetryClass, RiskTier};

/// What the gate decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Dispatch now.
    Execute,
    /// Dispatch only after the human confirms this specific invocation. The
    /// action does **not** run and no side effect occurs until they do.
    ConfirmFirst {
        /// Why, so the UI can say something true rather than "are you sure?".
        reason: ConfirmReason,
    },
    /// Do not dispatch. Raise a `attome_approval` request (D-195) and return a
    /// pending handle. **Never build a second approval mechanism**
    /// (guidelines §13) — the four-eyes primitive already exists.
    RequiresApproval,
    /// AH8: dispatch after an undo window. The action is held for `seconds`
    /// in `ai_deferred_action`, where the person it acts for (or an
    /// administrator) can cancel it; then it is re-checked and run.
    /// `report` tells the person it acts for once it ran.
    ExecuteAfterDelay { seconds: u32, report: bool },
    /// AH8 level 3: dispatch now and tell the person the agent acts for.
    ExecuteAndReport,
    /// V2-D702 `act_on_review`: do not dispatch. Stage it in
    /// `ai_deferred_action` with the session's other staged actions, for the
    /// person the agent acts for to apply or discard together.
    Stage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmReason {
    /// I-10: the triggering context contains text obtained through a tool,
    /// which is attacker-influenceable. A `Reversible` write that would
    /// normally auto-execute for an agent degrades to confirm-first.
    RetrievedContentInContext,
    /// M35 v1 C1: the action is declared `agent_must_confirm` — an agent may
    /// propose it, only the human completes it, regardless of taint.
    AgentProposalNeedsConfirmation,
    /// AH8: the agent's autonomy level for this action is `ask_first` (set
    /// by an administrator, or lowered by a limit).
    AutonomyAskFirst,
    /// AE1-T4: a person invoked a consequential action without confirming
    /// this invocation.
    ConsequentialNeedsConfirmation,
}

/// Why the gate refused outright. Separate from [`GateDecision`] because a
/// refusal is an error the caller maps to a status code, while a decision is a
/// value the caller acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRefusal {
    /// The module is unlicensed, or the AI kill-switch is off for this
    /// surface. Deliberately **one** variant covering both: they must be
    /// indistinguishable to a caller, and both must produce a 404 rather than
    /// a 403 — a 403 confirms the feature exists, which is exactly what the
    /// dark license gate (D-010) refuses to do.
    NotAvailable,
    /// The caller lacks a required privilege.
    Forbidden,
    /// The action's risk exceeds this agent session's ceiling.
    AboveCeiling,
    /// An agent invoked a non-idempotent action without an idempotency key.
    /// Tool loops retry; without a key a retried write duplicates (TODO-043).
    IdempotencyKeyRequired,
    /// The action reaches outside the deployment and external effects are not
    /// enabled (I-7). An air-gapped deployment refuses these.
    ExternalEffectDisabled,
    /// The invocation runs under an agent session whose action allow-list
    /// does not name this action. A 404 rather than a 403, for the same
    /// reason as [`GateRefusal::NotAvailable`]: `visible_to` hides the action
    /// from that session, and an invocation must not be able to tell a hidden
    /// action from an absent one.
    NotInSessionAllowList,
}

impl GateRefusal {
    /// The variant as a metric label (`ai_gate_refusals_total{variant}`,
    /// C13.1). Operator-side only: a caller still sees the masked `AppError`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAvailable => "not_available",
            Self::Forbidden => "forbidden",
            Self::AboveCeiling => "above_ceiling",
            Self::IdempotencyKeyRequired => "idempotency_key_required",
            Self::ExternalEffectDisabled => "external_effect_disabled",
            Self::NotInSessionAllowList => "not_in_session_allow_list",
        }
    }
}

impl From<GateRefusal> for AppError {
    fn from(refusal: GateRefusal) -> Self {
        match refusal {
            // NotAvailable is NotFound, not Forbidden. See the variant.
            GateRefusal::NotAvailable => AppError::NotFound,
            GateRefusal::Forbidden | GateRefusal::AboveCeiling => AppError::Forbidden,
            GateRefusal::IdempotencyKeyRequired => AppError::Validation(
                "this action requires an idempotency key when invoked by an agent".into(),
            ),
            GateRefusal::ExternalEffectDisabled | GateRefusal::NotInSessionAllowList => {
                AppError::NotFound
            }
        }
    }
}

/// Everything the gate consults that is not on the descriptor or the context.
pub struct GateInputs<'a> {
    /// Whether the descriptor's module bit is licensed.
    pub licensed: bool,
    /// The deployment's AI kill-switch.
    pub ai: &'a AiEnablement,
    /// Which surface this invocation is reaching the registry through, when
    /// it is an AI surface at all. `None` for an ordinary non-AI caller — the
    /// kill-switch must not disable the platform's own read actions when they
    /// are invoked by a human clicking a button.
    pub surface: Option<AiSurface>,
    /// Whether `Effect::External` is enabled for this deployment (I-7).
    pub external_effects_enabled: bool,
}

impl std::fmt::Debug for GateInputs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateInputs").finish_non_exhaustive()
    }
}

/// The whole gate. One function, called before dispatch, by every façade.
///
/// Order matters and is not arbitrary: availability first (so an unlicensed or
/// switched-off feature reveals nothing about itself), then privilege, then
/// ceiling, then retry safety, then the risk/initiator/taint matrix. A check
/// that ran after dispatch would not be a gate.
pub fn evaluate(
    descriptor: &ActionDescriptor,
    ctx: &ActionContext,
    inputs: &GateInputs<'_>,
) -> Result<GateDecision, GateRefusal> {
    admissible(descriptor, ctx, inputs)?;

    // 5. Retry safety for agents. A human clicking twice is a human's
    // decision; a tool loop retrying is a machine's, and it happens.
    if ctx.initiator == Initiator::Agent
        && descriptor.retry == RetryClass::RequiresKey
        && ctx.idempotency_key.is_none()
    {
        return Err(GateRefusal::IdempotencyKeyRequired);
    }

    // 6. The matrix.
    let decision = match (descriptor.risk, ctx.initiator) {
        (RiskTier::Read, _) => return Ok(GateDecision::Execute),

        // AE1-T4: a person on a live surface confirms a consequential action
        // before it runs, whatever the surface (an API call, a button, a
        // macro step). A flow or job acting as a user is not a person here:
        // its author decided when it was published.
        (RiskTier::Consequential, Initiator::User) if ctx.interactive && !ctx.confirmed => {
            GateDecision::ConfirmFirst {
                reason: ConfirmReason::ConsequentialNeedsConfirmation,
            }
        }

        // A human invoking a Consequential action through the UI is the
        // existing four-eyes question, answered by the deployment's
        // `approval.required_actions` policy rather than by this gate.
        (_, Initiator::User) => GateDecision::Execute,

        // An `autonomy_locked` action keeps its built-in rule whatever level
        // is stored: checked first, so no row is a way around it.
        (risk, Initiator::Agent) if descriptor.autonomy_locked => {
            builtin(risk, ctx, descriptor.agent_must_confirm)
        }

        // AH8 (V2-D693): an administrator's autonomy level for this agent and
        // action. The fixed rail: untrusted text in the context lowers it by
        // one, whatever the row says.
        // M35 v1 C1 is the built-in rule of an `agent_must_confirm` action:
        // the agent proposes, the human completes, whatever the taint.
        (risk, Initiator::Agent) => match ctx.autonomy {
            None => builtin(risk, ctx, descriptor.agent_must_confirm),
            Some(grant) => {
                let level = if ctx.contains_retrieved_content {
                    grant.level.lowered()
                } else {
                    grant.level
                };
                by_level(level, risk, ctx, grant.undo_seconds)
            }
        },
    };

    // AH8: a caller-requested undo window delays an action that would run
    // now. It never turns a confirmation or an approval into a run.
    Ok(match (decision, ctx.undo_window_seconds) {
        (GateDecision::Execute, Some(seconds)) => GateDecision::ExecuteAfterDelay {
            seconds,
            report: false,
        },
        (GateDecision::ExecuteAndReport, Some(seconds)) => GateDecision::ExecuteAfterDelay {
            seconds,
            report: true,
        },
        (decision, _) => decision,
    })
}

/// The built-in matrix for an agent, used when no autonomy level applies.
///
/// I-10's operative half. A Reversible write normally auto-executes for an
/// agent and offers undo. When the context carries tool-obtained text, the
/// write may have been suggested by that text rather than by the human, so a
/// human confirms this specific invocation first. A Consequential action
/// always needs four-eyes approval here: only an administrator's stored
/// autonomy level takes it above that.
fn builtin(risk: RiskTier, ctx: &ActionContext, must_confirm: bool) -> GateDecision {
    match risk {
        RiskTier::Read => GateDecision::Execute,
        RiskTier::Consequential => GateDecision::RequiresApproval,
        RiskTier::Reversible if must_confirm => GateDecision::ConfirmFirst {
            reason: ConfirmReason::AgentProposalNeedsConfirmation,
        },
        RiskTier::Reversible if ctx.contains_retrieved_content => GateDecision::ConfirmFirst {
            reason: ConfirmReason::RetrievedContentInContext,
        },
        RiskTier::Reversible => GateDecision::Execute,
    }
}

/// What an agent's autonomy level means for one invocation (AH8).
fn by_level(
    level: AutonomyLevel,
    risk: RiskTier,
    ctx: &ActionContext,
    undo_seconds: u32,
) -> GateDecision {
    match level {
        AutonomyLevel::Suggest => GateDecision::ConfirmFirst {
            reason: ConfirmReason::AgentProposalNeedsConfirmation,
        },
        AutonomyLevel::AskFirst => match risk {
            RiskTier::Consequential => GateDecision::RequiresApproval,
            _ => GateDecision::ConfirmFirst {
                reason: if ctx.contains_retrieved_content {
                    ConfirmReason::RetrievedContentInContext
                } else {
                    ConfirmReason::AutonomyAskFirst
                },
            },
        },
        AutonomyLevel::ActOnReview => GateDecision::Stage,
        AutonomyLevel::ActWithUndo => GateDecision::ExecuteAfterDelay {
            seconds: ctx.undo_window_seconds.unwrap_or(undo_seconds),
            report: true,
        },
        AutonomyLevel::ActAndReport => GateDecision::ExecuteAndReport,
        AutonomyLevel::Automatic => GateDecision::Execute,
    }
}

/// Steps 1–4 of [`evaluate`]: may this caller invoke this action at all,
/// right now? Every refusal, and nothing else — no retry-safety check and no
/// risk/initiator/taint matrix.
///
/// Split out for `execute::dispatch_approved_agent_action`. A human's
/// four-eyes approval already answered the matrix's question (confirm first,
/// or approve), so re-running the whole of [`evaluate`] there would raise a
/// second approval request for an action a human just approved. What an
/// approval does **not** answer is whether the licence, the kill-switch, the
/// caller's privileges, the session's ceiling, or its allow-list still permit
/// the action at the moment it runs — an approval authorizes one action, it
/// does not freeze the security state it was requested under.
pub fn admissible(
    descriptor: &ActionDescriptor,
    ctx: &ActionContext,
    inputs: &GateInputs<'_>,
) -> Result<(), GateRefusal> {
    // 1. Availability. Unlicensed and switched-off are indistinguishable.
    if !inputs.licensed {
        return Err(GateRefusal::NotAvailable);
    }
    if let Some(surface) = inputs.surface
        && !inputs.ai.allows(surface)
    {
        return Err(GateRefusal::NotAvailable);
    }

    // 2. Air-gap (I-7). An external-effect action on a deployment that has not
    // enabled outbound effects does not exist, as far as any caller can tell.
    if descriptor.effect == Effect::External && !inputs.external_effects_enabled {
        return Err(GateRefusal::ExternalEffectDisabled);
    }

    // 3. The session's allow-list. Before privilege, so an action a session
    // cannot see is refused as absent rather than as forbidden — the same
    // ordering reason availability goes first. `session.rs`'s own doc for
    // `AgentSession::permits` names this gate as the enforcement point;
    // filtering `tools/list` alone would leave the list cosmetic.
    if !ctx.session_permits(descriptor.id) {
        return Err(GateRefusal::NotInSessionAllowList);
    }

    // 4. Privilege, against the CALLER's own context. Not the agent's, not a
    // service principal's — there is no such thing here (I-3).
    let holds_all = descriptor
        .required_privileges
        .iter()
        .all(|p| ctx.security.is_admin || ctx.security.privileges.contains(*p));
    if !holds_all {
        return Err(GateRefusal::Forbidden);
    }

    // 4b. Session ceiling.
    if let Some(ceiling) = ctx.risk_ceiling
        && descriptor.risk > ceiling
    {
        return Err(GateRefusal::AboveCeiling);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::tests::{security_context, security_context_with};
    use crate::descriptor::ActionDescriptor;
    use attome_modules::MODULE_AI;

    fn descriptor(risk: RiskTier, effect: Effect, retry: RetryClass) -> ActionDescriptor {
        ActionDescriptor::new("test.action", "test", risk, effect, retry, MODULE_AI, &[])
    }

    fn inputs<'a>(ai: &'a AiEnablement) -> GateInputs<'a> {
        GateInputs {
            licensed: true,
            ai,
            surface: None,
            external_effects_enabled: false,
        }
    }

    fn all_on() -> AiEnablement {
        AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        }
    }

    // ── The negative tests. These are the point of the file. ──────────────

    /// NEGATIVE TEST: an agent cannot reach a Consequential action, through
    /// any argument. Not with a Consequential ceiling, not with a clean
    /// context, not as an admin.
    #[test]
    fn an_agent_can_never_auto_execute_a_consequential_action() {
        let ai = all_on();
        let d = descriptor(
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::Idempotent,
        );

        for security in [security_context(), security_context_with(true, &[])] {
            let ctx = ActionContext::agent(security, RiskTier::Consequential);
            assert_eq!(
                evaluate(&d, &ctx, &inputs(&ai)),
                Ok(GateDecision::RequiresApproval),
                "a Consequential action must never auto-execute for an agent"
            );
            // And not by adding an idempotency key either.
            let keyed = ctx.with_idempotency_key("k");
            assert_eq!(
                evaluate(&d, &keyed, &inputs(&ai)),
                Ok(GateDecision::RequiresApproval)
            );
        }
    }

    /// NEGATIVE TEST (I-10): a Reversible write that would auto-execute for an
    /// agent degrades to confirm-first once the context carries tool-obtained
    /// text. This is the rule that stands between planted text in a record's
    /// notes and an unattended write.
    #[test]
    fn a_reversible_agent_write_degrades_to_confirm_first_on_a_tainted_context() {
        let ai = all_on();
        let d = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent);

        let clean = ActionContext::agent(security_context(), RiskTier::Consequential);
        assert_eq!(
            evaluate(&d, &clean, &inputs(&ai)),
            Ok(GateDecision::Execute)
        );

        let tainted = clean.tainted();
        assert_eq!(
            evaluate(&d, &tainted, &inputs(&ai)),
            Ok(GateDecision::ConfirmFirst {
                reason: ConfirmReason::RetrievedContentInContext
            }),
            "retrieved content in context must degrade an agent's Reversible \
             write to confirm-first (I-10)"
        );
    }

    /// NEGATIVE TEST (M35 v1 C1): an action declared `agent_must_confirm`
    /// never completes for an agent — on a clean context as well as a tainted
    /// one — while a human's own invocation still executes. The clean-context
    /// case is the bypass this rule exists to close.
    #[test]
    fn an_agent_must_confirm_action_confirms_for_an_agent_even_on_a_clean_context() {
        let ai = all_on();
        let d = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent)
            .agent_must_confirm();
        let expected = Ok(GateDecision::ConfirmFirst {
            reason: ConfirmReason::AgentProposalNeedsConfirmation,
        });

        let clean = ActionContext::agent(security_context(), RiskTier::Consequential);
        assert_eq!(
            evaluate(&d, &clean, &inputs(&ai)),
            expected,
            "a clean agent context must not complete an agent_must_confirm action"
        );
        assert_eq!(evaluate(&d, &clean.tainted(), &inputs(&ai)), expected);

        let human = ActionContext::user(security_context());
        assert_eq!(
            evaluate(&d, &human, &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
        assert_eq!(
            evaluate(&d, &human.tainted(), &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
    }

    /// Regression guard: the marker is per action. A Reversible write that
    /// does not declare it keeps the ordinary matrix — a clean agent context
    /// still executes it.
    #[test]
    fn a_reversible_agent_write_without_the_marker_is_unchanged() {
        let ai = all_on();
        let d = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent);
        assert!(!d.agent_must_confirm);
        let clean = ActionContext::agent(security_context(), RiskTier::Consequential);
        assert_eq!(
            evaluate(&d, &clean, &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
    }

    /// A human's own Reversible write is unaffected by taint — they are
    /// looking at the record.
    #[test]
    fn taint_does_not_gate_a_humans_own_write() {
        let ai = all_on();
        let d = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent);
        let ctx = ActionContext::user(security_context()).tainted();
        assert_eq!(evaluate(&d, &ctx, &inputs(&ai)), Ok(GateDecision::Execute));
    }

    /// NEGATIVE TEST: the kill-switch produces NotFound, not Forbidden. A 403
    /// would confirm the feature exists to a caller who is not entitled to
    /// know that.
    #[test]
    fn the_kill_switch_makes_an_action_invisible_rather_than_forbidden() {
        let off = AiEnablement::default();
        let d = descriptor(RiskTier::Read, Effect::Read, RetryClass::Idempotent);
        let ctx = ActionContext::user(security_context());
        let mut i = inputs(&off);
        i.surface = Some(AiSurface::Fields);

        assert_eq!(evaluate(&d, &ctx, &i), Err(GateRefusal::NotAvailable));
        assert!(matches!(
            AppError::from(GateRefusal::NotAvailable),
            AppError::NotFound
        ));
    }

    /// An unlicensed module is indistinguishable from a switched-off one.
    #[test]
    fn an_unlicensed_module_is_indistinguishable_from_a_disabled_one() {
        let ai = all_on();
        let d = descriptor(RiskTier::Read, Effect::Read, RetryClass::Idempotent);
        let ctx = ActionContext::user(security_context());
        let mut i = inputs(&ai);
        i.licensed = false;
        assert_eq!(evaluate(&d, &ctx, &i), Err(GateRefusal::NotAvailable));
    }

    /// The kill-switch must not disable a non-AI caller. A human clicking a
    /// button that happens to reach a read action is not an AI surface.
    #[test]
    fn the_kill_switch_does_not_gate_a_non_ai_surface() {
        let off = AiEnablement::default();
        let d = descriptor(RiskTier::Read, Effect::Read, RetryClass::Idempotent);
        let ctx = ActionContext::user(security_context());
        assert_eq!(
            evaluate(&d, &ctx, &inputs(&off)),
            Ok(GateDecision::Execute),
            "surface = None means this invocation is not an AI surface"
        );
    }

    /// NEGATIVE TEST (I-7): an external-effect action does not exist on a
    /// deployment that has not enabled outbound effects.
    #[test]
    fn an_external_effect_action_is_refused_when_external_effects_are_off() {
        let ai = all_on();
        let d = descriptor(RiskTier::Read, Effect::External, RetryClass::Idempotent);
        let ctx = ActionContext::user(security_context());
        assert_eq!(
            evaluate(&d, &ctx, &inputs(&ai)),
            Err(GateRefusal::ExternalEffectDisabled)
        );

        let mut enabled = inputs(&ai);
        enabled.external_effects_enabled = true;
        assert_eq!(evaluate(&d, &ctx, &enabled), Ok(GateDecision::Execute));
    }

    /// NEGATIVE TEST: an action above the session ceiling is refused before
    /// the risk matrix is ever consulted.
    #[test]
    fn an_action_above_the_session_ceiling_is_refused() {
        let ai = all_on();
        let d = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent);
        let ctx = ActionContext::agent(security_context(), RiskTier::Read);
        assert_eq!(
            evaluate(&d, &ctx, &inputs(&ai)),
            Err(GateRefusal::AboveCeiling)
        );
    }

    /// NEGATIVE TEST (TODO-043): an agent cannot invoke a
    /// duplicate-producing action without a key, because tool loops retry.
    #[test]
    fn an_agent_needs_an_idempotency_key_for_a_non_replayable_action() {
        let ai = all_on();
        let d = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::RequiresKey);
        let ctx = ActionContext::agent(security_context(), RiskTier::Consequential);
        assert_eq!(
            evaluate(&d, &ctx, &inputs(&ai)),
            Err(GateRefusal::IdempotencyKeyRequired)
        );
        assert_eq!(
            evaluate(
                &d,
                &ctx.clone().with_idempotency_key("session:call-1"),
                &inputs(&ai)
            ),
            Ok(GateDecision::Execute)
        );
        // A human clicking twice is a human's decision, not a retry loop.
        let human = ActionContext::user(security_context());
        assert_eq!(
            evaluate(&d, &human, &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
    }

    fn allow_listed_session(allowed: Option<Vec<&str>>) -> crate::session::AgentSession {
        crate::session::AgentSession {
            id: uuid::Uuid::now_v7(),
            owner_user_id: uuid::Uuid::now_v7(),
            risk_ceiling: RiskTier::Consequential,
            allowed_action_ids: allowed.map(|v| v.into_iter().map(str::to_owned).collect()),
            tainted: false,
            policy: crate::session::PolicySnapshot::NONE,
            anonymous_channel: false,
            surface: "test".to_owned(),
            trial: false,
        }
    }

    /// NEGATIVE TEST: a session's allow-list is an enforcement boundary, not
    /// a listing filter. An action the session does not name is refused at
    /// the gate — as absent (404), not forbidden — even though the caller
    /// holds every privilege it needs and it is within the ceiling.
    #[test]
    fn an_action_outside_the_sessions_allow_list_is_refused_at_the_gate() {
        let ai = all_on();
        let d = descriptor(RiskTier::Read, Effect::Read, RetryClass::Idempotent);
        let admin = security_context_with(true, &[]);

        let narrowed = allow_listed_session(Some(vec!["record.get"]));
        let ctx = ActionContext::for_session(admin.clone(), &narrowed);
        assert_eq!(
            evaluate(&d, &ctx, &inputs(&ai)),
            Err(GateRefusal::NotInSessionAllowList)
        );
        assert!(matches!(
            AppError::from(GateRefusal::NotInSessionAllowList),
            AppError::NotFound
        ));

        let nothing = allow_listed_session(Some(vec![]));
        assert_eq!(
            evaluate(
                &d,
                &ActionContext::for_session(admin.clone(), &nothing),
                &inputs(&ai)
            ),
            Err(GateRefusal::NotInSessionAllowList),
            "an empty allow-list permits nothing"
        );

        let naming_it = allow_listed_session(Some(vec!["test.action"]));
        assert_eq!(
            evaluate(
                &d,
                &ActionContext::for_session(admin.clone(), &naming_it),
                &inputs(&ai)
            ),
            Ok(GateDecision::Execute)
        );
        let unrestricted = allow_listed_session(None);
        assert_eq!(
            evaluate(
                &d,
                &ActionContext::for_session(admin, &unrestricted),
                &inputs(&ai)
            ),
            Ok(GateDecision::Execute)
        );
    }

    /// `admissible` carries every refusal but never the matrix: a tainted
    /// Reversible write and a Consequential agent action are both admissible,
    /// because the approval that precedes a post-approval run already is the
    /// confirmation/four-eyes step. Re-asking would loop back to a human.
    #[test]
    fn admissible_refuses_what_evaluate_refuses_but_never_reopens_confirmation() {
        let ai = all_on();
        let session = allow_listed_session(None);
        let tainted = ActionContext::for_session(security_context(), &session).tainted();

        let reversible = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent);
        assert_eq!(
            evaluate(&reversible, &tainted, &inputs(&ai)),
            Ok(GateDecision::ConfirmFirst {
                reason: ConfirmReason::RetrievedContentInContext
            })
        );
        assert_eq!(admissible(&reversible, &tainted, &inputs(&ai)), Ok(()));

        let consequential = descriptor(
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::RequiresKey,
        );
        assert_eq!(admissible(&consequential, &tainted, &inputs(&ai)), Ok(()));

        let mut unlicensed = inputs(&ai);
        unlicensed.licensed = false;
        assert_eq!(
            admissible(&reversible, &tainted, &unlicensed),
            Err(GateRefusal::NotAvailable)
        );

        let off = AiEnablement::default();
        let mut switched_off = inputs(&off);
        switched_off.surface = Some(AiSurface::Fields);
        assert_eq!(
            admissible(&reversible, &tainted, &switched_off),
            Err(GateRefusal::NotAvailable)
        );

        let privileged = ActionDescriptor::new(
            "test.privileged",
            "test",
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::Idempotent,
            MODULE_AI,
            &["ai_agent.supervise"],
        );
        assert_eq!(
            admissible(&privileged, &tainted, &inputs(&ai)),
            Err(GateRefusal::Forbidden)
        );
    }

    /// A missing privilege is Forbidden, and it is checked against the
    /// caller's own context even when an agent is driving.
    #[test]
    fn a_missing_privilege_is_refused_for_agent_and_user_alike() {
        let ai = all_on();
        let d = ActionDescriptor::new(
            "test.privileged",
            "test",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &["account.read"],
        );
        for ctx in [
            ActionContext::user(security_context()),
            ActionContext::agent(security_context(), RiskTier::Consequential),
        ] {
            assert_eq!(
                evaluate(&d, &ctx, &inputs(&ai)),
                Err(GateRefusal::Forbidden)
            );
        }

        let granted = security_context_with(false, &["account.read"]);
        assert_eq!(
            evaluate(&d, &ActionContext::user(granted), &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
    }

    /// THE property of this file, AH8 edition: across every input, a
    /// Consequential action runs for an agent only when an administrator
    /// stored a level of two or more for it and, after the taint rail, it is
    /// still two or more.
    #[test]
    fn no_consequential_action_runs_for_an_agent_without_a_stored_level_of_two_or_more() {
        let ai = all_on();
        let mut checked = 0;
        let grants: Vec<Option<AutonomyLevel>> = std::iter::once(None)
            .chain(AutonomyLevel::ALL.into_iter().map(Some))
            .collect();

        for effect in [Effect::Read, Effect::Write, Effect::External] {
            for retry in [RetryClass::Idempotent, RetryClass::RequiresKey] {
                for (must_confirm, locked) in [(false, false), (true, false), (true, true)] {
                    let mut d = descriptor(RiskTier::Consequential, effect, retry);
                    if must_confirm {
                        d = d.agent_must_confirm();
                    }
                    if locked {
                        d = d.autonomy_locked();
                    }
                    for ceiling in [
                        RiskTier::Read,
                        RiskTier::Reversible,
                        RiskTier::Consequential,
                    ] {
                        for tainted in [false, true] {
                            for keyed in [false, true] {
                                for surface in [None, Some(AiSurface::Chat)] {
                                    for grant in &grants {
                                        for undo in [None, Some(60)] {
                                            let mut ctx =
                                                ActionContext::agent(security_context(), ceiling);
                                            if tainted {
                                                ctx = ctx.tainted();
                                            }
                                            if keyed {
                                                ctx = ctx.with_idempotency_key("k");
                                            }
                                            ctx.autonomy =
                                                grant.map(|level| crate::autonomy::AutonomyGrant {
                                                    level,
                                                    undo_seconds: 300,
                                                });
                                            ctx.undo_window_seconds = undo;
                                            let gate_inputs = GateInputs {
                                                licensed: true,
                                                ai: &ai,
                                                surface,
                                                external_effects_enabled: true,
                                            };
                                            let decision = evaluate(&d, &ctx, &gate_inputs);
                                            checked += 1;

                                            let effective = grant
                                                .map(|l| if tainted { l.lowered() } else { l });
                                            let may_run = !locked
                                                && effective.is_some_and(|l| {
                                                    l >= AutonomyLevel::ActWithUndo
                                                });
                                            let runs = matches!(
                                                decision,
                                                Ok(GateDecision::Execute
                                                    | GateDecision::ExecuteAndReport
                                                    | GateDecision::ExecuteAfterDelay { .. })
                                            );
                                            assert!(
                                                may_run || !runs,
                                                "a Consequential agent action returned {decision:?} \
                                                 for grant={grant:?} tainted={tainted} \
                                                 must_confirm={must_confirm} locked={locked} \
                                                 ceiling={ceiling:?} \
                                                 keyed={keyed} effect={effect:?} retry={retry:?} \
                                                 surface={surface:?} undo={undo:?}"
                                            );
                                            // Below act_with_undo the only outcomes are
                                            // a refusal, approval, a confirmation the
                                            // confirm path turns into approval, or a
                                            // stage the person applies.
                                            if !may_run {
                                                assert!(
                                                    matches!(
                                                        decision,
                                                        Ok(GateDecision::RequiresApproval
                                                            | GateDecision::ConfirmFirst { .. }
                                                            | GateDecision::Stage)
                                                            | Err(_)
                                                    ),
                                                    "unexpected {decision:?}"
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(
            checked,
            3 * 2 * 3 * 3 * 2 * 2 * 2 * 7 * 2,
            "the sweep must be complete"
        );
    }

    fn agent_with(level: Option<AutonomyLevel>, tainted: bool) -> ActionContext {
        let mut ctx = ActionContext::agent(security_context(), RiskTier::Consequential);
        if tainted {
            ctx = ctx.tainted();
        }
        ctx.autonomy = level.map(|level| crate::autonomy::AutonomyGrant {
            level,
            undo_seconds: 120,
        });
        ctx
    }

    #[test]
    fn a_tainted_context_always_lowers_the_level_by_one() {
        let ai = all_on();
        for risk in [RiskTier::Reversible, RiskTier::Consequential] {
            let d = descriptor(risk, Effect::Write, RetryClass::Idempotent);
            for level in AutonomyLevel::ALL {
                let tainted = evaluate(&d, &agent_with(Some(level), true), &inputs(&ai));
                let clean_lower =
                    evaluate(&d, &agent_with(Some(level.lowered()), false), &inputs(&ai));
                // The confirm reason differs on purpose (it names the taint);
                // the kind of decision must not.
                assert_eq!(
                    tainted.as_ref().map(std::mem::discriminant),
                    clean_lower.as_ref().map(std::mem::discriminant),
                    "{risk:?} at {level:?}: tainted gave {tainted:?}"
                );
            }
        }
    }

    #[test]
    fn an_unset_consequential_action_still_requires_approval() {
        let ai = all_on();
        let d = descriptor(
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::Idempotent,
        );
        assert_eq!(
            evaluate(&d, &agent_with(None, false), &inputs(&ai)),
            Ok(GateDecision::RequiresApproval)
        );
    }

    #[test]
    fn each_level_maps_to_its_decision() {
        let ai = all_on();
        let d = descriptor(
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::Idempotent,
        );
        let at = |l| evaluate(&d, &agent_with(Some(l), false), &inputs(&ai));
        assert!(matches!(
            at(AutonomyLevel::Suggest),
            Ok(GateDecision::ConfirmFirst { .. })
        ));
        assert_eq!(
            at(AutonomyLevel::AskFirst),
            Ok(GateDecision::RequiresApproval)
        );
        assert_eq!(at(AutonomyLevel::ActOnReview), Ok(GateDecision::Stage));
        assert_eq!(
            at(AutonomyLevel::ActWithUndo),
            Ok(GateDecision::ExecuteAfterDelay {
                seconds: 120,
                report: true
            })
        );
        assert_eq!(
            at(AutonomyLevel::ActAndReport),
            Ok(GateDecision::ExecuteAndReport)
        );
        assert_eq!(at(AutonomyLevel::Automatic), Ok(GateDecision::Execute));
    }

    #[test]
    fn agent_must_confirm_is_the_built_in_rule_an_explicit_level_replaces() {
        let ai = all_on();
        let d = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent)
            .agent_must_confirm();
        assert_eq!(
            evaluate(&d, &agent_with(None, false), &inputs(&ai)),
            Ok(GateDecision::ConfirmFirst {
                reason: ConfirmReason::AgentProposalNeedsConfirmation
            }),
            "no row: the agent proposes and the human completes"
        );
        assert_eq!(
            evaluate(
                &d,
                &agent_with(Some(AutonomyLevel::Automatic), false),
                &inputs(&ai)
            ),
            Ok(GateDecision::Execute)
        );
    }

    #[test]
    fn an_autonomy_locked_action_ignores_the_level() {
        let ai = all_on();
        let d = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent)
            .agent_must_confirm()
            .autonomy_locked();
        assert_eq!(
            evaluate(
                &d,
                &agent_with(Some(AutonomyLevel::Automatic), false),
                &inputs(&ai)
            ),
            Ok(GateDecision::ConfirmFirst {
                reason: ConfirmReason::AgentProposalNeedsConfirmation
            })
        );
    }

    #[test]
    fn an_undo_window_delays_a_run_but_never_skips_approval() {
        let ai = all_on();
        let write = descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent);
        let user = ActionContext::user(security_context()).with_undo_window(60);
        assert_eq!(
            evaluate(&write, &user, &inputs(&ai)),
            Ok(GateDecision::ExecuteAfterDelay {
                seconds: 60,
                report: false
            })
        );
        let consequential = descriptor(
            RiskTier::Consequential,
            Effect::Write,
            RetryClass::Idempotent,
        );
        let agent = agent_with(None, false).with_undo_window(60);
        assert_eq!(
            evaluate(&consequential, &agent, &inputs(&ai)),
            Ok(GateDecision::RequiresApproval)
        );
        let read = descriptor(RiskTier::Read, Effect::Read, RetryClass::Idempotent);
        assert_eq!(
            evaluate(&read, &user, &inputs(&ai)),
            Ok(GateDecision::Execute),
            "a read is never delayed"
        );
    }

    // ── AE1-T4: the risk tier on every surface. ───────────────────────────

    fn tiers() -> [ActionDescriptor; 3] {
        [
            descriptor(RiskTier::Read, Effect::Read, RetryClass::Idempotent),
            descriptor(RiskTier::Reversible, Effect::Write, RetryClass::Idempotent),
            descriptor(
                RiskTier::Consequential,
                Effect::Write,
                RetryClass::Idempotent,
            ),
        ]
    }

    /// A person on a live surface: a read runs, a reversible write runs (its
    /// undo is offered), a consequential action stops until they confirm.
    #[test]
    fn risk_tier_person_confirms_consequential() {
        let ai = all_on();
        let [read, reversible, consequential] = tiers();
        let person = ActionContext::person(security_context(), false);
        assert_eq!(
            evaluate(&read, &person, &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
        assert_eq!(
            evaluate(&reversible, &person, &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
        assert_eq!(
            evaluate(&consequential, &person, &inputs(&ai)),
            Ok(GateDecision::ConfirmFirst {
                reason: ConfirmReason::ConsequentialNeedsConfirmation
            })
        );
        let confirmed = ActionContext::person(security_context(), true);
        assert_eq!(
            evaluate(&consequential, &confirmed, &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
    }

    /// An undo window never lets an unconfirmed consequential action run.
    #[test]
    fn risk_tier_undo_window_keeps_confirmation() {
        let ai = all_on();
        let [_, _, consequential] = tiers();
        let person = ActionContext::person(security_context(), false).with_undo_window(60);
        assert!(matches!(
            evaluate(&consequential, &person, &inputs(&ai)),
            Ok(GateDecision::ConfirmFirst { .. })
        ));
    }

    /// An agent (chat, MCP, a scheduled agent) never runs a consequential
    /// action on its own: it goes to approval, tainted or not.
    #[test]
    fn risk_tier_agent_needs_approval_for_consequential() {
        let ai = all_on();
        let [read, reversible, consequential] = tiers();
        for tainted in [false, true] {
            let agent = agent_with(None, tainted);
            assert_eq!(
                evaluate(&read, &agent, &inputs(&ai)),
                Ok(GateDecision::Execute)
            );
            assert_eq!(
                evaluate(&consequential, &agent, &inputs(&ai)),
                Ok(GateDecision::RequiresApproval)
            );
            let reversible_decision = evaluate(&reversible, &agent, &inputs(&ai));
            if tainted {
                assert!(matches!(
                    reversible_decision,
                    Ok(GateDecision::ConfirmFirst { .. })
                ));
            } else {
                assert_eq!(reversible_decision, Ok(GateDecision::Execute));
            }
        }
    }

    /// A flow or job acting as a user is not asked: it was decided when it
    /// was published.
    #[test]
    fn risk_tier_flow_context_is_not_asked() {
        let ai = all_on();
        let [_, _, consequential] = tiers();
        let flow = ActionContext::user(security_context());
        assert_eq!(
            evaluate(&consequential, &flow, &inputs(&ai)),
            Ok(GateDecision::Execute)
        );
    }
}

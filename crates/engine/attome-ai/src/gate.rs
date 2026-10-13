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
    Ok(match (descriptor.risk, ctx.initiator) {
        (RiskTier::Read, _) => GateDecision::Execute,

        (RiskTier::Reversible, Initiator::User) => GateDecision::Execute,

        // I-10's operative half. A Reversible write normally auto-executes for
        // an agent and offers undo. When the context carries tool-obtained
        // text, the write may have been suggested by that text rather than by
        // the human, so a human confirms this specific invocation first.
        (RiskTier::Reversible, Initiator::Agent) => {
            // M35 v1 C1: an action declared `agent_must_confirm` never
            // completes for an agent. Checked first so a clean context is
            // not a way around it — taint is irrelevant for these.
            if descriptor.agent_must_confirm {
                GateDecision::ConfirmFirst {
                    reason: ConfirmReason::AgentProposalNeedsConfirmation,
                }
            } else if ctx.contains_retrieved_content {
                GateDecision::ConfirmFirst {
                    reason: ConfirmReason::RetrievedContentInContext,
                }
            } else {
                GateDecision::Execute
            }
        }

        // A human invoking a Consequential action through the UI is the
        // existing four-eyes question, answered by the deployment's
        // `approval.required_actions` policy rather than by this gate.
        (RiskTier::Consequential, Initiator::User) => GateDecision::Execute,

        // NEVER auto-executes. Not when the context is clean, not when the
        // ceiling permits it, not when the model is confident. This arm is the
        // reason the whole file exists.
        (RiskTier::Consequential, Initiator::Agent) => GateDecision::RequiresApproval,
    })
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

    /// **The universal claim TODO-041 makes, swept rather than sampled.**
    ///
    /// *An agent cannot reach a Consequential action without an approval,
    /// through any façade or any argument.* That is a statement about every
    /// input combination, so it is tested as one: every ceiling, tainted and
    /// clean, with and without an idempotency key, every effect, every retry
    /// class, and every AI surface. 288 combinations, one answer.
    ///
    /// The levers in the sweep are the ones an over-eager tool loop — or
    /// someone trying to make a failing integration pass — actually reaches
    /// for. Raising the session ceiling to `Consequential` is the most
    /// plausible of them, and it is precisely the one that must not work: the
    /// ceiling bounds what an agent may *attempt*, and the risk matrix decides
    /// what happens when it does.
    #[test]
    fn no_input_combination_lets_an_agent_auto_execute_a_consequential_action() {
        let ai = all_on();
        let mut checked = 0;

        for effect in [Effect::Read, Effect::Write, Effect::External] {
            for retry in [RetryClass::Idempotent, RetryClass::RequiresKey] {
                let d = descriptor(RiskTier::Consequential, effect, retry);
                for ceiling in [
                    RiskTier::Read,
                    RiskTier::Reversible,
                    RiskTier::Consequential,
                ] {
                    for tainted in [false, true] {
                        for keyed in [false, true] {
                            for surface in [
                                None,
                                Some(AiSurface::Fields),
                                Some(AiSurface::SemanticSearch),
                                Some(AiSurface::Chat),
                            ] {
                                let mut ctx = ActionContext::agent(security_context(), ceiling);
                                if tainted {
                                    ctx = ctx.tainted();
                                }
                                if keyed {
                                    ctx = ctx.with_idempotency_key("k");
                                }
                                let gate_inputs = GateInputs {
                                    licensed: true,
                                    ai: &ai,
                                    surface,
                                    external_effects_enabled: true,
                                };

                                let decision = evaluate(&d, &ctx, &gate_inputs);
                                checked += 1;

                                // Either the gate refused outright (below the
                                // ceiling, air-gapped, unlicensed) or it
                                // required approval. What must never appear is
                                // `Execute` — or `ConfirmFirst`, which is a
                                // human-in-the-loop weaker than approval and
                                // would be a silent downgrade.
                                match decision {
                                    Ok(GateDecision::RequiresApproval) | Err(_) => {}
                                    other => panic!(
                                        "a Consequential agent action returned {other:?} for \
                                         ceiling={ceiling:?} tainted={tainted} keyed={keyed} \
                                         effect={effect:?} retry={retry:?} surface={surface:?}"
                                    ),
                                }
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(checked, 3 * 2 * 3 * 2 * 2 * 4, "the sweep must be complete");
    }
}

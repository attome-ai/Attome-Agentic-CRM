//! Who is invoking, on whose behalf, and whether the context is tainted.

use std::sync::Arc;

use attome_server::security::SecurityContext;
use uuid::Uuid;

use crate::descriptor::RiskTier;

/// Who initiated this invocation.
///
/// Invariant I-3: **an action always runs as the human.** There is no
/// service-principal variant here and no service-principal overload of
/// `invoke`, because the moment one exists it becomes the convenient way to
/// make a permission problem go away — and the audit trail then records that
/// "the system" changed a customer record.
///
/// `Agent` does not mean "a different principal". It means the same human's
/// `SecurityContext`, reached through a model rather than a click. Attribution
/// is dual: an auditor must be able to distinguish an agent-initiated change
/// from a user-initiated one, and must never see either resolve to the AI
/// alone or to the human alone (TODO-042).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Initiator {
    /// A human acted directly — clicked a button, submitted a form.
    User,
    /// A model chose this action inside a tool loop, on the human's behalf.
    Agent,
}

/// Everything the gate needs to decide, assembled by the caller and never by
/// the model.
#[derive(Clone)]
pub struct ActionContext {
    /// The caller's own security context. Visibility, privileges, and record
    /// scope are all resolved from this — the action inherits exactly what the
    /// human can already see and do, never more.
    ///
    /// `Arc`, not an owned value: `SecurityContext` deliberately does not
    /// derive `Clone` (see its doc comment — the deep `HashSet`/`Vec` clone
    /// was paid on every cache hit and every request), and shared ownership in
    /// this platform is always expressed with the `Arc` the resolver and
    /// `AuthorizedContext` already carry.
    pub security: Arc<SecurityContext>,
    pub initiator: Initiator,
    /// The ceiling from the agent session, when there is one. `None` for a
    /// direct user invocation.
    ///
    /// A session is the unit an admin can kill (TODO-039), which is why the
    /// ceiling lives on the context rather than being derived from the
    /// caller's role: revoking a runaway agent must not require revoking the
    /// human's own privileges.
    pub risk_ceiling: Option<RiskTier>,
    /// **Whether any content in this turn came from a tool.** Set when a
    /// retrieved segment enters prompt assembly and never cleared for the
    /// turn.
    ///
    /// This is invariant I-10's carrier. Text an agent obtained through any
    /// tool — a record's notes, a search hit, an OCR'd document — is
    /// attacker-influenceable, and an agent holding tools is the canonical
    /// injection target. The flag exists because the defense cannot live in
    /// the prompt: a prompt is not a control, an LLM can be argued out of one,
    /// and a match on `(risk, initiator, tainted)` before dispatch cannot.
    pub contains_retrieved_content: bool,
    /// Idempotency key for this invocation, derived from
    /// `(agent_session, tool_call_id)` — data the MODEL does not choose
    /// (TODO-043). A model-chosen key would let a retry be presented as a new
    /// call simply by changing the key.
    pub idempotency_key: Option<String>,
    /// The live session this invocation runs under, when there is one.
    ///
    /// Added for M98 Phase 1 (`record.update_field`'s blast-radius controls):
    /// a per-session daily write cap and the invocation ledger's
    /// `action_invocation.agent_session_id` both need the session's
    /// own id, and `risk_ceiling` alone does not carry it — the ceiling is a
    /// value copied off the session row, not a reference back to it. `None`
    /// for a direct human invocation and for any agent call this crate does
    /// not yet thread a real session through (no behavioural change for
    /// existing callers: every prior construction path leaves this `None`,
    /// exactly as before this field existed).
    pub agent_session_id: Option<Uuid>,
    /// The session's action allow-list, copied off the session row by
    /// [`Self::for_session`]. `None` means no allow-list restriction (a direct
    /// human invocation, or a session whose `allowed_action_ids` is NULL);
    /// `Some(vec![])` means nothing is allowed — see
    /// `crate::session::AgentSession::allowed_action_ids` for why the two
    /// must not collapse. Enforced by `gate::admissible`, so `tools/list`,
    /// `tools/call`, and a post-approval run all read the same list.
    pub session_allowed_action_ids: Option<Vec<String>>,
    /// The session's knowledge scope, copied off its D-505 snapshot by
    /// [`Self::for_session`] (D-512 §7). Retrieval intersects it with the
    /// caller's readable collections before any evidence is returned. `None`
    /// means no narrowing; `Some(vec![])` means no knowledge retrieval.
    pub session_knowledge_source_refs: Option<Vec<Uuid>>,
    /// The session's policy token limit, copied off its D-505 snapshot by
    /// [`Self::for_session`]. `budget_guard` applies the lower of it and
    /// `Budget::PER_SESSION_DEFAULT`. `None` keeps the default.
    pub session_max_tokens: Option<i64>,
    /// The `attome_approval` request a human approved this invocation under,
    /// when it runs from `approval_admin::execute_approved` (C19). `None` on
    /// every other path. Recorded on the mandatory `Ai` + `Execute` event as
    /// `approval_request_ref`.
    pub approval_request_id: Option<Uuid>,
    /// The session runs as a shared channel principal (C9, D-558) — copied
    /// from [`crate::session::AgentSession::anonymous_channel`] by
    /// [`Self::for_session`], and `false` on every other constructor.
    /// `budget_guard` meters such a session as its own visitor rather than as
    /// the shared principal; see that field's doc comment.
    pub anonymous_channel: bool,
    /// The surface of the session this invocation runs under
    /// (`agent_session.surface`), copied by [`Self::for_session`].
    /// `None` on every other constructor. Read only through
    /// [`Self::is_mcp_agent`], which decides whether MCP entity admission
    /// (`crate::mcp::admission`, plan item M3.4) applies.
    pub session_surface: Option<String>,
    /// AH8: the autonomy level an administrator granted this agent for this
    /// action, after its limits. **Set only by `execute::dispatch`** from the
    /// stored row, overwriting whatever a caller put here; `None` keeps the
    /// gate's built-in matrix.
    pub autonomy: Option<crate::autonomy::AutonomyGrant>,
    /// AH8: the caller asked for an undo window — hold the action this many
    /// seconds, cancellable, before it runs. Never skips a confirmation or an
    /// approval the gate requires; it only delays an action that would run.
    pub undo_window_seconds: Option<u32>,
}

impl std::fmt::Debug for ActionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionContext").finish_non_exhaustive()
    }
}

impl ActionContext {
    /// A direct human invocation: no ceiling, no taint, no agent session.
    pub fn user(security: Arc<SecurityContext>) -> Self {
        Self {
            security,
            initiator: Initiator::User,
            risk_ceiling: None,
            contains_retrieved_content: false,
            idempotency_key: None,
            agent_session_id: None,
            session_allowed_action_ids: None,
            session_knowledge_source_refs: None,
            session_max_tokens: None,
            approval_request_id: None,
            anonymous_channel: false,
            session_surface: None,
            autonomy: None,
            undo_window_seconds: None,
        }
    }

    /// An agent invocation on the human's behalf.
    ///
    /// The ceiling is required, not optional: an agent session without one is
    /// an agent with the human's full authority, which is the thing sessions
    /// exist to prevent. Making it a positional argument means it cannot be
    /// forgotten.
    pub fn agent(security: Arc<SecurityContext>, risk_ceiling: RiskTier) -> Self {
        Self {
            security,
            initiator: Initiator::Agent,
            risk_ceiling: Some(risk_ceiling),
            contains_retrieved_content: false,
            idempotency_key: None,
            agent_session_id: None,
            session_allowed_action_ids: None,
            session_knowledge_source_refs: None,
            session_max_tokens: None,
            approval_request_id: None,
            anonymous_channel: false,
            session_surface: None,
            autonomy: None,
            undo_window_seconds: None,
        }
    }

    /// Marks the context as carrying tool-obtained content. One-way: there is
    /// no `untaint`, because "we sanitised it" is not a claim this platform
    /// makes about text a model has already read.
    #[must_use]
    pub fn tainted(mut self) -> Self {
        self.contains_retrieved_content = true;
        self
    }

    #[must_use]
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Attaches the live `agent_session` id this invocation runs
    /// under. See the field's doc comment for why this is separate from
    /// `risk_ceiling`.
    #[must_use]
    pub fn with_agent_session(mut self, session_id: Uuid) -> Self {
        self.agent_session_id = Some(session_id);
        self
    }

    /// Holds the action for an undo window before it runs (AH8).
    #[must_use]
    pub fn with_undo_window(mut self, seconds: u32) -> Self {
        self.undo_window_seconds = Some(seconds.clamp(
            crate::autonomy::MIN_UNDO_SECONDS,
            crate::autonomy::MAX_UNDO_SECONDS,
        ));
        self
    }

    pub fn is_agent(&self) -> bool {
        self.initiator == Initiator::Agent
    }

    /// Whether this is an agent invocation under a session the MCP surface
    /// opened — the one caller MCP entity admission (plan item M3.4) governs.
    /// Derived from the session row's own `surface`, never from a request.
    pub fn is_mcp_agent(&self) -> bool {
        self.is_agent() && self.session_surface.as_deref() == Some(crate::mcp::MCP_SURFACE)
    }

    /// Whether the session this invocation runs under (if any) allows
    /// `action`. Always `true` outside a session.
    pub fn session_permits(&self, action: crate::descriptor::ActionId) -> bool {
        crate::session::allow_list_permits(self.session_allowed_action_ids.as_deref(), action)
    }

    /// Builds the context a live [`crate::session::AgentSession`]-driven
    /// invocation runs under (M33 Phase 1, D-460).
    ///
    /// **This is the one place a session's own `tainted` flag re-enters the
    /// per-invocation gate decision.** A session started downstream of a
    /// tainted `AgentStep` handoff (`crate::session::SessionStart.tainted`)
    /// carries that fact on the row, not on any in-flight context — so
    /// whatever eventually builds an `ActionContext` for a real invocation
    /// under that session MUST go through this constructor rather than
    /// `Self::agent` directly, or the taint silently disappears the moment a
    /// structured handoff repackages it. See the module doc's I-10 paragraph:
    /// taint is one-way, and a "clean-looking" JSON payload derived from
    /// tainted content is not itself a trust boundary.
    #[must_use]
    pub fn for_session(
        security: Arc<SecurityContext>,
        session: &crate::session::AgentSession,
    ) -> Self {
        let mut ctx = Self::agent(security, session.risk_ceiling);
        ctx.agent_session_id = Some(session.id);
        ctx.session_allowed_action_ids = session.allowed_action_ids.clone();
        ctx.session_knowledge_source_refs = session.policy.knowledge_source_refs.clone();
        ctx.session_max_tokens = session.policy.max_tokens_per_session;
        ctx.anonymous_channel = session.anonymous_channel;
        ctx.session_surface = Some(session.surface.clone());
        if session.tainted {
            ctx = ctx.tainted();
        }
        ctx
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

    pub(crate) fn security_context() -> Arc<SecurityContext> {
        security_context_with(false, &[])
    }

    /// `SecurityContext` deliberately does not derive `Clone`, so a test that
    /// wants an admin or a privilege-holder builds one rather than mutating a
    /// shared `Arc`.
    pub(crate) fn security_context_with(
        is_admin: bool,
        privileges: &[&str],
    ) -> Arc<SecurityContext> {
        Arc::new(SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
            privileges: privileges.iter().map(|p| (*p).to_owned()).collect(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            service_principal: false,
        })
    }

    #[test]
    fn a_user_context_carries_no_ceiling_and_no_taint() {
        let ctx = ActionContext::user(security_context());
        assert!(!ctx.is_agent());
        assert!(ctx.risk_ceiling.is_none());
        assert!(!ctx.contains_retrieved_content);
    }

    /// An agent session without a ceiling would be an agent holding the
    /// human's full authority. The constructor makes that unrepresentable.
    #[test]
    fn an_agent_context_always_carries_a_ceiling() {
        let ctx = ActionContext::agent(security_context(), RiskTier::Read);
        assert!(ctx.is_agent());
        assert_eq!(ctx.risk_ceiling, Some(RiskTier::Read));
    }

    /// Taint is one-way by design — there is no `untaint`, and this test
    /// exists so that adding one is a visible act.
    #[test]
    fn taint_is_one_way() {
        let ctx = ActionContext::agent(security_context(), RiskTier::Reversible).tainted();
        assert!(ctx.contains_retrieved_content);
        let still_tainted = ctx.clone().tainted();
        assert!(still_tainted.contains_retrieved_content);
    }

    fn agent_session(tainted: bool, ceiling: RiskTier) -> crate::session::AgentSession {
        crate::session::AgentSession {
            id: Uuid::now_v7(),
            owner_user_id: Uuid::now_v7(),
            risk_ceiling: ceiling,
            allowed_action_ids: None,
            tainted,
            policy: crate::session::PolicySnapshot::NONE,
            anonymous_channel: false,
            surface: "test".to_owned(),
        }
    }

    /// **The taint-does-not-propagate-as-trust property (M33 Phase 1,
    /// D-460), at the context boundary.** A session started downstream of a
    /// tainted `AgentStep` handoff must build a tainted `ActionContext` —
    /// `for_session` reads the session's own `tainted` flag, not some fresh
    /// assumption that a structured handoff payload is clean because it is
    /// no longer raw transcript.
    #[test]
    fn for_session_carries_the_sessions_own_taint_into_the_context() {
        let clean = ActionContext::for_session(
            security_context(),
            &agent_session(false, RiskTier::Reversible),
        );
        assert!(!clean.contains_retrieved_content);

        let session = agent_session(true, RiskTier::Reversible);
        let tainted = ActionContext::for_session(security_context(), &session);
        assert!(
            tainted.contains_retrieved_content,
            "a session started tainted must build a tainted context — the taint must not \
             be silently cleared just because the handoff that produced it was structured"
        );
        assert_eq!(tainted.agent_session_id, Some(session.id));
        assert_eq!(tainted.risk_ceiling, Some(RiskTier::Reversible));
    }

    /// MCP admission keys off the session row's surface: only a session the
    /// MCP surface opened counts, and a plain user or sessionless agent
    /// context never does.
    #[test]
    fn only_an_mcp_session_builds_an_mcp_agent_context() {
        let mut mcp = agent_session(true, RiskTier::Consequential);
        mcp.surface = crate::mcp::MCP_SURFACE.to_owned();
        assert!(ActionContext::for_session(security_context(), &mcp).is_mcp_agent());

        let mut webchat = agent_session(true, RiskTier::Consequential);
        webchat.surface = "webchat".to_owned();
        assert!(!ActionContext::for_session(security_context(), &webchat).is_mcp_agent());

        assert!(!ActionContext::user(security_context()).is_mcp_agent());
        assert!(!ActionContext::agent(security_context(), RiskTier::Read).is_mcp_agent());
    }

    /// The end-to-end version of the same property, through the real gate: a
    /// tainted session's Reversible write degrades to confirm-first — the
    /// same I-10 rule an untainted agent write would auto-execute under.
    /// This is what "taint does not propagate as trust across a handoff"
    /// means operationally: the downstream agent step is still gated as
    /// tainted, not silently trusted because the upstream step already
    /// "vouched" for it via a clean-looking JSON payload.
    #[test]
    fn a_tainted_handoff_session_degrades_a_reversible_write_through_the_real_gate() {
        use crate::descriptor::{ActionDescriptor, Effect, RetryClass, RiskTier as Tier};
        use crate::gate::{self, GateDecision};
        use attome_config::AiEnablement;

        let d = ActionDescriptor::new(
            "test.reversible_write",
            "d",
            Tier::Reversible,
            Effect::Write,
            RetryClass::Idempotent,
            attome_modules::MODULE_AI,
            &[],
        );
        let ai = AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        };
        let inputs = gate::GateInputs {
            licensed: true,
            ai: &ai,
            surface: None,
            external_effects_enabled: false,
        };

        // Upstream AgentStep A was tainted (e.g. its task came from retrieved
        // content); its session persisted `tainted = true`. Downstream
        // AgentStep B's session was started from A's structured handoff and
        // inherited that flag — this is what `for_session` reconstructs.
        let session_b = agent_session(true, Tier::Reversible);
        let ctx_b = ActionContext::for_session(security_context(), &session_b);

        assert_eq!(
            gate::evaluate(&d, &ctx_b, &inputs),
            Ok(GateDecision::ConfirmFirst {
                reason: crate::gate::ConfirmReason::RetrievedContentInContext
            }),
            "a handoff-tainted session's Reversible write must degrade to confirm-first, \
             not auto-execute as if the structured handoff had washed the taint away"
        );

        // Contrast: an untainted downstream session auto-executes, exactly
        // as the existing I-10 behaviour already establishes — proving the
        // difference above is really the taint flag, not something else.
        let session_c = agent_session(false, Tier::Reversible);
        let ctx_c = ActionContext::for_session(security_context(), &session_c);
        assert_eq!(
            gate::evaluate(&d, &ctx_c, &inputs),
            Ok(GateDecision::Execute)
        );
    }
}

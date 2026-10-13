//! The public web-chat assistant's governance (chatbot plan C9, D-558,
//! D-562 / I-19, I-20).
//!
//! `crates/server/src/omnichannel.rs` owns the transport — the anonymous
//! bearer token, rate limits, business hours, the `communication` thread.
//! This module owns what that transport must not decide for itself: which
//! session an anonymous visitor gets, what it may do, and what a turn's
//! outcome means for the reply. The handler stays thin.
//!
//! ## The session: a configured definition, narrowed, never widened
//!
//! [`start_session`] resolves `webchat.agent_definition_id` through the same
//! path an internal session uses (`agent::resolve_start`: the definition, its
//! live model, its policy, its capability packs), as the channel's service
//! principal, and then only narrows the result:
//!
//! - **Knowledge scope must be explicit.** A policy with no
//!   `knowledge_source_refs` (`None`, "every collection the caller can read")
//!   refuses the start: the caller here is a shared service principal, and
//!   "everything it can read" is not a scope anyone chose for anonymous
//!   visitors. An empty list (`Some([])`) means no knowledge at all — never
//!   "all" — and the retrieval actions are dropped with it. Nothing a visitor
//!   sends and nothing a model says can supply or widen the scope: it is the
//!   policy's, snapshotted at start.
//! - **The allow-list** is the definition's own list intersected with
//!   [`RETRIEVAL_ACTIONS`] (a definition with no list contributes both), plus
//!   `bot.handoff`. `query.execute` and every write are unreachable: they run
//!   as the service principal, and there is no public-query authorization
//!   boundary to run them under.
//! - **The ceiling is `Reversible`** (row A-68), never `Read`, which would
//!   refuse `bot.handoff`. With the allow-list above, the only `Reversible`
//!   action the session can hold is `bot.handoff`, which the channel — not
//!   the model — dispatches.
//! - **The token limit** is the lower of the policy's and
//!   `webchat.session_token_cap`, and `budget_guard` meters the session as its
//!   own visitor (`AgentSession::anonymous_channel`).
//!
//! ## `bot.handoff` is the channel's, not the model's
//!
//! It stays on the session's allow-list, because the channel dispatches it
//! under that session. It is never offered to the model
//! ([`CHANNEL_OWNED_ACTIONS`], filtered in `turn::run`): a turn that has
//! retrieved knowledge is tainted (I-10), a tainted `Reversible` call needs a
//! human confirmation, and an anonymous visitor has no route to give one. The
//! handoff would wait forever. The channel decides handoffs deterministically
//! instead ([`reply_for`]).

use attome_config::{AiEnablement, AiSurface, WebchatSection};
use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use uuid::Uuid;

use crate::actions::bot_handoff::{BOT_HANDOFF, HandoffReason};
use crate::agent::{ResolvedStart, SessionConstraints};
use crate::chat_view::Grounding;
use crate::conversation::TerminalState;
use crate::descriptor::RiskTier;
use crate::session::{AgentSession, PolicySnapshot, SessionStart};

use std::sync::Arc;

/// The surface an anonymous widget session is started under.
pub const SURFACE: &str = "webchat";

/// Actions a channel dispatches itself and the model is never offered, in any
/// anonymous channel session.
pub const CHANNEL_OWNED_ACTIONS: [&str; 1] = [BOT_HANDOFF];

/// The most an anonymous visitor's assistant may do besides the channel's own
/// handoff: read knowledge, within the policy's explicit scope.
pub const RETRIEVAL_ACTIONS: [&str; 2] = ["search.knowledge", "knowledge.answer"];

/// The session shape the widget runs under, from a resolved definition.
#[derive(Debug, Clone, PartialEq)]
pub struct WidgetGovernance {
    pub risk_ceiling: RiskTier,
    pub allowed_action_ids: Vec<String>,
    pub policy: PolicySnapshot,
}

/// Narrows a resolved definition to the widget's shape. Pure, so the boundary
/// is testable without a database.
///
/// Refuses (`Validation`) a policy with no explicit knowledge scope. See the
/// module doc for every rule applied.
pub fn clamp(
    resolved: ResolvedStart,
    session_token_cap: Option<u64>,
) -> Result<WidgetGovernance, AppError> {
    let ResolvedStart { effective, policy } = resolved;
    let Some(scope) = policy.knowledge_source_refs.as_deref() else {
        return Err(AppError::Validation(
            "the web-chat agent's policy names no knowledge scope; public web chat requires an \
             explicit knowledge_source_refs list (empty means no knowledge)"
                .into(),
        ));
    };

    let mut allowed: Vec<String> = if scope.is_empty() {
        Vec::new()
    } else {
        RETRIEVAL_ACTIONS
            .iter()
            .filter(|id| {
                effective
                    .allowed_action_ids
                    .as_deref()
                    .is_none_or(|list| list.iter().any(|a| a == *id))
            })
            .map(|id| (*id).to_owned())
            .collect()
    };
    allowed.push(BOT_HANDOFF.to_owned());

    let cap = session_token_cap.and_then(|c| i64::try_from(c).ok());
    let max_tokens_per_session = match (policy.max_tokens_per_session, cap) {
        (Some(p), Some(c)) => Some(p.min(c)),
        (p, c) => p.or(c),
    };

    Ok(WidgetGovernance {
        risk_ceiling: RiskTier::Reversible,
        allowed_action_ids: allowed,
        policy: PolicySnapshot {
            max_tokens_per_session,
            ..policy
        },
    })
}

/// Starts an anonymous visitor's session from the configured definition,
/// running as the channel's service principal (`principal`).
///
/// Errors when the widget is not enabled, names no definition, or the
/// definition cannot be resolved or has no explicit knowledge scope — the
/// caller treats every one of those as "the assistant is not available"
/// (legacy behaviour), never as permission to start something wider.
pub async fn start_session(
    state: &EngineState,
    principal: &SecurityContext,
    integration_system_id: Uuid,
) -> Result<AgentSession, AppError> {
    start_session_with(
        state,
        principal,
        &state.base.config.webchat,
        integration_system_id,
    )
    .await
}

/// [`start_session`] against an explicit `webchat` section — the boot-time
/// configuration in production, a test's own in the suites.
pub async fn start_session_with(
    state: &EngineState,
    principal: &SecurityContext,
    config: &WebchatSection,
    integration_system_id: Uuid,
) -> Result<AgentSession, AppError> {
    let definition = match (config.enabled, config.agent_definition_id) {
        (true, Some(id)) => id,
        _ => return Err(AppError::CapabilityUnavailable("webchat")),
    };
    let resolved = crate::agent::resolve_start(
        state,
        principal,
        definition,
        SessionConstraints {
            risk_ceiling: RiskTier::Reversible,
            allowed_action_ids: None,
        },
    )
    .await?;
    let governance = clamp(resolved, config.session_token_cap)?;
    let session = crate::session::start(
        &state.base.db,
        &attome_audit::audit_service(state),
        SessionStart {
            owner_user_id: principal.user_id,
            risk_ceiling: governance.risk_ceiling,
            allowed_action_ids: Some(governance.allowed_action_ids),
            surface: SURFACE,
            agent_definition_ref: Some(definition),
            integration_system_id: Some(integration_system_id),
            tainted: false,
            policy: governance.policy,
        },
    )
    .await?;
    // The session's one conversation ledger, created with it, so every later
    // message finds exactly one and no two first messages can race to
    // create two. Read back only by this session (`Access::Session`, I-20):
    // its owner is the shared principal, which authorizes nothing here.
    crate::conversation::create(
        &state.base.db,
        crate::conversation::NewConversation {
            agent_session_id: session.id,
            owner_user_id: principal.user_id,
            agent_definition_ref: Some(definition),
            surface: crate::conversation::Surface::WebChat,
            title: None,
        },
    )
    .await?;
    Ok(session)
}

/// A widget session's conversation: the one created with it, found by the
/// session alone (I-20) — never by owner, which every visitor shares.
async fn conversation_of(db: &sqlx::PgPool, session_id: Uuid) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM ai_conversation WHERE agent_session_id = $1 \
          ORDER BY started_at ASC LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// What one visitor message produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answered {
    pub reply: Reply,
    /// The model's answer; meaningful only for [`Reply::Answer`].
    pub text: String,
    /// The sources the answer drew on (C11 B6, P-6): built from the turn's
    /// executed retrieval only, never parsed from the answer text (A-56's
    /// rule), and carrying only what an anonymous visitor may see. Empty for
    /// anything but a grounded [`Reply::Answer`].
    pub citations: Vec<WidgetCitation>,
}

/// A citation as an anonymous visitor may see it (C11 B6, row A-86): the
/// article's title and the section cited — never a record, collection or
/// chunk id, and no link, because a knowledge article has no public address.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct WidgetCitation {
    pub title: String,
    /// The cited section's heading path, outermost first.
    pub heading_path: Vec<String>,
}

/// The widget's citations for a turn's executed retrieval: title and section,
/// de-duplicated, in the order retrieval cited them.
pub fn widget_citations(executed: &[(String, serde_json::Value)]) -> Vec<WidgetCitation> {
    let mut out: Vec<WidgetCitation> = Vec::new();
    for c in crate::chat_view::grounding_from(executed).citations {
        let citation = WidgetCitation {
            title: c.title,
            heading_path: c.heading_path,
        };
        if !out.contains(&citation) {
            out.push(citation);
        }
    }
    out
}

/// Runs one turn for an anonymous visitor's message and decides the reply.
///
/// The turn is the ordinary `turn::run` under the session's own snapshot, as
/// the channel's service principal: every gate, the D-502 claim, the knowledge
/// scope and the per-visitor budget apply exactly as for any session. The
/// reply comes from [`reply_for`] over the turn's terminal state and its
/// executed knowledge outcomes — no model text is parsed.
///
/// A session that is no longer live, or that has no conversation, is the
/// offline message rather than an error: the visitor is told the assistant is
/// unavailable, never handed off for an infrastructure reason.
pub async fn answer(
    state: &EngineState,
    principal: Arc<SecurityContext>,
    session_id: Uuid,
    text: &str,
) -> Result<Answered, AppError> {
    let offline = Answered {
        reply: Reply::Offline,
        text: String::new(),
        citations: Vec::new(),
    };
    let db = &state.base.db;
    let Some(governance) = crate::session::load_governance(db, session_id).await? else {
        return Ok(offline);
    };
    let Some(conversation_id) = conversation_of(db, session_id).await? else {
        tracing::error!(%session_id, "web chat session has no conversation ledger");
        return Ok(offline);
    };
    let outcome = crate::turn::run(
        state,
        &crate::engine::REGISTRY,
        &crate::engine::EXECUTORS,
        &crate::turn::TurnInputs {
            session: &governance.session,
            security: principal,
            conversation_id,
            step_budget: None,
        },
        text,
    )
    .await?;

    let executed = crate::chat_view::executed_knowledge(db, conversation_id, &[outcome.turn_id])
        .await?
        .remove(&outcome.turn_id)
        .unwrap_or_default();
    let grounding = crate::chat_view::grounding_from(&executed).grounding;
    let declined = executed.iter().any(|(action, result)| {
        action == crate::actions::knowledge_answer::KNOWLEDGE_ANSWER
            && result.get("status").and_then(|s| s.as_str()) == Some("declined")
    });
    let reply = reply_for(outcome.terminal_state, grounding, declined);
    // A completed turn with nothing to say is not an answer to send.
    if reply == Reply::Answer && outcome.text.trim().is_empty() {
        return Ok(offline);
    }
    let citations = if reply == Reply::Answer {
        widget_citations(&executed)
    } else {
        Vec::new()
    };
    Ok(Answered {
        reply,
        text: outcome.text,
        citations,
    })
}

/// How an inbound message is handled, before any turn runs. The precedence is
/// the order of the checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// `webchat.enabled` is false: the shipped behaviour, untouched — the
    /// fixed acknowledgment and the three-message handoff rule.
    Legacy,
    /// Enabled, but the assistant cannot answer: the AI kill switch has chat
    /// off, or no generation endpoint is configured. The configured offline
    /// message.
    Offline,
    /// Enabled and available: run a turn.
    Answer,
}

pub fn entry(config: &WebchatSection, ai: &AiEnablement, generation_configured: bool) -> Entry {
    if !config.enabled {
        Entry::Legacy
    } else if !ai.allows(AiSurface::Chat) || !generation_configured {
        Entry::Offline
    } else {
        Entry::Answer
    }
}

/// What a finished turn means for the visitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Send the model's answer.
    Answer,
    /// Send the configured offline message, and do **not** hand off.
    Offline,
    /// Hand the conversation to a person, for this reason.
    Handoff(HandoffReason),
}

/// Maps a turn's terminal state and grounding to the reply. Deterministic: no
/// model text is parsed.
///
/// - The chatbot could not answer → a handoff: the step limit
///   (`StepLimitReached`), a declined knowledge answer or a tool call it was
///   not allowed to make (`Refusal`), or a retrieval that found nothing
///   (`LowConfidence`).
/// - The service could not answer → the offline message, **never** a handoff:
///   an exhausted budget (a handoff there would give a visitor a way around
///   the cap: exhaust it, get a person, repeat), the kill switch, a model or
///   tool failure, a protocol error, a session no longer live. These are
///   infrastructure or policy states, not the assistant declining.
/// - `AwaitingConfirmation` / `AwaitingApproval` cannot arise (the session
///   offers no action that needs either), nor can `Cancelled` (the widget has
///   no Stop); all three are treated as the offline message rather than
///   trusted.
///
/// The step-limit and refusal mapping is `bot_handoff::handoff_reason`'s (M54 §5),
/// not restated here; this adds the two triggers that function leaves to its
/// caller — `LowConfidence` from grounding, and a disallowed tool call.
pub fn reply_for(terminal: TerminalState, grounding: Grounding, declined: bool) -> Reply {
    use crate::actions::bot_handoff::{LoopOutcome as Loop, handoff_reason};
    let handoff = |outcome| handoff_reason(outcome).map_or(Reply::Answer, Reply::Handoff);
    match terminal {
        TerminalState::Completed => match grounding {
            Grounding::NoSources if declined => handoff(Loop::Abstained),
            Grounding::NoSources => Reply::Handoff(HandoffReason::LowConfidence),
            Grounding::Sourced | Grounding::None => handoff(Loop::Answered),
        },
        TerminalState::MaxSteps => handoff(Loop::StepLimitReached),
        TerminalState::InvalidToolCall => Reply::Handoff(HandoffReason::Refusal),
        TerminalState::BudgetExceeded
        | TerminalState::KillSwitch
        | TerminalState::ModelFailure
        | TerminalState::ToolFailure
        | TerminalState::ProtocolError
        | TerminalState::SessionRevoked
        | TerminalState::PrivilegeRevoked
        | TerminalState::AwaitingConfirmation
        | TerminalState::AwaitingApproval
        | TerminalState::Cancelled => Reply::Offline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved(
        allowed: Option<Vec<&str>>,
        scope: Option<Vec<Uuid>>,
        ceiling: RiskTier,
    ) -> ResolvedStart {
        ResolvedStart {
            effective: SessionConstraints {
                risk_ceiling: ceiling,
                allowed_action_ids: allowed.map(|v| v.into_iter().map(str::to_owned).collect()),
            },
            policy: PolicySnapshot {
                knowledge_source_refs: scope,
                max_tokens_per_session: Some(50_000),
                ..PolicySnapshot::NONE
            },
        }
    }

    /// **Invariant 1.** No explicit scope refuses the start; it never becomes
    /// "every collection the service principal can read".
    #[test]
    fn a_policy_without_an_explicit_scope_is_refused() {
        let err = clamp(resolved(None, None, RiskTier::Reversible), Some(10_000)).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    /// An empty scope is no knowledge, not all knowledge: the retrieval
    /// actions go with it, and the scope stays the empty list.
    #[test]
    fn an_empty_scope_means_no_knowledge_and_no_retrieval_actions() {
        let g = clamp(
            resolved(None, Some(vec![]), RiskTier::Reversible),
            Some(10_000),
        )
        .unwrap();
        assert_eq!(g.allowed_action_ids, vec![BOT_HANDOFF.to_owned()]);
        assert_eq!(g.policy.knowledge_source_refs, Some(vec![]));
    }

    /// The allow-list is clamped to the retrieval actions plus the handoff,
    /// whatever the definition grants: `query.execute` and writes are gone,
    /// and a retrieval action the definition does not grant is not added.
    #[test]
    fn the_allow_list_is_clamped_to_retrieval_plus_handoff() {
        let scope = Some(vec![Uuid::now_v7()]);
        let wide = clamp(
            resolved(
                Some(vec![
                    "search.knowledge",
                    "query.execute",
                    "record.update",
                    "record.delete",
                ]),
                scope.clone(),
                RiskTier::Consequential,
            ),
            None,
        )
        .unwrap();
        assert_eq!(
            wide.allowed_action_ids,
            vec!["search.knowledge".to_owned(), BOT_HANDOFF.to_owned()]
        );

        let unrestricted = clamp(resolved(None, scope, RiskTier::Consequential), None).unwrap();
        assert_eq!(
            unrestricted.allowed_action_ids,
            vec![
                "search.knowledge".to_owned(),
                "knowledge.answer".to_owned(),
                BOT_HANDOFF.to_owned()
            ]
        );
    }

    /// Row A-68's shape: the ceiling is `Reversible` whatever the policy's.
    #[test]
    fn the_ceiling_is_reversible_whatever_the_policy() {
        for ceiling in [
            RiskTier::Read,
            RiskTier::Reversible,
            RiskTier::Consequential,
        ] {
            let g = clamp(resolved(None, Some(vec![]), ceiling), None).unwrap();
            assert_eq!(g.risk_ceiling, RiskTier::Reversible, "{ceiling:?}");
        }
    }

    /// The session cap only narrows the policy's token limit.
    #[test]
    fn the_session_cap_narrows_the_policy_limit() {
        let lower = clamp(resolved(None, Some(vec![]), RiskTier::Read), Some(10_000)).unwrap();
        assert_eq!(lower.policy.max_tokens_per_session, Some(10_000));
        let higher = clamp(resolved(None, Some(vec![]), RiskTier::Read), Some(90_000)).unwrap();
        assert_eq!(higher.policy.max_tokens_per_session, Some(50_000));
    }

    /// Disabled keeps the shipped behaviour whatever else is set; enabled but
    /// unable to answer is the offline message; only a fully available
    /// assistant answers.
    #[test]
    fn entry_precedence() {
        let on = WebchatSection {
            enabled: true,
            agent_definition_id: Some(Uuid::nil()),
            session_token_cap: Some(1),
            daily_token_cap: Some(1),
            deployment_daily_token_cap: Some(1),
        };
        let off = WebchatSection::default();
        let mut ai = AiEnablement::default();
        assert_eq!(
            entry(&off, &ai, true),
            Entry::Legacy,
            "disabled wins over everything"
        );
        assert_eq!(
            entry(&on, &ai, true),
            Entry::Offline,
            "the kill switch defaults chat off"
        );
        ai.enabled = true;
        ai.chat = true;
        assert_eq!(
            entry(&on, &ai, false),
            Entry::Offline,
            "no generation endpoint"
        );
        assert_eq!(entry(&on, &ai, true), Entry::Answer);
        assert_eq!(entry(&off, &ai, true), Entry::Legacy);
    }

    /// Service states are the offline message and never a handoff — above
    /// all an exhausted budget, which must not become a route around the cap.
    #[test]
    fn service_states_are_offline_never_a_handoff() {
        for state in [
            TerminalState::BudgetExceeded,
            TerminalState::KillSwitch,
            TerminalState::ModelFailure,
            TerminalState::ToolFailure,
            TerminalState::ProtocolError,
            TerminalState::SessionRevoked,
            TerminalState::PrivilegeRevoked,
            TerminalState::AwaitingConfirmation,
            TerminalState::AwaitingApproval,
        ] {
            assert_eq!(
                reply_for(state, Grounding::None, false),
                Reply::Offline,
                "{state:?}"
            );
        }
    }

    /// The four deterministic handoffs the model's behaviour can cause, and a
    /// plain answer.
    #[test]
    fn the_assistant_declining_is_a_handoff() {
        use HandoffReason::*;
        assert_eq!(
            reply_for(TerminalState::MaxSteps, Grounding::None, false),
            Reply::Handoff(StepLimitReached)
        );
        assert_eq!(
            reply_for(TerminalState::InvalidToolCall, Grounding::None, false),
            Reply::Handoff(Refusal)
        );
        assert_eq!(
            reply_for(TerminalState::Completed, Grounding::NoSources, true),
            Reply::Handoff(Refusal)
        );
        assert_eq!(
            reply_for(TerminalState::Completed, Grounding::NoSources, false),
            Reply::Handoff(LowConfidence)
        );
        assert_eq!(
            reply_for(TerminalState::Completed, Grounding::Sourced, false),
            Reply::Answer
        );
        assert_eq!(
            reply_for(TerminalState::Completed, Grounding::None, false),
            Reply::Answer
        );
    }
}

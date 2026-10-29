//! N18-T1: one bot runtime for every conversation channel.
//!
//! A bot is an agent definition (N9) answering on a channel: the web-chat
//! widget ([`crate::webchat`]), WhatsApp or SMS. Every channel gets the same
//! session ([`start_session`]: the definition's policy clamped by
//! [`crate::webchat::clamp`] — an explicit knowledge scope, retrieval plus
//! `bot.handoff`, `Reversible`, the channel's token cap), the same turn and
//! the same reply decision ([`reply`]); the channel's adapter only carries
//! the message in and the reply out, cut to what the channel carries
//! ([`fit`]).
//!
//! **Hand-off.** A person asking for a person ([`explicit_ask`], English or
//! Arabic) is handed off before any model call; otherwise the turn decides
//! (`webchat::reply_for`: the step limit, a refusal or nothing found). The
//! channel then routes the conversation to its queue (J10) with the
//! conversation so far, and the bot is silent on that thread.
//!
//! **Configuration.** The widget's bot is `webchat.agent_definition_id`; a
//! WhatsApp or SMS system's is its config's `bot` object
//! ([`BotConfig::from_system_config`]). No bot configured, no bot: the
//! channel behaves as before.

use std::sync::Arc;

use attome_config::AiSurface;
use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::actions::bot_handoff::HandoffReason;
use crate::agent::SessionConstraints;
use crate::conversation::Surface;
use crate::descriptor::RiskTier;
use crate::session::{AgentSession, SessionStart};
use crate::webchat::WidgetCitation;

/// Ten UCS-2 parts, what `attome_integration::sms::send` sends at most.
pub const SMS_MAX_CHARS: usize = 670;

/// A channel a bot answers on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    WebChat,
    WhatsApp,
    Sms,
}

impl Channel {
    /// The stored name, also the session's surface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WebChat => crate::webchat::SURFACE,
            Self::WhatsApp => "whatsapp",
            Self::Sms => "sms",
        }
    }

    /// The inverse of [`Channel::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        [Self::WebChat, Self::WhatsApp, Self::Sms]
            .into_iter()
            .find(|c| c.as_str() == s)
    }

    /// The conversation surface of the channel's conversations.
    pub fn surface(self) -> Surface {
        match self {
            Self::WebChat => Surface::WebChat,
            Self::WhatsApp => Surface::WhatsApp,
            Self::Sms => Surface::Sms,
        }
    }

    /// The longest reply the channel carries: a WhatsApp text's 4,096
    /// characters, the 670 of ten SMS parts, and a widget bubble's 4,000.
    pub fn max_reply_chars(self) -> usize {
        match self {
            Self::WebChat => 4_000,
            Self::WhatsApp => 4_096,
            Self::Sms => SMS_MAX_CHARS,
        }
    }
}

/// Which agent answers on a channel, and the most tokens one person's
/// session may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BotConfig {
    pub agent_definition_id: Uuid,
    pub session_token_cap: Option<u64>,
}

impl BotConfig {
    /// A WhatsApp or SMS system's bot: its config's
    /// `{"bot": {"agent_definition_id": "<uuid>", "session_token_cap": 20000}}`.
    /// `None` (no bot) when the object or its definition id is missing or
    /// malformed, or `"enabled": false`. Pure.
    pub fn from_system_config(config: &Value) -> Option<Self> {
        let bot = config.get("bot")?;
        if bot.get("enabled").and_then(Value::as_bool) == Some(false) {
            return None;
        }
        let agent_definition_id = bot
            .get("agent_definition_id")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())?;
        Some(Self {
            agent_definition_id,
            session_token_cap: bot.get("session_token_cap").and_then(Value::as_u64),
        })
    }
}

/// Starts one person's session with `bot` on `channel`, running as the
/// channel's service principal (`principal`), with its one conversation.
///
/// Errors when the definition cannot be resolved, is still in testing, or has
/// no explicit knowledge scope: the caller treats each as "no bot", never as
/// permission to start something wider.
pub async fn start_session(
    state: &EngineState,
    principal: &SecurityContext,
    channel: Channel,
    bot: &BotConfig,
    integration_system_id: Uuid,
) -> Result<AgentSession, AppError> {
    let definition = bot.agent_definition_id;
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
    // AH6: a definition still in testing never answers the public.
    if resolved.trial {
        return Err(AppError::Validation(format!(
            "the {} bot's agent is in testing; set it active to answer the public",
            channel.as_str()
        )));
    }
    let governance = crate::webchat::clamp(resolved, bot.session_token_cap)?;
    let session = crate::session::start(
        &state.base.db,
        &attome_audit::audit_service(state),
        SessionStart {
            owner_user_id: principal.user_id,
            risk_ceiling: governance.risk_ceiling,
            allowed_action_ids: Some(governance.allowed_action_ids),
            surface: channel.as_str(),
            agent_definition_ref: Some(definition),
            integration_system_id: Some(integration_system_id),
            tainted: false,
            policy: governance.policy,
        },
    )
    .await?;
    // The session's one conversation ledger, created with it, so every later
    // message finds exactly one. Read back only by this session
    // (`Access::Session`, I-20): its owner is the shared principal.
    crate::conversation::create(
        &state.base.db,
        crate::conversation::NewConversation {
            agent_session_id: session.id,
            owner_user_id: principal.user_id,
            agent_definition_ref: Some(definition),
            surface: channel.surface(),
            title: None,
        },
    )
    .await?;
    Ok(session)
}

/// Whether a message asks for a person, in English or Arabic: a phrase
/// match, made before any model call. Not exhaustive by design: a miss only
/// means the bot answers once more. Pure.
pub fn explicit_ask(message: &str) -> bool {
    const PHRASES: &[&str] = &[
        "human",
        "real person",
        "speak to someone",
        "speak with someone",
        "talk to someone",
        "talk to a person",
        "representative",
        "agent please",
        "customer service",
        "موظف",
        "شخص حقيقي",
        "انسان",
        "إنسان",
        "خدمة العملاء",
        "اكلم احد",
        "أكلم أحد",
        "اتكلم مع شخص",
        "أتكلم مع شخص",
    ];
    let lower = message.to_lowercase();
    PHRASES.iter().any(|p| lower.contains(p))
}

/// What the bot does with one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotReply {
    /// Send this answer (cut to the channel), with its citations.
    Say(String, Vec<WidgetCitation>),
    /// The assistant cannot answer now (switched off, no model, a fault):
    /// the channel's offline message, and no hand-off.
    Offline,
    /// Hand the conversation to a person, for this reason.
    Handoff(HandoffReason),
}

/// The reply to `text` on `channel`, from the session `session_id`, as the
/// channel's service principal. An error from the turn itself (a database
/// or queue fault, not a model outcome) is [`BotReply::Offline`], logged: it
/// is never a reason to hand off.
pub async fn reply(
    state: &EngineState,
    principal: Arc<SecurityContext>,
    channel: Channel,
    session_id: Uuid,
    text: &str,
) -> BotReply {
    if explicit_ask(text) {
        return BotReply::Handoff(HandoffReason::UserRequested);
    }
    if !available(state, channel).await {
        return BotReply::Offline;
    }
    match crate::webchat::answer(state, principal, session_id, text).await {
        Ok(answered) => match answered.reply {
            crate::webchat::Reply::Answer => {
                BotReply::Say(fit(channel, &answered.text), answered.citations)
            }
            crate::webchat::Reply::Offline => BotReply::Offline,
            crate::webchat::Reply::Handoff(reason) => BotReply::Handoff(reason),
        },
        Err(error) => {
            tracing::error!(%error, %session_id, channel = channel.as_str(), "bot turn failed; offline");
            BotReply::Offline
        }
    }
}

/// Whether the assistant may answer on `channel` now: a model is
/// configured, the chat surface is on in the configuration and the runtime
/// switch, and for the widget its own switch too.
async fn available(state: &EngineState, channel: Channel) -> bool {
    let config = &state.base.config;
    if config.inference.generation.base_url.trim().is_empty() {
        return false;
    }
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    if channel == Channel::WebChat && !attome_core::ai_runtime_switch::allows_webchat() {
        return false;
    }
    attome_core::ai_runtime_switch::effective(&config.inference.ai).allows(AiSurface::Chat)
}

/// `text` trimmed and cut to what `channel` carries, ending in `…` when cut.
/// Pure.
pub fn fit(channel: Channel, text: &str) -> String {
    let text = text.trim();
    let max = channel.max_reply_chars();
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod bot_channels {
    use super::*;
    use serde_json::json;

    #[test]
    fn bot_channels_name_their_surfaces() {
        for channel in [Channel::WebChat, Channel::WhatsApp, Channel::Sms] {
            assert_eq!(Channel::parse(channel.as_str()), Some(channel));
            assert_eq!(channel.surface().as_str(), channel.as_str());
        }
        assert_eq!(Channel::parse("email"), None);
    }

    #[test]
    fn bot_channels_read_a_systems_bot() {
        let id = Uuid::from_u128(7);
        assert_eq!(
            BotConfig::from_system_config(&json!({
                "bot": {"agent_definition_id": id.to_string(), "session_token_cap": 20000}
            })),
            Some(BotConfig {
                agent_definition_id: id,
                session_token_cap: Some(20_000),
            })
        );
        assert_eq!(BotConfig::from_system_config(&json!({})), None);
        assert_eq!(
            BotConfig::from_system_config(&json!({"bot": {"agent_definition_id": "nope"}})),
            None
        );
        assert_eq!(
            BotConfig::from_system_config(&json!({
                "bot": {"agent_definition_id": id.to_string(), "enabled": false}
            })),
            None
        );
    }

    #[test]
    fn bot_channels_cut_a_reply_to_the_channel() {
        let long = "a".repeat(5_000);
        let sms = fit(Channel::Sms, &long);
        assert_eq!(sms.chars().count(), SMS_MAX_CHARS);
        assert!(sms.ends_with('…'));
        assert_eq!(fit(Channel::WhatsApp, &long).chars().count(), 4_096);
        assert_eq!(
            fit(Channel::Sms, "  Your order ships today.  "),
            "Your order ships today."
        );
    }

    #[test]
    fn bot_channels_hand_off_when_asked_in_english_or_arabic() {
        assert!(explicit_ask("Can I talk to a real person?"));
        assert!(explicit_ask("أبي أكلم أحد من خدمة العملاء"));
        assert!(explicit_ask("ممكن موظف"));
        assert!(!explicit_ask("When does my order arrive?"));
        assert!(!explicit_ask("متى يصل طلبي؟"));
    }
}

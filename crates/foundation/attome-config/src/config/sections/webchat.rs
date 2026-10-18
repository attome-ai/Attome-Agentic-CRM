//! D-558 — the public web-chat assistant (chatbot plan C9). This crate
//! carries no `xrm-*` dependency and no engine behaviour (boundary ruling,
//! attome-config plan BCF-14); `xrm-ai` and `crates/server` read these
//! plain-data fields directly off `AppConfig.webchat`.
//!
//! `enabled` defaults `false`: C9 turns an unauthenticated route into one that
//! costs a model call per inbound message. Disabled, the widget keeps its
//! shipped behaviour (a fixed acknowledgment and the deterministic handoff
//! rules); nothing here changes it.
//!
//! Enabling it requires everything that bounds it, checked at boot by
//! `AppConfig::validate` — never a silent fallback to an unrelated default:
//! - `agent_definition_id`: the `xrm_ai_agent` whose policy supplies the
//!   assistant's knowledge scope, retrieval mode and token limit. The policy
//!   must name an **explicit** knowledge scope; that is checked when a session
//!   starts, because the definition is data, not configuration.
//! - `session_token_cap` and `daily_token_cap`: positive token limits for one
//!   anonymous visitor's session and for that visitor's day. Both are applied
//!   by the existing `budget_guard`, keyed on the visitor's own anonymous
//!   session — never on the shared service principal every visitor runs as —
//!   and both are clamped there to the platform's default budgets: a value
//!   above them is enforced as the default, never beyond it.
//! - `deployment_daily_token_cap`: a positive token limit for **every**
//!   anonymous visitor together, per day. A visitor can start a new session at
//!   will, so the per-visitor caps alone do not bound what the deployment
//!   spends; this does. One `budget_guard` key no session or visitor id is
//!   part of, clamped to the default per-caller day — the bound the whole
//!   widget had before C9.
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct WebchatSection {
    pub enabled: bool,
    pub agent_definition_id: Option<Uuid>,
    pub session_token_cap: Option<u64>,
    pub daily_token_cap: Option<u64>,
    pub deployment_daily_token_cap: Option<u64>,
}

impl WebchatSection {
    /// The boot rule (D-558 §1): enabled requires a definition and both caps,
    /// each a positive limit. Returns the offending field and why.
    pub(crate) fn check(&self) -> Result<(), (&'static str, &'static str)> {
        if !self.enabled {
            return Ok(());
        }
        if self.agent_definition_id.is_none() {
            return Err((
                "webchat.agent_definition_id",
                "public web chat is enabled but names no agent definition; its policy \
                 supplies the assistant's knowledge scope and limits",
            ));
        }
        for (field, cap) in [
            ("webchat.session_token_cap", self.session_token_cap),
            ("webchat.daily_token_cap", self.daily_token_cap),
            (
                "webchat.deployment_daily_token_cap",
                self.deployment_daily_token_cap,
            ),
        ] {
            match cap {
                None => {
                    return Err((
                        field,
                        "public web chat is enabled without this spend cap; D-558 requires \
                         every cap before an unauthenticated route may call a model",
                    ));
                }
                Some(0) => {
                    return Err((field, "a spend cap of zero would refuse every answer"));
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

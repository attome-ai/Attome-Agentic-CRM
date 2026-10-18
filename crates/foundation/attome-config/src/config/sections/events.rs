//! M62 Phase 1 — Event Bus subscriptions/webhook delivery. This crate
//! carries no `xrm-*` dependency and no engine behaviour (boundary ruling,
//! attome-config plan BCF-14); `xrm-events` reads these plain-data fields
//! directly off `AppConfig.events`.
//!
//! `webhooks_enabled` defaults `false` — mirrors `webcrawl.enabled`'s "ships
//! dark" posture: a fresh deployment pays no outbound-HMAC-key configuration
//! cost until an operator opts in. `POST /api/v1/admin/events/subscriptions`
//! with `kind = "webhook"` is rejected while this is `false`.
use crate::keyring::KeyRing;
use serde::Deserialize;

/// Hand-written: `webhook_signing_key` holds the HMAC key(s) every outbound
/// webhook is signed with. See `S2SSection`'s impl for why the section owns a
/// hand-written `Debug` rather than relying on `KeyRing`'s own (BCF-1).
impl std::fmt::Debug for EventsSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventsSection")
            .field("webhooks_enabled", &self.webhooks_enabled)
            .field("webhook_signing_key", &self.webhook_signing_key)
            .field("dispatch_batch_size", &self.dispatch_batch_size)
            .finish()
    }
}

#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct EventsSection {
    pub webhooks_enabled: bool,
    /// P-key-rotation-and-jwt (a) trust domain for signing outbound webhook
    /// deliveries, deliberately **separate** from `s2s.key_encryption_key`
    /// (D-069's "machine-auth secrets and human/other secrets are separate
    /// trust domains; a compromise or rotation of one key must never
    /// implicate the other" — S2S authenticates *inbound* machine calls,
    /// this key signs *outbound* payloads sent to a subscriber-controlled
    /// URL, so the two must be independently rotatable).
    pub webhook_signing_key: KeyRing,
    /// Bound on how many outbox events one dispatcher tick reads per active
    /// subscription (M62 plan §3 "Bounded batch").
    pub dispatch_batch_size: i64,
}

impl Default for EventsSection {
    fn default() -> Self {
        Self {
            webhooks_enabled: false,
            webhook_signing_key: KeyRing::default(),
            dispatch_batch_size: 200,
        }
    }
}

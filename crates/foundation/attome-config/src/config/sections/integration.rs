//! M59 Phase 1 — Integration & Connectors. This crate carries no `xrm-*`
//! dependency and no engine behaviour (boundary ruling, attome-config plan
//! BCF-14); `xrm-integration` reads these plain-data fields directly off
//! `AppConfig.integration`.
//!
//! `enabled` defaults `false`, same "ships dark" posture as
//! `WebcrawlSection`/`S2SSection`: outbound connector calls reach an
//! admin-configured `base_url` the same way a webhook workflow node or the
//! web crawler reaches an admin/user-supplied URL, so a deployment opts in
//! explicitly before paying any configuration cost.
//!
//! `credential_encryption_key` is its own [`KeyRing`], deliberately
//! **separate** from every other trust domain in this config (`s2s.
//! key_encryption_key`, `auth.mfa_encryption_key`, and — where it exists —
//! `events.webhook_signing_key`), per D-069's trust-domain-separation rule: a
//! compromise or rotation of one key must never implicate another. This ring
//! encrypts external-system credentials (`xrm_integration_credential.
//! secret_encrypted`) at rest; it is never used to sign or verify anything
//! else.
use crate::keyring::KeyRing;
use serde::Deserialize;

/// Hand-written: `credential_encryption_key` holds the AES master key(s)
/// protecting connector credentials at rest. See `S2SSection`'s impl for why
/// the section owns a hand-written `Debug` (BCF-1).
impl std::fmt::Debug for IntegrationSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrationSection")
            .field("enabled", &self.enabled)
            .field("credential_encryption_key", &self.credential_encryption_key)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct IntegrationSection {
    pub enabled: bool,
    pub credential_encryption_key: KeyRing,
    /// Bound on how long the REST adapter's outbound HTTP client waits for a
    /// pull/push/health call to an external system, mirroring
    /// `WebcrawlSection::request_timeout_secs`'s per-feature timeout
    /// convention rather than a shared global constant.
    pub request_timeout_secs: u64,
}

impl Default for IntegrationSection {
    fn default() -> Self {
        Self {
            enabled: false,
            credential_encryption_key: KeyRing::default(),
            request_timeout_secs: 15,
        }
    }
}

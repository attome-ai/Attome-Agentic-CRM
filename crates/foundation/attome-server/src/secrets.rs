//! Flat snapshot of every hot-read secret request-time consumers need
//! (`resolve_api_key`, JWT verification, S2S/webhook/integration key lookups)
//! — seeded once from `AppConfig` at boot via [`SecretRings::from_config`].
//!
//! The rotatable fields stay full `KeyRing`s (current + previous key, see
//! `attome_config::KeyRing`), not because of Vault — Vault support was
//! removed — but because a `KeyRing` is itself a plain config-native
//! feature: `config.auth.jwt_secret` (etc.) already accepts either a bare
//! string or a full `{keys, active_key_id}` shape directly in
//! `config.json`, letting an operator hand-roll a manual rotation (add the
//! new key, flip `active_key_id`, restart) with an overlap window, no
//! external secret store involved. What Vault used to add on top — fetching
//! a fresh value on a timer and merging it in without a restart — is what's
//! gone; every secret here now only ever changes via a config edit and a
//! restart, same as the fields that were never Vault-covered in the first
//! place (DB password, S3 keys, SMTP password).
use attome_config::{AppConfig, KeyRing};
use std::collections::HashMap;

#[derive(Clone)]
pub struct SecretRings {
    pub jwt_secret: KeyRing,
    pub mfa_encryption_key: KeyRing,
    pub s2s_key_encryption_key: KeyRing,
    pub webhook_signing_key: KeyRing,
    pub integration_credential_key: KeyRing,
    /// Its own trust domain (D-069), deliberately separate from
    /// `integration_credential_key`: encrypts an AI provider's API key
    /// (`xrm_ai_provider_credential.secret_encrypted`, migration 0478) and
    /// nothing else. Both hold "a third party's secret", but connector
    /// credentials and AI provider keys are held by different operators and
    /// rotated on different schedules.
    pub ai_provider_credential_key: KeyRing,
    pub oauth_google_client_secret: String,
    pub oidc_client_secrets: HashMap<String, String>,
    pub apikey_hash_pepper: String,
    pub apikey_hash_previous_peppers: Vec<attome_config::ApiKeyPepper>,
}

/// Hand-rolled: every field here is live secret material — the derived
/// `Debug` would print all of it raw. Counts, not values, for the collection
/// fields so this stays useful for debugging without leaking anything.
impl std::fmt::Debug for SecretRings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRings")
            .field("jwt_secret", &self.jwt_secret)
            .field("mfa_encryption_key", &self.mfa_encryption_key)
            .field("s2s_key_encryption_key", &self.s2s_key_encryption_key)
            .field("webhook_signing_key", &self.webhook_signing_key)
            .field(
                "integration_credential_key",
                &self.integration_credential_key,
            )
            .field(
                "ai_provider_credential_key",
                &self.ai_provider_credential_key,
            )
            .field("oauth_google_client_secret", &"[REDACTED]")
            .field(
                "oidc_client_secrets",
                &format!("[REDACTED; {} entries]", self.oidc_client_secrets.len()),
            )
            .field("apikey_hash_pepper", &"[REDACTED]")
            .field(
                "apikey_hash_previous_peppers",
                &self.apikey_hash_previous_peppers,
            )
            .finish()
    }
}

impl SecretRings {
    /// The only constructor — always valid immediately at boot.
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            jwt_secret: config.auth.jwt_secret.clone(),
            mfa_encryption_key: config.auth.mfa_encryption_key.clone(),
            s2s_key_encryption_key: config.s2s.key_encryption_key.clone(),
            webhook_signing_key: config.events.webhook_signing_key.clone(),
            integration_credential_key: config.integration.credential_encryption_key.clone(),
            ai_provider_credential_key: config.inference.provider_credential_key.clone(),
            oauth_google_client_secret: config.auth.oauth_google_client_secret.clone(),
            oidc_client_secrets: config
                .oidc
                .providers
                .iter()
                .map(|(key, provider)| (key.clone(), provider.client_secret.clone()))
                .collect(),
            apikey_hash_pepper: config.auth.apikey_hash_pepper.clone(),
            apikey_hash_previous_peppers: config.auth.apikey_hash_previous_peppers.clone(),
        }
    }
}

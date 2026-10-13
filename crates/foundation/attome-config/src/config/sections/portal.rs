//! D-588 — configuration for external-audience web portals. This crate
//! carries no `xrm-*` dependency (boundary ruling, attome-config plan BCF-14);
//! `xrm-portal` reads these plain-data fields off `AppConfig.portal`.
//!
//! - `oidc_providers`: the OpenID Connect providers portals may offer, keyed
//!   by a short name. A portal lists the keys it uses in its own account
//!   policy; the secrets stay here, `${VAR}`-expanded like every other secret,
//!   and never in the database.
//! - `captcha`: the server-side check on portal signup. `none` (the default)
//!   is refused at boot in the production profile only while some portal
//!   could take self-signups, which the configuration can't know, so the rule
//!   is enforced where it can be: signup fails closed when the provider is
//!   configured but unreachable, and a production node with `none` logs a
//!   `WARN` at boot — emitted by `server::boot::init`
//!   (`warn_if_public_portal_without_captcha`, BCF-17), because
//!   `attome-config` has no logger and no knowledge of which portals an
//!   installation actually exposes.
use std::collections::BTreeMap;

use serde::Deserialize;

use super::auth::OidcProviderConfig;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PortalSection {
    pub oidc_providers: BTreeMap<String, OidcProviderConfig>,
    pub captcha: CaptchaConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptchaProvider {
    #[default]
    None,
    Turnstile,
    Hcaptcha,
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct CaptchaConfig {
    pub provider: CaptchaProvider,
    /// The provider's server-side secret, `${VAR}`-expanded.
    pub secret: String,
    pub timeout_ms: u64,
}

/// Hand-written: `secret` is the CAPTCHA provider's server-side secret, and
/// the derived `Debug` would print it raw — including transitively through
/// `PortalSection`'s own `Debug`.
impl std::fmt::Debug for CaptchaConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaConfig")
            .field("provider", &self.provider)
            .field("secret", &"[REDACTED]")
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl Default for CaptchaConfig {
    fn default() -> Self {
        Self {
            provider: CaptchaProvider::None,
            secret: String::new(),
            timeout_ms: 3_000,
        }
    }
}

/// A CAPTCHA provider's server-side secret must clear the same 32-byte floor
/// `check_secret` gives every other key-material secret (BCF-16).
const MIN_CAPTCHA_SECRET_BYTES: usize = 32;
/// An OIDC `client_secret` is issued by the IdP, so its length is not the
/// operator's choice — 16 bytes is the floor, not the 32 used for
/// platform-generated key material (BCF-D7). The staff `oidc.providers`
/// section keeps its stricter `check_secret` floor.
const MIN_OIDC_CLIENT_SECRET_BYTES: usize = 16;

/// BCF-16/BCF-D7 — the shape rule every portal secret gets. Portal secrets
/// previously had only a non-empty check, so an unresolved `${VAR}`, a
/// one-character value or a shipped template placeholder all reached the
/// provider client.
fn check_portal_secret(
    field: &str,
    value: &str,
    min_bytes: usize,
    production: bool,
) -> Result<(), (String, String)> {
    if value.contains("${") {
        return Err((
            field.into(),
            "unresolved ${...} placeholder — the environment variable was not set".into(),
        ));
    }
    if value.len() < min_bytes {
        return Err((field.into(), format!("must be at least {min_bytes} bytes")));
    }
    if production && let Some(marker) = crate::config::helpers::template_secret_marker(value) {
        return Err((
            field.into(),
            format!(
                "is a value shipped in this repository's templates (matched {marker:?}) — it is publicly known, so it protects nothing; set a real secret"
            ),
        ));
    }
    Ok(())
}

impl PortalSection {
    /// Boot rule: a configured CAPTCHA provider needs its secret, provider
    /// keys are short lowercase names (they appear in portal URLs), and every
    /// provider has an issuer, a client id and a client secret.
    ///
    /// `production` selects the shipped-template denylist for the secrets
    /// (BCF-D1); the placeholder and minimum-length rules hold in every profile.
    pub(crate) fn check(&self, production: bool) -> Result<(), (String, String)> {
        if self.captcha.provider != CaptchaProvider::None {
            if self.captcha.secret.trim().is_empty() {
                return Err((
                    "portal.captcha.secret".into(),
                    "a CAPTCHA provider is configured without its secret".into(),
                ));
            }
            check_portal_secret(
                "portal.captcha.secret",
                &self.captcha.secret,
                MIN_CAPTCHA_SECRET_BYTES,
                production,
            )?;
        }
        for (key, p) in &self.oidc_providers {
            let key_ok = !key.is_empty()
                && key.len() <= 32
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            if !key_ok {
                return Err((
                    format!("portal.oidc_providers.{key}"),
                    "provider keys are 1-32 characters of [a-z0-9-]".into(),
                ));
            }
            if p.issuer.trim().is_empty()
                || p.client_id.trim().is_empty()
                || p.client_secret.trim().is_empty()
            {
                return Err((
                    format!("portal.oidc_providers.{key}"),
                    "issuer, client_id and client_secret are all required".into(),
                ));
            }
            check_portal_secret(
                &format!("portal.oidc_providers.{key}.client_secret"),
                &p.client_secret,
                MIN_OIDC_CLIENT_SECRET_BYTES,
                production,
            )?;
        }
        Ok(())
    }
}

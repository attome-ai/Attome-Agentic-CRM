//! Identity provider presets (roadmap Q2-T1): what an administrator would
//! otherwise look up for each identity provider when adding it to
//! `oidc.providers`, namely the issuer URL shape, the scopes, which claim
//! carries the email and the groups, and which claim values mean the person
//! passed multi-factor authentication at the provider.
//!
//! The four broker presets cover SAML identity providers reached through an
//! OpenID Connect broker (Entra ID, Okta, AD FS, Keycloak): Attome speaks
//! OpenID Connect to the broker, and the broker speaks SAML to the customer's
//! directory. The provider page groups them by [`PresetKind::Broker`].
//!
//! A preset only fills a form. Nothing here is trusted at sign-in: the
//! issuer, keys and claims are still verified as for any provider.

/// How a preset is grouped on the provider page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresetKind {
    /// An OpenID Connect provider used directly.
    Oidc,
    /// A SAML identity provider reached through an OpenID Connect broker.
    Broker,
}

/// The token claim whose values say multi-factor authentication was done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaClaim {
    /// `amr`: a list of the methods used.
    Amr,
    /// `acr`: the assurance level reached.
    Acr,
}

/// One identity provider preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OidcPreset {
    /// The `oidc.providers` key the preset suggests: ASCII letters, digits,
    /// `-` and `_` only, like every provider key.
    pub key: &'static str,
    pub display_name: &'static str,
    pub kind: PresetKind,
    /// The issuer URL with `{placeholders}` the administrator fills in.
    pub issuer_template: &'static str,
    pub scopes: &'static [&'static str],
    /// The claim holding the person's email address.
    pub email_claim: &'static str,
    /// The claim holding the person's groups.
    pub groups_claim: &'static str,
    /// Where the MFA evidence is, and the values that count as MFA.
    pub mfa_claim: MfaClaim,
    pub mfa_acr_values: &'static [&'static str],
    /// Whether the provider honours `prompt=login` / `max_age=0`, so a step-up
    /// in Attome reaches the person's own provider rather than a session.
    pub supports_forced_reauth: bool,
}

const SCOPES: &[&str] = &["openid", "email", "profile"];

/// Every preset, brokers included.
pub const PRESETS: &[OidcPreset] = &[
    OidcPreset {
        key: "broker_entra_saml",
        display_name: "Microsoft Entra ID",
        kind: PresetKind::Broker,
        issuer_template: "https://login.microsoftonline.com/{tenant_id}/v2.0",
        scopes: SCOPES,
        email_claim: "email",
        groups_claim: "groups",
        mfa_claim: MfaClaim::Amr,
        mfa_acr_values: &["mfa"],
        supports_forced_reauth: true,
    },
    OidcPreset {
        key: "broker_okta_saml",
        display_name: "Okta",
        kind: PresetKind::Broker,
        issuer_template: "https://{okta_domain}/oauth2/default",
        scopes: SCOPES,
        email_claim: "email",
        groups_claim: "groups",
        mfa_claim: MfaClaim::Amr,
        mfa_acr_values: &["mfa"],
        supports_forced_reauth: true,
    },
    OidcPreset {
        key: "broker_adfs",
        display_name: "Active Directory Federation Services",
        kind: PresetKind::Broker,
        issuer_template: "https://{adfs_host}/adfs",
        scopes: SCOPES,
        email_claim: "upn",
        groups_claim: "group",
        mfa_claim: MfaClaim::Amr,
        mfa_acr_values: &["http://schemas.microsoft.com/claims/multipleauthn"],
        // AD FS keeps its own session unless the relying party trust is set
        // to honour prompt=login, so a step-up may not reach the person.
        supports_forced_reauth: false,
    },
    OidcPreset {
        key: "broker_keycloak",
        display_name: "Keycloak",
        kind: PresetKind::Broker,
        issuer_template: "https://{keycloak_host}/realms/{realm}",
        scopes: SCOPES,
        email_claim: "email",
        groups_claim: "groups",
        // Keycloak reports the step-up level reached in `acr` once its
        // authentication flow is configured with levels of authentication.
        mfa_claim: MfaClaim::Acr,
        mfa_acr_values: &["2"],
        supports_forced_reauth: true,
    },
];

/// The preset named `key`.
pub fn preset(key: &str) -> Option<&'static OidcPreset> {
    PRESETS.iter().find(|p| p.key == key)
}

/// The presets of one kind, in catalogue order.
pub fn presets_of(kind: PresetKind) -> impl Iterator<Item = &'static OidcPreset> {
    PRESETS.iter().filter(move |p| p.kind == kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_presets_have_mfa_values() {
        let brokers: Vec<_> = presets_of(PresetKind::Broker).collect();
        assert_eq!(brokers.len(), 4);
        for p in brokers {
            assert!(!p.mfa_acr_values.is_empty(), "{}", p.key);
            assert!(
                p.mfa_acr_values.iter().all(|v| !v.trim().is_empty()),
                "{}",
                p.key
            );
            assert!(p.scopes.contains(&"openid"), "{}", p.key);
            assert!(p.issuer_template.starts_with("https://"), "{}", p.key);
        }
        assert!(!preset("broker_adfs").unwrap().supports_forced_reauth);
        assert!(preset("broker_entra_saml").unwrap().supports_forced_reauth);
    }

    #[test]
    fn broker_presets_keys_are_path_safe() {
        for p in PRESETS {
            assert!(
                !p.key.is_empty()
                    && p.key
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "{}",
                p.key
            );
        }
        let mut keys: Vec<_> = PRESETS.iter().map(|p| p.key).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), PRESETS.len(), "preset keys are unique");
    }
}

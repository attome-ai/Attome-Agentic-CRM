//! The authentication context a refresh-token family records about the sign-in
//! that created it (D-510 rule 2, attome-auth hardening 2.1a).
//!
//! `refresh_token.auth_time` and `amr` are written once, when `refresh::issue`
//! creates a family after a credential verification, and every rotation copies
//! them unchanged (D-504 rule 10). They are the only authoritative record of
//! when and how the session's owner last proved who they are. A session token
//! carries no authentication context; its `sid` claim only names the family, and
//! freshness and elevation are always read from that family's row.

use chrono::{DateTime, Utc};

/// One credential-verification method, as stored in `refresh_token.amr`.
/// Server-assigned values only; nothing a client sends becomes an `amr` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// A local password (`pwd`).
    Password,
    /// A TOTP code (`otp`).
    Totp,
    /// A single-use recovery code (`rcode`).
    RecoveryCode,
    /// Q5-T5: a one-time code sent by email (or SMS, WhatsApp): a weaker
    /// factor (`otp_weak`), never phishing-resistant and never counted as a
    /// strong second factor.
    WeakOtp,
    /// An external identity provider: OIDC or Google (`fed`).
    Federated,
    /// Multi-factor authentication the identity provider reported and this
    /// deployment trusts (`mfa`, roadmap Q2-T2). Only after [`Federated`].
    ///
    /// [`Federated`]: AuthMethod::Federated
    IdpMfa,
}

impl AuthMethod {
    /// The value stored in `amr`.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Password => "pwd",
            AuthMethod::Totp => "otp",
            AuthMethod::RecoveryCode => "rcode",
            AuthMethod::WeakOtp => "otp_weak",
            AuthMethod::Federated => "fed",
            AuthMethod::IdpMfa => "mfa",
        }
    }
}

/// When the credential was verified, as far as the server can prove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthTime {
    /// A local verification completed in this request. Stored as the database
    /// clock at the moment the family is created, never an application clock.
    AtIssue,
    /// A time taken from a validated assertion: an OIDC ID token's `auth_time`.
    Asserted(DateTime<Utc>),
    /// No usable time: Google before 2.6, or an OIDC token without
    /// `auth_time`. Stored as NULL, the lowest assurance. Callback time is never
    /// used instead.
    Unknown,
}

/// What a new refresh family records about the credential verification that
/// created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    auth_time: AuthTime,
    amr: Vec<AuthMethod>,
    /// Q1-T10: the OIDC provider key and its session id, for a sign-in
    /// through one.
    oidc: Option<(String, Option<String>)>,
    /// Q8-T4: the browser the sign-in came from, shown in the person's own
    /// session list.
    device: Option<SessionDevice>,
}

/// Q8-T4: what a family records about the browser and the way it signed in,
/// for the person's own session list. Never an address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionDevice {
    /// The `User-Agent` header, cut to [`SessionDevice::USER_AGENT_MAX`] characters.
    pub user_agent: Option<String>,
    /// The browser family, such as `chrome/windows`.
    pub device_label: Option<String>,
    /// How the person signed in, such as `password+totp` or `oidc:okta`.
    pub sign_in_method: Option<String>,
    /// The ISO country the sign-in came from, with `auth.geoip_database`.
    pub sign_in_country: Option<String>,
}

impl SessionDevice {
    /// The longest `User-Agent` kept.
    pub const USER_AGENT_MAX: usize = 512;
}

impl AuthContext {
    /// A password sign-in or registration.
    pub fn password() -> Self {
        Self {
            auth_time: AuthTime::AtIssue,
            amr: vec![AuthMethod::Password],
            oidc: None,
            device: None,
        }
    }

    /// A password sign-in completed with a TOTP code.
    pub fn password_and_totp() -> Self {
        Self {
            auth_time: AuthTime::AtIssue,
            amr: vec![AuthMethod::Password, AuthMethod::Totp],
            oidc: None,
            device: None,
        }
    }

    /// A password sign-in completed with a recovery code.
    /// Q5-T5: a password and a one-time code sent to the person.
    pub fn password_and_weak_otp() -> Self {
        Self {
            amr: vec![AuthMethod::Password, AuthMethod::WeakOtp],
            ..Self::password()
        }
    }

    pub fn password_and_recovery_code() -> Self {
        Self {
            auth_time: AuthTime::AtIssue,
            amr: vec![AuthMethod::Password, AuthMethod::RecoveryCode],
            oidc: None,
            device: None,
        }
    }

    /// A sign-in through an external identity provider. `asserted_auth_time` is
    /// the validated assertion's authentication time, or `None` when the
    /// provider gave no usable one.
    pub fn federated(asserted_auth_time: Option<DateTime<Utc>>) -> Self {
        Self {
            auth_time: asserted_auth_time.map_or(AuthTime::Unknown, AuthTime::Asserted),
            amr: vec![AuthMethod::Federated],
            oidc: None,
            device: None,
        }
    }

    /// Q2-T2: records that the provider reported MFA (`mfa` after `fed`),
    /// so a policy requiring MFA is met without Attome's own factor. `false`
    /// leaves the context as it is.
    pub fn with_idp_mfa(mut self, idp_mfa: bool) -> Self {
        if idp_mfa && self.amr.contains(&AuthMethod::Federated) {
            self.amr.push(AuthMethod::IdpMfa);
        }
        self
    }

    /// Q1-T10: records the OIDC provider this federated sign-in came through
    /// and its session id (`sid`, when the provider sent one), so sign-out
    /// can end the provider's session and a back-channel logout can find it.
    pub fn with_oidc_session(mut self, provider: &str, sid: Option<String>) -> Self {
        self.oidc = Some((provider.to_owned(), sid));
        self
    }

    /// Q8-T4: records the browser and sign-in method for the session list.
    pub fn with_device(mut self, device: SessionDevice) -> Self {
        self.device = Some(SessionDevice {
            user_agent: device
                .user_agent
                .map(|ua| ua.chars().take(SessionDevice::USER_AGENT_MAX).collect()),
            ..device
        });
        self
    }

    pub fn device(&self) -> Option<&SessionDevice> {
        self.device.as_ref()
    }

    pub fn oidc_provider(&self) -> Option<&str> {
        self.oidc.as_ref().map(|(provider, _)| provider.as_str())
    }

    pub fn oidc_sid(&self) -> Option<&str> {
        self.oidc.as_ref().and_then(|(_, sid)| sid.as_deref())
    }

    pub fn auth_time(&self) -> AuthTime {
        self.auth_time
    }

    /// The `amr` values to store, in verification order.
    pub fn amr(&self) -> Vec<String> {
        self.amr.iter().map(|m| m.as_str().to_owned()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_sign_ins_record_their_methods_at_issue_time() {
        assert_eq!(AuthContext::password().amr(), vec!["pwd"]);
        assert_eq!(AuthContext::password_and_totp().amr(), vec!["pwd", "otp"]);
        assert_eq!(
            AuthContext::password_and_recovery_code().amr(),
            vec!["pwd", "rcode"]
        );
        assert_eq!(AuthContext::password().auth_time(), AuthTime::AtIssue);
    }

    #[test]
    fn a_federated_sign_in_without_a_usable_time_records_no_time() {
        let context = AuthContext::federated(None);
        assert_eq!(context.amr(), vec!["fed"]);
        assert_eq!(context.auth_time(), AuthTime::Unknown);
    }

    #[test]
    fn idp_mfa_is_recorded_for_a_federated_sign_in_only() {
        let federated = AuthContext::federated(None).with_idp_mfa(true);
        assert_eq!(federated.amr(), vec!["fed", "mfa"]);
        assert_eq!(
            AuthContext::federated(None).with_idp_mfa(false).amr(),
            vec!["fed"]
        );
        assert_eq!(
            AuthContext::password().with_idp_mfa(true).amr(),
            vec!["pwd"]
        );
    }

    #[test]
    fn a_federated_sign_in_keeps_the_asserted_time() {
        let asserted = Utc::now() - chrono::Duration::minutes(3);
        assert_eq!(
            AuthContext::federated(Some(asserted)).auth_time(),
            AuthTime::Asserted(asserted)
        );
    }
}

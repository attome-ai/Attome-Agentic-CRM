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
    /// An external identity provider: OIDC or Google (`fed`).
    Federated,
}

impl AuthMethod {
    /// The value stored in `amr`.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::Password => "pwd",
            AuthMethod::Totp => "otp",
            AuthMethod::RecoveryCode => "rcode",
            AuthMethod::Federated => "fed",
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
}

impl AuthContext {
    /// A password sign-in or registration.
    pub fn password() -> Self {
        Self {
            auth_time: AuthTime::AtIssue,
            amr: vec![AuthMethod::Password],
        }
    }

    /// A password sign-in completed with a TOTP code.
    pub fn password_and_totp() -> Self {
        Self {
            auth_time: AuthTime::AtIssue,
            amr: vec![AuthMethod::Password, AuthMethod::Totp],
        }
    }

    /// A password sign-in completed with a recovery code.
    pub fn password_and_recovery_code() -> Self {
        Self {
            auth_time: AuthTime::AtIssue,
            amr: vec![AuthMethod::Password, AuthMethod::RecoveryCode],
        }
    }

    /// A sign-in through an external identity provider. `asserted_auth_time` is
    /// the validated assertion's authentication time, or `None` when the
    /// provider gave no usable one.
    pub fn federated(asserted_auth_time: Option<DateTime<Utc>>) -> Self {
        Self {
            auth_time: asserted_auth_time.map_or(AuthTime::Unknown, AuthTime::Asserted),
            amr: vec![AuthMethod::Federated],
        }
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
    fn a_federated_sign_in_keeps_the_asserted_time() {
        let asserted = Utc::now() - chrono::Duration::minutes(3);
        assert_eq!(
            AuthContext::federated(Some(asserted)).auth_time(),
            AuthTime::Asserted(asserted)
        );
    }
}

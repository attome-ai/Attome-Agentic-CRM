//! The typed send-outcome contract every email producer sees (BEM-1/BEM-2/
//! BEM-17, attome-email plan §4.2/§4.3).
//!
//! The old shape collapsed a relay outage, a mistyped SMTP password and a
//! mailbox-that-does-not-exist into one `Permanent`/one `Internal` (F2/F1), so
//! the job handler could not tell "stop retrying, this address is dead" from
//! "stop retrying, *our* password is wrong" from "this relay is down, try
//! again". Replaces the blanket `.map_err(AppError::internal)` collapse
//! `send` used to apply to every failure (P-email-hardening), and extends it
//! with the two classes that collapse could not express.
//!
//! Classification lives in exactly one place — `sender::classify` — and every
//! consumer (`crates/server/src/jobs.rs`'s `SendEmail` arm, health, tests)
//! reads these variants rather than re-parsing lettre's `Display` text.

use std::fmt;

#[derive(Debug)]
pub enum SendError {
    /// `config.email.enabled` is false.
    Disabled,
    /// The from/to address failed to parse, or the message body failed to
    /// build — caught before any network attempt.
    InvalidAddress(String),
    /// `email_suppression` already has an active row for this
    /// recipient — no SMTP attempt was made.
    Suppressed,
    /// The SMTP relay rejected the message with a 5xx (permanent) reply.
    /// `code` is the raw three-digit SMTP status; `message` the relay's own
    /// reply text.
    ///
    /// `recipient_attributable` is D-661's verdict on the reply: **true only**
    /// when the enhanced status is `5.1.x`/`5.2.1`/`5.2.2`, or the reply is a
    /// bare `550`/`551`/`553` with no enhanced status at all. That is the
    /// single input to the suppression write in `sender::send`, so a
    /// `535` (rotated password), `5.7.x` (sender not authorised), `552` or
    /// `554` can never blacklist a recipient again (F2).
    Permanent {
        code: String,
        message: String,
        recipient_attributable: bool,
    },
    /// The SMTP relay rejected the message with a 4xx (transient) reply, the
    /// relay is unreachable or refused the connection, the peer closed
    /// mid-session, or lettre's own per-connect timeout expired — every case
    /// where the message may still be delivered by a later attempt.
    Transient { message: String },
    /// No retry can fix this: a TLS handshake failure (implicit TLS against a
    /// plaintext listener, an untrusted certificate), no AUTH mechanism
    /// compatible with ours, STARTTLS required but not offered, credentials
    /// refused over a plaintext link, or a message shape the relay cannot
    /// accept. Terminal, never retried, never suppresses.
    Config { message: String },
    /// The send may or may not have been accepted — a timeout whose SMTP
    /// stage is not observable (plan §4.2, BEM-0.3: lettre's `connection()` is
    /// `pub(super)`, so `send_raw` fuses connect and DATA). Never
    /// blind-retried: a duplicate delivery is worse than a visible gap.
    Unknown { message: String },
    /// A database failure before any network I/O (the suppression lookup).
    Internal(String),
}

impl SendError {
    /// The bounded outcome vocabulary the metrics counter and the log field
    /// use (plan §5): never a recipient, never free text. Mirrors the
    /// ledger's terminal statuses one-for-one except where a class has no
    /// row of its own (`disabled`/`config`/`internal` are ledger
    /// `failed`).
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::InvalidAddress(_) | Self::Config { .. } => "config",
            Self::Suppressed => "suppressed",
            Self::Permanent {
                recipient_attributable: true,
                ..
            } => "permanent_recipient",
            Self::Permanent { .. } => "permanent_relay",
            Self::Transient { .. } => "transient",
            Self::Unknown { .. } => "unknown",
            Self::Internal(_) => "internal",
        }
    }

    /// `Display` with every address-shaped token replaced (plan §5, S7): relay
    /// replies routinely echo the recipient (`550 5.1.1 <a@b>: unknown`), and
    /// this is the text that reaches logs and `apalis.jobs.last_error`.
    pub fn redacted_message(&self) -> String {
        redact_addresses(&self.to_string())
    }
}

/// Replaces each whitespace-separated token containing `@` with
/// `<redacted>`, keeping the rest of the text (codes, reasons) readable.
pub(crate) fn redact_addresses(text: &str) -> String {
    text.split(' ')
        .map(|token| {
            if token.contains('@') {
                "<redacted>"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "email sending is disabled"),
            Self::InvalidAddress(m) => write!(f, "invalid address: {m}"),
            Self::Suppressed => write!(f, "recipient is on the suppression list"),
            Self::Permanent { code, message, .. } => {
                write!(f, "permanent SMTP rejection ({code}): {message}")
            }
            Self::Transient { message } => write!(f, "transient SMTP failure: {message}"),
            Self::Config { message } => write!(f, "SMTP configuration error: {message}"),
            Self::Unknown { message } => write!(f, "SMTP outcome unknown: {message}"),
            Self::Internal(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for SendError {}

impl From<SendError> for attome_types::AppError {
    fn from(err: SendError) -> Self {
        match err {
            SendError::Disabled => attome_types::AppError::FeatureUnavailable,
            other => attome_types::AppError::internal(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one property every producer and the job handler depend on: a
    /// permanent rejection says, in the type, whether the *recipient* is at
    /// fault. `sender::classify` fills it from the D-661 rule; this asserts
    /// the contract itself.
    #[test]
    fn a_permanent_rejection_carries_its_recipient_attributable_verdict() {
        let relay = SendError::Permanent {
            code: "535".into(),
            message: "Authentication credentials invalid".into(),
            recipient_attributable: false,
        };
        assert!(!matches!(
            &relay,
            SendError::Permanent {
                recipient_attributable: true,
                ..
            }
        ));
        assert_eq!(
            relay.to_string(),
            "permanent SMTP rejection (535): Authentication credentials invalid"
        );
    }

    #[test]
    fn a_redacted_message_carries_no_address() {
        let err = SendError::Permanent {
            code: "550".into(),
            message: "permanent error (550): 5.1.1 <jane.doe@example.com>: user unknown".into(),
            recipient_attributable: true,
        };
        let redacted = err.redacted_message();
        assert!(!redacted.contains('@'), "{redacted}");
        assert!(redacted.contains("5.1.1"), "{redacted}");
        assert_eq!(
            redact_addresses("450 4.2.0 x@y greylisted"),
            "450 4.2.0 <redacted> greylisted"
        );
    }

    #[test]
    fn the_new_classes_are_distinguishable_in_the_type_and_in_display() {
        assert_eq!(
            SendError::Config {
                message: "tls error".into()
            }
            .to_string(),
            "SMTP configuration error: tls error"
        );
        assert_eq!(
            SendError::Unknown {
                message: "no outcome within 120s".into()
            }
            .to_string(),
            "SMTP outcome unknown: no outcome within 120s"
        );
    }
}

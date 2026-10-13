use serde::{Deserialize, Serialize};

/// The recipient's domain only — never the local part, never a display name.
/// `<invalid>` for anything without an `@`, so a malformed address cannot
/// smuggle its whole value into a log line through this path.
fn debug_domain(address: &str) -> &str {
    address
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or("<invalid>")
}

/// Hand-written (BEM-13/F11): the derived `Debug` printed `text_body` and
/// `html_body` verbatim, and those carry a live, single-use password-reset /
/// verification / invitation token URL — the exact value D-166 refuses to
/// store in `email_delivery`, and the one `PlatformJob`'s
/// own derived `Debug` would put into any `{:?}` of a job payload.
///
/// Shows what an operator actually needs — the recipient's domain (deliverability
/// is per-domain), the sizes (a truncation/multipart bug shows up as a length),
/// and the two correlation ids — and nothing else.
impl std::fmt::Debug for EmailMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailMessage")
            .field("to_domain", &debug_domain(&self.to))
            .field("subject_len", &self.subject.chars().count())
            .field("text_body_len", &self.text_body.chars().count())
            .field(
                "html_body_len",
                &self.html_body.as_ref().map(|body| body.chars().count()),
            )
            .field("delivery_id", &self.delivery_id)
            .field("communication_id", &self.communication_id)
            .finish_non_exhaustive()
    }
}

/// A single email to send — pure data, so it doubles directly as an apalis
/// `PlatformJob::SendEmail` payload (`attome-jobs` depends on `attome-email` for
/// this type; both are foundation-tier crates, so this is a same-layer
/// dependency, not the base→xrm direction guidelines §1 forbids).
#[derive(Clone, Serialize, Deserialize)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub text_body: String,
    pub html_body: Option<String>,
    /// `email_delivery` row id (P-email-hardening), set by the three
    /// account-lifecycle producers (registration, reset, invitation) that
    /// write a tracking row in the same transaction as the enqueue.
    /// `#[serde(default)]` so an already-queued job from before this field
    /// existed still deserializes (as `None`) — no `JobEnvelope<EngineJob>`
    /// version bump needed. `None` for `xrm_notification::dispatch`'s own
    /// direct send path, which isn't tracked in that table (see
    /// `attome_email::delivery`'s module doc).
    #[serde(default)]
    pub delivery_id: Option<uuid::Uuid>,
    /// Overrides the deployment-wide `email.smtp_from_name`/`smtp_from_address`
    /// "From" header for this one message (M51 Phase 1) — set by
    /// `xrm_notification::dispatch` from `notification.email_from` so
    /// notification mail can appear to come from a different address than
    /// account-lifecycle mail, while still riding the same configured SMTP
    /// relay/credentials in `config.email`. `#[serde(default)]` so an
    /// already-queued job from before this field existed still deserializes
    /// (as `None`, i.e. the deployment default) — no `JobEnvelope<EngineJob>`
    /// version bump needed, same reasoning as `delivery_id` above.
    #[serde(default)]
    pub from_override: Option<String>,
    /// RFC 5322 `Message-ID` header value for this send (already formatted
    /// with angle brackets, e.g. `<uuid@domain>`), so a later reply can be
    /// threaded back to it via `in_reply_to`/`references` below. M52 Phase 1
    /// — set by `xrm_server::communication`'s outbound compose/reply path;
    /// `None` for every other producer (account-lifecycle mail, notification
    /// dispatch), which have no threading concept. `#[serde(default)]` for
    /// the same already-queued-job forward-compat reasoning `delivery_id`/
    /// `from_override` give.
    #[serde(default)]
    pub message_id: Option<String>,
    /// RFC 5322 `In-Reply-To` header — the `message_id` of the single message
    /// being replied to. `#[serde(default)]`, same reasoning as above.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// RFC 5322 `References` header — the whole thread's `message_id` chain,
    /// space-separated, oldest first. `#[serde(default)]`, same reasoning.
    #[serde(default)]
    pub references: Option<String>,
    /// Opaque pointer back to the `xrm_communication` row this send
    /// originated from (M52 Phase 1) — mirrors `dispatch_ref`'s loose-
    /// coupling convention in `delivery::record_queued_in_tx`: this crate
    /// stores and returns the id, never interprets it. `crates/server/src/
    /// jobs.rs`'s `SendEmail` arm uses it to append a status row to
    /// `xrm_communication_event` once the outcome is known, keeping
    /// `xrm_communication` itself append-only (D-465). `#[serde(default)]`,
    /// same forward-compat reasoning as the other optional fields.
    #[serde(default)]
    pub communication_id: Option<uuid::Uuid>,
}
#[cfg(test)]
mod tests {
    use super::*;

    fn token_message() -> EmailMessage {
        EmailMessage {
            to: "ada.lovelace@example.invalid".to_string(),
            subject: "Reset your password".to_string(),
            text_body:
                "Reset here: https://app.example.invalid/reset-password?token=SECRET-TOKEN-42"
                    .to_string(),
            html_body: Some(
                "<p><a href=\"https://app.example.invalid/reset-password?token=SECRET-TOKEN-42\">\
                 Reset</a></p>"
                    .to_string(),
            ),
            delivery_id: Some(uuid::Uuid::nil()),
            from_override: Some("Notifications <notifications@example.invalid>".to_string()),
            message_id: Some("<1@example.invalid>".to_string()),
            in_reply_to: Some("<0@example.invalid>".to_string()),
            references: Some("<0@example.invalid>".to_string()),
            communication_id: None,
        }
    }

    /// BEM-13 acceptance — the one property that matters: a `{:?}` of a
    /// token-bearing message must not contain the token, the link, or the
    /// local part of the recipient.
    #[test]
    fn debug_never_prints_a_token_link_or_local_part() {
        let rendered = format!("{:?}", token_message());
        assert!(
            !rendered.contains("SECRET-TOKEN-42"),
            "the single-use token must never reach a log line: {rendered}"
        );
        assert!(
            !rendered.contains("reset-password"),
            "the link must never reach a log line: {rendered}"
        );
        assert!(
            !rendered.contains("ada.lovelace"),
            "the local part is not needed to debug delivery: {rendered}"
        );
        assert!(
            rendered.contains("example.invalid"),
            "the domain is what an operator acts on: {rendered}"
        );
    }

    #[test]
    fn debug_falls_back_to_invalid_for_a_malformed_address() {
        assert_eq!(debug_domain("no-at-sign"), "<invalid>");
        assert_eq!(debug_domain("a@b@c"), "c");
        assert_eq!(debug_domain("user@example.invalid"), "example.invalid");
    }
}

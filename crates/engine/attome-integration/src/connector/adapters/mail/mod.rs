//! J2-T1: mailbox readers with incremental sync, behind the mailbox
//! connector's `pull` (`integration_system.kind = 'mailbox'`). The system's
//! config names the reader (`"mail": "imap" | "graph" | "gmail"`):
//!
//! - **IMAP** ([`imap`]): `host`, `port` (993), `username`, `folder`
//!   (`INBOX`); the password is the credential. The cursor is the folder's
//!   UIDVALIDITY and the last UID read, so each message is read once; a
//!   changed UIDVALIDITY restarts from the newest messages.
//! - **Microsoft Graph** ([`graph`]): `tenant`, `client_id`, `mailbox` (the
//!   address); the app's client secret is the credential. The cursor is
//!   Graph's delta link for the inbox.
//! - **Gmail** ([`gmail`]): `client_id`; the credential is a JSON object
//!   with `client_secret` and `refresh_token`. The cursor is the mailbox's
//!   history id.
//!
//! Every reader answers the same [`MailMessage`]s (at most
//! [`MAX_PER_PULL`] a pull) and the next cursor. Attachments are listed with
//! a provider reference, not fetched: whoever routes the message (J2-T2)
//! fetches the ones it keeps and stores them through the upload pipeline, so
//! they are scanned before anything uses them.

pub mod gmail;
pub mod graph;
pub mod imap;

use attome_types::AppError;
use serde::Serialize;
use serde_json::Value;

use crate::connector::PullResult;
use crate::system::IntegrationSystem;

/// Most messages one pull answers; the cursor continues from there.
pub const MAX_PER_PULL: usize = 100;

/// An address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MailAddress {
    pub name: Option<String>,
    pub address: String,
}

/// An attachment, listed, not fetched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MailAttachment {
    pub name: Option<String>,
    pub content_type: Option<String>,
    pub size: u64,
    /// How to fetch it from the provider (adapter-defined).
    pub reference: String,
}

/// One message as every reader answers it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MailMessage {
    /// `imap`, `graph` or `gmail`.
    pub provider: &'static str,
    /// The provider's id for the message (an IMAP UID, a Graph or Gmail id).
    pub id: String,
    /// The `Message-ID` header, without angle brackets.
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    /// The provider's conversation, when it has one (Graph, Gmail).
    pub thread_hint: Option<String>,
    pub from: Option<MailAddress>,
    pub to: Vec<MailAddress>,
    pub cc: Vec<MailAddress>,
    pub subject: Option<String>,
    /// RFC 3339.
    pub date: Option<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    /// `Auto-Submitted`, `Precedence` and `List-Id`, for loop and bulk
    /// detection.
    pub auto_submitted: Option<String>,
    pub precedence: Option<String>,
    pub list_id: Option<String>,
    pub attachments: Vec<MailAttachment>,
    /// Marked private or confidential by the sender (Graph's sensitivity,
    /// the `Sensitivity` header): D15-T2 does not capture it.
    pub private: bool,
    /// Whether the provider says it has attachments (Graph), so the list is
    /// fetched only then.
    #[serde(skip)]
    pub has_attachments: bool,
}

/// A message id without its angle brackets. Pure.
pub fn bare_id(raw: &str) -> Option<String> {
    let id = raw
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim();
    (!id.is_empty()).then(|| id.to_owned())
}

/// The ids in a `References` header, in order. Pure.
pub fn reference_ids(raw: &str) -> Vec<String> {
    raw.split_whitespace().filter_map(bare_id).collect()
}

/// The system's config as JSON.
pub fn config(system: &IntegrationSystem) -> Value {
    system
        .config
        .as_deref()
        .and_then(|c| serde_json::from_str(c).ok())
        .unwrap_or(Value::Null)
}

/// A required config value.
pub fn required<'a>(
    config: &'a Value,
    system: &IntegrationSystem,
    name: &str,
) -> Result<&'a str, AppError> {
    config
        .get(name)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AppError::Validation(format!("{}: config has no {name}", system.name)))
}

/// Reads the messages after `cursor` with the system's reader.
pub async fn pull(
    system: &IntegrationSystem,
    credential: Option<&str>,
    cursor: Option<&str>,
) -> Result<PullResult, AppError> {
    let cfg = config(system);
    let credential = credential
        .ok_or_else(|| AppError::Validation(format!("{}: no credential set", system.name)))?;
    let (messages, next) = match cfg.get("mail").and_then(Value::as_str) {
        Some("imap") => imap::pull(system, &cfg, credential, cursor).await?,
        Some("graph") => graph::pull(system, &cfg, credential, cursor).await?,
        Some("gmail") => gmail::pull(system, &cfg, credential, cursor).await?,
        _ => {
            return Err(AppError::Validation(format!(
                "{}: config.mail must be imap, graph or gmail",
                system.name
            )));
        }
    };
    Ok(PullResult {
        records: messages
            .into_iter()
            .map(|m| serde_json::to_value(m).unwrap_or(Value::Null))
            .collect(),
        next_cursor: next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_ids_lose_their_brackets() {
        assert_eq!(bare_id(" <abc@x.sa> "), Some("abc@x.sa".into()));
        assert_eq!(bare_id("<>"), None);
        assert_eq!(
            reference_ids("<a@x> <b@y>\r\n <c@z>"),
            vec!["a@x", "b@y", "c@z"]
        );
    }
}

//! G1-T2: one conversation thread per case. An inbound email joins a case
//! (`service_ticket`) by, in this order:
//!
//! 1. the case number in its subject, `[Case #<ticket_number>]` (a number a
//!    merge retired joins the surviving case through `merged_numbers`);
//! 2. its `In-Reply-To`/`References` headers naming a message already on a
//!    case (a `communication` on `service_ticket`);
//! 3. its sender's most recent open case updated within
//!    `service.email_thread_days` days (default 7; 0 turns this off).
//!
//! No match is a new case, which is the mailbox router's (J2-T2) to open.
//! Every message joins as a `communication` on the case with its own
//! `channel` and `direction`, so the case timeline shows one conversation
//! across channels; [`case_subject`] stamps outbound mail so the reply finds
//! its way back.

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

const CASE_ENTITY: &str = "service_ticket";
/// Statuses a case is no longer open in.
const CLOSED_STATUSES: [&str; 2] = ["resolved", "closed"];
/// The default for `service.email_thread_days`.
pub const DEFAULT_THREAD_DAYS: i64 = 7;

/// How an inbound message found its case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadMatch {
    /// The case number in the subject.
    SubjectToken,
    /// The reply headers.
    ReplyHeaders,
    /// The sender's recent open case.
    RecentCase,
}

impl ThreadMatch {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubjectToken => "subject_token",
            Self::ReplyHeaders => "reply_headers",
            Self::RecentCase => "recent_case",
        }
    }
}

/// What threading reads of one inbound message.
#[derive(Debug, Clone, Default)]
pub struct InboundEmail {
    pub subject: Option<String>,
    /// The sender's address.
    pub from: Option<String>,
    /// `In-Reply-To`, without angle brackets.
    pub in_reply_to: Option<String>,
    /// `References`, oldest first, without angle brackets.
    pub references: Vec<String>,
}

/// The case number in `subject`'s `[Case #…]` token, if any. Pure.
pub fn case_token(subject: &str) -> Option<String> {
    let lower = subject.to_ascii_lowercase();
    let mut from = 0;
    while let Some(at) = lower[from..].find("[case") {
        let start = from + at + "[case".len();
        let rest = &subject[start..];
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('#').unwrap_or(rest).trim_start();
        if let Some(end) = rest.find(']') {
            let number = rest[..end].trim();
            if !number.is_empty()
                && number.len() <= 64
                && number
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.'))
            {
                return Some(number.to_owned());
            }
        }
        from = start;
    }
    None
}

/// `subject` carrying the case token, unless it already does. Pure.
pub fn case_subject(ticket_number: &str, subject: &str) -> String {
    if case_token(subject).as_deref() == Some(ticket_number) {
        return subject.to_owned();
    }
    let subject = subject.trim();
    if subject.is_empty() {
        format!("[Case #{ticket_number}]")
    } else {
        format!("[Case #{ticket_number}] {subject}")
    }
}

/// The header message ids to look for, newest first, as stored on a
/// `communication` (`<id>`). Pure.
pub fn reply_ids(email: &InboundEmail) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    for id in email
        .in_reply_to
        .iter()
        .chain(email.references.iter().rev())
    {
        let id = id.trim().trim_start_matches('<').trim_end_matches('>');
        if id.is_empty() {
            continue;
        }
        let stored = format!("<{id}>");
        if !ids.contains(&stored) {
            ids.push(stored);
        }
    }
    ids
}

/// `service.email_thread_days`.
pub fn thread_days(state: &EngineState) -> i64 {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get("service.email_thread_days")
        .and_then(|d| store.resolve(d, None, None).0.as_i64())
        .unwrap_or(DEFAULT_THREAD_DAYS)
        .clamp(0, 90)
}

/// The case `email` belongs to, and how it was found; `None` is a new case.
pub async fn find_case(
    state: &EngineState,
    email: &InboundEmail,
) -> Result<Option<(Uuid, ThreadMatch)>, AppError> {
    let db = &state.base.db;

    if let Some(number) = email.subject.as_deref().and_then(case_token) {
        let case: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM service_ticket \
              WHERE is_active IS NOT FALSE \
                AND (ticket_number = $1 \
                     OR $1 = ANY (string_to_array(replace(coalesce(merged_numbers, ''), ' ', ''), ','))) \
              ORDER BY (ticket_number = $1) DESC, created_at DESC LIMIT 1",
        )
        .bind(&number)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if let Some(case) = case {
            return Ok(Some((case, ThreadMatch::SubjectToken)));
        }
    }

    let ids = reply_ids(email);
    if !ids.is_empty() {
        let case: Option<Uuid> = sqlx::query_scalar(
            "SELECT t.id FROM communication c \
               JOIN service_ticket t ON t.id::text = c.record_id \
              WHERE c.message_id = ANY($1) AND c.entity_name = $2 \
                AND c.is_active IS NOT FALSE AND t.is_active IS NOT FALSE \
              ORDER BY c.created_at DESC LIMIT 1",
        )
        .bind(&ids)
        .bind(CASE_ENTITY)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if let Some(case) = case {
            return Ok(Some((case, ThreadMatch::ReplyHeaders)));
        }
    }

    let days = thread_days(state);
    let from = email.from.as_deref().map(str::trim).unwrap_or_default();
    if days > 0 && !from.is_empty() {
        let case: Option<Uuid> = sqlx::query_scalar(
            "SELECT t.id FROM service_ticket t \
               JOIN user_account u ON u.id = t.requester_id \
              WHERE lower(u.email) = lower($1) AND u.is_active IS NOT FALSE \
                AND t.is_active IS NOT FALSE AND NOT (t.status = ANY($2)) \
                AND coalesce(t.modified_at, t.created_at) >= now() - make_interval(days => $3) \
              ORDER BY coalesce(t.modified_at, t.created_at) DESC LIMIT 1",
        )
        .bind(from)
        .bind(CLOSED_STATUSES.as_slice())
        .bind(i32::try_from(days).unwrap_or(7))
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if let Some(case) = case {
            return Ok(Some((case, ThreadMatch::RecentCase)));
        }
    }
    Ok(None)
}

/// The fields of a case opened from an inbound email: a placeholder number
/// until an Auto Value rule numbers cases, the subject as title, the text
/// as description, channel `email`, status `new`. Pure.
pub fn new_case_body(
    subject: Option<&str>,
    text: Option<&str>,
    requester: Uuid,
) -> serde_json::Value {
    let title = subject
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("(no subject)");
    let mut body = serde_json::json!({
        "ticket_number": crate::intake::placeholder_number("TKT"),
        "title": title.chars().take(200).collect::<String>(),
        "requester_id": requester.to_string(),
        "channel": "email",
        "priority": "medium",
        "status": "new",
    });
    if let Some(text) = text.map(str::trim).filter(|t| !t.is_empty()) {
        body["description"] = serde_json::json!(text.chars().take(10_000).collect::<String>());
    }
    body
}

/// J2-T2: opens a case from an inbound email through the generic create, as
/// `actor` (the mailbox's service principal). Returns the new case's id.
pub async fn open_case_from_email(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    actor: Uuid,
    subject: Option<&str>,
    text: Option<&str>,
    requester: Uuid,
) -> Result<Uuid, AppError> {
    let (id, _) = attome_records::entity_crud::create_record_with_id_for(
        state,
        ctx,
        actor,
        CASE_ENTITY,
        new_case_body(subject, text, requester),
        Uuid::now_v7(),
    )
    .await?;
    Ok(id)
}

/// The fields of the `communication` that puts one message on a case's
/// thread, for the generic create: any channel, either direction.
pub fn thread_entry(
    case: Uuid,
    channel: &str,
    direction: &str,
    subject: Option<&str>,
    body: &str,
    message_id: Option<&str>,
) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "entity_name": CASE_ENTITY,
        "record_id": case.to_string(),
        "channel": channel,
        "direction": direction,
        "body": body,
        "status": "logged",
    });
    if let Some(subject) = subject {
        entry["subject"] = serde_json::json!(subject);
    }
    if let Some(id) = message_id {
        let id = id.trim().trim_start_matches('<').trim_end_matches('>');
        if !id.is_empty() {
            entry["message_id"] = serde_json::json!(format!("<{id}>"));
        }
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_case_token_is_read_from_the_subject() {
        assert_eq!(
            case_token("RE: [Case #TCK-0042] printer jam").as_deref(),
            Some("TCK-0042")
        );
        assert_eq!(case_token("[case 17] hello").as_deref(), Some("17"));
        assert_eq!(case_token("Fwd: [CASE # 9 ]").as_deref(), Some("9"));
        assert_eq!(case_token("no token here"), None);
        assert_eq!(case_token("[Case #]"), None);
        assert_eq!(case_token("[Case #a b]"), None);
        // The first valid token wins.
        assert_eq!(
            case_token("[Case #bad token] [Case #7]").as_deref(),
            Some("7")
        );
    }

    #[test]
    fn outbound_subjects_carry_the_token_once() {
        assert_eq!(case_subject("42", "Printer"), "[Case #42] Printer");
        assert_eq!(
            case_subject("42", "RE: [Case #42] Printer"),
            "RE: [Case #42] Printer"
        );
        assert_eq!(case_subject("42", "  "), "[Case #42]");
        assert_eq!(
            case_token(&case_subject("TCK-1", "x")).as_deref(),
            Some("TCK-1")
        );
    }

    #[test]
    fn reply_ids_are_newest_first_and_bracketed_once() {
        let email = InboundEmail {
            in_reply_to: Some("c@x".into()),
            references: vec!["<a@x>".into(), "b@x".into(), "c@x".into()],
            ..InboundEmail::default()
        };
        assert_eq!(reply_ids(&email), vec!["<c@x>", "<b@x>", "<a@x>"]);
        assert!(reply_ids(&InboundEmail::default()).is_empty());
    }

    #[test]
    fn a_case_from_email_carries_subject_text_and_requester() {
        let requester = Uuid::now_v7();
        let body = new_case_body(Some("  Printer jam "), Some("It jams."), requester);
        assert_eq!(body["title"], "Printer jam");
        assert_eq!(body["description"], "It jams.");
        assert_eq!(body["requester_id"], requester.to_string());
        assert_eq!(body["channel"], "email");
        assert!(body["ticket_number"].as_str().unwrap().starts_with("TKT-"));
        let blank = new_case_body(None, Some("  "), requester);
        assert_eq!(blank["title"], "(no subject)");
        assert!(blank.get("description").is_none());
    }

    #[test]
    fn a_thread_entry_names_the_case_channel_and_direction() {
        let case = Uuid::now_v7();
        let entry = thread_entry(case, "whatsapp", "inbound", None, "hi", Some("m@x"));
        assert_eq!(entry["entity_name"], "service_ticket");
        assert_eq!(entry["record_id"], case.to_string());
        assert_eq!(entry["channel"], "whatsapp");
        assert_eq!(entry["direction"], "inbound");
        assert_eq!(entry["message_id"], "<m@x>");
        assert!(entry.get("subject").is_none());
    }
}

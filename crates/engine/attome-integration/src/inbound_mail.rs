//! J2-T2: what happens to a message read from a shared mailbox (a
//! `kind = "mailbox"` integration system). The runner that reads, threads
//! and writes is the app's `inbound_mail` job; this module holds its rules.
//!
//! A message is skipped when it has no `Message-ID` (nothing keeps it from
//! being routed twice), is automatic (`Auto-Submitted` other than `no`),
//! bulk or list mail, or comes from one of the mailbox's own addresses (our
//! own sends read back). Otherwise it joins the case it threads to (G1-T2),
//! or the mailbox's rule (`config.routing`) decides:
//!
//! - `create`: `case` (the default), `lead` or `none`;
//! - `unknown_sender`: `create` (the default) or `ignore` — whether a sender
//!   who is neither a user nor a contact still opens a record.
//!
//! A known contact's mail under a `lead` or `none` rule is logged on the
//! contact. Each sender is also limited to [`MAX_PER_SENDER_HOUR`] routed
//! messages an hour, so an autoresponder that leaves out `Auto-Submitted`
//! cannot loop with the desk.

use serde_json::Value;
use uuid::Uuid;

use crate::connector::adapters::mail::MailMessage;

/// Most messages routed from one sender in an hour.
pub const MAX_PER_SENDER_HOUR: i64 = 20;

/// What a message with no thread opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateKind {
    Case,
    Lead,
    Nothing,
}

/// A mailbox's routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxRouting {
    pub create: CreateKind,
    /// Whether an unknown sender still opens a record.
    pub unknown_sender_creates: bool,
    /// The mailbox's own addresses, lower case: mail from them is skipped.
    pub own_addresses: Vec<String>,
}

impl MailboxRouting {
    /// The rule in a mailbox system's config (`routing`, plus `address`
    /// and `username` as own addresses). Pure.
    pub fn from_config(config: &Value) -> Self {
        let routing = config.get("routing").cloned().unwrap_or(Value::Null);
        let create = match routing.get("create").and_then(Value::as_str) {
            Some("lead") => CreateKind::Lead,
            Some("none") => CreateKind::Nothing,
            _ => CreateKind::Case,
        };
        let unknown_sender_creates =
            routing.get("unknown_sender").and_then(Value::as_str) != Some("ignore");
        let mut own_addresses: Vec<String> = Vec::new();
        let listed = routing
            .get("own_addresses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str);
        let named = ["address", "username", "mailbox"]
            .into_iter()
            .filter_map(|k| config.get(k).and_then(Value::as_str));
        for address in listed.chain(named) {
            let address = address.trim().to_ascii_lowercase();
            if address.contains('@') && !own_addresses.contains(&address) {
                own_addresses.push(address);
            }
        }
        Self {
            create,
            unknown_sender_creates,
            own_addresses,
        }
    }
}

/// Why a message was not routed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    NoMessageId,
    Automatic,
    Bulk,
    OwnAddress,
    RateLimited,
    AlreadyRouted,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoMessageId => "skipped_no_message_id",
            Self::Automatic => "skipped_automatic",
            Self::Bulk => "skipped_bulk",
            Self::OwnAddress => "skipped_own_address",
            Self::RateLimited => "skipped_rate_limited",
            Self::AlreadyRouted => "skipped_already_routed",
        }
    }
}

/// The sender's address, lower case. Pure.
pub fn sender(message: &MailMessage) -> Option<String> {
    message
        .from
        .as_ref()
        .map(|f| f.address.trim().to_ascii_lowercase())
        .filter(|a| a.contains('@'))
}

/// Why `message` must not be routed, if it must not. Pure.
pub fn skip_reason(message: &MailMessage, routing: &MailboxRouting) -> Option<SkipReason> {
    if message
        .message_id
        .as_deref()
        .is_none_or(|id| id.trim().is_empty())
    {
        return Some(SkipReason::NoMessageId);
    }
    if message
        .auto_submitted
        .as_deref()
        .is_some_and(|v| !v.trim().eq_ignore_ascii_case("no"))
    {
        return Some(SkipReason::Automatic);
    }
    let bulk = message.precedence.as_deref().is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "bulk" | "list" | "junk"
        )
    });
    if bulk || message.list_id.is_some() {
        return Some(SkipReason::Bulk);
    }
    if sender(message).is_some_and(|s| routing.own_addresses.contains(&s)) {
        return Some(SkipReason::OwnAddress);
    }
    None
}

/// Who the sender is, by email.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SenderMatch {
    pub user: Option<Uuid>,
    pub contact: Option<Uuid>,
}

impl SenderMatch {
    pub fn known(&self) -> bool {
        self.user.is_some() || self.contact.is_some()
    }
}

/// Where a routable message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Onto the case it threads to.
    JoinCase(Uuid),
    /// A new case, requested by the matched user (else the mailbox's
    /// service principal).
    CreateCase { requester: Option<Uuid> },
    /// Logged on the matched contact.
    LogOnContact(Uuid),
    /// A new lead from the sender.
    CreateLead,
    /// Read, not routed.
    Ignore,
}

/// The route for a message that passed [`skip_reason`]. Pure.
pub fn decide(routing: &MailboxRouting, thread: Option<Uuid>, sender: SenderMatch) -> Route {
    if let Some(case) = thread {
        return Route::JoinCase(case);
    }
    if !sender.known() && !routing.unknown_sender_creates {
        return Route::Ignore;
    }
    match routing.create {
        CreateKind::Case => Route::CreateCase {
            requester: sender.user,
        },
        CreateKind::Lead => match sender.contact {
            Some(contact) => Route::LogOnContact(contact),
            None => Route::CreateLead,
        },
        CreateKind::Nothing => match sender.contact {
            Some(contact) => Route::LogOnContact(contact),
            None => Route::Ignore,
        },
    }
}

/// The Redis key counting one sender's routed messages this hour.
pub fn sender_rate_key(system_id: Uuid, sender: &str) -> String {
    format!("integration:inbound_rate:{system_id}:{sender}")
}

#[cfg(test)]
mod inbound_mail_routing {
    use super::*;
    use crate::connector::adapters::mail::MailAddress;
    use serde_json::json;

    fn message(from: &str) -> MailMessage {
        MailMessage {
            provider: "imap",
            id: "1".into(),
            message_id: Some("m1@example.com".into()),
            from: Some(MailAddress {
                name: Some("Sara".into()),
                address: from.into(),
            }),
            subject: Some("Printer".into()),
            ..MailMessage::default()
        }
    }

    fn support() -> MailboxRouting {
        MailboxRouting::from_config(&json!({
            "mail": "imap",
            "username": "Support@Acme.sa",
            "routing": { "own_addresses": ["noreply@acme.sa"] },
        }))
    }

    #[test]
    fn the_rule_defaults_to_opening_cases_for_anyone() {
        let rule = MailboxRouting::from_config(&Value::Null);
        assert_eq!(rule.create, CreateKind::Case);
        assert!(rule.unknown_sender_creates);
        let rule = support();
        assert_eq!(
            rule.own_addresses,
            vec!["noreply@acme.sa", "support@acme.sa"]
        );
        let lead = MailboxRouting::from_config(
            &json!({"routing": {"create": "lead", "unknown_sender": "ignore"}}),
        );
        assert_eq!(lead.create, CreateKind::Lead);
        assert!(!lead.unknown_sender_creates);
    }

    #[test]
    fn loops_bulk_and_our_own_sends_are_skipped() {
        let rule = support();
        assert_eq!(skip_reason(&message("sara@client.sa"), &rule), None);

        let mut auto = message("sara@client.sa");
        auto.auto_submitted = Some("auto-replied".into());
        assert_eq!(skip_reason(&auto, &rule), Some(SkipReason::Automatic));
        auto.auto_submitted = Some("no".into());
        assert_eq!(skip_reason(&auto, &rule), None);

        let mut bulk = message("news@shop.sa");
        bulk.precedence = Some("Bulk".into());
        assert_eq!(skip_reason(&bulk, &rule), Some(SkipReason::Bulk));
        let mut list = message("list@lists.sa");
        list.list_id = Some("<x.lists.sa>".into());
        assert_eq!(skip_reason(&list, &rule), Some(SkipReason::Bulk));

        assert_eq!(
            skip_reason(&message("SUPPORT@acme.sa"), &rule),
            Some(SkipReason::OwnAddress)
        );
        let mut no_id = message("sara@client.sa");
        no_id.message_id = None;
        assert_eq!(skip_reason(&no_id, &rule), Some(SkipReason::NoMessageId));
    }

    #[test]
    fn a_thread_wins_then_the_rule_decides() {
        let case = Uuid::now_v7();
        let contact = Uuid::now_v7();
        let user = Uuid::now_v7();
        let rule = support();
        let unknown = SenderMatch::default();
        assert_eq!(decide(&rule, Some(case), unknown), Route::JoinCase(case));
        assert_eq!(
            decide(&rule, None, unknown),
            Route::CreateCase { requester: None }
        );
        assert_eq!(
            decide(
                &rule,
                None,
                SenderMatch {
                    user: Some(user),
                    contact: None
                }
            ),
            Route::CreateCase {
                requester: Some(user)
            }
        );

        let lead = MailboxRouting::from_config(&json!({"routing": {"create": "lead"}}));
        assert_eq!(decide(&lead, None, unknown), Route::CreateLead);
        let known = SenderMatch {
            user: None,
            contact: Some(contact),
        };
        assert_eq!(decide(&lead, None, known), Route::LogOnContact(contact));

        let quiet = MailboxRouting::from_config(
            &json!({"routing": {"create": "none", "unknown_sender": "ignore"}}),
        );
        assert_eq!(decide(&quiet, None, unknown), Route::Ignore);
        assert_eq!(decide(&quiet, None, known), Route::LogOnContact(contact));
        // Even a thread joins under the quietest rule.
        assert_eq!(decide(&quiet, Some(case), unknown), Route::JoinCase(case));
    }

    #[test]
    fn senders_are_compared_in_lower_case() {
        assert_eq!(
            sender(&message(" Sara@Client.SA ")).as_deref(),
            Some("sara@client.sa")
        );
        assert_eq!(sender(&message("not-an-address")), None);
        let id = Uuid::nil();
        assert_eq!(
            sender_rate_key(id, "a@b.sa"),
            format!("integration:inbound_rate:{id}:a@b.sa")
        );
    }
}

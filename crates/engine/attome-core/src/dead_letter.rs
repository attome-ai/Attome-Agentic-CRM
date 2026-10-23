//! One shape for everything that gave up (M5-T1).
//!
//! Four places keep work that failed for good, each in its own table and
//! with its own admin route: background jobs (`apalis.jobs`, `Killed`),
//! flow triggers (`workflow_trigger_failure`), flow runs (`workflow_instance`,
//! `failed`) and webhook deliveries (`event_delivery`, `dead_letter`). Each
//! owning crate implements [`DeadLetterSource`] over its own table, so one
//! inbox (M5-T2) can list, group, replay and discard them all the same way.
//!
//! **Grouping.** Items with the same [`cause_group`] (source + step + error
//! kind) failed the same way and are usually fixed and replayed together.
//! The error kind is [`classify_error`] over the failure text: coarse on
//! purpose, so two timeouts against different hosts still land in one group.
//!
//! **Audit.** `replay` and `discard` change state, so every implementation
//! writes its audit event the way its own admin route already does; the
//! trait does not, because `attome-core` sits below `attome-audit`.
//!
//! The futures are boxed by hand, the [`crate::my_work`] convention (the
//! workspace does not use the `async_trait` crate).

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::state::EngineState;

/// The future every [`DeadLetterSource`] method returns.
pub type DeadLetterFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// The longest failure text an item carries; the source keeps the whole one.
pub const MESSAGE_LIMIT: usize = 500;

/// One thing that failed for good, in the shape every source shares.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DeadLetter {
    /// The source's [`DeadLetterSource::source`] name.
    pub source: String,
    /// The item's id within its source (an `apalis.jobs` id is not a UUID,
    /// so this is a string for every source).
    pub id: String,
    /// What failed inside the source: the job variant, the flow step, the
    /// trigger's entity and operation, the subscription. `None` when the
    /// source cannot tell.
    pub step: Option<String>,
    /// [`classify_error`] of the failure text.
    pub error_kind: String,
    /// [`cause_group`] of source, step and error kind.
    pub cause_group: String,
    /// The last failure text, cut to [`MESSAGE_LIMIT`] characters.
    pub message: Option<String>,
    /// When the work first failed.
    pub first_seen: DateTime<Utc>,
    pub attempts: i32,
    /// Where the payload lives, for a reader with access to its source
    /// (`workflow_instance:<id>`); never the payload itself, which can hold
    /// tokens or personal data.
    pub payload_ref: Option<String>,
}

impl DeadLetter {
    /// Builds an item, deriving `error_kind`, `cause_group` and the cut
    /// message from the failure text.
    pub fn new(
        source: &str,
        id: String,
        step: Option<String>,
        message: Option<&str>,
        first_seen: DateTime<Utc>,
        attempts: i32,
        payload_ref: Option<String>,
    ) -> Self {
        let error_kind = classify_error(message.unwrap_or(""));
        DeadLetter {
            source: source.to_string(),
            cause_group: cause_group(source, step.as_deref(), error_kind),
            error_kind: error_kind.to_string(),
            message: message.map(cut_message),
            id,
            step,
            first_seen,
            attempts,
            payload_ref,
        }
    }
}

/// What a replay did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    /// The work runs again.
    Replayed,
    /// No such dead letter: replayed or discarded already, or never failed.
    NotDeadLettered,
    /// The source refused, for the reason given (a live job holds the same
    /// key; the run changed since it was read).
    Refused(&'static str),
}

/// A place that keeps work that failed for good.
pub trait DeadLetterSource: Send + Sync + 'static {
    /// Stable name, e.g. `jobs`, `flow_trigger`, `flow_run`, `webhook`.
    fn source(&self) -> &'static str;

    /// Dead letters, newest first.
    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        offset: i64,
        limit: i64,
    ) -> DeadLetterFuture<'a, Vec<DeadLetter>>;

    /// How many dead letters the source holds.
    fn count<'a>(&'a self, state: &'a EngineState) -> DeadLetterFuture<'a, i64>;

    /// One dead letter, or `None` when `id` names none.
    fn get<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
    ) -> DeadLetterFuture<'a, Option<DeadLetter>>;

    /// Runs the work again as `actor` and audits it.
    fn replay<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
        actor: Uuid,
    ) -> DeadLetterFuture<'a, ReplayOutcome>;

    /// Drops the dead letter as `actor` with `reason` and audits it; `false`
    /// when `id` names none.
    fn discard<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
        actor: Uuid,
        reason: &'a str,
    ) -> DeadLetterFuture<'a, bool>;
}

/// The group key: source, step and error kind, `:`-joined; a missing step is
/// `-`.
pub fn cause_group(source: &str, step: Option<&str>, error_kind: &str) -> String {
    format!("{source}:{}:{error_kind}", step.unwrap_or("-"))
}

/// A coarse kind for a failure text, the same for every source:
/// `timeout`, `connect`, `rate_limited`, `http_4xx`, `http_5xx`,
/// `permission`, `not_found`, `conflict`, `validation`, `unavailable`, or
/// `other`. Checked in that order, so "HTTP 503 after timeout" is a timeout.
pub fn classify_error(message: &str) -> &'static str {
    let m = message.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| m.contains(n));
    if has(&["timed out", "timeout", "deadline"]) {
        "timeout"
    } else if has(&[
        "could not connect",
        "connection refused",
        "connect error",
        "dns",
    ]) {
        "connect"
    } else if has(&["429", "rate limit", "too many requests"]) {
        "rate_limited"
    } else if let Some(class) = http_status_class(&m) {
        class
    } else if has(&["forbidden", "permission", "not allowed", "unauthori"]) {
        "permission"
    } else if has(&["not found", "no such", "does not exist"]) {
        "not_found"
    } else if has(&["conflict", "version", "already"]) {
        "conflict"
    } else if has(&["invalid", "validation", "required", "must "]) {
        "validation"
    } else if has(&["unavailable", "overloaded", "circuit"]) {
        "unavailable"
    } else {
        "other"
    }
}

/// `http_4xx` / `http_5xx` for a text naming an HTTP status (`status 502`,
/// `HTTP 404`).
fn http_status_class(m: &str) -> Option<&'static str> {
    for marker in ["status ", "http ", "status=", "status: "] {
        let mut rest = m;
        while let Some(at) = rest.find(marker) {
            let after = &rest[at + marker.len()..];
            let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
            match (digits.len(), digits.chars().next()) {
                (3, Some('4')) => return Some("http_4xx"),
                (3, Some('5')) => return Some("http_5xx"),
                _ => {}
            }
            rest = after;
        }
    }
    None
}

fn cut_message(message: &str) -> String {
    match message.char_indices().nth(MESSAGE_LIMIT) {
        Some((at, _)) => format!("{}…", &message[..at]),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_letter_sources_share_one_group_key() {
        assert_eq!(
            cause_group("webhook", Some("sub-1"), "timeout"),
            "webhook:sub-1:timeout"
        );
        assert_eq!(cause_group("jobs", None, "other"), "jobs:-:other");
    }

    #[test]
    fn dead_letter_sources_classify_errors_coarsely() {
        assert_eq!(classify_error("webhook delivery timed out"), "timeout");
        assert_eq!(
            classify_error("webhook delivery could not connect"),
            "connect"
        );
        assert_eq!(classify_error("HTTP 429 Too Many Requests"), "rate_limited");
        assert_eq!(classify_error("upstream returned status 502"), "http_5xx");
        assert_eq!(classify_error("HTTP 404 from target"), "http_4xx");
        assert_eq!(classify_error("caller lacks permission"), "permission");
        assert_eq!(classify_error("record not found"), "not_found");
        assert_eq!(classify_error("row_version conflict"), "conflict");
        assert_eq!(classify_error("amount is required"), "validation");
        assert_eq!(classify_error("dependency unavailable"), "unavailable");
        assert_eq!(classify_error("boom"), "other");
        assert_eq!(classify_error(""), "other");
    }

    #[test]
    fn dead_letter_sources_build_items_with_a_cut_message() {
        let long = "x".repeat(MESSAGE_LIMIT + 20);
        let item = DeadLetter::new(
            "flow_run",
            "id-1".into(),
            Some("send_mail".into()),
            Some(&long),
            Utc::now(),
            3,
            None,
        );
        assert_eq!(item.error_kind, "other");
        assert_eq!(item.cause_group, "flow_run:send_mail:other");
        let message = item.message.expect("message kept");
        assert_eq!(
            message.chars().count(),
            MESSAGE_LIMIT + 1,
            "cut plus the ellipsis"
        );

        let none = DeadLetter::new("jobs", "id-2".into(), None, None, Utc::now(), 1, None);
        assert_eq!(none.message, None);
        assert_eq!(none.cause_group, "jobs:-:other");
    }
}

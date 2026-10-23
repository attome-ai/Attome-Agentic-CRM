//! M15-T1: one way to tell a person something — `notify(recipient, kind,
//! data, priority)`.
//!
//! `kind` is a notification template key; the template renders each channel
//! (subject, HTML, text, with `data` as its variables) and names the
//! channels it goes to. On top of the dispatch engine
//! (`dispatch::create_dispatch_in_tx`), which already removes the channels
//! the person muted for the kind and records every channel's outcome, this
//! adds the parts that depend on the person and the urgency:
//!
//! - **Quiet hours.** During the person's `notification.quiet_hours` (their
//!   own time zone, `core.time_zone`), a `low` or `normal` notification
//!   leaves out the interrupting channels (push and SMS); in-app and email
//!   still get it. `high` and `urgent` go through. A mandatory template
//!   ignores quiet hours as it ignores mutes.
//! - **Fallback.** A `high` or `urgent` notification that goes by push but
//!   not by email falls back to email when it is still unread after
//!   [`PUSH_FALLBACK_MINUTES`] (the dispatch engine's escalation).
//!
//! Digest delivery (collecting low-priority notifications into one message)
//! is not part of this; a person who wants fewer messages mutes the kind.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::NaiveTime;
use uuid::Uuid;

use crate::dispatch::{DispatchRequest, create_dispatch_in_tx};

/// Minutes an unread high-priority push waits before email follows.
pub const PUSH_FALLBACK_MINUTES: i32 = 5;

/// The channels quiet hours hold back for low and normal priority.
const INTERRUPTING: &[&str] = &["push", "sms"];

/// How urgent a notification is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    Normal,
    High,
    Urgent,
}

impl Priority {
    pub fn as_str(self) -> &'static str {
        match self {
            Priority::Low => "low",
            Priority::Normal => "normal",
            Priority::High => "high",
            Priority::Urgent => "urgent",
        }
    }
}

/// One notification to one person.
#[derive(Debug, Clone)]
pub struct Notify {
    pub recipient: Uuid,
    /// The template key.
    pub kind: String,
    /// The template's variables.
    pub data: HashMap<String, String>,
    pub priority: Priority,
    /// Where the in-app notification links to.
    pub route: Option<String>,
}

/// The channels a notification goes to, and its fallback: `(after minutes,
/// channels)`, or `None` to keep the template's own escalation.
pub fn plan_channels(
    channels: Vec<String>,
    priority: Priority,
    quiet: bool,
) -> (Vec<String>, Option<(i32, Vec<String>)>) {
    let mut channels: Vec<String> = if quiet && priority < Priority::High {
        channels
            .into_iter()
            .filter(|c| !INTERRUPTING.contains(&c.as_str()))
            .collect()
    } else {
        channels
    };
    if channels.is_empty() {
        channels.push("in_app".to_owned());
    }
    let fallback = (priority >= Priority::High
        && channels.iter().any(|c| c == "push")
        && !channels.iter().any(|c| c == "email"))
    .then(|| (PUSH_FALLBACK_MINUTES, vec!["email".to_owned()]));
    (channels, fallback)
}

/// Whether `now` falls in quiet hours from `start` to `end` (a range that
/// passes midnight, 22:00 to 07:00, wraps; equal bounds are no quiet hours).
pub fn in_quiet_hours(now: NaiveTime, start: NaiveTime, end: NaiveTime) -> bool {
    if start == end {
        false
    } else if start < end {
        now >= start && now < end
    } else {
        now >= start || now < end
    }
}

/// The person's quiet hours as `(start, end)`, from
/// `notification.quiet_hours` (`{"start": "22:00", "end": "07:00"}`).
fn quiet_hours_of(value: &serde_json::Value) -> Option<(NaiveTime, NaiveTime)> {
    let at = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|s| NaiveTime::parse_from_str(s, "%H:%M").ok())
    };
    Some((at("start")?, at("end")?))
}

/// Whether it is quiet hours for `user` right now.
fn quiet_now(state: &EngineState, user: Uuid) -> bool {
    let registry = attome_core::setting_registry();
    let snapshot = state.settings.load();
    let Some(hours) = registry
        .get("notification.quiet_hours")
        .map(|d| snapshot.resolve(d, Some(user), None).0)
        .as_ref()
        .and_then(quiet_hours_of)
    else {
        return false;
    };
    let zone = registry.get("core.time_zone").and_then(|d| {
        snapshot
            .resolve(d, Some(user), None)
            .0
            .as_str()
            .map(str::to_owned)
    });
    let local = attome_core::calendar::deployment_now(zone.as_deref()).time();
    in_quiet_hours(local, hours.0, hours.1)
}

/// Sends one notification; answers its dispatch id.
pub async fn notify(state: &EngineState, n: Notify) -> Result<Uuid, AppError> {
    let locale: String = state.user_locale(n.recipient).chars().take(2).collect();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (channels, mandatory) = crate::dispatch::template_channels(&mut tx, &n.kind, &locale)
        .await?
        .ok_or_else(|| AppError::Validation(format!("unknown notification kind: {}", n.kind)))?;
    let quiet = !mandatory && quiet_now(state, n.recipient);
    let (channels, fallback) = plan_channels(channels, n.priority, quiet);
    let (escalate_after_minutes, escalate_channels) = match fallback {
        Some((minutes, channels)) => (Some(minutes), Some(channels)),
        None => (None, None),
    };
    let request = DispatchRequest {
        template_key: Some(n.kind),
        locale,
        recipient_user_ref: Some(n.recipient),
        is_global: false,
        organization_ref: None,
        channels: Some(channels),
        subject: None,
        body_html: None,
        body_text: None,
        route: n.route,
        variables: n.data,
        priority: n.priority.as_str().to_owned(),
        escalate_after_minutes,
        escalate_channels,
    };
    let id = create_dispatch_in_tx(&mut tx, &state.base.config.notification, request, None).await?;
    attome_db::tx::commit(tx).await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(raw: &str) -> NaiveTime {
        NaiveTime::parse_from_str(raw, "%H:%M").unwrap_or_default()
    }

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn notify_quiet_hours_wrap_past_midnight() {
        assert!(in_quiet_hours(t("23:30"), t("22:00"), t("07:00")));
        assert!(in_quiet_hours(t("06:59"), t("22:00"), t("07:00")));
        assert!(!in_quiet_hours(t("07:00"), t("22:00"), t("07:00")));
        assert!(in_quiet_hours(t("13:00"), t("12:00"), t("14:00")));
        assert!(!in_quiet_hours(t("13:00"), t("09:00"), t("09:00")));
        let hours = serde_json::json!({ "start": "22:00", "end": "07:00" });
        assert_eq!(quiet_hours_of(&hours), Some((t("22:00"), t("07:00"))));
        assert_eq!(quiet_hours_of(&serde_json::json!({})), None);
    }

    #[test]
    fn notify_quiet_hours_hold_back_push_for_normal_priority_only() {
        let all = list(&["in_app", "push", "email"]);
        let (normal, _) = plan_channels(all.clone(), Priority::Normal, true);
        assert_eq!(normal, list(&["in_app", "email"]));
        let (high, _) = plan_channels(all.clone(), Priority::High, true);
        assert_eq!(high, all);
        let (only_push, _) = plan_channels(list(&["push"]), Priority::Low, true);
        assert_eq!(only_push, list(&["in_app"]), "never nothing");
    }

    #[test]
    fn notify_high_priority_push_falls_back_to_email() {
        let (_, fallback) = plan_channels(list(&["in_app", "push"]), Priority::High, false);
        assert_eq!(fallback, Some((PUSH_FALLBACK_MINUTES, list(&["email"]))));
        let (_, with_email) = plan_channels(list(&["push", "email"]), Priority::Urgent, false);
        assert_eq!(with_email, None, "email already goes");
        let (_, normal) = plan_channels(list(&["push"]), Priority::Normal, false);
        assert_eq!(normal, None);
    }
}

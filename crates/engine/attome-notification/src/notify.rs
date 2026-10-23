//! M15-T1/T2: one way to tell a person something — `notify(recipient, kind,
//! data, priority)`.
//!
//! `kind` is a notification template key; the template renders each channel
//! (subject, HTML, text, with `data` as its variables) and names the
//! channels it goes to. On top of the dispatch engine
//! (`dispatch::create_dispatch_in_tx`), which already removes the channels
//! the person muted for the kind and records every channel's outcome, this
//! adds the parts that depend on the person and the urgency:
//!
//! - **Digest (M15-T2).** A `low` notification for a person whose
//!   `notification.digest` is `hourly` or `daily` is held in
//!   `notification_queue_item` (migration 0207) and goes out with the
//!   others of its digest in one in-app and email message, at the next top
//!   of the hour or the next 08:00 in the person's time zone.
//! - **Quiet hours (M15-T2).** A `low` or `normal` notification sent during
//!   the person's `notification.quiet_hours` (their own `core.time_zone`) is
//!   held until the quiet hours end, then sent as usual. `high` and
//!   `urgent` go at once.
//! - **Fallback.** A `high` or `urgent` notification that goes by push but
//!   not by email falls back to email when it is still unread after
//!   [`PUSH_FALLBACK_MINUTES`] (the dispatch engine's escalation).
//!
//! A mandatory template is never held: it ignores digests and quiet hours as
//! it ignores mutes. [`sweep`] (every five minutes) sends what is due.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, NaiveDateTime, NaiveTime, Timelike, Utc};
use uuid::Uuid;

use crate::dispatch::{DispatchRequest, create_dispatch_in_tx};

/// Minutes an unread high-priority push waits before email follows.
pub const PUSH_FALLBACK_MINUTES: i32 = 5;

/// The local time a daily digest goes out.
pub const DAILY_DIGEST_AT: (u32, u32) = (8, 0);

/// Held items one sweep sends at most.
const SWEEP_LIMIT: i64 = 200;

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

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Priority::Low),
            "normal" => Some(Priority::Normal),
            "high" => Some(Priority::High),
            "urgent" => Some(Priority::Urgent),
            _ => None,
        }
    }
}

/// How a person takes their low-priority notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    Off,
    Hourly,
    Daily,
}

impl Digest {
    fn parse(value: &str) -> Self {
        match value {
            "hourly" => Digest::Hourly,
            "daily" => Digest::Daily,
            _ => Digest::Off,
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

/// What [`notify`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    /// Sent now, as this dispatch.
    Dispatched(Uuid),
    /// Held for a digest or until quiet hours end, as this queue item.
    Held(Uuid),
}

/// The channels a notification goes to, and its fallback: `(after minutes,
/// channels)`, or `None` to keep the template's own escalation. `quiet`
/// leaves out push and SMS for low and normal priority (a held item sent
/// when quiet hours have started again still never buzzes at night).
pub fn plan_channels(
    channels: Vec<String>,
    priority: Priority,
    quiet: bool,
) -> (Vec<String>, Option<(i32, Vec<String>)>) {
    let mut channels: Vec<String> = if quiet && priority < Priority::High {
        channels
            .into_iter()
            .filter(|c| c != "push" && c != "sms")
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

/// The first `at` (a local time of day) after `now`.
pub fn next_time_of_day(now: NaiveDateTime, at: NaiveTime) -> NaiveDateTime {
    let today = now.date().and_time(at);
    if today > now {
        today
    } else {
        today + Duration::days(1)
    }
}

/// When a digest that collects an item at `now` goes out.
pub fn next_digest_slot(now: NaiveDateTime, digest: Digest) -> Option<NaiveDateTime> {
    match digest {
        Digest::Off => None,
        Digest::Hourly => now
            .date()
            .and_hms_opt(now.hour(), 0, 0)
            .map(|hour| hour + Duration::hours(1)),
        Digest::Daily => NaiveTime::from_hms_opt(DAILY_DIGEST_AT.0, DAILY_DIGEST_AT.1, 0)
            .map(|at| next_time_of_day(now, at)),
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

/// What the person's settings say about holding a notification now.
struct PersonalTiming {
    /// The person's local wall clock now.
    now: DateTime<chrono::FixedOffset>,
    quiet_hours: Option<(NaiveTime, NaiveTime)>,
    digest: Digest,
}

fn personal_timing(state: &EngineState, user: Uuid) -> PersonalTiming {
    let registry = attome_core::setting_registry();
    let snapshot = state.settings.load();
    let value = |key: &str| {
        registry
            .get(key)
            .map(|d| snapshot.resolve(d, Some(user), None).0)
    };
    let zone = value("core.time_zone").and_then(|v| v.as_str().map(str::to_owned));
    PersonalTiming {
        now: attome_core::calendar::deployment_now(zone.as_deref()),
        quiet_hours: value("notification.quiet_hours")
            .as_ref()
            .and_then(quiet_hours_of),
        digest: value("notification.digest")
            .and_then(|v| v.as_str().map(Digest::parse))
            .unwrap_or(Digest::Off),
    }
}

/// When to hold a notification until, and why; `None` to send it now.
fn hold_until(
    timing: &PersonalTiming,
    priority: Priority,
) -> Option<(&'static str, DateTime<Utc>)> {
    let local = timing.now.naive_local();
    let to_utc = |at: NaiveDateTime| {
        at.and_local_timezone(*timing.now.offset())
            .single()
            .map(|at| at.with_timezone(&Utc))
    };
    if priority == Priority::Low
        && let Some(slot) = next_digest_slot(local, timing.digest)
    {
        return to_utc(slot).map(|at| ("digest", at));
    }
    if priority < Priority::High
        && let Some((start, end)) = timing.quiet_hours
        && in_quiet_hours(local.time(), start, end)
    {
        return to_utc(next_time_of_day(local, end)).map(|at| ("quiet", at));
    }
    None
}

/// Sends one notification, or holds it for a digest or until quiet hours
/// end.
pub async fn notify(state: &EngineState, n: Notify) -> Result<Sent, AppError> {
    let locale = locale_of(state, n.recipient);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (channels, mandatory) = crate::dispatch::template_channels(&mut tx, &n.kind, &locale)
        .await?
        .ok_or_else(|| AppError::Validation(format!("unknown notification kind: {}", n.kind)))?;
    let held = if mandatory {
        None
    } else {
        hold_until(&personal_timing(state, n.recipient), n.priority)
    };
    if let Some((reason, deliver_after)) = held {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO notification_queue_item \
                 (user_ref, kind, data, priority, route, reason, deliver_after) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(n.recipient)
        .bind(&n.kind)
        .bind(serde_json::to_value(&n.data).map_err(AppError::internal)?)
        .bind(n.priority.as_str())
        .bind(&n.route)
        .bind(reason)
        .bind(deliver_after)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        return Ok(Sent::Held(id));
    }
    let id = dispatch_in_tx(&mut tx, state, &n, &locale, channels).await?;
    attome_db::tx::commit(tx).await?;
    Ok(Sent::Dispatched(id))
}

fn locale_of(state: &EngineState, user: Uuid) -> String {
    state.user_locale(user).chars().take(2).collect()
}

async fn dispatch_in_tx(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    n: &Notify,
    locale: &str,
    channels: Vec<String>,
) -> Result<Uuid, AppError> {
    let (channels, fallback) = plan_channels(channels, n.priority, false);
    let (escalate_after_minutes, escalate_channels) = match fallback {
        Some((minutes, channels)) => (Some(minutes), Some(channels)),
        None => (None, None),
    };
    let request = DispatchRequest {
        template_key: Some(n.kind.clone()),
        locale: locale.to_owned(),
        recipient_user_ref: Some(n.recipient),
        is_global: false,
        organization_ref: None,
        channels: Some(channels),
        subject: None,
        body_html: None,
        body_text: None,
        route: n.route.clone(),
        variables: n.data.clone(),
        priority: n.priority.as_str().to_owned(),
        escalate_after_minutes,
        escalate_channels,
    };
    create_dispatch_in_tx(tx, &state.base.config.notification, request, None).await
}

#[derive(sqlx::FromRow)]
struct HeldRow {
    id: Uuid,
    user_ref: Uuid,
    kind: String,
    data: serde_json::Value,
    priority: String,
    route: Option<String>,
}

impl HeldRow {
    fn notification(&self) -> Notify {
        Notify {
            recipient: self.user_ref,
            kind: self.kind.clone(),
            data: serde_json::from_value(self.data.clone()).unwrap_or_default(),
            priority: Priority::parse(&self.priority).unwrap_or(Priority::Normal),
            route: self.route.clone(),
        }
    }
}

/// What one sweep sent.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepCounts {
    pub quiet_sent: u64,
    pub digests_sent: u64,
}

/// M15-T2: sends every held item that is due: a quiet-hours item on its own
/// (push and SMS left out if quiet hours started again), a person's due
/// digest items as one in-app and email message. Each send claims its rows
/// (`FOR UPDATE SKIP LOCKED`) in the transaction that writes the dispatch,
/// so two sweeps send nothing twice.
pub async fn sweep(state: &EngineState) -> Result<SweepCounts, AppError> {
    let mut counts = SweepCounts::default();
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM notification_queue_item \
          WHERE sent_at IS NULL AND reason = 'quiet' AND deliver_after <= now() \
          ORDER BY deliver_after LIMIT $1",
    )
    .bind(SWEEP_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for id in due {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let row: Option<HeldRow> = sqlx::query_as(
            "SELECT id, user_ref, kind, data, priority, route FROM notification_queue_item \
              WHERE id = $1 AND sent_at IS NULL FOR UPDATE SKIP LOCKED",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let Some(row) = row else { continue };
        let n = row.notification();
        let locale = locale_of(state, n.recipient);
        let Some((channels, _)) =
            crate::dispatch::template_channels(&mut tx, &n.kind, &locale).await?
        else {
            // The template went away while the item waited: drop it.
            mark_sent(&mut tx, &[row.id], None).await?;
            attome_db::tx::commit(tx).await?;
            continue;
        };
        let timing = personal_timing(state, n.recipient);
        let quiet_again = timing
            .quiet_hours
            .is_some_and(|(s, e)| in_quiet_hours(timing.now.naive_local().time(), s, e));
        let (channels, _) = plan_channels(channels, n.priority, quiet_again);
        let dispatch = dispatch_in_tx(&mut tx, state, &n, &locale, channels).await?;
        mark_sent(&mut tx, &[row.id], Some(dispatch)).await?;
        attome_db::tx::commit(tx).await?;
        counts.quiet_sent += 1;
    }

    let users: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_ref FROM notification_queue_item \
          WHERE sent_at IS NULL AND reason = 'digest' AND deliver_after <= now() LIMIT $1",
    )
    .bind(SWEEP_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for user in users {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let rows: Vec<HeldRow> = sqlx::query_as(
            "SELECT id, user_ref, kind, data, priority, route FROM notification_queue_item \
              WHERE user_ref = $1 AND sent_at IS NULL AND reason = 'digest' \
                AND deliver_after <= now() \
              ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED",
        )
        .bind(user)
        .bind(SWEEP_LIMIT)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if rows.is_empty() {
            continue;
        }
        let locale = locale_of(state, user);
        let mut lines = Vec::with_capacity(rows.len());
        for row in &rows {
            let n = row.notification();
            let line = crate::dispatch::render_summary(&mut tx, &n.kind, &locale, &n.data)
                .await?
                .unwrap_or(n.kind);
            lines.push(line);
        }
        let request = digest_request(user, &locale, &lines);
        let dispatch =
            create_dispatch_in_tx(&mut tx, &state.base.config.notification, request, None).await?;
        let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
        mark_sent(&mut tx, &ids, Some(dispatch)).await?;
        attome_db::tx::commit(tx).await?;
        counts.digests_sent += 1;
    }
    Ok(counts)
}

async fn mark_sent(
    tx: &mut attome_db::Tx<'_>,
    ids: &[Uuid],
    dispatch: Option<Uuid>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE notification_queue_item SET sent_at = now(), dispatch_ref = $2 WHERE id = ANY($1)",
    )
    .bind(ids)
    .bind(dispatch)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// One digest message: a count in the subject and a line per item.
pub(crate) fn digest_request(user: Uuid, locale: &str, lines: &[String]) -> DispatchRequest {
    let subject = if locale == "ar" {
        format!("لديك {} إشعارات", lines.len())
    } else if lines.len() == 1 {
        "You have 1 notification".to_owned()
    } else {
        format!("You have {} notifications", lines.len())
    };
    let body = lines
        .iter()
        .map(|l| format!("• {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    DispatchRequest {
        template_key: None,
        locale: locale.to_owned(),
        recipient_user_ref: Some(user),
        is_global: false,
        organization_ref: None,
        channels: Some(vec!["in_app".to_owned(), "email".to_owned()]),
        subject: Some(subject),
        body_html: None,
        body_text: Some(body),
        route: None,
        variables: HashMap::new(),
        priority: Priority::Low.as_str().to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(raw: &str) -> NaiveTime {
        NaiveTime::parse_from_str(raw, "%H:%M").unwrap()
    }

    fn at(raw: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M").unwrap()
    }

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A person at `local` wall-clock time in UTC+3.
    fn timing(local: &str, quiet: Option<(&str, &str)>, digest: Digest) -> PersonalTiming {
        let offset = chrono::FixedOffset::east_opt(3 * 3600).unwrap();
        PersonalTiming {
            now: at(local).and_local_timezone(offset).single().unwrap(),
            quiet_hours: quiet.map(|(s, e)| (t(s), t(e))),
            digest,
        }
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
    fn notify_quiet_hours_hold_non_urgent_until_they_end() {
        let night = timing("2026-10-23 23:30", Some(("22:00", "07:00")), Digest::Off);
        let (reason, until) = hold_until(&night, Priority::Normal).expect("held");
        assert_eq!(reason, "quiet");
        // 07:00 the next morning in UTC+3 is 04:00 UTC.
        assert_eq!(until.naive_utc(), at("2026-10-24 04:00"));
        assert_eq!(
            hold_until(&night, Priority::High),
            None,
            "high goes at once"
        );
        let day = timing("2026-10-23 12:00", Some(("22:00", "07:00")), Digest::Off);
        assert_eq!(hold_until(&day, Priority::Normal), None);
    }

    #[test]
    fn notify_digest_collects_low_priority_into_the_next_slot() {
        assert_eq!(
            next_digest_slot(at("2026-10-23 09:20"), Digest::Hourly),
            Some(at("2026-10-23 10:00"))
        );
        assert_eq!(
            next_digest_slot(at("2026-10-23 09:20"), Digest::Daily),
            Some(at("2026-10-24 08:00"))
        );
        assert_eq!(
            next_digest_slot(at("2026-10-23 07:00"), Digest::Daily),
            Some(at("2026-10-23 08:00"))
        );
        assert_eq!(next_digest_slot(at("2026-10-23 07:00"), Digest::Off), None);
        let daily = timing("2026-10-23 09:20", None, Digest::Daily);
        assert_eq!(
            hold_until(&daily, Priority::Low).map(|h| h.0),
            Some("digest")
        );
        assert_eq!(
            hold_until(&daily, Priority::Normal),
            None,
            "only low waits for a digest"
        );
    }

    #[test]
    fn notify_high_priority_push_falls_back_to_email() {
        let (_, fallback) = plan_channels(list(&["in_app", "push"]), Priority::High, false);
        assert_eq!(fallback, Some((PUSH_FALLBACK_MINUTES, list(&["email"]))));
        let (_, with_email) = plan_channels(list(&["push", "email"]), Priority::Urgent, false);
        assert_eq!(with_email, None, "email already goes");
        let (quiet, _) = plan_channels(list(&["push"]), Priority::Low, true);
        assert_eq!(quiet, list(&["in_app"]), "never nothing");
    }

    #[test]
    fn notify_digest_message_counts_its_items() {
        let user = Uuid::now_v7();
        let one = digest_request(user, "en", &list(&["Task due"]));
        assert_eq!(one.subject.as_deref(), Some("You have 1 notification"));
        let two = digest_request(user, "ar", &list(&["a", "b"]));
        assert_eq!(two.subject.as_deref(), Some("لديك 2 إشعارات"));
        assert_eq!(two.body_text.as_deref(), Some("• a\n• b"));
    }
}

//! D15-T3: two-way sync between a person's meetings in Attome and their own
//! Microsoft 365 or Google calendar, over their D15-T1 connection.
//!
//! **What syncs.** Open `meeting` activities the person owns that start
//! within a day before or 90 days after now. Each synced activity has one
//! `calendar_event_link` row per connected calendar: the provider's event
//! id, the activity's `row_version` and the event's last-modified time as of
//! the last sync.
//!
//! **Each run** (the `calendar_sync` job, every five minutes, per
//! connection):
//! - an activity with no link becomes a new event;
//! - a linked activity whose `row_version` moved is a change in Attome;
//! - a linked event whose last-modified time moved is a change in the
//!   calendar.
//!
//! One side changed: the change is copied to the other. Both changed: the
//! later writer wins (Attome on a tie), and the losing side's values are kept
//! in `calendar_sync_conflict`, so nothing is lost silently. An event deleted
//! or cancelled in the calendar cancels the open activity; an activity
//! cancelled, completed or deleted in Attome deletes a future event.
//!
//! Changes made in Attome go through the generic mutation path as the
//! person (`update_record_for`), so privileges, the state model, audit and
//! the record timeline apply exactly as for an edit in the app.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use chrono::{DateTime, Duration as ChronoDuration, NaiveDateTime, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use super::user_mail_sync::{Provider, access_token};
use super::video::{answer, client};

/// A meeting's length when the activity gives none.
const DEFAULT_MINUTES: i64 = 30;
/// Most activities one connection syncs per run.
const BATCH: i64 = 200;

const GRAPH_EVENTS: &str = "https://graph.microsoft.com/v1.0/me/events";
const GOOGLE_EVENTS: &str = "https://www.googleapis.com/calendar/v3/calendars/primary/events";

/// The meeting as Attome holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalMeeting {
    pub subject: String,
    pub description: Option<String>,
    pub start: DateTime<Utc>,
    pub minutes: i64,
}

impl LocalMeeting {
    pub fn end(&self) -> DateTime<Utc> {
        self.start + ChronoDuration::minutes(self.minutes.max(1))
    }
}

/// The event as the calendar holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteEvent {
    pub id: String,
    pub subject: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub updated: Option<DateTime<Utc>>,
    pub cancelled: bool,
}

impl RemoteEvent {
    pub fn minutes(&self) -> i64 {
        (self.end - self.start).num_minutes().max(1)
    }
}

/// The request body that creates or replaces the event. Pure.
pub fn event_body(provider: Provider, m: &LocalMeeting) -> Value {
    let description = m.description.clone().unwrap_or_default();
    match provider {
        Provider::Microsoft => json!({
            "subject": m.subject,
            "body": { "contentType": "text", "content": description },
            "start": { "dateTime": m.start.format("%Y-%m-%dT%H:%M:%S").to_string(), "timeZone": "UTC" },
            "end": { "dateTime": m.end().format("%Y-%m-%dT%H:%M:%S").to_string(), "timeZone": "UTC" },
        }),
        Provider::Google => json!({
            "summary": m.subject,
            "description": description,
            "start": { "dateTime": m.start.to_rfc3339(), "timeZone": "UTC" },
            "end": { "dateTime": m.end().to_rfc3339(), "timeZone": "UTC" },
        }),
    }
}

fn rfc3339(v: Option<&Value>) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(v?.as_str()?)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Graph's `{dateTime, timeZone}`; only UTC is read (every request asks for
/// it with `Prefer: outlook.timezone="UTC"`).
fn graph_time(v: Option<&Value>) -> Option<DateTime<Utc>> {
    let v = v?;
    let zone = v.get("timeZone").and_then(Value::as_str).unwrap_or("UTC");
    if !zone.eq_ignore_ascii_case("UTC") {
        return None;
    }
    let raw = v.get("dateTime")?.as_str()?;
    NaiveDateTime::parse_from_str(raw.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|t| t.and_utc())
}

/// Reads an event answer; `None` when it is not a 2xx event. Pure.
pub fn parse_event(provider: Provider, status: u16, body: &str) -> Option<RemoteEvent> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    let id = v.get("id")?.as_str()?.to_owned();
    match provider {
        Provider::Microsoft => Some(RemoteEvent {
            id,
            subject: v
                .get("subject")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            start: graph_time(v.get("start"))?,
            end: graph_time(v.get("end"))?,
            updated: rfc3339(v.get("lastModifiedDateTime")),
            cancelled: v
                .get("isCancelled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        Provider::Google => Some(RemoteEvent {
            id,
            subject: v
                .get("summary")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            start: rfc3339(v.get("start").and_then(|s| s.get("dateTime")))?,
            end: rfc3339(v.get("end").and_then(|s| s.get("dateTime")))?,
            updated: rfc3339(v.get("updated")),
            cancelled: v.get("status").and_then(Value::as_str) == Some("cancelled"),
        }),
    }
}

/// What one linked meeting needs this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Nothing changed.
    None,
    /// Attome changed: copy it to the calendar.
    Push,
    /// The calendar changed: copy it to Attome.
    Pull,
    /// Both changed; Attome wrote last (or at the same time): push, keep the
    /// calendar's values as the loser.
    PushOverConflict,
    /// Both changed; the calendar wrote last: pull, keep Attome's values.
    PullOverConflict,
}

/// The last writer wins; Attome on a tie. Pure.
pub fn decide(
    local_changed: bool,
    remote_changed: bool,
    local_at: Option<DateTime<Utc>>,
    remote_at: Option<DateTime<Utc>>,
) -> Step {
    match (local_changed, remote_changed) {
        (false, false) => Step::None,
        (true, false) => Step::Push,
        (false, true) => Step::Pull,
        (true, true) => match (local_at, remote_at) {
            (Some(l), Some(r)) if r > l => Step::PullOverConflict,
            (None, Some(_)) => Step::PullOverConflict,
            _ => Step::PushOverConflict,
        },
    }
}

/// The activity fields a calendar change sets. Pure.
pub fn local_patch(event: &RemoteEvent) -> Value {
    json!({
        "subject": event.subject,
        "due_at": event.start.to_rfc3339(),
        "duration_minutes": event.minutes(),
    })
}

/// Whether the event's times or subject differ from the meeting's. Pure.
pub fn differs(m: &LocalMeeting, e: &RemoteEvent) -> bool {
    m.subject != e.subject || m.start != e.start || m.end() != e.end
}

// ── Provider calls ──────────────────────────────────────────────────────────

fn event_url(provider: Provider, id: Option<&str>) -> String {
    let base = match provider {
        Provider::Microsoft => GRAPH_EVENTS,
        Provider::Google => GOOGLE_EVENTS,
    };
    match id {
        Some(id) => format!(
            "{base}/{}",
            url::form_urlencoded::byte_serialize(id.as_bytes()).collect::<String>()
        ),
        None => base.to_owned(),
    }
}

fn request(
    provider: Provider,
    builder: reqwest::RequestBuilder,
    token: &str,
) -> reqwest::RequestBuilder {
    let builder = builder.bearer_auth(token);
    match provider {
        Provider::Microsoft => builder.header("Prefer", "outlook.timezone=\"UTC\""),
        Provider::Google => builder,
    }
}

fn refused(provider: Provider, status: u16) -> AppError {
    AppError::Validation(format!(
        "{} calendar refused the request ({status})",
        provider.as_str()
    ))
}

/// The event, `Ok(None)` when it no longer exists.
async fn fetch(provider: Provider, token: &str, id: &str) -> Result<Option<RemoteEvent>, AppError> {
    let (status, body) = answer(request(
        provider,
        client().get(event_url(provider, Some(id))),
        token,
    ))
    .await?;
    if status == 404 || status == 410 {
        return Ok(None);
    }
    parse_event(provider, status, &body)
        .map(Some)
        .ok_or_else(|| refused(provider, status))
}

async fn create_event(
    provider: Provider,
    token: &str,
    m: &LocalMeeting,
) -> Result<RemoteEvent, AppError> {
    let (status, body) = answer(
        request(provider, client().post(event_url(provider, None)), token)
            .json(&event_body(provider, m)),
    )
    .await?;
    parse_event(provider, status, &body).ok_or_else(|| refused(provider, status))
}

async fn update_event(
    provider: Provider,
    token: &str,
    id: &str,
    m: &LocalMeeting,
) -> Result<RemoteEvent, AppError> {
    let (status, body) = answer(
        request(
            provider,
            client().patch(event_url(provider, Some(id))),
            token,
        )
        .json(&event_body(provider, m)),
    )
    .await?;
    parse_event(provider, status, &body).ok_or_else(|| refused(provider, status))
}

async fn delete_event(provider: Provider, token: &str, id: &str) -> Result<(), AppError> {
    let (status, _) = answer(request(
        provider,
        client().delete(event_url(provider, Some(id))),
        token,
    ))
    .await?;
    if (200..300).contains(&status) || status == 404 || status == 410 {
        Ok(())
    } else {
        Err(refused(provider, status))
    }
}

// ── The run ─────────────────────────────────────────────────────────────────

/// One activity as the run reads it, with its link when it has one.
#[derive(sqlx::FromRow)]
struct Row {
    id: Uuid,
    subject: Option<String>,
    description: Option<String>,
    due_at: Option<DateTime<Utc>>,
    minutes: Option<f64>,
    status: Option<String>,
    live: bool,
    row_version: i64,
    modified_at: Option<DateTime<Utc>>,
    link_id: Option<Uuid>,
    event_id: Option<String>,
    local_row_version: Option<i64>,
    remote_updated_at: Option<DateTime<Utc>>,
}

impl Row {
    fn meeting(&self) -> Option<LocalMeeting> {
        Some(LocalMeeting {
            subject: self.subject.clone().unwrap_or_default(),
            description: self.description.clone(),
            start: self.due_at?,
            minutes: self
                .minutes
                .filter(|m| m.is_finite() && *m >= 1.0)
                .map_or(DEFAULT_MINUTES, |m| m.round() as i64),
        })
    }

    /// Open, live and dated: the meeting still exists in Attome.
    fn active(&self) -> bool {
        self.live && self.status.as_deref().unwrap_or("open") == "open" && self.due_at.is_some()
    }
}

/// What one run did, for the log.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub created: u32,
    pub pushed: u32,
    pub pulled: u32,
    pub removed: u32,
    pub conflicts: u32,
    pub failed: u32,
}

/// One pass over every connected calendar. A failing connection or meeting
/// is logged and counted; the rest still sync.
pub async fn run(state: &EngineState) -> Result<Summary, AppError> {
    let connections: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT user_id, provider FROM user_mail_connection ORDER BY user_id, provider",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut summary = Summary::default();
    for (user, provider) in connections {
        let Some(provider) = Provider::parse(&provider) else {
            continue;
        };
        if let Err(error) = sync_connection(state, user, provider, &mut summary).await {
            summary.failed += 1;
            tracing::warn!(%user, provider = provider.as_str(), %error, "calendar sync: connection skipped");
        }
    }
    Ok(summary)
}

async fn sync_connection(
    state: &EngineState,
    user: Uuid,
    provider: Provider,
    summary: &mut Summary,
) -> Result<(), AppError> {
    let Some(token) = access_token(state, user, provider).await? else {
        return Ok(());
    };
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT a.id, a.subject, a.description, a.due_at, a.duration_minutes::float8 AS minutes, \
                a.status, (a.is_active IS NOT FALSE) AS live, a.row_version, a.modified_at, \
                l.id AS link_id, l.event_id, l.local_row_version, l.remote_updated_at \
           FROM activity a \
           LEFT JOIN calendar_event_link l \
             ON l.activity_id = a.id AND l.user_id = $1 AND l.provider = $2 \
          WHERE a.owner_ref = $1 AND a.activity_type = 'meeting' \
            AND (l.id IS NOT NULL \
                 OR (a.status = 'open' AND a.is_active IS NOT FALSE \
                     AND a.due_at BETWEEN now() - interval '1 day' AND now() + interval '90 days')) \
          ORDER BY a.due_at NULLS LAST, a.id \
          LIMIT $3",
    )
    .bind(user)
    .bind(provider.as_str())
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    for row in rows {
        if let Err(error) = sync_one(state, user, provider, &token, &row, summary).await {
            summary.failed += 1;
            tracing::warn!(activity = %row.id, %user, %error, "calendar sync: meeting skipped");
        }
    }
    Ok(())
}

async fn sync_one(
    state: &EngineState,
    user: Uuid,
    provider: Provider,
    token: &str,
    row: &Row,
    summary: &mut Summary,
) -> Result<(), AppError> {
    let (Some(link_id), Some(event_id)) = (row.link_id, row.event_id.as_deref()) else {
        // New in Attome.
        let Some(meeting) = row.meeting().filter(|_| row.active()) else {
            return Ok(());
        };
        let event = create_event(provider, token, &meeting).await?;
        let inserted = sqlx::query(
            "INSERT INTO calendar_event_link \
               (activity_id, user_id, provider, event_id, local_row_version, remote_updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (activity_id, user_id, provider) DO NOTHING",
        )
        .bind(row.id)
        .bind(user)
        .bind(provider.as_str())
        .bind(&event.id)
        .bind(row.row_version)
        .bind(event.updated)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if inserted.rows_affected() == 0 {
            // Another run linked it first: this event is a duplicate.
            delete_event(provider, token, &event.id).await?;
        } else {
            summary.created += 1;
        }
        return Ok(());
    };

    if !row.active() {
        // Cancelled, completed or deleted in Attome: a future event goes.
        if row.due_at.is_some_and(|d| d > Utc::now()) {
            delete_event(provider, token, event_id).await?;
        }
        unlink(state, link_id).await?;
        summary.removed += 1;
        return Ok(());
    }
    let Some(meeting) = row.meeting() else {
        return Ok(());
    };
    let remote = fetch(provider, token, event_id).await?;
    let Some(remote) = remote.filter(|e| !e.cancelled) else {
        // Gone from the calendar: the meeting is cancelled in Attome.
        cancel_activity(state, user, row).await?;
        unlink(state, link_id).await?;
        summary.removed += 1;
        return Ok(());
    };

    let local_changed = row.local_row_version != Some(row.row_version);
    let remote_changed = remote.updated.is_some() && remote.updated != row.remote_updated_at;
    let step = decide(
        local_changed,
        remote_changed,
        row.modified_at,
        remote.updated,
    );
    match step {
        Step::None => Ok(()),
        Step::Push | Step::PushOverConflict => {
            if step == Step::PushOverConflict && differs(&meeting, &remote) {
                keep_conflict(state, row, user, provider, "attome", &remote).await?;
                summary.conflicts += 1;
            }
            let event = if differs(&meeting, &remote) {
                update_event(provider, token, event_id, &meeting).await?
            } else {
                remote
            };
            stamp(state, link_id, row.row_version, event.updated).await?;
            summary.pushed += 1;
            Ok(())
        }
        Step::Pull | Step::PullOverConflict => {
            if step == Step::PullOverConflict && differs(&meeting, &remote) {
                keep_conflict(state, row, user, provider, "calendar", &remote).await?;
                summary.conflicts += 1;
            }
            let row_version = if differs(&meeting, &remote) {
                update_activity(state, user, row, local_patch(&remote)).await?
            } else {
                row.row_version
            };
            stamp(state, link_id, row_version, remote.updated).await?;
            summary.pulled += 1;
            Ok(())
        }
    }
}

/// Writes the activity as its owner, through the generic mutation path;
/// answers the new `row_version`.
async fn update_activity(
    state: &EngineState,
    user: Uuid,
    row: &Row,
    body: Value,
) -> Result<i64, AppError> {
    let ctx = state.base.security.resolve(user).await?;
    ctx.require("activity", "update")?;
    let updated = attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        user,
        "activity",
        row.id,
        row.row_version,
        body,
    )
    .await?;
    Ok(updated.row_version())
}

async fn cancel_activity(state: &EngineState, user: Uuid, row: &Row) -> Result<(), AppError> {
    update_activity(state, user, row, json!({ "status": "cancelled" })).await?;
    Ok(())
}

async fn stamp(
    state: &EngineState,
    link_id: Uuid,
    row_version: i64,
    remote_updated_at: Option<DateTime<Utc>>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE calendar_event_link \
            SET local_row_version = $2, remote_updated_at = $3, synced_at = now() \
          WHERE id = $1",
    )
    .bind(link_id)
    .bind(row_version)
    .bind(remote_updated_at)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn unlink(state: &EngineState, link_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM calendar_event_link WHERE id = $1")
        .bind(link_id)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Keeps both sides of a conflict: `winner` is the side that was kept.
async fn keep_conflict(
    state: &EngineState,
    row: &Row,
    user: Uuid,
    provider: Provider,
    winner: &str,
    remote: &RemoteEvent,
) -> Result<(), AppError> {
    let attome = json!({
        "subject": row.subject,
        "due_at": row.due_at,
        "duration_minutes": row.minutes,
        "row_version": row.row_version,
        "modified_at": row.modified_at,
    });
    let calendar = json!({
        "subject": remote.subject,
        "start": remote.start,
        "end": remote.end,
        "updated": remote.updated,
    });
    sqlx::query(
        "INSERT INTO calendar_sync_conflict (activity_id, user_id, provider, winner, attome, calendar) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(row.id)
    .bind(user)
    .bind(provider.as_str())
    .bind(winner)
    .bind(attome)
    .bind(calendar)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    tracing::info!(activity = %row.id, %user, winner, "calendar sync: both sides changed; later writer kept");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn meeting() -> LocalMeeting {
        LocalMeeting {
            subject: "Kick-off".into(),
            description: Some("Agenda".into()),
            start: at("2026-11-02T09:00:00Z"),
            minutes: 45,
        }
    }

    #[test]
    fn calendar_sync_event_bodies() {
        let graph = event_body(Provider::Microsoft, &meeting());
        assert_eq!(graph["subject"], "Kick-off");
        assert_eq!(graph["start"]["dateTime"], "2026-11-02T09:00:00");
        assert_eq!(graph["end"]["dateTime"], "2026-11-02T09:45:00");
        assert_eq!(graph["start"]["timeZone"], "UTC");
        let google = event_body(Provider::Google, &meeting());
        assert_eq!(google["summary"], "Kick-off");
        assert_eq!(google["end"]["dateTime"], "2026-11-02T09:45:00+00:00");
        assert_eq!(google["description"], "Agenda");
    }

    #[test]
    fn calendar_sync_reads_events() {
        let graph = r#"{"id":"AAMk1","subject":"Kick-off (moved)",
            "start":{"dateTime":"2026-11-02T10:00:00.0000000","timeZone":"UTC"},
            "end":{"dateTime":"2026-11-02T11:00:00.0000000","timeZone":"UTC"},
            "lastModifiedDateTime":"2026-10-19T08:00:00.1234567Z","isCancelled":false}"#;
        let e = parse_event(Provider::Microsoft, 200, graph).unwrap();
        assert_eq!(e.id, "AAMk1");
        assert_eq!(e.start, at("2026-11-02T10:00:00Z"));
        assert_eq!(e.minutes(), 60);
        assert!(e.updated.is_some());
        assert!(!e.cancelled);
        let other_zone = graph.replace(r#""timeZone":"UTC""#, r#""timeZone":"Arab Standard Time""#);
        assert_eq!(parse_event(Provider::Microsoft, 200, &other_zone), None);

        let google = r#"{"id":"evt9","summary":"Review","status":"cancelled",
            "start":{"dateTime":"2026-11-03T12:00:00+03:00"},
            "end":{"dateTime":"2026-11-03T12:30:00+03:00"},
            "updated":"2026-10-19T07:00:00.000Z"}"#;
        let e = parse_event(Provider::Google, 200, google).unwrap();
        assert_eq!(e.start, at("2026-11-03T09:00:00Z"));
        assert_eq!(e.minutes(), 30);
        assert!(e.cancelled);
        assert_eq!(parse_event(Provider::Google, 403, google), None);
        assert_eq!(parse_event(Provider::Google, 200, "not json"), None);
    }

    #[test]
    fn calendar_sync_last_writer_wins() {
        let early = Some(at("2026-10-19T08:00:00Z"));
        let late = Some(at("2026-10-19T09:00:00Z"));
        assert_eq!(decide(false, false, early, late), Step::None);
        assert_eq!(decide(true, false, early, late), Step::Push);
        assert_eq!(decide(false, true, late, early), Step::Pull);
        assert_eq!(decide(true, true, late, early), Step::PushOverConflict);
        assert_eq!(decide(true, true, early, late), Step::PullOverConflict);
        assert_eq!(
            decide(true, true, early, early),
            Step::PushOverConflict,
            "a tie keeps Attome"
        );
        assert_eq!(decide(true, true, None, late), Step::PullOverConflict);
    }

    #[test]
    fn calendar_sync_patch_and_difference() {
        let e = RemoteEvent {
            id: "x".into(),
            subject: "Kick-off".into(),
            start: at("2026-11-02T09:00:00Z"),
            end: at("2026-11-02T09:45:00Z"),
            updated: None,
            cancelled: false,
        };
        assert!(!differs(&meeting(), &e));
        let moved = RemoteEvent {
            start: at("2026-11-02T10:00:00Z"),
            end: at("2026-11-02T10:30:00Z"),
            ..e
        };
        assert!(differs(&meeting(), &moved));
        assert_eq!(
            local_patch(&moved),
            json!({ "subject": "Kick-off", "due_at": "2026-11-02T10:00:00+00:00", "duration_minutes": 30 })
        );
        assert_eq!(
            event_url(Provider::Google, Some("a/b")),
            format!("{GOOGLE_EVENTS}/a%2Fb")
        );
    }
}

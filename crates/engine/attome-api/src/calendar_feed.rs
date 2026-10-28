//! Z12-T8: a calendar's holidays from an iCal feed (`calendar_feed`,
//! migration 0087), fetched by the daily `calendar_feed_fetch` job.
//!
//! - `POST /api/v1/calendar-feeds` adds a feed to a calendar (an `https`
//!   URL whose host resolves to a public address), `DELETE
//!   /api/v1/calendar-feeds/{id}` removes one. Administrators only;
//!   Configuration events.
//! - The job fetches each enabled feed through the guarded client (30
//!   seconds, `If-None-Match` with the stored ETag, at most 2 MiB), reads
//!   only all-day events (`DTSTART;VALUE=DATE`, with `DTEND` when present)
//!   and their `SUMMARY`, and refuses a feed of more than 400 events. After
//!   the fetch, one short transaction upserts the feed's holidays
//!   (`source = 'feed'`) and turns off feed holidays the feed no longer
//!   has. A manual or pack holiday on the same day is never touched: the
//!   feed's day is skipped.
//! - Each feed keeps `last_fetched_at`, its `etag` and a masked
//!   `last_error` (the HTTP status or the parse failure, never a body).

use std::collections::BTreeMap;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, post},
};
use chrono::{Duration, NaiveDate};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "calendar_feed_fetch";
/// The largest feed read.
pub const MAX_FEED_BYTES: usize = 2 * 1024 * 1024;
/// The most events one feed may hold.
pub const MAX_EVENTS: usize = 400;
/// The most days one all-day event may span.
const MAX_EVENT_DAYS: i64 = 31;
const FETCH_TIMEOUT_SECS: u64 = 30;

/// One holiday a feed names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedHoliday {
    pub date: NaiveDate,
    pub name: String,
}

fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => out.push(' '),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out.trim().to_owned()
}

/// An event being read.
#[derive(Debug, Default)]
struct Draft {
    start: Option<NaiveDate>,
    end: Option<NaiveDate>,
    summary: Option<String>,
    all_day: bool,
}

fn date_of(value: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(value.trim(), "%Y%m%d").ok()
}

/// The all-day holidays in an iCal body, one per day an event covers.
/// Timed events and everything but `DTSTART`, `DTEND` and `SUMMARY` are
/// ignored. Pure.
pub fn parse_ics(body: &str) -> Result<Vec<FeedHoliday>, String> {
    // Unfold: a line starting with a space or tab continues the one before.
    let mut lines: Vec<String> = Vec::new();
    for raw in body.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = line.strip_prefix([' ', '\t'])
            && let Some(last) = lines.last_mut()
        {
            last.push_str(rest);
        } else {
            lines.push(line.to_owned());
        }
    }
    let mut out = Vec::new();
    let mut events = 0usize;
    let mut current: Option<Draft> = None;
    for line in &lines {
        let Some((head, value)) = line.split_once(':') else {
            continue;
        };
        let mut parts = head.split(';');
        let name = parts.next().unwrap_or_default().to_ascii_uppercase();
        let all_day = parts.any(|p| p.eq_ignore_ascii_case("VALUE=DATE"));
        match name.as_str() {
            "BEGIN" if value.trim().eq_ignore_ascii_case("VEVENT") => {
                events += 1;
                if events > MAX_EVENTS {
                    return Err(format!("the feed has more than {MAX_EVENTS} events"));
                }
                current = Some(Draft {
                    all_day: true,
                    ..Draft::default()
                });
            }
            "END" if value.trim().eq_ignore_ascii_case("VEVENT") => {
                if let Some(Draft {
                    start: Some(start),
                    end,
                    summary: Some(summary),
                    all_day: true,
                }) = current.take()
                {
                    let end = end
                        .filter(|e| *e > start)
                        .unwrap_or(start + Duration::days(1));
                    let days = (end - start).num_days().min(MAX_EVENT_DAYS);
                    for i in 0..days {
                        out.push(FeedHoliday {
                            date: start + Duration::days(i),
                            name: summary.clone(),
                        });
                    }
                }
            }
            "DTSTART" => {
                if let Some(event) = current.as_mut() {
                    // A timed event (no VALUE=DATE, or a date-time) is not a holiday.
                    match date_of(value).filter(|_| all_day) {
                        Some(d) => event.start = Some(d),
                        None => event.all_day = false,
                    }
                }
            }
            "DTEND" => {
                if let Some(event) = current.as_mut() {
                    event.end = date_of(value).filter(|_| all_day);
                }
            }
            "SUMMARY" => {
                if let Some(event) = current.as_mut() {
                    let summary = unescape(value);
                    if !summary.is_empty() {
                        event.summary = Some(summary.chars().take(200).collect());
                    }
                }
            }
            _ => {}
        }
    }
    // One name per day: the first event wins.
    let mut by_day: BTreeMap<NaiveDate, String> = BTreeMap::new();
    for h in out {
        by_day.entry(h.date).or_insert(h.name);
    }
    Ok(by_day
        .into_iter()
        .map(|(date, name)| FeedHoliday { date, name })
        .collect())
}

/// A feed as an administrator adds it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CalendarFeedBody {
    pub calendar_id: Uuid,
    /// An `https` URL whose host resolves to a public address.
    pub url: String,
    #[serde(default)]
    pub enabled: bool,
}

/// A feed.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct CalendarFeed {
    pub id: Uuid,
    pub calendar_id: Uuid,
    pub url: String,
    pub enabled: bool,
    pub last_fetched_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Why the last fetch failed: an HTTP status or a parse failure.
    pub last_error: Option<String>,
}

/// An `https` URL whose host resolves to a public address.
async fn check_url(raw: &str) -> Result<reqwest::Url, AppError> {
    let url = reqwest::Url::parse(raw.trim())
        .map_err(|_| AppError::Validation("the feed URL is not a URL".into()))?;
    if url.scheme() != "https" {
        return Err(AppError::Validation("a feed URL is https".into()));
    }
    attome_server::ssrf_guard::validate_url(&url)
        .await
        .map_err(|_| AppError::Validation("the feed URL must reach a public address".into()))?;
    Ok(url)
}

fn configuration_event(
    operation: AuditOperation,
    actor: Uuid,
    feed: Uuid,
    name: &str,
) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        "calendar_feed",
        Some(feed),
    )
    .named(name.to_owned())
}

/// Add a calendar feed
///
/// Z12-T8: an iCal feed whose all-day events the daily fetch turns into the
/// calendar's holidays, never over a manual or pack holiday. Administrators
/// only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/calendar-feeds",
    tag = "admin",
    operation_id = "create_calendar_feed",
    request_body = CalendarFeedBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The feed", body = CalendarFeed),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such calendar", body = ErrorResponse),
        (status = 422, description = "Not an https URL, or one that reaches a private address", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_feed(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Json(body): Json<CalendarFeedBody>,
) -> Result<(StatusCode, Json<CalendarFeed>), AppError> {
    let url = check_url(&body.url).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM calendar WHERE id = $1)")
        .bind(body.calendar_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let feed: CalendarFeed = sqlx::query_as(
        "INSERT INTO calendar_feed (calendar_id, url, enabled) VALUES ($1, $2, $3) \
         RETURNING id, calendar_id, url, enabled, last_fetched_at, last_error",
    )
    .bind(body.calendar_id)
    .bind(url.as_str())
    .bind(body.enabled)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        configuration_event(
            AuditOperation::Create,
            ctx.user_id,
            feed.id,
            "calendar.feed_add",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(feed)))
}

/// Z12-T13: whose feeds to list.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct FeedsQuery {
    /// The calendar.
    calendar_id: Uuid,
}

/// List a calendar's feeds
///
/// Z12-T13: the calendar's iCal feeds with whether each is on, when it was
/// last fetched and why the last fetch failed. Administrators of automation
/// only.
#[utoipa::path(
    get,
    path = "/api/v1/calendar-feeds",
    tag = "admin",
    operation_id = "list_calendar_feeds",
    params(FeedsQuery, attome_types::OnePageQuery),
    responses(
        (status = 200, description = "One page of the calendar's feeds", body = attome_types::PaginatedResponse<CalendarFeed>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "A malformed page or page size", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_feeds(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
    axum::extract::Query(q): axum::extract::Query<FeedsQuery>,
    axum::extract::Query(page): axum::extract::Query<attome_types::OnePageQuery>,
) -> Result<Json<attome_types::PaginatedResponse<CalendarFeed>>, AppError> {
    let window = page.window();
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM calendar_feed WHERE calendar_id = $1")
            .bind(q.calendar_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let items: Vec<CalendarFeed> = sqlx::query_as(
        "SELECT id, calendar_id, url, enabled, last_fetched_at, last_error FROM calendar_feed \
          WHERE calendar_id = $1 ORDER BY url, id LIMIT $2 OFFSET $3",
    )
    .bind(q.calendar_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Remove a calendar feed
///
/// Z12-T8. The holidays it brought stay until removed by hand.
/// Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/calendar-feeds/{id}",
    tag = "admin",
    operation_id = "delete_calendar_feed",
    params(("id" = Uuid, Path, description = "The feed")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such feed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_feed(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let removed = sqlx::query("DELETE FROM calendar_feed WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if removed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        configuration_event(
            AuditOperation::HardDelete,
            ctx.user_id,
            id,
            "calendar.feed_remove",
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// What one fetch found.
enum Fetched {
    Unchanged,
    Body { text: String, etag: Option<String> },
}

async fn fetch(url: &str, etag: Option<&str>) -> Result<Fetched, String> {
    let url = reqwest::Url::parse(url).map_err(|_| "the stored URL does not parse".to_owned())?;
    let client = attome_server::ssrf_guard::GuardedClient::new(FETCH_TIMEOUT_SECS)
        .map_err(|_| "no HTTP client".to_owned())?;
    let mut request = client
        .get(url)
        .map_err(|_| "the URL reaches a private address".to_owned())?;
    if let Some(etag) = etag {
        request = request.header("If-None-Match", etag);
    }
    let mut res = request
        .send()
        .await
        .map_err(|_| "the feed did not answer".to_owned())?;
    if res.status().as_u16() == 304 {
        return Ok(Fetched::Unchanged);
    }
    if !res.status().is_success() {
        return Err(format!("HTTP {}", res.status().as_u16()));
    }
    if res
        .content_length()
        .is_some_and(|n| n > MAX_FEED_BYTES as u64)
    {
        return Err("the feed is larger than 2 MiB".into());
    }
    let etag = res
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.chars().take(200).collect());
    let mut bytes = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|_| "the feed broke off".to_owned())?
    {
        if bytes.len() + chunk.len() > MAX_FEED_BYTES {
            return Err("the feed is larger than 2 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let text = String::from_utf8(bytes).map_err(|_| "the feed is not UTF-8".to_owned())?;
    Ok(Fetched::Body { text, etag })
}

/// Fetches every enabled feed; answers how many were read.
pub async fn fetch_all(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let feeds: Vec<(Uuid, Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, calendar_id, url, etag FROM calendar_feed WHERE enabled ORDER BY id",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut read = 0;
    for (id, calendar_id, url, etag) in feeds {
        let fetched = fetch(&url, etag.as_deref()).await;
        let parsed = match fetched {
            Ok(Fetched::Unchanged) => Ok(None),
            Ok(Fetched::Body { text, etag }) => parse_ics(&text).map(|h| Some((h, etag))),
            Err(e) => Err(e),
        };
        match parsed {
            Ok(holidays) => {
                apply(state, id, calendar_id, holidays).await?;
                read += 1;
            }
            Err(reason) => {
                tracing::warn!(feed = %id, %reason, "calendar feed not read");
                sqlx::query(
                    "UPDATE calendar_feed SET last_fetched_at = now(), last_error = $2, \
                            row_version = row_version + 1 WHERE id = $1",
                )
                .bind(id)
                .bind(reason)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
            }
        }
    }
    Ok(read)
}

/// Stores one feed's holidays in one short transaction (`None`: the feed
/// did not change since the last fetch).
async fn apply(
    state: &EngineState,
    feed: Uuid,
    calendar_id: Uuid,
    fetched: Option<(Vec<FeedHoliday>, Option<String>)>,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if let Some((holidays, etag)) = &fetched {
        let dates: Vec<NaiveDate> = holidays.iter().map(|h| h.date).collect();
        let names: Vec<String> = holidays.iter().map(|h| h.name.clone()).collect();
        // A day a manual or pack holiday holds is skipped (the partial
        // unique index is on the calendar and day among active holidays).
        sqlx::query(
            "INSERT INTO calendar_holiday \
                 (id, calendar_id, name, holiday_date, is_active, created_at, owner_layer, source) \
             SELECT uuidv7(), $1, h.name, h.day, true, now(), 'customer', 'feed' \
               FROM UNNEST($2::date[], $3::text[]) AS h(day, name) \
             ON CONFLICT (calendar_id, holiday_date) WHERE is_active = true DO UPDATE \
                SET name = EXCLUDED.name, row_version = calendar_holiday.row_version + 1 \
              WHERE calendar_holiday.source = 'feed' AND calendar_holiday.name <> EXCLUDED.name",
        )
        .bind(calendar_id)
        .bind(&dates)
        .bind(&names)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "UPDATE calendar_holiday SET is_active = false, row_version = row_version + 1 \
              WHERE calendar_id = $1 AND source = 'feed' AND is_active \
                AND holiday_date <> ALL($2::date[])",
        )
        .bind(calendar_id)
        .bind(&dates)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "UPDATE calendar_feed SET last_fetched_at = now(), last_error = NULL, etag = $2, \
                    row_version = row_version + 1 WHERE id = $1",
        )
        .bind(feed)
        .bind(etag)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    } else {
        sqlx::query(
            "UPDATE calendar_feed SET last_fetched_at = now(), last_error = NULL, \
                    row_version = row_version + 1 WHERE id = $1",
        )
        .bind(feed)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/calendar-feeds", post(create_feed).get(list_feeds))
        .route("/api/v1/calendar-feeds/{id}", delete(delete_feed))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(create_feed, delete_feed, list_feeds),
    components(schemas(CalendarFeedBody, CalendarFeed))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn day(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn parses_all_day_events() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART;VALUE=DATE:20270923\r\n\
                   SUMMARY:Saudi National Day\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\n\
                   DTSTART;VALUE=DATE:20270310\r\nDTEND;VALUE=DATE:20270313\r\n\
                   SUMMARY:Eid al-Fitr\\, Day\r\n  off\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let holidays = parse_ics(ics).unwrap();
        assert_eq!(holidays.len(), 4);
        assert_eq!(holidays[0].date, day("2027-03-10"));
        assert_eq!(holidays[0].name, "Eid al-Fitr, Day off");
        assert_eq!(holidays[2].date, day("2027-03-12"));
        assert_eq!(holidays[3].name, "Saudi National Day");
    }

    #[test]
    fn ignores_timed_events() {
        let ics = "BEGIN:VEVENT\nDTSTART:20270923T090000Z\nSUMMARY:Meeting\nEND:VEVENT\n\
                   BEGIN:VEVENT\nDTSTART;VALUE=DATE:20270101\nEND:VEVENT\n";
        assert!(parse_ics(ics).unwrap().is_empty(), "timed, and no summary");
    }

    #[test]
    fn rejects_oversized_feed() {
        let one = "BEGIN:VEVENT\nDTSTART;VALUE=DATE:20270101\nSUMMARY:x\nEND:VEVENT\n";
        let feed = one.repeat(MAX_EVENTS + 1);
        assert!(parse_ics(&feed).is_err());
        assert!(parse_ics(&one.repeat(MAX_EVENTS)).is_ok());
    }

    #[tokio::test]
    async fn feed_rejects_private_address() {
        assert!(check_url("https://127.0.0.1/holidays.ics").await.is_err());
        assert!(check_url("http://example.com/holidays.ics").await.is_err());
        assert!(check_url("not a url").await.is_err());
    }
}

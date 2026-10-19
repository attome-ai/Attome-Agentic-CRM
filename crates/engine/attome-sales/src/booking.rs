//! D20-T2: public booking links.
//!
//! A **booking page** (`booking_page`, the sales pack) names a team, a
//! meeting length, a buffer kept around busy time, how far apart offered
//! start times are, how far ahead and how soon one may book. Its public page
//! lists the times at least one team member is free:
//! - within their working hours, holidays and absences (their calendar,
//!   `load_calendar_for_user`);
//! - outside their open meetings, visits and calls in Attome and their
//!   bookings;
//! - outside what their own connected calendar shows as busy (D15,
//!   `calendar_sync::busy`). A calendar that cannot be read takes that person
//!   out of the offer, so nobody is double-booked because their calendar was
//!   unreachable.
//!
//! **Booking** re-checks who is free at that time and gives the meeting to
//! the next of them round robin (M11; a cursor per page). The claim is a
//! `booking` row written under two-argument advisory locks on the page and
//! on the member, after checking the member has no booking overlapping it,
//! so two people booking the same time at once cannot both get the same
//! person. The meeting is then created as a `meeting` activity owned by that
//! member, through the generic mutation path as them. It is attached to the
//! prospect: a contact or lead with that email, else a new lead, else the
//! booking page itself. D15-T3 puts it in their calendar. The prospect gets a
//! confirmation email with a signed link to reschedule or cancel; that link
//! is the only authority on those routes.

use attome_auth::signed_link;
use attome_calendar::availability::{Interval, SlotRequest, free_slots};
use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The signed link's domain, so a booking link never stands in for another.
const LINK_DOMAIN: &str = "attome-sales/booking";
/// How long a manage link works.
const LINK_DAYS: i64 = 365;
/// Most team members a page considers.
const MAX_MEMBERS: i64 = 20;
/// Most slots one answer lists.
const MAX_SLOTS: usize = 200;
/// Longest window one slot request covers.
const MAX_WINDOW_DAYS: i64 = 31;
const MAX_HORIZON_DAYS: i64 = 365;

/// A booking page's settings.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BookingPage {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub team_ref: Option<Uuid>,
    pub duration_minutes: Option<f64>,
    pub buffer_minutes: Option<f64>,
    pub step_minutes: Option<f64>,
    pub horizon_days: Option<f64>,
    pub min_notice_hours: Option<f64>,
    /// D20-T3: `video`, `phone` or `in_person`.
    pub meeting_type: Option<String>,
    /// For a video meeting: `teams`, `meet`, `zoom` or `jitsi` (J7-T1).
    pub video_provider: Option<String>,
    /// Where an in-person meeting is, or the number a phone meeting uses.
    pub location: Option<String>,
}

/// The page's settings with defaults, as durations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rules {
    pub duration: Duration,
    pub buffer: Duration,
    pub step: Duration,
    pub horizon: Duration,
    pub notice: Duration,
}

fn whole(v: Option<f64>, default: i64, min: i64, max: i64) -> i64 {
    v.filter(|v| v.is_finite())
        .map_or(default, |v| v.round() as i64)
        .clamp(min, max)
}

impl BookingPage {
    /// 30-minute meetings every 30 minutes, no buffer, 30 days ahead, at
    /// least 4 hours' notice, unless the page says otherwise. Pure.
    pub fn rules(&self) -> Rules {
        let duration = whole(self.duration_minutes, 30, 5, 8 * 60);
        Rules {
            duration: Duration::minutes(duration),
            buffer: Duration::minutes(whole(self.buffer_minutes, 0, 0, 240)),
            step: Duration::minutes(whole(self.step_minutes, duration.min(60), 5, 8 * 60)),
            horizon: Duration::days(whole(self.horizon_days, 30, 1, MAX_HORIZON_DAYS)),
            notice: Duration::hours(whole(self.min_notice_hours, 4, 0, 24 * 30)),
        }
    }
}

/// The part of `[from, to)` the page offers at `now`: not sooner than the
/// notice, not later than the horizon, at most 31 days long. Pure.
pub fn window(
    rules: &Rules,
    now: DateTime<Utc>,
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    let earliest = now + rules.notice;
    let latest = now + rules.horizon;
    let start = from.map_or(earliest, |f| f.max(earliest));
    let end = to
        .map_or(latest, |t| t.min(latest))
        .min(start + Duration::days(MAX_WINDOW_DAYS));
    (start < end).then_some((start, end))
}

/// Whether a meeting at `start` is one the page offers at `now`. Pure.
pub fn bookable(rules: &Rules, now: DateTime<Utc>, start: DateTime<Utc>) -> bool {
    start >= now + rules.notice && start + rules.duration <= now + rules.horizon
}

/// Every member's slots as one list, by start, each start once. Pure.
pub fn merge_slots(per_member: Vec<Vec<Interval>>, limit: usize) -> Vec<Interval> {
    let mut all: Vec<Interval> = per_member.into_iter().flatten().collect();
    all.sort();
    all.dedup_by_key(|s| s.0);
    all.truncate(limit);
    all
}

/// `free` in round-robin order: the member after `last` first. Pure.
pub fn round_robin_order(free: &[Uuid], last: Option<Uuid>) -> Vec<Uuid> {
    let mut sorted = free.to_vec();
    sorted.sort();
    let at = last
        .and_then(|l| sorted.iter().position(|m| *m > l))
        .unwrap_or(0);
    sorted.rotate_left(at);
    sorted
}

// ── Wire types ──────────────────────────────────────────────────────────────

/// A time that can be booked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Slot {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// A booking page as the public sees it.
#[derive(Debug, Serialize, ToSchema)]
pub struct PublicBookingPage {
    pub name: String,
    pub description: Option<String>,
    pub duration_minutes: i64,
    /// D20-T3: `video`, `phone` or `in_person`; none when the page does not say.
    pub meeting_type: Option<String>,
    /// The video service of a video meeting.
    pub video_provider: Option<String>,
    /// Where an in-person meeting is, or the number a phone meeting uses.
    pub location: Option<String>,
    pub slots: Vec<Slot>,
}

/// The window to list.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SlotQuery {
    /// From (UTC); not before the page's notice.
    pub from: Option<DateTime<Utc>>,
    /// To (UTC); not past the page's horizon, at most 31 days after `from`.
    pub to: Option<DateTime<Utc>>,
}

/// A booking.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct BookRequest {
    /// One of the listed slot starts.
    pub start: DateTime<Utc>,
    pub name: String,
    pub email: String,
    pub phone: Option<String>,
    pub notes: Option<String>,
    /// The challenge answer, when the deployment uses one.
    pub captcha_token: Option<String>,
}

/// A booking made.
#[derive(Debug, Serialize, ToSchema)]
pub struct Booked {
    pub booking_id: Uuid,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// The token of the reschedule/cancel link (also in the email).
    pub manage_token: String,
}

/// A booking as its manage link shows it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ManagedBooking {
    pub page_name: String,
    pub slug: String,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// `booked` or `cancelled`.
    pub status: String,
}

/// A new time.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RescheduleRequest {
    pub start: DateTime<Utc>,
}

// ── Reading ─────────────────────────────────────────────────────────────────

const PAGE_COLUMNS: &str = "id, name, slug, description, team_ref, \
     duration_minutes::float8 AS duration_minutes, buffer_minutes::float8 AS buffer_minutes, \
     step_minutes::float8 AS step_minutes, horizon_days::float8 AS horizon_days, \
     min_notice_hours::float8 AS min_notice_hours, meeting_type, video_provider, location";

async fn installed(state: &EngineState) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass('booking_page') IS NOT NULL")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// The enabled page with this slug, or none.
pub async fn page_by_slug(
    state: &EngineState,
    slug: &str,
) -> Result<Option<BookingPage>, AppError> {
    let slug = slug.trim();
    if slug.is_empty() || slug.len() > 100 || !installed(state).await? {
        return Ok(None);
    }
    sqlx::query_as(&format!(
        "SELECT {PAGE_COLUMNS} FROM booking_page \
          WHERE lower(slug) = lower($1) AND coalesce(is_enabled, true) \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT 1"
    ))
    .bind(slug)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn page_by_id(state: &EngineState, id: Uuid) -> Result<Option<BookingPage>, AppError> {
    if !installed(state).await? {
        return Ok(None);
    }
    sqlx::query_as(&format!(
        "SELECT {PAGE_COLUMNS} FROM booking_page WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The page's team members who can sign in, in id order.
async fn members(state: &EngineState, page: &BookingPage) -> Result<Vec<Uuid>, AppError> {
    let Some(team) = page.team_ref else {
        return Ok(Vec::new());
    };
    sqlx::query_scalar(
        "SELECT u.id FROM user_account u \
           JOIN user_account_mm_team m ON m.user_ref = u.id AND m.is_deleted = false \
          WHERE m.team_ref = $1 AND u.is_active = true \
          ORDER BY u.id LIMIT $2",
    )
    .bind(team)
    .bind(MAX_MEMBERS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// What keeps `user` busy in `[from, to)`, leaving out one booking (when
/// moving it); `None` when their calendar cannot be read.
async fn member_busy(
    state: &EngineState,
    user: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    except: Option<(Uuid, Option<Uuid>)>,
) -> Result<Option<Vec<Interval>>, AppError> {
    let (except_booking, except_activity) = except.map_or((None, None), |(b, a)| (Some(b), a));
    let meetings: Vec<(DateTime<Utc>, Option<f64>)> = sqlx::query_as(
        "SELECT due_at, duration_minutes::float8 FROM activity \
          WHERE owner_ref = $1 AND status = 'open' AND is_active IS NOT FALSE \
            AND activity_type IN ('meeting', 'visit', 'phone_call') \
            AND due_at IS NOT NULL AND due_at < $3 AND due_at > $2 - interval '1 day' \
            AND id IS DISTINCT FROM $4",
    )
    .bind(user)
    .bind(from)
    .bind(to)
    .bind(except_activity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut busy: Vec<Interval> = meetings
        .into_iter()
        .map(|(at, minutes)| {
            let minutes = minutes
                .filter(|m| m.is_finite() && *m >= 1.0)
                .map_or(30, |m| m.round() as i64);
            (at, at + Duration::minutes(minutes))
        })
        .collect();
    let booked: Vec<Interval> = sqlx::query_as(
        "SELECT starts_at, ends_at FROM booking \
          WHERE user_id = $1 AND status = 'booked' AND starts_at < $3 AND ends_at > $2 \
            AND id IS DISTINCT FROM $4",
    )
    .bind(user)
    .bind(from)
    .bind(to)
    .bind(except_booking)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    busy.extend(booked);
    match attome_integration::connector::adapters::calendar_sync::busy(state, user, from, to).await
    {
        Ok(remote) => busy.extend(remote),
        Err(error) => {
            tracing::warn!(%user, %error, "booking: calendar unreadable; person left out of the offer");
            return Ok(None);
        }
    }
    Ok(Some(busy))
}

/// `user`'s free slots in `[from, to)`.
async fn member_slots(
    state: &EngineState,
    user: Uuid,
    rules: &Rules,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    limit: usize,
    except: Option<(Uuid, Option<Uuid>)>,
) -> Result<Vec<Interval>, AppError> {
    let Ok(loaded) = attome_core::calendar::load_calendar_for_user(&state.base.db, user).await?
    else {
        return Ok(Vec::new());
    };
    // The buffer reaches outside the window: look that far for busy time.
    let Some(busy) =
        member_busy(state, user, from - rules.buffer, to + rules.buffer, except).await?
    else {
        return Ok(Vec::new());
    };
    free_slots(
        &[(&loaded.calendar, busy.as_slice())],
        &SlotRequest {
            from,
            to,
            duration: rules.duration,
            buffer: rules.buffer,
            step: rules.step,
            limit,
        },
    )
    .map_err(AppError::internal)
}

/// Whether `user` is free for exactly `[start, start + duration)`.
async fn free_at(
    state: &EngineState,
    user: Uuid,
    rules: &Rules,
    start: DateTime<Utc>,
    except: Option<(Uuid, Option<Uuid>)>,
) -> Result<bool, AppError> {
    let end = start + rules.duration;
    let slots = member_slots(state, user, rules, start, end, 1, except).await?;
    Ok(slots.first() == Some(&(start, end)))
}

/// The public page: its name and the times someone on the team is free.
pub async fn public_page(
    state: &EngineState,
    slug: &str,
    query: &SlotQuery,
) -> Result<PublicBookingPage, AppError> {
    let page = page_by_slug(state, slug).await?.ok_or(AppError::NotFound)?;
    let rules = page.rules();
    let mut per_member = Vec::new();
    if let Some((from, to)) = window(&rules, Utc::now(), query.from, query.to) {
        for user in members(state, &page).await? {
            per_member.push(member_slots(state, user, &rules, from, to, MAX_SLOTS, None).await?);
        }
    }
    Ok(PublicBookingPage {
        name: page.name,
        description: page.description,
        duration_minutes: rules.duration.num_minutes(),
        meeting_type: page.meeting_type,
        video_provider: page.video_provider,
        location: page.location,
        slots: merge_slots(per_member, MAX_SLOTS)
            .into_iter()
            .map(|(start, end)| Slot { start, end })
            .collect(),
    })
}

// ── Booking ─────────────────────────────────────────────────────────────────

fn clean(value: &str, field: &str, max: usize, required: bool) -> Result<Option<String>, AppError> {
    let v = value.trim();
    if v.chars().count() > max {
        return Err(AppError::Validation(format!(
            "{field}: at most {max} characters"
        )));
    }
    if v.is_empty() {
        return if required {
            Err(AppError::Validation(format!("{field}: required")))
        } else {
            Ok(None)
        };
    }
    Ok(Some(v.to_owned()))
}

/// The validated name, email, phone and notes. Pure.
pub fn validate(
    req: &BookRequest,
) -> Result<(String, String, Option<String>, Option<String>), AppError> {
    let name = clean(&req.name, "name", 200, true)?.unwrap_or_default();
    let email = clean(&req.email, "email", 254, true)?.unwrap_or_default();
    let valid_email = email.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && domain.contains('.') && !domain.contains('@')
    }) && !email.chars().any(char::is_whitespace);
    if !valid_email {
        return Err(AppError::Validation("email: not an address".into()));
    }
    let phone = clean(req.phone.as_deref().unwrap_or_default(), "phone", 40, false)?;
    let notes = clean(
        req.notes.as_deref().unwrap_or_default(),
        "notes",
        2000,
        false,
    )?;
    Ok((name, email, phone, notes))
}

async fn lock(tx: &mut attome_db::Tx<'_>, key: String) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

async fn overlaps(
    tx: &mut attome_db::Tx<'_>,
    user: Uuid,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    except: Option<Uuid>,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM booking \
          WHERE user_id = $1 AND status = 'booked' AND starts_at < $3 AND ends_at > $2 \
            AND id IS DISTINCT FROM $4)",
    )
    .bind(user)
    .bind(start)
    .bind(end)
    .bind(except)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Claims the slot for the first free member in round-robin order; the
/// booking id and the member.
async fn claim(
    state: &EngineState,
    page: &BookingPage,
    free: &[Uuid],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    name: &str,
    email: &str,
) -> Result<Option<(Uuid, Uuid)>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !lock(&mut tx, format!("attome-sales/booking-rr:{}", page.id)).await? {
        return Err(AppError::Conflict(
            "another booking on this page is being made; try again",
        ));
    }
    let last: Option<Uuid> =
        sqlx::query_scalar("SELECT last_user_id FROM booking_assign_cursor WHERE page_id = $1")
            .bind(page.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .flatten();
    for member in round_robin_order(free, last) {
        if !lock(&mut tx, format!("attome-sales/booking:{member}")).await? {
            continue;
        }
        if overlaps(&mut tx, member, start, end, None).await? {
            continue;
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO booking (id, page_id, user_id, starts_at, ends_at, name, email) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(page.id)
        .bind(member)
        .bind(start)
        .bind(end)
        .bind(name)
        .bind(email)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO booking_assign_cursor (page_id, last_user_id) VALUES ($1, $2) \
             ON CONFLICT (page_id) DO UPDATE SET last_user_id = EXCLUDED.last_user_id, updated_at = now()",
        )
        .bind(page.id)
        .bind(member)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        return Ok(Some((id, member)));
    }
    Ok(None)
}

/// The record the meeting is about: a contact or lead with this email, else
/// a new lead the member creates, else none.
async fn prospect(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    member: Uuid,
    name: &str,
    email: &str,
    phone: Option<&str>,
) -> Option<(String, Uuid)> {
    for entity in ["contact", "lead"] {
        let has_email = state
            .entities
            .load()
            .get(entity)
            .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == "email"));
        if !has_email {
            continue;
        }
        let found: Result<Option<Uuid>, sqlx::Error> = sqlx::query_scalar(&format!(
            "SELECT id FROM {entity} WHERE lower(email) = lower($1) AND is_active IS NOT FALSE \
              ORDER BY id LIMIT 1"
        ))
        .bind(email)
        .fetch_optional(&state.base.db)
        .await;
        match found {
            Ok(Some(id)) => return Some((entity.to_owned(), id)),
            Ok(None) => {}
            Err(error) => tracing::warn!(entity, %error, "booking: prospect lookup failed"),
        }
    }
    if state.entities.load().get("lead").is_none() || ctx.require("lead", "create").is_err() {
        return None;
    }
    let mut body = json!({ "name": name, "email": email, "source": "booking" });
    if let Some(phone) = phone {
        body["phone"] = Value::String(phone.to_owned());
    }
    match attome_records::entity_crud::create_record_for(state, ctx, member, "lead", body).await {
        Ok((id, _)) => Some(("lead".to_owned(), id)),
        Err(error) => {
            tracing::warn!(%member, %error, "booking: lead not created; the meeting goes on the booking page");
            None
        }
    }
}

/// Creates the meeting as `member`, on the prospect when allowed, else on
/// the booking page; with its join link or place, for the email. For a
/// video page the online meeting is made first, on the member's own
/// connection (J7-T1); when that fails the meeting is still booked, without
/// a link, and the member sees why in the log.
async fn create_meeting(
    state: &EngineState,
    page: &BookingPage,
    member: Uuid,
    start: DateTime<Utc>,
    rules: &Rules,
    (name, email, phone, notes): (&str, &str, Option<&str>, Option<&str>),
) -> Result<(Uuid, Option<String>), AppError> {
    let ctx = state.base.security.resolve(member).await?;
    ctx.require("activity", "create")?;
    let mut extra = serde_json::Map::new();
    let mut place = None;
    match page.meeting_type.as_deref() {
        Some("video") => {
            if let Some(provider) = page.video_provider.as_deref().filter(|p| !p.is_empty()) {
                let request = attome_integration::connector::adapters::video::MeetingRequest {
                    provider: provider.to_owned(),
                    subject: format!("{}: {name}", page.name),
                    start,
                    end: start + rules.duration,
                };
                match attome_integration::connector::adapters::video::create(
                    state, member, &request,
                )
                .await
                {
                    Ok(meeting) => {
                        extra.insert("meeting_provider".into(), json!(meeting.provider));
                        extra.insert("meeting_id".into(), json!(meeting.id));
                        extra.insert("meeting_url".into(), json!(meeting.join_url));
                        place = Some(meeting.join_url);
                    }
                    Err(error) => {
                        tracing::warn!(%member, %error, "booking: online meeting not created; booked without a link")
                    }
                }
            }
        }
        Some("phone" | "in_person") => {
            place = page.location.clone().filter(|l| !l.trim().is_empty());
        }
        _ => {}
    }
    let mut description = format!("Booked through \"{}\" by {name} <{email}>", page.name);
    if let Some(phone) = phone {
        description.push_str(&format!(", {phone}"));
    }
    if let Some(notes) = notes {
        description.push_str("\n\n");
        description.push_str(notes);
    }
    if let Some(place) = &place {
        description.push_str(&format!("\n{place}"));
    }
    let body = |entity: &str, record: Uuid| {
        let mut body = json!({
            "subject": format!("{}: {name}", page.name),
            "activity_type": "meeting",
            "due_at": start.to_rfc3339(),
            "duration_minutes": rules.duration.num_minutes(),
            "description": description,
            "entity_name": entity,
            "record_id": record.to_string(),
        });
        if let Value::Object(map) = &mut body {
            map.extend(extra.clone());
        }
        body
    };
    if let Some((entity, record)) = prospect(state, &ctx, member, name, email, phone).await {
        match attome_records::entity_crud::create_record_for(
            state,
            &ctx,
            member,
            "activity",
            body(&entity, record),
        )
        .await
        {
            Ok((id, _)) => return Ok((id, place)),
            Err(error) => {
                tracing::warn!(%member, %error, "booking: meeting not allowed on the prospect; put on the page")
            }
        }
    }
    let (id, _) = attome_records::entity_crud::create_record_for(
        state,
        &ctx,
        member,
        "activity",
        body("booking_page", page.id),
    )
    .await?;
    Ok((id, place))
}

fn link_secret(state: &EngineState) -> Result<String, AppError> {
    state
        .base
        .secrets
        .load()
        .jwt_secret
        .active()
        .map(str::to_owned)
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))
}

/// The manage link's token for a booking.
fn manage_token(state: &EngineState, booking: Uuid) -> Result<String, AppError> {
    let expires = (Utc::now() + Duration::days(LINK_DAYS)).timestamp();
    signed_link::sign(
        &link_secret(state)?,
        LINK_DOMAIN,
        &booking.to_string(),
        expires,
    )
    .ok_or_else(|| AppError::internal("booking link could not be signed"))
}

/// The booking a manage token names, or none when it is altered or expired.
fn token_booking(state: &EngineState, token: &str) -> Result<Option<Uuid>, AppError> {
    Ok(signed_link::verify(
        &link_secret(state)?,
        LINK_DOMAIN,
        token,
        Utc::now().timestamp(),
    )
    .and_then(|subject| Uuid::parse_str(&subject).ok()))
}

/// The confirmation, reschedule or cancellation email to the prospect,
/// queued in one transaction with its delivery row.
async fn notify(
    state: &EngineState,
    to: &str,
    subject: String,
    text: String,
) -> Result<(), AppError> {
    let html = format!("<p>{}</p>", escape(&text).replace('\n', "<br>"));
    let delivery_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_email::delivery::record_queued_in_tx(
        &mut tx,
        delivery_id,
        attome_email::delivery::EmailDeliveryKind::Generic,
        to,
        &subject,
        None,
        None,
        None,
    )
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: to.to_owned(),
            subject,
            text_body: text,
            html_body: Some(html),
            delivery_id: Some(delivery_id),
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
        })),
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Text made safe inside HTML. Pure.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn manage_url(state: &EngineState, token: &str) -> String {
    format!(
        "{}/book/manage/{token}",
        state.base.config.frontend_url().trim_end_matches('/')
    )
}

fn when(start: DateTime<Utc>, end: DateTime<Utc>) -> String {
    format!(
        "{} to {} UTC",
        start.format("%A %-d %B %Y, %H:%M"),
        end.format("%H:%M")
    )
}

/// Books a meeting on the page. Rate limits and the challenge are the
/// caller's (the public route's).
pub async fn book(state: &EngineState, slug: &str, req: &BookRequest) -> Result<Booked, AppError> {
    let (name, email, phone, notes) = validate(req)?;
    let page = page_by_slug(state, slug).await?.ok_or(AppError::NotFound)?;
    let rules = page.rules();
    let start = req.start;
    if !bookable(&rules, Utc::now(), start) {
        return Err(AppError::Validation(
            "start: not a time this page offers".into(),
        ));
    }
    let end = start + rules.duration;
    let mut free = Vec::new();
    for member in members(state, &page).await? {
        if free_at(state, member, &rules, start, None).await? {
            free.push(member);
        }
    }
    let Some((booking_id, member)) = claim(state, &page, &free, start, end, &name, &email).await?
    else {
        return Err(AppError::Conflict("that time is no longer free"));
    };
    let (activity, place) = match create_meeting(
        state,
        &page,
        member,
        start,
        &rules,
        (
            name.as_str(),
            email.as_str(),
            phone.as_deref(),
            notes.as_deref(),
        ),
    )
    .await
    {
        Ok(created) => created,
        Err(error) => {
            // The claim must not hold the time for a meeting that does not exist.
            sqlx::query(
                "UPDATE booking SET status = 'cancelled', updated_at = now() WHERE id = $1",
            )
            .bind(booking_id)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            return Err(error);
        }
    };
    sqlx::query("UPDATE booking SET activity_id = $2, updated_at = now() WHERE id = $1")
        .bind(booking_id)
        .bind(activity)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let token = manage_token(state, booking_id)?;
    notify(
        state,
        &email,
        format!("Booked: {}", page.name),
        format!(
            "Hello {name},\n\nYour meeting \"{}\" is booked for {}.{}\n\n\
             To reschedule or cancel: {}",
            page.name,
            when(start, end),
            place.map(|p| format!("\n{p}")).unwrap_or_default(),
            manage_url(state, &token)
        ),
    )
    .await?;
    tracing::info!(%booking_id, page = %page.id, %member, "booking: meeting booked");
    Ok(Booked {
        booking_id,
        start,
        end,
        manage_token: token,
    })
}

#[derive(sqlx::FromRow)]
struct BookingRow {
    id: Uuid,
    page_id: Uuid,
    user_id: Uuid,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    status: String,
    activity_id: Option<Uuid>,
    name: String,
    email: String,
}

async fn booking_for(state: &EngineState, token: &str) -> Result<BookingRow, AppError> {
    let id = token_booking(state, token)?.ok_or(AppError::NotFound)?;
    sqlx::query_as(
        "SELECT id, page_id, user_id, starts_at, ends_at, status, activity_id, name, email \
           FROM booking WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

async fn shaped(state: &EngineState, row: &BookingRow) -> Result<ManagedBooking, AppError> {
    let page = page_by_id(state, row.page_id).await?;
    Ok(ManagedBooking {
        page_name: page.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
        slug: page.map(|p| p.slug).unwrap_or_default(),
        start: row.starts_at,
        end: row.ends_at,
        status: row.status.clone(),
    })
}

/// The booking a manage link names.
pub async fn managed(state: &EngineState, token: &str) -> Result<ManagedBooking, AppError> {
    let row = booking_for(state, token).await?;
    shaped(state, &row).await
}

/// Writes the meeting activity as its owner.
async fn update_meeting(
    state: &EngineState,
    row: &BookingRow,
    body: Value,
) -> Result<(), AppError> {
    let Some(activity) = row.activity_id else {
        return Ok(());
    };
    let version: Option<i64> = sqlx::query_scalar(
        "SELECT row_version FROM activity WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(activity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(version) = version else {
        return Ok(());
    };
    let ctx = state.base.security.resolve(row.user_id).await?;
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        row.user_id,
        "activity",
        activity,
        version,
        body,
    )
    .await?;
    Ok(())
}

fn not_started(row: &BookingRow) -> Result<(), AppError> {
    if row.status != "booked" {
        return Err(AppError::Conflict("this booking is cancelled"));
    }
    if row.starts_at <= Utc::now() {
        return Err(AppError::Conflict("this meeting has already started"));
    }
    Ok(())
}

/// Cancels the booking and its meeting.
pub async fn cancel(state: &EngineState, token: &str) -> Result<ManagedBooking, AppError> {
    let mut row = booking_for(state, token).await?;
    not_started(&row)?;
    let changed = sqlx::query(
        "UPDATE booking SET status = 'cancelled', updated_at = now() WHERE id = $1 AND status = 'booked'",
    )
    .bind(row.id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::Conflict("this booking is cancelled"));
    }
    row.status = "cancelled".into();
    if let Err(error) = update_meeting(state, &row, json!({ "status": "cancelled" })).await {
        // The time is free again either way; the owner sees the meeting still open.
        tracing::warn!(booking = %row.id, %error, "booking: cancelled, but the meeting was not");
    }
    let page = shaped(state, &row).await?;
    notify(
        state,
        &row.email,
        format!("Cancelled: {}", page.page_name),
        format!(
            "Hello {},\n\nYour meeting \"{}\" on {} is cancelled.",
            row.name,
            page.page_name,
            when(row.starts_at, row.ends_at)
        ),
    )
    .await?;
    Ok(page)
}

/// Moves the booking to a new time with the same person, when they are free.
pub async fn reschedule(
    state: &EngineState,
    token: &str,
    req: &RescheduleRequest,
) -> Result<ManagedBooking, AppError> {
    let mut row = booking_for(state, token).await?;
    not_started(&row)?;
    let page = page_by_id(state, row.page_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let rules = page.rules();
    let start = req.start;
    if !bookable(&rules, Utc::now(), start) {
        return Err(AppError::Validation(
            "start: not a time this page offers".into(),
        ));
    }
    let end = start + rules.duration;
    let except = Some((row.id, row.activity_id));
    if !free_at(state, row.user_id, &rules, start, except).await? {
        return Err(AppError::Conflict("that time is no longer free"));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !lock(&mut tx, format!("attome-sales/booking:{}", row.user_id)).await? {
        return Err(AppError::Conflict(
            "another booking is being made; try again",
        ));
    }
    if overlaps(&mut tx, row.user_id, start, end, Some(row.id)).await? {
        return Err(AppError::Conflict("that time is no longer free"));
    }
    let moved = sqlx::query(
        "UPDATE booking SET starts_at = $2, ends_at = $3, updated_at = now() \
          WHERE id = $1 AND status = 'booked'",
    )
    .bind(row.id)
    .bind(start)
    .bind(end)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() == 0 {
        return Err(AppError::Conflict("this booking is cancelled"));
    }
    attome_db::tx::commit(tx).await?;
    row.starts_at = start;
    row.ends_at = end;
    update_meeting(state, &row, json!({ "due_at": start.to_rfc3339() })).await?;
    notify(
        state,
        &row.email,
        format!("Rescheduled: {}", page.name),
        format!(
            "Hello {},\n\nYour meeting \"{}\" is now on {}.\n\nTo change it again: {}",
            row.name,
            page.name,
            when(start, end),
            manage_url(state, token)
        ),
    )
    .await?;
    shaped(state, &row).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn page() -> BookingPage {
        BookingPage {
            id: Uuid::nil(),
            name: "Intro call".into(),
            slug: "intro".into(),
            description: None,
            team_ref: None,
            duration_minutes: None,
            buffer_minutes: Some(10.0),
            step_minutes: None,
            horizon_days: Some(14.0),
            min_notice_hours: Some(2.0),
            meeting_type: None,
            video_provider: None,
            location: None,
        }
    }

    #[test]
    fn booking_rules_default_and_clamp() {
        let rules = page().rules();
        assert_eq!(rules.duration, Duration::minutes(30));
        assert_eq!(rules.step, Duration::minutes(30));
        assert_eq!(rules.buffer, Duration::minutes(10));
        assert_eq!(rules.horizon, Duration::days(14));
        assert_eq!(rules.notice, Duration::hours(2));
        let long = BookingPage {
            duration_minutes: Some(90.0),
            horizon_days: Some(9999.0),
            ..page()
        };
        assert_eq!(
            long.rules().step,
            Duration::minutes(60),
            "steps at most an hour by default"
        );
        assert_eq!(long.rules().horizon, Duration::days(MAX_HORIZON_DAYS));
    }

    #[test]
    fn booking_window_respects_notice_and_horizon() {
        let rules = page().rules();
        let now = at("2026-11-01T08:00:00Z");
        assert_eq!(
            window(&rules, now, None, None),
            Some((at("2026-11-01T10:00:00Z"), at("2026-11-15T08:00:00Z")))
        );
        assert_eq!(
            window(
                &rules,
                now,
                Some(at("2026-11-03T00:00:00Z")),
                Some(at("2026-11-04T00:00:00Z"))
            ),
            Some((at("2026-11-03T00:00:00Z"), at("2026-11-04T00:00:00Z")))
        );
        assert_eq!(
            window(&rules, now, Some(at("2026-12-01T00:00:00Z")), None),
            None
        );
        assert!(bookable(&rules, now, at("2026-11-01T10:00:00Z")));
        assert!(
            !bookable(&rules, now, at("2026-11-01T09:59:00Z")),
            "inside the notice"
        );
        assert!(
            !bookable(&rules, now, at("2026-11-15T07:45:00Z")),
            "past the horizon"
        );
    }

    #[test]
    fn booking_slots_merge_and_round_robin() {
        let s = |h: u32| {
            let start = at(&format!("2026-11-02T{h:02}:00:00Z"));
            (start, start + Duration::minutes(30))
        };
        assert_eq!(
            merge_slots(vec![vec![s(9), s(11)], vec![s(9), s(10)]], 10),
            vec![s(9), s(10), s(11)]
        );
        assert_eq!(
            merge_slots(vec![vec![s(9), s(10), s(11)]], 2),
            vec![s(9), s(10)]
        );

        let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        assert_eq!(round_robin_order(&[c, a, b], None), vec![a, b, c]);
        assert_eq!(round_robin_order(&[a, b, c], Some(a)), vec![b, c, a]);
        assert_eq!(
            round_robin_order(&[a, c], Some(b)),
            vec![c, a],
            "the next after a busy one"
        );
        assert_eq!(round_robin_order(&[a, b], Some(c)), vec![a, b]);
    }

    #[test]
    fn booking_validates_the_prospect() {
        let req = |email: &str| BookRequest {
            start: at("2026-11-02T09:00:00Z"),
            name: " Sara Al-Qahtani ".into(),
            email: email.into(),
            phone: Some("  ".into()),
            notes: None,
            captcha_token: None,
        };
        let (name, email, phone, notes) = validate(&req("sara@example.sa")).unwrap();
        assert_eq!(
            (name.as_str(), email.as_str()),
            ("Sara Al-Qahtani", "sara@example.sa")
        );
        assert_eq!((phone, notes), (None, None));
        assert!(validate(&req("not-an-address")).is_err());
        assert!(validate(&req("a@b")).is_err());
        assert!(validate(&req("a b@c.d")).is_err());
        assert!(
            validate(&BookRequest {
                name: "".into(),
                ..req("a@b.c")
            })
            .is_err()
        );
        assert_eq!(
            escape("<b>\"Tom & Jerry's\"</b>"),
            "&lt;b&gt;&quot;Tom &amp; Jerry&#39;s&quot;&lt;/b&gt;"
        );
    }
}

//! Minimal ticket SLA: policy assignment, a business-hours due-date
//! calculator, and breach detection. Built 2026-08-25 after discovering
//! D-398's original plan — reuse `attome-workflow`'s `sla_sweep.rs`/
//! `escalation.rs` — was a misreading: neither file has anything to do with
//! SLA policy, business hours, or breach detection (`sla_sweep.rs` is that
//! crate's generic wait-node resume sweep; `escalation.rs` is an unrelated
//! privilege-escalation guard for workflow graphs). No SLA machinery existed
//! anywhere in the workspace to reuse, so this is new, deliberately narrow
//! work — see D-398's follow-up section for the full scope call.
//!
//! **Deliberately out of scope, same "don't guess a product decision"
//! reasoning `convert.rs` already applies to its required parent lookups:**
//! first-response SLA (would need a definition of "first response" from
//! ticket comments/notes that doesn't exist yet) — real, separate follow-up
//! work. The breach and warning sweeps are plain, directly testable functions
//! that the periodic `EngineJob::TicketSlaSweep` runs
//! (`crates/server/src/jobs.rs`, M73/D-422).
//!
//! **D-404 / M83 Phase 1:** when a policy's `calendar_ref` names an
//! `calendar`, due dates and elapsed time use `attome_calendar
//! ::BusinessCalendar` (real timezone, working days, holidays), loaded through
//! the shared `attome_core::calendar` loader. A policy with no
//! `calendar_ref` keeps the original `business_hours_start_minute`/
//! `business_hours_end_minute` UTC/Mon-Fri window math.
//!
//! **D-517: an SLA deadline is calculated or explicitly unresolved, never
//! invented.** Before D-517 a `calendar_ref` that could not be loaded fell
//! back to the UTC/Mon-Fri window, and a degenerate window fell back to plain
//! wall-clock time — both produced a deadline that looked contractual and was
//! not. Now a ticket whose SLA cannot be calculated is still created and
//! still carries its policy, but gets `resolution_due_at = NULL`,
//! `sla_calculation_status = 'unresolved'` and a `sla_unresolved_reason`; the
//! breach and warning sweeps skip it (a NULL deadline is neither met nor
//! breached), and `clock::recalculate_ticket` computes it once the
//! configuration is repaired. Every calculation, resolved or not, appends an
//! `service_sla_calculation` row recording the calendar id and content
//! hash it used — calendars stay mutable (later calculations use the current
//! calendar), the evidence of what each deadline was computed against does
//! not. The tz database version is recorded beside the hash, because a DST-rule
//! bump can move an answer while the hash stays put (D-621, amending D-517
//! ruling 2).

use attome_calendar::{BusinessCalendar, CalendarError, MAX_DAYS_SCAN};
use attome_core::EngineState;
use attome_core::calendar::{self, parse_calendar_ref};
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, Timelike, Utc, Weekday};
use serde::Serialize;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::TicketUpdate;

fn is_weekend(date: NaiveDate) -> bool {
    matches!(date.weekday(), Weekday::Sat | Weekday::Sun)
}

/// The next business day on/after `date` — `date` itself if it is not a
/// weekend. `None` past the end of the representable calendar.
fn next_business_day(mut date: NaiveDate) -> Option<NaiveDate> {
    while is_weekend(date) {
        date = date.succ_opt()?;
    }
    Some(date)
}

/// `date` at `minute_of_day` (UTC). `1440` is the next midnight.
fn at_minute_of_day(date: NaiveDate, minute_of_day: i32) -> Option<DateTime<Utc>> {
    date.and_time(NaiveTime::MIN)
        .checked_add_signed(Duration::minutes(i64::from(minute_of_day)))
        .map(|naive| naive.and_utc())
}

/// The window bounds once clamped to `0..=1440`, or
/// [`UnresolvedReason::BusinessHoursInvalid`] when they leave no business time.
fn legacy_window(start: i32, end: i32) -> Result<(i32, i32), UnresolvedReason> {
    let start = start.clamp(0, 1440);
    let end = end.clamp(start, 1440);
    if end == start {
        Err(UnresolvedReason::BusinessHoursInvalid)
    } else {
        Ok((start, end))
    }
}

/// Advances `start` by `target_minutes` of business time — minutes that fall
/// inside `[business_start_minute, business_end_minute)` (both expressed as
/// minutes-from-midnight UTC, e.g. `540`/`1020` for 09:00/17:00) on a
/// Monday–Friday. Weekend time and out-of-window time are skipped entirely,
/// not counted. `target_minutes <= 0` returns `start`.
///
/// A window with no business time in it (`business_end_minute <=
/// business_start_minute` once clamped) is
/// [`UnresolvedReason::BusinessHoursInvalid`]; a target that cannot be
/// reached within `attome_calendar::MAX_DAYS_SCAN` days is
/// [`UnresolvedReason::CalculationFailed`] (D-517 — neither degrades to
/// wall-clock time).
pub fn resolution_due_at(
    start: DateTime<Utc>,
    target_minutes: i64,
    business_start_minute: i32,
    business_end_minute: i32,
) -> Result<DateTime<Utc>, UnresolvedReason> {
    if target_minutes <= 0 {
        return Ok(start);
    }
    let (business_start_minute, business_end_minute) =
        legacy_window(business_start_minute, business_end_minute)?;
    let failed = UnresolvedReason::CalculationFailed;

    let mut date = start.date_naive();
    let mut minute_of_day = start.hour() as i32 * 60 + start.minute() as i32;

    if is_weekend(date) || minute_of_day >= business_end_minute {
        date = date.succ_opt().and_then(next_business_day).ok_or(failed)?;
        minute_of_day = business_start_minute;
    } else if minute_of_day < business_start_minute {
        minute_of_day = business_start_minute;
    }

    let mut remaining = target_minutes;
    for _ in 0..MAX_DAYS_SCAN {
        let minutes_left_today = i64::from(business_end_minute - minute_of_day);
        if remaining <= minutes_left_today {
            return at_minute_of_day(date, minute_of_day + remaining as i32).ok_or(failed);
        }
        remaining -= minutes_left_today;
        date = date.succ_opt().and_then(next_business_day).ok_or(failed)?;
        minute_of_day = business_start_minute;
    }
    Err(failed)
}

/// `pub(crate)` so `clock.rs` can hold a resolved policy and pass it back
/// into this module's own [`compute_elapsed`]/[`compute_due`] — its fields
/// stay private; `clock.rs` reads it only through the accessors below.
pub(crate) struct SlaPolicy {
    id: Uuid,
    resolution_target_minutes: i64,
    business_start_minute: i32,
    business_end_minute: i32,
    /// D-404 / M83 Phase 1: `service_sla_policy.calendar_ref`, a `text`
    /// attribute storing a `calendar.id`, kept raw. Blank means "no
    /// calendar configured, use the hour fields above"; any other value that
    /// does not resolve to a usable calendar leaves the SLA unresolved
    /// (D-517) — it is never read as "unset".
    calendar_ref: Option<String>,
}

/// Picks the active policy matching the ticket's priority, falling back to
/// an active `priority = 'any'` policy. `None` if neither exists — callers
/// treat that as "no SLA applies," not an error.
async fn select_policy_by_priority(
    db: &DbPool,
    priority: &str,
) -> Result<Option<SlaPolicy>, AppError> {
    let row: Option<(Uuid, f64, f64, f64, Option<String>)> = sqlx::query_as(
        "SELECT id, \
                resolution_target_minutes::double precision, \
                business_hours_start_minute::double precision, \
                business_hours_end_minute::double precision, \
                calendar_ref \
         FROM service_sla_policy \
         WHERE (is_active IS NULL OR is_active = true) AND priority = $1 \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(priority)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(|(id, target, start, end, calendar_ref)| SlaPolicy {
        id,
        resolution_target_minutes: target as i64,
        business_start_minute: start as i32,
        business_end_minute: end as i32,
        calendar_ref,
    }))
}

/// Why a ticket's SLA has no deadline (D-517) — the value stored in
/// `service_ticket.sla_unresolved_reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedReason {
    /// The policy's `calendar_ref` is malformed, names no active calendar,
    /// or names one whose stored definition is invalid.
    CalendarUnresolved,
    /// The calendar is valid but has no working time to run the target
    /// through.
    CalendarNoWorkingTime,
    /// The policy has no `calendar_ref` and its own hour window contains no
    /// business time.
    BusinessHoursInvalid,
    /// The arithmetic cannot produce a deadline (a target beyond the
    /// ten-year scan limit, or outside the representable date range).
    CalculationFailed,
}

impl UnresolvedReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CalendarUnresolved => "calendar_unresolved",
            Self::CalendarNoWorkingTime => "calendar_no_working_time",
            Self::BusinessHoursInvalid => "business_hours_invalid",
            Self::CalculationFailed => "calculation_failed",
        }
    }

    fn from_calendar_error(error: &CalendarError) -> Self {
        match error {
            CalendarError::NoWorkingTime => Self::CalendarNoWorkingTime,
            _ => Self::CalculationFailed,
        }
    }
}

/// A calculation that produced no value: the stored reason plus a detail for
/// the log and the evidence row.
#[derive(Debug, Clone)]
pub(crate) struct Unresolved {
    pub(crate) reason: UnresolvedReason,
    pub(crate) detail: String,
}

impl Unresolved {
    fn new(reason: UnresolvedReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl From<UnresolvedReason> for Unresolved {
    fn from(reason: UnresolvedReason) -> Self {
        let detail = match reason {
            UnresolvedReason::BusinessHoursInvalid => {
                "the policy's business-hours window contains no business time"
            }
            UnresolvedReason::CalculationFailed => {
                "the target cannot be reached within the calculation limits"
            }
            UnresolvedReason::CalendarUnresolved => "the policy's calendar cannot be used",
            UnresolvedReason::CalendarNoWorkingTime => "the calendar has no working time",
        };
        Self::new(reason, detail)
    }
}

/// The calendar content a calculation used — D-517 evidence, extended by
/// D-621. Every field is `None` for a policy on the plain hour window.
#[derive(Debug, Clone, Default)]
pub(crate) struct CalendarEvidence {
    pub(crate) calendar_ref: Option<String>,
    pub(crate) content_hash: Option<String>,
    /// The IANA tz database version the answer depended on (`"2025b"`), from
    /// [`attome_calendar::TZDB_VERSION`] by way of the loader. Recorded beside
    /// the hash so a tz-database bump that moves a deadline is visible in the
    /// evidence (D-621).
    pub(crate) tzdb_version: Option<String>,
}

/// A calculation's result together with what it was computed against.
pub(crate) struct Calculation<T> {
    pub(crate) outcome: Result<T, Unresolved>,
    pub(crate) evidence: CalendarEvidence,
}

enum BusinessTime {
    Calendar(BusinessCalendar),
    Window { start_minute: i32, end_minute: i32 },
}

/// Decides which business-time model a policy uses right now. A blank
/// `calendar_ref` is the plain hour window; a set one must resolve through
/// the shared loader or the calculation is unresolved — there is no fallback
/// from a configured calendar to the window.
async fn resolve_business_time(
    db: &DbPool,
    policy: &SlaPolicy,
) -> Result<(Result<BusinessTime, Unresolved>, CalendarEvidence), AppError> {
    let raw = policy.calendar_ref.as_deref();
    let mut evidence = CalendarEvidence {
        calendar_ref: raw
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        content_hash: None,
        tzdb_version: None,
    };
    let calendar_id = match parse_calendar_ref(raw) {
        Ok(Some(id)) => id,
        Ok(None) => {
            let window = BusinessTime::Window {
                start_minute: policy.business_start_minute,
                end_minute: policy.business_end_minute,
            };
            return Ok((Ok(window), evidence));
        }
        Err(unresolved) => {
            let unresolved =
                Unresolved::new(UnresolvedReason::CalendarUnresolved, unresolved.to_string());
            return Ok((Err(unresolved), evidence));
        }
    };
    match calendar::load_calendar(db, calendar_id).await? {
        Ok(loaded) => {
            evidence.content_hash = Some(loaded.content_hash);
            evidence.tzdb_version = Some(loaded.tzdb_version.to_string());
            Ok((Ok(BusinessTime::Calendar(loaded.calendar)), evidence))
        }
        Err(unresolved) => Ok((
            Err(Unresolved::new(
                UnresolvedReason::CalendarUnresolved,
                format!("calendar {calendar_id}: {unresolved}"),
            )),
            evidence,
        )),
    }
}

/// The due date for running `target_minutes` of business time forward from
/// `start` under the policy's *current* business-time model — the one
/// calculation `apply_policy`, resume and recalculation all share.
/// `target_minutes <= 0` is due at `start`: a budget already spent is due
/// immediately, not granted a fresh window.
pub(crate) async fn compute_due(
    db: &DbPool,
    policy: &SlaPolicy,
    start: DateTime<Utc>,
    target_minutes: i64,
) -> Result<Calculation<DateTime<Utc>>, AppError> {
    let (time, evidence) = resolve_business_time(db, policy).await?;
    let target_minutes = target_minutes.max(0);
    let outcome = time.and_then(|time| match time {
        BusinessTime::Calendar(cal) => {
            let duration = Duration::try_minutes(target_minutes)
                .ok_or_else(|| Unresolved::from(UnresolvedReason::CalculationFailed))?;
            cal.add_business_duration(start, duration).map_err(|e| {
                Unresolved::new(UnresolvedReason::from_calendar_error(&e), e.to_string())
            })
        }
        BusinessTime::Window {
            start_minute,
            end_minute,
        } => resolution_due_at(start, target_minutes, start_minute, end_minute)
            .map_err(Unresolved::from),
    });
    Ok(Calculation { outcome, evidence })
}

/// The business minutes between `a` and `b` under the plain UTC/Mon-Fri
/// hour-window model — the elapsed-time counterpart to [`resolution_due_at`]
/// (which advances a start by a target; this sums the window instead). Same
/// window rules: a window with no business time is
/// [`UnresolvedReason::BusinessHoursInvalid`] (D-517 — not wall-clock
/// minutes), a span longer than `attome_calendar::MAX_DAYS_SCAN` days is
/// [`UnresolvedReason::CalculationFailed`]. `b <= a` returns 0 (an
/// elapsed-time count is never negative) — a clock's "current segment" is
/// always `state_changed_at..=now`, never reversed.
pub fn business_minutes_elapsed(
    a: DateTime<Utc>,
    b: DateTime<Utc>,
    business_start_minute: i32,
    business_end_minute: i32,
) -> Result<i64, UnresolvedReason> {
    if b <= a {
        return Ok(0);
    }
    let (business_start_minute, business_end_minute) =
        legacy_window(business_start_minute, business_end_minute)?;

    let mut total: i64 = 0;
    let mut date = a.date_naive();
    let mut minute_of_day = a.hour() as i32 * 60 + a.minute() as i32;
    let end_date = b.date_naive();
    let end_minute_of_day = b.hour() as i32 * 60 + b.minute() as i32;

    for _ in 0..=MAX_DAYS_SCAN {
        if !is_weekend(date) {
            let day_start = minute_of_day.max(business_start_minute);
            let day_end = if date == end_date {
                end_minute_of_day.min(business_end_minute)
            } else {
                business_end_minute
            };
            if day_end > day_start {
                total += i64::from(day_end - day_start);
            }
        }
        if date == end_date {
            return Ok(total);
        }
        date = date.succ_opt().ok_or(UnresolvedReason::CalculationFailed)?;
        minute_of_day = 0;
    }
    Err(UnresolvedReason::CalculationFailed)
}

/// The business seconds between `start` and `end` (never negative) under
/// the policy's *current* business-time model — what a clock banks for one
/// running segment.
pub(crate) async fn compute_elapsed(
    db: &DbPool,
    policy: &SlaPolicy,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Calculation<i64>, AppError> {
    let (time, evidence) = resolve_business_time(db, policy).await?;
    let outcome = time.and_then(|time| match time {
        BusinessTime::Calendar(cal) => cal
            .business_duration_between(start, end)
            .map(|d| d.num_seconds().max(0))
            .map_err(|e| Unresolved::new(UnresolvedReason::from_calendar_error(&e), e.to_string())),
        BusinessTime::Window {
            start_minute,
            end_minute,
        } => business_minutes_elapsed(start, end, start_minute, end_minute)
            .map(|minutes| minutes * 60)
            .map_err(Unresolved::from),
    });
    Ok(Calculation { outcome, evidence })
}

impl SlaPolicy {
    pub(crate) fn id(&self) -> Uuid {
        self.id
    }

    /// The budget left after `elapsed_seconds` of business time were banked
    /// (negative once exhausted; [`compute_due`] treats that as due now).
    pub(crate) fn remaining_minutes(&self, elapsed_seconds: i64) -> i64 {
        self.resolution_target_minutes
            .saturating_sub(elapsed_seconds / 60)
    }
}

/// What prompted an SLA calculation — `service_sla_calculation.calculation_type`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CalculationType {
    Apply,
    Pause,
    Resume,
    Recalculate,
}

impl CalculationType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Recalculate => "recalculate",
        }
    }
}

/// One `service_sla_calculation` evidence row.
pub(crate) struct CalculationRecord<'a> {
    pub(crate) ticket_id: Uuid,
    pub(crate) policy_id: Option<Uuid>,
    pub(crate) calculation_type: CalculationType,
    pub(crate) unresolved: Option<&'a Unresolved>,
    pub(crate) evidence: &'a CalendarEvidence,
    pub(crate) start_at: DateTime<Utc>,
    pub(crate) end_at: Option<DateTime<Utc>>,
    pub(crate) target_minutes: Option<i64>,
    pub(crate) business_seconds: Option<i64>,
    pub(crate) result_due_at: Option<DateTime<Utc>>,
}

/// Appends the evidence row inside the caller's transaction (atomic with the
/// state change it explains), and logs an unresolved calculation at `error`
/// so an operator sees it without querying.
pub(crate) async fn record_calculation(
    conn: &mut PgConnection,
    record: CalculationRecord<'_>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO service_sla_calculation \
             (id, ticket_ref, sla_policy_ref, calculation_type, outcome, unresolved_reason, detail, \
              calendar_ref, calendar_content_hash, calendar_tzdb_version, start_at, end_at, \
              target_business_seconds, business_seconds, result_due_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(Uuid::now_v7())
    .bind(record.ticket_id)
    .bind(record.policy_id)
    .bind(record.calculation_type.as_str())
    .bind(if record.unresolved.is_some() {
        "unresolved"
    } else {
        "calculated"
    })
    .bind(record.unresolved.map(|u| u.reason.as_str()))
    .bind(record.unresolved.map(|u| u.detail.as_str()))
    .bind(record.evidence.calendar_ref.as_deref())
    .bind(record.evidence.content_hash.as_deref())
    .bind(record.evidence.tzdb_version.as_deref())
    .bind(record.start_at)
    .bind(record.end_at)
    .bind(record.target_minutes.map(|m| m.saturating_mul(60)))
    .bind(record.business_seconds)
    .bind(record.result_due_at)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    if let Some(unresolved) = record.unresolved {
        tracing::error!(
            ticket_id = %record.ticket_id,
            calculation_type = record.calculation_type.as_str(),
            reason = unresolved.reason.as_str(),
            detail = %unresolved.detail,
            "sla: deadline could not be calculated; the ticket's SLA is unresolved until its configuration is repaired and it is recalculated"
        );
    }
    Ok(())
}

/// Writes a ticket's SLA state: a calculated deadline, or no deadline with
/// an explicit unresolved reason.
pub(crate) async fn set_ticket_deadline(
    conn: &mut PgConnection,
    ticket_id: Uuid,
    outcome: Result<DateTime<Utc>, &Unresolved>,
) -> Result<(), AppError> {
    let (due_at, status, reason) = match outcome {
        Ok(due_at) => (Some(due_at), "calculated", None),
        Err(unresolved) => (None, "unresolved", Some(unresolved.reason.as_str())),
    };
    let updated = sqlx::query(
        "UPDATE service_ticket \
         SET resolution_due_at = $2, sla_calculation_status = $3, sla_unresolved_reason = $4 \
         WHERE id = $1",
    )
    .bind(ticket_id)
    .bind(due_at)
    .bind(status)
    .bind(reason)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// The policy matching the ticket's exact priority, or the `priority =
/// 'any'` fallback if none does.
async fn select_policy(db: &DbPool, priority: &str) -> Result<Option<SlaPolicy>, AppError> {
    if let Some(policy) = select_policy_by_priority(db, priority).await? {
        return Ok(Some(policy));
    }
    select_policy_by_priority(db, "any").await
}

/// M85 (Incident Management): the active policy matching `severity` exactly
/// — `service_sla_policy.severity`, unset on every pre-M85 policy. No `any`
/// fallback here (unlike `select_policy_by_priority`'s `priority = 'any'`
/// row): a severity-specific miss falls through to the ordinary
/// priority-based [`select_policy`] in [`select_policy_for_ticket`] below,
/// which already has its own `any` fallback — a second one here would just
/// mean two different policies could claim the same "no severity policy
/// matched" case.
async fn select_policy_by_severity(
    db: &DbPool,
    severity: &str,
) -> Result<Option<SlaPolicy>, AppError> {
    let row: Option<(Uuid, f64, f64, f64, Option<String>)> = sqlx::query_as(
        "SELECT id, \
                resolution_target_minutes::double precision, \
                business_hours_start_minute::double precision, \
                business_hours_end_minute::double precision, \
                calendar_ref \
         FROM service_sla_policy \
         WHERE (is_active IS NULL OR is_active = true) AND severity = $1 \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(severity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(|(id, target, start, end, calendar_ref)| SlaPolicy {
        id,
        resolution_target_minutes: target as i64,
        business_start_minute: start as i32,
        business_end_minute: end as i32,
        calendar_ref,
    }))
}

/// M85: the policy a ticket's SLA should use, given its `ticket_type`,
/// `priority`, and (for incidents) `severity`. For an incident-type ticket
/// with a `severity` set, a policy whose `service_sla_policy.severity` matches
/// wins first; anything else — a non-incident ticket, an incident with no
/// severity set, or an incident whose severity matches no active policy —
/// falls through to the existing priority-based [`select_policy`] unchanged.
/// This is purely additive: a deployment that has never set
/// `service_sla_policy.severity` on any row gets exactly the pre-M85 selection
/// for every ticket, incident or not.
async fn select_policy_for_ticket(
    db: &DbPool,
    ticket_type: Option<&str>,
    priority: &str,
    severity: Option<&str>,
) -> Result<Option<SlaPolicy>, AppError> {
    if ticket_type == Some("incident")
        && let Some(severity) = severity
        && let Some(policy) = select_policy_by_severity(db, severity).await?
    {
        return Ok(Some(policy));
    }
    select_policy(db, priority).await
}

/// G9-T2: whether an entitlement covers a ticket opened at `now` — active
/// (or with no status set) and inside its period, each end open when unset.
fn entitlement_applies(
    status: Option<&str>,
    period_start: Option<DateTime<Utc>>,
    period_end: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    status.is_none_or(|s| s == "active")
        && period_start.is_none_or(|start| start <= now)
        && period_end.is_none_or(|end| end >= now)
}

/// The entitlement columns G9-T2 reads: policy, status and period.
type EntitlementRow = (
    Option<Uuid>,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
);

/// G9-T2: the SLA policy of the entitlement the ticket is raised under (the
/// customer-service pack's `service_ticket.entitlement_ref` and
/// `entitlement.sla_policy_ref`), when that entitlement covers the ticket
/// now and names an active policy. `None` on a deployment without the pack,
/// a ticket with no entitlement, or an entitlement that does not apply, so
/// selection falls back to the policy rules.
async fn entitlement_policy(db: &DbPool, ticket_id: Uuid) -> Result<Option<SlaPolicy>, AppError> {
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('entitlement') IS NOT NULL             AND EXISTS (SELECT 1 FROM information_schema.columns                         WHERE table_schema = current_schema() AND table_name = 'service_ticket'                           AND column_name = 'entitlement_ref')             AND EXISTS (SELECT 1 FROM information_schema.columns                         WHERE table_schema = current_schema() AND table_name = 'entitlement'                           AND column_name = 'sla_policy_ref')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(None);
    }
    let row: Option<EntitlementRow> =
        sqlx::query_as(
            "SELECT e.sla_policy_ref, e.status::text,                     e.period_start::timestamptz, e.period_end::timestamptz              FROM service_ticket t JOIN entitlement e ON e.id = t.entitlement_ref              WHERE t.id = $1 AND (e.is_active IS NULL OR e.is_active = true)",
        )
        .bind(ticket_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
    let Some((Some(policy_id), status, start, end)) = row else {
        return Ok(None);
    };
    if !entitlement_applies(status.as_deref(), start, end, Utc::now()) {
        return Ok(None);
    }
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM service_sla_policy          WHERE id = $1 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(policy_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !active {
        return Ok(None);
    }
    policy_by_id(db, policy_id).await
}

/// The exact policy already assigned to a ticket (`service_ticket.sla_policy_id`)
/// — used by `clock.rs`'s pause/resume, which must recompute the *same*
/// policy's due date from a remaining budget, not re-run priority selection
/// (a policy's priority mapping may have changed since the ticket was
/// originally assigned one).
pub(crate) async fn policy_by_id(
    db: &DbPool,
    policy_id: Uuid,
) -> Result<Option<SlaPolicy>, AppError> {
    let row: Option<(Uuid, f64, f64, f64, Option<String>)> = sqlx::query_as(
        "SELECT id, \
                resolution_target_minutes::double precision, \
                business_hours_start_minute::double precision, \
                business_hours_end_minute::double precision, \
                calendar_ref \
         FROM service_sla_policy \
         WHERE id = $1",
    )
    .bind(policy_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(|(id, target, start, end, calendar_ref)| SlaPolicy {
        id,
        resolution_target_minutes: target as i64,
        business_start_minute: start as i32,
        business_end_minute: end as i32,
        calendar_ref,
    }))
}

/// `service_ticket.sla_calculation_status` (D-517).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SlaCalculationStatus {
    /// `resolution_due_at` holds a deadline calculated from a usable
    /// business-time model.
    Calculated,
    /// No deadline could be calculated; `resolution_due_at` is null and the
    /// ticket is neither within SLA nor breached until it is recalculated.
    Unresolved,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct ApplySlaPolicyResponse {
    pub sla_policy_id: Uuid,
    /// The calculated deadline; `null` when the SLA is unresolved.
    pub resolution_due_at: Option<DateTime<Utc>>,
    pub sla_calculation_status: SlaCalculationStatus,
    /// Why no deadline could be calculated; `null` when it was.
    pub sla_unresolved_reason: Option<UnresolvedReason>,
}

/// Assigns the ticket an SLA policy and calculates `resolution_due_at` from
/// now. M85: for an incident-type ticket, `severity` is tried first
/// ([`select_policy_for_ticket`]); every other ticket, and any incident whose
/// severity matches no policy, falls back to the pre-M85 priority-based
/// selection (then the `priority = 'any'` policy). `Ok(None)` (not an error)
/// when no policy matches at all, so a deployment that hasn't configured any
/// `service_sla_policy` rows yet doesn't fail every ticket operation.
///
/// D-517: a policy whose deadline cannot be calculated is still assigned —
/// the ticket carries its policy with `sla_calculation_status = unresolved`
/// and no deadline, never a substitute one. The assignment, the ticket's SLA
/// state and the evidence row commit together.
pub async fn apply_policy(
    db: &DbPool,
    ticket_id: Uuid,
) -> Result<Option<ApplySlaPolicyResponse>, AppError> {
    let row: Option<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT priority, ticket_type, severity FROM service_ticket WHERE id = $1")
            .bind(ticket_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let (priority, ticket_type, severity) = row.ok_or(AppError::NotFound)?;

    // G9-T2: the entitlement's SLA first (a case under a contract gets the
    // contract's SLA), then the policy rules.
    let selected = match entitlement_policy(db, ticket_id).await? {
        Some(policy) => Some(policy),
        None => {
            select_policy_for_ticket(db, ticket_type.as_deref(), &priority, severity.as_deref())
                .await?
        }
    };
    let Some(policy) = selected else {
        return Ok(None);
    };

    let start = Utc::now();
    let calculation = compute_due(db, &policy, start, policy.resolution_target_minutes).await?;
    let due_at = calculation.outcome.as_ref().ok().copied();
    let unresolved = calculation.outcome.as_ref().err();

    let mut tx = attome_db::tx::begin(db).await?;
    let assigned = sqlx::query("UPDATE service_ticket SET sla_policy_id = $2 WHERE id = $1")
        .bind(ticket_id)
        .bind(policy.id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if assigned.rows_affected() != 1 {
        return Err(AppError::internal(
            "ticket row vanished between read and update",
        ));
    }
    set_ticket_deadline(&mut tx, ticket_id, calculation.outcome.as_ref().copied()).await?;
    record_calculation(
        &mut tx,
        CalculationRecord {
            ticket_id,
            policy_id: Some(policy.id),
            calculation_type: CalculationType::Apply,
            unresolved,
            evidence: &calculation.evidence,
            start_at: start,
            end_at: None,
            target_minutes: Some(policy.resolution_target_minutes),
            business_seconds: None,
            result_due_at: due_at,
        },
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(Some(ApplySlaPolicyResponse {
        sla_policy_id: policy.id,
        resolution_due_at: due_at,
        sla_calculation_status: if unresolved.is_some() {
            SlaCalculationStatus::Unresolved
        } else {
            SlaCalculationStatus::Calculated
        },
        sla_unresolved_reason: unresolved.map(|u| u.reason),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/ticket/{id}/apply-sla-policy",
    tag = "service",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Policy applied", body = ApplySlaPolicyResponse),
        (status = 204, description = "No matching or fallback SLA policy is configured"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such ticket", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn apply_sla_policy(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<TicketUpdate>>,
    Path(ticket_id): Path<Uuid>,
) -> Result<Response, AppError> {
    match apply_policy(&state.base.db, ticket_id).await? {
        Some(response) => {
            // Plan 3.7 (I5): this route previously wrote no audit event at
            // all — the only SLA-mutating route in this file without one.
            attome_audit::write_business_event(
                &state,
                "service_ticket",
                ticket_id,
                attome_audit::AuditOperation::Update,
                "sla_policy.applied",
                ctx.user_id,
                None,
                None,
                format!(
                    "SLA policy {} applied; status {}",
                    response.sla_policy_id,
                    match response.sla_calculation_status {
                        SlaCalculationStatus::Calculated => "calculated",
                        SlaCalculationStatus::Unresolved => "unresolved",
                    }
                ),
            )
            .await;
            Ok((StatusCode::OK, Json(response)).into_response())
        }
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/ticket/{id}/apply-sla-policy",
        post(apply_sla_policy),
    )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own model.
#[derive(utoipa::OpenApi)]
#[openapi(paths(apply_sla_policy))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

const SWEEP_BATCH_SIZE: i64 = 500;

/// Finds open tickets whose `resolution_due_at` has passed and marks them
/// `sla_breached`, leaving a system-authored `note` (internal, not
/// customer-visible) recording the breach — the same `note`/
/// `entity_name`+`record_id` polymorphic attachment ticket comments already
/// use (D-398's follow-up), rather than a new notification integration.
///
/// M73/D-422: a ticket whose `service_sla_clock` is currently `paused` is
/// excluded — `resolution_due_at` is a fixed calendar timestamp computed the
/// last time the clock started running, and while paused no further business
/// time is accruing against it, so wall-clock time passing it must not count
/// as a breach (`clock::resume_ticket` recomputes `resolution_due_at` from
/// the remaining budget before the clock resumes ticking).
///
/// Also runs the M73/D-422 breach-escalation chain (`clock::
/// escalate_on_breach`) and the `sla.breached` domain event for each newly
/// breached ticket — best-effort, after the breach itself is durably
/// committed: a notification/event-emission failure must never make a real
/// breach look unrecorded. Returns the number of tickets newly marked
/// breached.
pub async fn sweep_breaches(
    db: &DbPool,
    notification_cfg: &attome_config::NotificationSection,
) -> Result<u64, AppError> {
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT t.id FROM service_ticket t \
         WHERE t.resolution_due_at IS NOT NULL AND t.resolution_due_at < NOW() \
           AND (t.sla_breached IS NULL OR t.sla_breached = false) \
           AND t.status NOT IN ('resolved', 'closed') \
           AND NOT EXISTS ( \
               SELECT 1 FROM service_sla_clock c \
               WHERE c.ticket_ref = t.id AND c.state = 'paused' \
           ) \
         LIMIT $1",
    )
    .bind(SWEEP_BATCH_SIZE)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut breached = 0u64;
    for ticket_id in due {
        let mut tx = attome_db::tx::begin(db).await?;

        let updated = sqlx::query(
            "UPDATE service_ticket SET sla_breached = true \
             WHERE id = $1 AND (sla_breached IS NULL OR sla_breached = false)",
        )
        .bind(ticket_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if updated.rows_affected() == 0 {
            // Another sweep pass (or a concurrent one) already caught it.
            tx.rollback().await.map_err(AppError::internal)?;
            continue;
        }

        sqlx::query(
            "INSERT INTO note (id, entity_name, record_id, note_text, is_customer_visible) \
             VALUES ($1, 'service_ticket', $2, 'SLA resolution target missed.', false)",
        )
        .bind(Uuid::now_v7())
        .bind(ticket_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

        tx.commit().await.map_err(AppError::internal)?;
        breached += 1;

        if let Err(e) = crate::clock::escalate_on_breach(db, notification_cfg, ticket_id).await {
            tracing::error!(
                error = %e,
                ticket_id = %ticket_id,
                "sla: post-breach escalation failed (ticket is still correctly marked breached)"
            );
        }
    }

    Ok(breached)
}

/// Pre-breach warning: a ticket whose elapsed *wall-clock* fraction of its
/// `[created_at, resolution_due_at]` span has crossed the assigned policy's
/// `warn_at_percent` gets `sla_warned = true` (a one-shot marker, mirroring
/// `sla_breached`'s own shape) and the `sla.warning` domain event, plus a
/// heads-up notification to the current assignee (proactive information, not
/// an escalation — `escalation_level` is untouched here).
///
/// **Why a wall-clock fraction, not a second calendar-aware business-seconds
/// computation.** `resolution_due_at` is already the calendar/fallback-aware
/// endpoint of `[created_at, resolution_due_at]` — that interval's *length*
/// already encodes however much business time the policy's target minutes
/// took to reach it. The fraction of that same interval elapsed in wall-clock
/// terms is therefore a sound, monotonic proxy for "how far through the SLA
/// window are we" that reaches exactly 100% at the same instant the breach
/// sweep above would fire, without a second per-row calendar lookup for every
/// candidate ticket on every sweep pass.
///
/// Same paused-clock exclusion as `sweep_breaches`, for the same reason: no
/// business time is accruing while paused, so no warning should fire either.
pub async fn sweep_warnings(
    db: &DbPool,
    notification_cfg: &attome_config::NotificationSection,
) -> Result<u64, AppError> {
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT t.id FROM service_ticket t \
         JOIN service_sla_policy p ON p.id = t.sla_policy_id \
         WHERE t.resolution_due_at IS NOT NULL \
           AND t.resolution_due_at > t.created_at \
           AND (t.sla_breached IS NULL OR t.sla_breached = false) \
           AND (t.sla_warned IS NULL OR t.sla_warned = false) \
           AND t.status NOT IN ('resolved', 'closed') \
           AND p.warn_at_percent IS NOT NULL \
           AND EXTRACT(EPOCH FROM (NOW() - t.created_at)) \
               / EXTRACT(EPOCH FROM (t.resolution_due_at - t.created_at)) * 100 \
               >= p.warn_at_percent::double precision \
           AND NOT EXISTS ( \
               SELECT 1 FROM service_sla_clock c \
               WHERE c.ticket_ref = t.id AND c.state = 'paused' \
           ) \
         LIMIT $1",
    )
    .bind(SWEEP_BATCH_SIZE)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut warned = 0u64;
    for ticket_id in due {
        let mut tx = attome_db::tx::begin(db).await?;

        let updated = sqlx::query(
            "UPDATE service_ticket SET sla_warned = true \
             WHERE id = $1 AND (sla_warned IS NULL OR sla_warned = false)",
        )
        .bind(ticket_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if updated.rows_affected() == 0 {
            tx.rollback().await.map_err(AppError::internal)?;
            continue;
        }

        attome_core::change_feed::emit_named(
            &mut tx,
            "service_ticket",
            ticket_id,
            attome_core::change_feed::ChangeOperation::Update,
            "sla.warning",
        )
        .await?;

        tx.commit().await.map_err(AppError::internal)?;
        warned += 1;

        if let Err(e) = crate::clock::notify_warning(db, notification_cfg, ticket_id).await {
            tracing::error!(
                error = %e,
                ticket_id = %ticket_id,
                "sla: post-warning notification failed (ticket is still correctly marked warned)"
            );
        }
    }

    Ok(warned)
}

#[cfg(test)]
mod sla_policy_selection {
    use super::entitlement_applies;
    use chrono::{Duration, Utc};

    #[test]
    fn an_active_entitlement_in_its_period_applies() {
        let now = Utc::now();
        assert!(entitlement_applies(
            Some("active"),
            Some(now - Duration::days(30)),
            Some(now + Duration::days(30)),
            now
        ));
        assert!(entitlement_applies(None, None, None, now), "open-ended");
    }

    #[test]
    fn an_expired_or_exhausted_entitlement_falls_back_to_the_rules() {
        let now = Utc::now();
        assert!(!entitlement_applies(Some("exhausted"), None, None, now));
        assert!(!entitlement_applies(
            Some("active"),
            None,
            Some(now - Duration::days(1)),
            now
        ));
        assert!(!entitlement_applies(
            Some("active"),
            Some(now + Duration::days(1)),
            None,
            now
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    /// Same-day: plenty of business time left before the window closes.
    #[test]
    fn same_day_within_the_window() {
        // Monday 2026-08-24 10:00, +120 business minutes, window 09:00-17:00.
        let start = utc(2026, 8, 24, 10, 0);
        assert_eq!(
            resolution_due_at(start, 120, 540, 1020),
            Ok(utc(2026, 8, 24, 12, 0))
        );
    }

    /// Rolls into the next business day when today's window runs out.
    #[test]
    fn rolls_into_the_next_business_day() {
        // Monday 16:00, +180 minutes (only 60 left today) -> 120 minutes
        // into Tuesday's window, i.e. Tuesday 11:00.
        let start = utc(2026, 8, 24, 16, 0);
        assert_eq!(
            resolution_due_at(start, 180, 540, 1020),
            Ok(utc(2026, 8, 25, 11, 0))
        );
    }

    /// Friday afternoon skips the weekend entirely, landing Monday.
    #[test]
    fn skips_the_weekend() {
        // Friday 2026-08-28 16:00, +180 minutes -> 60 left Friday, 120 into
        // Monday's window -> Monday 2026-08-31 11:00.
        let start = utc(2026, 8, 28, 16, 0);
        assert_eq!(
            resolution_due_at(start, 180, 540, 1020),
            Ok(utc(2026, 8, 31, 11, 0))
        );
    }

    /// Starting outside the window (before it opens) is pulled forward to
    /// the window's start, not treated as already-elapsed business time.
    #[test]
    fn starting_before_the_window_opens_pulls_forward() {
        let start = utc(2026, 8, 24, 6, 0);
        assert_eq!(
            resolution_due_at(start, 60, 540, 1020),
            Ok(utc(2026, 8, 24, 10, 0))
        );
    }

    /// Starting on a weekend jumps to the next Monday's window.
    #[test]
    fn starting_on_a_weekend_jumps_to_monday() {
        // Saturday 2026-08-29.
        let start = utc(2026, 8, 29, 12, 0);
        assert_eq!(
            resolution_due_at(start, 30, 540, 1020),
            Ok(utc(2026, 8, 31, 9, 30))
        );
    }

    /// A target spanning multiple full business days.
    #[test]
    fn spans_multiple_business_days() {
        // Monday 09:00, window is 8 hours (480 min)/day, target 20 hours
        // (1200 min) -> 2 full days (960) + 240 remaining -> Wednesday 13:00.
        let start = utc(2026, 8, 24, 9, 0);
        assert_eq!(
            resolution_due_at(start, 1200, 540, 1020),
            Ok(utc(2026, 8, 26, 13, 0))
        );
    }

    /// D-517: a window with no business time in it is an explicit reason,
    /// not a wall-clock deadline.
    #[test]
    fn degenerate_window_is_business_hours_invalid() {
        let start = utc(2026, 8, 24, 10, 0);
        assert_eq!(
            resolution_due_at(start, 120, 900, 900),
            Err(UnresolvedReason::BusinessHoursInvalid)
        );
    }

    /// A deadline landing exactly on a 24:00 window close is the next
    /// midnight — this used to panic building hour 24.
    #[test]
    fn a_deadline_at_a_midnight_window_close_does_not_panic() {
        let start = utc(2026, 8, 24, 23, 0); // Monday
        assert_eq!(
            resolution_due_at(start, 60, 0, 1440),
            Ok(utc(2026, 8, 25, 0, 0))
        );
    }

    /// A target the window can never reach within the scan limit fails
    /// rather than looping or guessing.
    #[test]
    fn an_unreachable_target_is_calculation_failed() {
        let start = utc(2026, 8, 24, 10, 0);
        assert_eq!(
            resolution_due_at(start, i64::MAX, 540, 541),
            Err(UnresolvedReason::CalculationFailed)
        );
    }

    /// Zero or negative targets return the start time unchanged.
    #[test]
    fn zero_target_returns_start_unchanged() {
        let start = utc(2026, 8, 24, 10, 0);
        assert_eq!(resolution_due_at(start, 0, 540, 1020), Ok(start));
    }

    // ── M73/D-422: `business_minutes_elapsed`, the elapsed-time counterpart
    // to `resolution_due_at` ─────────────────────────────────────────────────

    /// `resolution_due_at`'s own `same_day_within_the_window` case, inverted:
    /// advancing 120 business minutes from 10:00 lands at 12:00, so the
    /// elapsed business minutes between those two instants must be 120.
    #[test]
    fn elapsed_matches_the_forward_calculator_same_day() {
        let start = utc(2026, 8, 24, 10, 0);
        let end = utc(2026, 8, 24, 12, 0);
        assert_eq!(business_minutes_elapsed(start, end, 540, 1020), Ok(120));
    }

    /// `resolution_due_at`'s `rolls_into_the_next_business_day` case,
    /// inverted: Monday 16:00 -> Tuesday 11:00 is 180 business minutes (60
    /// left Monday + 120 into Tuesday), even though ~19 wall-clock hours pass.
    #[test]
    fn elapsed_excludes_the_overnight_gap() {
        let start = utc(2026, 8, 24, 16, 0);
        let end = utc(2026, 8, 25, 11, 0);
        assert_eq!(business_minutes_elapsed(start, end, 540, 1020), Ok(180));
    }

    /// `resolution_due_at`'s `skips_the_weekend` case, inverted: Friday 16:00
    /// -> Monday 11:00 is 180 business minutes, with the whole weekend
    /// excluded even though ~67 wall-clock hours pass.
    #[test]
    fn elapsed_excludes_the_weekend() {
        let start = utc(2026, 8, 28, 16, 0); // Friday
        let end = utc(2026, 8, 31, 11, 0); // Monday
        assert_eq!(business_minutes_elapsed(start, end, 540, 1020), Ok(180));
    }

    /// A span with no elapsed time (or `end` before `start`) is zero, not
    /// negative — a clock's "current running segment" is never reversed.
    #[test]
    fn elapsed_is_zero_when_end_does_not_come_after_start() {
        let a = utc(2026, 8, 24, 10, 0);
        assert_eq!(business_minutes_elapsed(a, a, 540, 1020), Ok(0));
        assert_eq!(
            business_minutes_elapsed(a, a - chrono::Duration::hours(1), 540, 1020),
            Ok(0)
        );
    }

    /// D-517: a degenerate window is an explicit reason, mirroring
    /// `resolution_due_at` for the same malformed input — not wall-clock
    /// minutes.
    #[test]
    fn elapsed_degenerate_window_is_business_hours_invalid() {
        let start = utc(2026, 8, 24, 10, 0);
        let end = utc(2026, 8, 24, 12, 0);
        assert_eq!(
            business_minutes_elapsed(start, end, 900, 900),
            Err(UnresolvedReason::BusinessHoursInvalid)
        );
    }

    // ── D-404 / M83 Phase 1: the calendar-aware path, DB-backed ─────────────

    async fn test_db() -> Option<DbPool> {
        let url = attome_testkit::migrated_db_url()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(5)
                .connect(&url)
                .await
                .expect("failed to connect to DATABASE_URL"),
        )
    }

    async fn insert_calendar(db: &DbPool, working_days: &[&str], hours: serde_json::Value) -> Uuid {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO calendar (id, name, tz, working_days, hours, is_active, owner_layer) \
             VALUES ($1, $2, 'UTC', $3, $4, true, 'project')",
        )
        .bind(id)
        .bind(format!("sla-test-calendar-{id}"))
        .bind(
            working_days
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        )
        .bind(hours)
        .execute(db)
        .await
        .expect("insert calendar");
        id
    }

    async fn insert_holiday(db: &DbPool, calendar_id: Uuid, name: &str, date: NaiveDate) {
        sqlx::query(
            "INSERT INTO calendar_holiday (id, calendar_id, name, holiday_date, is_active, owner_layer) \
             VALUES ($1, $2, $3, $4, true, 'project')",
        )
        .bind(Uuid::now_v7())
        .bind(calendar_id)
        .bind(name)
        .bind(date)
        .execute(db)
        .await
        .expect("insert calendar_holiday");
    }

    fn sun_thu_hours() -> serde_json::Value {
        let window = serde_json::json!([{ "start_minute": 540, "end_minute": 1020 }]);
        serde_json::json!({
            "sun": window, "mon": window, "tue": window, "wed": window, "thu": window,
        })
    }

    fn policy(calendar_ref: Option<String>, start_minute: i32, end_minute: i32) -> SlaPolicy {
        SlaPolicy {
            id: Uuid::now_v7(),
            resolution_target_minutes: 8 * 60,
            business_start_minute: start_minute,
            business_end_minute: end_minute,
            calendar_ref,
        }
    }

    fn unresolved_reason(calc: &Calculation<DateTime<Utc>>) -> UnresolvedReason {
        match &calc.outcome {
            Err(unresolved) => unresolved.reason,
            Ok(due) => panic!("expected an unresolved SLA, got a deadline of {due}"),
        }
    }

    /// M83 §5's Phase 1 acceptance test, exercised through `compute_due`
    /// exactly as `apply_policy` calls it: a ticket opened Thursday 16:00
    /// with an 8-business-hour resolution target, on a Sun-Thu working
    /// calendar with a Friday holiday, is due Sunday 16:00 — NOT Friday. The
    /// calculation also carries the calendar's id and content hash.
    #[tokio::test]
    async fn acceptance_calendar_ref_thursday_8h_due_sunday_not_friday() {
        let db = attome_testkit::skip_if_no_db!(test_db().await);
        let calendar_id =
            insert_calendar(&db, &["sun", "mon", "tue", "wed", "thu"], sun_thu_hours()).await;
        insert_holiday(
            &db,
            calendar_id,
            "Test Holiday",
            NaiveDate::from_ymd_opt(2026, 8, 28).unwrap(), // Friday
        )
        .await;

        let policy = policy(Some(calendar_id.to_string()), 540, 1020);
        let opened = utc(2026, 8, 27, 16, 0); // Thursday 16:00
        let calc = compute_due(&db, &policy, opened, policy.resolution_target_minutes)
            .await
            .expect("compute_due");

        let due = calc
            .outcome
            .as_ref()
            .copied()
            .expect("a calculated deadline");
        assert_eq!(due, utc(2026, 8, 30, 16, 0), "must be Sunday, not Friday");
        assert_eq!(due.weekday(), Weekday::Sun);
        assert_eq!(
            calc.evidence.calendar_ref.as_deref(),
            Some(calendar_id.to_string().as_str())
        );
        assert_eq!(
            calc.evidence.content_hash.as_ref().map(String::len),
            Some(64)
        );
        assert_eq!(
            calc.evidence.tzdb_version.as_deref(),
            Some(attome_calendar::TZDB_VERSION),
            "D-621: the tz database version is recorded beside the content hash"
        );
    }

    /// `calendar_ref` unset reproduces the original hour-window math exactly.
    #[tokio::test]
    async fn no_calendar_ref_uses_the_business_hours_window() {
        let db = attome_testkit::skip_if_no_db!(test_db().await);
        let policy = policy(None, 540, 1020);
        let start = utc(2026, 8, 24, 16, 0); // Monday 16:00
        let calc = compute_due(&db, &policy, start, 180)
            .await
            .expect("compute_due");
        assert_eq!(
            calc.outcome.ok(),
            resolution_due_at(start, 180, 540, 1020).ok()
        );
        assert!(calc.evidence.calendar_ref.is_none());
    }

    /// D-517: a `calendar_ref` naming a calendar that does not exist leaves
    /// the SLA unresolved — it must NOT fall back to the hour window.
    #[tokio::test]
    async fn calendar_ref_to_a_missing_calendar_is_unresolved_not_a_fallback() {
        let db = attome_testkit::skip_if_no_db!(test_db().await);
        let policy = policy(Some(Uuid::now_v7().to_string()), 540, 1020);
        let calc = compute_due(&db, &policy, utc(2026, 8, 24, 16, 0), 180)
            .await
            .expect("compute_due must not error on a dangling calendar_ref");
        assert_eq!(
            unresolved_reason(&calc),
            UnresolvedReason::CalendarUnresolved
        );
    }

    #[tokio::test]
    async fn a_malformed_calendar_ref_is_unresolved_not_treated_as_unset() {
        let db = attome_testkit::skip_if_no_db!(test_db().await);
        let policy = policy(Some("uae-hq".into()), 540, 1020);
        let calc = compute_due(&db, &policy, utc(2026, 8, 24, 16, 0), 180)
            .await
            .expect("compute_due");
        assert_eq!(
            unresolved_reason(&calc),
            UnresolvedReason::CalendarUnresolved
        );
    }

    /// A stored definition the strict loader rejects (here an unknown weekday
    /// code, which the pre-D-517 loader silently dropped) is unresolved.
    #[tokio::test]
    async fn an_invalid_stored_calendar_is_unresolved_not_partially_loaded() {
        let db = attome_testkit::skip_if_no_db!(test_db().await);
        let window = serde_json::json!([{ "start_minute": 540, "end_minute": 1020 }]);
        let calendar_id = insert_calendar(
            &db,
            &["monday", "tue"],
            serde_json::json!({ "monday": window, "tue": window }),
        )
        .await;
        let policy = policy(Some(calendar_id.to_string()), 540, 1020);
        let calc = compute_due(&db, &policy, utc(2026, 8, 24, 16, 0), 180)
            .await
            .expect("compute_due");
        assert_eq!(
            unresolved_reason(&calc),
            UnresolvedReason::CalendarUnresolved
        );
    }

    /// A valid calendar with no working time is a different state from an
    /// unresolvable one.
    #[tokio::test]
    async fn a_calendar_with_no_working_time_is_its_own_reason() {
        let db = attome_testkit::skip_if_no_db!(test_db().await);
        let calendar_id = insert_calendar(&db, &[], serde_json::json!({})).await;
        let policy = policy(Some(calendar_id.to_string()), 540, 1020);
        let calc = compute_due(&db, &policy, utc(2026, 8, 24, 16, 0), 180)
            .await
            .expect("compute_due");
        assert_eq!(
            unresolved_reason(&calc),
            UnresolvedReason::CalendarNoWorkingTime
        );
        assert!(calc.evidence.content_hash.is_some());
    }
}

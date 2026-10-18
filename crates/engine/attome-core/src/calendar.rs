//! Business-calendar resolution (D-404 / D-517): the one place that turns an
//! `calendar` row and its holidays into a validated
//! [`attome_calendar::BusinessCalendar`].
//!
//! Before D-517 every consumer carried its own copy of this loader (SLA,
//! resource capacity), and each one quietly dropped whatever it could not
//! parse — an unknown weekday code like `"monday"` simply vanished, leaving a
//! calendar with less (or no) working time that still "loaded". Now:
//!
//! - [`build_calendar`] is strict: an unknown weekday, a malformed range,
//!   overlapping ranges, hours for a non-working day or a working day without
//!   hours is an [`InvalidCalendarDefinition`], never a partial calendar. The
//!   admin API and bundle reconcile run it before writing, so a bad
//!   definition is rejected at the door; the loader runs it again on read,
//!   so a row written before D-517 cannot slip through either.
//! - [`load_calendar`] distinguishes *why* a calendar is unusable
//!   ([`CalendarUnresolved`]) from infrastructure failure (`AppError`), so a
//!   caller can put its own record into an explicit state instead of
//!   substituting a different calendar.
//! - Per-date exceptions (D-592) are part of the calendar: [`load_calendar`]
//!   reads them, and [`parse_exception_ranges`] is the one parser the admin
//!   API, the bundle reconcile and the loader share for their `ranges`.
//! - [`content_hash`] fingerprints exactly what a calculation used, so a
//!   caller can record it as evidence (D-517: calendars stay mutable; the
//!   evidence does not). The tz database version is the one input that
//!   fingerprint cannot carry, so [`LoadedCalendar::tzdb_version`] exposes
//!   it for the caller to record beside the hash (D-621).
//!
//! This module owns loading only. Which calendar a record uses, and what an
//! unresolved one means for that record, belong to the consuming engine.

/// AG1: the Umm al-Qura Hijri calendar, for crates that reach the calendar
/// through this one.
pub use attome_calendar::hijri;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use attome_calendar::{
    BusinessCalendar, CalendarError, TZDB_VERSION, TimeRange, parse_weekday_code, weekday_code,
};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Datelike, NaiveDate};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// A calendar definition that cannot be turned into a `BusinessCalendar`;
/// the message is actionable for the administrator who wrote it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidCalendarDefinition(pub String);

/// Why a calendar reference could not be used. Distinct from a valid
/// calendar that happens to have no working time — that one resolves, and
/// the arithmetic reports `CalendarError::NoWorkingTime` itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarUnresolved {
    /// The reference is set but is not a calendar id at all.
    MalformedReference(String),
    /// No active calendar has this id (never existed, or deleted).
    NotFound,
    /// The stored definition fails validation.
    Invalid(String),
}

impl std::fmt::Display for CalendarUnresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedReference(raw) => write!(f, "'{raw}' is not a calendar id"),
            Self::NotFound => f.write_str("no active calendar has this id"),
            Self::Invalid(reason) => write!(f, "the calendar definition is invalid: {reason}"),
        }
    }
}

/// A calendar ready for arithmetic, with the fingerprint of its content.
#[derive(Debug, Clone)]
pub struct LoadedCalendar {
    pub id: Uuid,
    pub calendar: BusinessCalendar,
    pub content_hash: String,
    /// The IANA tz database version this calendar's answers depend on
    /// (`attome_calendar::TZDB_VERSION`, e.g. `"2025b"`).
    ///
    /// [`Self::content_hash`] covers the calendar definition only: the DST
    /// rules that decide where a range's bounds land come from the compiled
    /// database, and a bump can move an answer while the hash stays put. A
    /// caller that records the hash as evidence records this beside it
    /// (D-621, amending D-517 ruling 2).
    pub tzdb_version: &'static str,
    /// Z12-T4: the calendar's content version, bumped when its loaded
    /// definition (inherited parts included) changes.
    pub version: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRange {
    start_minute: u16,
    end_minute: u16,
}

const WEEKDAY_HINT: &str = "use one of mon, tue, wed, thu, fri, sat, sun";

/// The minute a day ends (a 24/7 day is `[0, DAY_END)`).
const DAY_END: u16 = 1440;

/// Z12-T4: the most calendars in an inheritance chain (a calendar, its
/// parent and its grandparent).
pub const MAX_CALENDAR_DEPTH: usize = 3;

/// Validates a calendar definition in its stored/wire shape — `tz` an IANA
/// zone name, `working_days` weekday codes, `hours` an object of weekday code
/// to `[{"start_minute", "end_minute"}]` — and builds the calendar.
/// `exceptions` are already parsed ([`parse_exception_ranges`]); their
/// overlap and bounds rules are checked here with the rest.
/// A4-T1: the current time in the deployment's time zone (`app.time_zone`,
/// an IANA name). An unset or unknown name is UTC, logged once.
pub fn deployment_now(time_zone: Option<&str>) -> chrono::DateTime<chrono::FixedOffset> {
    use chrono::Utc;
    let now = Utc::now();
    match time_zone.map(str::trim).filter(|name| !name.is_empty()) {
        None => now.fixed_offset(),
        Some(name) => match name.parse::<chrono_tz::Tz>() {
            Ok(tz) => now.with_timezone(&tz).fixed_offset(),
            Err(_) => {
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(
                        time_zone = name,
                        "app.time_zone is not a known IANA time zone; using UTC"
                    );
                });
                now.fixed_offset()
            }
        },
    }
}

pub fn build_calendar(
    tz: &str,
    working_days: &[String],
    hours: &serde_json::Value,
    holidays: BTreeSet<NaiveDate>,
    exceptions: BTreeMap<NaiveDate, Vec<TimeRange>>,
) -> Result<BusinessCalendar, InvalidCalendarDefinition> {
    let invalid = |message: String| InvalidCalendarDefinition(message);
    let tz_name = tz.trim();
    let tz: chrono_tz::Tz = tz_name
        .parse()
        .map_err(|_| invalid(format!("'{tz_name}' is not a recognized IANA timezone")))?;

    let mut days = HashSet::new();
    for code in working_days {
        let day = parse_weekday_code(code.trim())
            .ok_or_else(|| invalid(format!("'{code}' is not a weekday; {WEEKDAY_HINT}")))?;
        if !days.insert(day) {
            return Err(invalid(format!(
                "working day '{}' is listed more than once",
                weekday_code(day)
            )));
        }
    }

    let Some(hours) = hours.as_object() else {
        return Err(invalid("hours must be an object keyed by weekday".into()));
    };
    let mut ranges_by_day: HashMap<chrono::Weekday, Vec<TimeRange>> = HashMap::new();
    let mut given = HashSet::new();
    for (code, ranges) in hours {
        let day = parse_weekday_code(code.trim()).ok_or_else(|| {
            invalid(format!(
                "hours key '{code}' is not a weekday; {WEEKDAY_HINT}"
            ))
        })?;
        let wire: Vec<WireRange> = serde_json::from_value(ranges.clone()).map_err(|e| {
            invalid(format!(
                "hours for '{code}' must be a list of {{\"start_minute\", \"end_minute\"}} ranges: {e}"
            ))
        })?;
        if !given.insert(day) {
            return Err(invalid(format!(
                "hours for '{}' are given more than once",
                weekday_code(day)
            )));
        }
        for r in wire {
            if r.start_minute > r.end_minute && r.start_minute < DAY_END {
                // Z12-T4: an overnight range (22:00 to 06:00) runs to midnight
                // and on into the next weekday, which it makes a working day.
                ranges_by_day
                    .entry(day)
                    .or_default()
                    .push(TimeRange::new(r.start_minute, DAY_END));
                if r.end_minute > 0 {
                    let next = day.succ();
                    ranges_by_day
                        .entry(next)
                        .or_default()
                        .push(TimeRange::new(0, r.end_minute));
                    days.insert(next);
                }
            } else {
                ranges_by_day
                    .entry(day)
                    .or_default()
                    .push(TimeRange::new(r.start_minute, r.end_minute));
            }
        }
    }

    BusinessCalendar::new(tz, days, ranges_by_day, holidays, exceptions).map_err(|e| match e {
        CalendarError::InvalidCalendar(reason) => invalid(reason),
        other => invalid(other.to_string()),
    })
}

/// Validates a definition without holidays — what a write path checks.
pub fn validate_definition(
    tz: &str,
    working_days: &[String],
    hours: &serde_json::Value,
) -> Result<(), InvalidCalendarDefinition> {
    build_calendar(tz, working_days, hours, BTreeSet::new(), BTreeMap::new()).map(|_| ())
}

/// Parses and validates one exception's `ranges` — a list of
/// `{"start_minute", "end_minute"}` on `date`; empty closes the date
/// (D-592). The same bounds and overlap rules as weekday hours, checked by
/// `attome-calendar` itself so the two can never disagree.
pub fn parse_exception_ranges(
    date: NaiveDate,
    ranges: &serde_json::Value,
) -> Result<Vec<TimeRange>, InvalidCalendarDefinition> {
    let wire: Vec<WireRange> = serde_json::from_value(ranges.clone()).map_err(|e| {
        InvalidCalendarDefinition(format!(
            "ranges for exception {date} must be a list of {{\"start_minute\", \"end_minute\"}} ranges: {e}"
        ))
    })?;
    let ranges: Vec<TimeRange> = wire
        .into_iter()
        .map(|r| TimeRange::new(r.start_minute, r.end_minute))
        .collect();
    BusinessCalendar::new(
        chrono_tz::UTC,
        HashSet::new(),
        HashMap::new(),
        BTreeSet::new(),
        BTreeMap::from([(date, ranges)]),
    )
    .map(|calendar| {
        calendar
            .exceptions()
            .get(&date)
            .cloned()
            .unwrap_or_default()
    })
    .map_err(|e| InvalidCalendarDefinition(e.to_string()))
}

/// Hex SHA-256 of [`BusinessCalendar::canonical_form`]: equal exactly when two
/// calendars give identical answers.
pub fn content_hash(calendar: &BusinessCalendar) -> String {
    hex::encode(Sha256::digest(calendar.canonical_form().as_bytes()))
}

/// Parses a text calendar reference (`calendar_ref` attributes and settings
/// store an `calendar.id` as text). Blank means "no calendar
/// configured"; anything else must be a UUID — a malformed value is not
/// quietly treated as unset.
pub fn parse_calendar_ref(raw: Option<&str>) -> Result<Option<Uuid>, CalendarUnresolved> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(value) => Uuid::parse_str(value)
            .map(Some)
            .map_err(|_| CalendarUnresolved::MalformedReference(value.to_string())),
    }
}

/// One calendar of an inheritance chain, as stored.
#[derive(Debug, Clone, Default)]
pub struct CalendarLayer {
    pub tz: String,
    pub working_days: Vec<String>,
    pub hours: serde_json::Value,
    pub holidays: Vec<NaiveDate>,
    pub exceptions: Vec<(NaiveDate, serde_json::Value)>,
    /// `(rule id, rule, needs a sighting)`.
    pub rules: Vec<(Uuid, attome_calendar::rules::HolidayRule, bool)>,
    pub seasons: Vec<attome_calendar::rules::Season>,
}

/// A chain merged root first: the definition a calendar answers with.
#[derive(Debug, Clone, PartialEq)]
pub struct MergedDefinition {
    pub tz: String,
    pub working_days: Vec<String>,
    pub hours: serde_json::Value,
    pub holidays: BTreeSet<NaiveDate>,
    pub exceptions: BTreeMap<NaiveDate, Vec<TimeRange>>,
}

fn hours_given(hours: &serde_json::Value) -> bool {
    hours.as_object().is_some_and(|o| !o.is_empty())
}

/// Z12-T4: merges `layers` (root first, the calendar itself last). A layer's
/// non-empty working days and hours replace the ones above it, and its zone
/// is the zone; holidays are unioned, and per date a layer's exception (or
/// season hours, which its own exceptions override) wins over its parent's.
/// Holiday rules and seasons are expanded for `years`, a confirmed sighting
/// (`sightings`, by rule and Hijri year) moving a sighted Hijri holiday.
pub fn merge_layers(
    layers: &[CalendarLayer],
    sightings: &HashMap<(Uuid, i32), NaiveDate>,
    years: std::ops::RangeInclusive<i32>,
) -> Result<MergedDefinition, InvalidCalendarDefinition> {
    let invalid = |e: CalendarError| InvalidCalendarDefinition(e.to_string());
    let mut merged = MergedDefinition {
        tz: String::new(),
        working_days: Vec::new(),
        hours: serde_json::json!({}),
        holidays: BTreeSet::new(),
        exceptions: BTreeMap::new(),
    };
    for layer in layers {
        if !layer.tz.trim().is_empty() {
            merged.tz.clone_from(&layer.tz);
        }
        if !layer.working_days.is_empty() {
            merged.working_days.clone_from(&layer.working_days);
        }
        if hours_given(&layer.hours) {
            merged.hours = layer.hours.clone();
        }
        merged.holidays.extend(layer.holidays.iter().copied());
        for (id, rule, needs_sighting) in &layer.rules {
            for year in years.clone() {
                merged.holidays.extend(
                    rule_dates(*id, rule, *needs_sighting, sightings, year).map_err(invalid)?,
                );
            }
        }
        let mut own = BTreeMap::new();
        for season in &layer.seasons {
            for year in years.clone() {
                own.extend(attome_calendar::rules::expand_season(season, year).map_err(invalid)?);
            }
        }
        for (date, ranges) in &layer.exceptions {
            own.insert(*date, parse_exception_ranges(*date, ranges)?);
        }
        merged.exceptions.extend(own);
    }
    Ok(merged)
}

/// The dates `rule` closes for holidays starting in `year`; for a sighted
/// Hijri rule, a confirmed start replaces the expected one for that Hijri
/// year.
pub fn rule_dates(
    rule_id: Uuid,
    rule: &attome_calendar::rules::HolidayRule,
    needs_sighting: bool,
    sightings: &HashMap<(Uuid, i32), NaiveDate>,
    year: i32,
) -> Result<Vec<NaiveDate>, CalendarError> {
    use attome_calendar::rules::{HolidayRule, expand};
    let HolidayRule::Hijri {
        month,
        day,
        span_days,
    } = rule
    else {
        return expand(rule, year);
    };
    if !needs_sighting {
        return expand(rule, year);
    }
    let first_only = HolidayRule::Hijri {
        month: *month,
        day: *day,
        span_days: 1,
    };
    let mut out = Vec::new();
    for expected in expand(&first_only, year)? {
        let hijri_year = i32::from(attome_calendar::hijri::to_hijri(expected)?.year);
        let start = sightings
            .get(&(rule_id, hijri_year))
            .copied()
            .unwrap_or(expected);
        out.extend(
            (0..i64::from(*span_days))
                .filter_map(|n| start.checked_add_signed(chrono::Duration::days(n))),
        );
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

type CalendarRow = (String, Vec<String>, serde_json::Value, Option<Uuid>);

/// The chain from `calendar_id` up, the calendar itself first.
async fn load_chain(
    db: &DbPool,
    calendar_id: Uuid,
) -> Result<Result<Vec<(Uuid, CalendarRow)>, CalendarUnresolved>, AppError> {
    let mut chain = Vec::new();
    let mut next = Some(calendar_id);
    while let Some(id) = next {
        if chain.iter().any(|(seen, _)| *seen == id) {
            return Ok(Err(CalendarUnresolved::Invalid(format!(
                "calendar {calendar_id} inherits from itself through {id}"
            ))));
        }
        if chain.len() == MAX_CALENDAR_DEPTH {
            return Ok(Err(CalendarUnresolved::Invalid(format!(
                "calendar {calendar_id} inherits through more than {MAX_CALENDAR_DEPTH} levels"
            ))));
        }
        let row: Option<CalendarRow> = sqlx::query_as(
            "SELECT tz, working_days, hours, parent_calendar_id FROM calendar \
              WHERE id = $1 AND is_active = true",
        )
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let Some(row) = row else {
            if id == calendar_id {
                tracing::warn!(calendar_id = %calendar_id, "calendar: no active calendar has this id");
                return Ok(Err(CalendarUnresolved::NotFound));
            }
            return Ok(Err(CalendarUnresolved::Invalid(format!(
                "calendar {calendar_id} inherits from {id}, which is not an active calendar"
            ))));
        };
        next = row.3;
        chain.push((id, row));
    }
    Ok(Ok(chain))
}

/// Loads an active calendar with what it inherits (Z12-T4): its parent chain
/// merged ([`merge_layers`]), holiday rules and seasons expanded for last
/// year to two years ahead, confirmed sightings applied, and its content
/// version kept ([`LoadedCalendar::version`]). The outer `Result` is
/// infrastructure failure; the inner one is whether this calendar is usable.
pub async fn load_calendar(
    db: &DbPool,
    calendar_id: Uuid,
) -> Result<Result<LoadedCalendar, CalendarUnresolved>, AppError> {
    let chain = match load_chain(db, calendar_id).await? {
        Ok(chain) => chain,
        Err(unresolved) => return Ok(Err(unresolved)),
    };
    let ids: Vec<Uuid> = chain.iter().map(|(id, _)| *id).collect();

    let holidays: Vec<(Uuid, NaiveDate)> = sqlx::query_as(
        "SELECT calendar_id, holiday_date FROM calendar_holiday \
          WHERE calendar_id = ANY($1) AND is_active = true",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let exceptions: Vec<(Uuid, NaiveDate, serde_json::Value)> = sqlx::query_as(
        "SELECT calendar_id, exception_date, ranges FROM calendar_exception \
          WHERE calendar_id = ANY($1) AND is_active = true",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rules: Vec<(Uuid, Uuid, serde_json::Value, bool)> = sqlx::query_as(
        "SELECT calendar_id, id, rule, needs_sighting FROM calendar_holiday_rule \
          WHERE calendar_id = ANY($1) AND is_active = true",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let seasons: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
        "SELECT calendar_id, definition FROM calendar_season \
          WHERE calendar_id = ANY($1) AND is_active = true",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rule_ids: Vec<Uuid> = rules.iter().map(|r| r.1).collect();
    let sightings: HashMap<(Uuid, i32), NaiveDate> = if rule_ids.is_empty() {
        HashMap::new()
    } else {
        sqlx::query_as::<_, (Uuid, i32, NaiveDate)>(
            "SELECT rule_id, hijri_year, confirmed_start FROM calendar_sighting \
              WHERE rule_id = ANY($1)",
        )
        .bind(&rule_ids)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(rule, year, start)| ((rule, year), start))
        .collect()
    };

    let mut layers = Vec::with_capacity(chain.len());
    // Root first: the chain was read from the calendar up.
    for (id, (tz, working_days, hours, _)) in chain.into_iter().rev() {
        let mut layer = CalendarLayer {
            tz,
            working_days,
            hours,
            ..CalendarLayer::default()
        };
        layer.holidays = holidays
            .iter()
            .filter(|(c, _)| *c == id)
            .map(|(_, d)| *d)
            .collect();
        layer.exceptions = exceptions
            .iter()
            .filter(|(c, _, _)| *c == id)
            .map(|(_, d, r)| (*d, r.clone()))
            .collect();
        for (c, rule_id, rule, needs_sighting) in &rules {
            if *c != id {
                continue;
            }
            match serde_json::from_value(rule.clone()) {
                Ok(rule) => layer.rules.push((*rule_id, rule, *needs_sighting)),
                Err(e) => {
                    return Ok(Err(invalid_definition(
                        calendar_id,
                        format!("holiday rule {rule_id} is not a rule: {e}"),
                    )));
                }
            }
        }
        for (c, definition) in &seasons {
            if *c != id {
                continue;
            }
            match serde_json::from_value(definition.clone()) {
                Ok(season) => layer.seasons.push(season),
                Err(e) => {
                    return Ok(Err(invalid_definition(
                        calendar_id,
                        format!("a season of calendar {id} is not a season: {e}"),
                    )));
                }
            }
        }
        layers.push(layer);
    }

    let this_year = chrono::Utc::now().year();
    let built = merge_layers(&layers, &sightings, this_year - 1..=this_year + 2)
        .and_then(|m| build_calendar(&m.tz, &m.working_days, &m.hours, m.holidays, m.exceptions));
    match built {
        Ok(calendar) => {
            let hash = content_hash(&calendar);
            let version = record_version(db, calendar_id, &calendar, &hash).await?;
            Ok(Ok(LoadedCalendar {
                id: calendar_id,
                content_hash: hash,
                tzdb_version: TZDB_VERSION,
                version,
                calendar,
            }))
        }
        Err(InvalidCalendarDefinition(reason)) => {
            tracing::error!(
                calendar_id = %calendar_id,
                reason = %reason,
                "calendar: stored calendar definition is invalid; fix it under /api/v1/admin/calendars"
            );
            Ok(Err(CalendarUnresolved::Invalid(reason)))
        }
    }
}

fn invalid_definition(calendar_id: Uuid, reason: String) -> CalendarUnresolved {
    tracing::error!(
        calendar_id = %calendar_id,
        reason = %reason,
        "calendar: stored calendar definition is invalid; fix it under /api/v1/admin/calendars"
    );
    CalendarUnresolved::Invalid(reason)
}

/// Z12-T4: the calendar's content version for `hash`. The same hash as the
/// latest version reads it; a new one writes the next version and moves
/// `calendar.current_version`, under a per-calendar try-lock (a busy lock
/// means another node is writing it: this one reads the version instead).
/// Migration 0087's empty version 1 is filled in place.
async fn record_version(
    db: &DbPool,
    calendar_id: Uuid,
    calendar: &BusinessCalendar,
    hash: &str,
) -> Result<i32, AppError> {
    let read = "SELECT version, content_hash FROM calendar_version \
                 WHERE calendar_id = $1 ORDER BY version DESC LIMIT 1";
    let (version, stored): (i32, String) = sqlx::query_as(read)
        .bind(calendar_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .unwrap_or_default();
    if version > 0 && stored == hash {
        return Ok(version);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-core/calendar-version:{calendar_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let (version, stored): (i32, String) = sqlx::query_as(read)
        .bind(calendar_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .unwrap_or_default();
    if !locked || stored == hash {
        attome_db::tx::commit(tx).await?;
        return Ok(version.max(1));
    }
    let canonical = calendar.canonical_form();
    let next = if version == 1 && stored.is_empty() {
        sqlx::query(
            "UPDATE calendar_version SET canonical = $2, content_hash = $3 \
              WHERE calendar_id = $1 AND version = 1",
        )
        .bind(calendar_id)
        .bind(&canonical)
        .bind(hash)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        1
    } else {
        let next = version + 1;
        sqlx::query(
            "INSERT INTO calendar_version (calendar_id, version, canonical, content_hash) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (calendar_id, version) DO NOTHING",
        )
        .bind(calendar_id)
        .bind(next)
        .bind(&canonical)
        .bind(hash)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        next
    };
    sqlx::query("UPDATE calendar SET current_version = $2 WHERE id = $1")
        .bind(calendar_id)
        .bind(next)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(next)
}

/// Z12-T5: the days a person is away, from whichever engine keeps leave
/// (HR registers [`register_absence_source`] at boot). The calendar layer
/// knows no leave table of its own.
pub trait AbsenceSource: Send + Sync {
    /// The dates in `[from, to]` the user is away.
    fn absences<'a>(
        &'a self,
        db: &'a DbPool,
        user_id: Uuid,
        from: NaiveDate,
        to: NaiveDate,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<NaiveDate>, AppError>> + Send + 'a>,
    >;
}

static ABSENCES: std::sync::OnceLock<std::sync::Arc<dyn AbsenceSource>> =
    std::sync::OnceLock::new();

/// Z12-T5: sets the process's absence source, once; `false` when one was
/// already set (the first stays).
pub fn register_absence_source(source: std::sync::Arc<dyn AbsenceSource>) -> bool {
    ABSENCES.set(source).is_ok()
}

/// Z12-T5: the calendar a person works to: their own assignment, else the
/// assignment of their team with the lowest id among their teams that have
/// one, else the deployment's default. Only active calendars count.
pub async fn resolve_calendar_id_for_user(
    db: &DbPool,
    user_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let own: Option<Uuid> = sqlx::query_scalar(
        "SELECT a.calendar_id FROM calendar_assignment a \
           JOIN calendar c ON c.id = a.calendar_id AND c.is_active = true \
          WHERE a.subject_type = 'user' AND a.subject_id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if own.is_some() {
        return Ok(own);
    }
    let team: Option<Uuid> = sqlx::query_scalar(
        "SELECT a.calendar_id FROM user_account_mm_team m \
           JOIN calendar_assignment a ON a.subject_type = 'team' AND a.subject_id = m.team_ref \
           JOIN calendar c ON c.id = a.calendar_id AND c.is_active = true \
          WHERE m.user_ref = $1 AND m.is_deleted = false \
          ORDER BY m.team_ref ASC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if team.is_some() {
        return Ok(team);
    }
    default_calendar_id(db).await
}

/// Z12-T5: the person's calendar ([`resolve_calendar_id_for_user`]) with
/// their absences from the registered [`AbsenceSource`] as closed days, for
/// last year to two years ahead. With no source registered nothing is
/// added. `NotFound` when no calendar applies at all.
pub async fn load_calendar_for_user(
    db: &DbPool,
    user_id: Uuid,
) -> Result<Result<LoadedCalendar, CalendarUnresolved>, AppError> {
    let Some(calendar_id) = resolve_calendar_id_for_user(db, user_id).await? else {
        return Ok(Err(CalendarUnresolved::NotFound));
    };
    let mut loaded = match load_calendar(db, calendar_id).await? {
        Ok(loaded) => loaded,
        Err(unresolved) => return Ok(Err(unresolved)),
    };
    let Some(source) = ABSENCES.get() else {
        return Ok(Ok(loaded));
    };
    let year = chrono::Utc::now().year();
    let (Some(from), Some(to)) = (
        NaiveDate::from_ymd_opt(year - 1, 1, 1),
        NaiveDate::from_ymd_opt(year + 2, 12, 31),
    ) else {
        return Ok(Ok(loaded));
    };
    let away = source.absences(db, user_id, from, to).await?;
    if away.is_empty() {
        return Ok(Ok(loaded));
    }
    loaded.calendar = with_closed_days(&loaded.calendar, &away)
        .map_err(|e| AppError::internal(format!("calendar with absences: {e}")))?;
    loaded.content_hash = content_hash(&loaded.calendar);
    Ok(Ok(loaded))
}

/// `calendar` with `days` closed (an empty exception on each).
pub fn with_closed_days(
    calendar: &BusinessCalendar,
    days: &[NaiveDate],
) -> Result<BusinessCalendar, CalendarError> {
    let mut exceptions = calendar.exceptions().clone();
    for day in days {
        exceptions.insert(*day, Vec::new());
    }
    BusinessCalendar::new(
        calendar.tz(),
        calendar.working_days().clone(),
        calendar.hours().clone(),
        calendar.holidays().clone(),
        exceptions,
    )
}

/// The deployment's single active default calendar, if one is configured.
pub async fn default_calendar_id(db: &DbPool) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM calendar WHERE is_default = true AND is_active = true LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn days(codes: &[&str]) -> Vec<String> {
        codes.iter().map(|c| c.to_string()).collect()
    }

    fn nine_to_five() -> serde_json::Value {
        json!([{ "start_minute": 540, "end_minute": 1020 }])
    }

    fn reason(result: Result<BusinessCalendar, InvalidCalendarDefinition>) -> String {
        match result {
            Err(InvalidCalendarDefinition(reason)) => reason,
            Ok(_) => panic!("expected the definition to be rejected"),
        }
    }

    #[test]
    fn a_well_formed_definition_builds() {
        let hours = json!({ "sun": nine_to_five(), "mon": nine_to_five() });
        let cal = build_calendar(
            "Asia/Dubai",
            &days(&["sun", "mon"]),
            &hours,
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(cal.working_days().len(), 2);
    }

    #[test]
    fn an_empty_calendar_is_a_valid_definition() {
        assert!(validate_definition("UTC", &[], &json!({})).is_ok());
    }

    #[test]
    fn an_unknown_weekday_is_rejected_not_dropped() {
        let hours = json!({ "mon": nine_to_five() });
        let r = reason(build_calendar(
            "UTC",
            &days(&["monday"]),
            &hours,
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(r.contains("'monday' is not a weekday"), "{r}");
        let r = reason(build_calendar(
            "UTC",
            &days(&["mon"]),
            &json!({ "monday": nine_to_five() }),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(r.contains("hours key 'monday'"), "{r}");
    }

    #[test]
    fn duplicate_days_are_rejected() {
        let hours = json!({ "mon": nine_to_five(), "Mon": nine_to_five() });
        let r = reason(build_calendar(
            "UTC",
            &days(&["mon"]),
            &hours,
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(r.contains("more than once"), "{r}");
        let r = reason(build_calendar(
            "UTC",
            &days(&["mon", "MON"]),
            &json!({ "mon": nine_to_five() }),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(r.contains("listed more than once"), "{r}");
    }

    #[test]
    fn malformed_hours_shapes_are_rejected() {
        let r = reason(build_calendar(
            "UTC",
            &[],
            &json!([]),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(r.contains("must be an object"), "{r}");
        for bad in [
            json!({ "mon": { "start_minute": 540, "end_minute": 1020 } }),
            json!({ "mon": [{ "start": 540, "end": 1020 }] }),
            json!({ "mon": [{ "start_minute": -1, "end_minute": 1020 }] }),
            json!({ "mon": [{ "start_minute": 540, "end_minute": 1020, "extra": true }] }),
        ] {
            let r = reason(build_calendar(
                "UTC",
                &days(&["mon"]),
                &bad,
                BTreeSet::new(),
                BTreeMap::new(),
            ));
            assert!(r.contains("hours for 'mon'"), "{r}");
        }
    }

    #[test]
    fn calendar_level_rules_surface_as_definition_errors() {
        let overlapping = json!({ "mon": [
            { "start_minute": 540, "end_minute": 780 },
            { "start_minute": 720, "end_minute": 1020 },
        ]});
        assert!(
            reason(build_calendar(
                "UTC",
                &days(&["mon"]),
                &overlapping,
                BTreeSet::new(),
                BTreeMap::new()
            ))
            .contains("overlap")
        );
        // Z12-T4: an overnight range is a valid shift now, not an error.
        let overnight = json!({ "mon": [{ "start_minute": 1320, "end_minute": 360 }] });
        assert!(
            build_calendar(
                "UTC",
                &days(&["mon"]),
                &overnight,
                BTreeSet::new(),
                BTreeMap::new()
            )
            .is_ok()
        );
        let r = reason(build_calendar(
            "UTC",
            &days(&["mon"]),
            &json!({ "sat": nine_to_five(), "mon": nine_to_five() }),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(r.contains("'sat'"), "{r}");
        let r = reason(build_calendar(
            "UTC",
            &days(&["mon", "tue"]),
            &json!({ "mon": nine_to_five() }),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(r.contains("'tue' has no working hours"), "{r}");
        let r = reason(build_calendar(
            "Mars/Olympus",
            &[],
            &json!({}),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(r.contains("IANA timezone"), "{r}");
    }

    #[test]
    fn content_hash_ignores_json_key_order_and_tracks_holidays() {
        let a = build_calendar(
            "UTC",
            &days(&["mon", "tue"]),
            &json!({ "mon": nine_to_five(), "tue": nine_to_five() }),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let b = build_calendar(
            "UTC",
            &days(&["tue", "mon"]),
            &json!({ "tue": nine_to_five(), "mon": nine_to_five() }),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(content_hash(&a), content_hash(&b));
        assert_eq!(content_hash(&a).len(), 64);
        let with_holiday = build_calendar(
            "UTC",
            &days(&["mon", "tue"]),
            &json!({ "mon": nine_to_five(), "tue": nine_to_five() }),
            BTreeSet::from([NaiveDate::from_ymd_opt(2026, 12, 25).unwrap()]),
            BTreeMap::new(),
        )
        .unwrap();
        assert_ne!(content_hash(&a), content_hash(&with_holiday));
    }

    fn ymd(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    /// D-592: an exception closes a working day or opens a non-working one,
    /// and it is part of the content hash.
    #[test]
    fn exceptions_override_the_weekday_and_change_the_hash() {
        use chrono::TimeZone;
        let plain = build_calendar(
            "UTC",
            &days(&["mon", "tue", "wed", "thu", "fri"]),
            &json!({
                "mon": nine_to_five(), "tue": nine_to_five(), "wed": nine_to_five(),
                "thu": nine_to_five(), "fri": nine_to_five(),
            }),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let friday = ymd(2026, 12, 18);
        let saturday = ymd(2026, 12, 19);
        let exceptions = BTreeMap::from([
            (friday, parse_exception_ranges(friday, &json!([])).unwrap()),
            (
                saturday,
                parse_exception_ranges(
                    saturday,
                    &json!([{ "start_minute": 600, "end_minute": 720 }]),
                )
                .unwrap(),
            ),
        ]);
        let cal = build_calendar(
            "UTC",
            &days(&["mon", "tue", "wed", "thu", "fri"]),
            &json!({
                "mon": nine_to_five(), "tue": nine_to_five(), "wed": nine_to_five(),
                "thu": nine_to_five(), "fri": nine_to_five(),
            }),
            BTreeSet::new(),
            exceptions,
        )
        .unwrap();
        let friday_noon = chrono::Utc
            .with_ymd_and_hms(2026, 12, 18, 12, 0, 0)
            .unwrap();
        let saturday_eleven = chrono::Utc
            .with_ymd_and_hms(2026, 12, 19, 11, 0, 0)
            .unwrap();
        assert!(plain.is_working(friday_noon));
        assert!(
            !cal.is_working(friday_noon),
            "an empty exception closes the date"
        );
        assert!(!plain.is_working(saturday_eleven));
        assert!(
            cal.is_working(saturday_eleven),
            "an exception opens a weekend date"
        );
        assert_ne!(content_hash(&plain), content_hash(&cal));
    }

    #[test]
    fn malformed_exception_ranges_are_rejected() {
        let date = ymd(2026, 12, 24);
        for (bad, expected) in [
            (
                json!({ "start_minute": 540, "end_minute": 720 }),
                "must be a list",
            ),
            (json!([{ "start_minute": 540 }]), "must be a list"),
            (
                json!([{ "start_minute": 1320, "end_minute": 360 }]),
                "cannot cross midnight",
            ),
            (
                json!([
                    { "start_minute": 540, "end_minute": 780 },
                    { "start_minute": 720, "end_minute": 1020 },
                ]),
                "overlap",
            ),
        ] {
            let r = parse_exception_ranges(date, &bad).unwrap_err().0;
            assert!(r.contains(expected), "{r}");
            assert!(r.contains("2026-12-24"), "{r}");
        }
        let sorted = parse_exception_ranges(
            date,
            &json!([
                { "start_minute": 780, "end_minute": 900 },
                { "start_minute": 540, "end_minute": 720 },
            ]),
        )
        .unwrap();
        assert_eq!(
            sorted,
            vec![TimeRange::new(540, 720), TimeRange::new(780, 900)]
        );
    }

    #[test]
    fn calendar_refs_are_unset_valid_or_malformed_never_silently_unset() {
        assert_eq!(parse_calendar_ref(None), Ok(None));
        assert_eq!(parse_calendar_ref(Some("  ")), Ok(None));
        let id = Uuid::now_v7();
        assert_eq!(parse_calendar_ref(Some(&format!(" {id} "))), Ok(Some(id)));
        assert_eq!(
            parse_calendar_ref(Some("uae-hq")),
            Err(CalendarUnresolved::MalformedReference("uae-hq".into()))
        );
    }

    fn layer(tz: &str, working: &[&str], hours: serde_json::Value) -> CalendarLayer {
        CalendarLayer {
            tz: tz.to_owned(),
            working_days: days(working),
            hours,
            ..CalendarLayer::default()
        }
    }

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn child_overrides_parent_hours() {
        let mut parent = layer(
            "Asia/Riyadh",
            &["sun", "mon"],
            json!({ "sun": nine_to_five(), "mon": nine_to_five() }),
        );
        parent.holidays = vec![d(2026, 9, 23)];
        parent.exceptions = vec![(d(2026, 3, 1), json!([]))];
        // The child changes the hours only; the zone, days, holiday and the
        // parent's exception come down, and its own exception on that date wins.
        let mut child = layer(
            "",
            &[],
            json!({ "sun": [{ "start_minute": 480, "end_minute": 960 }],
                    "mon": [{ "start_minute": 480, "end_minute": 960 }] }),
        );
        child.exceptions = vec![(
            d(2026, 3, 1),
            json!([{ "start_minute": 600, "end_minute": 720 }]),
        )];
        let merged = merge_layers(&[parent, child], &HashMap::new(), 2026..=2026).unwrap();
        assert_eq!(merged.tz, "Asia/Riyadh");
        assert_eq!(merged.working_days, days(&["sun", "mon"]));
        assert_eq!(merged.hours["sun"][0]["start_minute"], 480);
        assert!(merged.holidays.contains(&d(2026, 9, 23)));
        assert_eq!(
            merged.exceptions[&d(2026, 3, 1)],
            vec![TimeRange::new(600, 720)]
        );
        let cal = build_calendar(
            &merged.tz,
            &merged.working_days,
            &merged.hours,
            merged.holidays,
            merged.exceptions,
        )
        .unwrap();
        assert_eq!(cal.working_days().len(), 2);
    }

    #[test]
    fn overnight_range_is_split() {
        use chrono::Weekday;
        let hours = json!({ "thu": [{ "start_minute": 1320, "end_minute": 360 }] });
        let cal = build_calendar(
            "UTC",
            &days(&["thu"]),
            &hours,
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(cal.hours()[&Weekday::Thu], vec![TimeRange::new(1320, 1440)]);
        assert_eq!(cal.hours()[&Weekday::Fri], vec![TimeRange::new(0, 360)]);
        assert!(cal.working_days().contains(&Weekday::Fri));
        // 24/7: every day, the whole day.
        let all = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
        let whole = json!([{ "start_minute": 0, "end_minute": 1440 }]);
        let hours: serde_json::Map<String, serde_json::Value> = all
            .iter()
            .map(|c| ((*c).to_owned(), whole.clone()))
            .collect();
        let cal = build_calendar(
            "UTC",
            &days(&all),
            &serde_json::Value::Object(hours),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(cal.working_days().len(), 7);
    }

    #[test]
    fn absences_close_their_days() {
        use chrono::Weekday;
        let hours = json!({ "sun": nine_to_five(), "mon": nine_to_five() });
        let cal = build_calendar(
            "UTC",
            &days(&["sun", "mon"]),
            &hours,
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let away = d(2026, 10, 18);
        assert_eq!(away.weekday(), Weekday::Sun);
        let closed = with_closed_days(&cal, &[away]).unwrap();
        assert_eq!(closed.exceptions()[&away], Vec::<TimeRange>::new());
        assert_ne!(content_hash(&closed), content_hash(&cal));
    }

    #[test]
    fn sighting_overrides_expected_date() {
        use attome_calendar::rules::HolidayRule;
        let rule_id = Uuid::now_v7();
        // Eid al-Fitr, 1 Shawwal, three days.
        let rule = HolidayRule::Hijri {
            month: 10,
            day: 1,
            span_days: 3,
        };
        let expected = rule_dates(rule_id, &rule, true, &HashMap::new(), 2026).unwrap();
        assert_eq!(expected.len(), 3);
        let first = expected[0];
        let hijri_year = i32::from(attome_calendar::hijri::to_hijri(first).unwrap().year);
        let sighted = first.succ_opt().unwrap();
        let sightings = HashMap::from([((rule_id, hijri_year), sighted)]);
        let moved = rule_dates(rule_id, &rule, true, &sightings, 2026).unwrap();
        assert_eq!(moved[0], sighted);
        assert_eq!(moved.len(), 3);
        // A rule that needs no sighting ignores one.
        let fixed = rule_dates(rule_id, &rule, false, &sightings, 2026).unwrap();
        assert_eq!(fixed, expected);
    }
}

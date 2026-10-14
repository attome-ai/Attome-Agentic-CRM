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
use chrono::NaiveDate;
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
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRange {
    start_minute: u16,
    end_minute: u16,
}

const WEEKDAY_HINT: &str = "use one of mon, tue, wed, thu, fri, sat, sun";

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
    let mut ranges_by_day = HashMap::new();
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
        let ranges: Vec<TimeRange> = wire
            .into_iter()
            .map(|r| TimeRange::new(r.start_minute, r.end_minute))
            .collect();
        if ranges_by_day.insert(day, ranges).is_some() {
            return Err(invalid(format!(
                "hours for '{}' are given more than once",
                weekday_code(day)
            )));
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

/// Loads an active calendar with its active holidays and exceptions. The
/// outer `Result` is infrastructure failure; the inner one is whether this
/// calendar is usable.
pub async fn load_calendar(
    db: &DbPool,
    calendar_id: Uuid,
) -> Result<Result<LoadedCalendar, CalendarUnresolved>, AppError> {
    let row: Option<(String, Vec<String>, serde_json::Value)> = sqlx::query_as(
        "SELECT tz, working_days, hours FROM calendar WHERE id = $1 AND is_active = true",
    )
    .bind(calendar_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((tz, working_days, hours)) = row else {
        tracing::warn!(calendar_id = %calendar_id, "calendar: no active calendar has this id");
        return Ok(Err(CalendarUnresolved::NotFound));
    };

    let holidays: Vec<NaiveDate> = sqlx::query_scalar(
        "SELECT holiday_date FROM calendar_holiday WHERE calendar_id = $1 AND is_active = true",
    )
    .bind(calendar_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let exception_rows: Vec<(NaiveDate, serde_json::Value)> = sqlx::query_as(
        "SELECT exception_date, ranges FROM calendar_exception WHERE calendar_id = $1 AND is_active = true",
    )
    .bind(calendar_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let built = exception_rows
        .iter()
        .map(|(date, ranges)| parse_exception_ranges(*date, ranges).map(|r| (*date, r)))
        .collect::<Result<BTreeMap<_, _>, _>>()
        .and_then(|exceptions| {
            build_calendar(
                &tz,
                &working_days,
                &hours,
                holidays.into_iter().collect(),
                exceptions,
            )
        });
    match built {
        Ok(calendar) => Ok(Ok(LoadedCalendar {
            id: calendar_id,
            content_hash: content_hash(&calendar),
            tzdb_version: TZDB_VERSION,
            calendar,
        })),
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
        let overnight = json!({ "mon": [{ "start_minute": 1320, "end_minute": 360 }] });
        assert!(
            reason(build_calendar(
                "UTC",
                &days(&["mon"]),
                &overnight,
                BTreeSet::new(),
                BTreeMap::new()
            ))
            .contains("cannot cross midnight")
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
}

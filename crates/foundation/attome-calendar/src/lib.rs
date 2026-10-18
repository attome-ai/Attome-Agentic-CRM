//! `attome-calendar` — D-404 / D-517 / `document/xrm/module/M83-scheduling/master-plan.md`
//! Phase 1: the platform's single business-time arithmetic primitive.
//!
//! Lives in the base layer (zero `xrm-*` knowledge, guidelines §1) because
//! every engine that reasons about due dates, SLAs, project schedules, or
//! resource availability needs the same working-days/hours/holidays math.
//! `BusinessCalendar` is that logic, generalized once: named working days,
//! per-day hour ranges (so a lunch break or a half day is just two ranges),
//! specific-date holidays, and per-date exceptions (an override of a date's
//! ranges — empty means "closed", non-empty means "use these ranges instead of
//! the weekday default").
//!
//! Pure, synchronous, no I/O, no database — every date/time computation
//! that needs a calendar's actual working hours takes a `&BusinessCalendar`
//! and returns an answer. Callers own fetching a calendar's data (row +
//! holidays) from wherever it lives; this crate has no idea what a
//! `xrm_core_calendar` row is.
//!
//! ## The contract (D-517)
//!
//! **A calculation either produces a result that is exactly right for a
//! valid calendar, or returns a [`CalendarError`]. It never invents one.**
//! Before D-517 a scan that found no working time degraded to plain
//! wall-clock arithmetic (`start + duration`); that answer looked like a
//! deadline and was not one. Callers now decide what business state an
//! error puts them in.
//!
//! - **Validated at construction.** A `BusinessCalendar` can only be built
//!   through [`BusinessCalendar::new`]/[`BusinessCalendar::simple`], which
//!   reject malformed input ([`CalendarError::InvalidCalendar`]) rather than
//!   silently dropping parts of it: a range must satisfy
//!   `start_minute < end_minute <= 1440`, ranges on one day (or one exception
//!   date) must not overlap (touching is fine), every working day needs at
//!   least one range, and no hours may be given for a non-working day.
//! - **A calendar with no working time is valid.** It is not the same thing
//!   as an invalid one: asking it for a deadline returns
//!   [`CalendarError::NoWorkingTime`]; asking how much business time lies
//!   between two instants correctly returns zero.
//! - **Ranges never cross midnight.** A `TimeRange` lives inside one local
//!   calendar date; `22:00-06:00` is rejected, not reinterpreted. A night
//!   shift is two ranges on two dates (`22:00-24:00` and `00:00-06:00`).
//!   Trading sessions that wrap midnight keep their own representation
//!   (`trd-engine::sessions`).
//! - **Instants are UTC; interpretation is local.** Every input and output
//!   is a `DateTime<Utc>`; deciding which date an instant falls on and
//!   whether it is inside a range happens in the calendar's IANA zone.
//! - **Daylight saving.** A range's wall-clock bounds are resolved to real
//!   instants on the date they belong to:
//!   - a wall-clock time that occurs twice (clocks go back) resolves to its
//!     **earlier** occurrence, so on New York's fall-back day `00:00-04:00`
//!     spans five real hours and `01:00-01:30` covers only the first
//!     (daylight-time) pass through 01:00-01:30;
//!   - a wall-clock time that never occurs (clocks go forward) resolves to
//!     the **first real instant after the gap**, searched for up to 26 hours
//!     — enough for a whole local day to vanish, as `Pacific/Apia`'s
//!     2011-12-30 did — so on New York's spring-forward day `02:00-04:00`
//!     spans one real hour (03:00-04:00) and `01:00-04:00` spans two, and a
//!     date that never happened resolves to an empty span: no working time,
//!     not an error.
//! - **Working time is the union of every date's real range spans.** When
//!   clocks go back *across* local midnight (an Atlantic-Canada rule moved
//!   `America/St_Johns` back at 00:01 on 2010-11-07), a date's last ranges
//!   end at the *earlier* occurrence of the next midnight, so an instant whose
//!   local date is D can fall inside D+1's span. The calculators agree by
//!   construction: they are all one internal walk (`IntervalWalk`), and
//!   [`BusinessCalendar::is_working`] consults the local date and the one
//!   after it.
//! - **Bounded.** Every scan stops after [`MAX_DAYS_SCAN`] days (ten years)
//!   and reports [`CalendarError::NoWorkingTime`] or
//!   [`CalendarError::SearchLimitExceeded`]; arithmetic past chrono's
//!   representable range is [`CalendarError::Overflow`], never a panic.
//!
//! **Deliberately out of scope for Phase 1** (see M83 §6 Phase 2/3):
//! `Recurrence`/RRULE, availability intersection, appointments, conflict
//! detection, sync. This crate is the primitive those build on, not those
//! features themselves.

pub mod availability;
pub mod hijri;
pub mod recurrence;
pub mod rrule;
pub mod rules;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use chrono::{
    DateTime, Datelike, Duration, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc,
    Weekday,
};
use chrono_tz::Tz;

/// Safety valve against an unbounded scan: 10 years is far beyond any real
/// due-date or lookback horizon this platform computes, so hitting it means
/// "this calendar cannot satisfy the request," not "keep searching."
pub const MAX_DAYS_SCAN: i64 = 366 * 10;

/// The IANA time zone database version compiled into this crate (*"2025b"*),
/// re-exported from `chrono-tz`.
///
/// Every answer here depends on it, together with the calendar itself: the
/// same calendar and the same instants can cross a different DST rule after a
/// database bump, so a consumer that records
/// [`BusinessCalendar::canonical_form`] for audit must record this beside it
/// (D-621). It is deliberately **not** folded into the canonical form —
/// that would move every content hash on every tz bump (BCL-D1).
pub const TZDB_VERSION: &str = chrono_tz::IANA_TZDB_VERSION;

/// How far past a nonexistent (spring-forward) wall-clock time to look for the
/// first real instant — 26 hours, enough for a whole local date to be skipped
/// (`Pacific/Apia` lost 2011-12-30 to a date-line move; the gap is 24 hours),
/// while still terminating on a pathological offset table.
const DST_GAP_SEARCH_MINUTES: u32 = 26 * 60;

const MINUTES_PER_DAY: u16 = 1440;

/// Monday-first, so every rendering that iterates weekdays (error messages,
/// [`BusinessCalendar::canonical_form`]) is deterministic.
const WEEKDAYS: [Weekday; 7] = [
    Weekday::Mon,
    Weekday::Tue,
    Weekday::Wed,
    Weekday::Thu,
    Weekday::Fri,
    Weekday::Sat,
    Weekday::Sun,
];

/// Why a business-time calculation could not produce an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CalendarError {
    /// The calendar definition itself is malformed (the message says how).
    InvalidCalendar(String),
    /// The calendar has no working time at all within [`MAX_DAYS_SCAN`] of
    /// the start — a valid but closed calendar, or one whose holidays and
    /// exceptions close every working day in that window.
    NoWorkingTime,
    /// Working time exists, but not enough of it within [`MAX_DAYS_SCAN`] to
    /// cover the request (or the requested span is itself longer than that).
    SearchLimitExceeded,
    /// The result would fall outside chrono's representable date range.
    Overflow,
    /// A range bound could not be resolved to a real instant in the
    /// calendar's timezone. The resolution rule (earlier occurrence of a
    /// repeated wall time, first real instant after a skipped one, searched
    /// for up to 26 hours) answers for every shape the IANA database
    /// contains, so this is reachable only for a synthetic or corrupt offset
    /// table.
    InvalidLocalTime,
    /// A negative duration was asked for; business time only moves forward.
    NegativeDuration,
    /// A Hijri date, or a Gregorian day, outside the Umm al-Qura table
    /// (1356 to 1500 AH).
    OutOfHijriRange,
}

impl fmt::Display for CalendarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCalendar(reason) => write!(f, "invalid calendar: {reason}"),
            Self::NoWorkingTime => f.write_str("the calendar has no working time"),
            Self::SearchLimitExceeded => write!(
                f,
                "the calculation needs more than {MAX_DAYS_SCAN} days of calendar time"
            ),
            Self::Overflow => f.write_str("the result is outside the representable date range"),
            Self::InvalidLocalTime => {
                f.write_str("a working-hours bound does not resolve to a real instant")
            }
            Self::NegativeDuration => f.write_str("business durations cannot be negative"),
            Self::OutOfHijriRange => f.write_str(
                "the date is outside the Umm al-Qura calendar (1356 to 1500 AH, 1937 to 2077)",
            ),
        }
    }
}

impl std::error::Error for CalendarError {}

/// The lowercase three-letter code (`mon`..`sun`) calendars use for weekdays
/// on the wire — chosen over an ISO number to sidestep the Sunday-vs-Monday
/// first-day-of-week ambiguity entirely.
pub fn weekday_code(day: Weekday) -> &'static str {
    match day {
        Weekday::Mon => "mon",
        Weekday::Tue => "tue",
        Weekday::Wed => "wed",
        Weekday::Thu => "thu",
        Weekday::Fri => "fri",
        Weekday::Sat => "sat",
        Weekday::Sun => "sun",
    }
}

/// The inverse of [`weekday_code`], case-insensitive. `None` for anything
/// else — callers must reject unknown codes, not skip them.
pub fn parse_weekday_code(code: &str) -> Option<Weekday> {
    WEEKDAYS
        .into_iter()
        .find(|day| weekday_code(*day).eq_ignore_ascii_case(code))
}

/// A working window on a single local date, expressed as minutes from local
/// midnight, `start_minute..end_minute` (start included, end excluded).
/// Must satisfy `start_minute < end_minute <= 1440` to be accepted into a
/// [`BusinessCalendar`]; see the crate docs for why overnight ranges are not
/// representable.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct TimeRange {
    pub start_minute: u16,
    pub end_minute: u16,
}

impl TimeRange {
    pub const fn new(start_minute: u16, end_minute: u16) -> Self {
        Self {
            start_minute,
            end_minute,
        }
    }

    /// The rule a range must satisfy to be accepted into a
    /// [`BusinessCalendar`]: `start_minute < end_minute <= 1440`. Public so a
    /// consumer can check a range before building one, instead of
    /// re-implementing the rule and drifting (D-404).
    pub const fn is_valid(self) -> bool {
        self.start_minute < self.end_minute && self.end_minute <= MINUTES_PER_DAY
    }

    /// [`TimeRange::new`] plus [`TimeRange::is_valid`], reporting the same
    /// `HH:MM`-rendered reason a calendar constructor would.
    pub fn try_new(start_minute: u16, end_minute: u16) -> Result<Self, CalendarError> {
        let range = Self::new(start_minute, end_minute);
        if range.is_valid() {
            Ok(range)
        } else {
            Err(CalendarError::InvalidCalendar(range_rule_message(range)))
        }
    }
}

/// The `HH:MM-HH:MM` rendering of a range bound; `1440` is `24:00`, the only
/// value above 23:59 a range may carry.
fn render_minute(minute: u16) -> String {
    format!("{:02}:{:02}", minute / 60, minute % 60)
}

/// `22:00-06:00 (1320-360 minutes)` — the raw minutes stay in parentheses so a
/// log or a support ticket still carries the exact wire value.
fn render_range(range: TimeRange) -> String {
    format!(
        "{}-{} ({} - {} minutes)",
        render_minute(range.start_minute),
        render_minute(range.end_minute),
        range.start_minute,
        range.end_minute
    )
}

fn range_rule_message(range: TimeRange) -> String {
    format!(
        "range {} must satisfy start < end <= 24:00 (ranges cannot cross midnight)",
        render_range(range)
    )
}

/// A validated business calendar: a timezone, which weekdays are working
/// days, what hours those days run, which specific dates are holidays
/// (closed regardless of weekday), and per-date exceptions that override the
/// normal weekday ranges for one date (an extra working Saturday, a
/// shortened afternoon, ...).
///
/// Fields are private so an unvalidated calendar cannot exist; build one
/// with [`BusinessCalendar::new`] or [`BusinessCalendar::simple`].
#[derive(Debug, Clone)]
pub struct BusinessCalendar {
    tz: Tz,
    working_days: HashSet<Weekday>,
    /// Per working day, sorted by start and non-overlapping.
    hours: HashMap<Weekday, Vec<TimeRange>>,
    holidays: BTreeSet<NaiveDate>,
    /// Per date, sorted by start and non-overlapping; empty means closed.
    exceptions: BTreeMap<NaiveDate, Vec<TimeRange>>,
}

/// Sorts `ranges` and rejects any malformed or overlapping one.
fn normalize_ranges(ranges: &[TimeRange], label: &str) -> Result<Vec<TimeRange>, CalendarError> {
    let mut sorted = ranges.to_vec();
    sorted.sort();
    if let Some(bad) = sorted.iter().find(|r| !r.is_valid()) {
        return Err(CalendarError::InvalidCalendar(format!(
            "{label}: {}",
            range_rule_message(*bad)
        )));
    }
    if let Some(pair) = sorted
        .windows(2)
        .find(|pair| pair[1].start_minute < pair[0].end_minute)
    {
        return Err(CalendarError::InvalidCalendar(format!(
            "{label}: ranges {} and {} overlap",
            render_range(pair[0]),
            render_range(pair[1])
        )));
    }
    Ok(sorted)
}

/// Ranges as `09:00-12:00 (540 - 720 minutes)`, comma-joined — what an error
/// message shows for one day's hours.
fn render_ranges(ranges: &[TimeRange]) -> String {
    ranges
        .iter()
        .map(|r| render_range(*r))
        .collect::<Vec<_>>()
        .join(", ")
}

impl BusinessCalendar {
    pub fn new(
        tz: Tz,
        working_days: HashSet<Weekday>,
        hours: HashMap<Weekday, Vec<TimeRange>>,
        holidays: BTreeSet<NaiveDate>,
        exceptions: BTreeMap<NaiveDate, Vec<TimeRange>>,
    ) -> Result<Self, CalendarError> {
        let mut normalized_hours = HashMap::with_capacity(hours.len());
        for day in WEEKDAYS {
            let ranges = hours.get(&day).map_or(&[][..], Vec::as_slice);
            let is_working_day = working_days.contains(&day);
            if !is_working_day && !ranges.is_empty() {
                return Err(CalendarError::InvalidCalendar(format!(
                    "hours are given for '{}', which is not a working day",
                    weekday_code(day)
                )));
            }
            if !is_working_day {
                continue;
            }
            if ranges.is_empty() {
                return Err(CalendarError::InvalidCalendar(format!(
                    "working day '{}' has no working hours",
                    weekday_code(day)
                )));
            }
            normalized_hours.insert(day, normalize_ranges(ranges, weekday_code(day))?);
        }

        let mut normalized_exceptions = BTreeMap::new();
        for (date, ranges) in exceptions {
            let normalized = normalize_ranges(&ranges, &format!("exception {date}"))?;
            normalized_exceptions.insert(date, normalized);
        }

        Ok(Self {
            tz,
            working_days,
            hours: normalized_hours,
            holidays,
            exceptions: normalized_exceptions,
        })
    }

    /// A calendar with no holidays/exceptions and one flat range applied to
    /// every day in `working_days` — the common case (a straight Mon-Fri or
    /// Sun-Thu 9-to-5).
    pub fn simple(
        tz: Tz,
        working_days: HashSet<Weekday>,
        range: TimeRange,
    ) -> Result<Self, CalendarError> {
        let hours = working_days.iter().map(|d| (*d, vec![range])).collect();
        Self::new(tz, working_days, hours, BTreeSet::new(), BTreeMap::new())
    }

    pub fn tz(&self) -> Tz {
        self.tz
    }

    pub fn working_days(&self) -> &HashSet<Weekday> {
        &self.working_days
    }

    pub fn hours(&self) -> &HashMap<Weekday, Vec<TimeRange>> {
        &self.hours
    }

    pub fn holidays(&self) -> &BTreeSet<NaiveDate> {
        &self.holidays
    }

    pub fn exceptions(&self) -> &BTreeMap<NaiveDate, Vec<TimeRange>> {
        &self.exceptions
    }

    /// A deterministic text rendering of the calendar content a calculation
    /// reads, independent of how the input collections were ordered: two
    /// calendars with the same form give the same answers **for one time zone
    /// database version**. The rules that version compiles in are the one
    /// input the form cannot carry, so a caller that stamps a calculation with
    /// it (D-517) records [`TZDB_VERSION`] beside the hash (D-621).
    pub fn canonical_form(&self) -> String {
        let days = WEEKDAYS
            .into_iter()
            .filter(|d| self.working_days.contains(d))
            .map(weekday_code)
            .collect::<Vec<_>>()
            .join(",");
        let hours = WEEKDAYS
            .into_iter()
            .filter_map(|d| {
                self.hours
                    .get(&d)
                    .map(|ranges| format!("{}:{}", weekday_code(d), render_ranges(ranges)))
            })
            .collect::<Vec<_>>()
            .join("|");
        let holidays = self
            .holidays
            .iter()
            .map(NaiveDate::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let exceptions = self
            .exceptions
            .iter()
            .map(|(date, ranges)| {
                if ranges.is_empty() {
                    format!("{date}:closed")
                } else {
                    format!("{date}:{}", render_ranges(ranges))
                }
            })
            .collect::<Vec<_>>()
            .join("|");
        format!(
            "tz={};working_days={days};hours={hours};holidays={holidays};exceptions={exceptions}",
            self.tz.name()
        )
    }

    /// The working ranges for a local calendar date, precedence: holiday
    /// (always closed) > exception (explicit override) > weekday default.
    /// Already sorted and validated.
    fn ranges_for_date(&self, date: NaiveDate) -> &[TimeRange] {
        if self.holidays.contains(&date) {
            return &[];
        }
        if let Some(exception) = self.exceptions.get(&date) {
            return exception;
        }
        let weekday = date.weekday();
        if !self.working_days.contains(&weekday) {
            return &[];
        }
        self.hours.get(&weekday).map_or(&[], Vec::as_slice)
    }

    /// Resolves a local wall-clock time in `self.tz` to a real instant per
    /// the crate-level DST contract: the earlier occurrence of an ambiguous
    /// time, the first real instant after a nonexistent one, searched for up
    /// to [`DST_GAP_SEARCH_MINUTES`] (26 hours) so a whole skipped local date
    /// resolves to the instant the date would have begun. `None` only if no
    /// real instant exists within that window.
    fn resolve_local(&self, naive: NaiveDateTime) -> Option<DateTime<Tz>> {
        let mut candidate = naive;
        for _ in 0..=DST_GAP_SEARCH_MINUTES {
            match self.tz.from_local_datetime(&candidate) {
                LocalResult::Single(dt) => return Some(dt),
                LocalResult::Ambiguous(earlier, _later) => return Some(earlier),
                LocalResult::None => {
                    candidate = candidate.checked_add_signed(Duration::minutes(1))?;
                }
            }
        }
        None
    }

    /// The real start/end instants of `range` on `date`.
    fn range_bounds(
        &self,
        date: NaiveDate,
        range: TimeRange,
    ) -> Result<(DateTime<Tz>, DateTime<Tz>), CalendarError> {
        let midnight = date.and_time(NaiveTime::MIN);
        let at = |minute: u16| {
            let naive = midnight
                .checked_add_signed(Duration::minutes(i64::from(minute)))
                .ok_or(CalendarError::Overflow)?;
            self.resolve_local(naive)
                .ok_or(CalendarError::InvalidLocalTime)
        };
        Ok((at(range.start_minute)?, at(range.end_minute)?))
    }

    /// Whether `instant` falls inside one of the calendar's working ranges.
    ///
    /// Consults the instant's own local date **and the following one**: when
    /// clocks go back across local midnight, the date's last ranges end at the
    /// earlier occurrence of the next midnight, so an instant of the previous
    /// local date can belong to the next date's span. A range whose bounds
    /// cannot be resolved counts as not working — the conservative answer for
    /// "is it open?".
    pub fn is_working(&self, instant: DateTime<Utc>) -> bool {
        let local = instant.with_timezone(&self.tz);
        let date = local.date_naive();
        [Some(date), date.succ_opt()]
            .into_iter()
            .flatten()
            .any(|d| {
                self.ranges_for_date(d).iter().any(|r| {
                    self.range_bounds(d, *r)
                        .is_ok_and(|(start, end)| end > start && local >= start && local < end)
                })
            })
    }

    /// Whether `date` (a local date of this calendar) has any working hours:
    /// a working weekday that is not a holiday, or an exception that opens it
    /// (Z11-T4's working-day functions count these).
    pub fn is_working_date(&self, date: NaiveDate) -> bool {
        !self.ranges_for_date(date).is_empty()
    }

    /// Whether any date can ever be working time: a working weekday, or an
    /// exception that opens one. A calendar that answers `false` is closed for
    /// good, so the deadline calculators answer
    /// [`CalendarError::NoWorkingTime`] without scanning [`MAX_DAYS_SCAN`]
    /// dates first.
    pub(crate) fn has_working_time(&self) -> bool {
        self.hours.values().any(|ranges| !ranges.is_empty())
            || self.exceptions.values().any(|ranges| !ranges.is_empty())
    }

    /// The working intervals of real time inside `[from, to)`, earliest first.
    ///
    /// Each item is a half-open `(start, end)` with `from <= start < end <=
    /// to`. Intervals are non-empty and never overlap, and two that touch — a
    /// date's last range ending exactly where the next date's first begins, the
    /// usual case across a local midnight — are coalesced into one, so the
    /// working time of a span is exactly the sum of its intervals' lengths.
    ///
    /// This is the platform's one working-interval walk (D-404): the
    /// calculators below are built on it, and so is any consumer that needs the
    /// intervals themselves (explaining an SLA result, finding a free slot).
    ///
    /// The walk is bounded by [`MAX_DAYS_SCAN`] local dates starting at
    /// `from`; a `to` beyond that is simply never reached. An `Err` ends the
    /// walk where the resolution failed.
    ///
    /// Test-only today (cleanup 1.8): no caller outside this crate uses it,
    /// and the calculators drive [`IntervalWalk`] directly. The unit and
    /// property tests use it to pin the walk's invariants.
    #[cfg(test)]
    pub(crate) fn working_intervals(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Iterator<Item = Result<(DateTime<Utc>, DateTime<Utc>), CalendarError>> + '_ {
        IntervalWalk::new(self, from, to)
    }

    /// The earliest working instant at or after `instant` — `instant`
    /// itself if it is already working time.
    ///
    /// [`CalendarError::NoWorkingTime`] if no working time starts within
    /// [`MAX_DAYS_SCAN`] days.
    ///
    /// The tests also use it to check the walk agrees with
    /// [`Self::is_working`].
    #[cfg(test)]
    pub(crate) fn next_business_instant(
        &self,
        instant: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, CalendarError> {
        self.next_working_moment(instant)
    }

    /// The earliest working instant at or after `from` (Z12-T2) — `from`
    /// itself when it is already working time — found with the same bounded
    /// walk as [`Self::add_business_duration`].
    ///
    /// [`CalendarError::NoWorkingTime`] if no working time starts within
    /// [`MAX_DAYS_SCAN`] days.
    pub fn next_working_moment(&self, from: DateTime<Utc>) -> Result<DateTime<Utc>, CalendarError> {
        let instant = from;
        if !self.has_working_time() {
            return Err(CalendarError::NoWorkingTime);
        }
        let to = instant
            .checked_add_signed(Duration::days(MAX_DAYS_SCAN))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        let mut walk = IntervalWalk::new(self, instant, to);
        loop {
            match walk.step() {
                Step::Item(Ok((start, _end))) => return Ok(start),
                Step::Item(Err(error)) => return Err(error),
                Step::End => return Err(CalendarError::NoWorkingTime),
                // A pending interval's start is final: merging only extends
                // its end, so the first interval is known before it is closed.
                Step::Continue => {
                    if let Some((start, _end)) = walk.pending {
                        return Ok(start);
                    }
                }
            }
        }
    }

    /// Advances `start` by `duration` of business time — time that falls
    /// inside a working range. Non-working time (nights, weekends,
    /// holidays, exceptions) is skipped entirely, not counted.
    ///
    /// A zero duration returns `start` unchanged; a negative one is
    /// [`CalendarError::NegativeDuration`]. When the result lands exactly
    /// where a range closes, that closing instant is returned.
    pub fn add_business_duration(
        &self,
        start: DateTime<Utc>,
        duration: Duration,
    ) -> Result<DateTime<Utc>, CalendarError> {
        if duration < Duration::zero() {
            return Err(CalendarError::NegativeDuration);
        }
        if duration.is_zero() {
            return Ok(start);
        }
        if !self.has_working_time() {
            return Err(CalendarError::NoWorkingTime);
        }
        let mut remaining = duration;
        let mut saw_working_time = false;
        let mut walk = IntervalWalk::new(self, start, DateTime::<Utc>::MAX_UTC);
        loop {
            let (segment_start, segment_end) = match walk.step() {
                Step::Item(interval) => interval?,
                Step::End => break,
                // The pending interval only grows at its end, so once it
                // already covers what remains, the answer is final.
                Step::Continue => match walk.pending {
                    Some((pending_start, pending_end))
                        if remaining <= pending_end - pending_start =>
                    {
                        return pending_start
                            .checked_add_signed(remaining)
                            .ok_or(CalendarError::Overflow);
                    }
                    _ => continue,
                },
            };
            saw_working_time = true;
            let available = segment_end - segment_start;
            if remaining <= available {
                return segment_start
                    .checked_add_signed(remaining)
                    .ok_or(CalendarError::Overflow);
            }
            remaining -= available;
        }
        Err(if saw_working_time {
            CalendarError::SearchLimitExceeded
        } else {
            CalendarError::NoWorkingTime
        })
    }

    /// The total business time between `a` and `b` — non-working time is
    /// excluded from the sum, same rule as [`Self::add_business_duration`].
    /// Negative when `b < a` (mirrors `chrono::Duration`'s own sign
    /// convention). Zero, correctly, for a calendar with no working time.
    ///
    /// [`CalendarError::SearchLimitExceeded`] when the span covers more than
    /// [`MAX_DAYS_SCAN`] local dates.
    pub fn business_duration_between(
        &self,
        a: DateTime<Utc>,
        b: DateTime<Utc>,
    ) -> Result<Duration, CalendarError> {
        if b < a {
            return self.business_duration_between(b, a).map(|d| -d);
        }
        let mut walk = IntervalWalk::new(self, a, b);
        let mut total = Duration::zero();
        for interval in &mut walk {
            let (start, end) = interval?;
            total += end - start;
        }
        if walk.truncated {
            Err(CalendarError::SearchLimitExceeded)
        } else {
            Ok(total)
        }
    }
}

/// A half-open working interval in UTC: `start <= t < end`.
type WorkingInterval = (DateTime<Utc>, DateTime<Utc>);

/// One item of the working-interval walk.
type IntervalItem = Result<WorkingInterval, CalendarError>;

/// The lazy walk every calculator drives (D-404): one local date
/// at a time, each date's ranges resolved to real instants, clipped to
/// `[from, to)` and coalesced into non-overlapping intervals.
struct IntervalWalk<'a> {
    cal: &'a BusinessCalendar,
    /// Exclusive upper bound of the walk.
    to: DateTime<Utc>,
    /// The earliest instant the walk has not yet accounted for.
    cursor: DateTime<Utc>,
    /// The local date whose ranges are being consumed.
    date: NaiveDate,
    ranges: &'a [TimeRange],
    range_index: usize,
    /// Local dates still allowed by [`MAX_DAYS_SCAN`].
    dates_left: i64,
    /// The interval waiting to be flushed: it may still absorb the next one.
    pending: Option<WorkingInterval>,
    done: bool,
    /// The walk stopped because the date budget ran out with `to` still ahead.
    truncated: bool,
}

impl<'a> IntervalWalk<'a> {
    fn new(cal: &'a BusinessCalendar, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        let date = from.with_timezone(&cal.tz).date_naive();
        Self {
            cal,
            to,
            cursor: from,
            date,
            ranges: cal.ranges_for_date(date),
            range_index: 0,
            dates_left: MAX_DAYS_SCAN,
            pending: None,
            done: from >= to,
            truncated: false,
        }
    }

    /// Merges `(start, end)` into the pending interval, or flushes the pending
    /// interval and keeps the new one when they are disjoint.
    fn push(&mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Option<WorkingInterval> {
        match self.pending {
            Some((pending_start, pending_end)) if pending_end >= start => {
                self.pending = Some((pending_start, pending_end.max(end)));
                None
            }
            Some(ready) => {
                self.pending = Some((start, end));
                Some(ready)
            }
            None => {
                self.pending = Some((start, end));
                None
            }
        }
    }

    /// Moves to the next local date, or finishes the walk. The cursor advances
    /// to the new date's start even when the date holds no ranges, so a run of
    /// closed dates still moves the walk toward its upper bound instead of
    /// idling on one spot.
    fn advance(&mut self) -> Option<IntervalItem> {
        if self.cursor >= self.to {
            self.done = true;
            self.truncated = false;
            return None;
        }
        let Some(next) = self.date.succ_opt() else {
            self.done = true;
            return Some(Err(CalendarError::Overflow));
        };
        let midnight = match self.cal.resolve_local(next.and_time(NaiveTime::MIN)) {
            Some(midnight) => midnight.with_timezone(&Utc),
            None => {
                self.done = true;
                return Some(Err(CalendarError::InvalidLocalTime));
            }
        };
        self.date = next;
        self.ranges = self.cal.ranges_for_date(next);
        self.range_index = 0;
        self.cursor = self.cursor.max(midnight);
        self.dates_left -= 1;
        if self.dates_left <= 0 {
            self.done = true;
            // The last date may already have started at or after the upper
            // bound, in which case nothing was left uncovered.
            self.truncated = self.cursor < self.to;
        }
        None
    }
}

/// The outcome of one [`IntervalWalk::step`].
enum Step {
    /// The walk produced an item, as [`Iterator::next`] would return it.
    Item(IntervalItem),
    /// The walk is over.
    End,
    /// Nothing to hand out yet; the pending interval may have grown.
    Continue,
}

impl IntervalWalk<'_> {
    /// One unit of the walk's work: one range, or one move to the next date.
    ///
    /// Exposed below the iterator so a caller whose question the pending
    /// interval already answers can stop early. Across an always-open calendar
    /// every date touches the next, so the iterator itself yields nothing until
    /// the whole [`MAX_DAYS_SCAN`] budget is spent.
    fn step(&mut self) -> Step {
        if self.done {
            return match self.pending.take() {
                Some(interval) => Step::Item(Ok(interval)),
                None => Step::End,
            };
        }
        if self.range_index < self.ranges.len() {
            let range = self.ranges[self.range_index];
            self.range_index += 1;
            let (range_start, range_end) = match self.cal.range_bounds(self.date, range) {
                Ok(bounds) => bounds,
                Err(error) => {
                    self.pending = None;
                    self.done = true;
                    return Step::Item(Err(error));
                }
            };
            // A local date that never happened resolves both bounds to one
            // instant and therefore holds no working time.
            if range_end <= range_start {
                return Step::Continue;
            }
            let start = self.cursor.max(range_start.with_timezone(&Utc));
            let end = range_end.with_timezone(&Utc).min(self.to);
            if end <= start {
                return Step::Continue;
            }
            self.cursor = end;
            return match self.push(start, end) {
                Some(ready) => Step::Item(Ok(ready)),
                None => Step::Continue,
            };
        }
        match self.advance() {
            Some(error) => Step::Item(error),
            None => Step::Continue,
        }
    }
}

impl Iterator for IntervalWalk<'_> {
    type Item = IntervalItem;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.step() {
                Step::Item(item) => return Some(item),
                Step::End => return None,
                Step::Continue => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono_tz::UTC;

    fn utc(y: i32, m: u32, d: u32, h: u32, min: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, min, 0).unwrap()
    }

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn days(list: &[Weekday]) -> HashSet<Weekday> {
        list.iter().copied().collect()
    }

    const SUN_THU: [Weekday; 5] = [
        Weekday::Sun,
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
    ];

    /// Sun–Thu 09:00-17:00 UTC calendar with no holidays — the baseline
    /// most tests build on.
    fn sun_thu_calendar() -> BusinessCalendar {
        BusinessCalendar::simple(UTC, days(&SUN_THU), TimeRange::new(9 * 60, 17 * 60)).unwrap()
    }

    fn with_holidays(cal: &BusinessCalendar, dates: &[NaiveDate]) -> BusinessCalendar {
        let mut holidays = cal.holidays().clone();
        holidays.extend(dates.iter().copied());
        BusinessCalendar::new(
            cal.tz(),
            cal.working_days().clone(),
            cal.hours().clone(),
            holidays,
            cal.exceptions().clone(),
        )
        .unwrap()
    }

    fn ny() -> Tz {
        "America/New_York".parse().unwrap()
    }

    // ── The Phase 1 acceptance test (M83 §5) ─────────────────────────────
    //
    // A ticket opened Thursday 16:00 with an 8-business-hour resolution
    // target, on a Sun-Thu working calendar with a Friday holiday, is due
    // Sunday 16:00 — NOT Friday.
    #[test]
    fn acceptance_thursday_8h_due_sunday_not_friday_across_a_holiday() {
        // 2026-08-28 is a Friday; 2026-08-27 the preceding Thursday.
        let cal = with_holidays(&sun_thu_calendar(), &[date(2026, 8, 28)]);
        let due = cal
            .add_business_duration(utc(2026, 8, 27, 16, 0), Duration::hours(8))
            .unwrap();
        assert_eq!(due, utc(2026, 8, 30, 16, 0), "must land on Sunday");
        assert!(!cal.is_working(utc(2026, 8, 28, 12, 0)));
    }

    #[test]
    fn is_working_true_inside_window_false_outside() {
        let cal = sun_thu_calendar();
        assert!(cal.is_working(utc(2026, 8, 27, 10, 0))); // Thursday, inside
        assert!(!cal.is_working(utc(2026, 8, 27, 8, 0))); // before it opens
        assert!(!cal.is_working(utc(2026, 8, 27, 17, 0))); // [start, end)
        assert!(!cal.is_working(utc(2026, 8, 28, 12, 0))); // Friday
    }

    #[test]
    fn next_business_instant_is_identity_when_already_working() {
        let t = utc(2026, 8, 27, 10, 0);
        assert_eq!(sun_thu_calendar().next_business_instant(t), Ok(t));
    }

    #[test]
    fn next_working_moment_skips_weekend() {
        let friday_noon = utc(2026, 8, 28, 12, 0);
        assert_eq!(
            sun_thu_calendar().next_working_moment(friday_noon),
            Ok(utc(2026, 8, 30, 9, 0))
        );
        let closed = BusinessCalendar::new(
            UTC,
            HashSet::new(),
            HashMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            closed.next_working_moment(friday_noon),
            Err(CalendarError::NoWorkingTime)
        );
    }

    #[test]
    fn next_business_instant_jumps_weekend_to_sunday_open() {
        let t = utc(2026, 8, 28, 12, 0); // Friday noon
        assert_eq!(
            sun_thu_calendar().next_business_instant(t),
            Ok(utc(2026, 8, 30, 9, 0))
        );
    }

    #[test]
    fn business_duration_between_excludes_the_weekend() {
        let cal = sun_thu_calendar();
        let a = utc(2026, 8, 27, 16, 0);
        let b = utc(2026, 8, 30, 16, 0);
        assert_eq!(cal.business_duration_between(a, b), Ok(Duration::hours(8)));
        assert_eq!(cal.business_duration_between(b, a), Ok(Duration::hours(-8)));
    }

    #[test]
    fn a_holiday_falling_on_a_non_working_weekend_day_changes_nothing() {
        let plain = sun_thu_calendar();
        let with_holiday = with_holidays(&plain, &[date(2026, 8, 29)]); // Saturday
        let start = utc(2026, 8, 27, 16, 0);
        assert_eq!(
            with_holiday.add_business_duration(start, Duration::hours(8)),
            plain.add_business_duration(start, Duration::hours(8)),
        );
    }

    #[test]
    fn leap_day_is_an_ordinary_working_day() {
        assert_eq!(date(2028, 2, 29).weekday(), Weekday::Tue);
        let due = sun_thu_calendar()
            .add_business_duration(utc(2028, 2, 29, 9, 0), Duration::hours(2))
            .unwrap();
        assert_eq!(due, utc(2028, 2, 29, 11, 0));
    }

    #[test]
    fn split_shift_skips_the_lunch_break() {
        let hours = HashMap::from([(
            Weekday::Mon,
            vec![
                TimeRange::new(13 * 60, 17 * 60),
                TimeRange::new(9 * 60, 12 * 60),
            ],
        )]);
        let cal = BusinessCalendar::new(
            UTC,
            days(&[Weekday::Mon]),
            hours,
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        // Monday 2026-08-24 11:00 + 2h: 1h before lunch, 1h after.
        let due = cal
            .add_business_duration(utc(2026, 8, 24, 11, 0), Duration::hours(2))
            .unwrap();
        assert_eq!(due, utc(2026, 8, 24, 14, 0));
        assert!(!cal.is_working(utc(2026, 8, 24, 12, 30)));
    }

    #[test]
    fn exceptions_close_a_working_day_and_open_a_weekend_day() {
        let hours = SUN_THU
            .iter()
            .map(|d| (*d, vec![TimeRange::new(9 * 60, 17 * 60)]))
            .collect();
        let exceptions = BTreeMap::from([
            (date(2026, 8, 27), vec![]), // Thursday: closed
            (date(2026, 8, 29), vec![TimeRange::new(10 * 60, 12 * 60)]), // Saturday: open
        ]);
        let cal =
            BusinessCalendar::new(UTC, days(&SUN_THU), hours, BTreeSet::new(), exceptions).unwrap();
        assert!(!cal.is_working(utc(2026, 8, 27, 10, 0)));
        assert!(cal.is_working(utc(2026, 8, 29, 11, 0)));
        // Wednesday 16:00 + 3h: 1h Wednesday, Thursday closed, 2h Saturday.
        let due = cal
            .add_business_duration(utc(2026, 8, 26, 16, 0), Duration::hours(3))
            .unwrap();
        assert_eq!(due, utc(2026, 8, 29, 12, 0));
    }

    #[test]
    fn zero_duration_returns_start_and_negative_is_an_error() {
        let cal = sun_thu_calendar();
        let start = utc(2026, 8, 27, 10, 0);
        assert_eq!(
            cal.add_business_duration(start, Duration::zero()),
            Ok(start)
        );
        assert_eq!(
            cal.add_business_duration(start, Duration::hours(-5)),
            Err(CalendarError::NegativeDuration)
        );
    }

    // ── No fabricated answers (D-517) ──────────────────────────────────────

    #[test]
    fn a_calendar_with_no_working_days_is_valid_but_yields_no_deadline() {
        let cal = BusinessCalendar::new(
            UTC,
            HashSet::new(),
            HashMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let start = utc(2026, 8, 27, 10, 0);
        assert_eq!(
            cal.add_business_duration(start, Duration::hours(2)),
            Err(CalendarError::NoWorkingTime)
        );
        assert_eq!(
            cal.next_business_instant(start),
            Err(CalendarError::NoWorkingTime)
        );
        assert_eq!(
            cal.business_duration_between(start, start + Duration::days(30)),
            Ok(Duration::zero()),
            "zero business time is a correct answer, not an error"
        );
        assert!(!cal.is_working(start));
    }

    #[test]
    fn too_little_working_time_is_search_limit_exceeded_not_a_guess() {
        // One working minute a week can never cover 600 hours in ten years.
        let cal =
            BusinessCalendar::simple(UTC, days(&[Weekday::Mon]), TimeRange::new(540, 541)).unwrap();
        assert_eq!(
            cal.add_business_duration(utc(2026, 8, 24, 0, 0), Duration::hours(600)),
            Err(CalendarError::SearchLimitExceeded)
        );
    }

    #[test]
    fn a_span_longer_than_the_scan_limit_is_an_error_not_a_truncated_sum() {
        let cal = sun_thu_calendar();
        let a = utc(2026, 1, 1, 0, 0);
        assert_eq!(
            cal.business_duration_between(a, a + Duration::days(MAX_DAYS_SCAN + 5)),
            Err(CalendarError::SearchLimitExceeded)
        );
    }

    #[test]
    fn arithmetic_past_the_representable_range_is_overflow_not_a_panic() {
        let cal = BusinessCalendar::simple(UTC, days(&WEEKDAYS), TimeRange::new(0, 1440)).unwrap();
        let near_max = DateTime::<Utc>::MAX_UTC - Duration::hours(1);
        assert_eq!(
            cal.add_business_duration(near_max, Duration::hours(3)),
            Err(CalendarError::Overflow)
        );
        assert_eq!(
            cal.add_business_duration(near_max, Duration::MAX),
            Err(CalendarError::Overflow)
        );
    }

    // ── Validation ──────────────────────────────────────────────────────────

    fn invalid(result: Result<BusinessCalendar, CalendarError>) -> String {
        match result {
            Err(CalendarError::InvalidCalendar(reason)) => reason,
            other => panic!("expected InvalidCalendar, got {other:?}"),
        }
    }

    #[test]
    fn rejects_an_overnight_or_out_of_bounds_range() {
        let reason = invalid(BusinessCalendar::simple(
            UTC,
            days(&[Weekday::Mon]),
            TimeRange::new(22 * 60, 6 * 60),
        ));
        assert!(reason.contains("cannot cross midnight"), "{reason}");
        invalid(BusinessCalendar::simple(
            UTC,
            days(&[Weekday::Mon]),
            TimeRange::new(9 * 60, 25 * 60),
        ));
        invalid(BusinessCalendar::simple(
            UTC,
            days(&[Weekday::Mon]),
            TimeRange::new(540, 540),
        ));
    }

    #[test]
    fn rejects_overlapping_ranges_but_accepts_touching_ones() {
        let build = |ranges: Vec<TimeRange>| {
            BusinessCalendar::new(
                UTC,
                days(&[Weekday::Mon]),
                HashMap::from([(Weekday::Mon, ranges)]),
                BTreeSet::new(),
                BTreeMap::new(),
            )
        };
        let reason = invalid(build(vec![
            TimeRange::new(9 * 60, 13 * 60),
            TimeRange::new(12 * 60, 17 * 60),
        ]));
        assert!(reason.contains("overlap"), "{reason}");
        assert!(
            build(vec![
                TimeRange::new(9 * 60, 12 * 60),
                TimeRange::new(12 * 60, 17 * 60)
            ])
            .is_ok()
        );
    }

    #[test]
    fn rejects_hours_for_a_non_working_day_and_a_working_day_without_hours() {
        let reason = invalid(BusinessCalendar::new(
            UTC,
            days(&[Weekday::Mon]),
            HashMap::from([
                (Weekday::Mon, vec![TimeRange::new(540, 1020)]),
                (Weekday::Sat, vec![TimeRange::new(540, 1020)]),
            ]),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(reason.contains("'sat'"), "{reason}");
        let reason = invalid(BusinessCalendar::new(
            UTC,
            days(&[Weekday::Mon, Weekday::Tue]),
            HashMap::from([(Weekday::Mon, vec![TimeRange::new(540, 1020)])]),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(reason.contains("'tue' has no working hours"), "{reason}");
    }

    #[test]
    fn rejects_a_malformed_exception() {
        let reason = invalid(BusinessCalendar::new(
            UTC,
            HashSet::new(),
            HashMap::new(),
            BTreeSet::new(),
            BTreeMap::from([(date(2026, 12, 19), vec![TimeRange::new(600, 500)])]),
        ));
        assert!(reason.contains("exception 2026-12-19"), "{reason}");
    }

    #[test]
    fn weekday_codes_round_trip_and_unknown_codes_are_none() {
        for day in WEEKDAYS {
            assert_eq!(parse_weekday_code(weekday_code(day)), Some(day));
        }
        assert_eq!(parse_weekday_code("MON"), Some(Weekday::Mon));
        assert_eq!(parse_weekday_code("monday"), None);
        assert_eq!(parse_weekday_code(""), None);
    }

    #[test]
    fn canonical_form_ignores_input_order_and_tracks_content() {
        let a = BusinessCalendar::new(
            UTC,
            days(&[Weekday::Tue, Weekday::Mon]),
            HashMap::from([
                (
                    Weekday::Tue,
                    vec![TimeRange::new(780, 1020), TimeRange::new(540, 720)],
                ),
                (Weekday::Mon, vec![TimeRange::new(540, 1020)]),
            ]),
            BTreeSet::from([date(2026, 12, 26), date(2026, 12, 25)]),
            BTreeMap::from([(date(2026, 12, 20), vec![])]),
        )
        .unwrap();
        let b = BusinessCalendar::new(
            UTC,
            days(&[Weekday::Mon, Weekday::Tue]),
            HashMap::from([
                (Weekday::Mon, vec![TimeRange::new(540, 1020)]),
                (
                    Weekday::Tue,
                    vec![TimeRange::new(540, 720), TimeRange::new(780, 1020)],
                ),
            ]),
            BTreeSet::from([date(2026, 12, 25), date(2026, 12, 26)]),
            BTreeMap::from([(date(2026, 12, 20), vec![])]),
        )
        .unwrap();
        assert_eq!(a.canonical_form(), b.canonical_form());
        assert_eq!(
            a.canonical_form(),
            "tz=UTC;working_days=mon,tue;hours=mon:09:00-17:00 (540 - 1020 minutes)|\
             tue:09:00-12:00 (540 - 720 minutes), 13:00-17:00 (780 - 1020 minutes);\
             holidays=2026-12-25,2026-12-26;exceptions=2026-12-20:closed"
        );
        assert_ne!(
            a.canonical_form(),
            with_holidays(&a, &[date(2027, 1, 1)]).canonical_form()
        );
    }

    // ── Daylight saving: exact amounts, per the crate-level contract ───────
    //
    // America/New_York 2026: clocks go forward Sun 2026-03-08 02:00 EST ->
    // 03:00 EDT, and back Sun 2026-11-01 02:00 EDT -> 01:00 EST.

    fn sunday_only(tz: Tz, range: TimeRange) -> BusinessCalendar {
        BusinessCalendar::simple(tz, days(&[Weekday::Sun]), range).unwrap()
    }

    #[test]
    fn dst_spring_forward_01_to_04_counts_two_real_hours() {
        let cal = sunday_only(ny(), TimeRange::new(60, 240));
        // 01:00 EST = 06:00Z; 04:00 EDT = 08:00Z.
        assert_eq!(
            cal.business_duration_between(utc(2026, 3, 8, 5, 0), utc(2026, 3, 9, 4, 0)),
            Ok(Duration::hours(2))
        );
        assert_eq!(
            cal.add_business_duration(utc(2026, 3, 8, 5, 0), Duration::hours(2)),
            Ok(utc(2026, 3, 8, 8, 0))
        );
    }

    #[test]
    fn dst_spring_forward_range_starting_in_the_gap_starts_after_it() {
        let cal = sunday_only(ny(), TimeRange::new(120, 240)); // 02:00-04:00
        // 02:00 never happens; the range runs 03:00 EDT (07:00Z) to 08:00Z.
        assert_eq!(
            cal.business_duration_between(utc(2026, 3, 8, 5, 0), utc(2026, 3, 9, 4, 0)),
            Ok(Duration::hours(1))
        );
        assert!(!cal.is_working(utc(2026, 3, 8, 6, 30))); // 01:30 EST
        assert!(cal.is_working(utc(2026, 3, 8, 7, 30))); // 03:30 EDT
        assert_eq!(
            cal.next_business_instant(utc(2026, 3, 8, 5, 0)),
            Ok(utc(2026, 3, 8, 7, 0))
        );
    }

    #[test]
    fn dst_spring_forward_whole_day_is_twenty_three_hours() {
        let cal = sunday_only(ny(), TimeRange::new(0, 1440));
        // 00:00 EST = 05:00Z; 24:00 (Monday 00:00 EDT) = 04:00Z next day.
        let start = utc(2026, 3, 8, 5, 0);
        assert_eq!(
            cal.add_business_duration(start, Duration::hours(23)),
            Ok(utc(2026, 3, 9, 4, 0))
        );
        // The 24th hour is the first hour of the next Sunday (00:00 EDT = 04:00Z).
        assert_eq!(
            cal.add_business_duration(start, Duration::hours(24)),
            Ok(utc(2026, 3, 15, 5, 0))
        );
    }

    #[test]
    fn dst_fall_back_00_to_04_counts_five_real_hours() {
        let cal = sunday_only(ny(), TimeRange::new(0, 240));
        // 00:00 EDT = 04:00Z; 04:00 EST = 09:00Z.
        assert_eq!(
            cal.business_duration_between(utc(2026, 11, 1, 3, 0), utc(2026, 11, 2, 5, 0)),
            Ok(Duration::hours(5))
        );
        assert!(cal.is_working(utc(2026, 11, 1, 5, 30))); // 01:30 EDT
        assert!(cal.is_working(utc(2026, 11, 1, 6, 30))); // 01:30 EST, the repeat
    }

    #[test]
    fn dst_fall_back_repeated_wall_time_means_its_earlier_occurrence() {
        let cal = sunday_only(ny(), TimeRange::new(60, 90)); // 01:00-01:30
        // First pass: 01:00-01:30 EDT = 05:00Z-05:30Z. The second pass
        // (01:00-01:30 EST = 06:00Z-06:30Z) is not working time.
        assert_eq!(
            cal.business_duration_between(utc(2026, 11, 1, 3, 0), utc(2026, 11, 2, 5, 0)),
            Ok(Duration::minutes(30))
        );
        assert!(cal.is_working(utc(2026, 11, 1, 5, 15)));
        assert!(!cal.is_working(utc(2026, 11, 1, 6, 15)));
    }

    #[test]
    fn southern_hemisphere_dst_days_are_twenty_three_and_twenty_five_hours() {
        let sydney: Tz = "Australia/Sydney".parse().unwrap();
        let cal = sunday_only(sydney, TimeRange::new(0, 1440));
        // Sun 2026-10-04: 00:00 AEST (14:00Z Sat) to 24:00 AEDT (13:00Z Sun).
        assert_eq!(
            cal.business_duration_between(utc(2026, 10, 3, 14, 0), utc(2026, 10, 4, 13, 0)),
            Ok(Duration::hours(23))
        );
        // Sun 2026-04-05: 00:00 AEDT (13:00Z Sat) to 24:00 AEST (14:00Z Sun).
        assert_eq!(
            cal.business_duration_between(utc(2026, 4, 4, 13, 0), utc(2026, 4, 5, 14, 0)),
            Ok(Duration::hours(25))
        );
    }

    #[test]
    fn fixed_offset_zones_interpret_wall_clock_locally() {
        let dubai: Tz = "Asia/Dubai".parse().unwrap(); // UTC+4, no DST
        let cal = with_holidays(
            &BusinessCalendar::simple(dubai, days(&SUN_THU), TimeRange::new(540, 1020)).unwrap(),
            &[date(2026, 8, 28)],
        );
        assert!(!cal.is_working(utc(2026, 8, 27, 4, 30))); // 08:30 local
        assert!(cal.is_working(utc(2026, 8, 27, 5, 30))); // 09:30 local
        // Thursday 16:00 local (12:00Z) + 8h -> Sunday 16:00 local (12:00Z).
        assert_eq!(
            cal.add_business_duration(utc(2026, 8, 27, 12, 0), Duration::hours(8)),
            Ok(utc(2026, 8, 30, 12, 0))
        );

        let kolkata: Tz = "Asia/Kolkata".parse().unwrap(); // UTC+5:30
        let cal = BusinessCalendar::simple(
            kolkata,
            days(&[Weekday::Mon, Weekday::Tue]),
            TimeRange::new(540, 1020),
        )
        .unwrap();
        assert!(cal.is_working(utc(2026, 8, 24, 3, 30))); // 09:00 IST
        assert!(!cal.is_working(utc(2026, 8, 24, 3, 29)));
        assert_eq!(
            cal.business_duration_between(utc(2026, 8, 24, 3, 30), utc(2026, 8, 24, 11, 30)),
            Ok(Duration::hours(8))
        );
    }

    #[test]
    fn an_instant_late_in_the_utc_day_can_be_the_next_local_date() {
        let dubai: Tz = "Asia/Dubai".parse().unwrap();
        let cal =
            BusinessCalendar::simple(dubai, days(&[Weekday::Fri]), TimeRange::new(0, 120)).unwrap();
        // Thursday 2026-08-27 21:00Z is Friday 01:00 in Dubai.
        assert!(cal.is_working(utc(2026, 8, 27, 21, 0)));
    }

    // ── BCL-F3 / BCL-F9: the shapes where the calculators disagree ────────
    //
    // Both tests below are Phase 0 of the component plan: they encode the
    // defect before it is fixed. A 24x7 calendar has no non-working time at
    // all, so in every zone shape the four calculators must agree with plain
    // real time.

    /// Every weekday, `00:00-24:00` — working time is all real time.
    fn always_open(tz: Tz) -> BusinessCalendar {
        BusinessCalendar::simple(tz, days(&WEEKDAYS), TimeRange::new(0, MINUTES_PER_DAY)).unwrap()
    }

    /// BCL-P0.1 (BCL-F3). In `America/St_Johns` the 2010 fall-back happens at
    /// 00:01 local, so the clock goes back *across* local midnight: the second
    /// pass through 23:30 is an instant of 2010-11-06's evening that the
    /// current model files under 2010-11-07. `add_business_duration` walks to
    /// the 2010-11-07 range and answers 04:00Z; `business_duration_between`
    /// used to jump its cursor a whole day and answer zero.
    #[test]
    fn fall_back_across_midnight_add_and_between_agree() {
        let cal = always_open("America/St_Johns".parse().unwrap());
        let a = utc(2010, 11, 7, 3, 0); // 2010-11-06 23:30 NST, the second pass
        let due = cal
            .add_business_duration(a, Duration::hours(1))
            .expect("a 24x7 calendar always has an answer");
        assert_eq!(due, utc(2010, 11, 7, 4, 0));
        assert_eq!(
            cal.business_duration_between(a, due),
            Ok(Duration::hours(1)),
            "the elapsed time back from the answer must be the duration asked for"
        );
        assert_eq!(
            cal.is_working(a),
            cal.next_business_instant(a) == Ok(a),
            "is_working and next_business_instant must agree on the same instant"
        );
    }

    /// BCL-P0.2 (BCL-F9). `Pacific/Apia` skipped 2011-12-30 entirely when it
    /// crossed the date line. Real time is continuous, so on a 24x7 calendar
    /// the skipped local date holds no working time — it is not an error.
    #[test]
    fn a_whole_skipped_day_has_no_working_time_not_an_error() {
        let cal = always_open("Pacific/Apia".parse().unwrap());
        assert_eq!(
            cal.business_duration_between(utc(2011, 12, 29, 0, 0), utc(2012, 1, 1, 0, 0)),
            Ok(Duration::hours(72)),
            "three real days on a calendar open around the clock"
        );
        assert_eq!(
            cal.add_business_duration(utc(2011, 12, 29, 0, 0), Duration::hours(72)),
            Ok(utc(2012, 1, 1, 0, 0)),
            "adding three real days must cross the skipped local date"
        );
    }

    // ── The range rule is public (BCL-0.2) ────────────────────────────────

    #[test]
    fn try_new_rejects_an_overnight_range() {
        assert!(matches!(
            TimeRange::try_new(1320, 420),
            Err(CalendarError::InvalidCalendar(reason))
                if reason.contains("22:00-07:00") && reason.contains("cannot cross midnight")
        ));
    }

    #[test]
    fn try_new_accepts_a_day_range() {
        assert_eq!(TimeRange::try_new(540, 1020), Ok(TimeRange::new(540, 1020)));
    }

    #[test]
    fn is_valid_is_the_public_range_rule() {
        // An inline const block proves the rule is callable in a constant context.
        const { assert!(TimeRange::new(0, MINUTES_PER_DAY).is_valid()) };
        assert!(TimeRange::new(0, 1).is_valid());
        assert!(!TimeRange::new(600, 500).is_valid());
        assert!(!TimeRange::new(540, 540).is_valid());
        assert!(!TimeRange::new(0, MINUTES_PER_DAY + 1).is_valid());
    }

    // ── Errors an admin can read (BCL-0.3) ──────────────────────────────

    #[test]
    fn range_errors_render_hh_mm_beside_the_raw_minutes() {
        let reason = invalid(BusinessCalendar::simple(
            UTC,
            days(&[Weekday::Mon]),
            TimeRange::new(22 * 60, 6 * 60),
        ));
        assert!(reason.contains("22:00-06:00"), "{reason}");
        assert!(reason.contains("1320"), "{reason}");
        assert!(reason.contains("cannot cross midnight"), "{reason}");

        let reason = invalid(BusinessCalendar::simple(
            UTC,
            days(&[Weekday::Mon]),
            TimeRange::new(9 * 60, 25 * 60),
        ));
        assert!(reason.contains("09:00-25:00"), "{reason}");

        let reason = invalid(BusinessCalendar::new(
            UTC,
            days(&[Weekday::Mon]),
            HashMap::from([(
                Weekday::Mon,
                vec![
                    TimeRange::new(9 * 60, 13 * 60),
                    TimeRange::new(12 * 60, 17 * 60),
                ],
            )]),
            BTreeSet::new(),
            BTreeMap::new(),
        ));
        assert!(reason.contains("09:00-13:00"), "{reason}");
        assert!(reason.contains("12:00-17:00"), "{reason}");
        assert!(reason.contains("overlap"), "{reason}");
    }

    #[test]
    fn a_range_bound_of_1440_renders_as_24_00() {
        assert_eq!(render_minute(MINUTES_PER_DAY), "24:00");
        assert_eq!(render_minute(0), "00:00");
        assert_eq!(render_minute(9 * 60 + 5), "09:05");
        assert_eq!(
            render_range(TimeRange::new(0, MINUTES_PER_DAY)),
            "00:00-24:00 (0 - 1440 minutes)"
        );
    }

    // ── The evidence records the tz rules too (BCL-2.1a) ──────────────────

    #[test]
    fn tzdb_version_is_a_real_release() {
        let bytes = TZDB_VERSION.as_bytes();
        assert_eq!(
            bytes.len(),
            5,
            "expected a YYYYx version, got {TZDB_VERSION}"
        );
        assert!(bytes[..4].iter().all(u8::is_ascii_digit), "{TZDB_VERSION}");
        assert!(bytes[4].is_ascii_lowercase(), "{TZDB_VERSION}");
    }

    #[test]
    fn tzdb_version_is_absent_from_every_canonical_form() {
        for cal in [sun_thu_calendar(), always_open(ny())] {
            assert!(
                !cal.canonical_form().contains(TZDB_VERSION),
                "folding the version into the form would move every content hash"
            );
        }
    }

    // ── Zone shapes: the transitions that break a naive walk (BCL-1.2) ───

    /// Fails if the compiled tz data stops containing the gap a shape test
    /// targets, so a chrono-tz bump cannot silently drop the coverage.
    fn assert_gap(tz: Tz, naive: NaiveDateTime) {
        assert!(
            matches!(tz.from_local_datetime(&naive), LocalResult::None),
            "{naive} is not a spring-forward gap in {}",
            tz.name()
        );
    }

    /// The same for a repeated wall time (clocks go back).
    fn assert_fold(tz: Tz, naive: NaiveDateTime) {
        assert!(
            matches!(tz.from_local_datetime(&naive), LocalResult::Ambiguous(..)),
            "{naive} is not a repeated wall time in {}",
            tz.name()
        );
    }

    fn local(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
        date(y, m, d).and_hms_opt(h, min, 0).unwrap()
    }

    fn sundays(tz: Tz) -> BusinessCalendar {
        BusinessCalendar::simple(tz, days(&[Weekday::Sun]), TimeRange::new(0, 1440)).unwrap()
    }

    /// `America/Havana`: the spring-forward happens **at** local midnight
    /// (00:00 becomes 01:00), and the autumn fold lands on midnight too.
    #[test]
    fn havana_midnight_gap_and_midnight_fold() {
        let tz: Tz = "America/Havana".parse().unwrap();
        assert_eq!(date(2026, 3, 8).weekday(), Weekday::Sun);
        assert_eq!(date(2026, 11, 1).weekday(), Weekday::Sun);
        assert_gap(tz, local(2026, 3, 8, 0, 0));
        assert_fold(tz, local(2026, 11, 1, 0, 0));
        let cal = sundays(tz);
        // Sun 2026-03-08: 00:00 EST(-5) is 05:00Z; 24:00 -> Mon 00:00 EDT(-4) is 04:00Z.
        assert_eq!(
            cal.next_business_instant(utc(2026, 3, 8, 0, 0)),
            Ok(utc(2026, 3, 8, 5, 0))
        );
        assert_eq!(
            cal.business_duration_between(utc(2026, 3, 8, 5, 0), utc(2026, 3, 9, 4, 0)),
            Ok(Duration::hours(23))
        );
        assert_eq!(
            cal.add_business_duration(utc(2026, 3, 8, 5, 0), Duration::hours(23)),
            Ok(utc(2026, 3, 9, 4, 0))
        );
        // Sun 2026-11-01: 00:00 EDT(-4) is 04:00Z; 24:00 -> Mon 00:00 EST(-5) is 05:00Z.
        assert_eq!(
            cal.business_duration_between(utc(2026, 11, 1, 4, 0), utc(2026, 11, 2, 5, 0)),
            Ok(Duration::hours(25))
        );
        assert!(
            cal.is_working(utc(2026, 11, 1, 5, 30)),
            "the repeated 00:30 EST is still Sunday's working time"
        );
        assert_eq!(
            cal.add_business_duration(utc(2026, 11, 1, 4, 0), Duration::hours(25)),
            Ok(utc(2026, 11, 2, 5, 0))
        );
    }

    /// `America/Santiago`: the autumn fold happens **at** local midnight —
    /// 00:00 becomes 23:00 of the day before — so the day before lasts 25
    /// real hours, and the spring gap at midnight starts the day at 01:00.
    #[test]
    fn santiago_midnight_fold_and_midnight_gap() {
        let tz: Tz = "America/Santiago".parse().unwrap();
        assert_eq!(date(2026, 4, 4).weekday(), Weekday::Sat);
        assert_eq!(date(2026, 9, 6).weekday(), Weekday::Sun);
        // The repeated wall times are the last hour of 2026-04-04, not midnight.
        assert_fold(tz, local(2026, 4, 4, 23, 30));
        assert_gap(tz, local(2026, 9, 6, 0, 0));

        let open = always_open(tz);
        // Local 2026-04-04 runs 00:00 -03:00 (03:00Z) to 00:00 -04:00 next day (04:00Z).
        assert_eq!(
            open.business_duration_between(utc(2026, 4, 4, 3, 0), utc(2026, 4, 5, 4, 0)),
            Ok(Duration::hours(25))
        );
        let second_pass = utc(2026, 4, 5, 3, 30); // local 2026-04-04 23:30
        assert!(open.is_working(second_pass));
        assert_eq!(open.next_business_instant(second_pass), Ok(second_pass));
        assert_eq!(
            open.business_duration_between(second_pass, utc(2026, 4, 5, 4, 30)),
            Ok(Duration::hours(1))
        );
        assert_eq!(
            open.add_business_duration(second_pass, Duration::hours(1)),
            Ok(utc(2026, 4, 5, 4, 30))
        );

        // Sun 2026-09-06: 00:00 is skipped, so the day starts at 01:00 -03:00 (04:00Z)
        // and ends at Mon 00:00 -03:00 (03:00Z the next day).
        let cal = sundays(tz);
        assert_eq!(
            cal.next_business_instant(utc(2026, 9, 6, 0, 0)),
            Ok(utc(2026, 9, 6, 4, 0))
        );
        assert_eq!(
            cal.business_duration_between(utc(2026, 9, 6, 4, 0), utc(2026, 9, 7, 3, 0)),
            Ok(Duration::hours(23))
        );
        assert_eq!(
            cal.add_business_duration(utc(2026, 9, 6, 4, 0), Duration::hours(23)),
            Ok(utc(2026, 9, 7, 3, 0))
        );
    }

    /// `Australia/Lord_Howe` moves its clocks by **30 minutes**.
    #[test]
    fn lord_howe_thirty_minute_dst_days_are_24_5_and_23_5_hours() {
        let tz: Tz = "Australia/Lord_Howe".parse().unwrap();
        assert_eq!(date(2026, 4, 5).weekday(), Weekday::Sun);
        assert_eq!(date(2026, 10, 4).weekday(), Weekday::Sun);
        assert_fold(tz, local(2026, 4, 5, 1, 45));
        assert_gap(tz, local(2026, 10, 4, 2, 15));
        let cal = sundays(tz);
        // Sun 2026-04-05: 00:00 +11:00 (2026-04-04 13:00Z) to Mon 00:00 +10:30 (2026-04-05 13:30Z).
        assert_eq!(
            cal.business_duration_between(utc(2026, 4, 4, 13, 0), utc(2026, 4, 5, 13, 30)),
            Ok(Duration::minutes(24 * 60 + 30))
        );
        assert_eq!(
            cal.add_business_duration(utc(2026, 4, 4, 13, 0), Duration::minutes(24 * 60 + 30)),
            Ok(utc(2026, 4, 5, 13, 30))
        );
        // Sun 2026-10-04: 00:00 +10:30 (2026-10-03 13:30Z) to Mon 00:00 +11:00 (2026-10-04 13:00Z).
        assert_eq!(
            cal.business_duration_between(utc(2026, 10, 3, 13, 30), utc(2026, 10, 4, 13, 0)),
            Ok(Duration::minutes(24 * 60 - 30))
        );
    }

    /// `America/St_Johns` 2010: exact amounts for the fall-back that crosses
    /// local midnight (BCL-P0.1 is the agreement check on a 24x7 calendar).
    #[test]
    fn st_johns_fall_back_across_midnight_exact_amounts() {
        let tz: Tz = "America/St_Johns".parse().unwrap();
        assert_fold(tz, local(2010, 11, 7, 0, 0));
        let cal = always_open(tz);
        // 2010-11-06 00:00 NDT (-2:30) is 02:30Z; the fold runs from
        // 2010-11-07 00:01 NDT (02:31Z) back to 2010-11-06 23:01 NST (-3:30).
        assert_eq!(
            cal.business_duration_between(utc(2010, 11, 6, 2, 30), utc(2010, 11, 8, 3, 30)),
            Ok(Duration::hours(49)),
            "two local dates that together cover 49 real hours"
        );
        assert_eq!(
            cal.add_business_duration(utc(2010, 11, 6, 2, 30), Duration::hours(49)),
            Ok(utc(2010, 11, 8, 3, 30))
        );
    }

    // ── Near the scan limit (BCL-1.3) ───────────────────────────────────

    #[test]
    fn a_span_just_inside_the_scan_limit_is_summed_not_refused() {
        let cal = sun_thu_calendar();
        let a = utc(2026, 1, 1, 0, 0);
        assert!(
            cal.business_duration_between(a, a + Duration::days(MAX_DAYS_SCAN - 1))
                .is_ok(),
            "a span inside the limit must be summed, not reported as too long"
        );
        assert!(matches!(
            cal.business_duration_between(a, a + Duration::days(MAX_DAYS_SCAN + 5)),
            Err(CalendarError::SearchLimitExceeded)
        ));
    }

    #[test]
    fn add_near_the_scan_limit_is_ok_inside_and_exceeded_outside() {
        // One working hour a week: 3 660 scanned dates reach about 522 hours.
        let cal =
            BusinessCalendar::simple(UTC, days(&[Weekday::Mon]), TimeRange::new(540, 600)).unwrap();
        let start = utc(2026, 1, 5, 0, 0); // a Monday, before the range opens
        assert!(
            cal.add_business_duration(start, Duration::hours(500))
                .is_ok()
        );
        assert_eq!(
            cal.add_business_duration(start, Duration::hours(600)),
            Err(CalendarError::SearchLimitExceeded)
        );
    }

    // ── A closed calendar answers at once (BCL-3.2) ─────────────────────

    fn closed_calendar() -> BusinessCalendar {
        BusinessCalendar::new(
            UTC,
            HashSet::new(),
            HashMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    #[test]
    fn has_working_time_recognises_a_closed_calendar_and_an_opened_exception() {
        assert!(!closed_calendar().has_working_time());
        assert!(sun_thu_calendar().has_working_time());
        let opened = BusinessCalendar::new(
            UTC,
            HashSet::new(),
            HashMap::new(),
            BTreeSet::new(),
            BTreeMap::from([(date(2026, 8, 29), vec![TimeRange::new(600, 720)])]),
        )
        .unwrap();
        assert!(opened.has_working_time());
        let one_closed_date = BusinessCalendar::new(
            UTC,
            days(&[Weekday::Mon]),
            HashMap::from([(Weekday::Mon, vec![TimeRange::new(540, 1020)])]),
            BTreeSet::new(),
            BTreeMap::from([(date(2026, 8, 24), vec![])]),
        )
        .unwrap();
        assert!(
            one_closed_date.has_working_time(),
            "one closed date does not close the calendar"
        );
    }

    // ── The one interval walk (BCL-3.1) ─────────────────────────────────

    #[test]
    fn working_intervals_coalesce_across_midnight_and_skip_a_closed_day() {
        let cal = sun_thu_calendar();
        let intervals = cal
            .working_intervals(utc(2026, 8, 27, 8, 0), utc(2026, 8, 31, 0, 0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            intervals,
            vec![
                (utc(2026, 8, 27, 9, 0), utc(2026, 8, 27, 17, 0)), // Thursday
                (utc(2026, 8, 30, 9, 0), utc(2026, 8, 30, 17, 0)), // Sunday; Friday and Saturday closed
            ]
        );

        let open = always_open(UTC);
        let intervals = open
            .working_intervals(utc(2026, 8, 27, 8, 0), utc(2026, 8, 29, 8, 0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            intervals,
            vec![(utc(2026, 8, 27, 8, 0), utc(2026, 8, 29, 8, 0))],
            "a calendar open around the clock is one interval, not one per date"
        );

        assert_eq!(
            open.working_intervals(utc(2026, 8, 27, 8, 0), utc(2026, 8, 27, 8, 0))
                .count(),
            0
        );
        assert_eq!(
            closed_calendar()
                .working_intervals(utc(2026, 8, 27, 8, 0), utc(2026, 8, 28, 8, 0))
                .count(),
            0
        );
    }

    #[test]
    fn working_intervals_handle_the_fall_back_across_midnight() {
        let cal = always_open("America/St_Johns".parse().unwrap());
        let intervals = cal
            .working_intervals(utc(2010, 11, 6, 0, 0), utc(2010, 11, 9, 0, 0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            intervals,
            vec![(utc(2010, 11, 6, 0, 0), utc(2010, 11, 9, 0, 0))],
            "the fold's two dates are contiguous working time"
        );
    }

    #[test]
    fn working_intervals_skip_a_whole_skipped_local_date() {
        let cal = always_open("Pacific/Apia".parse().unwrap());
        let intervals = cal
            .working_intervals(utc(2011, 12, 29, 0, 0), utc(2012, 1, 1, 0, 0))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            intervals,
            vec![(utc(2011, 12, 29, 0, 0), utc(2012, 1, 1, 0, 0))]
        );
    }

    // ── Measured performance (BCL-4.1) ─────────────────────────────────

    /// Three ranges a day, Mon-Fri, `America/New_York` — the shape BCL-4.1
    /// measures.
    fn ny_three_ranges() -> BusinessCalendar {
        let weekdays = days(&[
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
            Weekday::Fri,
        ]);
        let ranges = vec![
            TimeRange::new(9 * 60, 12 * 60),
            TimeRange::new(13 * 60, 17 * 60),
            TimeRange::new(18 * 60, 20 * 60),
        ];
        let hours = weekdays.iter().map(|d| (*d, ranges.clone())).collect();
        BusinessCalendar::new(ny(), weekdays, hours, BTreeSet::new(), BTreeMap::new()).unwrap()
    }

    #[test]
    #[ignore = "BCL-4.1 timing measurement: cargo test --release -p attome-calendar -- --ignored --nocapture timing"]
    fn timing_between_over_3650_days_with_three_ranges_a_day() {
        let cal = ny_three_ranges();
        let start = utc(2026, 1, 1, 0, 0);
        let end = start + Duration::days(3650);
        let _ = cal.business_duration_between(start, end).unwrap();
        let began = std::time::Instant::now();
        let total = cal.business_duration_between(start, end).unwrap();
        let measured = began.elapsed();
        println!(
            "BCL-4.1(a) business_duration_between over 3650 days: {measured:?} (business time {total:?})"
        );
        assert!(
            measured <= std::time::Duration::from_millis(5),
            "budget 5 ms, measured {measured:?}"
        );
    }

    #[test]
    #[ignore = "BCL-4.1 timing measurement: cargo test --release -p attome-calendar -- --ignored --nocapture timing"]
    fn timing_add_two_thousand_business_hours() {
        let cal = ny_three_ranges();
        let start = utc(2026, 1, 1, 0, 0);
        let _ = cal
            .add_business_duration(start, Duration::hours(2000))
            .unwrap();
        let began = std::time::Instant::now();
        let due = cal
            .add_business_duration(start, Duration::hours(2000))
            .unwrap();
        let measured = began.elapsed();
        println!(
            "BCL-4.1(b) add_business_duration of 2000 business hours: {measured:?} (due {due})"
        );
        assert!(
            measured <= std::time::Duration::from_millis(1),
            "budget 1 ms, measured {measured:?}"
        );
    }

    #[test]
    #[ignore = "BCL-4.1 timing measurement: cargo test --release -p attome-calendar -- --ignored --nocapture timing"]
    fn timing_closed_calendar_refuses_immediately() {
        let cal = closed_calendar();
        let start = utc(2026, 1, 1, 0, 0);
        let _ = cal.next_business_instant(start);
        let began = std::time::Instant::now();
        assert_eq!(
            cal.next_business_instant(start),
            Err(CalendarError::NoWorkingTime)
        );
        assert_eq!(
            cal.add_business_duration(start, Duration::hours(8)),
            Err(CalendarError::NoWorkingTime)
        );
        let measured = began.elapsed();
        println!("BCL-4.1(c) closed-calendar refusal: {measured:?}");
        assert!(
            measured <= std::time::Duration::from_micros(10),
            "budget 10 us, measured {measured:?}"
        );
    }

    /// An always-open calendar merges every date into one interval, so the
    /// early answer from the growing interval must match the full walk's.
    #[test]
    fn an_always_open_calendar_answers_like_wall_clock_time() {
        for cal in [always_open(UTC), always_open(ny())] {
            // 2026-03-08 is New York's spring-forward day.
            let start = utc(2026, 3, 7, 15, 20);
            assert_eq!(cal.next_business_instant(start), Ok(start));
            for duration in [
                Duration::minutes(90),
                Duration::days(2),
                Duration::days(400),
            ] {
                assert_eq!(
                    cal.add_business_duration(start, duration),
                    Ok(start + duration),
                    "{duration:?}"
                );
            }
            assert_eq!(
                cal.add_business_duration(start, Duration::days(MAX_DAYS_SCAN + 5)),
                Err(CalendarError::SearchLimitExceeded)
            );
        }
    }

    #[test]
    #[ignore = "BCL-4.1 timing measurement: cargo test --release -p attome-calendar -- --ignored --nocapture timing"]
    fn timing_always_open_calendar_answers_without_the_full_scan() {
        let cal = always_open(ny());
        let start = utc(2026, 1, 1, 0, 0);
        let _ = cal.add_business_duration(start, Duration::hours(8));
        let began = std::time::Instant::now();
        assert_eq!(cal.next_business_instant(start), Ok(start));
        assert_eq!(
            cal.add_business_duration(start, Duration::hours(8)),
            Ok(start + Duration::hours(8))
        );
        let measured = began.elapsed();
        println!("BCL-4.1(d) 24x7 next instant + 8 business hours: {measured:?}");
        assert!(
            measured <= std::time::Duration::from_micros(50),
            "budget 50 us, measured {measured:?}"
        );
    }

    #[test]
    fn timing_tests_print_the_environment_they_measured() {
        println!(
            "BCL-4.1 environment: {} {} ({} logical cores), profile {}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::thread::available_parallelism().map_or(0, |n| n.get()),
            if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Real zones covering no DST, a half-hour offset, and both hemispheres'
    /// DST rules.
    const ZONES: [&str; 12] = [
        "UTC",
        "America/New_York",
        "Europe/London",
        "Australia/Sydney",
        "Asia/Dubai",
        "Asia/Kolkata",
        "America/Sao_Paulo",
        "America/Havana",
        "America/Santiago",
        "Australia/Lord_Howe",
        "America/St_Johns",
        "Pacific/Apia",
    ];

    /// Known DST transition instants (UTC) the instant generator clusters
    /// around, so transition days are exercised deliberately, not by luck.
    fn dst_transitions() -> Vec<DateTime<Utc>> {
        [
            (2026, 3, 8, 7),    // New York spring forward
            (2026, 11, 1, 6),   // New York fall back
            (2026, 3, 29, 1),   // London spring forward
            (2026, 10, 25, 1),  // London fall back
            (2026, 4, 4, 16),   // Sydney fall back
            (2026, 10, 3, 16),  // Sydney spring forward
            (2026, 3, 8, 5),    // Havana: midnight spring forward
            (2026, 11, 1, 5),   // Havana: midnight fall back
            (2026, 4, 5, 3),    // Santiago: fall back across midnight
            (2026, 9, 6, 4),    // Santiago: midnight spring forward
            (2026, 4, 4, 15),   // Lord Howe: 30-minute fall back
            (2026, 10, 3, 15),  // Lord Howe: 30-minute spring forward
            (2010, 11, 7, 2),   // St John's: fall back across midnight
            (2011, 12, 30, 10), // Apia: a whole skipped day
        ]
        .into_iter()
        .map(|(y, m, d, h)| Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap())
        .collect()
    }

    /// 1-3 non-overlapping ranges drawn from sorted, distinct cut points.
    fn arb_ranges() -> impl Strategy<Value = Vec<TimeRange>> {
        prop::collection::btree_set(0u16..=MINUTES_PER_DAY, 2..=6).prop_map(|cuts| {
            let cuts: Vec<u16> = cuts.into_iter().collect();
            cuts.chunks_exact(2)
                .map(|pair| TimeRange::new(pair[0], pair[1]))
                .collect()
        })
    }

    /// 1990-01-01 through 2037 — forty-eight years, so the generators cover
    /// historic and near-future DST rules, not one three-year slice (BCL-1.3).
    fn arb_date() -> impl Strategy<Value = NaiveDate> {
        (0i64..(366 * 48)).prop_map(|offset| {
            NaiveDate::from_ymd_opt(1990, 1, 1).unwrap() + Duration::days(offset)
        })
    }

    prop_compose! {
        fn arb_calendar()(
            zone in prop::sample::select(ZONES.to_vec()),
            day_hours in prop::collection::vec(prop::option::of(arb_ranges()), 7),
            holidays in prop::collection::btree_set(arb_date(), 0..12),
            exceptions in prop::collection::btree_map(
                arb_date(),
                prop::option::of(arb_ranges()),
                0..6,
            ),
        ) -> BusinessCalendar {
            let mut working_days = HashSet::new();
            let mut hours = HashMap::new();
            for (day, ranges) in WEEKDAYS.into_iter().zip(day_hours) {
                if let Some(ranges) = ranges {
                    working_days.insert(day);
                    hours.insert(day, ranges);
                }
            }
            let exceptions = exceptions
                .into_iter()
                .map(|(date, ranges)| (date, ranges.unwrap_or_default()))
                .collect();
            BusinessCalendar::new(zone.parse().unwrap(), working_days, hours, holidays, exceptions)
                .expect("the generator only builds valid calendars")
        }
    }

    fn arb_instant() -> impl Strategy<Value = DateTime<Utc>> {
        let uniform = (0i64..(366 * 48 * 24 * 60)).prop_map(|minutes| {
            Utc.with_ymd_and_hms(1990, 1, 1, 0, 0, 0).unwrap() + Duration::minutes(minutes)
        });
        let near_dst = (
            prop::sample::select(dst_transitions()),
            -(48i64 * 60)..(48 * 60),
        )
            .prop_map(|(transition, minutes)| transition + Duration::minutes(minutes));
        prop_oneof![uniform, near_dst]
    }

    fn arb_duration() -> impl Strategy<Value = Duration> {
        (1i64..(60 * 24 * 400)).prop_map(Duration::minutes)
    }

    /// The duration the minute oracle can walk: at most two days of business
    /// time, per BCL-1.1.
    fn arb_oracle_duration() -> impl Strategy<Value = Duration> {
        (1i64..(60 * 24 * 2)).prop_map(Duration::minutes)
    }

    /// A result landing exactly where a range closes is the one legitimate
    /// non-working answer `add_business_duration` can give.
    fn is_working_or_a_range_close(cal: &BusinessCalendar, t: DateTime<Utc>) -> bool {
        if cal.is_working(t) {
            return true;
        }
        let local_date = t.with_timezone(&cal.tz()).date_naive();
        [local_date.pred_opt(), Some(local_date)]
            .into_iter()
            .flatten()
            .any(|d| {
                cal.ranges_for_date(d)
                    .iter()
                    .any(|r| cal.range_bounds(d, *r).is_ok_and(|(_, end)| end == t))
            })
    }

    // ── BCL-1.1: an independent oracle ──────────────────────────────
    //
    // Everything below re-derives the answer from `chrono`/`chrono-tz` and the
    // public accessors instead of calling the crate's own private helpers, so a
    // shared mistake (BCL-F3 was one) cannot pass every property.

    /// The DST rule itself: the earlier occurrence of a repeated wall time, the
    /// first real instant after a skipped one.
    fn oracle_resolve(tz: Tz, naive: NaiveDateTime) -> Option<DateTime<Utc>> {
        let mut candidate = naive;
        for _ in 0..=(26 * 60) {
            match tz.from_local_datetime(&candidate) {
                LocalResult::Single(dt) => return Some(dt.with_timezone(&Utc)),
                LocalResult::Ambiguous(earlier, _later) => {
                    return Some(earlier.with_timezone(&Utc));
                }
                LocalResult::None => {
                    candidate = candidate.checked_add_signed(Duration::minutes(1))?;
                }
            }
        }
        None
    }

    /// The precedence rule (holiday > exception > weekday default), re-derived
    /// from the public accessors rather than the crate's own `ranges_for_date`.
    fn oracle_ranges(cal: &BusinessCalendar, date: NaiveDate) -> Vec<TimeRange> {
        if cal.holidays().contains(&date) {
            return Vec::new();
        }
        if let Some(exception) = cal.exceptions().get(&date) {
            return exception.clone();
        }
        let weekday = date.weekday();
        if !cal.working_days().contains(&weekday) {
            return Vec::new();
        }
        cal.hours().get(&weekday).cloned().unwrap_or_default()
    }

    fn oracle_bounds(
        cal: &BusinessCalendar,
        date: NaiveDate,
        range: TimeRange,
    ) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
        let midnight = date.and_time(NaiveTime::MIN);
        let at = |minute: u16| {
            midnight
                .checked_add_signed(Duration::minutes(i64::from(minute)))
                .and_then(|naive| oracle_resolve(cal.tz(), naive))
        };
        Some((at(range.start_minute)?, at(range.end_minute)?))
    }

    /// `is_working` re-derived: the instant's local date and the following one.
    fn oracle_is_working(cal: &BusinessCalendar, instant: DateTime<Utc>) -> bool {
        let local = instant.with_timezone(&cal.tz());
        let date = local.date_naive();
        [Some(date), date.succ_opt()]
            .into_iter()
            .flatten()
            .any(|d| {
                oracle_ranges(cal, d).iter().any(|r| {
                    oracle_bounds(cal, d, *r).is_some_and(|(start, end)| {
                        end > start && instant >= start && instant < end
                    })
                })
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(192))]

        #[test]
        fn add_never_goes_backward_and_lands_on_working_time(
            cal in arb_calendar(),
            start in arb_instant(),
            d in arb_duration(),
        ) {
            if let Ok(due) = cal.add_business_duration(start, d) {
                prop_assert!(due > start);
                prop_assert!(is_working_or_a_range_close(&cal, due), "due {} is not working time", due);
            }
        }

        /// The forward and elapsed calculators agree exactly: whatever
        /// `add` returns, the business time between the start and it is `d`.
        #[test]
        fn add_then_between_round_trips(
            cal in arb_calendar(),
            start in arb_instant(),
            d in arb_duration(),
        ) {
            if let Ok(due) = cal.add_business_duration(start, d) {
                prop_assert_eq!(cal.business_duration_between(start, due), Ok(d));
            }
        }

        #[test]
        fn add_is_monotonic_in_its_start(
            cal in arb_calendar(),
            a in arb_instant(),
            b in arb_instant(),
            d in arb_duration(),
        ) {
            let (early, late) = if a <= b { (a, b) } else { (b, a) };
            if let (Ok(x), Ok(y)) = (
                cal.add_business_duration(early, d),
                cal.add_business_duration(late, d),
            ) {
                prop_assert!(x <= y);
            }
        }

        #[test]
        fn within_range_add_fails_only_for_lack_of_working_time(
            cal in arb_calendar(),
            start in arb_instant(),
            d in arb_duration(),
        ) {
            match cal.add_business_duration(start, d) {
                Ok(_) | Err(CalendarError::NoWorkingTime | CalendarError::SearchLimitExceeded) => {}
                Err(other) => prop_assert!(false, "unexpected error {:?}", other),
            }
        }

        #[test]
        fn between_is_antisymmetric(
            cal in arb_calendar(),
            a in arb_instant(),
            b in arb_instant(),
        ) {
            let forward = cal.business_duration_between(a, b);
            let backward = cal.business_duration_between(b, a).map(|d| -d);
            prop_assert_eq!(forward, backward);
        }

        /// `is_working(t)` holds exactly when the minute starting at `t`
        /// contains business time (range bounds are whole local minutes).
        #[test]
        fn is_working_agrees_with_between(cal in arb_calendar(), t in arb_instant()) {
            let minute = cal.business_duration_between(t, t + Duration::minutes(1)).unwrap();
            prop_assert_eq!(cal.is_working(t), minute > Duration::zero());
        }

        #[test]
        fn next_business_instant_is_working_and_idempotent(
            cal in arb_calendar(),
            t in arb_instant(),
        ) {
            if let Ok(next) = cal.next_business_instant(t) {
                prop_assert!(next >= t);
                prop_assert!(cal.is_working(next), "next {} is not working time", next);
                prop_assert_eq!(cal.next_business_instant(next), Ok(next));
                prop_assert_eq!(cal.business_duration_between(t, next), Ok(Duration::zero()));
            }
        }

        #[test]
        fn adding_a_holiday_never_adds_business_time(
            cal in arb_calendar(),
            a in arb_instant(),
            b in arb_instant(),
            holiday in arb_date(),
        ) {
            let mut holidays = cal.holidays().clone();
            holidays.insert(holiday);
            let closed = BusinessCalendar::new(
                cal.tz(),
                cal.working_days().clone(),
                cal.hours().clone(),
                holidays,
                cal.exceptions().clone(),
            )
            .unwrap();
            let (early, late) = if a <= b { (a, b) } else { (b, a) };
            // A fifty-year generator can exceed the scan limit; compare on a
            // span both calculators can actually answer. The budget counts
            // local dates, and a zone that skips a whole date (Samoa 2011)
            // plus a DST hour makes a UTC span of `MAX_DAYS_SCAN - 2` days
            // cover too many of them, so keep a week's margin.
            let late = late.min(early + Duration::days(MAX_DAYS_SCAN - 7));
            prop_assert!(
                closed.business_duration_between(early, late).unwrap()
                    <= cal.business_duration_between(early, late).unwrap()
            );
        }

        /// BCL-1.1 — the minute oracle. Business time between two instants is
        /// the number of minute-aligned instants that are working time, and
        /// `is_working` itself agrees with the independent derivation at every
        /// one of those minutes.
        #[test]
        fn oracle_minutes_are_the_business_time_between(
            cal in arb_calendar(),
            a in arb_instant(),
            b in arb_instant(),
        ) {
            let (from, to) = if a <= b { (a, b) } else { (b, a) };
            let to = to.min(from + Duration::days(4));
            let mut count = Duration::zero();
            let mut cursor = from;
            while cursor < to {
                let working = oracle_is_working(&cal, cursor);
                prop_assert_eq!(cal.is_working(cursor), working, "is_working disagrees at {}", cursor);
                if working {
                    count += Duration::minutes(1);
                }
                cursor += Duration::minutes(1);
            }
            prop_assert_eq!(cal.business_duration_between(from, to), Ok(count));
        }

        /// BCL-1.1 — `add` lands on the first instant where the oracle's
        /// minute count reaches the duration.
        #[test]
        fn oracle_add_lands_where_the_count_reaches_the_duration(
            cal in arb_calendar(),
            start in arb_instant(),
            d in arb_oracle_duration(),
        ) {
            let window_end = start + Duration::days(4);
            let mut elapsed = Duration::zero();
            let mut cursor = start;
            let mut landing = None;
            while cursor <= window_end {
                if elapsed >= d {
                    landing = Some(cursor);
                    break;
                }
                if oracle_is_working(&cal, cursor) {
                    elapsed += Duration::minutes(1);
                }
                cursor += Duration::minutes(1);
            }
            match cal.add_business_duration(start, d) {
                Ok(due) if due <= window_end => prop_assert_eq!(Some(due), landing),
                // A landing beyond the oracle's window is not the oracle's business.
                Ok(_) => {}
                Err(_) => prop_assert!(
                    landing.is_none(),
                    "the oracle found a landing the calculator did not"
                ),
            }
        }

        /// BCL-3.1 — the one walk: clipped, ordered, non-overlapping,
        /// non-empty intervals whose lengths sum to `between`.
        #[test]
        fn working_intervals_are_clipped_ordered_and_sum_to_between(
            cal in arb_calendar(),
            a in arb_instant(),
            b in arb_instant(),
        ) {
            let (from, to) = if a <= b { (a, b) } else { (b, a) };
            let to = to.min(from + Duration::days(4));
            let mut total = Duration::zero();
            let mut previous_end = None;
            for interval in cal.working_intervals(from, to) {
                let (start, end) = interval.unwrap();
                prop_assert!(start >= from && end <= to, "{}..{} is not clipped to {}..{}", start, end, from, to);
                prop_assert!(start < end, "empty interval {}..{}", start, end);
                if let Some(previous_end) = previous_end {
                    prop_assert!(start > previous_end, "intervals touch or overlap at {}", start);
                }
                prop_assert!(
                    cal.is_working(start + Duration::seconds(1)),
                    "the interior of {}..{} is not working time",
                    start,
                    end
                );
                previous_end = Some(end);
                total += end - start;
            }
            prop_assert_eq!(cal.business_duration_between(from, to), Ok(total));
        }

        /// BCL-3.1 — the walk's first interval starts where
        /// `next_business_instant` says it does.
        #[test]
        fn first_interval_start_is_the_next_business_instant(
            cal in arb_calendar(),
            from in arb_instant(),
        ) {
            let to = from + Duration::days(4);
            let first = cal.working_intervals(from, to).next().transpose();
            match (cal.next_business_instant(from), first) {
                (Ok(expected), Ok(Some((start, _end)))) => {
                    prop_assert_eq!(start, expected);
                    prop_assert!(expected < to);
                }
                (Ok(expected), Ok(None)) => prop_assert!(
                    expected >= to,
                    "the walk over {}..{} found nothing although the next business instant is {}",
                    from,
                    to,
                    expected
                ),
                (Err(_), Ok(Some((start, _end)))) => prop_assert!(
                    false,
                    "the walk found {} where the calculator found nothing",
                    start
                ),
                _ => {}
            }
        }

        /// BCL-3.2 — the closed-calendar fast path never changes an answer.
        #[test]
        fn fast_path_agrees_with_the_scan(
            cal in arb_calendar(),
            start in arb_instant(),
            d in arb_duration(),
        ) {
            if !cal.has_working_time() {
                prop_assert_eq!(
                    cal.add_business_duration(start, d),
                    Err(CalendarError::NoWorkingTime)
                );
                prop_assert_eq!(
                    cal.next_business_instant(start),
                    Err(CalendarError::NoWorkingTime)
                );
                if let Some(end) = start.checked_add_signed(Duration::days(30)) {
                    prop_assert_eq!(
                        cal.business_duration_between(start, end),
                        Ok(Duration::zero())
                    );
                }
            }
        }
    }
}

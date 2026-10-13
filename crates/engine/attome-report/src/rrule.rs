//! A narrow RFC 5545 RRULE subset, and next-occurrence computation over it.
//!
//! **This is a documented stopgap, not `attome-calendar`.** D-404 (2026-08-26)
//! is explicit that recurrence is out of scope for `attome-calendar` Phase 1
//! — "Recurrence (RRULE)... out of scope for this crate and this decision —
//! `M83-scheduling.md`'s Phase 2/3, not built yet" — so there is nothing in
//! this repo to reuse today. This module implements only the subset M83's
//! own plan names for that future work (`document/module-master-plans/
//! M83-scheduling.md`: "daily/weekly/monthly/yearly, interval, byday,
//! until/count"), minus `COUNT` (an occurrence counter would need its own
//! persisted state on `report_schedule`, and `UNTIL` alone is enough to
//! bound a schedule for this pass — deferred, not silently dropped). It is
//! deliberately self-contained and crate-local so replacing it with
//! `attome_calendar`'s eventual recurrence primitive (M83 Phase 2) is a
//! drop-in swap of this one file, not an API change to callers.
//!
//! Grammar supported: `FREQ=DAILY|WEEKLY|MONTHLY|YEARLY;INTERVAL=n;
//! BYDAY=MO,TU,...;UNTIL=<RFC3339>` — `;`-separated `KEY=VALUE` pairs,
//! `FREQ` required, everything else optional. `BYDAY` only filters a
//! `WEEKLY` rule (a subset of a subset — monthly/yearly BYDAY, e.g. "the
//! second Tuesday", is out of scope here too).

use chrono::{DateTime, Datelike, Duration, Utc, Weekday};

/// Bounds the next-occurrence walk so a malformed or absurdly sparse rule
/// (e.g. `INTERVAL=999999`) fails closed with `None` rather than looping —
/// same posture `attome-calendar`'s own `MAX_DAYS_SCAN` documents for the
/// same reason (D-404).
const MAX_STEPS: u32 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freq {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone)]
pub struct Rrule {
    freq: Freq,
    interval: u32,
    byday: Vec<Weekday>,
    until: Option<DateTime<Utc>>,
}

fn parse_weekday(s: &str) -> Option<Weekday> {
    match s.trim().to_uppercase().as_str() {
        "MO" => Some(Weekday::Mon),
        "TU" => Some(Weekday::Tue),
        "WE" => Some(Weekday::Wed),
        "TH" => Some(Weekday::Thu),
        "FR" => Some(Weekday::Fri),
        "SA" => Some(Weekday::Sat),
        "SU" => Some(Weekday::Sun),
        _ => None,
    }
}

impl Rrule {
    /// Parses the subset this module supports. Rejects `COUNT` explicitly
    /// (named, not silently ignored) so a caller who wrote one learns why it
    /// has no effect rather than getting a rule that never terminates.
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut freq: Option<Freq> = None;
        let mut interval: u32 = 1;
        let mut byday: Vec<Weekday> = Vec::new();
        let mut until: Option<DateTime<Utc>> = None;

        for part in s.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let Some((key, value)) = part.split_once('=') else {
                return Err(format!("malformed RRULE segment: {part:?}"));
            };
            match key.trim().to_uppercase().as_str() {
                "FREQ" => {
                    freq = Some(match value.trim().to_uppercase().as_str() {
                        "DAILY" => Freq::Daily,
                        "WEEKLY" => Freq::Weekly,
                        "MONTHLY" => Freq::Monthly,
                        "YEARLY" => Freq::Yearly,
                        other => return Err(format!("unsupported FREQ: {other:?}")),
                    });
                }
                "INTERVAL" => {
                    interval = value
                        .trim()
                        .parse::<u32>()
                        .map_err(|_| format!("invalid INTERVAL: {value:?}"))?;
                    if interval == 0 {
                        return Err("INTERVAL must be >= 1".into());
                    }
                }
                "BYDAY" => {
                    for d in value.split(',') {
                        byday.push(
                            parse_weekday(d)
                                .ok_or_else(|| format!("invalid BYDAY value: {d:?}"))?,
                        );
                    }
                }
                "UNTIL" => {
                    until = Some(
                        DateTime::parse_from_rfc3339(value.trim())
                            .map_err(|e| format!("invalid UNTIL ({e}): {value:?}"))?
                            .with_timezone(&Utc),
                    );
                }
                "COUNT" => {
                    return Err(
                        "COUNT is not supported by this pass's RRULE subset — use UNTIL".into(),
                    );
                }
                other => return Err(format!("unsupported RRULE key: {other:?}")),
            }
        }

        Ok(Rrule {
            freq: freq.ok_or("RRULE must set FREQ")?,
            interval,
            byday,
            until,
        })
    }

    /// The first occurrence strictly after `after`, walking forward from
    /// `dtstart` in `freq`/`interval` steps and filtering by `byday` when
    /// set (WEEKLY only — see module doc). `None` means the rule has no
    /// further occurrences (past `until`, or the bounded walk gave up).
    pub fn next_after(
        &self,
        dtstart: DateTime<Utc>,
        after: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        if let Some(until) = self.until
            && after >= until
        {
            return None;
        }

        let candidate = if !self.byday.is_empty() && self.freq == Freq::Weekly {
            self.next_weekly_byday_after(dtstart, after)?
        } else {
            let mut candidate = dtstart;
            let mut steps = 0u32;
            while candidate <= after {
                candidate = self.step(candidate)?;
                steps += 1;
                if steps > MAX_STEPS {
                    return None;
                }
            }
            candidate
        };

        match self.until {
            Some(until) if candidate > until => None,
            _ => Some(candidate),
        }
    }

    /// WEEKLY + BYDAY: walks day-by-day from `dtstart` rather than jumping
    /// `interval` weeks via [`Self::step`] first — jumping first lands back
    /// on `dtstart`'s own weekday, which the day-filter loop then accepts
    /// immediately whenever that weekday is itself one of `byday`, silently
    /// skipping every other `byday` weekday in between (the bug
    /// `weekly_byday_filters_to_matching_weekday` exists to catch: starting
    /// Monday with `BYDAY=MO,WE,FR` must yield Wednesday next, not jump 7
    /// days to the following Monday). A day counts only when its weekday is
    /// in `byday` AND it falls in a week that is a whole multiple of
    /// `interval` weeks after `dtstart`'s week — `INTERVAL` skips whole
    /// weeks, never individual days within an active week.
    fn next_weekly_byday_after(
        &self,
        dtstart: DateTime<Utc>,
        after: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let week_start =
            |d: DateTime<Utc>| d - Duration::days(d.weekday().num_days_from_monday() as i64);
        let dtstart_week_start = week_start(dtstart);

        let mut day = dtstart;
        let mut steps = 0u32;
        loop {
            let weeks_since = (week_start(day) - dtstart_week_start).num_days() / 7;
            if day > after
                && weeks_since % self.interval as i64 == 0
                && self.byday.contains(&day.weekday())
            {
                return Some(day);
            }
            day += Duration::days(1);
            steps += 1;
            if steps > MAX_STEPS {
                return None;
            }
        }
    }

    fn step(&self, from: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self.freq {
            Freq::Daily => Some(from + Duration::days(self.interval as i64)),
            Freq::Weekly => Some(from + Duration::weeks(self.interval as i64)),
            Freq::Monthly => add_months(from, self.interval as i32),
            Freq::Yearly => add_months(from, self.interval as i32 * 12),
        }
    }
}

/// Adds calendar months, clamping the day-of-month into the target month's
/// range (e.g. Jan 31 + 1 month -> Feb 28/29) rather than overflowing into
/// the month after, the same clamp `chrono`'s own `checked_add_months`
/// avoids by returning `None` on an invalid date — this clamps instead of
/// failing so a schedule anchored on the 31st keeps firing every month.
fn add_months(from: DateTime<Utc>, months: i32) -> Option<DateTime<Utc>> {
    let total = from.year() * 12 + (from.month() as i32 - 1) + months;
    let year = total.div_euclid(12);
    let month0 = total.rem_euclid(12);
    let month = (month0 + 1) as u32;
    let last_day = last_day_of_month(year, month);
    let day = from.day().min(last_day);
    chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_time(from.time()).and_local_timezone(Utc).single())
}

#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
fn last_day_of_month(year: i32, month: u32) -> u32 {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    chrono::NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .expect("month is always 1..=12")
        .pred_opt()
        .expect("first of a month always has a predecessor")
        .day()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn dt(y: i32, m: u32, d: u32, h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap()
    }

    #[test]
    fn rejects_count() {
        assert!(Rrule::parse("FREQ=DAILY;COUNT=5").is_err());
    }

    #[test]
    fn rejects_missing_freq() {
        assert!(Rrule::parse("INTERVAL=2").is_err());
    }

    #[test]
    fn daily_next_after() {
        let rule = Rrule::parse("FREQ=DAILY").unwrap();
        let start = dt(2026, 8, 28, 9);
        let next = rule.next_after(start, dt(2026, 8, 28, 10)).unwrap();
        assert_eq!(next, dt(2026, 8, 29, 9));
    }

    #[test]
    fn weekly_interval_two() {
        let rule = Rrule::parse("FREQ=WEEKLY;INTERVAL=2").unwrap();
        let start = dt(2026, 8, 3, 9); // a Monday
        let next = rule.next_after(start, start).unwrap();
        assert_eq!(next, dt(2026, 8, 17, 9));
    }

    #[test]
    fn weekly_byday_filters_to_matching_weekday() {
        let rule = Rrule::parse("FREQ=WEEKLY;BYDAY=MO,WE,FR").unwrap();
        let start = dt(2026, 8, 24, 9); // a Monday
        let next = rule.next_after(start, dt(2026, 8, 24, 9)).unwrap();
        assert_eq!(next.weekday(), Weekday::Wed);
    }

    #[test]
    fn monthly_clamps_short_months() {
        let rule = Rrule::parse("FREQ=MONTHLY").unwrap();
        let start = dt(2026, 1, 31, 9);
        let next = rule.next_after(start, start).unwrap();
        assert_eq!((next.year(), next.month(), next.day()), (2026, 2, 28));
    }

    #[test]
    fn until_bounds_future_occurrences() {
        let rule = Rrule::parse("FREQ=DAILY;UNTIL=2026-08-29T00:00:00Z").unwrap();
        let start = dt(2026, 8, 28, 9);
        assert!(rule.next_after(start, dt(2026, 8, 30, 0)).is_none());
    }

    #[test]
    fn yearly_next_after() {
        let rule = Rrule::parse("FREQ=YEARLY").unwrap();
        let start = dt(2026, 8, 28, 9);
        let next = rule.next_after(start, start).unwrap();
        assert_eq!((next.year(), next.month(), next.day()), (2027, 8, 28));
    }
}

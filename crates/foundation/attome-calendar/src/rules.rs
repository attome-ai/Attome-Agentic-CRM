//! Recurring holidays and seasonal hours (roadmap Z12-T2), expanded into
//! the concrete dates a [`crate::BusinessCalendar`] holds.
//!
//! A [`HolidayRule`] names a holiday once — a fixed date, the nth weekday of
//! a month, a Hijri date or a one-off date — and [`expand`] turns it into
//! the Gregorian dates it closes in one year. A Hijri date moves about eleven
//! days earlier each Gregorian year, so a Hijri rule can fall twice in one
//! Gregorian year, or not at all; every Hijri year that overlaps the
//! Gregorian year is expanded.
//!
//! A [`Season`] (Ramadan's short hours, say) gives per-weekday hours between
//! two rules; [`expand_season`] turns it into per-date exceptions. Rules only
//! feed the calendar's existing holidays and exceptions: the calendar's own
//! representation does not change, and a range never crosses midnight.

use std::collections::BTreeMap;

use chrono::{Datelike, Duration, NaiveDate};
use serde::{Deserialize, Serialize};

use crate::hijri::{self, HijriDate};
use crate::{CalendarError, TimeRange, parse_weekday_code, weekday_code};

/// The longest a holiday may run.
pub const MAX_SPAN_DAYS: u8 = 15;

/// The longest a season may run, in days.
pub const MAX_SEASON_DAYS: i64 = 400;

/// A holiday that recurs (or happens once). `span_days` is how many days it
/// closes from its first, 1 to [`MAX_SPAN_DAYS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HolidayRule {
    /// The same Gregorian date every year.
    Fixed { month: u32, day: u32, span_days: u8 },
    /// The `n`th `weekday` (`mon`..`sun`) of `month`; `n = -1` is the last.
    NthWeekday {
        month: u32,
        weekday: String,
        n: i8,
        span_days: u8,
    },
    /// The same Hijri (Umm al-Qura) date every Hijri year.
    Hijri { month: u8, day: u8, span_days: u8 },
    /// One date only.
    OneOff { date: NaiveDate, span_days: u8 },
}

impl HolidayRule {
    fn span_days(&self) -> u8 {
        match self {
            Self::Fixed { span_days, .. }
            | Self::NthWeekday { span_days, .. }
            | Self::Hijri { span_days, .. }
            | Self::OneOff { span_days, .. } => *span_days,
        }
    }
}

fn invalid(message: impl Into<String>) -> CalendarError {
    CalendarError::InvalidCalendar(message.into())
}

/// `first` and the `span - 1` days after it.
fn spanned(first: NaiveDate, span: u8) -> Vec<NaiveDate> {
    (0..i64::from(span))
        .filter_map(|n| first.checked_add_signed(Duration::days(n)))
        .collect()
}

/// The `n`th `weekday` of `month` in `year` (`n = -1` the last), if there is one.
fn nth_weekday(year: i32, month: u32, weekday: chrono::Weekday, n: i8) -> Option<NaiveDate> {
    if n == -1 {
        let next_month = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
        }?;
        let mut day = next_month.pred_opt()?;
        while day.weekday() != weekday {
            day = day.pred_opt()?;
        }
        return Some(day);
    }
    let n = u32::try_from(n).ok().filter(|n| (1..=5).contains(n))?;
    let first = NaiveDate::from_ymd_opt(year, month, 1)?;
    let offset = (7 + weekday.num_days_from_monday() - first.weekday().num_days_from_monday()) % 7;
    let day = first.checked_add_signed(Duration::days(i64::from(offset + 7 * (n - 1))))?;
    (day.month() == month).then_some(day)
}

/// The dates `rule` closes whose holiday starts in `gregorian_year`, sorted
/// (a holiday starting on 31 December runs into the next year).
pub fn expand(rule: &HolidayRule, gregorian_year: i32) -> Result<Vec<NaiveDate>, CalendarError> {
    let span = rule.span_days();
    if !(1..=MAX_SPAN_DAYS).contains(&span) {
        return Err(invalid(format!(
            "a holiday spans 1 to {MAX_SPAN_DAYS} days, not {span}"
        )));
    }
    let firsts: Vec<NaiveDate> = match rule {
        HolidayRule::Fixed { month, day, .. } => {
            if !(1..=12).contains(month) || !(1..=31).contains(day) {
                return Err(invalid(format!("{month}/{day} is not a date")));
            }
            // 29 February closes nothing in a common year.
            NaiveDate::from_ymd_opt(gregorian_year, *month, *day)
                .into_iter()
                .collect()
        }
        HolidayRule::NthWeekday {
            month, weekday, n, ..
        } => {
            if !(1..=12).contains(month) {
                return Err(invalid(format!("{month} is not a month")));
            }
            let day = parse_weekday_code(weekday)
                .ok_or_else(|| invalid(format!("{weekday} is not a weekday (mon..sun)")))?;
            if !(*n == -1 || (1..=5).contains(n)) {
                return Err(invalid(format!("n is 1 to 5, or -1 for the last, not {n}")));
            }
            nth_weekday(gregorian_year, *month, day, *n)
                .into_iter()
                .collect()
        }
        HolidayRule::Hijri { month, day, .. } => {
            if !(1..=12).contains(month) || !(1..=30).contains(day) {
                return Err(invalid(format!("{month}/{day} is not a Hijri date")));
            }
            let (Some(jan1), Some(dec31)) = (
                NaiveDate::from_ymd_opt(gregorian_year, 1, 1),
                NaiveDate::from_ymd_opt(gregorian_year, 12, 31),
            ) else {
                return Err(CalendarError::Overflow);
            };
            let from = hijri::to_hijri(jan1)?.year;
            let to = hijri::to_hijri(dec31)?.year;
            let mut found = Vec::new();
            for year in from..=to {
                // Day 30 of a 29-day month falls on the next month's first.
                let length = hijri::month_length(year, *month)?;
                let date = if *day > length {
                    hijri::from_hijri(HijriDate::new(year, *month, length))?.succ_opt()
                } else {
                    Some(hijri::from_hijri(HijriDate::new(year, *month, *day))?)
                };
                if let Some(date) = date.filter(|d| d.year() == gregorian_year) {
                    found.push(date);
                }
            }
            found
        }
        HolidayRule::OneOff { date, .. } => {
            if date.year() == gregorian_year {
                vec![*date]
            } else {
                Vec::new()
            }
        }
    };
    let mut dates: Vec<NaiveDate> = firsts.into_iter().flat_map(|d| spanned(d, span)).collect();
    dates.sort_unstable();
    dates.dedup();
    Ok(dates)
}

/// Hours that replace the usual ones between two rules: from the day `start`
/// expands to through the day `end` expands to, inclusive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Season {
    pub start: HolidayRule,
    pub end: HolidayRule,
    /// Per weekday code (`mon`..`sun`), the working ranges in the season; a
    /// weekday not listed keeps its usual hours.
    pub hours: BTreeMap<String, Vec<TimeRange>>,
}

/// The per-date exceptions `season` sets for every season that starts in
/// `year` (one season can run into the next year).
pub fn expand_season(
    season: &Season,
    year: i32,
) -> Result<BTreeMap<NaiveDate, Vec<TimeRange>>, CalendarError> {
    let mut hours = BTreeMap::new();
    for (code, ranges) in &season.hours {
        let day = parse_weekday_code(code)
            .ok_or_else(|| invalid(format!("{code} is not a weekday (mon..sun)")))?;
        for range in ranges {
            if !range.is_valid() {
                return Err(TimeRange::try_new(range.start_minute, range.end_minute)
                    .err()
                    .unwrap_or_else(|| invalid("a season range is not valid")));
            }
        }
        hours.insert(day, ranges.clone());
    }
    let mut ends = expand(&season.end, year)?;
    ends.extend(expand(&season.end, year + 1)?);
    ends.sort_unstable();
    let mut out = BTreeMap::new();
    for start in expand(&season.start, year)? {
        let Some(end) = ends.iter().copied().find(|e| *e >= start) else {
            return Err(invalid(format!("the season starting {start} has no end")));
        };
        if (end - start).num_days() > MAX_SEASON_DAYS {
            return Err(invalid(format!(
                "a season runs at most {MAX_SEASON_DAYS} days; {start} to {end} is longer"
            )));
        }
        let mut day = start;
        while day <= end {
            if let Some(ranges) = hours.get(&day.weekday()) {
                out.insert(day, ranges.clone());
            }
            let Some(next) = day.succ_opt() else { break };
            day = next;
        }
    }
    Ok(out)
}

/// The weekday codes a season sets hours for, in week order (for display).
pub fn season_weekdays(season: &Season) -> Vec<&'static str> {
    let mut days: Vec<chrono::Weekday> = season
        .hours
        .keys()
        .filter_map(|code| parse_weekday_code(code))
        .collect();
    days.sort_by_key(chrono::Weekday::num_days_from_monday);
    days.into_iter().map(weekday_code).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap_or_else(|| panic!("{y}-{m}-{day}"))
    }

    #[test]
    fn eid_al_fitr_2025_expands_to_three_days() {
        let eid = HolidayRule::Hijri {
            month: 10,
            day: 1,
            span_days: 3,
        };
        assert_eq!(
            expand(&eid, 2025).unwrap_or_default(),
            vec![d(2025, 3, 30), d(2025, 3, 31), d(2025, 4, 1)]
        );
    }

    #[test]
    fn nth_weekday_last_monday() {
        let last_monday_of_may = HolidayRule::NthWeekday {
            month: 5,
            weekday: "mon".into(),
            n: -1,
            span_days: 1,
        };
        assert_eq!(
            expand(&last_monday_of_may, 2026).unwrap_or_default(),
            vec![d(2026, 5, 25)]
        );
        let first_sunday = HolidayRule::NthWeekday {
            month: 3,
            weekday: "sun".into(),
            n: 1,
            span_days: 1,
        };
        assert_eq!(
            expand(&first_sunday, 2026).unwrap_or_default(),
            vec![d(2026, 3, 1)]
        );
        let fifth_friday = HolidayRule::NthWeekday {
            month: 2,
            weekday: "fri".into(),
            n: 5,
            span_days: 1,
        };
        assert!(
            expand(&fifth_friday, 2026).unwrap_or_default().is_empty(),
            "none in Feb 2026"
        );
    }

    #[test]
    fn hijri_rule_can_hit_twice_in_one_year() {
        let ramadan = HolidayRule::Hijri {
            month: 9,
            day: 1,
            span_days: 1,
        };
        assert_eq!(
            expand(&ramadan, 2030).unwrap_or_default(),
            vec![d(2030, 1, 5), d(2030, 12, 26)]
        );
    }

    #[test]
    fn ramadan_season_sets_short_hours() {
        let short = vec![TimeRange::new(9 * 60, 15 * 60)];
        let season = Season {
            start: HolidayRule::Hijri {
                month: 9,
                day: 1,
                span_days: 1,
            },
            end: HolidayRule::Hijri {
                month: 9,
                day: 29,
                span_days: 1,
            },
            hours: ["sun", "mon", "tue", "wed", "thu"]
                .into_iter()
                .map(|code| (code.to_owned(), short.clone()))
                .collect(),
        };
        let exceptions = expand_season(&season, 2025).unwrap_or_default();
        // Ramadan 1446: 1 to 29 March 2025; Friday 7 and Saturday 8 keep
        // their usual (closed) days.
        assert_eq!(exceptions.get(&d(2025, 3, 2)), Some(&short), "a Sunday");
        assert_eq!(exceptions.get(&d(2025, 3, 27)), Some(&short), "a Thursday");
        assert!(!exceptions.contains_key(&d(2025, 3, 7)), "a Friday");
        assert!(
            !exceptions.contains_key(&d(2025, 3, 30)),
            "Eid, after the season"
        );
        // 29 days less five Saturdays and four Fridays.
        assert_eq!(exceptions.len(), 20);
        assert_eq!(
            season_weekdays(&season),
            vec!["mon", "tue", "wed", "thu", "sun"]
        );
    }

    #[test]
    fn bad_rules_are_refused() {
        let long = HolidayRule::Fixed {
            month: 1,
            day: 1,
            span_days: 16,
        };
        assert!(expand(&long, 2026).is_err());
        let leap = HolidayRule::Fixed {
            month: 2,
            day: 29,
            span_days: 1,
        };
        assert!(expand(&leap, 2026).unwrap_or_default().is_empty());
        assert_eq!(
            expand(&leap, 2028).unwrap_or_default(),
            vec![d(2028, 2, 29)]
        );
        let night = Season {
            start: HolidayRule::OneOff {
                date: d(2026, 1, 1),
                span_days: 1,
            },
            end: HolidayRule::OneOff {
                date: d(2026, 1, 3),
                span_days: 1,
            },
            hours: [("thu".to_owned(), vec![TimeRange::new(22 * 60, 6 * 60)])]
                .into_iter()
                .collect(),
        };
        assert!(
            expand_season(&night, 2026).is_err(),
            "a range may not cross midnight"
        );
    }
}

//! RFC 5545 recurrence rules (roadmap Z12-T9), moved here from
//! `attome-report`, with RFC 7529's Hijri calendar.
//!
//! Grammar: `;`-separated `KEY=VALUE` pairs, `FREQ` required:
//! - `FREQ=DAILY|WEEKLY|MONTHLY|YEARLY`, `INTERVAL=n` (default 1);
//! - `UNTIL=<RFC 3339>` and `COUNT=n` (the caller passes how many
//!   occurrences it has already emitted to [`Rrule::next_after_with`]);
//! - `BYMONTH=1,6`, `BYMONTHDAY=1,15,-1` (negative counts from the end);
//! - `BYDAY=MO,WE` or, for MONTHLY and YEARLY, with an ordinal: `2TU` (the
//!   second Tuesday), `-1FR` (the last Friday) — within each month;
//! - `RSCALE=ISLAMIC-UMALQURA` (with `SKIP=FORWARD`, the only skip mode):
//!   months, years, `BYMONTH` and `BYMONTHDAY` are Hijri (Umm al-Qura); a day
//!   past a month's end moves to the next month's first.
//!
//! Exception dates are passed to [`Rrule::next_after_with`]. Every walk is
//! bounded by [`MAX_STEPS`] periods and answers `None` rather than looping.

use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc, Weekday};

use crate::hijri::{self, HijriDate};

/// The most periods a walk looks at.
pub const MAX_STEPS: u32 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freq {
    Daily,
    Weekly,
    Monthly,
    Yearly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scale {
    Gregorian,
    UmmAlQura,
}

/// A parsed rule.
#[derive(Debug, Clone)]
pub struct Rrule {
    freq: Freq,
    interval: u32,
    /// `(ordinal, weekday)`; ordinal 0 means every such weekday.
    byday: Vec<(i8, Weekday)>,
    bymonth: Vec<u32>,
    bymonthday: Vec<i32>,
    until: Option<DateTime<Utc>>,
    count: Option<u32>,
    scale: Scale,
}

fn parse_weekday(s: &str) -> Option<(i8, Weekday)> {
    let s = s.trim().to_uppercase();
    let split = s.len().checked_sub(2)?;
    let (ordinal, day) = s.split_at(split);
    let weekday = match day {
        "MO" => Weekday::Mon,
        "TU" => Weekday::Tue,
        "WE" => Weekday::Wed,
        "TH" => Weekday::Thu,
        "FR" => Weekday::Fri,
        "SA" => Weekday::Sat,
        "SU" => Weekday::Sun,
        _ => return None,
    };
    let ordinal: i8 = if ordinal.is_empty() {
        0
    } else {
        ordinal.trim_start_matches('+').parse().ok()?
    };
    (ordinal == 0 || (1..=5).contains(&ordinal.abs())).then_some((ordinal, weekday))
}

fn list<T: std::str::FromStr>(value: &str, what: &str) -> Result<Vec<T>, String> {
    value
        .split(',')
        .map(|v| {
            v.trim()
                .parse::<T>()
                .map_err(|_| format!("invalid {what} value: {v:?}"))
        })
        .collect()
}

impl Rrule {
    /// Parses a rule (see the module doc for the grammar).
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut freq: Option<Freq> = None;
        let mut rule = Rrule {
            freq: Freq::Daily,
            interval: 1,
            byday: Vec::new(),
            bymonth: Vec::new(),
            bymonthday: Vec::new(),
            until: None,
            count: None,
            scale: Scale::Gregorian,
        };
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
                    rule.interval = value
                        .trim()
                        .parse::<u32>()
                        .map_err(|_| format!("invalid INTERVAL: {value:?}"))?;
                    if rule.interval == 0 {
                        return Err("INTERVAL must be >= 1".into());
                    }
                }
                "BYDAY" => {
                    for d in value.split(',') {
                        rule.byday.push(
                            parse_weekday(d)
                                .ok_or_else(|| format!("invalid BYDAY value: {d:?}"))?,
                        );
                    }
                }
                "BYMONTH" => {
                    rule.bymonth = list(value, "BYMONTH")?;
                    if rule.bymonth.iter().any(|m| !(1..=12).contains(m)) {
                        return Err(format!("BYMONTH is 1 to 12: {value:?}"));
                    }
                }
                "BYMONTHDAY" => {
                    rule.bymonthday = list(value, "BYMONTHDAY")?;
                    if rule
                        .bymonthday
                        .iter()
                        .any(|d| *d == 0 || !(-31..=31).contains(d))
                    {
                        return Err(format!("BYMONTHDAY is 1 to 31 or -1 to -31: {value:?}"));
                    }
                }
                "UNTIL" => {
                    rule.until = Some(
                        DateTime::parse_from_rfc3339(value.trim())
                            .map_err(|e| format!("invalid UNTIL ({e}): {value:?}"))?
                            .with_timezone(&Utc),
                    );
                }
                "COUNT" => {
                    let count = value
                        .trim()
                        .parse::<u32>()
                        .map_err(|_| format!("invalid COUNT: {value:?}"))?;
                    if count == 0 {
                        return Err("COUNT must be >= 1".into());
                    }
                    rule.count = Some(count);
                }
                "RSCALE" => match value.trim().to_uppercase().as_str() {
                    "GREGORIAN" => rule.scale = Scale::Gregorian,
                    "ISLAMIC-UMALQURA" => rule.scale = Scale::UmmAlQura,
                    other => return Err(format!("unsupported RSCALE: {other:?}")),
                },
                "SKIP" => {
                    if !value.trim().eq_ignore_ascii_case("FORWARD") {
                        return Err("SKIP=FORWARD is the only skip mode".into());
                    }
                }
                other => return Err(format!("unsupported RRULE key: {other:?}")),
            }
        }
        rule.freq = freq.ok_or("RRULE must set FREQ")?;
        Ok(rule)
    }

    /// The rule's `COUNT`, when it has one: a caller that keeps no count of
    /// emitted occurrences should refuse such a rule.
    pub fn count(&self) -> Option<u32> {
        self.count
    }

    /// The first occurrence strictly after `after`, starting at `dtstart`.
    /// `None` when the rule has no further occurrences (past `UNTIL`, or the
    /// bounded walk gave up).
    pub fn next_after(
        &self,
        dtstart: DateTime<Utc>,
        after: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        self.next_after_with(dtstart, after, 0, &[])
    }

    /// [`Self::next_after`] for a series that has already emitted `emitted`
    /// occurrences (for `COUNT`), skipping `exdates`.
    pub fn next_after_with(
        &self,
        dtstart: DateTime<Utc>,
        after: DateTime<Utc>,
        emitted: u32,
        exdates: &[NaiveDate],
    ) -> Option<DateTime<Utc>> {
        if self.count.is_some_and(|count| emitted >= count) {
            return None;
        }
        if self.until.is_some_and(|until| after >= until) {
            return None;
        }
        let time = dtstart.time();
        let start = dtstart.date_naive();
        for period in 0..MAX_STEPS {
            let mut dates = self.candidates(start, period)?;
            dates.sort_unstable();
            dates.dedup();
            for date in dates {
                let at = date.and_time(time).and_utc();
                if at < dtstart || at <= after || exdates.contains(&date) {
                    continue;
                }
                return match self.until {
                    Some(until) if at > until => None,
                    _ => Some(at),
                };
            }
            // A period whose first day is past UNTIL ends the walk.
            if let Some(until) = self.until
                && self.period_start(start, period)?.and_time(time).and_utc() > until
            {
                return None;
            }
        }
        None
    }

    /// The first day of period `n`.
    fn period_start(&self, start: NaiveDate, n: u32) -> Option<NaiveDate> {
        let steps = i64::from(n) * i64::from(self.interval);
        match (self.freq, self.scale) {
            (Freq::Daily, _) => start.checked_add_signed(Duration::days(steps)),
            (Freq::Weekly, _) => start.checked_add_signed(Duration::weeks(steps)),
            (Freq::Monthly, Scale::Gregorian) => add_months(start, steps).map(|d| d.with_day(1))?,
            (Freq::Yearly, Scale::Gregorian) => {
                add_months(start, steps * 12).map(|d| d.with_day(1))?
            }
            (Freq::Monthly | Freq::Yearly, Scale::UmmAlQura) => {
                let months = if self.freq == Freq::Yearly {
                    steps * 12
                } else {
                    steps
                };
                let (year, month) = hijri_add_months(hijri::to_hijri(start).ok()?, months)?;
                hijri::from_hijri(HijriDate::new(year, month, 1)).ok()
            }
        }
    }

    /// The candidate dates of period `n` (some may precede `dtstart`).
    fn candidates(&self, start: NaiveDate, n: u32) -> Option<Vec<NaiveDate>> {
        let steps = i64::from(n) * i64::from(self.interval);
        Some(match self.freq {
            Freq::Daily => {
                let day = start.checked_add_signed(Duration::days(steps))?;
                if self.day_matches(day) {
                    vec![day]
                } else {
                    Vec::new()
                }
            }
            Freq::Weekly => {
                let week = start.checked_add_signed(Duration::weeks(steps))?;
                let monday =
                    week - Duration::days(i64::from(week.weekday().num_days_from_monday()));
                if self.byday.is_empty() {
                    vec![week]
                } else {
                    self.byday
                        .iter()
                        .filter_map(|(_, wd)| {
                            monday.checked_add_signed(Duration::days(i64::from(
                                wd.num_days_from_monday(),
                            )))
                        })
                        .filter(|d| self.bymonth.is_empty() || self.bymonth.contains(&d.month()))
                        .collect()
                }
            }
            Freq::Monthly | Freq::Yearly => match self.scale {
                Scale::Gregorian => self.gregorian_months(start, steps)?,
                Scale::UmmAlQura => self.hijri_months(start, steps)?,
            },
        })
    }

    /// DAILY's filters.
    fn day_matches(&self, day: NaiveDate) -> bool {
        (self.bymonth.is_empty() || self.bymonth.contains(&day.month()))
            && (self.bymonthday.is_empty()
                || self
                    .bymonthday
                    .iter()
                    .any(|d| resolve_monthday(day.year(), day.month(), *d) == Some(day.day())))
            && (self.byday.is_empty() || self.byday.iter().any(|(_, wd)| *wd == day.weekday()))
    }

    fn gregorian_months(&self, start: NaiveDate, steps: i64) -> Option<Vec<NaiveDate>> {
        let months: Vec<(i32, u32)> = if self.freq == Freq::Yearly {
            let year = add_months(start, steps * 12)?.year();
            if self.bymonth.is_empty() {
                vec![(year, start.month())]
            } else {
                self.bymonth.iter().map(|m| (year, *m)).collect()
            }
        } else {
            let d = add_months(start, steps)?;
            if !self.bymonth.is_empty() && !self.bymonth.contains(&d.month()) {
                return Some(Vec::new());
            }
            vec![(d.year(), d.month())]
        };
        let mut out = Vec::new();
        for (year, month) in months {
            out.extend(self.in_month(year, month, start));
        }
        Some(out)
    }

    /// The days of one Gregorian month the rule picks.
    fn in_month(&self, year: i32, month: u32, start: NaiveDate) -> Vec<NaiveDate> {
        let last = last_day_of_month(year, month);
        let by_monthday: Option<Vec<u32>> = (!self.bymonthday.is_empty()).then(|| {
            self.bymonthday
                .iter()
                .filter_map(|d| resolve_monthday(year, month, *d))
                .collect()
        });
        let by_day: Option<Vec<u32>> = (!self.byday.is_empty()).then(|| {
            self.byday
                .iter()
                .flat_map(|(ordinal, wd)| weekdays_in_month(year, month, *ordinal, *wd))
                .collect()
        });
        let days: Vec<u32> = match (by_monthday, by_day) {
            (Some(a), Some(b)) => a.into_iter().filter(|d| b.contains(d)).collect(),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            // No BY-rule: dtstart's day, clamped into a short month.
            (None, None) => vec![start.day().min(last)],
        };
        days.into_iter()
            .filter_map(|d| NaiveDate::from_ymd_opt(year, month, d))
            .collect()
    }

    fn hijri_months(&self, start: NaiveDate, steps: i64) -> Option<Vec<NaiveDate>> {
        let base = hijri::to_hijri(start).ok()?;
        let months: Vec<(u16, u8)> = if self.freq == Freq::Yearly {
            let (year, _) = hijri_add_months(base, steps * 12)?;
            if self.bymonth.is_empty() {
                vec![(year, base.month)]
            } else {
                self.bymonth
                    .iter()
                    .filter_map(|m| u8::try_from(*m).ok().map(|m| (year, m)))
                    .collect()
            }
        } else {
            let (year, month) = hijri_add_months(base, steps)?;
            if !self.bymonth.is_empty() && !self.bymonth.contains(&u32::from(month)) {
                return Some(Vec::new());
            }
            vec![(year, month)]
        };
        let days: Vec<i32> = if self.bymonthday.is_empty() {
            vec![i32::from(base.day)]
        } else {
            self.bymonthday.clone()
        };
        let mut out = Vec::new();
        for (year, month) in months {
            let Ok(length) = hijri::month_length(year, month) else {
                continue;
            };
            for day in &days {
                let day = if *day < 0 {
                    i32::from(length) + day + 1
                } else {
                    *day
                };
                let Ok(day) = u8::try_from(day) else { continue };
                if day == 0 {
                    continue;
                }
                // SKIP=FORWARD: past the month's end is the next month's first.
                let date = if day > length {
                    hijri::from_hijri(HijriDate::new(year, month, length))
                        .ok()
                        .and_then(|d| d.succ_opt())
                } else {
                    hijri::from_hijri(HijriDate::new(year, month, day)).ok()
                };
                out.extend(date);
            }
        }
        Some(out)
    }
}

/// Day `d` of a month (negative from its end), if the month has it.
fn resolve_monthday(year: i32, month: u32, d: i32) -> Option<u32> {
    let last = i32::try_from(last_day_of_month(year, month)).ok()?;
    let day = if d < 0 { last + d + 1 } else { d };
    (1..=last).contains(&day).then(|| u32::try_from(day).ok())?
}

/// The days of `month` that are `wd`: all of them for ordinal 0, else the
/// `ordinal`th (negative from the end).
fn weekdays_in_month(year: i32, month: u32, ordinal: i8, wd: Weekday) -> Vec<u32> {
    let last = last_day_of_month(year, month);
    let all: Vec<u32> = (1..=last)
        .filter(|d| {
            NaiveDate::from_ymd_opt(year, month, *d).is_some_and(|date| date.weekday() == wd)
        })
        .collect();
    match ordinal {
        0 => all,
        n if n > 0 => all
            .get(usize::from(n.unsigned_abs()) - 1)
            .copied()
            .into_iter()
            .collect(),
        n => all
            .len()
            .checked_sub(usize::from(n.unsigned_abs()))
            .and_then(|i| all.get(i).copied())
            .into_iter()
            .collect(),
    }
}

/// Adds Gregorian months, clamping the day into the target month (31 Jan +
/// 1 month is 28 or 29 Feb) so a schedule anchored on the 31st keeps firing.
fn add_months(from: NaiveDate, months: i64) -> Option<NaiveDate> {
    let total = i64::from(from.year()) * 12 + i64::from(from.month0()) + months;
    let year = i32::try_from(total.div_euclid(12)).ok()?;
    let month = u32::try_from(total.rem_euclid(12)).ok()? + 1;
    NaiveDate::from_ymd_opt(year, month, from.day().min(last_day_of_month(year, month)))
}

/// A Hijri year and month `months` after `base`'s.
fn hijri_add_months(base: HijriDate, months: i64) -> Option<(u16, u8)> {
    let total = i64::from(base.year) * 12 + i64::from(base.month) - 1 + months;
    let year = u16::try_from(total.div_euclid(12)).ok()?;
    let month = u8::try_from(total.rem_euclid(12)).ok()? + 1;
    Some((year, month))
}

fn last_day_of_month(year: i32, month: u32) -> u32 {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    NaiveDate::from_ymd_opt(next_year, next_month, 1)
        .and_then(|d| d.pred_opt())
        .map_or(28, |d| d.day())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn dt(y: i32, m: u32, d: u32, h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, h, 0, 0).unwrap()
    }

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn rejects_missing_freq() {
        assert!(Rrule::parse("INTERVAL=2").is_err());
        assert!(Rrule::parse("FREQ=DAILY;SKIP=BACKWARD").is_err());
        assert!(Rrule::parse("FREQ=DAILY;RSCALE=CHINESE").is_err());
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
        assert_eq!(next, dt(2026, 8, 26, 9));
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
        assert!(
            rule.next_after(start, start).is_none(),
            "29 Aug 09:00 is past UNTIL"
        );
    }

    #[test]
    fn yearly_next_after() {
        let rule = Rrule::parse("FREQ=YEARLY").unwrap();
        let start = dt(2026, 8, 28, 9);
        let next = rule.next_after(start, start).unwrap();
        assert_eq!((next.year(), next.month(), next.day()), (2027, 8, 28));
    }

    #[test]
    fn second_tuesday_monthly() {
        let rule = Rrule::parse("FREQ=MONTHLY;BYDAY=2TU").unwrap();
        let start = dt(2026, 1, 13, 9); // the second Tuesday of January 2026
        assert_eq!(rule.next_after(start, start), Some(dt(2026, 2, 10, 9)));
        let last_friday = Rrule::parse("FREQ=MONTHLY;BYDAY=-1FR").unwrap();
        assert_eq!(
            last_friday.next_after(start, start),
            Some(dt(2026, 1, 30, 9))
        );
        let fifteenth = Rrule::parse("FREQ=MONTHLY;BYMONTHDAY=15,-1").unwrap();
        assert_eq!(fifteenth.next_after(start, start), Some(dt(2026, 1, 15, 9)));
        assert_eq!(
            fifteenth.next_after(start, dt(2026, 1, 15, 9)),
            Some(dt(2026, 1, 31, 9))
        );
        let june = Rrule::parse("FREQ=YEARLY;BYMONTH=6;BYMONTHDAY=1").unwrap();
        assert_eq!(june.next_after(start, start), Some(dt(2026, 6, 1, 9)));
    }

    #[test]
    fn count_stops_series() {
        let rule = Rrule::parse("FREQ=DAILY;COUNT=3").unwrap();
        let start = dt(2026, 8, 28, 9);
        assert_eq!(
            rule.next_after_with(start, start, 2, &[]),
            Some(dt(2026, 8, 29, 9))
        );
        assert_eq!(rule.next_after_with(start, start, 3, &[]), None);
    }

    #[test]
    fn exdate_skipped() {
        let rule = Rrule::parse("FREQ=DAILY").unwrap();
        let start = dt(2026, 8, 28, 9);
        assert_eq!(
            rule.next_after_with(start, start, 0, &[date(2026, 8, 29)]),
            Some(dt(2026, 8, 30, 9))
        );
    }

    #[test]
    fn hijri_every_first_ramadan() {
        let rule =
            Rrule::parse("RSCALE=ISLAMIC-UMALQURA;FREQ=YEARLY;BYMONTH=9;BYMONTHDAY=1;SKIP=FORWARD")
                .unwrap();
        let start = dt(2025, 3, 1, 6); // 1 Ramadan 1446
        assert_eq!(
            rule.next_after(start, dt(2025, 3, 2, 0)),
            Some(dt(2026, 2, 18, 6))
        );
        // Every Hijri month on the 30th: a 29-day month moves to the next first.
        let thirtieth = Rrule::parse("RSCALE=ISLAMIC-UMALQURA;FREQ=MONTHLY;BYMONTHDAY=30").unwrap();
        assert!(thirtieth.next_after(start, start).is_some());
    }
}

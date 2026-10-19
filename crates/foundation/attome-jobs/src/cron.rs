//! Z7-T2: a standard five-field cron expression (`minute hour day-of-month
//! month day-of-week`), the form operators already write in crontab.
//!
//! Each field takes `*`, a value, a range `a-b`, a step `*/n` or `a-b/n`,
//! and comma lists of those. Months and weekdays also take their English
//! three-letter names (`jan`, `mon`); weekday 0 and 7 are both Sunday. As in
//! cron, when both day fields are restricted a day matches either one.
//!
//! The times are wall-clock times in the schedule's own time zone; how a
//! time that a daylight-saving change skips or repeats is handled is
//! [`crate::schedule::Schedule::next_after`]'s concern.

use std::fmt;

/// A parsed expression: one bit per allowed value in each field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    source: String,
    minutes: u64,
    hours: u32,
    days: u32,
    months: u16,
    weekdays: u8,
    /// Day-of-month was written as something other than `*`.
    days_restricted: bool,
    /// Day-of-week was written as something other than `*`.
    weekdays_restricted: bool,
}

/// Why an expression was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronError(pub String);

impl fmt::Display for CronError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid cron expression: {}", self.0)
    }
}

impl std::error::Error for CronError {}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const WEEKDAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/// One field's values as a bit set over `min..=max`.
fn field(text: &str, name: &str, min: u32, max: u32, names: &[&str]) -> Result<u64, CronError> {
    let value = |part: &str| -> Result<u32, CronError> {
        let lower = part.to_ascii_lowercase();
        if let Some(at) = names.iter().position(|n| *n == lower) {
            // Month names start at 1, weekday names at 0.
            return Ok(u32::try_from(at).unwrap_or(0) + min);
        }
        part.parse::<u32>()
            .map_err(|_| CronError(format!("{name}: `{part}` is not a number")))
    };
    let mut bits = 0u64;
    for item in text.split(',') {
        let (range, step) = match item.split_once('/') {
            Some((range, step)) => {
                let step: u32 = step
                    .parse()
                    .map_err(|_| CronError(format!("{name}: step `{step}` is not a number")))?;
                if step == 0 {
                    return Err(CronError(format!("{name}: a step of 0")));
                }
                (range, step)
            }
            None => (item, 1),
        };
        let (from, to) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            (value(a)?, value(b)?)
        } else {
            let at = value(range)?;
            // `5/15` means from 5 to the end, every 15.
            (at, if item.contains('/') { max } else { at })
        };
        if from < min || to > max || from > to {
            return Err(CronError(format!(
                "{name}: `{item}` is outside {min}-{max}"
            )));
        }
        let mut at = from;
        while at <= to {
            bits |= 1 << at;
            at += step;
        }
    }
    Ok(bits)
}

impl CronExpr {
    pub fn parse(text: &str) -> Result<Self, CronError> {
        let parts: Vec<&str> = text.split_whitespace().collect();
        let [minute, hour, day, month, weekday] = parts.as_slice() else {
            return Err(CronError(format!(
                "`{text}` has {} fields; five are needed: minute hour day month weekday",
                parts.len()
            )));
        };
        let mut weekdays = field(weekday, "weekday", 0, 7, &WEEKDAYS)?;
        // 7 is Sunday too.
        if weekdays & (1 << 7) != 0 {
            weekdays = (weekdays | 1) & 0x7f;
        }
        let narrow = |bits: u64, what: &str| {
            u32::try_from(bits).map_err(|_| CronError(format!("{what}: out of range")))
        };
        Ok(Self {
            source: parts.join(" "),
            minutes: field(minute, "minute", 0, 59, &[])?,
            hours: narrow(field(hour, "hour", 0, 23, &[])?, "hour")?,
            days: narrow(field(day, "day", 1, 31, &[])?, "day")?,
            months: u16::try_from(field(month, "month", 1, 12, &MONTHS)?)
                .map_err(|_| CronError("month: out of range".into()))?,
            weekdays: u8::try_from(weekdays)
                .map_err(|_| CronError("weekday: out of range".into()))?,
            days_restricted: *day != "*",
            weekdays_restricted: *weekday != "*",
        })
    }

    /// The expression as written, normalised to single spaces.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    pub fn matches_minute(&self, minute: u32) -> bool {
        self.minutes & (1 << minute) != 0
    }

    pub fn matches_hour(&self, hour: u32) -> bool {
        self.hours & (1 << hour) != 0
    }

    /// Whether the day matches: its month, and its day of month or weekday
    /// (`weekday` 0 = Sunday) as cron combines them.
    pub fn matches_day(&self, month: u32, day: u32, weekday: u32) -> bool {
        if self.months & (1 << month) == 0 {
            return false;
        }
        let by_day = self.days & (1 << day) != 0;
        let by_weekday = self.weekdays & (1 << weekday) != 0;
        match (self.days_restricted, self.weekdays_restricted) {
            (true, true) => by_day || by_weekday,
            (true, false) => by_day,
            (false, true) => by_weekday,
            (false, false) => true,
        }
    }

    /// The matching hours and minutes of a day, in order.
    pub fn times(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        (0..24)
            .filter(|h| self.matches_hour(*h))
            .flat_map(move |h| {
                (0..60)
                    .filter(|m| self.matches_minute(*m))
                    .map(move |m| (h, m))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_parse_lists_ranges_steps_and_names() {
        let e = CronExpr::parse("*/15 9-17 * jan,jul mon-fri").expect("parse");
        assert!(e.matches_minute(0) && e.matches_minute(45) && !e.matches_minute(10));
        assert!(e.matches_hour(9) && e.matches_hour(17) && !e.matches_hour(8));
        assert!(e.matches_day(1, 6, 1), "a Monday in January");
        assert!(!e.matches_day(1, 4, 6), "a Saturday");
        assert!(!e.matches_day(2, 2, 1), "February");
        assert_eq!(e.as_str(), "*/15 9-17 * jan,jul mon-fri");
    }

    #[test]
    fn sunday_is_zero_or_seven_and_days_combine_with_or() {
        let e = CronExpr::parse("0 0 1 * 7").expect("parse");
        assert!(e.matches_day(3, 1, 3), "the first, a Wednesday");
        assert!(e.matches_day(3, 5, 0), "a Sunday");
        assert!(!e.matches_day(3, 6, 1));
    }

    #[test]
    fn a_bad_expression_is_refused_with_its_field() {
        for (text, needle) in [
            ("* * * *", "five are needed"),
            ("60 * * * *", "minute"),
            ("* 24 * * *", "hour"),
            ("* * 0 * *", "day"),
            ("* * * 13 *", "month"),
            ("* * * * 8", "weekday"),
            ("*/0 * * * *", "step of 0"),
            ("x * * * *", "not a number"),
            ("5-1 * * * *", "outside"),
        ] {
            let error = CronExpr::parse(text).expect_err(text).to_string();
            assert!(error.contains(needle), "{text}: {error}");
        }
    }

    #[test]
    fn a_step_from_a_value_runs_to_the_end() {
        let e = CronExpr::parse("5/20 * * * *").expect("parse");
        let minutes: Vec<u32> = (0..60).filter(|m| e.matches_minute(*m)).collect();
        assert_eq!(minutes, [5, 25, 45]);
    }
}

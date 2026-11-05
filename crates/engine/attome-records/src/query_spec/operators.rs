//! Relative-date operators (roadmap S4-T5): the half-open range `[start,
//! end)` each one names, computed here and bound, never `now()` in SQL, so a
//! plan and a test do not depend on when they run. Days, months, quarters and
//! years start at midnight in the deployment's time zone; quarters and years
//! follow the fiscal year that starts in `fiscal_start_month`.

use attome_types::AppError;
use chrono::{DateTime, Datelike, Duration, NaiveDate, TimeZone, Utc};
use chrono_tz::Tz;

/// The relative-date operators.
pub const DATE_OPS: &[&str] = &[
    "today",
    "last_n_days",
    "next_n_days",
    "this_week",
    "last_week",
    "after_today",
    "before_today",
    "this_month",
    "last_month",
    "this_quarter",
    "this_year",
];

/// The most days `last_n_days` and `next_n_days` take, as the stored
/// filters' `@last_n_days` (`attome_core::filter`).
pub const MAX_DAYS: i64 = 3660;

/// The deployment's clock for relative dates.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    pub now: DateTime<Utc>,
    pub tz: Tz,
    /// 1 (January) to 12; 1 when the deployment sets no fiscal year.
    pub fiscal_start_month: u32,
}

impl Clock {
    /// Now, in UTC, on the calendar year.
    pub fn utc_now() -> Self {
        Self {
            now: Utc::now(),
            tz: Tz::UTC,
            fiscal_start_month: 1,
        }
    }
}

/// `[start, end)` for `op`. `n` is the day count of `last_n_days` and
/// `next_n_days`: the last `n` days and today, or today and the next `n`.
pub fn date_range(
    op: &str,
    n: Option<i64>,
    now: DateTime<Utc>,
    tz: Tz,
    fiscal_start_month: u32,
) -> Result<(DateTime<Utc>, DateTime<Utc>), AppError> {
    if !(1..=12).contains(&fiscal_start_month) {
        return Err(AppError::Validation(
            "fiscal_start_month must be between 1 and 12".into(),
        ));
    }
    let today = now.with_timezone(&tz).date_naive();
    let days = || -> Result<i64, AppError> {
        match n {
            Some(n) if (1..=MAX_DAYS).contains(&n) => Ok(n),
            _ => Err(AppError::Validation(format!(
                "{op} takes a number of days from 1 to {MAX_DAYS}"
            ))),
        }
    };
    let month_index = i64::from(today.year()) * 12 + i64::from(today.month0());
    // Months since the fiscal year began, 0 to 11.
    let into_year = (i64::from(today.month0()) - i64::from(fiscal_start_month - 1)).rem_euclid(12);
    let (start, end) = match op {
        "today" => (today, today + Duration::days(1)),
        "last_n_days" => (today - Duration::days(days()?), today + Duration::days(1)),
        "next_n_days" => (today, today + Duration::days(days()? + 1)),
        // Every day after today, or before it: `expires_on > CURRENT_DATE`.
        "after_today" => (today + Duration::days(1), far_date(9999, 12, 31)?),
        "before_today" => (far_date(1, 1, 1)?, today),
        // Weeks start on Monday, as PostgreSQL's `date_trunc('week', ...)`.
        "this_week" | "last_week" => {
            let monday = today - Duration::days(i64::from(today.weekday().num_days_from_monday()));
            let start = if op == "last_week" {
                monday - Duration::days(7)
            } else {
                monday
            };
            (start, start + Duration::days(7))
        }
        "this_month" => (month_start(month_index)?, month_start(month_index + 1)?),
        "last_month" => (month_start(month_index - 1)?, month_start(month_index)?),
        "this_quarter" => {
            let start = month_index - into_year % 3;
            (month_start(start)?, month_start(start + 3)?)
        }
        "this_year" => {
            let start = month_index - into_year;
            (month_start(start)?, month_start(start + 12)?)
        }
        other => {
            return Err(AppError::Validation(format!(
                "unknown date operator: {other}"
            )));
        }
    };
    Ok((midnight(start, tz), midnight(end, tz)))
}

/// A fixed far date bounding an open-ended range.
fn far_date(year: i32, month: u32, day: u32) -> Result<NaiveDate, AppError> {
    NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| AppError::Validation("date out of range".into()))
}

/// The first day of the month `index` months after year 0's January.
fn month_start(index: i64) -> Result<NaiveDate, AppError> {
    let year = i32::try_from(index.div_euclid(12))
        .map_err(|_| AppError::Validation("date out of range".into()))?;
    let month = u32::try_from(index.rem_euclid(12)).unwrap_or(0) + 1;
    NaiveDate::from_ymd_opt(year, month, 1)
        .ok_or_else(|| AppError::Validation("date out of range".into()))
}

/// Midnight of `date` in `tz`, in UTC. A midnight a clock change skips
/// becomes the first hour that exists.
fn midnight(date: NaiveDate, tz: Tz) -> DateTime<Utc> {
    let start = date.and_hms_opt(0, 0, 0).unwrap_or_default();
    (0..3)
        .find_map(|h| {
            tz.from_local_datetime(&(start + Duration::hours(h)))
                .earliest()
        })
        .map_or_else(|| Utc.from_utc_datetime(&start), |t| t.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weeks_start_on_monday() {
        // 2026-11-05 is a Thursday.
        let now = "2026-11-05T10:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let monday = "2026-11-02T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        assert_eq!(
            date_range("this_week", None, now, Tz::UTC, 1).unwrap(),
            (monday, monday + Duration::days(7))
        );
        assert_eq!(
            date_range("last_week", None, now, Tz::UTC, 1).unwrap(),
            (monday - Duration::days(7), monday)
        );
    }

    #[test]
    fn after_and_before_today_leave_today_out() {
        let now = "2026-11-05T10:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let today = "2026-11-05T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let (start, end) = date_range("after_today", None, now, Tz::UTC, 1).unwrap();
        assert_eq!(start, today + Duration::days(1));
        assert_eq!(end.year(), 9999);
        let (start, end) = date_range("before_today", None, now, Tz::UTC, 1).unwrap();
        assert_eq!(start.year(), 1);
        assert_eq!(end, today);
    }

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn this_quarter_respects_fiscal_start() {
        let now = at("2026-10-24T12:00:00Z");
        // Calendar quarters: October to December.
        assert_eq!(
            date_range("this_quarter", None, now, Tz::UTC, 1).unwrap(),
            (at("2026-10-01T00:00:00Z"), at("2027-01-01T00:00:00Z"))
        );
        // A fiscal year from February: Q3 is August to October.
        assert_eq!(
            date_range("this_quarter", None, now, Tz::UTC, 2).unwrap(),
            (at("2026-08-01T00:00:00Z"), at("2026-11-01T00:00:00Z"))
        );
        // The fiscal year from April runs April 2026 to March 2027; in
        // February it is the year that began the April before.
        assert_eq!(
            date_range("this_year", None, now, Tz::UTC, 4).unwrap(),
            (at("2026-04-01T00:00:00Z"), at("2027-04-01T00:00:00Z"))
        );
        assert_eq!(
            date_range("this_year", None, at("2027-02-10T00:00:00Z"), Tz::UTC, 4).unwrap(),
            (at("2026-04-01T00:00:00Z"), at("2027-04-01T00:00:00Z"))
        );
        assert!(date_range("this_year", None, now, Tz::UTC, 13).is_err());
    }

    #[test]
    fn last_n_days_bounds_are_half_open() {
        let now = at("2026-10-24T22:30:00Z");
        // In Riyadh (UTC+3) it is already the 25th.
        let riyadh: Tz = "Asia/Riyadh".parse().unwrap();
        assert_eq!(
            date_range("today", None, now, riyadh, 1).unwrap(),
            (at("2026-10-24T21:00:00Z"), at("2026-10-25T21:00:00Z"))
        );
        let (start, end) = date_range("last_n_days", Some(7), now, Tz::UTC, 1).unwrap();
        assert_eq!(start, at("2026-10-17T00:00:00Z"));
        assert_eq!(
            end,
            at("2026-10-25T00:00:00Z"),
            "tomorrow's midnight, excluded"
        );
        assert_eq!(
            date_range("next_n_days", Some(1), now, Tz::UTC, 1).unwrap(),
            (at("2026-10-24T00:00:00Z"), at("2026-10-26T00:00:00Z"))
        );
        assert_eq!(
            date_range("last_month", None, at("2026-01-15T00:00:00Z"), Tz::UTC, 1).unwrap(),
            (at("2025-12-01T00:00:00Z"), at("2026-01-01T00:00:00Z"))
        );
        for bad in [None, Some(0), Some(MAX_DAYS + 1)] {
            assert!(date_range("last_n_days", bad, now, Tz::UTC, 1).is_err());
        }
    }
}

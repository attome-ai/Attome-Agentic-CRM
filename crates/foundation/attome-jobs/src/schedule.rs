//! The schedule ledger: a periodic job runs **once per slot** across any
//! number of workers and restarts.
//!
//! Enqueue deduplication ([`crate::enqueue_dedup`] with a fixed key) blocks a
//! second row only while one is live, which closes *overlap* but does not
//! bound how often a slot runs: a worker that starts while no earlier row is
//! live enqueues again, so N workers could run one slot N times.
//!
//! The ledger is the gate in front of that: one row per schedule, claimed by a
//! single `UPDATE ... WHERE next_due_at <= now()` compare-and-swap. Exactly one
//! caller wins each slot and enqueues; every other caller sees a row that is
//! not due and does nothing. The dedup key stays behind it as the overlap
//! guard, so a slot whose job is still running cannot double-enqueue.
//!
//! No leader election, no advisory lock, no second broker: one table
//! (`job_schedule`, migration `0001_job_queue.sql`) and one short transaction
//! per tick per schedule.
//!
//! Z7-T2: besides a fixed interval ([`tick`]), a schedule can be a cron
//! expression, a one-off instant, a Hijri day of the month or every working
//! day of a business calendar, each on a chosen time zone's wall clock
//! ([`Schedule`], claimed by [`tick_at`]). The slot is the computed run
//! time, so the one-run-per-slot guarantee is the same.

use std::sync::Arc;

use chrono::{DateTime, Datelike, LocalResult, NaiveDateTime, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;

/// One schedule's persisted state. Backs the ledger's own observability
/// (BJB-14b) and lets tests assert slot behaviour without re-deriving it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ScheduleState {
    pub name: String,
    pub interval_secs: i32,
    pub next_due_at: DateTime<Utc>,
    pub last_enqueued_at: Option<DateTime<Utc>>,
    pub last_succeeded_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// Claims one schedule's current slot and enqueues `job` if this caller won
/// it.
///
/// `name` is the schedule's stable identity — deliberately the same string
/// as the scheduler's existing dedup key (D-618), so there is exactly one name
/// per periodic job and the two mechanisms cannot drift apart.
///
/// Returns `Ok(true)` when **this call won the slot** (the row was due and
/// this call advanced it). Another replica in the same slot, or a restart
/// inside it, gets `Ok(false)` and enqueues nothing. A `true` does not
/// promise a new `apalis.jobs` row: if the previous slot's job is still live,
/// [`crate::enqueue_in_tx_dedup`] is a no-op and the slot is simply skipped —
/// the same overlap guard D-165 established.
///
/// One short transaction: register-if-new, take the CAS, enqueue, commit. A
/// crash after the CAS but before the commit rolls the whole slot back, so the
/// next tick re-claims it rather than losing it.
#[expect(
    clippy::disallowed_methods,
    reason = "attome-jobs' whole public surface is `sqlx::Error`, so it cannot adopt \
              `attome_db::tx::begin`'s `AppError`; a tick that cannot get a connection fails \
              the tick, which the scheduler logs and re-claims on the next interval"
)]
pub async fn tick<J: crate::Job>(
    pool: &attome_db::DbPool,
    name: &str,
    interval: std::time::Duration,
    job: J,
) -> Result<bool, sqlx::Error> {
    let interval_secs = interval_secs(interval);

    let mut tx = pool.begin().await?;

    // Register on first sight, due immediately so a brand-new schedule's first
    // tick claims its slot at once. The interval is kept current on every tick
    // (a redeploy that changes a scheduler's interval should show up in the
    // ledger), but only written when it actually changed, so the common case
    // adds no writes.
    sqlx::query(attome_db::tagged_sql!(
        "jobs.schedule",
        "INSERT INTO job_schedule (name, interval_secs) VALUES ($1, $2) \
         ON CONFLICT (name) DO UPDATE \
             SET interval_secs = EXCLUDED.interval_secs, updated_at = now() \
             WHERE job_schedule.interval_secs <> EXCLUDED.interval_secs"
    ))
    .bind(name)
    .bind(interval_secs)
    .execute(&mut *tx)
    .await?;

    // The slot CAS. `now()` is the transaction's own start time, so a caller
    // that loses simply reads the winner's already-advanced `next_due_at`.
    let claimed: Option<String> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.schedule",
        "UPDATE job_schedule \
         SET next_due_at = now() + make_interval(secs => $2), \
             last_enqueued_at = now(), \
             row_version = row_version + 1, \
             updated_at = now() \
         WHERE name = $1 AND next_due_at <= now() \
         RETURNING name"
    ))
    .bind(name)
    .bind(interval_secs)
    .fetch_optional(&mut *tx)
    .await?;

    if claimed.is_none() {
        tx.commit().await?;
        return Ok(false);
    }

    crate::enqueue_in_tx_dedup(&mut tx, job, name).await?;
    tx.commit().await?;
    Ok(true)
}

/// Stamps a schedule's last successful run (BJB-4d), called by the worker
/// wrapper (`server::jobs::handle_platform_job`) after a schedule-originated
/// kind's handler returns `Ok`. Backs
/// `job_schedule_last_success_age_seconds{name}` (BJB-14b) — the signal that
/// distinguishes "the scheduler is ticking" from "the sweep is actually
/// running and succeeding".
pub async fn mark_succeeded(pool: &attome_db::DbPool, name: &str) -> Result<(), sqlx::Error> {
    sqlx::query(attome_db::tagged_sql!(
        "jobs.schedule",
        "UPDATE job_schedule SET last_succeeded_at = now(), updated_at = now() \
         WHERE name = $1"
    ))
    .bind(name)
    .execute(pool)
    .await?;
    Ok(())
}

/// Every schedule's persisted row, ordered by name — the metrics refresh
/// loop's read (BJB-14b) and tests' inspection point.
pub async fn all(pool: &attome_db::DbPool) -> Result<Vec<ScheduleState>, sqlx::Error> {
    sqlx::query_as(attome_db::tagged_sql!(
        "jobs.schedule",
        "SELECT name, interval_secs, next_due_at, last_enqueued_at, last_succeeded_at, \
                row_version \
         FROM job_schedule ORDER BY name"
    ))
    .fetch_all(pool)
    .await
}

/// Seconds since one schedule last succeeded, or `None` when it has never
/// succeeded. The gauge behind
/// `job_schedule_last_success_age_seconds{name}`: an alert threshold is
/// `2 ×` the schedule's own interval (plan §1).
pub async fn last_success_age_seconds(
    pool: &attome_db::DbPool,
    name: &str,
) -> Result<Option<f64>, sqlx::Error> {
    // Both "no row for this schedule" and "a row that has never succeeded"
    // are `None`: the caller (an alert on the age gauge) treats both as
    // "nothing has succeeded yet".
    let age: Option<Option<f64>> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.schedule",
        "SELECT EXTRACT(EPOCH FROM (now() - last_succeeded_at))::float8 \
         FROM job_schedule WHERE name = $1"
    ))
    .bind(name)
    .fetch_optional(pool)
    .await?;
    Ok(age.flatten())
}

/// `(name, seconds since last success)` for every registered schedule — one
/// query for the metrics refresh loop, `None` for a schedule that has not
/// succeeded yet.
pub async fn last_success_ages(
    pool: &attome_db::DbPool,
) -> Result<Vec<(String, Option<f64>)>, sqlx::Error> {
    sqlx::query_as(attome_db::tagged_sql!(
        "jobs.schedule",
        "SELECT name, EXTRACT(EPOCH FROM (now() - last_succeeded_at))::float8 \
         FROM job_schedule ORDER BY name"
    ))
    .fetch_all(pool)
    .await
}

/// Z7-T2: when a scheduled job runs. Every kind but [`Every`](Self::Every)
/// is computed in a chosen time zone, on its wall clock.
#[derive(Debug, Clone)]
pub enum Schedule {
    /// A fixed interval, as [`tick`] has always run.
    Every(std::time::Duration),
    /// A five-field cron expression ([`crate::cron`]) in `tz`.
    Cron { expr: crate::cron::CronExpr, tz: Tz },
    /// Once, at this instant; never again.
    Once(DateTime<Utc>),
    /// Day `day` of every Hijri month (Umm al-Qura), at `time` in `tz`. A
    /// month shorter than `day` runs on its last day.
    HijriMonthly { day: u8, time: NaiveTime, tz: Tz },
    /// Every working day of `calendar` (its holidays skipped), at `time` in
    /// the calendar's time zone.
    WorkingDays {
        time: NaiveTime,
        calendar: Arc<attome_calendar::BusinessCalendar>,
    },
}

/// Why a schedule was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleError(pub String);

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScheduleError {}

/// How far ahead a search for the next run looks before giving up: an
/// expression that matches nothing (`0 0 31 2 *`) ends there.
const HORIZON_DAYS: i64 = 366 * 5;

/// The instant `naive` is at on `tz`'s wall clock. A time the clocks skip
/// (spring forward) runs at the same wall time one hour on, the first
/// moment after the gap; a time they repeat (fall back) runs at its first
/// occurrence only.
fn on_wall_clock(tz: Tz, naive: NaiveDateTime) -> Option<DateTime<Utc>> {
    match tz.from_local_datetime(&naive) {
        LocalResult::Single(at) => Some(at.with_timezone(&Utc)),
        LocalResult::Ambiguous(first, _) => Some(first.with_timezone(&Utc)),
        LocalResult::None => match tz.from_local_datetime(&(naive + chrono::Duration::hours(1))) {
            LocalResult::Single(at) | LocalResult::Ambiguous(at, _) => Some(at.with_timezone(&Utc)),
            LocalResult::None => None,
        },
    }
}

impl Schedule {
    /// A cron schedule, the expression and time zone checked.
    pub fn cron(expr: &str, tz: &str) -> Result<Self, ScheduleError> {
        let expr = crate::cron::CronExpr::parse(expr).map_err(|e| ScheduleError(e.to_string()))?;
        let tz = parse_tz(tz)?;
        Ok(Self::Cron { expr, tz })
    }

    /// A Hijri-monthly schedule, the day and time zone checked.
    pub fn hijri_monthly(day: u8, time: NaiveTime, tz: &str) -> Result<Self, ScheduleError> {
        if !(1..=30).contains(&day) {
            return Err(ScheduleError(format!("a Hijri day is 1 to 30, got {day}")));
        }
        Ok(Self::HijriMonthly {
            day,
            time,
            tz: parse_tz(tz)?,
        })
    }

    /// The first run after `after`, or `None` when there is none (a
    /// one-off already past, an expression that matches no date).
    pub fn next_after(&self, after: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Self::Every(interval) => {
                Some(after + chrono::Duration::seconds(i64::from(interval_secs(*interval))))
            }
            Self::Once(at) => (*at > after).then_some(*at),
            Self::Cron { expr, tz } => {
                let start = after.with_timezone(tz).date_naive();
                (0..HORIZON_DAYS)
                    .filter_map(|offset| start.checked_add_signed(chrono::Duration::days(offset)))
                    .filter(|date| {
                        expr.matches_day(
                            date.month(),
                            date.day(),
                            date.weekday().num_days_from_sunday(),
                        )
                    })
                    .find_map(|date| {
                        expr.times()
                            .filter_map(|(h, m)| date.and_hms_opt(h, m, 0))
                            .filter_map(|naive| on_wall_clock(*tz, naive))
                            .find(|at| *at > after)
                    })
            }
            Self::HijriMonthly { day, time, tz } => {
                let start = after.with_timezone(tz).date_naive();
                let today = attome_calendar::hijri::to_hijri(start).ok()?;
                let (mut year, mut month) = (today.year, today.month);
                for _ in 0..24 {
                    let length = attome_calendar::hijri::month_length(year, month).ok()?;
                    let date = attome_calendar::hijri::from_hijri(
                        attome_calendar::hijri::HijriDate::new(year, month, (*day).min(length)),
                    )
                    .ok()?;
                    if let Some(at) = on_wall_clock(*tz, date.and_time(*time))
                        && at > after
                    {
                        return Some(at);
                    }
                    (year, month) = if month == 12 {
                        (year + 1, 1)
                    } else {
                        (year, month + 1)
                    };
                }
                None
            }
            Self::WorkingDays { time, calendar } => {
                let tz = calendar.tz();
                let start = after.with_timezone(&tz).date_naive();
                (0..HORIZON_DAYS)
                    .filter_map(|offset| start.checked_add_signed(chrono::Duration::days(offset)))
                    .filter(|date| calendar.is_working_date(*date))
                    .filter_map(|date| on_wall_clock(tz, date.and_time(*time)))
                    .find(|at| *at > after)
            }
        }
    }

    /// The first slot a newly registered schedule is due: a one-off's own
    /// instant (even if already past, so it still runs once), an interval's
    /// `now` (as [`tick`] has always done), else the next run.
    pub fn first_due(&self, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        match self {
            Self::Once(at) => Some(*at),
            Self::Every(_) => Some(now),
            _ => self.next_after(now),
        }
    }

    /// How the ledger shows this schedule; a changed description restarts
    /// the schedule at its new first slot.
    pub fn describe(&self) -> String {
        match self {
            Self::Every(interval) => format!("every {}s", interval_secs(*interval)),
            Self::Cron { expr, tz } => format!("cron {} {tz}", expr.as_str()),
            Self::Once(at) => format!("once {}", at.to_rfc3339()),
            Self::HijriMonthly { day, time, tz } => format!("hijri-monthly {day} {time} {tz}"),
            Self::WorkingDays { time, calendar } => {
                format!("working-days {time} {}", calendar.canonical_form())
            }
        }
    }

    /// Roughly how long between two runs, in seconds, for the ledger's
    /// `interval_secs` (the last-success alert's threshold is twice it).
    fn period_secs(&self, now: DateTime<Utc>) -> i32 {
        let gap = self
            .next_after(now)
            .and_then(|first| Some((self.next_after(first)? - first).num_seconds()))
            .unwrap_or(86_400);
        i32::try_from(gap.max(1)).unwrap_or(i32::MAX)
    }
}

fn parse_tz(tz: &str) -> Result<Tz, ScheduleError> {
    tz.parse::<Tz>()
        .map_err(|_| ScheduleError(format!("`{tz}` is not an IANA time zone")))
}

/// Where a schedule with no run left is parked: never due again.
fn never() -> DateTime<Utc> {
    chrono::NaiveDate::from_ymd_opt(9999, 12, 31)
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .map_or(DateTime::<Utc>::MAX_UTC, |at| at.and_utc())
}

/// Z7-T2: [`tick`] for any [`Schedule`]. The slot is the computed run time:
/// the row's `next_due_at` is claimed (row-locked, skipping a row another
/// caller holds) once it is due, and advanced to the schedule's next run
/// after now, so slots missed while nothing ran are not run one by one: the
/// job runs once and the schedule moves on. A schedule whose description
/// changed restarts at its new first slot. One short transaction, as
/// [`tick`].
#[expect(
    clippy::disallowed_methods,
    reason = "attome-jobs' whole public surface is `sqlx::Error`, as `tick`"
)]
pub async fn tick_at<J: crate::Job>(
    pool: &attome_db::DbPool,
    name: &str,
    schedule: &Schedule,
    job: J,
) -> Result<bool, sqlx::Error> {
    let now = Utc::now();
    let description = schedule.describe();
    let first = schedule.first_due(now).unwrap_or_else(never);
    let mut tx = pool.begin().await?;
    sqlx::query(attome_db::tagged_sql!(
        "jobs.schedule",
        "INSERT INTO job_schedule (name, interval_secs, schedule, next_due_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (name) DO UPDATE \
             SET interval_secs = EXCLUDED.interval_secs, schedule = EXCLUDED.schedule, \
                 next_due_at = EXCLUDED.next_due_at, updated_at = now() \
             WHERE job_schedule.schedule IS DISTINCT FROM EXCLUDED.schedule"
    ))
    .bind(name)
    .bind(schedule.period_secs(now))
    .bind(&description)
    .bind(first)
    .execute(&mut *tx)
    .await?;

    let due: Option<DateTime<Utc>> = sqlx::query_scalar(attome_db::tagged_sql!(
        "jobs.schedule",
        "SELECT next_due_at FROM job_schedule \
         WHERE name = $1 AND next_due_at <= now() \
         FOR UPDATE SKIP LOCKED"
    ))
    .bind(name)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(due) = due else {
        tx.commit().await?;
        return Ok(false);
    };
    let next = schedule.next_after(now.max(due)).unwrap_or_else(never);
    sqlx::query(attome_db::tagged_sql!(
        "jobs.schedule",
        "UPDATE job_schedule \
         SET next_due_at = $2, last_enqueued_at = now(), \
             row_version = row_version + 1, updated_at = now() \
         WHERE name = $1"
    ))
    .bind(name)
    .bind(next)
    .execute(&mut *tx)
    .await?;
    crate::enqueue_in_tx_dedup(&mut tx, job, name).await?;
    tx.commit().await?;
    Ok(true)
}

/// A duration as whole seconds for `make_interval`/`interval_secs`, never
/// zero (the table's own CHECK) and never negative.
fn interval_secs(interval: std::time::Duration) -> i32 {
    interval.as_secs().clamp(1, i32::MAX as u64) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(text: &str) -> DateTime<Utc> {
        text.parse().expect("an RFC 3339 instant")
    }

    #[test]
    fn every_and_once() {
        let at = utc("2026-10-19T10:00:00Z");
        let every = Schedule::Every(std::time::Duration::from_secs(90));
        assert_eq!(every.next_after(at), Some(utc("2026-10-19T10:01:30Z")));
        assert_eq!(every.first_due(at), Some(at));
        let once = Schedule::Once(utc("2026-10-20T00:00:00Z"));
        assert_eq!(once.next_after(at), Some(utc("2026-10-20T00:00:00Z")));
        assert_eq!(once.next_after(utc("2026-10-20T00:00:00Z")), None);
        assert_eq!(
            once.first_due(utc("2026-12-01T00:00:00Z")),
            Some(utc("2026-10-20T00:00:00Z"))
        );
    }

    #[test]
    fn cron_runs_on_the_zone_wall_clock() {
        let s = Schedule::cron("0 2 * * *", "Asia/Riyadh").expect("schedule");
        // 02:00 in Riyadh (UTC+3) is 23:00 UTC the day before.
        assert_eq!(
            s.next_after(utc("2026-10-19T10:00:00Z")),
            Some(utc("2026-10-19T23:00:00Z"))
        );
        assert_eq!(
            s.next_after(utc("2026-10-19T23:00:00Z")),
            Some(utc("2026-10-20T23:00:00Z"))
        );
        let weekdays = Schedule::cron("30 9 * * sun-thu", "Asia/Riyadh").expect("schedule");
        // Thursday 2026-10-22 09:30, then Sunday 2026-10-25.
        assert_eq!(
            weekdays.next_after(utc("2026-10-22T07:00:00Z")),
            Some(utc("2026-10-25T06:30:00Z"))
        );
        assert!(Schedule::cron("0 2 * *", "Asia/Riyadh").is_err());
        assert!(Schedule::cron("0 2 * * *", "Mars/Olympus").is_err());
        let never = Schedule::cron("0 0 31 2 *", "UTC").expect("schedule");
        assert_eq!(never.next_after(utc("2026-01-01T00:00:00Z")), None);
    }

    #[test]
    fn cron_across_daylight_saving_changes() {
        let skipped = Schedule::cron("30 2 * * *", "America/New_York").expect("schedule");
        // 2026-03-08 02:30 does not exist in New York: it runs at 03:30 EDT.
        assert_eq!(
            skipped.next_after(utc("2026-03-07T12:00:00Z")),
            Some(utc("2026-03-08T07:30:00Z"))
        );
        let repeated = Schedule::cron("30 1 * * *", "America/New_York").expect("schedule");
        // 2026-11-01 01:30 happens twice: it runs at the first (EDT) only.
        let first = repeated
            .next_after(utc("2026-10-31T12:00:00Z"))
            .expect("first");
        assert_eq!(first, utc("2026-11-01T05:30:00Z"));
        assert_eq!(
            repeated.next_after(first),
            Some(utc("2026-11-02T06:30:00Z"))
        );
    }

    #[test]
    fn hijri_monthly_runs_on_the_hijri_day() {
        use attome_calendar::hijri::{HijriDate, from_hijri};
        let ramadan = from_hijri(HijriDate::new(1447, 9, 1)).expect("1 Ramadan 1447");
        let s = Schedule::hijri_monthly(
            1,
            NaiveTime::from_hms_opt(9, 0, 0).expect("time"),
            "Asia/Riyadh",
        )
        .expect("schedule");
        let before = (ramadan - chrono::Duration::days(2))
            .and_hms_opt(12, 0, 0)
            .expect("t")
            .and_utc();
        let expected = ramadan.and_hms_opt(6, 0, 0).expect("t").and_utc();
        assert_eq!(s.next_after(before), Some(expected));
        // Day 30 of a 29-day month runs on its last day.
        let length = attome_calendar::hijri::month_length(1447, 9).expect("length");
        let last = from_hijri(HijriDate::new(1447, 9, length)).expect("last day");
        let thirtieth = Schedule::hijri_monthly(
            30,
            NaiveTime::from_hms_opt(9, 0, 0).expect("time"),
            "Asia/Riyadh",
        )
        .expect("schedule");
        assert_eq!(
            thirtieth.next_after(expected),
            Some(last.and_hms_opt(6, 0, 0).expect("t").and_utc())
        );
        assert!(Schedule::hijri_monthly(31, NaiveTime::MIN, "UTC").is_err());
    }

    #[test]
    fn working_days_skip_weekends_and_holidays() {
        use attome_calendar::{BusinessCalendar, TimeRange};
        use chrono::Weekday;
        let days: std::collections::HashSet<Weekday> = [
            Weekday::Sun,
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
        ]
        .into();
        let hours = days
            .iter()
            .map(|d| (*d, vec![TimeRange::try_new(480, 1020).expect("range")]))
            .collect();
        let holiday = chrono::NaiveDate::from_ymd_opt(2026, 10, 25).expect("date");
        let calendar = BusinessCalendar::new(
            "Asia/Riyadh".parse().expect("tz"),
            days,
            hours,
            [holiday].into(),
            Default::default(),
        )
        .expect("calendar");
        let s = Schedule::WorkingDays {
            time: NaiveTime::from_hms_opt(8, 0, 0).expect("time"),
            calendar: Arc::new(calendar),
        };
        // Thursday 2026-10-22 10:00 Riyadh: Friday and Saturday are off and
        // Sunday the 25th is a holiday, so Monday the 26th at 08:00.
        assert_eq!(
            s.next_after(utc("2026-10-22T07:00:00Z")),
            Some(utc("2026-10-26T05:00:00Z"))
        );
        assert!(s.describe().starts_with("working-days 08:00:00 "));
    }

    #[test]
    fn interval_secs_is_never_zero_or_negative() {
        assert_eq!(interval_secs(std::time::Duration::ZERO), 1);
        assert_eq!(interval_secs(std::time::Duration::from_millis(999)), 1);
        assert_eq!(interval_secs(std::time::Duration::from_secs(60)), 60);
        assert_eq!(
            interval_secs(std::time::Duration::from_secs(u64::MAX)),
            i32::MAX
        );
    }
}

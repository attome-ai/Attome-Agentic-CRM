//! G17-T6: building a schedule as a durable job.
//!
//! [`enqueue`] queues the `workforce_build_schedule` job for a planning group
//! and a period inside the caller's transaction. The job ([`run`]):
//!
//! 1. reads, in short read-only queries, the group's staffing rules, its
//!    stored forecast (`wfm_forecast_interval`, workforce pack 0002), its
//!    shift templates, its members (`wfm_group_member`) and their leave
//!    (`resource_availability`), and the coverage of the schedule it would
//!    replace (the published one for the period);
//! 2. per day, turns the forecast into a requirement
//!    ([`crate::staffing::requirement_for_group`]) and each template's start
//!    window into concrete shifts ([`day_templates`]), and solves it with
//!    [`crate::solver::GreedySolver`] on a blocking thread under a deadline
//!    (default [`DEFAULT_DEADLINE_SECS`]); more than [`MAX_PEOPLE`] members
//!    fail with a clear error;
//! 3. writes the result in one transaction under the group's build lock
//!    (`attome-workforce/build:{group}`, `Conflict` while another build
//!    holds it): one `wfm_schedule` in `draft`, keyed by the run id, so a
//!    retry replaces its own assignments instead of adding a second draft,
//!    with `coverage_json` holding the requirement and the coverage before
//!    and after per interval.
//!
//! People on leave on a day are not scheduled that day. Nothing is
//! published: a person reviews and publishes the draft (G17-T7).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration as StdDuration;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::solver::{Agent, GreedySolver, Problem, ScheduleSolver, Template};
use crate::staffing::{ChannelKind, IntervalForecast, PlanningGroup, requirement_for_group};

/// Shift start and end times.
type Spans = Vec<(DateTime<Utc>, DateTime<Utc>)>;

/// The registered job.
pub const JOB: &str = "workforce_build_schedule";
/// The solving deadline when the caller gives none, in seconds.
pub const DEFAULT_DEADLINE_SECS: u64 = 300;
/// Most members one build schedules.
pub const MAX_PEOPLE: usize = 2_000;
/// Longest period one build covers, in days.
pub const MAX_DAYS: i64 = 31;
/// Longest `coverage_json` stored (the attribute's length).
const MAX_COVERAGE_CHARS: usize = 20_000;

/// The job's payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuildJob {
    /// Keys the draft: a retry with the same run id updates the same one.
    pub run_id: Uuid,
    pub group_id: Uuid,
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub requested_by: Uuid,
    #[serde(default)]
    pub deadline_secs: Option<u64>,
}

/// Queues a build in the caller's transaction.
pub async fn enqueue(tx: &mut attome_db::Tx<'_>, job: &BuildJob) -> Result<(), AppError> {
    check_period(job.from, job.to)?;
    let registered = attome_core::jobs::JOB_TYPES
        .job(JOB, job)
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(tx, attome_core::jobs::EngineJob::Registered(registered))
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// The period must run forwards and stay within [`MAX_DAYS`]. Pure.
pub fn check_period(from: NaiveDate, to: NaiveDate) -> Result<(), AppError> {
    if to < from {
        return Err(AppError::Validation("to: on or after from".into()));
    }
    if (to - from).num_days() >= MAX_DAYS {
        return Err(AppError::Validation(format!(
            "a build covers at most {MAX_DAYS} days"
        )));
    }
    Ok(())
}

/// Minutes after midnight of `HH:MM`. Pure.
pub fn parse_hhmm(raw: &str) -> Option<u32> {
    let (h, m) = raw.trim().split_once(':')?;
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

/// A stored shift template.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredTemplate {
    pub id: Uuid,
    pub window_from: u32,
    pub window_to: u32,
    pub length_minutes: u32,
}

/// One concrete shift of a day: the template it comes from and its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DayShift {
    pub template: Uuid,
    pub start_minute: u32,
    pub length_minutes: u32,
}

/// Every concrete shift a day's templates allow, one per interval-aligned
/// start in each start window, with its solver template (interval indices,
/// clipped to the day). Pure.
pub fn day_templates(
    stored: &[StoredTemplate],
    interval_minutes: u32,
) -> (Vec<Template>, Vec<DayShift>) {
    let step = interval_minutes.max(1);
    let slots = (24 * 60) / step;
    let mut templates = Vec::new();
    let mut shifts = Vec::new();
    for t in stored {
        if t.length_minutes == 0 || t.window_to < t.window_from {
            continue;
        }
        let first = t.window_from.div_ceil(step) * step;
        let mut start = first;
        while start <= t.window_to {
            let start_idx = (start / step) as usize;
            let end_idx = (((start + t.length_minutes).div_ceil(step)).min(slots)) as usize;
            if end_idx > start_idx {
                templates.push(Template {
                    id: Uuid::from_u128(shifts.len() as u128),
                    start: start_idx,
                    end: end_idx,
                });
                shifts.push(DayShift {
                    template: t.id,
                    start_minute: start,
                    length_minutes: t.length_minutes,
                });
            }
            start += step;
        }
    }
    (templates, shifts)
}

/// The requirement per interval of a day from interval requirements that
/// start that day. Pure.
pub fn day_requirement(
    day: NaiveDate,
    interval_minutes: u32,
    reqs: &[(DateTime<Utc>, u32)],
) -> Vec<u32> {
    let step = i64::from(interval_minutes.max(1));
    let slots = (24 * 60 / step) as usize;
    let mut out = vec![0; slots];
    let midnight = day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    for (start, agents) in reqs {
        let minutes = (*start - midnight).num_minutes();
        if minutes < 0 {
            continue;
        }
        let idx = (minutes / step) as usize;
        if let Some(slot) = out.get_mut(idx) {
            *slot = (*slot).max(*agents);
        }
    }
    out
}

/// One day's result, for `coverage_json`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DayCoverage {
    pub day: NaiveDate,
    pub requirement: Vec<u32>,
    pub before: Vec<u32>,
    pub after: Vec<u32>,
    pub under: u32,
    pub over: u32,
}

/// Coverage per interval of `assignments` (start and end) on `day`. Pure.
pub fn coverage_of(
    day: NaiveDate,
    interval_minutes: u32,
    assignments: &[(DateTime<Utc>, DateTime<Utc>)],
) -> Vec<u32> {
    let step = i64::from(interval_minutes.max(1));
    let slots = (24 * 60 / step) as usize;
    let mut out = vec![0; slots];
    let midnight = day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    for (i, slot) in out.iter_mut().enumerate() {
        let at = midnight + Duration::minutes(step * i as i64);
        *slot = assignments
            .iter()
            .filter(|(s, e)| *s <= at && at < *e)
            .count() as u32;
    }
    out
}

/// What a build did.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BuildResult {
    pub schedule_id: Uuid,
    pub assignments: usize,
    pub days: Vec<DayCoverage>,
}

fn channel(raw: Option<&str>) -> ChannelKind {
    match raw {
        Some("chat") => ChannelKind::Chat,
        Some("email") => ChannelKind::Email,
        Some("case") => ChannelKind::Case,
        _ => ChannelKind::Voice,
    }
}

/// `(id, window from, window to, length)`.
type TemplateRow = (Uuid, Option<String>, Option<String>, Option<f64>);

/// `(channel, sl pct, sl secs, interval, shrinkage, concurrency, backlog, aht)`.
type GroupRow = (
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<String>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

/// Runs one build.
pub async fn run(state: &EngineState, job: &BuildJob) -> Result<BuildResult, AppError> {
    check_period(job.from, job.to)?;
    let db = &state.base.db;
    let ready: bool = sqlx::query_scalar(
        "SELECT to_regclass('wfm_group_member') IS NOT NULL \
            AND to_regclass('wfm_forecast_interval') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Err(AppError::NotFound);
    }

    // 1. Inputs, in short reads.
    let group: Option<GroupRow> = sqlx::query_as(
        "SELECT channel::text, service_level_target_pct::float8, service_level_seconds::float8, \
                interval_minutes::text, shrinkage_pct::float8, concurrency::float8, \
                backlog_hours::float8, aht_seconds::float8 \
           FROM wfm_planning_group WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(job.group_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((chan, sl_pct, sl_secs, interval, shrink, conc, backlog, aht)) = group else {
        return Err(AppError::NotFound);
    };
    let interval_minutes: u32 = interval
        .as_deref()
        .and_then(|i| i.trim().parse().ok())
        .filter(|i| *i == 15 || *i == 30)
        .unwrap_or(30);
    let planning = PlanningGroup {
        id: job.group_id,
        channel: channel(chan.as_deref()),
        aht_secs: aht.filter(|a| *a > 0.0).unwrap_or(180.0),
        target_pct: sl_pct.unwrap_or(80.0),
        target_secs: sl_secs.unwrap_or(20.0),
        concurrency: conc.filter(|c| *c >= 1.0).unwrap_or(1.0),
        backlog_hours: backlog.unwrap_or(8.0),
        shrinkage_pct: shrink.unwrap_or(0.0),
    };
    let from_at = job.from.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    let to_at = (job.to + Duration::days(1))
        .and_hms_opt(0, 0, 0)
        .unwrap_or_default()
        .and_utc();
    let forecast_rows: Vec<(DateTime<Utc>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT interval_start::timestamptz, volume::float8, digital_share::float8 \
           FROM wfm_forecast_interval \
          WHERE planning_group_ref = $1 AND interval_start::timestamptz >= $2 \
            AND interval_start::timestamptz < $3 AND (is_active IS NULL OR is_active = true) \
          ORDER BY interval_start",
    )
    .bind(job.group_id)
    .bind(from_at)
    .bind(to_at)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let forecast: Vec<IntervalForecast> = forecast_rows
        .into_iter()
        .map(|(start, volume, digital)| IntervalForecast {
            start,
            interval_secs: f64::from(interval_minutes * 60),
            volume: volume.unwrap_or(0.0).max(0.0),
            digital_share: digital.unwrap_or(0.0),
        })
        .collect();
    let requirement: Vec<(DateTime<Utc>, u32)> = requirement_for_group(&planning, &forecast)
        .into_iter()
        .map(|r| (r.start, r.scheduled))
        .collect();

    let template_rows: Vec<TemplateRow> = sqlx::query_as(
        "SELECT id, start_window_from, start_window_to, length_minutes::float8 FROM wfm_shift_template \
          WHERE planning_group_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .bind(job.group_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let stored: Vec<StoredTemplate> = template_rows
        .into_iter()
        .filter_map(|(id, from, to, length)| {
            let window_from = parse_hhmm(from.as_deref()?)?;
            let window_to = to.as_deref().and_then(parse_hhmm).unwrap_or(window_from);
            let length_minutes = length.filter(|l| *l > 0.0)? as u32;
            Some(StoredTemplate {
                id,
                window_from,
                window_to,
                length_minutes,
            })
        })
        .collect();
    if stored.is_empty() {
        return Err(AppError::Validation(
            "the planning group has no usable shift templates (start window HH:MM and a length)"
                .into(),
        ));
    }
    let members: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_ref FROM wfm_group_member \
          WHERE planning_group_ref = $1 AND user_ref IS NOT NULL \
            AND (is_active IS NULL OR is_active = true) LIMIT $2",
    )
    .bind(job.group_id)
    .bind(i64::try_from(MAX_PEOPLE + 1).unwrap_or(i64::MAX))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if members.len() > MAX_PEOPLE {
        return Err(AppError::Validation(format!(
            "a build schedules at most {MAX_PEOPLE} people; split the planning group"
        )));
    }
    let leave: Vec<(Uuid, NaiveDate, NaiveDate)> = sqlx::query_as(
        "SELECT user_id, leave_start::date, leave_end::date FROM resource_availability \
          WHERE user_id = ANY($1) AND is_active IS NOT FALSE \
            AND leave_start::date <= $3 AND leave_end::date >= $2",
    )
    .bind(&members)
    .bind(job.from)
    .bind(job.to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let published: Vec<(DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT a.start_at::timestamptz, a.end_at::timestamptz FROM wfm_shift_assignment a \
           JOIN wfm_schedule s ON s.id = a.schedule_ref \
          WHERE s.planning_group_ref = $1 AND s.status = 'published' AND a.activity = 'work' \
            AND a.start_at::timestamptz < $3 AND a.end_at::timestamptz > $2 \
            AND (a.is_active IS NULL OR a.is_active = true)",
    )
    .bind(job.group_id)
    .bind(from_at)
    .bind(to_at)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    // 2. Solve each day off the runtime, under the deadline.
    let deadline =
        StdDuration::from_secs(job.deadline_secs.unwrap_or(DEFAULT_DEADLINE_SECS).max(1));
    let (templates, shifts) = day_templates(&stored, interval_minutes);
    let mut days = Vec::new();
    let mut day = job.from;
    while day <= job.to {
        days.push(day);
        day += Duration::days(1);
    }
    let problems: Vec<(NaiveDate, Problem)> = days
        .iter()
        .map(|d| {
            let away: HashSet<Uuid> = leave
                .iter()
                .filter(|(_, s, e)| s <= d && d <= e)
                .map(|(u, _, _)| *u)
                .collect();
            let agents = members
                .iter()
                .filter(|u| !away.contains(u))
                .map(|u| Agent {
                    id: *u,
                    allowed: templates.iter().map(|t| t.id).collect(),
                })
                .collect();
            (
                *d,
                Problem {
                    requirement: day_requirement(*d, interval_minutes, &requirement),
                    templates: templates.clone(),
                    agents,
                    under_weight: 3.0,
                },
            )
        })
        .collect();
    let solved = tokio::time::timeout(
        deadline,
        tokio::task::spawn_blocking(move || {
            let solver = GreedySolver::default();
            problems
                .into_iter()
                .map(|(d, p)| {
                    let s = solver.solve(&p);
                    (d, p.requirement, s)
                })
                .collect::<Vec<_>>()
        }),
    )
    .await
    .map_err(|_| {
        AppError::Validation(format!(
            "the schedule did not solve within {}s",
            deadline.as_secs()
        ))
    })?
    .map_err(AppError::internal)?;

    // 3. Write the draft under the group's build lock.
    let index: HashMap<Uuid, DayShift> = templates
        .iter()
        .zip(&shifts)
        .map(|(t, s)| (t.id, *s))
        .collect();
    let mut rows: Vec<(Uuid, DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    let mut coverage = Vec::new();
    let mut by_day_before: BTreeMap<NaiveDate, Spans> = BTreeMap::new();
    for (s, e) in &published {
        by_day_before
            .entry(s.date_naive())
            .or_default()
            .push((*s, *e));
    }
    for (d, requirement, solution) in solved {
        let midnight = d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
        let mut today = Vec::new();
        for a in &solution.assignments {
            let Some(shift) = index.get(&a.template) else {
                continue;
            };
            let start = midnight + Duration::minutes(i64::from(shift.start_minute));
            let end = start + Duration::minutes(i64::from(shift.length_minutes));
            rows.push((a.agent, start, end));
            today.push((start, end));
        }
        coverage.push(DayCoverage {
            day: d,
            before: coverage_of(
                d,
                interval_minutes,
                by_day_before.get(&d).map_or(&[][..], Vec::as_slice),
            ),
            after: coverage_of(d, interval_minutes, &today),
            requirement,
            under: solution.under,
            over: solution.over,
        });
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-workforce/build:{}", job.group_id))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a schedule build for this group is running",
        ));
    }
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM wfm_schedule WHERE build_run_id = $1 AND status = 'draft' LIMIT 1",
    )
    .bind(job.run_id.to_string())
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut coverage_json = json!(coverage).to_string();
    if coverage_json.len() > MAX_COVERAGE_CHARS {
        // Too long for the attribute: per-day totals only.
        coverage_json = json!(
            coverage
                .iter()
                .map(|c| json!({ "day": c.day, "under": c.under, "over": c.over }))
                .collect::<Vec<_>>()
        )
        .to_string();
    }
    let schedule = match existing {
        Some(id) => {
            sqlx::query("DELETE FROM wfm_shift_assignment WHERE schedule_ref = $1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            sqlx::query(
                "UPDATE wfm_schedule SET coverage_json = $2, modified_at = now(), \
                     row_version = row_version + 1 WHERE id = $1",
            )
            .bind(id)
            .bind(&coverage_json)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            id
        }
        None => sqlx::query_scalar(
            "INSERT INTO wfm_schedule (id, planning_group_ref, period_from, period_to, status, \
                 build_run_id, coverage_json, created_by, owner_ref) \
             VALUES ($1, $2, $3, $4, 'draft', $5, $6, $7, $7) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(job.group_id)
        .bind(job.from)
        .bind(job.to)
        .bind(job.run_id.to_string())
        .bind(&coverage_json)
        .bind(job.requested_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?,
    };
    for (user, start, end) in &rows {
        sqlx::query(
            "INSERT INTO wfm_shift_assignment (id, schedule_ref, user_ref, start_at, end_at, \
                 activity, created_by, owner_ref) VALUES ($1, $2, $3, $4, $5, 'work', $6, $6)",
        )
        .bind(Uuid::now_v7())
        .bind(schedule)
        .bind(user)
        .bind(start)
        .bind(end)
        .bind(job.requested_by)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;
    tracing::info!(group = %job.group_id, %schedule, assignments = rows.len(), "workforce: draft schedule built");
    Ok(BuildResult {
        schedule_id: schedule,
        assignments: rows.len(),
        days: coverage,
    })
}

#[cfg(test)]
mod build_job_tests {
    use super::*;

    fn day(d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2027, 3, d).expect("a real date")
    }

    #[test]
    fn times_parse_as_minutes_after_midnight() {
        assert_eq!(parse_hhmm("08:30"), Some(510));
        assert_eq!(parse_hhmm(" 00:00 "), Some(0));
        assert_eq!(parse_hhmm("24:00"), None);
        assert_eq!(parse_hhmm("8"), None);
    }

    #[test]
    fn a_start_window_becomes_one_shift_per_interval() {
        let stored = [StoredTemplate {
            id: Uuid::from_u128(9),
            window_from: 8 * 60,
            window_to: 9 * 60,
            length_minutes: 8 * 60,
        }];
        let (templates, shifts) = day_templates(&stored, 30);
        assert_eq!(templates.len(), 3, "08:00, 08:30 and 09:00");
        assert_eq!((templates[0].start, templates[0].end), (16, 32));
        assert_eq!(shifts[2].start_minute, 9 * 60);
        assert!(shifts.iter().all(|s| s.template == Uuid::from_u128(9)));
        // A night shift is clipped at midnight.
        let night = [StoredTemplate {
            id: Uuid::from_u128(1),
            window_from: 22 * 60,
            window_to: 22 * 60,
            length_minutes: 8 * 60,
        }];
        let (t, _) = day_templates(&night, 30);
        assert_eq!((t[0].start, t[0].end), (44, 48));
    }

    #[test]
    fn requirement_and_coverage_land_on_their_intervals() {
        let at = |h: u32, m: u32| day(1).and_hms_opt(h, m, 0).expect("a time").and_utc();
        let req = day_requirement(day(1), 30, &[(at(9, 0), 3), (at(9, 30), 4), (at(0, 0), 1)]);
        assert_eq!(req.len(), 48);
        assert_eq!((req[0], req[18], req[19], req[20]), (1, 3, 4, 0));
        let cov = coverage_of(day(1), 30, &[(at(9, 0), at(10, 0)), (at(9, 30), at(17, 0))]);
        assert_eq!(
            (cov[17], cov[18], cov[19], cov[20], cov[34]),
            (0, 1, 2, 1, 0)
        );
    }

    #[test]
    fn a_build_covers_a_bounded_forward_period() {
        assert!(check_period(day(1), day(1)).is_ok());
        assert!(check_period(day(2), day(1)).is_err());
        assert!(check_period(day(1), day(1) + Duration::days(MAX_DAYS)).is_err());
    }

    #[test]
    fn a_solved_day_meets_a_flat_requirement() {
        let stored = [StoredTemplate {
            id: Uuid::from_u128(9),
            window_from: 8 * 60,
            window_to: 8 * 60,
            length_minutes: 8 * 60,
        }];
        let (templates, _) = day_templates(&stored, 30);
        let mut requirement = vec![0; 48];
        for slot in requirement.iter_mut().take(32).skip(16) {
            *slot = 2;
        }
        let agents = (0..3)
            .map(|n| Agent {
                id: Uuid::from_u128(100 + n),
                allowed: templates.iter().map(|t| t.id).collect(),
            })
            .collect();
        let solution = GreedySolver::default().solve(&Problem {
            requirement,
            templates,
            agents,
            under_weight: 3.0,
        });
        assert_eq!(solution.under, 0);
        assert_eq!(
            solution.assignments.len(),
            2,
            "the third person is not needed"
        );
    }
}

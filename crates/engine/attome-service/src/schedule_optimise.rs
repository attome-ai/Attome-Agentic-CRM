//! I2-T2: a proposed day plan for technicians, never committed.
//!
//! `POST /api/v1/service/day-plans/propose` takes a day and work orders
//! (by default the day's scheduled work orders with no technician) and
//! answers **ghost assignments**: who does which job, in which order, from
//! when to when, with the travel between. Nothing is written; a dispatcher
//! applies what they accept by assigning the work orders.
//!
//! Each job's eligible technicians come from the I2-T1 hard rules
//! ([`crate::schedule_candidates::find`], with van parts relaxed), so a
//! proposal never breaks one. [`plan`] then:
//!
//! 1. **inserts** jobs one by one, the most constrained first (fewest
//!    eligible technicians, then earliest due), at the position in an
//!    eligible technician's route that adds the least travel while the day
//!    still ends within the working window;
//! 2. **improves** by moving one job at a time to the position that lowers
//!    total travel most, until nothing improves or the time budget
//!    ([`TIME_BUDGET`], 10 s) runs out.
//!
//! Jobs that fit nowhere are answered as unassigned.

use std::collections::HashMap;
use std::time::{Duration as StdDuration, Instant};

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::schedule_candidates::{WorkOrderDispatch, travel_minutes};

/// The longest a proposal runs.
pub const TIME_BUDGET: StdDuration = StdDuration::from_secs(10);
/// A job's length when its incident type gives none.
pub const DEFAULT_JOB_MINUTES: i64 = 60;
/// The working day when a technician has no shift that day.
pub const DAY_START_HOUR: u32 = 8;
pub const DAY_END_HOUR: u32 = 17;
/// Most jobs one proposal plans.
pub const MAX_JOBS: usize = 300;

/// A job to place.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanJob {
    pub id: Uuid,
    pub site: Option<(f64, f64)>,
    pub minutes: i64,
    /// The technicians the hard rules allow.
    pub eligible: Vec<Uuid>,
    pub due: Option<DateTime<Utc>>,
}

/// A technician's day.
#[derive(Debug, Clone, PartialEq)]
pub struct PlanTech {
    pub id: Uuid,
    pub base: Option<(f64, f64)>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// One proposed visit.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Ghost {
    pub work_order_id: Uuid,
    pub technician_id: Uuid,
    /// Position in the technician's route, 1 first.
    pub sequence: usize,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Travel to this visit, in minutes (0 when not known).
    pub travel_minutes: i64,
}

/// A proposed day.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DayPlan {
    pub assignments: Vec<Ghost>,
    pub unassigned: Vec<Uuid>,
    /// Total travel, in minutes.
    pub total_travel_minutes: i64,
    /// Whether the time budget ended the improvement early.
    pub stopped_at_budget: bool,
}

fn leg(a: Option<(f64, f64)>, b: Option<(f64, f64)>) -> i64 {
    travel_minutes(a, b).unwrap_or(0)
}

/// A route's visits with times, or `None` when it overruns the day. Pure.
/// A route's visits as `(travel, start, end)` and its total travel.
type Timed = (Vec<(i64, DateTime<Utc>, DateTime<Utc>)>, i64);

/// `(site latitude, site longitude, minutes, due)`.
type JobRow = (Option<f64>, Option<f64>, Option<f64>, Option<DateTime<Utc>>);

fn timed(tech: &PlanTech, route: &[usize], jobs: &[PlanJob]) -> Option<Timed> {
    let mut at = tech.start;
    let mut here = tech.base;
    let mut travel = 0;
    let mut out = Vec::with_capacity(route.len());
    for &j in route {
        let job = &jobs[j];
        let t = leg(here, job.site);
        travel += t;
        let start = at + Duration::minutes(t);
        let end = start + Duration::minutes(job.minutes.max(1));
        if end > tech.end {
            return None;
        }
        out.push((t, start, end));
        at = end;
        here = job.site.or(here);
    }
    Some((out, travel))
}

fn total(techs: &[PlanTech], routes: &[Vec<usize>], jobs: &[PlanJob]) -> i64 {
    techs
        .iter()
        .zip(routes)
        .map(|(t, r)| timed(t, r, jobs).map_or(i64::MAX / 4, |(_, travel)| travel))
        .sum()
}

/// The cheapest feasible insertion of `job` into any eligible route:
/// `(tech index, position, added travel)`.
fn best_insertion(
    techs: &[PlanTech],
    routes: &[Vec<usize>],
    jobs: &[PlanJob],
    job: usize,
) -> Option<(usize, usize, i64)> {
    let mut best: Option<(usize, usize, i64)> = None;
    for (ti, tech) in techs.iter().enumerate() {
        if !jobs[job].eligible.contains(&tech.id) {
            continue;
        }
        let Some((_, before)) = timed(tech, &routes[ti], jobs) else {
            continue;
        };
        for pos in 0..=routes[ti].len() {
            let mut r = routes[ti].clone();
            r.insert(pos, job);
            if let Some((_, after)) = timed(tech, &r, jobs) {
                let added = after - before;
                if best.is_none_or(|(_, _, b)| added < b) {
                    best = Some((ti, pos, added));
                }
            }
        }
    }
    best
}

/// Plans a day: greedy insertion, then moves that cut travel, within
/// `budget`. Pure apart from the clock that bounds it.
pub fn plan(jobs: &[PlanJob], techs: &[PlanTech], budget: StdDuration) -> DayPlan {
    let started = Instant::now();
    let mut routes: Vec<Vec<usize>> = vec![Vec::new(); techs.len()];
    let mut order: Vec<usize> = (0..jobs.len()).collect();
    order.sort_by(|&a, &b| {
        jobs[a]
            .eligible
            .len()
            .cmp(&jobs[b].eligible.len())
            .then(jobs[a].due.cmp(&jobs[b].due))
            .then(jobs[a].id.cmp(&jobs[b].id))
    });
    let mut unassigned = Vec::new();
    for j in order {
        match best_insertion(techs, &routes, jobs, j) {
            Some((ti, pos, _)) => routes[ti].insert(pos, j),
            None => unassigned.push(jobs[j].id),
        }
    }

    // Relocate: take one job out and put it back at its best place.
    let mut stopped = false;
    'improve: loop {
        let mut improved = false;
        for ti in 0..routes.len() {
            let mut pos = 0;
            while pos < routes[ti].len() {
                if started.elapsed() >= budget {
                    stopped = true;
                    break 'improve;
                }
                let current = total(techs, &routes, jobs);
                let job = routes[ti].remove(pos);
                if let Some((bt, bp, _)) = best_insertion(techs, &routes, jobs, job) {
                    let mut candidate = routes.clone();
                    candidate[bt].insert(bp, job);
                    if total(techs, &candidate, jobs) < current {
                        routes = candidate;
                        improved = true;
                        continue;
                    }
                }
                routes[ti].insert(pos, job);
                pos += 1;
            }
        }
        if !improved {
            break;
        }
    }

    let mut assignments = Vec::new();
    let mut travel_total = 0;
    for (tech, route) in techs.iter().zip(&routes) {
        let Some((visits, travel)) = timed(tech, route, jobs) else {
            continue;
        };
        travel_total += travel;
        for (i, (&j, (t, start, end))) in route.iter().zip(visits).enumerate() {
            assignments.push(Ghost {
                work_order_id: jobs[j].id,
                technician_id: tech.id,
                sequence: i + 1,
                start,
                end,
                travel_minutes: t,
            });
        }
    }
    unassigned.sort();
    DayPlan {
        assignments,
        unassigned,
        total_travel_minutes: travel_total,
        stopped_at_budget: stopped,
    }
}

/// What to plan.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ProposeBody {
    pub date: NaiveDate,
    /// The work orders to plan; by default the day's scheduled work orders
    /// with no technician.
    pub work_order_ids: Option<Vec<Uuid>>,
}

fn at(date: NaiveDate, hour: u32) -> DateTime<Utc> {
    date.and_hms_opt(hour, 0, 0).unwrap_or_default().and_utc()
}

/// Loads, checks and plans one day.
pub async fn propose(
    state: &EngineState,
    body: &ProposeBody,
    now: DateTime<Utc>,
) -> Result<DayPlan, AppError> {
    let db = &state.base.db;
    let day_from = at(body.date, 0);
    let day_to = day_from + Duration::days(1);
    let ids: Vec<Uuid> = match &body.work_order_ids {
        Some(ids) => ids.clone(),
        None => sqlx::query_scalar(
            "SELECT id FROM work_order \
              WHERE scheduled_start::timestamptz >= $1 AND scheduled_start::timestamptz < $2 \
                AND assigned_to IS NULL AND status IN ('new', 'scheduled') \
                AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $3",
        )
        .bind(day_from)
        .bind(day_to)
        .bind(i64::try_from(MAX_JOBS).unwrap_or(i64::MAX))
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?,
    };
    if ids.len() > MAX_JOBS {
        return Err(AppError::Validation(format!(
            "work_order_ids: at most {MAX_JOBS} work orders in one proposal"
        )));
    }
    let mut jobs = Vec::with_capacity(ids.len());
    let mut techs: HashMap<Uuid, PlanTech> = HashMap::new();
    for id in ids {
        let row: Option<JobRow> = sqlx::query_as(
            "SELECT wo.site_latitude::float8, wo.site_longitude::float8, it.default_minutes::float8, \
                    wo.scheduled_end::timestamptz \
               FROM work_order wo LEFT JOIN incident_type it ON it.id = wo.incident_type_ref \
              WHERE wo.id = $1",
        )
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let Some((lat, lon, minutes, due)) = row else {
            continue;
        };
        // The I2-T1 hard rules, parts relaxed (a technician may collect them).
        let candidates = crate::schedule_candidates::find(state, id, true, now).await?;
        let eligible: Vec<Uuid> = candidates.candidates.iter().map(|c| c.user_id).collect();
        for user in &eligible {
            techs.entry(*user).or_insert_with(|| PlanTech {
                id: *user,
                base: None,
                start: at(body.date, DAY_START_HOUR),
                end: at(body.date, DAY_END_HOUR),
            });
        }
        jobs.push(PlanJob {
            id,
            site: match (lat, lon) {
                (Some(a), Some(b)) => Some((a, b)),
                _ => None,
            },
            minutes: minutes
                .filter(|m| *m > 0.0)
                .map_or(DEFAULT_JOB_MINUTES, |m| m.round() as i64),
            eligible,
            due,
        });
    }
    let users: Vec<Uuid> = techs.keys().copied().collect();
    let bases: Vec<(Uuid, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT user_ref, base_latitude::float8, base_longitude::float8 FROM technician_profile \
          WHERE user_ref = ANY($1) AND (is_active IS NULL OR is_active = true)",
    )
    .bind(&users)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (user, lat, lon) in bases {
        if let (Some(t), Some(a), Some(b)) = (techs.get_mut(&user), lat, lon) {
            t.base = Some((a, b));
        }
    }
    let shifts: Vec<(Uuid, DateTime<Utc>, DateTime<Utc>)> =
        if sqlx::query_scalar::<_, bool>("SELECT to_regclass('wfm_shift_assignment') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?
        {
            sqlx::query_as(
                "SELECT user_ref, min(start_at::timestamptz), max(end_at::timestamptz) \
               FROM wfm_shift_assignment \
              WHERE user_ref = ANY($1) AND activity = 'work' \
                AND start_at::timestamptz < $3 AND end_at::timestamptz > $2 \
                AND (is_active IS NULL OR is_active = true) GROUP BY user_ref",
            )
            .bind(&users)
            .bind(day_from)
            .bind(day_to)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
        } else {
            Vec::new()
        };
    for (user, start, end) in shifts {
        if let Some(t) = techs.get_mut(&user) {
            t.start = start;
            t.end = end;
        }
    }
    let mut techs: Vec<PlanTech> = techs.into_values().collect();
    techs.sort_by_key(|t| t.id);
    let result = tokio::task::spawn_blocking(move || plan(&jobs, &techs, TIME_BUDGET))
        .await
        .map_err(AppError::internal)?;
    Ok(result)
}

#[utoipa::path(
    post,
    path = "/api/v1/service/day-plans/propose",
    operation_id = "post_day_plan_propose",
    tag = "service",
    request_body = ProposeBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "computes a proposal and writes nothing; the dispatcher assigns what they accept",
    )))),
    responses(
        (status = 200, description = "The proposed day", body = DayPlan),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks work_order.update", body = ErrorResponse),
        (status = 404, description = "Field service is not installed", body = ErrorResponse),
        (status = 422, description = "Too many work orders", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Proposes a technicians' day plan.
///
/// Ghost assignments that respect the hard rules and keep travel low; the
/// proposal is never committed.
async fn post_propose(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<WorkOrderDispatch>>,
    Json(body): Json<ProposeBody>,
) -> Result<Json<DayPlan>, AppError> {
    Ok(Json(propose(&state, &body, Utc::now()).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/service/day-plans/propose", post(post_propose))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_propose), components(schemas(ProposeBody, DayPlan, Ghost)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod schedule_optimise_tests {
    use super::*;

    fn at_h(h: u32) -> DateTime<Utc> {
        at(NaiveDate::from_ymd_opt(2027, 3, 1).expect("a date"), h)
    }

    fn tech(n: u128, base: (f64, f64)) -> PlanTech {
        PlanTech {
            id: Uuid::from_u128(n),
            base: Some(base),
            start: at_h(8),
            end: at_h(17),
        }
    }

    fn job(n: u128, site: (f64, f64), eligible: &[u128]) -> PlanJob {
        PlanJob {
            id: Uuid::from_u128(n),
            site: Some(site),
            minutes: 60,
            eligible: eligible.iter().map(|e| Uuid::from_u128(*e)).collect(),
            due: None,
        }
    }

    // Riyadh east and west, about 20 km apart.
    const EAST: (f64, f64) = (24.70, 46.80);
    const WEST: (f64, f64) = (24.70, 46.60);

    #[test]
    fn each_job_goes_to_the_nearer_eligible_technician() {
        let techs = [tech(1, EAST), tech(2, WEST)];
        let jobs = [job(10, EAST, &[1, 2]), job(11, WEST, &[1, 2])];
        let p = plan(&jobs, &techs, TIME_BUDGET);
        let who = |j: u128| {
            p.assignments
                .iter()
                .find(|g| g.work_order_id == Uuid::from_u128(j))
                .map(|g| g.technician_id.as_u128())
        };
        assert_eq!(who(10), Some(1));
        assert_eq!(who(11), Some(2));
        assert_eq!(p.total_travel_minutes, 0);
        assert!(p.unassigned.is_empty());
    }

    #[test]
    fn hard_rules_are_never_broken() {
        let techs = [tech(1, EAST), tech(2, WEST)];
        // Only the far technician may take it.
        let jobs = [job(10, EAST, &[2])];
        let p = plan(&jobs, &techs, TIME_BUDGET);
        assert_eq!(p.assignments[0].technician_id, Uuid::from_u128(2));
        assert!(p.assignments[0].travel_minutes > 0);
        let nobody = [job(11, EAST, &[])];
        assert_eq!(
            plan(&nobody, &techs, TIME_BUDGET).unassigned,
            vec![Uuid::from_u128(11)]
        );
    }

    #[test]
    fn a_day_never_runs_past_its_window() {
        let techs = [tech(1, EAST)];
        let jobs: Vec<PlanJob> = (0..12).map(|n| job(100 + n, EAST, &[1])).collect();
        let p = plan(&jobs, &techs, TIME_BUDGET);
        assert_eq!(
            p.assignments.len(),
            9,
            "nine one-hour jobs fill 08:00-17:00"
        );
        assert_eq!(p.unassigned.len(), 3);
        assert!(p.assignments.iter().all(|g| g.end <= at_h(17)));
        let seqs: Vec<usize> = p.assignments.iter().map(|g| g.sequence).collect();
        assert_eq!(seqs, (1..=9).collect::<Vec<_>>());
    }

    #[test]
    fn improvement_does_not_add_travel_and_respects_the_budget() {
        let techs = [tech(1, EAST), tech(2, WEST)];
        let jobs = [
            job(10, WEST, &[1, 2]),
            job(11, EAST, &[1, 2]),
            job(12, WEST, &[1, 2]),
            job(13, EAST, &[1, 2]),
        ];
        let p = plan(&jobs, &techs, TIME_BUDGET);
        assert_eq!(
            p.total_travel_minutes, 0,
            "each side served from its own base"
        );
        let rushed = plan(&jobs, &techs, StdDuration::ZERO);
        assert_eq!(
            rushed.assignments.len(),
            4,
            "insertion still places every job"
        );
    }
}

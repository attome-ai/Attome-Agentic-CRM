//! G17-T11: what-if on a schedule, and a hiring view. Nothing is written.
//!
//! `POST /api/v1/workforce/schedules/{id}/what-if` recomputes, in memory, a
//! schedule's requirement, coverage and service level with a changed
//! forecast (`forecast_multiplier`), targets (`target_pct`, `target_secs`,
//! `aht_seconds`) or headcount (`headcount_delta` agents added to, or taken
//! from, every interval's coverage). The requirement comes from
//! [`crate::staffing::requirement_for_group`]; a live channel's service
//! level per interval is the Erlang C answer for the agents on the floor.
//!
//! `GET /api/v1/workforce/groups/{id}/hiring-plan?months=6` sums the stored
//! forecast's required agent-hours per month into full-time equivalents
//! ([`FTE_HOURS_PER_MONTH`]) beside the group's current members. A month
//! with no forecast answers no requirement.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::admin::ScheduleRead;
use crate::build_job::{coverage_of, day_requirement};
use crate::staffing::{ChannelKind, IntervalForecast, PlanningGroup, requirement_for_group};

/// Working hours of one full-time person a month.
pub const FTE_HOURS_PER_MONTH: f64 = 160.0;
/// Longest hiring view, in months.
pub const MAX_MONTHS: u32 = 24;

/// The changes to try.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct WhatIfBody {
    /// Volume multiplier (1.2 is 20% more), default 1.
    pub forecast_multiplier: Option<f64>,
    pub target_pct: Option<f64>,
    pub target_secs: Option<f64>,
    pub aht_seconds: Option<f64>,
    /// Agents added to (or, negative, taken from) every interval.
    pub headcount_delta: Option<i32>,
}

/// One day of the what-if.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct WhatIfDay {
    pub day: NaiveDate,
    pub requirement: Vec<u32>,
    pub coverage: Vec<u32>,
    pub under: u32,
    pub over: u32,
    /// Service level per interval in percent (live channels; absent for
    /// deferred work or an interval with no volume).
    pub service_level: Vec<Option<f64>>,
}

/// The what-if answer.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WhatIf {
    pub schedule_id: Uuid,
    pub days: Vec<WhatIfDay>,
    pub under: u32,
    pub over: u32,
}

/// Coverage shifted by a headcount change, never below zero. Pure.
pub fn shift_coverage(coverage: &[u32], delta: i32) -> Vec<u32> {
    coverage
        .iter()
        .map(|c| u32::try_from((i64::from(*c) + i64::from(delta)).max(0)).unwrap_or(0))
        .collect()
}

/// Under- and over-staffing of a day. Pure.
pub fn gaps(requirement: &[u32], coverage: &[u32]) -> (u32, u32) {
    requirement
        .iter()
        .zip(coverage)
        .fold((0, 0), |(u, o), (need, have)| {
            if have < need {
                (u + need - have, o)
            } else {
                (u, o + have - need)
            }
        })
}

/// Required full-time people for `agent_hours` in a month. Pure.
pub fn fte(agent_hours: f64) -> f64 {
    ((agent_hours / FTE_HOURS_PER_MONTH) * 10.0).round() / 10.0
}

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

async fn group_of(db: &attome_db::DbPool, id: Uuid) -> Result<(PlanningGroup, u32), AppError> {
    let row: Option<GroupRow> = sqlx::query_as(
        "SELECT channel::text, service_level_target_pct::float8, service_level_seconds::float8, \
                interval_minutes::text, shrinkage_pct::float8, concurrency::float8, \
                backlog_hours::float8, aht_seconds::float8 \
           FROM wfm_planning_group WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((chan, pct, secs, interval, shrink, conc, backlog, aht)) = row else {
        return Err(AppError::NotFound);
    };
    let interval_minutes = interval
        .as_deref()
        .and_then(|i| i.trim().parse().ok())
        .filter(|i: &u32| *i == 15 || *i == 30)
        .unwrap_or(30);
    let channel = match chan.as_deref() {
        Some("chat") => ChannelKind::Chat,
        Some("email") => ChannelKind::Email,
        Some("case") => ChannelKind::Case,
        _ => ChannelKind::Voice,
    };
    Ok((
        PlanningGroup {
            id,
            channel,
            aht_secs: aht.filter(|a| *a > 0.0).unwrap_or(180.0),
            target_pct: pct.unwrap_or(80.0),
            target_secs: secs.unwrap_or(20.0),
            concurrency: conc.filter(|c| *c >= 1.0).unwrap_or(1.0),
            backlog_hours: backlog.unwrap_or(8.0),
            shrinkage_pct: shrink.unwrap_or(0.0),
        },
        interval_minutes,
    ))
}

async fn forecast(
    db: &attome_db::DbPool,
    group: Uuid,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    interval_minutes: u32,
) -> Result<Vec<IntervalForecast>, AppError> {
    let rows: Vec<(DateTime<Utc>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT interval_start::timestamptz, volume::float8, digital_share::float8 \
           FROM wfm_forecast_interval \
          WHERE planning_group_ref = $1 AND interval_start::timestamptz >= $2 \
            AND interval_start::timestamptz < $3 AND (is_active IS NULL OR is_active = true) \
          ORDER BY interval_start",
    )
    .bind(group)
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(start, volume, digital)| IntervalForecast {
            start,
            interval_secs: f64::from(interval_minutes * 60),
            volume: volume.unwrap_or(0.0).max(0.0),
            digital_share: digital.unwrap_or(0.0),
        })
        .collect())
}

fn midnight(day: NaiveDate) -> DateTime<Utc> {
    day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc()
}

/// Recomputes a schedule with the changes in `body`; writes nothing.
pub async fn what_if(state: &EngineState, id: Uuid, body: &WhatIfBody) -> Result<WhatIf, AppError> {
    let db = &state.base.db;
    let row: Option<(Option<Uuid>, Option<NaiveDate>, Option<NaiveDate>)> = sqlx::query_as(
        "SELECT planning_group_ref, period_from::date, period_to::date FROM wfm_schedule \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(group_id), Some(from), Some(to))) = row else {
        return Err(AppError::NotFound);
    };
    crate::build_job::check_period(from, to)?;
    let multiplier = body.forecast_multiplier.unwrap_or(1.0);
    if !multiplier.is_finite() || !(0.0..=10.0).contains(&multiplier) {
        return Err(AppError::Validation("forecast_multiplier: 0 to 10".into()));
    }
    let (mut group, interval_minutes) = group_of(db, group_id).await?;
    if let Some(p) = body.target_pct.filter(|p| (1.0..=100.0).contains(p)) {
        group.target_pct = p;
    }
    if let Some(s) = body.target_secs.filter(|s| *s > 0.0) {
        group.target_secs = s;
    }
    if let Some(a) = body.aht_seconds.filter(|a| *a > 0.0) {
        group.aht_secs = a;
    }
    let mut fc = forecast(
        db,
        group_id,
        midnight(from),
        midnight(to + Duration::days(1)),
        interval_minutes,
    )
    .await?;
    for f in &mut fc {
        f.volume *= multiplier;
    }
    let required: Vec<(DateTime<Utc>, u32)> = requirement_for_group(&group, &fc)
        .into_iter()
        .map(|r| (r.start, r.scheduled))
        .collect();
    let shifts: Vec<(DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT start_at::timestamptz, end_at::timestamptz FROM wfm_shift_assignment \
          WHERE schedule_ref = $1 AND activity = 'work' AND start_at IS NOT NULL \
            AND end_at IS NOT NULL AND (is_active IS NULL OR is_active = true)",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let delta = body.headcount_delta.unwrap_or(0).clamp(-1_000, 1_000);
    let live = matches!(group.channel, ChannelKind::Voice | ChannelKind::Chat);
    let step = i64::from(interval_minutes);
    let mut days = Vec::new();
    let (mut under, mut over) = (0, 0);
    let mut day = from;
    while day <= to {
        let requirement = day_requirement(day, interval_minutes, &required);
        let coverage = shift_coverage(&coverage_of(day, interval_minutes, &shifts), delta);
        let (u, o) = gaps(&requirement, &coverage);
        under += u;
        over += o;
        let service_level = coverage
            .iter()
            .enumerate()
            .map(|(i, agents)| {
                if !live {
                    return None;
                }
                let at = midnight(day) + Duration::minutes(step * i as i64);
                let f = fc.iter().find(|f| f.start == at)?;
                let volume = f.volume * (1.0 - f.digital_share.clamp(0.0, 1.0));
                if volume <= 0.0 {
                    return None;
                }
                let aht = group.aht_secs / group.concurrency.max(1.0);
                let traffic = volume * aht / f.interval_secs;
                let on_floor = (f64::from(*agents)
                    * (1.0 - group.shrinkage_pct.clamp(0.0, 99.0) / 100.0))
                    .floor() as u32;
                let sl = crate::staffing::service_level(on_floor, traffic, aht, group.target_secs);
                Some((sl * 1000.0).round() / 10.0)
            })
            .collect();
        days.push(WhatIfDay {
            day,
            requirement,
            coverage,
            under: u,
            over: o,
            service_level,
        });
        day += Duration::days(1);
    }
    Ok(WhatIf {
        schedule_id: id,
        days,
        under,
        over,
    })
}

/// The hiring view's query.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HiringQuery {
    /// Months ahead, from this month (default 6, at most 24).
    pub months: Option<u32>,
}

/// One month of the hiring view.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct HiringMonth {
    /// The first day of the month.
    pub month: NaiveDate,
    /// Full-time people the forecast needs; absent without a forecast.
    pub required_fte: Option<f64>,
    pub headcount: u32,
    /// Required less headcount (positive: hire).
    pub gap: Option<f64>,
}

/// The hiring view.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HiringPlan {
    pub group_id: Uuid,
    pub months: Vec<HiringMonth>,
}

fn add_month(d: NaiveDate) -> NaiveDate {
    let (y, m) = if d.month() == 12 {
        (d.year() + 1, 1)
    } else {
        (d.year(), d.month() + 1)
    };
    NaiveDate::from_ymd_opt(y, m, 1).unwrap_or(d)
}

/// Required FTE per month against current headcount.
pub async fn hiring_plan(
    state: &EngineState,
    group_id: Uuid,
    months: u32,
    today: NaiveDate,
) -> Result<HiringPlan, AppError> {
    let db = &state.base.db;
    let (group, interval_minutes) = group_of(db, group_id).await?;
    let headcount: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT user_ref) FROM wfm_group_member \
          WHERE planning_group_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(group_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let headcount = u32::try_from(headcount).unwrap_or(u32::MAX);
    let mut month = NaiveDate::from_ymd_opt(today.year(), today.month(), 1).unwrap_or(today);
    let mut out = Vec::new();
    for _ in 0..months.clamp(1, MAX_MONTHS) {
        let next = add_month(month);
        let fc = forecast(
            db,
            group_id,
            midnight(month),
            midnight(next),
            interval_minutes,
        )
        .await?;
        let required = if fc.is_empty() {
            None
        } else {
            let hours: f64 = requirement_for_group(&group, &fc)
                .iter()
                .map(|r| f64::from(r.scheduled) * f64::from(interval_minutes) / 60.0)
                .sum();
            Some(fte(hours))
        };
        out.push(HiringMonth {
            month,
            required_fte: required,
            headcount,
            gap: required.map(|r| ((r - f64::from(headcount)) * 10.0).round() / 10.0),
        });
        month = next;
    }
    Ok(HiringPlan {
        group_id,
        months: out,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/workforce/schedules/{id}/what-if",
    operation_id = "post_workforce_what_if",
    tag = "workforce",
    params(("id" = Uuid, Path, description = "The schedule")),
    request_body = WhatIfBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "read-only calculation",
    )))),
    responses(
        (status = 200, description = "Requirement, coverage and service level with the changes", body = WhatIf),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.read", body = ErrorResponse),
        (status = 404, description = "No such schedule", body = ErrorResponse),
        (status = 422, description = "A multiplier out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Tries a schedule with a changed forecast, targets or headcount.
///
/// Recomputes coverage and service level in memory and writes nothing.
async fn post_what_if(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<ScheduleRead>>,
    Path(id): Path<Uuid>,
    Json(body): Json<WhatIfBody>,
) -> Result<Json<WhatIf>, AppError> {
    Ok(Json(what_if(&state, id, &body).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/workforce/groups/{id}/hiring-plan",
    operation_id = "get_workforce_hiring_plan",
    tag = "workforce",
    params(("id" = Uuid, Path, description = "The planning group"), HiringQuery),
    responses(
        (status = 200, description = "Required FTE per month against headcount", body = HiringPlan),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.read", body = ErrorResponse),
        (status = 404, description = "No such planning group", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// The monthly hiring view of a planning group.
///
/// Required full-time people from the stored forecast, beside the
/// current members and the gap.
async fn get_hiring(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<ScheduleRead>>,
    Path(id): Path<Uuid>,
    Query(q): Query<HiringQuery>,
) -> Result<Json<HiringPlan>, AppError> {
    Ok(Json(
        hiring_plan(&state, id, q.months.unwrap_or(6), Utc::now().date_naive()).await?,
    ))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/workforce/schedules/{id}/what-if",
            post(post_what_if),
        )
        .route("/api/v1/workforce/groups/{id}/hiring-plan", get(get_hiring))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_what_if, get_hiring),
    components(schemas(WhatIfBody, WhatIfDay, WhatIf, HiringMonth, HiringPlan))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod what_if_tests {
    use super::*;

    #[test]
    fn headcount_shifts_coverage_but_never_below_zero() {
        assert_eq!(shift_coverage(&[0, 2, 5], 1), vec![1, 3, 6]);
        assert_eq!(shift_coverage(&[0, 2, 5], -3), vec![0, 0, 2]);
    }

    #[test]
    fn gaps_count_under_and_over() {
        assert_eq!(gaps(&[2, 2, 0], &[1, 3, 0]), (1, 1));
    }

    #[test]
    fn hours_become_full_time_people() {
        assert_eq!(fte(1_600.0), 10.0);
        assert_eq!(fte(240.0), 1.5);
    }

    #[test]
    fn months_roll_over_the_year() {
        let d = NaiveDate::from_ymd_opt(2027, 12, 1).expect("a date");
        assert_eq!(
            add_month(d),
            NaiveDate::from_ymd_opt(2028, 1, 1).expect("a date")
        );
    }

    #[test]
    fn more_volume_needs_more_agents() {
        let group = PlanningGroup {
            id: Uuid::nil(),
            channel: ChannelKind::Voice,
            aht_secs: 180.0,
            target_pct: 80.0,
            target_secs: 20.0,
            concurrency: 1.0,
            backlog_hours: 8.0,
            shrinkage_pct: 0.0,
        };
        let f = |v: f64| IntervalForecast {
            start: midnight(NaiveDate::from_ymd_opt(2027, 3, 1).expect("a date")),
            interval_secs: 1800.0,
            volume: v,
            digital_share: 0.0,
        };
        let base = requirement_for_group(&group, &[f(100.0)])[0].scheduled;
        let more = requirement_for_group(&group, &[f(120.0)])[0].scheduled;
        assert!(more > base, "{more} > {base}");
    }
}

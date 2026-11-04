//! G17-T12: a planning group's KPIs over a range of days —
//! `GET /api/v1/workforce/groups/{id}/kpis?from=YYYY-MM-DD&to=YYYY-MM-DD`.
//!
//! - **forecast accuracy**: 1 − |actual − forecast| / forecast over the
//!   range's volume, actuals read as intraday reads them ([`ActualsSource`],
//!   service tickets on the group's channel by default);
//! - **service level against plan**: not measured yet (no answer times are
//!   stored); answered as `null` beside the target;
//! - **occupancy**: the actual workload (volume × handling time ÷
//!   concurrency) over the scheduled working hours;
//! - **shrinkage**: hours scheduled away from work (breaks, leave, training)
//!   over all scheduled hours, beside the group's planned shrinkage;
//! - **adherence**: the members' daily adherence, weighted by minutes;
//! - **coverage**: the share of intervals needing people that the published
//!   schedule staffs to the requirement;
//! - **overtime**: hours of overtime offers taken.
//!
//! Each KPI names the screen holding the records behind it. Reads only,
//! with the schedule read privilege; at most 31 days.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use chrono::{Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::admin::ScheduleRead;
use crate::build_job::{coverage_of, day_requirement};
use crate::intraday::{ActualsSource, TicketActuals};
use crate::staffing::{ChannelKind, IntervalForecast, PlanningGroup, requirement_for_group};

/// Days one KPI request covers at most.
pub const MAX_DAYS: i64 = 31;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct KpiQuery {
    /// The first day of the period, inclusive.
    pub from: NaiveDate,
    /// The last day of the period, inclusive.
    pub to: NaiveDate,
}

/// One KPI.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Kpi {
    pub key: &'static str,
    /// A share as a percentage, or hours for `overtime`; `None` when there
    /// is nothing to measure it on.
    pub value: Option<f64>,
    /// The plan it is held against, when there is one.
    pub target: Option<f64>,
    /// The screen with the records behind it.
    pub drill: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GroupKpis {
    pub group: Uuid,
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub kpis: Vec<Kpi>,
}

/// What the KPIs are computed from.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KpiInputs {
    pub forecast_volume: f64,
    pub actual_volume: f64,
    pub aht_secs: f64,
    pub concurrency: f64,
    pub work_hours: f64,
    pub away_hours: f64,
    pub planned_shrinkage_pct: f64,
    /// (adherence %, minutes) per member and day.
    pub adherence: Vec<(f64, i64)>,
    pub intervals_needed: u32,
    pub intervals_covered: u32,
    pub overtime_hours: f64,
    pub service_level_target_pct: f64,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// The seven KPIs from their inputs. Pure.
pub fn compute(group: Uuid, i: &KpiInputs) -> Vec<Kpi> {
    let drill = |path: &str| format!("/xrm/workforce/{path}?group={group}");
    let accuracy = (i.forecast_volume > 0.0).then(|| {
        round1(
            (1.0 - (i.actual_volume - i.forecast_volume).abs() / i.forecast_volume).max(0.0)
                * 100.0,
        )
    });
    let workload_hours = i.actual_volume * i.aht_secs / 3600.0 / i.concurrency.max(1.0);
    let occupancy = (i.work_hours > 0.0).then(|| round1(workload_hours / i.work_hours * 100.0));
    let scheduled = i.work_hours + i.away_hours;
    let shrinkage = (scheduled > 0.0).then(|| round1(i.away_hours / scheduled * 100.0));
    let minutes: i64 = i.adherence.iter().map(|(_, m)| *m).sum();
    let adherence = (minutes > 0).then(|| {
        round1(
            i.adherence
                .iter()
                .map(|(pct, m)| pct * *m as f64)
                .sum::<f64>()
                / minutes as f64,
        )
    });
    let coverage = (i.intervals_needed > 0)
        .then(|| round1(f64::from(i.intervals_covered) / f64::from(i.intervals_needed) * 100.0));
    vec![
        Kpi {
            key: "forecast_accuracy",
            value: accuracy,
            target: None,
            drill: drill("forecast"),
        },
        Kpi {
            key: "service_level",
            value: None,
            target: Some(i.service_level_target_pct),
            drill: drill("intraday"),
        },
        Kpi {
            key: "occupancy",
            value: occupancy,
            target: None,
            drill: drill("schedule"),
        },
        Kpi {
            key: "shrinkage",
            value: shrinkage,
            target: Some(i.planned_shrinkage_pct),
            drill: drill("schedule"),
        },
        Kpi {
            key: "adherence",
            value: adherence,
            target: None,
            drill: drill("adherence"),
        },
        Kpi {
            key: "coverage",
            value: coverage,
            target: Some(100.0),
            drill: drill("schedule"),
        },
        Kpi {
            key: "overtime",
            value: Some(round1(i.overtime_hours)),
            target: None,
            drill: drill("offers"),
        },
    ]
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

/// Reads the inputs of `group`'s KPIs over `[from, to]`.
pub async fn inputs<A: ActualsSource>(
    state: &EngineState,
    actuals: &A,
    id: Uuid,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<KpiInputs, AppError> {
    let db = &state.base.db;
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
    let (chan, pct, secs, interval, shrink, conc, backlog, aht) = row.ok_or(AppError::NotFound)?;
    let interval_minutes: u32 = interval
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
    let group = PlanningGroup {
        id,
        channel,
        aht_secs: aht.filter(|a| *a > 0.0).unwrap_or(180.0),
        target_pct: pct.unwrap_or(80.0),
        target_secs: secs.unwrap_or(20.0),
        concurrency: conc.filter(|c| *c >= 1.0).unwrap_or(1.0),
        backlog_hours: backlog.unwrap_or(8.0),
        shrinkage_pct: shrink.unwrap_or(0.0),
    };
    let start = from.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    let end = to.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc() + Duration::days(1);

    let forecast_rows: Vec<(chrono::DateTime<Utc>, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT interval_start::timestamptz, volume::float8, digital_share::float8 \
           FROM wfm_forecast_interval \
          WHERE planning_group_ref = $1 AND interval_start::timestamptz >= $2 \
            AND interval_start::timestamptz < $3 AND (is_active IS NULL OR is_active = true) \
          ORDER BY interval_start",
    )
    .bind(id)
    .bind(start)
    .bind(end)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let forecast: Vec<IntervalForecast> = forecast_rows
        .into_iter()
        .map(|(at, volume, digital)| IntervalForecast {
            start: at,
            interval_secs: f64::from(interval_minutes * 60),
            volume: volume.unwrap_or(0.0).max(0.0),
            digital_share: digital.unwrap_or(0.0),
        })
        .collect();
    let forecast_volume: f64 = forecast.iter().map(|f| f.volume).sum();
    let actual_volume = actuals
        .volume(state, channel, start, end.min(Utc::now()))
        .await?;

    // The published schedules' assignments in the range.
    let shifts: Vec<(chrono::DateTime<Utc>, chrono::DateTime<Utc>, Option<String>)> =
        sqlx::query_as(
            "SELECT a.start_at::timestamptz, a.end_at::timestamptz, a.activity::text \
               FROM wfm_shift_assignment a JOIN wfm_schedule s ON s.id = a.schedule_ref \
              WHERE s.planning_group_ref = $1 AND s.status = 'published' \
                AND a.start_at::timestamptz >= $2 AND a.start_at::timestamptz < $3 \
                AND (a.is_active IS NULL OR a.is_active = true) \
                AND (s.is_active IS NULL OR s.is_active = true)",
        )
        .bind(id)
        .bind(start)
        .bind(end)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    let hours = |a: &chrono::DateTime<Utc>, b: &chrono::DateTime<Utc>| {
        (*b - *a).num_minutes().max(0) as f64 / 60.0
    };
    let work_hours: f64 = shifts
        .iter()
        .filter(|s| s.2.as_deref() == Some("work"))
        .map(|s| hours(&s.0, &s.1))
        .sum();
    let away_hours: f64 = shifts
        .iter()
        .filter(|s| s.2.as_deref() != Some("work"))
        .map(|s| hours(&s.0, &s.1))
        .sum();

    // Coverage, day by day, against the forecast's requirement.
    let requirements: Vec<(chrono::DateTime<Utc>, u32)> = requirement_for_group(&group, &forecast)
        .into_iter()
        .map(|r| (r.start, r.scheduled))
        .collect();
    let (mut needed, mut covered) = (0u32, 0u32);
    let mut day = from;
    while day <= to {
        let required = day_requirement(day, interval_minutes, &requirements);
        let worked: Vec<_> = shifts
            .iter()
            .filter(|s| s.2.as_deref() == Some("work") && s.0.date_naive() == day)
            .map(|s| (s.0, s.1))
            .collect();
        let staffed = coverage_of(day, interval_minutes, &worked);
        for (r, c) in required.iter().zip(staffed.iter()) {
            if *r > 0 {
                needed += 1;
                if c >= r {
                    covered += 1;
                }
            }
        }
        day = day.succ_opt().unwrap_or(to + Duration::days(1));
    }

    let adherence: Vec<(f64, i64)> = sqlx::query_as(
        "SELECT d.adherence_pct::float8, d.minutes FROM wfm_adherence_day d \
          WHERE d.day BETWEEN $2 AND $3 AND d.adherence_pct IS NOT NULL \
            AND d.user_id IN (SELECT user_ref FROM wfm_group_member \
                               WHERE planning_group_ref = $1 \
                                 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(id)
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let overtime_hours: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(EXTRACT(EPOCH FROM (end_at::timestamptz - start_at::timestamptz))) \
                         / 3600.0, 0)::float8 \
           FROM wfm_offer WHERE planning_group_ref = $1 AND kind = 'overtime' \
            AND status = 'taken' AND start_at::timestamptz >= $2 AND start_at::timestamptz < $3",
    )
    .bind(id)
    .bind(start)
    .bind(end)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    Ok(KpiInputs {
        forecast_volume,
        actual_volume,
        aht_secs: group.aht_secs,
        concurrency: group.concurrency,
        work_hours,
        away_hours,
        planned_shrinkage_pct: group.shrinkage_pct,
        adherence,
        intervals_needed: needed,
        intervals_covered: covered,
        overtime_hours,
        service_level_target_pct: group.target_pct,
    })
}

/// A planning group's KPIs
///
/// Forecast accuracy, service level against plan, occupancy, shrinkage, adherence, coverage and overtime over at most 31 days, each with the screen holding the records behind it. Reads only.
#[utoipa::path(
    get,
    path = "/api/v1/workforce/groups/{id}/kpis",
    operation_id = "workforce_group_kpis",
    tag = "workforce",
    params(("id" = Uuid, Path, description = "The planning group"), KpiQuery),
    responses(
        (status = 200, description = "Success", body = GroupKpis),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.read", body = ErrorResponse),
        (status = 404, description = "No such planning group", body = ErrorResponse),
        (status = 422, description = "The range is backwards or longer than 31 days", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn group_kpis(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<ScheduleRead>>,
    Path(id): Path<Uuid>,
    Query(q): Query<KpiQuery>,
) -> Result<Json<GroupKpis>, AppError> {
    let days = (q.to - q.from).num_days();
    if !(0..MAX_DAYS).contains(&days) {
        return Err(AppError::Validation(format!(
            "from..to: up to {MAX_DAYS} days, from not after to"
        )));
    }
    let inputs = inputs(&state, &TicketActuals, id, q.from, q.to).await?;
    Ok(Json(GroupKpis {
        group: id,
        from: q.from,
        to: q.to,
        kpis: compute(id, &inputs),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/workforce/groups/{id}/kpis", get(group_kpis))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(group_kpis), components(schemas(GroupKpis, Kpi)))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kpis_from_their_inputs() {
        let inputs = KpiInputs {
            forecast_volume: 100.0,
            actual_volume: 90.0,
            aht_secs: 360.0,
            concurrency: 1.0,
            work_hours: 12.0,
            away_hours: 3.0,
            planned_shrinkage_pct: 25.0,
            adherence: vec![(90.0, 300), (100.0, 100)],
            intervals_needed: 40,
            intervals_covered: 30,
            overtime_hours: 2.5,
            service_level_target_pct: 80.0,
        };
        let kpis = compute(Uuid::nil(), &inputs);
        let value = |key: &str| kpis.iter().find(|k| k.key == key).unwrap().value;
        assert_eq!(kpis.len(), 7);
        assert_eq!(value("forecast_accuracy"), Some(90.0));
        // 90 contacts × 6 minutes = 9 hours over 12 scheduled.
        assert_eq!(value("occupancy"), Some(75.0));
        assert_eq!(value("shrinkage"), Some(20.0));
        assert_eq!(value("adherence"), Some(92.5));
        assert_eq!(value("coverage"), Some(75.0));
        assert_eq!(value("overtime"), Some(2.5));
        assert_eq!(value("service_level"), None);
        assert!(kpis[0].drill.starts_with("/xrm/workforce/forecast?group="));
        let empty = compute(Uuid::nil(), &KpiInputs::default());
        assert!(
            empty
                .iter()
                .filter(|k| k.key != "overtime")
                .all(|k| k.value.is_none())
        );
    }
}

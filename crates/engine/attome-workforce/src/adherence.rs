//! G17-T10: schedule adherence — what people did, minute by minute, against
//! what their published schedule said.
//!
//! **Presence.** J10's presence events do not exist yet, so the minute
//! writer reads presence through the [`PresenceSource`] trait; a deployment
//! plugs a source in when J10 lands, and tests use a fixed one. A presence
//! state counts as working when it is one of [`WORKING_STATES`].
//!
//! **In-memory state (guidelines §5).** [`ScheduleCache`] holds one UTC
//! day's shifts per person on published schedules. Source of truth:
//! `wfm_shift_assignment` joined to its `wfm_schedule`. It is rebuilt from
//! the database when the day changes or when a node starts (cold start
//! reads the day again), holds at most [`MAX_CACHED_PEOPLE`] people, and is
//! never shared between nodes: each node writes the minutes of the people
//! its presence source saw. A schedule edited during the day is picked up
//! at the next rebuild ([`ScheduleCache::refresh`] every
//! [`REFRESH_MINUTES`]).
//!
//! **Minutes.** [`record_minute`] writes one row per person seen
//! (`wfm_adherence_minute`, migration 0289) in one batched
//! `INSERT … ON CONFLICT DO NOTHING`, so two nodes or a retry never double a
//! minute. A minute is in adherence when the person's state matches the
//! scheduled activity, or matches the activity of the previous or next
//! slot within the tolerance (`workforce.adherence_tolerance_minutes`,
//! 3 by default), so a few minutes' drift at a change does not count.
//!
//! **Days.** The nightly [`DAY_JOB`] ([`roll_up_day`]) writes each person's
//! adherence (minutes in adherence over minutes seen) and conformance
//! (minutes working over minutes scheduled to work) for yesterday into
//! `wfm_adherence_day`, and deletes minute rows older than
//! [`MINUTE_RETENTION_DAYS`].
//!
//! **Reading.** `GET /api/v1/workforce/adherence/live?group=` shows a
//! planning group's people over the last [`LIVE_MINUTES`] minutes to a
//! holder of `wfm_adherence.read` who is a member of that group (a
//! supervisor of another team gets 403); `GET /api/v1/workforce/me/adherence`
//! shows the caller's own days.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Duration, DurationRound, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The nightly roll-up job.
pub const DAY_JOB: &str = "wfm_adherence_day";
/// The tolerance setting.
pub const TOLERANCE_SETTING: &str = "workforce.adherence_tolerance_minutes";
/// The default tolerance, in minutes.
pub const DEFAULT_TOLERANCE_MINUTES: i64 = 3;
/// How long minute rows are kept.
pub const MINUTE_RETENTION_DAYS: i64 = 35;
/// Most people one node's cache holds.
pub const MAX_CACHED_PEOPLE: usize = 50_000;
/// How often the cache reads the day's schedule again.
pub const REFRESH_MINUTES: i64 = 15;
/// The window the live view shows.
pub const LIVE_MINUTES: i64 = 5;
/// Presence states that count as working.
pub const WORKING_STATES: [&str; 4] = ["available", "busy", "on_call", "after_call_work"];

/// Where presence comes from (J10, when built).
pub trait PresenceSource: Send + Sync {
    /// Each person's presence state at `at`.
    fn states(&self, at: DateTime<Utc>) -> Vec<(Uuid, String)>;
}

/// One scheduled interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// `work`, `break`, `meal` or `training`.
    pub activity: String,
}

/// The activity scheduled at `at`: the latest-starting interval covering
/// it (a break inside a work shift wins), or `off`. Pure.
pub fn scheduled_at(intervals: &[Interval], at: DateTime<Utc>) -> &str {
    intervals
        .iter()
        .filter(|i| i.start <= at && at < i.end)
        .max_by_key(|i| i.start)
        .map_or("off", |i| i.activity.as_str())
}

/// Whether a presence state fits a scheduled activity. Pure.
pub fn fits(scheduled: &str, actual: &str) -> bool {
    let working = WORKING_STATES.contains(&actual);
    match scheduled {
        "work" => working,
        "training" => actual == "training",
        // A break, a meal or time off is kept by not working.
        _ => !working,
    }
}

/// Whether a minute is in adherence, with `tolerance` either side of a
/// change of scheduled activity. Pure.
pub fn in_adherence(
    intervals: &[Interval],
    minute: DateTime<Utc>,
    actual: &str,
    tolerance: Duration,
) -> bool {
    fits(scheduled_at(intervals, minute), actual)
        || fits(scheduled_at(intervals, minute - tolerance), actual)
        || fits(scheduled_at(intervals, minute + tolerance), actual)
}

/// One UTC day's published shifts per person.
#[derive(Debug, Default)]
pub struct ScheduleCache {
    day: Option<NaiveDate>,
    loaded_at: Option<DateTime<Utc>>,
    by_user: HashMap<Uuid, Vec<Interval>>,
}

impl ScheduleCache {
    /// The person's intervals, after reading the day again when needed.
    pub async fn refresh(&mut self, db: &DbPool, now: DateTime<Utc>) -> Result<(), AppError> {
        let day = now.date_naive();
        let stale = self
            .loaded_at
            .is_none_or(|at| now - at >= Duration::minutes(REFRESH_MINUTES));
        if self.day == Some(day) && !stale {
            return Ok(());
        }
        let from = day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
        let rows: Vec<(Uuid, DateTime<Utc>, DateTime<Utc>, Option<String>)> = sqlx::query_as(
            "SELECT a.user_ref, a.start_at::timestamptz, a.end_at::timestamptz, a.activity::text \
               FROM wfm_shift_assignment a JOIN wfm_schedule s ON s.id = a.schedule_ref \
              WHERE s.status::text = 'published' \
                AND (a.is_active IS NULL OR a.is_active = true) \
                AND a.user_ref IS NOT NULL \
                AND a.start_at < $2 AND a.end_at > $1 \
              ORDER BY a.user_ref, a.start_at",
        )
        .bind(from)
        .bind(from + Duration::days(1))
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let mut by_user: HashMap<Uuid, Vec<Interval>> = HashMap::new();
        for (user, start, end, activity) in rows {
            if by_user.len() >= MAX_CACHED_PEOPLE && !by_user.contains_key(&user) {
                tracing::warn!(cap = MAX_CACHED_PEOPLE, "adherence schedule cache is full");
                continue;
            }
            by_user.entry(user).or_default().push(Interval {
                start,
                end,
                activity: activity.unwrap_or_else(|| "work".to_owned()),
            });
        }
        self.day = Some(day);
        self.loaded_at = Some(now);
        self.by_user = by_user;
        Ok(())
    }

    pub fn intervals(&self, user: Uuid) -> &[Interval] {
        self.by_user.get(&user).map_or(&[], Vec::as_slice)
    }
}

fn tolerance(state: &EngineState) -> Duration {
    let minutes = attome_core::setting_registry()
        .get(TOLERANCE_SETTING)
        .and_then(|d| state.settings.load().resolve(d, None, None).0.as_i64())
        .unwrap_or(DEFAULT_TOLERANCE_MINUTES)
        .clamp(0, 30);
    Duration::minutes(minutes)
}

/// Writes the minute `at` falls in for everyone the source saw; the rows
/// written.
pub async fn record_minute(
    state: &EngineState,
    cache: &mut ScheduleCache,
    source: &dyn PresenceSource,
    at: DateTime<Utc>,
) -> Result<u64, AppError> {
    let minute = at.duration_trunc(Duration::minutes(1)).unwrap_or(at);
    cache.refresh(&state.base.db, minute).await?;
    let tolerance = tolerance(state);
    let seen = source.states(minute);
    if seen.is_empty() {
        return Ok(0);
    }
    let mut users = Vec::with_capacity(seen.len());
    let mut scheduled = Vec::with_capacity(seen.len());
    let mut actual = Vec::with_capacity(seen.len());
    let mut fitting = Vec::with_capacity(seen.len());
    for (user, state_now) in seen {
        let intervals = cache.intervals(user);
        users.push(user);
        scheduled.push(scheduled_at(intervals, minute).to_owned());
        fitting.push(in_adherence(intervals, minute, &state_now, tolerance));
        actual.push(state_now);
    }
    let written = sqlx::query(
        "INSERT INTO wfm_adherence_minute (user_id, minute, scheduled, actual, in_adherence) \
         SELECT u, $1, s, a, f FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::bool[]) \
             AS t(u, s, a, f) \
         ON CONFLICT (user_id, minute) DO NOTHING",
    )
    .bind(minute)
    .bind(&users)
    .bind(&scheduled)
    .bind(&actual)
    .bind(&fitting)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(written)
}

/// Writes `day`'s adherence and conformance per person, and drops minute
/// rows past retention; the people written.
pub async fn roll_up_day(db: &DbPool, day: NaiveDate) -> Result<u64, AppError> {
    let from = day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    let working: Vec<&str> = WORKING_STATES.to_vec();
    let written = sqlx::query(
        "INSERT INTO wfm_adherence_day (user_id, day, adherence_pct, conformance_pct, minutes) \
         SELECT user_id, $1, \
                round(100.0 * count(*) FILTER (WHERE in_adherence) / count(*), 2), \
                CASE WHEN count(*) FILTER (WHERE scheduled = 'work') = 0 THEN NULL \
                     ELSE round(100.0 * count(*) FILTER (WHERE actual = ANY($4)) \
                                / count(*) FILTER (WHERE scheduled = 'work'), 2) END, \
                count(*) \
           FROM wfm_adherence_minute WHERE minute >= $2 AND minute < $3 \
          GROUP BY user_id \
         ON CONFLICT (user_id, day) DO UPDATE \
            SET adherence_pct = EXCLUDED.adherence_pct, \
                conformance_pct = EXCLUDED.conformance_pct, minutes = EXCLUDED.minutes",
    )
    .bind(day)
    .bind(from)
    .bind(from + Duration::days(1))
    .bind(&working)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    sqlx::query("DELETE FROM wfm_adherence_minute WHERE minute < $1")
        .bind(from - Duration::days(MINUTE_RETENTION_DAYS))
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(written)
}

// ── Reading ──────────────────────────────────────────────────────────────────

/// `wfm_adherence.read`: supervisors watching their teams.
#[derive(Debug)]
pub struct AdherenceRead;

impl PrivilegeKey for AdherenceRead {
    const KEY: &'static str = "wfm_adherence.read";
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LiveQuery {
    /// The planning group.
    pub group: Uuid,
}

/// One person's latest minute.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct LiveRow {
    pub user_id: Uuid,
    pub minute: DateTime<Utc>,
    pub scheduled: String,
    pub actual: String,
    pub in_adherence: bool,
}

/// One person's day.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct DayRow {
    pub day: NaiveDate,
    pub adherence_pct: Option<f64>,
    pub conformance_pct: Option<f64>,
    pub minutes: i64,
}

/// A group's people now; the caller must be a member of the group.
pub async fn live(
    state: &EngineState,
    ctx: &SecurityContext,
    group: Uuid,
    now: DateTime<Utc>,
) -> Result<Vec<LiveRow>, AppError> {
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM wfm_group_member WHERE planning_group_ref = $1 \
            AND user_ref = $2 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(group)
    .bind(ctx.user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !member && !ctx.is_admin {
        return Err(AppError::Forbidden);
    }
    sqlx::query_as(
        "SELECT DISTINCT ON (m.user_id) m.user_id, m.minute, m.scheduled, m.actual, m.in_adherence \
           FROM wfm_adherence_minute m \
           JOIN wfm_group_member g ON g.user_ref = m.user_id AND g.planning_group_ref = $1 \
                AND (g.is_active IS NULL OR g.is_active = true) \
          WHERE m.minute >= $2 \
          ORDER BY m.user_id, m.minute DESC",
    )
    .bind(group)
    .bind(now - Duration::minutes(LIVE_MINUTES))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The caller's own last 31 days.
pub async fn my_days(state: &EngineState, user: Uuid) -> Result<Vec<DayRow>, AppError> {
    sqlx::query_as(
        "SELECT day, adherence_pct::float8 AS adherence_pct, \
                conformance_pct::float8 AS conformance_pct, minutes \
           FROM wfm_adherence_day WHERE user_id = $1 AND day >= CURRENT_DATE - 31 \
          ORDER BY day DESC",
    )
    .bind(user)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// A planning group's adherence now
///
/// Each member's latest minute in the last five minutes: what was
/// scheduled, what they were doing and whether that fits. For a holder of
/// `wfm_adherence.read` who is a member of the group.
#[utoipa::path(
    get,
    path = "/api/v1/workforce/adherence/live",
    operation_id = "workforce_adherence_live",
    tag = "workforce",
    params(LiveQuery),
    responses(
        (status = 200, description = "The group's people now", body = [LiveRow]),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_adherence.read or is not in the group", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_live(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<AdherenceRead>>,
    Query(q): Query<LiveQuery>,
) -> Result<Json<Vec<LiveRow>>, AppError> {
    live(&state, &ctx, q.group, Utc::now()).await.map(Json)
}

/// My adherence
///
/// The caller's own adherence and conformance for the last 31 days.
#[utoipa::path(
    get,
    path = "/api/v1/workforce/me/adherence",
    operation_id = "workforce_my_adherence",
    tag = "workforce",
    responses(
        (status = 200, description = "The caller's days, newest first", body = [DayRow]),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_mine(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<Vec<DayRow>>, AppError> {
    my_days(&state, ctx.user_id).await.map(Json)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/workforce/adherence/live", get(get_live))
        .route("/api/v1/workforce/me/adherence", get(get_mine))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_live, get_mine), components(schemas(LiveRow, DayRow)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(h: u32, m: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(2026, 10, 26)
            .and_then(|d| d.and_hms_opt(h, m, 0))
            .unwrap()
            .and_utc()
    }

    fn shift() -> Vec<Interval> {
        vec![
            Interval {
                start: at(9, 0),
                end: at(17, 0),
                activity: "work".into(),
            },
            Interval {
                start: at(12, 0),
                end: at(12, 30),
                activity: "break".into(),
            },
        ]
    }

    #[test]
    fn adherence_break_inside_a_shift_wins() {
        assert_eq!(scheduled_at(&shift(), at(10, 0)), "work");
        assert_eq!(scheduled_at(&shift(), at(12, 10)), "break");
        assert_eq!(scheduled_at(&shift(), at(18, 0)), "off");
    }

    #[test]
    fn adherence_tolerance_at_a_change() {
        let tol = Duration::minutes(3);
        // Two minutes late back from the break: still in adherence.
        assert!(in_adherence(&shift(), at(12, 32), "away", tol));
        // Ten minutes late: out.
        assert!(!in_adherence(&shift(), at(12, 40), "away", tol));
        // Working on schedule.
        assert!(in_adherence(&shift(), at(10, 0), "available", tol));
        // Logged in after hours is not adherence to time off.
        assert!(!in_adherence(&shift(), at(20, 0), "available", tol));
    }
}

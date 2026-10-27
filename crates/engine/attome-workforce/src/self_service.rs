//! G17-T8: staff self-service.
//!
//! - `GET /api/v1/workforce/me/schedule?from&to`: the caller's own shifts on
//!   published schedules, nobody else's.
//! - `PUT /api/v1/workforce/me/preferences`: replaces the caller's own
//!   preferences (weekday, preferred start, day off).
//! - `POST /api/v1/workforce/swaps`: gives one of the caller's shifts to a
//!   colleague in the same planning group. When the colleague's week still
//!   passes their rules ([`crate::admin::person_breaches`]) and they are not
//!   already working then (which would drop coverage), the swap is approved
//!   and applied at once, guarded on the shift's row version; otherwise it
//!   waits (`requested`) for a planner.
//! - `POST /api/v1/workforce/swaps/{id}/decide` (`wfm_swap_request.update`):
//!   a planner approves (applying it) or rejects a waiting swap.
//! - `GET /api/v1/workforce/coverage-impact?user_id&from&to`
//!   (`wfm_schedule.read`): the intervals that would fall below requirement
//!   if the person were away, for a leave approval to show
//!   ([`leave_coverage_impact`]).
//!
//! Swaps and decisions are audited in their transaction.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post, put},
};
use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::admin::{AssignmentView, ScheduleRead, breach_message, event, notify, person_breaches};
use crate::build_job::coverage_of;

/// `wfm_swap_request.update`: who decides swaps.
#[derive(Debug)]
pub struct SwapDecide;

impl PrivilegeKey for SwapDecide {
    const KEY: &'static str = "wfm_swap_request.update";
}

/// Most days one self-service read covers.
const MAX_DAYS: i64 = 62;
/// Most preferences one person keeps.
const MAX_PREFERENCES: usize = 14;

fn range(from: NaiveDate, to: NaiveDate) -> Result<(DateTime<Utc>, DateTime<Utc>), AppError> {
    if to < from || (to - from).num_days() >= MAX_DAYS {
        return Err(AppError::Validation(format!(
            "from/to: forwards and at most {MAX_DAYS} days"
        )));
    }
    let at = |d: NaiveDate| d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    Ok((at(from), at(to + Duration::days(1))))
}

/// Whether two shifts overlap. Pure.
pub fn overlaps(a: (DateTime<Utc>, DateTime<Utc>), b: (DateTime<Utc>, DateTime<Utc>)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

/// Whether a swap may approve itself: the colleague's rules hold and they
/// do not already work any of the shift's time. Pure.
pub fn auto_approves(rule_breaches: usize, overlapping_shifts: usize) -> bool {
    rule_breaches == 0 && overlapping_shifts == 0
}

// ── My schedule and preferences ─────────────────────────────────────────

/// A period.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct Period {
    /// From this time (inclusive).
    pub from: NaiveDate,
    /// Up to this time (exclusive).
    pub to: NaiveDate,
}

async fn my_schedule(
    db: &attome_db::DbPool,
    user: Uuid,
    period: &Period,
) -> Result<Vec<AssignmentView>, AppError> {
    let (from, to) = range(period.from, period.to)?;
    sqlx::query_as(
        "SELECT a.id, a.user_ref AS user_id, a.start_at::timestamptz AS start_at, \
                a.end_at::timestamptz AS end_at, a.activity::text AS activity, a.booking_id, \
                a.row_version \
           FROM wfm_shift_assignment a JOIN wfm_schedule s ON s.id = a.schedule_ref \
          WHERE a.user_ref = $1 AND s.status = 'published' \
            AND a.start_at::timestamptz < $3 AND a.end_at::timestamptz > $2 \
            AND (a.is_active IS NULL OR a.is_active = true) ORDER BY a.start_at",
    )
    .bind(user)
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// One preference.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct Preference {
    /// 0 Monday to 6 Sunday.
    pub weekday: u8,
    /// `HH:MM`.
    pub preferred_start: Option<String>,
    #[serde(default)]
    pub day_off: bool,
}

/// The caller's preferences, replacing what was there.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PreferencesBody {
    pub preferences: Vec<Preference>,
}

async fn set_preferences(
    state: &EngineState,
    ctx: &SecurityContext,
    body: &PreferencesBody,
) -> Result<Vec<Preference>, AppError> {
    if body.preferences.len() > MAX_PREFERENCES {
        return Err(AppError::Validation(format!(
            "preferences: at most {MAX_PREFERENCES}"
        )));
    }
    for (i, p) in body.preferences.iter().enumerate() {
        if p.weekday > 6 {
            return Err(AppError::Validation(format!(
                "preferences[{i}].weekday: 0 to 6"
            )));
        }
        if let Some(s) = &p.preferred_start
            && crate::build_job::parse_hhmm(s).is_none()
        {
            return Err(AppError::Validation(format!(
                "preferences[{i}].preferred_start: HH:MM"
            )));
        }
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("DELETE FROM wfm_preference WHERE user_ref = $1")
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for p in &body.preferences {
        sqlx::query(
            "INSERT INTO wfm_preference (id, user_ref, weekday, preferred_start, day_off, \
                 created_by, owner_ref) VALUES ($1, $2, $3, $4, $5, $2, $2)",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.user_id)
        .bind(i64::from(p.weekday))
        .bind(p.preferred_start.as_deref().map(str::trim))
        .bind(p.day_off)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    event(
        &mut tx,
        state,
        "wfm_preference",
        ctx.user_id,
        "workforce.preferences_set",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(body.preferences.clone())
}

// ── Swaps ───────────────────────────────────────────────────────────────

/// A swap or give-away.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SwapBody {
    /// One of the caller's shifts.
    pub assignment_id: Uuid,
    /// The colleague who takes it.
    pub to_user_id: Uuid,
    pub reason: Option<String>,
}

/// The swap's state.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SwapResult {
    pub swap_id: Uuid,
    /// `approved` (applied) or `requested` (waiting for a planner).
    pub status: String,
    /// Why it waits, when it does.
    pub waiting_because: Option<String>,
}

/// `(user, schedule, group, start, end, row version, schedule status)`.
type ShiftRow = (
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    i64,
    Option<String>,
);

async fn shift_row(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<ShiftRow, AppError> {
    sqlx::query_as(
        "SELECT a.user_ref, a.schedule_ref, s.planning_group_ref, a.start_at::timestamptz, \
                a.end_at::timestamptz, a.row_version, s.status::text \
           FROM wfm_shift_assignment a JOIN wfm_schedule s ON s.id = a.schedule_ref \
          WHERE a.id = $1 AND (a.is_active IS NULL OR a.is_active = true) FOR NO KEY UPDATE OF a",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

/// Gives the shift to `to`, guarded on its row version; moves its booking.
async fn apply_swap(
    tx: &mut attome_db::Tx<'_>,
    assignment: Uuid,
    expected_version: i64,
    to: Uuid,
) -> Result<(), AppError> {
    let booking: Option<Option<String>> = sqlx::query_scalar(
        "UPDATE wfm_shift_assignment SET user_ref = $3, modified_at = now(), \
             row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 RETURNING booking_id",
    )
    .bind(assignment)
    .bind(expected_version)
    .bind(to)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some(booking) = booking else {
        return Err(AppError::VersionConflict);
    };
    if let Some(b) = booking.as_deref().and_then(|b| Uuid::parse_str(b).ok()) {
        sqlx::query(
            "UPDATE resource_allocation SET user_id = $2, modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1",
        )
        .bind(b)
        .bind(to)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

async fn request_swap(
    state: &EngineState,
    ctx: &SecurityContext,
    body: &SwapBody,
) -> Result<SwapResult, AppError> {
    let db = &state.base.db;
    if body.to_user_id == ctx.user_id {
        return Err(AppError::Validation("to_user_id: a colleague".into()));
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let (owner, schedule, group, start, end, version, status) =
        shift_row(&mut tx, body.assignment_id).await?;
    if owner != Some(ctx.user_id) {
        // Someone else's shift is not the caller's to give.
        return Err(AppError::NotFound);
    }
    if !matches!(status.as_deref(), Some("published" | "draft")) {
        return Err(AppError::Conflict("this shift's schedule is superseded"));
    }
    let (Some(start), Some(end)) = (start, end) else {
        return Err(AppError::Validation("the shift has no times".into()));
    };
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM wfm_group_member WHERE planning_group_ref = $1 \
            AND user_ref = $2 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(group)
    .bind(body.to_user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !member {
        return Err(AppError::Validation(
            "to_user_id: not a member of this planning group".into(),
        ));
    }
    let breaches = person_breaches(
        &mut tx,
        schedule,
        group,
        body.to_user_id,
        body.assignment_id,
        start,
        end,
    )
    .await?;
    let theirs: Vec<(DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT start_at::timestamptz, end_at::timestamptz FROM wfm_shift_assignment \
          WHERE schedule_ref = $1 AND user_ref = $2 AND activity = 'work' \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(schedule)
    .bind(body.to_user_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let overlapping = theirs
        .iter()
        .filter(|s| overlaps(**s, (start, end)))
        .count();
    let approve = auto_approves(breaches.len(), overlapping);
    let waiting = if approve {
        None
    } else if !breaches.is_empty() {
        Some(breach_message(&breaches))
    } else {
        Some("the colleague already works then, so coverage would drop".to_owned())
    };
    if approve {
        apply_swap(&mut tx, body.assignment_id, version, body.to_user_id).await?;
    }
    let swap: Uuid = sqlx::query_scalar(
        "INSERT INTO wfm_swap_request (id, from_assignment_ref, to_user_ref, status, reason, \
             created_by, owner_ref) VALUES ($1, $2, $3, $4, $5, $6, $6) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(body.assignment_id)
    .bind(body.to_user_id)
    .bind(if approve { "approved" } else { "requested" })
    .bind(body.reason.as_deref().map(str::trim))
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    event(
        &mut tx,
        state,
        "wfm_swap_request",
        swap,
        "workforce.swap_requested",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    if approve {
        notify(
            state,
            body.to_user_id,
            "A shift is now yours",
            &format!("A colleague gave you their shift {start} to {end}."),
        )
        .await;
    }
    Ok(SwapResult {
        swap_id: swap,
        status: if approve { "approved" } else { "requested" }.to_owned(),
        waiting_because: waiting,
    })
}

/// A planner's decision. Named apart from the approval engine's
/// `DecideBody` in the OpenAPI document, where one name is one schema.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = WorkforceSwapDecideBody)]
pub struct DecideBody {
    pub approve: bool,
    pub reason: Option<String>,
}

async fn decide(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    body: &DecideBody,
) -> Result<SwapResult, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(Option<Uuid>, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT from_assignment_ref, to_user_ref, status::text FROM wfm_swap_request \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR NO KEY UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(assignment), Some(to), status)) = row else {
        return Err(AppError::NotFound);
    };
    if !matches!(status.as_deref(), Some("requested" | "accepted")) {
        return Err(AppError::Conflict("this swap was already decided"));
    }
    if body.approve {
        let (_, _, _, _, _, version, _) = shift_row(&mut tx, assignment).await?;
        apply_swap(&mut tx, assignment, version, to).await?;
    }
    let to_status = if body.approve { "approved" } else { "rejected" };
    sqlx::query(
        "UPDATE wfm_swap_request SET status = $2, decided_by = $3, \
             reason = COALESCE($4, reason), modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(to_status)
    .bind(ctx.user_id)
    .bind(body.reason.as_deref().map(str::trim))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    event(
        &mut tx,
        state,
        "wfm_swap_request",
        id,
        "workforce.swap_decided",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(SwapResult {
        swap_id: id,
        status: to_status.to_owned(),
        waiting_because: None,
    })
}

// ── Leave coverage impact ───────────────────────────────────────────────

/// One interval that would fall short.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DroppedInterval {
    pub start: DateTime<Utc>,
    pub requirement: u32,
    /// Coverage without the person.
    pub coverage_without: u32,
}

/// What a person's absence does to coverage.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CoverageImpact {
    pub user_id: Uuid,
    pub shifts_affected: usize,
    pub dropped: Vec<DroppedInterval>,
}

/// The intervals of `day` where coverage without the person's shifts falls
/// below requirement, inside their shifts. Pure.
pub fn dropped_intervals(
    day: NaiveDate,
    interval_minutes: u32,
    requirement: &[u32],
    all_shifts: &[(DateTime<Utc>, DateTime<Utc>)],
    their_shifts: &[(DateTime<Utc>, DateTime<Utc>)],
) -> Vec<DroppedInterval> {
    let with = coverage_of(day, interval_minutes, all_shifts);
    let theirs = coverage_of(day, interval_minutes, their_shifts);
    let midnight = day.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc();
    with.iter()
        .zip(&theirs)
        .zip(requirement)
        .enumerate()
        .filter_map(|(i, ((w, t), need))| {
            let without = w.saturating_sub(*t);
            (*t > 0 && without < *need).then(|| DroppedInterval {
                start: midnight + Duration::minutes(i64::from(interval_minutes) * i as i64),
                requirement: *need,
                coverage_without: without,
            })
        })
        .collect()
}

/// G17-T8: the coverage a person's leave from `from` to `to` would drop, on
/// published schedules, for a leave approval step to show.
pub async fn leave_coverage_impact(
    state: &EngineState,
    user: Uuid,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<CoverageImpact, AppError> {
    let db = &state.base.db;
    let (from_at, to_at) = range(from, to)?;
    let mine: Vec<(Uuid, Uuid, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT a.schedule_ref, s.planning_group_ref, a.start_at::timestamptz, a.end_at::timestamptz \
           FROM wfm_shift_assignment a JOIN wfm_schedule s ON s.id = a.schedule_ref \
          WHERE a.user_ref = $1 AND s.status = 'published' AND a.activity = 'work' \
            AND a.start_at::timestamptz < $3 AND a.end_at::timestamptz > $2 \
            AND s.planning_group_ref IS NOT NULL AND (a.is_active IS NULL OR a.is_active = true)",
    )
    .bind(user)
    .bind(from_at)
    .bind(to_at)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut dropped = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (schedule, _group, start, _) in &mine {
        let day = start.date_naive();
        if !seen.insert((*schedule, day)) {
            continue;
        }
        let impact =
            crate::what_if::what_if(state, *schedule, &crate::what_if::WhatIfBody::default())
                .await?;
        let Some(today) = impact.days.iter().find(|d| d.day == day) else {
            continue;
        };
        let all: Vec<(DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT start_at::timestamptz, end_at::timestamptz FROM wfm_shift_assignment \
              WHERE schedule_ref = $1 AND activity = 'work' AND start_at::date = $2 \
                AND (is_active IS NULL OR is_active = true)",
        )
        .bind(schedule)
        .bind(day)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let theirs: Vec<(DateTime<Utc>, DateTime<Utc>)> = mine
            .iter()
            .filter(|(s, _, st, _)| s == schedule && st.date_naive() == day)
            .map(|(_, _, s, e)| (*s, *e))
            .collect();
        let slots = today.requirement.len().max(1);
        let interval_minutes = u32::try_from((24 * 60) / slots).unwrap_or(30);
        dropped.extend(dropped_intervals(
            day,
            interval_minutes,
            &today.requirement,
            &all,
            &theirs,
        ));
    }
    Ok(CoverageImpact {
        user_id: user,
        shifts_affected: mine.len(),
        dropped,
    })
}

// ── Routes ──────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/workforce/me/schedule",
    operation_id = "get_workforce_my_schedule",
    tag = "workforce",
    params(Period),
    responses(
        (status = 200, description = "The caller's own published shifts", body = Vec<AssignmentView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "A backwards or too long period", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// The caller's own schedule.
///
/// Only their own shifts on published schedules, in a period of at most
/// two months.
async fn get_my_schedule(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(period): Query<Period>,
) -> Result<Json<Vec<AssignmentView>>, AppError> {
    Ok(Json(
        my_schedule(&state.base.db, ctx.user_id, &period).await?,
    ))
}

#[utoipa::path(
    put,
    path = "/api/v1/workforce/me/preferences",
    operation_id = "put_workforce_my_preferences",
    tag = "workforce",
    request_body = PreferencesBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The caller's preferences now", body = Vec<Preference>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "A weekday or start out of range, or too many", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Replaces the caller's own shift preferences.
///
/// Weekday, preferred start and day off; only the caller's own rows change.
async fn put_my_preferences(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<PreferencesBody>,
) -> Result<Json<Vec<Preference>>, AppError> {
    Ok(Json(set_preferences(&state, &ctx, &body).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/workforce/swaps",
    operation_id = "post_workforce_swap",
    tag = "workforce",
    request_body = SwapBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Approved and applied, or waiting for a planner", body = SwapResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Not one of the caller's shifts", body = ErrorResponse),
        (status = 409, description = "The shift changed meanwhile, or its schedule is superseded", body = ErrorResponse),
        (status = 422, description = "The colleague is not in the group, or is the caller", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Gives one of the caller's shifts to a colleague.
///
/// Approved at once when the colleague's rules hold and coverage stays,
/// otherwise left for a planner.
async fn post_swap(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<SwapBody>,
) -> Result<Json<SwapResult>, AppError> {
    Ok(Json(request_swap(&state, &ctx, &body).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/workforce/swaps/{id}/decide",
    operation_id = "post_workforce_swap_decide",
    tag = "workforce",
    params(("id" = Uuid, Path, description = "The swap request")),
    request_body = DecideBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Decided", body = SwapResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_swap_request.update", body = ErrorResponse),
        (status = 404, description = "No such swap", body = ErrorResponse),
        (status = 409, description = "Already decided, or the shift changed meanwhile", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Decides a waiting swap.
///
/// Approving gives the shift to the colleague; rejecting leaves it.
async fn post_decide(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<SwapDecide>>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecideBody>,
) -> Result<Json<SwapResult>, AppError> {
    Ok(Json(decide(&state, &ctx, id, &body).await?))
}

/// Whose absence, and when.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ImpactQuery {
    /// Only this user.
    pub user_id: Uuid,
    /// From this time (inclusive).
    pub from: NaiveDate,
    /// Up to this time (exclusive).
    pub to: NaiveDate,
}

#[utoipa::path(
    get,
    path = "/api/v1/workforce/coverage-impact",
    operation_id = "get_workforce_coverage_impact",
    tag = "workforce",
    params(ImpactQuery),
    responses(
        (status = 200, description = "The intervals that would fall short", body = CoverageImpact),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.read", body = ErrorResponse),
        (status = 422, description = "A backwards or too long period", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// What a person's absence would do to coverage.
///
/// For a leave approval: the intervals of their published shifts that
/// would fall below requirement without them.
async fn get_impact(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<ScheduleRead>>,
    Query(q): Query<ImpactQuery>,
) -> Result<Json<CoverageImpact>, AppError> {
    Ok(Json(
        leave_coverage_impact(&state, q.user_id, q.from, q.to).await?,
    ))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/workforce/me/schedule", get(get_my_schedule))
        .route("/api/v1/workforce/me/preferences", put(put_my_preferences))
        .route("/api/v1/workforce/swaps", post(post_swap))
        .route("/api/v1/workforce/swaps/{id}/decide", post(post_decide))
        .route("/api/v1/workforce/coverage-impact", get(get_impact))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_my_schedule,
        put_my_preferences,
        post_swap,
        post_decide,
        get_impact
    ),
    components(schemas(
        Preference,
        PreferencesBody,
        SwapBody,
        SwapResult,
        DecideBody,
        DroppedInterval,
        CoverageImpact
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod self_service_tests {
    use super::*;

    fn at(h: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(2027, 3, 1)
            .and_then(|d| d.and_hms_opt(h, 0, 0))
            .expect("a time")
            .and_utc()
    }

    #[test]
    fn a_swap_approves_itself_only_when_rules_and_coverage_hold() {
        assert!(auto_approves(0, 0));
        assert!(!auto_approves(1, 0), "a rule breach waits");
        assert!(!auto_approves(0, 1), "already working then: coverage drops");
    }

    #[test]
    fn overlapping_shifts_are_found() {
        assert!(overlaps((at(8), at(16)), (at(15), at(20))));
        assert!(!overlaps((at(8), at(16)), (at(16), at(20))), "back to back");
    }

    #[test]
    fn leave_drops_only_the_short_intervals_inside_the_shift() {
        let day = NaiveDate::from_ymd_opt(2027, 3, 1).expect("a date");
        let mut req = vec![0; 24];
        for slot in req.iter_mut().take(12).skip(8) {
            *slot = 2;
        }
        let all = [(at(8), at(12)), (at(8), at(12)), (at(10), at(12))];
        let theirs = [(at(8), at(12))];
        let dropped = dropped_intervals(day, 60, &req, &all, &theirs);
        let hours: Vec<u32> = dropped
            .iter()
            .map(|d| chrono::Timelike::hour(&d.start))
            .collect();
        assert_eq!(hours, vec![8, 9], "10:00-12:00 still has two");
        assert!(dropped.iter().all(|d| d.coverage_without == 1));
    }

    #[test]
    fn periods_run_forwards_and_stay_short() {
        let d = |m, day| NaiveDate::from_ymd_opt(2027, m, day).expect("a date");
        assert!(range(d(3, 1), d(3, 31)).is_ok());
        assert!(range(d(3, 2), d(3, 1)).is_err());
        assert!(range(d(1, 1), d(6, 1)).is_err());
    }
}

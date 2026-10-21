//! G17-T7: schedule routes.
//!
//! - `POST /api/v1/workforce/groups/{id}/schedules/build` queues a build
//!   ([`crate::build_job`]) and answers `202` with its run id.
//! - `GET /api/v1/workforce/schedules?group_id=` lists schedules (one-based
//!   pages); `GET /api/v1/workforce/schedules/{id}` answers one with its
//!   assignments and coverage.
//! - `PATCH /api/v1/workforce/assignments/{id}` (`If-Match: "<row_version>"`)
//!   moves an assignment or gives it to someone else; the person's week is
//!   checked against their rule set ([`crate::rules::check`]) and a breach
//!   is a `422` naming its codes. An assignment of a published schedule
//!   needs a `reason`, and the person is told.
//! - `POST /api/v1/workforce/schedules/{id}/publish`
//!   (`If-Match: "<row_version>"` of the schedule) publishes a draft in one
//!   transaction under its row lock: a stale version is `409
//!   version_conflict`; every work assignment becomes a booking on the
//!   person's time (`resource_allocation`, regarding the assignment, its id
//!   kept in `booking_id`), the group's earlier published schedule for an
//!   overlapping period becomes `superseded`, and each person is told after
//!   commit.
//!
//! The week a rule check reads starts on the working week's first day of a
//! Sunday-to-Thursday calendar (the deployment's calendars are not yet
//! linked to planning groups); a member with no rule set is not checked.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{get, patch, post},
};
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc, Weekday};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::rules::{RuleBreach, RuleSet, Shift, WeekContext};

/// `wfm_schedule.create`: who builds.
#[derive(Debug)]
pub struct ScheduleCreate;

impl PrivilegeKey for ScheduleCreate {
    const KEY: &'static str = "wfm_schedule.create";
}

/// `wfm_schedule.read`: who reads schedules.
#[derive(Debug)]
pub struct ScheduleRead;

impl PrivilegeKey for ScheduleRead {
    const KEY: &'static str = "wfm_schedule.read";
}

/// `wfm_schedule.update`: who edits and publishes.
#[derive(Debug)]
pub struct ScheduleUpdate;

impl PrivilegeKey for ScheduleUpdate {
    const KEY: &'static str = "wfm_schedule.update";
}

pub(crate) fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

async fn installed(db: &attome_db::DbPool) -> Result<(), AppError> {
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'wfm_schedule' \
            AND column_name = 'build_run_id')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if ready {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

// ── Build ────────────────────────────────────────────────────────────────

/// What to build.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BuildBody {
    pub from: NaiveDate,
    pub to: NaiveDate,
    /// Seconds the solver may take (default 300).
    pub deadline_secs: Option<u64>,
}

/// The queued build.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BuildQueued {
    pub run_id: Uuid,
}

async fn start_build(
    state: &EngineState,
    ctx: &SecurityContext,
    group: Uuid,
    body: &BuildBody,
) -> Result<BuildQueued, AppError> {
    let db = &state.base.db;
    installed(db).await?;
    attome_records::entity_crud::read_record(state, ctx, "wfm_planning_group", group).await?;
    let job = crate::build_job::BuildJob {
        run_id: Uuid::now_v7(),
        group_id: group,
        from: body.from,
        to: body.to,
        requested_by: ctx.user_id,
        deadline_secs: body.deadline_secs.map(|d| d.clamp(1, 3_600)),
    };
    let mut tx = attome_db::tx::begin(db).await?;
    crate::build_job::enqueue(&mut tx, &job).await?;
    event(
        &mut tx,
        state,
        "wfm_planning_group",
        group,
        "workforce.build_queued",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(BuildQueued { run_id: job.run_id })
}

pub(crate) async fn event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    entity: &str,
    id: Uuid,
    what: &str,
    user: Uuid,
) -> Result<(), AppError> {
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            entity,
            id,
            attome_audit::AuditOperation::Update,
            what,
            user,
        ),
    )
    .await
    .map(|_| ())
}

// ── Read ─────────────────────────────────────────────────────────────────

/// One schedule in a list.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ScheduleSummary {
    pub id: Uuid,
    pub planning_group_id: Option<Uuid>,
    pub period_from: Option<NaiveDate>,
    pub period_to: Option<NaiveDate>,
    pub status: Option<String>,
    pub row_version: i64,
}

/// One assignment.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AssignmentView {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub start_at: Option<DateTime<Utc>>,
    pub end_at: Option<DateTime<Utc>>,
    pub activity: Option<String>,
    pub booking_id: Option<String>,
    pub row_version: i64,
}

/// A schedule with its assignments and coverage.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScheduleDetail {
    #[serde(flatten)]
    pub schedule: ScheduleSummary,
    pub assignments: Vec<AssignmentView>,
    /// The build's coverage per day (requirement, before, after).
    #[schema(value_type = Object)]
    pub coverage: Value,
}

/// The list filter.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ScheduleFilter {
    /// Only this planning group's schedules.
    pub group_id: Option<Uuid>,
}

const SUMMARY: &str = "SELECT id, planning_group_ref AS planning_group_id, period_from::date AS period_from, \
     period_to::date AS period_to, status::text AS status, row_version FROM wfm_schedule";

async fn list(
    db: &attome_db::DbPool,
    filter: &ScheduleFilter,
    page: &OnePageQuery,
) -> Result<PaginatedResponse<ScheduleSummary>, AppError> {
    installed(db).await?;
    let window = page.window();
    let items: Vec<ScheduleSummary> = sqlx::query_as(&format!(
        "{SUMMARY} WHERE (is_active IS NULL OR is_active = true) \
           AND ($1::uuid IS NULL OR planning_group_ref = $1) \
         ORDER BY period_from DESC NULLS LAST, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(filter.group_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM wfm_schedule WHERE (is_active IS NULL OR is_active = true) \
           AND ($1::uuid IS NULL OR planning_group_ref = $1)",
    )
    .bind(filter.group_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

async fn detail(db: &attome_db::DbPool, id: Uuid) -> Result<ScheduleDetail, AppError> {
    installed(db).await?;
    let schedule: ScheduleSummary = sqlx::query_as(&format!(
        "{SUMMARY} WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let coverage: Option<String> =
        sqlx::query_scalar("SELECT coverage_json FROM wfm_schedule WHERE id = $1")
            .bind(id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let assignments: Vec<AssignmentView> = sqlx::query_as(
        "SELECT id, user_ref AS user_id, start_at::timestamptz AS start_at, \
                end_at::timestamptz AS end_at, activity::text AS activity, booking_id, row_version \
           FROM wfm_shift_assignment \
          WHERE schedule_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY start_at, user_ref",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(ScheduleDetail {
        schedule,
        assignments,
        coverage: coverage
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or(Value::Null),
    })
}

// ── Edit ─────────────────────────────────────────────────────────────────

/// An assignment change.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignmentPatch {
    pub start_at: Option<DateTime<Utc>>,
    pub end_at: Option<DateTime<Utc>>,
    /// Give the shift to this person.
    pub user_id: Option<Uuid>,
    /// Required once the schedule is published; sent to the person.
    pub reason: Option<String>,
}

/// The first day of the rule week holding `day`, for a Sunday-to-Thursday
/// working week (starts Sunday). Pure.
pub fn week_of(day: NaiveDate, week_start: Weekday) -> (NaiveDate, NaiveDate) {
    let back = (7 + day.weekday().num_days_from_monday() - week_start.num_days_from_monday()) % 7;
    let start = day - Duration::days(i64::from(back));
    (start, start + Duration::days(6))
}

/// A rule set row with the limits the pack does not store at their
/// defaults: nights are 22:00 to 06:00 and a week has one day off. Pure.
pub fn rule_set(
    max_day: Option<f64>,
    max_week: Option<f64>,
    min_rest: Option<f64>,
    max_nights: Option<f64>,
    ramadan_day: Option<f64>,
) -> RuleSet {
    RuleSet {
        max_hours_day: max_day.unwrap_or(12.0),
        max_hours_week: max_week.unwrap_or(48.0),
        min_rest_hours: min_rest.unwrap_or(11.0),
        max_nights_week: max_nights.map_or(7, |n| n.max(0.0) as u32),
        night_from_hour: 22,
        night_to_hour: 6,
        min_days_off_week: 1,
        ramadan_max_hours_day: ramadan_day.unwrap_or(6.0),
    }
}

/// The breach codes as one message. Pure.
pub fn breach_message(breaches: &[RuleBreach]) -> String {
    let mut codes: Vec<&str> = breaches.iter().map(|b| b.code).collect();
    codes.sort_unstable();
    codes.dedup();
    format!("rule_breach: {}", codes.join(", "))
}

/// `(max day, max week, min rest, max nights, Ramadan day)`.
type RuleRow = (
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
);

/// `(row version, status, group, from, to)`.
type PublishRow = (
    i64,
    Option<String>,
    Option<Uuid>,
    Option<NaiveDate>,
    Option<NaiveDate>,
);

type AssignmentRow = (
    Option<Uuid>,
    Option<Uuid>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    i64,
    Option<String>,
    Option<Uuid>,
);

/// Every rule a person's week breaks once they work `start`..`end` (as
/// shift `id`) in `schedule`, read against their group membership's rule
/// set; none when they have no rule set.
pub(crate) async fn person_breaches(
    tx: &mut attome_db::Tx<'_>,
    schedule: Option<Uuid>,
    group: Option<Uuid>,
    user: Uuid,
    id: Uuid,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<RuleBreach>, AppError> {
    let rules: Option<RuleRow> = sqlx::query_as(
        "SELECT r.max_hours_day::float8, r.max_hours_week::float8, r.min_rest_hours::float8,                 r.max_nights_week::float8, r.ramadan_max_hours_day::float8            FROM wfm_group_member m JOIN wfm_rule_set r ON r.id = m.rule_set_ref           WHERE m.planning_group_ref = $1 AND m.user_ref = $2             AND (m.is_active IS NULL OR m.is_active = true) LIMIT 1",
    )
    .bind(group)
    .bind(user)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((day, week, rest, nights, ramadan)) = rules else {
        return Ok(Vec::new());
    };
    let (from, to) = week_of(start.date_naive(), Weekday::Sun);
    let others: Vec<(Uuid, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, start_at::timestamptz, end_at::timestamptz FROM wfm_shift_assignment           WHERE schedule_ref = $1 AND user_ref = $2 AND id <> $3 AND activity = 'work'             AND start_at::date BETWEEN $4 AND $5 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(schedule)
    .bind(user)
    .bind(id)
    .bind(from)
    .bind(to)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let mut week_shifts: Vec<Shift> = others
        .into_iter()
        .map(|(sid, s, e)| Shift {
            id: sid,
            start: s.naive_utc(),
            end: e.naive_utc(),
        })
        .collect();
    week_shifts.push(Shift {
        id,
        start: start.naive_utc(),
        end: end.naive_utc(),
    });
    let working: HashSet<Weekday> = [
        Weekday::Sun,
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
    ]
    .into_iter()
    .collect();
    let calendar = attome_calendar::BusinessCalendar::simple(
        chrono_tz::UTC,
        working,
        attome_calendar::TimeRange::new(8 * 60, 17 * 60),
    )
    .map_err(AppError::internal)?;
    Ok(crate::rules::check(
        &week_shifts,
        &rule_set(day, week, rest, nights, ramadan),
        &WeekContext {
            calendar: &calendar,
            ramadan: None,
            ramadan_pattern: false,
        },
    ))
}

async fn edit_assignment(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    expected: i64,
    body: &AssignmentPatch,
) -> Result<AssignmentView, AppError> {
    let db = &state.base.db;
    installed(db).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<AssignmentRow> = sqlx::query_as(
        "SELECT a.schedule_ref, a.user_ref, a.start_at::timestamptz, a.end_at::timestamptz, \
                a.row_version, s.status::text, s.planning_group_ref \
           FROM wfm_shift_assignment a JOIN wfm_schedule s ON s.id = a.schedule_ref \
          WHERE a.id = $1 AND (a.is_active IS NULL OR a.is_active = true) FOR NO KEY UPDATE OF a",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((schedule, user, start, end, version, status, group)) = row else {
        return Err(AppError::NotFound);
    };
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    let published = status.as_deref() == Some("published");
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    if published && reason.is_none() {
        return Err(AppError::Validation(
            "reason: a published shift changes only with a reason the person is told".into(),
        ));
    }
    if status.as_deref() == Some("superseded") {
        return Err(AppError::Conflict("a superseded schedule is not edited"));
    }
    let user = body
        .user_id
        .or(user)
        .ok_or_else(|| AppError::Validation("user_id: required".into()))?;
    let start = body
        .start_at
        .or(start)
        .ok_or_else(|| AppError::Validation("start_at: required".into()))?;
    let end = body
        .end_at
        .or(end)
        .ok_or_else(|| AppError::Validation("end_at: required".into()))?;
    if end <= start {
        return Err(AppError::Validation("end_at: after start_at".into()));
    }

    // The person's week against their rule set.
    let breaches = person_breaches(&mut tx, schedule, group, user, id, start, end).await?;
    if !breaches.is_empty() {
        return Err(AppError::Validation(breach_message(&breaches)));
    }

    let view: AssignmentView = sqlx::query_as(
        "UPDATE wfm_shift_assignment SET user_ref = $2, start_at = $3, end_at = $4, \
             modified_at = now(), modified_by = $5, row_version = row_version + 1 \
          WHERE id = $1 \
          RETURNING id, user_ref AS user_id, start_at::timestamptz AS start_at, \
                    end_at::timestamptz AS end_at, activity::text AS activity, booking_id, row_version",
    )
    .bind(id)
    .bind(user)
    .bind(start)
    .bind(end)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if published
        && let Some(booking) = view
            .booking_id
            .as_deref()
            .and_then(|b| Uuid::parse_str(b).ok())
    {
        sqlx::query(
            "UPDATE resource_allocation SET user_id = $2, start_date = $3, end_date = $4, \
                 modified_at = now(), row_version = row_version + 1 WHERE id = $1",
        )
        .bind(booking)
        .bind(user)
        .bind(start)
        .bind(end)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    event(
        &mut tx,
        state,
        "wfm_shift_assignment",
        id,
        "workforce.assignment_changed",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    if let Some(reason) = reason.filter(|_| published) {
        notify(
            state,
            user,
            "Your shift changed",
            &format!("Your shift is now {start} to {end}. Reason: {reason}"),
        )
        .await;
    }
    Ok(view)
}

pub(crate) async fn notify(state: &EngineState, user: Uuid, subject: &str, body: &str) {
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: Some(user),
        is_global: false,
        organization_ref: None,
        channels: None,
        subject: Some(subject.to_owned()),
        body_html: None,
        body_text: Some(body.to_owned()),
        route: Some("/workforce/my-schedule".to_owned()),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await
    {
        tracing::warn!(%user, %error, "workforce: notice not sent");
    }
}

// ── Publish ──────────────────────────────────────────────────────────────

/// The published schedule.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Published {
    pub schedule_id: Uuid,
    pub bookings: u64,
    pub superseded: u64,
    pub row_version: i64,
}

async fn publish(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    expected: i64,
) -> Result<Published, AppError> {
    let db = &state.base.db;
    installed(db).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    let row: Option<PublishRow> = sqlx::query_as(
        "SELECT row_version, status::text, planning_group_ref, period_from::date, period_to::date \
               FROM wfm_schedule WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
               FOR NO KEY UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((version, status, group, from, to)) = row else {
        return Err(AppError::NotFound);
    };
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    if status.as_deref() != Some("draft") {
        return Err(AppError::Conflict("only a draft schedule is published"));
    }
    // Every work assignment becomes a booking on the person's time.
    let assignments: Vec<(Uuid, Uuid, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, user_ref, start_at::timestamptz, end_at::timestamptz FROM wfm_shift_assignment \
          WHERE schedule_ref = $1 AND activity = 'work' AND user_ref IS NOT NULL \
            AND start_at IS NOT NULL AND end_at IS NOT NULL AND booking_id IS NULL \
            AND (is_active IS NULL OR is_active = true) FOR NO KEY UPDATE",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut people = HashSet::new();
    for (assignment, user, start, end) in &assignments {
        let booking: Uuid = sqlx::query_scalar(
            "INSERT INTO resource_allocation (id, user_id, regarding_entity, regarding_id, \
                 allocation_percent, start_date, end_date, created_by, owner_ref) \
             VALUES ($1, $2, 'wfm_shift_assignment', $3, 100, $4, $5, $6, $6) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(user)
        .bind(assignment.to_string())
        .bind(start)
        .bind(end)
        .bind(ctx.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "UPDATE wfm_shift_assignment SET booking_id = $2, row_version = row_version + 1 \
              WHERE id = $1",
        )
        .bind(assignment)
        .bind(booking.to_string())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        people.insert(*user);
    }
    let superseded = sqlx::query(
        "UPDATE wfm_schedule SET status = 'superseded', modified_at = now(), \
             row_version = row_version + 1 \
          WHERE planning_group_ref = $1 AND id <> $2 AND status = 'published' \
            AND period_from::date <= $4 AND period_to::date >= $3",
    )
    .bind(group)
    .bind(id)
    .bind(from)
    .bind(to)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    let new_version: i64 = sqlx::query_scalar(
        "UPDATE wfm_schedule SET status = 'published', modified_at = now(), modified_by = $2, \
             row_version = row_version + 1 WHERE id = $1 RETURNING row_version",
    )
    .bind(id)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    event(
        &mut tx,
        state,
        "wfm_schedule",
        id,
        "workforce.schedule_published",
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    for person in people {
        notify(
            state,
            person,
            "Your schedule is published",
            "Your new schedule is ready to view.",
        )
        .await;
    }
    Ok(Published {
        schedule_id: id,
        bookings: assignments.len() as u64,
        superseded,
        row_version: new_version,
    })
}

// ── Routes ───────────────────────────────────────────────────────────────

fn x_audit() -> Value {
    json!(attome_audit::security::x_audit(&[(
        attome_audit::AuditCategory::BusinessEvent,
        attome_audit::AuditOperation::Update
    )]))
}

#[utoipa::path(
    post,
    path = "/api/v1/workforce/groups/{id}/schedules/build",
    operation_id = "post_workforce_schedule_build",
    tag = "workforce",
    params(("id" = Uuid, Path, description = "The planning group")),
    request_body = BuildBody,
    extensions(("x-audit" = x_audit())),
    responses(
        (status = 202, description = "The build is queued", body = BuildQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.create", body = ErrorResponse),
        (status = 404, description = "No such planning group, or builds are not installed", body = ErrorResponse),
        (status = 422, description = "A backwards or too long period", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Queues a schedule build for a planning group.
///
/// The build runs as a job and writes one draft schedule with coverage;
/// read it by the schedules list once it finishes.
async fn post_build(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ScheduleCreate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<BuildBody>,
) -> Result<(StatusCode, Json<BuildQueued>), AppError> {
    Ok((
        StatusCode::ACCEPTED,
        Json(start_build(&state, &ctx, id, &body).await?),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/workforce/schedules",
    operation_id = "list_workforce_schedules",
    tag = "workforce",
    params(ScheduleFilter, OnePageQuery),
    responses(
        (status = 200, description = "Schedules, newest period first", body = PaginatedResponse<ScheduleSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.read", body = ErrorResponse),
        (status = 404, description = "Builds are not installed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Lists schedules.
///
/// One-based pages, optionally for one planning group.
async fn get_list(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<ScheduleRead>>,
    Query(filter): Query<ScheduleFilter>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ScheduleSummary>>, AppError> {
    Ok(Json(list(&state.base.db, &filter, &page).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/workforce/schedules/{id}",
    operation_id = "get_workforce_schedule",
    tag = "workforce",
    params(("id" = Uuid, Path, description = "The schedule")),
    responses(
        (status = 200, description = "The schedule with assignments and coverage", body = ScheduleDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.read", body = ErrorResponse),
        (status = 404, description = "No such schedule", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Reads a schedule.
///
/// With its assignments and the build's coverage per day.
async fn get_detail(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<ScheduleRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ScheduleDetail>, AppError> {
    Ok(Json(detail(&state.base.db, id).await?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/workforce/assignments/{id}",
    operation_id = "patch_workforce_assignment",
    tag = "workforce",
    params(
        ("id" = Uuid, Path, description = "The assignment"),
        ("If-Match" = String, Header, description = "The assignment's row_version"),
    ),
    request_body = AssignmentPatch,
    extensions(("x-audit" = x_audit())),
    responses(
        (status = 200, description = "Changed", body = AssignmentView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.update", body = ErrorResponse),
        (status = 404, description = "No such assignment", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or a superseded schedule", body = ErrorResponse),
        (status = 422, description = "A rule breach (its codes), no If-Match, or no reason on a published shift", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Changes one assignment.
///
/// The person's week is checked against their rule set; a published shift
/// needs a reason, which the person is told.
async fn patch_assignment(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ScheduleUpdate>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<AssignmentPatch>,
) -> Result<Json<AssignmentView>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        edit_assignment(&state, &ctx, id, expected, &body).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/workforce/schedules/{id}/publish",
    operation_id = "post_workforce_schedule_publish",
    tag = "workforce",
    params(
        ("id" = Uuid, Path, description = "The draft schedule"),
        ("If-Match" = String, Header, description = "The schedule's row_version"),
    ),
    extensions(("x-audit" = x_audit())),
    responses(
        (status = 200, description = "Published", body = Published),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks wfm_schedule.update", body = ErrorResponse),
        (status = 404, description = "No such schedule", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or not a draft", body = ErrorResponse),
        (status = 422, description = "No If-Match", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Publishes a draft schedule.
///
/// Each shift becomes a booking on the person's time, an overlapping
/// published schedule is superseded, and everyone scheduled is told.
async fn post_publish(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ScheduleUpdate>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Published>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(publish(&state, &ctx, id, expected).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/workforce/groups/{id}/schedules/build",
            post(post_build),
        )
        .route("/api/v1/workforce/schedules", get(get_list))
        .route("/api/v1/workforce/schedules/{id}", get(get_detail))
        .route(
            "/api/v1/workforce/schedules/{id}/publish",
            post(post_publish),
        )
        .route(
            "/api/v1/workforce/assignments/{id}",
            patch(patch_assignment),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_build, get_list, get_detail, patch_assignment, post_publish),
    components(schemas(
        BuildBody,
        BuildQueued,
        ScheduleSummary,
        AssignmentView,
        ScheduleDetail,
        AssignmentPatch,
        Published
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod schedule_routes {
    use super::*;

    fn day(m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2027, m, d).expect("a real date")
    }

    #[test]
    fn the_rule_week_starts_on_sunday() {
        // 2027-03-03 is a Wednesday.
        assert_eq!(week_of(day(3, 3), Weekday::Sun), (day(2, 28), day(3, 6)));
        assert_eq!(week_of(day(2, 28), Weekday::Sun), (day(2, 28), day(3, 6)));
        assert_eq!(week_of(day(3, 6), Weekday::Sun).0, day(2, 28));
    }

    #[test]
    fn unset_limits_take_their_defaults() {
        let r = rule_set(Some(9.0), None, None, Some(2.0), None);
        assert_eq!(r.max_hours_day, 9.0);
        assert_eq!(r.max_hours_week, 48.0);
        assert_eq!(r.max_nights_week, 2);
        assert_eq!(
            (r.night_from_hour, r.night_to_hour, r.min_days_off_week),
            (22, 6, 1)
        );
    }

    #[test]
    fn breaches_are_named_once_each() {
        let b = |code| RuleBreach {
            code,
            shift_ids: Vec::new(),
        };
        assert_eq!(
            breach_message(&[b("max_week"), b("max_day"), b("max_day")]),
            "rule_breach: max_day, max_week"
        );
    }
}

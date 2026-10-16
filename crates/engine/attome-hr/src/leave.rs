//! Leave (roadmap W6-T2): submitting a leave request counts its working
//! days on the deployment's default business calendar (holidays excluded;
//! Friday and Saturday off when no calendar is set), checks the employee's
//! balance for that leave type and year, and opens an approval regarding the
//! request ([`ACTION_LEAVE_DECIDE`]). The approval moves the request to
//! `approved` and the days from `remaining` to `taken`; a rejection moves it
//! to `rejected`. [`availability`] answers which days a user is away on
//! approved leave, for scheduling and routing.

use std::collections::{BTreeSet, HashSet};

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::{Datelike, NaiveDate, Weekday};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The approval that decides a leave request.
pub const ACTION_LEAVE_DECIDE: &str = "hr.leave_decide";

/// Longest leave one request covers, in calendar days.
pub const MAX_LEAVE_SPAN_DAYS: i64 = 366;

/// `leave_request.update`: may submit a leave request.
#[derive(Debug)]
pub struct LeaveUpdate;

impl PrivilegeKey for LeaveUpdate {
    const KEY: &'static str = "leave_request.update";
}

/// `employee.read`: may read people's availability.
#[derive(Debug)]
pub struct EmployeeRead;

impl PrivilegeKey for EmployeeRead {
    const KEY: &'static str = "employee.read";
}

/// The working days between two dates, both included.
pub fn leave_days(
    start: NaiveDate,
    end: NaiveDate,
    working: &HashSet<Weekday>,
    holidays: &BTreeSet<NaiveDate>,
) -> u32 {
    if end < start {
        return 0;
    }
    start
        .iter_days()
        .take_while(|d| *d <= end)
        .filter(|d| working.contains(&d.weekday()) && !holidays.contains(d))
        .count() as u32
}

/// Sunday to Thursday, when no calendar is configured.
fn default_working_days() -> HashSet<Weekday> {
    [
        Weekday::Sun,
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
    ]
    .into_iter()
    .collect()
}

/// The deployment's working days and holidays.
pub async fn working_calendar(
    db: &attome_db::DbPool,
) -> Result<(HashSet<Weekday>, BTreeSet<NaiveDate>), AppError> {
    if let Some(id) = attome_core::calendar::default_calendar_id(db).await?
        && let Ok(loaded) = attome_core::calendar::load_calendar(db, id).await?
    {
        return Ok((
            loaded.calendar.working_days().clone(),
            loaded.calendar.holidays().clone(),
        ));
    }
    Ok((default_working_days(), BTreeSet::new()))
}

type RequestRow = (
    Option<Uuid>,
    Option<String>,
    Option<NaiveDate>,
    Option<NaiveDate>,
    Option<String>,
);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct HrLeaveSubmitted {
    pub leave_request_id: Uuid,
    pub days: u32,
    pub approval_request_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/hr/leave-requests/{id}/submit",
    tag = "hr",
    params(("id" = Uuid, Path, description = "The leave request")),
    responses(
        (status = 202, description = "In manager review; an approval regarding the request is open", body = HrLeaveSubmitted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this request", body = ErrorResponse),
        (status = 404, description = "No such leave request", body = ErrorResponse),
        (status = 409, description = "The request is not in `requested`", body = ErrorResponse),
        (status = 422, description = "Dates missing or reversed, no working day in the span, or not enough balance", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_hr_leave_submit(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<LeaveUpdate>>,
    Path(request): Path<Uuid>,
) -> Result<(StatusCode, Json<HrLeaveSubmitted>), AppError> {
    let entity = state
        .entities
        .load()
        .get("leave_request")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        &state,
        &ctx,
        entity,
        "leave_request",
        request,
        RecordAction::Update,
    )
    .await?;
    let db = &state.base.db;
    let row: Option<RequestRow> = sqlx::query_as(
        "SELECT employee_ref, leave_type, start_date::date, end_date::date, status \
         FROM leave_request WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(request)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((employee, kind, Some(start), Some(end), status)) = row else {
        return Err(AppError::Validation(
            "the request needs an employee, a start and an end date".into(),
        ));
    };
    if status.as_deref().is_some_and(|s| s != "requested") {
        return Err(AppError::Conflict(
            "only a requested leave can be submitted",
        ));
    }
    if end < start || (end - start).num_days() > MAX_LEAVE_SPAN_DAYS {
        return Err(AppError::Validation(format!(
            "the end date is before the start, or the span is over {MAX_LEAVE_SPAN_DAYS} days"
        )));
    }
    let (working, holidays) = working_calendar(db).await?;
    let days = leave_days(start, end, &working, &holidays);
    if days == 0 {
        return Err(AppError::Validation(
            "no working day falls in the span".into(),
        ));
    }
    // The balance of the request's leave type, matched by name, for its year.
    let remaining: Option<Option<String>> = sqlx::query_scalar(
        "SELECT b.remaining::text FROM leave_balance b \
         JOIN leave_type t ON t.id = b.leave_type_ref \
         WHERE b.employee_ref = $1 AND lower(t.name) = lower($2) AND b.year = $3 \
           AND (b.is_active IS NULL OR b.is_active = true) LIMIT 1",
    )
    .bind(employee)
    .bind(kind.as_deref().unwrap_or("annual"))
    .bind(start.year())
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some(Some(remaining)) = remaining
        && let Ok(remaining) = remaining.parse::<Decimal>()
        && remaining < Decimal::from(days)
    {
        return Err(AppError::Validation(format!(
            "not enough balance: {days} working days asked, {remaining} remaining"
        )));
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let moved = sqlx::query(
        "UPDATE leave_request SET status = 'manager_review', modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND (status IS NULL OR status = 'requested')",
    )
    .bind(request)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "only a requested leave can be submitted",
        ));
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "leave_request",
            request,
            AuditOperation::Update,
            "hr.leave_submitted",
            ctx.user_id,
        )
        .comment(format!("{days} working days")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    let approval = match attome_audit::approval::gate_regarding_required(
        &state,
        ACTION_LEAVE_DECIDE,
        serde_json::json!({ "leave_request_id": request, "days": days }),
        ctx.user_id,
        Some(("leave_request", request)),
    )
    .await
    {
        Ok(approval) => approval,
        Err(e) => {
            // Back to requested, so a resubmit works.
            let _ = sqlx::query(
                "UPDATE leave_request SET status = 'requested' WHERE id = $1 AND status = 'manager_review'",
            )
            .bind(request)
            .execute(db)
            .await
            .map_err(|err| tracing::error!(%request, error = %err, "leave: could not reset a request whose approval failed"));
            return Err(e);
        }
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(HrLeaveSubmitted {
            leave_request_id: request,
            days,
            approval_request_id: approval.id,
        }),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct HrLeaveDecided {
    pub leave_request_id: Uuid,
    pub status: String,
}

/// The approved request: `approved`, and its days moved from remaining to
/// taken. Called by the approval executor.
pub async fn do_approve_leave(
    state: &EngineState,
    request: Uuid,
    days: u32,
    approver: Uuid,
) -> Result<HrLeaveDecided, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(Option<Uuid>, Option<String>, Option<NaiveDate>)> = sqlx::query_as(
        "UPDATE leave_request SET status = 'approved', modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND status = 'manager_review' \
         RETURNING employee_ref, leave_type, start_date::date",
    )
    .bind(request)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((employee, kind, start)) = row else {
        return Err(AppError::Conflict("the leave request is not in review"));
    };
    if let Some(start) = start {
        sqlx::query(
            "UPDATE leave_balance b SET taken = COALESCE(b.taken, 0) + $4, \
                 remaining = COALESCE(b.remaining, b.entitled, 0) - $4, \
                 modified_at = now(), row_version = b.row_version + 1 \
             FROM leave_type t \
             WHERE t.id = b.leave_type_ref AND b.employee_ref = $1 \
               AND lower(t.name) = lower($2) AND b.year = $3 \
               AND (b.is_active IS NULL OR b.is_active = true)",
        )
        .bind(employee)
        .bind(kind.as_deref().unwrap_or("annual"))
        .bind(start.year())
        .bind(i64::from(days))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "leave_request",
            request,
            AuditOperation::Update,
            "hr.leave_approved",
            approver,
        )
        .comment(format!("{days} working days")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(HrLeaveDecided {
        leave_request_id: request,
        status: "approved".into(),
    })
}

/// A rejected leave request becomes `rejected`. A no-op for any other
/// approval.
pub async fn settle_rejected(
    state: &EngineState,
    approval: &attome_approval::ApprovalRequest,
    decider: Uuid,
) {
    if approval.action_type != ACTION_LEAVE_DECIDE {
        return;
    }
    let Some(request) = approval
        .payload
        .get("leave_request_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    else {
        return;
    };
    let result = async {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        sqlx::query(
            "UPDATE leave_request SET status = 'rejected', modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1 AND status = 'manager_review'",
        )
        .bind(request)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_audit::write_business_event_in_tx(
            &mut tx,
            &attome_audit::audit_service(state),
            attome_audit::BusinessEvent::new(
                "leave_request",
                request,
                AuditOperation::Update,
                "hr.leave_rejected",
                decider,
            ),
        )
        .await?;
        attome_db::tx::commit(tx).await
    }
    .await;
    if let Err(e) = result {
        tracing::error!(%request, error = %e, "leave: a rejected request could not be marked rejected");
    }
}

/// The days `user` is away on approved leave between two dates.
pub async fn availability(
    db: &attome_db::DbPool,
    user: Uuid,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<NaiveDate>, AppError> {
    let spans: Vec<(NaiveDate, NaiveDate)> = sqlx::query_as(
        "SELECT r.start_date::date, r.end_date::date FROM leave_request r \
         JOIN employee e ON e.id = r.employee_ref \
         WHERE e.user_ref = $1 AND r.status IN ('approved', 'taken') \
           AND r.start_date::date <= $3 AND r.end_date::date >= $2 \
           AND (r.is_active IS NULL OR r.is_active = true)",
    )
    .bind(user)
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut away: BTreeSet<NaiveDate> = BTreeSet::new();
    for (start, end) in spans {
        for day in start.iter_days().take_while(|d| *d <= end) {
            if day >= from && day <= to {
                away.insert(day);
            }
        }
    }
    Ok(away.into_iter().collect())
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AvailabilityQuery {
    pub user_id: Uuid,
    pub from: NaiveDate,
    pub to: NaiveDate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct HrAvailability {
    pub user_id: Uuid,
    /// The days the user is away on approved leave.
    pub away: Vec<NaiveDate>,
}

#[utoipa::path(
    get,
    path = "/api/v1/hr/availability",
    tag = "hr",
    params(AvailabilityQuery),
    responses(
        (status = 200, description = "The days the user is away on approved leave", body = HrAvailability),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks employee.read", body = ErrorResponse),
        (status = 422, description = "The range is reversed or over a year", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_hr_availability(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<EmployeeRead>>,
    Query(q): Query<AvailabilityQuery>,
) -> Result<Json<HrAvailability>, AppError> {
    if q.to < q.from || (q.to - q.from).num_days() > MAX_LEAVE_SPAN_DAYS {
        return Err(AppError::Validation(
            "to is before from, or the range is over a year".into(),
        ));
    }
    Ok(Json(HrAvailability {
        user_id: q.user_id,
        away: availability(&state.base.db, q.user_id, q.from, q.to).await?,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_hr_leave_submit, get_hr_availability),
    components(schemas(HrLeaveSubmitted, HrLeaveDecided, HrAvailability))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn d(m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, m, day).unwrap_or_default()
    }

    #[test]
    fn leave_counts_working_days_without_holidays() {
        let working = default_working_days();
        // Sun 1 Nov 2026 to Sat 7 Nov: Sunday to Thursday are five days.
        assert_eq!(
            leave_days(d(11, 1), d(11, 7), &working, &BTreeSet::new()),
            5
        );
        let holidays: BTreeSet<NaiveDate> = [d(11, 3)].into_iter().collect();
        assert_eq!(leave_days(d(11, 1), d(11, 7), &working, &holidays), 4);
        // A weekend alone has no working day; a reversed span none either.
        assert_eq!(
            leave_days(d(11, 6), d(11, 7), &working, &BTreeSet::new()),
            0
        );
        assert_eq!(
            leave_days(d(11, 7), d(11, 1), &working, &BTreeSet::new()),
            0
        );
    }
}

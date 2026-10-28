//! Revenue and quantity schedules (roadmap D6-T6).
//!
//! `POST /api/v1/sales/opportunity-lines/{line_id}/schedule` replaces a
//! line's schedule in one transaction: spread evenly over a number of
//! months, by a percentage pattern (which must total 100), or row by row
//! (which must total the line). Amounts are rounded once per row and the
//! rounding remainder goes to the last row, so a schedule always adds up to
//! its line exactly.
//!
//! `POST /api/v1/sales/opportunities/{id}/schedules/shift` moves every row
//! of a deal by whole months. It is called only after the user agrees to
//! move the schedule with a new close date, never automatically; a deal
//! with more than [`INLINE_SHIFT_LIMIT`] rows is shifted by a job.
//! Periods are Gregorian dates; Hijri display is the interface's.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use chrono::{Months, NaiveDate};
use rust_decimal::{Decimal, RoundingStrategy};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::split_store::OpportunityUpdate;

/// Rows shifted in the request; more go to a job.
pub const INLINE_SHIFT_LIMIT: i64 = 500;

/// Longest schedule, in months.
pub const MAX_MONTHS: u32 = 240;

/// One schedule row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ScheduleRow {
    pub period_start: NaiveDate,
    #[schema(value_type = String)]
    pub revenue: Decimal,
    #[schema(value_type = Option<String>)]
    pub quantity: Option<Decimal>,
}

fn round(value: Decimal) -> Decimal {
    value.round_dp_with_strategy(2, RoundingStrategy::MidpointAwayFromZero)
}

fn month(start: NaiveDate, n: u32) -> Result<NaiveDate, AppError> {
    start.checked_add_months(Months::new(n)).ok_or_else(|| {
        AppError::Validation("the schedule runs past the last supported date".into())
    })
}

/// Splits `total` by `shares` (fractions summing to one), rounded once per
/// row, the remainder on the last row.
fn spread(total: Decimal, shares: &[Decimal]) -> Vec<Decimal> {
    let mut out: Vec<Decimal> = shares.iter().map(|s| round(total * s)).collect();
    let sum: Decimal = out.iter().sum();
    if let Some(last) = out.last_mut() {
        *last += round(total) - sum;
    }
    out
}

/// The rows of an even or pattern schedule.
pub fn planned_rows(
    start: NaiveDate,
    revenue: Decimal,
    quantity: Option<Decimal>,
    months: u32,
    pattern: Option<&[Decimal]>,
) -> Result<Vec<ScheduleRow>, AppError> {
    let shares: Vec<Decimal> = match pattern {
        Some(pattern) => {
            if pattern.is_empty() || pattern.len() > MAX_MONTHS as usize {
                return Err(AppError::Validation(format!(
                    "pattern: 1 to {MAX_MONTHS} percentages"
                )));
            }
            if pattern.iter().any(|p| p.is_sign_negative()) {
                return Err(AppError::Validation(
                    "pattern percentages are not negative".into(),
                ));
            }
            let sum: Decimal = pattern.iter().sum();
            if sum != Decimal::ONE_HUNDRED {
                return Err(AppError::Validation(format!(
                    "pattern totals {sum}%, not 100%"
                )));
            }
            pattern.iter().map(|p| p / Decimal::ONE_HUNDRED).collect()
        }
        None => {
            if months == 0 || months > MAX_MONTHS {
                return Err(AppError::Validation(format!("months: 1 to {MAX_MONTHS}")));
            }
            let each = Decimal::ONE / Decimal::from(months);
            (0..months).map(|_| each).collect()
        }
    };
    let revenues = spread(revenue, &shares);
    let quantities = quantity.map(|q| spread(q, &shares));
    revenues
        .into_iter()
        .enumerate()
        .map(|(i, rev)| {
            Ok(ScheduleRow {
                period_start: month(start, i as u32)?,
                revenue: rev,
                quantity: quantities.as_ref().map(|q| q[i]),
            })
        })
        .collect()
}

/// Checks hand-entered rows add up to the line.
pub fn check_manual(rows: &[ScheduleRow], line_total: Decimal) -> Result<(), AppError> {
    if rows.is_empty() || rows.len() > MAX_MONTHS as usize {
        return Err(AppError::Validation(format!("rows: 1 to {MAX_MONTHS}")));
    }
    let sum: Decimal = rows.iter().map(|r| r.revenue).sum();
    if round(sum) != round(line_total) {
        return Err(AppError::Validation(format!(
            "the rows total {sum}, not the line total {line_total}"
        )));
    }
    Ok(())
}

async fn require(
    state: &EngineState,
    ctx: &SecurityContext,
    opportunity: Uuid,
) -> Result<(), AppError> {
    crate::flags::require(state, ctx, crate::flags::SCHEDULES).await?;
    let entity = state
        .entities
        .load()
        .get("opportunity")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        entity,
        "opportunity",
        opportunity,
        RecordAction::Update,
    )
    .await
}

/// How a schedule is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleMethod {
    Even,
    Pattern,
    Manual,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesScheduleBody {
    pub method: ScheduleMethod,
    /// The first period, for `even` and `pattern`.
    #[serde(default)]
    pub start: Option<NaiveDate>,
    #[serde(default)]
    pub months: Option<u32>,
    /// Percentages per month, totalling 100.
    #[serde(default)]
    #[schema(value_type = Option<Vec<String>>)]
    pub pattern: Option<Vec<Decimal>>,
    /// Hand-entered rows, totalling the line.
    #[serde(default)]
    pub rows: Option<Vec<ScheduleRow>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesSchedule {
    pub line_id: Uuid,
    pub rows: Vec<ScheduleRow>,
}

/// Set a deal line's schedule
///
/// Replaces the line's revenue or quantity schedule: spread evenly over months, by a percentage
/// pattern (totalling 100), or row by row (totalling the line). Rounding goes to the last row, so the
/// schedule always adds up to its line. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunity-lines/{line_id}/schedule",
    tag = "sales",
    params(("line_id" = Uuid, Path, description = "The opportunity line")),
    request_body = SalesScheduleBody,
    responses(
        (status = 200, description = "The line's schedule is replaced", body = SalesSchedule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update the line's opportunity", body = ErrorResponse),
        (status = 404, description = "No such line, or schedules are switched off", body = ErrorResponse),
        (status = 409, description = "The deal is being changed by another request", body = ErrorResponse),
        (status = 422, description = "A pattern not totalling 100, rows not totalling the line, or a missing start or months", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_line_schedule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(line): Path<Uuid>,
    Json(body): Json<SalesScheduleBody>,
) -> Result<Json<SalesSchedule>, AppError> {
    let found: Option<(Option<Uuid>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT opportunity_ref, line_total::text, quantity::text FROM opportunity_line \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(line)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(opportunity), total, quantity)) = found else {
        return Err(AppError::NotFound);
    };
    require(&state, &ctx, opportunity).await?;
    let total: Decimal = total.and_then(|t| t.parse().ok()).unwrap_or(Decimal::ZERO);
    let quantity: Option<Decimal> = quantity.and_then(|q| q.parse().ok());
    let rows = match body.method {
        ScheduleMethod::Manual => {
            let rows = body.rows.ok_or_else(|| {
                AppError::Validation("rows are required for a manual schedule".into())
            })?;
            check_manual(&rows, total)?;
            rows
        }
        method => {
            let start = body
                .start
                .ok_or_else(|| AppError::Validation("start is required".into()))?;
            let pattern = if method == ScheduleMethod::Pattern {
                Some(
                    body.pattern
                        .ok_or_else(|| AppError::Validation("pattern is required".into()))?,
                )
            } else {
                None
            };
            let months = body.months.unwrap_or(0);
            planned_rows(start, total, quantity, months, pattern.as_deref())?
        }
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::split_store::lock_deal(&mut tx, opportunity).await?;
    sqlx::query("DELETE FROM opportunity_line_schedule WHERE line_ref = $1")
        .bind(line)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for (i, row) in rows.iter().enumerate() {
        sqlx::query(
            "INSERT INTO opportunity_line_schedule \
               (name, line_ref, period_start, revenue, quantity, owner_ref) \
             SELECT $1, $2, $3, $4::numeric, $5::numeric, o.owner_ref \
             FROM opportunity o WHERE o.id = $6",
        )
        .bind(format!("{}", i + 1))
        .bind(line)
        .bind(row.period_start)
        .bind(row.revenue.to_string())
        .bind(row.quantity.map(|q| q.to_string()))
        .bind(opportunity)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "opportunity_line",
            line,
            AuditOperation::Update,
            "sales.schedule_replaced",
            ctx.user_id,
        )
        .comment(format!("{} rows", rows.len())),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(SalesSchedule {
        line_id: line,
        rows,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesScheduleShiftBody {
    /// Whole months; negative moves earlier.
    pub months: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesScheduleShifted {
    pub opportunity_id: Uuid,
    /// Rows moved now; zero when a job moves them.
    pub rows_shifted: u64,
    pub queued: bool,
}

/// Moves every schedule row of a deal by `months`, inside a transaction.
pub async fn shift_in_tx(
    tx: &mut attome_db::Tx<'_>,
    opportunity: Uuid,
    months: i32,
) -> Result<u64, AppError> {
    Ok(sqlx::query(
        "UPDATE opportunity_line_schedule s \
         SET period_start = (s.period_start::date + make_interval(months => $2))::date, \
             modified_at = now(), row_version = row_version + 1 \
         FROM opportunity_line l \
         WHERE l.id = s.line_ref AND l.opportunity_ref = $1 \
           AND (s.is_active IS NULL OR s.is_active = true)",
    )
    .bind(opportunity)
    .bind(months)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected())
}

/// The shift job: the whole deal in one transaction under its lock.
pub async fn run_shift(
    state: &EngineState,
    opportunity: Uuid,
    months: i32,
) -> Result<u64, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::split_store::lock_deal(&mut tx, opportunity).await?;
    let moved = shift_in_tx(&mut tx, opportunity, months).await?;
    attome_db::tx::commit(tx).await?;
    Ok(moved)
}

/// Shift a deal's schedules
///
/// Moves every revenue and quantity schedule row of the deal by whole months, after the user agreed to
/// move them with a new close date; never called automatically. Needs update rights on the
/// opportunity. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunities/{id}/schedules/shift",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity")),
    request_body = SalesScheduleShiftBody,
    responses(
        (status = 200, description = "The deal's schedule rows are moved, or a job is queued to move them", body = SalesScheduleShifted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity, or schedules are switched off", body = ErrorResponse),
        (status = 409, description = "The deal is being changed by another request", body = ErrorResponse),
        (status = 422, description = "Zero months, or more than 240 either way", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_schedule_shift(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(opportunity): Path<Uuid>,
    Json(body): Json<SalesScheduleShiftBody>,
) -> Result<Json<SalesScheduleShifted>, AppError> {
    if body.months == 0 || body.months.unsigned_abs() > MAX_MONTHS {
        return Err(AppError::Validation(format!(
            "months: -{MAX_MONTHS} to {MAX_MONTHS}, not zero"
        )));
    }
    require(&state, &ctx, opportunity).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::split_store::lock_deal(&mut tx, opportunity).await?;
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM opportunity_line_schedule s \
         JOIN opportunity_line l ON l.id = s.line_ref \
         WHERE l.opportunity_ref = $1 AND (s.is_active IS NULL OR s.is_active = true)",
    )
    .bind(opportunity)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (shifted, queued) = if rows > INLINE_SHIFT_LIMIT {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::SalesScheduleShift {
                opportunity_id: opportunity,
                months: body.months,
            },
        )
        .await
        .map_err(AppError::internal)?;
        (0, true)
    } else {
        (shift_in_tx(&mut tx, opportunity, body.months).await?, false)
    };
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "opportunity",
            opportunity,
            AuditOperation::Update,
            "sales.schedule_shifted",
            ctx.user_id,
        )
        .comment(format!("{} months", body.months)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(SalesScheduleShifted {
        opportunity_id: opportunity,
        rows_shifted: shifted,
        queued,
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_sales_line_schedule, post_sales_schedule_shift),
    components(schemas(
        ScheduleRow,
        ScheduleMethod,
        SalesScheduleBody,
        SalesSchedule,
        SalesScheduleShiftBody,
        SalesScheduleShifted
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, 1).unwrap_or_default()
    }

    #[test]
    fn an_even_schedule_adds_up_with_the_remainder_last() {
        let rows = planned_rows(
            d(2026, 11),
            Decimal::from(100),
            Some(Decimal::from(3)),
            3,
            None,
        )
        .unwrap_or_default();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].revenue, Decimal::new(3333, 2));
        assert_eq!(rows[2].revenue, Decimal::new(3334, 2));
        assert_eq!(
            rows.iter().map(|r| r.revenue).sum::<Decimal>(),
            Decimal::from(100)
        );
        assert_eq!(rows[2].period_start, d(2027, 1));
        assert_eq!(
            rows.iter().filter_map(|r| r.quantity).sum::<Decimal>(),
            Decimal::from(3)
        );
    }

    #[test]
    fn a_pattern_must_total_100() {
        let ok = [Decimal::from(50), Decimal::from(30), Decimal::from(20)];
        let rows =
            planned_rows(d(2026, 1), Decimal::from(1000), None, 0, Some(&ok)).unwrap_or_default();
        assert_eq!(rows[1].revenue, Decimal::from(300));
        let bad = [Decimal::from(50), Decimal::from(30)];
        assert!(planned_rows(d(2026, 1), Decimal::from(1000), None, 0, Some(&bad)).is_err());
        assert!(planned_rows(d(2026, 1), Decimal::from(1000), None, 0, None).is_err());
    }

    #[test]
    fn manual_rows_must_total_the_line() {
        let row = |rev: i64| ScheduleRow {
            period_start: d(2026, 1),
            revenue: Decimal::from(rev),
            quantity: None,
        };
        assert!(check_manual(&[row(60), row(40)], Decimal::from(100)).is_ok());
        assert!(check_manual(&[row(60), row(30)], Decimal::from(100)).is_err());
        assert!(check_manual(&[], Decimal::ZERO).is_err());
    }
}

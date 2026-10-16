//! The payroll hand-off (roadmap W6-T3): one CSV per period for the payroll
//! system, in the column layout of a template. Each active employee's row
//! carries their base salary, the unpaid leave days that fall in the period
//! (working days, on the same calendar as leave), and, when the commission
//! pack is installed, the commission payouts approved for them in the
//! period. Attome does not run payroll; it hands the inputs over.
//!
//! The export needs the field grants for salaries and national ids (it is
//! refused without them, never silently blanked), every cell is escaped and
//! guarded against spreadsheet formula injection, and each export writes an
//! Access/Export security event.

use std::collections::BTreeMap;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    extract::{Query, State},
    http::header,
    response::{IntoResponse, Response},
};
use chrono::NaiveDate;
use rust_decimal::{Decimal, RoundingStrategy};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::leave::EmployeeRead;

/// A payroll template: its columns, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayrollTemplate {
    /// Every column Attome has, with English headers.
    Generic,
    /// Wage-protection style: national id first, amounts in whole riyals.
    Wps,
}

impl PayrollTemplate {
    pub fn header(self) -> &'static [&'static str] {
        match self {
            Self::Generic => &[
                "employee_id",
                "full_name",
                "national_id",
                "base_salary",
                "unpaid_leave_days",
                "commission",
            ],
            Self::Wps => &[
                "national_id",
                "employee_name",
                "basic_salary",
                "deductible_days",
                "other_earnings",
            ],
        }
    }
}

/// One employee's payroll inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayrollRow {
    pub employee_id: Uuid,
    pub full_name: String,
    pub national_id: String,
    pub base_salary: Decimal,
    pub unpaid_leave_days: u32,
    pub commission: Decimal,
}

/// A CSV cell: quoted when it has to be, and with a leading `'` when it
/// would otherwise start a spreadsheet formula.
pub fn cell(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn money(value: Decimal, places: u32) -> String {
    value
        .round_dp_with_strategy(places, RoundingStrategy::MidpointAwayFromZero)
        .to_string()
}

/// The CSV for `rows` in `template`'s layout.
pub fn render(template: PayrollTemplate, rows: &[PayrollRow]) -> String {
    let mut out = template.header().join(",");
    out.push_str("\r\n");
    for r in rows {
        let fields: Vec<String> = match template {
            PayrollTemplate::Generic => vec![
                r.employee_id.to_string(),
                r.full_name.clone(),
                r.national_id.clone(),
                money(r.base_salary, 2),
                r.unpaid_leave_days.to_string(),
                money(r.commission, 2),
            ],
            PayrollTemplate::Wps => vec![
                r.national_id.clone(),
                r.full_name.clone(),
                money(r.base_salary, 0),
                r.unpaid_leave_days.to_string(),
                money(r.commission, 0),
            ],
        };
        out.push_str(&fields.iter().map(|f| cell(f)).collect::<Vec<_>>().join(","));
        out.push_str("\r\n");
    }
    out
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PayrollExportQuery {
    /// The period's first day.
    pub from: NaiveDate,
    /// The period's last day.
    pub to: NaiveDate,
    /// `generic` (default) or `wps`.
    #[param(value_type = Option<String>)]
    pub template: Option<PayrollTemplate>,
}

type EmployeeRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
);

async fn rows(
    state: &EngineState,
    from: NaiveDate,
    to: NaiveDate,
) -> Result<Vec<PayrollRow>, AppError> {
    let db = &state.base.db;
    let employees: Vec<EmployeeRow> = sqlx::query_as(
        "SELECT id, full_name, national_id, base_salary::text, user_ref FROM employee \
         WHERE (is_active IS NULL OR is_active = true) \
           AND (employment_status IS NULL OR employment_status <> 'terminated') \
         ORDER BY full_name, id",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let (working, holidays) = crate::leave::working_calendar(db).await?;
    let unpaid: Vec<(Uuid, NaiveDate, NaiveDate)> = sqlx::query_as(
        "SELECT employee_ref, start_date::date, end_date::date FROM leave_request \
         WHERE leave_type = 'unpaid' AND status IN ('approved', 'taken') \
           AND start_date::date <= $2 AND end_date::date >= $1 \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(from)
    .bind(to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut unpaid_days: BTreeMap<Uuid, u32> = BTreeMap::new();
    for (employee, start, end) in unpaid {
        let days = crate::leave::leave_days(start.max(from), end.min(to), &working, &holidays);
        *unpaid_days.entry(employee).or_default() += days;
    }
    let mut commission: BTreeMap<Uuid, Decimal> = BTreeMap::new();
    let has_commission: bool = sqlx::query_scalar("SELECT to_regclass('comp_payout') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if has_commission {
        let paid: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT p.owner_ref, SUM(p.amount)::text FROM comp_payout p \
             JOIN comp_run r ON r.id = p.run_ref \
             JOIN comp_period cp ON cp.id = r.period_ref \
             WHERE p.status = 'approved' AND p.owner_ref IS NOT NULL \
               AND cp.ends_on::date BETWEEN $1 AND $2 \
               AND (p.is_active IS NULL OR p.is_active = true) \
             GROUP BY p.owner_ref",
        )
        .bind(from)
        .bind(to)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (user, amount) in paid {
            commission.insert(
                user,
                amount.and_then(|a| a.parse().ok()).unwrap_or(Decimal::ZERO),
            );
        }
    }
    Ok(employees
        .into_iter()
        .map(|(id, name, national_id, salary, user)| PayrollRow {
            employee_id: id,
            full_name: name.unwrap_or_default(),
            national_id: national_id.unwrap_or_default(),
            base_salary: salary.and_then(|s| s.parse().ok()).unwrap_or(Decimal::ZERO),
            unpaid_leave_days: unpaid_days.get(&id).copied().unwrap_or(0),
            commission: user
                .and_then(|u| commission.get(&u).copied())
                .unwrap_or(Decimal::ZERO),
        })
        .collect())
}

#[utoipa::path(
    get,
    path = "/api/v1/hr/payroll-export",
    tag = "hr",
    params(PayrollExportQuery),
    responses(
        (status = 200, description = "The period's payroll inputs as CSV", content_type = "text/csv", body = String),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks employee.read, or the salary or national id field grant", body = ErrorResponse),
        (status = 422, description = "The period is reversed or over a year", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_hr_payroll_export(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<EmployeeRead>>,
    Query(q): Query<PayrollExportQuery>,
) -> Result<Response, AppError> {
    if q.to < q.from || (q.to - q.from).num_days() > 366 {
        return Err(AppError::Validation(
            "to is before from, or the period is over a year".into(),
        ));
    }
    for field in ["base_salary", "national_id"] {
        if !ctx.has_field_read_grant("employee", field) {
            return Err(AppError::Forbidden);
        }
    }
    let template = q.template.unwrap_or(PayrollTemplate::Generic);
    let rows = rows(&state, q.from, q.to).await?;
    let csv = render(template, &rows);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Access,
            AuditOperation::Export,
            ctx.user_id,
            "employee",
            None,
        )
        .comment(format!(
            "payroll export {} to {}: {} employees",
            q.from,
            q.to,
            rows.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"payroll-{}-{}.csv\"", q.from, q.to),
            ),
        ],
        csv,
    )
        .into_response())
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_hr_payroll_export))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> PayrollRow {
        PayrollRow {
            employee_id: Uuid::from_u128(1),
            full_name: "Sara, Al-Harbi".into(),
            national_id: "=1+1".into(),
            base_salary: Decimal::new(1250050, 2),
            unpaid_leave_days: 2,
            commission: Decimal::new(99950, 2),
        }
    }

    #[test]
    fn cells_are_quoted_and_formulas_disarmed() {
        assert_eq!(cell("plain"), "plain");
        assert_eq!(cell("a,b"), "\"a,b\"");
        assert_eq!(cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(cell("=SUM(A1)"), "'=SUM(A1)");
        assert_eq!(cell("-5"), "'-5");
    }

    #[test]
    fn templates_lay_out_the_same_row_their_own_way() {
        let generic = render(PayrollTemplate::Generic, &[row()]);
        let mut lines = generic.lines();
        assert_eq!(
            lines.next(),
            Some("employee_id,full_name,national_id,base_salary,unpaid_leave_days,commission")
        );
        assert_eq!(
            lines.next(),
            Some("00000000-0000-0000-0000-000000000001,\"Sara, Al-Harbi\",'=1+1,12500.50,2,999.50")
        );
        let wps = render(PayrollTemplate::Wps, &[row()]);
        assert_eq!(
            wps.lines().nth(1),
            Some("'=1+1,\"Sara, Al-Harbi\",12501,2,1000")
        );
    }
}

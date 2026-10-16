//! Hiring (roadmap W7-T2): an accepted job offer becomes an employee. The
//! employee is created through the generic record write, as the caller,
//! from the candidate's name, the offer's salary and start date and the
//! posting's title; a user account with the candidate's email is linked when
//! one exists (accounts themselves are created through invitations).
//! Hiring the same offer twice is refused.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::NaiveDate;
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// `employee.create`: may hire.
#[derive(Debug)]
pub struct EmployeeCreate;

impl PrivilegeKey for EmployeeCreate {
    const KEY: &'static str = "employee.create";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct HrHired {
    pub offer_id: Uuid,
    pub employee_id: Uuid,
    /// The user account linked by the candidate's email, when one exists.
    pub user_id: Option<Uuid>,
}

type OfferRow = (
    Option<String>,
    Option<String>,
    Option<NaiveDate>,
    Option<String>,
    Option<String>,
    Option<String>,
);

#[utoipa::path(
    post,
    path = "/api/v1/hr/offers/{id}/hire",
    tag = "hr",
    params(("id" = Uuid, Path, description = "The accepted job offer")),
    responses(
        (status = 201, description = "The employee is created from the offer", body = HrHired),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks employee.create", body = ErrorResponse),
        (status = 404, description = "No such offer", body = ErrorResponse),
        (status = 409, description = "The offer is not accepted, or was already hired", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_hr_hire(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<EmployeeCreate>>,
    Path(offer): Path<Uuid>,
) -> Result<(StatusCode, Json<HrHired>), AppError> {
    let db = &state.base.db;
    let row: Option<OfferRow> = sqlx::query_as(
        "SELECT o.status, o.salary::text, o.start_date::date, c.full_name, c.email, p.title \
         FROM job_offer o \
         LEFT JOIN job_application a ON a.id = o.application_ref \
         LEFT JOIN candidate c ON c.id = a.candidate_ref \
         LEFT JOIN job_posting p ON p.id = a.posting_ref \
         WHERE o.id = $1 AND (o.is_active IS NULL OR o.is_active = true)",
    )
    .bind(offer)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, salary, start, name, email, title)) = row else {
        return Err(AppError::NotFound);
    };
    if status.as_deref() != Some("accepted") {
        return Err(AppError::Conflict("only an accepted offer can be hired"));
    }
    let name = name.unwrap_or_default();
    // The same person starting the same day from this offer is one hire.
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-hr/hire:{offer}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this offer is being hired by another request",
        ));
    }
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM employee WHERE full_name = $1 \
             AND hire_date::date IS NOT DISTINCT FROM $2 \
             AND (is_active IS NULL OR is_active = true))",
    )
    .bind(&name)
    .bind(start)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    if already {
        return Err(AppError::Conflict("this offer was already hired"));
    }
    let user: Option<Uuid> = match email.as_deref().map(str::trim).filter(|e| !e.is_empty()) {
        Some(email) => sqlx::query_scalar(
            "SELECT id FROM user_account WHERE lower(email) = lower($1) \
               AND (is_active IS NULL OR is_active = true) LIMIT 1",
        )
        .bind(email)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?,
        None => None,
    };
    let mut values = serde_json::Map::new();
    values.insert("full_name".into(), json!(name));
    values.insert("employment_status".into(), json!("active"));
    if let Some(start) = start {
        values.insert("hire_date".into(), json!(start.to_string()));
    }
    // `base_salary` is a number field; the offer's currency renders as text.
    if let Some(salary) = salary.and_then(|s| serde_json::from_str::<serde_json::Number>(&s).ok()) {
        values.insert("base_salary".into(), serde_json::Value::Number(salary));
    }
    if let Some(title) = title {
        values.insert("job_title".into(), json!(title));
    }
    if let Some(user) = user {
        values.insert("user_ref".into(), json!(user.to_string()));
    }
    let (employee, _) = attome_records::entity_crud::create_record_for(
        &state,
        &ctx,
        ctx.user_id,
        "employee",
        serde_json::Value::Object(values),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(HrHired {
            offer_id: offer,
            employee_id: employee,
            user_id: user,
        }),
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_hr_hire), components(schemas(HrHired)))]
pub(crate) struct ApiDocFragment;

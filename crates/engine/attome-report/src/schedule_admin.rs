//! M25 Phase 1 (Report, D-440) — bespoke create/update for
//! `report_schedule`.
//!
//! Same asymmetry as `report_admin.rs`: `report_schedule` is a normal,
//! generically-CRUD-able entity (`seed.rs`), and this is the intended write
//! path because two things generic CRUD cannot express live here:
//!
//! - `rrule` must parse (`attome_calendar::rrule`, without `COUNT`) —
//!   checked here, and used to compute the `next_run_at` the scheduler
//!   sweep (`crate::scheduler`) reads.
//! - `run_as` must name a real, active, **non-admin** user — D-440's core
//!   ruling. Existence is also covered for free by generic CRUD's own
//!   lookup-integrity check (D-077, since `run_as` is a real `lookup`
//!   field), but "not an elevated account" is business logic no field type
//!   expresses, so it is checked here explicitly.
//!
//! `delivery` is a `choice` field whose only allowed values are `in_app`/
//! `email_link` (`seed.rs`) — `email attachment` is out of scope for this
//! pass (attachment-size-cap-to-link-fallback is deferred complexity) and is
//! rejected the same way `pdf`/`html` is rejected for `attome_report.format`:
//! it is simply not in the allowed-choices list.
//!
//! Authorization: `Authorized<Privilege<ScheduleCreate/ScheduleUpdate>>`
//! (`crate::auth`) — same reasoning as `report_admin.rs`'s module doc (no
//! `{entity}` path segment for `RecordScoped` to bind, and the bare-policy
//! ratchet is already full).

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{ScheduleCreate, ScheduleUpdate};
use attome_calendar::rrule::Rrule;

const ENTITY: &str = "report_schedule";

#[derive(Deserialize, ToSchema)]
struct CreateScheduleBody {
    report_ref: Uuid,
    rrule: String,
    run_as: Uuid,
    /// User emails, team names, or literal email addresses — resolved at
    /// delivery time, not validated against a directory here (same
    /// "opaque until delivery" posture `record_share`'s
    /// principal resolution uses for `user_email`/`team_name`).
    #[serde(default)]
    recipients: Vec<String>,
    /// `in_app` or `email_link` only — see module doc.
    delivery: String,
    #[serde(default = "default_skip_if_empty")]
    skip_if_empty: bool,
}

fn default_skip_if_empty() -> bool {
    true
}

#[derive(Deserialize, ToSchema)]
struct UpdateScheduleBody {
    rrule: Option<String>,
    run_as: Option<Uuid>,
    recipients: Option<Vec<String>>,
    delivery: Option<String>,
    skip_if_empty: Option<bool>,
    row_version: i64,
}

fn valid_delivery(d: &str) -> bool {
    matches!(d, "in_app" | "email_link")
}

/// D-440's core check: `run_as` must be a real, active, non-admin user.
/// Existence-as-a-live-`lookup`-target is separately (and redundantly)
/// enforced by generic CRUD's own lookup integrity once the write reaches
/// `entity_crud::create_record_for`/`update_record_for` — this runs first so
/// the caller gets one clear reason, not a generic lookup-integrity error,
/// when the real problem is "this account is a superuser".
async fn validate_run_as(state: &EngineState, run_as: Uuid) -> Result<(), AppError> {
    let is_active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(run_as)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match is_active {
        None => {
            return Err(AppError::Validation(
                "run_as does not name an existing user".into(),
            ));
        }
        Some(false) => {
            return Err(AppError::Validation("run_as must be an active user".into()));
        }
        Some(true) => {}
    }
    let ctx = attome_security::resolve_uncached(&state.base.db, run_as).await?;
    if ctx.is_admin {
        return Err(AppError::Validation(
            "run_as must not hold system.admin — D-440: a scheduled report runs under a real \
             user's ordinary permissions, never an elevated/superuser one"
                .into(),
        ));
    }
    Ok(())
}

/// Parses `rrule` and returns its first occurrence after now — a rule with
/// no future occurrence (an already-past `UNTIL`) is rejected outright
/// rather than silently creating a schedule that will never fire.
fn compute_next_run_at(rrule: &str) -> Result<chrono::DateTime<Utc>, AppError> {
    let rule = Rrule::parse(rrule).map_err(AppError::Validation)?;
    // A report schedule keeps no occurrence count, so COUNT could never stop it.
    if rule.count().is_some() {
        return Err(AppError::Validation(
            "COUNT is not supported for report schedules; use UNTIL".into(),
        ));
    }
    let now = Utc::now();
    rule.next_after(now, now).ok_or_else(|| {
        AppError::Validation("rrule produces no future occurrences (check UNTIL)".into())
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/reports/schedules",
    tag = "report",
    request_body = CreateScheduleBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_schedule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ScheduleCreate>>,
    Json(body): Json<CreateScheduleBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if !valid_delivery(&body.delivery) {
        return Err(AppError::Validation(
            "delivery must be in_app or email_link for this pass (email attachment is deferred)"
                .into(),
        ));
    }
    validate_run_as(&state, body.run_as).await?;
    let next_run_at = compute_next_run_at(&body.rrule)?;

    let body_value = serde_json::json!({
        "report_ref": body.report_ref.to_string(),
        "rrule": body.rrule,
        "run_as": body.run_as.to_string(),
        "recipients": serde_json::to_string(&body.recipients).map_err(AppError::internal)?,
        "delivery": body.delivery,
        "skip_if_empty": body.skip_if_empty,
        "next_run_at": next_run_at.to_rfc3339(),
    });

    let (_, response) = attome_records::entity_crud::create_record_for(
        &state,
        &ctx,
        ctx.user_id,
        ENTITY,
        body_value,
    )
    .await?;
    let response = serde_json::to_value(response).map_err(AppError::internal)?;
    Ok((StatusCode::CREATED, Json(response)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/reports/schedules/{id}",
    tag = "report",
    params(("id" = Uuid, Path)),
    request_body = UpdateScheduleBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_schedule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ScheduleUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateScheduleBody>,
) -> Result<Json<Value>, AppError> {
    if let Some(delivery) = &body.delivery
        && !valid_delivery(delivery)
    {
        return Err(AppError::Validation(
            "delivery must be in_app or email_link for this pass (email attachment is deferred)"
                .into(),
        ));
    }
    if let Some(run_as) = body.run_as {
        validate_run_as(&state, run_as).await?;
    }
    let next_run_at = match &body.rrule {
        Some(rrule) => Some(compute_next_run_at(rrule)?),
        None => None,
    };

    let mut obj = serde_json::Map::new();
    if let Some(rrule) = body.rrule {
        obj.insert("rrule".into(), Value::String(rrule));
    }
    if let Some(next_run_at) = next_run_at {
        obj.insert(
            "next_run_at".into(),
            Value::String(next_run_at.to_rfc3339()),
        );
    }
    if let Some(run_as) = body.run_as {
        obj.insert("run_as".into(), Value::String(run_as.to_string()));
    }
    if let Some(recipients) = body.recipients {
        obj.insert(
            "recipients".into(),
            Value::String(serde_json::to_string(&recipients).map_err(AppError::internal)?),
        );
    }
    if let Some(delivery) = body.delivery {
        obj.insert("delivery".into(), Value::String(delivery));
    }
    if let Some(skip_if_empty) = body.skip_if_empty {
        obj.insert("skip_if_empty".into(), Value::Bool(skip_if_empty));
    }

    let response = attome_records::entity_crud::update_record_for(
        &state,
        &ctx,
        ctx.user_id,
        ENTITY,
        id,
        body.row_version,
        Value::Object(obj),
    )
    .await?;
    let response = serde_json::to_value(response).map_err(AppError::internal)?;
    Ok(Json(response))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/reports/schedules", post(create_schedule))
        .route(
            "/api/v1/reports/schedules/{id}",
            axum::routing::patch(update_schedule),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged in `lib.rs::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(create_schedule, update_schedule))]
#[derive(Debug)]
pub struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

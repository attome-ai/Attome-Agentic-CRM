//! Y12-T11: `POST /api/v1/admin/entities/{entity_id}/rehearse` — run a
//! field's change on the configured copy database
//! (`metadata.rehearsal_database_url`) and answer how long each step took
//! there. Only the copy is written; nothing in this deployment changes, so
//! the route is exempt from the audit declaration as a dry run. 409 when no
//! copy is configured.

use attome_core::{EngineState, FieldType};
use attome_metadata::provision::{self, rehearse};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// The change to rehearse: the field and its target contract; absent
/// values keep the field's current ones.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RehearseRequest {
    /// The field's logical name.
    pub field: String,
    #[serde(default)]
    pub is_required: Option<bool>,
    #[serde(default)]
    pub max_length: Option<i32>,
}

/// One timed step on the copy.
#[derive(Debug, Serialize, ToSchema)]
pub struct RehearsalStepDto {
    pub name: String,
    pub duration_ms: u64,
    pub rows: Option<i64>,
}

/// What the rehearsal measured.
#[derive(Debug, Serialize, ToSchema)]
pub struct RehearsalReportDto {
    pub per_change: Vec<RehearsalStepDto>,
    pub total_ms: u64,
}

/// Rehearse a field change on the copy database
///
/// Y12-T11: runs the same schema change the real update would run, on
/// `metadata.rehearsal_database_url`, and answers each step's time and the
/// rows it touched. Admin only. Writes only to the copy.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/rehearse",
    tag = "admin",
    operation_id = "rehearse_entity_field_change",
    params(("entity_id" = Uuid, Path, description = "The entity")),
    request_body = RehearseRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "runs the change on the configured copy database only; this deployment is not written",
    )))),
    responses(
        (status = 200, description = "Each step's time on the copy", body = RehearsalReportDto),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity or field", body = ErrorResponse),
        (status = 409, description = "No rehearsal database is configured", body = ErrorResponse),
        (status = 422, description = "The copy did not answer, has no such table, or the change fails there", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rehearse_field(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<RehearseRequest>,
) -> Result<Json<RehearsalReportDto>, AppError> {
    let Some(url) = state.base.config.metadata.rehearsal_database_url.as_ref() else {
        return Err(AppError::Conflict(
            "no rehearsal database is configured (metadata.rehearsal_database_url)",
        ));
    };
    let entity: String = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let current: (i32, Option<bool>, Option<i32>, Option<Value>) = sqlx::query_as(
        r#"SELECT "type", required, max_length, options FROM attribute_info
            WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true)"#,
    )
    .bind(entity_id)
    .bind(body.field.trim())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let (code, required, max_length, options) = current;
    let field_type = FieldType::from_int(code)
        .map(|t| t.as_str())
        .unwrap_or("text")
        .to_owned();
    let change = rehearse::FieldChange {
        entity,
        field: body.field.trim().to_owned(),
        is_required: body.is_required.unwrap_or(required.unwrap_or(false)),
        max_length: body.max_length.or(max_length),
        is_multi: provision::is_multi_valued(&field_type, options.as_ref()),
        field_type,
    };
    let report = rehearse::rehearse_field_change(url.expose(), &change).await?;
    Ok(Json(RehearsalReportDto {
        total_ms: report.total_ms,
        per_change: report
            .per_change
            .into_iter()
            .map(|s| RehearsalStepDto {
                name: s.name,
                duration_ms: s.duration_ms,
                rows: s.rows,
            })
            .collect(),
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/entities/{entity_id}/rehearse",
        post(rehearse_field),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(rehearse_field),
    components(schemas(RehearseRequest, RehearsalStepDto, RehearsalReportDto))
)]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

//! M25 Phase 1 (Report, D-440) — bespoke create/update for `attome_report`.
//!
//! `attome_report` is a normal, generically-CRUD-able XRM entity (`seed.rs`),
//! reachable at `/api/v1/attome_report` like any other — same asymmetry
//! `attome-workflow`'s `workflow_definition` entity already lives with
//! (generic CRUD stays reachable; the intended write path is this bespoke
//! one). The one thing generic CRUD cannot express is checked here:
//! `query_ref` must name a real, live `sql_query` row. `format`
//! being `csv`/`xlsx` only is instead enforced by the `format` attribute's
//! `choice` options (`seed.rs`), so even a caller who goes straight to
//! generic CRUD gets the same rejection.
//!
//! Both handlers hand the actual write off to
//! `attome_records::entity_crud::create_record_for`/`update_record_for` — the
//! same reusable primitive `attome-ai`'s `record.create`/`record.update`
//! actions call — so lookup integrity (`owner`), field-write grants, the
//! implicit D-133 creator-share row, record-level access on update, audit,
//! and file-field sync are one implementation, not a second one grown here.
//!
//! Authorization: `Authorized<Privilege<ReportCreate/ReportUpdate>>`
//! (`crate::auth`), not `RecordScoped` — the route is `/api/v1/reports`,
//! not `/api/v1/{entity}`, so there is no `{entity}` path segment for
//! `RecordScoped`'s extractor to resolve against, and a bare
//! `Authorized<RecordScoped>` here would count toward
//! `route_authz.rs`'s `MAX_BARE_RECORD_SCOPED` ratchet (already fully
//! claimed by `query_exec::execute`/`aggregate::aggregate`, the two
//! genuinely dynamic-entity routes). `Privilege<K>` checks the identical
//! `attome_report.{create,update}` string a `RecordScoped<Create/Update>` on
//! `attome_report`'s own generic-CRUD route would — see `crate::auth`'s doc.

use attome_core::{EngineState, Filter};
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use serde::Deserialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{ReportCreate, ReportUpdate};

const ENTITY: &str = "attome_report";

#[derive(Deserialize, ToSchema)]
struct CreateReportBody {
    name: String,
    query_ref: Uuid,
    /// Default parameter filters applied when a run doesn't override them —
    /// same `Filter` grammar `query/execute` and `{entity}/export` already
    /// use, so no new binding/whitelisting surface is introduced.
    #[serde(default)]
    parameters: Vec<Filter>,
    /// `csv` or `xlsx` only for this pass — `pdf`/`html` are rejected by the
    /// `format` attribute's `choice` options (see module doc).
    format: String,
    #[serde(default)]
    is_template: bool,
}

#[derive(Deserialize, ToSchema)]
struct UpdateReportBody {
    name: Option<String>,
    query_ref: Option<Uuid>,
    parameters: Option<Vec<Filter>>,
    format: Option<String>,
    is_template: Option<bool>,
    row_version: i64,
}

async fn query_ref_exists(db: &attome_db::DbPool, query_id: Uuid) -> Result<bool, AppError> {
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sql_query \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(query_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(found.is_some())
}

#[utoipa::path(
    post,
    path = "/api/v1/reports",
    tag = "report",
    request_body = CreateReportBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_report(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ReportCreate>>,
    Json(body): Json<CreateReportBody>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    if !matches!(body.format.as_str(), "csv" | "xlsx") {
        return Err(AppError::Validation(
            "format must be csv or xlsx for this pass".into(),
        ));
    }
    if !query_ref_exists(&state.base.db, body.query_ref).await? {
        return Err(AppError::Validation(
            "query_ref does not name a live stored query".into(),
        ));
    }

    let body_value = serde_json::json!({
        "name": body.name,
        "query_ref": body.query_ref.to_string(),
        "parameters": serde_json::to_string(&body.parameters).map_err(AppError::internal)?,
        "format": body.format,
        "owner": ctx.user_id.to_string(),
        "is_template": body.is_template,
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
    path = "/api/v1/reports/{id}",
    tag = "report",
    params(("id" = Uuid, Path)),
    request_body = UpdateReportBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_report(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ReportUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateReportBody>,
) -> Result<Json<Value>, AppError> {
    if let Some(format) = &body.format
        && !matches!(format.as_str(), "csv" | "xlsx")
    {
        return Err(AppError::Validation(
            "format must be csv or xlsx for this pass".into(),
        ));
    }
    if let Some(query_ref) = body.query_ref
        && !query_ref_exists(&state.base.db, query_ref).await?
    {
        return Err(AppError::Validation(
            "query_ref does not name a live stored query".into(),
        ));
    }

    let mut obj = serde_json::Map::new();
    if let Some(name) = body.name {
        obj.insert("name".into(), Value::String(name));
    }
    if let Some(query_ref) = body.query_ref {
        obj.insert("query_ref".into(), Value::String(query_ref.to_string()));
    }
    if let Some(parameters) = body.parameters {
        obj.insert(
            "parameters".into(),
            Value::String(serde_json::to_string(&parameters).map_err(AppError::internal)?),
        );
    }
    if let Some(format) = body.format {
        obj.insert("format".into(), Value::String(format));
    }
    if let Some(is_template) = body.is_template {
        obj.insert("is_template".into(), Value::Bool(is_template));
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
        .route("/api/v1/reports", post(create_report))
        .route("/api/v1/reports/{id}", axum::routing::patch(update_report))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged in `lib.rs::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(create_report, update_report))]
#[derive(Debug)]
pub struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

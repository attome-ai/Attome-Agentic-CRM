//! `prediction_model` admin CRUD — `/api/v1/admin/predict/models*`.
//!
//! Mounted through `PredictModel::routes()` (`lib.rs`), so every route here
//! is already license-gated by `ModelRegistry` before this module ever sees
//! a request (D-010) — handlers only need `Authorized<Admin>`, the same
//! posture `attome-process::case_def_admin` uses for its own migration-owned
//! config table.
//!
//! The actual model-row writes live in `train.rs` ([`crate::train::
//! create_and_enqueue`]/[`crate::train::enqueue_retrain`], both
//! insert-or-update-and-enqueue in one transaction) — this module is a thin
//! parse/validate/respond layer over them, plus the read side and the
//! `retire` mutation (a plain status flip with no job to enqueue).

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::model::{ModelSummary, PredictionModelRow};

const MODEL_COLUMNS: &str = "id, name, target, entity, features, algorithm, trained_version, \
     metrics, model_artifact, status, created_by, organization_ref, created_at, updated_at, \
     row_version, is_deleted";

/// `POST /api/v1/admin/predict/models` body. No `features`/`algorithm` field:
/// Phase 1 has no per-model configurable feature set yet — `features` is
/// derived and overwritten from `features::FEATURE_KEYS` once training
/// actually runs (`model::FeatureDescriptor`'s own doc comment), and
/// `algorithm` is always `logistic_regression` — so accepting either here
/// would just be a client-supplied value this crate silently ignores.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateModelBody {
    pub name: String,
    pub target: String,
    pub entity: String,
}

fn validate_name(name: &str) -> Result<String, AppError> {
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    Ok(name)
}

async fn fetch_summary(state: &EngineState, id: Uuid) -> Result<ModelSummary, AppError> {
    let row: PredictionModelRow = sqlx::query_as(&format!(
        "SELECT {MODEL_COLUMNS} FROM prediction_model WHERE id = $1 AND is_deleted = false"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    Ok(row.into())
}

/// List prediction models
///
/// The prediction models, one-based pages. AI administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/predict/models",
    tag = "predict",
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ModelSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_models(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
) -> Result<Json<PaginatedResponse<ModelSummary>>, AppError> {
    let rows: Vec<PredictionModelRow> = sqlx::query_as(&format!(
        "SELECT {MODEL_COLUMNS} FROM prediction_model \
         WHERE is_deleted = false ORDER BY name"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = rows.len() as i64;
    let items: Vec<ModelSummary> = rows.into_iter().map(Into::into).collect();
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// Get a prediction model
///
/// One prediction model. AI administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/predict/models/{id}",
    tag = "predict",
    params(("id" = Uuid, Path, description = "Prediction model id")),
    responses(
        (status = 200, description = "Success", body = ModelSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_model(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ModelSummary>, AppError> {
    Ok(Json(fetch_summary(&state, id).await?))
}

/// Create a prediction model
///
/// Creates the model for its target and entity and queues its first training run in the same
/// transaction; a duplicate name is 409. AI administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/predict/models",
    tag = "predict",
    request_body = CreateModelBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = ModelSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "A model with this name already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation, or an unsupported target/entity pair", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_model(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Json(body): Json<CreateModelBody>,
) -> Result<(StatusCode, Json<ModelSummary>), AppError> {
    let name = validate_name(&body.name)?;
    let model_id =
        crate::train::create_and_enqueue(&state, &name, &body.target, &body.entity, ctx.user_id)
            .await?;
    Ok((
        StatusCode::CREATED,
        Json(fetch_summary(&state, model_id).await?),
    ))
}

/// Retrain a prediction model
///
/// Queues a new training run; a model already training is refused. AI administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/predict/models/{id}/train",
    tag = "predict",
    params(("id" = Uuid, Path, description = "Prediction model id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 202, description = "Training run enqueued"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
        (status = 409, description = "A training run is already in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn retrain_model(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    crate::train::enqueue_retrain(&state, id, ctx.user_id).await?;
    Ok(StatusCode::ACCEPTED)
}

/// Retire a prediction model
///
/// Retires the model; its past predictions stay readable. AI administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/predict/models/{id}",
    tag = "predict",
    params(("id" = Uuid, Path, description = "Prediction model id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Not found", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn retire_model(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let n = sqlx::query(
        "UPDATE prediction_model \
         SET status = 'retired', updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::SoftDelete,
            ctx.user_id,
            "prediction_model",
            Some(id),
        )
        .named("predict_model.retire"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/predict/models",
            get(list_models).post(create_model),
        )
        .route(
            "/api/v1/admin/predict/models/{id}",
            get(get_model).delete(retire_model),
        )
        .route(
            "/api/v1/admin/predict/models/{id}/train",
            post(retrain_model),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_models, get_model, create_model, retrain_model, retire_model))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

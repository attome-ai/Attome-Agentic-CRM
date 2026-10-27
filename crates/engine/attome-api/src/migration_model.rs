//! A24-T3: a migration project's model mapping — which source entities and
//! fields go to which of this deployment's entities and attributes — kept as
//! one document per project (`migration_model_mapping`, migration 0307).
//!
//! - `POST .../model-mapping/draft` takes the source's model (as a source
//!   connector describes it, `attome_integration`'s `SourceModel`) and
//!   stores the proposed mapping (`migration_mapping::draft_mapping`
//!   against the live entity registry), replacing any earlier draft.
//! - `GET .../model-mapping` reads it, with what in it cannot run.
//! - `POST .../source-model` reads a source's model from the integration
//!   system that is the source (`migration_connect`), for a draft; it
//!   writes nothing.
//! - `PUT .../model-mapping` saves the person's edits, refused with 409
//!   when someone saved since the version they read.
//!
//! `system.admin` only, mounted with `strict_authz` beside the migration
//! project routes (`crate::migration`).

use attome_core::{EngineState, FieldType};
use attome_integration::connector::adapters::migration_mapping::{
    self, ModelMapping, TargetAttribute, TargetEntity,
};
use attome_integration::connector::adapters::migration_source::SourceModel;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// The most source entities one mapping holds.
pub const MAX_SOURCE_ENTITIES: usize = 500;

#[derive(Deserialize, ToSchema)]
pub(crate) struct DraftBody {
    /// The source's model, as its connector describes it.
    source_model: SourceModel,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct DescribeBody {
    /// The integration system that is the source; its `config.migration`
    /// names the source's kind.
    system: String,
}

/// A source's model, as its connector describes it.
#[derive(Serialize, ToSchema)]
pub(crate) struct DescribedSource {
    /// `salesforce`, `dynamics`, `hubspot`, `zoho` or `odoo`.
    kind: String,
    source_model: SourceModel,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct SaveBody {
    mapping: ModelMapping,
    /// The version the edits were made on.
    row_version: i32,
}

/// A project's model mapping.
#[derive(Serialize, ToSchema)]
pub(crate) struct MappingDoc {
    project_id: Uuid,
    row_version: i32,
    source_model: SourceModel,
    mapping: ModelMapping,
    /// What in the mapping cannot run against this deployment's entities
    /// now; empty when it can.
    problems: Vec<String>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct MappingRow {
    source_model: Value,
    mapping: Value,
    row_version: i32,
    updated_at: DateTime<Utc>,
}

/// The values a choice attribute's options allow.
fn choices_of(options: Option<&Value>) -> Vec<String> {
    options
        .and_then(|o| o["choices"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|c| {
            c.as_str()
                .or_else(|| c["value"].as_str())
                .map(str::to_owned)
        })
        .collect()
}

/// This deployment's entities and attributes, from the live registry.
pub(crate) fn targets(state: &EngineState) -> Vec<TargetEntity> {
    let registry = state.entities.load();
    let mut out: Vec<TargetEntity> = registry
        .iter()
        .map(|m| TargetEntity {
            logicalname: m.logicalname.clone(),
            attributes: m
                .attrs
                .iter()
                .map(|a| TargetAttribute {
                    logicalname: a.logicalname.clone(),
                    field_type: FieldType::from_int(a.field_type_int)
                        .map_or("text", |t| t.as_str())
                        .to_owned(),
                    choices: choices_of(a.options.as_ref()),
                })
                .collect(),
        })
        .collect();
    out.sort_by(|a, b| a.logicalname.cmp(&b.logicalname));
    out
}

async fn project_exists(state: &EngineState, id: Uuid) -> Result<(), AppError> {
    let found: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM migration_project WHERE id = $1 AND is_deleted = false)",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if found {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

fn doc(state: &EngineState, project_id: Uuid, row: MappingRow) -> Result<MappingDoc, AppError> {
    let source_model: SourceModel = serde_json::from_value(row.source_model)
        .map_err(|e| AppError::internal(format!("a stored source model does not decode: {e}")))?;
    let mapping: ModelMapping = serde_json::from_value(row.mapping)
        .map_err(|e| AppError::internal(format!("a stored mapping does not decode: {e}")))?;
    let problems = migration_mapping::validate_mapping(&mapping, &targets(state));
    Ok(MappingDoc {
        project_id,
        row_version: row.row_version,
        source_model,
        mapping,
        problems,
        updated_at: row.updated_at,
    })
}

async fn audit(
    state: &EngineState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor: Uuid,
    operation: attome_audit::AuditOperation,
    project_id: Uuid,
    name: &'static str,
) -> Result<(), AppError> {
    attome_audit::security::write_security_event(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            operation,
            actor,
            "migration_model_mapping",
            Some(project_id),
        )
        .named(name),
    )
    .await
    .map(|_| ())
}

/// Draft a model mapping
///
/// Proposes the mapping of a source model onto this deployment's entities
/// and stores it as the project's mapping, replacing an earlier one.
/// Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/migration-projects/{id}/model-mapping/draft",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    request_body = DraftBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The drafted mapping", body = MappingDoc),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn draft_model_mapping(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<DraftBody>,
) -> Result<Json<MappingDoc>, AppError> {
    project_exists(&state, id).await?;
    if body.source_model.entities.is_empty() {
        return Err(AppError::Validation(
            "source_model.entities must not be empty".into(),
        ));
    }
    if body.source_model.entities.len() > MAX_SOURCE_ENTITIES {
        return Err(AppError::Validation(format!(
            "source_model holds more than {MAX_SOURCE_ENTITIES} entities"
        )));
    }
    let mut mapping = migration_mapping::draft_mapping(&body.source_model, &targets(&state));
    // The source's people, matched to accounts here by email.
    let accounts: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, email FROM user_account WHERE is_active IS NOT FALSE AND email IS NOT NULL",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let accounts: Vec<(String, String)> = accounts
        .into_iter()
        .filter_map(|(id, email)| Some((id.to_string(), email?)))
        .collect();
    mapping.users = migration_mapping::draft_users(&body.source_model.users, &accounts);
    let source_json = serde_json::to_value(&body.source_model).map_err(AppError::internal)?;
    let mapping_json = serde_json::to_value(&mapping).map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: MappingRow = sqlx::query_as(
        "INSERT INTO migration_model_mapping (project_id, source_model, mapping, updated_by) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (project_id) DO UPDATE SET source_model = EXCLUDED.source_model, \
             mapping = EXCLUDED.mapping, row_version = migration_model_mapping.row_version + 1, \
             updated_by = EXCLUDED.updated_by, updated_at = now() \
         RETURNING source_model, mapping, row_version, updated_at",
    )
    .bind(id)
    .bind(&source_json)
    .bind(&mapping_json)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit(
        &state,
        &mut tx,
        ctx.user_id,
        attome_audit::AuditOperation::Create,
        id,
        "migration_model_mapping.draft",
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(doc(&state, id, row)?))
}

/// A project's model mapping
///
/// The project's model mapping and what in it cannot run now.
/// Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/migration-projects/{id}/model-mapping",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    responses(
        (status = 200, description = "The mapping", body = MappingDoc),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project, or no mapping drafted yet", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_model_mapping(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<MappingDoc>, AppError> {
    project_exists(&state, id).await?;
    let row: Option<MappingRow> = sqlx::query_as(
        "SELECT source_model, mapping, row_version, updated_at \
         FROM migration_model_mapping WHERE project_id = $1",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    Ok(Json(doc(&state, id, row)?))
}

/// Save a model mapping
///
/// Saves the person's edits to the project's mapping. Refused with 409 when
/// the mapping changed since `row_version`. A mapping that cannot run yet
/// is saved too; its problems come back with it. Administrators only.
/// Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/migration-projects/{id}/model-mapping",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    request_body = SaveBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The saved mapping", body = MappingDoc),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project, or no mapping drafted yet", body = ErrorResponse),
        (status = 409, description = "Saved by someone else since `row_version`", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn save_model_mapping(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<SaveBody>,
) -> Result<Json<MappingDoc>, AppError> {
    project_exists(&state, id).await?;
    if body.mapping.entities.len() > MAX_SOURCE_ENTITIES {
        return Err(AppError::Validation(format!(
            "mapping holds more than {MAX_SOURCE_ENTITIES} entities"
        )));
    }
    let mapping_json = serde_json::to_value(&body.mapping).map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<MappingRow> = sqlx::query_as(
        "UPDATE migration_model_mapping SET mapping = $2, row_version = row_version + 1, \
             updated_by = $4, updated_at = now() \
         WHERE project_id = $1 AND row_version = $3 \
         RETURNING source_model, mapping, row_version, updated_at",
    )
    .bind(id)
    .bind(&mapping_json)
    .bind(body.row_version)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM migration_model_mapping WHERE project_id = $1)",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::VersionConflict
        } else {
            AppError::NotFound
        });
    };
    audit(
        &state,
        &mut tx,
        ctx.user_id,
        attome_audit::AuditOperation::Update,
        id,
        "migration_model_mapping.save",
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(doc(&state, id, row)?))
}

/// Describe a migration source
///
/// Reads the model of the source system named by `system` (its entities and
/// fields, with each field's Attome type), to draft a mapping from. Writes
/// nothing. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/migration-projects/{id}/source-model",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    request_body = DescribeBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "reads the source system's model; writes nothing"
    )))),
    responses(
        (status = 200, description = "The source's model", body = DescribedSource),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project or system", body = ErrorResponse),
        (status = 422, description = "The system is not a migration source, or the source refused", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn describe_source(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<DescribeBody>,
) -> Result<Json<DescribedSource>, AppError> {
    project_exists(&state, id).await?;
    let system = body.system.trim();
    if system.is_empty() {
        return Err(AppError::Validation("system must not be empty".into()));
    }
    let (kind, source_model) =
        attome_integration::connector::adapters::migration_connect::describe_named(&state, system)
            .await?;
    Ok(Json(DescribedSource {
        kind: kind.as_str().to_owned(),
        source_model,
    }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/migration-projects/{id}/source-model",
            post(describe_source),
        )
        .route(
            "/api/v1/admin/migration-projects/{id}/model-mapping",
            get(get_model_mapping).put(save_model_mapping),
        )
        .route(
            "/api/v1/admin/migration-projects/{id}/model-mapping/draft",
            post(draft_model_mapping),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    draft_model_mapping,
    get_model_mapping,
    save_model_mapping,
    describe_source
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_choices_read_strings_and_value_objects() {
        let options = serde_json::json!({ "choices": ["a", { "value": "b", "label": "B" }, 3] });
        assert_eq!(choices_of(Some(&options)), ["a", "b"]);
        assert!(choices_of(None).is_empty());
    }
}

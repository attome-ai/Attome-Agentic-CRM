//! A27-T3: changing a record's type, with a preview.
//!
//! `POST /api/v1/{entity}/{id}/change-type?preview=true` changes nothing and
//! says what would happen: the attributes that hold a value the new type's
//! form does not show, and the stage a record of the new type starts in.
//! Without `preview` it applies the change through the ordinary update path
//! (row version, field rules, audit), clearing only the attributes the
//! caller names in `clear`, each of which must be one the preview lists. The
//! caller's roles must be allowed the new type (A27-T2). The stage itself is
//! not moved: that stays with the state model's own transitions.

use std::collections::HashSet;

use attome_auth::SessionClaims;
use attome_core::{EngineState, quote_ident};
use attome_metadata::provision::record_type::{
    ATTRIBUTE, decide_create, form_attributes, initial_stage, published_types,
};
use attome_security::record_action::Update;
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::access::require_record_read;
use super::resolve::resolve_entity;
use super::timeline::readable_attr;

#[derive(Debug, Deserialize, IntoParams)]
pub(super) struct ChangeTypeQuery {
    /// True: change nothing and answer what the change would do.
    #[serde(default)]
    preview: bool,
}

/// A record type change.
#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct RecordTypeChangeBody {
    /// The new type's code.
    record_type: String,
    /// Attributes to clear; each must be one the preview lists.
    #[serde(default)]
    clear: Vec<String>,
    /// The record's row version; required to apply the change.
    #[serde(default)]
    row_version: Option<i64>,
}

/// The stage a record of the new type starts in.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordTypeStage {
    pub state_model: Uuid,
    /// The attribute that holds the record's state.
    pub state_field: String,
    pub initial_state: String,
}

/// What a type change does, or did.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecordTypeChange {
    /// The record's type now (`null`: the entity's default type).
    pub from: Option<String>,
    pub to: String,
    /// Attributes holding a value that the new type's form does not show.
    pub invalid_attributes: Vec<String>,
    pub target_stage: Option<RecordTypeStage>,
    /// False for a preview.
    pub applied: bool,
    pub cleared: Vec<String>,
    /// The record's row version after the change.
    pub row_version: Option<i64>,
}

/// Changes a record's type.
///
/// With `preview=true` nothing changes: the answer lists the attributes
/// holding a value the new type's form does not show and the stage a record
/// of the new type starts in. Otherwise the type changes through the
/// ordinary update (row version required), clearing the attributes named in
/// `clear`.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/change-type",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record's id"),
        ChangeTypeQuery,
    ),
    request_body = RecordTypeChangeBody,
    responses(
        (status = 200, description = "What the change does, or did", body = RecordTypeChange),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller's roles may not use the new type", body = ErrorResponse),
        (status = 404, description = "No such record", body = ErrorResponse),
        (status = 409, description = "The record changed since row_version", body = ErrorResponse),
        (status = 422, description = "Unknown type, no row_version, or a cleared attribute the preview does not list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
pub(super) async fn change_type(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Extension(claims): Extension<SessionClaims>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Query(query): Query<ChangeTypeQuery>,
    Json(body): Json<RecordTypeChangeBody>,
) -> Result<Json<RecordTypeChange>, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(&state, &entity_input).await?;
    if !attrs.iter().any(|a| a.logicalname == ATTRIBUTE) {
        return Err(AppError::Validation(
            "this entity has no record types".into(),
        ));
    }
    require_record_read(&state, &ctx, entity_id, &entity_name, record_id).await?;
    let db = &state.base.db;
    let types = published_types(db, entity_id).await?;
    let code = body.record_type.trim();
    let target = decide_create(&types, Some(code), ctx.role_ids.as_deref())?
        .ok_or_else(|| AppError::Validation("this entity has no record types".into()))?;

    let row: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT row_to_json(t) FROM {} t WHERE id = $1 AND is_active = true",
        quote_ident(&entity_name)
    ))
    .bind(record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    let from = row
        .get(ATTRIBUTE)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(str::to_owned);

    let shown: Option<HashSet<String>> = match target.form {
        Some(form) => form_attributes(db, form).await?,
        None => None,
    };
    let invalid_attributes: Vec<String> = match &shown {
        None => Vec::new(),
        Some(on_form) => attrs
            .iter()
            .filter(|a| a.logicalname != ATTRIBUTE && !on_form.contains(&a.logicalname))
            .filter(|a| readable_attr(&ctx, &entity_name, &attrs, &a.logicalname).is_some())
            .filter(|a| row.get(&a.logicalname).is_some_and(|v| !v.is_null()))
            .map(|a| a.logicalname.clone())
            .collect(),
    };
    let target_stage = match target.state_model {
        Some(model) => {
            initial_stage(db, model)
                .await?
                .map(
                    |(state_model, state_field, initial_state)| RecordTypeStage {
                        state_model,
                        state_field,
                        initial_state,
                    },
                )
        }
        None => None,
    };

    let mut outcome = RecordTypeChange {
        from,
        to: target.code.clone(),
        invalid_attributes,
        target_stage,
        applied: false,
        cleared: Vec::new(),
        row_version: None,
    };
    if query.preview {
        return Ok(Json(outcome));
    }

    let version = body.row_version.ok_or_else(|| {
        AppError::Validation("row_version is required to change a record's type".into())
    })?;
    if let Some(unknown) = body
        .clear
        .iter()
        .find(|name| !outcome.invalid_attributes.contains(name))
    {
        return Err(AppError::Validation(format!(
            "`{unknown}` is not a value the new type leaves out"
        )));
    }
    let mut update = Map::new();
    update.insert(ATTRIBUTE.to_owned(), Value::String(target.code.clone()));
    for name in &body.clear {
        update.insert(name.clone(), Value::Null);
    }
    let updated = super::mutations::update_record_for(
        &state,
        &ctx,
        claims.sub,
        &entity_input,
        record_id,
        version,
        Value::Object(update),
    )
    .await?;
    outcome.applied = true;
    outcome.cleared = body.clear;
    outcome.row_version = Some(updated.row_version());
    Ok(Json(outcome))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(change_type),
    components(schemas(RecordTypeChangeBody, RecordTypeChange, RecordTypeStage))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

//! `POST /api/v1/{entity}/{id}/clone` (roadmap B7-T1/B7-T2, the record
//! itself): a new record with the source's values, through the ordinary
//! create path, so validation, rules, defaults, autonumbers and audit all
//! run as for any create.
//!
//! What is not copied: system columns (id, owner, timestamps, version),
//! autonumbered fields (the new record gets its own number), files and
//! images (a copy would share the stored object), formulas (recomputed), and
//! fields an engine owns. `overrides` replaces any copied value; `preview`
//! returns the body without creating anything.

use std::collections::HashSet;

use attome_core::{EngineState, FieldType};
use attome_security::record_action::Read;
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use super::resolve::resolve_entity;

/// Columns the system sets on every record.
const SYSTEM_FIELDS: &[&str] = &[
    "id",
    "created_at",
    "created_by",
    "modified_at",
    "modified_by",
    "row_version",
    "is_active",
    "owner_ref",
    "owner_type",
    "organization_ref",
];

/// `POST /api/v1/{entity}/{id}/clone`.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CloneRequest {
    /// Values for the copy that replace the source's, by field.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub overrides: Map<String, Value>,
    /// Return the copy's body without creating it.
    #[serde(default)]
    pub preview: bool,
}

/// What a clone made, or would make.
#[derive(Debug, Serialize, ToSchema)]
pub struct CloneResult {
    /// The new record's id; absent for a preview.
    pub id: Option<Uuid>,
    /// The body sent to the create path.
    #[schema(value_type = Object)]
    pub body: Map<String, Value>,
    /// Fields of the source left out of the copy, and why.
    pub left_out: Vec<String>,
}

/// The body a copy of `data` is created from: the copyable fields, then the
/// overrides (known fields only).
pub fn copy_body(
    attrs: &[attome_core::AttrInfo],
    data: &Map<String, Value>,
    numbered: &HashSet<String>,
    engine_owned: impl Fn(&str) -> bool,
    overrides: &Map<String, Value>,
) -> (Map<String, Value>, Vec<String>) {
    let mut body = Map::new();
    let mut left_out = Vec::new();
    for attr in attrs {
        let name = attr.logicalname.as_str();
        let Some(value) = data.get(name) else {
            continue;
        };
        let reason = if SYSTEM_FIELDS.contains(&name) {
            None
        } else if numbered.contains(name) {
            Some("numbered automatically")
        } else if matches!(attr.storage_type(), FieldType::File | FieldType::Image) {
            Some("a file is not copied")
        } else if attr.field_type() == FieldType::Formula {
            Some("computed")
        } else if attr.is_write_restricted || engine_owned(name) {
            Some("set by the system")
        } else {
            body.insert(name.to_owned(), value.clone());
            continue;
        };
        if let Some(reason) = reason
            && !value.is_null()
        {
            left_out.push(format!("{name}: {reason}"));
        }
    }
    for (name, value) in overrides {
        if attrs.iter().any(|a| &a.logicalname == name) && !SYSTEM_FIELDS.contains(&name.as_str()) {
            body.insert(name.clone(), value.clone());
        }
    }
    (body, left_out)
}

/// Copies one record the caller can read into a new one they create.
pub async fn clone_record(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    request: &CloneRequest,
) -> Result<CloneResult, AppError> {
    let source = super::read_record(state, ctx, entity_input, record_id).await?;
    let data = source.data().as_object().cloned().unwrap_or_default();
    let (_, entity, attrs, _) = resolve_entity(state, entity_input).await?;
    let numbered: HashSet<String> =
        attome_metadata::autovalue::numbered_fields(&state.base.db, &entity)
            .await?
            .into_iter()
            .collect();
    let engine = state.engine_managed_fields.clone();
    let (body, left_out) = copy_body(
        &attrs,
        &data,
        &numbered,
        |field| engine.contains(&(entity.clone(), field.to_owned())),
        &request.overrides,
    );
    if request.preview {
        return Ok(CloneResult {
            id: None,
            body,
            left_out,
        });
    }
    let (id, _) = super::create_record_for(
        state,
        ctx,
        ctx.user_id,
        &entity,
        Value::Object(body.clone()),
    )
    .await?;
    Ok(CloneResult {
        id: Some(id),
        body,
        left_out,
    })
}

/// B7-T2: copies a record: the new record starts with the source's values
/// (less system, numbered, file, formula and engine-owned fields), with
/// `overrides` applied, through the ordinary create. `preview` creates
/// nothing.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/clone",
    tag = "entity",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    request_body = CloneRequest,
    responses(
        (status = 201, description = "The copy was created", body = CloneResult),
        (status = 200, description = "A preview: nothing was created", body = CloneResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read the source or create records", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
        (status = 422, description = "The copy failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn clone_record_route(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity, id)): Path<(String, Uuid)>,
    Json(request): Json<CloneRequest>,
) -> Result<(StatusCode, Json<CloneResult>), AppError> {
    let result = clone_record(&state, &ctx, &entity, id, &request).await?;
    let status = if result.id.is_some() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(result)))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(clone_record_route))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::meta_registry::{DataClassification, OnTargetDelete};
    use serde_json::json;

    fn attr(name: &str, field_type_int: i32) -> attome_core::AttrInfo {
        attome_core::AttrInfo {
            logicalname: name.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            options: None,
        }
    }

    #[test]
    fn a_copy_leaves_out_system_numbered_and_file_fields() {
        let file = 12; // FieldType::File
        let attrs = vec![
            attr("id", 0),
            attr("name", 0),
            attr("number", 0),
            attr("contract", file),
            attr("status", 0),
        ];
        let data = json!({
            "id": "x", "name": "Acme", "number": "INV-0001",
            "contract": "files/a.pdf", "status": "open"
        });
        let numbered: HashSet<String> = ["number".to_owned()].into();
        let overrides = json!({"name": "Acme (copy)", "id": "evil", "nope": 1});
        let (body, left_out) = copy_body(
            &attrs,
            data.as_object().unwrap(),
            &numbered,
            |f| f == "status",
            overrides.as_object().unwrap(),
        );
        assert_eq!(body, *json!({"name": "Acme (copy)"}).as_object().unwrap());
        assert_eq!(left_out.len(), 3, "{left_out:?}");
        assert!(left_out.iter().any(|l| l.starts_with("number:")));
    }
}

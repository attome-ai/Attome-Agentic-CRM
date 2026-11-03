//! A1-T7: the "free on creation" set — `POST /api/v1/admin/entities/{entity_id}/scaffold`.
//!
//! What an entity gets once its fields are in, so a builder starts from
//! working screens:
//!
//! - **a main form** saved as a draft (`<entity>_main`,
//!   `attome_model::kinds::form::scaffold_form`): the primary name, the
//!   required fields and the lookups first, the rest in lazily loaded tabs of
//!   12; a person edits and publishes it;
//! - **list views**: the Active and Inactive views every entity is made with
//!   (`provision::ensure_entity_list_views`), and a **kanban view** grouped by
//!   the entity's status choice when it has one (`status`, `state`, `stage`
//!   or a name ending in `_status` or `_stage`), created through the view
//!   route's own recorded path;
//! - **the import template's columns**: the fields an import fills, the key
//!   fields first, system columns left out;
//! - **a digest entry**: the entity's fields, types and lookups, for an agent
//!   or a person reading the model;
//! - **access**: nothing is exposed until granted. No role holds the new
//!   entity's privileges, so every role's row for it denies until someone
//!   grants it; the answer counts those roles.
//!
//! Each piece already there (a form of that name, a kanban view) is left as
//! it is, so the route can run again after more fields are added. In a
//! Develop workspace (T5) the drafts and the recorded view land in the
//! workspace and its changeset. Data-model area; the form and view writes
//! are audited as configuration changes.

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_core::changeset::RecordingCtx;
use attome_model::kinds::form::{MAX_FIELDS, ScaffoldField, scaffold_form};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The field type code of a choice (`attome_core::FieldType::Choice`).
const CHOICE: i32 = 7;

/// What a scaffold made or found.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScaffoldReport {
    pub entity: String,
    /// The main form's draft object.
    pub form_id: Uuid,
    /// `false` when a form of that name was already there.
    pub form_created: bool,
    /// The kanban view, when the entity has a status choice.
    pub kanban_view_id: Option<Uuid>,
    pub kanban_view_created: bool,
    /// The columns an import of this entity fills, in order.
    pub import_template: Vec<String>,
    /// The entity as the model digest lists it.
    #[schema(value_type = Object)]
    pub digest: Value,
    /// Roles with no access to the entity yet (every role, until granted).
    pub roles_without_access: i64,
}

#[derive(sqlx::FromRow)]
struct FieldRow {
    id: Uuid,
    logicalname: String,
    name: Option<String>,
    field_type: i32,
    required: bool,
    lookup_target: Option<String>,
}

/// The status choice a kanban view groups by, when there is one. Pure.
fn status_field(fields: &[(String, i32)]) -> Option<&str> {
    let named = |name: &str| {
        matches!(name, "status" | "state" | "stage" | "status_code")
            || name.ends_with("_status")
            || name.ends_with("_stage")
    };
    fields
        .iter()
        .find(|(name, kind)| *kind == CHOICE && named(name))
        .map(|(name, _)| name.as_str())
}

/// The import template's columns: the key fields first (as the form places
/// them), then the rest, system columns left out. Pure.
fn import_columns(primary: Option<&str>, fields: &[(String, bool)]) -> Vec<String> {
    let system = |name: &str| attome_core::ALL_SYSTEM_COLS.contains(&name);
    let mut out: Vec<String> = Vec::new();
    if let Some(p) = primary
        && fields.iter().any(|(name, _)| name == p)
    {
        out.push(p.to_owned());
    }
    let required = fields.iter().filter(|(_, r)| *r);
    let optional = fields.iter().filter(|(_, r)| !*r);
    for (name, _) in required.chain(optional) {
        if !system(name) && !out.contains(name) {
            out.push(name.clone());
        }
    }
    out
}

/// Make an entity's starting set
///
/// Saves a draft main form, adds a kanban view when the entity has a status
/// choice, and returns the import template's columns and the entity's digest
/// entry. A piece already there is left as it is. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/scaffold",
    operation_id = "scaffold_entity",
    tag = "admin",
    params(("entity_id" = Uuid, Path, description = "The entity")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Made or found", body = ScaffoldReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 409, description = "changeset_required or another changeset refusal", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn scaffold_entity(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    recording: RecordingCtx,
    Path(entity_id): Path<Uuid>,
) -> Result<Json<ScaffoldReport>, AppError> {
    let entity: (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT logicalname::text, name::text, primary_name_attribute::text FROM entity_info \
          WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(entity_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let (logicalname, display, primary) = entity;
    let display = display.unwrap_or_else(|| logicalname.clone());
    let limit = i64::try_from(MAX_FIELDS).unwrap_or(i64::MAX);
    let fields: Vec<FieldRow> = sqlx::query_as(
        "SELECT a.id, a.logicalname::text AS logicalname, a.name::text AS name, \
                a.\"type\" AS field_type, COALESCE(a.required, false) AS required, \
                t.logicalname::text AS lookup_target \
           FROM attribute_info a LEFT JOIN entity_info t ON t.id = a.lookup_entity_ref \
          WHERE a.entity_ref = $1 AND a.is_active IS NOT FALSE \
          ORDER BY a.id LIMIT $2",
    )
    .bind(entity_id)
    .bind(limit)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let user_fields: Vec<&FieldRow> = fields
        .iter()
        .filter(|f| !attome_core::ALL_SYSTEM_COLS.contains(&f.logicalname.as_str()))
        .collect();

    // The main form, as a draft.
    let form_name = format!("{logicalname}_main");
    let existing_form: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM metadata_object WHERE kind = 'form' AND name = $1")
            .bind(&form_name)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let (form_id, form_created) = match existing_form {
        Some(id) => (id, false),
        None => {
            let placed: Vec<ScaffoldField> = user_fields
                .iter()
                .map(|f| ScaffoldField {
                    id: f.id,
                    primary: primary.as_deref() == Some(f.logicalname.as_str()),
                    required: f.required,
                    lookup: f.lookup_target.is_some(),
                })
                .collect();
            let doc = scaffold_form(entity_id, &placed);
            let id = Uuid::now_v7();
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            attome_metadata::model_edit::edit(
                &state.base.db,
                &mut tx,
                &attome_model::kinds::FormKind,
                attome_metadata::model_edit::EditRequest {
                    id,
                    base_hash: String::new(),
                    name: Some(form_name.clone()),
                    commands: vec![
                        json!({ "op": "set", "path": "/entity", "value": doc["entity"] }),
                        json!({ "op": "set", "path": "/form_kind", "value": doc["form_kind"] }),
                        json!({ "op": "set", "path": "/tabs", "value": doc["tabs"] }),
                    ],
                },
                Some(ctx.user_id),
            )
            .await?;
            write_security_event(
                &mut tx,
                &audit_service(&state),
                SecurityEvent::new(
                    MandatoryCategory::Configuration,
                    AuditOperation::Create,
                    ctx.user_id,
                    "metadata_object",
                    Some(id),
                )
                .named("entity.scaffold")
                .comment(format!("main form draft `{form_name}` for {logicalname}")),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            (id, true)
        }
    };

    // A kanban view over the status choice, through the view route's path.
    let choices: Vec<(String, i32)> = user_fields
        .iter()
        .map(|f| (f.logicalname.clone(), f.field_type))
        .collect();
    let (kanban_view_id, kanban_view_created) = match status_field(&choices) {
        None => (None, false),
        Some(state_field) => {
            let existing: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM view WHERE entity_logical_name = $1 AND kind = 'kanban' \
                   AND is_active = true LIMIT 1",
            )
            .bind(entity_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            match existing {
                Some(id) => (Some(id), false),
                None => {
                    let base: Option<(Uuid, Value)> = sqlx::query_as(
                        "SELECT sql_query_ref, table_definition FROM view \
                          WHERE entity_logical_name = $1 AND is_default = true LIMIT 1",
                    )
                    .bind(entity_id)
                    .fetch_optional(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    let (query, table_definition) = base.ok_or_else(|| {
                        AppError::internal(format!("{logicalname} has no default list view"))
                    })?;
                    let body: crate::view_admin::ViewBody = serde_json::from_value(json!({
                        "name": format!("{display} board"),
                        "entity_logical_name": entity_id,
                        "sql_query_ref": query,
                        "table_definition": table_definition,
                        "kind": "kanban",
                        "view_metadata": { "state_field": state_field },
                    }))
                    .map_err(AppError::internal)?;
                    crate::view_admin::check_new_view(&state, &body)?;
                    let row =
                        crate::view_admin::create_recorded(&state, ctx.user_id, &recording, &body)
                            .await?;
                    (Some(row.id), true)
                }
            }
        }
    };

    let import_template = import_columns(
        primary.as_deref(),
        &user_fields
            .iter()
            .map(|f| (f.logicalname.clone(), f.required))
            .collect::<Vec<_>>(),
    );
    let digest = json!({
        "entity": logicalname,
        "label": display,
        "primary_name": primary,
        "fields": user_fields.iter().map(|f| json!({
            "name": f.logicalname,
            "label": f.name,
            "type": attome_core::FieldType::from_int(f.field_type)
                .map_or("text", |t| t.as_str()),
            "required": f.required,
            "lookup": f.lookup_target,
        })).collect::<Vec<_>>(),
    });
    let roles_without_access: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role r WHERE NOT EXISTS ( \
             SELECT 1 FROM role_mm_privilege rp JOIN privilege p ON p.id = rp.privilege_ref \
              WHERE rp.role_ref = r.id AND p.key LIKE $1)",
    )
    .bind(format!("{logicalname}.%"))
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(ScaffoldReport {
        entity: logicalname,
        form_id,
        form_created,
        kanban_view_id,
        kanban_view_created,
        import_template,
        digest,
        roles_without_access,
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/entities/{entity_id}/scaffold",
        post(scaffold_entity),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(scaffold_entity), components(schemas(ScaffoldReport)))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_choice_gets_a_kanban_view() {
        let fields = vec![
            ("subject".to_owned(), 3),
            ("status".to_owned(), 3),
            ("deal_stage".to_owned(), CHOICE),
        ];
        // A text `status` is not a choice; `deal_stage` is.
        assert_eq!(status_field(&fields), Some("deal_stage"));
        assert_eq!(status_field(&[("subject".to_owned(), CHOICE)]), None);
    }

    #[test]
    fn the_import_template_puts_key_fields_first() {
        let fields = vec![
            ("notes".to_owned(), false),
            ("code".to_owned(), true),
            ("title".to_owned(), false),
            ("created_at".to_owned(), false),
        ];
        assert_eq!(
            import_columns(Some("title"), &fields),
            vec!["title", "code", "notes"]
        );
    }
}

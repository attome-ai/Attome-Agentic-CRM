//! Using record templates (roadmap B8-T2; the `record_template` kind is
//! B8-T1's).
//!
//! - `POST /api/v1/record-templates/{id}/create` creates a record from a
//!   published template, with the person's answers to its prompts, and the
//!   child records its child templates describe, each linked to the new
//!   record. Everything goes through the ordinary create path.
//! - `POST /api/v1/record-templates/{id}/apply` fills records already there:
//!   only fields that are empty, unless `overwrite`. One record is updated
//!   now; more are handed to the bulk job (`attome_records::bulk`), which
//!   tracks progress and audits each record.
//! - `POST /api/v1/record-templates/from-record` saves a record's values as
//!   a new draft template, published like any metadata.
//! - `GET /api/v1/record-templates?entity=&type=&stage=` (B8-T3) lists the
//!   published templates of an entity the caller may create records of,
//!   offered only when their `when` condition holds for the record's type
//!   and stage and the caller's role names (`roles`), with the prompts the
//!   New dialog asks.
//!
//! A template's expression values are V2 rule text evaluated with no record
//! context (`today() + 30`); its attributes are named by id and resolved
//! here against the entity's live attributes.

use std::sync::Arc;

use attome_audit::AuditOperation;
use attome_audit::audit_service;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::{EngineState, FieldType};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, SelfService, area};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most records one apply request fills.
pub const MAX_APPLY: usize = 1_000;

/// The most child records one create makes.
const MAX_CHILDREN: usize = 20;

/// Field types a template never sets: they hold files or are computed.
const UNSETTABLE: [FieldType; 4] = [
    FieldType::File,
    FieldType::Image,
    FieldType::Formula,
    FieldType::Rollup,
];

/// Columns every record has, which a saved template leaves out.
const SYSTEM_FIELDS: [&str; 10] = [
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

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct CreateFromTemplate {
    /// Answers to the template's prompts, by field name.
    #[serde(default)]
    #[schema(value_type = Object)]
    pub answers: Map<String, Value>,
}

/// One record a template created.
#[derive(Debug, Serialize, ToSchema)]
pub struct TemplateRecord {
    pub entity: String,
    pub id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedFromTemplate {
    pub entity: String,
    pub id: Uuid,
    /// The child records created with it.
    pub children: Vec<TemplateRecord>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ApplyTemplate {
    /// The records to fill, 1 to 1,000, all of the template's entity.
    pub ids: Vec<Uuid>,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub answers: Map<String, Value>,
    /// Replace values already set; otherwise only empty fields are filled.
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AppliedTemplate {
    /// For one record: the fields it filled.
    pub filled: Vec<String>,
    /// For several: the bulk operation filling them (`GET /api/v1/{entity}/bulk/{id}`).
    pub bulk_operation_id: Option<Uuid>,
    /// Records the request changes (one record whose fields were all set
    /// already changes none).
    pub total: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SaveAsTemplate {
    /// The record's entity (its logical name).
    pub entity: String,
    pub id: Uuid,
    /// The new template's name.
    pub name: String,
    pub label_en: String,
    #[serde(default)]
    pub label_ar: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SavedTemplate {
    /// The new draft template.
    pub id: Uuid,
    pub name: String,
    /// The fields it fixes.
    pub values: usize,
}

/// The published template `id`.
fn template(id: Uuid) -> Result<Arc<Value>, AppError> {
    crate::model_admin::cooked()
        .get::<Value>("record_template", &format!("record_template:{id}"))
        .ok_or(AppError::NotFound)
}

fn uuid_at(value: &Value) -> Option<Uuid> {
    value.as_str().and_then(|s| Uuid::parse_str(s).ok())
}

/// One live attribute of an entity: id, name and type.
struct Attr {
    id: Uuid,
    name: String,
    field_type: FieldType,
}

/// The entity `entity_id`'s name and live attributes.
async fn entity_attrs(
    state: &EngineState,
    entity_id: Uuid,
) -> Result<(String, Vec<Attr>), AppError> {
    let entity = state
        .entities
        .load()
        .get_by_id(entity_id)
        .map(|meta| meta.logicalname.clone())
        .ok_or_else(|| AppError::Validation("the template's entity no longer exists".into()))?;
    let rows: Vec<(Uuid, String, i32)> = sqlx::query_as(
        r#"SELECT id, logicalname, "type" FROM attribute_info
            WHERE entity_ref = $1 AND (is_active IS NULL OR is_active = true)"#,
    )
    .bind(entity_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let attrs = rows
        .into_iter()
        .map(|(id, name, code)| Attr {
            id,
            name,
            field_type: FieldType::from_int(code).unwrap_or(FieldType::Text),
        })
        .collect();
    Ok((entity, attrs))
}

/// What a template sets on a record of its entity.
struct Resolved {
    entity: String,
    values: Map<String, Value>,
    /// Child templates and the lookup id that points back at the record.
    children: Vec<(Uuid, Uuid)>,
}

/// One template value as JSON: fixed, an evaluated expression, or the
/// person's answer (by field name or attribute id).
fn template_value(
    spec: &Value,
    attr: &Attr,
    answers: &Map<String, Value>,
) -> Result<Option<Value>, AppError> {
    if let Some(fixed) = spec.get("fixed") {
        return Ok(Some(fixed.clone()));
    }
    if let Some(src) = spec.get("expression").and_then(Value::as_str) {
        let compiled = attome_rules::compile_versioned(
            src,
            &attome_rules::Schema::new(),
            attome_rules::LanguageVersion::V2,
            attome_rules::Budgets::default(),
        )
        .map_err(|e| AppError::Validation(format!("{}: {e}", attr.name)))?;
        let value = compiled
            .eval(&attome_rules::Context::new(chrono::Utc::now()))
            .map_err(|e| AppError::Validation(format!("{}: {e}", attr.name)))?;
        return Ok(Some(attome_records::rule_engine::json_from_rules_value(
            &value,
        )));
    }
    if let Some(prompt) = spec.get("prompt") {
        let answer = answers
            .get(&attr.name)
            .or_else(|| answers.get(&attr.id.to_string()))
            .filter(|v| !v.is_null());
        return match answer {
            Some(v) => Ok(Some(v.clone())),
            None if prompt["required"].as_bool().unwrap_or(false) => Err(AppError::Validation(
                format!("{} needs an answer", attr.name),
            )),
            None => Ok(None),
        };
    }
    Ok(None)
}

/// The values `doc` sets, by field name.
async fn resolve(
    state: &EngineState,
    doc: &Value,
    answers: &Map<String, Value>,
) -> Result<Resolved, AppError> {
    let entity_id = uuid_at(&doc["entity"])
        .ok_or_else(|| AppError::Validation("the template names no entity".into()))?;
    let (entity, attrs) = entity_attrs(state, entity_id).await?;
    let mut values = Map::new();
    for spec in doc["values"].as_array().into_iter().flatten() {
        let attr = uuid_at(&spec["attribute"])
            .and_then(|id| attrs.iter().find(|a| a.id == id))
            .ok_or_else(|| {
                AppError::Validation("the template sets a field that no longer exists".into())
            })?;
        if UNSETTABLE.contains(&attr.field_type) {
            continue;
        }
        if let Some(value) = template_value(spec, attr, answers)? {
            values.insert(attr.name.clone(), value);
        }
    }
    let children = doc["children"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| Some((uuid_at(&c["template"])?, uuid_at(&c["link"])?)))
        .take(MAX_CHILDREN)
        .collect();
    Ok(Resolved {
        entity,
        values,
        children,
    })
}

/// Create a record from a template
///
/// Creates a record of the template's entity with the template's values and
/// the person's answers, and the child records its child templates
/// describe, each linked back to it. Needs the create privilege on every
/// entity it writes.
#[utoipa::path(
    post,
    path = "/api/v1/record-templates/{id}/create",
    operation_id = "create_from_record_template",
    tag = "entity",
    params(("id" = Uuid, Path, description = "The published template")),
    request_body = CreateFromTemplate,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The record and its children", body = CreatedFromTemplate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller cannot create records of an entity the template writes", body = ErrorResponse),
        (status = 404, description = "No such published template", body = ErrorResponse),
        (status = 422, description = "A required answer is missing, the template names a field that is gone, or a record fails validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_from_template(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateFromTemplate>,
) -> Result<(StatusCode, Json<CreatedFromTemplate>), AppError> {
    let doc = template(id)?;
    let resolved = resolve(&state, &doc, &body.answers).await?;
    // Every child template resolves before anything is written.
    let mut children = Vec::with_capacity(resolved.children.len());
    for (child_id, link) in &resolved.children {
        let child_doc = template(*child_id)?;
        let child = resolve(&state, &child_doc, &body.answers).await?;
        let child_entity_id = uuid_at(&child_doc["entity"]).unwrap_or_default();
        let (_, child_attrs) = entity_attrs(&state, child_entity_id).await?;
        let link_name = child_attrs
            .iter()
            .find(|a| a.id == *link)
            .map(|a| a.name.clone())
            .ok_or_else(|| {
                AppError::Validation("a child template links through a field that is gone".into())
            })?;
        ctx.require(&child.entity, "create")?;
        children.push((child, link_name));
    }
    ctx.require(&resolved.entity, "create")?;
    let (record_id, _) = attome_records::entity_crud::create_record_for(
        &state,
        &ctx,
        ctx.user_id,
        &resolved.entity,
        Value::Object(resolved.values),
    )
    .await?;
    let mut created = Vec::with_capacity(children.len());
    for (mut child, link_name) in children {
        child
            .values
            .insert(link_name, Value::String(record_id.to_string()));
        let (child_id, _) = attome_records::entity_crud::create_record_for(
            &state,
            &ctx,
            ctx.user_id,
            &child.entity,
            Value::Object(child.values),
        )
        .await?;
        created.push(TemplateRecord {
            entity: child.entity,
            id: child_id,
        });
    }
    Ok((
        StatusCode::CREATED,
        Json(CreatedFromTemplate {
            entity: resolved.entity,
            id: record_id,
            children: created,
        }),
    ))
}

fn is_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.trim().is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        _ => false,
    }
}

/// The part of `values` a record with `data` takes. Pure.
fn patch_for(values: &Map<String, Value>, data: &Value, overwrite: bool) -> Map<String, Value> {
    values
        .iter()
        .filter(|(name, _)| overwrite || is_empty(data.get(name.as_str())))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// One record's patch and the version it was read at.
async fn record_patch(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
    values: &Map<String, Value>,
    overwrite: bool,
) -> Result<(Map<String, Value>, i64), AppError> {
    let record = attome_records::entity_crud::read_record(state, ctx, entity, id).await?;
    Ok((
        patch_for(values, record.data(), overwrite),
        record.row_version(),
    ))
}

/// Apply a template to records
///
/// Fills records of the template's entity with its values: only the fields
/// that are empty, unless `overwrite`. One record is updated now; several
/// become a bulk operation that runs in the background. Needs the update
/// privilege (and `bulk` for several).
#[utoipa::path(
    post,
    path = "/api/v1/record-templates/{id}/apply",
    operation_id = "apply_record_template",
    tag = "entity",
    params(("id" = Uuid, Path, description = "The published template")),
    request_body = ApplyTemplate,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What was filled, or the bulk operation filling it", body = AppliedTemplate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller cannot update these records", body = ErrorResponse),
        (status = 404, description = "No such published template, or a record the caller cannot read", body = ErrorResponse),
        (status = 409, description = "A record changed while it was being filled", body = ErrorResponse),
        (status = 422, description = "No records or more than 1,000, a missing required answer, or a value that fails validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn apply_template(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<ApplyTemplate>,
) -> Result<Json<AppliedTemplate>, AppError> {
    if body.ids.is_empty() || body.ids.len() > MAX_APPLY {
        return Err(AppError::Validation(format!(
            "apply a template to 1 to {MAX_APPLY} records"
        )));
    }
    let doc = template(id)?;
    let resolved = resolve(&state, &doc, &body.answers).await?;
    ctx.require(&resolved.entity, "update")?;
    if let [one] = body.ids.as_slice() {
        let (patch, row_version) = record_patch(
            &state,
            &ctx,
            &resolved.entity,
            *one,
            &resolved.values,
            body.overwrite,
        )
        .await?;
        let filled: Vec<String> = patch.keys().cloned().collect();
        if !patch.is_empty() {
            attome_records::entity_crud::update_record_for(
                &state,
                &ctx,
                ctx.user_id,
                &resolved.entity,
                *one,
                row_version,
                Value::Object(patch),
            )
            .await?;
        }
        let total = usize::from(!filled.is_empty());
        return Ok(Json(AppliedTemplate {
            filled,
            bulk_operation_id: None,
            total,
        }));
    }
    let mut items = Vec::with_capacity(body.ids.len());
    for record_id in &body.ids {
        let (patch, row_version) = record_patch(
            &state,
            &ctx,
            &resolved.entity,
            *record_id,
            &resolved.values,
            body.overwrite,
        )
        .await?;
        if patch.is_empty() {
            continue;
        }
        items.push(attome_records::bulk::BulkItem {
            id: Some(*record_id),
            expected_row_version: Some(row_version),
            data: Value::Object(patch),
        });
    }
    let total = items.len();
    if items.is_empty() {
        return Ok(Json(AppliedTemplate {
            filled: Vec::new(),
            bulk_operation_id: None,
            total: 0,
        }));
    }
    let submitted = attome_records::bulk::submit_bulk(
        &state,
        &ctx,
        &resolved.entity,
        "update",
        items,
        false,
        false,
    )
    .await?;
    Ok(Json(AppliedTemplate {
        filled: Vec::new(),
        bulk_operation_id: Some(submitted.id),
        total,
    }))
}

/// Save a record as a template
///
/// Saves a record's values as a new draft record template of its entity:
/// each set field it may hold becomes a fixed value. The draft is published
/// like any metadata. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/record-templates/from-record",
    operation_id = "save_record_as_template",
    tag = "admin",
    request_body = SaveAsTemplate,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The new draft template", body = SavedTemplate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or one the caller cannot read", body = ErrorResponse),
        (status = 422, description = "A blank name or label, or the template fails validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn save_as_template(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Json(body): Json<SaveAsTemplate>,
) -> Result<(StatusCode, Json<SavedTemplate>), AppError> {
    if body.name.trim().is_empty() || body.label_en.trim().is_empty() {
        return Err(AppError::Validation(
            "a template needs a name and an English label".into(),
        ));
    }
    let record =
        attome_records::entity_crud::read_record(&state, &ctx, &body.entity, body.id).await?;
    let entity_id = state
        .entities
        .load()
        .get(&body.entity)
        .map(|meta| meta.entity_id)
        .ok_or(AppError::NotFound)?;
    let (entity, attrs) = entity_attrs(&state, entity_id).await?;
    // Numbered fields get their own number on every new record.
    let numbered = attome_metadata::autovalue::numbered_fields(&state.base.db, &entity).await?;
    let engine_owned = state.engine_managed_fields.clone();
    let values: Vec<Value> = attrs
        .iter()
        .filter(|a| !SYSTEM_FIELDS.contains(&a.name.as_str()))
        .filter(|a| !UNSETTABLE.contains(&a.field_type) && !numbered.contains(&a.name))
        .filter(|a| !engine_owned.contains(&(entity.clone(), a.name.clone())))
        .filter_map(|a| {
            let value = record.data().get(&a.name)?;
            (!is_empty(Some(value)))
                .then(|| json!({ "attribute": a.id.to_string(), "fixed": value }))
        })
        .collect();
    let count = values.len();
    let mut commands = vec![
        json!({ "op": "set", "path": "/entity", "value": entity_id.to_string() }),
        json!({ "op": "set", "path": "/label_en", "value": body.label_en.trim() }),
        json!({ "op": "set", "path": "/values", "value": values }),
    ];
    if let Some(label_ar) = body
        .label_ar
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        commands.push(json!({ "op": "set", "path": "/label_ar", "value": label_ar }));
    }
    let template_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let edited = attome_metadata::model_edit::edit(
        &state.base.db,
        &mut tx,
        &attome_model::kinds::RecordTemplateKind,
        attome_metadata::model_edit::EditRequest {
            id: template_id,
            base_hash: String::new(),
            name: Some(body.name.trim().to_owned()),
            commands,
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
            Some(template_id),
        )
        .named("record_template.from_record")
        .comment(format!(
            "record template `{}` drafted from {} {} ({count} values)",
            edited.name, body.entity, body.id
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(SavedTemplate {
            id: template_id,
            name: edited.name,
            values: count,
        }),
    ))
}

/// The list's filter: the entity and what the new record will be.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TemplateFilter {
    /// The entity's logical name.
    pub entity: String,
    /// The new record's type, for a template whose condition reads `type`.
    #[serde(default, rename = "type")]
    pub record_type: Option<String>,
    /// The new record's stage, for a template whose condition reads `stage`.
    #[serde(default)]
    pub stage: Option<String>,
}

/// One question a template asks.
#[derive(Debug, Serialize, ToSchema)]
pub struct TemplatePrompt {
    /// The field it fills.
    pub field: String,
    pub label_en: String,
    pub label_ar: Option<String>,
    pub required: bool,
}

/// One template the caller may use.
#[derive(Debug, Serialize, ToSchema)]
pub struct OfferedTemplate {
    pub id: Uuid,
    pub label_en: String,
    pub label_ar: Option<String>,
    pub prompts: Vec<TemplatePrompt>,
    /// How many child records it creates with the record.
    pub children: usize,
}

/// Whether a template's `when` holds for `input`; no condition always does.
pub fn offered(when: Option<&str>, input: &Value) -> bool {
    match when.map(str::trim).filter(|w| !w.is_empty()) {
        None => true,
        Some(src) => attome_workflow::condition::expression_holds(src, input),
    }
}

/// List record templates
///
/// B8-T3: the published templates of an entity the caller may create
/// records of, those whose condition holds for the new record's type and
/// stage and the caller's roles, each with its prompts.
#[utoipa::path(
    get,
    path = "/api/v1/record-templates",
    operation_id = "list_record_templates",
    tag = "entity",
    params(TemplateFilter),
    responses(
        (status = 200, description = "The templates offered", body = attome_types::PaginatedResponse<OfferedTemplate>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such entity, or one the caller cannot create records of", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_templates(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(filter): Query<TemplateFilter>,
) -> Result<Json<attome_types::PaginatedResponse<OfferedTemplate>>, AppError> {
    ctx.require(&filter.entity, "create")
        .map_err(|_| AppError::NotFound)?;
    let entity_id = state
        .entities
        .load()
        .get(&filter.entity)
        .map(|meta| meta.entity_id)
        .ok_or(AppError::NotFound)?;
    let role_ids = ctx.role_ids.clone().unwrap_or_default();
    let roles: Vec<String> = if role_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_scalar("SELECT name FROM role WHERE id = ANY($1) AND is_deleted = false")
            .bind(&role_ids)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
    };
    let input = json!({
        "type": filter.record_type,
        "stage": filter.stage,
        "roles": roles,
    });
    let (_, attrs) = entity_attrs(&state, entity_id).await?;
    let mut items = Vec::new();
    for (key, _) in crate::model_admin::cooked().hashes("record_template") {
        let Some(id) = key
            .strip_prefix("record_template:")
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        let Ok(doc) = template(id) else {
            continue;
        };
        if uuid_at(&doc["entity"]) != Some(entity_id) || !offered(doc["when"].as_str(), &input) {
            continue;
        }
        let prompts = doc["values"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| {
                let prompt = v.get("prompt")?;
                let attr =
                    uuid_at(&v["attribute"]).and_then(|a| attrs.iter().find(|x| x.id == a))?;
                Some(TemplatePrompt {
                    field: attr.name.clone(),
                    label_en: prompt["label_en"].as_str().unwrap_or(&attr.name).to_owned(),
                    label_ar: prompt["label_ar"].as_str().map(str::to_owned),
                    required: prompt["required"].as_bool().unwrap_or(false),
                })
            })
            .collect();
        items.push(OfferedTemplate {
            id,
            label_en: doc["label_en"].as_str().unwrap_or_default().to_owned(),
            label_ar: doc["label_ar"].as_str().map(str::to_owned),
            prompts,
            children: doc["children"].as_array().map_or(0, Vec::len),
        });
    }
    items.sort_by(|a, b| a.label_en.cmp(&b.label_en));
    let n = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(attome_types::PaginatedResponse::new(
        items,
        n,
        1,
        n.max(1),
    )))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/record-templates", get(list_templates))
        .route(
            "/api/v1/record-templates/{id}/create",
            post(create_from_template),
        )
        .route("/api/v1/record-templates/{id}/apply", post(apply_template))
        .route(
            "/api/v1/record-templates/from-record",
            post(save_as_template),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(create_from_template, apply_template, save_as_template, list_templates),
    components(schemas(
        OfferedTemplate,
        TemplatePrompt,
        CreateFromTemplate,
        CreatedFromTemplate,
        TemplateRecord,
        ApplyTemplate,
        AppliedTemplate,
        SaveAsTemplate,
        SavedTemplate
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_is_offered_when_its_condition_holds() {
        let input = json!({ "type": "renewal", "stage": null, "roles": ["Sales"] });
        assert!(offered(None, &input));
        assert!(offered(Some(" "), &input));
        assert!(offered(Some("type == \"renewal\""), &input));
        assert!(!offered(Some("type == \"new\""), &input));
        // A condition that does not compile against the input is not offered.
        assert!(!offered(Some("region == \"riyadh\""), &input));
    }

    #[test]
    fn template_apply_fills_only_empty_fields_unless_overwrite() {
        let values: Map<String, Value> = serde_json::from_value(json!({
            "terms": "Net 30", "seats": 5, "notes": "from template"
        }))
        .unwrap();
        let data = json!({ "terms": "Net 60", "seats": null, "notes": "  " });
        let patch = patch_for(&values, &data, false);
        assert_eq!(
            Value::Object(patch),
            json!({ "seats": 5, "notes": "from template" })
        );
        assert_eq!(patch_for(&values, &data, true).len(), 3);
    }
}

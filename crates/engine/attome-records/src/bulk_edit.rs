//! Bulk edit (roadmap B5-T1): change the same attributes on many records,
//! picked by id or by the view's filters, with per-attribute operations
//! (`set`, `clear`, `add`, `remove`, `increment`).
//!
//! The edit is planned here and applied by the bulk engine: the records are
//! read with the caller's read access (a record they cannot read is not
//! touched), each record's new values are computed from its current ones,
//! and the result is submitted as one bulk `update` carrying every record's
//! row version. The bulk engine then applies each record through the normal
//! update path (validation, business rules, update access, field security)
//! and reports a record that changed in between as a version conflict
//! rather than overwriting it. Per-record results come from
//! `GET /api/v1/{entity}/bulk/{id}`.

use attome_core::filter::{
    FieldCastError, Filter, FilterSchema, cast_for_attr, is_multi_choice_attr,
};
use attome_core::{AttrInfo, EngineState, FieldType, quote_ident};
use attome_security::RecordAction;
use attome_security::record_action::Bulk;
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::capability::{Available, BatchJobs};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::bulk::{BulkItem, submit_bulk};
use crate::entity_crud::{POLYMORPHIC_AUDIT_ENTITIES, POLYMORPHIC_CHILD_ENTITIES, resolve_entity};

/// The most records one bulk edit may change, the bulk engine's own cap.
pub const MAX_BULK_EDIT_RECORDS: usize = 500;
/// The most operations one bulk edit may carry.
const MAX_OPERATIONS: usize = 50;

/// What to change on the picked records.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct BulkEditRequest {
    /// The records to change, at most 500. Give `ids` or `filters`.
    #[serde(default)]
    pub ids: Vec<Uuid>,
    /// The records to change, by the same filters a list uses. At most 500
    /// may match.
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// The changes, applied in order to each record.
    pub operations: Vec<EditOperation>,
}

/// One change to one attribute.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct EditOperation {
    pub attribute: String,
    /// `set` (to `value`), `clear`, `add` or `remove` (values of a
    /// multi-select choice), `increment` (a number by `value`, may be
    /// negative).
    pub op: String,
    #[serde(default)]
    pub value: Option<Value>,
}

/// The bulk edit as submitted.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BulkEditSubmitted {
    /// The bulk operation applying the edit; follow it at
    /// `/api/v1/{entity}/bulk/{id}`. Empty when no record needed a change.
    pub id: Option<Uuid>,
    /// Records the edit will change.
    pub total: i32,
    /// Records picked that the caller can read.
    pub matched: usize,
    /// Picked records already holding the requested values.
    pub unchanged: usize,
    /// B5-T3: what to send to `POST /api/v1/{entity}/bulk-edit/undo` to put
    /// the changed records back. Kept by the caller, like a clone's undo
    /// list.
    pub undo: Vec<UndoItem>,
    /// B5-T3: set when the edit is above the approval count; it runs once
    /// that approval is given, and `id` is empty until then.
    pub approval_request_id: Option<Uuid>,
}

/// B5-T3: the approval a large bulk edit waits on.
pub const ACTION_BULK_EDIT: &str = "records.bulk_edit";

/// B5-T3: the setting holding the record count above which a bulk edit
/// needs an approval (0, the default, never asks).
pub const BULK_EDIT_APPROVAL_SETTING: &str = "records.bulk_edit_approval_count";

/// One record of a bulk edit waiting on its approval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BulkEditApprovalItem {
    pub id: Option<Uuid>,
    pub expected_row_version: Option<i64>,
    pub data: Value,
}

/// A bulk edit as stored in its approval request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BulkEditApprovalPayload {
    pub entity: String,
    pub items: Vec<BulkEditApprovalItem>,
    pub requested_by: Uuid,
}

/// The approval count, 0 when unset.
pub fn approval_count(state: &EngineState) -> usize {
    let Some(descriptor) = attome_core::setting_registry().get(BULK_EDIT_APPROVAL_SETTING) else {
        return 0;
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0)
}

/// Runs an approved bulk edit as the person who asked for it.
pub async fn do_apply_bulk_edit(
    state: &EngineState,
    payload: &BulkEditApprovalPayload,
) -> Result<crate::bulk::BulkSubmitted, AppError> {
    let ctx = state
        .base
        .security
        .resolve_strict(payload.requested_by)
        .await?;
    let items = payload
        .items
        .iter()
        .map(|i| BulkItem {
            id: i.id,
            expected_row_version: i.expected_row_version,
            data: i.data.clone(),
        })
        .collect();
    submit_bulk(state, &ctx, &payload.entity, "update", items, false).await
}

/// B5-T3: one record's values before a bulk edit, and the row version the
/// edit leaves it at.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UndoItem {
    pub id: Uuid,
    /// The record's row version once the edit has applied; an undo only
    /// reverts a record still at it.
    pub row_version: i64,
    /// The changed attributes' values before the edit.
    #[schema(value_type = Object)]
    pub values: Map<String, Value>,
}

/// B5-T3: a bulk edit to put back.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct BulkEditUndoRequest {
    /// The `undo` list the bulk edit returned.
    pub undo: Vec<UndoItem>,
}

/// B5-T2: one record as the edit would change it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PreviewRecord {
    pub id: Uuid,
    /// The changed attributes' values now.
    #[schema(value_type = Object)]
    pub before: Map<String, Value>,
    /// The same attributes after the edit.
    #[schema(value_type = Object)]
    pub after: Map<String, Value>,
}

/// B5-T2: what a bulk edit would do, without doing it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BulkEditPreview {
    /// Records picked that the caller can read.
    pub matched: usize,
    /// Records the edit would change.
    pub to_change: usize,
    /// Picked records already holding the requested values.
    pub unchanged: usize,
    /// The first 20 records the edit would change, before and after.
    pub samples: Vec<PreviewRecord>,
}

/// The planned edit: the bulk-update items and what the preview shows.
#[derive(Debug, Clone)]
pub struct BulkEditPlan {
    pub items: Vec<BulkItem>,
    pub matched: usize,
    pub unchanged: usize,
    pub samples: Vec<PreviewRecord>,
    pub undo: Vec<UndoItem>,
}

/// Records a preview shows before and after.
const PREVIEW_SAMPLES: usize = 20;

/// The kind of attribute an operation targets, for the checks and the
/// arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Number,
    MultiChoice,
    Other,
}

fn shape_of(attr: &AttrInfo) -> Shape {
    if is_multi_choice_attr(attr) {
        Shape::MultiChoice
    } else if matches!(attr.storage_type(), FieldType::Number | FieldType::Currency) {
        Shape::Number
    } else {
        Shape::Other
    }
}

/// Checks one operation against its attribute's shape.
fn check_operation(op: &EditOperation, shape: Shape) -> Result<(), AppError> {
    let needs_value = match op.op.as_str() {
        "set" => true,
        "clear" => false,
        "add" | "remove" if shape == Shape::MultiChoice => true,
        "add" | "remove" => {
            return Err(AppError::Validation(format!(
                "{}: add and remove are for a multi-select choice",
                op.attribute
            )));
        }
        "increment" if shape == Shape::Number => {
            if !op.value.as_ref().is_some_and(Value::is_number) {
                return Err(AppError::Validation(format!(
                    "{}: increment by a number",
                    op.attribute
                )));
            }
            true
        }
        "increment" => {
            return Err(AppError::Validation(format!(
                "{}: increment is for a number",
                op.attribute
            )));
        }
        other => {
            return Err(AppError::Validation(format!(
                "{}: unknown operation `{other}`; use set, clear, add, remove or increment",
                op.attribute
            )));
        }
    };
    if needs_value && op.value.is_none() {
        return Err(AppError::Validation(format!(
            "{}: {} needs a value",
            op.attribute, op.op
        )));
    }
    Ok(())
}

/// The values an `add` or `remove` names: one string or an array of them.
fn listed(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items.clone(),
        Some(item) => vec![item.clone()],
        None => Vec::new(),
    }
}

/// The value after one operation, from the current one. Checked by
/// [`check_operation`] first.
fn apply_operation(current: &Value, op: &EditOperation) -> Value {
    match op.op.as_str() {
        "set" => op.value.clone().unwrap_or(Value::Null),
        "add" => {
            let mut items = current.as_array().cloned().unwrap_or_default();
            for item in listed(op.value.as_ref()) {
                if !items.contains(&item) {
                    items.push(item);
                }
            }
            Value::Array(items)
        }
        "remove" => {
            let gone = listed(op.value.as_ref());
            let items: Vec<Value> = current
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|item| !gone.contains(item))
                .collect();
            Value::Array(items)
        }
        "increment" => {
            let by = op.value.as_ref().unwrap_or(&Value::Null);
            match (
                current.as_i64().or(current.is_null().then_some(0)),
                by.as_i64(),
            ) {
                (Some(a), Some(b)) => a.checked_add(b).map_or(Value::Null, |n| json!(n)),
                _ => {
                    let a = current.as_f64().unwrap_or(0.0);
                    let b = by.as_f64().unwrap_or(0.0);
                    serde_json::Number::from_f64(a + b).map_or(Value::Null, Value::Number)
                }
            }
        }
        // "clear"
        _ => Value::Null,
    }
}

/// One record's patch: only the attributes whose value changes.
fn patch_for(row: &Map<String, Value>, operations: &[EditOperation]) -> Map<String, Value> {
    let mut values: Map<String, Value> = Map::new();
    for op in operations {
        let current = values
            .get(&op.attribute)
            .or_else(|| row.get(&op.attribute))
            .cloned()
            .unwrap_or(Value::Null);
        values.insert(op.attribute.clone(), apply_operation(&current, op));
    }
    values
        .into_iter()
        .filter(|(name, value)| row.get(name).unwrap_or(&Value::Null) != value)
        .collect()
}

/// The filter schema over the attributes the caller may read in bulk.
struct EditFilterSchema<'a> {
    attrs: &'a [AttrInfo],
}

impl FilterSchema for EditFilterSchema<'_> {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        if field == "id" {
            return Ok("uuid");
        }
        let attr = self
            .attrs
            .iter()
            .find(|a| a.logicalname == field)
            .ok_or(FieldCastError::Unknown)?;
        cast_for_attr(attr)
    }

    fn is_multi_choice(&self, field: &str) -> bool {
        self.attrs
            .iter()
            .find(|a| a.logicalname == field)
            .is_some_and(is_multi_choice_attr)
    }
}

/// Plans a bulk edit: the bulk-update items, the records matched and left
/// unchanged, and the first records' before and after values.
pub async fn plan_bulk_edit(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    request: &BulkEditRequest,
) -> Result<BulkEditPlan, AppError> {
    if request.operations.is_empty() || request.operations.len() > MAX_OPERATIONS {
        return Err(AppError::Validation(format!(
            "operations: 1 to {MAX_OPERATIONS}"
        )));
    }
    if request.ids.is_empty() == request.filters.is_empty() {
        return Err(AppError::Validation(
            "give ids or filters to pick the records, not both".into(),
        ));
    }
    if request.ids.len() > MAX_BULK_EDIT_RECORDS {
        return Err(AppError::Validation(format!(
            "at most {MAX_BULK_EDIT_RECORDS} records per bulk edit"
        )));
    }
    let (entity_id, entity_name, attrs, _) = resolve_entity(state, entity).await?;
    if POLYMORPHIC_AUDIT_ENTITIES.contains(&entity_name.as_str())
        || POLYMORPHIC_CHILD_ENTITIES.contains(&entity_name.as_str())
    {
        return Err(AppError::Forbidden);
    }
    let primary_name = state
        .entities
        .load()
        .get(&entity_name)
        .and_then(|m| m.primary_name_attribute.clone());
    let readable: Vec<AttrInfo> = attrs
        .iter()
        .filter(|attr| {
            attome_security::field_gate::readable(
                ctx,
                &entity_name,
                attr,
                primary_name.as_deref(),
                attome_security::field_gate::Surface::Bulk,
            )
        })
        .cloned()
        .collect();

    let mut columns: Vec<String> = Vec::new();
    for op in &request.operations {
        let attr = readable
            .iter()
            .find(|a| a.logicalname == op.attribute)
            .filter(|a| !attome_core::ALL_SYSTEM_COLS.contains(&a.logicalname.as_str()))
            .filter(|a| !a.is_formula())
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "{}: not an attribute that can be edited in bulk",
                    op.attribute
                ))
            })?;
        check_operation(op, shape_of(attr))?;
        if !columns.contains(&attr.logicalname) {
            columns.push(attr.logicalname.clone());
        }
    }

    // The picked records the caller can read, with their current values.
    let mut conds: Vec<String> = vec!["(is_active IS NULL OR is_active = TRUE)".to_owned()];
    let mut text_binds: Vec<String> = Vec::new();
    let ids_param = if request.ids.is_empty() {
        let schema = EditFilterSchema { attrs: &readable };
        for filter in &request.filters {
            let (cond, binds) =
                attome_core::filter::compile(filter, &schema, text_binds.len() + 1)?;
            conds.push(cond);
            text_binds.extend(binds);
        }
        None
    } else {
        let n = text_binds.len() + 1;
        conds.push(format!("id = ANY(${n})"));
        Some(n)
    };
    let next = text_binds.len() + usize::from(ids_param.is_some()) + 1;
    let access_level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        &entity_name,
        RecordAction::Read,
    )
    .await?;
    let predicate = attome_security::rls_predicate(
        ctx,
        entity_id,
        "",
        access_level,
        RecordAction::Read.share_capability(),
        next,
    );
    let limit_param = next + if predicate.is_some() { 6 } else { 0 };
    let projection = columns
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT row_to_json(r) FROM (SELECT id, row_version, {projection} FROM {} \
         WHERE {} {} ORDER BY id LIMIT ${limit_param}) r",
        quote_ident(&entity_name),
        conds.join(" AND "),
        predicate.as_ref().map_or("", |p| p.sql.as_str()),
    );
    let mut query = sqlx::query_scalar::<_, Value>(&sql);
    for bind in &text_binds {
        query = query.bind(bind);
    }
    if ids_param.is_some() {
        query = query.bind(&request.ids);
    }
    if let Some(p) = &predicate {
        query = query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    let rows: Vec<Value> = query
        .bind(i64::try_from(MAX_BULK_EDIT_RECORDS + 1).unwrap_or(i64::MAX))
        .fetch_all(&state.base.db)
        .await
        .map_err(attome_db::classify)?;
    if rows.len() > MAX_BULK_EDIT_RECORDS {
        return Err(AppError::Validation(format!(
            "more than {MAX_BULK_EDIT_RECORDS} records match; narrow the filters"
        )));
    }

    let matched = rows.len();
    let mut items = Vec::new();
    let mut samples = Vec::new();
    let mut undo = Vec::new();
    for row in rows {
        let Value::Object(row) = row else { continue };
        let Some(id) = row
            .get("id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        let patch = patch_for(&row, &request.operations);
        if patch.is_empty() {
            continue;
        }
        if samples.len() < PREVIEW_SAMPLES {
            samples.push(PreviewRecord {
                id,
                before: patch
                    .keys()
                    .map(|name| (name.clone(), row.get(name).cloned().unwrap_or(Value::Null)))
                    .collect(),
                after: patch.clone(),
            });
        }
        let row_version = row.get("row_version").and_then(Value::as_i64);
        if let Some(version) = row_version {
            undo.push(UndoItem {
                id,
                row_version: version + 1,
                values: patch
                    .keys()
                    .map(|name| (name.clone(), row.get(name).cloned().unwrap_or(Value::Null)))
                    .collect(),
            });
        }
        items.push(BulkItem {
            id: Some(id),
            expected_row_version: row_version,
            data: Value::Object(patch),
        });
    }
    let unchanged = matched - items.len();
    Ok(BulkEditPlan {
        items,
        matched,
        unchanged,
        samples,
        undo,
    })
}

/// B5-T1: changes the same attributes on many records.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/bulk-edit",
    tag = "entity",
    params(("entity" = String, Path)),
    request_body = BulkEditRequest,
    responses(
        (status = 202, description = "The edit is planned and running as a bulk update", body = BulkEditSubmitted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's bulk or update privilege", body = ErrorResponse),
        (status = 422, description = "Invalid operations, or too many records", body = ErrorResponse),
        (status = 503, description = "No batch worker can run the edit", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::BulkAccepted)])))),
)]
async fn bulk_edit(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Bulk>>,
    _jobs: Available<BatchJobs>,
    Path(entity): Path<String>,
    Json(request): Json<BulkEditRequest>,
) -> Result<(StatusCode, Json<BulkEditSubmitted>), AppError> {
    let BulkEditPlan {
        items,
        matched,
        unchanged,
        undo,
        ..
    } = plan_bulk_edit(&state, &ctx, &entity, &request).await?;
    if items.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(BulkEditSubmitted {
                id: None,
                total: 0,
                matched,
                unchanged,
                undo: Vec::new(),
                approval_request_id: None,
            }),
        ));
    }
    // B5-T3: above the approval count the edit waits on an approval.
    let threshold = approval_count(&state);
    if threshold > 0 && items.len() > threshold {
        let total = i32::try_from(items.len()).unwrap_or(i32::MAX);
        let payload = BulkEditApprovalPayload {
            entity: entity.clone(),
            items: items
                .iter()
                .map(|i| BulkEditApprovalItem {
                    id: i.id,
                    expected_row_version: i.expected_row_version,
                    data: i.data.clone(),
                })
                .collect(),
            requested_by: ctx.user_id,
        };
        let value = serde_json::to_value(&payload).map_err(AppError::internal)?;
        let request = attome_audit::approval::gate_regarding_required(
            &state,
            ACTION_BULK_EDIT,
            value,
            ctx.user_id,
            None,
        )
        .await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(BulkEditSubmitted {
                id: None,
                total,
                matched,
                unchanged,
                undo,
                approval_request_id: Some(request.id),
            }),
        ));
    }
    let submitted = submit_bulk(&state, &ctx, &entity, "update", items, false).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(BulkEditSubmitted {
            id: Some(submitted.id),
            total: submitted.total,
            matched,
            unchanged,
            undo,
            approval_request_id: None,
        }),
    ))
}

/// B5-T2: what a bulk edit would change, without changing anything: the
/// counts and the first 20 records before and after.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/bulk-edit/preview",
    tag = "entity",
    params(("entity" = String, Path)),
    request_body = BulkEditRequest,
    responses(
        (status = 200, description = "What the edit would change", body = BulkEditPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's bulk privilege", body = ErrorResponse),
        (status = 422, description = "Invalid operations, or too many records", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "computes the edit a bulk-edit would make and writes nothing"
    )))),
)]
async fn bulk_edit_preview(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Bulk>>,
    Path(entity): Path<String>,
    Json(request): Json<BulkEditRequest>,
) -> Result<Json<BulkEditPreview>, AppError> {
    let plan = plan_bulk_edit(&state, &ctx, &entity, &request).await?;
    Ok(Json(BulkEditPreview {
        matched: plan.matched,
        to_change: plan.items.len(),
        unchanged: plan.unchanged,
        samples: plan.samples,
    }))
}

/// B5-T3: puts a bulk edit back. The undo list goes in as a bulk update
/// carrying each record's post-edit row version, so a record changed since
/// the edit is reported as a conflict and left as it is; every record still
/// goes through the normal update path with the caller's own access.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/bulk-edit/undo",
    tag = "entity",
    params(("entity" = String, Path)),
    request_body = BulkEditUndoRequest,
    responses(
        (status = 202, description = "The undo is running as a bulk update", body = BulkEditSubmitted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's bulk or update privilege", body = ErrorResponse),
        (status = 422, description = "An empty or oversized undo list", body = ErrorResponse),
        (status = 503, description = "No batch worker can run the undo", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::BulkAccepted)])))),
)]
async fn bulk_edit_undo(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Bulk>>,
    _jobs: Available<BatchJobs>,
    Path(entity): Path<String>,
    Json(request): Json<BulkEditUndoRequest>,
) -> Result<(StatusCode, Json<BulkEditSubmitted>), AppError> {
    if request.undo.is_empty() || request.undo.len() > MAX_BULK_EDIT_RECORDS {
        return Err(AppError::Validation(format!(
            "undo: 1 to {MAX_BULK_EDIT_RECORDS} records"
        )));
    }
    let count = request.undo.len();
    let items: Vec<BulkItem> = request
        .undo
        .into_iter()
        .map(|item| BulkItem {
            id: Some(item.id),
            expected_row_version: Some(item.row_version),
            data: Value::Object(item.values),
        })
        .collect();
    let submitted = submit_bulk(&state, &ctx, &entity, "update", items, false).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(BulkEditSubmitted {
            id: Some(submitted.id),
            total: submitted.total,
            matched: count,
            unchanged: 0,
            undo: Vec::new(),
        }),
    ))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/{entity}/bulk-edit", post(bulk_edit))
        .route(
            "/api/v1/{entity}/bulk-edit/preview",
            post(bulk_edit_preview),
        )
        .route("/api/v1/{entity}/bulk-edit/undo", post(bulk_edit_undo))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(bulk_edit, bulk_edit_preview, bulk_edit_undo))]
struct ApiDocFragment;

/// The bulk-edit routes' slice of the API document (merged by attome-api).
pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(attribute: &str, op: &str, value: Option<Value>) -> EditOperation {
        EditOperation {
            attribute: attribute.to_owned(),
            op: op.to_owned(),
            value,
        }
    }

    #[test]
    fn operations_compute_from_the_current_value() {
        assert_eq!(
            apply_operation(&json!("a"), &op("x", "set", Some(json!("b")))),
            json!("b")
        );
        assert_eq!(
            apply_operation(&json!("a"), &op("x", "clear", None)),
            Value::Null
        );
        assert_eq!(
            apply_operation(
                &json!(["red"]),
                &op("x", "add", Some(json!(["blue", "red"])))
            ),
            json!(["red", "blue"])
        );
        assert_eq!(
            apply_operation(&Value::Null, &op("x", "add", Some(json!("red")))),
            json!(["red"])
        );
        assert_eq!(
            apply_operation(
                &json!(["red", "blue"]),
                &op("x", "remove", Some(json!("red")))
            ),
            json!(["blue"])
        );
        assert_eq!(
            apply_operation(&json!(5), &op("x", "increment", Some(json!(-2)))),
            json!(3)
        );
        assert_eq!(
            apply_operation(&Value::Null, &op("x", "increment", Some(json!(4)))),
            json!(4)
        );
        assert_eq!(
            apply_operation(&json!(1.5), &op("x", "increment", Some(json!(1)))),
            json!(2.5)
        );
    }

    #[test]
    fn a_record_already_holding_the_values_is_left_alone() {
        let row: Map<String, Value> = serde_json::from_value(json!({
            "id": "0190a0c0-0000-7000-8000-000000000001", "status": "open", "tags": ["a"]
        }))
        .unwrap();
        assert!(patch_for(&row, &[op("status", "set", Some(json!("open")))]).is_empty());
        assert!(patch_for(&row, &[op("tags", "add", Some(json!("a")))]).is_empty());
        let patch = patch_for(
            &row,
            &[
                op("status", "set", Some(json!("closed"))),
                op("tags", "add", Some(json!("b"))),
            ],
        );
        assert_eq!(
            Value::Object(patch),
            json!({"status": "closed", "tags": ["a", "b"]})
        );
    }

    #[test]
    fn operations_must_fit_the_attribute() {
        assert!(check_operation(&op("n", "increment", Some(json!(1))), Shape::Number).is_ok());
        assert!(check_operation(&op("t", "increment", Some(json!(1))), Shape::Other).is_err());
        assert!(check_operation(&op("n", "increment", Some(json!("1"))), Shape::Number).is_err());
        assert!(check_operation(&op("c", "add", Some(json!("x"))), Shape::MultiChoice).is_ok());
        assert!(check_operation(&op("t", "add", Some(json!("x"))), Shape::Other).is_err());
        assert!(check_operation(&op("t", "set", None), Shape::Other).is_err());
        assert!(check_operation(&op("t", "clear", None), Shape::Other).is_ok());
        assert!(check_operation(&op("t", "rename", None), Shape::Other).is_err());
    }
}

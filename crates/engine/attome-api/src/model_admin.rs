//! The metadata model's admin API (roadmap Y1-T9), under
//! `/api/v1/admin/model`.
//!
//! Thin handlers over `attome_model`: each parses its input, calls one model
//! function and shapes the response. Reads and writes need an administrator
//! (narrower delegated roles are Q12's). The only write,
//! `POST .../commands`, records one Configuration audit event in its own
//! transaction; `POST .../validate` writes nothing.
//!
//! `GET /api/v1/model/forms/{id}/plan` is the one non-admin route: any
//! signed-in user reads a published form's render plan, which the web
//! renderer draws (Y14).
//!
//! The prefix is `/admin/model`, not `/admin/metadata`, because
//! `/admin/metadata/...` already holds the bundle and sync routes, which a
//! kind of the same name would otherwise be shadowed by.

use std::sync::{Arc, OnceLock};

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_model::store::{self, ObjectSpec};
use attome_model::{Issue, Kind, KindRegistry, Layer, ObjectId, ObjectRef};
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The process-wide kind registry (`attome_metadata::model_edit`).
pub fn kinds() -> &'static KindRegistry {
    attome_metadata::model_edit::registry()
}

/// The cooked registry of the published metadata, one per process.
pub fn cooked() -> &'static attome_model::runtime::CookedRegistry {
    static COOKED: OnceLock<attome_model::runtime::CookedRegistry> = OnceLock::new();
    COOKED.get_or_init(attome_model::runtime::CookedRegistry::default)
}

/// Rebuilds the cooked registry from the published store, reusing unchanged
/// artefacts. Serialised so two publishes cannot interleave their swaps. On
/// one server this keeps forms current; several servers switch versions with
/// Y8.
pub async fn refresh_cooked(state: &EngineState) -> Result<(), AppError> {
    static REBUILD: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _guard = REBUILD.lock().await;
    let current = cooked().snapshot();
    let manifest =
        attome_model::publish::cook_published(&state.base.db, kinds(), Some(&current.manifest))
            .await?;
    cooked()
        .load_version(&state.base.db, current.version + 1, manifest)
        .await
}

fn kind(name: &str) -> Result<&'static Arc<dyn Kind>, AppError> {
    kinds().get(name).ok_or(AppError::NotFound)
}

#[derive(Serialize, ToSchema)]
pub(crate) struct KindView {
    name: String,
    schema_version: u32,
    description: String,
    /// The JSON Schema of the kind's documents.
    #[schema(value_type = Object)]
    json_schema: Value,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ObjectSummaryView {
    id: Uuid,
    name: String,
    app: String,
    owner_layer: String,
    version_no: i64,
    state: String,
    content_hash: String,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ObjectVersionView {
    id: Uuid,
    kind: String,
    name: String,
    version_no: i64,
    kind_schema_version: i32,
    state: String,
    #[schema(value_type = Object)]
    doc: Value,
    content_hash: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct VersionSummaryView {
    version_no: i64,
    state: String,
    content_hash: String,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PatchOpView {
    op: String,
    path: String,
    #[schema(value_type = Option<Object>)]
    value: Option<Value>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ReferenceView {
    from_kind: String,
    from_ref: Uuid,
    to: String,
    mode: String,
    created_at: DateTime<Utc>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct IssueView {
    path: String,
    code: String,
    message: String,
}

impl From<&Issue> for IssueView {
    fn from(issue: &Issue) -> Self {
        Self {
            path: issue.path.clone(),
            code: issue.code.to_owned(),
            message: issue.message.clone(),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ModelValidateResponse {
    valid: bool,
    issues: Vec<IssueView>,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct ValidateRequest {
    /// The document to check, as it would be saved.
    #[schema(value_type = Object)]
    doc: Value,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct CommandsRequest {
    /// The content hash of the document the commands were made against; empty
    /// for an object that does not exist yet.
    base_hash: String,
    /// The object's name; required when it does not exist yet.
    name: Option<String>,
    /// `add`, `remove`, `move` and `set` edits, applied in order.
    #[schema(value_type = Vec<Object>)]
    commands: Vec<Value>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct CommandsResponse {
    id: Uuid,
    version_no: i64,
    content_hash: String,
    /// References to objects that do not exist; they do not block the draft.
    issues: Vec<IssueView>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct DiffQuery {
    /// The older version.
    from: i64,
    /// The newer version.
    to: i64,
}

fn object_ref(kind: &dyn Kind, id: Uuid) -> ObjectRef {
    ObjectRef {
        kind: kind.name(),
        id: ObjectId(id),
    }
}

/// Lists every registered kind.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/kinds",
    tag = "admin",
    responses(
        (status = 200, description = "Every kind, by name", body = PaginatedResponse<KindView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_kinds(_ctx: Authorized<Admin>) -> Json<PaginatedResponse<KindView>> {
    let items: Vec<KindView> = kinds()
        .iter()
        .map(|kind| KindView {
            name: kind.name().as_str().to_owned(),
            schema_version: kind.schema_version(),
            description: kind.agent_tool_description().to_owned(),
            json_schema: kind.json_schema(),
        })
        .collect();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: total.max(1),
    })
}

/// Lists the objects of one kind.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/{kind}",
    tag = "admin",
    params(("kind" = String, Path, description = "Kind name"), OnePageQuery),
    responses(
        (status = 200, description = "The kind's objects, by name", body = PaginatedResponse<ObjectSummaryView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_objects(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(kind_name): Path<String>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ObjectSummaryView>>, AppError> {
    let kind = kind(&kind_name)?;
    let page = store::list_objects(&state.base.db, kind.name().as_str(), &page).await?;
    Ok(Json(PaginatedResponse {
        items: page
            .items
            .into_iter()
            .map(|o| ObjectSummaryView {
                id: o.id,
                name: o.name,
                app: o.app,
                owner_layer: o.owner_layer,
                version_no: o.version_no,
                state: o.state,
                content_hash: o.content_hash,
            })
            .collect(),
        total: page.total,
        page: page.page,
        page_size: page.page_size,
    }))
}

fn version_view(v: store::ObjectVersion) -> ObjectVersionView {
    ObjectVersionView {
        id: v.object_id,
        kind: v.kind,
        name: v.name,
        version_no: v.version_no,
        kind_schema_version: v.kind_schema_version,
        state: v.state,
        doc: v.doc,
        content_hash: v.content_hash,
        created_at: v.created_at,
    }
}

async fn read_checked(
    state: &EngineState,
    kind_name: &str,
    id: Uuid,
    at: Option<i64>,
) -> Result<store::ObjectVersion, AppError> {
    let kind = kind(kind_name)?;
    let version = store::read(&state.base.db, id, at).await?;
    if version.kind != kind.name().as_str() {
        return Err(AppError::NotFound);
    }
    Ok(version)
}

/// Reads an object's newest version (its draft, when it has one).
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/{kind}/{id}",
    tag = "admin",
    params(("kind" = String, Path, description = "Kind name"), ("id" = Uuid, Path, description = "Object id")),
    responses(
        (status = 200, description = "The newest version", body = ObjectVersionView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind or object", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_object(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((kind_name, id)): Path<(String, Uuid)>,
) -> Result<Json<ObjectVersionView>, AppError> {
    Ok(Json(version_view(
        read_checked(&state, &kind_name, id, None).await?,
    )))
}

/// Reads one version of an object.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/{kind}/{id}/versions/{version}",
    operation_id = "get_model_version",
    tag = "admin",
    params(
        ("kind" = String, Path, description = "Kind name"),
        ("id" = Uuid, Path, description = "Object id"),
        ("version" = i64, Path, description = "Version number"),
    ),
    responses(
        (status = 200, description = "That version", body = ObjectVersionView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind, object or version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_version(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((kind_name, id, version)): Path<(String, Uuid, i64)>,
) -> Result<Json<ObjectVersionView>, AppError> {
    Ok(Json(version_view(
        read_checked(&state, &kind_name, id, Some(version)).await?,
    )))
}

/// Lists an object's versions, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/{kind}/{id}/history",
    tag = "admin",
    params(("kind" = String, Path, description = "Kind name"), ("id" = Uuid, Path, description = "Object id"), OnePageQuery),
    responses(
        (status = 200, description = "Versions, newest first", body = PaginatedResponse<VersionSummaryView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind or object", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_history(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((kind_name, id)): Path<(String, Uuid)>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<VersionSummaryView>>, AppError> {
    read_checked(&state, &kind_name, id, None).await?;
    let page = store::history(&state.base.db, id, &page).await?;
    Ok(Json(PaginatedResponse {
        items: page
            .items
            .into_iter()
            .map(|v| VersionSummaryView {
                version_no: v.version_no,
                state: v.state,
                content_hash: v.content_hash,
                created_by: v.created_by,
                created_at: v.created_at,
            })
            .collect(),
        total: page.total,
        page: page.page,
        page_size: page.page_size,
    }))
}

/// The RFC 6902 operations from one version to another.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/{kind}/{id}/diff",
    tag = "admin",
    params(("kind" = String, Path, description = "Kind name"), ("id" = Uuid, Path, description = "Object id"), DiffQuery),
    responses(
        (status = 200, description = "The operations, in order", body = PaginatedResponse<PatchOpView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind, object or version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_diff(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((kind_name, id)): Path<(String, Uuid)>,
    Query(query): Query<DiffQuery>,
) -> Result<Json<PaginatedResponse<PatchOpView>>, AppError> {
    read_checked(&state, &kind_name, id, None).await?;
    let ops = store::diff(&state.base.db, id, query.from, query.to).await?;
    let items: Vec<PatchOpView> = ops
        .into_iter()
        .map(|op| PatchOpView {
            op: op.op.to_owned(),
            path: op.path,
            value: op.value,
        })
        .collect();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: total.max(1),
    }))
}

/// The references an object makes.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/{kind}/{id}/references",
    tag = "admin",
    params(("kind" = String, Path, description = "Kind name"), ("id" = Uuid, Path, description = "Object id"), OnePageQuery),
    responses(
        (status = 200, description = "Outgoing references", body = PaginatedResponse<ReferenceView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind or object", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_references(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((kind_name, id)): Path<(String, Uuid)>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<ReferenceView>>, AppError> {
    read_checked(&state, &kind_name, id, None).await?;
    let source = object_ref(kind(&kind_name)?.as_ref(), id);
    let page = attome_model::references::references_out(&state.base.db, &source, &page).await?;
    Ok(Json(PaginatedResponse {
        items: page
            .items
            .into_iter()
            .map(|r| ReferenceView {
                from_kind: r.from_kind,
                from_ref: r.from_ref,
                to: if r.to_attribute.is_empty() {
                    r.to_entity
                } else {
                    format!("{}.{}", r.to_entity, r.to_attribute)
                },
                mode: r.mode,
                created_at: r.created_at,
            })
            .collect(),
        total: page.total,
        page: page.page,
        page_size: page.page_size,
    }))
}

/// Checks a document as it would be saved, without saving it.
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/{kind}/{id}/validate",
    tag = "admin",
    params(("kind" = String, Path, description = "Kind name"), ("id" = Uuid, Path, description = "Object id")),
    request_body = ValidateRequest,
    responses(
        (status = 200, description = "Whether it is valid, and every issue", body = ModelValidateResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::ReadOnly, None, "checks a document and writes nothing")))),
)]
async fn validate(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path((kind_name, _id)): Path<(String, Uuid)>,
    Json(request): Json<ValidateRequest>,
) -> Result<Json<ModelValidateResponse>, AppError> {
    let kind = kind(&kind_name)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let issues =
        attome_model::validate::validate_save(&mut tx, kinds(), kind.as_ref(), &request.doc)
            .await?;
    tx.rollback().await.map_err(AppError::internal)?;
    Ok(Json(ModelValidateResponse {
        valid: issues.is_empty(),
        issues: issues.iter().map(IssueView::from).collect(),
    }))
}

/// Applies edit commands to an object's draft (creating the object on its
/// first edit) and saves it.
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/{kind}/{id}/commands",
    tag = "admin",
    params(("kind" = String, Path, description = "Kind name"), ("id" = Uuid, Path, description = "Object id")),
    request_body = CommandsRequest,
    responses(
        (status = 200, description = "The saved draft", body = CommandsResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind, or no such object for a non-empty base hash", body = ErrorResponse),
        (status = 409, description = "The draft changed since base_hash, or another save is in progress", body = ErrorResponse),
        (status = 422, description = "A command or the resulting document is invalid", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn apply_commands(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((kind_name, id)): Path<(String, Uuid)>,
    Json(request): Json<CommandsRequest>,
) -> Result<Json<CommandsResponse>, AppError> {
    let kind = kind(&kind_name)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let edited = attome_metadata::model_edit::edit(
        &state.base.db,
        &mut tx,
        kind.as_ref(),
        attome_metadata::model_edit::EditRequest {
            id,
            base_hash: request.base_hash,
            name: request.name,
            commands: request.commands,
        },
        Some(ctx.user_id),
    )
    .await?;
    let (name, saved) = (edited.name, edited.saved);
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_object",
            Some(id),
        )
        .named("model.commands")
        .comment(format!(
            "{} `{name}` draft v{}: {} command(s)",
            kind.name(),
            saved.version_no,
            edited.commands
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(CommandsResponse {
        id,
        version_no: saved.version_no,
        content_hash: saved.content_hash,
        issues: saved.issues.iter().map(IssueView::from).collect(),
    }))
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ModelPublishResponse {
    id: Uuid,
    version_no: i64,
    /// Reasons to look again that did not stop the publish, such as an eval
    /// suite whose score fell (N23-T2). Empty when there are none.
    warnings: Vec<String>,
}

/// Publishes an object's open draft once it passes the publish checks, and
/// refreshes the cooked metadata.
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/{kind}/{id}/publish",
    operation_id = "publish_model_object",
    tag = "admin",
    params(("kind" = String, Path, description = "Kind name"), ("id" = Uuid, Path, description = "Object id")),
    responses(
        (status = 200, description = "Published", body = ModelPublishResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such kind, or no open draft", body = ErrorResponse),
        (status = 409, description = "Another save is in progress", body = ErrorResponse),
        (status = 422, description = "The draft fails the publish checks, or an eval suite's newest run fails a safety case; the issues are listed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn publish(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((kind_name, id)): Path<(String, Uuid)>,
) -> Result<Json<ModelPublishResponse>, AppError> {
    let kind = kind(&kind_name)?;
    // N23-T2: an agent or prompt publishes only while its eval suites' newest
    // runs pass every safety case.
    let gate = attome_ai::publish_gate::check(&state.base.db, kind.name().as_str(), id).await?;
    if !gate.blocked.is_empty() {
        return Err(AppError::Validation(gate.blocked.join("; ")));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let published = attome_model::publish::publish(
        &mut tx,
        kinds(),
        &attome_model::validate::CrossChecks::default(),
        kind.as_ref(),
        id,
    )
    .await?;
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_object",
            Some(id),
        )
        .named("model.publish")
        .comment(format!(
            "{} published v{}",
            kind.name(),
            published.version_no
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    refresh_cooked(&state).await?;
    Ok(Json(ModelPublishResponse {
        id,
        version_no: published.version_no,
        warnings: gate.warnings,
    }))
}

/// A form's cooked plan, as the cooker wrote it.
#[derive(Deserialize)]
struct CookedForm {
    entity: Uuid,
    name: String,
    sections: Vec<CookedSection>,
}

#[derive(Deserialize)]
struct CookedSection {
    label: String,
    fields: Vec<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct FormPlan {
    id: Uuid,
    name: String,
    /// The entity's logical name, as the record API addresses it.
    entity: String,
    sections: Vec<FormPlanSection>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct FormPlanSection {
    label: String,
    fields: Vec<FormPlanField>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct FormPlanField {
    /// The attribute's logical name: the key of its value in a record.
    attribute: String,
    label: String,
    /// The attribute's field type number.
    field_type: i32,
    required: bool,
    /// An AI attribute (N11-T1): `record.ai_field` can suggest its value.
    ai: bool,
}

#[derive(sqlx::FromRow)]
struct AttributeRow {
    id: Uuid,
    logicalname: String,
    name: Option<String>,
    field_type: Option<i32>,
    required: Option<bool>,
    ai: Option<bool>,
}

/// The render plan of a published form: its sections and, for each field,
/// the attribute's logical name, label, type and whether it is required.
/// The form comes from the cooked registry in memory; the attribute details
/// from one bounded query (a form holds at most 400 fields).
#[utoipa::path(
    get,
    path = "/api/v1/model/forms/{id}/plan",
    tag = "model",
    params(
        ("id" = Uuid, Path, description = "Form id"),
        ("If-None-Match" = Option<String>, Header, description = "The ETag of a plan the client holds"),
    ),
    responses(
        (status = 200, description = "The form's render plan, with a content ETag", body = FormPlan),
        (status = 304, description = "Unchanged since the ETag in If-None-Match"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No published form with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn form_plan(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if cooked().snapshot().version == 0 {
        // Cold start: build the cooked registry from the published store.
        refresh_cooked(&state).await?;
    }
    let key = format!("form:{id}");
    let form = cooked()
        .get::<CookedForm>("form", &key)
        .ok_or(AppError::NotFound)?;
    let cached = state
        .entities
        .load()
        .get_by_id(form.entity)
        .map(|meta| meta.logicalname.clone());
    let entity = match cached {
        Some(name) => name,
        // The registry is refreshed in the background; a just-created entity
        // may not be in it yet.
        None => sqlx::query_scalar::<_, String>(
            "SELECT logicalname FROM entity_info WHERE id = $1 AND is_active IS NOT FALSE",
        )
        .bind(form.entity)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?,
    };
    let ids: Vec<Uuid> = form
        .sections
        .iter()
        .flat_map(|s| s.fields.iter().copied())
        .collect();
    let rows: Vec<AttributeRow> = sqlx::query_as(
        "SELECT id, logicalname, name, type AS field_type, required, \
                (options->'ai'->>'prompt') IS NOT NULL AS ai \
         FROM attribute_info WHERE id = ANY($1) AND is_active IS NOT FALSE",
    )
    .bind(&ids)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let by_id: std::collections::BTreeMap<Uuid, AttributeRow> =
        rows.into_iter().map(|row| (row.id, row)).collect();
    let sections = form
        .sections
        .iter()
        .map(|section| FormPlanSection {
            label: section.label.clone(),
            // A field whose attribute has since been removed is left out.
            fields: section
                .fields
                .iter()
                .filter_map(|field| by_id.get(field))
                .map(|row| FormPlanField {
                    attribute: row.logicalname.clone(),
                    label: row.name.clone().unwrap_or_else(|| row.logicalname.clone()),
                    field_type: row.field_type.unwrap_or(0),
                    required: row.required.unwrap_or(false),
                    ai: row.ai.unwrap_or(false),
                })
                .collect(),
        })
        .collect();
    let plan = FormPlan {
        id,
        name: form.name.clone(),
        entity,
        sections,
    };
    // Y14-T2: a content ETag, so a client that already holds this plan gets
    // a bodyless 304 instead of downloading it again.
    let etag = serde_json::to_value(&plan)
        .map_err(AppError::internal)
        .and_then(|value| attome_model::canonical::content_hash(&value).map_err(AppError::internal))
        .map(|hash| format!("\"{hash}\""))?;
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|tag| tag.trim() == etag));
    let etag_header = HeaderValue::from_str(&etag).map_err(AppError::internal)?;
    if unchanged {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag_header)]).into_response());
    }
    Ok(([(header::ETAG, etag_header)], Json(plan)).into_response())
}

/// One object of a blueprint and what applying it would do (N12-T3).
#[derive(Serialize, ToSchema)]
pub(crate) struct BlueprintItem {
    path: String,
    kind: String,
    name: String,
    /// The existing object's id; `null` for a new one.
    id: Option<Uuid>,
    /// `new` | `changed` | `same`.
    status: String,
    /// The version that is published now, which a rollback returns to.
    published_version: Option<i64>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct BlueprintPlan {
    items: Vec<BlueprintItem>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct BlueprintApplied {
    /// Every object the apply published, with the version it published and
    /// the one it replaced (pass these to rollback to undo).
    items: Vec<BlueprintAppliedItem>,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct BlueprintAppliedItem {
    id: Uuid,
    kind: String,
    version_no: i64,
    /// `null` when the object was new.
    previous_version: Option<i64>,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct BlueprintRollback {
    items: Vec<BlueprintAppliedItem>,
}

/// One readable blueprint file.
struct BlueprintObject {
    path: String,
    kind: &'static Arc<dyn Kind>,
    object: attome_model::files::FileObject,
}

/// Reads blueprint files, refusing the set when any is unreadable, invalid
/// or of an adapter kind.
fn read_blueprint(request: &ModelFiles) -> Result<Vec<BlueprintObject>, AppError> {
    if request.files.len() > MAX_IMPORT_FILES {
        return Err(AppError::Validation(format!(
            "a blueprint holds at most {MAX_IMPORT_FILES} files"
        )));
    }
    let mut out = Vec::with_capacity(request.files.len());
    let mut issues = Vec::new();
    for file in &request.files {
        match attome_model::files::from_file(kinds(), std::path::Path::new(&file.path), &file.text)
        {
            Ok(object) => {
                let Some(kind) = kinds().get(object.kind.as_str()) else {
                    continue;
                };
                if kind.adapter_table().is_some() {
                    issues.push(Issue::new(
                        &file.path,
                        "adapter_kind",
                        format!("{} objects are not part of a blueprint", object.kind),
                    ));
                    continue;
                }
                issues.extend(
                    attome_model::validate::validate_edit(kind.as_ref(), &object.doc)
                        .into_iter()
                        .map(|issue| Issue {
                            path: format!("{}{}", file.path, issue.path),
                            ..issue
                        }),
                );
                out.push(BlueprintObject {
                    path: file.path.clone(),
                    kind,
                    object,
                });
            }
            Err(issue) => issues.push(issue),
        }
    }
    if issues.is_empty() {
        Ok(out)
    } else {
        Err(attome_model::validate::publish_error(&issues))
    }
}

/// What applying a blueprint would change, without changing anything
/// (N12-T3): each object new, changed or the same as what is published.
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/blueprint/plan",
    tag = "admin",
    request_body = ModelFiles,
    responses(
        (status = 200, description = "Each object's status", body = BlueprintPlan),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "A file is unreadable or invalid; the issues are listed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::ReadOnly, None, "plans a blueprint and writes nothing")))),
)]
async fn blueprint_plan(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Json(request): Json<ModelFiles>,
) -> Result<Json<BlueprintPlan>, AppError> {
    let objects = read_blueprint(&request)?;
    let mut items = Vec::with_capacity(objects.len());
    for BlueprintObject { path, kind, object } in objects {
        let kind_name = kind.name();
        let existing = store::published_state(
            &state.base.db,
            kind_name.as_str(),
            &object.app,
            &object.name,
        )
        .await?;
        let hash =
            attome_model::canonical::content_hash(&object.doc).map_err(AppError::Validation)?;
        let (id, published_version, status) = match existing {
            None => (None, None, "new"),
            Some(found) => match found.published {
                Some((version, published_hash)) if published_hash == hash => {
                    (Some(found.id), Some(version), "same")
                }
                Some((version, _)) => (Some(found.id), Some(version), "changed"),
                None => (Some(found.id), None, "changed"),
            },
        };
        items.push(BlueprintItem {
            path,
            kind: kind_name.as_str().to_owned(),
            name: object.name,
            id,
            status: status.to_owned(),
            published_version,
        });
    }
    Ok(Json(BlueprintPlan { items }))
}

/// Applies a blueprint (N12-T3): every new or changed object is saved and
/// published in one transaction, so a blueprint lands whole or not at all.
/// Objects already the same are left alone.
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/blueprint/apply",
    tag = "admin",
    request_body = ModelFiles,
    responses(
        (status = 200, description = "What was published, with the versions it replaced", body = BlueprintApplied),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Another save of one of the objects is in progress", body = ErrorResponse),
        (status = 422, description = "A file is invalid or an object fails the publish checks", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn blueprint_apply(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(request): Json<ModelFiles>,
) -> Result<Json<BlueprintApplied>, AppError> {
    let objects = read_blueprint(&request)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut items = Vec::new();
    for BlueprintObject { kind, object, .. } in &objects {
        let kind_name = kind.name();
        let existing = store::published_state(
            &state.base.db,
            kind_name.as_str(),
            &object.app,
            &object.name,
        )
        .await?;
        let hash =
            attome_model::canonical::content_hash(&object.doc).map_err(AppError::Validation)?;
        let previous_version = existing
            .as_ref()
            .and_then(|e| e.published.as_ref())
            .map(|p| p.0);
        if existing
            .as_ref()
            .and_then(|e| e.published.as_ref())
            .is_some_and(|(_, published_hash)| *published_hash == hash)
        {
            continue;
        }
        let id = existing.map_or_else(Uuid::now_v7, |e| e.id);
        let spec = ObjectSpec {
            id: ObjectId(id),
            name: object.name.clone(),
            app: object.app.clone(),
            layer: if object.app == "customer" {
                Layer::Customer
            } else {
                Layer::App
            },
        };
        store::save_draft(
            &mut tx,
            kinds(),
            kind.as_ref(),
            &spec,
            &object.doc,
            Some(ctx.user_id),
        )
        .await?;
        let published = attome_model::publish::publish(
            &mut tx,
            kinds(),
            &attome_model::validate::CrossChecks::default(),
            kind.as_ref(),
            id,
        )
        .await?;
        items.push(BlueprintAppliedItem {
            id,
            kind: kind_name.as_str().to_owned(),
            version_no: published.version_no,
            previous_version,
        });
    }
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_object",
            None,
        )
        .named("model.blueprint.apply")
        .comment(format!(
            "{} object(s) published from a blueprint",
            items.len()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    refresh_cooked(&state).await?;
    Ok(Json(BlueprintApplied { items }))
}

/// Rolls a blueprint back (N12-T3): each object returns to the version it
/// had before, published again as a new version; an object the blueprint
/// created is left as it is, for an administrator to retire.
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/blueprint/rollback",
    tag = "admin",
    request_body = BlueprintRollback,
    responses(
        (status = 200, description = "What was republished", body = BlueprintApplied),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "An object or version is unknown", body = ErrorResponse),
        (status = 409, description = "Another save of one of the objects is in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn blueprint_rollback(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(request): Json<BlueprintRollback>,
) -> Result<Json<BlueprintApplied>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut items = Vec::new();
    for item in &request.items {
        let Some(previous) = item.previous_version else {
            continue;
        };
        let kind = kind(&item.kind)?;
        let old = store::read(&state.base.db, item.id, Some(previous)).await?;
        if old.kind != kind.name().as_str() {
            return Err(AppError::NotFound);
        }
        let current = store::read(&state.base.db, item.id, None).await?;
        let spec = ObjectSpec {
            id: ObjectId(item.id),
            name: current.name.clone(),
            app: "customer".to_owned(),
            layer: Layer::Customer,
        };
        store::save_draft(
            &mut tx,
            kinds(),
            kind.as_ref(),
            &spec,
            &old.doc,
            Some(ctx.user_id),
        )
        .await?;
        let published = attome_model::publish::publish(
            &mut tx,
            kinds(),
            &attome_model::validate::CrossChecks::default(),
            kind.as_ref(),
            item.id,
        )
        .await?;
        items.push(BlueprintAppliedItem {
            id: item.id,
            kind: item.kind.clone(),
            version_no: published.version_no,
            previous_version: Some(item.version_no),
        });
    }
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_object",
            None,
        )
        .named("model.blueprint.rollback")
        .comment(format!("{} object(s) rolled back", items.len())),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    refresh_cooked(&state).await?;
    Ok(Json(BlueprintApplied { items }))
}

/// A menu as one caller sees it (A21-T2).
#[derive(Serialize, ToSchema)]
pub(crate) struct MenuView {
    id: Uuid,
    name: String,
    #[schema(value_type = Vec<Object>)]
    groups: Vec<Value>,
    /// `<group>/<item>` of this caller's landing page, when the menu sets one.
    landing: Option<String>,
}

/// The groups and landing page `roles` may see: an item limited to roles
/// shows only to a holder of one of them (an administrator sees all), and a
/// group left with no items is dropped. Visibility never grants access to
/// what an item opens; that stays the target's own check.
pub(crate) fn menu_for(
    menu: &Value,
    roles: &[Uuid],
    is_admin: bool,
) -> (Vec<Value>, Option<String>) {
    let may_see = |item: &Value| {
        is_admin
            || match item["roles"].as_array() {
                None => true,
                Some(list) if list.is_empty() => true,
                Some(list) => list.iter().any(|r| {
                    r.as_str()
                        .and_then(|t| Uuid::parse_str(t).ok())
                        .is_some_and(|id| roles.contains(&id))
                }),
            }
    };
    let groups: Vec<Value> = menu["groups"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|group| {
            let items: Vec<Value> = group["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|item| may_see(item))
                .map(|item| {
                    let mut item = item.clone();
                    if let Some(object) = item.as_object_mut() {
                        object.remove("roles");
                    }
                    item
                })
                .collect();
            (!items.is_empty())
                .then(|| serde_json::json!({ "label": group["label"], "items": items }))
        })
        .collect();
    let landing = menu["landing"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| {
            entry["role"]
                .as_str()
                .and_then(|t| Uuid::parse_str(t).ok())
                .is_some_and(|id| roles.contains(&id))
        })
        .and_then(|entry| entry["item"].as_str().map(str::to_owned));
    (groups, landing)
}

/// A published menu, filtered to what the caller may see (A21-T2).
#[utoipa::path(
    get,
    path = "/api/v1/model/navigation/{id}",
    tag = "model",
    params(("id" = Uuid, Path, description = "Menu (navigation object) id")),
    responses(
        (status = 200, description = "The menu as this caller sees it", body = MenuView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No published menu with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn menu(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<MenuView>, AppError> {
    if cooked().snapshot().version == 0 {
        refresh_cooked(&state).await?;
    }
    let cooked_menu = cooked()
        .get::<Value>("navigation", &format!("navigation:{id}"))
        .ok_or(AppError::NotFound)?;
    let roles = ctx.role_ids.clone().unwrap_or_default();
    let (groups, landing) = menu_for(&cooked_menu, &roles, ctx.is_admin);
    Ok(Json(MenuView {
        id,
        name: cooked_menu["name"].as_str().unwrap_or_default().to_owned(),
        groups,
        landing,
    }))
}

/// `POST /api/v1/model/navigation/{id}/opened`.
#[derive(Deserialize, ToSchema)]
pub(crate) struct MenuItemOpened {
    /// The item, as `<group label>/<item label>`.
    item: String,
}

/// A21-T5: counts one open of a menu item for today.
#[utoipa::path(
    post,
    path = "/api/v1/model/navigation/{id}/opened",
    tag = "model",
    params(("id" = Uuid, Path)),
    request_body = MenuItemOpened,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Telemetry,
        None,
        "counts a menu item's opens; no business or security effect"
    )))),
    responses(
        (status = 204, description = "Counted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "No item, or an item over 300 characters", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn menu_item_opened(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<MenuItemOpened>,
) -> Result<axum::http::StatusCode, AppError> {
    let item = body.item.trim();
    if item.is_empty() || item.chars().count() > 300 {
        return Err(AppError::Validation("item is 1 to 300 characters".into()));
    }
    sqlx::query(
        "INSERT INTO menu_item_use (menu_id, item, day, opens) VALUES ($1, $2, CURRENT_DATE, 1) \
         ON CONFLICT (menu_id, item, day) DO UPDATE SET opens = menu_item_use.opens + 1",
    )
    .bind(id)
    .bind(item)
    .execute(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// One menu item's use over the period.
#[derive(Serialize, ToSchema, Debug, PartialEq, Eq)]
pub(crate) struct MenuItemUsage {
    /// `<group label>/<item label>`.
    item: String,
    opens: i64,
    last_opened: Option<chrono::NaiveDate>,
    /// Not opened in the period: a candidate to hide.
    unused: bool,
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct MenuUsageQuery {
    /// Days to look back, 1 to 365 (default 60).
    days: Option<i64>,
}

/// The `<group>/<item>` paths of every item in a cooked menu.
pub(crate) fn menu_item_paths(menu: &Value) -> Vec<String> {
    menu["groups"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|group| {
            let group_label = group["label"].as_str().unwrap_or_default().to_owned();
            group["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(move |item| {
                    item["label"]
                        .as_str()
                        .map(|label| format!("{group_label}/{label}"))
                })
        })
        .collect()
}

/// A21-T5: each item of a published menu with its opens over the last
/// `days` (default 60), the items nobody opened flagged `unused`.
/// Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/navigation/{id}/usage",
    tag = "model",
    params(("id" = Uuid, Path), MenuUsageQuery),
    responses(
        (status = 200, description = "Each item's opens, the unused ones flagged", body = attome_types::PaginatedResponse<MenuItemUsage>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such published menu", body = ErrorResponse),
        (status = 422, description = "days is out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn menu_usage(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<MenuUsageQuery>,
) -> Result<Json<attome_types::PaginatedResponse<MenuItemUsage>>, AppError> {
    let days = query.days.unwrap_or(60);
    if !(1..=365).contains(&days) {
        return Err(AppError::Validation("days is 1 to 365".into()));
    }
    if cooked().snapshot().version == 0 {
        refresh_cooked(&state).await?;
    }
    let cooked_menu = cooked()
        .get::<Value>("navigation", &format!("navigation:{id}"))
        .ok_or(AppError::NotFound)?;
    let rows: Vec<(String, i64, Option<chrono::NaiveDate>)> = sqlx::query_as(
        "SELECT item, SUM(opens)::bigint, MAX(day) FROM menu_item_use \
         WHERE menu_id = $1 AND day > CURRENT_DATE - $2::int GROUP BY item",
    )
    .bind(id)
    .bind(i32::try_from(days).map_err(AppError::internal)?)
    .fetch_all(&state.base.db)
    .await
    .map_err(attome_db::classify)?;
    let used: std::collections::HashMap<String, (i64, Option<chrono::NaiveDate>)> = rows
        .into_iter()
        .map(|(item, opens, last)| (item, (opens, last)))
        .collect();
    let items: Vec<MenuItemUsage> = menu_item_paths(&cooked_menu)
        .into_iter()
        .map(|item| {
            let (opens, last_opened) = used.get(&item).copied().unwrap_or((0, None));
            MenuItemUsage {
                unused: opens == 0,
                item,
                opens,
                last_opened,
            }
        })
        .collect();
    let total = i64::try_from(items.len()).map_err(AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        items,
        total,
        1,
        total.max(1),
    )))
}

/// One object as a readable text file (Y1-T10).
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct ModelFile {
    /// `<kind>/<app>/<name>.json`, always with `/` separators.
    path: String,
    /// Pretty JSON with sorted keys and a trailing newline.
    text: String,
}

/// A set of object files. Not a paginated list: an export is one artefact,
/// written to a directory whole and read back whole.
#[derive(Serialize, Deserialize, ToSchema)]
pub(crate) struct ModelFiles {
    files: Vec<ModelFile>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ImportResponse {
    /// The drafts saved, in file order.
    drafts: Vec<CommandsResponse>,
}

/// The most files one import takes.
const MAX_IMPORT_FILES: usize = 5_000;

/// Exports the newest version (the draft, when there is one) of every object
/// in the store, one file per object. Adapter kinds (entities, attributes)
/// live in their own tables and travel in bundles, not here.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/export",
    tag = "admin",
    responses(
        (status = 200, description = "Every stored object as a file, by path", body = ModelFiles),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export_files(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<ModelFiles>, AppError> {
    let stored: Vec<String> = kinds()
        .iter()
        .filter(|kind| kind.adapter_table().is_none())
        .map(|kind| kind.name().as_str().to_owned())
        .collect();
    let rows = store::export_newest(&state.base.db, &stored).await?;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(kind) = kinds().get(&row.kind) else {
            continue;
        };
        let object = attome_model::files::FileObject {
            kind: kind.name(),
            app: row.app,
            name: row.name,
            schema_version: u32::try_from(row.kind_schema_version).unwrap_or(0),
            doc: row.doc,
        };
        let (path, text) = attome_model::files::to_file(&object);
        let path: Vec<String> = path
            .iter()
            .map(|part| part.to_string_lossy().into_owned())
            .collect();
        files.push(ModelFile {
            path: path.join("/"),
            text,
        });
    }
    Ok(Json(ModelFiles { files }))
}

/// Imports object files as drafts: an object with the same kind, app and
/// name gets a new draft, any other is created. Nothing is published. Every
/// file is read (and upgraded to its kind's current shape) before anything
/// is saved, and all drafts save in one transaction, so a bad file saves
/// nothing.
#[utoipa::path(
    post,
    path = "/api/v1/admin/model/import",
    tag = "admin",
    request_body = ModelFiles,
    responses(
        (status = 200, description = "The drafts saved", body = ImportResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "Another save of one of the objects is in progress", body = ErrorResponse),
        (status = 422, description = "A file is unreadable or its document invalid; the issues are listed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn import_files(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(request): Json<ModelFiles>,
) -> Result<Json<ImportResponse>, AppError> {
    if request.files.len() > MAX_IMPORT_FILES {
        return Err(AppError::Validation(format!(
            "an import takes at most {MAX_IMPORT_FILES} files"
        )));
    }
    let mut objects = Vec::with_capacity(request.files.len());
    let mut issues = Vec::new();
    for file in &request.files {
        match attome_model::files::from_file(kinds(), std::path::Path::new(&file.path), &file.text)
        {
            Ok(object) => {
                let Some(kind) = kinds().get(object.kind.as_str()) else {
                    continue;
                };
                if kind.adapter_table().is_some() {
                    issues.push(Issue::new(
                        &file.path,
                        "adapter_kind",
                        format!("{} objects are not imported as files", object.kind),
                    ));
                    continue;
                }
                issues.extend(
                    attome_model::validate::validate_edit(kind.as_ref(), &object.doc)
                        .into_iter()
                        .map(|issue| Issue {
                            path: format!("{}{}", file.path, issue.path),
                            ..issue
                        }),
                );
                objects.push((kind, object));
            }
            Err(issue) => issues.push(issue),
        }
    }
    if !issues.is_empty() {
        return Err(attome_model::validate::publish_error(&issues));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut drafts = Vec::with_capacity(objects.len());
    for (kind, object) in &objects {
        let kind_name = kind.name();
        let id = store::find_by_name(&mut tx, kind_name.as_str(), &object.app, &object.name)
            .await?
            .unwrap_or_else(Uuid::now_v7);
        let spec = ObjectSpec {
            id: ObjectId(id),
            name: object.name.clone(),
            app: object.app.clone(),
            layer: if object.app == "customer" {
                Layer::Customer
            } else {
                Layer::App
            },
        };
        let saved = store::save_draft(
            &mut tx,
            kinds(),
            kind.as_ref(),
            &spec,
            &object.doc,
            Some(ctx.user_id),
        )
        .await?;
        drafts.push(CommandsResponse {
            id,
            version_no: saved.version_no,
            content_hash: saved.content_hash,
            issues: saved.issues.iter().map(IssueView::from).collect(),
        });
    }
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_object",
            None,
        )
        .named("model.import")
        .comment(format!("{} draft(s) imported from files", drafts.len())),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(ImportResponse { drafts }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/model/kinds", get(list_kinds))
        .route("/api/v1/model/navigation/{id}", get(menu))
        .route(
            "/api/v1/model/navigation/{id}/opened",
            axum::routing::post(menu_item_opened),
        )
        .route("/api/v1/admin/model/navigation/{id}/usage", get(menu_usage))
        .route("/api/v1/admin/model/export", get(export_files))
        .route("/api/v1/admin/model/import", post(import_files))
        .route("/api/v1/admin/model/blueprint/plan", post(blueprint_plan))
        .route("/api/v1/admin/model/blueprint/apply", post(blueprint_apply))
        .route(
            "/api/v1/admin/model/blueprint/rollback",
            post(blueprint_rollback),
        )
        .route("/api/v1/admin/model/{kind}", get(list_objects))
        .route("/api/v1/admin/model/{kind}/{id}", get(get_object))
        .route(
            "/api/v1/admin/model/{kind}/{id}/versions/{version}",
            get(get_version),
        )
        .route("/api/v1/admin/model/{kind}/{id}/history", get(get_history))
        .route("/api/v1/admin/model/{kind}/{id}/diff", get(get_diff))
        .route(
            "/api/v1/admin/model/{kind}/{id}/references",
            get(get_references),
        )
        .route("/api/v1/admin/model/{kind}/{id}/validate", post(validate))
        .route(
            "/api/v1/admin/model/{kind}/{id}/commands",
            post(apply_commands),
        )
        .route("/api/v1/admin/model/{kind}/{id}/publish", post(publish))
        .route("/api/v1/model/forms/{id}/plan", get(form_plan))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        menu_item_opened,
        menu_usage,
        list_kinds,
        list_objects,
        get_object,
        get_version,
        get_history,
        get_diff,
        get_references,
        validate,
        apply_commands,
        publish,
        export_files,
        import_files,
        blueprint_plan,
        blueprint_apply,
        blueprint_rollback,
        menu,
        form_plan
    ),
    components(schemas(
        KindView,
        ObjectSummaryView,
        ObjectVersionView,
        VersionSummaryView,
        PatchOpView,
        ReferenceView,
        IssueView,
        ValidateRequest,
        ModelValidateResponse,
        CommandsRequest,
        CommandsResponse,
        ModelPublishResponse,
        ModelFile,
        ModelFiles,
        MenuView,
        BlueprintItem,
        BlueprintPlan,
        BlueprintApplied,
        BlueprintAppliedItem,
        BlueprintRollback,
        ImportResponse,
        FormPlan,
        FormPlanSection,
        FormPlanField
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod menu_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn menu_item_paths_name_each_item_by_group() {
        let menu = json!({ "groups": [
            { "label": "Sales", "items": [{ "label": "Accounts" }, { "label": "Deals" }] },
            { "label": "Help", "items": [{ "label": "Guide" }] }
        ] });
        assert_eq!(
            menu_item_paths(&menu),
            vec![
                "Sales/Accounts".to_owned(),
                "Sales/Deals".to_owned(),
                "Help/Guide".to_owned()
            ]
        );
    }

    #[test]
    fn a_menu_shows_each_role_only_its_items_and_landing() {
        let (sales, support) = (Uuid::now_v7(), Uuid::now_v7());
        let menu = json!({
            "groups": [
                { "label": "Sales", "items": [
                    { "label": "Accounts", "kind": "url", "url": "/a", "roles": [sales.to_string()] },
                    { "label": "Help", "kind": "url", "url": "/h" }
                ] },
                { "label": "Support", "items": [
                    { "label": "Cases", "kind": "url", "url": "/c", "roles": [support.to_string()] }
                ] }
            ],
            "landing": [{ "role": support.to_string(), "item": "Support/Cases" }]
        });
        let (groups, landing) = menu_for(&menu, &[sales], false);
        assert_eq!(groups.len(), 1, "the support group has nothing for sales");
        assert_eq!(groups[0]["items"].as_array().map(Vec::len), Some(2));
        assert!(
            groups[0]["items"][0].get("roles").is_none(),
            "roles are not sent"
        );
        assert_eq!(landing, None);
        let (groups, landing) = menu_for(&menu, &[support], false);
        assert_eq!(groups.len(), 2);
        assert_eq!(landing.as_deref(), Some("Support/Cases"));
        let (groups, _) = menu_for(&menu, &[], true);
        assert_eq!(groups.len(), 2, "an administrator sees everything");
    }
}

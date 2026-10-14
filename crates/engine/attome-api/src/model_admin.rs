//! The metadata model's admin API (roadmap Y1-T9), under
//! `/api/v1/admin/model`.
//!
//! Thin handlers over `attome_model`: each parses its input, calls one model
//! function and shapes the response. Reads and writes need an administrator
//! (narrower delegated roles are Q12's). The only write,
//! `POST .../commands`, records one Configuration audit event in its own
//! transaction; `POST .../validate` writes nothing.
//!
//! The prefix is `/admin/model`, not `/admin/metadata`, because
//! `/admin/metadata/...` already holds the bundle and sync routes, which a
//! kind of the same name would otherwise be shadowed by.

use std::sync::{Arc, OnceLock};

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_model::commands::{self, Command};
use attome_model::store::{self, ObjectSpec};
use attome_model::{Issue, Kind, KindRegistry, Layer, ObjectId, ObjectRef};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The kinds every engine registers (Y1-T13 adds the first ones).
fn registered_kinds() -> Vec<Arc<dyn Kind>> {
    Vec::new()
}

/// The process-wide kind registry.
pub fn kinds() -> &'static KindRegistry {
    static KINDS: OnceLock<KindRegistry> = OnceLock::new();
    KINDS.get_or_init(|| {
        let mut registry = KindRegistry::default();
        for kind in registered_kinds() {
            if let Err(error) = registry.register(kind) {
                tracing::error!(%error, "metadata kind registered twice; the second is ignored");
            }
        }
        registry
    })
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
pub(crate) struct ValidateResponse {
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
        (status = 200, description = "Whether it is valid, and every issue", body = ValidateResponse),
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
) -> Result<Json<ValidateResponse>, AppError> {
    let kind = kind(&kind_name)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let issues =
        attome_model::validate::validate_save(&mut tx, kinds(), kind.as_ref(), &request.doc)
            .await?;
    tx.rollback().await.map_err(AppError::internal)?;
    Ok(Json(ValidateResponse {
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
    let parsed: Vec<Command> = request
        .commands
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|error| AppError::Validation(format!("a command is malformed: {error}")))?;
    let name = match store::read(&state.base.db, id, None).await {
        Ok(existing) if existing.kind != kind.name().as_str() => return Err(AppError::NotFound),
        Ok(existing) => existing.name,
        Err(AppError::NotFound) => request.name.clone().ok_or_else(|| {
            AppError::Validation("name is required for an object that does not exist yet".into())
        })?,
        Err(other) => return Err(other),
    };
    let object = ObjectSpec {
        id: ObjectId(id),
        name: name.clone(),
        app: "customer".to_owned(),
        layer: Layer::Customer,
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let saved = commands::apply_commands(
        &mut tx,
        kinds(),
        kind.as_ref(),
        &object,
        &request.base_hash,
        &parsed,
        Some(ctx.user_id),
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
        .named("model.commands")
        .comment(format!(
            "{} `{name}` draft v{}: {} command(s)",
            kind.name(),
            saved.version_no,
            parsed.len()
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

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/model/kinds", get(list_kinds))
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
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_kinds,
        list_objects,
        get_object,
        get_version,
        get_history,
        get_diff,
        get_references,
        validate,
        apply_commands
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
        ValidateResponse,
        CommandsRequest,
        CommandsResponse
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

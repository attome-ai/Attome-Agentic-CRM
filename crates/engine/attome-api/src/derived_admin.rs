//! A26-T1: `/api/v1/admin/derived-entities`, defining derived entities
//! (`attome_metadata::provision::derived_entity`): the anchor's rows that
//! match a rule-language condition over the anchor's own fields, read-only
//! (V2-D1628 (1)). Once defined, `GET /api/v1/{name}` lists the members
//! through the anchor's query and every write answers 405.
//!
//! - `GET` lists the definitions.
//! - `PUT /{name}` creates or replaces one: the condition is checked, the
//!   view `xrm_dv_<name>` (and, when `stored`, the membership table
//!   `xrm_dm_<name>`) is recreated with SELECT-only grants.
//! - `DELETE /{name}` drops the view, the membership table and the
//!   definition.
//!
//! All need the data-model administration area; the two writes are audited.

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::EngineState;
use attome_metadata::provision::derived_entity::{self, DerivedEntity, DerivedMode};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;

/// A derived entity's definition.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DerivedEntityView {
    pub name: String,
    /// The entity whose rows it selects.
    pub anchor: String,
    /// A rule-language condition over the anchor's own fields.
    pub condition: String,
    /// `live` or `stored`.
    pub mode: String,
}

impl From<DerivedEntity> for DerivedEntityView {
    fn from(d: DerivedEntity) -> Self {
        Self {
            name: d.name,
            anchor: d.anchor,
            condition: d.condition,
            mode: d.mode.as_str().to_owned(),
        }
    }
}

/// What `PUT` takes.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DerivedEntityBody {
    pub anchor: String,
    pub condition: String,
    /// `live` (the default) or `stored`.
    #[serde(default)]
    pub mode: Option<String>,
}

/// List derived entities
#[utoipa::path(
    get,
    path = "/api/v1/admin/derived-entities",
    operation_id = "list_derived_entities",
    tag = "admin",
    responses(
        (status = 200, description = "Every derived entity, by name", body = PaginatedResponse<DerivedEntityView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
) -> Result<Json<PaginatedResponse<DerivedEntityView>>, AppError> {
    let items: Vec<DerivedEntityView> = derived_entity::list(&state.base.db)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// Create or replace a derived entity
///
/// Checks the condition against the anchor's own fields, recreates the
/// read-only view (and, when stored, the membership table) and saves the
/// definition. Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/derived-entities/{name}",
    operation_id = "put_derived_entity",
    tag = "admin",
    params(("name" = String, Path, description = "The derived entity's name")),
    request_body = DerivedEntityBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The saved definition", body = DerivedEntityView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such anchor entity", body = ErrorResponse),
        (status = 422, description = "A bad name, mode or condition", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(name): Path<String>,
    Json(body): Json<DerivedEntityBody>,
) -> Result<Json<DerivedEntityView>, AppError> {
    let mode = match body.mode.as_deref() {
        None => DerivedMode::Live,
        Some(m) => DerivedMode::parse(m)
            .ok_or_else(|| AppError::Validation("mode is live or stored".into()))?,
    };
    let def = DerivedEntity {
        name,
        anchor: body.anchor,
        condition: body.condition,
        mode,
    };
    let anchor = state
        .entities
        .load()
        .get(&def.anchor)
        .cloned()
        .ok_or(AppError::NotFound)?;
    // Decided before the DDL runs: the registry guard is not held across it.
    let taken = state.entities.load().get(&def.name).is_some();
    derived_entity::install(
        &state.base.db_migrator,
        &state.base.db,
        &def,
        &anchor,
        |_| taken,
        ctx.user_id,
    )
    .await?;
    audit(&state, ctx.user_id, AuditOperation::Update, &def.name).await?;
    // A26-T3: a stored one is filled from the records it already has.
    if def.mode == DerivedMode::Stored {
        crate::derived_maintain::queue_refresh(&state, &def.name).await?;
    }
    Ok(Json(def.into()))
}

/// Delete a derived entity
///
/// Drops its view, its membership table and its definition. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/derived-entities/{name}",
    operation_id = "delete_derived_entity",
    tag = "admin",
    params(("name" = String, Path, description = "The derived entity's name")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Delete)])))),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such derived entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    if !derived_entity::remove(&state.base.db_migrator, &state.base.db, &name).await? {
        return Err(AppError::NotFound);
    }
    audit(&state, ctx.user_id, AuditOperation::Delete, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// What resuming a paused derived entity moved.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DerivedResumed {
    pub name: String,
    /// Members that entered.
    pub entered: usize,
    /// Members that left.
    pub left: usize,
}

/// Resume a paused derived entity
///
/// A stored derived entity is paused when one change would move more than
/// 10,000 members (A26-T2's surge guard). Resuming applies every change held
/// since, then keeps it current again. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/derived-entities/{name}/resume",
    operation_id = "resume_derived_entity",
    tag = "admin",
    params(("name" = String, Path, description = "The derived entity's name")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What moved", body = DerivedResumed),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such derived entity, or its anchor is gone", body = ErrorResponse),
        (status = 409, description = "It is not paused", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn resume(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(name): Path<String>,
) -> Result<Json<DerivedResumed>, AppError> {
    let def = derived_entity::find(&state.base.db, &name)
        .await?
        .ok_or(AppError::NotFound)?;
    let anchor = state
        .entities
        .load()
        .get(&def.anchor)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let moved = derived_entity::resume(&state.base.db, &def, &anchor)
        .await?
        .ok_or(AppError::Conflict("the derived entity is not paused"))?;
    audit(&state, ctx.user_id, AuditOperation::Update, &name).await?;
    Ok(Json(DerivedResumed {
        name,
        entered: moved.enter.len(),
        left: moved.leave.len(),
    }))
}

/// The configuration event of a derived entity change. The DDL cannot share
/// its transaction (it runs on the migrator pool), so it follows the change.
async fn audit(
    state: &EngineState,
    actor: uuid::Uuid,
    operation: AuditOperation,
    name: &str,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_security_event(
        &mut tx,
        &audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            operation,
            actor,
            "derived_entity",
            None,
        )
        .named("metadata.derived_entity")
        .comment(format!("derived entity {name}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/derived-entities", get(list))
        .route(
            "/api/v1/admin/derived-entities/{name}",
            axum::routing::put(put).delete(delete),
        )
        .route(
            "/api/v1/admin/derived-entities/{name}/resume",
            axum::routing::post(resume),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list, put, delete, resume))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

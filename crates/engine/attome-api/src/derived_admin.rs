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
    // Roles are granted `<name>.read` (and `.bulk` for member actions) like
    // any entity's privileges; writes have none, since nothing writes here.
    for (action, what) in [("read", "read"), ("bulk", "act in bulk on the members of")] {
        let key = format!("{}.{action}", def.name);
        attome_security::db::ensure_privilege(
            &state.base.db_migrator,
            &key,
            &key,
            &format!("Derived entity privilege: {what} {}", def.name),
            attome_core::changeset::Layer::Project,
        )
        .await?;
    }
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
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::HardDelete)])))),
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
    audit(&state, ctx.user_id, AuditOperation::HardDelete, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A condition to preview, against the saved version of `name` if any.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DerivedPreviewBody {
    /// The derived entity's name, to compare with its saved version.
    #[serde(default)]
    pub name: Option<String>,
    pub anchor: String,
    pub condition: String,
}

/// A member in a preview.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DerivedSampleMember {
    pub id: uuid::Uuid,
    pub name: Option<String>,
}

/// What saving a condition would select.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DerivedPreview {
    /// Live anchor records matching now.
    pub matching: i64,
    /// Of those, the ones not members of the saved version.
    pub entering: i64,
    /// Members of the saved version that would leave; absent with no saved
    /// version on this anchor.
    pub leaving: Option<i64>,
    pub sample: Vec<DerivedSampleMember>,
}

/// Preview a derived entity
///
/// A26-T4: how many live anchor records the condition selects now, up to
/// 20 of them, and against the saved version of `name`, how many would
/// enter and leave. Writes nothing. Data-model administrators.
#[utoipa::path(
    post,
    path = "/api/v1/admin/derived-entities/preview",
    operation_id = "preview_derived_entity",
    tag = "admin",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "counts what a derived entity condition selects; writes nothing"
    )))),
    request_body = DerivedPreviewBody,
    responses(
        (status = 200, description = "What the condition selects", body = DerivedPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such anchor entity", body = ErrorResponse),
        (status = 422, description = "The condition does not parse or reads past the anchor's own fields", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn preview(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Json(body): Json<DerivedPreviewBody>,
) -> Result<Json<DerivedPreview>, AppError> {
    let anchor = state
        .entities
        .load()
        .get(&body.anchor)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let current = match body.name.as_deref() {
        Some(name) => derived_entity::find(&state.base.db, name).await?,
        None => None,
    };
    let def = DerivedEntity {
        name: body.name.unwrap_or_default(),
        anchor: body.anchor,
        condition: body.condition,
        mode: DerivedMode::Live,
    };
    let p = derived_entity::preview(&state.base.db, &def, &anchor, current.as_ref()).await?;
    Ok(Json(DerivedPreview {
        matching: p.matching,
        entering: p.entering,
        leaving: p.leaving,
        sample: p
            .sample
            .into_iter()
            .map(|m| DerivedSampleMember {
                id: m.id,
                name: m.name,
            })
            .collect(),
    }))
}

/// One part of a condition for one record.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DerivedPartExplained {
    /// The part as written.
    pub part: String,
    /// Whether it holds; absent when a field it reads is empty.
    pub holds: Option<bool>,
    /// The record's value of each field the part reads.
    #[schema(value_type = Object)]
    pub values: serde_json::Map<String, serde_json::Value>,
}

/// Why a record is, or is not, a member.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DerivedExplanation {
    pub record_id: uuid::Uuid,
    pub member: bool,
    pub live: bool,
    pub matches: bool,
    pub parts: Vec<DerivedPartExplained>,
}

/// Explain a derived entity's membership
///
/// A26-T4: each part of the condition with whether it holds for the record
/// and the record's values. Needs the derived entity's read privilege, the
/// anchor's, and access to the record itself.
#[utoipa::path(
    get,
    path = "/api/v1/derived-entities/{entity}/explain/{record_id}",
    operation_id = "explain_derived_membership",
    tag = "records",
    params(
        ("entity" = String, Path, description = "The derived entity"),
        ("record_id" = uuid::Uuid, Path, description = "An anchor record"),
    ),
    responses(
        (status = 200, description = "Why it is or is not a member", body = DerivedExplanation),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such derived entity, or a record the caller may not read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn explain(
    State(state): State<EngineState>,
    ctx: Authorized<attome_server::authz::RecordScoped<attome_security::record_action::Read>>,
    Path((entity, record_id)): Path<(String, uuid::Uuid)>,
) -> Result<Json<DerivedExplanation>, AppError> {
    let e = attome_records::derived_entity::explain_for(&state, &ctx, &entity, record_id).await?;
    Ok(Json(DerivedExplanation {
        record_id: e.record_id,
        member: e.member,
        live: e.live,
        matches: e.matches,
        parts: e
            .parts
            .into_iter()
            .map(|p| DerivedPartExplained {
                part: p.part,
                holds: p.holds,
                values: p.values,
            })
            .collect(),
    }))
}

/// How many weeks a trend covers.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TrendQuery {
    /// 1 to 104; 12 by default.
    pub weeks: Option<i64>,
}

/// One week of membership.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DerivedWeek {
    /// The Monday the week starts on.
    pub week: chrono::NaiveDate,
    pub entered: i64,
    pub left: i64,
    /// Members at the end of the week.
    pub members: i64,
}

/// A derived entity's membership over time
///
/// A26-T4: weekly entries, exits and members, oldest first, from the
/// stored membership's history (a live one has only this week's count).
/// Data-model administrators.
#[utoipa::path(
    get,
    path = "/api/v1/admin/derived-entities/{name}/trend",
    operation_id = "derived_entity_trend",
    tag = "admin",
    params(("name" = String, Path, description = "The derived entity's name"), TrendQuery),
    responses(
        (status = 200, description = "Weekly membership", body = PaginatedResponse<DerivedWeek>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such derived entity, or its anchor is gone", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn trend(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path(name): Path<String>,
    axum::extract::Query(q): axum::extract::Query<TrendQuery>,
) -> Result<Json<PaginatedResponse<DerivedWeek>>, AppError> {
    let def = derived_entity::find(&state.base.db, &name)
        .await?
        .ok_or(AppError::NotFound)?;
    let anchor = state
        .entities
        .load()
        .get(&def.anchor)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let weeks = derived_entity::trend(&state.base.db, &def, &anchor, q.weeks.unwrap_or(12)).await?;
    let items: Vec<DerivedWeek> = weeks
        .into_iter()
        .map(|w| DerivedWeek {
            week: w.week,
            entered: w.entered,
            left: w.left,
            members: w.members,
        })
        .collect();
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// The most members one mass action covers.
pub const MAX_MASS_MEMBERS: i64 = 100_000;

/// A mass action on a derived entity's current members: the anchor's mass
/// operation body (`kind`: `update`, `delete`, `reassign`; `payload`),
/// without a filter.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DerivedMassBody {
    pub kind: String,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub payload: serde_json::Value,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub confirm_estimate_rows: Option<i64>,
}

/// Act on a derived entity's members
///
/// A26-T5: one change over every current member, as the anchor's mass
/// operation (`/api/v1/{entity}/mass`) over the members taken at the
/// start: each record through its normal single-record path (record
/// access, validation, rules, audit), in the background past the inline
/// threshold, with progress, pause, cancel and undo at
/// `/api/v1/mass/{id}`. Needs bulk on the derived entity and the anchor.
#[utoipa::path(
    post,
    path = "/api/v1/derived-entities/{entity}/mass",
    operation_id = "derived_entity_mass",
    tag = "records",
    params(("entity" = String, Path, description = "The derived entity")),
    request_body = DerivedMassBody,
    responses(
        (status = 200, description = "Ran in the request", body = attome_records::mass::MassRun),
        (status = 202, description = "Queued for the background", body = attome_records::mass::MassRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not make this change in bulk", body = ErrorResponse),
        (status = 404, description = "No such derived entity", body = ErrorResponse),
        (status = 422, description = "No members, too many, or an invalid kind or payload", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::BulkAccepted),
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::BulkCompleted),
    ])))),
)]
async fn mass(
    State(state): State<EngineState>,
    ctx: Authorized<attome_server::authz::RecordScoped<attome_security::record_action::Bulk>>,
    Path(entity): Path<String>,
    Json(body): Json<DerivedMassBody>,
) -> Result<(StatusCode, Json<attome_records::mass::MassRun>), AppError> {
    use attome_security::SecurityContextExt;
    let read = attome_records::derived_entity::for_read(&state, &entity)
        .await?
        .ok_or(AppError::NotFound)?;
    ctx.require(&read.anchor, "bulk")?;
    let anchor = state
        .entities
        .load()
        .get(&read.anchor)
        .cloned()
        .ok_or(AppError::NotFound)?;
    let ids =
        derived_entity::member_ids(&state.base.db, &read.definition, &anchor, MAX_MASS_MEMBERS)
            .await?;
    if ids.is_empty() {
        return Err(AppError::Validation(format!("{entity} has no members now")));
    }
    if ids.len() as i64 > MAX_MASS_MEMBERS {
        return Err(AppError::Validation(format!(
            "{entity} has more than {MAX_MASS_MEMBERS} members; act on the anchor with a filter"
        )));
    }
    let start: attome_records::mass::MassStartBody = serde_json::from_value(json!({
        "filter": { "kind": "compare", "field": "id", "op": "in", "value": ids },
        "kind": body.kind,
        "payload": body.payload,
        "reason": body.reason,
        "confirm_estimate_rows": body.confirm_estimate_rows,
    }))
    .map_err(|e| AppError::Validation(format!("invalid mass action: {e}")))?;
    let (run, inline) =
        attome_records::mass::start(&state, &ctx, &read.anchor, start, None).await?;
    let status = if inline {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((status, Json(run)))
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
        .route(
            "/api/v1/admin/derived-entities/preview",
            axum::routing::post(preview),
        )
        .route("/api/v1/admin/derived-entities/{name}/trend", get(trend))
        .route(
            "/api/v1/derived-entities/{entity}/explain/{record_id}",
            get(explain),
        )
        .route(
            "/api/v1/derived-entities/{entity}/mass",
            axum::routing::post(mass),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list, put, delete, resume, preview, explain, trend, mass))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

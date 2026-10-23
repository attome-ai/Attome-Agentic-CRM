//! L1-T5: the data steward's routes over a master entity's golden records.
//!
//! - `POST /api/v1/master/{entity}/{id}/pins` pins an attribute (optionally
//!   setting its value first through the generic update path) and
//!   `DELETE .../pins/{attribute}` unpins it and queues a rebuild.
//! - `POST /api/v1/master/{entity}/contributions/{cid}/release` validates a
//!   held contribution again (with a corrected payload, if one is sent) and
//!   attaches it; `/reject` detaches it with the steward's reason; `/detach`
//!   takes an attached one out of its golden record and queues a rebuild.
//! - `POST /api/v1/master/{entity}/{id}/certify` sets the golden record's
//!   certification: `draft`, `certified` or `retired`.
//! - `GET /api/v1/master/held` lists held contributions, newest first.
//!
//! A steward of the entity's data domain (an owner or steward, L3) or an
//! administrator may act; a steward's held queue holds only their domains'
//! entities. Pins and certification write a Configuration security event in
//! the same transaction as the change.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_core::lineage::manual;
use attome_records::entity_crud::master::{self, Pending, steward};
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most master entities the held queue reads across.
const MAX_MASTER_ENTITIES: i64 = 200;

/// The caller acts on `entity`'s golden records: an administrator, or an
/// owner or steward of the entity's data domain.
async fn require_master_steward(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
) -> Result<(), AppError> {
    if ctx.is_admin {
        return Ok(());
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    if manual::may_document(&mut conn, entity, ctx.user_id).await? {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// `entity` exists and is master data, and the caller stewards it.
async fn master_entity(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
) -> Result<(), AppError> {
    if state.entities.load().get(entity).is_none() {
        return Err(AppError::NotFound);
    }
    require_master_steward(state, ctx, entity).await?;
    if !master::is_master(state, entity).await? {
        return Err(AppError::Validation(format!("{entity} is not master data")));
    }
    Ok(())
}

/// A pin of one attribute.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = MasterPinBody)]
pub struct PinBody {
    pub attribute: String,
    /// The value to set before pinning; the current value is kept when
    /// absent.
    pub value: Option<Value>,
}

/// A held contribution's release; `{}` validates the stored payload again.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[schema(as = MasterReleaseBody)]
pub struct ReleaseBody {
    /// The corrected payload; the stored one is validated again when absent.
    pub payload: Option<Map<String, Value>>,
}

/// A held contribution's rejection.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = MasterRejectBody)]
pub struct RejectBody {
    /// Why it is rejected; kept on the contribution.
    pub reason: String,
}

/// A golden record's new certification.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = MasterCertifyBody)]
pub struct CertifyBody {
    /// `draft`, `certified` or `retired`.
    pub status: String,
}

/// What a release or detach did to the golden record.
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = MasterRebuildQueued)]
pub struct RebuildQueued {
    pub golden_id: Uuid,
    /// False when an identical rebuild was already waiting.
    pub rebuild_queued: bool,
}

/// A certification change.
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = MasterCertified)]
pub struct Certified {
    pub status: String,
    pub previous: String,
}

/// One held contribution.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[schema(as = MasterHeldContribution)]
pub struct HeldContribution {
    pub entity: String,
    pub id: Uuid,
    pub source_system: String,
    pub external_id: String,
    pub received_at: DateTime<Utc>,
    pub held_reason: Option<String>,
}

fn attribute_of(state: &EngineState, entity: &str, attribute: &str) -> Result<(), AppError> {
    let known = state.entities.load().get(entity).is_some_and(|m| {
        m.attrs
            .iter()
            .any(|a| a.logicalname == attribute && !a.is_formula())
    });
    if known {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "{attribute} is not a stored attribute of {entity}"
        )))
    }
}

async fn live_golden(state: &EngineState, entity: &str, golden: Uuid) -> Result<(), AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    if steward::golden_exists(&mut conn, entity, golden).await? {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/master/{entity}/{id}/pins",
    operation_id = "master_pin",
    tag = "admin",
    params(
        ("entity" = String, Path, description = "The master entity"),
        ("id" = Uuid, Path, description = "The golden record"),
    ),
    request_body = PinBody,
    responses(
        (status = 204, description = "Pinned: rebuilds leave the attribute alone"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator or a steward of the entity's domain", body = ErrorResponse),
        (status = 404, description = "No such entity or golden record", body = ErrorResponse),
        (status = 409, description = "The record changed while the value was set", body = ErrorResponse),
        (status = 422, description = "Not master data, an unknown attribute, or an invalid value", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
)]
/// Pins an attribute of a golden record.
///
/// The survivorship rebuild leaves a pinned attribute alone. With `value`,
/// the value is first written through the generic update path (validation,
/// audit, row version); without it the current value is kept.
async fn pin(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, golden)): Path<(String, Uuid)>,
    Json(body): Json<PinBody>,
) -> Result<StatusCode, AppError> {
    master_entity(&state, &ctx, &entity).await?;
    attribute_of(&state, &entity, &body.attribute)?;
    live_golden(&state, &entity, golden).await?;
    if let Some(value) = body.value {
        let row_version: i64 = sqlx::query_scalar(&format!(
            "SELECT row_version FROM {} WHERE id = $1",
            attome_core::quote_ident(&entity)
        ))
        .bind(golden)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let mut patch = Map::new();
        patch.insert(body.attribute.clone(), value);
        attome_records::entity_crud::update_record_for(
            &state,
            &ctx,
            ctx.user_id,
            &entity,
            golden,
            row_version,
            Value::Object(patch),
        )
        .await?;
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    steward::pin(&mut tx, &entity, golden, &body.attribute, ctx.user_id).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            &entity,
            Some(golden),
        )
        .named("master.value_pinned")
        .comment(format!("pinned {entity}.{}", body.attribute)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/v1/master/{entity}/{id}/pins/{attribute}",
    operation_id = "master_unpin",
    tag = "admin",
    params(
        ("entity" = String, Path, description = "The master entity"),
        ("id" = Uuid, Path, description = "The golden record"),
        ("attribute" = String, Path, description = "The pinned attribute"),
    ),
    responses(
        (status = 204, description = "Unpinned; a rebuild is queued"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator or a steward of the entity's domain", body = ErrorResponse),
        (status = 404, description = "No such entity, golden record or pin", body = ErrorResponse),
        (status = 422, description = "Not master data", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
)]
/// Unpins an attribute of a golden record.
///
/// The survivorship rules choose its value again: a rebuild of the golden
/// record is queued.
async fn unpin(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, golden, attribute)): Path<(String, Uuid, String)>,
) -> Result<StatusCode, AppError> {
    master_entity(&state, &ctx, &entity).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !steward::unpin(&mut tx, &entity, golden, &attribute).await? {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            &entity,
            Some(golden),
        )
        .named("master.value_unpinned")
        .comment(format!("unpinned {entity}.{attribute}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    master::queue_rebuild(&state, &entity, golden, ctx.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/master/{entity}/contributions/{cid}/release",
    operation_id = "master_contribution_release",
    tag = "admin",
    params(
        ("entity" = String, Path, description = "The master entity"),
        ("cid" = Uuid, Path, description = "The held contribution"),
    ),
    request_body = ReleaseBody,
    responses(
        (status = 200, description = "Attached; its golden record's rebuild is queued", body = RebuildQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator or a steward of the entity's domain", body = ErrorResponse),
        (status = 404, description = "No such entity or contribution", body = ErrorResponse),
        (status = 409, description = "The contribution is not held", body = ErrorResponse),
        (status = 422, description = "Not master data, or the payload still fails validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
/// Releases a held contribution.
///
/// The payload (the corrected one when sent, else the stored one) is
/// validated again; a valid one is attached to its golden record and a
/// rebuild queued. Of two stewards releasing it at once, one wins.
async fn release(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, cid)): Path<(String, Uuid)>,
    Json(body): Json<ReleaseBody>,
) -> Result<Json<RebuildQueued>, AppError> {
    master_entity(&state, &ctx, &entity).await?;
    let db = &state.base.db;
    let row = steward::contribution(db, &entity, cid)
        .await?
        .ok_or(AppError::NotFound)?;
    if row.status != "held" {
        return Err(AppError::Conflict("the contribution is not held"));
    }
    let payload = body.payload.unwrap_or_else(|| row.payload_object());
    if let Some(reason) = master::validation_failure(&state, &entity, &payload)? {
        return Err(AppError::Validation(reason));
    }
    if !steward::claim_release(db, &entity, cid, &payload).await? {
        return Err(AppError::Conflict("the contribution is not held"));
    }
    let attached = master::attach(
        &state,
        &ctx,
        &entity,
        Pending {
            contribution: cid,
            golden: row.golden_id,
            source_system: &row.source_system,
            external_id: &row.external_id,
            payload: &payload,
        },
    )
    .await;
    match attached {
        Ok((golden_id, rebuild_queued)) => Ok(Json(RebuildQueued {
            golden_id,
            rebuild_queued,
        })),
        Err(e) => {
            steward::hold(db, &entity, cid, "the release could not attach it").await?;
            Err(e)
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/master/{entity}/contributions/{cid}/reject",
    operation_id = "master_contribution_reject",
    tag = "admin",
    params(
        ("entity" = String, Path, description = "The master entity"),
        ("cid" = Uuid, Path, description = "The held contribution"),
    ),
    request_body = RejectBody,
    responses(
        (status = 204, description = "Detached with the reason"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator or a steward of the entity's domain", body = ErrorResponse),
        (status = 404, description = "No such entity or contribution", body = ErrorResponse),
        (status = 409, description = "The contribution is not held", body = ErrorResponse),
        (status = 422, description = "Not master data, or no reason", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
/// Rejects a held contribution.
///
/// It is detached and keeps the steward's reason; it never reaches its
/// golden record.
async fn reject(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, cid)): Path<(String, Uuid)>,
    Json(body): Json<RejectBody>,
) -> Result<StatusCode, AppError> {
    master_entity(&state, &ctx, &entity).await?;
    let reason = body.reason.trim();
    if reason.is_empty() || reason.chars().count() > 1_000 {
        return Err(AppError::Validation(
            "a rejection gives its reason, up to 1000 characters".into(),
        ));
    }
    let db = &state.base.db;
    if steward::contribution(db, &entity, cid).await?.is_none() {
        return Err(AppError::NotFound);
    }
    if !steward::reject(db, &entity, cid, reason).await? {
        return Err(AppError::Conflict("the contribution is not held"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/master/{entity}/contributions/{cid}/detach",
    operation_id = "master_contribution_detach",
    tag = "admin",
    params(
        ("entity" = String, Path, description = "The master entity"),
        ("cid" = Uuid, Path, description = "The attached contribution"),
    ),
    responses(
        (status = 200, description = "Detached; its golden record's rebuild is queued", body = RebuildQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator or a steward of the entity's domain", body = ErrorResponse),
        (status = 404, description = "No such entity or contribution", body = ErrorResponse),
        (status = 409, description = "The contribution is not attached", body = ErrorResponse),
        (status = 422, description = "Not master data", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
/// Detaches a contribution from its golden record.
///
/// The golden record is rebuilt without it; the contribution keeps the
/// golden record's id for its history.
async fn detach(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, cid)): Path<(String, Uuid)>,
) -> Result<Json<RebuildQueued>, AppError> {
    master_entity(&state, &ctx, &entity).await?;
    let db = &state.base.db;
    if steward::contribution(db, &entity, cid).await?.is_none() {
        return Err(AppError::NotFound);
    }
    let golden_id = steward::detach(db, &entity, cid)
        .await?
        .ok_or(AppError::Conflict("the contribution is not attached"))?;
    let rebuild_queued = master::queue_rebuild(&state, &entity, golden_id, ctx.user_id).await?;
    Ok(Json(RebuildQueued {
        golden_id,
        rebuild_queued,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/master/{entity}/{id}/certify",
    operation_id = "master_certify",
    tag = "admin",
    params(
        ("entity" = String, Path, description = "The master entity"),
        ("id" = Uuid, Path, description = "The golden record"),
    ),
    request_body = CertifyBody,
    responses(
        (status = 200, description = "The new and the previous certification", body = Certified),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator or a steward of the entity's domain", body = ErrorResponse),
        (status = 404, description = "No such entity or golden record", body = ErrorResponse),
        (status = 422, description = "Not master data, or an unknown status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
)]
/// Sets a golden record's certification.
///
/// A golden record is `draft` until a steward certifies it; `retired` takes
/// it out of use.
async fn certify(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((entity, golden)): Path<(String, Uuid)>,
    Json(body): Json<CertifyBody>,
) -> Result<Json<Certified>, AppError> {
    master_entity(&state, &ctx, &entity).await?;
    let status = steward::Certification::parse(body.status.trim())
        .ok_or_else(|| AppError::Validation("status is draft, certified or retired".into()))?;
    live_golden(&state, &entity, golden).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let previous = steward::certify(&mut tx, &entity, golden, status, ctx.user_id).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            &entity,
            Some(golden),
        )
        .named("master.certification_set")
        .comment(format!(
            "{entity} golden record {} -> {}",
            previous.as_str(),
            status.as_str()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(Certified {
        status: status.as_str().to_owned(),
        previous: previous.as_str().to_owned(),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/master/held",
    operation_id = "master_held_list",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Held contributions, newest first", body = PaginatedResponse<HeldContribution>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Lists held contributions waiting for a steward.
///
/// An administrator sees every master entity's; a steward sees only the
/// entities of the data domains they own or steward.
async fn held(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<HeldContribution>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let db = &state.base.db;
    let entities: Vec<String> = sqlx::query_scalar(
        "SELECT e.logicalname FROM entity_info e \
          WHERE e.is_master \
            AND ($1 OR EXISTS (SELECT 1 FROM governance_role g \
                                WHERE g.domain_ref = e.domain_ref AND g.user_id = $2 \
                                  AND g.role IN ('owner', 'steward'))) \
          ORDER BY e.logicalname LIMIT $3",
    )
    .bind(ctx.is_admin)
    .bind(ctx.user_id)
    .bind(MAX_MASTER_ENTITIES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut parts = Vec::new();
    for entity in entities {
        if !master::is_master(&state, &entity).await? {
            continue;
        }
        let table = attome_core::quote_ident(
            &attome_metadata::provision::master::contribution_table(&entity),
        );
        // The entity name is bound, never spliced: each part names its own.
        let n = parts.len() + 1;
        parts.push((
            format!(
                "SELECT ${n}::text AS entity, id, source_system, external_id, received_at, \
                        held_reason FROM {table} WHERE status = 'held'"
            ),
            entity,
        ));
    }
    if parts.is_empty() {
        return Ok(Json(PaginatedResponse::new(Vec::new(), 0, page, page_size)));
    }
    let union = parts
        .iter()
        .map(|(sql, _)| sql.as_str())
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let names: Vec<&str> = parts.iter().map(|(_, e)| e.as_str()).collect();
    let count_sql = format!("SELECT count(*) FROM ({union}) h");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql);
    for name in &names {
        count = count.bind(*name);
    }
    let total = count.fetch_one(db).await.map_err(AppError::internal)?;
    let n = names.len();
    let list_sql = format!(
        "SELECT entity, id, source_system, external_id, received_at, held_reason \
           FROM ({union}) h ORDER BY received_at DESC, id DESC LIMIT ${} OFFSET ${}",
        n + 1,
        n + 2
    );
    let mut list = sqlx::query_as::<_, HeldContribution>(&list_sql);
    for name in &names {
        list = list.bind(*name);
    }
    let items = list
        .bind(page_size)
        .bind(offset)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/master/held", get(held))
        .route("/api/v1/master/{entity}/{id}/pins", post(pin))
        .route(
            "/api/v1/master/{entity}/{id}/pins/{attribute}",
            delete(unpin),
        )
        .route("/api/v1/master/{entity}/{id}/certify", post(certify))
        .route(
            "/api/v1/master/{entity}/contributions/{cid}/release",
            post(release),
        )
        .route(
            "/api/v1/master/{entity}/contributions/{cid}/reject",
            post(reject),
        )
        .route(
            "/api/v1/master/{entity}/contributions/{cid}/detach",
            post(detach),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(pin, unpin, release, reject, detach, certify, held),
    components(schemas(
        PinBody,
        ReleaseBody,
        RejectBody,
        CertifyBody,
        RebuildQueued,
        Certified,
        HeldContribution
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

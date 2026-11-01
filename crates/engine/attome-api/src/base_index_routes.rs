//! A1-T5: a base's records across every entity that extends it
//! (`attome_records::base_index`), and rebuilding a base's index.

use attome_core::EngineState;
use attome_records::base_index::{BaseRecord, BaseRecordsQuery, ReindexJob};
use attome_server::authz::{Authorized, Privilege, SelfService, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Serialize;
use utoipa::ToSchema;

/// A base's records
///
/// The records of every entity that extends the base, at any depth, that
/// the caller may read in their own entity: id, entity, owner, status and
/// due time, due first. `owner=me` keeps the caller's own. One-based pages,
/// at most 10,000 records deep.
#[utoipa::path(
    get,
    path = "/api/v1/bases/{base}/records",
    operation_id = "get_base_records",
    tag = "entity",
    params(("base" = String, Path, description = "The base entity's logical name"), BaseRecordsQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<BaseRecord>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No entity extends this base", body = ErrorResponse),
        (status = 422, description = "A bad owner, or a page too deep", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_base_records(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(base): Path<String>,
    Query(q): Query<BaseRecordsQuery>,
) -> Result<Json<PaginatedResponse<BaseRecord>>, AppError> {
    attome_records::base_index::list(&state, &ctx, &base, &q)
        .await
        .map(Json)
}

/// The rebuild, queued.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReindexQueued {
    pub base: String,
}

/// Rebuild a base's index
///
/// Rebuilds the base's index from its entities' tables in the background.
/// The index follows every write by itself; this is for after a restore or
/// a change to which entities extend the base. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/bases/{base}/reindex",
    operation_id = "post_base_reindex",
    tag = "admin",
    params(("base" = String, Path, description = "The base entity's logical name")),
    responses(
        (status = 202, description = "Queued", body = ReindexQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn reindex_base(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(base): Path<String>,
) -> Result<(StatusCode, Json<ReindexQueued>), AppError> {
    if state.entities.load().get(&base).is_none() {
        return Err(AppError::NotFound);
    }
    let job = attome_core::jobs::JOB_TYPES
        .job(
            attome_records::base_index::JOB,
            &ReindexJob { base: base.clone() },
        )
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "base_record_index",
            None,
        )
        .comment(format!("rebuild of the {base} index queued")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::ACCEPTED, Json(ReindexQueued { base })))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/bases/{base}/records", get(list_base_records))
        .route("/api/v1/admin/bases/{base}/reindex", post(reindex_base))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_base_records, reindex_base),
    components(schemas(BaseRecord, ReindexQueued))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

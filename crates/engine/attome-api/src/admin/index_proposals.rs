//! Y2-T10: `GET /api/v1/admin/entities/{entity_id}/index-proposals`, the
//! single-column indexes slow statements suggest for an entity
//! (`attome_metadata::index_advisor`). A builder applies one by making the
//! attribute filterable (`PATCH .../fields/{field_id}`, `is_filterable:
//! true`), which builds the index concurrently. Admin only; reads only.

use std::collections::{BTreeSet, HashMap};

use attome_core::EngineState;
use attome_metadata::index_advisor::{self, Advice};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// One proposed index.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IndexProposalView {
    pub attribute: String,
    /// The attribute to make filterable to build the index.
    pub field_id: Option<Uuid>,
    /// Slow statements that filter on it, and their calls.
    pub statements: i64,
    pub calls: i64,
    pub worst_mean_ms: f64,
}

/// The advice for one entity.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct IndexAdvice {
    /// `false` when pg_stat_statements cannot be read (see `reason`).
    pub available: bool,
    pub reason: Option<String>,
    pub proposals: Vec<IndexProposalView>,
}

/// Index proposals for an entity
///
/// Index proposals for an entity. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/index-proposals",
    tag = "admin",
    params(("entity_id" = Uuid, Path, description = "The entity")),
    responses(
        (status = 200, description = "Proposed indexes, most called first", body = IndexAdvice),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn index_proposals(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity_id): Path<Uuid>,
) -> Result<Json<IndexAdvice>, AppError> {
    let (entity, attributes) = {
        let registry = state.entities.load();
        let meta = registry.get_by_id(entity_id).ok_or(AppError::NotFound)?;
        let attributes: BTreeSet<String> =
            meta.attrs.iter().map(|a| a.logicalname.clone()).collect();
        (meta.logicalname.clone(), attributes)
    };
    let db = &state.base.db;
    let proposals = match index_advisor::proposals(db, &entity, &attributes).await? {
        Advice::Unavailable(reason) => {
            return Ok(Json(IndexAdvice {
                available: false,
                reason: Some(reason),
                proposals: Vec::new(),
            }));
        }
        Advice::Proposals(proposals) => proposals,
    };
    let names: Vec<String> = proposals.iter().map(|p| p.attribute.clone()).collect();
    let ids: HashMap<String, Uuid> = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT logicalname, id FROM attribute_info \
          WHERE entity_ref = $1 AND logicalname = ANY($2) \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .bind(&names)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    Ok(Json(IndexAdvice {
        available: true,
        reason: None,
        proposals: proposals
            .into_iter()
            .map(|p| IndexProposalView {
                field_id: ids.get(&p.attribute).copied(),
                attribute: p.attribute,
                statements: p.statements,
                calls: p.calls,
                worst_mean_ms: p.worst_mean_ms,
            })
            .collect(),
    }))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/entities/{entity_id}/index-proposals",
        get(index_proposals),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(index_proposals))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

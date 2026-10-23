//! L5-T4: the lineage graph routes (`attome_core::lineage::graph`).
//!
//! - `GET /api/v1/lineage/{kind}/{ref}?direction=up|down&depth=&kinds=&version=`
//!   walks from a node: `entity` with `<entity>` or `<entity>.<attribute>`,
//!   or a definition kind (`workflow`, `query`, `metric`, `dashboard`, ...)
//!   with its id. Depth 1 to 10 (default 3); `kinds` (comma separated)
//!   keeps only those definition kinds; `version` reads the graph as it was
//!   after that publish. An administrator sees every node. Anyone else sees
//!   the data of entities they may read; definitions and other data are
//!   counted in `hidden`.
//! - `GET /api/v1/lineage/compare?from=&to=` (administrators) lists the
//!   edges added and removed between two graph versions.
//! - `GET /api/v1/lineage/cleanup` (administrators) lists edges to deleted
//!   entities or attributes, cycles among definitions, and attributes no
//!   definition uses.
//!
//! - `GET /api/v1/lineage/export/openlineage` (administrators, behind
//!   `lineage.export_enabled`) exports the graph as OpenLineage events
//!   ([`lineage_export`], L5-T6).
//!
//! The handlers parse and shape; the engine reads.

/// L5-T6: the graph as OpenLineage events.
pub mod lineage_export;

use attome_core::EngineState;
use attome_core::lineage::graph::{self, Cleanup, Comparison, Direction, Graph, NodeRef};
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WalkQuery {
    /// `down` (what depends on it, the default) or `up` (what it uses).
    pub direction: Option<String>,
    /// 1 to 10 (default 3).
    pub depth: Option<u8>,
    /// Definition kinds to keep, comma separated.
    pub kinds: Option<String>,
    /// The graph version to read as of; the current graph when absent.
    pub version: Option<i64>,
}

/// Walks the lineage graph from a node.
#[utoipa::path(
    get,
    path = "/api/v1/lineage/{kind}/{ref}",
    operation_id = "lineage_walk",
    tag = "admin",
    params(
        ("kind" = String, Path, description = "`entity`, or a definition kind"),
        ("ref" = String, Path, description = "`<entity>[.<attribute>]`, or the definition's id"),
        WalkQuery,
    ),
    responses(
        (status = 200, description = "The nodes and edges reached", body = Graph),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Unknown node, direction or depth", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn walk(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((kind, reference)): Path<(String, String)>,
    Query(q): Query<WalkQuery>,
) -> Result<Json<Graph>, AppError> {
    let start = NodeRef::parse(&kind, &reference).ok_or_else(|| {
        AppError::Validation(
            "name an entity as entity/<entity>[.<attribute>], or a definition by its kind and id"
                .into(),
        )
    })?;
    let direction = match q.direction.as_deref().unwrap_or("down") {
        "down" => Direction::Down,
        "up" => Direction::Up,
        _ => return Err(AppError::Validation("direction is up or down".into())),
    };
    let depth = q.depth.unwrap_or(3);
    if !(1..=graph::MAX_DEPTH).contains(&depth) {
        return Err(AppError::Validation(format!(
            "depth is 1 to {}",
            graph::MAX_DEPTH
        )));
    }
    let kinds: Option<Vec<String>> = q.kinds.as_deref().map(|k| {
        k.split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(str::to_owned)
            .collect()
    });
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let admin = ctx.is_admin;
    let found = graph::walk(
        &mut conn,
        &start,
        direction,
        depth,
        kinds.as_deref(),
        q.version,
        |node| {
            admin
                || matches!(node, NodeRef::Data { entity, .. }
                    if ctx.require(entity, "read").is_ok())
        },
    )
    .await?;
    Ok(Json(found))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CompareQuery {
    pub from: i64,
    pub to: i64,
}

/// Compares the lineage graph at two versions.
#[utoipa::path(
    get,
    path = "/api/v1/lineage/compare",
    operation_id = "lineage_compare",
    tag = "admin",
    params(CompareQuery),
    responses(
        (status = 200, description = "Edges added and removed", body = Comparison),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn compare(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<CompareQuery>,
) -> Result<Json<Comparison>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    Ok(Json(graph::compare(&mut conn, q.from, q.to).await?))
}

/// Lists what needs tidying in the lineage graph.
#[utoipa::path(
    get,
    path = "/api/v1/lineage/cleanup",
    operation_id = "lineage_cleanup",
    tag = "admin",
    responses(
        (status = 200, description = "Dangling edges, cycles and unused attributes", body = Cleanup),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn cleanup(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<Cleanup>, AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    Ok(Json(graph::cleanup(&mut conn).await?))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/lineage/compare", get(compare))
        .route("/api/v1/lineage/cleanup", get(cleanup))
        .route(
            "/api/v1/lineage/export/openlineage",
            get(lineage_export::openlineage),
        )
        .route("/api/v1/lineage/{kind}/{ref}", get(walk))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(walk, compare, cleanup, lineage_export::openlineage))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

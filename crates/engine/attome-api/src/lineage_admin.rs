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
//! - `POST /api/v1/lineage/manual-links` records a hand-documented link
//!   (an outside system, or a definition's use the parser missed, to an
//!   entity or attribute) and `DELETE /api/v1/lineage/manual-links/{id}`
//!   removes one (L5-T5): administrators, or an owner or steward of the
//!   entity's data domain; audited.
//! - `GET /api/v1/lineage/export/openlineage` (administrators, behind
//!   `lineage.export_enabled`) exports the graph as OpenLineage events
//!   ([`lineage_export`], L5-T6).
//!
//! The handlers parse and shape; the engine reads.

/// L5-T6: the graph as OpenLineage events.
pub mod lineage_export;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_core::lineage::graph::{self, Cleanup, Comparison, Direction, Graph, NodeRef};
use attome_core::lineage::manual::{self, LinkFrom, ManualLink};
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

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

/// Walk the lineage graph
///
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

/// Compare lineage versions
///
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

/// Lineage clean-up list
///
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

/// A link to document by hand.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ManualLinkBody {
    /// `system` for an outside system, or a definition kind (`workflow`,
    /// `query`, `metric`, ...).
    pub from_kind: String,
    /// The definition's id (not for a system).
    pub from_ref: Option<Uuid>,
    /// The system's name (for a system); a new name adds the system.
    pub system_name: Option<String>,
    /// What the system is: `connector`, `events`, `import`, `warehouse`,
    /// `source` (default `connector`).
    pub system_kind: Option<String>,
    /// `inbound`, `outbound` or `both` (the default).
    pub direction: Option<String>,
    pub to_entity: String,
    pub to_attribute: Option<String>,
    /// `reads`, `writes`, `derives` or `triggers`.
    pub edge_kind: String,
    /// Why the link exists, as the steward documents it.
    pub note: String,
}

/// A recorded link.
#[derive(Debug, Serialize, ToSchema)]
pub struct ManualLinkRecorded {
    pub id: Uuid,
    /// The node the link starts at (`system:<id>` or `<kind>:<id>`).
    pub from: String,
    pub graph_version: i64,
}

/// The caller documents links to `entity`: an administrator, or an owner or
/// steward of its data domain.
async fn require_lineage_steward(
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

/// Add a lineage link
///
/// Records a hand-documented lineage link.
#[utoipa::path(
    post,
    path = "/api/v1/lineage/manual-links",
    operation_id = "lineage_manual_link_add",
    tag = "admin",
    request_body = ManualLinkBody,
    responses(
        (status = 201, description = "The link is in the graph, marked hand-documented", body = ManualLinkRecorded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator or a steward of the entity's domain", body = ErrorResponse),
        (status = 409, description = "The definition itself already records this link", body = ErrorResponse),
        (status = 422, description = "Unknown entity, kind or direction, or no note", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
)]
async fn add_manual_link(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<ManualLinkBody>,
) -> Result<(StatusCode, Json<ManualLinkRecorded>), AppError> {
    let from = if body.from_kind == "system" {
        LinkFrom::System {
            name: body.system_name.unwrap_or_default(),
            kind: body.system_kind.unwrap_or_else(|| "connector".into()),
            direction: body.direction.unwrap_or_else(|| "both".into()),
        }
    } else {
        LinkFrom::Definition {
            kind: body.from_kind,
            id: body.from_ref.ok_or_else(|| {
                AppError::Validation("from_ref names the definition the link starts at".into())
            })?,
        }
    };
    let link = ManualLink {
        from,
        to_entity: body.to_entity,
        to_attribute: body.to_attribute.filter(|a| !a.trim().is_empty()),
        edge_kind: body.edge_kind,
        note: body.note,
    };
    manual::check(&link)?;
    require_lineage_steward(&state, &ctx, &link.to_entity).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (id, graph_version) = manual::add(&mut tx, &link, ctx.user_id).await?;
    let from: (String, Uuid) =
        sqlx::query_as("SELECT from_kind, from_ref FROM metadata_reference WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let from = format!("{}:{}", from.0, from.1);
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "metadata_reference",
            Some(id),
        )
        .named("lineage.manual_link_added")
        .comment(format!(
            "hand-documented link {from} {} {}{}",
            link.edge_kind,
            link.to_entity,
            link.to_attribute
                .as_deref()
                .map(|a| format!(".{a}"))
                .unwrap_or_default()
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(ManualLinkRecorded {
            id,
            from,
            graph_version,
        }),
    ))
}

/// Remove a lineage link
///
/// Removes a hand-documented lineage link.
#[utoipa::path(
    delete,
    path = "/api/v1/lineage/manual-links/{id}",
    operation_id = "lineage_manual_link_remove",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The link")),
    responses(
        (status = 204, description = "Removed; kept in the graph's history"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator or a steward of the entity's domain", body = ErrorResponse),
        (status = 404, description = "No hand-documented link with that id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::HardDelete)])))),
)]
async fn remove_manual_link(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let entity: Option<String> = sqlx::query_scalar(
        "SELECT to_entity FROM metadata_reference WHERE id = $1 AND confidence = 'hand'",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let entity = entity.ok_or(AppError::NotFound)?;
    require_lineage_steward(&state, &ctx, &entity).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let removed = manual::remove(&mut tx, id).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::HardDelete,
            ctx.user_id,
            "metadata_reference",
            Some(id),
        )
        .named("lineage.manual_link_removed")
        .comment(format!(
            "hand-documented link {}:{} to {}{} removed at graph version {}",
            removed.from_kind,
            removed.from_ref,
            removed.to_entity,
            if removed.to_attribute.is_empty() {
                String::new()
            } else {
                format!(".{}", removed.to_attribute)
            },
            removed.version
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/lineage/compare", get(compare))
        .route("/api/v1/lineage/cleanup", get(cleanup))
        .route("/api/v1/lineage/manual-links", post(add_manual_link))
        .route(
            "/api/v1/lineage/manual-links/{id}",
            delete(remove_manual_link),
        )
        .route(
            "/api/v1/lineage/export/openlineage",
            get(lineage_export::openlineage),
        )
        .route("/api/v1/lineage/{kind}/{ref}", get(walk))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        walk,
        compare,
        cleanup,
        add_manual_link,
        remove_manual_link,
        lineage_export::openlineage
    ),
    components(schemas(ManualLinkBody, ManualLinkRecorded))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

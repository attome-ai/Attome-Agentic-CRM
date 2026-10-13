//! Portal metadata (web-portal plan Phase 5, the `PortalMetadataProjector`):
//! what the portal app needs to draw forms and lists, and nothing a portal
//! user isn't allowed to know.
//!
//! Every entity view is **built from the caller's own access plan**
//! ([`access_plan::describe`]), never filtered down from staff metadata: the
//! fields are the plan's readable and writable ones, and the labels are read
//! for exactly those names. The index only names the entities the caller's
//! role has a grant on (and today's metadata knows), with their labels; their
//! actions and fields come from the entity view. An entity the caller can't reach, whether it exists or not,
//! is the same 404 the record routes give (C4). A child of [`super`], so it
//! shares the session, budget, consent and plan path of the record routes
//! (I-18).

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_records::access_plan::{self, PortalEntityView};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;

use super::{Caller, data_caller, plan_of};
use crate::roles;

/// The most entities one metadata index lists: page 1 of a capped structural
/// result (§12), `total` saying how many there are. A role has a grant per
/// entity; real roles have a handful.
const MAX_INDEXED_ENTITIES: usize = 100;

/// One entity the caller's role has a grant on. Its actions and fields:
/// `GET /{keyword}/api/v1/metadata/{entity}`.
#[derive(Serialize, ToSchema)]
pub struct PortalEntitySummary {
    pub entity: String,
    pub label: Option<String>,
}

impl std::fmt::Debug for PortalEntitySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalEntitySummary")
            .finish_non_exhaustive()
    }
}

/// The display labels of `entities` (one statement).
async fn entity_labels(
    state: &EngineState,
    entities: &[String],
) -> Result<BTreeMap<String, String>, AppError> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT logicalname, name FROM entity_info          WHERE logicalname = ANY($1) AND is_active IS NOT FALSE",
    )
    .bind(entities)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(entity, label)| Some((entity, label?)))
        .collect())
}

/// The display labels of `entity` and of exactly `fields` of it (one
/// statement). Names outside `fields` are never read.
async fn labels(
    state: &EngineState,
    entity: &str,
    fields: &[String],
) -> Result<(Option<String>, BTreeMap<String, String>), AppError> {
    let rows: Vec<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT e.name, a.logicalname, a.name FROM entity_info e \
         LEFT JOIN attribute_info a ON a.entity_ref = e.id \
              AND a.logicalname = ANY($2) AND a.is_active IS NOT FALSE \
         WHERE e.logicalname = $1 AND e.is_active IS NOT FALSE",
    )
    .bind(entity)
    .bind(fields)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let entity_label = rows.first().and_then(|r| r.0.clone());
    let labels = rows
        .into_iter()
        .filter_map(|(_, field, label)| Some((field?, label?)))
        .collect();
    Ok((entity_label, labels))
}

/// The caller's view of `entity`, or `None` when they can't reach it.
async fn view(
    state: &EngineState,
    caller: &Caller,
    entity: &str,
) -> Result<Option<PortalEntityView>, AppError> {
    // `write` so `can_create` reflects a live owning team (G-15).
    let Some(plan) = plan_of(state, caller, entity, true).await? else {
        return Ok(None);
    };
    let fields: Vec<String> = plan.readable.union(&plan.writable).cloned().collect();
    let (entity_label, labels) = labels(state, entity, &fields).await?;
    Ok(Some(access_plan::describe(
        &plan,
        &state.entities.load(),
        entity_label,
        &labels,
    )))
}

#[utoipa::path(
    get,
    operation_id = "portal_metadata_index",
    path = "/{keyword}/api/v1/metadata",
    tag = "entity",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    responses(
        (status = 200, description = "The entities the caller's role has a grant on (page 1, at most 100; `total` counts them all)", body = PaginatedResponse<PortalEntitySummary>),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 403, description = "Consent to the portal's current terms is missing", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn metadata_index(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PaginatedResponse<PortalEntitySummary>>, AppError> {
    let caller = data_caller(&state, &keyword, &headers, false).await?;
    let mut entities = match caller.principal.role_id {
        Some(role_id) => {
            let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
            roles::granted_entities(&mut conn, caller.entry.detail.id, role_id).await?
        }
        None => Vec::new(),
    };
    {
        let registry = state.entities.load();
        entities.retain(|e| registry.get(e).is_some());
    }
    let total = i64::try_from(entities.len()).unwrap_or(i64::MAX);
    entities.truncate(MAX_INDEXED_ENTITIES);
    let labels = entity_labels(&state, &entities).await?;
    let items = entities
        .into_iter()
        .map(|entity| PortalEntitySummary {
            label: labels.get(&entity).cloned(),
            entity,
        })
        .collect();
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_INDEXED_ENTITIES as i64,
    }))
}

#[utoipa::path(
    get,
    operation_id = "portal_metadata_entity",
    path = "/{keyword}/api/v1/metadata/{entity}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
    ),
    responses(
        (status = 200, description = "The entity's actions and the fields the caller may read or write", body = PortalEntityView),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 403, description = "Consent to the portal's current terms is missing", body = ErrorResponse),
        (status = 404, description = "No such portal, or no access to this entity (indistinguishable from a missing one)", body = ErrorResponse),
    ),
)]
async fn metadata_entity(
    State(state): State<EngineState>,
    Path((keyword, entity)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<PortalEntityView>, AppError> {
    let caller = data_caller(&state, &keyword, &headers, false).await?;
    view(&state, &caller, &entity)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/{keyword}/api/v1/metadata", get(metadata_index))
        .route("/{keyword}/api/v1/metadata/{entity}", get(metadata_entity))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(metadata_index, metadata_entity))]
pub(super) struct MetadataApiDoc;

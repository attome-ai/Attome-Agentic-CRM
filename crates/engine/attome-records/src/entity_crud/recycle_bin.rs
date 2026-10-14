//! The recycle bin's list (roadmap A18-T7, first slice): an entity's deleted
//! records the caller may see, newest deletion first. A deleted record comes
//! back through `POST /api/v1/{entity}/{id}/restore`.
//!
//! Visibility is the entity's own record rules, through the same
//! `rls_predicate` every read uses: a deleted record the caller could not
//! read while it was live stays out of their bin.

use attome_core::{EngineState, quote_ident};
use attome_security::record_action::Read;
use attome_security::{RecordAction, SecurityContextExt};
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use super::resolve::resolve_entity;

/// One deleted record.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DeletedRecord {
    pub id: Uuid,
    /// The record's primary name, when its entity declares one.
    pub label: Option<String>,
    /// When it was last changed, which for a deleted record is its deletion.
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by: Option<Uuid>,
}

/// A page of `entity`'s deleted records the caller may see.
pub async fn deleted_records(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    query: &OnePageQuery,
) -> Result<PaginatedResponse<DeletedRecord>, AppError> {
    let window = query.window();
    let (entity_id, entity, _, is_append_only) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity, "read")?;
    if is_append_only {
        // An append-only entity never deletes, so its bin is always empty.
        return Ok(PaginatedResponse::new(
            Vec::new(),
            0,
            window.page,
            window.page_size,
        ));
    }
    let name_attr = state
        .entities
        .load()
        .get(&entity)
        .and_then(|m| m.primary_name_attribute.clone());
    let access_level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        &entity,
        RecordAction::Read,
    )
    .await?;
    let table = quote_ident(&entity);
    let name_expr = name_attr.as_deref().map_or_else(
        || "NULL::text".to_owned(),
        |c| format!("{}::text", quote_ident(c)),
    );

    let count_pred = attome_security::rls_predicate(
        ctx,
        entity_id,
        "",
        access_level,
        RecordAction::Read.share_capability(),
        1,
    );
    let count_sql = format!(
        "SELECT COUNT(*) FROM {table} WHERE is_active = false {}",
        count_pred.as_ref().map_or("", |p| p.sql.as_str())
    );
    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    if let Some(p) = &count_pred {
        count_query = count_query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    let total = count_query
        .fetch_one(&state.base.db)
        .await
        .map_err(attome_db::classify)?;

    let pred = attome_security::rls_predicate(
        ctx,
        entity_id,
        "",
        access_level,
        RecordAction::Read.share_capability(),
        3,
    );
    let sql = format!(
        "SELECT id, {name_expr} AS label, modified_at AS deleted_at, modified_by AS deleted_by \
         FROM {table} WHERE is_active = false {} \
         ORDER BY modified_at DESC NULLS LAST, id DESC LIMIT $1 OFFSET $2",
        pred.as_ref().map_or("", |p| p.sql.as_str())
    );
    let mut rows_query = sqlx::query_as::<_, DeletedRecord>(&sql)
        .bind(window.page_size)
        .bind(window.offset);
    if let Some(p) = &pred {
        rows_query = rows_query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    let items = rows_query
        .fetch_all(&state.base.db)
        .await
        .map_err(attome_db::classify)?;
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

/// A18-T7: the entity's deleted records the caller may see, newest
/// deletion first. Restore one with `POST /api/v1/{entity}/{id}/restore`.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/deleted",
    tag = "entity",
    params(("entity" = String, Path), OnePageQuery),
    responses(
        (status = 200, description = "A page of deleted records", body = PaginatedResponse<DeletedRecord>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_deleted(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path(entity): Path<String>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DeletedRecord>>, AppError> {
    Ok(Json(deleted_records(&state, &ctx, &entity, &query).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_deleted))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

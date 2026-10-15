//! Y12-T2: `GET /api/v1/admin/entities/{entity_id}/ddl-log`, every DDL
//! statement the provisioning engine ran against an entity's table, newest
//! first, with how long it took, how many lock retries it needed and how it
//! ended. Admin only. Written by `attome_metadata`'s `exec_ddl_locked`.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// One DDL statement as the ledger recorded it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DdlLogEntry {
    pub id: Uuid,
    pub entity: String,
    /// The statement's leading keywords, e.g. `ALTER TABLE`.
    pub statement_kind: String,
    /// The DDL text (never values; at most 4000 characters).
    pub statement: String,
    pub metadata_change_id: Option<i64>,
    pub actor: Option<Uuid>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub duration_ms: i32,
    pub rows_touched: Option<i64>,
    pub attempts: i32,
    /// `ok`, `lock_timeout` or `failed`.
    pub outcome: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/ddl-log",
    tag = "admin",
    params(("entity_id" = Uuid, Path), OnePageQuery),
    responses(
        (status = 200, description = "The entity's DDL statements, newest first", body = PaginatedResponse<DdlLogEntry>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_ddl_log(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(entity_id): Path<Uuid>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DdlLogEntry>>, AppError> {
    let entity = state
        .entities
        .load()
        .get_by_id(entity_id)
        .map(|meta| meta.logicalname.clone())
        .ok_or(AppError::NotFound)?;
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let db = &state.base.db;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM ddl_log WHERE entity = $1")
        .bind(&entity)
        .fetch_one(db)
        .await
        .map_err(attome_db::classify)?;
    let items: Vec<DdlLogEntry> = sqlx::query_as(
        "SELECT id, entity, statement_kind, statement, metadata_change_id, actor, started_at, \
                duration_ms, rows_touched, attempts, outcome \
           FROM ddl_log WHERE entity = $1 \
          ORDER BY started_at DESC, id DESC LIMIT $2 OFFSET $3",
    )
    .bind(&entity)
    .bind(page_size)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/entities/{entity_id}/ddl-log",
        get(list_ddl_log),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_ddl_log))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

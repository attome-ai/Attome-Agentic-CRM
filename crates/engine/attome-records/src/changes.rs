//! AA7-T4: `POST /api/v1/query/changes` — what changed in one entity since a
//! cursor, as the caller may see it.
//!
//! The cursor is a position in the change feed (`entity_change_event`),
//! sealed by `attome_types::cursor` so a client cannot forge one: a cursor
//! the server did not issue is `400 invalid_cursor`. With no cursor the read
//! starts now and answers only a cursor, the starting point for the next
//! call. Each call reads up to `page_size` finished events for the entity
//! after the cursor (`change_feed::read_after_for_entity`, the feed's own
//! visibility gate), then reads the records they touched with the caller's
//! record-level access:
//!
//! - a record the caller may read now is in `upserted`, as the record read
//!   answers it (field security applied);
//! - a record that is gone, or that the caller may no longer read, is in
//!   `removed` with its id only, so a record newly hidden from the caller
//!   leaves their copy without its data leaking.
//!
//! A record changed several times in one page is read once. The answer's
//! `next_cursor` resumes after the last event read; a page shorter than
//! `page_size` means the caller is up to date.

use std::collections::HashSet;

use attome_core::EngineState;
use attome_core::change_feed::{CursorPosition, horizon, read_after_for_entity};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::entity_crud::EntityRecordResponse;

/// Events read per call when the request names no `page_size`.
const DEFAULT_PAGE_SIZE: i64 = 100;

/// The most events one call reads.
const MAX_PAGE_SIZE: i64 = 500;

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangesRequest {
    /// The entity's logical name.
    pub entity: String,
    /// The `next_cursor` of the previous call; absent to start from now.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Change events to read, 1 to 500 (default 100).
    #[serde(default)]
    pub page_size: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChangesResponse {
    /// Records added or changed since the cursor that the caller may read.
    pub upserted: Vec<EntityRecordResponse>,
    /// Records deleted since the cursor, or no longer visible to the caller.
    pub removed: Vec<Uuid>,
    /// Where the next call resumes.
    pub next_cursor: String,
    /// Whether the page was full: more changes may be waiting.
    pub has_more: bool,
}

fn seal_position(position: CursorPosition) -> String {
    attome_types::cursor::seal(&format!(
        "{}:{}",
        position.last_commit_xid,
        position
            .last_id
            .map(|id| id.to_string())
            .unwrap_or_default()
    ))
}

fn open_position(sealed: &str) -> Result<CursorPosition, AppError> {
    let raw = attome_types::cursor::open(sealed)?;
    let (xid, id) = raw.split_once(':').ok_or(AppError::InvalidCursor)?;
    let last_commit_xid: i64 = xid.parse().map_err(|_| AppError::InvalidCursor)?;
    let last_id = if id.is_empty() {
        None
    } else {
        Some(Uuid::parse_str(id).map_err(|_| AppError::InvalidCursor)?)
    };
    Ok(CursorPosition {
        last_commit_xid,
        last_id,
    })
}

/// The ids among `ids` that are live and that `ctx` may read in `entity`.
async fn readable_ids(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_id: Uuid,
    entity: &str,
    ids: &[Uuid],
) -> Result<HashSet<Uuid>, AppError> {
    let level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        entity,
        attome_security::RecordAction::Read,
    )
    .await?;
    let predicate = if ctx.is_admin || level == AccessLevel::Global {
        None
    } else {
        attome_security::rls_predicate(
            ctx,
            entity_id,
            "",
            level,
            attome_security::RecordAction::Read.share_capability(),
            2,
        )
    };
    let table = attome_core::quote_ident(entity);
    let sql = format!(
        "SELECT id FROM {table} WHERE id = ANY($1) AND (is_active IS NULL OR is_active = TRUE) {}",
        predicate.as_ref().map_or("", |p| p.sql.as_str())
    );
    let sql = attome_db::tag_dynamic("records.changes", &sql);
    let mut query = sqlx::query_scalar::<_, Uuid>(&sql).bind(ids);
    if let Some(p) = &predicate {
        query = query
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    let visible = query
        .fetch_all(state.base.read_pool(ctx.user_id).await)
        .await
        .map_err(AppError::internal)?;
    Ok(visible.into_iter().collect())
}

/// What changed in an entity since a cursor
///
/// AA7-T4: records added, changed or removed since `cursor`, as the caller
/// may see them now. A record the caller can no longer read is listed in
/// `removed` with its id only. Without a cursor the read starts now.
#[utoipa::path(
    post,
    path = "/api/v1/query/changes",
    tag = "query",
    operation_id = "query_changes",
    request_body = ChangesRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "reads the change feed and the caller's visible records; writes nothing",
    )))),
    responses(
        (status = 200, description = "The changes since the cursor, and the cursor to resume from", body = ChangesResponse),
        (status = 400, description = "A cursor this deployment did not issue", body = ErrorResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The caller may not read this entity", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "page_size out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn changes(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped>,
    Json(body): Json<ChangesRequest>,
) -> Result<Json<ChangesResponse>, AppError> {
    let page_size = body.page_size.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(AppError::Validation(format!(
            "page_size must be between 1 and {MAX_PAGE_SIZE}"
        )));
    }
    let (entity_id, entity) = state
        .entities
        .load()
        .get(&body.entity)
        .map(|meta| (meta.entity_id, meta.logicalname.clone()))
        .ok_or(AppError::NotFound)?;
    ctx.require(&entity, "read")?;

    let mut conn = state
        .base
        .read_pool(ctx.user_id)
        .await
        .acquire()
        .await
        .map_err(AppError::internal)?;
    let Some(cursor) = body.cursor.as_deref() else {
        let start = horizon(&mut conn).await?;
        return Ok(Json(ChangesResponse {
            upserted: Vec::new(),
            removed: Vec::new(),
            next_cursor: seal_position(start),
            has_more: false,
        }));
    };
    let position = open_position(cursor)?;
    let (events, next) = read_after_for_entity(&mut conn, &entity, position, page_size).await?;
    drop(conn);
    let has_more = i64::try_from(events.len()).unwrap_or(i64::MAX) >= page_size;

    // Each record once, in the order its latest change was read.
    let mut ids: Vec<Uuid> = Vec::new();
    for event in events.iter().rev() {
        if !ids.contains(&event.record_id) {
            ids.push(event.record_id);
        }
    }
    ids.reverse();
    let visible = readable_ids(&state, &ctx, entity_id, &entity, &ids).await?;

    let mut upserted = Vec::new();
    let mut removed = Vec::new();
    for id in ids {
        if !visible.contains(&id) {
            removed.push(id);
            continue;
        }
        // The record read applies field security; a record that went away
        // between the two reads counts as removed.
        match crate::entity_crud::read_record(&state, &ctx, &entity, id).await {
            Ok(record) => upserted.push(record),
            Err(AppError::NotFound | AppError::Forbidden) => removed.push(id),
            Err(other) => return Err(other),
        }
    }
    Ok(Json(ChangesResponse {
        upserted,
        removed,
        next_cursor: seal_position(next),
        has_more,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_position_round_trips_and_a_forged_cursor_is_refused() {
        let position = CursorPosition {
            last_commit_xid: 4242,
            last_id: Some(Uuid::now_v7()),
        };
        let sealed = seal_position(position);
        let back = open_position(&sealed).unwrap();
        assert_eq!(back.last_commit_xid, 4242);
        assert_eq!(back.last_id, position.last_id);
        let start = open_position(&seal_position(CursorPosition {
            last_commit_xid: 7,
            last_id: None,
        }))
        .unwrap();
        assert_eq!(start.last_id, None);
        assert!(matches!(
            open_position("not-a-cursor"),
            Err(AppError::InvalidCursor)
        ));
        let unsealed = attome_types::cursor::seal("garbage");
        assert!(matches!(
            open_position(&unsealed),
            Err(AppError::InvalidCursor)
        ));
    }
}

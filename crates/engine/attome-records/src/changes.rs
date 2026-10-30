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
//!
//! **Delta tokens** (L7-T4). `GET /api/v1/{entity}?delta_token=` and
//! `query/execute`'s `delta_token` answer the same question for a filtered
//! list: [`delta_window`] reads the feed after the token, then the caller runs
//! its own list or query restricted to the touched ids, so the list's filters,
//! record scope and field security decide what comes back. A record that
//! comes back is `created` when its first change in the window made it, else
//! `updated`; a touched record that does not come back (deleted, hidden from
//! the caller, or no longer matching the filters) is `deleted`. The token is
//! the feed position, when it was issued and a version (`d1`), sealed by
//! `attome_types::cursor`; `latest` asks for a first token and no changes. A
//! token older than `change_feed.retention_days` is `410 resync_needed`: the
//! events after it may have been pruned, so the client reads the list again.

use std::collections::HashSet;

use chrono::Utc;

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

/// L7-T4: a delta token's version tag.
const DELTA_VERSION: &str = "d1";

/// L7-T4: the most change events one delta answer reads.
pub const DELTA_PAGE: i64 = 200;

/// L7-T4: the value of `delta_token` that asks for a first token.
pub const DELTA_LATEST: &str = "latest";

/// L7-T4: a delta token for `position`, issued at `issued_unix`.
pub fn seal_delta(position: CursorPosition, issued_unix: i64) -> String {
    attome_types::cursor::seal(&format!(
        "{DELTA_VERSION}:{}:{}:{issued_unix}",
        position.last_commit_xid,
        position
            .last_id
            .map(|id| id.to_string())
            .unwrap_or_default()
    ))
}

/// L7-T4: a delta token's position and issue time; `InvalidCursor` for
/// anything this deployment did not issue, or another version.
pub fn open_delta(token: &str) -> Result<(CursorPosition, i64), AppError> {
    let raw = attome_types::cursor::open(token)?;
    let mut parts = raw.splitn(4, ':');
    if parts.next() != Some(DELTA_VERSION) {
        return Err(AppError::InvalidCursor);
    }
    let last_commit_xid: i64 = parts
        .next()
        .and_then(|x| x.parse().ok())
        .ok_or(AppError::InvalidCursor)?;
    let last_id = match parts.next().ok_or(AppError::InvalidCursor)? {
        "" => None,
        id => Some(Uuid::parse_str(id).map_err(|_| AppError::InvalidCursor)?),
    };
    let issued: i64 = parts
        .next()
        .and_then(|t| t.parse().ok())
        .ok_or(AppError::InvalidCursor)?;
    Ok((
        CursorPosition {
            last_commit_xid,
            last_id,
        },
        issued,
    ))
}

/// L7-T4: whether a token issued at `issued_unix` is older than the feed
/// keeps. Pure.
pub fn past_retention(issued_unix: i64, now_unix: i64, retention_days: i64) -> bool {
    now_unix.saturating_sub(issued_unix) > retention_days.saturating_mul(86_400)
}

/// L7-T4: what a list or query answers to a delta token.
#[derive(Debug, Serialize, ToSchema)]
pub struct EntityDelta {
    /// Records made since the token that the list now holds, as it shows them.
    #[schema(value_type = Vec<Object>)]
    pub created: Vec<serde_json::Value>,
    /// Records changed since the token that the list now holds.
    #[schema(value_type = Vec<Object>)]
    pub updated: Vec<serde_json::Value>,
    /// Records changed since the token that the list no longer holds:
    /// deleted, hidden from the caller, or no longer matching its filters.
    pub deleted: Vec<Uuid>,
    /// The token for the next call.
    pub next_token: String,
    /// Whether more changes wait: call again with `next_token` at once.
    pub has_more: bool,
}

/// L7-T4: the records the feed says changed in `entity` after `token`.
#[derive(Debug, Clone, Default)]
pub struct DeltaWindow {
    /// Each changed record once, oldest change first.
    pub touched: Vec<Uuid>,
    /// Those whose first change in the window made them.
    pub created: HashSet<Uuid>,
    pub next_token: String,
    pub has_more: bool,
}

impl DeltaWindow {
    /// The answer, given the touched records the list or query now holds
    /// (each with its `id`). Pure.
    pub fn answer(self, rows: Vec<serde_json::Value>) -> EntityDelta {
        let mut held: HashSet<Uuid> = HashSet::new();
        let (mut created, mut updated) = (Vec::new(), Vec::new());
        for row in rows {
            let Some(id) = row
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                continue;
            };
            if !held.insert(id) {
                continue;
            }
            if self.created.contains(&id) {
                created.push(row);
            } else {
                updated.push(row);
            }
        }
        EntityDelta {
            created,
            updated,
            deleted: self
                .touched
                .into_iter()
                .filter(|id| !held.contains(id))
                .collect(),
            next_token: self.next_token,
            has_more: self.has_more,
        }
    }
}

/// L7-T4: the change feed for `entity` after `token`, as `ctx` may read the
/// entity (`{entity}.read`); `latest` gives a first token and no changes.
pub async fn delta_window(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    token: &str,
) -> Result<DeltaWindow, AppError> {
    let entity = state
        .entities
        .load()
        .get(entity)
        .map(|meta| meta.logicalname.clone())
        .ok_or(AppError::NotFound)?;
    ctx.require(&entity, "read")?;
    let now = Utc::now().timestamp();
    let mut conn = state
        .base
        .read_pool(ctx.user_id)
        .await
        .acquire()
        .await
        .map_err(AppError::internal)?;
    if token.trim() == DELTA_LATEST {
        let start = horizon(&mut conn).await?;
        return Ok(DeltaWindow {
            next_token: seal_delta(start, now),
            ..DeltaWindow::default()
        });
    }
    let (position, issued) = open_delta(token.trim())?;
    if past_retention(issued, now, state.base.config.change_feed.retention_days) {
        return Err(AppError::ResyncNeeded);
    }
    let (events, next) = read_after_for_entity(&mut conn, &entity, position, DELTA_PAGE).await?;
    drop(conn);
    let has_more = i64::try_from(events.len()).unwrap_or(i64::MAX) >= DELTA_PAGE;
    let mut window = DeltaWindow {
        // A full page keeps the old issue time: the client is still catching
        // up from it. Up to date, the token is as fresh as now.
        next_token: seal_delta(next, if has_more { issued } else { now }),
        has_more,
        ..DeltaWindow::default()
    };
    for event in &events {
        if window.touched.contains(&event.record_id) {
            continue;
        }
        window.touched.push(event.record_id);
        if event.operation() == Some(attome_core::change_feed::ChangeOperation::Create) {
            window.created.insert(event.record_id);
        }
    }
    Ok(window)
}

/// The ids among `ids` that are live and that `ctx` may read in `entity`.
pub async fn readable_ids(
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
    let sql = format!(
        "SELECT id FROM {table} WHERE id = ANY($1) AND (is_active IS NULL OR is_active = TRUE) {}",
        predicate.as_ref().map_or("", |p| p.sql.as_str()),
        table = attome_core::quote_ident(entity)
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
    changes_since(&state, &ctx, &body).await.map(Json)
}

/// AA7-T4: what changed in `request.entity` since its cursor, as `ctx` may
/// read it now. The route's body, and what an agent's `query.changes` tool
/// calls in-process (AA7-T10).
pub async fn changes_since(
    state: &EngineState,
    ctx: &SecurityContext,
    body: &ChangesRequest,
) -> Result<ChangesResponse, AppError> {
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
        return Ok(ChangesResponse {
            upserted: Vec::new(),
            removed: Vec::new(),
            next_cursor: seal_position(start),
            has_more: false,
        });
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
    let visible = readable_ids(state, ctx, entity_id, &entity, &ids).await?;

    let mut upserted = Vec::new();
    let mut removed = Vec::new();
    for id in ids {
        if !visible.contains(&id) {
            removed.push(id);
            continue;
        }
        // The record read applies field security; a record that went away
        // between the two reads counts as removed.
        match crate::entity_crud::read_record(state, ctx, &entity, id).await {
            Ok(record) => upserted.push(record),
            Err(AppError::NotFound | AppError::Forbidden) => removed.push(id),
            Err(other) => return Err(other),
        }
    }
    // AA7-T9: how large each read of the feed is.
    attome_server::metrics::record_delta_rows(upserted.len() + removed.len());
    Ok(ChangesResponse {
        upserted,
        removed,
        next_cursor: seal_position(next),
        has_more,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // feature: L7
    #[test]
    fn a_delta_token_round_trips_and_ages_out() {
        let position = CursorPosition {
            last_commit_xid: 99,
            last_id: Some(Uuid::now_v7()),
        };
        let token = seal_delta(position, 1_700_000_000);
        let (back, issued) = open_delta(&token).unwrap();
        assert_eq!(back.last_commit_xid, 99);
        assert_eq!(back.last_id, position.last_id);
        assert_eq!(issued, 1_700_000_000);
        // A changes cursor is not a delta token, and neither is a forgery.
        assert!(matches!(
            open_delta(&seal_position(position)),
            Err(AppError::InvalidCursor)
        ));
        assert!(matches!(
            open_delta("d1:1::2"),
            Err(AppError::InvalidCursor)
        ));
        assert!(!past_retention(1_000, 1_000 + 30 * 86_400, 30));
        assert!(past_retention(1_000, 1_000 + 30 * 86_400 + 1, 30));
    }

    // feature: L7
    #[test]
    fn a_delta_answer_splits_created_updated_and_deleted() {
        let (a, b, c, d) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let window = DeltaWindow {
            touched: vec![a, b, c, d],
            created: HashSet::from([a, c]),
            next_token: "next".into(),
            has_more: false,
        };
        let delta = window.answer(vec![
            serde_json::json!({"id": a, "name": "new"}),
            serde_json::json!({"id": b, "name": "changed"}),
        ]);
        assert_eq!(delta.created.len(), 1);
        assert_eq!(delta.created[0]["name"], "new");
        assert_eq!(delta.updated[0]["id"], serde_json::json!(b));
        assert_eq!(
            delta.deleted,
            vec![c, d],
            "made then gone, or no longer in the list"
        );
        assert_eq!(delta.next_token, "next");
    }

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

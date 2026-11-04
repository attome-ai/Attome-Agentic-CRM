//! E9-T8: hand-offs and nurture over HTTP.
//!
//! - `POST /api/v1/marketing/handoffs/{id}/accept` and `.../return`
//!   (`{reason, wake_up_on?}`): only the hand-off's assignee or their
//!   manager (the holders of the parent position of a position the assignee
//!   holds, as the SLA sweep reads it), or an administrator. Accepting moves
//!   a pending or overdue hand-off to `accepted`; returning goes through
//!   [`crate::nurture_handoff::recycle`] (returned with the reason, and the
//!   person nurtured again from `wake_up_on` when the programme recycles).
//!   Both are audited in the change's transaction.
//! - `GET /api/v1/marketing/handoffs?status&page&page_size`: the caller's
//!   own hand-offs; with `marketing_nurture_program.read` (or as an
//!   administrator) every hand-off, of people the caller may read.
//! - `GET /api/v1/marketing/people/{person_id}/nurture-history?entity=`:
//!   the person's nurture states, the content they have seen and their
//!   hand-offs; 404 for a person the caller cannot read.
//! - `GET /api/v1/marketing/nurture/programs/{id}/stats`: people per state
//!   and per track, hand-offs per track, the content most often seen before
//!   a hand-off, and the SLA rates over the last 90 days.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// `marketing_nurture_program.read`: may see every hand-off and a
/// programme's statistics.
#[derive(Debug)]
pub struct ProgramRead;

impl PrivilegeKey for ProgramRead {
    const KEY: &'static str = "marketing_nurture_program.read";
}

/// Statuses a hand-off can have.
pub const HANDOFF_STATUSES: [&str; 4] = ["pending", "accepted", "returned", "overdue"];

/// One hand-off.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow, ToSchema)]
#[schema(as = NurtureHandoff)]
pub struct Handoff {
    pub id: Uuid,
    pub program_id: Uuid,
    pub person_id: Uuid,
    pub status: String,
    pub score: Option<f64>,
    #[schema(value_type = Object)]
    pub summary: Option<serde_json::Value>,
    pub assigned_to: Option<Uuid>,
    pub due_at: Option<DateTime<Utc>>,
    pub decided_at: Option<DateTime<Utc>>,
    pub return_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

const HANDOFF_COLUMNS: &str = "id, program_id, person_id, status, score::float8 AS score, summary, \
     assigned_to, due_at, decided_at, return_reason, created_at";

/// Who may decide a hand-off assigned to `assignee`: the assignee, their
/// manager, or an administrator.
async fn may_decide(
    db: &attome_db::DbPool,
    ctx: &SecurityContext,
    assignee: Option<Uuid>,
) -> Result<bool, AppError> {
    if ctx.is_admin {
        return Ok(true);
    }
    let Some(assignee) = assignee else {
        return Ok(false);
    };
    if assignee == ctx.user_id {
        return Ok(true);
    }
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_account_mm_position own \
             JOIN position pos ON pos.id = own.position_ref AND pos.is_deleted = false \
             JOIN user_account_mm_position mgr \
                 ON mgr.position_ref = pos.parent_position_ref AND mgr.is_deleted = false \
            WHERE own.user_ref = $1 AND own.is_deleted = false AND mgr.user_ref = $2)",
    )
    .bind(assignee)
    .bind(ctx.user_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// The hand-off's assignee and person's entity, or 404.
async fn handoff_head(
    db: &attome_db::DbPool,
    id: Uuid,
) -> Result<(Option<Uuid>, Uuid, String), AppError> {
    let row: Option<(Option<Uuid>, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT h.assigned_to, h.person_id, s.person_entity FROM marketing_handoff h \
           LEFT JOIN marketing_nurture_state s \
                  ON s.program_id = h.program_id AND s.person_id = h.person_id \
          WHERE h.id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (assignee, person, entity) = row.ok_or(AppError::NotFound)?;
    Ok((
        assignee,
        person,
        entity.unwrap_or_else(|| "contact".to_owned()),
    ))
}

/// Accept a hand-off
///
/// Sales takes the person: a pending or overdue hand-off becomes `accepted`. Only its assignee, the
/// assignee's manager or an administrator. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/handoffs/{id}/accept",
    operation_id = "accept_marketing_handoff",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The hand-off")),
    responses(
        (status = 200, description = "The hand-off, accepted", body = Handoff),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not the assignee, their manager or an administrator", body = ErrorResponse),
        (status = 404, description = "No such hand-off", body = ErrorResponse),
        (status = 409, description = "Already accepted or returned", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_accept(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<Handoff>, AppError> {
    let db = &state.base.db;
    let (assignee, person, entity) = handoff_head(db, id).await?;
    if !may_decide(db, &ctx, assignee).await? {
        return Err(AppError::Forbidden);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let accepted: Option<Handoff> = sqlx::query_as(&format!(
        "UPDATE marketing_handoff SET status = 'accepted', decided_at = now() \
          WHERE id = $1 AND status IN ('pending', 'overdue') RETURNING {HANDOFF_COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(accepted) = accepted else {
        return Err(AppError::Conflict("the hand-off was already decided"));
    };
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            &entity,
            person,
            attome_audit::AuditOperation::Update,
            "marketing.handoff_accepted",
            ctx.user_id,
        )
        .comment(format!("hand-off {id}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(accepted))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReturnBody {
    /// Why sales returns the person.
    pub reason: String,
    /// When nurture starts again; now when absent.
    #[serde(default)]
    pub wake_up_on: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct ReturnResult {
    pub handoff_id: Uuid,
    /// Whether the person is nurtured again (the programme recycles).
    pub recycled: bool,
}

/// Return a hand-off
///
/// Sales gives the person back with a reason: the hand-off becomes `returned` and, when the
/// programme recycles, the person is nurtured again from `wake_up_on`. Only its assignee, the
/// assignee's manager or an administrator. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/handoffs/{id}/return",
    operation_id = "return_marketing_handoff",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The hand-off")),
    request_body = ReturnBody,
    responses(
        (status = 200, description = "Returned, and whether the person is nurtured again", body = ReturnResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not the assignee, their manager or an administrator", body = ErrorResponse),
        (status = 404, description = "No such hand-off, or one already returned", body = ErrorResponse),
        (status = 422, description = "No reason", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_return(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<ReturnBody>,
) -> Result<Json<ReturnResult>, AppError> {
    let reason = body.reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(AppError::Validation(
            "reason says why, in at most 500 characters".into(),
        ));
    }
    let (assignee, _, _) = handoff_head(&state.base.db, id).await?;
    if !may_decide(&state.base.db, &ctx, assignee).await? {
        return Err(AppError::Forbidden);
    }
    let recycled =
        crate::nurture_handoff::recycle(&state, id, reason, body.wake_up_on, ctx.user_id).await?;
    Ok(Json(ReturnResult {
        handoff_id: id,
        recycled,
    }))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct HandoffQuery {
    /// `pending`, `accepted`, `returned` or `overdue`.
    pub status: Option<String>,
    /// One-based.
    pub page: Option<i64>,
    /// Hand-offs per page.
    pub page_size: Option<i64>,
}

/// List hand-offs
///
/// The caller's own hand-offs, newest first; with `marketing_nurture_program.read` every hand-off of
/// a person the caller may read.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/handoffs",
    operation_id = "list_marketing_handoffs",
    tag = "marketing",
    params(HandoffQuery),
    responses(
        (status = 200, description = "One page of hand-offs", body = PaginatedResponse<Handoff>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "An unknown status", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_handoffs(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<HandoffQuery>,
) -> Result<Json<PaginatedResponse<Handoff>>, AppError> {
    if let Some(status) = q.status.as_deref()
        && !HANDOFF_STATUSES.contains(&status)
    {
        return Err(AppError::Validation(
            "status is pending, accepted, returned or overdue".into(),
        ));
    }
    let window = attome_types::OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    let everyone = ctx.is_admin || ctx.privileges.contains(ProgramRead::KEY);
    let rows: Vec<Handoff> = sqlx::query_as(&format!(
        "SELECT {HANDOFF_COLUMNS} FROM marketing_handoff \
          WHERE ($1::text IS NULL OR status = $1) AND ($2 OR assigned_to = $3) \
          ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5"
    ))
    .bind(q.status.as_deref())
    .bind(everyone)
    .bind(ctx.user_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM marketing_handoff \
          WHERE ($1::text IS NULL OR status = $1) AND ($2 OR assigned_to = $3)",
    )
    .bind(q.status.as_deref())
    .bind(everyone)
    .bind(ctx.user_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    // Only people the caller may read (a person is a contact or a lead).
    let mut visible = std::collections::HashSet::new();
    for entity in ["contact", "lead"] {
        if state.entities.load().get(entity).is_none() {
            continue;
        }
        let ids: Vec<Uuid> = rows.iter().map(|h| h.person_id).collect();
        visible.extend(crate::segment_insight::readable(&state, &ctx, entity, &ids).await?);
    }
    let items: Vec<Handoff> = rows
        .into_iter()
        .filter(|h| h.assigned_to == Some(ctx.user_id) || visible.contains(&h.person_id))
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct HistoryQuery {
    /// `contact` (the default) or `lead`.
    pub entity: Option<String>,
}

/// A person's place in one programme.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow, ToSchema)]
pub struct NurtureStateItem {
    pub program_id: Uuid,
    pub track_id: Option<Uuid>,
    pub status: String,
    pub position: i32,
    pub next_due_at: Option<DateTime<Utc>>,
    pub paused_reason: Option<String>,
}

/// A piece of content the person has seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow, ToSchema)]
pub struct ContentSeen {
    pub content_kind: String,
    pub content_id: String,
    pub first_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct NurtureHistory {
    pub person_id: Uuid,
    pub states: Vec<NurtureStateItem>,
    pub content_seen: Vec<ContentSeen>,
    pub handoffs: Vec<Handoff>,
}

/// Read a person's nurture history
///
/// The person's nurture states, the content they have seen and their hand-offs, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/people/{person_id}/nurture-history",
    operation_id = "get_marketing_nurture_history",
    tag = "marketing",
    params(("person_id" = Uuid, Path, description = "The contact or lead"), HistoryQuery),
    responses(
        (status = 200, description = "The person's nurture history", body = NurtureHistory),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "A person the caller may not read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_history(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(person): Path<Uuid>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<NurtureHistory>, AppError> {
    let entity = q.entity.as_deref().unwrap_or("contact");
    if !["contact", "lead"].contains(&entity) {
        return Err(AppError::Validation("entity is contact or lead".into()));
    }
    if !crate::segment_insight::readable(&state, &ctx, entity, &[person])
        .await?
        .contains(&person)
    {
        return Err(AppError::NotFound);
    }
    let db = &state.base.db;
    let states: Vec<NurtureStateItem> = sqlx::query_as(
        "SELECT program_id, track_id, status, position, next_due_at, paused_reason \
           FROM marketing_nurture_state WHERE person_id = $1 ORDER BY program_id",
    )
    .bind(person)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let content_seen: Vec<ContentSeen> = sqlx::query_as(
        "SELECT content_kind, content_id, first_seen_at FROM marketing_content_seen \
          WHERE person_id = $1 ORDER BY first_seen_at DESC LIMIT 200",
    )
    .bind(person)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let handoffs: Vec<Handoff> = sqlx::query_as(&format!(
        "SELECT {HANDOFF_COLUMNS} FROM marketing_handoff WHERE person_id = $1 \
          ORDER BY created_at DESC LIMIT 100"
    ))
    .bind(person)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(NurtureHistory {
        person_id: person,
        states,
        content_seen,
        handoffs,
    }))
}

/// People of a programme by state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow, ToSchema)]
pub struct StateCount {
    pub status: String,
    pub people: i64,
}

/// One track's people and hand-offs.
#[derive(Debug, Clone, PartialEq, Serialize, sqlx::FromRow, ToSchema)]
pub struct TrackStats {
    pub track_id: Option<Uuid>,
    pub people: i64,
    pub handed_off: i64,
    /// `handed_off / people`.
    pub conversion: f64,
}

/// A piece of content and how many hand-offs saw it first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow, ToSchema)]
pub struct ContentBeforeHandoff {
    pub content_kind: String,
    pub content_id: String,
    pub handoffs: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ProgramStats {
    pub program_id: Uuid,
    pub by_state: Vec<StateCount>,
    pub by_track: Vec<TrackStats>,
    pub content_before_handoff: Vec<ContentBeforeHandoff>,
    /// Hand-offs of the last 90 days: accepted, returned, overdue.
    pub accepted: i64,
    pub returned: i64,
    pub overdue: i64,
    /// Median minutes from hand-off to decision.
    pub median_minutes_to_decision: Option<f64>,
}

/// Read a nurture programme's statistics
///
/// People per state and per track, conversion to a hand-off by track, the content most often seen
/// before a hand-off, and the hand-off SLA over the last 90 days.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/nurture/programs/{id}/stats",
    operation_id = "get_marketing_nurture_program_stats",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The nurture programme")),
    responses(
        (status = 200, description = "The programme's statistics", body = ProgramStats),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_nurture_program.read", body = ErrorResponse),
        (status = 404, description = "No such programme", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_stats(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<ProgramRead>>,
    Path(program): Path<Uuid>,
) -> Result<Json<ProgramStats>, AppError> {
    let db = &state.base.db;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM marketing_nurture_program \
                         WHERE id = $1 AND is_active IS NOT FALSE)",
    )
    .bind(program)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let by_state: Vec<StateCount> = sqlx::query_as(
        "SELECT status, COUNT(*) AS people FROM marketing_nurture_state \
          WHERE program_id = $1 GROUP BY status ORDER BY status",
    )
    .bind(program)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let by_track: Vec<TrackStats> = sqlx::query_as(
        "SELECT track_id, COUNT(*) AS people, \
                COUNT(*) FILTER (WHERE status = 'handed_off') AS handed_off, \
                COALESCE(COUNT(*) FILTER (WHERE status = 'handed_off')::float8 \
                         / NULLIF(COUNT(*), 0), 0) AS conversion \
           FROM marketing_nurture_state WHERE program_id = $1 \
          GROUP BY track_id ORDER BY track_id NULLS LAST",
    )
    .bind(program)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let content_before_handoff: Vec<ContentBeforeHandoff> = sqlx::query_as(
        "SELECT c ->> 'kind' AS content_kind, c ->> 'id' AS content_id, COUNT(*) AS handoffs \
           FROM marketing_handoff h, jsonb_array_elements(h.summary -> 'content_seen') c \
          WHERE h.program_id = $1 \
          GROUP BY 1, 2 ORDER BY 3 DESC, 1, 2 LIMIT 10",
    )
    .bind(program)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let now = Utc::now();
    let rates = crate::handoff_sla::rates(db, program, now - Duration::days(90), now).await?;
    Ok(Json(ProgramStats {
        program_id: program,
        by_state,
        by_track,
        content_before_handoff,
        accepted: rates.accepted,
        returned: rates.returned,
        overdue: rates.overdue,
        median_minutes_to_decision: rates.median_minutes_to_decision,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/marketing/handoffs", get(get_handoffs))
        .route("/api/v1/marketing/handoffs/{id}/accept", post(post_accept))
        .route("/api/v1/marketing/handoffs/{id}/return", post(post_return))
        .route(
            "/api/v1/marketing/people/{person_id}/nurture-history",
            get(get_history),
        )
        .route(
            "/api/v1/marketing/nurture/programs/{id}/stats",
            get(get_stats),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_accept, post_return, get_handoffs, get_history, get_stats),
    components(schemas(
        Handoff,
        ReturnBody,
        ReturnResult,
        NurtureHistory,
        NurtureStateItem,
        ContentSeen,
        ProgramStats,
        StateCount,
        TrackStats,
        ContentBeforeHandoff
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_statuses_are_the_tables() {
        assert_eq!(
            HANDOFF_STATUSES,
            ["pending", "accepted", "returned", "overdue"]
        );
    }
}

//! `GET /api/v1/admin/ai/evidence` (roadmap N29-T2): what AI did, for an
//! auditor, by agent, model or period.
//!
//! Two kinds of row, oldest first, keyset-paged:
//!
//! - **actions** — every action an agent session invoked
//!   (`action_invocation`): the action, its outcome, the person it acted for,
//!   the session and the agent object it ran as; filtered by `agent` (agent
//!   object) when given. Results are never included: they may hold record
//!   data, which the records' own routes govern.
//! - **generations** — every model-written suggestion (`ai_suggestion_outcome`):
//!   the action, model, prompt version, record and what a person did with it;
//!   filtered by `model` when given.
//!
//! The period is `from` to `to` (default: the last 30 days). One page holds
//! at most [`MAX_PAGE`] rows of the requested kind; `next_cursor` continues.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, CursorPage, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The most rows one page holds.
pub const MAX_PAGE: i64 = 1_000;

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EvidenceQuery {
    /// `actions` (default) or `generations`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Only this agent object's sessions (actions).
    #[serde(default)]
    pub agent: Option<Uuid>,
    /// Only this model (generations).
    #[serde(default)]
    pub model: Option<String>,
    /// From this time (inclusive).
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
    /// Up to this time (exclusive).
    #[serde(default)]
    pub to: Option<DateTime<Utc>>,
    /// The previous page's `next_cursor`, verbatim.
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct EvidenceRow {
    pub id: Uuid,
    pub at: DateTime<Utc>,
    pub action_id: String,
    /// The action's outcome, or what a person did with a suggestion.
    pub outcome: String,
    pub user_id: Option<Uuid>,
    pub agent_session_id: Option<Uuid>,
    pub agent_object_ref: Option<Uuid>,
    pub model_id: Option<String>,
    pub prompt_version: Option<String>,
    pub entity: Option<String>,
    pub record_id: Option<Uuid>,
}

/// `GET /api/v1/admin/ai/evidence`
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/evidence",
    tag = "action",
    params(EvidenceQuery),
    responses(
        (status = 200, description = "One page of evidence, oldest first", body = CursorPage<EvidenceRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "Unknown kind, or a period that ends before it starts", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn evidence(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<EvidenceQuery>,
) -> Result<Json<CursorPage<EvidenceRow>>, AppError> {
    let to = q.to.unwrap_or_else(Utc::now);
    let from = q.from.unwrap_or(to - Duration::days(30));
    if from > to {
        return Err(AppError::Validation("from must be before to".into()));
    }
    let cursor = attome_types::cursor::open_uuid(q.cursor.as_deref())?.unwrap_or(Uuid::nil());
    let rows: Vec<EvidenceRow> = match q.kind.as_deref().unwrap_or("actions") {
        "actions" => sqlx::query_as(
            "SELECT i.id, i.created_at AS at, i.action_id, i.outcome, \
                    i.acting_user_id AS user_id, i.agent_session_id, s.agent_object_ref, \
                    NULL::text AS model_id, NULL::text AS prompt_version, \
                    NULL::text AS entity, NULL::uuid AS record_id \
             FROM action_invocation i \
             LEFT JOIN agent_session s ON s.id = i.agent_session_id \
             WHERE i.created_at >= $1 AND i.created_at < $2 AND i.id > $3 \
               AND ($4::uuid IS NULL OR s.agent_object_ref = $4) \
             ORDER BY i.id LIMIT $5",
        )
        .bind(from)
        .bind(to)
        .bind(cursor)
        .bind(q.agent)
        .bind(MAX_PAGE + 1)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?,
        "generations" => sqlx::query_as(
            "SELECT o.id, o.created_at AS at, o.action_id, o.outcome, \
                    o.user_ref AS user_id, o.agent_session_ref AS agent_session_id, \
                    NULL::uuid AS agent_object_ref, o.model_id, o.prompt_version, \
                    o.entity_logicalname AS entity, o.record_id \
             FROM ai_suggestion_outcome o \
             WHERE o.created_at >= $1 AND o.created_at < $2 AND o.id > $3 \
               AND ($4::text IS NULL OR o.model_id = $4) \
             ORDER BY o.id LIMIT $5",
        )
        .bind(from)
        .bind(to)
        .bind(cursor)
        .bind(q.model.as_deref())
        .bind(MAX_PAGE + 1)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?,
        other => {
            return Err(AppError::Validation(format!(
                "kind is actions or generations, not {other:?}"
            )));
        }
    };
    let mut rows = rows;
    let more = rows.len() as i64 > MAX_PAGE;
    rows.truncate(MAX_PAGE as usize);
    let next = more
        .then(|| rows.last().map(|r| r.id.to_string()))
        .flatten();
    Ok(Json(CursorPage::new(rows, next)))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/ai/evidence", get(evidence))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(evidence), components(schemas(EvidenceRow)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

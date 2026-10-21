//! AH5-T5: `GET /api/v1/admin/ai/agents/{id}/behaviour` (administrators):
//! an agent's status and `row_version`, its baseline, its last 24 hours of
//! activity and the last time it was stopped automatically, with the
//! reason. Switching it back on is the ordinary update of the agent
//! (`PATCH /api/v1/ai_agent/{id}` with `status: active` and `If-Match`), so
//! it is audited like any other change and stays a person's step.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// The baseline as the screen shows it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct BaselineView {
    pub computed_at: DateTime<Utc>,
    pub first_activity_at: Option<DateTime<Utc>>,
    pub mean_writes_per_hour: Option<f32>,
    pub stddev_writes_per_hour: Option<f32>,
    pub mean_deletes_per_hour: Option<f32>,
    pub stddev_deletes_per_hour: Option<f32>,
    pub usual_entities: Vec<String>,
    pub usual_hours: Vec<i16>,
}

/// One hour of activity.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct HourView {
    pub hour: DateTime<Utc>,
    pub writes: i32,
    pub deletes: i32,
    pub external_calls: i32,
    pub entities: Vec<String>,
}

/// The last automatic stop.
#[derive(Debug, Serialize, ToSchema)]
pub struct TripView {
    pub at: DateTime<Utc>,
    /// The departure, e.g. `automatic: volume: observed 200, expected 5`.
    pub reason: Option<String>,
}

/// An agent's behaviour.
#[derive(Debug, Serialize, ToSchema)]
pub struct AgentBehaviour {
    pub agent_id: Uuid,
    pub name: Option<String>,
    pub status: Option<String>,
    pub row_version: i64,
    pub baseline: Option<BaselineView>,
    /// The last 24 hours with activity, oldest first.
    pub hours: Vec<HourView>,
    pub last_trip: Option<TripView>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/{id}/behaviour",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The agent (ai_agent)")),
    responses(
        (status = 200, description = "Status, baseline, the last 24 hours and the last automatic stop", body = AgentBehaviour),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such agent", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_behaviour(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(agent): Path<Uuid>,
) -> Result<Json<AgentBehaviour>, AppError> {
    let db = &state.base.db;
    let head: Option<(Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT name, status::text, row_version::bigint FROM ai_agent \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(agent)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (name, status, row_version) = head.ok_or(AppError::NotFound)?;
    let baseline: Option<BaselineView> = sqlx::query_as(
        "SELECT computed_at, first_activity_at, mean_writes_per_hour, stddev_writes_per_hour, \
                mean_deletes_per_hour, stddev_deletes_per_hour, usual_entities, usual_hours \
           FROM ai_agent_baseline WHERE agent_ref = $1",
    )
    .bind(agent)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let mut hours: Vec<HourView> = sqlx::query_as(
        "SELECT hour, writes, deletes, external_calls, entities FROM ai_agent_activity_hourly \
          WHERE agent_ref = $1 ORDER BY hour DESC LIMIT 24",
    )
    .bind(agent)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    hours.reverse();
    let trip: Option<(DateTime<Utc>, Option<String>)> = sqlx::query_as(
        "SELECT created_at, event_comment FROM audit_header \
          WHERE entity_name = 'ai_agent' AND record_id = $1 \
            AND event_name = 'ai.agent.auto_stopped' \
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(agent)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(AgentBehaviour {
        agent_id: agent,
        name,
        status,
        row_version,
        baseline,
        hours,
        last_trip: trip.map(|(at, reason)| TripView { at, reason }),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/ai/agents/{id}/behaviour", get(get_behaviour))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_behaviour),
    components(schemas(AgentBehaviour, BaselineView, HourView, TripView))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

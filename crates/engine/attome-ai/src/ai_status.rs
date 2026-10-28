//! `GET /api/v1/admin/ai/status` (roadmap N31-T2): the AI status page in one
//! read: the generation model's card and whether it is approved, what is
//! switched off, how turns ended over the last day, and the latest switch
//! changes as the incident timeline.
//!
//! Read-only and admin-gated. Every part is read from its own source of
//! truth (`ai_model`, `ai_scope_switch`, `ai_message`), so the page and the
//! enforcement agree.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// Switch changes the timeline shows.
const TIMELINE_ENTRIES: i64 = 20;

/// The generation model's catalogue entry.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct ModelCard {
    pub id: Uuid,
    pub name: Option<String>,
    pub version: Option<String>,
    pub provider_model_id: Option<String>,
    pub approval_status: Option<String>,
    pub context_window: Option<f64>,
    pub max_output_tokens: Option<f64>,
    pub knowledge_cutoff: Option<DateTime<Utc>>,
    pub description: Option<String>,
}

/// How many turns ended one way in the last day.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct TurnCount {
    pub terminal_state: String,
    pub turns: i64,
}

/// One switch change.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct SwitchEvent {
    pub scope_kind: String,
    pub scope_key: String,
    pub enabled: bool,
    pub cause: String,
    pub reason: Option<String>,
    pub changed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AiStatus {
    /// `inference.generation.model`; empty when none is configured.
    pub generation_model: String,
    /// Whether a live catalogue entry approves it (generation refuses
    /// otherwise).
    pub model_approved: bool,
    /// The catalogue entries naming it.
    pub model_cards: Vec<ModelCard>,
    /// Scopes switched off now.
    pub switched_off: i64,
    /// Turns over the last 24 hours, by how they ended.
    pub turns_last_day: Vec<TurnCount>,
    /// The latest switch changes, newest first.
    pub timeline: Vec<SwitchEvent>,
}

/// Whether any of the catalogue entries approves the model.
pub fn approved(cards: &[ModelCard]) -> bool {
    cards
        .iter()
        .any(|c| c.approval_status.as_deref() == Some("approved"))
}

/// Read the AI status page
///
/// The generation model's card and whether it is approved, what is switched off, how turns ended over
/// the last day, and the latest switch changes as an incident timeline. AI administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/status",
    tag = "action",
    responses(
        (status = 200, description = "The AI status page", body = AiStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn ai_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
) -> Result<Json<AiStatus>, AppError> {
    let db = &state.base.db;
    let generation_model = state.base.config.inference.generation.model.clone();
    let model_cards: Vec<ModelCard> = if generation_model.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT id, name, version, provider_model_id, approval_status, \
                    context_window::float8 AS context_window, \
                    max_output_tokens::float8 AS max_output_tokens, \
                    knowledge_cutoff, description \
             FROM ai_model \
             WHERE provider_model_id = $1 AND (is_active IS NULL OR is_active = true) \
             ORDER BY name LIMIT 20",
        )
        .bind(&generation_model)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
    };
    let switched_off: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ai_scope_switch WHERE NOT enabled")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let turns_last_day: Vec<TurnCount> = sqlx::query_as(
        "SELECT terminal_state, COUNT(*) AS turns FROM ai_message \
         WHERE role = 'assistant' AND terminal_state IS NOT NULL \
           AND created_at > now() - interval '24 hours' \
         GROUP BY terminal_state ORDER BY turns DESC",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let timeline: Vec<SwitchEvent> = sqlx::query_as(
        "SELECT scope_kind, scope_key, enabled, cause, reason, changed_at \
         FROM ai_scope_switch ORDER BY changed_at DESC LIMIT $1",
    )
    .bind(TIMELINE_ENTRIES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(AiStatus {
        model_approved: approved(&model_cards),
        generation_model,
        model_cards,
        switched_off,
        turns_last_day,
        timeline,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/ai/status", get(ai_status))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(ai_status),
    components(schemas(AiStatus, ModelCard, TurnCount, SwitchEvent))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(status: Option<&str>) -> ModelCard {
        ModelCard {
            id: Uuid::now_v7(),
            name: Some("m".into()),
            version: None,
            provider_model_id: Some("m".into()),
            approval_status: status.map(str::to_owned),
            context_window: None,
            max_output_tokens: None,
            knowledge_cutoff: None,
            description: None,
        }
    }

    #[test]
    fn a_model_is_approved_when_any_entry_approves_it() {
        assert!(!approved(&[]));
        assert!(!approved(&[card(Some("pending")), card(None)]));
        assert!(approved(&[card(Some("pending")), card(Some("approved"))]));
    }
}

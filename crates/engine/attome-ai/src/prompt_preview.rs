//! `POST /api/v1/admin/ai/preview/summary` (roadmap N28-T3): exactly what a
//! model would receive for a record summary, without calling it.
//!
//! Built by the same functions `record.summarize` uses
//! (`summary_context::gather`, `read::summarize_messages`), as the calling
//! administrator, so the preview is the request byte for byte: the system
//! instruction, the record, its related names and its timeline inside the
//! data block. Nothing is generated, cached or spent.

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryPreviewRequest {
    pub entity: String,
    pub record_id: Uuid,
    #[serde(default)]
    pub language: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromptPreview {
    pub prompt_version: String,
    /// The messages in order, as sent: `role` and `content`.
    #[schema(value_type = Vec<Object>)]
    pub messages: Value,
    /// Characters across all messages.
    pub chars: usize,
}

/// `POST /api/v1/admin/ai/preview/summary`
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/preview/summary",
    tag = "action",
    request_body = SummaryPreviewRequest,
    responses(
        (status = 200, description = "What the model would receive", body = PromptPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "builds the prompt a summary would send; generates, caches and writes nothing"
    )))),
)]
async fn preview_summary(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<SummaryPreviewRequest>,
) -> Result<Json<PromptPreview>, AppError> {
    let facts =
        crate::actions::summary_context::gather(&state, &ctx, &body.entity, body.record_id).await?;
    let language = body
        .language
        .as_deref()
        .unwrap_or("the record's own language");
    // The administrator's override too, exactly as `record.summarize` layers it.
    let layer = crate::prompt_layer::effective(
        &state.base.db,
        crate::actions::read::RECORD_SUMMARIZE,
        crate::actions::read::SUMMARIZE_PROMPT_VERSION,
        &crate::actions::read::summarize_system_prompt(language),
        &ctx.user_id.to_string(),
    )
    .await;
    let messages = crate::prompt::assemble(&[
        crate::prompt::Segment::trusted(layer.system),
        crate::prompt::Segment::untrusted(&body.entity, &facts),
    ]);
    let chars = messages.iter().map(|m| m.content.chars().count()).sum();
    Ok(Json(PromptPreview {
        prompt_version: layer.version,
        messages: serde_json::to_value(&messages).map_err(AppError::internal)?,
        chars,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/ai/preview/summary", post(preview_summary))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(preview_summary),
    components(schemas(SummaryPreviewRequest, PromptPreview))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

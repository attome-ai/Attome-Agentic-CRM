//! AI6: meeting briefs before a meeting and notes after it, on the
//! `ai_meeting_brief` and `ai_meeting_notes` entities (platform bundle
//! `attome-ai-meeting`). A meeting is an `activity` whose `activity_type` is
//! `meeting`; it points at the record it is about through `entity_name` and
//! `record_id`.

pub mod brief;
pub mod notes;
pub mod routes;
pub mod run;

use attome_core::EngineState;
use attome_inference::GenerationRequest;
use attome_types::AppError;

use crate::context::ActionContext;
use crate::prompt::Segment;

/// One model call: the action it is spent under, the prompt (and its
/// administrator override) it uses, and the untrusted data block.
pub(crate) struct Ask<'a> {
    /// The action the call is routed, approved and budgeted as.
    pub feature: &'static str,
    /// The prompt id an administrator's override is looked up by.
    pub prompt_id: &'static str,
    pub version: &'static str,
    pub system: String,
    pub label: &'a str,
    pub data: &'a str,
}

/// What the model wrote.
#[derive(Debug)]
pub struct Generated {
    pub text: String,
    pub truncated: bool,
    pub model_id: String,
    pub prompt_version: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub latency_ms: i32,
}

/// Asks the model once: the routed client, the model-registry check, the
/// prompt layer, then the call inside the budget guard's admit/settle.
pub(crate) async fn generate(
    state: &EngineState,
    ctx: &ActionContext,
    ask: &Ask<'_>,
) -> Result<Generated, AppError> {
    let client = crate::inference_client::client_for(state, ask.feature).await?;
    crate::model_registry::require_approved_model(&state.base.db, client.model_id(), ask.feature)
        .await?;
    let layer = crate::prompt_layer::effective(
        &state.base.db,
        ask.prompt_id,
        ask.version,
        &ask.system,
        &ctx.security.user_id.to_string(),
    )
    .await;
    let started = std::time::Instant::now();
    let mut request = GenerationRequest::new(crate::prompt::assemble(&[
        Segment::trusted(layer.system.clone()),
        Segment::untrusted(ask.label, ask.data),
    ]));
    let grant = crate::budget_guard::admit(
        state,
        ctx,
        attome_inference::budget::Priority::Chat,
        ask.feature,
        &mut request,
    )
    .await?;
    let generated = client.generate(request).await.map_err(|e| {
        tracing::warn!(error = %e, feature = ask.feature, "meeting generation failed");
        AppError::internal("generation failed")
    })?;
    grant.settle(state, &generated.usage).await;
    let text = generated.text.trim().to_owned();
    if text.is_empty() {
        return Err(AppError::internal("the model wrote nothing"));
    }
    Ok(Generated {
        text,
        truncated: generated.truncated,
        model_id: generated.usage.model_id.clone(),
        prompt_version: layer.version.clone(),
        prompt_tokens: generated.usage.prompt_tokens,
        completion_tokens: generated.usage.completion_tokens,
        latency_ms: i32::try_from(started.elapsed().as_millis()).unwrap_or(i32::MAX),
    })
}

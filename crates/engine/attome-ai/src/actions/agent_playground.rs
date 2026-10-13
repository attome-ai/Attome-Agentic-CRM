//! `agent.playground_complete` — test an `ai_agent` definition's persona
//! against a single message (D-503 §5, §6).
//!
//! **Which definitions it runs.** A definition whose `status` is `draft`,
//! `testing` or `active` ([`PLAYGROUND_STATUSES`]); `suspended` and `archived`
//! are refused. This is a playground rule only: a runtime agent session still
//! requires `active` (`crate::agent::start_session`).
//!
//! **How the persona reaches the model (D-360 ruling 4 as amended by D-503).**
//! The prompt is the code-owned playground frame ([`playground_system_prompt`],
//! registered as [`AGENT_PLAYGROUND_PROMPT_VERSION`]) with the definition's
//! `system_instructions` as a typed [`Segment::Persona`], assembled by
//! `crate::prompt::assemble`. Operator text is never sent as a bare system
//! message, never precedes the frame, and cannot close its own block.
//!
//! **Provenance.** The result names the definition, the template version and
//! the model, and carries a SHA-256 of the persona text used, so a reply can
//! be traced to exactly what produced it.
//!
//! Read tier: reads a record the caller can already see
//! (`attome_records::entity_crud::read_record` is the authorization), checks
//! model approval (D-435) and the inference budget, calls the model, and writes
//! nothing. It holds no session and invokes no action, so nothing in a persona
//! can reach the action gate from here.

use std::future::Future;
use std::pin::Pin;

use attome_config::InferenceEndpoint;
use attome_core::EngineState;
use attome_inference::{ChatMessage, GenerationClient, GenerationRequest};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::{self, Segment};
use crate::provider::ApiProtocol;

pub const AGENT_PLAYGROUND_COMPLETE: &str = "agent.playground_complete";

/// The version of the code-owned playground frame. Bump it whenever
/// [`playground_system_prompt`] changes.
pub const AGENT_PLAYGROUND_PROMPT_VERSION: &str = "agent.playground_complete/v1";

/// Per-request timeout for a provider-resolved generation call when
/// `inference.generation.request_timeout_secs` is unset. Matches the config
/// section's own serde default.
const DEFAULT_GENERATION_TIMEOUT_SECS: u64 = 60;

/// The definition statuses the playground may test (D-503 §5).
pub const PLAYGROUND_STATUSES: [&str; 3] = ["draft", "testing", "active"];

fn get_str<'a>(data: &'a Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

/// The code-owned playground frame. A prompt is code (D-360 ruling 4): the
/// persona is added as a separate typed segment, never spliced in here.
pub fn playground_system_prompt() -> String {
    "You are an AI agent being tested by an administrator in the agent \
     playground. Reply to the administrator's message helpfully and honestly. \
     You cannot take actions, call tools or change any data here, so never \
     claim to have done anything other than write this reply."
        .to_owned()
}

/// Refuses a definition the playground may not test.
pub fn require_playground_status(data: &Value) -> Result<(), AppError> {
    let status = get_str(data, "status").unwrap_or("");
    if PLAYGROUND_STATUSES.contains(&status) {
        Ok(())
    } else {
        Err(AppError::Validation(format!(
            "agent definition status is {status:?}; the playground tests only draft, \
             testing or active definitions"
        )))
    }
}

/// Provenance for a persona: a SHA-256 of its exact text, hex-encoded.
pub fn persona_sha256(persona: &str) -> String {
    format!("{:x}", Sha256::digest(persona.as_bytes()))
}

/// The messages sent to the model: the code-owned frame and the typed persona,
/// assembled by `prompt::assemble`, followed by the administrator's message.
pub fn playground_messages(persona: &str, message: &str) -> Vec<ChatMessage> {
    let mut messages = prompt::assemble(&[
        Segment::trusted(playground_system_prompt()),
        Segment::persona(persona),
    ]);
    messages.push(ChatMessage::user(message.to_owned()));
    messages
}

#[derive(Deserialize)]
struct PlaygroundArgs {
    agent_id: Uuid,
    message: String,
}

const AGENT_PLAYGROUND_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "agent_id": { "type": "string", "format": "uuid", "description": "The ai_agent definition whose persona to test. Its status must be draft, testing or active." },
    "message": { "type": "string", "description": "A single user message to send." }
  },
  "required": ["agent_id", "message"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        AGENT_PLAYGROUND_COMPLETE,
        "Send one message to an ai_agent's persona and return the model's \
         reply, for testing a draft, testing or active definition. Writes nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        attome_modules::MODULE_AI,
        &[],
    )
    .input_schema(AGENT_PLAYGROUND_SCHEMA)
}

/// Refuses a provider whose API protocol the generation client cannot speak.
///
/// `attome-inference` sends OpenAI-compatible chat completions and nothing else
/// (D-554 forbids a provider-adapter layer). Rather than send an Anthropic- or
/// Responses-shaped provider a request in the wrong wire format, say so.
pub fn require_chat_completions(protocol: Option<&str>) -> Result<(), AppError> {
    match protocol.and_then(ApiProtocol::parse) {
        Some(ApiProtocol::OpenAiCompletions) => Ok(()),
        Some(other) => Err(AppError::Validation(format!(
            "the playground can only talk to providers using the openai-completions \
             protocol; this provider uses {}",
            other.as_str()
        ))),
        None => Err(AppError::Validation(
            "this provider has no API protocol set".into(),
        )),
    }
}

/// The generation client for one agent definition (D-571).
///
/// An agent that names a model (`primary_model_ref`) is tested against **that
/// model's provider**: its Base URL, its stored API key (decrypted here, in
/// process, and never returned) and its own `allow_external_endpoint`
/// permission (D-568), through the same endpoint gate model discovery uses —
/// so an external Base URL is refused unless the provider or the operator has
/// allowed it, and is SSRF-screened and IP-pinned when it is.
///
/// An agent with no model falls back to the deployment's configured
/// `inference.generation` endpoint, exactly as before this existed.
///
/// Every read here goes through `read_record`, so a caller who cannot see the
/// agent, its model or its provider cannot test through them. The playground
/// still sends only the code-owned frame, the persona and one administrator
/// message — no record content leaves the deployment.
async fn client_for_agent(
    state: &EngineState,
    ctx: &ActionContext,
    agent: &Value,
) -> Result<GenerationClient, AppError> {
    let inference = &state.base.config.inference;

    let Some(model_id) = get_str(agent, "primary_model_ref").and_then(|s| Uuid::parse_str(s).ok())
    else {
        return crate::inference_client::generation_client(&state.base.config).map_err(|e| {
            tracing::warn!(error = %e, "generation client unavailable");
            AppError::NotFound
        });
    };

    let model =
        attome_records::entity_crud::read_record(state, &ctx.security, "ai_model", model_id)
            .await?;
    let model_data = model.data();
    let provider_model_id = get_str(model_data, "provider_model_id")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("the agent's model has no Provider Model ID".into()))?
        .to_owned();
    let provider_id = get_str(model_data, "provider_ref")
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("the agent's model has no provider".into()))?;

    // Authorization for the provider row; the columns below come from the
    // engine's own loader, which also holds the encrypted-credential reference.
    attome_records::entity_crud::read_record(
        state,
        &ctx.security,
        crate::provider::ENTITY,
        provider_id,
    )
    .await?;
    let provider = crate::provider::load(&state.base.db, provider_id)
        .await?
        .ok_or(AppError::NotFound)?;

    require_chat_completions(provider.api_protocol.as_deref())?;
    let base_url = provider
        .endpoint_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("the agent's provider has no Base URL".into()))?
        .to_owned();

    let ring = state.base.secrets.load().ai_provider_credential_key.clone();
    let api_key = crate::provider_credential::resolve(
        &state.base.db,
        &ring,
        provider.credential_ref.as_deref(),
    )
    .await?;

    // An unconfigured `inference.generation` deserialises to a derived-Default
    // endpoint whose timeout is 0 — not the serde default of 60 — so 0 means
    // "unset", and clamping it to 1 second would time out every real request.
    let timeout_secs = match inference.generation.request_timeout_secs {
        0 => DEFAULT_GENERATION_TIMEOUT_SECS,
        configured => configured,
    };
    let http = crate::provider_models::http_client_for(
        &base_url,
        inference,
        provider.allow_external_endpoint.unwrap_or(false),
        timeout_secs,
    )
    .await?;

    let endpoint = InferenceEndpoint {
        base_url,
        model: provider_model_id,
        api_key,
        request_timeout_secs: timeout_secs,
    };
    GenerationClient::for_endpoint(endpoint, inference.max_output_tokens, http).map_err(|e| {
        tracing::warn!(error = %e, "generation client unavailable for the agent's provider");
        AppError::NotFound
    })
}

#[derive(Debug)]
pub struct AgentPlaygroundComplete;

impl Action for AgentPlaygroundComplete {
    fn id(&self) -> ActionId {
        ActionId(AGENT_PLAYGROUND_COMPLETE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: PlaygroundArgs = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("invalid action arguments: {e}")))?;
            let message = args.message.trim();
            if message.is_empty() {
                return Err(AppError::Validation("message must not be empty".into()));
            }

            // The read is the authorization: a caller who cannot read this
            // agent definition cannot test it either.
            let record = attome_records::entity_crud::read_record(
                state,
                &ctx.security,
                "ai_agent",
                args.agent_id,
            )
            .await?;
            let data = record.data();
            require_playground_status(data)?;
            let name = get_str(data, "name").unwrap_or("agent").to_owned();
            // The playground still requires instructions to test. What it
            // sends is the same composition a session snapshots (C11 B2), so
            // what an administrator tests here is what users get.
            get_str(data, "system_instructions")
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    AppError::Validation("agent definition has no system_instructions".into())
                })?;
            let persona = crate::agent::compose_persona(data).unwrap_or_default();

            let client = client_for_agent(state, ctx, data).await?;

            // D-435: require an approved catalog entry for the model actually
            // used (the agent's own, or the deployment's configured one)
            // before spending a transport call on it.
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                AGENT_PLAYGROUND_COMPLETE,
            )
            .await?;

            let request = GenerationRequest::new(playground_messages(&persona, message));

            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                &request,
            )
            .await?;

            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "agent.playground_complete generation failed");
                AppError::internal("generation failed")
            })?;

            grant.settle(state, &generated.usage).await;

            Ok(ActionResult {
                value: serde_json::json!({
                    "agent_id": args.agent_id,
                    "agent_name": name,
                    "reply": generated.text,
                    "truncated": generated.truncated,
                    "agent_definition_ref": args.agent_id,
                    "persona_sha256": persona_sha256(&persona),
                }),
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: AGENT_PLAYGROUND_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_inference::Role;

    #[test]
    fn the_playground_tests_draft_testing_and_active_definitions_only() {
        for status in ["draft", "testing", "active"] {
            assert!(
                require_playground_status(&serde_json::json!({ "status": status })).is_ok(),
                "{status}"
            );
        }
        for status in ["suspended", "archived", "", "Active"] {
            assert!(
                require_playground_status(&serde_json::json!({ "status": status })).is_err(),
                "{status:?} must be refused"
            );
        }
        assert!(require_playground_status(&serde_json::json!({})).is_err());
    }

    /// The frame is first, the persona is a delimited block after it, and the
    /// administrator's message is the only user turn.
    #[test]
    fn the_code_owned_frame_leads_and_the_persona_follows_it() {
        let persona = "Speak like a pirate.";
        let messages = playground_messages(persona, "Hello");
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert_eq!(messages[0].role, Role::System);
        assert!(messages[0].content.starts_with(&playground_system_prompt()));
        let frame_end = playground_system_prompt().len();
        let persona_at = messages[0]
            .content
            .find(persona)
            .expect("the persona is shown to the model");
        assert!(persona_at > frame_end, "the persona must follow the frame");
        assert!(messages[0].content.contains(prompt::PERSONA_OPEN));
        assert_eq!(messages[1].role, Role::User);
        assert_eq!(messages[1].content, "Hello");
    }

    /// The generation client only speaks OpenAI-compatible chat completions, so
    /// any other protocol is refused with a message naming it, and an unset or
    /// unrecognised one is refused rather than guessed.
    #[test]
    fn only_the_openai_completions_protocol_is_accepted() {
        assert!(require_chat_completions(Some("openai-completions")).is_ok());
        for other in ["openai-responses", "anthropic-messages"] {
            let error = require_chat_completions(Some(other)).unwrap_err();
            assert!(
                matches!(&error, AppError::Validation(m) if m.contains(other)),
                "{other}: {error:?}"
            );
        }
        for unset in [None, Some(""), Some("chat")] {
            assert!(require_chat_completions(unset).is_err(), "{unset:?}");
        }
    }

    /// No second path: the playground never builds a system message itself.
    #[test]
    fn the_playground_has_no_bare_system_message_path() {
        let source = include_str!("agent_playground.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !production.contains("ChatMessage::system("),
            "operator text must reach the model only through prompt::assemble"
        );
    }

    #[test]
    fn the_playground_frame_is_a_registered_prompt_version() {
        let entry = crate::prompt_registry::find_version(AGENT_PLAYGROUND_PROMPT_VERSION)
            .expect("the playground frame must be registered");
        assert_eq!(entry.action_id, AGENT_PLAYGROUND_COMPLETE);
        assert_eq!(entry.text, playground_system_prompt());
    }

    #[test]
    fn the_persona_hash_is_bound_to_the_exact_text() {
        assert_eq!(persona_sha256("Be concise."), persona_sha256("Be concise."));
        assert_ne!(persona_sha256("Be concise."), persona_sha256("Be concise"));
        assert_eq!(persona_sha256("").len(), 64);
    }
}

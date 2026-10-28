//! `metadata.propose_conflict_resolution` (roadmap Y11-T8): when a builder
//! asks, an agent proposes how to resolve an upgrade conflict
//! (`metadata_layer_conflict`, Y11-T6): keep the customer's value, take the
//! platform's, or combine them into a value of its own, with its reasoning.
//!
//! The model sees the three values of one metadata property (the platform's
//! old and new value and the customer's) and what the property means; never
//! record data. The action only proposes: it has no write effect, never
//! calls the resolve route, and the conflict stays open until a builder
//! resolves it (`POST /api/v1/admin/metadata/conflicts/{id}/resolve`).
//! Administrators only, like the conflict routes; through the budget guard
//! and the approved-model check like every model action.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_inference::GenerationRequest;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const METADATA_PROPOSE_CONFLICT_RESOLUTION: &str = "metadata.propose_conflict_resolution";
/// Bumped whenever the prompt changes in a way that could move results.
pub const PROPOSE_PROMPT_VERSION: &str = "metadata.propose_conflict_resolution/v1";

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "conflict_id": { "type": "string", "format": "uuid", "description": "The open conflict to propose a resolution for." }
  },
  "required": ["conflict_id"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        METADATA_PROPOSE_CONFLICT_RESOLUTION,
        "Propose how to resolve an upgrade conflict on an entity or field: keep the \
         customer's value, take the platform's, or combine them, with the reasoning. \
         Proposes only; a builder decides and resolves it.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(SCHEMA)
}

/// What each layered property means, for the model.
fn property_meaning(kind: &str, property: &str) -> &'static str {
    match (kind, property) {
        (_, "name") => "the display label people see (text)",
        ("attribute", "required") => "whether a value must be entered (true or false)",
        ("attribute", "max_length") => "the most characters a text value may have (integer)",
        ("attribute", "options") => "the field's options object, such as its choice values",
        ("attribute", "on_target_delete") => {
            "what happens to this lookup when its target record is deleted (orphan, cascade or restrict)"
        }
        ("attribute", "data_classification") => {
            "the field's data classification (general, personal, sensitive_special_category)"
        }
        ("attribute", "purpose") => "a developer note on why the field exists (text)",
        ("attribute", "lookup_entity_ref") => "the id of the entity a lookup points to",
        ("attribute", p) if p.starts_with("is_") => "a yes-or-no setting of the field",
        ("entity", "primary_name_attribute") => "the field that names a record (a field name)",
        ("entity", "category") => "the entity's category in navigation (text)",
        ("entity", p) if p.starts_with("is_") => "a yes-or-no setting of the entity",
        _ => "a metadata setting",
    }
}

pub fn system_prompt() -> String {
    "You help a builder resolve an upgrade conflict on one metadata setting of an \
     entity or field. The platform changed the setting from its old value to a new \
     one, and this system had already changed it to its own value. Propose one of: \
     keep_customer (keep this system's value), take_platform (use the platform's new \
     value), or combine (a value of your own that keeps what matters in both). Prefer \
     keep_customer when this system's value looks deliberate, take_platform when the \
     platform's change fixes something this system's value would break, and combine \
     only when a single value can honour both. Answer with JSON only: \
     {\"choice\": \"keep_customer\" | \"take_platform\" | \"combine\", \
     \"value\": <the combined value, only for combine>, \"reasoning\": \"<two or three \
     plain sentences>\"}."
        .to_owned()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    conflict_id: Uuid,
}

#[derive(Deserialize)]
struct Proposal {
    choice: String,
    #[serde(default)]
    value: Option<Value>,
    reasoning: String,
}

/// The model's reply as a checked proposal, or why it is unusable. Pure.
fn proposal_from_reply(text: &str) -> Result<Value, &'static str> {
    let start = text.find('{').ok_or("malformed")?;
    let end = text.rfind('}').ok_or("malformed")?;
    let proposal: Proposal =
        serde_json::from_str(text.get(start..=end).ok_or("malformed")?).map_err(|_| "malformed")?;
    let value = match (proposal.choice.as_str(), proposal.value) {
        ("keep_customer" | "take_platform", _) => None,
        ("combine", Some(value)) => Some(value),
        ("combine", None) => return Err("combine_without_value"),
        _ => return Err("unknown_choice"),
    };
    let reasoning: String = proposal.reasoning.trim().chars().take(1_000).collect();
    if reasoning.is_empty() {
        return Err("no_reasoning");
    }
    Ok(json!({
        "status": "proposed",
        "choice": proposal.choice,
        "value": value,
        "reasoning": reasoning,
    }))
}

pub(crate) struct ProposeConflictResolution;

impl Action for ProposeConflictResolution {
    fn id(&self) -> ActionId {
        ActionId(METADATA_PROPOSE_CONFLICT_RESOLUTION)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!(
                    "invalid {METADATA_PROPOSE_CONFLICT_RESOLUTION} arguments: {e}"
                ))
            })?;
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let conflict =
                attome_metadata::provision::layer_conflicts::get(&state.base.db, args.conflict_id)
                    .await?;
            if conflict.status != "open" {
                return Ok(ActionResult::plain(json!({
                    "status": "declined",
                    "reason": "already_resolved",
                })));
            }
            let facts = json!({
                "item": format!("{} {}", conflict.object_kind, conflict.object_key),
                "setting": conflict.property,
                "meaning": property_meaning(&conflict.object_kind, &conflict.property),
                "platform_old_value": conflict.old_platform,
                "platform_new_value": conflict.new_platform,
                "this_system_value": conflict.customer,
            });
            let client =
                crate::inference_client::client_for(state, METADATA_PROPOSE_CONFLICT_RESOLUTION)
                    .await?;
            let mut request = GenerationRequest::new(crate::prompt::assemble(&[
                Segment::trusted(system_prompt()),
                Segment::untrusted("conflict", facts.to_string()),
            ]));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                METADATA_PROPOSE_CONFLICT_RESOLUTION,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                METADATA_PROPOSE_CONFLICT_RESOLUTION,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "{METADATA_PROPOSE_CONFLICT_RESOLUTION} generation failed");
                AppError::internal("the proposal could not be made")
            })?;
            grant.settle(state, &generated.usage).await;
            let provenance = Some(Provenance {
                model_id: generated.usage.model_id.clone(),
                prompt_version: PROPOSE_PROMPT_VERSION.to_owned(),
                suggestion_id: None,
            });
            let mut value = if generated.truncated {
                json!({ "status": "declined", "reason": "malformed" })
            } else {
                match proposal_from_reply(&generated.text) {
                    Ok(proposal) => proposal,
                    Err(reason) => json!({ "status": "declined", "reason": reason }),
                }
            };
            value["conflict_id"] = json!(conflict.id);
            Ok(ActionResult { value, provenance })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_never_resolves() {
        // No write capability: the action reads and proposes; a builder resolves.
        let d = descriptor();
        assert_eq!(d.effect, Effect::Read);
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.limit_class(), crate::descriptor::LimitClass::None);
    }

    #[test]
    fn a_reply_becomes_a_checked_proposal() {
        let ok = proposal_from_reply(
            r#"Here: {"choice": "combine", "value": 40, "reasoning": "Both widened it."}"#,
        )
        .unwrap();
        assert_eq!(ok["choice"], "combine");
        assert_eq!(ok["value"], 40);
        assert_eq!(
            proposal_from_reply(r#"{"choice": "combine", "reasoning": "x"}"#),
            Err("combine_without_value")
        );
        assert_eq!(
            proposal_from_reply(r#"{"choice": "merge", "reasoning": "x"}"#),
            Err("unknown_choice")
        );
        let kept =
            proposal_from_reply(r#"{"choice": "keep_customer", "value": 1, "reasoning": "y"}"#)
                .unwrap();
        assert_eq!(kept["value"], Value::Null, "only combine carries a value");
    }
}

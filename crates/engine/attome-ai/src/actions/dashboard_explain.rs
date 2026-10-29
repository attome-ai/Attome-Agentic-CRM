//! `dashboard.explain_number` (roadmap P7-T10): a widget's number in words.
//!
//! The facts come from the widget's explanation, computed as the caller by
//! the same function the explain route uses
//! (`attome_dashboard::drill::explain_widget`): the definition, the filters
//! with their origins, the grouping and the computation facts. The model only
//! restates them in the caller's language, citing each filter; it sees no
//! records and the action writes nothing.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_dashboard::execution::WidgetInputs;
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

pub const DASHBOARD_EXPLAIN_NUMBER: &str = "dashboard.explain_number";
/// Bumped whenever the prompt changes in a way that could move results.
pub const EXPLAIN_PROMPT_VERSION: &str = "dashboard.explain_number/v1";

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "dashboard_id": { "type": "string", "format": "uuid" },
    "widget_id": { "type": "string", "format": "uuid" },
    "inputs": { "type": "object", "description": "The dashboard parameters and cross-filters the number was shown with: {parameters, cross_filters, preview}." },
    "language": { "type": "string", "description": "The language to answer in, such as Arabic or English; the person's own when omitted." }
  },
  "required": ["dashboard_id", "widget_id"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        DASHBOARD_EXPLAIN_NUMBER,
        "Explain in plain words what a dashboard widget's number is: what it counts or \
         adds up, over which records, with which filters (and where each filter comes \
         from), grouped how, and when it was computed. Reads the widget's explanation as \
         the caller; changes nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(SCHEMA)
}

pub fn system_prompt(language: &str) -> String {
    format!(
        "You explain a dashboard number to the person looking at it. Write in {language}, \
         in two to five plain sentences. Use only the facts given: say what is measured, \
         over which records, each filter and where it comes from (the dashboard's own \
         definition, a parameter the person chose, a cross-filter, or their own access), \
         how it is grouped, and when it was computed if that is given. Do not guess at \
         values that are not in the facts, and do not give advice."
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    dashboard_id: Uuid,
    widget_id: Uuid,
    #[serde(default)]
    inputs: Option<WidgetInputs>,
    #[serde(default)]
    language: Option<String>,
}

/// The facts the model restates: the explanation's words, filters and
/// computation facts, without fingerprints and ids it has no use for. Pure.
pub fn facts(explanation: &Value) -> Value {
    let keep = [
        "widget_type",
        "data_class",
        "definition_en",
        "definition_ar",
        "filters",
        "measure_basis",
        "computed_at",
        "timezone",
        "structured",
        "kpi",
        "query",
    ];
    let mut out = serde_json::Map::new();
    if let Some(obj) = explanation.as_object() {
        for key in keep {
            if let Some(value) = obj.get(key).filter(|v| !v.is_null()) {
                out.insert(key.to_owned(), value.clone());
            }
        }
    }
    Value::Object(out)
}

pub(crate) struct DashboardExplain;

impl Action for DashboardExplain {
    fn id(&self) -> ActionId {
        ActionId(DASHBOARD_EXPLAIN_NUMBER)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {DASHBOARD_EXPLAIN_NUMBER} arguments: {e}"))
            })?;
            let explanation = attome_dashboard::drill::explain_widget(
                state,
                &ctx.security,
                args.dashboard_id,
                args.widget_id,
                &args.inputs.unwrap_or_default(),
            )
            .await?;
            let explanation = serde_json::to_value(&explanation).map_err(AppError::internal)?;
            let facts = facts(&explanation);
            let language = args
                .language
                .as_deref()
                .unwrap_or("the language the person wrote in");
            let client =
                crate::inference_client::client_for(state, DASHBOARD_EXPLAIN_NUMBER).await?;
            let mut request = GenerationRequest::new(crate::prompt::assemble(&[
                Segment::trusted(system_prompt(language)),
                Segment::untrusted("widget explanation", facts.to_string()),
            ]));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                DASHBOARD_EXPLAIN_NUMBER,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                DASHBOARD_EXPLAIN_NUMBER,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "{DASHBOARD_EXPLAIN_NUMBER} generation failed");
                AppError::internal("the number could not be explained")
            })?;
            grant.settle(state, &generated.usage).await;
            let provenance = Some(Provenance {
                model_id: generated.usage.model_id.clone(),
                prompt_version: EXPLAIN_PROMPT_VERSION.to_owned(),
                suggestion_id: None,
            });
            Ok(ActionResult {
                value: json!({
                    "widget_id": args.widget_id,
                    "explanation": generated.text.trim(),
                    "facts": facts,
                }),
                provenance,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_explain_is_read_only() {
        let d = descriptor();
        assert_eq!(d.effect, Effect::Read);
        assert_eq!(d.risk, RiskTier::Read);
        assert_eq!(d.limit_class(), crate::descriptor::LimitClass::None);
    }

    #[test]
    fn dashboard_explain_passes_only_the_facts() {
        let explanation = json!({
            "widget_id": "w",
            "definition_fingerprint": "abc",
            "definition_en": "Count of Deals",
            "filters": [{ "field": "status", "origin": { "kind": "definition" } }],
            "computed_at": null,
        });
        let f = facts(&explanation);
        assert_eq!(f["definition_en"], "Count of Deals");
        assert!(f.get("definition_fingerprint").is_none());
        assert!(f.get("computed_at").is_none(), "a null fact is left out");
        assert_eq!(f["filters"][0]["origin"]["kind"], "definition");
    }
}

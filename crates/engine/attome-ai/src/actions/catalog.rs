//! Data catalogue tools (roadmap L4-T7), each as the person (or the agent's
//! principal), through `attome_core::catalog_tools::CatalogTools`: the
//! catalogue routes' own privilege (`metadata.read`) and visibility.
//!
//! - `catalog.search` and `catalog.describe_asset` read.
//! - `catalog.draft_descriptions` proposes descriptions: each becomes a
//!   `draft` through the description edit (with the asset's `row_version`),
//!   never approved here; a builder approves it in the catalogue. It is
//!   `Reversible` and an agent only proposes it: the gate stops every agent
//!   invocation for a person's confirmation.
//! - `catalog.ask` answers a question in words from the assets a search
//!   finds: one model call over their names and descriptions, citing the
//!   assets it used (checked as `knowledge.answer` checks citations).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_core::catalog_tools::CatalogTools;
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

use super::knowledge_answer::{DeclineReason, Verdict, evidence_id, judge};

pub const CATALOG_SEARCH: &str = "catalog.search";
pub const CATALOG_DESCRIBE: &str = "catalog.describe_asset";
pub const CATALOG_DRAFT: &str = "catalog.draft_descriptions";
pub const CATALOG_ASK: &str = "catalog.ask";
/// Bumped whenever the prompt changes in a way that could move answers.
pub const ASK_PROMPT_VERSION: &str = "catalog.ask/v1";

/// The most assets one search answers with, and one ask reads.
pub const MAX_RESULTS: i64 = 20;
const ASK_FROM: i64 = 10;
/// The most descriptions one call drafts.
pub const MAX_DRAFTS: usize = 10;

const SEARCH_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "q": { "type": "string", "description": "Words to find in asset names and descriptions." },
    "kind": { "type": "string", "description": "One asset kind: entity, attribute, option_set, view, saved_query, report, dashboard, metric, flow or agent_tool." },
    "limit": { "type": "integer", "minimum": 1, "maximum": 20 }
  },
  "additionalProperties": false
}"#;

const DESCRIBE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "asset_id": { "type": "string", "format": "uuid" }
  },
  "required": ["asset_id"],
  "additionalProperties": false
}"#;

const DRAFT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "drafts": {
      "type": "array",
      "minItems": 1,
      "maxItems": 10,
      "items": {
        "type": "object",
        "properties": {
          "asset_id": { "type": "string", "format": "uuid" },
          "row_version": { "type": "integer", "description": "The asset's row_version, from catalog.describe_asset." },
          "description_en": { "type": "string" },
          "description_ar": { "type": "string" }
        },
        "required": ["asset_id", "row_version"],
        "additionalProperties": false
      }
    }
  },
  "required": ["drafts"],
  "additionalProperties": false
}"#;

const ASK_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "question": { "type": "string", "description": "A question about the data, in words." }
  },
  "required": ["question"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            CATALOG_SEARCH,
            "Find data assets (entities, fields, views, queries, reports, dashboards, metrics, \
             flows, agent tools) by words, with counts by kind, domain and label. Only what the \
             person may see.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SEARCH_SCHEMA),
        ActionDescriptor::new(
            CATALOG_DESCRIBE,
            "Describe one data asset: its descriptions, domain, label, glossary terms, quality, \
             profile, lineage, usage, certification and history.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(DESCRIBE_SCHEMA),
        ActionDescriptor::new(
            CATALOG_DRAFT,
            "Propose descriptions for data assets, in English and/or Arabic. Each becomes a \
             draft a builder reviews; nothing is approved by this tool.",
            RiskTier::Reversible,
            Effect::Write,
            // A second call with the same row_version is refused as stale.
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(DRAFT_SCHEMA)
        .agent_must_confirm(),
        ActionDescriptor::new(
            CATALOG_ASK,
            "Answer a question about the data (which entity holds what, where a figure comes \
             from) from the catalogue, citing the assets used, or decline.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(ASK_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(CatalogSearch),
        Box::new(CatalogDescribe),
        Box::new(CatalogDraft),
        Box::new(CatalogAsk),
    ]
}

fn tools(state: &EngineState) -> Result<&dyn CatalogTools, AppError> {
    state
        .catalog_tools
        .as_deref()
        .ok_or(AppError::CapabilityUnavailable("catalog"))
}

/// What a search asks for.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    #[serde(default)]
    pub q: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

impl SearchArgs {
    /// The limit, within 1 to [`MAX_RESULTS`] (10 when absent).
    pub fn limit(&self) -> i64 {
        self.limit.unwrap_or(10).clamp(1, MAX_RESULTS)
    }
}

/// One description to draft.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftArgs {
    pub asset_id: Uuid,
    pub row_version: i64,
    #[serde(default)]
    pub description_en: Option<String>,
    #[serde(default)]
    pub description_ar: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftsArgs {
    drafts: Vec<DraftArgs>,
}

/// The drafts a call asks for, at most [`MAX_DRAFTS`], each with some text.
/// Anything beyond the drafts themselves (a status, an approval) is refused:
/// this tool only ever drafts. Pure.
pub fn drafts_from(args: &Value) -> Result<Vec<DraftArgs>, AppError> {
    let parsed: DraftsArgs = serde_json::from_value(args.clone()).map_err(|e| {
        AppError::Validation(format!("invalid catalog.draft_descriptions arguments: {e}"))
    })?;
    if parsed.drafts.is_empty() || parsed.drafts.len() > MAX_DRAFTS {
        return Err(AppError::Validation(format!(
            "draft 1 to {MAX_DRAFTS} descriptions"
        )));
    }
    if parsed
        .drafts
        .iter()
        .any(|d| d.description_en.is_none() && d.description_ar.is_none())
    {
        return Err(AppError::Validation(
            "each draft needs description_en, description_ar or both".into(),
        ));
    }
    Ok(parsed.drafts)
}

pub(crate) struct CatalogSearch;

impl Action for CatalogSearch {
    fn id(&self) -> ActionId {
        ActionId(CATALOG_SEARCH)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: SearchArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid catalog.search arguments: {e}"))
            })?;
            // As the person (or the agent's principal): their visibility.
            let found = tools(state)?
                .search(
                    state,
                    &ctx.security,
                    args.q.as_deref(),
                    args.kind.as_deref(),
                    args.limit(),
                )
                .await?;
            Ok(ActionResult::plain(found))
        })
    }
}

pub(crate) struct CatalogDescribe;

impl Action for CatalogDescribe {
    fn id(&self) -> ActionId {
        ActionId(CATALOG_DESCRIBE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let asset = args["asset_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("asset_id must be a UUID".into()))?;
            let page = tools(state)?.describe(state, &ctx.security, asset).await?;
            Ok(ActionResult::plain(page))
        })
    }
}

pub(crate) struct CatalogDraft;

impl Action for CatalogDraft {
    fn id(&self) -> ActionId {
        ActionId(CATALOG_DRAFT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let drafts = drafts_from(args)?;
            let catalog = tools(state)?;
            let mut results = Vec::with_capacity(drafts.len());
            for d in &drafts {
                let outcome = catalog
                    .draft_description(
                        state,
                        &ctx.security,
                        d.asset_id,
                        d.row_version,
                        d.description_en.as_deref(),
                        d.description_ar.as_deref(),
                    )
                    .await;
                results.push(match outcome {
                    Ok(asset) => {
                        json!({ "asset_id": d.asset_id, "status": "drafted", "asset": asset })
                    }
                    Err(AppError::VersionConflict) => {
                        json!({ "asset_id": d.asset_id, "status": "stale" })
                    }
                    Err(AppError::NotFound) => {
                        json!({ "asset_id": d.asset_id, "status": "not_found" })
                    }
                    Err(e) => return Err(e),
                });
            }
            Ok(ActionResult::plain(json!({ "results": results })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let drafts = drafts_from(args).ok()?;
        Some(json!({
            "drafts": drafts
                .iter()
                .map(|d| json!({
                    "asset_id": d.asset_id,
                    "description_en": d.description_en,
                    "description_ar": d.description_ar,
                }))
                .collect::<Vec<_>>(),
        }))
    }
}

/// The ask prompt.
pub fn ask_system_prompt() -> String {
    "You answer a question about an organisation's data using only the catalogue \
     entries provided: data assets with their kind, name and description. Each is \
     labelled with an evidence id such as E1.\n\n\
     Reply with exactly one JSON object and nothing else:\n\
     {\"status\": \"answered\" or \"insufficient\", \"answer\": string, \
     \"citations\": [evidence ids]}\n\n\
     Use \"answered\" only when the entries answer the question, and list every \
     entry you used. Use \"insufficient\" otherwise, with an empty answer and no \
     citations. Write the answer in the language of the question."
        .to_owned()
}

/// One asset as the ask prompt shows it. Pure.
fn asset_text(asset: &Value) -> String {
    let field = |k: &str| asset.get(k).and_then(Value::as_str).unwrap_or_default();
    let mut out = format!("{} {}", field("kind"), field("ref"));
    for (label, key) in [
        ("Name", "name_en"),
        ("Name (ar)", "name_ar"),
        ("Description", "description_en"),
        ("Description (ar)", "description_ar"),
    ] {
        let value = field(key);
        if !value.is_empty() {
            out.push_str(&format!(
                "\n{label}: {}",
                value.chars().take(600).collect::<String>()
            ));
        }
    }
    out
}

pub(crate) struct CatalogAsk;

impl Action for CatalogAsk {
    fn id(&self) -> ActionId {
        ActionId(CATALOG_ASK)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let question: String = args["question"]
                .as_str()
                .unwrap_or_default()
                .trim()
                .chars()
                .take(500)
                .collect();
            if question.is_empty() {
                return Err(AppError::Validation("question must not be empty".into()));
            }
            let found = tools(state)?
                .search(state, &ctx.security, Some(&question), None, ASK_FROM)
                .await?;
            let assets: Vec<Value> = found["items"].as_array().cloned().unwrap_or_default();
            if assets.is_empty() {
                return Ok(ActionResult::plain(
                    json!({ "answer": null, "reason": "not_found" }),
                ));
            }
            let client = crate::inference_client::client_for(state, CATALOG_ASK).await?;
            let mut segments = vec![
                Segment::trusted(ask_system_prompt()),
                Segment::untrusted("question", question.clone()),
            ];
            for (index, asset) in assets.iter().enumerate() {
                segments.push(Segment::untrusted(evidence_id(index), asset_text(asset)));
            }
            let mut request = GenerationRequest::new(crate::prompt::assemble(&segments));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                CATALOG_ASK,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                CATALOG_ASK,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "catalog.ask generation failed");
                AppError::internal("answer generation failed")
            })?;
            grant.settle(state, &generated.usage).await;
            let value = match judge(&generated.text, generated.truncated, assets.len()) {
                Verdict::Answered { answer, cited } => json!({
                    "answer": answer,
                    "citations": cited
                        .iter()
                        .map(|i| json!({
                            "asset_id": assets[*i].get("id"),
                            "kind": assets[*i].get("kind"),
                            "ref": assets[*i].get("ref"),
                        }))
                        .collect::<Vec<_>>(),
                }),
                Verdict::Declined(
                    DeclineReason::InsufficientEvidence | DeclineReason::NoEvidence,
                ) => {
                    json!({ "answer": null, "reason": "not_found" })
                }
                Verdict::Declined(reason) => json!({ "answer": null, "reason": reason.as_str() }),
            };
            Ok(ActionResult {
                value,
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: ASK_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::tests::security_context_with;
    use crate::gate::{self, GateDecision};

    fn inputs(ai: &attome_config::AiEnablement) -> gate::GateInputs<'_> {
        gate::GateInputs {
            licensed: true,
            ai,
            surface: None,
            external_effects_enabled: false,
        }
    }

    fn ai() -> attome_config::AiEnablement {
        attome_config::AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        }
    }

    /// The reads run as whoever asks, with no elevation: an agent's search
    /// is a plain read the gate lets through, and it carries no privilege of
    /// its own (the catalogue applies the caller's `metadata.read` and
    /// visibility); its arguments cannot widen it.
    #[test]
    fn search_respects_agent_permissions() {
        let ai = ai();
        let agent = ActionContext::agent(security_context_with(false, &[]), RiskTier::Read);
        for d in descriptors() {
            if d.id.0 == CATALOG_SEARCH || d.id.0 == CATALOG_DESCRIBE || d.id.0 == CATALOG_ASK {
                assert_eq!(
                    (d.risk, d.effect),
                    (RiskTier::Read, Effect::Read),
                    "{}",
                    d.id.0
                );
                assert!(
                    d.required_privileges.is_empty(),
                    "{} names no privilege",
                    d.id.0
                );
                assert!(
                    matches!(
                        gate::evaluate(&d, &agent, &inputs(&ai)),
                        Ok(GateDecision::Execute)
                    ),
                    "{}",
                    d.id.0
                );
            }
        }
        let args: SearchArgs =
            serde_json::from_value(json!({"q": "invoices", "limit": 500})).unwrap();
        assert_eq!(args.limit(), MAX_RESULTS);
        assert!(serde_json::from_value::<SearchArgs>(json!({"q": "x", "as_admin": true})).is_err());
    }

    /// Drafts stay drafts: an agent's call waits for a person, and nothing
    /// in the arguments can approve one.
    #[test]
    fn drafts_are_not_approved() {
        let ai = ai();
        let agent =
            ActionContext::agent(security_context_with(false, &[]), RiskTier::Consequential);
        let draft = descriptors()
            .into_iter()
            .find(|d| d.id.0 == CATALOG_DRAFT)
            .unwrap();
        assert_eq!(draft.risk, RiskTier::Reversible);
        assert!(matches!(
            gate::evaluate(&draft, &agent, &inputs(&ai)),
            Ok(GateDecision::ConfirmFirst { .. })
        ));
        let id = Uuid::now_v7();
        assert!(
            drafts_from(&json!({"drafts": [{"asset_id": id, "row_version": 2, "description_en": "x", "description_status": "reviewed"}]}))
                .is_err(),
            "a status is not an argument"
        );
        assert!(drafts_from(&json!({"drafts": [{"asset_id": id, "row_version": 2}]})).is_err());
        let ok = drafts_from(
            &json!({"drafts": [{"asset_id": id, "row_version": 2, "description_ar": "وصف"}]}),
        )
        .unwrap();
        assert_eq!(ok[0].row_version, 2);
        let proposal = CatalogDraft
            .confirmation_proposal(
                &json!({"drafts": [{"asset_id": id, "row_version": 2, "description_en": "x"}]}),
            )
            .unwrap();
        assert_eq!(proposal["drafts"][0]["description_en"], "x");
    }

    #[test]
    fn the_ask_prompt_cites_entries() {
        assert!(ask_system_prompt().contains("evidence id"));
        let text = asset_text(
            &json!({"kind": "entity", "ref": "account", "name_en": "Account", "description_en": "Companies we sell to."}),
        );
        assert!(text.starts_with("entity account"));
        assert!(text.contains("Description: Companies we sell to."));
    }
}

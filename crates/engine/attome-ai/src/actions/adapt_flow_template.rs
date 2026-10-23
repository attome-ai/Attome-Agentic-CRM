//! `flow_template.adapt` (roadmap M6-T2): maps a flow template's parameters
//! to this deployment's entities and attributes, for a person to confirm.
//!
//! The agent names a published flow template. For each `entity` parameter
//! the action ranks this deployment's entities by how well their logical
//! names share words with the parameter's name and labels. For each
//! `attribute` parameter it ranks that entity's attributes the same way,
//! preferring a number or currency attribute when the parameter reads like an
//! amount. A `text` or `number` parameter takes its default. `user` and
//! `users` parameters are never guessed. The best candidate becomes the
//! proposal, the next ones are offered as alternatives, and every parameter
//! with no proposal is listed as unresolved.
//!
//! It writes nothing. The answer carries the confirmation step: the admin
//! route `POST /api/v1/admin/model/flow_template/{id}/instantiate` with the
//! proposed `args`, which fills the template and answers the graph or its
//! issues. The person, or the agent through its write tools under the agent
//! limits (AH4) and human approval (N30), then saves that graph as a draft.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::{EngineState, FieldType};
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const FLOW_TEMPLATE_ADAPT: &str = "flow_template.adapt";

/// Alternatives offered per parameter besides the proposal.
const ALTERNATIVES: usize = 3;

/// One local entity a parameter may map to.
#[derive(Debug, Clone)]
pub struct EntityCandidate {
    pub logicalname: String,
    /// (logical name, is numeric) per attribute.
    pub attributes: Vec<(String, bool)>,
}

/// The words of a name or label: lower case, split on anything not a letter
/// or digit, a plural `s` dropped.
fn words(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 1)
        .map(|w| {
            let w = w.to_lowercase();
            match w.strip_suffix("ies") {
                Some(stem) if stem.len() > 2 => format!("{stem}y"),
                _ => match w.strip_suffix('s') {
                    Some(stem) if stem.len() > 2 && !w.ends_with("ss") => stem.to_owned(),
                    _ => w,
                },
            }
        })
        .collect()
}

fn parameter_words(parameter: &Map<String, Value>) -> BTreeSet<String> {
    ["name", "label_en"]
        .iter()
        .filter_map(|k| parameter.get(*k).and_then(Value::as_str))
        .flat_map(words)
        .collect()
}

fn score(wanted: &BTreeSet<String>, name: &str) -> usize {
    words(name).intersection(wanted).count()
}

fn amount_like(wanted: &BTreeSet<String>) -> bool {
    [
        "amount", "total", "value", "price", "cost", "sum", "limit", "budget", "discount",
    ]
    .iter()
    .any(|w| wanted.contains(*w))
}

/// The ranked candidates of `names` for `wanted`: best first, ties by name,
/// only those sharing a word (or, with `prefer_numeric`, numeric ones).
fn ranked(
    wanted: &BTreeSet<String>,
    names: impl Iterator<Item = (String, bool)>,
    prefer_numeric: bool,
) -> Vec<String> {
    let mut scored: Vec<(usize, String)> = names
        .filter_map(|(name, numeric)| {
            let s = score(wanted, &name) * 2 + usize::from(prefer_numeric && numeric);
            (s > 0).then_some((s, name))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, n)| n).collect()
}

/// M6-T2: the proposed arguments, alternatives and unresolved parameters
/// for `template` against `entities`.
pub fn propose(template: &Value, entities: &[EntityCandidate]) -> Value {
    let parameters: Vec<&Map<String, Value>> = template["parameters"]
        .as_array()
        .map(|list| list.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default();
    let mut args = Map::new();
    let mut alternatives = Map::new();
    let mut unresolved = Vec::new();
    // Entities first, so attributes can look inside the chosen one.
    for parameter in parameters
        .iter()
        .filter(|p| p.get("type").and_then(Value::as_str) == Some("entity"))
    {
        let name = parameter["name"].as_str().unwrap_or_default();
        let ranking = ranked(
            &parameter_words(parameter),
            entities.iter().map(|e| (e.logicalname.clone(), false)),
            false,
        );
        match ranking.split_first() {
            Some((best, rest)) => {
                args.insert(name.to_owned(), json!(best));
                alternatives.insert(
                    name.to_owned(),
                    json!(rest.iter().take(ALTERNATIVES).collect::<Vec<_>>()),
                );
            }
            None => unresolved.push(name.to_owned()),
        }
    }
    for parameter in &parameters {
        let name = parameter["name"].as_str().unwrap_or_default();
        match parameter.get("type").and_then(Value::as_str) {
            Some("attribute") => {
                let of = parameter
                    .get("of")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let entity = args
                    .get(of)
                    .and_then(Value::as_str)
                    .and_then(|chosen| entities.iter().find(|e| e.logicalname == chosen));
                let wanted = parameter_words(parameter);
                let ranking = entity
                    .map(|e| ranked(&wanted, e.attributes.iter().cloned(), amount_like(&wanted)))
                    .unwrap_or_default();
                match ranking.split_first() {
                    Some((best, rest)) => {
                        args.insert(name.to_owned(), json!(best));
                        alternatives.insert(
                            name.to_owned(),
                            json!(rest.iter().take(ALTERNATIVES).collect::<Vec<_>>()),
                        );
                    }
                    None => unresolved.push(name.to_owned()),
                }
            }
            Some("text" | "number") => match parameter.get("default") {
                Some(default) => {
                    args.insert(name.to_owned(), default.clone());
                }
                None => unresolved.push(name.to_owned()),
            },
            Some("user" | "users") => unresolved.push(name.to_owned()),
            _ => {}
        }
    }
    json!({
        "args": args,
        "alternatives": alternatives,
        "unresolved": unresolved,
    })
}

const INPUT: &str = r#"{
  "type": "object",
  "required": ["template_id"],
  "additionalProperties": false,
  "properties": {
    "template_id": { "type": "string", "format": "uuid", "description": "A published flow template's id." }
  }
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        FLOW_TEMPLATE_ADAPT,
        "Propose how a published flow template's parameters map to this deployment: an entity \
         for each entity parameter, an attribute of it for each attribute parameter, defaults \
         for text and number ones; users are left for the person. Answers the proposed args, \
         alternatives, the parameters still unresolved, and the instantiate route to confirm \
         them with. Writes nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(INPUT)
}

pub(crate) struct FlowTemplateAdapt;

impl Action for FlowTemplateAdapt {
    fn id(&self) -> ActionId {
        ActionId(FLOW_TEMPLATE_ADAPT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let template_id = args["template_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("template_id is a flow template id".into()))?;
            let published =
                attome_model::store::read_published(&state.base.db, template_id).await?;
            if published.kind != attome_model::kinds::FLOW_TEMPLATE.0 {
                return Err(AppError::NotFound);
            }
            let registry = state.entities.load();
            let entities: Vec<EntityCandidate> = registry
                .iter()
                .map(|meta| EntityCandidate {
                    logicalname: meta.logicalname.clone(),
                    attributes: meta
                        .attrs
                        .iter()
                        .map(|a| {
                            let numeric =
                                matches!(a.storage_type(), FieldType::Number | FieldType::Currency);
                            (a.logicalname.clone(), numeric)
                        })
                        .collect(),
                })
                .collect();
            let mut proposal = propose(&published.doc, &entities);
            proposal["template_id"] = json!(template_id);
            proposal["template_name"] = json!(published.name);
            proposal["confirm"] = json!({
                "method": "POST",
                "route": format!("/api/v1/admin/model/flow_template/{template_id}/instantiate"),
                "body": { "args": proposal["args"].clone() },
            });
            Ok(ActionResult::plain(proposal))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entities() -> Vec<EntityCandidate> {
        vec![
            EntityCandidate {
                logicalname: "invoice".into(),
                attributes: vec![
                    ("invoice_number".into(), false),
                    ("grand_total".into(), true),
                    ("customer_note".into(), false),
                ],
            },
            EntityCandidate {
                logicalname: "invoice_line".into(),
                attributes: vec![("line_amount".into(), true)],
            },
            EntityCandidate {
                logicalname: "contact".into(),
                attributes: vec![("full_name".into(), false)],
            },
        ]
    }

    fn template() -> Value {
        json!({
            "parameters": [
                { "name": "entity", "type": "entity", "label_en": "Invoices" },
                { "name": "amount", "type": "attribute", "of": "entity", "label_en": "Invoice total" },
                { "name": "approvers", "type": "users" },
                { "name": "limit", "type": "number", "default": 10000 },
                { "name": "subject", "type": "text" }
            ]
        })
    }

    #[test]
    fn adapt_template_maps_parameters_to_local_entities() {
        let proposal = propose(&template(), &entities());
        assert_eq!(proposal["args"]["entity"], "invoice");
        assert_eq!(proposal["alternatives"]["entity"], json!(["invoice_line"]));
        assert_eq!(
            proposal["args"]["amount"], "grand_total",
            "the amount-like numeric total"
        );
        assert_eq!(proposal["args"]["limit"], 10000);
        assert_eq!(proposal["unresolved"], json!(["approvers", "subject"]));
    }

    #[test]
    fn adapt_template_leaves_what_it_cannot_match_unresolved() {
        let proposal = propose(
            &json!({ "parameters": [
                { "name": "entity", "type": "entity", "label_en": "Shipments" },
                { "name": "weight", "type": "attribute", "of": "entity" }
            ] }),
            &entities(),
        );
        assert!(proposal["args"].as_object().unwrap().is_empty());
        assert_eq!(proposal["unresolved"], json!(["entity", "weight"]));
        assert_eq!(
            words("Opportunities"),
            BTreeSet::from(["opportunity".to_owned()])
        );
    }
}

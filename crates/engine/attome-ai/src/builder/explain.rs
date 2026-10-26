//! `builder.explain` (roadmap AD6-T1): answers a question about how the
//! deployment is configured ("how does case escalation work?") by finding
//! the objects the question names and walking their lineage, then citing
//! the flows, rules, queries and entities the answer rests on.
//!
//! **Finding the objects.** The question's words (stop words dropped) each
//! search the data catalogue through `attome_core::catalog_tools::CatalogTools`,
//! as the person: the catalogue's own `metadata.read` and visibility apply.
//! **Walking.** From each entity found, what uses it (flows, rules, queries,
//! metrics, dashboards; two steps down); from each flow found, what it uses
//! (one step up). The walk shows a definition only through data the person
//! may read, as `lineage.downstream` does; hidden nodes are counted, never
//! named.
//! **Answering.** One model call over the numbered objects (kind, name,
//! description, and the edges between them), whose answer must cite them by
//! evidence id: [`judge`] declines an uncited or invented citation. With no
//! object found, no model is called.
//!
//! An MCP agent's objects are cut to the entities its read admission names
//! (`mcp::admission::ReadAdmission`), as the other entity-less read tools do.
//!
//! It only reads: it builds the AD6 building agent's explanations, and like
//! every N12 build tool it changes nothing (a change goes through the
//! Develop draft and its review, V2-D27).

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_core::lineage::graph::{self, Direction, Graph, NodeRef};
use attome_inference::GenerationRequest;
use attome_modules::MODULE_AI;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::actions::knowledge_answer::{DeclineReason, Verdict, evidence_id, judge};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

pub const BUILDER_EXPLAIN: &str = "builder.explain";
/// Bumped whenever the prompt changes in a way that could move answers.
pub const EXPLAIN_PROMPT_VERSION: &str = "builder.explain/v1";

/// The most words of a question searched, assets per word, and objects one
/// answer reads.
const MAX_WORDS: usize = 6;
const PER_WORD: i64 = 5;
pub const MAX_OBJECTS: usize = 25;
const MAX_QUESTION_CHARS: usize = 500;

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "question": { "type": "string", "description": "A question about how something is configured, in words." }
  },
  "required": ["question"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        BUILDER_EXPLAIN,
        "Explain how something in this deployment is configured (which flows, rules, queries \
         and entities take part), citing the objects, from the catalogue and the lineage. \
         Changes nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(SCHEMA)
}

/// One object the answer may cite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigObject {
    /// `entity`, `attribute`, or a definition kind (`workflow`, `rule`,
    /// `query`, `metric`, `dashboard`, …).
    pub kind: String,
    /// The entity (or `entity.attribute`) name, or the definition's id.
    pub reference: String,
    pub label: String,
    pub description: Option<String>,
}

impl ConfigObject {
    fn key(&self) -> String {
        format!("{}:{}", self.kind, self.reference)
    }
}

/// Words worth searching: lower-cased, three letters or more, stop words
/// dropped, each once, at most [`MAX_WORDS`]. Pure.
pub fn keywords(question: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "the",
        "and",
        "for",
        "how",
        "does",
        "did",
        "what",
        "when",
        "where",
        "which",
        "who",
        "why",
        "work",
        "works",
        "working",
        "is",
        "are",
        "was",
        "were",
        "with",
        "from",
        "into",
        "this",
        "that",
        "our",
        "your",
        "can",
        "about",
        "get",
        "gets",
        "happen",
        "happens",
        "explain",
        "tell",
        "show",
        "كيف",
        "ماذا",
        "متى",
        "أين",
        "لماذا",
        "يعمل",
        "تعمل",
        "هل",
        "في",
        "من",
        "على",
        "عن",
        "إلى",
        "التي",
        "الذي",
        "هذا",
        "هذه",
    ];
    let mut out: Vec<String> = Vec::new();
    for word in question
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .map(str::to_lowercase)
    {
        if word.chars().count() >= 3 && !STOP.contains(&word.as_str()) && !out.contains(&word) {
            out.push(word);
        }
        if out.len() == MAX_WORDS {
            break;
        }
    }
    out
}

/// A catalogue asset as an object; its lineage kind (`flow` assets are
/// `workflow` definitions). Pure.
pub fn asset_object(asset: &Value) -> Option<ConfigObject> {
    let text = |k: &str| {
        asset
            .get(k)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let kind = match text("kind")? {
        "flow" => "workflow",
        "saved_query" | "report" => "query",
        other => other,
    };
    let reference = text("ref")?.to_owned();
    Some(ConfigObject {
        kind: kind.to_owned(),
        label: text("name_en")
            .or_else(|| text("name_ar"))
            .unwrap_or(&reference)
            .to_owned(),
        reference,
        description: text("description_en")
            .or_else(|| text("description_ar"))
            .map(|d| d.chars().take(400).collect()),
    })
}

/// Where a walk starts from an object, and which way: down from data (what
/// uses it), up from a flow (what it uses). Pure.
pub fn walk_start(object: &ConfigObject) -> Option<(NodeRef, Direction, u8)> {
    match object.kind.as_str() {
        "entity" | "attribute" => {
            NodeRef::parse("entity", &object.reference).map(|n| (n, Direction::Down, 2))
        }
        "workflow" => NodeRef::parse("workflow", &object.reference).map(|n| (n, Direction::Up, 1)),
        _ => None,
    }
}

/// A walk's visible nodes as objects (the start excluded), and its edges as
/// `from_key edge to_key` lines. Pure.
pub fn graph_objects(walked: &Graph) -> (Vec<ConfigObject>, Vec<(String, String, String)>) {
    let objects = walked
        .nodes
        .iter()
        .filter(|n| n.depth > 0)
        .map(|n| match &n.node {
            NodeRef::Data { entity, attribute } => ConfigObject {
                kind: if attribute.is_some() {
                    "attribute".to_owned()
                } else {
                    "entity".to_owned()
                },
                reference: match attribute {
                    Some(a) => format!("{entity}.{a}"),
                    None => entity.clone(),
                },
                label: n.label.clone(),
                description: None,
            },
            NodeRef::Definition { kind, id } => ConfigObject {
                kind: kind.clone(),
                reference: id.to_string(),
                label: if n.label.is_empty() {
                    format!("{kind} {id}")
                } else {
                    n.label.clone()
                },
                description: None,
            },
        })
        .collect();
    let edges = walked
        .edges
        .iter()
        .map(|e| (e.from.clone(), e.edge_kind.clone(), e.to.clone()))
        .collect();
    (objects, edges)
}

/// The lineage key of an object (`entity:<e>[.<a>]` or `<kind>:<id>`), for
/// matching edges to evidence. Pure.
fn lineage_key(object: &ConfigObject) -> String {
    match object.kind.as_str() {
        "entity" | "attribute" => format!("entity:{}", object.reference),
        _ => object.key(),
    }
}

/// One object as the model sees it: its kind, name, description and how it
/// connects to the other objects shown. Pure.
pub fn object_text(
    object: &ConfigObject,
    objects: &[ConfigObject],
    edges: &[(String, String, String)],
) -> String {
    let mut out = format!("{} {}", object.kind, object.label);
    if let Some(d) = &object.description {
        out.push_str(&format!("\nDescription: {d}"));
    }
    let own = lineage_key(object);
    let name_of = |key: &str| {
        objects
            .iter()
            .find(|o| lineage_key(o) == key)
            .map(|o| format!("{} {}", o.kind, o.label))
    };
    for (from, kind, to) in edges {
        if *from == own
            && let Some(other) = name_of(to)
        {
            out.push_str(&format!("\nIt {kind} {other}"));
        }
    }
    out
}

/// The prompt.
pub fn explain_system_prompt() -> String {
    "You explain how a business application is configured, for the people who build it, \
     using only the configuration objects provided: entities, their attributes, flows \
     (workflows), rules, stored queries, metrics and dashboards, with what each uses. Each is \
     labelled with an evidence id such as E1.\n\n\
     Reply with exactly one JSON object and nothing else:\n\
     {\"status\": \"answered\" or \"insufficient\", \"answer\": string, \
     \"citations\": [evidence ids]}\n\n\
     Use \"answered\" only when the objects explain it: say which objects take part and in \
     what order or relation, and list every object you used. Use \"insufficient\" otherwise, \
     with an empty answer and no citations. Write the answer in the language of the question."
        .to_owned()
}

/// The model's reply judged against the objects: the answer with each
/// citation's object, or why there is none. Pure.
pub fn judged(reply: &str, truncated: bool, objects: &[ConfigObject]) -> Value {
    match judge(reply, truncated, objects.len()) {
        Verdict::Answered { answer, cited } => json!({
            "answer": answer,
            "citations": cited
                .iter()
                .filter_map(|i| objects.get(*i).map(|o| json!({
                    "evidence": evidence_id(*i),
                    "kind": o.kind,
                    "ref": o.reference,
                    "label": o.label,
                })))
                .collect::<Vec<_>>(),
        }),
        Verdict::Declined(DeclineReason::InsufficientEvidence | DeclineReason::NoEvidence) => {
            json!({ "answer": null, "reason": "not_found" })
        }
        Verdict::Declined(reason) => json!({ "answer": null, "reason": reason.as_str() }),
    }
}

/// Adds `more` to `objects`, each once, up to [`MAX_OBJECTS`].
fn add_objects(
    objects: &mut Vec<ConfigObject>,
    seen: &mut BTreeSet<String>,
    more: Vec<ConfigObject>,
) {
    for o in more {
        if objects.len() >= MAX_OBJECTS {
            return;
        }
        if seen.insert(lineage_key(&o)) {
            objects.push(o);
        }
    }
}

pub(crate) struct BuilderExplain;

impl Action for BuilderExplain {
    fn id(&self) -> ActionId {
        ActionId(BUILDER_EXPLAIN)
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
                .take(MAX_QUESTION_CHARS)
                .collect();
            if question.is_empty() {
                return Err(AppError::Validation("question must not be empty".into()));
            }
            let catalog = state
                .catalog_tools
                .as_deref()
                .ok_or(AppError::CapabilityUnavailable("catalog"))?;

            // The objects the words name, as the person sees the catalogue.
            let mut found: Vec<ConfigObject> = Vec::new();
            let mut seen = BTreeSet::new();
            for word in keywords(&question) {
                let page = catalog
                    .search(state, &ctx.security, Some(&word), None, PER_WORD)
                    .await?;
                let assets = page["items"].as_array().cloned().unwrap_or_default();
                add_objects(
                    &mut found,
                    &mut seen,
                    assets.iter().filter_map(asset_object).collect(),
                );
            }
            if found.is_empty() {
                return Ok(ActionResult::plain(
                    json!({ "answer": null, "reason": "not_found" }),
                ));
            }

            // What takes part with them, through data the person may read.
            let security = &ctx.security;
            let visible = |node: &NodeRef| {
                security.is_admin
                    || matches!(node, NodeRef::Data { entity, .. }
                        if security.require(entity, "read").is_ok())
            };
            let mut objects = found.clone();
            let mut edges = Vec::new();
            let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
            for object in &found {
                let Some((start, direction, depth)) = walk_start(object) else {
                    continue;
                };
                let walked =
                    graph::walk(&mut conn, &start, direction, depth, None, None, &visible).await?;
                let (more, more_edges) = graph_objects(&walked);
                add_objects(&mut objects, &mut seen, more);
                edges.extend(more_edges);
            }
            drop(conn);
            // An MCP agent hears only of the entities its admission names.
            if let Some(admission) = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)? {
                objects.retain(|o| match o.kind.as_str() {
                    "entity" | "attribute" => {
                        admission.admits(o.reference.split('.').next().unwrap_or_default())
                    }
                    _ => true,
                });
                if objects.is_empty() {
                    return Ok(ActionResult::plain(
                        json!({ "answer": null, "reason": "not_found" }),
                    ));
                }
            }

            let client = crate::inference_client::client_for(state, BUILDER_EXPLAIN).await?;
            let mut segments = vec![
                Segment::trusted(explain_system_prompt()),
                Segment::untrusted("question", question.clone()),
            ];
            for (index, object) in objects.iter().enumerate() {
                segments.push(Segment::untrusted(
                    evidence_id(index),
                    object_text(object, &objects, &edges),
                ));
            }
            let mut request = GenerationRequest::new(crate::prompt::assemble(&segments));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                BUILDER_EXPLAIN,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                BUILDER_EXPLAIN,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "builder.explain generation failed");
                AppError::internal("explanation generation failed")
            })?;
            grant.settle(state, &generated.usage).await;
            Ok(ActionResult {
                value: judged(&generated.text, generated.truncated, &objects),
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: EXPLAIN_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::lineage::graph::{GraphEdge, Node};
    use uuid::Uuid;

    /// The builder-suite case for this skill (AD10), scripted.
    const CASE_ESCALATION: &str =
        include_str!("../../tests/fixtures/builder/explain_case_escalation.json");

    fn escalation_graph(flow: Uuid, rule: Uuid) -> Graph {
        Graph {
            nodes: vec![
                Node {
                    key: "entity:service_ticket".into(),
                    node: NodeRef::Data {
                        entity: "service_ticket".into(),
                        attribute: None,
                    },
                    label: "entity:service_ticket".into(),
                    depth: 0,
                    reads_personal: false,
                },
                Node {
                    key: format!("workflow:{flow}"),
                    node: NodeRef::Definition {
                        kind: "workflow".into(),
                        id: flow,
                    },
                    label: "Escalate overdue cases".into(),
                    depth: 1,
                    reads_personal: false,
                },
                Node {
                    key: format!("rule:{rule}"),
                    node: NodeRef::Definition {
                        kind: "rule".into(),
                        id: rule,
                    },
                    label: "Priority from SLA breach".into(),
                    depth: 1,
                    reads_personal: false,
                },
            ],
            edges: vec![
                GraphEdge {
                    from: format!("workflow:{flow}"),
                    to: "entity:service_ticket".into(),
                    edge_kind: "triggers".into(),
                    confidence: "exact".into(),
                },
                GraphEdge {
                    from: format!("rule:{rule}"),
                    to: "entity:service_ticket".into(),
                    edge_kind: "writes".into(),
                    confidence: "exact".into(),
                },
            ],
            hidden: 1,
            truncated: false,
        }
    }

    #[test]
    fn builder_explain_keywords_drop_stop_words() {
        assert_eq!(
            keywords("How does case escalation work?"),
            vec!["case".to_owned(), "escalation".to_owned()]
        );
        assert_eq!(keywords("كيف يعمل تصعيد الحالات؟"), vec!["تصعيد", "الحالات"]);
        assert!(keywords("how is it?").is_empty());
        assert_eq!(keywords("a b c d e f g h i j k l m n o p q r s t").len(), 0);
        assert_eq!(
            keywords("one two three four five six seven eight").len(),
            MAX_WORDS
        );
    }

    #[test]
    fn builder_explain_walks_entities_down_and_flows_up() {
        let entity =
            asset_object(&json!({"kind": "entity", "ref": "service_ticket", "name_en": "Case"}))
                .unwrap();
        assert_eq!(entity.label, "Case");
        assert!(matches!(walk_start(&entity), Some((_, Direction::Down, 2))));
        let id = Uuid::now_v7();
        let flow =
            asset_object(&json!({"kind": "flow", "ref": id.to_string(), "name_en": "Escalate"}))
                .unwrap();
        assert_eq!(flow.kind, "workflow");
        assert!(matches!(walk_start(&flow), Some((_, Direction::Up, 1))));
        let view = asset_object(&json!({"kind": "view", "ref": id.to_string()})).unwrap();
        assert!(walk_start(&view).is_none());
        assert!(asset_object(&json!({"kind": "entity"})).is_none());
    }

    /// The fake model's reply to the AD10 case, judged: the answer cites the
    /// flow and the rule that take part, each mapped back to its object.
    #[test]
    fn builder_explain_case_escalation_cites_the_flow_and_rule() {
        let case: Value = serde_json::from_str(CASE_ESCALATION).unwrap();
        let flow = Uuid::parse_str(case["flow_id"].as_str().unwrap()).unwrap();
        let rule = Uuid::parse_str(case["rule_id"].as_str().unwrap()).unwrap();
        assert_eq!(
            keywords(case["question"].as_str().unwrap()),
            vec!["case".to_owned(), "escalation".to_owned()]
        );
        let (more, edges) = graph_objects(&escalation_graph(flow, rule));
        let mut objects = vec![asset_object(&case["catalogue"][0]).unwrap()];
        let mut seen: BTreeSet<String> = objects.iter().map(lineage_key).collect();
        add_objects(&mut objects, &mut seen, more);
        assert_eq!(objects.len(), 3, "{objects:?}");
        let flow_text = object_text(&objects[1], &objects, &edges);
        assert_eq!(
            flow_text,
            "workflow Escalate overdue cases\nIt triggers entity Case"
        );

        let value = judged(case["model_reply"].as_str().unwrap(), false, &objects);
        assert!(
            value["answer"]
                .as_str()
                .unwrap()
                .contains("Escalate overdue cases")
        );
        let cited: Vec<&str> = value["citations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["kind"].as_str().unwrap())
            .collect();
        let expected: Vec<&str> = case["expect_cited_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k.as_str().unwrap())
            .collect();
        assert_eq!(cited, expected);
        assert_eq!(value["citations"][1]["ref"], json!(flow.to_string()));
    }

    #[test]
    fn builder_explain_declines_ungrounded_answers() {
        let objects = vec![ConfigObject {
            kind: "entity".into(),
            reference: "service_ticket".into(),
            label: "Case".into(),
            description: None,
        }];
        let invented = judged(
            r#"{"status": "answered", "answer": "A nightly job escalates.", "citations": ["E4"]}"#,
            false,
            &objects,
        );
        assert_eq!(invented["reason"], "ungrounded");
        assert_eq!(
            judged(
                r#"{"status": "insufficient", "answer": "", "citations": []}"#,
                false,
                &objects
            )["reason"],
            "not_found"
        );
        assert!(explain_system_prompt().contains("evidence id"));
        let d = descriptor();
        assert_eq!((d.risk, d.effect), (RiskTier::Read, Effect::Read));
    }
}

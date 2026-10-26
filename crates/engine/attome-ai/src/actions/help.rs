//! `help.answer` (roadmap B14-T2): answers a how-to question ("how do I add a
//! field?") from the product's documentation and this deployment's
//! configuration, citing both.
//!
//! **Documentation.** The user and builder documents under `docs/` (and the
//! Arabic ones under `docs/ar/`) are built into the binary, so help works
//! offline and matches the version running. Each is split into its sections
//! (a heading and the text under it); [`rank`] scores a section by the
//! question's words (stop words dropped, a plural matching its singular)
//! found in its heading (three times the weight) and its text, and the best
//! [`MAX_SECTIONS`] are evidence. Internal documents ([`EXCLUDED`]) are not
//! help; a test fails when a new document is neither built in nor excluded.
//!
//! **Configuration.** As AD6's explanations find it: the question's words
//! search the data catalogue through `CatalogTools` as the person, and the
//! assets found (at most [`MAX_ASSETS`]) are evidence too. A person without
//! `metadata.read`, or a deployment without the catalogue, gets help from
//! the documents alone.
//!
//! An MCP agent's configuration evidence is cut to the entities its read
//! admission names.
//!
//! **Answering.** One model call over the numbered evidence, cited by
//! evidence id and judged as `knowledge.answer` judges it; no evidence means
//! no model call. It reads and changes nothing.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_inference::GenerationRequest;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::builder::explain::{ConfigObject, asset_object, keywords};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult, Provenance};
use crate::prompt::Segment;

use super::knowledge_answer::{DeclineReason, Verdict, evidence_id, judge};

pub const HELP_ANSWER: &str = "help.answer";
/// Bumped whenever the prompt changes in a way that could move answers.
pub const HELP_PROMPT_VERSION: &str = "help.answer/v1";

/// The most document sections and configuration assets one answer reads.
pub const MAX_SECTIONS: usize = 6;
pub const MAX_ASSETS: usize = 6;
/// The most text of one section the model sees.
const SECTION_CHARS: usize = 1_500;
const MAX_QUESTION_CHARS: usize = 500;

/// Documents that are not help: internal to building and releasing Attome.
pub const EXCLUDED: &[&str] = &[
    "build-machine.md",
    "competitors.md",
    "release.md",
    "release-signing.md",
    "roadmap-paths.md",
    "testing.md",
];

/// The help documents, by their path in the repository.
pub const DOCS: &[(&str, &str)] = &[
    (
        "docs/README.md",
        include_str!("../../../../../docs/README.md"),
    ),
    (
        "docs/agents.md",
        include_str!("../../../../../docs/agents.md"),
    ),
    (
        "docs/api-versions.md",
        include_str!("../../../../../docs/api-versions.md"),
    ),
    (
        "docs/architecture.md",
        include_str!("../../../../../docs/architecture.md"),
    ),
    (
        "docs/backup.md",
        include_str!("../../../../../docs/backup.md"),
    ),
    (
        "docs/branding.md",
        include_str!("../../../../../docs/branding.md"),
    ),
    (
        "docs/caching.md",
        include_str!("../../../../../docs/caching.md"),
    ),
    (
        "docs/config-reference.md",
        include_str!("../../../../../docs/config-reference.md"),
    ),
    (
        "docs/data-catalog.md",
        include_str!("../../../../../docs/data-catalog.md"),
    ),
    (
        "docs/data-layer.md",
        include_str!("../../../../../docs/data-layer.md"),
    ),
    (
        "docs/data-profiling.md",
        include_str!("../../../../../docs/data-profiling.md"),
    ),
    (
        "docs/data-quality.md",
        include_str!("../../../../../docs/data-quality.md"),
    ),
    (
        "docs/deal-teams.md",
        include_str!("../../../../../docs/deal-teams.md"),
    ),
    (
        "docs/dialer.md",
        include_str!("../../../../../docs/dialer.md"),
    ),
    (
        "docs/duplicates.md",
        include_str!("../../../../../docs/duplicates.md"),
    ),
    ("docs/edge.md", include_str!("../../../../../docs/edge.md")),
    (
        "docs/email.md",
        include_str!("../../../../../docs/email.md"),
    ),
    (
        "docs/hijri.md",
        include_str!("../../../../../docs/hijri.md"),
    ),
    (
        "docs/identity-brokers.md",
        include_str!("../../../../../docs/identity-brokers.md"),
    ),
    (
        "docs/imports-and-exports.md",
        include_str!("../../../../../docs/imports-and-exports.md"),
    ),
    (
        "docs/invoicing.md",
        include_str!("../../../../../docs/invoicing.md"),
    ),
    ("docs/jobs.md", include_str!("../../../../../docs/jobs.md")),
    (
        "docs/limits.md",
        include_str!("../../../../../docs/limits.md"),
    ),
    (
        "docs/lineage.md",
        include_str!("../../../../../docs/lineage.md"),
    ),
    (
        "docs/mass-operations.md",
        include_str!("../../../../../docs/mass-operations.md"),
    ),
    (
        "docs/metadata-versions.md",
        include_str!("../../../../../docs/metadata-versions.md"),
    ),
    (
        "docs/model-servers.md",
        include_str!("../../../../../docs/model-servers.md"),
    ),
    (
        "docs/odata.md",
        include_str!("../../../../../docs/odata.md"),
    ),
    (
        "docs/offline.md",
        include_str!("../../../../../docs/offline.md"),
    ),
    (
        "docs/opportunity-lines.md",
        include_str!("../../../../../docs/opportunity-lines.md"),
    ),
    (
        "docs/org-chart.md",
        include_str!("../../../../../docs/org-chart.md"),
    ),
    (
        "docs/procurement.md",
        include_str!("../../../../../docs/procurement.md"),
    ),
    (
        "docs/recycle-bin.md",
        include_str!("../../../../../docs/recycle-bin.md"),
    ),
    (
        "docs/rule-language.md",
        include_str!("../../../../../docs/rule-language.md"),
    ),
    (
        "docs/scanning.md",
        include_str!("../../../../../docs/scanning.md"),
    ),
    (
        "docs/schema-changes.md",
        include_str!("../../../../../docs/schema-changes.md"),
    ),
    (
        "docs/secrets.md",
        include_str!("../../../../../docs/secrets.md"),
    ),
    ("docs/slo.md", include_str!("../../../../../docs/slo.md")),
    (
        "docs/slow-queries.md",
        include_str!("../../../../../docs/slow-queries.md"),
    ),
    (
        "docs/solo-memory-backend.md",
        include_str!("../../../../../docs/solo-memory-backend.md"),
    ),
    (
        "docs/storage.md",
        include_str!("../../../../../docs/storage.md"),
    ),
    (
        "docs/versions-and-support.md",
        include_str!("../../../../../docs/versions-and-support.md"),
    ),
    (
        "docs/workforce.md",
        include_str!("../../../../../docs/workforce.md"),
    ),
    (
        "docs/ar/README.md",
        include_str!("../../../../../docs/ar/README.md"),
    ),
    (
        "docs/ar/identity-brokers.md",
        include_str!("../../../../../docs/ar/identity-brokers.md"),
    ),
];

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "question": { "type": "string", "description": "A how-to question about using or configuring the product." }
  },
  "required": ["question"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        HELP_ANSWER,
        "Answer a how-to question about using or configuring the product from its \
         documentation and this deployment's configuration, citing the sections and objects \
         used, or decline.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(SCHEMA)
}

/// One section of a document: its heading (under the document's title) and
/// the text up to the next heading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocSection {
    pub file: String,
    pub heading: String,
    pub text: String,
}

/// `doc`'s sections, a heading line (`#` to `######`) opening each; text
/// before the first heading belongs to the title. Pure.
pub fn split_sections(file: &str, doc: &str) -> Vec<DocSection> {
    let mut sections: Vec<DocSection> = Vec::new();
    let mut title = String::new();
    let mut heading = String::new();
    let mut text = String::new();
    let mut in_code = false;
    let flush = |heading: &str, text: &mut String, sections: &mut Vec<DocSection>| {
        let body = text.trim();
        if !heading.is_empty() || !body.is_empty() {
            sections.push(DocSection {
                file: file.to_owned(),
                heading: heading.to_owned(),
                text: body.chars().take(SECTION_CHARS).collect(),
            });
        }
        text.clear();
    };
    for line in doc.lines() {
        if line.trim_start().starts_with("```") {
            in_code = !in_code;
        }
        let level = line.chars().take_while(|c| *c == '#').count();
        if !in_code && (1..=6).contains(&level) && line[level..].starts_with(' ') {
            flush(&heading, &mut text, &mut sections);
            let name = line[level..].trim().to_owned();
            if level == 1 {
                title = name.clone();
                heading = name;
            } else if title.is_empty() {
                heading = name;
            } else {
                heading = format!("{title} > {name}");
            }
            continue;
        }
        text.push_str(line);
        text.push('\n');
    }
    flush(&heading, &mut text, &mut sections);
    sections
}

/// Every help section.
pub fn sections() -> Vec<DocSection> {
    DOCS.iter()
        .flat_map(|(file, doc)| split_sections(file, doc))
        .collect()
}

/// How often `word` (or its singular) appears in `text`, lower-cased. Pure.
fn occurrences(text: &str, word: &str) -> usize {
    let singular = word.strip_suffix('s').filter(|s| s.chars().count() >= 3);
    text.matches(word).count()
        + singular.map_or(0, |s| {
            text.matches(s)
                .count()
                .saturating_sub(text.matches(word).count())
        })
}

/// The best `top` sections for `question`, best first; none that match no
/// word. Pure.
pub fn rank<'a>(question: &str, sections: &'a [DocSection], top: usize) -> Vec<&'a DocSection> {
    let words = keywords(question);
    if words.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(usize, &DocSection)> = sections
        .iter()
        .map(|section| {
            let heading = section.heading.to_lowercase();
            let text = section.text.to_lowercase();
            let score = words
                .iter()
                .map(|w| occurrences(&heading, w) * 3 + occurrences(&text, w))
                .sum::<usize>()
                // A section that names every word beats one that repeats one.
                + 5 * words
                    .iter()
                    .filter(|w| occurrences(&heading, w) + occurrences(&text, w) > 0)
                    .count();
            (score, section)
        })
        .filter(|(score, _)| *score > 5)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.file.cmp(&b.1.file)));
    scored.into_iter().take(top).map(|(_, s)| s).collect()
}

/// One piece of evidence: a document section or a configuration object.
#[derive(Debug, Clone, PartialEq)]
pub enum Evidence {
    Doc(DocSection),
    Config(ConfigObject),
}

impl Evidence {
    /// The evidence as the model reads it. Pure.
    pub fn text(&self) -> String {
        match self {
            Evidence::Doc(s) => format!("Documentation {} - {}\n{}", s.file, s.heading, s.text),
            Evidence::Config(o) => {
                let mut out = format!("This deployment's {} {}", o.kind, o.label);
                if let Some(d) = &o.description {
                    out.push_str(&format!("\nDescription: {d}"));
                }
                out
            }
        }
    }

    /// The evidence as a citation names it. Pure.
    pub fn citation(&self, index: usize) -> Value {
        match self {
            Evidence::Doc(s) => json!({
                "evidence": evidence_id(index),
                "kind": "doc",
                "file": s.file,
                "heading": s.heading,
            }),
            Evidence::Config(o) => json!({
                "evidence": evidence_id(index),
                "kind": o.kind,
                "ref": o.reference,
                "label": o.label,
            }),
        }
    }
}

/// The prompt.
pub fn help_system_prompt() -> String {
    "You help people use and configure a business application. Answer the question using \
     only the evidence provided: sections of the product's documentation and objects of \
     this deployment's configuration. Each is labelled with an evidence id such as E1.\n\n\
     Reply with exactly one JSON object and nothing else:\n\
     {\"status\": \"answered\" or \"insufficient\", \"answer\": string, \
     \"citations\": [evidence ids]}\n\n\
     Use \"answered\" only when the evidence answers the question: give the steps plainly and \
     list every piece of evidence you used. Use \"insufficient\" otherwise, with an empty \
     answer and no citations. Write the answer in the language of the question."
        .to_owned()
}

/// The model's reply judged against the evidence. Pure.
pub fn judged(reply: &str, truncated: bool, evidence: &[Evidence]) -> Value {
    match judge(reply, truncated, evidence.len()) {
        Verdict::Answered { answer, cited } => json!({
            "answer": answer,
            "citations": cited
                .iter()
                .filter_map(|i| evidence.get(*i).map(|e| e.citation(*i)))
                .collect::<Vec<_>>(),
        }),
        Verdict::Declined(DeclineReason::InsufficientEvidence | DeclineReason::NoEvidence) => {
            json!({ "answer": null, "reason": "not_found" })
        }
        Verdict::Declined(reason) => json!({ "answer": null, "reason": reason.as_str() }),
    }
}

/// This deployment's objects the question's words name, as the person sees
/// the catalogue; none when they may not read it or it is not there.
async fn config_evidence(
    state: &EngineState,
    ctx: &ActionContext,
    question: &str,
) -> Vec<Evidence> {
    let Some(catalog) = state.catalog_tools.as_deref() else {
        return Vec::new();
    };
    let mut out: Vec<Evidence> = Vec::new();
    for word in keywords(question) {
        let page = match catalog
            .search(state, &ctx.security, Some(&word), None, 3)
            .await
        {
            Ok(page) => page,
            // No metadata.read: help from the documents alone.
            Err(AppError::Forbidden) => return Vec::new(),
            Err(error) => {
                tracing::warn!(%error, "help.answer: catalogue search failed; documents only");
                return Vec::new();
            }
        };
        for object in page["items"]
            .as_array()
            .map(|items| items.iter().filter_map(asset_object).collect::<Vec<_>>())
            .unwrap_or_default()
        {
            if out.len() >= MAX_ASSETS {
                return out;
            }
            if !out
                .iter()
                .any(|e| matches!(e, Evidence::Config(o) if o == &object))
            {
                out.push(Evidence::Config(object));
            }
        }
    }
    out
}

pub(crate) struct HelpAnswer;

impl Action for HelpAnswer {
    fn id(&self) -> ActionId {
        ActionId(HELP_ANSWER)
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
            let all = sections();
            let mut evidence: Vec<Evidence> = rank(&question, &all, MAX_SECTIONS)
                .into_iter()
                .cloned()
                .map(Evidence::Doc)
                .collect();
            let mut config = config_evidence(state, ctx, &question).await;
            // An MCP agent hears only of the entities its admission names.
            if let Some(admission) = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)? {
                config.retain(|e| match e {
                    Evidence::Config(o) if matches!(o.kind.as_str(), "entity" | "attribute") => {
                        admission.admits(o.reference.split('.').next().unwrap_or_default())
                    }
                    _ => true,
                });
            }
            evidence.extend(config);
            if evidence.is_empty() {
                return Ok(ActionResult::plain(
                    json!({ "answer": null, "reason": "not_found" }),
                ));
            }
            let client = crate::inference_client::client_for(state, HELP_ANSWER).await?;
            let mut segments = vec![
                Segment::trusted(help_system_prompt()),
                Segment::untrusted("question", question.clone()),
            ];
            for (index, item) in evidence.iter().enumerate() {
                segments.push(Segment::untrusted(evidence_id(index), item.text()));
            }
            let mut request = GenerationRequest::new(crate::prompt::assemble(&segments));
            request.temperature = 0.0;
            crate::model_registry::require_approved_model(
                &state.base.db,
                client.model_id(),
                HELP_ANSWER,
            )
            .await?;
            let grant = crate::budget_guard::admit(
                state,
                ctx,
                attome_inference::budget::Priority::Chat,
                HELP_ANSWER,
                &mut request,
            )
            .await?;
            let generated = client.generate(request).await.map_err(|e| {
                tracing::warn!(error = %e, "help.answer generation failed");
                AppError::internal("help answer generation failed")
            })?;
            grant.settle(state, &generated.usage).await;
            Ok(ActionResult {
                value: judged(&generated.text, generated.truncated, &evidence),
                provenance: Some(Provenance {
                    model_id: generated.usage.model_id,
                    prompt_version: HELP_PROMPT_VERSION.to_owned(),
                    suggestion_id: None,
                }),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUIDE: &str = "# Fields\n\nIntro text.\n\n## Adding a field\n\nOpen the entity, choose Add field, \
pick a type and save.\n\n```\n# not a heading\n```\n\n## Removing a field\n\nRemoving keeps the values \
for 30 days.\n";

    #[test]
    fn help_answer_splits_sections_under_their_title() {
        let sections = split_sections("docs/fields.md", GUIDE);
        let headings: Vec<&str> = sections.iter().map(|s| s.heading.as_str()).collect();
        assert_eq!(
            headings,
            vec![
                "Fields",
                "Fields > Adding a field",
                "Fields > Removing a field"
            ]
        );
        assert!(sections[1].text.contains("# not a heading"), "code is text");
    }

    /// "How do I add a field" finds the section on adding one first.
    #[test]
    fn help_answer_ranks_the_section_that_answers() {
        let mut all = split_sections("docs/fields.md", GUIDE);
        all.extend(split_sections(
            "docs/email.md",
            "# Email\n\n## Sending\n\nAn email field is a field of type email.\n",
        ));
        let best = rank("How do I add a field?", &all, 3);
        assert_eq!(best[0].heading, "Fields > Adding a field");
        assert!(rank("how is it?", &all, 3).is_empty());
        // The built-in documents have sections to rank.
        assert!(!sections().is_empty());
        assert!(!rank("How do I restore a deleted record?", &sections(), 3).is_empty());
    }

    /// The fake model's reply, judged: citations name the document section
    /// and the configuration object; an invented one is declined.
    #[test]
    fn help_answer_cites_docs_and_configuration() {
        let evidence = vec![
            Evidence::Doc(split_sections("docs/fields.md", GUIDE)[1].clone()),
            Evidence::Config(ConfigObject {
                kind: "entity".into(),
                reference: "contact".into(),
                label: "Contact".into(),
                description: None,
            }),
        ];
        assert!(
            evidence[1]
                .text()
                .starts_with("This deployment's entity Contact")
        );
        let value = judged(
            r#"{"status": "answered", "answer": "Open Contact, choose Add field, pick a type and save.", "citations": ["E1", "E2"]}"#,
            false,
            &evidence,
        );
        assert_eq!(value["citations"][0]["kind"], "doc");
        assert_eq!(value["citations"][0]["file"], "docs/fields.md");
        assert_eq!(value["citations"][0]["heading"], "Fields > Adding a field");
        assert_eq!(value["citations"][1]["ref"], "contact");
        let invented = judged(
            r#"{"status": "answered", "answer": "x", "citations": ["E9"]}"#,
            false,
            &evidence,
        );
        assert_eq!(invented["reason"], "ungrounded");
        assert!(help_system_prompt().contains("evidence id"));
        let d = descriptor();
        assert_eq!((d.risk, d.effect), (RiskTier::Read, Effect::Read));
    }

    /// A new document is either built in or excluded on purpose.
    #[test]
    fn help_answer_builds_in_every_user_document() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs");
        for dir in [root.clone(), root.join("ar")] {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|e| e.to_str()) != Some("md") {
                    continue;
                }
                let name = path.file_name().unwrap().to_str().unwrap().to_owned();
                let rel = if dir == root {
                    format!("docs/{name}")
                } else {
                    format!("docs/ar/{name}")
                };
                assert!(
                    DOCS.iter().any(|(file, _)| *file == rel) || EXCLUDED.contains(&name.as_str()),
                    "{rel} is neither in help.rs's DOCS nor EXCLUDED"
                );
            }
        }
    }
}

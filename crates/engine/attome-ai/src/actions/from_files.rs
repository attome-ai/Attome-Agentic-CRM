//! `model.from_files` (roadmap AD5-T1): a data model from several uploaded
//! sheets, and the import that loads them.
//!
//! The sheets are profiled before any model is called
//! ([`crate::builder::from_files`]): column types from the cells (Hijri
//! dates too), currency columns, each sheet's key, and lookups where a
//! column holds another sheet's keys. Only names reach the model, to label
//! the entities and attributes in English and Arabic; never a cell.
//!
//! The answer is the draft, the review's findings, the plan (AD1-T1: reuse,
//! extend, ask or create) with its build-tool calls, and per sheet the
//! import to send once the model is built, as a dry run first. Nothing is
//! saved: the calls are made in the person's Develop workspace, where
//! nothing publishes without the owner's review (V2-D27).

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::actions::draft_model::{DRAFT_PROMPT_VERSION, review_view};
use crate::builder::from_files::{FilesDraft, Sheet, from_files};
use crate::builder::review::review;
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const MODEL_FROM_FILES: &str = "model.from_files";
/// Sheets one call takes.
const MAX_SHEETS: usize = 10;
/// Text taken in all, across the sheets.
const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;

const SCHEMA: &str = r#"{
  "type": "object",
  "required": ["files"],
  "properties": {
    "files": {
      "type": "array",
      "minItems": 1,
      "maxItems": 10,
      "items": {
        "type": "object",
        "required": ["name", "csv"],
        "properties": {
          "name": { "type": "string", "description": "The file or sheet name; the entity is named from it." },
          "csv": { "type": "string", "description": "The sheet's text as CSV (comma or semicolon); its first row is the header." }
        },
        "additionalProperties": false
      }
    }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            MODEL_FROM_FILES,
            "Draft a data model from several spreadsheets (CSV text, one per sheet): one entity per \
             sheet with types read from the cells (Hijri dates, currency amounts), each sheet's key, \
             lookups where a column holds another sheet's keys, the build-tool calls that make it, \
             and per sheet the import that loads the file afterwards. Saves nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SCHEMA),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(FromFiles)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    files: Vec<Sheet>,
}

/// Applies the model's labels (`{name: {label_en, label_ar}}`) to the draft.
/// Pure.
pub fn apply_labels(draft: &mut FilesDraft, labels: &Value) {
    for table in &mut draft.tables {
        if let Some(ar) = labels[&table.name]["label_ar"].as_str() {
            ar.clone_into(&mut table.label_ar);
        }
        for a in &mut table.attributes {
            if let Some(ar) = labels[&a.name]["label_ar"].as_str() {
                ar.clone_into(&mut a.label_ar);
            }
        }
    }
}

#[derive(Debug)]
pub struct FromFiles;

impl Action for FromFiles {
    fn id(&self) -> ActionId {
        ActionId(MODEL_FROM_FILES)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {MODEL_FROM_FILES} arguments: {e}"))
            })?;
            if args.files.is_empty() || args.files.len() > MAX_SHEETS {
                return Err(AppError::Validation(format!(
                    "files: one to {MAX_SHEETS} sheets"
                )));
            }
            if args.files.iter().map(|f| f.csv.len()).sum::<usize>() > MAX_TOTAL_BYTES {
                return Err(AppError::Validation(format!(
                    "files: at most {} MB in all",
                    MAX_TOTAL_BYTES / (1024 * 1024)
                )));
            }
            let mut draft = from_files(&args.files);

            // Arabic labels from the names alone: no cell reaches the model.
            let mut names: Vec<&str> = Vec::new();
            for t in &draft.tables {
                names.push(&t.name);
                names.extend(t.attributes.iter().map(|a| a.name.as_str()));
            }
            let system = "You label database entities and fields. Answer with one JSON object \
                and nothing else, mapping each given name to {\"label_en\", \"label_ar\"}; Arabic \
                labels in Modern Standard Arabic."
                .to_owned();
            let facts = json!({ "names": names }).to_string();
            let (text, provenance) = crate::actions::metric_draft::generate(
                state,
                ctx,
                MODEL_FROM_FILES,
                DRAFT_PROMPT_VERSION,
                system,
                facts,
            )
            .await?;
            if let Ok(labels) =
                serde_json::from_str::<Value>(crate::actions::metric_draft::strip_fence(&text))
            {
                apply_labels(&mut draft, &labels);
            }

            let existing: HashSet<String> = state
                .entities
                .load()
                .iter()
                .map(|m| m.logicalname.clone())
                .collect();
            let findings = review(&review_view(&draft.tables), &existing);
            let library = crate::actions::draft_model::library(state).await?;
            let steps = crate::builder::entities::plan(&draft.tables, &library);
            let calls = crate::builder::entities::build_plan_calls(&draft.tables, &steps);
            Ok(ActionResult {
                value: json!({
                    "draft": draft.tables,
                    "keys": draft.keys,
                    "currencies": draft.currencies,
                    "lookups": draft.lookups,
                    "findings": findings,
                    "plan": steps,
                    "calls": calls,
                    "imports": draft.imports,
                    "note": "make the calls in a Develop workspace, then send each import (a dry run first) in the listed order",
                    "saved": false,
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
    fn builder_from_files_labels_from_the_model_answer() {
        let mut draft = from_files(&[Sheet {
            name: "Patients".into(),
            csv: "Code,Name\nP1,Sara\nP2,Omar\n".into(),
        }]);
        // What the fake model answers for the names it was given.
        let labels = json!({
            "patients": { "label_en": "Patients", "label_ar": "المرضى" },
            "name": { "label_en": "Name", "label_ar": "الاسم" },
        });
        apply_labels(&mut draft, &labels);
        assert_eq!(draft.tables[0].label_ar, "المرضى");
        assert_eq!(draft.tables[0].attributes[1].label_ar, "الاسم");
        assert_eq!(draft.tables[0].attributes[0].label_ar, "");
    }

    #[test]
    fn builder_from_files_is_a_read_tool() {
        let d = &descriptors()[0];
        assert_eq!((d.risk, d.effect), (RiskTier::Read, Effect::Read));
    }
}

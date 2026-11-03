//! `model.draft` (roadmap A1-T13): "describe it" and "upload a spreadsheet"
//! creation. A building agent drafts entities, attributes with types,
//! relationships, labels in Arabic and English and up to 20 sample rows,
//! from a description or from a CSV's text; the draft is reviewed against the
//! existing model ([`crate::builder::review`]) before it is returned.
//!
//! Nothing is saved. The answer carries the plan (AD1-T1,
//! [`crate::builder::entities`]: each drafted entity reuses a library entity
//! of the same name, extends a base, waits on a question when it is near an
//! existing one, or is created) and the build-tool calls that would carry it
//! out (`model.entity.create`, `model.attribute.create`, N12-T1); made
//! in a Develop workspace (`X-Attome-Workspace`), they land in its draft and
//! changeset, and a person confirms each. For a spreadsheet the column types
//! come from the cells ([`crate::builder::infer`]), and only the headers
//! reach the model, never a cell: sample rows are the file's own first rows.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::builder::infer::{duplicate_columns, infer_columns, parse_csv};
use crate::builder::review::{DraftAttribute, DraftEntity, DraftRelationship, review};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const MODEL_DRAFT: &str = "model.draft";
/// Bumped whenever the prompt changes in a way that could move results.
pub const DRAFT_PROMPT_VERSION: &str = "model.draft/v1";
/// Sample rows a draft carries.
pub const MAX_SAMPLE_ROWS: usize = 20;
/// Rows of a CSV the column types are read from.
pub const MAX_INFER_ROWS: usize = 1_000;
/// The largest CSV text taken.
const MAX_CSV_BYTES: usize = 2 * 1024 * 1024;
/// Entities a description may draft.
const MAX_ENTITIES: usize = 12;

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "description": { "type": "string", "description": "What the app keeps, in the person's words." },
    "csv": { "type": "string", "description": "A spreadsheet's text as CSV (comma or semicolon); its first row is the header." },
    "entity": { "type": "string", "description": "For a CSV: the entity's name, when known." }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            MODEL_DRAFT,
            "Draft a data model from a description or a spreadsheet's CSV text: entities, typed \
             attributes, relationships, Arabic and English labels and sample rows, reviewed \
             against the existing model. Saves nothing; returns the model.entity.create and \
             model.attribute.create calls that would make it in a Develop workspace.",
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
    vec![Box::new(DraftModel)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    csv: Option<String>,
    #[serde(default)]
    entity: Option<String>,
}

/// A labelled attribute of the draft.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DraftField {
    pub name: String,
    pub field_type: String,
    #[serde(default)]
    pub label_en: String,
    #[serde(default)]
    pub label_ar: String,
    /// `islamic-umalqura` for a Hijri date column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar: Option<String>,
}

/// A labelled entity of the draft.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DraftTable {
    pub name: String,
    #[serde(default)]
    pub label_en: String,
    #[serde(default)]
    pub label_ar: String,
    #[serde(default)]
    pub attributes: Vec<DraftField>,
    #[serde(default)]
    pub relationships: Vec<DraftRelationship>,
    #[serde(default)]
    pub sample_rows: Vec<Value>,
}

/// Lower snake case of a header or a name: letters and digits joined by
/// `_`, at most 60 characters; `field` when nothing is left. Pure.
pub fn snake(text: &str) -> String {
    let mut out = String::new();
    for c in text.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    let out = out
        .trim_end_matches('_')
        .chars()
        .take(60)
        .collect::<String>();
    if out.is_empty() || out.starts_with(|c: char| c.is_ascii_digit()) {
        format!("field_{out}").trim_end_matches('_').to_owned()
    } else {
        out
    }
}

/// The draft of one entity from a CSV: one attribute per column (named from
/// its header, typed from its cells), and the first rows as samples. Pure.
pub fn table_from_csv(entity: &str, text: &str) -> DraftTable {
    let (headers, rows) = parse_csv(text);
    let rows: Vec<Vec<String>> = rows.into_iter().take(MAX_INFER_ROWS).collect();
    let columns = infer_columns(&headers, &rows);
    let mut seen = HashSet::new();
    let attributes: Vec<DraftField> = columns
        .iter()
        .map(|c| {
            let mut name = snake(&c.header);
            while !seen.insert(name.clone()) {
                name.push('_');
                name.push('2');
            }
            DraftField {
                name,
                field_type: c.field_type.to_owned(),
                label_en: c.header.trim().to_owned(),
                label_ar: String::new(),
                calendar: c.calendar.map(str::to_owned),
            }
        })
        .collect();
    let sample_rows = rows
        .iter()
        .take(MAX_SAMPLE_ROWS)
        .map(|row| {
            let mut record = serde_json::Map::new();
            for (field, cell) in attributes.iter().zip(row) {
                if !cell.trim().is_empty() {
                    record.insert(field.name.clone(), Value::String(cell.clone()));
                }
            }
            Value::Object(record)
        })
        .collect();
    DraftTable {
        name: snake(entity),
        label_en: entity.trim().to_owned(),
        label_ar: String::new(),
        attributes,
        relationships: Vec::new(),
        sample_rows,
    }
}

/// The review's view of the draft. Pure.
pub fn review_view(tables: &[DraftTable]) -> Vec<DraftEntity> {
    tables
        .iter()
        .map(|t| DraftEntity {
            name: t.name.clone(),
            attributes: t
                .attributes
                .iter()
                .map(|a| DraftAttribute {
                    name: a.name.clone(),
                    field_type: a.field_type.clone(),
                })
                .collect(),
            relationships: t.relationships.clone(),
        })
        .collect()
}

/// The build-tool calls that would make the draft: each entity, then its
/// attributes, then its lookups. Pure.
pub fn build_calls(tables: &[DraftTable]) -> Vec<Value> {
    let mut calls = Vec::new();
    for t in tables {
        calls.push(json!({
            "action": crate::actions::schema_build::ENTITY_CREATE,
            "args": { "logicalname": t.name, "name": if t.label_en.is_empty() { &t.name } else { &t.label_en } },
        }));
    }
    for t in tables {
        for a in &t.attributes {
            calls.push(json!({
                "action": crate::actions::schema_build::ATTRIBUTE_CREATE,
                "args": {
                    "entity": t.name,
                    "logicalname": a.name,
                    "name": if a.label_en.is_empty() { &a.name } else { &a.label_en },
                    "field_type": a.field_type,
                },
            }));
        }
    }
    calls
}

/// The deployment's entity library: every entity with its attributes and
/// its English and Arabic labels where it has them.
pub(crate) async fn library(
    state: &EngineState,
) -> Result<Vec<crate::builder::entities::LibraryEntity>, AppError> {
    let labels: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT object_ref, locale, display_name FROM metadata_label \
          WHERE object_kind = 'entity' AND NOT is_deleted AND locale IN ('en', 'ar')",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let label = |entity: &crate::builder::entities::LibraryEntity, locale: &str| {
        labels
            .iter()
            .find(|(object, l, _)| {
                l == locale && (object == &entity.name || object == &entity.id.to_string())
            })
            .map(|(_, _, text)| text.clone())
            .unwrap_or_default()
    };
    let mut out: Vec<crate::builder::entities::LibraryEntity> = state
        .entities
        .load()
        .iter()
        .map(|m| crate::builder::entities::LibraryEntity {
            id: m.entity_id,
            name: m.logicalname.clone(),
            label_en: String::new(),
            label_ar: String::new(),
            attributes: m.attrs.iter().map(|a| a.logicalname.clone()).collect(),
        })
        .collect();
    for entity in &mut out {
        entity.label_en = label(entity, "en");
        entity.label_ar = label(entity, "ar");
    }
    Ok(out)
}

/// A field type the field route accepts for `name`: one of
/// `attome_core::FieldType`'s names as it is, a common other name mapped
/// onto one (`boolean` to `bool`, `email` to `text`), anything else `text`.
/// Pure.
pub fn field_type_of(name: &str) -> &'static str {
    let name = name.trim().to_ascii_lowercase();
    match name.as_str() {
        "number" | "integer" | "int" | "decimal" | "float" | "double" => "number",
        "currency" | "money" | "amount" => "currency",
        "date" => "date",
        "date_time" | "datetime" | "timestamp" => "date_time",
        "time" => "time",
        "bool" | "boolean" | "yes_no" | "checkbox" => "bool",
        "choice" | "option_set" | "picklist" | "enum" | "select" => "choice",
        "lookup" | "reference" => "lookup",
        "rich_text" | "html" => "rich_text",
        "file" | "attachment" => "file",
        "image" | "photo" => "image",
        _ => "text",
    }
}

/// The model's tables, bounded, named by the naming rules and typed with
/// the field route's type names. Pure.
fn tidy(mut tables: Vec<DraftTable>) -> Vec<DraftTable> {
    tables.truncate(MAX_ENTITIES);
    for t in &mut tables {
        t.name = snake(&t.name);
        t.sample_rows.truncate(MAX_SAMPLE_ROWS);
        for a in &mut t.attributes {
            a.name = snake(&a.name);
            a.field_type = field_type_of(&a.field_type).to_owned();
        }
    }
    tables
}

#[derive(Debug)]
pub struct DraftModel;

impl Action for DraftModel {
    fn id(&self) -> ActionId {
        ActionId(MODEL_DRAFT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // The build tools the draft feeds are administrators' only.
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {MODEL_DRAFT} arguments: {e}"))
            })?;
            let existing: HashSet<String> = state
                .entities
                .load()
                .iter()
                .map(|m| m.logicalname.clone())
                .collect();
            let mut existing_names: Vec<&String> = existing.iter().collect();
            existing_names.sort();
            existing_names.truncate(300);

            let (tables, duplicates, provenance) = match (args.description, args.csv) {
                (Some(description), None) if !description.trim().is_empty() => {
                    let system = format!(
                        "You draft a data model for a business app. Answer with one JSON array \
                         and nothing else, at most {MAX_ENTITIES} items: [{{\"name\" (lower \
                         snake case), \"label_en\", \"label_ar\", \"attributes\": [{{\"name\", \
                         \"field_type\" (text, rich_text, number, currency, date, date_time, \
                         time, bool, choice, lookup, file, image), \"label_en\", \
                         \"label_ar\"}}], \"relationships\": [{{\"target\", \"kind\" \
                         (many_to_one or one_to_many), \"attribute\" (the lookup, for \
                         many_to_one)}}], \"sample_rows\": [at most {MAX_SAMPLE_ROWS} objects \
                         keyed by attribute name]}}]. Reuse an existing entity by naming it as a \
                         relationship target instead of drafting it again."
                    );
                    let facts = json!({
                        "description": description,
                        "existing_entities": existing_names,
                    })
                    .to_string();
                    let (text, provenance) = crate::actions::metric_draft::generate(
                        state,
                        ctx,
                        MODEL_DRAFT,
                        DRAFT_PROMPT_VERSION,
                        system,
                        facts,
                    )
                    .await?;
                    let tables: Vec<DraftTable> =
                        serde_json::from_str(crate::actions::metric_draft::strip_fence(&text))
                            .map_err(|e| {
                                AppError::Validation(format!(
                                    "the drafted model is not a list of entities: {e}"
                                ))
                            })?;
                    (tidy(tables), Vec::new(), provenance)
                }
                (None, Some(csv)) if !csv.trim().is_empty() => {
                    if csv.len() > MAX_CSV_BYTES {
                        return Err(AppError::Validation(format!(
                            "csv: at most {} MB",
                            MAX_CSV_BYTES / (1024 * 1024)
                        )));
                    }
                    let entity = args.entity.as_deref().unwrap_or("imported");
                    let mut table = table_from_csv(entity, &csv);
                    let (headers, rows) = parse_csv(&csv);
                    let rows: Vec<Vec<String>> = rows.into_iter().take(MAX_INFER_ROWS).collect();
                    let duplicates: Vec<Value> = duplicate_columns(&headers, &rows)
                        .into_iter()
                        .map(|(a, b)| json!({ "first": headers[a], "second": headers[b] }))
                        .collect();
                    // Arabic labels from the headers alone: no cell reaches the model.
                    let system = "You label database fields. Answer with one JSON object and \
                        nothing else, mapping each given field name to {\"label_en\", \
                        \"label_ar\"}; Arabic labels in Modern Standard Arabic."
                        .to_owned();
                    let mut names: Vec<&str> =
                        table.attributes.iter().map(|a| a.name.as_str()).collect();
                    names.push(&table.name);
                    let facts = json!({ "fields": names }).to_string();
                    let (text, provenance) = crate::actions::metric_draft::generate(
                        state,
                        ctx,
                        MODEL_DRAFT,
                        DRAFT_PROMPT_VERSION,
                        system,
                        facts,
                    )
                    .await?;
                    if let Ok(labels) = serde_json::from_str::<Value>(
                        crate::actions::metric_draft::strip_fence(&text),
                    ) {
                        for a in &mut table.attributes {
                            if let Some(ar) = labels[&a.name]["label_ar"].as_str() {
                                a.label_ar = ar.to_owned();
                            }
                        }
                        if let Some(ar) = labels[&table.name]["label_ar"].as_str() {
                            table.label_ar = ar.to_owned();
                        }
                    }
                    (vec![table], duplicates, provenance)
                }
                _ => {
                    return Err(AppError::Validation(
                        "give one of description or csv".into(),
                    ));
                }
            };

            let findings = review(&review_view(&tables), &existing);
            // AD1-T1: the library first: reuse, extend, ask or create.
            let library = library(state).await?;
            let steps = crate::builder::entities::plan(&tables, &library);
            let calls = crate::builder::entities::build_plan_calls(&tables, &steps);
            Ok(ActionResult {
                value: json!({
                    "draft": tables,
                    "duplicate_columns": duplicates,
                    "findings": findings,
                    "plan": steps,
                    "calls": calls,
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
    fn names_follow_the_naming_rules() {
        assert_eq!(snake("Customer Name"), "customer_name");
        assert_eq!(snake("  رقم الهوية "), "field");
        assert_eq!(snake("2nd phone"), "field_2nd_phone");
        assert_eq!(snake("Amount (SAR)"), "amount_sar");
    }

    #[test]
    fn a_csv_becomes_one_typed_entity_with_samples() {
        let csv = "Name,Email,Joined\nSara,sara@example.com,1446/03/15\nOmar,omar@example.com,1446/04/01\n";
        let table = table_from_csv("Members", csv);
        assert_eq!(table.name, "members");
        let names: Vec<&str> = table.attributes.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["name", "email", "joined"]);
        let joined = &table.attributes[2];
        assert_eq!(joined.calendar.as_deref(), Some("islamic-umalqura"));
        assert_eq!(table.sample_rows.len(), 2);
        assert_eq!(table.sample_rows[0]["email"], "sara@example.com");
        // The entity first, then each field.
        let calls = build_calls(&[table]);
        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls[0]["action"],
            crate::actions::schema_build::ENTITY_CREATE
        );
        assert_eq!(calls[1]["args"]["entity"], "members");
    }

    #[test]
    fn field_types_are_the_field_routes_own() {
        assert_eq!(field_type_of("Boolean"), "bool");
        assert_eq!(field_type_of("datetime"), "date_time");
        assert_eq!(field_type_of("email"), "text");
        assert_eq!(field_type_of("decimal"), "number");
        assert_eq!(field_type_of("choice"), "choice");
        assert_eq!(field_type_of("anything"), "text");
    }

    #[test]
    fn the_model_draft_is_bounded_and_renamed() {
        let tables = tidy(vec![DraftTable {
            name: "Service Visit".into(),
            label_en: "Service visit".into(),
            label_ar: "زيارة خدمة".into(),
            attributes: vec![DraftField {
                name: "Visit Date".into(),
                field_type: "date".into(),
                label_en: String::new(),
                label_ar: String::new(),
                calendar: None,
            }],
            relationships: Vec::new(),
            sample_rows: vec![json!({}); 30],
        }]);
        assert_eq!(tables[0].name, "service_visit");
        assert_eq!(tables[0].attributes[0].name, "visit_date");
        assert_eq!(tables[0].sample_rows.len(), MAX_SAMPLE_ROWS);
    }
}

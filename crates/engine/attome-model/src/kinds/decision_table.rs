//! The decision table kind (roadmap Z11-T11): rows of conditions on named
//! inputs and the result each row gives.
//!
//! ```json
//! { "name": "discount", "inputs": [{ "name": "amount", "type": "number" }],
//!   "output": "number", "hit": "first",
//!   "rows": [{ "cells": ["it >= 1000"], "result": "0.1" },
//!            { "cells": [null], "result": "0" }],
//!   "accept_gaps": false }
//! ```
//!
//! Cooking compiles every cell and result and checks the table
//! ([`attome_rules::CompiledTable::check`]): an overlap of a `first` table is
//! allowed (the first row wins), a gap in the numbers no row covers refuses
//! the publish unless `accept_gaps` is set.

use attome_rules::{Budgets, DecisionRow, DecisionTable, HitPolicy, TableIssue};
use attome_types::AppError;
use serde_json::{Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};
use crate::kinds::rule_function::{TYPE_NAMES, rule_type};

/// The kind's name.
pub const DECISION_TABLE: KindName = KindName("decision_table");

/// The decision table kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct DecisionTableKind;

/// The table a document describes, or the problems with it. Pure.
pub fn decision_table(doc: &Value) -> Result<DecisionTable, Vec<Issue>> {
    let mut issues = Vec::new();
    if doc["name"].as_str().is_none_or(str::is_empty) {
        issues.push(Issue::new("/name", "required", "a table has a name"));
    }
    let mut inputs = Vec::new();
    for (i, input) in doc["inputs"].as_array().into_iter().flatten().enumerate() {
        let name = input["name"].as_str().unwrap_or_default();
        match input["type"].as_str().and_then(rule_type) {
            Some(ty) if !name.is_empty() => inputs.push((name.to_owned(), ty)),
            _ => issues.push(Issue::new(
                format!("/inputs/{i}"),
                "invalid",
                format!("an input has a name and a type ({})", TYPE_NAMES.join(", ")),
            )),
        }
    }
    if inputs.is_empty() && issues.is_empty() {
        issues.push(Issue::new("/inputs", "required", "a table has inputs"));
    }
    let output = doc["output"].as_str().and_then(rule_type);
    if output.is_none() {
        issues.push(Issue::new(
            "/output",
            "unknown_value",
            format!("output is one of {}", TYPE_NAMES.join(", ")),
        ));
    }
    let hit = match doc["hit"].as_str().unwrap_or("first") {
        "first" => HitPolicy::First,
        "all" => HitPolicy::All,
        _ => {
            issues.push(Issue::new("/hit", "unknown_value", "hit is first or all"));
            HitPolicy::First
        }
    };
    let mut rows = Vec::new();
    for (i, row) in doc["rows"].as_array().into_iter().flatten().enumerate() {
        let cells: Vec<Option<String>> = row["cells"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| c.as_str().map(str::to_owned))
            .collect();
        match row["result"].as_str() {
            Some(result) => rows.push(DecisionRow {
                cells,
                result: result.to_owned(),
            }),
            None => issues.push(Issue::new(
                format!("/rows/{i}/result"),
                "required",
                "a row has a result expression",
            )),
        }
    }
    if rows.is_empty() && issues.is_empty() {
        issues.push(Issue::new("/rows", "required", "a table has rows"));
    }
    if issues.is_empty() {
        Ok(DecisionTable {
            inputs,
            output: output.unwrap_or(attome_rules::Type::Null),
            hit,
            rows,
        })
    } else {
        Err(issues)
    }
}

/// The problems that refuse the table's publish, as messages. Pure.
pub fn table_problems(doc: &Value) -> Vec<String> {
    let table = match decision_table(doc) {
        Ok(table) => table,
        Err(issues) => return issues.into_iter().map(|i| i.message).collect(),
    };
    let compiled = match table.compile(Budgets::default()) {
        Ok(compiled) => compiled,
        Err(e) => return vec![e.to_string()],
    };
    let accept_gaps = doc["accept_gaps"].as_bool().unwrap_or(false);
    compiled
        .check()
        .into_iter()
        // Overlaps are allowed: a `first` table takes the first match and an
        // `all` table answers every match.
        .filter_map(|issue| match issue {
            TableIssue::Gap { input, .. } if !accept_gaps => Some(format!(
                "no row covers some values of {input}; add a row or set accept_gaps"
            )),
            _ => None,
        })
        .collect()
}

impl Kind for DecisionTableKind {
    fn name(&self) -> KindName {
        DECISION_TABLE
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["name", "inputs", "output", "rows"],
            "additionalProperties": false,
            "properties": {
                "name": { "type": "string" },
                "inputs": {
                    "type": "array",
                    "maxItems": attome_rules::decision_table::MAX_INPUTS,
                    "items": {
                        "type": "object",
                        "required": ["name", "type"],
                        "properties": {
                            "name": { "type": "string" },
                            "type": { "enum": TYPE_NAMES }
                        }
                    }
                },
                "output": { "enum": TYPE_NAMES },
                "hit": { "enum": ["first", "all"] },
                "rows": {
                    "type": "array",
                    "maxItems": attome_rules::decision_table::MAX_ROWS,
                    "items": {
                        "type": "object",
                        "required": ["cells", "result"],
                        "properties": {
                            "cells": { "type": "array", "items": { "type": ["string", "null"] } },
                            "result": { "type": "string" }
                        }
                    }
                },
                "accept_gaps": { "type": "boolean" }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        if !doc.is_object() {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a decision table is a JSON object",
            )]);
        }
        decision_table(doc).map(|_| ())
    }

    fn references(&self, _doc: &Value) -> Vec<Reference> {
        Vec::new()
    }

    fn check(&self, doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        table_problems(doc)
            .into_iter()
            .map(|message| Issue::new("/rows", "table_check", message))
            .collect()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let problems = table_problems(&input.doc);
                if !problems.is_empty() {
                    return Err(AppError::Validation(format!(
                        "decision table {}: {}",
                        input.name,
                        problems.join("; ")
                    )));
                }
                let text =
                    crate::canonical::canonicalize(&input.doc).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: DECISION_TABLE,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a decision table: typed inputs, an output type, and rows of conditions on the inputs with the result each row gives; gaps in the covered values must be accepted explicitly."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(rows: Value, accept_gaps: bool) -> Value {
        json!({
            "name": "discount",
            "inputs": [{ "name": "amount", "type": "number" }],
            "output": "number",
            "hit": "first",
            "rows": rows,
            "accept_gaps": accept_gaps
        })
    }

    #[test]
    fn decision_table_gap_needs_accept() {
        let gappy = json!([{ "cells": ["it >= 1000"], "result": "0.1" }]);
        assert!(!table_problems(&table(gappy.clone(), false)).is_empty());
        assert!(table_problems(&table(gappy, true)).is_empty());
        let full = json!([
            { "cells": ["it >= 1000"], "result": "0.1" },
            { "cells": [null], "result": "0" }
        ]);
        assert!(table_problems(&table(full, false)).is_empty());
    }

    #[test]
    fn decision_table_shape_names_its_problems() {
        let issues = DecisionTableKind
            .validate_shape(&json!({
                "name": "t", "inputs": [{ "name": "a", "type": "money" }],
                "output": "blob", "hit": "some", "rows": [{ "cells": [] }]
            }))
            .unwrap_err();
        let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        for expected in ["/inputs/0", "/output", "/hit", "/rows/0/result"] {
            assert!(paths.contains(&expected), "{expected} in {paths:?}");
        }
    }
}

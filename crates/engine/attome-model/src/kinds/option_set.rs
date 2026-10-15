//! The option set kind (roadmap A5-T1): a list of values with stable codes,
//! shared by choice attributes across entities.
//!
//! ```json
//! { "values": [
//!     { "code": "open", "label_en": "Open", "label_ar": "مفتوح", "colour": "#2563eb", "order": 1 },
//!     { "code": "lost", "label_en": "Lost", "label_ar": "خاسر", "retired": true } ] }
//! ```
//!
//! Records store the code, so renaming a label changes no record. A retired
//! value is refused on new writes and kept on the records that hold it.

use std::collections::BTreeSet;

use attome_types::AppError;
use serde_json::{Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const OPTION_SET: KindName = KindName("option_set");

/// Most values in one set.
pub const MAX_VALUES: usize = 1000;
/// Longest code.
pub const MAX_CODE_CHARS: usize = 100;
/// Longest label.
pub const MAX_LABEL_CHARS: usize = 200;

/// The option set kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct OptionSetKind;

/// Whether `code` is a usable code: 1 to 100 letters, digits, `_`, `-` or `.`.
pub fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.chars().count() <= MAX_CODE_CHARS
        && code
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Whether `colour` is `#rrggbb`.
fn valid_colour(colour: &str) -> bool {
    colour.len() == 7
        && colour.starts_with('#')
        && colour[1..].chars().all(|h| h.is_ascii_hexdigit())
}

/// The codes a set offers for new writes (not retired), in order.
pub fn active_codes(doc: &Value) -> Vec<String> {
    let mut values: Vec<&Value> = doc["values"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|v| v["retired"] != json!(true))
        .collect();
    values.sort_by_key(|v| v["order"].as_i64().unwrap_or(i64::MAX));
    values
        .into_iter()
        .filter_map(|v| v["code"].as_str().map(str::to_owned))
        .collect()
}

impl Kind for OptionSetKind {
    fn name(&self) -> KindName {
        OPTION_SET
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["values"],
            "additionalProperties": false,
            "properties": {
                "values": {
                    "type": "array",
                    "maxItems": MAX_VALUES,
                    "items": {
                        "type": "object",
                        "required": ["code", "label_en"],
                        "additionalProperties": false,
                        "properties": {
                            "code": { "type": "string", "minLength": 1, "maxLength": MAX_CODE_CHARS },
                            "label_en": { "type": "string", "minLength": 1, "maxLength": MAX_LABEL_CHARS },
                            "label_ar": { "type": "string", "maxLength": MAX_LABEL_CHARS },
                            "colour": { "type": "string", "pattern": "^#[0-9a-fA-F]{6}$" },
                            "order": { "type": "integer" },
                            "retired": { "type": "boolean" }
                        }
                    }
                }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "an option set is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if key != "values" {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("an option set has no `{key}`"),
                ));
            }
        }
        let Some(values) = doc["values"].as_array() else {
            issues.push(Issue::new(
                "/values",
                "required",
                "an option set has a list of values",
            ));
            return Err(issues);
        };
        if values.len() > MAX_VALUES {
            issues.push(Issue::new(
                "/values",
                "too_many",
                format!("an option set holds at most {MAX_VALUES} values"),
            ));
        }
        let mut codes = BTreeSet::new();
        for (i, value) in values.iter().enumerate() {
            let at = |key: &str| format!("/values/{i}/{key}");
            if let Some(entry) = value.as_object() {
                for key in entry.keys() {
                    if !["code", "label_en", "label_ar", "colour", "order", "retired"]
                        .contains(&key.as_str())
                    {
                        issues.push(Issue::new(
                            at(key),
                            "unknown_property",
                            format!("a value has no `{key}`"),
                        ));
                    }
                }
            }
            match value["code"].as_str() {
                Some(code) if valid_code(code) => {
                    if !codes.insert(code.to_owned()) {
                        issues.push(Issue::new(
                            at("code"),
                            "duplicate_code",
                            format!("the code `{code}` appears twice"),
                        ));
                    }
                }
                _ => issues.push(Issue::new(
                    at("code"),
                    "invalid",
                    "a code is 1 to 100 letters, digits, `_`, `-` or `.`",
                )),
            }
            let label_ok = value["label_en"]
                .as_str()
                .map(str::trim)
                .is_some_and(|l| !l.is_empty() && l.chars().count() <= MAX_LABEL_CHARS);
            if !label_ok {
                issues.push(Issue::new(
                    at("label_en"),
                    "required",
                    "a value has an English label of 1 to 200 characters",
                ));
            }
            if value.get("label_ar").is_some_and(|l| {
                l.as_str()
                    .is_none_or(|l| l.chars().count() > MAX_LABEL_CHARS)
            }) {
                issues.push(Issue::new(
                    at("label_ar"),
                    "invalid",
                    "an Arabic label is text of at most 200 characters",
                ));
            }
            if value
                .get("colour")
                .is_some_and(|c| c.as_str().is_none_or(|c| !valid_colour(c)))
            {
                issues.push(Issue::new(at("colour"), "invalid", "a colour is #rrggbb"));
            }
            if value.get("order").is_some_and(|o| !o.is_i64()) {
                issues.push(Issue::new(
                    at("order"),
                    "invalid",
                    "an order is a whole number",
                ));
            }
            if value.get("retired").is_some_and(|r| !r.is_boolean()) {
                issues.push(Issue::new(
                    at("retired"),
                    "invalid",
                    "retired is true or false",
                ));
            }
        }
        if !values.is_empty() && active_codes(doc).is_empty() {
            issues.push(Issue::new(
                "/values",
                "all_retired",
                "an option set keeps at least one value that is not retired",
            ));
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, _doc: &Value) -> Vec<Reference> {
        Vec::new()
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut set = input.doc.clone();
                if let Some(object) = set.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                    object.insert("active_codes".into(), json!(active_codes(&input.doc)));
                }
                let text = crate::canonical::canonicalize(&set).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: OPTION_SET,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Edit a shared list of values (codes with English and Arabic labels, colours and order) that choice fields on several entities use; retire a value instead of deleting it."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> Value {
        json!({ "values": [
            { "code": "won", "label_en": "Won", "label_ar": "فاز", "order": 2 },
            { "code": "open", "label_en": "Open", "colour": "#2563eb", "order": 1 },
            { "code": "lost", "label_en": "Lost", "retired": true, "order": 3 }
        ] })
    }

    #[test]
    fn a_set_validates_and_offers_its_active_codes_in_order() {
        assert!(OptionSetKind.validate_shape(&set()).is_ok());
        assert_eq!(
            active_codes(&set()),
            vec!["open".to_owned(), "won".to_owned()]
        );
        assert!(valid_code("in-progress.v2"));
        assert!(!valid_code("has space"));
    }

    #[test]
    fn bad_values_are_named() {
        let doc = json!({ "values": [
            { "code": "a", "label_en": "A", "colour": "blue" },
            { "code": "a", "label_en": "" },
            { "code": "x y", "label_en": "X", "extra": 1 }
        ] });
        let issues = OptionSetKind.validate_shape(&doc).unwrap_err();
        let found: Vec<(&str, &str)> = issues.iter().map(|i| (i.path.as_str(), i.code)).collect();
        assert!(found.contains(&("/values/0/colour", "invalid")));
        assert!(found.contains(&("/values/1/code", "duplicate_code")));
        assert!(found.contains(&("/values/1/label_en", "required")));
        assert!(found.contains(&("/values/2/code", "invalid")));
        assert!(found.contains(&("/values/2/extra", "unknown_property")));
    }

    #[test]
    fn a_set_keeps_one_value_in_use() {
        let doc = json!({ "values": [{ "code": "a", "label_en": "A", "retired": true }] });
        let issues = OptionSetKind.validate_shape(&doc).unwrap_err();
        assert!(issues.iter().any(|i| i.code == "all_retired"));
    }
}

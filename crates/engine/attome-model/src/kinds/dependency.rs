//! The dependency kind (roadmap A6-T1): which values a dependent attribute
//! may take for each value of a controlling attribute, such as the cities
//! of a region.
//!
//! ```json
//! { "entity": "account",
//!   "controlling": "region",
//!   "dependent": "city",
//!   "matrix": { "central": ["riyadh", "kharj"], "western": ["jeddah", "makkah"] },
//!   "default": ["other"] }
//! ```
//!
//! Publishing compiles it to A11 business rules through the changeset
//! ledger ([`changeset_for`]): one `allowed_values` rule per controlling
//! value, and with a `default`, one for any other non-empty controlling
//! value. The server refuses a write whose dependent value is not allowed,
//! with the A3 field failure, and the form offers only the allowed values.
//! A controlling value dropped from the matrix on a later publish has its
//! rule turned off. Filtering a lookup by a related record (the plan's
//! `source` mode) is not built.

use attome_types::AppError;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const DEPENDENCY: KindName = KindName("dependency");

/// Most controlling values one matrix maps, and most values per entry.
pub const MAX_ENTRIES: usize = 500;

const MAX_DESCRIPTION_CHARS: usize = 500;

/// The dependency kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct DependencyKind;

fn name_ok(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn codes(value: &Value) -> Option<Vec<String>> {
    let items = value.as_array()?;
    if items.is_empty() || items.len() > MAX_ENTRIES {
        return None;
    }
    items
        .iter()
        .map(|v| v.as_str().map(str::to_owned).filter(|s| !s.is_empty()))
        .collect()
}

/// The entity a dependency is on.
pub fn entity_of(doc: &Value) -> Option<&str> {
    doc.get("entity").and_then(Value::as_str)
}

/// The controlling values a dependency maps.
pub fn controlling_values(doc: &Value) -> Vec<String> {
    doc.get("matrix")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

impl Kind for DependencyKind {
    fn name(&self) -> KindName {
        DEPENDENCY
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["entity", "controlling", "dependent", "matrix"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string" },
                "controlling": { "type": "string" },
                "dependent": { "type": "string" },
                "matrix": {
                    "type": "object",
                    "maxProperties": MAX_ENTRIES,
                    "additionalProperties": { "type": "array", "items": { "type": "string" } }
                },
                "default": { "type": "array", "items": { "type": "string" } },
                "description_en": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS },
                "description_ar": { "type": "string", "maxLength": MAX_DESCRIPTION_CHARS }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a dependency is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if ![
                "entity",
                "controlling",
                "dependent",
                "matrix",
                "default",
                "description_en",
                "description_ar",
            ]
            .contains(&key.as_str())
            {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("a dependency has no `{key}`"),
                ));
            }
        }
        for key in ["entity", "controlling", "dependent"] {
            if !doc[key].as_str().is_some_and(name_ok) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "required",
                    format!("{key} is a logical name"),
                ));
            }
        }
        if doc["controlling"].is_string() && doc["controlling"] == doc["dependent"] {
            issues.push(Issue::new(
                "/dependent",
                "same_attribute",
                "an attribute cannot depend on itself",
            ));
        }
        match doc.get("matrix").and_then(Value::as_object) {
            Some(matrix) if !matrix.is_empty() && matrix.len() <= MAX_ENTRIES => {
                for (code, allowed) in matrix {
                    if code.is_empty() || codes(allowed).is_none() {
                        issues.push(Issue::new(
                            format!("/matrix/{code}"),
                            "invalid",
                            "each controlling value maps to a list of 1 to 500 allowed values",
                        ));
                    }
                }
            }
            _ => issues.push(Issue::new(
                "/matrix",
                "required",
                "matrix maps 1 to 500 controlling values to their allowed values",
            )),
        }
        if doc.get("default").is_some_and(|d| codes(d).is_none()) {
            issues.push(Issue::new(
                "/default",
                "invalid",
                "default is a list of allowed values",
            ));
        }
        for key in ["description_en", "description_ar"] {
            if doc.get(key).is_some_and(|d| {
                d.as_str()
                    .is_none_or(|d| d.chars().count() > MAX_DESCRIPTION_CHARS)
            }) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "invalid",
                    "a description is text of at most 500 characters",
                ));
            }
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
                let mut dependency = input.doc.clone();
                if let Some(object) = dependency.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text =
                    crate::canonical::canonicalize(&dependency).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: DEPENDENCY,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define which values a dependent attribute may take for each value of a controlling attribute (the cities of a region). Publishing turns it into allowed-values rules that the server enforces and the form follows."
    }
}

fn short(id: Uuid) -> String {
    id.simple().to_string()[..12].to_owned()
}

/// The rule name for one controlling value: stable, and safe whatever the
/// value's characters.
pub fn rule_name(dependency: Uuid, code: Option<&str>) -> String {
    match code {
        Some(code) => {
            let digest = Sha256::digest(code.as_bytes());
            let hex: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
            format!("dep_{}_{hex}", short(dependency))
        }
        None => format!("dep_{}_default", short(dependency)),
    }
}

/// The changeset scope of one dependency's rules.
pub fn scope_of(dependency: Uuid) -> String {
    format!("dependency_{}", short(dependency))
}

/// The ledger id for this content: the same dependency and content always
/// give the same id, so publishing it again applies nothing.
pub fn changeset_id(dependency: Uuid, doc: &Value, retired: &[String]) -> Uuid {
    let canonical = crate::canonical::canonicalize(doc).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(dependency.as_bytes());
    hasher.update(canonical.as_bytes());
    for code in retired {
        hasher.update(b"\x00retired:");
        hasher.update(code.as_bytes());
    }
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn rule(
    entity: &str,
    name: String,
    display_name: String,
    condition: Value,
    dependent: &str,
    allowed: Vec<String>,
    active: bool,
) -> Value {
    json!({
        "args": { "definition": {
            "applies_to": "all",
            "condition": condition,
            "description": "Generated from a dependency (A6-T1); edit the dependency, not this rule.",
            "display_name": display_name,
            "display_order": 0,
            "entity_logicalname": entity,
            "is_active": active,
            "kind": "business",
            "message": null,
            "name": name,
            "policies": [ { "field": dependent, "type": "allowed_values", "value": allowed } ],
            "severity": "error",
            "target_field": null
        }},
        "op": "upsert_rule",
        "phase": "expand",
        "target": { "entity": entity, "rule": name }
    })
}

/// The changeset that brings the entity's rules in line with `doc`:
/// one rule per controlling value, a default rule (on, or off when the
/// default is gone), and `retired` controlling values' rules turned off.
pub fn changeset_for(dependency: Uuid, doc: &Value, retired: &[String], seq: i32) -> Value {
    let entity = entity_of(doc).unwrap_or_default();
    let controlling = doc["controlling"].as_str().unwrap_or_default();
    let dependent = doc["dependent"].as_str().unwrap_or_default();
    let mut ops = Vec::new();
    let matrix = doc
        .get("matrix")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (code, allowed) in &matrix {
        ops.push(rule(
            entity,
            rule_name(dependency, Some(code)),
            format!("{dependent} for {controlling} = {code}"),
            json!({ "field": controlling, "op": "eq", "value": code }),
            dependent,
            codes(allowed).unwrap_or_default(),
            true,
        ));
    }
    // An `allowed_values` policy lists at least one code, so a rule that is
    // switched off keeps every value the matrix names.
    let mut every: Vec<String> = matrix.values().filter_map(codes).flatten().collect();
    every.sort();
    every.dedup();
    let default = doc.get("default").and_then(codes);
    ops.push(rule(
        entity,
        rule_name(dependency, None),
        format!("{dependent} for any other {controlling}"),
        json!({ "all": [
            { "field": controlling, "op": "is_not_empty" },
            { "field": controlling, "op": "not_in", "value": matrix.keys().cloned().collect::<Vec<_>>() }
        ]}),
        dependent,
        default.clone().unwrap_or_else(|| every.clone()),
        default.is_some(),
    ));
    for code in retired {
        ops.push(rule(
            entity,
            rule_name(dependency, Some(code)),
            format!("{dependent} for {controlling} = {code} (removed)"),
            json!({ "field": controlling, "op": "eq", "value": code }),
            dependent,
            every.clone(),
            false,
        ));
    }
    for (i, op) in ops.iter_mut().enumerate() {
        op["seq"] = json!(i + 1);
    }

    let mut out = Map::new();
    out.insert("author".into(), json!("dependency"));
    out.insert(
        "checksum".into(),
        json!(format!("sha256:{}", "0".repeat(64))),
    );
    out.insert("closed_at".into(), json!(FIXED_TIME));
    out.insert(
        "description".into(),
        json!(format!(
            "The allowed {dependent} values for each {controlling} on {entity} (A6-T1)."
        )),
    );
    out.insert("format".into(), json!("attome-changeset/v1"));
    out.insert(
        "id".into(),
        json!(changeset_id(dependency, doc, retired).to_string()),
    );
    out.insert("layer".into(), json!("project"));
    out.insert(
        "name".into(),
        json!(format!("dependency-{}", short(dependency))),
    );
    out.insert("opened_at".into(), json!(FIXED_TIME));
    out.insert("operations".into(), Value::Array(ops));
    out.insert(
        "requires".into(),
        json!({ "modules": ["core"], "platform": ">=0.1.0" }),
    );
    out.insert("scope".into(), json!(scope_of(dependency)));
    out.insert("seq".into(), json!(seq));
    out.insert(
        "title".into(),
        json!(
            format!("Dependency: {dependent} by {controlling}")
                .chars()
                .take(200)
                .collect::<String>()
        ),
    );
    let mut document = Value::Object(out);
    if let Ok(checksum) = crate::canonical::document_checksum(&document) {
        document["checksum"] = json!(checksum);
    }
    document
}

/// Fixed open and close times: the same id must keep the same checksum.
const FIXED_TIME: &str = "2026-10-25T00:00:00Z";

#[cfg(test)]
mod tests {
    use super::*;

    fn regions() -> Value {
        json!({
            "entity": "account",
            "controlling": "region",
            "dependent": "city",
            "matrix": { "central": ["riyadh", "kharj"], "western": ["jeddah"] },
            "default": ["other"]
        })
    }

    #[test]
    fn a_dependency_needs_two_attributes_and_a_matrix() {
        let kind = DependencyKind;
        assert!(kind.validate_shape(&regions()).is_ok());
        let mut same = regions();
        same["dependent"] = json!("region");
        assert!(kind.validate_shape(&same).is_err());
        let mut empty = regions();
        empty["matrix"] = json!({});
        assert!(kind.validate_shape(&empty).is_err());
        let mut bad = regions();
        bad["matrix"] = json!({ "central": "riyadh" });
        assert!(kind.validate_shape(&bad).is_err());
    }

    #[test]
    fn publishing_compiles_one_allowed_values_rule_per_value() {
        let id = Uuid::now_v7();
        let doc = changeset_for(id, &regions(), &["eastern".to_owned()], 3);
        let ops = doc["operations"].as_array().unwrap();
        // two values, the default, one retired value.
        assert_eq!(ops.len(), 4);
        let central = &ops
            .iter()
            .find(|op| op["target"]["rule"] == rule_name(id, Some("central")).as_str())
            .unwrap()["args"]["definition"];
        assert_eq!(central["condition"]["value"], "central");
        assert_eq!(central["policies"][0]["type"], "allowed_values");
        assert_eq!(central["policies"][0]["value"], json!(["riyadh", "kharj"]));
        let retired = &ops[3]["args"]["definition"];
        assert_eq!(retired["is_active"], false);
        assert_eq!(doc["seq"], 3);
        assert_eq!(doc["scope"], scope_of(id));
        assert!(doc["checksum"].as_str().unwrap().starts_with("sha256:"));
        // The same content gives the same ledger id.
        assert_eq!(
            changeset_for(id, &regions(), &["eastern".to_owned()], 3)["id"],
            doc["id"]
        );
    }

    #[test]
    fn rule_names_are_safe_and_stable() {
        let id = Uuid::now_v7();
        let name = rule_name(id, Some("المنطقة الوسطى"));
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        );
        assert_eq!(name, rule_name(id, Some("المنطقة الوسطى")));
        assert_ne!(name, rule_name(id, Some("western")));
    }
}

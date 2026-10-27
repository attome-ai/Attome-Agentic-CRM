//! The entity settings kind (roadmap A31-T2): which platform features an
//! entity uses, set one by one or through a preset.
//!
//! ```json
//! { "entity": "<entity id>", "preset": "standard",
//!   "switches": { "offline": true, "audit_level": "full" } }
//! ```
//!
//! The switches are `activities`, `notes`, `attachments`,
//! `attribute_history`, `search`, `duplicate_detection`, `offline` and `ai`
//! (on or off) and `audit_level` (`off`, `changes` or `full`). A preset
//! (`light`, `standard`, `full`; `standard` when none is named) gives every
//! switch a value; a switch named under `switches` overrides it.
//! [`effective`] answers each switch's value and where it came from:
//! `preset` or `set_here` (a base entity's value joins once entities can
//! extend one another, A1-T4). Cooking writes that effective table, so a
//! reader never recomputes it.
//!
//! Q14-T3: `"access": { "mode": "controlled_by_parent", "lookup": "<attribute id>" }`
//! makes the entity's records follow the parent record that one of its
//! many-to-one lookups names (`attome_security::parent_access`); `"own"`, the
//! default, keeps the entity's own access.

use std::collections::BTreeMap;

use attome_types::AppError;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};

/// The kind's name.
pub const ENTITY_SETTINGS: KindName = KindName("entity_settings");

/// The on/off switches.
pub const BOOL_SWITCHES: [&str; 8] = [
    "activities",
    "notes",
    "attachments",
    "attribute_history",
    "search",
    "duplicate_detection",
    "offline",
    "ai",
];

/// The audit levels.
pub const AUDIT_LEVELS: [&str; 3] = ["off", "changes", "full"];

/// The presets, lightest first.
pub const PRESETS: [&str; 3] = ["light", "standard", "full"];

/// Q14-T3: the access modes.
pub const ACCESS_MODES: [&str; 2] = ["own", "controlled_by_parent"];

/// Q14-T3: the entity and its parent lookup attribute, from cooked entity
/// settings whose records are controlled by a parent.
pub fn parent_lookup(cooked: &Value) -> Option<(Uuid, Uuid)> {
    let access = &cooked["access"];
    (access["mode"].as_str() == Some("controlled_by_parent"))
        .then(|| Some((uuid_at(&cooked["entity"])?, uuid_at(&access["lookup"])?)))
        .flatten()
}

/// The entity settings kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct EntitySettingsKind;

/// A preset's value for every switch. Pure.
pub fn preset_values(preset: &str) -> BTreeMap<&'static str, Value> {
    let on = |names: &[&str], name: &str| names.contains(&name);
    let (enabled, audit): (&[&str], &str) = match preset {
        "light" => (&["notes", "search"], "off"),
        "full" => (&BOOL_SWITCHES, "full"),
        _ => (
            &[
                "activities",
                "notes",
                "attachments",
                "search",
                "duplicate_detection",
            ],
            "changes",
        ),
    };
    let mut out: BTreeMap<&'static str, Value> = BOOL_SWITCHES
        .iter()
        .map(|name| (*name, Value::Bool(on(enabled, name))))
        .collect();
    out.insert("audit_level", json!(audit));
    out
}

/// Every switch's effective value and its source (`preset` or
/// `set_here`). Pure.
pub fn effective(doc: &Value) -> BTreeMap<String, (Value, &'static str)> {
    let preset = doc["preset"].as_str().unwrap_or("standard");
    let mut out: BTreeMap<String, (Value, &'static str)> = preset_values(preset)
        .into_iter()
        .map(|(name, value)| (name.to_owned(), (value, "preset")))
        .collect();
    if let Some(switches) = doc["switches"].as_object() {
        for (name, value) in switches {
            if out.contains_key(name) {
                out.insert(name.clone(), (value.clone(), "set_here"));
            }
        }
    }
    out
}

fn uuid_at(value: &Value) -> Option<Uuid> {
    value.as_str().and_then(|s| Uuid::parse_str(s).ok())
}

/// Q14-T3: `access` is absent, or a known mode; a parent mode names its
/// lookup and only a parent mode does.
fn check_access(access: &Value, issues: &mut Vec<Issue>) {
    let Some(object) = access.as_object() else {
        if !access.is_null() {
            issues.push(Issue::new(
                "/access",
                "not_an_object",
                "access is an object",
            ));
        }
        return;
    };
    for key in object.keys() {
        if !matches!(key.as_str(), "mode" | "lookup") {
            issues.push(Issue::new(
                format!("/access/{key}"),
                "unknown_property",
                format!("access has no `{key}`"),
            ));
        }
    }
    let mode = access["mode"].as_str();
    if !mode.is_some_and(|m| ACCESS_MODES.contains(&m)) {
        issues.push(Issue::new(
            "/access/mode",
            "unknown_value",
            format!("access mode is one of {}", ACCESS_MODES.join(", ")),
        ));
    }
    let lookup = &access["lookup"];
    if mode == Some("controlled_by_parent") && uuid_at(lookup).is_none() {
        issues.push(Issue::new(
            "/access/lookup",
            "required",
            "controlled by parent names the lookup to the parent by attribute id",
        ));
    }
    if mode == Some("own") && !lookup.is_null() {
        issues.push(Issue::new(
            "/access/lookup",
            "unknown_property",
            "only controlled by parent names a lookup",
        ));
    }
}

impl Kind for EntitySettingsKind {
    fn name(&self) -> KindName {
        ENTITY_SETTINGS
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        let mut switches = Map::new();
        for name in BOOL_SWITCHES {
            switches.insert(name.to_owned(), json!({ "type": "boolean" }));
        }
        switches.insert("audit_level".into(), json!({ "enum": AUDIT_LEVELS }));
        json!({
            "type": "object",
            "required": ["entity"],
            "additionalProperties": false,
            "properties": {
                "entity": { "type": "string", "format": "uuid" },
                "preset": { "enum": PRESETS },
                "access": {
                    "type": "object",
                    "required": ["mode"],
                    "additionalProperties": false,
                    "properties": {
                        "mode": { "enum": ACCESS_MODES },
                        "lookup": { "type": "string", "format": "uuid" }
                    }
                },
                "switches": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": switches
                }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let mut issues = Vec::new();
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "entity settings are a JSON object",
            )]);
        };
        for key in object.keys() {
            if !matches!(key.as_str(), "entity" | "preset" | "switches" | "access") {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("entity settings have no `{key}`"),
                ));
            }
        }
        if uuid_at(&doc["entity"]).is_none() {
            issues.push(Issue::new(
                "/entity",
                "required",
                "entity settings name their entity by id",
            ));
        }
        if !doc["preset"].is_null() && !doc["preset"].as_str().is_some_and(|p| PRESETS.contains(&p))
        {
            issues.push(Issue::new(
                "/preset",
                "unknown_value",
                format!("preset is one of {}", PRESETS.join(", ")),
            ));
        }
        check_access(&doc["access"], &mut issues);
        match &doc["switches"] {
            Value::Null => {}
            Value::Object(switches) => {
                for (name, value) in switches {
                    let ok = if name == "audit_level" {
                        value.as_str().is_some_and(|v| AUDIT_LEVELS.contains(&v))
                    } else if BOOL_SWITCHES.contains(&name.as_str()) {
                        value.is_boolean()
                    } else {
                        issues.push(Issue::new(
                            format!("/switches/{name}"),
                            "unknown_property",
                            format!("there is no switch `{name}`"),
                        ));
                        continue;
                    };
                    if !ok {
                        issues.push(Issue::new(
                            format!("/switches/{name}"),
                            "wrong_type",
                            if name == "audit_level" {
                                format!("audit_level is one of {}", AUDIT_LEVELS.join(", "))
                            } else {
                                format!("{name} is true or false")
                            },
                        ));
                    }
                }
            }
            _ => issues.push(Issue::new(
                "/switches",
                "not_an_object",
                "switches are an object",
            )),
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, doc: &Value) -> Vec<Reference> {
        let entity = uuid_at(&doc["entity"]).map(|entity| Reference {
            target: ObjectRef {
                kind: crate::kinds::form::ENTITY,
                id: ObjectId(entity),
            },
            mode: RefMode::Reads,
        });
        let lookup = uuid_at(&doc["access"]["lookup"]).map(|lookup| Reference {
            target: ObjectRef {
                kind: crate::kinds::form::ATTRIBUTE,
                id: ObjectId(lookup),
            },
            mode: RefMode::Reads,
        });
        entity.into_iter().chain(lookup).collect()
    }

    /// Q14-T3: the parent lookup is a lookup attribute (that it belongs to
    /// this entity is checked when the version is loaded, against the
    /// entity's attributes).
    fn check(&self, doc: &Value, ctx: &dyn ValidationCtx) -> Vec<Issue> {
        let Some(lookup) = uuid_at(&doc["access"]["lookup"]) else {
            return Vec::new();
        };
        match ctx.attribute_type(&ObjectRef {
            kind: crate::kinds::form::ATTRIBUTE,
            id: ObjectId(lookup),
        }) {
            Some(field_type) if field_type != "lookup" => vec![Issue::new(
                "/access/lookup",
                "not_a_lookup",
                "a parent is named by one of the entity's many-to-one lookups",
            )],
            _ => Vec::new(),
        }
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let switches: Map<String, Value> = effective(&input.doc)
                    .into_iter()
                    .map(|(name, (value, source))| {
                        (name, json!({ "value": value, "source": source }))
                    })
                    .collect();
                let mut plan = json!({
                    "id": input.id.to_string(),
                    "name": input.name,
                    "entity": input.doc["entity"],
                    "preset": input.doc["preset"].as_str().unwrap_or("standard"),
                    "switches": switches,
                });
                // Q14-T3: only a parent mode is cooked, so settings without
                // one keep their artefact.
                if input.doc["access"]["mode"].as_str() == Some("controlled_by_parent") {
                    plan["access"] = json!({
                        "mode": "controlled_by_parent",
                        "lookup": input.doc["access"]["lookup"],
                    });
                }
                let text = crate::canonical::canonicalize(&plan).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: ENTITY_SETTINGS,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Choose which platform features an entity uses: activities, notes, attachments, attribute history, audit level, search, duplicate detection, offline and AI, through a preset (light, standard, full) and per-switch overrides."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_settings_presets_and_overrides_report_their_source() {
        let doc = json!({
            "entity": Uuid::now_v7().to_string(),
            "preset": "light",
            "switches": { "offline": true, "audit_level": "full" }
        });
        assert!(EntitySettingsKind.validate_shape(&doc).is_ok());
        let e = effective(&doc);
        assert_eq!(e["notes"], (json!(true), "preset"));
        assert_eq!(e["activities"], (json!(false), "preset"));
        assert_eq!(e["offline"], (json!(true), "set_here"));
        assert_eq!(e["audit_level"], (json!("full"), "set_here"));
        let standard = effective(&json!({ "entity": Uuid::now_v7().to_string() }));
        assert_eq!(standard["audit_level"], (json!("changes"), "preset"));
        assert_eq!(standard["duplicate_detection"].0, json!(true));
        assert!(preset_values("full").values().all(|v| v != &json!(false)));
    }

    /// Q14-T3: a parent mode names a lookup attribute, is cooked, and is
    /// read back; a non-lookup attribute is refused at save.
    #[test]
    fn controlled_by_parent_settings_name_a_lookup() {
        let (entity, lookup) = (Uuid::now_v7(), Uuid::now_v7());
        let doc = json!({
            "entity": entity.to_string(),
            "access": { "mode": "controlled_by_parent", "lookup": lookup.to_string() }
        });
        assert!(EntitySettingsKind.validate_shape(&doc).is_ok());
        let refs = EntitySettingsKind.references(&doc);
        assert!(
            refs.iter()
                .any(|r| r.target.id.0 == lookup && r.target.kind == crate::kinds::form::ATTRIBUTE)
        );

        let cooked = EntitySettingsKind
            .cook(&[CookInput {
                id: ObjectId(Uuid::now_v7()),
                name: "contact".into(),
                doc: doc.clone(),
            }])
            .unwrap();
        let plan: Value = serde_json::from_slice(&cooked[0].payload).unwrap();
        assert_eq!(parent_lookup(&plan), Some((entity, lookup)));

        struct Text;
        impl ValidationCtx for Text {
            fn exists(&self, _target: &ObjectRef) -> bool {
                true
            }
            fn attribute_type(&self, _attribute: &ObjectRef) -> Option<String> {
                Some("text".into())
            }
        }
        let issues = EntitySettingsKind.check(&doc, &Text);
        assert_eq!(issues[0].code, "not_a_lookup");

        for bad in [
            json!({ "mode": "controlled_by_parent" }),
            json!({ "mode": "inherit" }),
            json!({ "mode": "own", "lookup": lookup.to_string() }),
        ] {
            let doc = json!({ "entity": entity.to_string(), "access": bad });
            assert!(EntitySettingsKind.validate_shape(&doc).is_err(), "{doc}");
        }
        let own = json!({ "entity": entity.to_string(), "access": { "mode": "own" } });
        assert!(EntitySettingsKind.validate_shape(&own).is_ok());
        let plain = EntitySettingsKind
            .cook(&[CookInput {
                id: ObjectId(Uuid::now_v7()),
                name: "contact".into(),
                doc: own,
            }])
            .unwrap();
        let plan: Value = serde_json::from_slice(&plain[0].payload).unwrap();
        assert!(plan.get("access").is_none(), "own access is not cooked");
        assert_eq!(parent_lookup(&plan), None);
    }

    #[test]
    fn entity_settings_shape_problems_are_named() {
        let issues = EntitySettingsKind
            .validate_shape(&json!({
                "entity": "x", "preset": "huge",
                "switches": { "offline": "yes", "teleport": true, "audit_level": "some" }
            }))
            .unwrap_err();
        let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        for expected in [
            "/entity",
            "/preset",
            "/switches/offline",
            "/switches/teleport",
            "/switches/audit_level",
        ] {
            assert!(paths.contains(&expected), "{expected} in {paths:?}");
        }
    }
}

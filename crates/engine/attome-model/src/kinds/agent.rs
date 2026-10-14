//! The agent kind (roadmap N9-T1): an agent defined as validated metadata.
//!
//! ```json
//! { "role": "Support triage",
//!   "instructions": "Read the case and propose a queue ...",
//!   "tools": ["records.read", "model.form.edit"],
//!   "knowledge": ["kb:returns-policy"],
//!   "identity": { "run_as": "caller" },
//!   "limits": { "max_steps": 20, "max_tool_calls": 40, "max_tokens": 60000 },
//!   "triggers": [{ "kind": "record_change", "entity": "<entity id>" }],
//!   "channels": ["chat", "web"],
//!   "persona": { "model": "<ai_model id>", "language": "ar", "temperature": 0.2 } }
//! ```
//!
//! `limits.daily` optionally caps what the agent does per day across all its
//! sessions, by limit class (`record_changes`, `deletes`, `messages`,
//! `external_calls`, V2-D487); `persona` is the optional model and voice
//! configuration that v1 kept on `ai_agent`.
//!
//! Checked on every edit: the tools are action ids the AI engine knows (the
//! engine hands its list over at boot through [`set_known_tools`]; without
//! one the existence check is skipped, never guessed), the limits are within
//! the platform ceilings below, and each trigger's entity is a reference that
//! must exist at publish. An agent never writes on its own authority: its
//! write tools still pass the action gate's confirmation and approval rules
//! (N30) at run time. Cooking writes the definition with its id and name for
//! the agent runtime.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::identity::{KindName, ObjectId, ObjectRef};
use crate::kind::{Artefact, CookInput, Issue, Kind, RefMode, Reference, ValidationCtx};
use crate::kinds::form::ENTITY;

/// The kind's name.
pub const AGENT: KindName = KindName("agent");

/// The platform ceilings an agent's own limits must stay within.
pub const MAX_STEPS_CEILING: u64 = 100;
pub const MAX_TOOL_CALLS_CEILING: u64 = 500;
pub const MAX_TOKENS_CEILING: u64 = 1_000_000;
/// Most tools one agent may hold.
pub const MAX_TOOLS: usize = 64;
/// The ceiling on any one daily limit.
pub const MAX_DAILY_CEILING: u64 = 1_000_000;
/// The daily limit classes (V2-D487).
pub const DAILY_CLASSES: [&str; 4] = ["record_changes", "deletes", "messages", "external_calls"];

const RUN_AS: [&str; 2] = ["caller", "service"];
const TRIGGER_KINDS: [&str; 3] = ["manual", "record_change", "schedule"];
const CHANNELS: [&str; 5] = ["chat", "web", "whatsapp", "sms", "email"];
const PROPERTIES: [&str; 9] = [
    "role",
    "instructions",
    "tools",
    "knowledge",
    "identity",
    "limits",
    "triggers",
    "channels",
    "persona",
];

static KNOWN_TOOLS: OnceLock<BTreeSet<String>> = OnceLock::new();

/// Hands the AI engine's action ids to the agent kind, once per process.
/// Later calls are ignored.
pub fn set_known_tools(tools: impl IntoIterator<Item = String>) {
    let _ = KNOWN_TOOLS.set(tools.into_iter().collect());
}

/// The agent kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentKind;

fn text(doc: &Value, key: &str) -> Option<String> {
    doc[key]
        .as_str()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

fn trigger_entity(trigger: &Value) -> Option<Uuid> {
    trigger["entity"]
        .as_str()
        .and_then(|t| Uuid::parse_str(t).ok())
}

impl Kind for AgentKind {
    fn name(&self) -> KindName {
        AGENT
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["role", "instructions", "tools", "limits"],
            "additionalProperties": false,
            "properties": {
                "role": { "type": "string", "minLength": 1, "maxLength": 200 },
                "instructions": { "type": "string", "minLength": 1, "maxLength": 20000 },
                "tools": { "type": "array", "maxItems": MAX_TOOLS, "items": { "type": "string" } },
                "knowledge": { "type": "array", "items": { "type": "string" } },
                "identity": {
                    "type": "object",
                    "properties": { "run_as": { "enum": RUN_AS } }
                },
                "limits": {
                    "type": "object",
                    "required": ["max_steps", "max_tool_calls", "max_tokens"],
                    "properties": {
                        "max_steps": { "type": "integer", "minimum": 1, "maximum": MAX_STEPS_CEILING },
                        "max_tool_calls": { "type": "integer", "minimum": 1, "maximum": MAX_TOOL_CALLS_CEILING },
                        "max_tokens": { "type": "integer", "minimum": 1, "maximum": MAX_TOKENS_CEILING },
                        "daily": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "record_changes": { "type": "integer", "minimum": 0, "maximum": MAX_DAILY_CEILING },
                                "deletes": { "type": "integer", "minimum": 0, "maximum": MAX_DAILY_CEILING },
                                "messages": { "type": "integer", "minimum": 0, "maximum": MAX_DAILY_CEILING },
                                "external_calls": { "type": "integer", "minimum": 0, "maximum": MAX_DAILY_CEILING }
                            }
                        }
                    }
                },
                "persona": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "model": { "type": "string", "format": "uuid" },
                        "language": { "type": "string", "minLength": 2, "maxLength": 16 },
                        "temperature": { "type": "number", "minimum": 0, "maximum": 2 }
                    }
                },
                "triggers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["kind"],
                        "properties": {
                            "kind": { "enum": TRIGGER_KINDS },
                            "entity": { "type": "string", "format": "uuid" },
                            "cron": { "type": "string" }
                        }
                    }
                },
                "channels": { "type": "array", "items": { "enum": CHANNELS } }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        let Some(object) = doc.as_object() else {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "an agent is a JSON object",
            )]);
        };
        let mut issues = Vec::new();
        for key in object.keys() {
            if !PROPERTIES.contains(&key.as_str()) {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "unknown_property",
                    format!("an agent has no `{key}`"),
                ));
            }
        }
        for key in ["role", "instructions"] {
            if text(doc, key).is_none() {
                issues.push(Issue::new(
                    format!("/{key}"),
                    "required",
                    format!("an agent has a {key}"),
                ));
            }
        }
        match doc["tools"].as_array() {
            None => issues.push(Issue::new(
                "/tools",
                "required",
                "an agent has a list of tools (it may be empty)",
            )),
            Some(tools) => {
                if tools.len() > MAX_TOOLS {
                    issues.push(Issue::new(
                        "/tools",
                        "limit_exceeded",
                        format!("an agent holds at most {MAX_TOOLS} tools"),
                    ));
                }
                let mut seen = BTreeSet::new();
                for (i, tool) in tools.iter().enumerate() {
                    match tool.as_str() {
                        None => issues.push(Issue::new(
                            format!("/tools/{i}"),
                            "not_a_tool",
                            "a tool is an action id",
                        )),
                        Some(id) if !seen.insert(id) => issues.push(Issue::new(
                            format!("/tools/{i}"),
                            "duplicate_tool",
                            format!("`{id}` is already listed"),
                        )),
                        Some(_) => {}
                    }
                }
            }
        }
        let limits = &doc["limits"];
        if !limits.is_object() {
            issues.push(Issue::new(
                "/limits",
                "required",
                "an agent has limits: max_steps, max_tool_calls and max_tokens",
            ));
        } else {
            for (key, ceiling) in [
                ("max_steps", MAX_STEPS_CEILING),
                ("max_tool_calls", MAX_TOOL_CALLS_CEILING),
                ("max_tokens", MAX_TOKENS_CEILING),
            ] {
                match limits[key].as_u64() {
                    Some(value) if (1..=ceiling).contains(&value) => {}
                    Some(value) => issues.push(Issue::new(
                        format!("/limits/{key}"),
                        "limit_exceeded",
                        format!("{key} is {value}; it must be from 1 to {ceiling}"),
                    )),
                    None => issues.push(Issue::new(
                        format!("/limits/{key}"),
                        "required",
                        format!("{key} is a whole number from 1 to {ceiling}"),
                    )),
                }
            }
        }
        if let Some(daily) = limits.get("daily") {
            match daily.as_object() {
                None => issues.push(Issue::new(
                    "/limits/daily",
                    "invalid",
                    "daily limits are an object of whole numbers",
                )),
                Some(daily) => {
                    for (key, value) in daily {
                        if !DAILY_CLASSES.contains(&key.as_str()) {
                            issues.push(Issue::new(
                                format!("/limits/daily/{key}"),
                                "unknown_property",
                                format!("a daily limit is one of {}", DAILY_CLASSES.join(", ")),
                            ));
                        } else if !value.as_u64().is_some_and(|v| v <= MAX_DAILY_CEILING) {
                            issues.push(Issue::new(
                                format!("/limits/daily/{key}"),
                                "limit_exceeded",
                                format!("{key} is a whole number from 0 to {MAX_DAILY_CEILING}"),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(persona) = doc.get("persona") {
            match persona.as_object() {
                None => issues.push(Issue::new("/persona", "invalid", "a persona is an object")),
                Some(persona) => {
                    for (key, value) in persona {
                        let ok = match key.as_str() {
                            "model" => value.as_str().is_some_and(|v| Uuid::parse_str(v).is_ok()),
                            "language" => {
                                value.as_str().is_some_and(|v| (2..=16).contains(&v.len()))
                            }
                            "temperature" => {
                                value.as_f64().is_some_and(|v| (0.0..=2.0).contains(&v))
                            }
                            _ => {
                                issues.push(Issue::new(
                                    format!("/persona/{key}"),
                                    "unknown_property",
                                    format!("a persona has no `{key}`"),
                                ));
                                continue;
                            }
                        };
                        if !ok {
                            issues.push(Issue::new(
                                format!("/persona/{key}"),
                                "invalid",
                                format!("`{key}` is not valid here"),
                            ));
                        }
                    }
                }
            }
        }
        if let Some(run_as) = doc["identity"].get("run_as")
            && !run_as.as_str().is_some_and(|r| RUN_AS.contains(&r))
        {
            issues.push(Issue::new(
                "/identity/run_as",
                "invalid",
                "run_as is `caller` or `service`",
            ));
        }
        for (i, trigger) in doc["triggers"].as_array().into_iter().flatten().enumerate() {
            match trigger["kind"].as_str() {
                Some("record_change") if trigger_entity(trigger).is_none() => {
                    issues.push(Issue::new(
                        format!("/triggers/{i}/entity"),
                        "required",
                        "a record_change trigger names its entity by id",
                    ));
                }
                Some("schedule") if text(trigger, "cron").is_none() => issues.push(Issue::new(
                    format!("/triggers/{i}/cron"),
                    "required",
                    "a schedule trigger has a cron expression",
                )),
                Some(kind) if TRIGGER_KINDS.contains(&kind) => {}
                _ => issues.push(Issue::new(
                    format!("/triggers/{i}/kind"),
                    "invalid",
                    "a trigger is manual, record_change or schedule",
                )),
            }
        }
        for (i, channel) in doc["channels"].as_array().into_iter().flatten().enumerate() {
            if !channel.as_str().is_some_and(|c| CHANNELS.contains(&c)) {
                issues.push(Issue::new(
                    format!("/channels/{i}"),
                    "invalid",
                    format!("a channel is one of {}", CHANNELS.join(", ")),
                ));
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues)
        }
    }

    fn references(&self, doc: &Value) -> Vec<Reference> {
        doc["triggers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(trigger_entity)
            .map(|entity| Reference {
                target: ObjectRef {
                    kind: ENTITY,
                    id: ObjectId(entity),
                },
                mode: RefMode::Triggers,
            })
            .collect()
    }

    fn check(&self, doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        let Some(known) = KNOWN_TOOLS.get() else {
            return Vec::new();
        };
        doc["tools"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(|(i, tool)| {
                let id = tool.as_str()?;
                (!known.contains(id)).then(|| {
                    Issue::new(
                        format!("/tools/{i}"),
                        "unknown_tool",
                        format!("no action `{id}` exists"),
                    )
                })
            })
            .collect()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        docs.iter()
            .map(|input| {
                let mut definition = input.doc.clone();
                if let Some(object) = definition.as_object_mut() {
                    object.insert("id".into(), json!(input.id.to_string()));
                    object.insert("name".into(), json!(input.name));
                }
                let text =
                    crate::canonical::canonicalize(&definition).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: AGENT,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Edit an agent: its role, instructions, tools, knowledge, identity, limits, triggers and channels."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Value {
        json!({
            "role": "Triage",
            "instructions": "Route new cases.",
            "tools": ["records.read"],
            "limits": { "max_steps": 10, "max_tool_calls": 20, "max_tokens": 5000 },
            "triggers": [{ "kind": "record_change", "entity": Uuid::now_v7().to_string() }],
            "channels": ["chat"]
        })
    }

    #[test]
    fn a_well_formed_agent_validates_and_references_its_trigger_entity() {
        let doc = agent();
        assert!(AgentKind.validate_shape(&doc).is_ok());
        let refs = AgentKind.references(&doc);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].target.kind, ENTITY);
        assert_eq!(refs[0].mode, RefMode::Triggers);
    }

    #[test]
    fn limits_above_the_ceiling_and_bad_fields_are_named() {
        let mut doc = agent();
        doc["limits"]["max_steps"] = json!(MAX_STEPS_CEILING + 1);
        doc["tools"] = json!(["a.b", "a.b"]);
        doc["channels"] = json!(["fax"]);
        doc["triggers"] = json!([{ "kind": "schedule" }]);
        doc["identity"] = json!({ "run_as": "root" });
        doc["extra"] = json!(1);
        let issues = AgentKind.validate_shape(&doc).unwrap_err();
        let codes: Vec<(&str, &str)> = issues.iter().map(|i| (i.path.as_str(), i.code)).collect();
        assert!(codes.contains(&("/limits/max_steps", "limit_exceeded")));
        assert!(codes.contains(&("/tools/1", "duplicate_tool")));
        assert!(codes.contains(&("/channels/0", "invalid")));
        assert!(codes.contains(&("/triggers/0/cron", "required")));
        assert!(codes.contains(&("/identity/run_as", "invalid")));
        assert!(codes.contains(&("/extra", "unknown_property")));
    }

    #[test]
    fn unknown_tools_are_reported_once_the_engine_lists_its_tools() {
        struct AllExist;
        impl ValidationCtx for AllExist {
            fn exists(&self, _target: &ObjectRef) -> bool {
                true
            }
        }
        set_known_tools(["records.read".to_owned()]);
        let mut doc = agent();
        doc["tools"] = json!(["records.read", "no.such_tool"]);
        let issues = AgentKind.check(&doc, &AllExist);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].code, "unknown_tool");
        assert_eq!(issues[0].path, "/tools/1");
    }

    #[test]
    fn daily_limits_and_persona_are_checked() {
        let mut doc = agent();
        doc["limits"]["daily"] = json!({ "deletes": 5, "record_changes": 100 });
        doc["persona"] =
            json!({ "model": Uuid::now_v7().to_string(), "language": "ar", "temperature": 0.3 });
        assert!(AgentKind.validate_shape(&doc).is_ok());

        doc["limits"]["daily"] = json!({ "deletes": -1, "naps": 2 });
        doc["persona"] = json!({ "model": "x", "temperature": 9, "mood": "calm" });
        let issues = AgentKind.validate_shape(&doc).unwrap_err();
        let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        for path in [
            "/limits/daily/deletes",
            "/limits/daily/naps",
            "/persona/model",
            "/persona/temperature",
            "/persona/mood",
        ] {
            assert!(paths.contains(&path), "{path} in {paths:?}");
        }
    }

    #[test]
    fn cooking_carries_the_id_and_name_and_is_stable() {
        let input = CookInput {
            id: ObjectId::new(),
            name: "triage".into(),
            doc: agent(),
        };
        let one = AgentKind.cook(std::slice::from_ref(&input)).unwrap();
        let two = AgentKind.cook(std::slice::from_ref(&input)).unwrap();
        assert_eq!(one, two);
        let cooked: Value = serde_json::from_slice(&one[0].payload).unwrap();
        assert_eq!(cooked["name"], "triage");
        assert_eq!(cooked["id"], input.id.to_string());
    }
}

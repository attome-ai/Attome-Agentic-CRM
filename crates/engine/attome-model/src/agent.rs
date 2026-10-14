//! Agent tools from the kind registry (roadmap Y1-T14): one edit tool per
//! kind, `model.<kind>.edit`, described by the kind and taking the same edit
//! commands people send, so an agent edits metadata exactly as the admin API
//! does and under the same permission check.

use serde::Serialize;
use serde_json::{Value, json};

use crate::KindRegistry;

/// One generated tool.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema of the tool's input: the object id, the base hash and
    /// the edit commands.
    pub input_schema: Value,
}

/// The JSON Schema of one edit command (`add`, `remove`, `move`, `set`).
pub fn command_schema() -> Value {
    json!({
        "oneOf": [
            { "type": "object", "required": ["op", "path", "value"],
              "properties": { "op": { "const": "add" }, "path": { "type": "string" }, "value": {} } },
            { "type": "object", "required": ["op", "path"],
              "properties": { "op": { "const": "remove" }, "path": { "type": "string" } } },
            { "type": "object", "required": ["op", "from", "to"],
              "properties": { "op": { "const": "move" }, "from": { "type": "string" }, "to": { "type": "string" } } },
            { "type": "object", "required": ["op", "path", "value"],
              "properties": { "op": { "const": "set" }, "path": { "type": "string" }, "value": {} } }
        ]
    })
}

/// One edit tool per kind that is stored in the model (adapter kinds are
/// edited through their own APIs and get none).
pub fn tool_specs(registry: &KindRegistry) -> Vec<ToolSpec> {
    registry
        .iter()
        .filter(|kind| kind.adapter_table().is_none())
        .map(|kind| ToolSpec {
            name: format!("model.{}.edit", kind.name()),
            description: kind.agent_tool_description().to_owned(),
            input_schema: json!({
                "type": "object",
                "required": ["id", "base_hash", "commands"],
                "properties": {
                    "id": { "type": "string", "format": "uuid" },
                    "base_hash": { "type": "string", "description": "the content hash the edit is based on; empty for a new object" },
                    "name": { "type": "string", "description": "required for a new object" },
                    "commands": { "type": "array", "items": command_schema() },
                    "document_schema": kind.json_schema()
                }
            }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn one_tool_per_kind() {
        let mut registry = KindRegistry::default();
        registry.register(Arc::new(crate::kinds::FormKind)).unwrap();
        registry
            .register(Arc::new(crate::kind::tests::TestKind("note")))
            .unwrap();
        let tools = tool_specs(&registry);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["model.form.edit", "model.note.edit"]);
        assert!(tools[0].description.contains("form"));
    }
}

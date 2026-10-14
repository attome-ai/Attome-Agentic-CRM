//! The entity and attribute adapter kinds (roadmap Y1-T13): the metadata
//! model sees entities and attributes through their existing tables
//! (`entity_info`, `attribute_info`), which stay the source of truth. Writes
//! go through this crate's provisioning, never through the model's store, so
//! these kinds only answer "does it exist" (via [`Kind::adapter_table`]) and
//! describe themselves; they have no document shape of their own to edit.

use attome_model::kinds::{ATTRIBUTE, ENTITY};
use attome_model::{Artefact, CookInput, Issue, Kind, KindName, Reference, ValidationCtx};
use attome_types::AppError;
use serde_json::{Value, json};

/// An adapter over one typed table.
#[derive(Debug, Clone, Copy)]
pub struct AdapterKind {
    name: KindName,
    table: &'static str,
    description: &'static str,
}

/// Entities, over `entity_info`.
pub const ENTITY_KIND: AdapterKind = AdapterKind {
    name: ENTITY,
    table: "entity_info",
    description: "An entity: a table of records. Create and change entities through the schema API.",
};

/// Attributes, over `attribute_info`.
pub const ATTRIBUTE_KIND: AdapterKind = AdapterKind {
    name: ATTRIBUTE,
    table: "attribute_info",
    description: "An attribute: one field of an entity. Create and change attributes through the schema API.",
};

impl Kind for AdapterKind {
    fn name(&self) -> KindName {
        self.name
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({ "type": "object", "description": self.description })
    }

    fn validate_shape(&self, _doc: &Value) -> Result<(), Vec<Issue>> {
        Err(vec![Issue::new(
            "",
            "adapter_kind",
            format!(
                "{} objects are edited through the schema API, not the model store",
                self.name
            ),
        )])
    }

    fn references(&self, _doc: &Value) -> Vec<Reference> {
        Vec::new()
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, _docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        // The entity registry is still built from its tables directly; the
        // entity kind's own artefact joins in a later step of Y1-T13.
        Ok(Vec::new())
    }

    fn agent_tool_description(&self) -> &'static str {
        self.description
    }

    fn adapter_table(&self) -> Option<&'static str> {
        Some(self.table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_kinds_point_at_their_tables_and_refuse_store_edits() {
        assert_eq!(ENTITY_KIND.adapter_table(), Some("entity_info"));
        assert_eq!(ATTRIBUTE_KIND.adapter_table(), Some("attribute_info"));
        assert!(ENTITY_KIND.validate_shape(&json!({})).is_err());
    }
}

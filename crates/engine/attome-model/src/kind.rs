//! The [`Kind`] trait: everything the model needs to know about one kind of
//! metadata object (a form, an entity, a rule, ...). Each kind is defined by
//! the engine that owns it and registered into the [`crate::KindRegistry`];
//! this crate holds no engine-specific kinds.

use attome_types::AppError;
use serde_json::Value;

use crate::identity::{KindName, ObjectId, ObjectRef};

/// One problem found while validating a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// A JSON pointer into the document (`/sections/0/label`), or `""`.
    pub path: String,
    /// A stable machine code (`required`, `unknown_reference`, ...).
    pub code: &'static str,
    pub message: String,
}

impl Issue {
    pub fn new(path: impl Into<String>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code,
            message: message.into(),
        }
    }
}

/// How a document uses another object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefMode {
    /// It reads the target (a form showing an entity's fields).
    Reads,
    /// It writes the target (a flow updating records).
    Writes,
    /// It runs when the target changes (a rule on an entity).
    Triggers,
}

/// One outgoing reference of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference {
    pub target: ObjectRef,
    pub mode: RefMode,
}

/// What a kind's whole-version check can look at: whether an object exists.
pub trait ValidationCtx {
    /// Whether `target` exists (in the version being checked).
    fn exists(&self, target: &ObjectRef) -> bool;

    /// B8-T1: an attribute's field type (`text`, `number`, `lookup`, ...),
    /// when the context knows it; `None` skips type checks.
    fn attribute_type(&self, _attribute: &ObjectRef) -> Option<String> {
        None
    }
}

/// One object handed to the cooker.
#[derive(Debug, Clone)]
pub struct CookInput {
    pub id: ObjectId,
    pub name: String,
    pub doc: Value,
}

/// One cooked artefact, addressed by the hash of its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artefact {
    pub kind: KindName,
    /// The object it was cooked from, when it is one object's artefact.
    pub source: Option<ObjectId>,
    pub payload: Vec<u8>,
}

/// Size and count limits for a kind, checked at save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindLimits {
    /// Largest document, in bytes of canonical JSON.
    pub max_doc_bytes: usize,
    /// Most objects of this kind in one deployment.
    pub max_objects: usize,
}

impl Default for KindLimits {
    fn default() -> Self {
        Self {
            max_doc_bytes: 256 * 1024,
            max_objects: 10_000,
        }
    }
}

/// A kind of metadata object.
pub trait Kind: Send + Sync + 'static {
    /// The kind's stable name.
    fn name(&self) -> KindName;

    /// The version of the document shape this code writes.
    fn schema_version(&self) -> u32;

    /// The JSON Schema of the document, for editors and agents.
    fn json_schema(&self) -> Value;

    /// Step one of validation, on every edit: the document's own shape.
    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>>;

    /// The objects the document refers to, extracted on save.
    fn references(&self, doc: &Value) -> Vec<Reference>;

    /// Step two, on save: kind-specific checks that may look at other objects.
    fn check(&self, doc: &Value, ctx: &dyn ValidationCtx) -> Vec<Issue>;

    /// Turns the published documents of this kind into runtime artefacts.
    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError>;

    /// Size and count limits.
    fn limits(&self) -> KindLimits {
        KindLimits::default()
    }

    /// Upgrades a document written with an older `schema_version`.
    fn upgrade(&self, from_version: u32, doc: Value) -> Result<Value, AppError> {
        if from_version == self.schema_version() {
            Ok(doc)
        } else {
            Err(AppError::Validation(format!(
                "{} documents of schema version {from_version} cannot be upgraded",
                self.name()
            )))
        }
    }

    /// One line an agent tool built from this kind uses to describe it.
    fn agent_tool_description(&self) -> &'static str;

    /// For an adapter kind (entity, attribute, rule, ... over its existing
    /// table), that table, where an object's `id` column is its id. `None`
    /// for a kind stored in the metadata object store.
    fn adapter_table(&self) -> Option<&'static str> {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::KindRegistry;
    use std::sync::Arc;

    /// A minimal kind for registry tests.
    pub(crate) struct TestKind(pub &'static str);

    impl Kind for TestKind {
        fn name(&self) -> KindName {
            KindName(self.0)
        }
        fn schema_version(&self) -> u32 {
            1
        }
        fn json_schema(&self) -> Value {
            serde_json::json!({ "type": "object" })
        }
        fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
            if doc.is_object() {
                Ok(())
            } else {
                Err(vec![Issue::new(
                    "",
                    "not_an_object",
                    "a document is an object",
                )])
            }
        }
        fn references(&self, _doc: &Value) -> Vec<Reference> {
            Vec::new()
        }
        fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
            Vec::new()
        }
        fn cook(&self, _docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
            Ok(Vec::new())
        }
        fn agent_tool_description(&self) -> &'static str {
            "a test kind"
        }
    }

    #[test]
    fn duplicate_kind_name_is_rejected() {
        let mut registry = KindRegistry::default();
        assert!(registry.register(Arc::new(TestKind("form"))).is_ok());
        assert!(registry.register(Arc::new(TestKind("form"))).is_err());
        assert!(registry.get("form").is_some());
        assert!(registry.get("flow").is_none());
    }

    #[test]
    fn registry_iterates_in_name_order() {
        let mut registry = KindRegistry::default();
        for name in ["view", "entity", "form"] {
            registry.register(Arc::new(TestKind(name))).unwrap();
        }
        let names: Vec<&str> = registry.iter().map(|kind| kind.name().as_str()).collect();
        assert_eq!(names, ["entity", "form", "view"]);
    }

    #[test]
    fn the_default_upgrade_only_accepts_the_current_version() {
        let kind = TestKind("form");
        let doc = serde_json::json!({});
        assert!(kind.upgrade(1, doc.clone()).is_ok());
        assert!(kind.upgrade(0, doc).is_err());
    }
}

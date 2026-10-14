//! `attome-model`: the metadata model (roadmap Y1).
//!
//! Every kind of metadata object (forms first; entities, attributes, rules,
//! state models and relationships as adapter kinds over their existing
//! tables) is described by one [`Kind`] and registered in one
//! [`KindRegistry`]. Objects live in one versioned store
//! (`metadata_object`, `metadata_object_version`), are validated in three
//! steps (shape on every edit, references and kind checks on save, the whole
//! version at publish) and are cooked into content-hashed artefacts
//! (`metadata_artefact`) that the runtime serves from memory.
//!
//! This crate holds the model only: engine-specific kinds register from the
//! engine that owns them, and HTTP routes live in `attome-api`.

pub mod identity;
pub mod kind;

use std::collections::BTreeMap;
use std::sync::Arc;

pub use identity::{KindName, Layer, ObjectId, ObjectRef};
pub use kind::{Artefact, CookInput, Issue, Kind, KindLimits, RefMode, Reference, ValidationCtx};

/// Every registered kind, by name.
#[derive(Default, Clone)]
pub struct KindRegistry {
    kinds: BTreeMap<&'static str, Arc<dyn Kind>>,
}

impl std::fmt::Debug for KindRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.kinds.keys()).finish()
    }
}

impl KindRegistry {
    /// Adds a kind; a second kind with the same name is refused.
    pub fn register(&mut self, kind: Arc<dyn Kind>) -> Result<(), String> {
        let name = kind.name().as_str();
        if self.kinds.contains_key(name) {
            return Err(format!("the metadata kind `{name}` is already registered"));
        }
        self.kinds.insert(name, kind);
        Ok(())
    }

    /// The kind with this name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Kind>> {
        self.kinds.get(name)
    }

    /// Every kind, in name order.
    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn Kind>> {
        self.kinds.values()
    }

    /// How many kinds are registered.
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Whether no kind is registered.
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }
}

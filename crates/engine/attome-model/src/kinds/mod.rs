//! Kinds this crate owns. Engine-specific kinds (entity and attribute
//! adapters, rules, flows, ...) live in the engine that owns them.

pub mod form;

pub use form::{ATTRIBUTE, ENTITY, FORM, FormKind};

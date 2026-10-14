//! Identity types for metadata objects.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A metadata object's id (UUIDv7), stable across its versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub Uuid);

impl ObjectId {
    /// A fresh, time-ordered id.
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ObjectId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A kind's name, such as `form` or `entity`: lowercase, stable, and the
/// value stored in `metadata_object.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KindName(pub &'static str);

impl KindName {
    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for KindName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Who owns an object: the platform, an installed app (pack), or the
/// customer. Stored as `metadata_object.owner_layer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Platform,
    App,
    Customer,
}

impl Layer {
    /// The stored value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::App => "app",
            Self::Customer => "customer",
        }
    }
}

/// A reference to one object of one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectRef {
    pub kind: KindName,
    pub id: ObjectId,
}

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

    /// Y11-T1: the layer an `owner_layer` column value names. The changeset
    /// ledger stores four names (migration 0520's CHECK); `product` is an
    /// app's and `project` work belongs to the customer.
    pub fn from_stored(stored: &str) -> Option<Self> {
        match stored {
            "platform" => Some(Self::Platform),
            "product" | "app" => Some(Self::App),
            "project" | "customer" => Some(Self::Customer),
            _ => None,
        }
    }

    /// Y11-T1: the value a new `owner_layer` row stores, inside 0520's CHECK.
    pub fn as_stored(self) -> &'static str {
        match self {
            Self::Platform => "platform",
            Self::App => "product",
            Self::Customer => "customer",
        }
    }
}

#[cfg(test)]
mod layer_tests {
    use super::Layer;

    #[test]
    fn project_maps_to_customer() {
        assert_eq!(Layer::from_stored("project"), Some(Layer::Customer));
        assert_eq!(Layer::from_stored("customer"), Some(Layer::Customer));
        assert_eq!(Layer::Customer.as_stored(), "customer");
    }

    #[test]
    fn product_maps_to_app() {
        assert_eq!(Layer::from_stored("product"), Some(Layer::App));
        assert_eq!(Layer::App.as_stored(), "product");
        assert_eq!(Layer::from_stored("platform"), Some(Layer::Platform));
        assert_eq!(Layer::from_stored("other"), None);
    }
}

/// A reference to one object of one kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectRef {
    pub kind: KindName,
    pub id: ObjectId,
}

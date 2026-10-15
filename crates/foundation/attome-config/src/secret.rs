//! A secret configuration value (roadmap Z1-T1): a password, key or token
//! that never appears in `Debug` or logs, and cannot be serialized at all,
//! so it cannot leak through a config dump, an error message or a JSON
//! response. Read it with [`Secret::expose`] at the point it is handed to
//! the driver, client or hasher that needs it.
//!
//! It has no `Display` (Z1-T2): `format!("{}", secret)` does not compile, so
//! a connection string built from one has to call `expose()` and cannot
//! quietly come out as `[REDACTED]`.

use serde::{Deserialize, Deserializer};

/// A configuration value that is never shown.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The value itself, for the one place that needs it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// Constant-time over the shorter length: how long two equal-length secrets
/// take to compare does not depend on where they first differ.
impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        let (a, b) = (self.0.as_bytes(), other.0.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl Eq for Secret {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        assert_eq!(format!("{:?}", Secret::new("hunter2".into())), "[REDACTED]");
    }

    #[test]
    fn converts_from_text() {
        assert_eq!(Secret::from("hunter2").expose(), "hunter2");
        assert_eq!(Secret::from(String::from("hunter2")).expose(), "hunter2");
    }

    #[test]
    fn format_in_struct_debug_is_redacted() {
        #[derive(Debug)]
        #[allow(dead_code, reason = "only formatted")]
        struct Holder {
            user: String,
            password: Secret,
        }
        let text = format!(
            "{:?}",
            Holder {
                user: "app".into(),
                password: Secret::new("hunter2".into()),
            }
        );
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("[REDACTED]"), "{text}");
    }

    #[test]
    fn deserializes_from_plain_string() {
        let secret: Secret = serde_json::from_str("\"hunter2\"").expect("a string");
        assert_eq!(secret.expose(), "hunter2");
        assert!(!secret.is_empty());
        assert_eq!(secret, Secret::new("hunter2".into()));
        assert_ne!(secret, Secret::new("hunter3".into()));
        assert_ne!(secret, Secret::new("hunter".into()));
    }
}

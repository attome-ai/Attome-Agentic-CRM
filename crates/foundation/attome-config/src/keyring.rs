//! P-key-rotation-and-jwt (a) — a small map of `key_id -> secret material`
//! plus which one is currently active, for every config field that needs
//! non-destructive key rotation: `auth.jwt_secret`,
//! `auth.mfa_encryption_key`, `s2s.key_encryption_key`,
//! `audit.erasure_key_encryption_key`, `events.webhook_signing_key`,
//! `integration.credential_encryption_key` and
//! `inference.provider_credential_key`.
//!
//! Deliberately lives in `attome-config`, not `attome-auth` (which is where the
//! actual envelope-encryption/JWT logic that *consumes* this type lives):
//! `attome-auth` already depends on `attome-config` (guidelines §1 dependency
//! direction is strictly one-way), so a `KeyRing` field on `AuthSection`/
//! `S2SSection`/`AuditSection` cannot be of a type `attome-config` doesn't own
//! without creating a cycle. This type carries no crypto of its own — just
//! the map and a couple of pure helpers — so keeping it here costs nothing
//! and lets every crate that already depends on `attome-config` read config
//! shaped this way without a new dependency edge.
//!
//! `Deserialize` accepts either a bare string (`"jwt_secret": "abc..."`) —
//! wrapped into a single-entry ring under the fixed [`BARE_STRING_KEY_ID`] — or
//! the full `{ keys: {...}, active_key_id: "..." }` shape a deployment uses
//! once it wants more than one live key.

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;

/// The id a bare-string config value is wrapped under (see module doc).
pub const BARE_STRING_KEY_ID: &str = "legacy";

#[derive(Clone, Default)]
pub struct KeyRing {
    pub keys: HashMap<String, String>,
    pub active_key_id: String,
}

/// Hand-rolled: the derived `Debug` would print every raw secret value in
/// `keys`. Key ids are not secret material — they are operator-chosen names
/// (or the fixed id a bare config string is wrapped under) — so
/// those are safe to show as-is; only the map's values are redacted.
impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("key_ids", &self.keys.keys().collect::<Vec<_>>())
            .field("active_key_id", &self.active_key_id)
            .finish()
    }
}

impl KeyRing {
    /// A ring holding exactly one key under `BARE_STRING_KEY_ID`, active —
    /// what a plain config string deserializes to.
    pub fn single(secret: String) -> Self {
        let mut keys = HashMap::with_capacity(1);
        keys.insert(BARE_STRING_KEY_ID.to_string(), secret);
        Self {
            keys,
            active_key_id: BARE_STRING_KEY_ID.to_string(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn get(&self, key_id: &str) -> Option<&str> {
        self.keys.get(key_id).map(String::as_str)
    }

    pub fn active(&self) -> Option<&str> {
        self.get(&self.active_key_id)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum KeyRingRepr {
    Bare(String),
    Full {
        #[serde(default)]
        keys: HashMap<String, String>,
        #[serde(default)]
        active_key_id: String,
    },
}

impl<'de> Deserialize<'de> for KeyRing {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match KeyRingRepr::deserialize(deserializer)? {
            KeyRingRepr::Bare(s) if s.is_empty() => Ok(KeyRing::default()),
            KeyRingRepr::Bare(s) => Ok(KeyRing::single(s)),
            KeyRingRepr::Full {
                keys,
                active_key_id,
            } => Ok(KeyRing {
                keys,
                active_key_id,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_string_deserializes_into_a_single_entry() {
        let ring: KeyRing = serde_json::from_str(&serde_json::to_string(&"abcd1234").unwrap())
            .expect("bare string must deserialize");
        assert_eq!(ring.active(), Some("abcd1234"));
        assert_eq!(ring.active_key_id, BARE_STRING_KEY_ID);
    }

    #[test]
    fn empty_bare_string_deserializes_to_an_empty_ring() {
        let ring: KeyRing =
            serde_json::from_str(&serde_json::to_string(&"").unwrap()).expect("must deserialize");
        assert!(ring.is_empty());
        assert_eq!(ring.active(), None);
    }

    #[test]
    fn full_shape_deserializes_with_an_explicit_active_key() {
        let json = r#"{
            "keys": {"k1": "secret-one", "k2": "secret-two"},
            "active_key_id": "k2"
        }"#;
        let ring: KeyRing = serde_json::from_str(json).expect("full shape must deserialize");
        assert_eq!(ring.active(), Some("secret-two"));
        assert_eq!(ring.get("k1"), Some("secret-one"));
    }
}

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
//!
//! Z1-T6: a ring can also come from one environment variable, where only a
//! string fits: `ring:k2=secret-two;k1=secret-one` is a ring whose first key
//! (`k2`) is active and whose others stay readable, so a rotation needs no
//! JSON in the environment. A string without the `ring:` prefix is a bare
//! key as before.

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
            KeyRingRepr::Bare(s) if s.starts_with(RING_PREFIX) => {
                parse_compact(&s[RING_PREFIX.len()..]).map_err(serde::de::Error::custom)
            }
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

/// The prefix of a ring written as one string (Z1-T6).
pub const RING_PREFIX: &str = "ring:";

/// `k2=secret-two;k1=secret-one`: the first key is active. Every key needs an
/// id and a value, and ids are unique.
fn parse_compact(text: &str) -> Result<KeyRing, String> {
    let mut ring = KeyRing::default();
    for entry in text.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let (id, secret) = entry.split_once('=').ok_or("a ring entry is `id=secret`")?;
        let (id, secret) = (id.trim(), secret.trim());
        if id.is_empty() || secret.is_empty() {
            return Err("a ring entry needs an id and a secret".into());
        }
        if ring.keys.insert(id.to_owned(), secret.to_owned()).is_some() {
            return Err(format!("the ring names key {id} twice"));
        }
        if ring.active_key_id.is_empty() {
            ring.active_key_id = id.to_owned();
        }
    }
    if ring.keys.is_empty() {
        return Err("a `ring:` value names no key".into());
    }
    Ok(ring)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ring_fits_in_one_environment_variable() {
        let ring: KeyRing =
            serde_json::from_str(r#""ring:k2=secret-two; k1=secret-one""#).expect("compact ring");
        assert_eq!(ring.active_key_id, "k2");
        assert_eq!(ring.active(), Some("secret-two"));
        assert_eq!(ring.get("k1"), Some("secret-one"));
        for bad in [
            r#""ring:""#,
            r#""ring:k1""#,
            r#""ring:k1=a;k1=b""#,
            r#""ring:=x""#,
        ] {
            assert!(serde_json::from_str::<KeyRing>(bad).is_err(), "{bad}");
        }
        // Without the prefix a value is one bare key, `=` and `;` included.
        let bare: KeyRing = serde_json::from_str(r#""a=b;c""#).unwrap();
        assert_eq!(bare.active(), Some("a=b;c"));
    }

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

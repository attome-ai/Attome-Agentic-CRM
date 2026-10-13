//! Canonical serialization and hashing of a [`Bundle`].
//!
//! Two bundles that describe the same configuration must produce the same
//! bytes, whatever order their components or object keys were authored in —
//! the `basis_hash`/`bundle_hash` contract (P-environment-promotion §4 "Plan
//! and apply are separate calls, bound by a basis hash") depends on it, and
//! so does "export twice → byte-identical" (§3 Phase 1).
//!
//! The rules:
//! - the bundle is [`Bundle::normalize`]d first, so every component vector
//!   is sorted by its logical key;
//! - the result is serialized through [`serde_json::Value`] and written by
//!   this module's own writer, which emits every object's keys in sorted
//!   order regardless of how `serde_json`'s map happens to be configured
//!   (`preserve_order` is a feature-unified flag a transitive dependency can
//!   flip; this writer does not care);
//! - no whitespace, so the bytes are minimal and stable;
//! - the model carries no timestamps and no floats of its own (record-set
//!   rows may — `serde_json`'s float formatting is deterministic for a given
//!   `f64`, which is enough).
//!
//! `bundle_hash` is the lowercase hex SHA-256 of those bytes.

use super::model::Bundle;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The canonical bytes of `bundle`. Never fails: the model is plain data
/// and `serde_json::to_value` on it cannot error in practice — if it ever
/// did, the bytes of the error message would be as deterministic as the
/// bundle, so hashing stays stable rather than panicking.
pub fn canonical_json(bundle: &Bundle) -> Vec<u8> {
    let mut normalized = bundle.clone();
    normalized.normalize();
    let value = match serde_json::to_value(&normalized) {
        Ok(v) => v,
        Err(e) => Value::String(format!("unserializable bundle: {e}")),
    };
    let mut out = Vec::with_capacity(4096);
    write_canonical(&value, &mut out);
    out
}

/// Lowercase hex SHA-256 of [`canonical_json`].
pub fn bundle_hash(bundle: &Bundle) -> String {
    hash_bytes(&canonical_json(bundle))
}

/// Lowercase hex SHA-256 of arbitrary bytes — exposed so a caller holding
/// already-canonical bytes (a stored plan row) hashes them the same way.
pub fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_scalar(&Value::String((*key).clone()), out);
                out.push(b':');
                if let Some(v) = map.get(*key) {
                    write_canonical(v, out);
                }
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => write_scalar(scalar, out),
    }
}

fn write_scalar(value: &Value, out: &mut Vec<u8>) {
    // `serde_json::to_writer` into a Vec cannot fail for a scalar; the
    // fallback keeps this infallible without an `expect`.
    if serde_json::to_writer(&mut *out, value).is_err() {
        out.extend_from_slice(b"null");
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::*;
    use super::*;

    fn attr(name: &str) -> AttributeDef {
        AttributeDef {
            logicalname: name.to_owned(),
            display_name: name.to_uppercase(),
            field_type: "text".to_owned(),
            is_required: false,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity: None,
            options: None,
            max_length: None,
            on_target_delete: "orphan".to_owned(),
            data_classification: "general".to_owned(),
            purpose: None,
            is_customized: false,
        }
    }

    fn entity(name: &str, attrs: Vec<AttributeDef>) -> EntityDef {
        EntityDef {
            logicalname: name.to_owned(),
            display_name: name.to_uppercase(),
            primary_name_attribute: None,
            is_append_only: false,
            is_audited: false,
            category: None,
            is_customized: false,
            attributes: attrs,
        }
    }

    fn requires() -> Requires {
        Requires {
            platform_version: ">=0.0.0".to_owned(),
            schema_version: 0,
            modules: vec!["core".to_owned()],
            depends_on_bundles: vec![],
        }
    }

    fn sample() -> Bundle {
        let mut b = Bundle::empty(requires());
        b.entities = vec![
            entity("account", vec![attr("name"), attr("email")]),
            entity("contact", vec![attr("name")]),
        ];
        b.roles = vec![RoleDef {
            name: "editor".to_owned(),
            description: None,
            access_level: 3,
            position_hierarchy_enabled: false,
            is_customized: false,
            privileges: vec![
                RoleGrant {
                    privilege: "account.read".to_owned(),
                    conditions: vec![],
                },
                RoleGrant {
                    privilege: "account.write".to_owned(),
                    conditions: vec![],
                },
            ],
            entity_access: vec![],
            field_security_profiles: vec![],
        }];
        b
    }

    #[test]
    fn order_of_components_does_not_change_the_hash() {
        let a = sample();
        let mut b = sample();
        b.entities.reverse();
        b.entities[1].attributes.reverse();
        b.roles[0].privileges.reverse();
        b.requires.modules = vec!["core".to_owned(), "core".to_owned()];
        assert_eq!(canonical_json(&a), canonical_json(&b));
        assert_eq!(bundle_hash(&a), bundle_hash(&b));
    }

    #[test]
    fn any_field_change_changes_the_hash() {
        let a = sample();
        let mut b = sample();
        b.entities[0].attributes[0].display_name.push('!');
        assert_ne!(bundle_hash(&a), bundle_hash(&b));

        let mut c = sample();
        c.entities[0].attributes[0].is_sensitive = true;
        assert_ne!(bundle_hash(&a), bundle_hash(&c));

        let mut d = sample();
        d.roles[0].privileges.pop();
        assert_ne!(bundle_hash(&a), bundle_hash(&d));

        let mut e = sample();
        e.requires.schema_version = 1;
        assert_ne!(bundle_hash(&a), bundle_hash(&e));
    }

    #[test]
    fn object_keys_are_emitted_sorted_and_compact() {
        let bytes = canonical_json(&sample());
        let text = String::from_utf8(bytes).expect("canonical bytes are utf-8");
        // Top-level keys sorted: "apps" < "attribute_patches" < "calendars" <
        // "entities" < "field_security_profiles" < "format" < ...; first key
        // must be "apps" (M65 Phase 1/D-467 added `apps`/`forms`; "apps"
        // sorts before "calendars", which used to be first — same precedent
        // D-404/M83 set when it added `calendars` ahead of what was then the
        // first key, "entities"). `attribute_patches` (cross-module field
        // promotion) now sorts second, ahead of "calendars".
        assert!(
            text.starts_with(
                r#"{"apps":[],"attribute_patches":[],"calendars":[],"entities":[{"attributes":[{"data_classification""#
            ),
            "{text}"
        );
        assert!(!text.contains('\n'));
        assert!(!text.contains(": "));
        // Parses back to the same bundle.
        let round: Bundle = serde_json::from_str(&text).expect("canonical bytes are a bundle");
        let mut expected = sample();
        expected.normalize();
        assert_eq!(round, expected);
    }

    #[test]
    fn hash_is_hex_sha256() {
        let h = bundle_hash(&sample());
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(
            hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}

//! Z1-T8: the secret inventory. Every secret the configuration can hold is
//! named here once ([`SECRETS`]), with the features that use it and how it
//! rotates; [`inventory_of`] reads a loaded document into one
//! [`SecretState`] per secret: set or not, its key ids and the active one.
//! Never a value, a hash or any part of one.
//!
//! The list is checked against the configuration's JSON Schema (every
//! `writeOnly` field, Z1-T4), so a new `Secret` or `KeyRing` field fails the
//! build's tests until it is named here with its users.

use serde_json::Value;

use crate::KeyRing;

/// How a secret is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    /// A key ring: a new key is added and made active while the old ones
    /// stay readable, so nothing written under them is lost.
    KeyRing,
    /// A single value: the new one replaces it at the next start.
    Replace,
}

impl Rotation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyRing => "key_ring",
            Self::Replace => "replace",
        }
    }
}

/// One secret of the configuration. `config_path` is its dotted path; `[]`
/// stands for every element of a list and `{}` for every entry of a map.
#[derive(Debug, Clone, Copy)]
pub struct SecretSpec {
    pub config_path: &'static str,
    pub used_by: &'static [&'static str],
    pub rotation: Rotation,
}

const fn ring(config_path: &'static str, used_by: &'static [&'static str]) -> SecretSpec {
    SecretSpec {
        config_path,
        used_by,
        rotation: Rotation::KeyRing,
    }
}

const fn value(config_path: &'static str, used_by: &'static [&'static str]) -> SecretSpec {
    SecretSpec {
        config_path,
        used_by,
        rotation: Rotation::Replace,
    }
}

/// Every secret the configuration can hold, by path.
pub const SECRETS: &[SecretSpec] = &[
    value(
        "audit.anchor_store.s3_secret_key",
        &["audit chain anchors (object store)"],
    ),
    ring(
        "audit.erasure_key_encryption_key",
        &["audit crypto-erasure (wraps per-subject keys)"],
    ),
    value("audit.signing_private_key", &["audit chain signatures"]),
    value("auth.apikey_hash_pepper", &["API key verification"]),
    value(
        "auth.apikey_hash_previous_peppers[].secret",
        &["API key verification (keys hashed under an older pepper)"],
    ),
    ring("auth.jwt_secret", &["session tokens"]),
    ring(
        "auth.jwt_signing_keys",
        &["session tokens (asymmetric signing)"],
    ),
    ring("auth.mfa_encryption_key", &["multi-factor secrets at rest"]),
    value("auth.oauth_google_client_secret", &["Google sign-in"]),
    ring("cache.encryption_key", &["cache values at rest"]),
    value("cache.password", &["cache connection"]),
    value(
        "cache.roles.coordination.password",
        &["coordination cache connection"],
    ),
    value(
        "cache.roles.coordination.sentinel.sentinel_password",
        &["coordination cache failover (Sentinel)"],
    ),
    value(
        "cache.sentinel.sentinel_password",
        &["cache failover (Sentinel)"],
    ),
    value("database.migrator.password", &["schema migrations"]),
    value("database.password", &["database bootstrap and role setup"]),
    value(
        "database.readonly.password",
        &["read-only queries and reports"],
    ),
    value("database.runtime.password", &["every request and job"]),
    value(
        "deployment.outbound_proxy",
        &["calls to outside services (proxy)"],
    ),
    ring(
        "einvoice.key_encryption_key",
        &["e-invoicing signing keys at rest"],
    ),
    value("email.providers.sendgrid.api_key", &["email (SendGrid)"]),
    value(
        "email.providers.ses.secret_access_key",
        &["email (Amazon SES)"],
    ),
    value("email.providers.ses.session_token", &["email (Amazon SES)"]),
    value("email.smtp_password", &["email (SMTP)"]),
    ring(
        "events.webhook_signing_key",
        &["outbound webhook signatures"],
    ),
    ring(
        "fleet.credential_encryption_key",
        &["fleet console credentials at rest"],
    ),
    value("google_ai.api_key", &["Google AI provider"]),
    ring(
        "idempotency.response_encryption_key",
        &["stored idempotent responses at rest"],
    ),
    value("inference.embedding.api_key", &["AI embeddings"]),
    value("inference.generation.api_key", &["AI generation"]),
    value("inference.ocr.api_key", &["document text recognition"]),
    ring(
        "inference.provider_credential_key",
        &["AI provider credentials at rest"],
    ),
    value("inference.rerank.api_key", &["search reranking"]),
    value("inference.speech.api_key", &["speech to text"]),
    ring(
        "integration.credential_encryption_key",
        &["connector credentials at rest"],
    ),
    ring(
        "oidc.client_secret_encryption_key",
        &["sign-in providers added on screen (client secrets)"],
    ),
    ring(
        "metadata.recovery_archive_key_encryption_key",
        &["metadata recovery archive"],
    ),
    value(
        "metadata.rehearsal_database_url",
        &["schema change rehearsal"],
    ),
    value("oidc.providers{}.client_secret", &["single sign-on (OIDC)"]),
    value("portal.captcha.secret", &["portal sign-up captcha"]),
    value(
        "portal.oidc_providers{}.client_secret",
        &["portal sign-in (OIDC)"],
    ),
    ring(
        "s2s.key_encryption_key",
        &["server-to-server client secrets at rest"],
    ),
    value(
        "s2s.seeded_clients[].secret",
        &["server-to-server clients seeded at boot"],
    ),
    value("storage.s3_secret_key", &["file storage (object store)"]),
    value(
        "storage.local.url_signing_key",
        &["file storage links (local disk)"],
    ),
    value("storage.azure.access_key", &["file storage (Azure Blob)"]),
    value(
        "storage.gcs.service_account_key",
        &["file storage (Google Cloud Storage)"],
    ),
];

/// One secret as this node is configured: `name` is its concrete path (a
/// list element by index, a map entry by key). `key_ids` and
/// `active_key_id` are filled for a key ring only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretState {
    pub name: String,
    pub config_path: &'static str,
    pub used_by: &'static [&'static str],
    pub rotation: Rotation,
    pub set: bool,
    pub key_ids: Vec<String>,
    pub active_key_id: Option<String>,
}

/// Every secret of `document` (the loaded configuration, `${VAR}` expanded),
/// in [`SECRETS`] order. A list or map with no entries contributes nothing;
/// any other secret appears whether set or not.
pub fn inventory_of(document: &Value) -> Vec<SecretState> {
    let mut out = Vec::new();
    for spec in SECRETS {
        let mut found = Vec::new();
        locate(document, spec.config_path, String::new(), &mut found);
        for (name, value) in found {
            out.push(state(spec, name, value));
        }
    }
    out
}

/// The values at `pattern` under `node`, with their concrete paths. A
/// missing plain key yields `None`; a missing or empty list or map yields
/// nothing.
fn locate<'a>(
    node: &'a Value,
    pattern: &str,
    prefix: String,
    out: &mut Vec<(String, Option<&'a Value>)>,
) {
    let (segment, rest) = match pattern.split_once('.') {
        Some((segment, rest)) => (segment, Some(rest)),
        None => (pattern, None),
    };
    let join = |key: &str| {
        if prefix.is_empty() {
            key.to_owned()
        } else {
            format!("{prefix}.{key}")
        }
    };
    let descend = |child: Option<&'a Value>, path: String, out: &mut Vec<_>| match rest {
        None => out.push((path, child.filter(|value| !value.is_null()))),
        Some(rest) => match child {
            Some(child) => locate(child, rest, path, out),
            None => {
                if !rest.contains("[]") && !rest.contains("{}") {
                    out.push((format!("{path}.{rest}"), None));
                }
            }
        },
    };
    if let Some(key) = segment.strip_suffix("[]") {
        if let Some(items) = node.get(key).and_then(Value::as_array) {
            for (index, item) in items.iter().enumerate() {
                descend(Some(item), format!("{}[{index}]", join(key)), out);
            }
        }
    } else if let Some(key) = segment.strip_suffix("{}") {
        if let Some(entries) = node.get(key).and_then(Value::as_object) {
            for (entry, item) in entries {
                descend(Some(item), format!("{}.{entry}", join(key)), out);
            }
        }
    } else {
        descend(node.get(segment), join(segment), out);
    }
}

/// A string still holding an unexpanded `${VAR}` is not a secret anyone set.
fn is_real(text: &str) -> bool {
    !text.is_empty() && !(text.starts_with("${") && text.ends_with('}'))
}

fn state(spec: &SecretSpec, name: String, value: Option<&Value>) -> SecretState {
    let mut state = SecretState {
        name,
        config_path: spec.config_path,
        used_by: spec.used_by,
        rotation: spec.rotation,
        set: false,
        key_ids: Vec::new(),
        active_key_id: None,
    };
    let Some(value) = value else {
        return state;
    };
    match spec.rotation {
        Rotation::Replace => state.set = value.as_str().is_some_and(is_real),
        Rotation::KeyRing => {
            let Ok(ring) = serde_json::from_value::<KeyRing>(value.clone()) else {
                return state;
            };
            state.set = ring.active().is_some_and(is_real);
            let mut ids: Vec<String> = ring
                .keys
                .iter()
                .filter(|(_, secret)| is_real(secret))
                .map(|(id, _)| id.clone())
                .collect();
            ids.sort();
            state.key_ids = ids;
            if state.set {
                state.active_key_id = Some(ring.active_key_id);
            }
        }
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn resolve<'a>(schema: &'a Value, defs: &'a Value) -> &'a Value {
        match schema["$ref"].as_str() {
            Some(target) => &defs[target.rsplit('/').next().unwrap_or_default()],
            None => schema,
        }
    }

    fn unwrap_option<'a>(schema: &'a Value, defs: &'a Value) -> &'a Value {
        if let Some(alternatives) = schema["anyOf"].as_array() {
            let present: Vec<&Value> = alternatives
                .iter()
                .filter(|alt| alt["type"] != "null")
                .collect();
            if present.len() == 1 && present.len() < alternatives.len() {
                return resolve(present[0], defs);
            }
        }
        resolve(schema, defs)
    }

    /// Every `writeOnly` field of the schema by path pattern, and whether
    /// it is a key ring (its schema accepts the `{keys, active_key_id}`
    /// object).
    fn write_only(
        path: &str,
        schema: &Value,
        defs: &Value,
        depth: usize,
        out: &mut BTreeMap<String, bool>,
    ) {
        if depth > 10 {
            return;
        }
        let inner = unwrap_option(schema, defs);
        if schema["writeOnly"] == true || inner["writeOnly"] == true {
            let ring = inner["anyOf"].as_array().is_some_and(|alternatives| {
                alternatives
                    .iter()
                    .any(|alt| alt["properties"].get("active_key_id").is_some())
            });
            out.insert(path.to_owned(), ring);
            return;
        }
        if let Some(properties) = inner["properties"].as_object() {
            for (name, field) in properties {
                let child = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}.{name}")
                };
                write_only(&child, field, defs, depth + 1, out);
            }
        }
        if inner["items"].is_object() {
            write_only(&format!("{path}[]"), &inner["items"], defs, depth + 1, out);
        }
        if inner["additionalProperties"].is_object() {
            write_only(
                &format!("{path}{{}}"),
                &inner["additionalProperties"],
                defs,
                depth + 1,
                out,
            );
        }
    }

    #[test]
    fn inventory_covers_every_secret_field() {
        let schema = crate::config_json_schema();
        let mut found = BTreeMap::new();
        write_only("", &schema, &schema["$defs"], 0, &mut found);
        assert!(
            found.len() > 30,
            "the schema walk found too little: {found:?}"
        );
        let listed: BTreeMap<String, bool> = SECRETS
            .iter()
            .map(|spec| {
                (
                    spec.config_path.to_owned(),
                    spec.rotation == Rotation::KeyRing,
                )
            })
            .collect();
        let missing: Vec<&String> = found.keys().filter(|p| !listed.contains_key(*p)).collect();
        let stale: Vec<&String> = listed.keys().filter(|p| !found.contains_key(*p)).collect();
        assert!(
            missing.is_empty(),
            "secret fields missing from SECRETS (name their users there): {missing:?}"
        );
        assert!(
            stale.is_empty(),
            "SECRETS names fields that no longer exist: {stale:?}"
        );
        assert_eq!(listed, found, "a field's rotation does not match its type");
        assert_eq!(listed.len(), SECRETS.len(), "a path is listed twice");
        assert!(SECRETS.iter().all(|spec| !spec.used_by.is_empty()));
    }

    #[test]
    fn inventory_reads_rings_lists_and_maps_without_values() {
        let document = json!({
            "auth": {
                "jwt_secret": "ring:k2=second-secret-value;k1=first-secret-value",
                "mfa_encryption_key": "${MFA_KEY}",
                "apikey_hash_pepper": "pepper-value",
                "apikey_hash_previous_peppers": [{"id": 1, "secret": "old-pepper"}]
            },
            "oidc": {"providers": {"okta": {"client_secret": "okta-secret"}}},
            "database": {"password": ""}
        });
        let states = inventory_of(&document);
        let by_name = |name: &str| {
            states
                .iter()
                .find(|state| state.name == name)
                .unwrap_or_else(|| panic!("{name} missing from {states:?}"))
        };
        let jwt = by_name("auth.jwt_secret");
        assert!(jwt.set);
        assert_eq!(jwt.key_ids, ["k1", "k2"]);
        assert_eq!(jwt.active_key_id.as_deref(), Some("k2"));
        assert!(
            !by_name("auth.mfa_encryption_key").set,
            "an unexpanded ${{VAR}} is unset"
        );
        assert!(by_name("auth.apikey_hash_pepper").set);
        assert!(by_name("auth.apikey_hash_previous_peppers[0].secret").set);
        assert!(by_name("oidc.providers.okta.client_secret").set);
        assert!(!by_name("database.password").set);
        assert!(
            !by_name("storage.s3_secret_key").set,
            "an absent secret is listed unset"
        );
        assert!(
            !states
                .iter()
                .any(|state| state.name.starts_with("s2s.seeded_clients")),
            "an empty list contributes nothing"
        );
        let shown = format!("{states:?}");
        for secret in [
            "second-secret-value",
            "pepper-value",
            "okta-secret",
            "old-pepper",
        ] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
    }
}

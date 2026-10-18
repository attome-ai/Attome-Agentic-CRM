//! Z1-T7: a configuration's fingerprint. Every start records what the node
//! was configured with, so an operator can tell two nodes apart, or this
//! start from the last one, without ever seeing a secret.
//!
//! The view is the loaded configuration document (after `${VAR}`
//! expansion) with every secret-looking key replaced by `{"set": bool}`:
//! any key naming a secret, password, token, key, pepper, credential or
//! private material, or holding a key ring. A password written into a URL
//! (`postgres://user:pass@host`) is replaced by `***`. Masking errs wide: a
//! non-secret value that looks like one is hidden too, which only makes the
//! view less detailed. Changing a secret's value does not change the
//! fingerprint; setting or clearing it does.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const SECRET_WORDS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "token",
    "pepper",
    "credential",
    "private",
    "api_key",
];

/// Whether the value under `key` may be secret.
pub fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SECRET_WORDS.iter().any(|word| key.contains(word))
        || key == "key"
        || key == "keys"
        || key.ends_with("_key")
        || key.ends_with("_keys")
}

fn is_set(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        _ => true,
    }
}

/// `scheme://user:pass@host...` with the password replaced.
fn without_url_password(text: &str) -> String {
    let Some(scheme_end) = text.find("://") else {
        return text.to_owned();
    };
    let rest = &text[scheme_end + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let Some(at) = authority.rfind('@') else {
        return text.to_owned();
    };
    let userinfo = &authority[..at];
    let Some(colon) = userinfo.find(':') else {
        return text.to_owned();
    };
    format!(
        "{}{}:***{}",
        &text[..scheme_end + 3],
        &userinfo[..colon],
        &rest[at..]
    )
}

/// The fingerprint view of a configuration document.
pub fn view_of(document: &Value) -> Value {
    match document {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, value) in map {
                let masked = if is_secret_key(key) {
                    serde_json::json!({ "set": is_set(value) })
                } else {
                    view_of(value)
                };
                out.insert(key.clone(), masked);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(view_of).collect()),
        Value::String(text) => Value::String(without_url_password(text)),
        other => other.clone(),
    }
}

/// `value` as canonical JSON: object keys sorted at every level.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let members: Vec<String> = keys
                .into_iter()
                .map(|key| format!("{}:{}", Value::String(key.clone()), canonical(&map[key])))
                .collect();
            format!("{{{}}}", members.join(","))
        }
        Value::Array(items) => {
            format!(
                "[{}]",
                items.iter().map(canonical).collect::<Vec<_>>().join(",")
            )
        }
        other => other.to_string(),
    }
}

/// The SHA-256 hex of a view's canonical JSON.
pub fn fingerprint_of(view: &Value) -> String {
    Sha256::digest(canonical(view).as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// One configuration key whose value differs between two views.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ChangedKey {
    /// The dotted path, e.g. `app.port`.
    pub path: String,
    pub before: Value,
    pub after: Value,
}

/// The keys whose values differ between `before` and `after`.
pub fn diff(before: &Value, after: &Value) -> Vec<ChangedKey> {
    let mut out = Vec::new();
    diff_at("", before, after, &mut out);
    out
}

fn diff_at(path: &str, before: &Value, after: &Value, out: &mut Vec<ChangedKey>) {
    if before == after {
        return;
    }
    match (before, after) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                diff_at(
                    &child,
                    a.get(key).unwrap_or(&Value::Null),
                    b.get(key).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        _ => out.push(ChangedKey {
            path: path.to_owned(),
            before: before.clone(),
            after: after.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn urls_lose_their_password_only() {
        assert_eq!(
            without_url_password("postgres://app:s3cr3t@db:5432/attome"),
            "postgres://app:***@db:5432/attome"
        );
        assert_eq!(
            without_url_password("redis://cache:6379"),
            "redis://cache:6379"
        );
        assert_eq!(without_url_password("plain text"), "plain text");
    }

    #[test]
    fn diff_names_dotted_paths() {
        let changes = diff(
            &json!({ "app": { "port": 1, "host": "a" } }),
            &json!({ "app": { "port": 2, "host": "a" }, "new": true }),
        );
        let paths: Vec<&str> = changes.iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, ["app.port", "new"]);
    }
}

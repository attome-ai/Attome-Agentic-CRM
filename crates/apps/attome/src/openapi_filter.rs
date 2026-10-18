//! S2-T14: the OpenAPI document each caller is served: only the operations
//! of the licence modules switched on here (`x-module`, S2-T9) and, for a
//! caller who is not an administrator, none whose `x-privilege` is `admin`
//! (S2-T7). Paths left with no operation are dropped, and so are component
//! schemas nothing left refers to.
//!
//! **Cache.** The filtered documents, keyed by their ETag, at most
//! [`MAX_CACHED`] of them, oldest dropped first. Source of truth: the static
//! assembled document plus the module set and the caller's admin flag, all
//! three in the key (the release version through the ETag), so a licence or
//! release change is a new key and needs no invalidation; no TTL. Per node,
//! rebuilt on the first call after a start; a lost entry is only rebuilt.
//! Never keyed by user.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The most filtered documents kept.
pub const MAX_CACHED: usize = 32;

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// `doc` as a caller with `enabled_modules` switched on and `is_admin` may
/// see it.
pub fn filter_document(doc: &Value, enabled_modules: &BTreeSet<String>, is_admin: bool) -> Value {
    let mut out = doc.clone();
    if let Some(paths) = out.get_mut("paths").and_then(Value::as_object_mut) {
        paths.retain(|_, item| {
            let Some(item) = item.as_object_mut() else {
                return true;
            };
            item.retain(|key, operation| {
                if !METHODS.contains(&key.as_str()) {
                    return true;
                }
                let module_on = operation
                    .get("x-module")
                    .and_then(Value::as_str)
                    .is_none_or(|module| enabled_modules.contains(module));
                let admin_only =
                    operation.get("x-privilege").and_then(Value::as_str) == Some("admin");
                module_on && (is_admin || !admin_only)
            });
            item.keys().any(|key| METHODS.contains(&key.as_str()))
        });
    }
    prune_schemas(&mut out);
    out
}

/// Every `#/components/schemas/<name>` reference in `value`.
fn schema_refs(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "$ref"
                    && let Some(name) = child
                        .as_str()
                        .and_then(|r| r.strip_prefix("#/components/schemas/"))
                {
                    out.insert(name.to_owned());
                } else {
                    schema_refs(child, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| schema_refs(item, out)),
        _ => {}
    }
}

/// Drops the component schemas nothing outside them (nor any schema kept)
/// refers to.
fn prune_schemas(doc: &mut Value) {
    let Some(schemas) = doc
        .pointer("/components/schemas")
        .and_then(Value::as_object)
        .cloned()
    else {
        return;
    };
    // Roots: every reference outside `components.schemas`.
    let mut outside = doc.clone();
    if let Some(components) = outside.get_mut("components").and_then(Value::as_object_mut) {
        components.remove("schemas");
    }
    let mut keep = BTreeSet::new();
    schema_refs(&outside, &mut keep);
    // Then whatever a kept schema refers to, until nothing new turns up.
    let mut queue: Vec<String> = keep.iter().cloned().collect();
    while let Some(name) = queue.pop() {
        let Some(schema) = schemas.get(&name) else {
            continue;
        };
        let mut found = BTreeSet::new();
        schema_refs(schema, &mut found);
        for next in found {
            if keep.insert(next.clone()) {
                queue.push(next);
            }
        }
    }
    let kept: Map<String, Value> = schemas
        .into_iter()
        .filter(|(name, _)| keep.contains(name))
        .collect();
    if let Some(slot) = doc.pointer_mut("/components/schemas") {
        *slot = Value::Object(kept);
    }
}

/// The document's ETag: the first 16 hex characters of a SHA-256 over the
/// release, the sorted module list and the admin flag.
pub fn etag(release: &str, enabled_modules: &BTreeSet<String>, is_admin: bool) -> String {
    let mut hasher = Sha256::new();
    hasher.update(release.as_bytes());
    for module in enabled_modules {
        hasher.update(b"\0");
        hasher.update(module.as_bytes());
    }
    hasher.update(if is_admin { b"\0admin" } else { b"\0staff" });
    let hex = hex::encode(hasher.finalize());
    format!("\"{}\"", &hex[..16])
}

static CACHE: Mutex<Vec<(String, Arc<Value>)>> = Mutex::new(Vec::new());

/// The filtered document for `etag`, built by `build` on a miss.
pub fn cached(etag: &str, build: impl FnOnce() -> Value) -> Arc<Value> {
    {
        let cache = CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, doc)) = cache.iter().find(|(key, _)| key == etag) {
            return Arc::clone(doc);
        }
    }
    let doc = Arc::new(build());
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !cache.iter().any(|(key, _)| key == etag) {
        if cache.len() >= MAX_CACHED {
            cache.remove(0);
        }
        cache.push((etag.to_owned(), Arc::clone(&doc)));
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn modules(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn doc() -> Value {
        json!({
            "paths": {
                "/api/v1/account": {
                    "get": {
                        "x-module": "core", "x-privilege": "authenticated",
                        "responses": { "200": { "content": { "application/json": {
                            "schema": { "$ref": "#/components/schemas/Account" } } } } }
                    }
                },
                "/api/v1/projects": {
                    "get": {
                        "x-module": "project", "x-privilege": "authenticated",
                        "responses": { "200": { "content": { "application/json": {
                            "schema": { "$ref": "#/components/schemas/Project" } } } } }
                    }
                },
                "/api/v1/admin/limits": {
                    "parameters": [],
                    "get": { "x-module": "core", "x-privilege": "admin", "responses": {} },
                    "put": { "x-module": "core", "x-privilege": "admin", "responses": {} }
                }
            },
            "components": { "schemas": {
                "Account": { "type": "object", "properties": {
                    "owner": { "$ref": "#/components/schemas/Owner" } } },
                "Owner": { "type": "object" },
                "Project": { "type": "object", "properties": {
                    "lead": { "$ref": "#/components/schemas/Lead" } } },
                "Lead": { "type": "object" },
                "Orphan": { "type": "object" }
            } }
        })
    }

    #[test]
    fn filter_removes_unlicensed_module_operations() {
        let out = filter_document(&doc(), &modules(&["core"]), true);
        assert!(out.pointer("/paths/~1api~1v1~1projects").is_none());
        assert!(out.pointer("/paths/~1api~1v1~1account/get").is_some());
        let with = filter_document(&doc(), &modules(&["core", "project"]), true);
        assert!(with.pointer("/paths/~1api~1v1~1projects/get").is_some());
    }

    #[test]
    fn filter_removes_admin_operations_for_non_admin() {
        let staff = filter_document(&doc(), &modules(&["core", "project"]), false);
        let paths = staff["paths"].as_object().expect("paths");
        assert!(
            paths.keys().all(|p| !p.starts_with("/api/v1/admin")),
            "{paths:?}"
        );
        let admin = filter_document(&doc(), &modules(&["core", "project"]), true);
        assert!(
            admin
                .pointer("/paths/~1api~1v1~1admin~1limits/put")
                .is_some()
        );
    }

    #[test]
    fn filter_prunes_unreferenced_schemas() {
        let out = filter_document(&doc(), &modules(&["core"]), false);
        let schemas = out["components"]["schemas"].as_object().expect("schemas");
        let names: Vec<&str> = schemas.keys().map(String::as_str).collect();
        // Account and what it refers to stay; the project's schemas and the
        // orphan go.
        assert_eq!(names, ["Account", "Owner"]);
    }

    #[test]
    fn the_etag_changes_with_modules_and_admin_only() {
        let core = modules(&["core"]);
        let a = etag("1.0.0", &core, false);
        assert_eq!(a, etag("1.0.0", &core, false));
        assert_ne!(a, etag("1.0.0", &core, true));
        assert_ne!(a, etag("1.0.0", &modules(&["core", "project"]), false));
        assert_ne!(a, etag("1.0.1", &core, false));
        assert_eq!(a.len(), 18, "16 hex characters, quoted");
    }
}

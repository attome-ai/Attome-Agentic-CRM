//! S2-T7: the policy extensions on every operation, derived in one pass over
//! the assembled document.
//!
//! - `x-privilege`: `{entity}.read|create|update|delete` on the generic
//!   entity routes (`/api/v1/{entity}...`), `admin` under `/api/v1/admin/`,
//!   `public` when the operation's security is only the empty requirement,
//!   `authenticated` otherwise.
//! - `x-risk`: `low` for reads, `medium` for writes, `high` for a delete and
//!   for any route under hard-delete, security, S2S or licence
//!   administration.
//! - `x-idempotent`: `key` for a write (safe to retry with an
//!   `Idempotency-Key`), `natural` for a read.
//! - `x-cache`: `etag` for a single record read and the document itself,
//!   `none` otherwise.
//!
//! A value an operation already declares (its own annotation, or an earlier
//! pass: Q20-T1's `x-rate-class` and AA7-T1's `x-cache`) is kept;
//! [`OVERRIDES`] then wins over both. The route policy table
//! (`attome_server::route_policy`) reads `x-idempotent` in either form.

use utoipa::openapi::OpenApi;
use utoipa::openapi::extensions::Extensions;

/// `(METHOD, path template, extension, value)` applied after the defaults.
/// AE1's per-route risk tiers land here as they are reviewed.
pub const OVERRIDES: &[(&str, &str, &str, &str)] = &[];

/// Paths whose every operation is high risk.
const HIGH_RISK_MARKERS: &[&str] = &[
    "hard-delete",
    "/api/v1/admin/security",
    "/api/v1/admin/s2s",
    "/api/v1/admin/license",
];

fn is_write(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn privilege(method: &str, path: &str, public: bool) -> String {
    if public {
        return "public".to_owned();
    }
    if path == "/api/v1/{entity}" || path.starts_with("/api/v1/{entity}/") {
        let action = match method {
            "POST" => "create",
            "PUT" | "PATCH" => "update",
            "DELETE" => "delete",
            _ => "read",
        };
        return format!("{{entity}}.{action}");
    }
    if path.starts_with("/api/v1/admin/") {
        return "admin".to_owned();
    }
    "authenticated".to_owned()
}

fn risk(method: &str, path: &str) -> &'static str {
    if method == "DELETE" || HIGH_RISK_MARKERS.iter().any(|m| path.contains(m)) {
        "high"
    } else if is_write(method) {
        "medium"
    } else {
        "low"
    }
}

fn cache(method: &str, path: &str) -> &'static str {
    if method == "GET" && (path == "/api/v1/{entity}/{id}" || path == "/api/v1/openapi.json") {
        "etag"
    } else {
        "none"
    }
}

/// Whether `security` admits an anonymous caller: it is present and every
/// requirement in it is empty.
fn is_public(security: Option<&Vec<utoipa::openapi::security::SecurityRequirement>>) -> bool {
    let Some(requirements) = security else {
        return false;
    };
    !requirements.is_empty()
        && requirements.iter().all(|r| {
            serde_json::to_value(r).is_ok_and(|v| v.as_object().is_some_and(|m| m.is_empty()))
        })
}

/// Sets the policy extensions on every operation of `doc`.
pub fn apply(doc: &mut OpenApi) {
    for (path, item) in doc.paths.paths.iter_mut() {
        for (method, operation) in [
            ("GET", &mut item.get),
            ("PUT", &mut item.put),
            ("POST", &mut item.post),
            ("DELETE", &mut item.delete),
            ("OPTIONS", &mut item.options),
            ("HEAD", &mut item.head),
            ("PATCH", &mut item.patch),
            ("TRACE", &mut item.trace),
        ] {
            let Some(operation) = operation else {
                continue;
            };
            let public = is_public(operation.security.as_ref());
            let defaults = [
                ("x-privilege", privilege(method, path, public)),
                ("x-risk", risk(method, path).to_owned()),
                (
                    "x-idempotent",
                    if is_write(method) { "key" } else { "natural" }.to_owned(),
                ),
                ("x-cache", cache(method, path).to_owned()),
            ];
            let extensions = operation.extensions.get_or_insert_with(Extensions::default);
            for (key, value) in defaults {
                extensions
                    .entry(key.to_owned())
                    .or_insert_with(|| serde_json::Value::from(value));
            }
            for (m, p, key, value) in OVERRIDES {
                if *m == method && *p == path.as_str() {
                    extensions.insert((*key).to_owned(), serde_json::Value::from(*value));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(paths: serde_json::Value) -> OpenApi {
        serde_json::from_value(serde_json::json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "0" },
            "paths": paths,
        }))
        .expect("a minimal document")
    }

    fn extension(doc: &OpenApi, path: &str, method: &str, key: &str) -> serde_json::Value {
        let value = serde_json::to_value(doc).expect("serialises");
        value["paths"][path][method][key].clone()
    }

    #[test]
    fn entity_get_is_read_privilege_low_risk() {
        let mut d = doc(serde_json::json!({
            "/api/v1/{entity}/{id}": { "get": { "responses": {}, "security": [{ "session_cookie": [] }] } }
        }));
        apply(&mut d);
        let at = |key| extension(&d, "/api/v1/{entity}/{id}", "get", key);
        assert_eq!(at("x-privilege"), "{entity}.read");
        assert_eq!(at("x-risk"), "low");
        assert_eq!(at("x-idempotent"), "natural");
        assert_eq!(at("x-cache"), "etag");
    }

    #[test]
    fn hard_delete_is_high_risk() {
        let mut d = doc(serde_json::json!({
            "/api/v1/{entity}/{id}/hard-delete": { "post": { "responses": {} } },
            "/api/v1/admin/roles/{id}": { "delete": { "responses": {} } },
            "/api/v1/admin/roles": { "post": { "responses": {} } }
        }));
        apply(&mut d);
        assert_eq!(
            extension(&d, "/api/v1/{entity}/{id}/hard-delete", "post", "x-risk"),
            "high"
        );
        assert_eq!(
            extension(&d, "/api/v1/admin/roles/{id}", "delete", "x-risk"),
            "high"
        );
        assert_eq!(
            extension(&d, "/api/v1/admin/roles", "post", "x-risk"),
            "medium"
        );
        assert_eq!(
            extension(&d, "/api/v1/admin/roles", "post", "x-privilege"),
            "admin"
        );
        assert_eq!(
            extension(&d, "/api/v1/admin/roles", "post", "x-idempotent"),
            "key"
        );
    }

    #[test]
    fn public_route_has_public_privilege() {
        let mut d = doc(serde_json::json!({
            "/api/v1/auth/login": { "post": { "responses": {}, "security": [{}] } },
            "/api/v1/me": { "get": { "responses": {}, "security": [{ "api_key": [] }] } }
        }));
        apply(&mut d);
        assert_eq!(
            extension(&d, "/api/v1/auth/login", "post", "x-privilege"),
            "public"
        );
        assert_eq!(
            extension(&d, "/api/v1/me", "get", "x-privilege"),
            "authenticated"
        );
    }

    #[test]
    fn a_declared_value_is_kept() {
        let mut d = doc(serde_json::json!({
            "/api/v1/upload": { "post": { "responses": {}, "x-idempotent": false, "x-cache": "no-store" } }
        }));
        apply(&mut d);
        assert_eq!(
            extension(&d, "/api/v1/upload", "post", "x-idempotent"),
            false
        );
        assert_eq!(
            extension(&d, "/api/v1/upload", "post", "x-cache"),
            "no-store"
        );
        assert_eq!(extension(&d, "/api/v1/upload", "post", "x-risk"), "medium");
    }
}

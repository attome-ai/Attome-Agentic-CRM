//! Z5-T3: per-route policy read from the API document. Three operation
//! extensions describe a route's handling, written with [`route_policy`]:
//! `x-auth` (`session`, `api_key`, `s2s`, `public` or `portal`),
//! `x-body-limit` (bytes) and `x-idempotent` (a bool, or S2-T7's `key`,
//! `natural` or `none`). The table is built once
//! at start from the merged document ([`RoutePolicyTable::from_document`],
//! by the app crate, which is the only one that sees every route) and
//! installed here ([`install`]); the body-limit layer reads it by matched
//! route. An operation without the extensions gets the defaults: `auth` from
//! its security declaration, the global body limit, not idempotent.
//!
//! A route's body limit can only lower the global one.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use serde_json::Value;

/// The operation extensions for one route, for its `#[utoipa::path]`.
pub fn route_policy(auth: &str, body_limit: Option<usize>, idempotent: bool) -> Value {
    let mut policy = serde_json::json!({ "x-auth": auth, "x-idempotent": idempotent });
    if let Some(limit) = body_limit {
        policy["x-body-limit"] = Value::from(limit);
    }
    policy
}

/// One route's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePolicy {
    pub auth: String,
    pub body_limit: usize,
    pub idempotent: bool,
}

/// Every route's policy, by `(METHOD, path template)`.
#[derive(Debug, Default)]
pub struct RoutePolicyTable(HashMap<(String, String), RoutePolicy>);

/// `auth` from an operation's security requirements.
fn auth_from_security(security: Option<&Value>) -> String {
    let Some(requirements) = security.and_then(Value::as_array) else {
        return "session".to_owned();
    };
    let schemes: Vec<&str> = requirements
        .iter()
        .filter_map(Value::as_object)
        .flat_map(|r| r.keys().map(String::as_str))
        .collect();
    if schemes.is_empty() {
        "public"
    } else if schemes.contains(&"portal_session") {
        "portal"
    } else if schemes == ["s2s_hmac"] {
        "s2s"
    } else if schemes.contains(&"session_cookie") {
        "session"
    } else {
        "api_key"
    }
    .to_owned()
}

impl RoutePolicyTable {
    /// The table for `document` (the merged OpenAPI document as JSON), with
    /// `global_body_limit` as every route's ceiling.
    pub fn from_document(document: &Value, global_body_limit: usize) -> Result<Self, String> {
        let paths = document["paths"]
            .as_object()
            .ok_or("the API document has no paths")?;
        let mut table = HashMap::new();
        for (path, item) in paths {
            let Some(item) = item.as_object() else {
                continue;
            };
            for (method, operation) in item {
                if operation.get("responses").is_none() {
                    continue;
                }
                let auth = match operation.get("x-auth") {
                    Some(Value::String(auth)) => auth.clone(),
                    Some(other) => {
                        return Err(format!(
                            "{method} {path}: x-auth must be a string, got {other}"
                        ));
                    }
                    None => auth_from_security(operation.get("security")),
                };
                let body_limit = match operation.get("x-body-limit") {
                    Some(limit) => {
                        let limit = limit.as_u64().ok_or_else(|| {
                            format!("{method} {path}: x-body-limit must be a byte count")
                        })?;
                        usize::try_from(limit)
                            .unwrap_or(usize::MAX)
                            .min(global_body_limit)
                    }
                    None => global_body_limit,
                };
                let idempotent = match operation.get("x-idempotent") {
                    Some(Value::Bool(flag)) => *flag,
                    Some(Value::String(form)) if form == "key" || form == "natural" => true,
                    Some(Value::String(form)) if form == "none" => false,
                    Some(_) => {
                        return Err(format!(
                            "{method} {path}: x-idempotent must be a boolean, key, natural or none"
                        ));
                    }
                    None => false,
                };
                table.insert(
                    (method.to_ascii_uppercase(), path.clone()),
                    RoutePolicy {
                        auth,
                        body_limit,
                        idempotent,
                    },
                );
            }
        }
        Ok(Self(table))
    }

    pub fn get(&self, method: &str, path: &str) -> Option<&RoutePolicy> {
        self.0.get(&(method.to_ascii_uppercase(), path.to_owned()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

static TABLE: OnceLock<Arc<RoutePolicyTable>> = OnceLock::new();

/// Installs the process's table, once; `false` when one is already set.
pub fn install(table: RoutePolicyTable) -> bool {
    TABLE.set(Arc::new(table)).is_ok()
}

/// The body limit of `method` on the matched route `path`, if a table is
/// installed and lists it.
pub fn body_limit_for(method: &str, path: &str) -> Option<usize> {
    TABLE
        .get()?
        .get(method, path)
        .map(|policy| policy.body_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document() -> Value {
        serde_json::json!({ "paths": {
            "/api/v1/upload": { "post": {
                "responses": {}, "security": [{ "session_cookie": [] }, { "api_key": [] }],
                "x-body-limit": 1024, "x-idempotent": true
            } },
            "/api/v1/auth/login": { "post": { "responses": {}, "security": [{}] } },
            "/{keyword}/api/v1/me": { "get": { "responses": {}, "security": [{ "portal_session": [] }] } },
            "/api/v1/big": { "post": { "responses": {}, "x-body-limit": 999_999_999 } }
        } })
    }

    #[test]
    fn policies_come_from_the_document() {
        let table = RoutePolicyTable::from_document(&document(), 10_000).unwrap();
        let upload = table.get("POST", "/api/v1/upload").unwrap();
        assert_eq!(
            (upload.auth.as_str(), upload.body_limit, upload.idempotent),
            ("session", 1024, true)
        );
        assert_eq!(
            table.get("post", "/api/v1/auth/login").unwrap().auth,
            "public"
        );
        assert_eq!(
            table.get("GET", "/{keyword}/api/v1/me").unwrap().auth,
            "portal"
        );
        assert_eq!(
            table.get("POST", "/api/v1/big").unwrap().body_limit,
            10_000,
            "a route never raises the global limit"
        );
    }

    #[test]
    fn a_malformed_extension_is_an_error() {
        let document = serde_json::json!({ "paths": {
            "/x": { "post": { "responses": {}, "x-body-limit": "big" } }
        } });
        assert!(RoutePolicyTable::from_document(&document, 10).is_err());
    }

    #[test]
    fn x_idempotent_reads_the_policy_forms() {
        let document = serde_json::json!({ "paths": {
            "/a": { "post": { "responses": {}, "x-idempotent": "key" } },
            "/b": { "get": { "responses": {}, "x-idempotent": "natural" } },
            "/c": { "post": { "responses": {}, "x-idempotent": "none" } },
            "/d": { "post": { "responses": {}, "x-idempotent": "sometimes" } }
        } });
        assert!(RoutePolicyTable::from_document(&document, 10).is_err());
        let document = serde_json::json!({ "paths": {
            "/a": { "post": { "responses": {}, "x-idempotent": "key" } },
            "/b": { "get": { "responses": {}, "x-idempotent": "natural" } },
            "/c": { "post": { "responses": {}, "x-idempotent": "none" } }
        } });
        let table = RoutePolicyTable::from_document(&document, 10).unwrap();
        assert!(table.get("POST", "/a").unwrap().idempotent);
        assert!(table.get("GET", "/b").unwrap().idempotent);
        assert!(!table.get("POST", "/c").unwrap().idempotent);
    }

    #[test]
    fn route_policy_writes_the_three_extensions() {
        let policy = route_policy("session", Some(65_536), false);
        assert_eq!(policy["x-auth"], "session");
        assert_eq!(policy["x-body-limit"], 65_536);
        assert_eq!(policy["x-idempotent"], false);
    }
}

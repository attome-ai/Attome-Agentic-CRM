//! Y12-T8: a renamed attribute's old name keeps working in the record API
//! for its alias period (`attome_metadata::provision::field_change::RENAME_ALIAS_DAYS`).
//! A create or update body, and a `query/execute` filter, may name the old
//! attribute; it is read as the current one, and the response carries
//! `Deprecation: true` and a `Link` naming the current attribute. Responses
//! only ever use the current name.

use attome_core::EngineState;
use axum::http::HeaderValue;
use axum::response::Response;
use serde_json::Value;

/// An old name the request used and the current name it was read as.
pub type Renamed = Vec<(String, String)>;

/// `body` with every aliased key of `entity` moved to its current name. A
/// body that names both the old and the current attribute keeps the
/// current one (the old key is dropped).
pub fn apply(state: &EngineState, entity: &str, mut body: Value) -> (Value, Renamed) {
    let registry = state.entities.load();
    if !registry.has_aliases(entity) {
        return (body, Vec::new());
    }
    let mut renamed = Vec::new();
    if let Some(fields) = body.as_object_mut() {
        let old: Vec<String> = fields
            .keys()
            .filter(|k| registry.alias(entity, k).is_some())
            .cloned()
            .collect();
        for old_name in old {
            let Some(current) = registry.alias(entity, &old_name).map(str::to_owned) else {
                continue;
            };
            if let Some(value) = fields.remove(&old_name)
                && !fields.contains_key(&current)
            {
                fields.insert(current.clone(), value);
            }
            renamed.push((old_name, current));
        }
    }
    (body, renamed)
}

/// The current name of a field a filter names, and whether it was an alias.
pub fn resolve_field(state: &EngineState, entity: &str, field: &str) -> Option<String> {
    state
        .entities
        .load()
        .alias(entity, field)
        .map(str::to_owned)
}

/// Adds the deprecation headers when the request used an old name.
pub fn mark(mut response: Response, entity: &str, renamed: &Renamed) -> Response {
    if renamed.is_empty() {
        return response;
    }
    let headers = response.headers_mut();
    headers.insert("deprecation", HeaderValue::from_static("true"));
    for (old_name, current) in renamed {
        // Names are validated identifiers (lower-case letters, digits, `_`).
        if let Ok(link) = HeaderValue::from_str(&format!(
            "<urn:attome:attribute:{entity}.{current}>; rel=\"successor-version\"; title=\"{old_name}\""
        )) {
            headers.append("link", link);
        }
    }
    response
}

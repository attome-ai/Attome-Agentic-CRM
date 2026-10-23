//! M14-T4: what an inbound hook's handler does with an event, pure.
//!
//! A handler is one of:
//! - `{"type": "record", "entity": "...", "fields": {"attr": "/json/pointer"},
//!   "key": "attr"}`: writes a record of `entity` from the body. With `key`
//!   (an attribute among `fields`, usually an external id) the record
//!   holding that value is updated, and one is created only when none does.
//!   Without it every event creates a record.
//! - `{"type": "flow", "definition_id": "..."}`: starts the flow's
//!   published version with the body as context.
//! - `{"type": "events", "event_type": "/type", "routes": {"order.created":
//!   <record or flow handler>, ...}, "default": <handler>}`: picks the
//!   handler by the event type at the `event_type` pointer. An event of a
//!   type with no route and no default is acknowledged and ignored.
//!
//! The writes themselves run in `attome-api`'s inbox job, as the hook's
//! service user through the generic write path.

use serde_json::{Map, Value};

/// The most routes one events handler holds.
pub const MAX_ROUTES: usize = 100;

fn pointer_ok(p: &Value) -> bool {
    p.as_str()
        .is_some_and(|p| (p.is_empty() || p.starts_with('/')) && p.len() <= 200)
}

/// Checks a record or flow handler's shape (not that its entity or flow
/// exists).
fn check_leaf(handler: &Value) -> Result<(), String> {
    match handler["type"].as_str() {
        Some("record") => {
            if handler["entity"].as_str().is_none_or(str::is_empty) {
                return Err("a record handler names its entity".into());
            }
            let Some(fields) = handler["fields"].as_object().filter(|m| !m.is_empty()) else {
                return Err("a record handler maps at least one attribute to a body field".into());
            };
            if let Some((attribute, _)) = fields.iter().find(|(_, p)| !pointer_ok(p)) {
                return Err(format!(
                    "the body field for {attribute} is a JSON pointer such as /data/id"
                ));
            }
            match &handler["key"] {
                Value::Null => Ok(()),
                Value::String(key) if fields.contains_key(key) => Ok(()),
                _ => Err("key is one of the attributes the handler maps".into()),
            }
        }
        Some("flow") => handler["definition_id"]
            .as_str()
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .map(|_| ())
            .ok_or_else(|| "a flow handler names definition_id".into()),
        _ => Err("a routed handler's type is record or flow".into()),
    }
}

/// Checks a handler's shape, routes included.
pub fn check_shape(handler: &Value) -> Result<(), String> {
    match handler["type"].as_str() {
        Some("events") => {}
        Some("record" | "flow") => return check_leaf(handler),
        _ => return Err("handler.type is record, flow or events".into()),
    }
    let event_pointer = handler["event_type"].as_str().unwrap_or_default();
    if !event_pointer.starts_with('/') || event_pointer.len() > 200 {
        return Err("event_type is a JSON pointer such as /type".into());
    }
    let Some(routes) = handler["routes"].as_object().filter(|m| !m.is_empty()) else {
        return Err("an events handler has at least one route".into());
    };
    if routes.len() > MAX_ROUTES {
        return Err(format!("an events handler has at most {MAX_ROUTES} routes"));
    }
    for (event_type, leaf) in routes {
        check_leaf(leaf).map_err(|e| format!("route {event_type:?}: {e}"))?;
    }
    if !handler["default"].is_null() {
        check_leaf(&handler["default"]).map_err(|e| format!("default: {e}"))?;
    }
    Ok(())
}

/// Every record or flow handler a handler can run.
pub fn leaves(handler: &Value) -> Vec<&Value> {
    if handler["type"].as_str() != Some("events") {
        return vec![handler];
    }
    handler["routes"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.values())
        .chain(Some(&handler["default"]).filter(|d| !d.is_null()))
        .collect()
}

/// The event's type at `pointer`, as text.
fn event_type(pointer: &str, payload: &Value) -> Option<String> {
    match payload.pointer(pointer)? {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// The handler that runs for `payload`; `None` when no route matches and
/// there is no default (the event is ignored).
pub fn select<'a>(handler: &'a Value, payload: &Value) -> Option<&'a Value> {
    if handler["type"].as_str() != Some("events") {
        return Some(handler);
    }
    let routed = handler["event_type"]
        .as_str()
        .and_then(|p| event_type(p, payload))
        .and_then(|t| handler["routes"].get(&t));
    routed.or(Some(&handler["default"]).filter(|d| !d.is_null()))
}

/// The attributes a record handler writes from `payload`; a pointer with
/// no value (or null) writes nothing.
pub fn record_fields(handler: &Value, payload: &Value) -> Map<String, Value> {
    handler["fields"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(attribute, pointer)| {
            let pointer = pointer.as_str()?;
            let value = if pointer.is_empty() {
                Some(payload)
            } else {
                payload.pointer(pointer)
            }?;
            (!value.is_null()).then(|| (attribute.clone(), value.clone()))
        })
        .collect()
}

/// A keyed record handler's key attribute and the value the event gives
/// it; `Ok(None)` for a handler without a key. An event that gives the key
/// no value is refused rather than creating a record nothing can match.
pub fn upsert_key<'a>(
    handler: &'a Value,
    fields: &'a Map<String, Value>,
) -> Result<Option<(&'a str, &'a Value)>, String> {
    let Some(key) = handler["key"].as_str() else {
        return Ok(None);
    };
    fields
        .get(key)
        .map(|value| Some((key, value)))
        .ok_or_else(|| format!("the event gives the key attribute {key} no value"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn routed() -> Value {
        json!({
            "type": "events",
            "event_type": "/type",
            "routes": {
                "order.created": { "type": "record", "entity": "sales_order",
                                   "fields": { "external_ref": "/data/id", "total": "/data/total" },
                                   "key": "external_ref" },
                "order.cancelled": { "type": "flow",
                                     "definition_id": "0192f7a0-0000-7000-8000-000000000001" }
            }
        })
    }

    #[test]
    fn inbound_handlers_route_by_event_type() {
        let handler = routed();
        assert!(check_shape(&handler).is_ok());
        let created = json!({ "type": "order.created", "data": { "id": "A-1", "total": 90 } });
        let leaf = select(&handler, &created).expect("a route");
        assert_eq!(leaf["entity"], "sales_order");
        let cancelled = json!({ "type": "order.cancelled" });
        assert_eq!(select(&handler, &cancelled).unwrap()["type"], "flow");
        assert!(
            select(&handler, &json!({ "type": "order.paid" })).is_none(),
            "no route and no default: ignored"
        );
        let mut with_default = handler.clone();
        with_default["default"] = json!({ "type": "record", "entity": "note",
                                          "fields": { "body": "" } });
        assert_eq!(
            select(&with_default, &json!({ "type": "order.paid" })).unwrap()["entity"],
            "note"
        );
        assert_eq!(leaves(&with_default).len(), 3);
        let plain = json!({ "type": "record", "entity": "lead", "fields": { "title": "/t" } });
        assert_eq!(select(&plain, &json!({})), Some(&plain));
    }

    #[test]
    fn inbound_handlers_upsert_by_the_key() {
        let handler = routed();
        let leaf = &handler["routes"]["order.created"];
        let fields = record_fields(leaf, &json!({ "data": { "id": "A-1", "total": 90 } }));
        assert_eq!(
            upsert_key(leaf, &fields).unwrap(),
            Some(("external_ref", &json!("A-1")))
        );
        let no_id = record_fields(leaf, &json!({ "data": { "total": 90 } }));
        assert!(
            upsert_key(leaf, &no_id).is_err(),
            "a keyed event needs its key"
        );
        let unkeyed = json!({ "type": "record", "entity": "lead", "fields": { "title": "/t" } });
        assert_eq!(upsert_key(&unkeyed, &fields).unwrap(), None);
    }

    #[test]
    fn inbound_handlers_shape_checks() {
        let bad_key = json!({ "type": "record", "entity": "lead",
                              "fields": { "title": "/t" }, "key": "external_ref" });
        assert!(
            check_shape(&bad_key).is_err(),
            "the key must be a mapped attribute"
        );
        let nested = json!({ "type": "events", "event_type": "/type",
                             "routes": { "a": routed() } });
        assert!(check_shape(&nested).is_err(), "routes do not nest");
        let no_pointer = json!({ "type": "events", "event_type": "type",
                                 "routes": { "a": { "type": "flow",
                                   "definition_id": "0192f7a0-0000-7000-8000-000000000001" } } });
        assert!(check_shape(&no_pointer).is_err());
        assert!(check_shape(&json!({ "type": "extension" })).is_err());
    }
}

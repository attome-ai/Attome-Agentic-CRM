//! Y7-T7: `GET /api/v1/asyncapi.json`, an AsyncAPI 3.0 document of the
//! change feed for this deployment: per entity a channel with its
//! `created`, `updated`, `deleted` and `restored` messages, and per
//! published business event (Y7-T5) a channel with its message, each
//! payload typed from the attributes (the same schemas as
//! `/api/v1/openapi/deployment.json`).
//!
//! A message is one `entity_change_event` row as the change stream and
//! webhooks deliver it: the entity, the record, the operation, the changed
//! attributes and their values before and after (a sensitive attribute's
//! values are `{"ref": true}`). Only the entities the caller may read, and
//! the business events about them, are listed. The document is built per
//! request from the current metadata, so it always matches the deployment;
//! it is not written to a file at build time, since it depends on the
//! deployment's own entities.

use attome_core::{EngineState, EntityMetaRegistry};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde_json::{Map, Value, json};

/// The operations an entity channel carries, as the feed names them.
const OPERATIONS: [&str; 4] = ["create", "update", "delete", "restore"];

fn message_name(operation: &str) -> &'static str {
    match operation {
        "create" => "created",
        "update" => "updated",
        "delete" => "deleted",
        _ => "restored",
    }
}

/// The envelope every change-feed message has; `values` types `before`
/// and `after`.
fn envelope(values: Value, event_name: Option<&str>) -> Value {
    let operations: Vec<&str> = OPERATIONS.iter().copied().chain(["purge"]).collect();
    let mut properties = json!({
        "entity_logicalname": { "type": "string" },
        "record_id": { "type": "string", "format": "uuid" },
        "operation": { "type": "string", "enum": operations },
        "changed_attributes": { "type": "array", "items": { "type": "string" } },
        "before": values.clone(),
        "after": values,
        "occurred_at": { "type": "string", "format": "date-time" }
    });
    if let Some(name) = event_name {
        properties["event_name"] = json!({ "type": "string", "const": name });
    }
    json!({
        "type": "object",
        "required": ["entity_logicalname", "record_id", "operation"],
        "properties": properties
    })
}

/// A business event's payload schema from its declared attributes.
fn event_values(definition: &Value) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    if let Some(attributes) = definition.get("attributes").and_then(Value::as_object) {
        for (name, attr) in attributes {
            let schema = match attr["type"].as_str().unwrap_or_default() {
                "number" => json!({ "type": "number" }),
                "boolean" => json!({ "type": "boolean" }),
                "date_time" => json!({ "type": "string", "format": "date-time" }),
                "uuid" => json!({ "type": "string", "format": "uuid" }),
                _ => json!({ "type": "string" }),
            };
            properties.insert(name.clone(), schema);
            if attr.get("required").and_then(Value::as_bool) == Some(true) {
                required.push(Value::String(name.clone()));
            }
        }
    }
    json!({ "type": "object", "properties": properties, "required": required })
}

/// The whole document for `registry` and the published business events,
/// keeping only what `readable` allows.
pub fn build_document(
    registry: &EntityMetaRegistry,
    events: &[Value],
    readable: impl Fn(&str) -> bool,
) -> Value {
    let mut channels = Map::new();
    let mut operations = Map::new();
    let mut messages = Map::new();
    let mut schemas = Map::new();

    let mut names: Vec<&str> = registry
        .iter()
        .map(|m| m.logicalname.as_str())
        .filter(|name| readable(name))
        .collect();
    names.sort_unstable();
    for name in names {
        let Some(meta) = registry.get(name) else {
            continue;
        };
        let mut values = Map::new();
        for attr in &meta.attrs {
            values.insert(
                attr.logicalname.clone(),
                crate::deployment_openapi::attribute_schema(attr),
            );
        }
        schemas.insert(
            format!("{name}.values"),
            json!({ "type": "object", "properties": values }),
        );
        let mut channel_messages = Map::new();
        for operation in OPERATIONS {
            let message = format!("{name}.{}", message_name(operation));
            messages.insert(
                message.clone(),
                json!({
                    "name": message,
                    "title": format!("{name} {}", message_name(operation)),
                    "payload": envelope(json!({ "$ref": format!("#/components/schemas/{name}.values") }), None)
                }),
            );
            channel_messages.insert(
                message_name(operation).to_owned(),
                json!({ "$ref": format!("#/components/messages/{message}") }),
            );
            operations.insert(
                format!("receive.{message}"),
                json!({
                    "action": "receive",
                    "channel": { "$ref": format!("#/channels/entity.{name}") },
                    "messages": [{ "$ref": format!("#/channels/entity.{name}/messages/{}", message_name(operation)) }]
                }),
            );
        }
        channels.insert(
            format!("entity.{name}"),
            json!({ "address": format!("entity/{name}"), "messages": channel_messages }),
        );
    }

    let mut events: Vec<&Value> = events
        .iter()
        .filter(|d| d["entity"].as_str().is_some_and(&readable))
        .collect();
    events.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    for definition in events {
        let Some(name) = definition["name"].as_str() else {
            continue;
        };
        let message = format!("event.{name}");
        let mut body = json!({
            "name": message,
            "title": name,
            "payload": envelope(event_values(definition), Some(name))
        });
        if let Some(text) = definition["description_en"].as_str() {
            body["summary"] = json!(text);
        }
        messages.insert(message.clone(), body);
        channels.insert(
            message.clone(),
            json!({
                "address": format!("event/{name}"),
                "messages": { "raised": { "$ref": format!("#/components/messages/{message}") } }
            }),
        );
        operations.insert(
            format!("receive.{message}"),
            json!({
                "action": "receive",
                "channel": { "$ref": format!("#/channels/{message}") },
                "messages": [{ "$ref": format!("#/channels/{message}/messages/raised") }]
            }),
        );
    }

    json!({
        "asyncapi": "3.0.0",
        "info": {
            "title": "Attome deployment change feed",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Record changes and business events, as the change stream and webhooks deliver them."
        },
        "defaultContentType": "application/json",
        "channels": channels,
        "operations": operations,
        "components": { "messages": messages, "schemas": schemas }
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/asyncapi.json",
    tag = "openapi",
    responses(
        (status = 200, description = "AsyncAPI 3.0 for the change feed of the entities the caller may read", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn asyncapi_document(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<Value>, AppError> {
    let registry = state.entities.load();
    let events = crate::business_event::definitions();
    Ok(Json(build_document(&registry, &events, |entity| {
        ctx.require(entity, "read").is_ok()
    })))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/asyncapi.json", get(asyncapi_document))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(asyncapi_document))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{AttrInfo, DataClassification, EntityMeta, FieldType, OnTargetDelete};

    fn attr(name: &str, ty: FieldType) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int: ty.to_int(),
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            options: None,
        }
    }

    fn entity(name: &str, attrs: Vec<AttrInfo>) -> EntityMeta {
        EntityMeta {
            entity_id: uuid::Uuid::now_v7(),
            logicalname: name.into(),
            attrs,
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    #[test]
    fn a_new_entity_appears_with_its_change_messages() {
        let before = EntityMetaRegistry::from_entities(vec![entity(
            "deal",
            vec![attr("amount", FieldType::Number)],
        )]);
        let doc = build_document(&before, &[], |_| true);
        assert!(doc["channels"]["entity.deal"].is_object());
        assert!(doc["channels"]["entity.order"].is_null());
        assert_eq!(
            doc["components"]["schemas"]["deal.values"]["properties"]["amount"]["type"],
            "number"
        );
        assert!(doc["components"]["messages"]["deal.deleted"].is_object());

        let after = EntityMetaRegistry::from_entities(vec![
            entity("deal", vec![attr("amount", FieldType::Number)]),
            entity("order", vec![attr("shipped_at", FieldType::DateTime)]),
        ]);
        let doc = build_document(&after, &[], |_| true);
        assert_eq!(
            doc["components"]["schemas"]["order.values"]["properties"]["shipped_at"]["format"],
            "date-time"
        );
        assert!(doc["operations"]["receive.order.created"].is_object());
    }

    #[test]
    fn business_events_are_listed_for_readable_entities_only() {
        let registry =
            EntityMetaRegistry::from_entities(vec![entity("order", vec![]), entity("hr", vec![])]);
        let events = vec![
            json!({ "name": "order.shipped", "entity": "order",
                    "attributes": { "carrier": { "type": "text", "required": true } } }),
            json!({ "name": "hr.leaver", "entity": "hr", "attributes": {} }),
        ];
        let doc = build_document(&registry, &events, |entity| entity != "hr");
        let payload = &doc["components"]["messages"]["event.order.shipped"]["payload"];
        assert_eq!(
            payload["properties"]["event_name"]["const"],
            "order.shipped"
        );
        assert_eq!(
            payload["properties"]["after"]["required"],
            json!(["carrier"])
        );
        assert!(doc["channels"]["event.hr.leaver"].is_null());
        assert!(doc["channels"]["entity.hr"].is_null());
    }
}

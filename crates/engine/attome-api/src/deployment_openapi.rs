//! Y9-T2: `GET /api/v1/openapi/deployment.json`, an OpenAPI document for
//! this deployment's own entities: for each one, typed list, get, create,
//! update and delete operations on the generic record routes, with schemas
//! built from its attributes. The platform document (`/api/v1/openapi.json`)
//! describes those routes once with an `{entity}` parameter; this one
//! describes them per entity, so a client generator gets a type per entity.
//!
//! Only the entities the caller may read appear. The whole document is
//! built once per metadata snapshot (the registry swaps a new `Arc` on every
//! metadata change, which is the cache key) and filtered per caller.

use std::sync::{Arc, Mutex};

use attome_core::{AttrInfo, EngineState, EntityMetaRegistry, FieldType};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde_json::{Map, Value, json};

/// The registry snapshot a document was built from (held, so its address
/// cannot be reused by a later snapshot) and the document.
type Cached = (Arc<EntityMetaRegistry>, Arc<Value>);

static CACHE: Mutex<Option<Cached>> = Mutex::new(None);

/// The JSON schema of one attribute's value. `pub(crate)` for the AsyncAPI
/// document (Y7-T7), which types the same values.
pub(crate) fn attribute_schema(attr: &AttrInfo) -> Value {
    let storage = attr.storage_type();
    let multi = attr
        .options
        .as_ref()
        .is_some_and(|o| storage.is_multi_valued(o));
    let scalar = match storage {
        FieldType::Number | FieldType::Currency => json!({ "type": "number" }),
        FieldType::Bool => json!({ "type": "boolean" }),
        FieldType::Date => json!({ "type": "string", "format": "date" }),
        FieldType::DateTime => json!({ "type": "string", "format": "date-time" }),
        FieldType::Time => json!({ "type": "string", "format": "time" }),
        FieldType::Lookup => json!({ "type": "string", "format": "uuid" }),
        FieldType::Choice => {
            let choices: Vec<Value> = attr
                .options
                .as_ref()
                .and_then(|o| o.get("choices"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if choices.is_empty() {
                json!({ "type": "string" })
            } else {
                json!({ "type": "string", "enum": choices })
            }
        }
        FieldType::Text
        | FieldType::RichText
        | FieldType::Icon
        | FieldType::Color
        | FieldType::File
        | FieldType::Image
        | FieldType::Formula => json!({ "type": "string" }),
    };
    let mut schema = if multi {
        json!({ "type": "array", "items": scalar })
    } else {
        scalar
    };
    if attr.is_formula()
        && let Some(object) = schema.as_object_mut()
    {
        object.insert("readOnly".into(), Value::Bool(true));
    }
    schema
}

/// The record and input schemas of one entity.
fn entity_schemas(attrs: &[AttrInfo]) -> (Value, Value) {
    let mut record = Map::new();
    for (name, schema) in [
        ("id", json!({ "type": "string", "format": "uuid" })),
        ("row_version", json!({ "type": "integer" })),
        (
            "created_at",
            json!({ "type": "string", "format": "date-time" }),
        ),
        (
            "modified_at",
            json!({ "type": ["string", "null"], "format": "date-time" }),
        ),
    ] {
        record.insert(name.to_owned(), schema);
    }
    let mut input = Map::new();
    let mut required = Vec::new();
    for attr in attrs {
        let schema = attribute_schema(attr);
        record.insert(attr.logicalname.clone(), schema.clone());
        if !attr.is_formula() {
            input.insert(attr.logicalname.clone(), schema);
            if attr.is_required {
                required.push(Value::String(attr.logicalname.clone()));
            }
        }
    }
    (
        json!({ "type": "object", "properties": record }),
        json!({ "type": "object", "properties": input, "required": required }),
    )
}

fn error_responses() -> Value {
    json!({
        "401": { "$ref": "#/components/responses/Error" },
        "403": { "$ref": "#/components/responses/Error" },
        "404": { "$ref": "#/components/responses/Error" },
        "422": { "$ref": "#/components/responses/Error" }
    })
}

fn with_errors(mut ok: Map<String, Value>) -> Value {
    if let Some(errors) = error_responses().as_object() {
        for (k, v) in errors {
            ok.insert(k.clone(), v.clone());
        }
    }
    Value::Object(ok)
}

/// The paths of one entity.
fn entity_paths(entity: &str) -> (Value, Value) {
    let record = json!({ "$ref": format!("#/components/schemas/{entity}") });
    let input = json!({ "$ref": format!("#/components/schemas/{entity}_input") });
    let body = |schema: &Value| json!({ "required": true, "content": { "application/json": { "schema": schema } } });
    let ok = |code: &str, schema: Value| {
        let mut m = Map::new();
        m.insert(
            code.to_owned(),
            json!({ "description": "OK", "content": { "application/json": { "schema": schema } } }),
        );
        with_errors(m)
    };
    let page = json!({
        "type": "object",
        "properties": {
            "items": { "type": "array", "items": record.clone() },
            "next_cursor": { "type": "string" }
        },
        "required": ["items"]
    });
    let id_param = json!([{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }]);
    let collection = json!({
        "get": {
            "operationId": format!("list_{entity}"),
            "tags": [entity],
            "parameters": [
                { "name": "select", "in": "query", "schema": { "type": "string" } },
                { "name": "sort", "in": "query", "schema": { "type": "string" } },
                { "name": "page_size", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 200 } },
                { "name": "cursor", "in": "query", "schema": { "type": "string", "format": "uuid" } }
            ],
            "responses": ok("200", page)
        },
        "post": {
            "operationId": format!("create_{entity}"),
            "tags": [entity],
            "requestBody": body(&input),
            "responses": ok("201", record.clone())
        }
    });
    let mut if_match = id_param.as_array().cloned().unwrap_or_default();
    if_match.push(json!({ "name": "If-Match", "in": "header", "required": true, "schema": { "type": "string" } }));
    let item = json!({
        "get": {
            "operationId": format!("get_{entity}"),
            "tags": [entity],
            "parameters": id_param.clone(),
            "responses": ok("200", record.clone())
        },
        "patch": {
            "operationId": format!("update_{entity}"),
            "tags": [entity],
            "parameters": if_match,
            "requestBody": body(&input),
            "responses": ok("200", record)
        },
        "delete": {
            "operationId": format!("delete_{entity}"),
            "tags": [entity],
            "parameters": id_param,
            "responses": with_errors({
                let mut m = Map::new();
                m.insert("204".into(), json!({ "description": "Deleted" }));
                m
            })
        }
    });
    (collection, item)
}

/// The whole document, every entity included.
pub fn build_document(registry: &EntityMetaRegistry) -> Value {
    let mut paths = Map::new();
    let mut schemas = Map::new();
    let mut names: Vec<&str> = registry.iter().map(|m| m.logicalname.as_str()).collect();
    names.sort_unstable();
    for name in names {
        let Some(meta) = registry.get(name) else {
            continue;
        };
        let (record, input) = entity_schemas(&meta.attrs);
        schemas.insert(name.to_owned(), record);
        schemas.insert(format!("{name}_input"), input);
        let (collection, item) = entity_paths(name);
        paths.insert(format!("/api/v1/{name}"), collection);
        paths.insert(format!("/api/v1/{name}/{{id}}"), item);
    }
    json!({
        "openapi": "3.1.0",
        "info": { "title": "Attome deployment entities", "version": env!("CARGO_PKG_VERSION") },
        "paths": paths,
        "components": {
            "schemas": schemas,
            "responses": {
                "Error": {
                    "description": "The platform's error body",
                    "content": { "application/json": { "schema": { "type": "object" } } }
                }
            }
        }
    })
}

/// The cached document for the current registry snapshot.
fn document_for(state: &EngineState) -> Arc<Value> {
    let guard = state.entities.load();
    let registry: Arc<EntityMetaRegistry> = Arc::clone(&*guard);
    let mut cache = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((cached, doc)) = cache.as_ref()
        && Arc::ptr_eq(cached, &registry)
    {
        return Arc::clone(doc);
    }
    let doc = Arc::new(build_document(&registry));
    *cache = Some((registry, Arc::clone(&doc)));
    doc
}

/// `doc` with only the entities `readable` allows.
pub fn filter_document(doc: &Value, readable: impl Fn(&str) -> bool) -> Value {
    let mut out = doc.clone();
    if let Some(paths) = out.get_mut("paths").and_then(Value::as_object_mut) {
        paths.retain(|path, _| {
            let entity = path
                .trim_start_matches("/api/v1/")
                .split('/')
                .next()
                .unwrap_or("");
            readable(entity)
        });
    }
    if let Some(schemas) = out
        .pointer_mut("/components/schemas")
        .and_then(Value::as_object_mut)
    {
        schemas.retain(|name, _| readable(name.strip_suffix("_input").unwrap_or(name)));
    }
    out
}

/// OpenAPI document of this deployment's entities
///
/// OpenAPI document of this deployment's entities. Any signed-in user.
#[utoipa::path(
    get,
    path = "/api/v1/openapi/deployment.json",
    tag = "openapi",
    responses(
        (status = 200, description = "OpenAPI 3.1 for the entities the caller may read", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn deployment_openapi(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<Value>, AppError> {
    let doc = document_for(&state);
    Ok(Json(filter_document(&doc, |entity| {
        ctx.require(entity, "read").is_ok()
    })))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/openapi/deployment.json", get(deployment_openapi))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(deployment_openapi))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{DataClassification, EntityMeta, OnTargetDelete};

    fn attr(name: &str, ty: FieldType, required: bool) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int: ty.to_int(),
            is_required: required,
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

    fn registry(attrs: Vec<AttrInfo>) -> EntityMetaRegistry {
        EntityMetaRegistry::from_entities(vec![
            EntityMeta {
                entity_id: uuid::Uuid::now_v7(),
                logicalname: "deal".into(),
                attrs,
                is_append_only: false,
                primary_name_attribute: None,
            },
            EntityMeta {
                entity_id: uuid::Uuid::now_v7(),
                logicalname: "secret".into(),
                attrs: vec![],
                is_append_only: false,
                primary_name_attribute: None,
            },
        ])
    }

    #[test]
    fn entities_get_typed_paths_and_schemas() {
        let doc = build_document(&registry(vec![
            attr("amount", FieldType::Number, true),
            attr("closed", FieldType::Date, false),
        ]));
        assert!(doc["paths"]["/api/v1/deal"]["get"].is_object());
        assert_eq!(
            doc["paths"]["/api/v1/deal/{id}"]["patch"]["operationId"],
            "update_deal"
        );
        let props = &doc["components"]["schemas"]["deal"]["properties"];
        assert_eq!(props["amount"]["type"], "number");
        assert_eq!(props["closed"]["format"], "date");
        assert_eq!(
            doc["components"]["schemas"]["deal_input"]["required"],
            json!(["amount"])
        );
    }

    #[test]
    fn a_new_attribute_appears_and_unreadable_entities_are_left_out() {
        let before = build_document(&registry(vec![attr("amount", FieldType::Number, false)]));
        assert!(before["components"]["schemas"]["deal"]["properties"]["stage"].is_null());
        let after = build_document(&registry(vec![
            attr("amount", FieldType::Number, false),
            attr("stage", FieldType::Text, false),
        ]));
        assert_eq!(
            after["components"]["schemas"]["deal"]["properties"]["stage"]["type"],
            "string"
        );
        let filtered = filter_document(&after, |entity| entity != "secret");
        assert!(filtered["paths"]["/api/v1/secret"].is_null());
        assert!(filtered["components"]["schemas"]["secret_input"].is_null());
        assert!(filtered["paths"]["/api/v1/deal"].is_object());
    }
}

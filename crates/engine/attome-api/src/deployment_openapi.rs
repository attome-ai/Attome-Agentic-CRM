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
//!
//! S2-T16: a builder describes their own entities with an OpenAPI Overlay
//! (`GET`/`PUT /api/v1/admin/openapi/overlay`). Its actions target a path
//! (`$.paths['/api/v1/deal']`) or one of its operations
//! (`$.paths['/api/v1/deal'].get`) and may set only `summary`,
//! `description` and `example`. It is applied after the caller's filter, so
//! an action aimed at an entity the caller cannot read has nothing to land
//! on.

use std::sync::{Arc, Mutex};

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::{AttrInfo, EngineState, EntityMetaRegistry, FieldType};
use attome_security::SecurityContextExt;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

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
    let mut filtered = filter_document(&doc, |entity| ctx.require(entity, "read").is_ok());
    // S2-T16: the builder's overlay, after the filter.
    let overlay: Option<Value> = sqlx::query_scalar("SELECT overlay FROM openapi_overlay LIMIT 1")
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    // AE1-T2: each published custom action the caller holds the privileges
    // of, as its own operation with its input schema.
    if let Some(paths) = filtered.get_mut("paths").and_then(Value::as_object_mut) {
        for descriptor in attome_ai::custom_action::descriptors() {
            let held = ctx.is_admin
                || descriptor
                    .required_privileges
                    .iter()
                    .all(|p| ctx.privileges.contains(*p));
            if held {
                let (path, item) = custom_action_path(descriptor);
                paths.insert(path, item);
            }
        }
    }
    if let Some(overlay) = overlay {
        apply_overlay(&mut filtered, &overlay);
    }
    Ok(Json(filtered))
}

/// AE1-T2: one custom action as a path of the deployment document. Pure.
pub fn custom_action_path(descriptor: &attome_ai::ActionDescriptor) -> (String, Value) {
    let id = descriptor.id.as_str();
    let name = id
        .strip_prefix(attome_ai::custom_action::ID_PREFIX)
        .unwrap_or(id);
    let schema: Value = serde_json::from_str(descriptor.input_schema)
        .unwrap_or_else(|_| json!({ "type": "object" }));
    let consequential = descriptor.risk == attome_ai::descriptor::RiskTier::Consequential;
    let mut parameters = Vec::new();
    if consequential {
        parameters.push(json!({
            "name": "Idempotency-Key", "in": "header", "required": true,
            "schema": { "type": "string" }
        }));
    }
    (
        format!("/api/v1/actions/{name}"),
        json!({
            "post": {
                "operationId": format!("custom_action_{name}"),
                "summary": descriptor.description,
                "tags": ["custom actions"],
                "parameters": parameters,
                "requestBody": {
                    "required": true,
                    "content": { "application/json": { "schema": schema } }
                },
                "responses": {
                    "200": { "description": "The action ran" },
                    "202": { "description": "The action waits for a confirmation, an approval or its undo window" },
                    "default": { "$ref": "#/components/responses/Error" }
                }
            }
        }),
    )
}

// ── S2-T16: the builder's overlay ───────────────────────────────────────────

/// The most actions one overlay holds.
pub const MAX_OVERLAY_ACTIONS: usize = 2_000;
/// The longest summary or description an action sets.
pub const MAX_OVERLAY_TEXT: usize = 4_000;
/// The keys an action may set.
const UPDATABLE: [&str; 3] = ["summary", "description", "example"];
const METHODS: [&str; 5] = ["get", "put", "post", "patch", "delete"];

/// An action's target as (path, operation): `$.paths['/api/v1/…']`,
/// optionally followed by `.get`, `.put`, `.post`, `.patch` or `.delete`.
/// Anything else is `None`. Pure.
pub fn parse_overlay_target(target: &str) -> Option<(&str, Option<&str>)> {
    let rest = target.strip_prefix("$.paths['")?;
    let (path, tail) = rest.split_once("']")?;
    if !path.starts_with("/api/v1/") || path.contains(['\'', '[', ']']) {
        return None;
    }
    if tail.is_empty() {
        return Some((path, None));
    }
    let method = tail.strip_prefix('.')?;
    METHODS.contains(&method).then_some((path, Some(method)))
}

/// Why an overlay is refused, every problem at once; empty when it fits.
/// Pure.
pub fn check_overlay(overlay: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(object) = overlay.as_object() else {
        return vec!["the overlay is a JSON object".to_owned()];
    };
    let Some(actions) = object.get("actions").and_then(Value::as_array) else {
        return vec!["the overlay has a list of `actions`".to_owned()];
    };
    if actions.len() > MAX_OVERLAY_ACTIONS {
        problems.push(format!(
            "the overlay has {} actions; the limit is {MAX_OVERLAY_ACTIONS}",
            actions.len()
        ));
    }
    for (i, action) in actions.iter().enumerate() {
        let target = action["target"].as_str().unwrap_or_default();
        if parse_overlay_target(target).is_none() {
            problems.push(format!(
                "actions[{i}].target must be $.paths['/api/v1/…'] or one of its operations"
            ));
        }
        if action.get("remove").is_some() {
            problems.push(format!("actions[{i}] may not remove anything"));
        }
        match action["update"].as_object() {
            Some(update) if !update.is_empty() => {
                for (key, value) in update {
                    if !UPDATABLE.contains(&key.as_str()) {
                        problems.push(format!(
                            "actions[{i}].update may set only summary, description and example, not `{key}`"
                        ));
                    } else if key != "example"
                        && !value
                            .as_str()
                            .is_some_and(|text| text.chars().count() <= MAX_OVERLAY_TEXT)
                    {
                        problems.push(format!(
                            "actions[{i}].update.{key} is text of at most {MAX_OVERLAY_TEXT} characters"
                        ));
                    }
                }
            }
            _ => problems.push(format!("actions[{i}] has an `update` object to apply")),
        }
    }
    problems
}

/// Applies `overlay`'s actions to `doc`, in order. An action whose target is
/// not in the document, or that does not fit [`check_overlay`], changes
/// nothing. Pure.
pub fn apply_overlay(doc: &mut Value, overlay: &Value) {
    for action in overlay["actions"].as_array().into_iter().flatten() {
        let Some((path, method)) = action["target"].as_str().and_then(parse_overlay_target) else {
            continue;
        };
        let Some(update) = action["update"].as_object() else {
            continue;
        };
        let Some(item) = doc.get_mut("paths").and_then(|paths| paths.get_mut(path)) else {
            continue;
        };
        let node = match method {
            Some(method) => match item.get_mut(method) {
                Some(operation) => operation,
                None => continue,
            },
            None => item,
        };
        let Some(node) = node.as_object_mut() else {
            continue;
        };
        for (key, value) in update {
            if UPDATABLE.contains(&key.as_str()) {
                node.insert(key.clone(), value.clone());
            }
        }
    }
}

/// The deployment's OpenAPI overlay.
#[derive(Debug, Serialize, ToSchema)]
pub struct OverlayView {
    /// The overlay document, or `null` when none is set.
    #[schema(value_type = Object)]
    pub overlay: Option<Value>,
    /// Send back to replace it; 0 when none is set.
    pub row_version: i64,
}

/// A new overlay.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PutOverlay {
    /// An OpenAPI Overlay 1.0 document whose actions set summary,
    /// description or example on this deployment's paths.
    #[schema(value_type = Object)]
    pub overlay: Value,
    /// The overlay's current `row_version`; 0 when none is set yet.
    pub row_version: i64,
}

/// The deployment's OpenAPI overlay
///
/// The overlay applied to the deployment document. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/openapi/overlay",
    tag = "openapi",
    responses(
        (status = 200, description = "The overlay, or null with row_version 0", body = OverlayView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_overlay(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<OverlayView>, AppError> {
    let row: Option<(Value, i64)> =
        sqlx::query_as("SELECT overlay, row_version FROM openapi_overlay LIMIT 1")
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(Json(match row {
        Some((overlay, row_version)) => OverlayView {
            overlay: Some(overlay),
            row_version,
        },
        None => OverlayView {
            overlay: None,
            row_version: 0,
        },
    }))
}

/// Replace the OpenAPI overlay
///
/// Sets the overlay applied to the deployment document: its actions may set
/// only summary, description and example on `/api/v1/` paths and their
/// operations. Send the current `row_version` (0 for the first). Administrators
/// only.
#[utoipa::path(
    put,
    path = "/api/v1/admin/openapi/overlay",
    tag = "openapi",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    request_body = PutOverlay,
    responses(
        (status = 200, description = "Saved", body = OverlayView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "row_version is stale", body = ErrorResponse),
        (status = 422, description = "The overlay does not fit; every problem is named", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_overlay(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<PutOverlay>,
) -> Result<Json<OverlayView>, AppError> {
    let problems = check_overlay(&body.overlay);
    if !problems.is_empty() {
        return Err(AppError::Validation(problems.join("; ")));
    }
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "openapi_overlay",
            None,
        )
        .named("openapi.overlay.update"),
    )
    .await?;
    let saved: Option<i64> = if body.row_version == 0 {
        sqlx::query_scalar(
            "INSERT INTO openapi_overlay (id, overlay, updated_by) VALUES ($1, $2, $3) \
             ON CONFLICT DO NOTHING RETURNING row_version",
        )
        .bind(Uuid::now_v7())
        .bind(&body.overlay)
        .bind(ctx.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
    } else {
        sqlx::query_scalar(
            "UPDATE openapi_overlay SET overlay = $1, row_version = row_version + 1, \
                 updated_at = now(), updated_by = $2 \
             WHERE row_version = $3 RETURNING row_version",
        )
        .bind(&body.overlay)
        .bind(ctx.user_id)
        .bind(body.row_version)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
    };
    let row_version = saved.ok_or(AppError::VersionConflict)?;
    tx.commit().await?;
    Ok(Json(OverlayView {
        overlay: Some(body.overlay),
        row_version,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/openapi/deployment.json", get(deployment_openapi))
        .route(
            "/api/v1/admin/openapi/overlay",
            get(get_overlay).put(put_overlay),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(deployment_openapi, get_overlay, put_overlay),
    components(schemas(OverlayView, PutOverlay))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod overlay_tests {
    use super::*;

    #[test]
    fn overlay_rejects_targets_outside_paths() {
        let overlay = json!({ "actions": [
            { "target": "$.info", "update": { "description": "x" } },
            { "target": "$.paths['/internal/metrics']", "update": { "description": "x" } },
            { "target": "$.paths['/api/v1/deal'].trace", "update": { "description": "x" } },
            { "target": "$.paths['/api/v1/deal']", "update": { "security": [] } },
            { "target": "$.paths['/api/v1/deal']", "remove": true, "update": { "summary": "x" } },
            { "target": "$.paths['/api/v1/deal'].get", "update": { "summary": "Deals" } }
        ]});
        let problems = check_overlay(&overlay);
        assert_eq!(problems.len(), 5, "{problems:?}");
        assert!(check_overlay(&json!({ "actions": [] })).is_empty());
        assert!(!check_overlay(&json!([])).is_empty());
    }

    #[test]
    fn overlay_sets_descriptions_on_paths_and_operations() {
        let mut doc = json!({ "paths": { "/api/v1/deal": { "get": { "summary": "List" } } } });
        let overlay = json!({ "actions": [
            { "target": "$.paths['/api/v1/deal']", "update": { "description": "Our deals" } },
            { "target": "$.paths['/api/v1/deal'].get", "update": { "summary": "صفقات" } },
            { "target": "$.paths['/api/v1/deal'].post", "update": { "summary": "missing" } },
            { "target": "$.paths['/api/v1/hidden']", "update": { "summary": "missing" } }
        ]});
        apply_overlay(&mut doc, &overlay);
        assert_eq!(doc["paths"]["/api/v1/deal"]["description"], "Our deals");
        assert_eq!(doc["paths"]["/api/v1/deal"]["get"]["summary"], "صفقات");
        assert!(doc["paths"]["/api/v1/deal"].get("post").is_none());
        assert!(doc["paths"].get("/api/v1/hidden").is_none());
    }
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
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
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

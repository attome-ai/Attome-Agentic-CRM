//! T3-T2: what a page needs to host a custom component.
//!
//! - `GET /api/v1/model/components/{id}`: a published component's manifest
//!   (T3-T3's component kind: tag, properties, events) and where its module
//!   is: the URL of the file in its package and the Subresource Integrity
//!   value the browser checks it against. `module_url` and `integrity` are
//!   absent when the package that should carry the module is not installed
//!   (or carries no such file): the page shows the component's error box.
//! - `GET /api/v1/packages/{id}/files?path=<path>`: one file of an installed
//!   package (the newest applied install, never an uninstalled one), with
//!   its type, an ETag of its SHA-256 and `nosniff`. Only what a package
//!   carried, signed and checked at install, is ever served: a component is
//!   never loaded from anywhere else.
//!
//! Both are reads any signed-in user may make: a component's module is code,
//! not data, and every read it makes goes through the API as that user.

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::bundle::package::{installed_file, is_file_path};
use crate::model_admin::cooked;

/// A component as a page hosts it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ComponentView {
    pub id: Uuid,
    pub name: String,
    /// The custom element's tag.
    pub tag: String,
    /// `<package id>/<path>`, as the manifest names it.
    pub module: String,
    /// Where the module is served, when its package is installed.
    pub module_url: Option<String>,
    /// `sha256-<base64>`, the module's Subresource Integrity value.
    pub integrity: Option<String>,
    /// The manifest's properties and events, as published.
    #[schema(value_type = Vec<Object>)]
    pub properties: Vec<Value>,
    #[schema(value_type = Vec<Object>)]
    pub events: Vec<Value>,
    pub label_en: Option<String>,
    pub label_ar: Option<String>,
}

/// `<package id>/<path>` split at its first `/`. Pure.
pub fn split_module(module: &str) -> Option<(&str, &str)> {
    let (package, path) = module.split_once('/')?;
    (!package.is_empty() && is_file_path(path)).then_some((package, path))
}

/// The URL a package file is served at. Pure.
pub fn file_url(package: &str, path: &str) -> String {
    let encode = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    format!(
        "/api/v1/packages/{}/files?path={}",
        encode(package),
        encode(path)
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/model/components/{id}",
    operation_id = "get_model_component",
    tag = "model",
    params(("id" = Uuid, Path, description = "The component (model object) id")),
    responses(
        (status = 200, description = "The published component and where its module is", body = ComponentView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No published component with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Get a custom component to host
///
/// T3-T2: a published component's tag, properties and events, and the URL
/// and Subresource Integrity value of its module in its installed package.
async fn get_component(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<ComponentView>, AppError> {
    crate::model_admin::ensure_cooked(&state).await?;
    let manifest = cooked()
        .get::<Value>("component", &format!("component:{id}"))
        .ok_or(AppError::NotFound)?;
    let text = |key: &str| manifest[key].as_str().map(str::to_owned);
    let module = text("module").unwrap_or_default();
    let mut view = ComponentView {
        id,
        name: text("name").unwrap_or_default(),
        tag: text("tag").unwrap_or_default(),
        module: module.clone(),
        module_url: None,
        integrity: None,
        properties: manifest["properties"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
        events: manifest["events"].as_array().cloned().unwrap_or_default(),
        label_en: text("label_en"),
        label_ar: text("label_ar"),
    };
    if let Some((package, path)) = split_module(&module)
        && let Some(file) = installed_file(&state.base.db, package, path, false).await?
    {
        view.module_url = Some(file_url(package, path));
        view.integrity = Some(file.integrity);
    }
    Ok(Json(view))
}

/// Which file.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FileQuery {
    /// The file's path in the package (`gauge.js`).
    pub path: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/packages/{id}/files",
    operation_id = "get_package_file",
    tag = "model",
    params(("id" = String, Path, description = "The package id (reverse DNS)"), FileQuery),
    responses(
        (status = 200, description = "The file, as the package carried it"),
        (status = 304, description = "Unchanged since the ETag the caller holds"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No installed package carries this file", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Get a file of an installed package
///
/// T3-T2: a static file an installed package carried (a custom component's
/// module), from its newest applied install.
async fn get_file(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Path(id): Path<String>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !is_file_path(&query.path) {
        return Err(AppError::NotFound);
    }
    let file = installed_file(&state.base.db, &id, &query.path, true)
        .await?
        .ok_or(AppError::NotFound)?;
    let etag = format!("\"{}\"", file.sha256);
    let mut response = if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|tag| tag.trim() == etag))
    {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        (StatusCode::OK, file.body).into_response()
    };
    let out = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&file.content_type) {
        out.insert(header::CONTENT_TYPE, value);
    }
    if let Ok(value) = HeaderValue::from_str(&etag) {
        out.insert(header::ETAG, value);
    }
    out.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/model/components/{id}", get(get_component))
        .route("/api/v1/packages/{id}/files", get(get_file))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_component, get_file), components(schemas(ComponentView)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_module_names_its_package_and_a_plain_path() {
        assert_eq!(
            split_module("com.example.fleet/gauge.js"),
            Some(("com.example.fleet", "gauge.js"))
        );
        assert_eq!(split_module("acme/dist/a.js"), Some(("acme", "dist/a.js")));
        assert_eq!(split_module("acme/../etc.js"), None);
        assert_eq!(split_module("gauge.js"), None);
        assert_eq!(split_module("/gauge.js"), None);
    }

    #[test]
    fn file_urls_are_encoded() {
        assert_eq!(
            file_url("com.example.fleet", "dist/gauge.js"),
            "/api/v1/packages/com.example.fleet/files?path=dist%2Fgauge.js"
        );
    }
}

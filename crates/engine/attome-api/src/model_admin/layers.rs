//! Y11-T5: the layer stack of an entity or a field. For each property, what
//! the platform, each installed app and the customer set it to, and which
//! layer wins (`attome_model::layer_stack`); and the properties two layers
//! set differently. Read-only. Metadata carries no secrets, so every value
//! is shown.

use attome_core::EngineState;
use attome_model::Layer;
use attome_model::layer_stack::{self, PropertyStack};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};

/// One layer's value for a property.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct LayerValueView {
    /// `platform`, `app` or `customer`.
    layer: String,
    /// The app that set it; empty for the platform and the customer.
    app: String,
    #[schema(value_type = Object)]
    value: Value,
}

/// A property across the layers.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PropertyStackView {
    property: String,
    /// The layer whose value applies.
    winner: String,
    /// Every layer's value, in merge order: platform, apps in install
    /// order, customer.
    values: Vec<LayerValueView>,
}

/// A property two layers set differently.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct LayerDifferenceView {
    property: String,
    /// `null` when the `from` layer does not set it.
    #[schema(value_type = Option<Object>)]
    from: Option<Value>,
    /// `null` when the `to` layer does not set it.
    #[schema(value_type = Option<Object>)]
    to: Option<Value>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct LayerDiffQuery {
    /// `platform`, `app` or `customer`.
    from: String,
    /// `platform`, `app` or `customer`.
    to: String,
}

/// The object's stack, after checking that it exists: `kind` is `entity`
/// (key: its logical name) or `attribute` (key: `<entity>.<field>`).
async fn stack_of(
    state: &EngineState,
    kind: &str,
    key: &str,
) -> Result<Vec<PropertyStack>, AppError> {
    let exists = {
        let registry = state.entities.load();
        match kind {
            "entity" => registry.get(key).is_some(),
            "attribute" => key.split_once('.').is_some_and(|(entity, field)| {
                registry
                    .get(entity)
                    .is_some_and(|meta| meta.attrs.iter().any(|a| a.logicalname == field))
            }),
            _ => false,
        }
    };
    if !exists {
        return Err(AppError::NotFound);
    }
    layer_stack::stack(&state.base.db, kind, key).await
}

fn page<T>(items: Vec<T>) -> PaginatedResponse<T> {
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: total.max(1),
        warnings: Vec::new(),
    }
}

fn layer_param(name: &str, value: &str) -> Result<Layer, AppError> {
    match value {
        "platform" => Ok(Layer::Platform),
        "app" => Ok(Layer::App),
        "customer" => Ok(Layer::Customer),
        _ => Err(AppError::Validation(format!(
            "{name} must be platform, app or customer"
        ))),
    }
}

/// An item's layer stack
///
/// For an entity or a field, each property's value in every layer that sets it and the layer whose value applies.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/{kind}/{key}/layers",
    tag = "admin",
    params(
        ("kind" = String, Path, description = "`entity` or `attribute`"),
        ("key" = String, Path, description = "The entity's logical name, or `<entity>.<field>`"),
    ),
    responses(
        (status = 200, description = "Every property the layers set, whole on page 1", body = PaginatedResponse<PropertyStackView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity or field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn layer_stack(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path((kind, key)): Path<(String, String)>,
) -> Result<Json<PaginatedResponse<PropertyStackView>>, AppError> {
    let stacks = stack_of(&state, &kind, &key).await?;
    Ok(Json(page(
        stacks
            .into_iter()
            .map(|stack| PropertyStackView {
                property: stack.property,
                winner: stack.winner.as_str().to_owned(),
                values: stack
                    .values
                    .into_iter()
                    .map(|v| LayerValueView {
                        layer: v.layer.as_str().to_owned(),
                        app: v.app,
                        value: v.value,
                    })
                    .collect(),
            })
            .collect(),
    )))
}

/// Compare two layers of an item
///
/// The properties of an entity or a field that two layers set differently.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/{kind}/{key}/layers/diff",
    tag = "admin",
    params(
        ("kind" = String, Path, description = "`entity` or `attribute`"),
        ("key" = String, Path, description = "The entity's logical name, or `<entity>.<field>`"),
        LayerDiffQuery,
    ),
    responses(
        (status = 200, description = "The differing properties, whole on page 1", body = PaginatedResponse<LayerDifferenceView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity or field", body = ErrorResponse),
        (status = 422, description = "A layer that is not platform, app or customer", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn layer_diff(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path((kind, key)): Path<(String, String)>,
    Query(query): Query<LayerDiffQuery>,
) -> Result<Json<PaginatedResponse<LayerDifferenceView>>, AppError> {
    let from = layer_param("from", &query.from)?;
    let to = layer_param("to", &query.to)?;
    let stacks = stack_of(&state, &kind, &key).await?;
    Ok(Json(page(
        layer_stack::diff(&stacks, from, to)
            .into_iter()
            .map(|d| LayerDifferenceView {
                property: d.property,
                from: d.from,
                to: d.to,
            })
            .collect(),
    )))
}

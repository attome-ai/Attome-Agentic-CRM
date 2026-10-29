//! Y11-T5: the layer stack of an entity or a field. For each property, what
//! the platform, each installed app and the customer set it to, and which
//! layer wins (`attome_model::layer_stack`); and the properties two layers
//! set differently. Read-only. Metadata carries no secrets, so every value
//! is shown.
//!
//! Y11-T7: the conflicts an upgrade recorded, and resolving one (keep the
//! customer's value, take the platform's, or combine them), through
//! `attome_metadata::provision::layer_conflicts`, with its audit event in
//! the same transaction.
//!
//! Y11-T9: resetting a customisation back to the layers below the customer,
//! with a preview and an undo (`attome_metadata::provision::layer_reset`).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_metadata::provision::layer_conflicts::{self, LayerConflict, Resolution};
use attome_metadata::provision::{layer_impact, layer_reset};
use attome_model::Layer;
use attome_model::layer_stack::{self, PropertyStack};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

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

/// An upgrade conflict.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct LayerConflictView {
    id: Uuid,
    /// `entity` or `attribute`.
    object_kind: String,
    /// The entity's logical name, or `<entity>.<field>`.
    object_key: String,
    property: String,
    /// The platform's value before the upgrade.
    #[schema(value_type = Option<Object>)]
    old_platform: Option<Value>,
    /// The platform's value now.
    #[schema(value_type = Option<Object>)]
    new_platform: Option<Value>,
    /// The value the customer (or an app) holds.
    #[schema(value_type = Option<Object>)]
    customer: Option<Value>,
    /// `open` or `resolved`.
    status: String,
    /// `keep_customer`, `take_platform` or `combine`, once resolved.
    resolution: Option<String>,
    resolved_by: Option<Uuid>,
    resolved_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<LayerConflict> for LayerConflictView {
    fn from(c: LayerConflict) -> Self {
        Self {
            id: c.id,
            object_kind: c.object_kind,
            object_key: c.object_key,
            property: c.property,
            old_platform: c.old_platform,
            new_platform: c.new_platform,
            customer: c.customer,
            status: c.status,
            resolution: c.resolution,
            resolved_by: c.resolved_by,
            resolved_at: c.resolved_at,
            created_at: c.created_at,
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ConflictListQuery {
    /// `open` or `resolved`; every conflict when absent.
    status: Option<String>,
}

/// How to resolve a conflict.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolveConflictBody {
    /// `keep_customer`, `take_platform` or `combine`.
    choice: String,
    /// The value to apply; required for `combine`, refused otherwise.
    #[schema(value_type = Option<Object>)]
    value: Option<Value>,
}

/// List upgrade conflicts
///
/// The properties an upgrade changed that the customer (or an app) had also changed, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/conflicts",
    tag = "admin",
    params(ConflictListQuery, OnePageQuery),
    responses(
        (status = 200, description = "One page of conflicts", body = PaginatedResponse<LayerConflictView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "A status that is not open or resolved", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_conflicts(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(query): Query<ConflictListQuery>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<LayerConflictView>>, AppError> {
    let status = query.status.as_deref();
    if status.is_some_and(|s| s != "open" && s != "resolved") {
        return Err(AppError::Validation(
            "status must be open or resolved".into(),
        ));
    }
    let window = page.window();
    let (items, total) = layer_conflicts::list(&state.base.db, status, window).await?;
    Ok(Json(PaginatedResponse {
        items: items.into_iter().map(LayerConflictView::from).collect(),
        total,
        page: window.page,
        page_size: window.page_size,
        warnings: Vec::new(),
    }))
}

/// Resolve an upgrade conflict
///
/// Keeps the customer's value, takes the platform's (the customer's layer value is removed), or applies a combined value as the customer's. Taking or combining changes the entity or field at once.
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/conflicts/{id}/resolve",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The conflict's id")),
    request_body = ResolveConflictBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The resolved conflict", body = LayerConflictView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such conflict, or its entity or field is gone", body = ErrorResponse),
        (status = 409, description = "The conflict is already resolved", body = ErrorResponse),
        (status = 422, description = "An unknown choice, or a value missing for combine or given otherwise", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn resolve_conflict(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(id): Path<Uuid>,
    Json(body): Json<ResolveConflictBody>,
) -> Result<Json<LayerConflictView>, AppError> {
    let resolution = match (body.choice.as_str(), body.value) {
        ("keep_customer", None) => Resolution::KeepCustomer,
        ("take_platform", None) => Resolution::TakePlatform,
        ("combine", Some(value)) => Resolution::Combine(value),
        ("combine", None) => {
            return Err(AppError::Validation("combine needs a value".into()));
        }
        ("keep_customer" | "take_platform", Some(_)) => {
            return Err(AppError::Validation("only combine takes a value".into()));
        }
        _ => {
            return Err(AppError::Validation(
                "choice must be keep_customer, take_platform or combine".into(),
            ));
        }
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let resolved = layer_conflicts::resolve_in_tx(&mut tx, id, resolution, ctx.user_id).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_layer_conflict",
            Some(id),
        )
        .named("metadata.conflict.resolve")
        .comment(format!(
            "{} {} {}: {}",
            resolved.object_kind,
            resolved.object_key,
            resolved.property,
            resolved.resolution.as_deref().unwrap_or("")
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    if resolved.resolution.as_deref() != Some("keep_customer") {
        crate::admin::notify_metadata_change(&state.base.redis).await;
    }
    Ok(Json(resolved.into()))
}

/// Y11-T9: what to reset; `{}` resets every customised property.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResetBody {
    /// The properties to reset; every customised property when absent.
    #[serde(default)]
    properties: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct ResetQuery {
    /// Answer what the reset would change, and change nothing.
    #[serde(default)]
    preview: bool,
}

/// One property a reset changes.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ResetChangeView {
    property: String,
    /// The customer's value now.
    #[schema(value_type = Object)]
    current: Value,
    /// The value after the reset: an app's, else the platform's; `null` when
    /// no lower layer recorded one, so the property is left as it is.
    #[schema(value_type = Option<Object>)]
    after: Option<Value>,
}

/// A reset, or its preview.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ResetView {
    /// The reset to undo; absent for a preview.
    reset_id: Option<Uuid>,
    changes: Vec<ResetChangeView>,
}

fn change_views(changes: Vec<layer_reset::ResetChange>) -> Vec<ResetChangeView> {
    changes
        .into_iter()
        .map(|c| ResetChangeView {
            property: c.property,
            current: c.current,
            after: c.after,
        })
        .collect()
}

/// Reset a customisation
///
/// Puts an entity's or a field's customised properties (all, or the ones named) back to what an app or the platform gives them, removing the customer's values; with `preview=true`, only answers what would change. Undo with the reset id.
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/{kind}/{key}/reset",
    tag = "admin",
    params(
        ("kind" = String, Path, description = "`entity` or `attribute`"),
        ("key" = String, Path, description = "The entity's logical name, or `<entity>.<field>`"),
        ResetQuery,
    ),
    request_body = ResetBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "What the reset changed, or would change", body = ResetView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity or field, or nothing to reset", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn reset_customisation(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path((kind, key)): Path<(String, String)>,
    Query(query): Query<ResetQuery>,
    Json(body): Json<ResetBody>,
) -> Result<Json<ResetView>, AppError> {
    // The item must exist, as for its layer stack.
    stack_of(&state, &kind, &key).await?;
    let properties = body.properties;
    if query.preview {
        let changes =
            layer_reset::preview(&state.base.db, &kind, &key, properties.as_deref()).await?;
        return Ok(Json(ResetView {
            reset_id: None,
            changes: change_views(changes),
        }));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (reset_id, changes) =
        layer_reset::reset_in_tx(&mut tx, &kind, &key, properties.as_deref(), ctx.user_id).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_layer_reset",
            Some(reset_id),
        )
        .named("metadata.customisation.reset")
        .comment(format!(
            "{kind} {key}: {}",
            changes
                .iter()
                .map(|c| c.property.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::admin::notify_metadata_change(&state.base.redis).await;
    Ok(Json(ResetView {
        reset_id: Some(reset_id),
        changes: change_views(changes),
    }))
}

/// Undo a reset
///
/// Puts back the customer's values a reset removed, once. Refused when the item was customised again since.
#[utoipa::path(
    post,
    path = "/api/v1/admin/metadata/resets/{reset_id}/undo",
    tag = "admin",
    params(("reset_id" = Uuid, Path, description = "The reset's id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "The customer's values are back"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such reset, or its item is gone", body = ErrorResponse),
        (status = 409, description = "Already undone, or the item was customised again", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn undo_reset(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(reset_id): Path<Uuid>,
) -> Result<axum::http::StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (kind, key) = layer_reset::undo_in_tx(&mut tx, reset_id, ctx.user_id).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "metadata_layer_reset",
            Some(reset_id),
        )
        .named("metadata.customisation.reset_undone")
        .comment(format!("{kind} {key}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::admin::notify_metadata_change(&state.base.redis).await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct UpgradeImpactQuery {
    /// The platform (or app) changeset to check, planned or applied.
    changeset_id: Uuid,
}

/// A customisation a release affects.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct UpgradeImpactView {
    /// `entity` or `attribute`.
    object_kind: String,
    /// The item it was made on: the entity's logical name, or `<entity>.<field>`.
    object_key: String,
    property: String,
    /// `customer` or `app`.
    layer: String,
    app: String,
    /// Where it would apply after the release: the renamed item's key; absent for a removal.
    suggested_key: Option<String>,
}

/// Customisations a release affects
///
/// Y11-T12: for a platform or app changeset (planned or applied), each customer or app customisation on an entity or field it retires, deletes or renames, with the new name for a rename. Nothing is moved.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/upgrade-impact",
    tag = "admin",
    params(UpgradeImpactQuery),
    responses(
        (status = 200, description = "Every affected customisation, whole on page 1", body = PaginatedResponse<UpgradeImpactView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No planned or applied changeset with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn upgrade_impact(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(query): Query<UpgradeImpactQuery>,
) -> Result<Json<PaginatedResponse<UpgradeImpactView>>, AppError> {
    let document: Value = sqlx::query_scalar(
        "SELECT document FROM changeset_apply WHERE changeset_id = $1 \
          ORDER BY seq DESC, id DESC LIMIT 1",
    )
    .bind(query.changeset_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let ops = document
        .get("operations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let (removed, renamed) = layer_impact::affected_items(&ops);
    let impacts = layer_impact::deprecation_impact(&state.base.db, &removed, &renamed).await?;
    Ok(Json(page(
        impacts
            .into_iter()
            .map(|i| UpgradeImpactView {
                object_kind: i.object_kind,
                object_key: i.object_key,
                property: i.property,
                layer: i.layer,
                app: i.app,
                suggested_key: i.suggested_key,
            })
            .collect(),
    )))
}

/// Installed apps in layer order
///
/// Y11-T11: every installed app (a pack's product changesets) and its place in the layer order; a later app sits above an earlier one, and the customer above all apps.
#[utoipa::path(
    get,
    path = "/api/v1/admin/metadata/app-layers",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "One page of installed apps, first installed first", body = PaginatedResponse<attome_metadata::provision::app_layers::AppLayer>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_app_layers(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<attome_metadata::provision::app_layers::AppLayer>>, AppError> {
    let window = page.window();
    let (items, total) = attome_metadata::provision::app_layers::list(
        &state.base.db,
        window.page_size,
        window.offset,
    )
    .await?;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: window.page,
        page_size: window.page_size,
        warnings: Vec::new(),
    }))
}

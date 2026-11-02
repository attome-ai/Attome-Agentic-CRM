//! F6-T15: where is my order.
//!
//! `GET /{keyword}/api/v1/fulfilment/orders/{order_id}` answers a signed-in
//! portal user an order's lines with their status, shipments and tracking
//! numbers (`attome_fulfilment::customer_updates::portal_order`), only for
//! an order of their own account: the account comes from the portal user's
//! contact, never from the request. 404 while the fulfilment module or the
//! setting `fulfilment.portal` is off, for a user with no account, and for
//! any other account's order alike, so the route reveals nothing.

use attome_core::EngineState;
use attome_fulfilment::order_view::OrderFulfilment;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
};
use uuid::Uuid;

use super::{authenticate, portal_for};

/// The account of the portal user's contact (also the subscriptions route's).
pub(super) async fn account_of(state: &EngineState, user: Uuid) -> Result<Option<Uuid>, AppError> {
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = current_schema() \
                           AND table_name = 'webportal_user' AND column_name = 'contact_ref')",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(None);
    }
    sqlx::query_scalar(
        "SELECT c.account_ref FROM webportal_user u \
           JOIN contact c ON c.id = u.contact_ref \
          WHERE u.id = $1 AND (c.is_active IS NULL OR c.is_active = true)",
    )
    .bind(user)
    .fetch_optional(&state.base.db)
    .await
    .map(Option::flatten)
    .map_err(AppError::internal)
}

/// Where is my order
///
/// F6-T15: one of the signed-in person's own account's orders, line by line, with the shipments
/// and tracking numbers carrying each line.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/fulfilment/orders/{order_id}",
    operation_id = "portal_fulfilment_order",
    tag = "fulfilment",
    params(
        ("keyword" = String, Path, description = "The portal"),
        ("order_id" = Uuid, Path, description = "The sales order"),
    ),
    responses(
        (status = 200, description = "The order's lines and shipments", body = OrderFulfilment),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "No such order of the person's account, or the route is off", body = ErrorResponse),
    ),
)]
async fn portal_order(
    State(state): State<EngineState>,
    Path((keyword, order_id)): Path<(String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<OrderFulfilment>, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_FULFILMENT)
        || !attome_fulfilment::customer_updates::portal_on(&state)
    {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    let account = account_of(&state, principal.user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    attome_fulfilment::customer_updates::portal_order(&state, account, order_id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/{keyword}/api/v1/fulfilment/orders/{order_id}",
        get(portal_order),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(portal_order), components(schemas(OrderFulfilment)))]
pub(super) struct FulfilmentApiDoc;

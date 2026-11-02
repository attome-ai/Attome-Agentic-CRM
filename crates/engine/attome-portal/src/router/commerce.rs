//! F7-T1: the portal shop over `attome_sales::commerce`.
//!
//! - `GET /{keyword}/api/v1/shop/catalogue?search=`: the products on sale to
//!   the portal user's account, priced for it.
//! - `GET /{keyword}/api/v1/shop/cart` and
//!   `PUT /{keyword}/api/v1/shop/cart/lines/{product_id}` `{quantity}` (0
//!   removes): the portal user's own open cart.
//! - `GET /{keyword}/api/v1/shop/orders`: the account's orders, newest
//!   first (each one's lines and tracking: the F6-T15 order route).
//! - `POST /{keyword}/api/v1/shop/cart/checkout`: a draft order for the
//!   account, written as the portal's service user (V2-D1588 (1)), with an
//!   approval request above the shop's limit.
//!
//! The account always comes from the portal user's contact. 404 while the
//! sales module or `commerce.enabled` is off, for a user with no account,
//! and, for checkout, while the portal has no service user.

use attome_core::EngineState;
use attome_sales::commerce::{Cart, CatalogueItem, CheckedOut, ShopOrder};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use serde::Deserialize;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::fulfilment::account_of;
use super::{authenticate, portal_for};

/// The signed-in portal user and their account, while the shop is open.
async fn shopper(
    state: &EngineState,
    keyword: &str,
    headers: &HeaderMap,
) -> Result<(crate::provision::PortalDetail, Uuid, Uuid), AppError> {
    if !state.modules.load().has(attome_modules::MODULE_SALES)
        || !attome_sales::commerce::enabled(state)
    {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(state, keyword).await?;
    let principal = authenticate(state, &portal, headers, false).await?;
    let account = account_of(state, principal.user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((portal, principal.user_id, account))
}

/// F8-T6: a coupon to apply at checkout.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CheckoutQuery {
    /// A coupon code.
    pub coupon: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CatalogueQuery {
    /// Part of a product's name or SKU.
    pub search: Option<String>,
}

/// The shop's catalogue
///
/// F7-T1: the products on sale to the signed-in person's account, priced for it.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/shop/catalogue",
    operation_id = "portal_shop_catalogue",
    tag = "sales",
    params(("keyword" = String, Path, description = "The portal"), CatalogueQuery),
    responses(
        (status = 200, description = "The products on sale", body = Vec<CatalogueItem>),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "The shop is off, or the person has no account", body = ErrorResponse),
    ),
)]
async fn catalogue(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    Query(q): Query<CatalogueQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<CatalogueItem>>, AppError> {
    let (_, _, account) = shopper(&state, &keyword, &headers).await?;
    Ok(Json(
        attome_sales::commerce::catalogue(&state, account, q.search.as_deref()).await?,
    ))
}

/// My cart
///
/// F7-T1: the signed-in person's open cart, priced now.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/shop/cart",
    operation_id = "portal_shop_cart",
    tag = "sales",
    params(("keyword" = String, Path, description = "The portal")),
    responses(
        (status = 200, description = "The cart", body = Cart),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "The shop is off, or the person has no account", body = ErrorResponse),
    ),
)]
async fn my_cart(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Cart>, AppError> {
    let (_, user, account) = shopper(&state, &keyword, &headers).await?;
    Ok(Json(
        attome_sales::commerce::cart(&state, user, account).await?,
    ))
}

/// A cart line's quantity.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CartQuantity {
    /// A decimal in text; 0 removes the line.
    pub quantity: String,
}

/// Set a cart line
///
/// F7-T1: puts a product on sale into the signed-in person's cart at a quantity, or removes it.
#[utoipa::path(
    put,
    path = "/{keyword}/api/v1/shop/cart/lines/{product_id}",
    operation_id = "portal_shop_cart_line",
    tag = "sales",
    params(
        ("keyword" = String, Path, description = "The portal"),
        ("product_id" = Uuid, Path, description = "The product"),
    ),
    request_body = CartQuantity,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::UserPreference,
        None,
        "a portal user's own cart: a product and a quantity, no price and no business effect \
         until checkout, which writes the order and its audited event"
    )))),
    responses(
        (status = 200, description = "The cart", body = Cart),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "The shop is off, or the product is not on sale to the account", body = ErrorResponse),
        (status = 422, description = "Not a quantity", body = ErrorResponse),
    ),
)]
async fn set_line(
    State(state): State<EngineState>,
    Path((keyword, product)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<CartQuantity>,
) -> Result<Json<Cart>, AppError> {
    let (_, user, account) = shopper(&state, &keyword, &headers).await?;
    let quantity = attome_billing::subscription::portal::parse_quantity(&body.quantity)?;
    Ok(Json(
        attome_sales::commerce::set_line(&state, user, account, product, quantity).await?,
    ))
}

/// Check out
///
/// F7-T1: turns the signed-in person's cart into a draft order for their account, re-priced now,
/// with an approval request above the shop's limit.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/shop/cart/checkout",
    operation_id = "portal_shop_checkout",
    tag = "sales",
    params(("keyword" = String, Path, description = "The portal"), CheckoutQuery),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The order made", body = CheckedOut),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "The shop is off, the person has no account, or the portal has no service user", body = ErrorResponse),
        (status = 409, description = "The cart is being checked out already, or the coupon is used up or busy", body = ErrorResponse),
        (status = 422, description = "The cart is empty, a product is no longer on sale, or the coupon does not apply", body = ErrorResponse),
    ),
)]
async fn checkout(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    Query(query): Query<CheckoutQuery>,
    headers: HeaderMap,
) -> Result<Json<CheckedOut>, AppError> {
    let (portal, user, account) = shopper(&state, &keyword, &headers).await?;
    // `shopper` found the account through the person's contact, so the
    // column is there.
    let contact: Option<Uuid> =
        sqlx::query_scalar("SELECT contact_ref FROM webportal_user WHERE id = $1")
            .bind(user)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let service_user = crate::provision::service_user(&state.base.db, portal.id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ctx = state.base.security.resolve_strict(service_user).await?;
    Ok(Json(
        attome_sales::commerce::checkout(
            &state,
            &ctx,
            &format!("portal user {user}"),
            user,
            account,
            contact,
            query.coupon.as_deref(),
        )
        .await?,
    ))
}

/// My account's orders
///
/// F7-T2: the signed-in person's account's orders, newest first.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/shop/orders",
    operation_id = "portal_shop_orders",
    tag = "sales",
    params(("keyword" = String, Path, description = "The portal")),
    responses(
        (status = 200, description = "The account's orders", body = Vec<ShopOrder>),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "The shop is off, or the person has no account", body = ErrorResponse),
    ),
)]
async fn my_orders(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<ShopOrder>>, AppError> {
    let (_, _, account) = shopper(&state, &keyword, &headers).await?;
    Ok(Json(attome_sales::commerce::orders(&state, account).await?))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/{keyword}/api/v1/shop/catalogue", get(catalogue))
        .route("/{keyword}/api/v1/shop/cart", get(my_cart))
        .route(
            "/{keyword}/api/v1/shop/cart/lines/{product_id}",
            put(set_line),
        )
        .route("/{keyword}/api/v1/shop/cart/checkout", post(checkout))
        .route("/{keyword}/api/v1/shop/orders", get(my_orders))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(catalogue, my_cart, set_line, checkout, my_orders),
    components(schemas(
        CatalogueItem,
        Cart,
        attome_sales::commerce::CartLine,
        CartQuantity,
        CheckedOut,
        ShopOrder
    ))
)]
pub(super) struct CommerceApiDoc;

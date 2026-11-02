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
//! - `GET /{keyword}/api/v1/shop/shipping?country=&city=&total=`: the ways
//!   to ship an order of that total to an address (F8-T7).
//! - `POST /{keyword}/api/v1/shop/guest/start` `{phone, lines}` and
//!   `POST /{keyword}/api/v1/shop/guest/confirm` (with `Idempotency-Key`):
//!   checkout without a portal account, proved by a code texted to the
//!   phone (`attome_sales::guest_checkout`), same-origin and limited per
//!   address; confirm writes as the portal's service user.
//!
//! The account always comes from the portal user's contact. 404 while the
//! sales module or `commerce.enabled` is off, for a user with no account,
//! and, for checkout, while the portal has no service user.

use attome_core::EngineState;
use attome_sales::commerce::{Cart, CatalogueItem, CheckedOut, ShopOrder};
use attome_sales::guest_checkout::{Confirm, GuestLine, GuestOrder, Started};
use attome_sales::shipping::ShippingOption;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::HeaderMap,
    routing::{get, post, put},
};
use serde::Deserialize;
use std::net::SocketAddr;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::fulfilment::account_of;
use super::{authenticate, budget, check_same_origin, portal_budget, portal_for};

/// Guest checkout starts and confirms per address and minute.
const GUEST_IP_RPM: i32 = 10;

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
        .route("/{keyword}/api/v1/shop/shipping", get(shipping))
        .route("/{keyword}/api/v1/shop/guest/start", post(guest_start))
        .route("/{keyword}/api/v1/shop/guest/confirm", post(guest_confirm))
        .route("/{keyword}/api/v1/shop/reviews", post(submit_review))
        .route(
            "/{keyword}/api/v1/shop/products/{product_id}/reviews",
            get(product_reviews),
        )
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReviewBody {
    pub product_id: Uuid,
    /// 1 to 5.
    pub rating: i32,
    pub body: Option<String>,
}

/// The review taken.
#[derive(Debug, serde::Serialize, ToSchema)]
pub struct ReviewTaken {
    pub review_id: Uuid,
    /// Always `pending`: a store person publishes it.
    pub status: String,
}

/// Review a product
///
/// F8-T8: a portal member reviews a product they received (a fulfilled order of it); the review waits
/// for a store person to publish it.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/shop/reviews",
    operation_id = "portal_shop_review",
    tag = "sales",
    params(("keyword" = String, Path, description = "The portal")),
    request_body = ReviewBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Taken, pending", body = ReviewTaken),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 403, description = "Not a buyer of the product", body = ErrorResponse),
        (status = 404, description = "The shop is off, the person has no account, or the portal has no service user", body = ErrorResponse),
        (status = 409, description = "The product has the person's review already", body = ErrorResponse),
        (status = 422, description = "Rating not 1 to 5, or the text is too long", body = ErrorResponse),
    ),
)]
async fn submit_review(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ReviewBody>,
) -> Result<Json<ReviewTaken>, AppError> {
    let (portal, user, _) = shopper(&state, &keyword, &headers).await?;
    let contact: Uuid = sqlx::query_scalar("SELECT contact_ref FROM webportal_user WHERE id = $1")
        .bind(user)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .flatten()
        .ok_or(AppError::Forbidden)?;
    let service_user = crate::provision::service_user(&state.base.db, portal.id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ctx = state.base.security.resolve_strict(service_user).await?;
    let review_id = attome_sales::review::submit(
        &state,
        &ctx,
        &format!("portal user {user}"),
        contact,
        body.product_id,
        body.rating,
        body.body.as_deref(),
    )
    .await?;
    Ok(Json(ReviewTaken {
        review_id,
        status: "pending".into(),
    }))
}

/// A product's reviews
///
/// F8-T8: the published reviews of a product, newest first, without names.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/shop/products/{product_id}/reviews",
    operation_id = "portal_shop_product_reviews",
    tag = "sales",
    params(
        ("keyword" = String, Path, description = "The portal"),
        ("product_id" = Uuid, Path, description = "The product"),
    ),
    responses(
        (status = 200, description = "Published reviews", body = Vec<attome_sales::review::PublicReview>),
        (status = 404, description = "The shop is off, or no such portal", body = ErrorResponse),
    ),
)]
async fn product_reviews(
    State(state): State<EngineState>,
    Path((keyword, product)): Path<(String, Uuid)>,
) -> Result<Json<Vec<attome_sales::review::PublicReview>>, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_SALES)
        || !attome_sales::commerce::enabled(&state)
    {
        return Err(AppError::NotFound);
    }
    portal_for(&state, &keyword).await?;
    Ok(Json(
        attome_sales::review::published(&state, product).await?,
    ))
}

/// F8-T7: an open shop on `keyword` for a guest, its per-address budget
/// spent.
async fn guest_portal(
    state: &EngineState,
    keyword: &str,
    headers: &HeaderMap,
    connect: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
) -> Result<crate::provision::PortalDetail, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_SALES)
        || !attome_sales::guest_checkout::enabled(state)
    {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(state, keyword).await?;
    check_same_origin(state, &portal, headers)?;
    portal_budget(state, &portal).await?;
    if let Some(c) = connect {
        let ip = attome_server::middleware::client_ip::client_ip_from_parts(
            c.0.0.ip(),
            headers,
            &state.base.config,
        );
        budget(
            state,
            format!("attome-portal:rl:guest-checkout:{}:{ip}", portal.id),
            GUEST_IP_RPM,
        )
        .await?;
    }
    Ok(portal)
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ShippingQuery {
    /// ISO 3166-1 alpha-2.
    pub country: String,
    pub city: Option<String>,
    /// The order's total, a decimal (for free-over rates).
    pub total: Option<String>,
}

/// Shipping options
///
/// F8-T7: the ways to ship an order of `total` to the address, cheapest first; cash on delivery adds each
/// option's `cod_fee`.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/shop/shipping",
    operation_id = "portal_shop_shipping",
    tag = "sales",
    params(("keyword" = String, Path, description = "The portal"), ShippingQuery),
    responses(
        (status = 200, description = "The options", body = Vec<ShippingOption>),
        (status = 404, description = "The shop is off, or no such portal", body = ErrorResponse),
    ),
)]
async fn shipping(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    Query(query): Query<ShippingQuery>,
) -> Result<Json<Vec<ShippingOption>>, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_SALES)
        || !attome_sales::commerce::enabled(&state)
    {
        return Err(AppError::NotFound);
    }
    portal_for(&state, &keyword).await?;
    Ok(Json(
        attome_sales::shipping::quote_for_address(
            &state,
            &query.country,
            query.city.as_deref(),
            query.total.as_deref(),
        )
        .await?,
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct GuestStart {
    pub phone: String,
    pub lines: Vec<GuestLine>,
}

/// Start a guest checkout
///
/// F8-T7: keeps the lines and texts a 6-digit code to the phone; the code works for 10 minutes.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/shop/guest/start",
    operation_id = "portal_shop_guest_start",
    tag = "sales",
    params(("keyword" = String, Path, description = "The portal")),
    request_body = GuestStart,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::UserPreference, None, "F8-T7: keeps an unconfirmed guest basket and texts its code; nothing is ordered until confirm, which is audited")))),
    responses(
        (status = 200, description = "The code was sent", body = Started),
        (status = 403, description = "Not from the portal's own origin", body = ErrorResponse),
        (status = 404, description = "Guest checkout is off, or no such portal", body = ErrorResponse),
        (status = 422, description = "Not a phone number, a product not on sale, or no SMS provider", body = ErrorResponse),
        (status = 429, description = "Too many codes for the phone or the address", body = ErrorResponse),
    ),
)]
async fn guest_start(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    connect: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<GuestStart>,
) -> Result<Json<Started>, AppError> {
    let portal = guest_portal(&state, &keyword, &headers, connect).await?;
    Ok(Json(
        attome_sales::guest_checkout::start(&state, portal.id, &body.phone, &body.lines).await?,
    ))
}

/// Confirm a guest checkout
///
/// F8-T7: with the texted code, places the order: prices, offers, shipping and VAT recomputed here. The
/// same `Idempotency-Key` again returns the same order.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/shop/guest/confirm",
    operation_id = "portal_shop_guest_confirm",
    tag = "sales",
    params(
        ("keyword" = String, Path, description = "The portal"),
        ("Idempotency-Key" = String, Header, description = "One key per order"),
    ),
    request_body = Confirm,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The order", body = GuestOrder),
        (status = 401, description = "Wrong, expired or exhausted code", body = ErrorResponse),
        (status = 403, description = "Not from the portal's own origin", body = ErrorResponse),
        (status = 404, description = "Guest checkout is off, or the portal has no service user", body = ErrorResponse),
        (status = 409, description = "The code was used already, or the order is being placed", body = ErrorResponse),
        (status = 422, description = "No Idempotency-Key, a product no longer on sale, a shipping rate that does not apply, or a coupon that does not", body = ErrorResponse),
        (status = 429, description = "Too many tries from the address", body = ErrorResponse),
    ),
)]
async fn guest_confirm(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    connect: Option<axum::Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<Confirm>,
) -> Result<Json<GuestOrder>, AppError> {
    let portal = guest_portal(&state, &keyword, &headers, connect).await?;
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let service_user = crate::provision::service_user(&state.base.db, portal.id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ctx = state.base.security.resolve_strict(service_user).await?;
    Ok(Json(
        attome_sales::guest_checkout::confirm(&state, &ctx, portal.id, &key, &body).await?,
    ))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        catalogue,
        my_cart,
        set_line,
        checkout,
        my_orders,
        shipping,
        guest_start,
        guest_confirm,
        submit_review,
        product_reviews
    ),
    components(schemas(
        ReviewBody,
        ReviewTaken,
        attome_sales::review::PublicReview,
        ShippingOption,
        GuestStart,
        GuestLine,
        Started,
        Confirm,
        GuestOrder,
        CatalogueItem,
        Cart,
        attome_sales::commerce::CartLine,
        CartQuantity,
        CheckedOut,
        ShopOrder
    ))
)]
pub(super) struct CommerceApiDoc;

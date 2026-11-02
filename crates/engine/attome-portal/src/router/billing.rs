//! F3-T13 and F5-T14, read parts: a portal user's own account's subscriptions,
//! open invoices and saved payment methods.
//!
//! `GET /{keyword}/api/v1/billing/subscriptions` answers each subscription
//! of the signed-in portal user's account (from their contact, never from
//! the request) with its lines in force and its coming charges
//! (`attome_billing::subscription::portal`). 404 while the billing module
//! or the setting `billing.portal.subscriptions` is off, and for a user
//! with no account.
//!
//! `GET /{keyword}/api/v1/billing/invoices/open` and
//! `GET /{keyword}/api/v1/billing/payment-methods`
//! (`attome_billing::payment::portal`) answer the account's issued invoices
//! with an amount open and its saved payment methods without their tokens,
//! while `billing.portal.payments` is on; 404 otherwise.

use attome_billing::payment::portal::{PortalInvoice, PortalPaymentMethod};
use attome_billing::subscription::portal::PortalSubscription;
use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
};

use super::fulfilment::account_of;
use super::{authenticate, portal_for};

/// My subscriptions
///
/// F3-T13: the signed-in person's own account's subscriptions, with the lines in force today and
/// the charges still to come.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/billing/subscriptions",
    operation_id = "portal_billing_subscriptions",
    tag = "billing",
    params(("keyword" = String, Path, description = "The portal")),
    responses(
        (status = 200, description = "The account's subscriptions", body = Vec<PortalSubscription>),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "The route is off, or the person has no account", body = ErrorResponse),
    ),
)]
async fn my_subscriptions(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<PortalSubscription>>, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_BILLING)
        || !attome_billing::subscription::portal::portal_on(&state)
    {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    let account = account_of(&state, principal.user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(
        attome_billing::subscription::portal::for_account(&state, account).await?,
    ))
}

/// The signed-in person's account, while the payments routes are open.
async fn payments_account(
    state: &EngineState,
    keyword: &str,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_BILLING)
        || !attome_billing::payment::portal::portal_on(state)
    {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(state, keyword).await?;
    let principal = authenticate(state, &portal, headers, false).await?;
    account_of(state, principal.user_id)
        .await?
        .ok_or(AppError::NotFound)
}

/// My open invoices
///
/// F5-T14: the signed-in person's own account's issued invoices with an amount still open, oldest
/// due first.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/billing/invoices/open",
    operation_id = "portal_billing_open_invoices",
    tag = "billing",
    params(("keyword" = String, Path, description = "The portal")),
    responses(
        (status = 200, description = "The account's open invoices", body = Vec<PortalInvoice>),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "The route is off, or the person has no account", body = ErrorResponse),
    ),
)]
async fn my_open_invoices(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<PortalInvoice>>, AppError> {
    let account = payments_account(&state, &keyword, &headers).await?;
    Ok(Json(
        attome_billing::payment::portal::open_invoices(&state, account).await?,
    ))
}

/// My payment methods
///
/// F5-T14: the signed-in person's own account's saved payment methods: brand, last four digits,
/// expiry and which is the default. Never a token.
#[utoipa::path(
    get,
    path = "/{keyword}/api/v1/billing/payment-methods",
    operation_id = "portal_billing_payment_methods",
    tag = "billing",
    params(("keyword" = String, Path, description = "The portal")),
    responses(
        (status = 200, description = "The account's saved payment methods", body = Vec<PortalPaymentMethod>),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "The route is off, or the person has no account", body = ErrorResponse),
    ),
)]
async fn my_payment_methods(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<PortalPaymentMethod>>, AppError> {
    let account = payments_account(&state, &keyword, &headers).await?;
    Ok(Json(
        attome_billing::payment::portal::payment_methods(&state, account).await?,
    ))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/{keyword}/api/v1/billing/subscriptions",
            get(my_subscriptions),
        )
        .route(
            "/{keyword}/api/v1/billing/invoices/open",
            get(my_open_invoices),
        )
        .route(
            "/{keyword}/api/v1/billing/payment-methods",
            get(my_payment_methods),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(my_subscriptions, my_open_invoices, my_payment_methods),
    components(schemas(PortalSubscription, PortalInvoice, PortalPaymentMethod))
)]
pub(super) struct BillingApiDoc;

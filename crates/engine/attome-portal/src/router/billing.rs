//! F3-T13 and F5-T14: a portal user's own account's subscriptions, open
//! invoices and saved payment methods, and the subscription changes they may
//! make.
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
//!
//! `POST /{keyword}/api/v1/billing/subscriptions/{id}/quantity` and
//! `.../{id}/cancel` change one of the account's subscriptions (a line's
//! quantity within its portal bounds, from today; cancelling at the end of
//! the term only) through the subscription service as the portal's service
//! user (`webportal.service_user_ref`, V2-D1588 (1)), the audit event naming
//! the portal user. 404 while `billing.portal.subscriptions` is off, for
//! another account's subscription, and while the portal has no service user.

use attome_billing::payment::portal::{PortalInvoice, PortalPaymentMethod};
use attome_billing::subscription::portal::PortalSubscription;
use attome_core::EngineState;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

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

/// A quantity change.
#[derive(Debug, Deserialize, ToSchema)]
pub struct QuantityChange {
    /// The subscription line.
    pub line_id: Uuid,
    /// The new quantity, a decimal in text, within the line's portal bounds.
    pub quantity: String,
}

/// What a quantity change did.
#[derive(Debug, Serialize, ToSchema)]
pub struct QuantityChanged {
    pub amendment_id: Uuid,
    /// Prorations or credits planned for the rest of the period.
    pub charges: usize,
}

/// A cancellation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PortalCancel {
    /// `price`, `product_fit`, `budget`, `switched_vendor` or `other`.
    pub reason: String,
}

/// When a cancelled subscription ends.
#[derive(Debug, Serialize, ToSchema)]
pub struct PortalCancelled {
    pub ends_on: chrono::NaiveDate,
}

/// The account, the portal user to name and the service user's context.
type Acting = (
    Uuid,
    String,
    std::sync::Arc<attome_server::security::SecurityContext>,
);

/// The signed-in person's account, the portal user to name, and the
/// portal's service user resolved, while the subscription routes are open.
async fn acting(
    state: &EngineState,
    keyword: &str,
    headers: &HeaderMap,
) -> Result<Acting, AppError> {
    if !state.modules.load().has(attome_modules::MODULE_BILLING)
        || !attome_billing::subscription::portal::portal_on(state)
    {
        return Err(AppError::NotFound);
    }
    let portal = portal_for(state, keyword).await?;
    let principal = authenticate(state, &portal, headers, false).await?;
    let account = account_of(state, principal.user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let service_user = crate::provision::service_user(&state.base.db, portal.id)
        .await?
        .ok_or(AppError::NotFound)?;
    let ctx = state.base.security.resolve_strict(service_user).await?;
    Ok((account, format!("portal user {}", principal.user_id), ctx))
}

/// Change a subscription line's quantity
///
/// F3-T13: sets one line of the signed-in person's own account's subscription to a quantity within
/// the line's portal bounds, from today, prorated, at the price in force.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/billing/subscriptions/{id}/quantity",
    operation_id = "portal_billing_subscription_quantity",
    tag = "billing",
    params(
        ("keyword" = String, Path, description = "The portal"),
        ("id" = Uuid, Path, description = "The subscription"),
    ),
    request_body = QuantityChange,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Changed", body = QuantityChanged),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "No such subscription of the person's account, or the route is off", body = ErrorResponse),
        (status = 409, description = "Another change to the subscription is in progress", body = ErrorResponse),
        (status = 422, description = "The line cannot be changed on the portal, or the quantity is outside its bounds", body = ErrorResponse),
    ),
)]
async fn change_quantity(
    State(state): State<EngineState>,
    Path((keyword, id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<QuantityChange>,
) -> Result<Json<QuantityChanged>, AppError> {
    let (account, behalf, ctx) = acting(&state, &keyword, &headers).await?;
    let quantity = attome_billing::subscription::portal::parse_quantity(&body.quantity)?;
    let done = attome_billing::subscription::portal::change_quantity(
        &state,
        &ctx,
        &behalf,
        account,
        id,
        body.line_id,
        quantity,
    )
    .await?;
    Ok(Json(QuantityChanged {
        amendment_id: done.amendment_id,
        charges: done.charges,
    }))
}

/// Cancel a subscription at the end of its term
///
/// F3-T13: cancels one of the signed-in person's own account's subscriptions at the end of its term;
/// never at once.
#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/billing/subscriptions/{id}/cancel",
    operation_id = "portal_billing_subscription_cancel",
    tag = "billing",
    params(
        ("keyword" = String, Path, description = "The portal"),
        ("id" = Uuid, Path, description = "The subscription"),
    ),
    request_body = PortalCancel,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Cancelled from the end of the term", body = PortalCancelled),
        (status = 401, description = "Not signed in to the portal", body = ErrorResponse),
        (status = 404, description = "No such subscription of the person's account, or the route is off", body = ErrorResponse),
        (status = 409, description = "Another change to the subscription is in progress", body = ErrorResponse),
        (status = 422, description = "Not a reason, already cancelled, or a subscription with no term end", body = ErrorResponse),
    ),
)]
async fn cancel(
    State(state): State<EngineState>,
    Path((keyword, id)): Path<(String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<PortalCancel>,
) -> Result<Json<PortalCancelled>, AppError> {
    let (account, behalf, ctx) = acting(&state, &keyword, &headers).await?;
    let ends_on = attome_billing::subscription::portal::cancel_at_term_end(
        &state,
        &ctx,
        &behalf,
        account,
        id,
        body.reason.trim(),
    )
    .await?;
    Ok(Json(PortalCancelled { ends_on }))
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
        .route(
            "/{keyword}/api/v1/billing/subscriptions/{id}/quantity",
            post(change_quantity),
        )
        .route(
            "/{keyword}/api/v1/billing/subscriptions/{id}/cancel",
            post(cancel),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        my_subscriptions,
        my_open_invoices,
        my_payment_methods,
        change_quantity,
        cancel
    ),
    components(schemas(
        PortalSubscription,
        PortalInvoice,
        PortalPaymentMethod,
        QuantityChange,
        QuantityChanged,
        PortalCancel,
        PortalCancelled
    ))
)]
pub(super) struct BillingApiDoc;

//! F3-T13, read part: a portal user's own account's subscriptions.
//!
//! `GET /{keyword}/api/v1/billing/subscriptions` answers each subscription
//! of the signed-in portal user's account (from their contact, never from
//! the request) with its lines in force and its coming charges
//! (`attome_billing::subscription::portal`). 404 while the billing module
//! or the setting `billing.portal.subscriptions` is off, and for a user
//! with no account.

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

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/{keyword}/api/v1/billing/subscriptions",
        get(my_subscriptions),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(my_subscriptions), components(schemas(PortalSubscription)))]
pub(super) struct BillingApiDoc;

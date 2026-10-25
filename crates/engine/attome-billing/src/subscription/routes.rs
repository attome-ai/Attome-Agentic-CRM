//! The subscription routes (roadmap F3-T6): thin handlers over
//! [`super::service`]. Each parses its body, calls the service and shapes
//! the answer; the service checks the caller (`subscription.create`,
//! `.update`, `.cancel`, `.amend_price` for a new price) and takes the
//! subscription's lock.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use rust_decimal::prelude::FromPrimitive;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::schedule::{Alignment, Cadence, Timing};
use super::segments::ChangeKind;
use super::service::{self, SubscriptionAsOf};

#[derive(Debug, Deserialize, ToSchema)]
pub struct BillingNewLineBody {
    pub product_ref: Uuid,
    pub quantity: f64,
    pub unit_price: f64,
    /// `flat`, `per_unit` (the default), `tiered`, `volume`, `setup_fee` or
    /// `minimum_commitment`.
    #[serde(default)]
    pub charge_model: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BillingCreateSubscriptionBody {
    pub name: String,
    pub account_ref: Uuid,
    pub currency: String,
    pub start_date: NaiveDate,
    #[serde(default)]
    pub end_date: Option<NaiveDate>,
    #[serde(default)]
    pub term_months: Option<i32>,
    /// `monthly` (the default), `quarterly` or `yearly`.
    #[serde(default)]
    pub billing_frequency: Option<String>,
    /// `advance` (the default) or `arrears`.
    #[serde(default)]
    pub billing_timing: Option<String>,
    /// `anniversary` (the default) or `calendar_month`.
    #[serde(default)]
    pub billing_alignment: Option<String>,
    /// Copies an accepted quote's lines instead of `lines`.
    #[serde(default)]
    pub quote_id: Option<Uuid>,
    /// From an order (refused until order lines carry a line type).
    #[serde(default)]
    pub order_id: Option<Uuid>,
    #[serde(default)]
    pub lines: Vec<BillingNewLineBody>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BillingSubscriptionCreated {
    pub id: Uuid,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BillingLineChangeBody {
    pub line_id: Uuid,
    pub quantity: f64,
    pub unit_price: f64,
    /// `add`, `remove`, `upgrade`, `downgrade` or `price_change`.
    pub kind: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BillingAmendmentBody {
    pub effective: NaiveDate,
    pub changes: Vec<BillingLineChangeBody>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BillingAmended {
    pub amendment_id: Uuid,
    pub segments_opened: usize,
    pub charges: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BillingCancelBody {
    /// Cancel at the end of the term instead of on `on`.
    #[serde(default)]
    pub at_term_end: bool,
    #[serde(default)]
    pub on: Option<NaiveDate>,
    /// `price`, `product_fit`, `budget`, `switched_vendor` or `other`.
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BillingCancelled {
    pub effective: NaiveDate,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BillingPauseBody {
    pub from: NaiveDate,
    #[serde(default)]
    pub resume_on: Option<NaiveDate>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BillingResumeBody {
    pub on: NaiveDate,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BillingSubscriptionChanged {
    pub status: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct BillingAsOfQuery {
    /// The day to read the subscription as of (`YYYY-MM-DD`); today when absent.
    pub as_of: Option<NaiveDate>,
}

fn decimal(value: f64, field: &str) -> Result<Decimal, AppError> {
    Decimal::from_f64(value)
        .filter(|d| !d.is_sign_negative())
        .ok_or_else(|| AppError::Validation(format!("{field} must be a number of 0 or more")))
}

fn cadence(value: Option<&str>) -> Result<Cadence, AppError> {
    match value.unwrap_or("monthly") {
        "monthly" => Ok(Cadence::Monthly),
        "quarterly" => Ok(Cadence::Quarterly),
        "yearly" => Ok(Cadence::Yearly),
        other => Err(AppError::Validation(format!(
            "billing_frequency is monthly, quarterly or yearly, not {other}"
        ))),
    }
}

fn timing(value: Option<&str>) -> Result<Timing, AppError> {
    match value.unwrap_or("advance") {
        "advance" => Ok(Timing::Advance),
        "arrears" => Ok(Timing::Arrears),
        other => Err(AppError::Validation(format!(
            "billing_timing is advance or arrears, not {other}"
        ))),
    }
}

fn alignment(value: Option<&str>) -> Result<Alignment, AppError> {
    match value.unwrap_or("anniversary") {
        "anniversary" => Ok(Alignment::Anniversary),
        "calendar_month" => Ok(Alignment::CalendarMonth),
        other => Err(AppError::Validation(format!(
            "billing_alignment is anniversary or calendar_month, not {other}"
        ))),
    }
}

fn change_kind(value: &str) -> Result<ChangeKind, AppError> {
    match value {
        "add" => Ok(ChangeKind::Add),
        "remove" => Ok(ChangeKind::Remove),
        "upgrade" => Ok(ChangeKind::Upgrade),
        "downgrade" => Ok(ChangeKind::Downgrade),
        "price_change" => Ok(ChangeKind::PriceChange),
        other => Err(AppError::Validation(format!(
            "kind is add, remove, upgrade, downgrade or price_change, not {other}"
        ))),
    }
}

/// Creates a subscription.
///
/// By hand from `lines`, or from an accepted quote (`quote_id`), whose lines
/// are copied. Each line starts with one dated segment.
#[utoipa::path(
    post,
    path = "/api/v1/billing/subscriptions",
    tag = "billing",
    request_body = BillingCreateSubscriptionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The subscription is created", body = BillingSubscriptionCreated),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not create subscriptions", body = ErrorResponse),
        (status = 404, description = "No such quote the caller may read", body = ErrorResponse),
        (status = 422, description = "Invalid terms or lines, or a quote not accepted", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_subscription(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<BillingCreateSubscriptionBody>,
) -> Result<(StatusCode, Json<BillingSubscriptionCreated>), AppError> {
    let source = match (body.quote_id, body.order_id) {
        (Some(quote), _) => service::Source::FromQuote(quote),
        (None, Some(order)) => service::Source::FromOrder(order),
        (None, None) => service::Source::ByHand(
            body.lines
                .iter()
                .map(|l| {
                    Ok(service::NewLine {
                        product_ref: l.product_ref,
                        quantity: decimal(l.quantity, "quantity")?,
                        unit_price: decimal(l.unit_price, "unit_price")?,
                        charge_model: l.charge_model.clone(),
                    })
                })
                .collect::<Result<Vec<_>, AppError>>()?,
        ),
    };
    let id = service::create(
        &state,
        &ctx,
        service::CreateSubscription {
            name: body.name,
            account_ref: body.account_ref,
            currency: body.currency,
            start_date: body.start_date,
            end_date: body.end_date,
            term_months: body.term_months,
            frequency: cadence(body.billing_frequency.as_deref())?,
            timing: timing(body.billing_timing.as_deref())?,
            alignment: alignment(body.billing_alignment.as_deref())?,
            source,
        },
    )
    .await?;
    Ok((StatusCode::CREATED, Json(BillingSubscriptionCreated { id })))
}

/// Reads a subscription as of a date.
///
/// The subscription as the caller may read it, with each line's quantity
/// and price in force on `as_of` (today when absent).
#[utoipa::path(
    get,
    path = "/api/v1/billing/subscriptions/{id}",
    operation_id = "get_billing_subscription",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The subscription"), BillingAsOfQuery),
    responses(
        (status = 200, description = "The subscription as of the date", body = SubscriptionAsOf),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read subscription lines", body = ErrorResponse),
        (status = 404, description = "No such subscription the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_subscription(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Query(query): Query<BillingAsOfQuery>,
) -> Result<Json<SubscriptionAsOf>, AppError> {
    ctx.require("subscription", "read")?;
    let as_of = query
        .as_of
        .unwrap_or_else(|| chrono::Utc::now().date_naive());
    Ok(Json(service::read_as_of(&state, &ctx, id, as_of).await?))
}

/// Amends a subscription from a date.
///
/// Each changed line's segment in force on `effective` closes and the next
/// opens; the rest of that billing period is prorated as a planned charge
/// or credit. Changing a price needs `subscription.amend_price`.
#[utoipa::path(
    post,
    path = "/api/v1/billing/subscriptions/{id}/amendments",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The subscription")),
    request_body = BillingAmendmentBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The amendment is made", body = BillingAmended),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not amend, or not change prices", body = ErrorResponse),
        (status = 404, description = "No such subscription", body = ErrorResponse),
        (status = 409, description = "Another change to this subscription is in progress", body = ErrorResponse),
        (status = 422, description = "No change, a line with no segment then, or a closed subscription", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_amendment(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<BillingAmendmentBody>,
) -> Result<Json<BillingAmended>, AppError> {
    let changes = body
        .changes
        .iter()
        .map(|c| {
            Ok(service::LineChange {
                line_id: c.line_id,
                quantity: decimal(c.quantity, "quantity")?,
                unit_price: decimal(c.unit_price, "unit_price")?,
                kind: change_kind(&c.kind)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let result = service::amend(
        &state,
        &ctx,
        id,
        service::Amendment {
            effective: body.effective,
            changes,
        },
    )
    .await?;
    Ok(Json(BillingAmended {
        amendment_id: result.amendment_id,
        segments_opened: result.segments_opened,
        charges: result.charges,
    }))
}

/// Reverses an amendment.
///
/// Voids the amendment's segments, lets the segments it closed run on and
/// cancels its planned charges. Once any part is invoiced it cannot be
/// reversed; amend again instead.
#[utoipa::path(
    post,
    path = "/api/v1/billing/subscriptions/{id}/amendments/{amendment_id}/reverse",
    tag = "billing",
    params(
        ("id" = Uuid, Path, description = "The subscription"),
        ("amendment_id" = Uuid, Path, description = "The amendment to reverse"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The amendment is reversed", body = BillingSubscriptionChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not amend subscriptions", body = ErrorResponse),
        (status = 404, description = "No such amendment of this subscription", body = ErrorResponse),
        (status = 409, description = "Part of the amendment is invoiced, or another change is in progress", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_reverse_amendment(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((id, amendment)): Path<(Uuid, Uuid)>,
) -> Result<Json<BillingSubscriptionChanged>, AppError> {
    service::reverse_amendment(&state, &ctx, id, amendment).await?;
    Ok(Json(BillingSubscriptionChanged {
        status: "reversed".into(),
    }))
}

/// Cancels a subscription.
///
/// At the end of its term, or on a date: the lines end then. Needs
/// `subscription.cancel`.
#[utoipa::path(
    post,
    path = "/api/v1/billing/subscriptions/{id}/cancel",
    operation_id = "cancel_billing_subscription",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The subscription")),
    request_body = BillingCancelBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The subscription is cancelled", body = BillingCancelled),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not cancel subscriptions", body = ErrorResponse),
        (status = 404, description = "No such subscription", body = ErrorResponse),
        (status = 409, description = "Another change to this subscription is in progress", body = ErrorResponse),
        (status = 422, description = "No date, no term end, or a date before the start", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_cancel(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<BillingCancelBody>,
) -> Result<Json<BillingCancelled>, AppError> {
    let on = match (body.at_term_end, body.on) {
        (true, on) => on.unwrap_or_else(|| chrono::Utc::now().date_naive()),
        (false, Some(on)) => on,
        (false, None) => {
            return Err(AppError::Validation(
                "give the date to cancel on, or at_term_end".into(),
            ));
        }
    };
    let effective =
        service::cancel(&state, &ctx, id, body.at_term_end, on, body.reason.trim()).await?;
    Ok(Json(BillingCancelled { effective }))
}

/// Pauses a subscription.
///
/// From a date, until `resume_on` when given: the lines bill nothing while
/// paused.
#[utoipa::path(
    post,
    path = "/api/v1/billing/subscriptions/{id}/pause",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The subscription")),
    request_body = BillingPauseBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The subscription is paused", body = BillingSubscriptionChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change subscriptions", body = ErrorResponse),
        (status = 404, description = "No such subscription", body = ErrorResponse),
        (status = 409, description = "Another change to this subscription is in progress", body = ErrorResponse),
        (status = 422, description = "Not active, or a resume before the pause", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_pause(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<BillingPauseBody>,
) -> Result<Json<BillingSubscriptionChanged>, AppError> {
    service::pause(&state, &ctx, id, body.from, body.resume_on).await?;
    Ok(Json(BillingSubscriptionChanged {
        status: "paused".into(),
    }))
}

/// Resumes a paused subscription.
///
/// On a date: each line bills at its quantity before the pause again.
#[utoipa::path(
    post,
    path = "/api/v1/billing/subscriptions/{id}/resume",
    tag = "billing",
    params(("id" = Uuid, Path, description = "The subscription")),
    request_body = BillingResumeBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The subscription is active again", body = BillingSubscriptionChanged),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change subscriptions", body = ErrorResponse),
        (status = 404, description = "No such subscription", body = ErrorResponse),
        (status = 409, description = "Another change to this subscription is in progress", body = ErrorResponse),
        (status = 422, description = "The subscription is not paused", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_resume(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<BillingResumeBody>,
) -> Result<Json<BillingSubscriptionChanged>, AppError> {
    service::resume(&state, &ctx, id, body.on).await?;
    Ok(Json(BillingSubscriptionChanged {
        status: "active".into(),
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    post_subscription,
    get_subscription,
    post_amendment,
    post_reverse_amendment,
    post_cancel,
    post_pause,
    post_resume
))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies_parse_to_the_service_terms() {
        assert_eq!(cadence(None).unwrap(), Cadence::Monthly);
        assert_eq!(cadence(Some("yearly")).unwrap(), Cadence::Yearly);
        assert!(cadence(Some("weekly")).is_err());
        assert_eq!(timing(Some("arrears")).unwrap(), Timing::Arrears);
        assert_eq!(
            alignment(Some("calendar_month")).unwrap(),
            Alignment::CalendarMonth
        );
        assert_eq!(
            change_kind("price_change").unwrap(),
            ChangeKind::PriceChange
        );
        assert!(
            change_kind("new").is_err(),
            "a new line is not an amendment"
        );
        assert!(decimal(-1.0, "quantity").is_err());
        assert_eq!(decimal(2.5, "quantity").unwrap(), Decimal::new(25, 1));
    }
}

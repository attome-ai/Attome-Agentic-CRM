//! Payment links and the hosted payment page's API (roadmap F5-T8).
//!
//! - [`create_link`] (`POST /api/v1/billing/payment-links`,
//!   `payment_link.create`) makes a single-use link for an issued invoice's
//!   open amount, an order's total, or a free amount for an account, valid
//!   for 72 hours by default. The link is `{public_id}.{secret}`: the public
//!   id is a lookup key, and only a peppered hash of the secret is stored
//!   (the scheme of portal tokens, D-500). The URL is
//!   `<public frontend URL>/pay/<public_id>.<secret>`.
//! - `GET /api/v1/pay/{token}` and `POST /api/v1/pay/{token}/checkout` are
//!   public (bypass-listed by an exact match of one token segment, then
//!   nothing or `checkout`), rate limited per address, and answer the same
//!   `404` for an unknown, wrong, expired, used or cancelled link: a wrong
//!   secret costs the same hash check as a right one.
//! - Checkout chooses the gateway by the `billing.gateway.rules`, saves a
//!   pending `customer_payment` naming the link first, then asks the gateway
//!   for a checkout outside any transaction and records its reference. The
//!   link is marked used only when the gateway reports the payment
//!   succeeded (the webhook job, through
//!   [`super::service::apply_gateway_status_in_tx`]), which allocates it to
//!   the link's invoice.

use std::str::FromStr;

use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, emit_named};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use axum::extract::{Path, Request, State};
use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::gateway::{
    CheckoutRequest, CheckoutWidget, GatewaySystem, Method, PaymentGateway, choose_gateway,
};

/// How long a link lasts unless the request says otherwise.
pub const DEFAULT_EXPIRY_HOURS: u32 = 72;

/// The longest a link may last.
pub const MAX_EXPIRY_HOURS: u32 = 720;

/// Public calls one address may make in a minute.
const PUBLIC_RATE_LIMIT_PER_MINUTE: i32 = 30;

/// What a link is for: an invoice, an order, or an amount for an account.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct LinkRequest {
    pub invoice_id: Option<Uuid>,
    pub order_id: Option<Uuid>,
    /// With `amount` and `currency`: a free amount for this account.
    pub account_id: Option<Uuid>,
    #[schema(value_type = Option<f64>)]
    pub amount: Option<serde_json::Number>,
    pub currency: Option<String>,
    /// 1 to 720; 72 by default.
    pub expires_in_hours: Option<u32>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LinkCreated {
    pub link_id: Uuid,
    /// The link to send the payer; shown once.
    pub url: String,
    pub expires_at: DateTime<Utc>,
}

/// What the payment page shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct PayView {
    /// Decimal, as text.
    pub amount: String,
    pub currency: String,
    pub invoice_number: Option<String>,
    pub seller_name: Option<String>,
    /// `ar` or `en`, from the payer's browser.
    pub locale: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct CheckoutStart {
    /// The method the payer chose; card by default.
    #[schema(value_type = Option<String>)]
    pub method: Option<Method>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CheckoutStarted {
    pub payment_id: Uuid,
    /// Send the payer here (a hosted page)...
    pub redirect_url: Option<String>,
    /// ...or embed this form (HyperPay).
    #[schema(value_type = Option<Object>)]
    pub widget: Option<CheckoutWidget>,
}

/// A live link, as the public routes read it.
#[derive(Debug, Clone)]
pub struct LiveLink {
    pub id: Uuid,
    pub invoice_id: Option<Uuid>,
    pub order_id: Option<Uuid>,
    pub account_id: Option<Uuid>,
    pub amount: Decimal,
    pub currency: String,
    pub expires_at: DateTime<Utc>,
}

fn decimal(n: &serde_json::Number) -> Result<Decimal, AppError> {
    Decimal::from_str(&n.to_string())
        .or_else(|_| Decimal::from_scientific(&n.to_string()))
        .map_err(|_| AppError::Validation(format!("{n} is not a decimal amount")))
}

fn text_decimal(t: Option<&str>) -> Decimal {
    t.and_then(|v| Decimal::from_str(v.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

fn currency_code(raw: &str) -> Result<String, AppError> {
    let code = raw.trim().to_ascii_uppercase();
    if code.len() == 3 && code.chars().all(|c| c.is_ascii_alphabetic()) {
        Ok(code)
    } else {
        Err(AppError::Validation(
            "currency is a three-letter ISO code".into(),
        ))
    }
}

type TargetRow = (Option<Uuid>, Option<String>, Option<String>, Option<String>);

/// The payer, amount and currency a request names, read within the
/// caller's record scope.
async fn target(
    state: &EngineState,
    ctx: &SecurityContext,
    req: &LinkRequest,
) -> Result<(Uuid, Decimal, String), AppError> {
    let named = [
        req.invoice_id.is_some(),
        req.order_id.is_some(),
        req.amount.is_some(),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if named != 1 {
        return Err(AppError::Validation(
            "a link is for one invoice, one order, or an amount".into(),
        ));
    }
    if let Some(invoice) = req.invoice_id {
        let scope = crate::scope::read_scope(state, ctx, "invoice", "i", 2).await?;
        let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
        let sql = format!(
            "SELECT i.account_ref, i.open_total::text, i.currency, \
                 CASE WHEN COALESCE(i.status, 'draft') IN ('issued', 'sent', 'overdue') \
                       AND COALESCE(i.payment_status, 'open') NOT IN ('paid', 'written_off') \
                      THEN 'payable' ELSE 'closed' END \
             FROM invoice i WHERE i.id = $1 AND (i.is_active IS NULL OR i.is_active = true) {rls}"
        );
        let row: Option<TargetRow> =
            crate::scope::bind_scope(sqlx::query_as(&sql).bind(invoice), &scope)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        let (account, open, currency, payable) = row.ok_or(AppError::NotFound)?;
        let open = text_decimal(open.as_deref());
        if payable.as_deref() != Some("payable") || open <= Decimal::ZERO {
            return Err(AppError::Validation(
                "only an issued invoice with an open amount takes a payment link".into(),
            ));
        }
        let account =
            account.ok_or_else(|| AppError::Validation("the invoice names no account".into()))?;
        return Ok((
            account,
            open,
            currency_code(currency.as_deref().unwrap_or("SAR"))?,
        ));
    }
    if let Some(order) = req.order_id {
        let scope = crate::scope::read_scope(state, ctx, "order", "o", 2).await?;
        let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
        let sql = format!(
            "SELECT o.account_ref, o.grand_total::text, o.currency, 'payable' \
             FROM \"order\" o WHERE o.id = $1 AND (o.is_active IS NULL OR o.is_active = true) {rls}"
        );
        let row: Option<TargetRow> =
            crate::scope::bind_scope(sqlx::query_as(&sql).bind(order), &scope)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        let (account, total, currency, _) = row.ok_or(AppError::NotFound)?;
        let total = text_decimal(total.as_deref());
        if total <= Decimal::ZERO {
            return Err(AppError::Validation("the order has no total to pay".into()));
        }
        let account =
            account.ok_or_else(|| AppError::Validation("the order names no account".into()))?;
        return Ok((
            account,
            total,
            currency_code(currency.as_deref().unwrap_or("SAR"))?,
        ));
    }
    let amount = decimal(req.amount.as_ref().ok_or(AppError::NotFound)?)?;
    if amount <= Decimal::ZERO {
        return Err(AppError::Validation("the amount must be positive".into()));
    }
    let account = req.account_id.ok_or_else(|| {
        AppError::Validation("an amount link names its payer's account_id".into())
    })?;
    let currency = currency_code(
        req.currency
            .as_deref()
            .ok_or_else(|| AppError::Validation("an amount link names its currency".into()))?,
    )?;
    let scope = crate::scope::read_scope(state, ctx, "account", "a", 2).await?;
    let rls = scope.as_ref().map_or("", |p| p.sql.as_str());
    let sql = format!(
        "SELECT a.id FROM account a WHERE a.id = $1 \
           AND (a.is_active IS NULL OR a.is_active = true) {rls}"
    );
    let found: Option<(Uuid,)> =
        crate::scope::bind_scope(sqlx::query_as(&sql).bind(account), &scope)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    found.ok_or(AppError::NotFound)?;
    Ok((account, amount, currency))
}

/// Creates a payment link.
pub async fn create_link(
    state: &EngineState,
    ctx: &SecurityContext,
    req: &LinkRequest,
) -> Result<LinkCreated, AppError> {
    ctx.require("payment_link", "create")?;
    let hours = req.expires_in_hours.unwrap_or(DEFAULT_EXPIRY_HOURS);
    if !(1..=MAX_EXPIRY_HOURS).contains(&hours) {
        return Err(AppError::Validation(format!(
            "expires_in_hours is 1 to {MAX_EXPIRY_HOURS}"
        )));
    }
    let (account, amount, currency) = target(state, ctx, req).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let created = insert_link_in_tx(
        &mut tx,
        state,
        NewLink {
            invoice_id: req.invoice_id,
            order_id: req.order_id,
            account_id: account,
            amount,
            currency,
            hours,
        },
        ctx.user_id,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(created)
}

/// A link's target, already checked.
#[derive(Debug, Clone)]
pub struct NewLink {
    pub invoice_id: Option<Uuid>,
    pub order_id: Option<Uuid>,
    pub account_id: Uuid,
    pub amount: Decimal,
    pub currency: String,
    pub hours: u32,
}

/// Writes a link in the caller's transaction (its change-feed and audit
/// events with it); the caller has checked who may and what it is for.
pub async fn insert_link_in_tx(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    new: NewLink,
    actor: Uuid,
) -> Result<LinkCreated, AppError> {
    let public_id = Uuid::now_v7();
    // 244 random bits, never stored: only its peppered hash is.
    let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let ring = state.base.pepper_ring();
    let secret_hash = attome_auth::apikey_hash::hash_peppered_secret(&ring, &secret);
    let expires_at = Utc::now() + Duration::hours(i64::from(new.hours));
    let link = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO payment_link (id, invoice_ref, order_ref, account_ref, amount, currency, \
             public_id, secret_hash, expires_at, status, created_by, owner_ref, owner_type, \
             is_active, row_version) \
         VALUES ($1, $2, $3, $4, $5::numeric, $6, $7, $8, $9, 'open', $10, $10, 0, true, 0)",
    )
    .bind(link)
    .bind(new.invoice_id)
    .bind(new.order_id)
    .bind(new.account_id)
    .bind(new.amount.to_string())
    .bind(&new.currency)
    .bind(public_id.to_string())
    .bind(&secret_hash)
    .bind(expires_at)
    .bind(actor)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    emit_named(
        tx,
        "payment_link",
        link,
        ChangeOperation::Create,
        "billing.payment_link.created",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "payment_link",
            link,
            attome_audit::AuditOperation::Create,
            "billing.payment_link_created",
            actor,
        ),
    )
    .await?;
    Ok(LinkCreated {
        link_id: link,
        url: format!(
            "{}/pay/{public_id}.{secret}",
            state.base.config.frontend_url().trim_end_matches('/')
        ),
        expires_at,
    })
}

type LinkRow = (
    Uuid,
    Option<Uuid>,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<DateTime<Utc>>,
);

/// The live link a token names, or `404` for every kind of miss, after the
/// same hash check whatever the miss.
pub async fn live_link(state: &EngineState, token: &str) -> Result<LiveLink, AppError> {
    let ring = state.base.pepper_ring();
    let parsed = token
        .split_once('.')
        .and_then(|(id, secret)| Some((Uuid::parse_str(id).ok()?, secret)));
    let row: Option<LinkRow> = match parsed {
        Some((public_id, _)) => sqlx::query_as(
            "SELECT id, invoice_ref, order_ref, account_ref, amount::text, currency, secret_hash, \
                 expires_at, status, used_at \
             FROM payment_link WHERE public_id = $1 AND (is_active IS NULL OR is_active = true) \
             LIMIT 1",
        )
        .bind(public_id.to_string())
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?,
        None => None,
    };
    let secret = parsed.map_or("", |(_, s)| s);
    let stored = row.as_ref().and_then(|r| r.6.as_deref());
    let hash = match stored {
        Some(hash) => hash.to_owned(),
        None => attome_auth::apikey_hash::dummy_peppered_hash(&ring),
    };
    let verified = attome_auth::apikey_hash::verify_peppered_secret(&ring, secret, &hash).await?
        != attome_auth::apikey_hash::VerifyOutcome::Fail;
    let Some((id, invoice, order, account, amount, currency, _, expires, status, used)) = row
    else {
        return Err(AppError::NotFound);
    };
    let expires_at = expires.ok_or(AppError::NotFound)?;
    if !verified || status.as_deref() != Some("open") || used.is_some() || expires_at <= Utc::now()
    {
        return Err(AppError::NotFound);
    }
    Ok(LiveLink {
        id,
        invoice_id: invoice,
        order_id: order,
        account_id: account,
        amount: text_decimal(amount.as_deref()),
        currency: currency.unwrap_or_else(|| "SAR".into()),
        expires_at,
    })
}

/// What the link asks for now: an invoice link asks for what the invoice
/// still owes (a paid invoice is a `404`).
async fn amount_due(state: &EngineState, link: &LiveLink) -> Result<Decimal, AppError> {
    let Some(invoice) = link.invoice_id else {
        return Ok(link.amount);
    };
    let open: Option<Option<String>> =
        sqlx::query_scalar("SELECT open_total::text FROM invoice WHERE id = $1")
            .bind(invoice)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let open = text_decimal(open.flatten().as_deref());
    if open <= Decimal::ZERO {
        return Err(AppError::NotFound);
    }
    Ok(open)
}

/// The payer's language from `Accept-Language`: Arabic or English.
fn locale(headers: &axum::http::HeaderMap) -> String {
    let wanted = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .trim_start()
        .to_ascii_lowercase();
    if wanted.starts_with("ar") { "ar" } else { "en" }.to_owned()
}

/// The caller's rate-limit subject, read before any await (a request is
/// not `Sync`).
fn subject(state: &EngineState, request: &Request) -> String {
    attome_server::middleware::client_ip::client_ip(request, &state.base.config).map_or_else(
        || "unknown".to_owned(),
        |ip| attome_server::middleware::client_ip::rate_limit_subject(ip, 64),
    )
}

async fn rate_limited(state: &EngineState, ip: &str, what: &str) -> Result<(), AppError> {
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &format!("attome-billing:rl:pay-{what}:{ip}"),
        PUBLIC_RATE_LIMIT_PER_MINUTE,
    )
    .await?;
    if outcome.allowed {
        Ok(())
    } else {
        Err(AppError::TooManyRequests {
            retry_after_secs: None,
        })
    }
}

/// The page's view of a live link.
pub async fn view(state: &EngineState, token: &str, locale: String) -> Result<PayView, AppError> {
    let link = live_link(state, token).await?;
    let amount = amount_due(state, &link).await?;
    let invoice_number: Option<String> = match link.invoice_id {
        Some(invoice) => sqlx::query_scalar::<_, Option<String>>(
            "SELECT invoice_number FROM invoice WHERE id = $1",
        )
        .bind(invoice)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .flatten(),
        None => None,
    };
    Ok(PayView {
        amount: amount.to_string(),
        currency: link.currency,
        invoice_number,
        seller_name: crate::document::setting_text(state, crate::document::SELLER_NAME_SETTING),
        locale,
        expires_at: link.expires_at,
    })
}

/// Starts a checkout for a live link with `gateway` (the adapter of
/// `system`, called with `secret`): saves the pending payment, asks the
/// gateway outside any transaction, and records its reference. A refused
/// checkout leaves the payment `failed`.
#[allow(clippy::too_many_arguments)]
pub async fn start_checkout(
    state: &EngineState,
    link: &LiveLink,
    method: Method,
    system: &GatewaySystem,
    gateway: &dyn PaymentGateway,
    secret: &str,
    return_url: &str,
) -> Result<CheckoutStarted, AppError> {
    if !gateway.supported_methods().contains(&method) {
        return Err(AppError::Validation(format!(
            "{} does not take {method:?}",
            gateway.name()
        )));
    }
    let amount = amount_due(state, link).await?;
    let payer = match link.account_id {
        Some(account) => account,
        None => {
            let account: Option<Option<Uuid>> = match link.invoice_id {
                Some(invoice) => {
                    sqlx::query_scalar("SELECT account_ref FROM invoice WHERE id = $1")
                        .bind(invoice)
                        .fetch_optional(&state.base.db)
                        .await
                        .map_err(AppError::internal)?
                }
                None => None,
            };
            account
                .flatten()
                .ok_or_else(|| AppError::Validation("the link names no payer".into()))?
        }
    };
    let actor = system.service_principal.unwrap_or_else(Uuid::nil);
    let payment = Uuid::now_v7();
    let method_text = serde_json::to_value(method)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "card".into());
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO customer_payment (id, name, payer_account_ref, amount, currency, method, \
             status, gateway_system_ref, payment_link_ref, unallocated, created_by, owner_ref, \
             owner_type, is_active, row_version) \
         VALUES ($1, $2, $3, $4::numeric, $5, $6, 'pending', $7, $8, 0, $9, $9, 0, true, 0)",
    )
    .bind(payment)
    .bind(format!("PAY-{}", payment.simple()))
    .bind(payer)
    .bind(amount.to_string())
    .bind(&link.currency)
    .bind(&method_text)
    .bind(system.id.to_string())
    .bind(link.id)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    emit_named(
        &mut tx,
        "customer_payment",
        payment,
        ChangeOperation::Create,
        "billing.payment.pending",
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    let description =
        match crate::document::setting_text(state, crate::document::SELLER_NAME_SETTING) {
            Some(seller) => format!("{seller}: {amount} {}", link.currency),
            None => format!("{amount} {}", link.currency),
        };
    let request = CheckoutRequest {
        amount,
        currency: link.currency.clone(),
        description,
        return_url: return_url.to_owned(),
        reference: payment.to_string(),
        idempotency_key: payment.to_string(),
        methods: vec![method],
    };
    let outcome = gateway.create_checkout(secret, &request).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let result = match &outcome {
        Ok(checkout) => {
            sqlx::query(
                "UPDATE customer_payment SET gateway_reference = $2, modified_at = now(), \
                     row_version = row_version + 1 WHERE id = $1",
            )
            .bind(payment)
            .bind(&checkout.gateway_reference)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            Ok(CheckoutStarted {
                payment_id: payment,
                redirect_url: checkout.redirect_url.clone(),
                widget: checkout.widget.clone(),
            })
        }
        Err(e) => {
            sqlx::query(
                "UPDATE customer_payment SET status = 'failed', modified_at = now(), \
                     row_version = row_version + 1 WHERE id = $1",
            )
            .bind(payment)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            tracing::warn!(%payment, gateway = gateway.name(), error = %e, "billing: the gateway refused a checkout");
            Err(AppError::from(e.clone()))
        }
    };
    emit_named(
        &mut tx,
        "customer_payment",
        payment,
        ChangeOperation::Update,
        "billing.payment.checkout",
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    result
}

/// `payment_link.create`: may create payment links.
#[derive(Debug)]
pub struct PaymentLinkCreate;

impl attome_server::authz::PrivilegeKey for PaymentLinkCreate {
    const KEY: &'static str = "payment_link.create";
}

#[utoipa::path(
    post,
    path = "/api/v1/billing/payment-links",
    tag = "billing",
    request_body = LinkRequest,
    responses(
        (status = 200, description = "The link, shown once", body = LinkCreated),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
        (status = 403, description = "Caller may not create payment links", body = attome_types::ErrorResponse),
        (status = 404, description = "No such invoice, order or account in the caller's scope", body = attome_types::ErrorResponse),
        (status = 422, description = "Not one target, not payable, or a bad amount, currency or expiry", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_link(
    State(state): State<EngineState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Privilege<PaymentLinkCreate>>,
    axum::Json(body): axum::Json<LinkRequest>,
) -> Result<axum::Json<LinkCreated>, AppError> {
    Ok(axum::Json(create_link(&state, &ctx, &body).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/pay/{token}",
    tag = "billing",
    params(("token" = String, Path, description = "The link's `{public_id}.{secret}`")),
    responses(
        (status = 200, description = "What the payer is asked to pay", body = PayView),
        (status = 404, description = "No live link (unknown, wrong, expired, used or cancelled)", body = attome_types::ErrorResponse),
        (status = 429, description = "Too many calls from this address", body = attome_types::ErrorResponse),
    ),
)]
pub(crate) async fn get_pay(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    request: Request,
) -> Result<axum::Json<PayView>, AppError> {
    let ip = subject(&state, &request);
    let locale = locale(request.headers());
    drop(request);
    rate_limited(&state, &ip, "view").await?;
    Ok(axum::Json(view(&state, &token, locale).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/pay/{token}/checkout",
    tag = "billing",
    params(("token" = String, Path, description = "The link's `{public_id}.{secret}`")),
    request_body = CheckoutStart,
    responses(
        (status = 200, description = "The checkout to send the payer to", body = CheckoutStarted),
        (status = 404, description = "No live link (unknown, wrong, expired, used or cancelled)", body = attome_types::ErrorResponse),
        (status = 422, description = "No gateway takes this payment, or the gateway refused it", body = attome_types::ErrorResponse),
        (status = 429, description = "Too many calls from this address", body = attome_types::ErrorResponse),
        (status = 503, description = "The gateway could not be reached", body = attome_types::ErrorResponse),
    ),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("BillingGatewayEventApply -> payment::service::apply_gateway_status_in_tx"),
        "public payer action; payment audited on success",
    )))),
)]
pub(crate) async fn post_checkout(
    State(state): State<EngineState>,
    Path(token): Path<String>,
    request: Request,
) -> Result<axum::Json<CheckoutStarted>, AppError> {
    let ip = subject(&state, &request);
    let body_stream = request.into_body();
    rate_limited(&state, &ip, "checkout").await?;
    let body = axum::body::to_bytes(body_stream, 4096)
        .await
        .map_err(|_| AppError::Validation("the request body is too large".into()))?;
    let start: CheckoutStart = if body.iter().all(u8::is_ascii_whitespace) {
        CheckoutStart::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| AppError::Validation(format!("the request does not read: {e}")))?
    };
    let link = live_link(&state, &token).await?;
    let amount = amount_due(&state, &link).await?;
    let country: Option<Option<String>> = match link.account_id {
        Some(account) => {
            sqlx::query_scalar("SELECT billing_country_code FROM account WHERE id = $1")
                .bind(account)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?
        }
        None => None,
    };
    let country = country.flatten().unwrap_or_else(|| "SA".into());
    let rules = crate::gateway::rules(&state);
    let system_id = choose_gateway(&rules, &link.currency, &country, amount).ok_or_else(|| {
        AppError::Validation(format!("no payment gateway takes {} here", link.currency))
    })?;
    let system = crate::gateway::system(&state, system_id).await?;
    let gateway = crate::gateway::gateway_for(
        &system.adapter,
        crate::gateway::GatewayHttp::new(&system.base_url)?,
    )
    .ok_or_else(|| AppError::Validation(format!("no adapter for {}", system.adapter)))?;
    let credential = crate::gateway::credential(&state, &system).await?;
    let return_url = format!(
        "{}/pay/return",
        state.base.config.frontend_url().trim_end_matches('/')
    );
    Ok(axum::Json(
        start_checkout(
            &state,
            &link,
            start.method.unwrap_or(Method::Card),
            &system,
            gateway.as_ref(),
            &credential,
            &return_url,
        )
        .await?,
    ))
}

/// This module's routes, for the OpenAPI document.
#[derive(Debug, utoipa::OpenApi)]
#[openapi(
    paths(post_link, get_pay, post_checkout),
    components(schemas(LinkRequest, LinkCreated, PayView, CheckoutStart, CheckoutStarted))
)]
pub struct ApiDocFragment;

//! F8-T7: checkout without an account, proved by a one-time code to the
//! buyer's phone.
//!
//! Off unless the shop is open ([`crate::commerce::ENABLED_SETTING`]) and
//! [`GUEST_ACCOUNT_SETTING`] names the account guest orders go under (a D10
//! order needs one); the portal routes answer 404 otherwise.
//!
//! 1. [`start`] takes the phone and the lines (products and quantities only;
//!    every product must be on sale), keeps them with a 6-digit code's
//!    SHA-256 (`commerce_guest_checkout`, migration 0375; never the code)
//!    for [`CODE_TTL_MINUTES`], and texts the code. At most
//!    [`CODES_PER_PHONE`] codes per phone in 15 minutes; the portal route
//!    also limits per address.
//! 2. [`confirm`] takes the code, the delivery details, the chosen shipping
//!    rate and a checkout key. A wrong code counts an attempt and is
//!    `Unauthorized` ([`MAX_ATTEMPTS`] in all); a right one claims the
//!    checkout with the key, so a retried confirm with the same key returns
//!    the same order and a second confirm of the same code is a conflict.
//!    Prices, offers (F8-T6), shipping and VAT ([`VAT_RATE_SETTING`], on
//!    the discounted lines and shipping) are recomputed here, never taken
//!    from the client. The contact is matched by phone or made, then the
//!    order and its lines are written through the record engine as the
//!    portal's service user, and the coupon redeemed under its lock. The
//!    record engine writes one record per transaction, so a failure part way
//!    deletes the order again and releases the claim for another try.
//! 3. After the order is written: cash on delivery sets `payment_status`
//!    `due_on_delivery` and `cod_amount` (the rate's fee is in the
//!    shipping); otherwise a payment link for the order (F5) is made and its
//!    URL returned. No gateway is called while a transaction is open.

use std::str::FromStr;

use attome_core::EngineState;
use attome_integration::connector::adapters::shop_sync::normalise_phone;
use attome_records::entity_mutation::{DeleteKind, DeleteOrigin};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::shipping::{ShipTo, rate_amount, rates_for};

/// The account guest orders go under (unset: no guest checkout).
pub const GUEST_ACCOUNT_SETTING: &str = "commerce.guest_account";
/// The VAT rate on guest orders, as a fraction (0.15).
pub const VAT_RATE_SETTING: &str = "commerce.vat_rate";
/// How long a code works.
pub const CODE_TTL_MINUTES: i64 = 10;
/// Wrong codes allowed per checkout.
pub const MAX_ATTEMPTS: i32 = 5;
/// Codes per phone in 15 minutes.
pub const CODES_PER_PHONE: i64 = 3;
/// The calling code a phone without one is read in.
const DEFAULT_COUNTRY: &str = "966";

/// A product and how many.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct GuestLine {
    pub product_id: Uuid,
    /// A decimal in text.
    pub quantity: String,
}

/// A started guest checkout.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Started {
    pub checkout_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

/// What a guest confirms.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct Confirm {
    pub checkout_id: Uuid,
    pub code: String,
    pub name: String,
    pub address: String,
    /// ISO 3166-1 alpha-2.
    pub country: String,
    pub city: Option<String>,
    /// A rate from the shipping options.
    pub shipping_rate_id: Uuid,
    #[serde(default)]
    pub cash_on_delivery: bool,
    pub coupon: Option<String>,
}

/// The order a guest placed.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GuestOrder {
    pub order_id: Uuid,
    /// Decimals in text.
    pub subtotal: String,
    pub discount_total: String,
    pub shipping: String,
    pub vat: String,
    pub total: String,
    /// Where to pay, unless cash on delivery (or no link could be made).
    pub payment_url: Option<String>,
}

fn guest_account(state: &EngineState) -> Option<Uuid> {
    crate::commerce::setting(state, GUEST_ACCOUNT_SETTING)
        .as_str()
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

fn vat_rate(state: &EngineState) -> Decimal {
    crate::commerce::setting(state, VAT_RATE_SETTING)
        .as_f64()
        .and_then(|v| Decimal::from_str(&v.to_string()).ok())
        .filter(|r| *r >= Decimal::ZERO && *r < Decimal::ONE)
        .unwrap_or(Decimal::ZERO)
}

/// Whether guests may check out.
pub fn enabled(state: &EngineState) -> bool {
    crate::commerce::enabled(state) && guest_account(state).is_some()
}

/// The stored digest of `code` for checkout `id`. Pure.
pub fn code_digest(id: Uuid, code: &str) -> String {
    hex::encode(Sha256::digest(format!("{id}:{}", code.trim()).as_bytes()))
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn new_code() -> String {
    let n = u32::from_le_bytes(Uuid::new_v4().as_bytes()[..4].try_into().unwrap_or([0; 4]));
    format!("{:06}", n % 1_000_000)
}

fn parse_lines(lines: &[GuestLine]) -> Result<Vec<(Uuid, Decimal)>, AppError> {
    if lines.is_empty() || lines.len() > usize::try_from(crate::commerce::MAX_LINES).unwrap_or(100)
    {
        return Err(AppError::Validation("an order has 1 to 100 lines".into()));
    }
    lines
        .iter()
        .map(|l| {
            let q = Decimal::from_str(l.quantity.trim())
                .ok()
                .filter(|q| *q > Decimal::ZERO && *q <= Decimal::from(10_000))
                .ok_or_else(|| AppError::Validation("a quantity is 0 to 10000".into()))?;
            Ok((l.product_id, q))
        })
        .collect()
}

/// Starts a guest checkout on `portal` for `phone` and texts its code.
pub async fn start(
    state: &EngineState,
    portal: Uuid,
    phone: &str,
    lines: &[GuestLine],
) -> Result<Started, AppError> {
    if !enabled(state) {
        return Err(AppError::NotFound);
    }
    let phone = normalise_phone(phone, DEFAULT_COUNTRY)
        .ok_or_else(|| AppError::Validation("not a phone number".into()))?;
    let lines = parse_lines(lines)?;
    let ids: Vec<Uuid> = lines.iter().map(|(p, _)| *p).collect();
    let on_sale = crate::commerce::visible_products(state, None, Some(&ids)).await?;
    if lines
        .iter()
        .any(|(p, _)| !on_sale.iter().any(|row| row.0 == *p))
    {
        return Err(AppError::Validation("a product is not on sale".into()));
    }
    let recent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM commerce_guest_checkout \
          WHERE phone = $1 AND created_at > now() - interval '15 minutes'",
    )
    .bind(&phone)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if recent >= CODES_PER_PHONE {
        return Err(AppError::TooManyRequests {
            retry_after_secs: Some(15 * 60),
        });
    }
    let id = Uuid::now_v7();
    let code = new_code();
    let expires_at = Utc::now() + Duration::minutes(CODE_TTL_MINUTES);
    let stored: Vec<Value> = lines
        .iter()
        .map(|(p, q)| json!({ "product_id": p, "quantity": q.to_string() }))
        .collect();
    sqlx::query(
        "INSERT INTO commerce_guest_checkout (id, portal_id, phone, code_hash, lines, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(portal)
    .bind(&phone)
    .bind(code_digest(id, &code))
    .bind(Value::Array(stored))
    .bind(expires_at)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let text = format!("{code} is your order code. It works for {CODE_TTL_MINUTES} minutes.");
    match attome_integration::sms::send(state, &phone, &text, None).await? {
        attome_integration::sms::Sent::Accepted(_) => Ok(Started {
            checkout_id: id,
            expires_at,
        }),
        attome_integration::sms::Sent::Skipped => Err(AppError::Validation(
            "the shop cannot send a code to this number".into(),
        )),
    }
}

type CheckoutRow = (
    String,
    String,
    Value,
    i32,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<String>,
    Option<Uuid>,
);

/// Places the guest's order; see the module documentation.
pub async fn confirm(
    state: &EngineState,
    ctx: &SecurityContext,
    portal: Uuid,
    key: &str,
    req: &Confirm,
) -> Result<GuestOrder, AppError> {
    if !enabled(state) {
        return Err(AppError::NotFound);
    }
    let key = key.trim();
    if key.is_empty() || key.len() > 200 {
        return Err(AppError::Validation(
            "an Idempotency-Key is required".into(),
        ));
    }
    ctx.require("contact", "create")?;
    ctx.require("order", "create")?;
    ctx.require("order_line", "create")?;
    let db = &state.base.db;
    // A retried confirm: the order made the first time.
    let earlier: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, order_id FROM commerce_guest_checkout WHERE portal_id = $1 AND checkout_key = $2",
    )
    .bind(portal)
    .bind(key)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some((_, order)) = earlier {
        return match order {
            Some(order) => summary(state, order, None).await,
            None => Err(AppError::Conflict("the order is being placed")),
        };
    }
    let row: Option<CheckoutRow> = sqlx::query_as(
        "SELECT phone, code_hash, lines, attempts, expires_at, used_at, checkout_key, order_id \
           FROM commerce_guest_checkout WHERE id = $1 AND portal_id = $2",
    )
    .bind(req.checkout_id)
    .bind(portal)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((phone, digest, lines, attempts, expires_at, used_at, _, _)) = row else {
        return Err(AppError::Unauthorized);
    };
    if used_at.is_some() {
        return Err(AppError::Conflict("the code was used already"));
    }
    if attempts >= MAX_ATTEMPTS || expires_at <= Utc::now() {
        return Err(AppError::Unauthorized);
    }
    if !same(&digest, &code_digest(req.checkout_id, &req.code)) {
        sqlx::query("UPDATE commerce_guest_checkout SET attempts = attempts + 1 WHERE id = $1")
            .bind(req.checkout_id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        return Err(AppError::Unauthorized);
    }
    let claimed = sqlx::query(
        "UPDATE commerce_guest_checkout SET used_at = now(), checkout_key = $2 \
          WHERE id = $1 AND used_at IS NULL",
    )
    .bind(req.checkout_id)
    .bind(key)
    .execute(db)
    .await;
    match claimed {
        Ok(done) if done.rows_affected() == 1 => {}
        Ok(_) => return Err(AppError::Conflict("the code was used already")),
        Err(error) if attome_db::is_unique_violation(&error) => {
            return Err(AppError::Conflict(
                "the checkout key was used for another order",
            ));
        }
        Err(error) => return Err(AppError::internal(error)),
    }
    match place(state, ctx, &phone, &lines, req).await {
        Ok((order, payment_url)) => {
            sqlx::query("UPDATE commerce_guest_checkout SET order_id = $2 WHERE id = $1")
                .bind(req.checkout_id)
                .bind(order)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
            summary(state, order, payment_url).await
        }
        Err(error) => {
            // Let the guest try again with the same code.
            sqlx::query(
                "UPDATE commerce_guest_checkout SET used_at = NULL, checkout_key = NULL WHERE id = $1",
            )
            .bind(req.checkout_id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            Err(error)
        }
    }
}

async fn summary(
    state: &EngineState,
    order: Uuid,
    payment_url: Option<String>,
) -> Result<GuestOrder, AppError> {
    let row: (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT subtotal::text, discount_total::text, shipping_total::text, tax_total::text, \
                    grand_total::text FROM \"order\" WHERE id = $1",
    )
    .bind(order)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let text = |v: Option<String>| v.unwrap_or_else(|| "0".into());
    Ok(GuestOrder {
        order_id: order,
        subtotal: text(row.0),
        discount_total: text(row.1),
        shipping: text(row.2),
        vat: text(row.3),
        total: text(row.4),
        payment_url,
    })
}

fn number(value: Decimal) -> Value {
    crate::order::number(&value.round_dp(2).to_string()).unwrap_or(Value::Null)
}

/// The totals of a guest order. Pure.
pub fn totals(
    subtotal: Decimal,
    discount: Decimal,
    shipping: Decimal,
    vat_rate: Decimal,
) -> (Decimal, Decimal) {
    let taxable = (subtotal - discount).max(Decimal::ZERO) + shipping;
    let vat = (taxable * vat_rate).round_dp(2);
    (vat, taxable + vat)
}

async fn place(
    state: &EngineState,
    ctx: &SecurityContext,
    phone: &str,
    stored: &Value,
    req: &Confirm,
) -> Result<(Uuid, Option<String>), AppError> {
    let account = guest_account(state).ok_or(AppError::NotFound)?;
    let currency = crate::commerce::currency(state);
    let mut lines = Vec::new();
    for line in stored.as_array().into_iter().flatten() {
        let product = line["product_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AppError::internal("a stored guest line has no product"))?;
        let quantity = line["quantity"]
            .as_str()
            .and_then(|s| Decimal::from_str(s).ok())
            .unwrap_or(Decimal::ZERO);
        let unit = crate::commerce::price(state, None, product, &currency, quantity)
            .await?
            .ok_or_else(|| AppError::Validation("a product is no longer on sale".into()))?;
        lines.push(crate::promotion::PricedLine {
            product,
            quantity,
            unit_price: unit,
        });
    }
    let subtotal: Decimal = lines.iter().map(|l| l.quantity * l.unit_price).sum();
    let to = ShipTo {
        country: req.country.trim().to_ascii_uppercase(),
        city: req.city.clone(),
    };
    // Products carry no weight yet: a weight band with a lower bound does
    // not match a guest order.
    let rate = rates_for(state, &to)
        .await?
        .into_iter()
        .find(|r| r.id == req.shipping_rate_id)
        .ok_or_else(|| AppError::Validation("that shipping does not reach the address".into()))?;
    let shipping = rate_amount(&rate, Decimal::ZERO, subtotal, req.cash_on_delivery)
        .ok_or_else(|| AppError::Validation("that shipping does not take this order".into()))?;
    let now = Utc::now();
    let coupon = req
        .coupon
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    let view = json!({
        "subtotal": subtotal.to_string().parse::<f64>().unwrap_or(0.0),
        "line_count": lines.len(),
        "currency": currency,
        "guest": true,
    });
    let offers = crate::promotion::applicable_promotions(state, &view, now, coupon).await?;
    if coupon.is_some() && !offers.iter().any(|o| o.coupon) {
        return Err(AppError::Validation(
            "the coupon does not apply to this order".into(),
        ));
    }
    let discounts = crate::promotion::price_offers(&offers, &lines, shipping, now);
    let line_discount: Decimal = discounts
        .iter()
        .filter(|d| !d.free_shipping)
        .map(|d| d.amount)
        .sum();
    let shipping_off: Decimal = discounts
        .iter()
        .filter(|d| d.free_shipping)
        .map(|d| d.amount)
        .sum();
    let shipping = (shipping - shipping_off).max(Decimal::ZERO);
    let (vat, total) = totals(subtotal, line_discount, shipping, vat_rate(state));

    // The buyer: a contact with this phone, else a new one.
    let known: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM contact WHERE (mobile_phone = $1 OR phone = $1) \
           AND (is_active IS NULL OR is_active = true) ORDER BY created_at, id LIMIT 1",
    )
    .bind(phone)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let contact = match known {
        Some(contact) => contact,
        None => {
            attome_records::entity_crud::create_record_for(
                state,
                ctx,
                ctx.user_id,
                "contact",
                json!({ "full_name": req.name.trim(), "mobile_phone": phone }),
            )
            .await?
            .0
        }
    };
    let mut head = json!({
        "name": format!("Guest order {}", now.format("%Y-%m-%d")),
        "status": "draft",
        "ordered_on": now,
        "account_ref": account,
        "currency": currency,
        "updates_contact_ref": contact,
        "delivery_address": req.address.trim(),
        "delivery_phone": phone,
        "subtotal": number(subtotal),
        "discount_total": number(line_discount + shipping_off),
        "shipping_total": number(shipping),
        "tax_total": number(vat),
        "grand_total": number(total),
        "source": "store:guest",
        "payment_status": if req.cash_on_delivery { "due_on_delivery" } else { "awaiting_payment" },
    });
    if req.cash_on_delivery {
        head["cod_amount"] = number(total);
    }
    let (order, _) =
        attome_records::entity_crud::create_record_for(state, ctx, ctx.user_id, "order", head)
            .await?;
    let written = async {
        for line in &lines {
            let off: Decimal = discounts
                .iter()
                .filter(|d| d.product == Some(line.product))
                .map(|d| d.amount)
                .sum();
            let promotion = discounts
                .iter()
                .find(|d| d.product == Some(line.product))
                .map(|d| d.promotion);
            let net = (line.quantity * line.unit_price - off).max(Decimal::ZERO);
            let mut body = json!({
                "order_ref": order,
                "product_ref": line.product,
                "quantity": number(line.quantity),
                "unit_price": number(line.unit_price),
                "line_total": number(net),
                "tax_amount": number((net * vat_rate(state)).round_dp(2)),
            });
            if !off.is_zero() {
                body["discount_amount"] = number(off);
                body["promotion_ref"] = json!(promotion);
            }
            attome_records::entity_crud::create_record_for(
                state,
                ctx,
                ctx.user_id,
                "order_line",
                body,
            )
            .await?;
        }
        if let Some(code) = coupon {
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            crate::promotion::redeem_coupon(&mut tx, code, order, Some(contact)).await?;
            attome_db::tx::commit(tx).await?;
        }
        Ok::<(), AppError>(())
    }
    .await;
    if let Err(error) = written {
        if let Err(undo) = attome_records::entity_crud::delete_record_for(
            state,
            ctx,
            ctx.user_id,
            "order",
            order,
            None,
            &DeleteOrigin::new(DeleteKind::Portal),
        )
        .await
        {
            tracing::error!(%order, error = %undo, "guest checkout: an order was not taken back");
        }
        return Err(error);
    }
    // F8-T8: a risky order gets its review (and so a fulfilment hold).
    crate::risk::assess_logged(state, ctx, order).await;
    // After every write: the payment link, unless cash on delivery.
    let payment_url = if req.cash_on_delivery {
        None
    } else {
        match attome_billing::payment::link::create_link_on_behalf(
            state,
            ctx,
            &attome_billing::payment::link::LinkRequest {
                invoice_id: None,
                order_id: Some(order),
                account_id: None,
                amount: None,
                currency: None,
                expires_in_hours: Some(24),
            },
            Some("a guest buyer"),
        )
        .await
        {
            Ok(link) => Some(link.url),
            Err(error) => {
                tracing::warn!(%order, %error, "guest checkout: no payment link for the order");
                None
            }
        }
    };
    Ok((order, payment_url))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_code_digest_is_per_checkout_and_compared_whole() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        assert_ne!(code_digest(a, "123456"), code_digest(b, "123456"));
        assert!(same(&code_digest(a, " 123456 "), &code_digest(a, "123456")));
        assert!(!same(&code_digest(a, "123457"), &code_digest(a, "123456")));
        assert!(!same("ab", "abc"));
        let code = new_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn guest_totals_tax_the_discounted_lines_and_shipping() {
        let d = |s: &str| Decimal::from_str(s).unwrap();
        assert_eq!(
            totals(d("100"), d("10"), d("25"), d("0.15")),
            (d("17.25"), d("132.25"))
        );
        assert_eq!(
            totals(d("50"), d("80"), d("0"), d("0.15")),
            (d("0"), d("0"))
        );
    }
}

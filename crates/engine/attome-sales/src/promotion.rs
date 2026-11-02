//! F8-T6: promotions and coupons in the shop's pricing order.
//!
//! After each line is priced from the list (D8's price resolution, as the
//! cart prices it) and before VAT, the live promotions are applied in a fixed
//! order: percent, amount, buy X get Y, free shipping, bundle. Each offer
//! takes from what earlier offers left of a line, so offers stack without
//! taking a line below zero. A promotion (sales pack changesets 0030, 0032)
//! is live while `is_enabled`, inside its `starts_on`..`ends_on` window, at
//! or above its `min_subtotal`, and when its `eligibility_rule` (Z11,
//! `attome-rules`) holds for the cart; a promotion with coupons applies only
//! when one of its codes is given. A promotion's `product_ref` limits it to
//! one product; `bundle_skus` names the products of a bundle.
//!
//! [`redeem_coupon`] records a coupon's use on an order inside the caller's
//! transaction, serialised per code by
//! `pg_try_advisory_xact_lock(ADVISORY_LOCK_NAMESPACE, hashtext('attome-sales/coupon:<code>'))`;
//! the coupon's `max_uses` and the promotion's `max_uses_per_customer` are
//! checked under the lock, and a busy lock is a `Conflict`, as is a coupon
//! used up. Each discount is kept on its order line (`discount_amount`,
//! `promotion_ref`) so the cost of every offer can be reported.

use std::collections::HashMap;
use std::str::FromStr;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde_json::Value;
use uuid::Uuid;

/// The kinds of offer, in the order they apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OfferKind {
    Percent,
    Amount,
    BuyXGetY,
    FreeShipping,
    Bundle,
}

impl OfferKind {
    pub fn parse(kind: &str) -> Option<Self> {
        match kind {
            "percent" => Some(Self::Percent),
            "amount" => Some(Self::Amount),
            "buy_x_get_y" => Some(Self::BuyXGetY),
            "free_shipping" => Some(Self::FreeShipping),
            "bundle" => Some(Self::Bundle),
            _ => None,
        }
    }
}

/// A promotion, as pricing reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub promotion: Uuid,
    pub kind: OfferKind,
    /// Percent (10 for 10%), an amount off, or the amount off each complete
    /// bundle.
    pub value: Decimal,
    /// The one product it applies to; `None`: every line.
    pub product: Option<Uuid>,
    /// Buy X get Y: X and Y.
    pub buy: Decimal,
    pub get: Decimal,
    /// The products of a bundle.
    pub bundle: Vec<Uuid>,
    pub min_subtotal: Decimal,
    pub starts_on: Option<DateTime<Utc>>,
    pub ends_on: Option<DateTime<Utc>>,
    /// It applies because its coupon was given.
    pub coupon: bool,
}

/// A priced cart line.
#[derive(Debug, Clone, PartialEq)]
pub struct PricedLine {
    pub product: Uuid,
    pub quantity: Decimal,
    pub unit_price: Decimal,
}

/// What one offer takes off.
#[derive(Debug, Clone, PartialEq)]
pub struct Discount {
    pub promotion: Uuid,
    /// The line's product; `None` for shipping.
    pub product: Option<Uuid>,
    pub amount: Decimal,
    pub free_shipping: bool,
}

fn matches(offer: &Offer, line: &PricedLine) -> bool {
    offer.product.is_none_or(|p| p == line.product)
}

/// Whether `now` is inside the window. Pure.
pub fn in_window(
    starts_on: Option<DateTime<Utc>>,
    ends_on: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    starts_on.is_none_or(|s| s <= now) && ends_on.is_none_or(|e| now <= e)
}

fn take(
    offer: &Offer,
    lines: &[PricedLine],
    left: &mut [Decimal],
    i: usize,
    amount: Decimal,
) -> Option<Discount> {
    let amount = amount.round_dp(2).min(left[i]).max(Decimal::ZERO);
    if amount.is_zero() {
        return None;
    }
    left[i] -= amount;
    Some(Discount {
        promotion: offer.promotion,
        product: Some(lines[i].product),
        amount,
        free_shipping: false,
    })
}

/// `amount` spread over the lines `idx` in proportion to what is left of
/// them, the last taking the rounding remainder.
fn spread(
    offer: &Offer,
    lines: &[PricedLine],
    left: &mut [Decimal],
    idx: &[usize],
    amount: Decimal,
) -> Vec<Discount> {
    let base: Decimal = idx.iter().map(|&i| left[i]).sum();
    if base <= Decimal::ZERO {
        return Vec::new();
    }
    let amount = amount.min(base);
    let mut out = Vec::new();
    let mut given = Decimal::ZERO;
    for (n, &i) in idx.iter().enumerate() {
        let share = if n + 1 == idx.len() {
            amount - given
        } else {
            (amount * left[i] / base).round_dp(2)
        };
        given += share;
        out.extend(take(offer, lines, left, i, share));
    }
    out
}

/// Percent off each matching line. Pure.
pub fn apply_percent(offer: &Offer, lines: &[PricedLine], left: &mut [Decimal]) -> Vec<Discount> {
    let rate = offer.value / Decimal::ONE_HUNDRED;
    (0..lines.len())
        .filter(|&i| matches(offer, &lines[i]))
        .filter_map(|i| {
            let amount = left[i] * rate;
            take(offer, lines, left, i, amount)
        })
        .collect()
}

/// An amount off the matching lines together. Pure.
pub fn apply_amount(offer: &Offer, lines: &[PricedLine], left: &mut [Decimal]) -> Vec<Discount> {
    let idx: Vec<usize> = (0..lines.len())
        .filter(|&i| matches(offer, &lines[i]))
        .collect();
    spread(offer, lines, left, &idx, offer.value)
}

/// Buy X get Y free of a matching line: of every X + Y bought, Y are free.
/// Pure.
pub fn apply_buy_x_get_y(
    offer: &Offer,
    lines: &[PricedLine],
    left: &mut [Decimal],
) -> Vec<Discount> {
    let group = offer.buy + offer.get;
    if offer.buy <= Decimal::ZERO || offer.get <= Decimal::ZERO {
        return Vec::new();
    }
    (0..lines.len())
        .filter(|&i| matches(offer, &lines[i]))
        .filter_map(|i| {
            let free = (lines[i].quantity / group).floor() * offer.get;
            take(offer, lines, left, i, free * lines[i].unit_price)
        })
        .collect()
}

/// The shipping charge off. Pure.
pub fn apply_free_shipping(offer: &Offer, shipping: Decimal) -> Vec<Discount> {
    if shipping <= Decimal::ZERO {
        return Vec::new();
    }
    vec![Discount {
        promotion: offer.promotion,
        product: None,
        amount: shipping,
        free_shipping: true,
    }]
}

/// The offer's value off each complete set of the bundle's products. Pure.
pub fn apply_bundle(offer: &Offer, lines: &[PricedLine], left: &mut [Decimal]) -> Vec<Discount> {
    if offer.bundle.is_empty() {
        return Vec::new();
    }
    let mut sets: Option<Decimal> = None;
    for product in &offer.bundle {
        let have: Decimal = lines
            .iter()
            .filter(|l| l.product == *product)
            .map(|l| l.quantity)
            .sum();
        let have = have.floor();
        sets = Some(sets.map_or(have, |s| s.min(have)));
    }
    let sets = sets.unwrap_or(Decimal::ZERO);
    if sets <= Decimal::ZERO {
        return Vec::new();
    }
    let idx: Vec<usize> = (0..lines.len())
        .filter(|&i| offer.bundle.contains(&lines[i].product))
        .collect();
    spread(offer, lines, left, &idx, offer.value * sets)
}

/// Every live offer applied to `lines` and `shipping`, in the pricing
/// order. Pure.
pub fn price_offers(
    offers: &[Offer],
    lines: &[PricedLine],
    shipping: Decimal,
    now: DateTime<Utc>,
) -> Vec<Discount> {
    let subtotal: Decimal = lines.iter().map(|l| l.quantity * l.unit_price).sum();
    let mut left: Vec<Decimal> = lines.iter().map(|l| l.quantity * l.unit_price).collect();
    let mut live: Vec<&Offer> = offers
        .iter()
        .filter(|o| in_window(o.starts_on, o.ends_on, now) && subtotal >= o.min_subtotal)
        .collect();
    live.sort_by_key(|o| o.kind);
    let mut shipping_left = shipping;
    let mut out = Vec::new();
    for offer in live {
        let found = match offer.kind {
            OfferKind::Percent => apply_percent(offer, lines, &mut left),
            OfferKind::Amount => apply_amount(offer, lines, &mut left),
            OfferKind::BuyXGetY => apply_buy_x_get_y(offer, lines, &mut left),
            OfferKind::FreeShipping => {
                let d = apply_free_shipping(offer, shipping_left);
                shipping_left = Decimal::ZERO;
                d
            }
            OfferKind::Bundle => apply_bundle(offer, lines, &mut left),
        };
        out.extend(found);
    }
    out
}

fn dec(text: Option<&str>) -> Decimal {
    text.and_then(|t| Decimal::from_str(t.trim()).ok())
        .unwrap_or(Decimal::ZERO)
}

type PromotionRow = (
    Uuid,
    String,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    bool,
    bool,
);

/// The promotions live at `now` whose rule holds for `cart` (the cart as
/// the rule sees it) and, for a promotion with coupons, whose code is
/// `coupon`.
pub async fn applicable_promotions(
    state: &EngineState,
    cart: &Value,
    now: DateTime<Utc>,
    coupon: Option<&str>,
) -> Result<Vec<Offer>, AppError> {
    let rows: Vec<PromotionRow> = sqlx::query_as(
        "SELECT p.id, p.kind::text, p.value::text, p.product_ref, p.buy_quantity::text, \
                p.get_quantity::text, p.bundle_skus, p.min_subtotal::text, p.eligibility_rule, \
                p.starts_on, p.ends_on, \
                EXISTS (SELECT 1 FROM coupon c WHERE c.promotion_ref = p.id \
                          AND (c.is_active IS NULL OR c.is_active = true)), \
                EXISTS (SELECT 1 FROM coupon c WHERE c.promotion_ref = p.id AND c.code = $2 \
                          AND (c.is_active IS NULL OR c.is_active = true)) \
           FROM promotion p \
          WHERE p.is_enabled = true AND (p.is_active IS NULL OR p.is_active = true) \
            AND (p.starts_on IS NULL OR p.starts_on <= $1) \
            AND (p.ends_on IS NULL OR p.ends_on >= $1) \
          ORDER BY p.created_at, p.id LIMIT 100",
    )
    .bind(now)
    .bind(coupon.map(str::trim))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let skus: Vec<String> = rows
        .iter()
        .filter_map(|r| r.6.as_deref())
        .flat_map(|s| s.split(','))
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    let by_sku: HashMap<String, Uuid> = if skus.is_empty() {
        HashMap::new()
    } else {
        sqlx::query_as::<_, (String, Uuid)>(
            "SELECT sku, id FROM product WHERE sku = ANY($1) \
               AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&skus)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .collect()
    };
    let mut offers = Vec::new();
    for (id, kind, value, product, buy, get, bundle, min, rule, starts, ends, coupons, coded) in
        rows
    {
        let Some(kind) = OfferKind::parse(&kind) else {
            continue;
        };
        if coupons && !coded {
            continue;
        }
        if !crate::plays::applies(rule.as_deref(), cart) {
            continue;
        }
        offers.push(Offer {
            promotion: id,
            kind,
            value: dec(value.as_deref()),
            product,
            buy: dec(buy.as_deref()),
            get: dec(get.as_deref()),
            bundle: bundle
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter_map(|s| by_sku.get(s.trim()).copied())
                .collect(),
            min_subtotal: dec(min.as_deref()),
            starts_on: starts,
            ends_on: ends,
            coupon: coded,
        });
    }
    Ok(offers)
}

/// Records `code`'s use on `order` for `contact` in `tx`; the redemption's
/// id. Once per coupon and order: a second call for the same order answers
/// the first redemption.
pub async fn redeem_coupon(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    code: &str,
    order: Uuid,
    contact: Option<Uuid>,
) -> Result<Uuid, AppError> {
    let code = code.trim();
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-sales/coupon:{code}"))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict("the coupon is being redeemed"));
    }
    let coupon: Option<(Uuid, Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT c.id, c.uses_count::text, p.max_uses::text, p.max_uses_per_customer::text \
           FROM coupon c JOIN promotion p ON p.id = c.promotion_ref \
          WHERE c.code = $1 AND (c.is_active IS NULL OR c.is_active = true) \
            AND (p.is_active IS NULL OR p.is_active = true) AND p.is_enabled = true",
    )
    .bind(code)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((coupon, used, max, per_customer)) = coupon else {
        return Err(AppError::Validation("no such coupon".into()));
    };
    let earlier: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM coupon_redemption WHERE coupon_ref = $1 AND order_ref = $2 \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(coupon)
    .bind(order)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(earlier) = earlier {
        return Ok(earlier);
    }
    let (used, max, per_customer) = (
        dec(used.as_deref()),
        dec(max.as_deref()),
        dec(per_customer.as_deref()),
    );
    if max > Decimal::ZERO && used >= max {
        return Err(AppError::Conflict("the coupon is used up"));
    }
    if let (Some(contact), true) = (contact, per_customer > Decimal::ZERO) {
        let theirs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM coupon_redemption \
              WHERE coupon_ref = $1 AND contact_ref = $2 \
                AND (is_active IS NULL OR is_active = true)",
        )
        .bind(coupon)
        .bind(contact)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if Decimal::from(theirs) >= per_customer {
            return Err(AppError::Conflict(
                "the coupon is used up for this customer",
            ));
        }
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO coupon_redemption (id, coupon_ref, order_ref, contact_ref, redeemed_at) \
         VALUES ($1, $2, $3, $4, now())",
    )
    .bind(id)
    .bind(coupon)
    .bind(order)
    .bind(contact)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE coupon SET uses_count = COALESCE(uses_count, 0) + 1, \
                row_version = row_version + 1, modified_at = now() \
          WHERE id = $1",
    )
    .bind(coupon)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn d(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn offer(kind: OfferKind, value: &str) -> Offer {
        Offer {
            promotion: Uuid::from_u128(1),
            kind,
            value: d(value),
            product: None,
            buy: Decimal::ZERO,
            get: Decimal::ZERO,
            bundle: Vec::new(),
            min_subtotal: Decimal::ZERO,
            starts_on: None,
            ends_on: None,
            coupon: false,
        }
    }

    fn line(product: u128, quantity: &str, price: &str) -> PricedLine {
        PricedLine {
            product: Uuid::from_u128(product),
            quantity: d(quantity),
            unit_price: d(price),
        }
    }

    fn total(discounts: &[Discount]) -> Decimal {
        discounts.iter().map(|x| x.amount).sum()
    }

    #[test]
    fn percent_offer() {
        let lines = [line(10, "2", "50"), line(11, "1", "30")];
        let got = price_offers(
            &[offer(OfferKind::Percent, "10")],
            &lines,
            Decimal::ZERO,
            Utc::now(),
        );
        assert_eq!(total(&got), d("13"));
        let mut only = offer(OfferKind::Percent, "10");
        only.product = Some(Uuid::from_u128(11));
        let got = price_offers(&[only], &lines, Decimal::ZERO, Utc::now());
        assert_eq!(total(&got), d("3"));
        // Offers stack in the pricing order, not the listed one: 10% of
        // 100 first, then 20 off the 90 left.
        let offers = [
            offer(OfferKind::Amount, "20"),
            offer(OfferKind::Percent, "10"),
        ];
        let got = price_offers(&offers, &[line(10, "1", "100")], Decimal::ZERO, Utc::now());
        assert_eq!(got[0].amount, d("10"));
        assert_eq!(total(&got), d("30"));
    }

    #[test]
    fn amount_offer() {
        let lines = [line(10, "1", "60"), line(11, "1", "40")];
        let got = price_offers(
            &[offer(OfferKind::Amount, "25")],
            &lines,
            Decimal::ZERO,
            Utc::now(),
        );
        assert_eq!(total(&got), d("25"));
        assert_eq!(got[0].amount, d("15"), "spread by line value");
        let got = price_offers(
            &[offer(OfferKind::Amount, "500")],
            &lines,
            Decimal::ZERO,
            Utc::now(),
        );
        assert_eq!(total(&got), d("100"), "never below zero");
    }

    #[test]
    fn buy_x_get_y_offer() {
        let mut o = offer(OfferKind::BuyXGetY, "0");
        o.buy = d("2");
        o.get = d("1");
        let got = price_offers(
            &[o.clone()],
            &[line(10, "7", "10")],
            Decimal::ZERO,
            Utc::now(),
        );
        assert_eq!(total(&got), d("20"), "two groups of three: two free");
        let got = price_offers(&[o], &[line(10, "2", "10")], Decimal::ZERO, Utc::now());
        assert!(got.is_empty());
    }

    #[test]
    fn free_shipping_offer() {
        let got = price_offers(
            &[offer(OfferKind::FreeShipping, "0")],
            &[line(10, "1", "10")],
            d("25"),
            Utc::now(),
        );
        assert_eq!(got.len(), 1);
        assert!(got[0].free_shipping);
        assert_eq!(got[0].amount, d("25"));
        let mut gated = offer(OfferKind::FreeShipping, "0");
        gated.min_subtotal = d("200");
        assert!(price_offers(&[gated], &[line(10, "1", "10")], d("25"), Utc::now()).is_empty());
    }

    #[test]
    fn bundle_offer() {
        let mut o = offer(OfferKind::Bundle, "15");
        o.bundle = vec![Uuid::from_u128(10), Uuid::from_u128(11)];
        let lines = [line(10, "2", "50"), line(11, "3", "20")];
        let got = price_offers(&[o.clone()], &lines, Decimal::ZERO, Utc::now());
        assert_eq!(total(&got), d("30"), "two complete sets");
        let got = price_offers(&[o], &[line(10, "2", "50")], Decimal::ZERO, Utc::now());
        assert!(got.is_empty(), "no set without every product");
    }

    #[test]
    fn expired_promotion_not_applied() {
        let now = Utc::now();
        let mut o = offer(OfferKind::Percent, "10");
        o.ends_on = Some(now - Duration::days(1));
        assert!(price_offers(&[o.clone()], &[line(10, "1", "100")], Decimal::ZERO, now).is_empty());
        o.ends_on = None;
        o.starts_on = Some(now + Duration::days(1));
        assert!(price_offers(&[o], &[line(10, "1", "100")], Decimal::ZERO, now).is_empty());
    }
}

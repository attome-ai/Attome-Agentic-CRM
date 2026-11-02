//! F8-T2: what an online shop exchanges with Attome, the same for every
//! platform (Salla, Zid, Shopify, WooCommerce; F8-T3, F8-T4).
//!
//! An adapter implements [`ShopPlatform`] and maps its own JSON into the
//! neutral [`ShopOrder`], [`ShopCustomer`] and [`ShopProduct`]; attome-sales'
//! `shop_sync::upsert_from_source` writes them through the record engine as
//! D10 orders, D1 contacts and D8 products, once per source id (the
//! `shop_sync_map`, sales pack changeset 0030). Amounts are decimals in the
//! order's own currency: nothing here assumes one.
//!
//! The helpers are pure: [`normalise_phone`] (E.164, so a shop customer
//! matches the contact already on file), [`split_vat_inclusive`] (a price
//! that includes VAT into net and VAT) and [`sum_lines`].

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

/// The connection kind a shop connection is registered under.
pub const KIND: &str = "commerce";

/// A shop customer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShopCustomer {
    /// The shop's id for the customer.
    pub source_id: String,
    pub name: String,
    pub email: Option<String>,
    /// As the shop has it; [`normalise_phone`] makes it E.164.
    pub phone: Option<String>,
}

/// One line of a shop order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShopOrderLine {
    /// The shop's id for the product.
    pub source_product_id: String,
    pub sku: Option<String>,
    pub name: String,
    pub quantity: Decimal,
    /// The price of one, as the shop charged it (with VAT when the order's
    /// `prices_include_vat`).
    pub unit_price: Decimal,
    /// The line's VAT rate as a fraction (0.15), when the shop sends one.
    pub vat_rate: Option<Decimal>,
}

/// A shop order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShopOrder {
    /// The shop's id for the order.
    pub source_id: String,
    /// The number the shop shows its customer.
    pub number: String,
    /// ISO 4217, from the shop; never assumed.
    pub currency: String,
    pub placed_at: DateTime<Utc>,
    /// The shop's own status word, kept as it is.
    pub status: String,
    pub customer: Option<ShopCustomer>,
    pub lines: Vec<ShopOrderLine>,
    /// Whether the line prices include VAT.
    pub prices_include_vat: bool,
    pub shipping: Decimal,
    pub discount: Decimal,
    /// What the shop says the customer pays in all.
    pub total: Decimal,
    /// Cash on delivery: the amount to collect.
    pub cod_amount: Option<Decimal>,
    pub delivery_address: Option<String>,
    pub delivery_phone: Option<String>,
}

/// A shop product.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShopProduct {
    /// The shop's id for the product.
    pub source_id: String,
    pub sku: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub price: Option<Decimal>,
    pub currency: Option<String>,
    pub stock: Option<Decimal>,
}

/// A page of records changed since a cursor.
#[derive(Debug, Clone, PartialEq)]
pub struct ShopPage<T> {
    pub items: Vec<T>,
    /// Where the next page starts; `None` on the last page.
    pub next_cursor: Option<String>,
}

/// A boxed future, as the other connector traits in this crate return.
pub type ShopFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// One shop platform. Every call goes out through the outbound guard with a
/// timeout, and none runs inside a database transaction.
pub trait ShopPlatform: Send + Sync {
    /// The platform's name (`salla`, `zid`, `shopify`, `woocommerce`).
    fn platform(&self) -> &'static str;
    /// Orders changed since `cursor` (`None`: from the start).
    fn fetch_orders_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopOrder>>;
    /// Customers changed since `cursor`.
    fn fetch_customers_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopCustomer>>;
    /// Products changed since `cursor`.
    fn fetch_products_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopProduct>>;
    /// Sets the shop's stock of `source_product_id`.
    fn push_stock<'a>(
        &'a self,
        source_product_id: &'a str,
        quantity: Decimal,
    ) -> ShopFuture<'a, ()>;
    /// Creates or updates a product in the shop; the shop's id for it.
    fn push_product<'a>(&'a self, product: &'a ShopProduct) -> ShopFuture<'a, String>;
}

/// `raw` as E.164 (`+9665…`), reading a number without a country code as
/// one in `default_country` (the calling code without `+`, `966` for Saudi
/// Arabia). `None` when it is not a phone number.
pub fn normalise_phone(raw: &str, default_country: &str) -> Option<String> {
    let trimmed = raw.trim();
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let international = if trimmed.starts_with('+') {
        digits
    } else if let Some(rest) = digits.strip_prefix("00") {
        rest.to_owned()
    } else if digits.starts_with(default_country) && digits.len() > 10 {
        digits
    } else {
        format!("{default_country}{}", digits.trim_start_matches('0'))
    };
    // E.164: at most 15 digits; anything under 8 is not a subscriber number.
    (8..=15)
        .contains(&international.len())
        .then(|| format!("+{international}"))
}

/// A lower-cased, trimmed email; `None` when it has no `@`.
pub fn normalise_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    (email.contains('@') && !email.starts_with('@') && !email.ends_with('@')).then_some(email)
}

/// A price that includes VAT at `rate` (a fraction, 0.15) as `(net, vat)`,
/// net rounded to 2 places and VAT the rest, so the two add back to `gross`.
pub fn split_vat_inclusive(gross: Decimal, rate: Decimal) -> (Decimal, Decimal) {
    if rate <= Decimal::ZERO {
        return (gross, Decimal::ZERO);
    }
    let net = (gross / (Decimal::ONE + rate)).round_dp(2);
    (net, gross - net)
}

/// The sum of quantity × unit price over `lines`.
pub fn sum_lines(lines: &[ShopOrderLine]) -> Decimal {
    lines
        .iter()
        .map(|line| line.quantity * line.unit_price)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn normalises_saudi_phone_to_e164() {
        for raw in [
            "0501234567",
            "501234567",
            "+966 50 123 4567",
            "00966501234567",
            "966501234567",
        ] {
            assert_eq!(
                normalise_phone(raw, "966").as_deref(),
                Some("+966501234567"),
                "{raw}"
            );
        }
        assert_eq!(
            normalise_phone("+971 50 123 4567", "966").as_deref(),
            Some("+971501234567")
        );
        assert_eq!(normalise_phone("n/a", "966"), None);
        assert_eq!(normalise_phone("12", "966"), None);
        assert_eq!(
            normalise_email(" Sara@Example.COM ").as_deref(),
            Some("sara@example.com")
        );
        assert_eq!(normalise_email("nobody"), None);
    }

    #[test]
    fn splits_vat_inclusive_price() {
        assert_eq!(
            split_vat_inclusive(dec("115"), dec("0.15")),
            (dec("100"), dec("15"))
        );
        let (net, vat) = split_vat_inclusive(dec("10"), dec("0.15"));
        assert_eq!(net, dec("8.70"));
        assert_eq!(net + vat, dec("10"), "the parts add back to the price");
        assert_eq!(
            split_vat_inclusive(dec("50"), Decimal::ZERO),
            (dec("50"), Decimal::ZERO)
        );
    }

    #[test]
    fn sums_line_totals() {
        let line = |q: &str, p: &str| ShopOrderLine {
            source_product_id: "p".into(),
            sku: None,
            name: "x".into(),
            quantity: dec(q),
            unit_price: dec(p),
            vat_rate: None,
        };
        assert_eq!(
            sum_lines(&[line("2", "10.50"), line("1", "4.25")]),
            dec("25.25")
        );
        assert_eq!(sum_lines(&[]), Decimal::ZERO);
    }
}

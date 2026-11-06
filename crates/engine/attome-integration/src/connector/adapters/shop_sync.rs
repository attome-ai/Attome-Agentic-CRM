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

/// F8-T3: how long one call to a shop platform may take.
pub const SHOP_TIMEOUT_SECS: u64 = 15;

/// F8-T3: the most items one backfill page asks a platform for.
pub const SHOP_PAGE_SIZE: u32 = 100;

/// F8-T3: one shop platform's HTTP: every call through the SSRF-guarded
/// client with [`SHOP_TIMEOUT_SECS`], JSON in and out. A transport failure,
/// a 429 or a 5xx is the `commerce` capability being down (retry later);
/// any other answer that is not 2xx is refused with its status only, never
/// the body (it can carry customer data).
#[derive(Clone)]
pub struct ShopHttp {
    platform: &'static str,
    base_url: String,
    client: std::sync::Arc<attome_server::ssrf_guard::GuardedClient>,
}

impl std::fmt::Debug for ShopHttp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShopHttp")
            .field("platform", &self.platform)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl ShopHttp {
    /// The guarded client for `base_url` (no trailing slash needed).
    pub fn new(platform: &'static str, base_url: &str) -> Result<Self, AppError> {
        let client = attome_server::ssrf_guard::GuardedClient::new(SHOP_TIMEOUT_SECS)
            .map_err(AppError::internal)?;
        Ok(Self {
            platform,
            base_url: base_url.trim_end_matches('/').to_owned(),
            client: std::sync::Arc::new(client),
        })
    }

    /// `method` on `path` (under the base URL) with `query`, `headers` and
    /// an optional JSON `body`; the answer's JSON.
    pub async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        query: &[(&str, String)],
        headers: &[(&str, String)],
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value, AppError> {
        let mut url = reqwest::Url::parse(&format!("{}{path}", self.base_url)).map_err(|_| {
            AppError::Validation(format!("{} base URL is not a URL", self.platform))
        })?;
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())));
        }
        let mut request = self
            .client
            .request(method, url)
            .map_err(|e| AppError::Validation(format!("{}: {e}", self.platform)))?
            .header(reqwest::header::ACCEPT, "application/json");
        for (name, value) in headers {
            request = request.header(*name, value.as_str());
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|e| {
            tracing::warn!(platform = self.platform, error = %e.without_url(), "shop platform unreachable");
            AppError::CapabilityUnavailable("commerce")
        })?;
        let status = response.status();
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            tracing::warn!(platform = self.platform, %status, "shop platform unavailable");
            return Err(AppError::CapabilityUnavailable("commerce"));
        }
        if !status.is_success() {
            return Err(AppError::Validation(format!(
                "{} answered {status}",
                self.platform
            )));
        }
        let text = response.text().await.map_err(|e| {
            tracing::warn!(platform = self.platform, error = %e.without_url(), "shop answer not read");
            AppError::CapabilityUnavailable("commerce")
        })?;
        if text.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_str(&text).map_err(|_| {
            AppError::Validation(format!(
                "{} answered a body that is not JSON",
                self.platform
            ))
        })
    }
}

/// F8-T3: a money or quantity value as a platform sends it: a JSON number
/// or a numeric string (`"6954.63998402370000"`, `"15.00"`). Pure.
pub fn decimal_of(value: &serde_json::Value) -> Option<Decimal> {
    use std::str::FromStr;
    match value {
        serde_json::Value::Number(n) => Decimal::from_str(&n.to_string())
            .or_else(|_| Decimal::from_scientific(&n.to_string()))
            .ok(),
        serde_json::Value::String(s) => Decimal::from_str(s.trim().replace(',', "").as_str()).ok(),
        _ => None,
    }
}

/// F8-T3: an id as a platform sends it (a number or a string), as text.
pub fn id_of(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
        _ => None,
    }
}

/// F8-T3: the UTC offset of the Gulf time zones a Saudi shop reports its
/// times in, in seconds; `None` for any other zone (there is no time-zone
/// database in this crate, and a guessed offset would misdate the order).
pub fn gulf_offset_secs(zone: &str) -> Option<i32> {
    match zone.trim() {
        "Asia/Riyadh" | "Asia/Kuwait" | "Asia/Qatar" | "Asia/Bahrain" | "Asia/Aden"
        | "Asia/Baghdad" | "+03:00" => Some(3 * 3600),
        "Asia/Dubai" | "Asia/Muscat" | "+04:00" => Some(4 * 3600),
        "UTC" | "Etc/UTC" | "+00:00" | "Z" => Some(0),
        _ => None,
    }
}

/// F8-T3: a local `YYYY-MM-DD HH:MM:SS[.ffffff]` in `zone` as UTC. Pure.
pub fn local_time_utc(raw: &str, zone: &str) -> Option<DateTime<Utc>> {
    use chrono::{FixedOffset, NaiveDateTime, TimeZone};
    let naive = NaiveDateTime::parse_from_str(raw.trim(), "%Y-%m-%d %H:%M:%S%.f").ok()?;
    let offset = FixedOffset::east_opt(gulf_offset_secs(zone)?)?;
    offset
        .from_local_datetime(&naive)
        .single()
        .map(|t| t.with_timezone(&Utc))
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

    #[test]
    fn reads_platform_numbers_ids_and_local_times() {
        assert_eq!(decimal_of(&serde_json::json!(16.39)), Some(dec("16.39")));
        assert_eq!(
            decimal_of(&serde_json::json!("6954.63998402370000")),
            Some(dec("6954.63998402370000"))
        );
        assert_eq!(
            decimal_of(&serde_json::json!("1,159.11")),
            Some(dec("1159.11"))
        );
        assert_eq!(decimal_of(&serde_json::json!(null)), None);
        assert_eq!(
            id_of(&serde_json::json!(1333249299)).as_deref(),
            Some("1333249299")
        );
        assert_eq!(id_of(&serde_json::json!(" ab ")).as_deref(), Some("ab"));
        assert_eq!(id_of(&serde_json::json!("")), None);
        let t = local_time_utc("2026-08-02 18:08:47.000000", "Asia/Riyadh").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-08-02T15:08:47+00:00");
        assert!(
            local_time_utc("2026-08-02 18:08:47", "Europe/Paris").is_none(),
            "no guessed offset"
        );
    }
}

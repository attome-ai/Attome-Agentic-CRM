//! F8-T3: Salla, on the neutral [`ShopPlatform`] (F8-T2).
//!
//! Salla's Merchant API (`https://api.salla.dev/admin/v2`), with the
//! store's OAuth access token as a bearer token (the shop connection's
//! encrypted credential; Salla issues it to a partner app the merchant
//! installs).
//!
//! What the shapes are read from: Salla's published API reference
//! (docs.salla.dev, read 2026-11-06), not a recorded payload. No partner
//! access exists yet (the design lists it as open), so the fixture
//! `tests/fixtures/shop/salla_order.json` is built from those documented
//! examples, and a recorded payload replaces it once there is one.
//!
//! - **Orders.** `GET /orders` lists orders (no line prices: its `items`
//!   carry only names and quantities). Each order is read with
//!   `GET /orders/{id}?format=light` (amounts, customer; the light format,
//!   the default since 2026-09-01, has no items) and its lines with
//!   `GET /orders/items?order_id={id}`. A line's `amounts.price_without_tax`
//!   is the net unit price and `amounts.tax.percent` its VAT rate, so
//!   [`ShopOrder::prices_include_vat`] is false. An order item carries no
//!   product id, so a line's product is its SKU, or `item:<id>` without one.
//! - **Backfill.** `GET /orders?sort_by=updated_at-asc&page=N`: the cursor
//!   is the page number in that order, so a run resumes where the last one
//!   stopped and orders changed since land at the end. The caller stores
//!   the cursor only after the page commits (attome-sales `shop_sync`).
//! - **Webhooks.** `order.created` and `order.updated` arrive at an inbound
//!   hook with the `salla` preset (`attome_integration::inbound`: the
//!   `X-Salla-Signature` HMAC-SHA256 of the body, compared in constant
//!   time); [`verify_webhook`] is the same check for a caller holding the
//!   raw request. [`parse_webhook`] reads the event and its order.
//! - **Money and time.** Amounts are numbers or numeric strings
//!   ([`decimal_of`]); times are local with a named zone
//!   ([`local_time_utc`]; an order in a zone outside the Gulf is refused
//!   rather than misdated).
//! - Raw payloads are never logged: a mapping failure names the field only.

use reqwest::Method;
use rust_decimal::Decimal;
use serde_json::Value;

use super::shop_sync::{
    SHOP_PAGE_SIZE, ShopCustomer, ShopFuture, ShopHttp, ShopOrder, ShopOrderLine, ShopPage,
    ShopPlatform, ShopProduct, decimal_of, id_of, local_time_utc, normalise_email, normalise_phone,
};
use attome_types::AppError;

/// Salla's production API base URL.
pub const BASE_URL: &str = "https://api.salla.dev/admin/v2";

/// The webhook events this adapter reads.
pub const ORDER_EVENTS: [&str; 2] = ["order.created", "order.updated"];

/// Saudi Arabia's calling code, for a number given without one.
const DEFAULT_COUNTRY: &str = "966";

fn amount(v: &Value) -> Option<Decimal> {
    // `{"amount": 16.39, "currency": "SAR"}` or a bare number.
    if v.is_object() {
        decimal_of(&v["amount"])
    } else {
        decimal_of(v)
    }
}

fn currency_of(v: &Value) -> Option<String> {
    v["currency"]
        .as_str()
        .map(str::trim)
        .filter(|c| c.len() == 3)
        .map(str::to_ascii_uppercase)
}

/// A Salla customer (`{id, first_name, last_name, full_name?, mobile,
/// mobile_code, email}`, as in an order and in `GET /customers`). Pure.
pub fn map_customer(c: &Value) -> Result<ShopCustomer, String> {
    let source_id = id_of(&c["id"]).ok_or("customer.id")?;
    let name = c["full_name"]
        .as_str()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            [c["first_name"].as_str(), c["last_name"].as_str()]
                .into_iter()
                .flatten()
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        });
    // `mobile` is a number without its code (557777777), `mobile_code` the
    // code with `+` (+966).
    let phone = id_of(&c["mobile"]).and_then(|mobile| {
        let code = c["mobile_code"].as_str().unwrap_or_default().trim();
        normalise_phone(&format!("{code}{mobile}"), DEFAULT_COUNTRY)
    });
    Ok(ShopCustomer {
        source_id,
        name,
        email: c["email"].as_str().and_then(normalise_email),
        phone,
    })
}

/// One line of `GET /orders/items` (`{id, name, sku, quantity, amounts:
/// {price_without_tax, total_discount, tax: {percent, amount}, total}}`).
/// Pure.
pub fn map_line(item: &Value) -> Result<ShopOrderLine, String> {
    let sku = item["sku"]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let source_product_id = match &sku {
        Some(sku) => sku.clone(),
        None => format!("item:{}", id_of(&item["id"]).ok_or("item.id")?),
    };
    let quantity = decimal_of(&item["quantity"]).ok_or("item.quantity")?;
    let unit_price =
        amount(&item["amounts"]["price_without_tax"]).ok_or("item.amounts.price_without_tax")?;
    let vat_rate = decimal_of(&item["amounts"]["tax"]["percent"])
        .map(|percent| (percent / Decimal::ONE_HUNDRED).normalize());
    Ok(ShopOrderLine {
        source_product_id,
        sku,
        name: item["name"].as_str().unwrap_or_default().trim().to_owned(),
        quantity,
        unit_price,
        vat_rate,
    })
}

/// An order from `GET /orders/{id}` (`data`) and its lines from
/// `GET /orders/items?order_id={id}` (`data`). Pure.
///
/// `shipping` is the shipping cost plus Salla's cash-on-delivery fee, the
/// two charges the order adds to its lines; `discount` the sum of its
/// `discounts`; `cod_amount` the total when the order is paid in cash on
/// delivery.
pub fn map_order(order: &Value, items: &[Value]) -> Result<ShopOrder, String> {
    let source_id = id_of(&order["id"]).ok_or("order.id")?;
    let number = id_of(&order["reference_id"]).unwrap_or_else(|| source_id.clone());
    let amounts = &order["amounts"];
    let total = amount(&amounts["total"])
        .or_else(|| amount(&order["total"]))
        .ok_or("order.amounts.total")?;
    let currency = order["currency"]
        .as_str()
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 3)
        .or_else(|| currency_of(&amounts["total"]))
        .or_else(|| currency_of(&order["total"]))
        .ok_or("order.currency")?;
    let date = &order["date"];
    let placed_at = local_time_utc(
        date["date"].as_str().ok_or("order.date.date")?,
        date["timezone"].as_str().unwrap_or("Asia/Riyadh"),
    )
    .ok_or("order.date (a time zone outside the Gulf, or not a time)")?;
    let status = order["status"]["slug"]
        .as_str()
        .or_else(|| order["status"].as_str())
        .unwrap_or_default()
        .to_owned();
    let customer = if order["customer"].is_object() {
        Some(map_customer(&order["customer"])?)
    } else {
        None
    };
    let lines = items.iter().map(map_line).collect::<Result<Vec<_>, _>>()?;
    let shipping = amount(&amounts["shipping_cost"]).unwrap_or_default()
        + amount(&amounts["cash_on_delivery"]).unwrap_or_default();
    let discount = amounts["discounts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| decimal_of(&d["discount"]))
        .map(|d| d.abs())
        .sum();
    let cod = order["payment_method"].as_str() == Some("cod");
    let phone = customer.as_ref().and_then(|c| c.phone.clone());
    Ok(ShopOrder {
        source_id,
        number,
        currency,
        placed_at,
        status,
        customer,
        lines,
        prices_include_vat: false,
        shipping,
        discount,
        total,
        cod_amount: cod.then_some(total),
        // The light format's `receiver` and `shipping` address shapes are
        // not in the documented example; read once a payload is recorded.
        delivery_address: None,
        delivery_phone: phone,
    })
}

/// A Salla product (`{id, sku, name, description, price: {amount,
/// currency}, quantity}`). Pure.
pub fn map_product(p: &Value) -> Result<ShopProduct, String> {
    Ok(ShopProduct {
        source_id: id_of(&p["id"]).ok_or("product.id")?,
        sku: p["sku"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        name: p["name"].as_str().unwrap_or_default().trim().to_owned(),
        description: p["description"]
            .as_str()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(str::to_owned),
        price: amount(&p["price"]),
        currency: currency_of(&p["price"]),
        stock: decimal_of(&p["quantity"]),
    })
}

/// A webhook body's event and its order (`{"event", "merchant",
/// "created_at", "data": {...}}`); `None` for an event this adapter does
/// not read. Pure.
pub fn parse_webhook(body: &Value) -> Option<(&str, &Value)> {
    let event = body["event"].as_str()?;
    (ORDER_EVENTS.contains(&event) && body["data"].is_object()).then(|| (event, &body["data"]))
}

/// Whether `signature` (the `X-Salla-Signature` header, hex) is the
/// HMAC-SHA256 of `body` under `secret`, compared in constant time.
pub fn verify_webhook(secret: &str, body: &[u8], signature: &str) -> bool {
    let mut headers = axum::http::HeaderMap::new();
    let Ok(value) = axum::http::HeaderValue::from_str(signature.trim()) else {
        return false;
    };
    headers.insert("x-salla-signature", value);
    crate::inbound::verify(
        &serde_json::json!({ "kind": "hmac", "preset": "salla" }),
        secret,
        &headers,
        body,
        chrono::Utc::now().timestamp(),
    )
    .is_ok()
}

/// The page number a cursor names (`None`: the first).
fn page_of(cursor: Option<&str>) -> Result<u32, AppError> {
    match cursor {
        None => Ok(1),
        Some(c) => c
            .parse::<u32>()
            .ok()
            .filter(|p| *p >= 1)
            .ok_or_else(|| AppError::Validation("a Salla cursor is a page number".into())),
    }
}

/// The next cursor from a list answer's `pagination` (`currentPage`,
/// `totalPages`). Pure.
pub fn next_cursor(answer: &Value) -> Option<String> {
    let p = &answer["pagination"];
    let current = p["currentPage"].as_u64()?;
    let pages = p["totalPages"].as_u64()?;
    (current < pages).then(|| (current + 1).to_string())
}

fn mapped<T>(what: &str, result: Result<T, String>) -> Result<T, AppError> {
    result.map_err(|field| {
        tracing::warn!(platform = "salla", what, field = %field, "a Salla record could not be read");
        AppError::Validation(format!("a Salla {what} could not be read: {field}"))
    })
}

/// Salla for one store.
#[derive(Debug, Clone)]
pub struct SallaShop {
    http: ShopHttp,
    access_token: String,
}

impl SallaShop {
    /// `base_url` is [`BASE_URL`] unless the connection names another (a
    /// sandbox); `access_token` the store's OAuth token.
    pub fn new(base_url: &str, access_token: String) -> Result<Self, AppError> {
        Ok(Self {
            http: ShopHttp::new("salla", base_url)?,
            access_token,
        })
    }

    fn auth(&self) -> [(&'static str, String); 1] {
        [("authorization", format!("Bearer {}", self.access_token))]
    }

    async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, AppError> {
        self.http
            .call(Method::GET, path, query, &self.auth(), None)
            .await
    }

    async fn list(
        &self,
        path: &str,
        cursor: Option<&str>,
    ) -> Result<(Vec<Value>, Option<String>), AppError> {
        let page = page_of(cursor)?;
        let answer = self
            .get(
                path,
                &[
                    ("page", page.to_string()),
                    ("per_page", SHOP_PAGE_SIZE.to_string()),
                    ("sort_by", "updated_at-asc".into()),
                ],
            )
            .await?;
        let items = answer["data"].as_array().cloned().unwrap_or_default();
        Ok((items, next_cursor(&answer)))
    }
}

impl ShopPlatform for SallaShop {
    fn platform(&self) -> &'static str {
        "salla"
    }

    fn fetch_orders_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopOrder>> {
        Box::pin(async move {
            let (summaries, next_cursor) = self.list("/orders", cursor).await?;
            let mut items = Vec::with_capacity(summaries.len());
            // One page at a time, one order at a time: at most
            // SHOP_PAGE_SIZE × 2 calls per page, sequential so the store's
            // rate limit is not hit by a burst.
            for summary in &summaries {
                let id = mapped(
                    "order",
                    id_of(&summary["id"]).ok_or_else(|| "order.id".to_owned()),
                )?;
                let order = self
                    .get(&format!("/orders/{id}"), &[("format", "light".into())])
                    .await?;
                let lines = self
                    .get("/orders/items", &[("order_id", id.clone())])
                    .await?;
                let lines = lines["data"].as_array().cloned().unwrap_or_default();
                items.push(mapped("order", map_order(&order["data"], &lines))?);
            }
            Ok(ShopPage { items, next_cursor })
        })
    }

    fn fetch_customers_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopCustomer>> {
        Box::pin(async move {
            let (rows, next_cursor) = self.list("/customers", cursor).await?;
            let items = rows
                .iter()
                .map(|c| mapped("customer", map_customer(c)))
                .collect::<Result<_, _>>()?;
            Ok(ShopPage { items, next_cursor })
        })
    }

    fn fetch_products_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopProduct>> {
        Box::pin(async move {
            let (rows, next_cursor) = self.list("/products", cursor).await?;
            let items = rows
                .iter()
                .map(|p| mapped("product", map_product(p)))
                .collect::<Result<_, _>>()?;
            Ok(ShopPage { items, next_cursor })
        })
    }

    fn push_stock<'a>(
        &'a self,
        _source_product_id: &'a str,
        _quantity: Decimal,
    ) -> ShopFuture<'a, ()> {
        // Not built: Salla's product and stock write shapes are not
        // confirmed without partner access, and no F8 task writes to a shop
        // yet; refused rather than guessed.
        Box::pin(async { Err(AppError::FeatureUnavailable) })
    }

    fn push_product<'a>(&'a self, _product: &'a ShopProduct) -> ShopFuture<'a, String> {
        Box::pin(async { Err(AppError::FeatureUnavailable) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    const FIXTURE: &str = include_str!("../../../tests/fixtures/shop/salla_order.json");

    #[test]
    fn maps_salla_order_fixture() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let lines = fixture["items"]["data"].as_array().unwrap();
        let order = map_order(&fixture["order"]["data"], lines).unwrap();

        assert_eq!(order.source_id, "1333249299");
        assert_eq!(order.number, "275839672");
        assert_eq!(order.currency, "SAR");
        assert_eq!(order.status, "under_review");
        assert_eq!(order.placed_at.to_rfc3339(), "2026-08-31T14:04:00+00:00");

        assert_eq!(order.lines.len(), 2);
        let first = &order.lines[0];
        assert_eq!(first.sku.as_deref(), Some("PRF-100"));
        assert_eq!(first.source_product_id, "PRF-100");
        assert_eq!(first.quantity, dec("1"));
        assert_eq!(first.unit_price, dec("150"));
        assert_eq!(first.vat_rate, Some(dec("0.15")));
        assert_eq!(
            order.lines[1].source_product_id, "item:365435778",
            "no SKU: the item id"
        );
        assert_eq!(order.lines[1].quantity, dec("2"));

        assert!(!order.prices_include_vat, "Salla's line prices are net");
        assert_eq!(super::super::shop_sync::sum_lines(&order.lines), dec("250"));
        assert_eq!(order.shipping, dec("25"));
        assert_eq!(order.discount, dec("0"));
        // 250 + 25 shipping, VAT 15% of 275 = 41.25.
        assert_eq!(order.total, dec("316.25"));
        assert_eq!(order.cod_amount, Some(dec("316.25")));

        let customer = order.customer.as_ref().unwrap();
        assert_eq!(customer.name, "Mohammed Ahmed");
        assert_eq!(customer.phone.as_deref(), Some("+966553333333"));
        assert_eq!(customer.email.as_deref(), Some("test-email@example.com"));
        assert_eq!(order.delivery_phone.as_deref(), Some("+966553333333"));
    }

    #[test]
    fn reads_order_webhooks_and_pages() {
        let body =
            serde_json::json!({ "event": "order.updated", "merchant": 1, "data": { "id": 7 } });
        let (event, data) = parse_webhook(&body).unwrap();
        assert_eq!(event, "order.updated");
        assert_eq!(data["id"], 7);
        assert!(
            parse_webhook(&serde_json::json!({ "event": "app.installed", "data": {} })).is_none()
        );

        let page = |current: u64, total: u64| serde_json::json!({ "pagination": { "currentPage": current, "totalPages": total } });
        assert_eq!(next_cursor(&page(1, 608)).as_deref(), Some("2"));
        assert_eq!(next_cursor(&page(608, 608)), None);
        assert!(page_of(Some("0")).is_err());
        assert_eq!(page_of(None).unwrap(), 1);
    }

    #[test]
    fn a_webhook_signature_is_checked() {
        use hmac::{Hmac, Mac};
        let body = br#"{"event":"order.created","data":{}}"#;
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(b"shared-secret").unwrap();
        mac.update(body);
        let good = hex::encode(mac.finalize().into_bytes());
        assert!(verify_webhook("shared-secret", body, &good));
        assert!(!verify_webhook("another-secret", body, &good));
        assert!(!verify_webhook("shared-secret", body, "not-hex"));
    }

    #[test]
    fn an_order_outside_the_gulf_time_zones_is_refused_not_misdated() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let mut order = fixture["order"]["data"].clone();
        order["date"]["timezone"] = serde_json::json!("Europe/Paris");
        assert!(map_order(&order, &[]).unwrap_err().contains("order.date"));
    }
}

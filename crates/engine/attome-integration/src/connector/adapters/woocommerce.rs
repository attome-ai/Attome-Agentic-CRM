//! F8-T4: WooCommerce, on the neutral [`ShopPlatform`] (F8-T2).
//!
//! The WooCommerce REST API v3 (`https://{store}/wp-json/wc/v3`) with the
//! store's consumer key and secret (the shop connection's encrypted
//! credential) as HTTP Basic credentials. They travel only over HTTPS: a
//! store URL that is not `https` is refused ([`base_url_for`]), because
//! Basic credentials over plain HTTP would be sent in the clear.
//!
//! What the shapes are read from: the WooCommerce REST API reference
//! (woocommerce.github.io/woocommerce-rest-api-docs, read 2026-11-08), not a
//! recorded payload. The fixture `tests/fixtures/shop/woocommerce_order.json`
//! is built from those documented examples, and a recorded payload replaces
//! it once there is a store.
//!
//! - **Orders, customers, products.** `GET /orders`, `/customers`,
//!   `/products` with `page` and `per_page`; the cursor is the page number.
//!   Orders are sorted by `modified` ascending, so a run resumes where the
//!   last one stopped and orders changed since land at the end. The answer
//!   carries its page count only in a header the shop HTTP layer does not
//!   return, so a page of fewer than [`SHOP_PAGE_SIZE`] records is the last
//!   and a full one names the next page (one empty page at an exact
//!   multiple).
//! - **Money.** A line's `subtotal` is its net amount before discounts and
//!   `subtotal_tax` its VAT, so the unit price is `subtotal / quantity`, the
//!   rate `subtotal_tax / subtotal`, and [`ShopOrder::prices_include_vat`] is
//!   false whatever the store's display setting. Shipping and discount are the
//!   order's `shipping_total` and `discount_total` (net); `total` is what the
//!   customer pays.
//! - **Time.** `date_created_gmt` is UTC without an offset.
//! - **Webhooks.** `order.created` and `order.updated` (`X-WC-Webhook-Topic`)
//!   carry the order as the body, signed in `X-WC-Webhook-Signature`: the
//!   base64 HMAC-SHA256 of the raw body under the webhook's secret, verified
//!   by [`verify_webhook`] in constant time (`Mac::verify_slice`).
//! - Raw payloads are never logged: a mapping failure names the field only.

use base64::Engine;
use hmac::{Hmac, Mac};
use reqwest::Method;
use rust_decimal::Decimal;
use serde_json::Value;

use super::shop_sync::{
    SHOP_PAGE_SIZE, ShopCustomer, ShopFuture, ShopHttp, ShopOrder, ShopOrderLine, ShopPage,
    ShopPlatform, ShopProduct, decimal_of, id_of, normalise_email, normalise_phone,
};
use attome_types::AppError;

/// The webhook topics this adapter reads.
pub const ORDER_TOPICS: [&str; 2] = ["order.created", "order.updated"];

/// Saudi Arabia's calling code, for a number given without one.
const DEFAULT_COUNTRY: &str = "966";

/// The REST API base URL of the store at `store_url`. Only `https` is
/// accepted, and a URL with a query, a fragment or credentials is refused.
/// Pure.
pub fn base_url_for(store_url: &str) -> Result<String, AppError> {
    let url = reqwest::Url::parse(store_url.trim())
        .map_err(|_| AppError::Validation("a WooCommerce store URL is a URL".into()))?;
    if url.scheme() != "https" {
        return Err(AppError::Validation(
            "a WooCommerce store URL must be https: the API keys are sent as Basic credentials"
                .into(),
        ));
    }
    if url.host_str().is_none_or(str::is_empty)
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AppError::Validation(
            "a WooCommerce store URL is https://host[/path] with no credentials or query".into(),
        ));
    }
    Ok(format!(
        "{}/wp-json/wc/v3",
        url.as_str().trim_end_matches('/')
    ))
}

fn text(v: &Value) -> Option<String> {
    v.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn full_name(c: &Value) -> String {
    [c["first_name"].as_str(), c["last_name"].as_str()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A WooCommerce customer (`GET /customers`: `{id, email, first_name,
/// last_name, billing: {phone}}`). Pure.
pub fn map_customer(c: &Value) -> Result<ShopCustomer, String> {
    let source_id = id_of(&c["id"]).ok_or("customer.id")?;
    Ok(ShopCustomer {
        source_id,
        name: full_name(c),
        email: c["email"].as_str().and_then(normalise_email),
        phone: c["billing"]["phone"]
            .as_str()
            .and_then(|p| normalise_phone(p, DEFAULT_COUNTRY)),
    })
}

/// One order line (`{id, product_id, variation_id, name, sku, quantity,
/// subtotal, subtotal_tax}`). Pure.
pub fn map_line(item: &Value) -> Result<ShopOrderLine, String> {
    let quantity = decimal_of(&item["quantity"])
        .filter(|q| !q.is_zero())
        .ok_or("line_item.quantity")?;
    let subtotal = decimal_of(&item["subtotal"]).ok_or("line_item.subtotal")?;
    let sku = text(&item["sku"]);
    let variation = id_of(&item["variation_id"]).filter(|v| v != "0");
    let product = id_of(&item["product_id"]).filter(|v| v != "0");
    let source_product_id = variation
        .or(product)
        .or_else(|| sku.clone())
        .or_else(|| id_of(&item["id"]).map(|id| format!("item:{id}")))
        .ok_or("line_item.product_id")?;
    let vat_rate = decimal_of(&item["subtotal_tax"])
        .filter(|_| !subtotal.is_zero())
        .map(|tax| (tax / subtotal).round_dp(4).normalize());
    Ok(ShopOrderLine {
        source_product_id,
        sku,
        name: item["name"].as_str().unwrap_or_default().trim().to_owned(),
        quantity,
        unit_price: (subtotal / quantity).normalize(),
        vat_rate,
    })
}

fn address_of(a: &Value) -> Option<String> {
    let parts: Vec<&str> = ["address_1", "address_2", "city", "state", "country"]
        .iter()
        .filter_map(|k| a[*k].as_str())
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// An order (`GET /orders` item, or a webhook body). Pure.
pub fn map_order(order: &Value) -> Result<ShopOrder, String> {
    let source_id = id_of(&order["id"]).ok_or("order.id")?;
    let number = id_of(&order["number"]).unwrap_or_else(|| source_id.clone());
    let currency = order["currency"]
        .as_str()
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 3)
        .ok_or("order.currency")?;
    let placed_at = chrono::NaiveDateTime::parse_from_str(
        order["date_created_gmt"]
            .as_str()
            .ok_or("order.date_created_gmt")?,
        "%Y-%m-%dT%H:%M:%S%.f",
    )
    .map_err(|_| "order.date_created_gmt")?
    .and_utc();
    let total = decimal_of(&order["total"]).ok_or("order.total")?;
    let billing = &order["billing"];
    let email = billing["email"].as_str().and_then(normalise_email);
    let phone = billing["phone"]
        .as_str()
        .and_then(|p| normalise_phone(p, DEFAULT_COUNTRY));
    // A guest has `customer_id` 0: known by the e-mail address, if any.
    let customer = match id_of(&order["customer_id"]).filter(|id| id != "0") {
        Some(id) => Some(id),
        None => email.as_ref().map(|e| format!("guest:{e}")),
    }
    .map(|source_id| ShopCustomer {
        source_id,
        name: full_name(billing),
        email: email.clone(),
        phone: phone.clone(),
    });
    let lines = order["line_items"]
        .as_array()
        .map(|items| items.iter().map(map_line).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();
    let delivery_phone = text(&order["shipping"]["phone"])
        .and_then(|p| normalise_phone(&p, DEFAULT_COUNTRY))
        .or(phone);
    Ok(ShopOrder {
        source_id,
        number,
        currency,
        placed_at,
        status: order["status"].as_str().unwrap_or_default().to_owned(),
        customer,
        lines,
        prices_include_vat: false,
        shipping: decimal_of(&order["shipping_total"]).unwrap_or_default(),
        discount: decimal_of(&order["discount_total"]).unwrap_or_default(),
        total,
        cod_amount: (order["payment_method"].as_str() == Some("cod")).then_some(total),
        delivery_address: address_of(&order["shipping"]).or_else(|| address_of(&order["billing"])),
        delivery_phone,
    })
}

/// A WooCommerce product (`{id, name, sku, description, price,
/// stock_quantity}`). Pure.
pub fn map_product(p: &Value) -> Result<ShopProduct, String> {
    Ok(ShopProduct {
        source_id: id_of(&p["id"]).ok_or("product.id")?,
        sku: text(&p["sku"]),
        name: p["name"].as_str().unwrap_or_default().trim().to_owned(),
        description: text(&p["description"]),
        price: decimal_of(&p["price"]),
        // WooCommerce prices a product in the store's currency, which the
        // product does not name.
        currency: None,
        stock: decimal_of(&p["stock_quantity"]),
    })
}

/// A webhook's order, for a topic this adapter reads
/// (`X-WC-Webhook-Topic`); `None` for any other. Pure.
pub fn parse_webhook<'a>(topic: &str, body: &'a Value) -> Option<&'a Value> {
    (ORDER_TOPICS.contains(&topic.trim()) && body["id"].is_number()).then_some(body)
}

/// Whether `signature` (the `X-WC-Webhook-Signature` header, base64) is the
/// HMAC-SHA256 of `body` under `secret`, compared in constant time.
pub fn verify_webhook(secret: &str, body: &[u8], signature: &str) -> bool {
    let Ok(expected) = base64::engine::general_purpose::STANDARD.decode(signature.trim()) else {
        return false;
    };
    let Ok(mut mac) = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// The page number a cursor names (`None`: the first).
fn page_of(cursor: Option<&str>) -> Result<u32, AppError> {
    match cursor {
        None => Ok(1),
        Some(c) => c
            .parse::<u32>()
            .ok()
            .filter(|p| *p >= 1)
            .ok_or_else(|| AppError::Validation("a WooCommerce cursor is a page number".into())),
    }
}

/// The next cursor after `page` when it held `count` records. Pure.
pub fn next_cursor(page: u32, count: usize) -> Option<String> {
    (count >= SHOP_PAGE_SIZE as usize).then(|| (page + 1).to_string())
}

fn mapped<T>(what: &str, result: Result<T, String>) -> Result<T, AppError> {
    result.map_err(|field| {
        tracing::warn!(platform = "woocommerce", what, field = %field, "a WooCommerce record could not be read");
        AppError::Validation(format!("a WooCommerce {what} could not be read: {field}"))
    })
}

/// WooCommerce for one store.
#[derive(Debug, Clone)]
pub struct WooCommerceShop {
    http: ShopHttp,
    /// `Basic base64(key:secret)`; its `Debug` prints `[REDACTED]`.
    authorization: Secret,
}

#[derive(Clone)]
struct Secret(String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl WooCommerceShop {
    /// `store_url` is the store's `https://` address; the keys are the REST
    /// API consumer key and secret.
    pub fn new(
        store_url: &str,
        consumer_key: &str,
        consumer_secret: &str,
    ) -> Result<Self, AppError> {
        let basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{consumer_key}:{consumer_secret}"));
        Ok(Self {
            http: ShopHttp::new("woocommerce", &base_url_for(store_url)?)?,
            authorization: Secret(format!("Basic {basic}")),
        })
    }

    async fn list(
        &self,
        path: &str,
        cursor: Option<&str>,
        extra: &[(&str, String)],
    ) -> Result<(Vec<Value>, Option<String>), AppError> {
        let page = page_of(cursor)?;
        let mut query = vec![
            ("page", page.to_string()),
            ("per_page", SHOP_PAGE_SIZE.to_string()),
        ];
        query.extend(extra.iter().map(|(k, v)| (*k, v.clone())));
        let answer = self
            .http
            .call(
                Method::GET,
                path,
                &query,
                &[("authorization", self.authorization.0.clone())],
                None,
            )
            .await?;
        let rows = answer.as_array().cloned().unwrap_or_default();
        let next = next_cursor(page, rows.len());
        Ok((rows, next))
    }
}

impl ShopPlatform for WooCommerceShop {
    fn platform(&self) -> &'static str {
        "woocommerce"
    }

    fn fetch_orders_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopOrder>> {
        Box::pin(async move {
            let (rows, next_cursor) = self
                .list(
                    "/orders",
                    cursor,
                    &[("orderby", "modified".into()), ("order", "asc".into())],
                )
                .await?;
            let items = rows
                .iter()
                .map(|o| mapped("order", map_order(o)))
                .collect::<Result<_, _>>()?;
            Ok(ShopPage { items, next_cursor })
        })
    }

    fn fetch_customers_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopCustomer>> {
        Box::pin(async move {
            let (rows, next_cursor) = self
                .list(
                    "/customers",
                    cursor,
                    &[("orderby", "id".into()), ("order", "asc".into())],
                )
                .await?;
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
            let (rows, next_cursor) = self
                .list(
                    "/products",
                    cursor,
                    &[("orderby", "id".into()), ("order", "asc".into())],
                )
                .await?;
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
        // Not built: no F8 task writes to a shop yet; refused rather than
        // guessed.
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

    const FIXTURE: &str = include_str!("../../../tests/fixtures/shop/woocommerce_order.json");

    #[test]
    fn maps_woocommerce_order_fixture() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let order = map_order(&fixture["order"]).unwrap();

        assert_eq!(order.source_id, "727");
        assert_eq!(order.number, "727");
        assert_eq!(order.currency, "SAR");
        assert_eq!(order.status, "processing");
        assert_eq!(order.placed_at.to_rfc3339(), "2026-08-31T14:04:00+00:00");

        assert_eq!(order.lines.len(), 2);
        let first = &order.lines[0];
        assert_eq!(first.sku.as_deref(), Some("PRF-100"));
        assert_eq!(first.source_product_id, "93");
        assert_eq!(first.quantity, dec("1"));
        assert_eq!(first.unit_price, dec("150"));
        assert_eq!(first.vat_rate, Some(dec("0.15")));
        let second = &order.lines[1];
        assert_eq!(
            second.source_product_id, "23",
            "a variation is its own product"
        );
        assert_eq!(second.sku, None);
        assert_eq!(second.quantity, dec("2"));
        assert_eq!(second.unit_price, dec("50"));

        assert!(!order.prices_include_vat);
        assert_eq!(super::super::shop_sync::sum_lines(&order.lines), dec("250"));
        assert_eq!(order.shipping, dec("25"));
        assert_eq!(order.discount, dec("0"));
        assert_eq!(order.total, dec("316.25"));
        assert_eq!(order.cod_amount, Some(dec("316.25")));

        let customer = order.customer.as_ref().unwrap();
        assert_eq!(customer.source_id, "25");
        assert_eq!(customer.name, "Mohammed Ahmed");
        assert_eq!(customer.email.as_deref(), Some("test-email@example.com"));
        assert_eq!(customer.phone.as_deref(), Some("+966553333333"));
        assert_eq!(
            order.delivery_address.as_deref(),
            Some("King Fahd Road 12, Riyadh, Riyadh Province, SA")
        );
        assert_eq!(order.delivery_phone.as_deref(), Some("+966553333333"));
    }

    #[test]
    fn rejects_http_store_url() {
        assert!(base_url_for("http://shop.example.com").is_err());
        assert!(base_url_for("ftp://shop.example.com").is_err());
        assert!(base_url_for("shop.example.com").is_err());
        assert!(base_url_for("https://key:secret@shop.example.com").is_err());
        assert!(base_url_for("https://shop.example.com/?consumer_key=x").is_err());
        assert_eq!(
            base_url_for("https://shop.example.com/").unwrap(),
            "https://shop.example.com/wp-json/wc/v3"
        );
        assert_eq!(
            base_url_for("https://example.com/store").unwrap(),
            "https://example.com/store/wp-json/wc/v3"
        );
        assert!(WooCommerceShop::new("http://shop.example.com", "ck", "cs").is_err());
        assert!(WooCommerceShop::new("https://shop.example.com", "ck", "cs").is_ok());
    }

    #[test]
    fn a_webhook_signature_is_checked_in_constant_time() {
        let body = br#"{"id":727}"#;
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(b"hook-secret").unwrap();
        mac.update(body);
        let good = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert!(verify_webhook("hook-secret", body, &good));
        assert!(!verify_webhook("other-secret", body, &good));
        assert!(!verify_webhook("hook-secret", b"{}", &good));
        assert!(!verify_webhook("hook-secret", body, "not base64 !"));
        assert!(!verify_webhook("hook-secret", body, ""));
    }

    #[test]
    fn reads_webhooks_guests_and_pages() {
        let order = serde_json::json!({ "id": 7 });
        assert!(parse_webhook("order.updated", &order).is_some());
        assert!(parse_webhook("product.updated", &order).is_none());

        let mut guest = serde_json::from_str::<Value>(FIXTURE).unwrap()["order"].clone();
        guest["customer_id"] = serde_json::json!(0);
        let mapped = map_order(&guest).unwrap();
        assert_eq!(
            mapped.customer.unwrap().source_id,
            "guest:test-email@example.com"
        );

        assert_eq!(next_cursor(1, 100).as_deref(), Some("2"));
        assert_eq!(next_cursor(3, 99), None);
        assert!(page_of(Some("0")).is_err());
        assert_eq!(page_of(None).unwrap(), 1);
    }
}

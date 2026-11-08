//! F8-T4: Shopify, on the neutral [`ShopPlatform`] (F8-T2).
//!
//! Shopify's Admin REST API (`https://{shop}.myshopify.com/admin/api/{version}`)
//! with the store's access token in `X-Shopify-Access-Token` (the shop
//! connection's encrypted credential). Shopify calls the REST Admin API
//! legacy and steers new apps to GraphQL; the task names REST, and the
//! resources read here (orders, customers, products) are the same in both.
//!
//! What the shapes are read from: Shopify's published API reference
//! (shopify.dev, read 2026-11-08), not a recorded payload. The fixture
//! `tests/fixtures/shop/shopify_order.json` is built from those documented
//! examples, and a recorded payload replaces it once there is a store.
//!
//! - **Orders.** `GET /orders.json?status=any&order=updated_at asc`; the
//!   cursor is the `updated_at` of the page's last order, sent back as
//!   `updated_at_min` (inclusive, so an order at the boundary is read twice
//!   and synced once: shop sync keeps one record per source id). A line's
//!   `price` is the unit price and carries VAT when the order's
//!   `taxes_included` is true ([`ShopOrder::prices_include_vat`]); its VAT
//!   rate is the sum of its `tax_lines[].rate`. A page that ends on the same
//!   `updated_at` it started from (a full page of orders changed in the same
//!   second) ends the run rather than loop; it is logged.
//! - **Customers and products.** `GET /customers.json` and `/products.json`
//!   with `since_id`, the cursor being the last id (Shopify returns them in
//!   id order). A product is its first variant: SKU, price and stock.
//! - **Cash on delivery.** An order whose payment gateway names a cash on
//!   delivery gateway and that is not paid.
//! - **Webhooks.** `orders/create` and `orders/updated` carry the order as
//!   the body, with `X-Shopify-Hmac-Sha256` (base64 HMAC-SHA256 of the raw
//!   body, compared in constant time by `attome_integration::inbound`'s
//!   `shopify` preset); [`verify_webhook`] is the same check for a caller
//!   holding the raw request.
//! - Raw payloads are never logged: a mapping failure names the field only.

use reqwest::Method;
use rust_decimal::Decimal;
use serde_json::Value;

use super::shop_sync::{
    SHOP_PAGE_SIZE, ShopCustomer, ShopFuture, ShopHttp, ShopOrder, ShopOrderLine, ShopPage,
    ShopPlatform, ShopProduct, decimal_of, id_of, normalise_email, normalise_phone,
};
use attome_types::AppError;

/// The Admin API version this adapter reads (a released quarterly version).
pub const API_VERSION: &str = "2026-07";

/// The webhook topics this adapter reads.
pub const ORDER_TOPICS: [&str; 2] = ["orders/create", "orders/updated"];

/// Saudi Arabia's calling code, for a number given without one.
const DEFAULT_COUNTRY: &str = "966";

/// The Admin API base URL of the store `shop_domain` (`acme.myshopify.com`).
/// Only a `*.myshopify.com` host is accepted: Shopify's Admin API is always
/// served from it, whatever domain the storefront uses. Pure.
pub fn base_url_for(shop_domain: &str) -> Result<String, AppError> {
    let host = shop_domain.trim().to_ascii_lowercase();
    let label = host.strip_suffix(".myshopify.com").unwrap_or_default();
    let valid = !label.is_empty()
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !valid {
        return Err(AppError::Validation(
            "a Shopify shop domain looks like acme.myshopify.com".into(),
        ));
    }
    Ok(format!("https://{host}/admin/api/{API_VERSION}"))
}

fn text(v: &Value) -> Option<String> {
    v.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// A Shopify customer (`{id, email, first_name, last_name, phone}`). Pure.
pub fn map_customer(c: &Value) -> Result<ShopCustomer, String> {
    let source_id = id_of(&c["id"]).ok_or("customer.id")?;
    let name = [c["first_name"].as_str(), c["last_name"].as_str()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Ok(ShopCustomer {
        source_id,
        name,
        email: c["email"].as_str().and_then(normalise_email),
        phone: c["phone"]
            .as_str()
            .and_then(|p| normalise_phone(p, DEFAULT_COUNTRY)),
    })
}

/// One order line (`{id, product_id, sku, name, quantity, price,
/// tax_lines: [{rate}]}`). Pure.
pub fn map_line(item: &Value) -> Result<ShopOrderLine, String> {
    let sku = text(&item["sku"]);
    let source_product_id = match id_of(&item["product_id"]) {
        Some(id) => id,
        // A custom line has no product: its SKU, else its own id.
        None => sku
            .clone()
            .or_else(|| id_of(&item["id"]).map(|id| format!("item:{id}")))
            .ok_or("line_item.id")?,
    };
    let rates: Vec<Decimal> = item["tax_lines"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| decimal_of(&t["rate"]))
        .collect();
    Ok(ShopOrderLine {
        source_product_id,
        sku,
        name: item["name"].as_str().unwrap_or_default().trim().to_owned(),
        quantity: decimal_of(&item["quantity"]).ok_or("line_item.quantity")?,
        unit_price: decimal_of(&item["price"]).ok_or("line_item.price")?,
        vat_rate: (!rates.is_empty()).then(|| rates.iter().sum::<Decimal>().normalize()),
    })
}

/// Whether the order is paid on delivery: a cash on delivery gateway and not
/// yet paid. Pure.
pub fn is_cash_on_delivery(order: &Value) -> bool {
    let paid = matches!(
        order["financial_status"].as_str(),
        Some("paid" | "partially_paid" | "refunded" | "partially_refunded")
    );
    if paid {
        return false;
    }
    let names = order["payment_gateway_names"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .chain(order["gateway"].as_str());
    names.into_iter().any(|name| {
        let n = name.to_ascii_lowercase();
        n.contains("cash on delivery") || n.contains("cash_on_delivery") || n == "cod"
    })
}

fn address_of(a: &Value) -> Option<String> {
    let parts: Vec<&str> = ["address1", "address2", "city", "province", "country"]
        .iter()
        .filter_map(|k| a[*k].as_str())
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// An order (`GET /orders.json` item, or a webhook body). Pure.
pub fn map_order(order: &Value) -> Result<ShopOrder, String> {
    let source_id = id_of(&order["id"]).ok_or("order.id")?;
    let number = text(&order["name"])
        .or_else(|| id_of(&order["order_number"]))
        .unwrap_or_else(|| source_id.clone());
    let currency = order["currency"]
        .as_str()
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 3)
        .ok_or("order.currency")?;
    let placed_at = chrono::DateTime::parse_from_rfc3339(
        order["created_at"].as_str().ok_or("order.created_at")?,
    )
    .map_err(|_| "order.created_at")?
    .with_timezone(&chrono::Utc);
    let total = decimal_of(&order["total_price"]).ok_or("order.total_price")?;
    let customer = if order["customer"].is_object() {
        Some(map_customer(&order["customer"])?)
    } else {
        None
    };
    let lines = order["line_items"]
        .as_array()
        .map(|items| items.iter().map(map_line).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();
    let shipping =
        decimal_of(&order["total_shipping_price_set"]["shop_money"]["amount"]).unwrap_or_default();
    let delivery_phone = text(&order["shipping_address"]["phone"])
        .or_else(|| customer.as_ref().and_then(|c| c.phone.clone()))
        .and_then(|p| normalise_phone(&p, DEFAULT_COUNTRY));
    Ok(ShopOrder {
        source_id,
        number,
        currency,
        placed_at,
        status: order["fulfillment_status"]
            .as_str()
            .or_else(|| order["financial_status"].as_str())
            .unwrap_or_default()
            .to_owned(),
        customer,
        lines,
        prices_include_vat: order["taxes_included"].as_bool().unwrap_or(false),
        shipping,
        discount: decimal_of(&order["total_discounts"]).unwrap_or_default(),
        total,
        cod_amount: is_cash_on_delivery(order).then_some(total),
        delivery_address: address_of(&order["shipping_address"]),
        delivery_phone,
    })
}

/// A Shopify product as its first variant (`{id, title, body_html,
/// variants: [{sku, price, inventory_quantity}]}`). Pure.
pub fn map_product(p: &Value) -> Result<ShopProduct, String> {
    let variant = &p["variants"][0];
    Ok(ShopProduct {
        source_id: id_of(&p["id"]).ok_or("product.id")?,
        sku: text(&variant["sku"]),
        name: p["title"].as_str().unwrap_or_default().trim().to_owned(),
        description: text(&p["body_html"]),
        price: decimal_of(&variant["price"]),
        // Shopify prices a product in the shop's currency, which the
        // product does not name.
        currency: None,
        stock: decimal_of(&variant["inventory_quantity"]),
    })
}

/// A webhook's order, for a topic this adapter reads (`X-Shopify-Topic`);
/// `None` for any other. Pure.
pub fn parse_webhook<'a>(topic: &str, body: &'a Value) -> Option<&'a Value> {
    (ORDER_TOPICS.contains(&topic.trim()) && body["id"].is_number()).then_some(body)
}

/// Whether `signature` (the `X-Shopify-Hmac-Sha256` header, base64) is the
/// HMAC-SHA256 of `body` under `secret`, compared in constant time.
pub fn verify_webhook(secret: &str, body: &[u8], signature: &str) -> bool {
    let mut headers = axum::http::HeaderMap::new();
    let Ok(value) = axum::http::HeaderValue::from_str(signature.trim()) else {
        return false;
    };
    headers.insert("x-shopify-hmac-sha256", value);
    crate::inbound::verify(
        &serde_json::json!({ "kind": "hmac", "preset": "shopify" }),
        secret,
        &headers,
        body,
        chrono::Utc::now().timestamp(),
    )
    .is_ok()
}

/// The next `updated_at` cursor of a full orders page: the last order's,
/// unless it is the cursor the page started from. Pure.
pub fn next_orders_cursor(
    orders: &[Value],
    started_from: Option<&str>,
    page_size: usize,
) -> Option<String> {
    if orders.len() < page_size {
        return None;
    }
    let last = orders.last()?["updated_at"].as_str()?;
    if Some(last) == started_from {
        tracing::warn!(
            platform = "shopify",
            "a full page of orders share one updated_at; the run ends here"
        );
        return None;
    }
    Some(last.to_owned())
}

/// The next `since_id` cursor of a full page: the last id. Pure.
pub fn next_id_cursor(rows: &[Value], page_size: usize) -> Option<String> {
    if rows.len() < page_size {
        return None;
    }
    id_of(&rows.last()?["id"])
}

fn mapped<T>(what: &str, result: Result<T, String>) -> Result<T, AppError> {
    result.map_err(|field| {
        tracing::warn!(platform = "shopify", what, field = %field, "a Shopify record could not be read");
        AppError::Validation(format!("a Shopify {what} could not be read: {field}"))
    })
}

/// Shopify for one store.
#[derive(Debug, Clone)]
pub struct ShopifyShop {
    http: ShopHttp,
    access_token: String,
}

impl ShopifyShop {
    /// `shop_domain` is the store's `acme.myshopify.com`; `access_token` the
    /// Admin API access token.
    pub fn new(shop_domain: &str, access_token: String) -> Result<Self, AppError> {
        Ok(Self {
            http: ShopHttp::new("shopify", &base_url_for(shop_domain)?)?,
            access_token,
        })
    }

    async fn get(&self, path: &str, query: &[(&str, String)]) -> Result<Value, AppError> {
        self.http
            .call(
                Method::GET,
                path,
                query,
                &[("x-shopify-access-token", self.access_token.clone())],
                None,
            )
            .await
    }

    async fn rows_since_id(
        &self,
        path: &str,
        key: &str,
        cursor: Option<&str>,
    ) -> Result<(Vec<Value>, Option<String>), AppError> {
        let mut query = vec![("limit", SHOP_PAGE_SIZE.to_string())];
        if let Some(id) = cursor {
            if id.parse::<u64>().is_err() {
                return Err(AppError::Validation(
                    "a Shopify cursor is a record id".into(),
                ));
            }
            query.push(("since_id", id.to_owned()));
        }
        let answer = self.get(path, &query).await?;
        let rows = answer[key].as_array().cloned().unwrap_or_default();
        let next = next_id_cursor(&rows, SHOP_PAGE_SIZE as usize);
        Ok((rows, next))
    }
}

impl ShopPlatform for ShopifyShop {
    fn platform(&self) -> &'static str {
        "shopify"
    }

    fn fetch_orders_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopOrder>> {
        Box::pin(async move {
            let mut query = vec![
                ("status", "any".to_owned()),
                ("limit", SHOP_PAGE_SIZE.to_string()),
                ("order", "updated_at asc".to_owned()),
            ];
            if let Some(since) = cursor {
                query.push(("updated_at_min", since.to_owned()));
            }
            let answer = self.get("/orders.json", &query).await?;
            let rows = answer["orders"].as_array().cloned().unwrap_or_default();
            let next_cursor = next_orders_cursor(&rows, cursor, SHOP_PAGE_SIZE as usize);
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
                .rows_since_id("/customers.json", "customers", cursor)
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
                .rows_since_id("/products.json", "products", cursor)
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
        // Not built: Shopify sets stock per inventory item and location, which
        // the neutral trait does not carry, and no F8 task writes to a shop
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

    const FIXTURE: &str = include_str!("../../../tests/fixtures/shop/shopify_order.json");

    #[test]
    fn maps_shopify_order_fixture() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let order = map_order(&fixture["order"]).unwrap();

        assert_eq!(order.source_id, "450789469");
        assert_eq!(order.number, "#1001");
        assert_eq!(order.currency, "SAR");
        assert_eq!(order.status, "pending");
        assert_eq!(order.placed_at.to_rfc3339(), "2026-08-31T14:04:00+00:00");

        assert_eq!(order.lines.len(), 2);
        let first = &order.lines[0];
        assert_eq!(first.sku.as_deref(), Some("PRF-100"));
        assert_eq!(first.source_product_id, "632910392");
        assert_eq!(first.quantity, dec("1"));
        assert_eq!(first.unit_price, dec("150.00"));
        assert_eq!(first.vat_rate, Some(dec("0.15")));
        assert_eq!(order.lines[1].sku, None);
        assert_eq!(order.lines[1].quantity, dec("2"));

        assert!(!order.prices_include_vat);
        assert_eq!(super::super::shop_sync::sum_lines(&order.lines), dec("250"));
        assert_eq!(order.shipping, dec("25.00"));
        assert_eq!(order.discount, dec("0"));
        assert_eq!(order.total, dec("316.25"));
        assert_eq!(order.cod_amount, Some(dec("316.25")));

        let customer = order.customer.as_ref().unwrap();
        assert_eq!(customer.name, "Mohammed Ahmed");
        assert_eq!(customer.email.as_deref(), Some("test-email@example.com"));
        assert_eq!(customer.phone.as_deref(), Some("+966553333333"));
        assert_eq!(
            order.delivery_address.as_deref(),
            Some("King Fahd Road 12, Riyadh, Riyadh Province, Saudi Arabia")
        );
        assert_eq!(order.delivery_phone.as_deref(), Some("+966553333333"));
    }

    #[test]
    fn rejects_bad_shopify_hmac() {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        let body = br#"{"id":450789469}"#;
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(b"shared-secret").unwrap();
        mac.update(body);
        let good = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert!(verify_webhook("shared-secret", body, &good));
        assert!(!verify_webhook("another-secret", body, &good));
        assert!(!verify_webhook("shared-secret", b"{}", &good));
        assert!(!verify_webhook("shared-secret", body, "not base64 !"));
        assert!(!verify_webhook("shared-secret", body, ""));
    }

    #[test]
    fn shop_domains_are_myshopify_hosts_only() {
        assert_eq!(
            base_url_for("Acme-Store.myshopify.com").unwrap(),
            "https://acme-store.myshopify.com/admin/api/2026-07"
        );
        for bad in [
            "evil.example.com",
            "acme.myshopify.com.evil.com",
            ".myshopify.com",
            "a_b.myshopify.com",
            "http://acme.myshopify.com",
            "",
        ] {
            assert!(base_url_for(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reads_webhooks_cod_taxes_included_and_cursors() {
        let order = serde_json::json!({ "id": 7 });
        assert!(parse_webhook("orders/updated", &order).is_some());
        assert!(parse_webhook("products/update", &order).is_none());
        assert!(parse_webhook("orders/create", &serde_json::json!({})).is_none());

        let paid = serde_json::json!({ "financial_status": "paid", "gateway": "cash_on_delivery" });
        assert!(!is_cash_on_delivery(&paid));
        let card =
            serde_json::json!({ "financial_status": "pending", "gateway": "shopify_payments" });
        assert!(!is_cash_on_delivery(&card));

        let rows: Vec<Value> = (1..=3)
            .map(
                |i| serde_json::json!({ "id": i, "updated_at": format!("2026-08-31T10:0{i}:00Z") }),
            )
            .collect();
        assert_eq!(
            next_orders_cursor(&rows, None, 3).as_deref(),
            Some("2026-08-31T10:03:00Z")
        );
        assert_eq!(
            next_orders_cursor(&rows, Some("2026-08-31T10:03:00Z"), 3),
            None
        );
        assert_eq!(
            next_orders_cursor(&rows, None, 4),
            None,
            "a short page is the last"
        );
        assert_eq!(next_id_cursor(&rows, 3).as_deref(), Some("3"));
        assert_eq!(next_id_cursor(&rows, 4), None);

        let mut inclusive = serde_json::from_str::<Value>(FIXTURE).unwrap()["order"].clone();
        inclusive["taxes_included"] = serde_json::json!(true);
        assert!(map_order(&inclusive).unwrap().prices_include_vat);
    }
}

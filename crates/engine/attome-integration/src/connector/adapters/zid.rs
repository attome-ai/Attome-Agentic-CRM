//! F8-T3: Zid, on the neutral [`ShopPlatform`] (F8-T2).
//!
//! Zid's Merchant API (`https://api.zid.sa/v1`). Every call carries two
//! tokens: `Authorization: Bearer <partner token>` (the app's, issued by
//! Zid) and `X-Manager-Token: <store token>` (the store's OAuth token, a
//! year long), both from the shop connection's encrypted credential.
//!
//! What the shapes are read from: Zid's published API reference
//! (docs.zid.sa: List Orders, View Order, read 2026-11-06), not a recorded
//! payload. No partner access exists yet, so the fixture
//! `tests/fixtures/shop/zid_order.json` is built from the documented View
//! Order example, and a recorded payload replaces it once there is one.
//!
//! - **Orders.** `GET /managers/store/orders?payload_type=default` (only
//!   `default` carries each order's `products`), `per_page` at most 100.
//!   A product's `price` is the unit price with VAT and `tax_percentage`
//!   its rate as a fraction (0.15), so [`ShopOrder::prices_include_vat`] is
//!   true; `order_total` is in the order's `currency_code`.
//! - **Backfill.** `date_attribute=updated_at&sort_by=asc&page=N`: the
//!   cursor is the page number; a page shorter than the page size is the
//!   last. The caller stores the cursor only after the page commits.
//! - **Times.** `created_at` comes without a zone (`2026-04-21 15:12:07`);
//!   it is read as Saudi time (UTC+3), the zone of a Zid store. Owed: a
//!   recorded payload from a store in another zone to confirm.
//! - **Webhooks.** [`parse_webhook`] reads an order from a webhook body.
//!   How Zid signs its webhooks is not in the reference read; until it is
//!   confirmed, an inbound hook for Zid uses a secret token of its own
//!   (the inbound hook's `bearer` or `custom` auth), never no check.
//! - **Customers and products.** Not built: their list shapes are not in
//!   the reference read. A customer arrives with each order already.
//! - Raw payloads are never logged: a mapping failure names the field only.

use reqwest::Method;
use rust_decimal::Decimal;
use serde_json::Value;

use super::shop_sync::{
    SHOP_PAGE_SIZE, ShopCustomer, ShopFuture, ShopHttp, ShopOrder, ShopOrderLine, ShopPage,
    ShopPlatform, ShopProduct, decimal_of, id_of, local_time_utc, normalise_email, normalise_phone,
};
use attome_types::AppError;

/// Zid's production API base URL.
pub const BASE_URL: &str = "https://api.zid.sa/v1";

/// The zone a Zid order's times are read in (see the module notes).
const STORE_ZONE: &str = "Asia/Riyadh";

/// Saudi Arabia's calling code, for a number given without one.
const DEFAULT_COUNTRY: &str = "966";

/// The payment method code of cash on delivery.
const COD: &str = "zid_cod";

fn text(v: &Value) -> Option<String> {
    // A name is a string, or `{ "ar": ..., "en": ... }` on some objects.
    let s = v
        .as_str()
        .or_else(|| v["en"].as_str().filter(|s| !s.trim().is_empty()))
        .or_else(|| v["ar"].as_str())?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

/// An order's customer (`{id, name, email, mobile}`; `mobile` with its
/// country code and no `+`, `966333333333`). Pure.
pub fn map_customer(c: &Value) -> Result<ShopCustomer, String> {
    Ok(ShopCustomer {
        source_id: id_of(&c["id"]).ok_or("customer.id")?,
        name: text(&c["name"]).unwrap_or_default(),
        email: c["email"].as_str().and_then(normalise_email),
        phone: id_of(&c["mobile"]).and_then(|m| normalise_phone(&m, DEFAULT_COUNTRY)),
    })
}

/// One of an order's `products` (`{id, sku, name, quantity, price,
/// is_taxable, tax_percentage, total, ...}`). Pure.
pub fn map_line(p: &Value) -> Result<ShopOrderLine, String> {
    let taxable = p["is_taxable"].as_bool().unwrap_or(true);
    Ok(ShopOrderLine {
        source_product_id: id_of(&p["id"]).ok_or("product.id")?,
        sku: p["sku"]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        name: text(&p["name"]).unwrap_or_default(),
        quantity: decimal_of(&p["quantity"]).ok_or("product.quantity")?,
        unit_price: decimal_of(&p["price"]).ok_or("product.price")?,
        vat_rate: if taxable {
            decimal_of(&p["tax_percentage"]).map(|rate| rate.normalize())
        } else {
            Some(Decimal::ZERO)
        },
    })
}

/// One entry of `payment.invoice[]` by its `code`.
fn invoice_value(order: &Value, code: &str) -> Option<Decimal> {
    order["payment"]["invoice"]
        .as_array()?
        .iter()
        .find(|line| line["code"].as_str() == Some(code))
        .and_then(|line| decimal_of(&line["value"]))
}

/// An order (`order` of View Order, or one of List Orders' `orders` with
/// `payload_type=default`). Pure.
///
/// `discount` is the coupon's (`coupon.discount`, or the invoice's `coupon`
/// line), as a positive amount. `shipping` is the invoice lines whose code
/// names shipping or the cash-on-delivery fee; the documented example is a
/// pickup order with none, so those codes are owed a recorded payload.
pub fn map_order(order: &Value) -> Result<ShopOrder, String> {
    let source_id = id_of(&order["id"]).ok_or("order.id")?;
    let number = id_of(&order["code"]).unwrap_or_else(|| source_id.clone());
    let currency = order["currency_code"]
        .as_str()
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 3)
        .ok_or("order.currency_code")?;
    let placed_at = local_time_utc(
        order["created_at"].as_str().ok_or("order.created_at")?,
        STORE_ZONE,
    )
    .ok_or("order.created_at")?;
    let status = order["order_status"]["code"]
        .as_str()
        .or_else(|| order["order_status"].as_str())
        .unwrap_or_default()
        .to_owned();
    let customer = if order["customer"].is_object() {
        Some(map_customer(&order["customer"])?)
    } else {
        None
    };
    let lines = order["products"]
        .as_array()
        .map(|products| products.iter().map(map_line).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();
    let total = decimal_of(&order["order_total"])
        .or_else(|| invoice_value(order, "total"))
        .ok_or("order.order_total")?;
    let discount = decimal_of(&order["coupon"]["discount"])
        .or_else(|| invoice_value(order, "coupon"))
        .map(|d| d.abs())
        .unwrap_or_default();
    let shipping = order["payment"]["invoice"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|line| {
            line["code"]
                .as_str()
                .is_some_and(|code| code.contains("shipping") || code == "cod")
        })
        .filter_map(|line| decimal_of(&line["value"]))
        .sum();
    let cod = order["payment"]["method"]["code"].as_str() == Some(COD);
    let address = &order["shipping"]["address"];
    let delivery_address = address["formatted_address"]
        .as_str()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .map(str::to_owned);
    let delivery_phone = customer.as_ref().and_then(|c| c.phone.clone());
    Ok(ShopOrder {
        source_id,
        number,
        currency,
        placed_at,
        status,
        customer,
        lines,
        prices_include_vat: true,
        shipping,
        discount,
        total,
        cod_amount: cod.then_some(total),
        delivery_address,
        delivery_phone,
    })
}

/// The order in a webhook body: `{"order": {...}}`, or the order itself.
/// `None` when the body holds no order. Pure.
pub fn parse_webhook(body: &Value) -> Option<&Value> {
    let order = if body["order"].is_object() {
        &body["order"]
    } else {
        body
    };
    (order["id"].is_number() || order["id"].is_string()).then_some(order)
}

/// The page number a cursor names (`None`: the first).
fn page_of(cursor: Option<&str>) -> Result<u32, AppError> {
    match cursor {
        None => Ok(1),
        Some(c) => c
            .parse::<u32>()
            .ok()
            .filter(|p| *p >= 1)
            .ok_or_else(|| AppError::Validation("a Zid cursor is a page number".into())),
    }
}

/// The next cursor after page `page` that held `count` orders: none once a
/// page is short. Pure.
pub fn next_cursor(page: u32, count: usize) -> Option<String> {
    (count >= SHOP_PAGE_SIZE as usize).then(|| (page + 1).to_string())
}

/// Zid for one store.
#[derive(Clone)]
pub struct ZidShop {
    http: ShopHttp,
    partner_token: String,
    manager_token: String,
}

impl std::fmt::Debug for ZidShop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZidShop")
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}

impl ZidShop {
    /// `base_url` is [`BASE_URL`] unless the connection names another.
    pub fn new(
        base_url: &str,
        partner_token: String,
        manager_token: String,
    ) -> Result<Self, AppError> {
        Ok(Self {
            http: ShopHttp::new("zid", base_url)?,
            partner_token,
            manager_token,
        })
    }

    fn headers(&self) -> [(&'static str, String); 3] {
        [
            ("authorization", format!("Bearer {}", self.partner_token)),
            ("x-manager-token", self.manager_token.clone()),
            ("accept-language", "en".into()),
        ]
    }
}

impl ShopPlatform for ZidShop {
    fn platform(&self) -> &'static str {
        "zid"
    }

    fn fetch_orders_since<'a>(
        &'a self,
        cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopOrder>> {
        Box::pin(async move {
            let page = page_of(cursor)?;
            let answer = self
                .http
                .call(
                    Method::GET,
                    "/managers/store/orders",
                    &[
                        ("payload_type", "default".into()),
                        ("page", page.to_string()),
                        ("per_page", SHOP_PAGE_SIZE.to_string()),
                        ("date_attribute", "updated_at".into()),
                        ("sort_by", "asc".into()),
                    ],
                    &self.headers(),
                    None,
                )
                .await?;
            let orders = answer["orders"].as_array().cloned().unwrap_or_default();
            let items = orders
                .iter()
                .map(|o| {
                    map_order(o).map_err(|field| {
                        tracing::warn!(platform = "zid", field = %field, "a Zid order could not be read");
                        AppError::Validation(format!("a Zid order could not be read: {field}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ShopPage {
                next_cursor: next_cursor(page, orders.len()),
                items,
            })
        })
    }

    fn fetch_customers_since<'a>(
        &'a self,
        _cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopCustomer>> {
        // Not built (module notes): customers arrive with their orders.
        Box::pin(async { Err(AppError::FeatureUnavailable) })
    }

    fn fetch_products_since<'a>(
        &'a self,
        _cursor: Option<&'a str>,
    ) -> ShopFuture<'a, ShopPage<ShopProduct>> {
        Box::pin(async { Err(AppError::FeatureUnavailable) })
    }

    fn push_stock<'a>(
        &'a self,
        _source_product_id: &'a str,
        _quantity: Decimal,
    ) -> ShopFuture<'a, ()> {
        // Not built: no F8 task writes to a shop yet, and the shapes are
        // unconfirmed; refused rather than guessed.
        Box::pin(async { Err(AppError::FeatureUnavailable) })
    }

    fn push_product<'a>(&'a self, _product: &'a ShopProduct) -> ShopFuture<'a, String> {
        Box::pin(async { Err(AppError::FeatureUnavailable) })
    }
}

#[cfg(test)]
mod tests {
    use super::super::shop_sync::{split_vat_inclusive, sum_lines};
    use super::*;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    const FIXTURE: &str = include_str!("../../../tests/fixtures/shop/zid_order.json");

    #[test]
    fn maps_zid_order_fixture() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let order = map_order(&fixture["order"]).unwrap();

        assert_eq!(order.source_id, "68340124");
        assert_eq!(order.number, "rEXuB20myr");
        assert_eq!(order.currency, "SAR");
        assert_eq!(order.status, "new");
        assert_eq!(order.placed_at.to_rfc3339(), "2026-04-21T12:12:07+00:00");

        assert_eq!(order.lines.len(), 2);
        let first = &order.lines[0];
        assert_eq!(
            first.source_product_id,
            "1696a85e-419e-4092-a54d-d4afac8289d6"
        );
        assert_eq!(first.sku.as_deref(), Some("Z.217795.16883190964075553"));
        assert_eq!(first.quantity, dec("2"));
        assert_eq!(first.unit_price, dec("115"));
        assert_eq!(first.vat_rate, Some(dec("0.15")));
        assert_eq!(order.lines[1].quantity, dec("1"));
        assert_eq!(order.lines[1].unit_price, dec("57.5"));

        assert!(order.prices_include_vat, "Zid's line prices include VAT");
        assert_eq!(sum_lines(&order.lines), dec("287.5"));
        assert_eq!(
            split_vat_inclusive(dec("287.5"), dec("0.15")),
            (dec("250"), dec("37.5"))
        );
        assert_eq!(order.total, dec("287.5"));
        assert_eq!(order.discount, dec("0"));
        assert_eq!(order.shipping, dec("0"), "a pickup order");
        assert_eq!(order.cod_amount, Some(dec("287.5")));

        let customer = order.customer.as_ref().unwrap();
        assert_eq!(customer.name, "test user");
        assert_eq!(customer.phone.as_deref(), Some("+966533333333"));
        assert_eq!(order.delivery_phone.as_deref(), Some("+966533333333"));
        assert_eq!(
            order.delivery_address.as_deref(),
            Some("King Fahd Rd, Al Olaya, Riyadh 12212")
        );
    }

    #[test]
    fn a_coupon_is_a_positive_discount() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let mut order = fixture["order"].clone();
        order["coupon"] = serde_json::json!({ "code": "3US1YJ", "discount": "-28.7500" });
        assert_eq!(map_order(&order).unwrap().discount, dec("28.75"));
    }

    #[test]
    fn reads_webhooks_and_pages() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        assert!(parse_webhook(&fixture).is_some(), "{{order: ...}}");
        assert!(parse_webhook(&fixture["order"]).is_some(), "a bare order");
        assert!(parse_webhook(&serde_json::json!({ "event": "x" })).is_none());
        assert_eq!(next_cursor(3, 100).as_deref(), Some("4"));
        assert_eq!(next_cursor(3, 12), None);
        assert!(page_of(Some("x")).is_err());
    }
}

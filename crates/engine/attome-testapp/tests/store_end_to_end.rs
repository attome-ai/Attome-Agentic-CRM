//! F8-T13: the store end to end. A guest checkout with a coupon and a
//! shipping rate makes one order, one coupon redemption and (asked for by
//! order, twice) one invoice; a Shopify order delivered three times makes
//! one order and one sync map row per source record.
//!
//! Written, owed its first run (V2-D1941).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::str::FromStr;

use attome_billing::requests::{InvoiceRequest, RequestLine, process_pending, submit_request};
use attome_integration::connector::adapters::shop_sync::{ShopCustomer, ShopOrder, ShopOrderLine};
use attome_sales::guest_checkout::{Confirm, code_digest, confirm};
use attome_sales::shop_sync::{SourceRecord, upsert_from_source};
use attome_testapp::TestApp;
use axum::http::Method;
use rust_decimal::Decimal;
use serde_json::{Value, json};
use uuid::Uuid;

const PACKS: [&str; 8] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
    "fulfilment",
];

async fn install(app: &TestApp) {
    for pack in PACKS {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn set(app: &TestApp, key: &str, value: Value) {
    let (status, body) = app
        .request(
            Method::PUT,
            &format!("/api/v1/admin/settings/{key}"),
            Some(json!({ "scope": "deployment", "value": value })),
        )
        .await;
    assert!(status.is_success(), "{key}: {status} {body}");
}

async fn count(app: &TestApp, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(app.db()).await.unwrap()
}

fn dec(s: &str) -> Decimal {
    Decimal::from_str(s).unwrap()
}

/// A shop open to guests: a product at 100 on the active list, a flat 25
/// rate to Saudi Arabia, VAT at 15%, a 10% coupon `WELCOME` (one use), and a
/// started checkout whose code is 123456. Returns (checkout, rate, account).
async fn shop(app: &TestApp) -> (Uuid, Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Guests') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    set(app, "commerce.enabled", json!(true)).await;
    set(app, "commerce.guest_account", json!(account.to_string())).await;
    set(app, "commerce.vat_rate", json!(0.15)).await;
    let product: Uuid = sqlx::query_scalar(
        "INSERT INTO product (name, sku, is_orderable, portal_visible) \
         VALUES ('Lamp', 'LAMP-1', true, true) RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    let list: Uuid = sqlx::query_scalar(
        "INSERT INTO price_list (name, currency, is_active_list) VALUES ('Retail', 'SAR', true) \
         RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO price_list_item (price_list_ref, product_ref, price) VALUES ($1, $2, 100)",
    )
    .bind(list)
    .bind(product)
    .execute(app.db())
    .await
    .unwrap();
    let zone: Uuid = sqlx::query_scalar(
        "INSERT INTO shipping_zone (name, countries) VALUES ('KSA', 'SA') RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    let rate: Uuid = sqlx::query_scalar(
        "INSERT INTO shipping_rate (shipping_zone_ref, method, amount, cod_fee) \
         VALUES ($1, 'flat', 25, 10) RETURNING id",
    )
    .bind(zone)
    .fetch_one(app.db())
    .await
    .unwrap();
    let promotion: Uuid = sqlx::query_scalar(
        "INSERT INTO promotion (name, kind, value, max_uses, is_enabled) \
         VALUES ('Welcome', 'percent', 10, 1, true) RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query("INSERT INTO coupon (code, promotion_ref, uses_count) VALUES ('WELCOME', $1, 0)")
        .bind(promotion)
        .execute(app.db())
        .await
        .unwrap();
    let checkout = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO commerce_guest_checkout (id, portal_id, phone, code_hash, lines, expires_at) \
         VALUES ($1, $2, '+966501234567', $3, $4, now() + interval '10 minutes')",
    )
    .bind(checkout)
    .bind(Uuid::nil())
    .bind(code_digest(checkout, "123456"))
    .bind(json!([{ "product_id": product, "quantity": "2" }]))
    .execute(app.db())
    .await
    .unwrap();
    (checkout, rate, account)
}

// feature: F8
#[test]
fn guest_order_creates_order_redemption_and_invoice_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (checkout, rate, account) = shop(&app).await;
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let request = Confirm {
            checkout_id: checkout,
            code: "123456".into(),
            name: "Sara Ali".into(),
            address: "King Fahd Rd, Riyadh".into(),
            country: "sa".into(),
            city: Some("Riyadh".into()),
            shipping_rate_id: rate,
            cash_on_delivery: true,
            coupon: Some("WELCOME".into()),
        };

        // The same checkout key twice: one order, one redemption.
        let placed = confirm(&app.state, &service, Uuid::nil(), "key-1", &request)
            .await
            .unwrap();
        let again = confirm(&app.state, &service, Uuid::nil(), "key-1", &request)
            .await
            .unwrap();
        assert_eq!(again.order_id, placed.order_id);
        assert_eq!(
            count(
                &app,
                "SELECT count(*) FROM \"order\" WHERE source = 'store:guest'"
            )
            .await,
            1,
            "one order"
        );
        assert_eq!(
            count(&app, "SELECT count(*) FROM coupon_redemption").await,
            1,
            "one redemption"
        );
        assert_eq!(
            count(
                &app,
                "SELECT uses_count::bigint FROM coupon WHERE code = 'WELCOME'"
            )
            .await,
            1
        );

        // Billing is asked for the order twice (a retried job): one request,
        // one draft invoice, whose lines carry the order's net amount.
        let ask = InvoiceRequest {
            source_kind: "order".into(),
            source_ref: placed.order_id.to_string(),
            idempotency_key: placed.order_id.to_string(),
            account_ref: account,
            currency: "SAR".into(),
            request_date: None,
            lines: vec![RequestLine {
                description: "Lamp".into(),
                quantity: serde_json::Number::from(2),
                unit_price: serde_json::Number::from(100),
                vat_category: None,
                product_ref: None,
                period_from: None,
                period_to: None,
            }],
        };
        let first = submit_request(&app.state, &service, &ask).await.unwrap();
        let repeat = submit_request(&app.state, &service, &ask).await.unwrap();
        assert!(first.created);
        assert!(!repeat.created, "the repeat answers the stored request");
        assert_eq!(repeat.request_id, first.request_id);
        process_pending(&app.state).await.unwrap();
        process_pending(&app.state).await.unwrap();
        assert_eq!(
            count(&app, "SELECT count(*) FROM billing_invoice_request").await,
            1
        );
        assert_eq!(
            count(
                &app,
                "SELECT count(*) FROM invoice WHERE account_ref IS NOT NULL"
            )
            .await,
            1,
            "one invoice, however often billing runs"
        );
    });
}

fn shopify_order() -> ShopOrder {
    ShopOrder {
        source_id: "820982911946154508".into(),
        number: "#1001".into(),
        currency: "SAR".into(),
        placed_at: chrono::Utc::now(),
        status: "pending".into(),
        customer: Some(ShopCustomer {
            source_id: "115310627314723954".into(),
            name: "Sara Ali".into(),
            email: Some("sara@example.com".into()),
            phone: Some("0501234567".into()),
        }),
        lines: vec![ShopOrderLine {
            source_product_id: "632910392".into(),
            sku: Some("IPOD2008PINK".into()),
            name: "IPod Nano - 8GB".into(),
            quantity: dec("1"),
            unit_price: dec("115"),
            vat_rate: Some(dec("0.15")),
        }],
        prices_include_vat: true,
        shipping: Decimal::ZERO,
        discount: Decimal::ZERO,
        total: dec("115"),
        cod_amount: None,
        delivery_address: None,
        delivery_phone: None,
    }
}

// feature: F8
#[test]
fn shopify_webhook_replayed_three_times_creates_one_order() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Online shop') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        let connection: Uuid = sqlx::query_scalar(
            "INSERT INTO shop_connection (name, platform, default_account_ref) \
             VALUES ('Shopify store', 'shopify', $1) RETURNING id",
        )
        .bind(account)
        .fetch_one(app.db())
        .await
        .unwrap();
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let mut created = 0;
        let mut target = None;
        for _ in 0..3 {
            let outcome = upsert_from_source(
                &app.state,
                &service,
                connection,
                &SourceRecord::Order(shopify_order()),
            )
            .await
            .unwrap();
            created += i32::from(outcome.created);
            assert_eq!(*target.get_or_insert(outcome.target_id), outcome.target_id);
        }
        assert_eq!(created, 1, "only the first delivery creates");
        assert_eq!(
            count(
                &app,
                "SELECT count(*) FROM \"order\" WHERE source = 'shop:shopify'"
            )
            .await,
            1
        );
        assert_eq!(
            count(
                &app,
                "SELECT count(*) FROM shop_sync_map WHERE source_kind = 'order'"
            )
            .await,
            1
        );
        assert_eq!(
            count(&app, "SELECT count(*) FROM contact").await,
            1,
            "the customer is matched, not duplicated"
        );
    });
}

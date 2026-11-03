//! F8-T7: a guest with the right code places one order, with shipping and
//! VAT; the same checkout key returns that order again; a wrong code is
//! unauthorized.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_sales::guest_checkout::{Confirm, code_digest, confirm};
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::http::Method;
use serde_json::{Value, json};
use uuid::Uuid;

const PACKS: [&str; 7] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
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

/// A shop open to guests: a product at 100 on the active list, a flat 25
/// rate to Saudi Arabia, VAT at 15%; a started checkout whose code is
/// 123456. Returns (checkout, rate).
async fn shop(app: &TestApp) -> (Uuid, Uuid) {
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
    // As `start` leaves it, without texting (no SMS provider in tests).
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
    (checkout, rate)
}

fn request(checkout: Uuid, rate: Uuid, code: &str) -> Confirm {
    Confirm {
        checkout_id: checkout,
        code: code.into(),
        name: "Sara Ali".into(),
        address: "King Fahd Rd, Riyadh".into(),
        country: "sa".into(),
        city: Some("Riyadh".into()),
        shipping_rate_id: rate,
        cash_on_delivery: true,
        coupon: None,
    }
}

// feature: F8
#[test]
fn retried_confirm_returns_same_order() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (checkout, rate) = shop(&app).await;
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let placed = confirm(
            &app.state,
            &service,
            Uuid::nil(),
            "key-1",
            &request(checkout, rate, "123456"),
        )
        .await
        .unwrap();
        // 200 + 25 shipping + 10 cash on delivery, then 15% VAT.
        assert_eq!(placed.vat.parse::<f64>().unwrap(), 35.25);
        assert_eq!(placed.total.parse::<f64>().unwrap(), 270.25);
        assert!(placed.payment_url.is_none(), "cash on delivery");

        let again = confirm(
            &app.state,
            &service,
            Uuid::nil(),
            "key-1",
            &request(checkout, rate, "123456"),
        )
        .await
        .unwrap();
        assert_eq!(again.order_id, placed.order_id);
        let orders: i64 =
            sqlx::query_scalar("SELECT count(*) FROM \"order\" WHERE source = 'store:guest'")
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(orders, 1);
        let status: Option<String> =
            sqlx::query_scalar("SELECT payment_status::text FROM \"order\" WHERE id = $1")
                .bind(placed.order_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status.as_deref(), Some("due_on_delivery"));

        // The code is spent: another key cannot place a second order.
        let second = confirm(
            &app.state,
            &service,
            Uuid::nil(),
            "key-2",
            &request(checkout, rate, "123456"),
        )
        .await;
        assert!(matches!(second, Err(AppError::Conflict(_))), "{second:?}");
    });
}

// feature: F8
#[test]
fn wrong_code_is_401() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (checkout, rate) = shop(&app).await;
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let wrong = confirm(
            &app.state,
            &service,
            Uuid::nil(),
            "key-w",
            &request(checkout, rate, "000000"),
        )
        .await;
        assert!(matches!(wrong, Err(AppError::Unauthorized)), "{wrong:?}");
        let attempts: i32 =
            sqlx::query_scalar("SELECT attempts FROM commerce_guest_checkout WHERE id = $1")
                .bind(checkout)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(attempts, 1);
        let orders: i64 = sqlx::query_scalar("SELECT count(*) FROM \"order\"")
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(orders, 0);
    });
}

// feature: F8
#[test]
fn guest_catalogue_shows_the_price_with_vat() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        shop(&app).await;

        let items = attome_sales::guest_checkout::guest_catalogue(&app.state, Some("lamp"))
            .await
            .unwrap();
        let lamp = items
            .iter()
            .find(|i| i.sku.as_deref() == Some("LAMP-1"))
            .expect("the lamp is on sale to guests");
        assert_eq!(lamp.price.parse::<f64>().unwrap(), 100.0);
        assert_eq!(lamp.vat.parse::<f64>().unwrap(), 15.0);
        assert_eq!(lamp.price_with_vat.parse::<f64>().unwrap(), 115.0);
        assert!(lamp.stock.is_none(), "no stock location is set");

        set(&app, "commerce.guest_account", Value::Null).await;
        assert!(matches!(
            attome_sales::guest_checkout::guest_catalogue(&app.state, None).await,
            Err(AppError::NotFound)
        ));
    });
}

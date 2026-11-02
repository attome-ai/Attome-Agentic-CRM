//! F8-T8: only a buyer reviews a product; a review is public only once a
//! person publishes it; a cash-on-delivery order above the limit gets a
//! risk review.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_sales::guest_checkout::{Confirm, code_digest, confirm};
use attome_sales::review::{published, submit};
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

async fn scalar(app: &TestApp, sql: &str) -> Uuid {
    sqlx::query_scalar(sql)
        .fetch_one(app.db())
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

/// A contact, a product, and (when `bought`) a fulfilled order of it for
/// the contact. Returns (contact, product).
async fn buyer(app: &TestApp, bought: bool) -> (Uuid, Uuid) {
    let account = scalar(
        app,
        "INSERT INTO account (name) VALUES ('Buyer') RETURNING id",
    )
    .await;
    let contact = scalar(
        app,
        "INSERT INTO contact (full_name) VALUES ('Sara') RETURNING id",
    )
    .await;
    let product = scalar(
        app,
        "INSERT INTO product (name, sku) VALUES ('Lamp', 'LAMP-R') RETURNING id",
    )
    .await;
    if bought {
        let order: Uuid = sqlx::query_scalar(
            "INSERT INTO \"order\" (name, currency, account_ref, status, updates_contact_ref) \
             VALUES ('Order', 'SAR', $1, 'fulfilled', $2) RETURNING id",
        )
        .bind(account)
        .bind(contact)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query("INSERT INTO order_line (order_ref, product_ref, quantity) VALUES ($1, $2, 1)")
            .bind(order)
            .bind(product)
            .execute(app.db())
            .await
            .unwrap();
    }
    (contact, product)
}

// feature: F8
#[test]
fn non_buyer_review_is_403() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (contact, product) = buyer(&app, false).await;
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let refused = submit(
            &app.state,
            &ctx,
            "portal user p1",
            contact,
            product,
            5,
            Some("Great"),
        )
        .await;
        assert!(matches!(refused, Err(AppError::Forbidden)), "{refused:?}");
    });
}

// feature: F8
#[test]
fn held_review_not_public() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (contact, product) = buyer(&app, true).await;
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let review = submit(
            &app.state,
            &ctx,
            "portal user p1",
            contact,
            product,
            4,
            Some("Good"),
        )
        .await
        .unwrap();
        assert!(
            published(&app.state, product).await.unwrap().is_empty(),
            "pending is not public"
        );
        for (status, shown) in [("held", 0), ("published", 1)] {
            sqlx::query("UPDATE product_review SET status = $2 WHERE id = $1")
                .bind(review)
                .bind(status)
                .execute(app.db())
                .await
                .unwrap();
            assert_eq!(
                published(&app.state, product).await.unwrap().len(),
                shown,
                "{status}"
            );
        }
        let again = submit(
            &app.state,
            &ctx,
            "portal user p1",
            contact,
            product,
            2,
            None,
        )
        .await;
        assert!(matches!(again, Err(AppError::Conflict(_))), "{again:?}");
    });
}

// feature: F8
#[test]
fn large_cod_order_is_held_for_review() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account = scalar(
            &app,
            "INSERT INTO account (name) VALUES ('Guests') RETURNING id",
        )
        .await;
        set(&app, "commerce.enabled", json!(true)).await;
        set(&app, "commerce.guest_account", json!(account.to_string())).await;
        set(&app, "commerce.risk.cod_limit", json!(100)).await;
        let product = scalar(
            &app,
            "INSERT INTO product (name, sku, is_orderable, portal_visible) \
             VALUES ('Lamp', 'LAMP-1', true, true) RETURNING id",
        )
        .await;
        let list = scalar(
            &app,
            "INSERT INTO price_list (name, currency, is_active_list) VALUES ('Retail', 'SAR', true) \
             RETURNING id",
        )
        .await;
        sqlx::query(
            "INSERT INTO price_list_item (price_list_ref, product_ref, price) VALUES ($1, $2, 100)",
        )
        .bind(list)
        .bind(product)
        .execute(app.db())
        .await
        .unwrap();
        let zone = scalar(
            &app,
            "INSERT INTO shipping_zone (name, countries) VALUES ('KSA', 'SA') RETURNING id",
        )
        .await;
        let rate: Uuid = sqlx::query_scalar(
            "INSERT INTO shipping_rate (shipping_zone_ref, method, amount, cod_fee) \
             VALUES ($1, 'flat', 25, 10) RETURNING id",
        )
        .bind(zone)
        .fetch_one(app.db())
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
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let placed = confirm(
            &app.state,
            &ctx,
            Uuid::nil(),
            "key-risk",
            &Confirm {
                checkout_id: checkout,
                code: "123456".into(),
                name: "Sara".into(),
                address: "Riyadh".into(),
                country: "SA".into(),
                city: None,
                shipping_rate_id: rate,
                cash_on_delivery: true,
                coupon: None,
            },
        )
        .await
        .unwrap();
        let open: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM risky_order_review WHERE order_ref = $1 AND status = 'open'",
        )
        .bind(placed.order_id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(open, 1, "235 + VAT on delivery is above the 100 limit");
    });
}

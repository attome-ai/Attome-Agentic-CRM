//! F7-T1: the portal shop. Only orderable products marked sold on the portal
//! with a price for the account are on sale; a cart holds quantities, not
//! prices; checkout writes a draft order re-priced now, and asks for
//! approval above the limit.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_sales::commerce::{cart, catalogue, checkout, set_line};
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::http::Method;
use rust_decimal::Decimal;
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

/// An account, a product on sale at 100 SAR on the active list, and one
/// that is orderable but not sold on the portal; returns (account, on sale,
/// hidden).
async fn shop(app: &TestApp) -> (Uuid, Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Buyer') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let mut products = Vec::new();
    for (name, visible) in [("Widget", true), ("Hidden part", false)] {
        let product: Uuid = sqlx::query_scalar(
            "INSERT INTO product (name, sku, is_orderable, portal_visible) \
             VALUES ($1, $1, true, $2) RETURNING id",
        )
        .bind(name)
        .bind(visible)
        .fetch_one(app.db())
        .await
        .unwrap();
        products.push(product);
    }
    let list: Uuid = sqlx::query_scalar(
        "INSERT INTO price_list (name, currency, is_active_list) VALUES ('Retail', 'SAR', true) \
         RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    for product in &products {
        sqlx::query(
            "INSERT INTO price_list_item (price_list_ref, product_ref, price) VALUES ($1, $2, 100)",
        )
        .bind(list)
        .bind(product)
        .execute(app.db())
        .await
        .unwrap();
    }
    (account, products[0], products[1])
}

// feature: F7
#[test]
fn only_products_on_sale_reach_the_cart() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set(&app, "commerce.enabled", json!(true)).await;
        let (account, on_sale, hidden) = shop(&app).await;
        let portal_user = Uuid::now_v7();

        let listed = catalogue(&app.state, account, None).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].product_id, on_sale);

        let refused = set_line(&app.state, portal_user, account, hidden, Decimal::from(1)).await;
        assert!(matches!(refused, Err(AppError::NotFound)), "{refused:?}");

        let cart_now = set_line(&app.state, portal_user, account, on_sale, Decimal::from(3))
            .await
            .unwrap();
        assert_eq!(cart_now.lines.len(), 1);
        assert_eq!(
            Decimal::from_str_exact(&cart_now.total).unwrap(),
            Decimal::from(300)
        );
        assert!(cart_now.can_check_out);

        let emptied = set_line(&app.state, portal_user, account, on_sale, Decimal::ZERO)
            .await
            .unwrap();
        assert!(emptied.lines.is_empty());
    });
}

// feature: F7
#[test]
fn checkout_makes_a_draft_order_and_asks_approval_above_the_limit() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set(&app, "commerce.enabled", json!(true)).await;
        set(&app, "commerce.approval_limit", json!(250)).await;
        let (account, on_sale, _) = shop(&app).await;
        let portal_user = Uuid::now_v7();
        set_line(&app.state, portal_user, account, on_sale, Decimal::from(3))
            .await
            .unwrap();
        let service = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let done = checkout(&app.state, &service, "portal user p6", portal_user, account)
            .await
            .unwrap();
        assert!(done.needs_approval, "300 is above the 250 limit");
        let (status, owner): (Option<String>, Option<Uuid>) =
            sqlx::query_as("SELECT status::text, account_ref FROM \"order\" WHERE id = $1")
                .bind(done.order_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status.as_deref(), Some("draft"));
        assert_eq!(owner, Some(account));
        let lines: i64 = sqlx::query_scalar("SELECT count(*) FROM order_line WHERE order_ref = $1")
            .bind(done.order_id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(lines, 1);

        // The cart is closed: checking out again finds nothing to order.
        let again = checkout(&app.state, &service, "portal user p6", portal_user, account).await;
        assert!(matches!(again, Err(AppError::Validation(_))), "{again:?}");
        assert!(
            cart(&app.state, portal_user, account)
                .await
                .unwrap()
                .cart_id
                .is_none()
        );
    });
}

//! F6-T13: an order billed on shipment asks billing once per shipment line,
//! for the shipped quantity; an order billed at confirm asks nothing here.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
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
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

/// A confirmed order (three units at 50, 150 in total) under `rule`, one
/// fulfilment order for it, and a shipment that has left carrying two of
/// the three; returns the shipment and its line.
async fn shipped(app: &TestApp, rule: &str) -> (Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Buyer') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let order: Uuid = sqlx::query_scalar(
        "INSERT INTO \"order\" (id, name, account_ref, currency, status, billing_rule, owner_ref, \
             is_active, row_version) \
         VALUES ($1, 'Shipped order', $2, 'SAR', 'confirmed', $3, $4, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .bind(rule)
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    let order_line: Uuid = sqlx::query_scalar(
        "INSERT INTO order_line (id, order_ref, description, quantity, unit_price, line_total, \
             is_active, row_version) \
         VALUES ($1, $2, 'Widget', 3, 50, 150, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(order)
    .fetch_one(app.db())
    .await
    .unwrap();
    let fulfilment: Uuid = sqlx::query_scalar(
        "INSERT INTO fulfilment_order (id, order_ref, status, is_active, row_version) \
         VALUES ($1, $2, 'shipped', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(order)
    .fetch_one(app.db())
    .await
    .unwrap();
    let fulfilment_line: Uuid = sqlx::query_scalar(
        "INSERT INTO fulfilment_order_line (id, fulfilment_order_ref, order_line_ref, quantity, \
             is_active, row_version) \
         VALUES ($1, $2, $3, 3, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(fulfilment)
    .bind(order_line.to_string())
    .fetch_one(app.db())
    .await
    .unwrap();
    let shipment: Uuid = sqlx::query_scalar(
        "INSERT INTO shipment (id, fulfilment_order_ref, carrier, status, shipped_on, is_active, \
             row_version) \
         VALUES ($1, $2, 'own_fleet', 'picked_up', now(), true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(fulfilment)
    .fetch_one(app.db())
    .await
    .unwrap();
    let line: Uuid = sqlx::query_scalar(
        "INSERT INTO shipment_line (id, shipment_ref, fulfilment_order_line_ref, quantity, \
             is_active, row_version) \
         VALUES ($1, $2, $3, 2, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(shipment)
    .bind(fulfilment_line)
    .fetch_one(app.db())
    .await
    .unwrap();
    (shipment, line)
}

/// The requests stored for one shipment line: (key, quantity, unit price).
async fn requests_for(app: &TestApp, line: Uuid) -> Vec<(String, f64, f64)> {
    sqlx::query_as(
        "SELECT idempotency_key, (lines -> 0 ->> 'quantity')::float8, \
                (lines -> 0 ->> 'unit_price')::float8 \
           FROM billing_invoice_request \
          WHERE source_kind = 'shipment_line' AND source_ref = $1",
    )
    .bind(line.to_string())
    .fetch_all(app.db())
    .await
    .unwrap()
}

// feature: F6
#[test]
fn billing_trigger_once_per_shipment_line() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (shipment, line) = shipped(&app, "on_shipment").await;

        let first = attome_fulfilment::billing_trigger::bill_shipment(&app.state, shipment)
            .await
            .expect("bill the shipment");
        assert_eq!(first, 1, "one request for the one shipment line");
        let again = attome_fulfilment::billing_trigger::bill_shipment(&app.state, shipment)
            .await
            .expect("bill the shipment again");
        assert_eq!(again, 0, "a rerun asks nothing new");

        let stored = requests_for(&app, line).await;
        assert_eq!(
            stored,
            vec![(format!("ship:{line}:on_shipment"), 2.0, 50.0)],
            "exactly the shipped quantity at the line's net price"
        );
    });
}

// feature: F6
#[test]
fn billing_trigger_leaves_confirm_billed_orders_alone() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        for rule in ["on_confirm", "on_delivery"] {
            let (shipment, line) = shipped(&app, rule).await;
            let made = attome_fulfilment::billing_trigger::bill_shipment(&app.state, shipment)
                .await
                .expect("bill the shipment");
            assert_eq!(made, 0, "{rule}: nothing is due when the shipment has left");
            assert!(requests_for(&app, line).await.is_empty(), "{rule}");
        }
    });
}

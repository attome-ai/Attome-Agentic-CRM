//! F6-T18: the fulfilment money path end to end, with the deployment's own
//! driver: a confirmed order is split, held, the hold cleared, released,
//! packed, taken out for delivery, delivered with proof, and billing is
//! asked for the delivered quantity once; and the fulfilment routes are
//! hidden without the licence.
//!
//! The Aramex leg is not here: the carrier seam calls out through the public
//! outbound guard, which refuses a local fake. `carrier_aramex`'s own tests
//! cover its request and answer shapes.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
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

async fn scalar(app: &TestApp, sql: &str, bind: Uuid) -> Uuid {
    sqlx::query_scalar(sql)
        .bind(bind)
        .fetch_one(app.db())
        .await
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
}

async fn post(app: &TestApp, path: &str, body: Value) -> (StatusCode, Value) {
    app.request(Method::POST, path, Some(body)).await
}

// feature: F6
#[test]
fn fulfilment_money_path_end_to_end() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (status, body) = app
            .request(
                Method::PUT,
                "/api/v1/admin/settings/fulfilment.delivery.otp",
                Some(json!({ "scope": "deployment", "value": false })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let admin = app.admin.id;
        scalar(
            &app,
            "INSERT INTO stock_location (name, code, is_enabled, owner_ref) \
             VALUES ('Riyadh DC', 'RUH', true, $1) RETURNING id",
            admin,
        )
        .await;
        let account = scalar(
            &app,
            "INSERT INTO account (name, owner_ref) VALUES ('Buyer', $1) RETURNING id",
            admin,
        )
        .await;
        let product = scalar(
            &app,
            "INSERT INTO product (name, sku, fulfilment_kind, owner_ref) \
             VALUES ('Lamp', 'LAMP-F', 'goods', $1) RETURNING id",
            admin,
        )
        .await;
        let order: Uuid = sqlx::query_scalar(
            "INSERT INTO \"order\" (name, account_ref, currency, status, billing_rule, \
                 delivery_address, owner_ref) \
             VALUES ('Order', $1, 'SAR', 'confirmed', 'on_delivery', 'King Fahd Rd, Riyadh', $2) \
             RETURNING id",
        )
        .bind(account)
        .bind(admin)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO order_line (order_ref, product_ref, description, quantity, unit_price, \
                 line_total, owner_ref) \
             VALUES ($1, $2, 'Lamp', 2, 50, 100, $3)",
        )
        .bind(order)
        .bind(product)
        .bind(admin)
        .execute(app.db())
        .await
        .unwrap();

        // Split: one fulfilment order from the one location.
        let made = attome_fulfilment::split::split_order(&app.state, order)
            .await
            .unwrap();
        assert_eq!(made, 1);
        let fo = scalar(
            &app,
            "SELECT id FROM fulfilment_order WHERE order_ref = $1",
            order,
        )
        .await;

        // Held: a person's hold stops the release until it is cleared.
        let hold = scalar(
            &app,
            "INSERT INTO fulfilment_hold (fulfilment_order_ref, kind, reason, owner_ref) \
             SELECT $1, 'manual', 'call the buyer first', owner_ref FROM fulfilment_order \
              WHERE id = $1 RETURNING id",
            fo,
        )
        .await;
        let release = format!("/api/v1/fulfilment/orders/{fo}/release");
        let (status, body) = post(&app, &release, json!({})).await;
        assert_eq!(status, StatusCode::CONFLICT, "held: {body}");
        let (status, body) = post(
            &app,
            &format!("/api/v1/fulfilment/holds/{hold}/clear"),
            json!({ "note": "the buyer confirmed" }),
        )
        .await;
        assert!(status.is_success(), "clear: {status} {body}");
        let (status, body) = post(&app, &release, json!({})).await;
        assert!(status.is_success(), "release: {status} {body}");
        assert_eq!(body["status"], "released");

        // Packed into one shipment, driven by our own driver.
        let (status, body) = post(
            &app,
            &format!("/api/v1/fulfilment/orders/{fo}/packages"),
            json!({ "packages": [{ "weight_kg": 1.5 }], "carrier": "own_fleet" }),
        )
        .await;
        assert!(status.is_success(), "pack: {status} {body}");
        let shipment = Uuid::parse_str(body["shipment_id"].as_str().unwrap()).unwrap();
        sqlx::query("UPDATE shipment SET driver_ref = $2, status = 'booked' WHERE id = $1")
            .bind(shipment)
            .bind(admin)
            .execute(app.db())
            .await
            .unwrap();

        // Out for delivery, then delivered with proof.
        let (status, body) = post(
            &app,
            &format!("/api/v1/fulfilment/shipments/{shipment}/out-for-delivery"),
            json!({}),
        )
        .await;
        assert!(status.is_success(), "out: {status} {body}");
        let (status, body) = post(
            &app,
            &format!("/api/v1/fulfilment/shipments/{shipment}/proof"),
            json!({ "outcome": "delivered" }),
        )
        .await;
        assert!(status.is_success(), "proof: {status} {body}");
        let delivered: String =
            sqlx::query_scalar("SELECT status::text FROM shipment WHERE id = $1")
                .bind(shipment)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(delivered, "delivered");

        // Billing is asked once for what was delivered.
        let first = attome_fulfilment::billing_trigger::bill_shipment(&app.state, shipment)
            .await
            .unwrap();
        let again = attome_fulfilment::billing_trigger::bill_shipment(&app.state, shipment)
            .await
            .unwrap();
        let asked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM billing_invoice_request r \
               JOIN shipment_line s ON s.id::text = r.source_ref \
              WHERE r.source_kind = 'shipment_line' AND s.shipment_ref = $1",
        )
        .bind(shipment)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(asked, 1, "one request for the one shipped line");
        assert_eq!((first, again), (1, 0), "a rerun asks nothing new");
    });
}

// feature: F6
#[test]
fn fulfilment_routes_unlicensed_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let before = app.state.modules.load_full();
        app.state
            .modules
            .store(Arc::new(attome_modules::ModuleSet::from_bits([0u64; 4])));
        let id = Uuid::now_v7();
        let calls = [
            (Method::GET, "/api/v1/fulfilment/orders".to_owned()),
            (
                Method::POST,
                format!("/api/v1/fulfilment/orders/{id}/release"),
            ),
            (
                Method::POST,
                format!("/api/v1/fulfilment/orders/{id}/packages"),
            ),
            (Method::POST, format!("/api/v1/fulfilment/holds/{id}/clear")),
            (
                Method::POST,
                format!("/api/v1/fulfilment/shipments/{id}/book"),
            ),
            (
                Method::POST,
                format!("/api/v1/fulfilment/shipments/{id}/proof"),
            ),
        ];
        let mut answers = Vec::new();
        for (method, path) in calls {
            let (status, body) = app.request(method, &path, Some(json!({}))).await;
            answers.push((path, status, body));
        }
        app.state.modules.store(before);
        // The platform's answer for a module that is off (D-279): hidden, 403
        // `feature_hidden`, before any handler runs.
        for (path, status, body) in answers {
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
            assert_eq!(body["error"], "feature_hidden", "{path}: {body}");
        }
    });
}

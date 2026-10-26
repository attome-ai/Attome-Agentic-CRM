//! F6-T11: only the shipment's driver records delivery proof, a wrong
//! delivery code is refused, and cash on delivery records a cash payment.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
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

async fn grant(app: &TestApp, user: Uuid, key: &str) {
    attome_security::db::ensure_privilege(
        app.db(),
        key,
        key,
        "test grant",
        attome_core::changeset::Layer::Project,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
    )
    .bind(user)
    .bind(key)
    .execute(app.db())
    .await
    .unwrap();
}

async fn set_otp(app: &TestApp, on: bool) {
    let (status, body) = app
        .request(
            Method::PUT,
            "/api/v1/admin/settings/fulfilment.delivery.otp",
            Some(json!({ "scope": "deployment", "value": on })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
}

/// A booked own-fleet shipment of an order (with `cod` cash on delivery),
/// driven by `driver`; returns the shipment and the order's account.
async fn shipment(app: &TestApp, driver: Uuid, cod: &str) -> (Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Receiver') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let order: Uuid = sqlx::query_scalar(
        "INSERT INTO \"order\" (id, name, account_ref, currency, cod_amount, is_active, row_version) \
         VALUES ($1, 'COD order', $2, 'SAR', $3::numeric, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .bind(cod)
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
    let shipment: Uuid = sqlx::query_scalar(
        "INSERT INTO shipment (id, fulfilment_order_ref, carrier, status, driver_ref, is_active, \
             row_version) \
         VALUES ($1, $2, 'own_fleet', 'booked', $3, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(fulfilment)
    .bind(driver)
    .fetch_one(app.db())
    .await
    .unwrap();
    (shipment, account)
}

async fn status_of(app: &TestApp, shipment: Uuid) -> String {
    sqlx::query_scalar("SELECT status::text FROM shipment WHERE id = $1")
        .bind(shipment)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: F6
// negative: POST /api/v1/fulfilment/shipments/{id}/proof
#[test]
fn delivery_other_driver_forbidden() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set_otp(&app, false).await;
        let (id, _) = shipment(&app, app.admin.id, "0").await;
        let other = seed_user(app.db(), "driver-b").await;
        grant(&app, other.id, "delivery_proof.create").await;
        for path in ["out-for-delivery", "proof"] {
            let (status, body) = app
                .request_as(
                    &other.cookie,
                    Method::POST,
                    &format!("/api/v1/fulfilment/shipments/{id}/{path}"),
                    Some(json!({ "outcome": "delivered" })),
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        }
        assert_eq!(status_of(&app, id).await, "booked");
    });
}

// feature: F6
// negative: POST /api/v1/fulfilment/shipments/{id}/proof
#[test]
fn delivery_wrong_otp_rejected() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set_otp(&app, true).await;
        let (id, _) = shipment(&app, app.admin.id, "0").await;
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/fulfilment/shipments/{id}/out-for-delivery"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(status_of(&app, id).await, "out_for_delivery");
        // Only a hash is kept; put a known code in its place.
        let stored: String = sqlx::query_scalar(
            "SELECT code_hash FROM shipment_delivery_otp WHERE shipment_id = $1",
        )
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(stored.len(), 64);
        sqlx::query("UPDATE shipment_delivery_otp SET code_hash = $2 WHERE shipment_id = $1")
            .bind(id)
            .bind(attome_fulfilment::delivery::hash_code(id, "123456"))
            .execute(app.db())
            .await
            .unwrap();

        let proof =
            |otp: &str| json!({ "outcome": "delivered", "otp": otp, "received_by": "Sara" });
        let path = format!("/api/v1/fulfilment/shipments/{id}/proof");
        let (status, body) = app
            .request(Method::POST, &path, Some(proof("654321")))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(status_of(&app, id).await, "out_for_delivery");
        let (status, body) = app
            .request(Method::POST, &path, Some(json!({ "outcome": "delivered" })))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "no code: {body}");

        let (status, body) = app
            .request(Method::POST, &path, Some(proof("123456")))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["otp_verified"], json!(true));
        assert_eq!(status_of(&app, id).await, "delivered");
        let proofs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM delivery_proof WHERE shipment_ref = $1 AND otp_verified",
        )
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(proofs, 1);
        set_otp(&app, false).await;
    });
}

// feature: F6
#[test]
fn delivery_cod_records_payment() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set_otp(&app, false).await;
        let (id, account) = shipment(&app, app.admin.id, "250.50").await;
        let path = format!("/api/v1/fulfilment/shipments/{id}/proof");
        let (status, body) = app
            .request(
                Method::POST,
                &path,
                Some(json!({ "outcome": "delivered", "latitude": 24.71, "longitude": 46.67 })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let payment: Uuid = serde_json::from_value(body["cod_payment_id"].clone()).unwrap();
        let (method, amount, payer, reference): (String, String, Uuid, String) = sqlx::query_as(
            "SELECT method::text, amount::text, payer_account_ref, reference \
               FROM customer_payment WHERE id = $1",
        )
        .bind(payment)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(method, "cash");
        assert_eq!(amount.parse::<f64>().unwrap(), 250.5);
        assert_eq!(payer, account);
        assert_eq!(reference, format!("shipment {id}"));
        assert_eq!(status_of(&app, id).await, "delivered");

        // A second proof for a closed shipment is refused; no second payment.
        let (status, _) = app
            .request(Method::POST, &path, Some(json!({ "outcome": "delivered" })))
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let payments: i64 =
            sqlx::query_scalar("SELECT count(*) FROM customer_payment WHERE reference = $1")
                .bind(format!("shipment {id}"))
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(payments, 1);
    });
}

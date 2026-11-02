//! F6-T15: an order update reaches the customer only with their consent,
//! once per shipment step, and an order is shown on the portal only to its
//! own account.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_fulfilment::customer_updates::{Step, notify, portal_order};
use attome_testapp::TestApp;
use axum::http::Method;
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

async fn updates_on(app: &TestApp) {
    let (status, body) = app
        .request(
            Method::PUT,
            "/api/v1/admin/settings/fulfilment.customer_updates",
            Some(json!({ "scope": "deployment", "value": true })),
        )
        .await;
    assert!(status.is_success(), "{status} {body}");
}

/// An account, its contact (`email`) as the order's updates contact, and a
/// shipment of the order; returns (account, contact, order, shipment).
async fn order_with_shipment(app: &TestApp, email: &str) -> (Uuid, Uuid, Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Buyer') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let contact: Uuid = sqlx::query_scalar(
        "INSERT INTO contact (full_name, email, account_ref) VALUES ('Buyer contact', $1, $2) \
         RETURNING id",
    )
    .bind(email)
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap();
    let order: Uuid = sqlx::query_scalar(
        "INSERT INTO \"order\" (id, name, account_ref, currency, updates_contact_ref, is_active, \
             row_version) \
         VALUES ($1, 'SO-1', $2, 'SAR', $3, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .bind(contact)
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
        "INSERT INTO shipment (id, fulfilment_order_ref, carrier, tracking_number, status, \
             is_active, row_version) \
         VALUES ($1, $2, 'aramex', 'AWB-1', 'in_transit', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(fulfilment)
    .fetch_one(app.db())
    .await
    .unwrap();
    (account, contact, order, shipment)
}

async fn grant(app: &TestApp, contact: Uuid) {
    sqlx::query(
        "INSERT INTO audit_consent (purpose_ref, regarding_entity, regarding_id, \
             subject_reference, status, source, is_active, row_version) \
         SELECT id, 'contact', $1, $1, 'granted', 'api', true, 0 \
           FROM audit_consent_purpose WHERE key = 'order_updates'",
    )
    .bind(contact.to_string())
    .execute(app.db())
    .await
    .unwrap();
}

async fn decision(app: &TestApp, shipment: Uuid) -> Option<String> {
    sqlx::query_scalar(
        "SELECT status FROM fulfilment_customer_update WHERE subject_id = $1 AND step = 'shipped'",
    )
    .bind(shipment)
    .fetch_optional(app.db())
    .await
    .unwrap()
}

async fn emails_to(app: &TestApp, email: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM apalis.jobs \
         WHERE job->>'variant' = 'SendEmail' AND job::text LIKE $1",
    )
    .bind(format!("%{email}%"))
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: F6
#[test]
fn updates_without_consent_not_sent() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        updates_on(&app).await;
        let email = format!("buyer-{}@example.invalid", Uuid::now_v7().simple());
        let (_, _, _, shipment) = order_with_shipment(&app, &email).await;

        let sent = notify(&app.state, Step::Shipped, shipment).await.unwrap();
        assert!(!sent);
        assert_eq!(
            decision(&app, shipment).await.as_deref(),
            Some("no_consent")
        );
        assert_eq!(emails_to(&app, &email).await, 0);
        // Decided once: consent given later does not send this step.
        let again = notify(&app.state, Step::Shipped, shipment).await.unwrap();
        assert!(!again);
    });
}

// feature: F6
#[test]
fn updates_with_consent_sent_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        updates_on(&app).await;
        let email = format!("buyer-{}@example.invalid", Uuid::now_v7().simple());
        let (_, contact, _, shipment) = order_with_shipment(&app, &email).await;
        grant(&app, contact).await;

        assert!(notify(&app.state, Step::Shipped, shipment).await.unwrap());
        assert!(!notify(&app.state, Step::Shipped, shipment).await.unwrap());
        assert_eq!(decision(&app, shipment).await.as_deref(), Some("sent"));
        assert_eq!(emails_to(&app, &email).await, 1);
        let body: String = sqlx::query_scalar(
            "SELECT job::text FROM apalis.jobs \
             WHERE job->>'variant' = 'SendEmail' AND job::text LIKE $1 LIMIT 1",
        )
        .bind(format!("%{email}%"))
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(
            body.contains("AWB-1"),
            "the tracking number is in the message"
        );
    });
}

// feature: F6
// negative: GET /{keyword}/api/v1/fulfilment/orders/{order_id}
#[test]
fn portal_other_account_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let email = format!("buyer-{}@example.invalid", Uuid::now_v7().simple());
        let (account, _, order, shipment) = order_with_shipment(&app, &email).await;
        let other: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Someone else') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();

        assert!(
            portal_order(&app.state, other, order)
                .await
                .unwrap()
                .is_none(),
            "another account's order is not found"
        );
        let mine = portal_order(&app.state, account, order)
            .await
            .unwrap()
            .expect("the account's own order");
        assert_eq!(mine.order_id, order);
        let _ = shipment;
    });
}

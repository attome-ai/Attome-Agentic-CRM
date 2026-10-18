//! F5-T7: a gateway's webhook is verified, stored once per event and
//! applied by a job: an event delivered twice changes its payment once, and
//! a call whose secret does not verify is a 401 that stores nothing.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
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

const WEBHOOK_SECRET: &str = "whsec-test-1";

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

/// A Moyasar gateway system with its credential (secret key and webhook
/// secret), acting as its own service principal.
async fn gateway(app: &TestApp) -> Uuid {
    // `integration_system` comes with the integration platform definition.
    attome_api::changeset::boot::apply_platform_definition(&app.state, "attome-integration")
        .await
        .unwrap();
    let principal = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO user_account (id, user_name, email, is_active) \
         VALUES ($1, $2, $2 || '@test.invalid', true)",
    )
    .bind(principal)
    .bind(format!("gateway-principal-{principal}"))
    .execute(app.db())
    .await
    .unwrap();
    let system = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO integration_system \
            (id, name, kind, base_url, auth_type, service_principal_ref, status, config, created_at) \
         VALUES ($1, 'Moyasar KSA', 'payment_gateway', 'https://api.moyasar.com/v1', 'api_key', \
             $2, 'active', '{\"gateway\": \"moyasar\"}', NOW())",
    )
    .bind(system)
    .bind(principal.to_string())
    .execute(app.db())
    .await
    .unwrap();
    let ring = app
        .state
        .base
        .secrets
        .load()
        .integration_credential_key
        .clone();
    let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
    let credential = attome_integration::credential::store(
        &mut tx,
        &ring,
        system,
        &json!({ "secret_key": "sk_test_x", "webhook_secret": WEBHOOK_SECRET }).to_string(),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE integration_system SET credential_ref = $2 WHERE id = $1")
        .bind(system)
        .bind(credential.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    attome_db::tx::commit(tx).await.unwrap();
    system
}

/// An account with one issued invoice of 100 + 15% VAT, and a pending
/// payment of 115 waiting at the gateway under `reference`.
async fn pending_payment(app: &TestApp, system: Uuid, reference: &str) -> (Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Gateway payer') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let invoice: Uuid = sqlx::query_scalar(
        "INSERT INTO invoice (id, status, kind, currency, account_ref, payment_terms_days, \
             series_key, is_active, row_version) \
         VALUES ($1, 'draft', 'invoice', 'SAR', $2, 30, 'TGWH', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO invoice_line (id, invoice_ref, description, quantity, unit_price, \
             vat_category, is_active, row_version) \
         VALUES ($1, $2, 'Line', 1, 100, 'standard', true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(invoice)
    .execute(app.db())
    .await
    .unwrap();
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/billing/invoices/{invoice}/issue"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let payment = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO customer_payment (id, name, payer_account_ref, amount, currency, method, \
             status, gateway_system_ref, gateway_reference, unallocated, is_active, row_version) \
         VALUES ($1, 'Card payment', $2, 115, 'SAR', 'card', 'pending', $3, $4, 0, true, 0)",
    )
    .bind(payment)
    .bind(account)
    .bind(system.to_string())
    .bind(reference)
    .execute(app.db())
    .await
    .unwrap();
    (payment, invoice)
}

fn paid_event(secret: &str, event_id: &str, invoice_reference: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": event_id,
        "type": "payment_paid",
        "created_at": "2026-10-18T10:00:00Z",
        "secret_token": secret,
        "account_name": "Test Merchant",
        "live": false,
        "data": {
            "id": "760878ec-d1d3-5f72-9056-191683f55872", "status": "paid", "amount": 11500,
            "fee": 230, "currency": "SAR", "refunded": 0, "captured": 0,
            "invoice_id": invoice_reference,
        },
    }))
    .unwrap()
}

async fn deliver(app: &TestApp, system: Uuid, body: Vec<u8>) -> (StatusCode, serde_json::Value) {
    app.request_public(
        Method::POST,
        &format!("/api/v1/billing/gateways/{system}/webhook"),
        &[("content-type", "application/json")],
        body,
    )
    .await
}

async fn payment_state(app: &TestApp, payment: Uuid) -> (String, Option<String>) {
    let (status, fee): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT status, fee::text FROM customer_payment WHERE id = $1")
            .bind(payment)
            .fetch_one(app.db())
            .await
            .unwrap();
    (status.unwrap_or_default(), fee)
}

// feature: F5
#[test]
fn webhook_duplicate_event_applied_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let system = gateway(&app).await;
        let reference = format!("inv-{}", Uuid::now_v7().simple());
        let (payment, invoice) = pending_payment(&app, system, &reference).await;
        let event = format!("evt-{}", Uuid::now_v7());

        let (status, body) =
            deliver(&app, system, paid_event(WEBHOOK_SECRET, &event, &reference)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({ "events": 1, "new": 1 }));
        // Nothing is applied in the request.
        assert_eq!(payment_state(&app, payment).await.0, "pending");

        // Delivered again before and after the job runs: stored once.
        let (_, again) =
            deliver(&app, system, paid_event(WEBHOOK_SECRET, &event, &reference)).await;
        assert_eq!(again, json!({ "events": 1, "new": 0 }));
        let changed = attome_billing::gateway::webhook::apply_events(&app.state)
            .await
            .unwrap();
        assert!(changed >= 1);
        let (_, third) =
            deliver(&app, system, paid_event(WEBHOOK_SECRET, &event, &reference)).await;
        assert_eq!(third, json!({ "events": 1, "new": 0 }));
        attome_billing::gateway::webhook::apply_events(&app.state)
            .await
            .unwrap();

        let (status, fee) = payment_state(&app, payment).await;
        assert_eq!(status, "succeeded");
        assert_eq!(fee.unwrap().parse::<f64>().unwrap(), 2.3);
        let allocations: i64 =
            sqlx::query_scalar("SELECT count(*) FROM payment_allocation WHERE payment_ref = $1")
                .bind(payment)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(allocations, 1, "applied once");
        let paid: Option<String> =
            sqlx::query_scalar("SELECT payment_status FROM invoice WHERE id = $1")
                .bind(invoice)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(paid.as_deref(), Some("paid"));
        let (stored, applied): (i64, i64) = sqlx::query_as(
            "SELECT count(*), count(applied_at) FROM billing_gateway_event \
             WHERE gateway_system_id = $1 AND event_key = $2",
        )
        .bind(system)
        .bind(&event)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!((stored, applied), (1, 1));

        // An event for no known payment is kept with its error, to retry.
        let orphan = format!("evt-{}", Uuid::now_v7());
        deliver(
            &app,
            system,
            paid_event(WEBHOOK_SECRET, &orphan, "inv-unknown"),
        )
        .await;
        attome_billing::gateway::webhook::apply_events(&app.state)
            .await
            .unwrap();
        let (applied_at, error, attempts): (
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
            i32,
        ) = sqlx::query_as(
            "SELECT applied_at, error, attempts FROM billing_gateway_event \
                 WHERE gateway_system_id = $1 AND event_key = $2",
        )
        .bind(system)
        .bind(&orphan)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(applied_at.is_none());
        assert!(error.unwrap().contains("inv-unknown"));
        assert_eq!(attempts, 1);
    });
}

// feature: F5
#[test]
fn webhook_bad_signature_is_401() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let system = gateway(&app).await;
        let event = format!("evt-{}", Uuid::now_v7());
        let (status, _) =
            deliver(&app, system, paid_event("not-the-secret", &event, "inv-x")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = deliver(&app, system, b"not json".to_vec()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM billing_gateway_event WHERE gateway_system_id = $1",
        )
        .bind(system)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(stored, 0, "nothing is stored from an unverified call");

        // An unknown gateway is a 404, and the bypass covers the webhook
        // only: another billing route still needs a session.
        let (status, _) = deliver(
            &app,
            Uuid::now_v7(),
            paid_event(WEBHOOK_SECRET, &event, "x"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = app
            .request_public(
                Method::POST,
                "/api/v1/billing/payments",
                &[],
                b"{}".to_vec(),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    });
}

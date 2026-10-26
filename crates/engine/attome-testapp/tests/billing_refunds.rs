//! F5-T10: a refund never exceeds what is left of a payment, waits for an
//! approval above the threshold, and leaves the payment refunded or
//! partially refunded with a draft credit note on the invoice it paid; a
//! chargeback opens a dispute whose evidence lists the invoice's files.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_billing::gateway::{DisputeOpened, GatewayEvent, GatewayStatus};
use attome_billing::payment::recurring::LiveAdapters;
use attome_billing::payment::refund::{RefundPayload, do_refund_approved, execute_refund};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
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

async fn set_threshold(app: &TestApp, value: Value) {
    let (status, body) = app
        .request(
            Method::PUT,
            "/api/v1/admin/settings/billing.refund.approval_threshold",
            Some(json!({ "scope": "deployment", "value": value })),
        )
        .await;
    assert!(status.is_success(), "{status}: {body}");
}

/// An issued invoice of 100 + 15% VAT, paid in full by transfer; returns
/// (invoice, payment).
async fn paid_invoice(app: &TestApp) -> (Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Refunded') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let invoice: Uuid = sqlx::query_scalar(
        "INSERT INTO invoice (id, status, kind, currency, account_ref, payment_terms_days, \
             series_key, is_active, row_version) \
         VALUES ($1, 'draft', 'invoice', 'SAR', $2, 30, 'TRFD', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO invoice_line (id, invoice_ref, description, quantity, unit_price, \
             vat_category, is_active, row_version) \
         VALUES ($1, $2, 'Service', 2, 50, 'standard', true, 0)",
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
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/billing/payments",
            Some(
                json!({ "payer_account_id": account, "amount": 115, "currency": "SAR",
                         "allocations": [{ "invoice_id": invoice, "amount": 115 }] }),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let payment = body["payment_id"].as_str().unwrap().parse().unwrap();
    (invoice, payment)
}

async fn refund(app: &TestApp, payment: Uuid, amount: f64) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/billing/payments/{payment}/refunds"),
        Some(json!({ "amount": amount, "reason": "Service not delivered" })),
    )
    .await
}

async fn payment_status(app: &TestApp, payment: Uuid) -> String {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM customer_payment WHERE id = $1")
            .bind(payment)
            .fetch_one(app.db())
            .await
            .unwrap();
    status.unwrap_or_default()
}

async fn refund_status(app: &TestApp, refund: Uuid) -> String {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM payment_refund WHERE id = $1")
            .bind(refund)
            .fetch_one(app.db())
            .await
            .unwrap();
    status.unwrap_or_default()
}

fn id(body: &Value, key: &str) -> Uuid {
    body[key].as_str().unwrap().parse().unwrap()
}

// feature: F5
// negative: POST /api/v1/billing/payments/{id}/refunds
#[test]
fn refund_more_than_paid_rejected() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set_threshold(&app, json!(0)).await;
        let (_, payment) = paid_invoice(&app).await;

        let (status, _) = refund(&app, payment, 115.01).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "more than paid");
        let (status, body) = refund(&app, payment, 100.0).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending");
        // 100 is held by the pending refund: only 15 is left.
        let (status, _) = refund(&app, payment, 20.0).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, body) = refund(&app, payment, 15.0).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _) = refund(&app, payment, 0.01).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "nothing left");
        // No reason, no refund.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/payments/{payment}/refunds"),
                Some(json!({ "amount": 1, "reason": " " })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: F5
#[test]
fn refund_over_threshold_needs_approval() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set_threshold(&app, json!(50)).await;
        let (_, payment) = paid_invoice(&app).await;

        let (status, body) = refund(&app, payment, 60.0).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending_approval");
        assert!(body["approval_id"].as_str().is_some());
        let refund_id = id(&body, "refund_id");
        assert_eq!(refund_status(&app, refund_id).await, "pending_approval");
        // Waiting, it is not refunded.
        execute_refund(&app.state, refund_id, &LiveAdapters)
            .await
            .unwrap();
        assert_eq!(payment_status(&app, payment).await, "succeeded");

        // Approved: the job refunds it.
        let outcome = do_refund_approved(&app.state, &RefundPayload { refund_id }, app.admin.id)
            .await
            .unwrap();
        assert_eq!(outcome.status, "pending");
        assert!(
            do_refund_approved(&app.state, &RefundPayload { refund_id }, app.admin.id)
                .await
                .is_err(),
            "approved once"
        );
        execute_refund(&app.state, refund_id, &LiveAdapters)
            .await
            .unwrap();
        assert_eq!(refund_status(&app, refund_id).await, "succeeded");
        assert_eq!(payment_status(&app, payment).await, "partially_refunded");

        // Under the threshold, no approval.
        let (_, body) = refund(&app, payment, 10.0).await;
        assert_eq!(body["status"], "pending");
        set_threshold(&app, json!(0)).await;
    });
}

// feature: F5
#[test]
fn refund_partial_sets_status() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        set_threshold(&app, json!(0)).await;
        let (invoice, payment) = paid_invoice(&app).await;

        let (_, body) = refund(&app, payment, 57.5).await;
        let first = id(&body, "refund_id");
        execute_refund(&app.state, first, &LiveAdapters)
            .await
            .unwrap();
        // Run again: settled once.
        execute_refund(&app.state, first, &LiveAdapters)
            .await
            .unwrap();
        assert_eq!(refund_status(&app, first).await, "succeeded");
        assert_eq!(payment_status(&app, payment).await, "partially_refunded");

        // Half the invoice is credited on a draft note.
        let (note, original): (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT r.credit_note_ref, n.original_invoice_ref FROM payment_refund r \
             LEFT JOIN invoice n ON n.id = r.credit_note_ref WHERE r.id = $1",
        )
        .bind(first)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(note.is_some(), "a draft credit note was asked for");
        assert_eq!(original, Some(invoice));
        let credited: Option<String> = sqlx::query_scalar(
            "SELECT SUM(-quantity)::text FROM invoice_line WHERE invoice_ref = $1",
        )
        .bind(note.unwrap())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(credited.unwrap().parse::<f64>().unwrap(), 1.0, "half of 2");

        // The rest: refunded.
        let (_, body) = refund(&app, payment, 57.5).await;
        let second = id(&body, "refund_id");
        execute_refund(&app.state, second, &LiveAdapters)
            .await
            .unwrap();
        assert_eq!(payment_status(&app, payment).await, "refunded");
        let (status, _) = refund(&app, payment, 1.0).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a refunded payment is not refunded again"
        );
    });
}

// feature: F5
#[test]
fn dispute_opens_and_lists_evidence() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        for module in ["attome-integration", "attome-document"] {
            attome_api::changeset::boot::apply_platform_definition(&app.state, module)
                .await
                .unwrap();
        }
        let (invoice, payment) = paid_invoice(&app).await;
        // The payment as a gateway's.
        let system = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO integration_system \
                (id, name, kind, base_url, auth_type, service_principal_ref, status, created_at) \
             VALUES ($1, 'Gateway', 'payment_gateway', 'https://pay.example', 'api_key', $2, \
                 'active', NOW())",
        )
        .bind(system)
        .bind(app.admin.id.to_string())
        .execute(app.db())
        .await
        .unwrap();
        let reference = format!("ref-{}", Uuid::now_v7().simple());
        sqlx::query(
            "UPDATE customer_payment SET gateway_system_ref = $2, gateway_reference = $3 \
             WHERE id = $1",
        )
        .bind(payment)
        .bind(system.to_string())
        .bind(&reference)
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO attome_document (id, name, entity_name, record_id, folder, file, is_active, \
                 row_version) \
             VALUES ($1, 'Delivery note', 'invoice', $2, 'Delivery', 'documents/delivery.pdf', \
                 true, 0)",
        )
        .bind(Uuid::now_v7())
        .bind(invoice.to_string())
        .execute(app.db())
        .await
        .unwrap();

        let event = GatewayEvent {
            event_id: format!("{reference}:chargeback"),
            gateway_reference: reference.clone(),
            status: GatewayStatus::Pending,
            card_update: None,
            dispute: Some(DisputeOpened {
                amount: "115.00".parse().unwrap(),
                reason_code: Some("4837".into()),
                evidence_due: None,
            }),
        };
        for _ in 0..2 {
            attome_billing::gateway::webhook::store_events(
                &app.state,
                system,
                std::slice::from_ref(&event),
            )
            .await
            .unwrap();
            attome_billing::gateway::webhook::apply_events(&app.state)
                .await
                .unwrap();
        }
        assert_eq!(payment_status(&app, payment).await, "disputed");
        let disputes: Vec<(Uuid, Option<String>)> =
            sqlx::query_as("SELECT id, status FROM payment_dispute WHERE payment_ref = $1")
                .bind(payment)
                .fetch_all(app.db())
                .await
                .unwrap();
        assert_eq!(disputes.len(), 1, "opened once");
        assert_eq!(disputes[0].1.as_deref(), Some("open"));

        let (status, evidence) = app
            .request(
                Method::GET,
                &format!("/api/v1/billing/disputes/{}/evidence", disputes[0].0),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{evidence}");
        let names: Vec<&str> = evidence["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|d| d["name"].as_str())
            .collect();
        assert!(names.contains(&"Delivery note"), "{evidence}");
        // A paid payment that is disputed is not refunded.
        let (status, _) = refund(&app, payment, 1.0).await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

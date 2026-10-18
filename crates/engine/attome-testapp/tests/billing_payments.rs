//! F5-T3: recording a payment allocates it to the account's open invoices
//! and moves their status; reversing reopens them; an account's payments
//! are serialised; a payment is never deleted or edited outside the engine.

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

async fn account(app: &TestApp) -> Uuid {
    sqlx::query_scalar("INSERT INTO account (name) VALUES ('Payer') RETURNING id")
        .fetch_one(app.db())
        .await
        .unwrap()
}

/// An issued invoice to `account` of `net` (+15% VAT), due `due_in` days
/// from today.
async fn issued(app: &TestApp, account: Uuid, net: &str, due_in: i32) -> Uuid {
    let invoice: Uuid = sqlx::query_scalar(
        "INSERT INTO invoice (id, status, kind, currency, account_ref, payment_terms_days, \
             series_key, is_active, row_version) \
         VALUES ($1, 'draft', 'invoice', 'SAR', $2, 30, 'TPAY', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO invoice_line (id, invoice_ref, description, quantity, unit_price, \
             vat_category, is_active, row_version) \
         VALUES ($1, $2, 'Line', 1, $3::numeric, 'standard', true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(invoice)
    .bind(net)
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
    sqlx::query("UPDATE invoice SET due_date = CURRENT_DATE + $2 WHERE id = $1")
        .bind(invoice)
        .bind(due_in)
        .execute(app.db())
        .await
        .unwrap();
    invoice
}

async fn invoice_state(app: &TestApp, invoice: Uuid) -> (String, f64) {
    let (status, open): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT payment_status, open_total::text FROM invoice WHERE id = $1")
            .bind(invoice)
            .fetch_one(app.db())
            .await
            .unwrap();
    (
        status.unwrap_or_default(),
        open.unwrap_or_default().parse().unwrap_or(-1.0),
    )
}

async fn pay(app: &TestApp, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    app.request(Method::POST, "/api/v1/billing/payments", Some(body))
        .await
}

// feature: F5
#[test]
fn payment_partial_marks_partly_paid() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let payer = account(&app).await;
        let older = issued(&app, payer, "100", 5).await; // 115 due first
        let newer = issued(&app, payer, "200", 20).await; // 230
        // 150: the older is paid, 35 goes to the newer.
        let (status, body) = pay(
            &app,
            json!({ "payer_account_id": payer, "amount": 150, "currency": "SAR", "reference": "TRF-1" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["allocations"].as_array().unwrap().len(), 2);
        assert_eq!(body["allocations"][0]["invoice_id"], json!(older));
        assert_eq!(invoice_state(&app, older).await, ("paid".into(), 0.0));
        assert_eq!(
            invoice_state(&app, newer).await,
            ("partly_paid".into(), 195.0)
        );

        // More than is open: the rest is the customer's credit, applied to
        // the next invoice when asked.
        let (_, body) = pay(
            &app,
            json!({ "payer_account_id": payer, "amount": 300, "currency": "SAR" }),
        )
        .await;
        assert_eq!(
            body["unallocated"]
                .as_str()
                .unwrap()
                .parse::<f64>()
                .unwrap(),
            105.0
        );
        assert_eq!(invoice_state(&app, newer).await, ("paid".into(), 0.0));
        let later = issued(&app, payer, "50", 30).await; // 57.50
        let (status, applied) = app
            .request(
                Method::POST,
                &format!("/api/v1/billing/accounts/{payer}/apply-credit"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{applied}");
        assert_eq!(invoice_state(&app, later).await, ("paid".into(), 0.0));
        assert_eq!(
            applied[0]["unallocated"]
                .as_str()
                .unwrap()
                .parse::<f64>()
                .unwrap(),
            47.5
        );

        // Allocating by hand: more than the invoice owes is refused.
        let other = issued(&app, payer, "10", 10).await; // 11.50
        let (status, _) = pay(
            &app,
            json!({ "payer_account_id": payer, "amount": 20, "currency": "SAR",
                    "allocations": [{ "invoice_id": other, "amount": 20 }] }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: F5
#[test]
fn payment_reverse_reopens_invoice() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let payer = account(&app).await;
        let invoice = issued(&app, payer, "100", -10).await; // 115, past due
        let (_, body) = pay(
            &app,
            json!({ "payer_account_id": payer, "amount": 115, "currency": "SAR" }),
        )
        .await;
        let payment = body["payment_id"].as_str().unwrap().to_owned();
        assert_eq!(invoice_state(&app, invoice).await, ("paid".into(), 0.0));
        let reverse = format!("/api/v1/billing/payments/{payment}/reverse");
        let (status, _) = app
            .request(Method::POST, &reverse, Some(json!({ "reason": " " })))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, body) = app
            .request(
                Method::POST,
                &reverse,
                Some(json!({ "reason": "Cheque bounced" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["invoices"][0], json!(invoice));
        // Past due and open again: overdue.
        assert_eq!(
            invoice_state(&app, invoice).await,
            ("overdue".into(), 115.0)
        );
        let (status, reversed, reason): (Option<String>, bool, Option<String>) = sqlx::query_as(
            "SELECT p.status, bool_and(a.reversed), p.reversal_reason \
             FROM customer_payment p JOIN payment_allocation a ON a.payment_ref = p.id \
             WHERE p.id = $1::uuid GROUP BY p.status, p.reversal_reason",
        )
        .bind(&payment)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(status.as_deref(), Some("reversed"));
        assert!(reversed);
        assert_eq!(reason.as_deref(), Some("Cheque bounced"));
        let (status, _) = app
            .request(Method::POST, &reverse, Some(json!({ "reason": "Again" })))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "reversed once");
    });
}

// feature: F5
#[test]
fn payment_concurrent_same_account_conflict() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let payer = account(&app).await;
        issued(&app, payer, "100", 10).await;
        // Another payment for the account holds its balance lock.
        let mut held = app.db().begin().await.unwrap();
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(attome_billing::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-billing/account-balance:{payer}"))
            .fetch_one(&mut *held)
            .await
            .unwrap();
        assert!(locked);
        let (status, _) = pay(
            &app,
            json!({ "payer_account_id": payer, "amount": 50, "currency": "SAR" }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        held.rollback().await.unwrap();
        let (status, body) = pay(
            &app,
            json!({ "payer_account_id": payer, "amount": 50, "currency": "SAR" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    });
}

// feature: F5
#[test]
fn payment_delete_is_forbidden() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let payer = account(&app).await;
        issued(&app, payer, "100", 10).await;
        let (_, body) = pay(
            &app,
            json!({ "payer_account_id": payer, "amount": 10, "currency": "SAR" }),
        )
        .await;
        let payment = body["payment_id"].as_str().unwrap().to_owned();
        let (status, _) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/customer_payment/{payment}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a payment is never deleted");
        let live: bool = sqlx::query_scalar(
            "SELECT COALESCE(is_active, true) FROM customer_payment WHERE id = $1::uuid",
        )
        .bind(&payment)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(live);
    });
}

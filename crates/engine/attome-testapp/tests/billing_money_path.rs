//! F5-T16: the money path end to end, with the Moyasar adapter against a
//! local fake of its API: an issued invoice, a payment link, the checkout,
//! a signed paid webhook delivered twice, the apply job, and the invoice
//! paid once; then a refund through the gateway with its draft credit note;
//! and every payment route hidden without the billing licence.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use attome_billing::gateway::moyasar::MoyasarGateway;
use attome_billing::gateway::{GatewayHttp, GatewaySystem, Method, PaymentGateway};
use attome_billing::payment::recurring::AdapterSource;
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::extract::{Path, Query, State};
use axum::http::{Method as HttpMethod, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
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

const WEBHOOK_SECRET: &str = "whsec-money-path";

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
    attome_api::changeset::boot::apply_platform_definition(&app.state, "attome-integration")
        .await
        .unwrap();
    let (status, body) = app
        .request(
            HttpMethod::PUT,
            "/api/v1/admin/settings/billing.refund.approval_threshold",
            Some(json!({ "scope": "deployment", "value": 0 })),
        )
        .await;
    assert!(status.is_success(), "{status}: {body}");
}

/// The fake's invoices and payments, by id.
#[derive(Default)]
struct Moyasar {
    invoices: HashMap<String, Value>,
    payments: HashMap<String, Value>,
}

type Shared = Arc<Mutex<Moyasar>>;

async fn create_invoice(
    State(fake): State<Shared>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let id = Uuid::new_v4().to_string();
    let invoice = json!({
        "id": id, "status": "initiated", "amount": body["amount"], "currency": body["currency"],
        "url": format!("https://checkout.moyasar.com/invoices/{id}"), "payments": [],
        "metadata": body["metadata"],
    });
    fake.lock().unwrap().invoices.insert(id, invoice.clone());
    (StatusCode::CREATED, Json(invoice))
}

async fn list_invoices(
    State(fake): State<Shared>,
    Query(query): Query<HashMap<String, String>>,
) -> Json<Value> {
    let fake = fake.lock().unwrap();
    let key = query.get("metadata[attome_idempotency_key]").cloned();
    let invoices: Vec<Value> = fake
        .invoices
        .values()
        .filter(|i| {
            key.as_deref()
                .is_some_and(|k| i["metadata"]["attome_idempotency_key"] == k)
        })
        .cloned()
        .collect();
    Json(json!({ "invoices": invoices }))
}

fn found(value: Option<&Value>) -> (StatusCode, Json<Value>) {
    match value {
        Some(v) => (StatusCode::OK, Json(v.clone())),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "message": "Object not found" })),
        ),
    }
}

async fn get_invoice(
    State(fake): State<Shared>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    found(fake.lock().unwrap().invoices.get(&id))
}

async fn get_payment(
    State(fake): State<Shared>,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    found(fake.lock().unwrap().payments.get(&id))
}

async fn refund(
    State(fake): State<Shared>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let mut fake = fake.lock().unwrap();
    let Some(payment) = fake.payments.get_mut(&id) else {
        return (StatusCode::NOT_FOUND, Json(json!({})));
    };
    payment["refunded"] = body["amount"].clone();
    payment["status"] = json!("refunded");
    (StatusCode::OK, Json(payment.clone()))
}

struct FakeSource(String);

impl AdapterSource for FakeSource {
    fn adapter(&self, _: &GatewaySystem) -> Result<Box<dyn PaymentGateway>, AppError> {
        Ok(Box::new(MoyasarGateway::new(GatewayHttp::for_tests(
            &self.0,
        ))))
    }
}

async fn fake_moyasar() -> (Shared, FakeSource) {
    let shared = Shared::default();
    let app = Router::new()
        .route("/v1/invoices", post(create_invoice).get(list_invoices))
        .route("/v1/invoices/{id}", get(get_invoice))
        .route("/v1/payments/{id}", get(get_payment))
        .route("/v1/payments/{id}/refund", post(refund))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (shared, FakeSource(format!("http://{addr}/v1")))
}

/// A Moyasar gateway system with its secret key and webhook secret.
async fn moyasar_system(app: &TestApp) -> Uuid {
    let system = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO integration_system \
            (id, name, kind, base_url, auth_type, service_principal_ref, status, config, created_at) \
         VALUES ($1, 'Moyasar', 'payment_gateway', 'https://api.moyasar.com/v1', 'api_key', $2, \
             'active', '{\"gateway\": \"moyasar\"}', NOW())",
    )
    .bind(system)
    .bind(app.admin.id.to_string())
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
        &json!({ "secret_key": "sk_test_fake", "webhook_secret": WEBHOOK_SECRET }).to_string(),
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

/// An issued invoice of 100 + 15% VAT.
async fn issued_invoice(app: &TestApp) -> Uuid {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Online buyer') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let invoice: Uuid = sqlx::query_scalar(
        "INSERT INTO invoice (id, status, kind, currency, account_ref, payment_terms_days, \
             series_key, is_active, row_version) \
         VALUES ($1, 'draft', 'invoice', 'SAR', $2, 30, 'TMNY', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO invoice_line (id, invoice_ref, description, quantity, unit_price, \
             vat_category, is_active, row_version) \
         VALUES ($1, $2, 'Subscription', 2, 50, 'standard', true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(invoice)
    .execute(app.db())
    .await
    .unwrap();
    let (status, body) = app
        .request(
            HttpMethod::POST,
            &format!("/api/v1/billing/invoices/{invoice}/issue"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    invoice
}

/// Link -> checkout -> the payer pays on Moyasar's page -> the webhook
/// (twice) -> the apply job. Returns (invoice, the succeeded payment).
async fn pay_through_link(app: &TestApp, shared: &Shared, source: &FakeSource) -> (Uuid, Uuid) {
    let system = moyasar_system(app).await;
    let invoice = issued_invoice(app).await;
    let (status, link) = app
        .request(
            HttpMethod::POST,
            "/api/v1/billing/payment-links",
            Some(json!({ "invoice_id": invoice })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{link}");
    let token = link["url"]
        .as_str()
        .unwrap()
        .rsplit_once("/pay/")
        .unwrap()
        .1
        .to_owned();
    let live = attome_billing::payment::link::live_link(&app.state, &token)
        .await
        .unwrap();
    let gateway_system = attome_billing::gateway::system(&app.state, system)
        .await
        .unwrap();
    let secret = attome_billing::gateway::credential(&app.state, &gateway_system)
        .await
        .unwrap();
    let gateway = source.adapter(&gateway_system).unwrap();
    let started = attome_billing::payment::link::start_checkout(
        &app.state,
        &live,
        Method::Card,
        &gateway_system,
        gateway.as_ref(),
        &secret,
        "https://crm.example/pay/return",
    )
    .await
    .unwrap();
    let redirect = started.redirect_url.unwrap();
    assert!(redirect.starts_with("https://checkout.moyasar.com/invoices/"));
    let moyasar_invoice = redirect.rsplit('/').next().unwrap().to_owned();

    // The payer pays on Moyasar's page.
    let moyasar_payment = Uuid::new_v4().to_string();
    let paid = json!({
        "id": moyasar_payment, "status": "paid", "amount": 11500, "fee": 230, "currency": "SAR",
        "refunded": 0, "captured": 0, "invoice_id": moyasar_invoice,
    });
    {
        let mut fake = shared.lock().unwrap();
        fake.payments.insert(moyasar_payment.clone(), paid.clone());
        let invoice = fake.invoices.get_mut(&moyasar_invoice).unwrap();
        invoice["status"] = json!("paid");
        invoice["payments"] = json!([paid.clone()]);
    }
    let webhook = serde_json::to_vec(&json!({
        "id": Uuid::new_v4().to_string(), "type": "payment_paid",
        "created_at": "2026-10-18T10:00:00Z", "secret_token": WEBHOOK_SECRET,
        "account_name": "Merchant", "live": false, "data": paid,
    }))
    .unwrap();
    for expected_new in [1, 0] {
        let (status, body) = app
            .request_public(
                HttpMethod::POST,
                &format!("/api/v1/billing/gateways/{system}/webhook"),
                &[("content-type", "application/json")],
                webhook.clone(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["new"], json!(expected_new));
    }
    attome_billing::gateway::webhook::apply_events(&app.state)
        .await
        .unwrap();
    (invoice, started.payment_id)
}

// feature: F5
#[test]
fn payment_money_path_link_to_paid() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (shared, source) = fake_moyasar().await;
        let (invoice, payment) = pay_through_link(&app, &shared, &source).await;

        let (status, fee, link): (Option<String>, Option<String>, Option<Uuid>) = sqlx::query_as(
            "SELECT status, fee::text, payment_link_ref FROM customer_payment WHERE id = $1",
        )
        .bind(payment)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(status.as_deref(), Some("succeeded"));
        assert_eq!(fee.unwrap().parse::<f64>().unwrap(), 2.3);
        let succeeded: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM customer_payment WHERE payment_link_ref = $1 AND status = 'succeeded'",
        )
        .bind(link)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(succeeded, 1, "one payment");
        let allocations: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT invoice_ref, amount::text FROM payment_allocation WHERE payment_ref = $1",
        )
        .bind(payment)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(allocations.len(), 1, "one allocation");
        assert_eq!(allocations[0].0, invoice);
        let (open, paid): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT open_total::text, payment_status FROM invoice WHERE id = $1")
                .bind(invoice)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(open.unwrap().parse::<f64>().unwrap(), 0.0);
        assert_eq!(paid.as_deref(), Some("paid"));
    });
}

// feature: F5
#[test]
fn payment_money_path_refund_creates_credit_note() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (shared, source) = fake_moyasar().await;
        let (invoice, payment) = pay_through_link(&app, &shared, &source).await;

        let (status, body) = app
            .request(
                HttpMethod::POST,
                &format!("/api/v1/billing/payments/{payment}/refunds"),
                Some(json!({ "amount": 57.5, "reason": "Half the service was not delivered" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending");
        let refund: Uuid = body["refund_id"].as_str().unwrap().parse().unwrap();
        attome_billing::payment::refund::execute_refund(&app.state, refund, &source)
            .await
            .unwrap();

        // Moyasar refunded 57.50 of the payment.
        let refunded = shared
            .lock()
            .unwrap()
            .payments
            .values()
            .map(|p| p["refunded"].as_i64().unwrap_or(0))
            .sum::<i64>();
        assert_eq!(refunded, 5750);
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM customer_payment WHERE id = $1")
                .bind(payment)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status.as_deref(), Some("partially_refunded"));
        let (refund_status, note): (Option<String>, Option<Uuid>) =
            sqlx::query_as("SELECT status, credit_note_ref FROM payment_refund WHERE id = $1")
                .bind(refund)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(refund_status.as_deref(), Some("succeeded"));
        let original: Option<Uuid> = sqlx::query_scalar(
            "SELECT original_invoice_ref FROM invoice WHERE id = $1 AND kind = 'credit_note'",
        )
        .bind(note.expect("a draft credit note"))
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(original, Some(invoice));
    });
}

// feature: F5
#[test]
fn payment_routes_unlicensed_hidden() {
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
            (HttpMethod::POST, "/api/v1/billing/payments".to_owned()),
            (
                HttpMethod::POST,
                format!("/api/v1/billing/payments/{id}/refunds"),
            ),
            (HttpMethod::POST, "/api/v1/billing/payment-links".to_owned()),
            (
                HttpMethod::GET,
                format!("/api/v1/billing/disputes/{id}/evidence"),
            ),
        ];
        let mut statuses = Vec::new();
        for (method, path) in calls {
            let (status, body) = app.request(method, &path, Some(json!({}))).await;
            statuses.push((path, status, body));
        }
        let (webhook, webhook_body) = app
            .request_public(
                HttpMethod::POST,
                &format!("/api/v1/billing/gateways/{id}/webhook"),
                &[],
                b"{}".to_vec(),
            )
            .await;
        let (page, page_body) = app
            .request_public(
                HttpMethod::GET,
                &format!("/api/v1/pay/{id}.x"),
                &[],
                Vec::new(),
            )
            .await;
        app.state.modules.store(before);
        // The platform's answer for a module that is off (D-279): 403
        // `feature_hidden`, before any handler, credential or link check.
        statuses.push(("webhook".into(), webhook, webhook_body));
        statuses.push(("pay page".into(), page, page_body));
        for (path, status, body) in statuses {
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
            assert_eq!(body["error"], "feature_hidden", "{path}: {body}");
        }
    });
}

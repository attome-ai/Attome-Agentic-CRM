//! F5-T11: a day's gateway payouts (the Moyasar adapter against a local
//! fake of its transfers API) are matched to their payments: an exact
//! payout is `matched` and its fees go on the change feed; a payout naming
//! an unknown payment is a `difference` listing it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::{Arc, Mutex};

use attome_billing::gateway::moyasar::MoyasarGateway;
use attome_billing::gateway::{GatewayHttp, GatewaySystem, PaymentGateway};
use attome_billing::payment::reconcile::reconcile_day;
use attome_billing::payment::recurring::AdapterSource;
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::NaiveDate;
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
    attome_api::changeset::boot::apply_platform_definition(&app.state, "attome-integration")
        .await
        .unwrap();
}

/// The fake's data: one transfer, its lines, and Moyasar's payments.
#[derive(Default)]
struct Moyasar {
    transfer_id: String,
    transfer: Value,
    lines: Vec<Value>,
    payments: Vec<Value>,
}

type Shared = Arc<Mutex<Moyasar>>;

async fn transfers(State(fake): State<Shared>) -> Json<Value> {
    let fake = fake.lock().unwrap();
    Json(json!({ "transfers": [fake.transfer.clone()], "meta": { "next_page": null } }))
}

async fn lines(State(fake): State<Shared>, Path(_id): Path<String>) -> Json<Value> {
    let fake = fake.lock().unwrap();
    Json(json!({ "lines": fake.lines.clone(), "meta": { "next_page": null } }))
}

async fn payment(
    State(fake): State<Shared>,
    Path(id): Path<String>,
) -> (axum::http::StatusCode, Json<Value>) {
    let fake = fake.lock().unwrap();
    match fake.payments.iter().find(|p| p["id"] == id) {
        Some(p) => (axum::http::StatusCode::OK, Json(p.clone())),
        None => (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "message": "Object not found" })),
        ),
    }
}

struct FakeSource(String);

impl AdapterSource for FakeSource {
    fn adapter(&self, _: &GatewaySystem) -> Result<Box<dyn PaymentGateway>, AppError> {
        Ok(Box::new(MoyasarGateway::new(GatewayHttp::for_tests(
            &self.0,
        ))))
    }
}

async fn fake_moyasar(shared: Shared) -> FakeSource {
    let app = Router::new()
        .route("/v1/transfers", get(transfers))
        .route("/v1/transfers/{id}/lines", get(lines))
        .route("/v1/payments/{id}", get(payment))
        .with_state(shared);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    FakeSource(format!("http://{addr}/v1"))
}

/// A Moyasar gateway system with a credential.
async fn system(app: &TestApp) -> Uuid {
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
    let credential = attome_integration::credential::store(&mut tx, &ring, system, "sk_test_fake")
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

/// A succeeded gateway payment Attome knows by `reference`.
async fn payment_row(app: &TestApp, system: Uuid, reference: &str, amount: &str, fee: &str) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Payer') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    sqlx::query(
        "INSERT INTO customer_payment (id, name, payer_account_ref, amount, fee, currency, method, \
             status, gateway_system_ref, gateway_reference, unallocated, is_active, row_version) \
         VALUES ($1, 'Card', $2, $3::numeric, $4::numeric, 'SAR', 'card', 'succeeded', $5, $6, 0, \
             true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .bind(amount)
    .bind(fee)
    .bind(system.to_string())
    .bind(reference)
    .execute(app.db())
    .await
    .unwrap();
}

/// Moyasar's side: two payments (one through an invoice checkout, one a
/// token charge) settled in one transfer of 172.50 less 3.45 in fees.
fn moyasar_day(invoice_ref: &str, charge_ref: &str, extra_line: Option<&str>) -> Moyasar {
    let transfer_id = Uuid::now_v7().to_string();
    let card_payment = Uuid::now_v7().to_string();
    let mut lines = vec![
        json!({ "payment_id": card_payment, "type": "payment", "amount": 11500, "fee": 230, "tax": 0 }),
        json!({ "payment_id": charge_ref, "type": "payment", "amount": 5750, "fee": 115, "tax": 0 }),
    ];
    if let Some(extra) = extra_line {
        lines.push(
            json!({ "payment_id": extra, "type": "payment", "amount": 1000, "fee": 0, "tax": 0 }),
        );
    }
    Moyasar {
        transfer_id: transfer_id.clone(),
        transfer: json!({
            "id": transfer_id, "recipient_type": "Entity", "currency": "SAR", "amount": 16905,
            "fee": 0, "tax": 0, "reference": format!("bank-{transfer_id}"),
            "transaction_count": 2, "created_at": "2026-10-17T08:06:54.000Z",
        }),
        lines,
        payments: vec![
            json!({ "id": card_payment, "status": "paid", "amount": 11500, "fee": 230,
                    "currency": "SAR", "invoice_id": invoice_ref }),
            json!({ "id": charge_ref, "status": "paid", "amount": 5750, "fee": 115,
                    "currency": "SAR", "invoice_id": null }),
        ],
    }
}

fn day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 10, 17).unwrap()
}

type PayoutRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

async fn payout(app: &TestApp, system: Uuid, reference: &str) -> PayoutRow {
    sqlx::query_as(
        "SELECT status, gross::text, fees::text, net::text, differences FROM gateway_payout \
         WHERE gateway_system_ref = $1 AND payout_reference = $2",
    )
    .bind(system.to_string())
    .bind(reference)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: F5
#[test]
fn reconcile_exact_payout_matches() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let system = system(&app).await;
        let invoice_ref = Uuid::now_v7().to_string();
        let charge_ref = Uuid::now_v7().to_string();
        payment_row(&app, system, &invoice_ref, "115.00", "2.30").await;
        payment_row(&app, system, &charge_ref, "57.50", "1.15").await;
        let data = moyasar_day(&invoice_ref, &charge_ref, None);
        let reference = format!("bank-{}", data.transfer_id);
        let source = fake_moyasar(Arc::new(Mutex::new(data))).await;

        let outcome = reconcile_day(&app.state, system, day(), &source)
            .await
            .unwrap();
        assert_eq!(
            (outcome.payouts, outcome.matched, outcome.differences),
            (1, 1, 0)
        );
        let (status, gross, fees, net, differences) = payout(&app, system, &reference).await;
        assert_eq!(status.as_deref(), Some("matched"));
        let num = |v: Option<String>| v.unwrap().parse::<f64>().unwrap();
        assert_eq!((num(gross), num(fees), num(net)), (172.5, 3.45, 169.05));
        assert!(differences.is_none());

        // The fees go to the ledger through the change feed, once.
        reconcile_day(&app.state, system, day(), &source)
            .await
            .unwrap();
        let fee_events: Vec<Value> = sqlx::query_scalar(
            "SELECT e.after FROM entity_change_event e JOIN gateway_payout p ON p.id = e.record_id \
             WHERE p.gateway_system_ref = $1 AND p.payout_reference = $2 \
               AND e.event_name = 'billing.gateway_fee'",
        )
        .bind(system.to_string())
        .bind(&reference)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(
            fee_events.len(),
            1,
            "a payout seen again reports its fees once"
        );
        assert_eq!(
            fee_events[0]["amount"]
                .as_str()
                .unwrap()
                .parse::<f64>()
                .unwrap(),
            3.45
        );
        assert_eq!(fee_events[0]["currency"], "SAR");
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM gateway_payout WHERE gateway_system_ref = $1")
                .bind(system.to_string())
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(rows, 1, "upserted, not duplicated");
    });
}

// feature: F5
#[test]
fn reconcile_missing_payment_flags_difference() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let system = system(&app).await;
        let invoice_ref = Uuid::now_v7().to_string();
        let charge_ref = Uuid::now_v7().to_string();
        payment_row(&app, system, &invoice_ref, "115.00", "2.30").await;
        payment_row(&app, system, &charge_ref, "57.50", "1.15").await;
        let stranger = Uuid::now_v7().to_string();
        let data = moyasar_day(&invoice_ref, &charge_ref, Some(&stranger));
        let reference = format!("bank-{}", data.transfer_id);
        let source = fake_moyasar(Arc::new(Mutex::new(data))).await;

        let outcome = reconcile_day(&app.state, system, day(), &source)
            .await
            .unwrap();
        assert_eq!(outcome.differences, 1);
        let (status, _, _, _, differences) = payout(&app, system, &reference).await;
        assert_eq!(status.as_deref(), Some("difference"));
        let differences: Value = serde_json::from_str(&differences.unwrap()).unwrap();
        assert_eq!(differences["unmatched_references"], json!([stranger]));

        // The stored query lists it for a person.
        let listed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM gateway_payout \
             WHERE status = 'difference' AND payout_reference = $1)",
        )
        .bind(&reference)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(listed);
    });
}

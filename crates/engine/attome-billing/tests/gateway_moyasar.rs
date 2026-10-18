//! F5-T5: the Moyasar adapter against a local fake of Moyasar's API (no
//! network): statuses map, a retried charge charges once, a webhook with
//! the wrong secret is refused, and a saved card keeps its brand and last
//! four digits only.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use attome_billing::gateway::moyasar::{MoyasarGateway, given_id};
use attome_billing::gateway::{
    CheckoutRequest, GatewayError, GatewayHttp, GatewayStatus, Method, PaymentGateway,
};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use rust_decimal::Decimal;
use serde_json::{Value, json};

const SECRET: &str = "sk_test_fake";

#[derive(Default)]
struct Fake {
    payments: HashMap<String, Value>,
    invoices: HashMap<String, Value>,
    /// Payments actually charged.
    charges: usize,
    /// Answer the next payment creation with a 500 after charging (a lost
    /// response).
    lose_next_answer: bool,
}

type Shared = Arc<Mutex<Fake>>;

fn authorised(headers: &axum::http::HeaderMap) -> bool {
    use base64::Engine as _;
    let expected = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{SECRET}:"))
    );
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(expected.as_str())
}

fn unauthorised() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(
            json!({ "type": "authentication_error", "message": "Invalid authorization credentials" }),
        ),
    )
}

async fn create_payment(
    State(fake): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    let mut fake = fake.lock().unwrap();
    let id = body["given_id"].as_str().unwrap().to_owned();
    if fake.payments.contains_key(&id) {
        // Moyasar: the same given_id is never charged again.
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "type": "invalid_request_error", "message": "Payment is already created." }),
            ),
        );
    }
    fake.charges += 1;
    let payment = json!({
        "id": id, "status": "paid", "amount": body["amount"], "fee": 230,
        "currency": body["currency"], "refunded": 0, "captured": 0, "invoice_id": null,
        "source": { "type": "token", "company": "visa", "name": "John Doe",
                    "number": "XXXX-XXXX-XXXX-1111", "message": null },
    });
    fake.payments.insert(id, payment.clone());
    if std::mem::take(&mut fake.lose_next_answer) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({})));
    }
    (StatusCode::CREATED, Json(payment))
}

async fn fetch_payment(
    State(fake): State<Shared>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    match fake.lock().unwrap().payments.get(&id) {
        Some(p) => (StatusCode::OK, Json(p.clone())),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "message": "Object not found" })),
        ),
    }
}

async fn create_invoice(
    State(fake): State<Shared>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    let id = uuid::Uuid::new_v4().to_string();
    let invoice = json!({
        "id": id, "status": "initiated", "amount": body["amount"], "currency": body["currency"],
        "description": body["description"], "url": format!("https://checkout.moyasar.com/invoices/{id}"),
        "payments": [], "metadata": body["metadata"],
    });
    fake.lock().unwrap().invoices.insert(id, invoice.clone());
    (StatusCode::CREATED, Json(invoice))
}

async fn list_invoices(
    State(fake): State<Shared>,
    headers: axum::http::HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    let fake = fake.lock().unwrap();
    let invoices: Vec<Value> = fake
        .invoices
        .values()
        .filter(|i| {
            query.iter().all(|(k, v)| {
                k.strip_prefix("metadata[")
                    .and_then(|k| k.strip_suffix(']'))
                    .is_none_or(|k| i["metadata"][k].as_str() == Some(v.as_str()))
            })
        })
        .cloned()
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "invoices": invoices, "meta": { "next_page": null } })),
    )
}

async fn fetch_invoice(
    State(fake): State<Shared>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    match fake.lock().unwrap().invoices.get(&id) {
        Some(i) => (StatusCode::OK, Json(i.clone())),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "message": "Object not found" })),
        ),
    }
}

async fn fetch_token(
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    (
        StatusCode::OK,
        Json(json!({
            "id": id, "status": "active", "brand": "visa", "funding": "credit",
            "country": "US", "month": "12", "year": "2030", "name": "John Doe",
            "last_four": "1111", "metadata": { "customer": "c-1" }, "message": null,
            "verification_url": null, "created_at": "2024-01-15T10:00:00.000Z",
        })),
    )
}

/// A fake Moyasar on a local port, and the adapter pointed at it.
async fn fake() -> (Shared, MoyasarGateway) {
    let shared = Shared::default();
    let app = Router::new()
        .route("/v1/payments", post(create_payment))
        .route("/v1/payments/{id}", get(fetch_payment))
        .route("/v1/invoices", post(create_invoice).get(list_invoices))
        .route("/v1/invoices/{id}", get(fetch_invoice))
        .route("/v1/tokens/{id}", get(fetch_token))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let gateway = MoyasarGateway::new(GatewayHttp::for_tests(&format!("http://{addr}/v1")));
    (shared, gateway)
}

fn sar(s: &str) -> Decimal {
    Decimal::from_str(s).unwrap()
}

fn checkout_request(key: &str) -> CheckoutRequest {
    CheckoutRequest {
        amount: sar("115.00"),
        currency: "SAR".into(),
        description: "Invoice INV-2026-000001".into(),
        return_url: "https://crm.example/pay/return".into(),
        reference: "INV-2026-000001".into(),
        idempotency_key: key.into(),
        methods: vec![Method::Mada, Method::ApplePay],
    }
}

// feature: F5
#[tokio::test]
async fn moyasar_paid_maps_to_succeeded() {
    let (shared, gateway) = fake().await;
    let checkout = gateway
        .create_checkout(SECRET, &checkout_request("checkout-1"))
        .await
        .unwrap();
    assert!(
        checkout
            .redirect_url
            .starts_with("https://checkout.moyasar.com/")
    );
    assert_eq!(
        gateway
            .get_status(SECRET, &checkout.gateway_reference)
            .await
            .unwrap(),
        GatewayStatus::Pending
    );

    // The payer pays on Moyasar's page.
    {
        let mut fake = shared.lock().unwrap();
        let invoice = fake.invoices.get_mut(&checkout.gateway_reference).unwrap();
        invoice["status"] = json!("paid");
        invoice["payments"] = json!([{
            "id": "6c1a6b1e-3f7e-4a43-9d6f-0f6b9a4f7d10", "status": "paid", "amount": 11500,
            "fee": 210, "currency": "SAR", "refunded": 0, "captured": 0,
            "invoice_id": checkout.gateway_reference,
        }]);
    }
    assert_eq!(
        gateway
            .get_status(SECRET, &checkout.gateway_reference)
            .await
            .unwrap(),
        GatewayStatus::Succeeded {
            amount: sar("115.00"),
            fee: Some(sar("2.10")),
        }
    );

    // A token charge's payment is found by its reference too, and a failed
    // one carries Moyasar's message.
    let key = uuid::Uuid::now_v7().to_string();
    gateway
        .charge_token(SECRET, "token_abc", sar("57.50"), "SAR", &key)
        .await
        .unwrap();
    assert_eq!(
        gateway.get_status(SECRET, &key).await.unwrap(),
        GatewayStatus::Succeeded {
            amount: sar("57.50"),
            fee: Some(sar("2.30")),
        }
    );
    {
        let mut fake = shared.lock().unwrap();
        let payment = fake.payments.get_mut(&key).unwrap();
        payment["status"] = json!("failed");
        payment["source"]["message"] = json!("INSUFFICIENT_FUNDS");
    }
    assert!(matches!(
        gateway.get_status(SECRET, &key).await.unwrap(),
        GatewayStatus::Failed { reason } if reason == "INSUFFICIENT_FUNDS"
    ));

    // A wrong secret key is a refusal, not an outage.
    assert!(matches!(
        gateway.get_status("sk_test_wrong", &key).await,
        Err(GatewayError::Refused(_))
    ));
}

// feature: F5
#[tokio::test]
async fn moyasar_retry_same_key_one_charge() {
    let (shared, gateway) = fake().await;
    let key = "renewal-2026-10";

    // The first answer is lost after Moyasar charged: the call reports an
    // outage, and the retry with the same key finds the payment.
    shared.lock().unwrap().lose_next_answer = true;
    let first = gateway
        .charge_token(SECRET, "token_abc", sar("100"), "SAR", key)
        .await;
    assert!(
        matches!(first, Err(GatewayError::Unavailable(_))),
        "{first:?}"
    );
    let retried = gateway
        .charge_token(SECRET, "token_abc", sar("100"), "SAR", key)
        .await
        .unwrap();
    assert!(matches!(retried, GatewayStatus::Succeeded { amount, .. } if amount == sar("100.00")));
    let again = gateway
        .charge_token(SECRET, "token_abc", sar("100"), "SAR", key)
        .await
        .unwrap();
    assert_eq!(again, retried);
    {
        let fake = shared.lock().unwrap();
        assert_eq!(fake.charges, 1, "one charge for one key");
        assert!(fake.payments.contains_key(&given_id(key).to_string()));
    }

    // A retried checkout reuses its invoice.
    let a = gateway
        .create_checkout(SECRET, &checkout_request("checkout-7"))
        .await
        .unwrap();
    let b = gateway
        .create_checkout(SECRET, &checkout_request("checkout-7"))
        .await
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(shared.lock().unwrap().invoices.len(), 1);

    // An amount finer than a halala is refused before any call.
    assert!(matches!(
        gateway
            .charge_token(SECRET, "token_abc", sar("1.005"), "SAR", "k-2")
            .await,
        Err(GatewayError::Refused(_))
    ));
    assert_eq!(shared.lock().unwrap().charges, 1);
}

fn webhook(secret: Option<&str>) -> Vec<u8> {
    let mut body = json!({
        "id": "65a2b41b-b644-4792-a45d-f1c6f67846fe",
        "type": "payment_paid",
        "created_at": "2026-10-18T10:00:00Z",
        "account_name": "Test Merchant",
        "live": false,
        "data": {
            "id": "760878ec-d1d3-5f72-9056-191683f55872", "status": "paid", "amount": 60000,
            "fee": 1580, "currency": "SAR", "refunded": 0, "captured": 0,
            "invoice_id": "9785ba96-a1be-5b13-a281-b27a4a6dad39",
        },
    });
    if let Some(secret) = secret {
        body["secret_token"] = json!(secret);
    }
    serde_json::to_vec(&body).unwrap()
}

// feature: F5
#[tokio::test]
async fn moyasar_bad_webhook_secret_rejected() {
    let (_, gateway) = fake().await;
    for body in [
        webhook(Some("not-the-secret")),
        webhook(None),
        b"not json".to_vec(),
    ] {
        assert_eq!(
            gateway.verify_webhook(&[], &body, "whsec-123"),
            Err(GatewayError::BadSignature)
        );
    }
    // No stored secret: nothing verifies.
    assert_eq!(
        gateway.verify_webhook(&[], &webhook(Some("")), ""),
        Err(GatewayError::BadSignature)
    );

    let events = gateway
        .verify_webhook(&[], &webhook(Some("whsec-123")), "whsec-123")
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, "65a2b41b-b644-4792-a45d-f1c6f67846fe");
    // The checkout's reference: the invoice.
    assert_eq!(
        events[0].gateway_reference,
        "9785ba96-a1be-5b13-a281-b27a4a6dad39"
    );
    assert_eq!(
        events[0].status,
        GatewayStatus::Succeeded {
            amount: sar("600.00"),
            fee: Some(sar("15.80")),
        }
    );
}

// feature: F5
#[tokio::test]
async fn moyasar_token_keeps_last4_only() {
    let (_, gateway) = fake().await;
    let card = gateway.saved_card(SECRET, "token_x6okRgkZ").await.unwrap();
    assert_eq!(card.brand, "visa");
    assert_eq!(card.last4, "1111");
    assert!(card.active);
    let kept = serde_json::to_value(&card).unwrap();
    let keys: Vec<&str> = kept
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.len(), 3, "{kept}");
    for dropped in ["John Doe", "2030", "c-1", "credit"] {
        assert!(
            !kept.to_string().contains(dropped),
            "{dropped} kept: {kept}"
        );
    }
    // A reference that is not one path segment never reaches the gateway.
    assert!(matches!(
        gateway.saved_card(SECRET, "../payments").await,
        Err(GatewayError::Refused(_))
    ));
}

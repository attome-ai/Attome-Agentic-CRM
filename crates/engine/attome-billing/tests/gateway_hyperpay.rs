//! F5-T6: the HyperPay adapter against a local fake of HyperPay's (OPPWA)
//! API (no network): result codes map, mada checks out on its own entity,
//! encrypted webhooks decrypt, and a tampered one is refused.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use attome_billing::gateway::hyperpay::HyperPayGateway;
use attome_billing::gateway::{
    CheckoutRequest, GatewayError, GatewayHttp, GatewayStatus, Method, PaymentGateway,
};
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use rust_decimal::Decimal;
use serde_json::{Value, json};

const TOKEN: &str = "OGE4Mjk0MTc0YjdlY2IyODAxNGI5Njk5MjIwMDE1Y2N8ZmFrZQ==";
const CARD_ENTITY: &str = "8a8294174b7ecb28014b9699220015ca";
const MADA_ENTITY: &str = "8a8294174b7ecb28014b9699220015cb";

fn credential() -> String {
    json!({
        "access_token": TOKEN,
        "entity_ids": { "card": CARD_ENTITY, "mada": MADA_ENTITY },
    })
    .to_string()
}

#[derive(Default)]
struct Fake {
    /// (entity, transaction) as HyperPay's query reports them.
    transactions: Vec<(String, Value)>,
    /// The entity each checkout was created on.
    checkout_entities: Vec<String>,
    charges: usize,
    lose_next_answer: bool,
    decline_next: bool,
}

type Shared = Arc<Mutex<Fake>>;

fn authorised(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(format!("Bearer {TOKEN}").as_str())
}

fn unauthorised() -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(
            json!({ "result": { "code": "800.900.300", "description": "invalid authentication information" } }),
        ),
    )
}

fn transaction(id: &str, kind: &str, amount: &str, code: &str, mtx: &str) -> Value {
    json!({
        "id": id, "paymentType": kind, "paymentBrand": "VISA", "amount": amount,
        "currency": "SAR", "merchantTransactionId": mtx,
        "result": { "code": code, "description": format!("result {code}") },
        "card": { "bin": "420000", "last4Digits": "0000", "holder": "Jane Jones" },
    })
}

async fn checkouts(
    State(fake): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    fake.lock()
        .unwrap()
        .checkout_entities
        .push(form["entityId"].clone());
    (
        StatusCode::OK,
        Json(json!({
            "result": { "code": "000.200.100", "description": "successfully created checkout" },
            "id": "8ac7a4c87b1c5f72017b1d9bd3d10a1b.uat01-vm-tx04",
            "integrity": "sha384-fakeintegrityhash",
        })),
    )
}

async fn query(
    State(fake): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    let fake = fake.lock().unwrap();
    let payments: Vec<Value> = fake
        .transactions
        .iter()
        .filter(|(entity, t)| {
            entity == &q["entityId"]
                && t["merchantTransactionId"].as_str() == Some(q["merchantTransactionId"].as_str())
        })
        .map(|(_, t)| t.clone())
        .collect();
    if payments.is_empty() {
        return (
            StatusCode::OK,
            Json(
                json!({ "result": { "code": "700.400.580", "description": "cannot find transaction" } }),
            ),
        );
    }
    (
        StatusCode::OK,
        Json(
            json!({ "result": { "code": "000.000.100", "description": "successful request" }, "payments": payments }),
        ),
    )
}

async fn registration_payment(
    State(fake): State<Shared>,
    headers: HeaderMap,
    Path(_token): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    let mut fake = fake.lock().unwrap();
    assert_eq!(form["standingInstruction.source"], "MIT");
    let decline = std::mem::take(&mut fake.decline_next);
    let code = if decline {
        "800.100.151"
    } else {
        "000.100.110"
    };
    let id = format!("8ac7a4a1{:024}", fake.transactions.len());
    let t = transaction(
        &id,
        "DB",
        &form["amount"],
        code,
        &form["merchantTransactionId"],
    );
    fake.transactions
        .push((form["entityId"].clone(), t.clone()));
    if !decline {
        fake.charges += 1;
    }
    if std::mem::take(&mut fake.lose_next_answer) {
        return (StatusCode::BAD_GATEWAY, Json(json!({})));
    }
    let status = if decline {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    (status, Json(t))
}

async fn backoffice(
    State(fake): State<Shared>,
    headers: HeaderMap,
    Path(_payment): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    if !authorised(&headers) {
        return unauthorised();
    }
    let mut fake = fake.lock().unwrap();
    assert_eq!(form["paymentType"], "RF");
    let id = format!("8ac7a4a2{:024}", fake.transactions.len());
    let mut t = transaction(
        &id,
        "RF",
        &form["amount"],
        "000.100.110",
        &form["merchantTransactionId"],
    );
    t["customParameters"] =
        json!({ "ATTOME_refund_key": form["customParameters[ATTOME_refund_key]"] });
    fake.transactions
        .push((form["entityId"].clone(), t.clone()));
    (StatusCode::OK, Json(t))
}

async fn fake() -> (Shared, HyperPayGateway) {
    let shared = Shared::default();
    let app = Router::new()
        .route("/v1/checkouts", post(checkouts))
        .route("/v1/query", get(query))
        .route(
            "/v1/registrations/{token}/payments",
            post(registration_payment),
        )
        .route("/v1/payments/{id}", post(backoffice))
        .with_state(shared.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (
        shared,
        HyperPayGateway::new(GatewayHttp::for_tests(&format!("http://{addr}"))),
    )
}

fn sar(s: &str) -> Decimal {
    Decimal::from_str(s).unwrap()
}

fn seed(shared: &Shared, entity: &str, t: Value) {
    shared.lock().unwrap().transactions.push((entity.into(), t));
}

// feature: F5
#[tokio::test]
async fn hyperpay_success_code_maps() {
    let (shared, gateway) = fake().await;
    let secret = credential();
    let status = |reference: &'static str| {
        let (gateway, secret) = (gateway.clone(), secret.clone());
        async move { gateway.get_status(&secret, reference).await.unwrap() }
    };

    seed(
        &shared,
        CARD_ENTITY,
        transaction("a1", "DB", "92.00", "000.100.110", "order-success"),
    );
    assert_eq!(
        status("order-success").await,
        GatewayStatus::Succeeded {
            amount: sar("92.00"),
            fee: None
        }
    );
    // Mada's entity is queried too.
    seed(
        &shared,
        MADA_ENTITY,
        transaction("a2", "DB", "10.00", "000.000.000", "order-mada"),
    );
    assert!(matches!(
        status("order-mada").await,
        GatewayStatus::Succeeded { .. }
    ));
    seed(
        &shared,
        CARD_ENTITY,
        transaction("a3", "DB", "92.00", "000.200.000", "order-pending"),
    );
    assert_eq!(status("order-pending").await, GatewayStatus::Pending);
    seed(
        &shared,
        CARD_ENTITY,
        transaction("a4", "DB", "92.00", "800.100.151", "order-declined"),
    );
    assert!(matches!(
        status("order-declined").await,
        GatewayStatus::Failed { reason } if reason.contains("800.100.151")
    ));
    // Nothing yet: the payer has not paid.
    assert_eq!(status("order-unknown").await, GatewayStatus::Pending);

    // A token charge, its answer lost after HyperPay charged: the retry
    // finds it and charges nothing more.
    shared.lock().unwrap().lose_next_answer = true;
    let lost = gateway
        .charge_token(
            &secret,
            "8ac7a4a19a1b2c3d",
            sar("50"),
            "SAR",
            "invoice:42:attempt:1",
        )
        .await;
    assert!(
        matches!(lost, Err(GatewayError::Unavailable(_))),
        "{lost:?}"
    );
    let retried = gateway
        .charge_token(
            &secret,
            "8ac7a4a19a1b2c3d",
            sar("50"),
            "SAR",
            "invoice:42:attempt:1",
        )
        .await
        .unwrap();
    assert_eq!(
        retried,
        GatewayStatus::Succeeded {
            amount: sar("50.00"),
            fee: None
        }
    );
    assert_eq!(shared.lock().unwrap().charges, 1);

    // A decline is a failed payment with HyperPay's code, not an error.
    shared.lock().unwrap().decline_next = true;
    let declined = gateway
        .charge_token(
            &secret,
            "8ac7a4a19a1b2c3d",
            sar("50"),
            "SAR",
            "invoice:42:attempt:2",
        )
        .await
        .unwrap();
    assert!(matches!(declined, GatewayStatus::Failed { reason } if reason.contains("800.100.151")));

    // A refund, retried with its key: refunded once.
    for _ in 0..2 {
        let refunded = gateway
            .refund(&secret, "order-success", sar("20"), "refund-0001")
            .await
            .unwrap();
        assert_eq!(
            refunded,
            GatewayStatus::Refunded {
                amount: sar("20.00")
            }
        );
    }
    let refunds = shared
        .lock()
        .unwrap()
        .transactions
        .iter()
        .filter(|(_, t)| t["paymentType"] == "RF")
        .count();
    assert_eq!(refunds, 1);
    assert_eq!(
        status("order-success").await,
        GatewayStatus::Refunded {
            amount: sar("20.00")
        }
    );
    // More than is left is refused.
    assert!(matches!(
        gateway
            .refund(&secret, "order-success", sar("80"), "refund-0002")
            .await,
        Err(GatewayError::Refused(_))
    ));

    // A wrong token is a refusal, not an outage.
    let wrong =
        json!({ "access_token": "nope", "entity_ids": { "card": CARD_ENTITY } }).to_string();
    assert!(matches!(
        gateway.get_status(&wrong, "order-success").await,
        Err(GatewayError::Refused(_))
    ));
}

fn checkout_request(methods: Vec<Method>) -> CheckoutRequest {
    CheckoutRequest {
        amount: sar("115.00"),
        currency: "SAR".into(),
        description: "Invoice INV-2026-000001".into(),
        return_url: "https://crm.example/pay/return".into(),
        reference: "INV-2026-000001".into(),
        idempotency_key: format!("checkout-{methods:?}"),
        methods,
    }
}

// feature: F5
#[tokio::test]
async fn hyperpay_mada_uses_mada_entity() {
    let (shared, gateway) = fake().await;
    let secret = credential();

    let mada = gateway
        .create_checkout(&secret, &checkout_request(vec![Method::Mada]))
        .await
        .unwrap();
    let widget = mada.widget.unwrap();
    assert!(mada.redirect_url.is_none());
    assert_eq!(widget.brands, "MADA");
    assert!(
        widget.script_url.ends_with(
            "/v1/paymentWidgets.js?checkoutId=8ac7a4c87b1c5f72017b1d9bd3d10a1b.uat01-vm-tx04"
        ),
        "{}",
        widget.script_url
    );
    assert_eq!(
        widget.integrity.as_deref(),
        Some("sha384-fakeintegrityhash")
    );

    // Cards and Apple Pay share the card entity (no Apple Pay entity set).
    let card = gateway
        .create_checkout(
            &secret,
            &checkout_request(vec![Method::Card, Method::ApplePay]),
        )
        .await
        .unwrap();
    assert_eq!(card.widget.unwrap().brands, "VISA MASTER APPLEPAY");
    assert_eq!(
        shared.lock().unwrap().checkout_entities,
        vec![MADA_ENTITY.to_owned(), CARD_ENTITY.to_owned()]
    );

    // Mada never rides on another entity's checkout.
    assert!(matches!(
        gateway
            .create_checkout(&secret, &checkout_request(vec![Method::Card, Method::Mada]))
            .await,
        Err(GatewayError::Refused(_))
    ));
    // And with no mada entity configured, it is refused, not sent as a card.
    let card_only =
        json!({ "access_token": TOKEN, "entity_ids": { "card": CARD_ENTITY } }).to_string();
    assert!(matches!(
        gateway
            .create_checkout(&card_only, &checkout_request(vec![Method::Mada]))
            .await,
        Err(GatewayError::Refused(_))
    ));
    assert_eq!(shared.lock().unwrap().checkout_entities.len(), 2);
}

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";

type Headers = Vec<(String, String)>;

fn headers(iv: &str, tag: &str) -> Headers {
    vec![
        ("X-Initialization-Vector".into(), iv.into()),
        ("X-Authentication-Tag".into(), tag.into()),
    ]
}

/// A notification sealed the way HyperPay seals it.
fn seal(plain: &Value, iv: [u8; 12]) -> (String, String) {
    let cipher = Aes256Gcm::new_from_slice(&hex::decode(KEY_HEX).unwrap()).unwrap();
    let mut sealed = cipher
        .encrypt(Nonce::from_slice(&iv), plain.to_string().as_bytes())
        .unwrap();
    let tag = sealed.split_off(sealed.len() - 16);
    (hex::encode_upper(sealed), hex::encode_upper(tag))
}

fn payment_notification() -> Value {
    json!({
        "type": "PAYMENT",
        "payload": transaction(
            "8a829449515d198b01517d5601df5584", "DB", "92.00", "000.000.000", "invoice:42:attempt:1"
        ),
    })
}

// feature: F5
#[tokio::test]
async fn hyperpay_webhook_decrypts() {
    let (_, gateway) = fake().await;
    // HyperPay's published decryption sample.
    let sample = gateway.verify_webhook(
        &headers(
            "000000000000000000000000",
            "CE573FB7A41AB78E743180DC83FF09BD",
        ),
        b"0A3471C72D9BE49A8520F79C66BBD9A12FF9",
        KEY_HEX,
    );
    assert_eq!(
        sample,
        Ok(Vec::new()),
        "the sample decrypts to a payload-less notification"
    );

    let iv = [7u8; 12];
    let (body, tag) = seal(&payment_notification(), iv);
    for body in [body.clone(), json!({ "encryptedBody": body }).to_string()] {
        let events = gateway
            .verify_webhook(&headers(&hex::encode(iv), &tag), body.as_bytes(), KEY_HEX)
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_id,
            "8a829449515d198b01517d5601df5584:000.000.000"
        );
        assert_eq!(events[0].gateway_reference, "invoice:42:attempt:1");
        assert_eq!(
            events[0].status,
            GatewayStatus::Succeeded {
                amount: sar("92.00"),
                fee: None
            }
        );
    }

    // Registrations and test pings carry no payment event.
    let (body, tag) = seal(
        &json!({ "type": "REGISTRATION", "action": "CREATED", "payload": {} }),
        iv,
    );
    assert_eq!(
        gateway.verify_webhook(&headers(&hex::encode(iv), &tag), body.as_bytes(), KEY_HEX),
        Ok(Vec::new())
    );
}

// feature: F5
#[tokio::test]
async fn hyperpay_tampered_webhook_rejected() {
    let (_, gateway) = fake().await;
    let iv = [9u8; 12];
    let iv_hex = hex::encode(iv);
    let (body, tag) = seal(&payment_notification(), iv);

    // One ciphertext byte changed.
    let mut tampered = hex::decode(&body).unwrap();
    tampered[3] ^= 0x01;
    let tampered = hex::encode(tampered);
    // A tag that is not the tag.
    let wrong_tag = "00".repeat(16);
    let other_key = "ff".repeat(32);
    let cases: Vec<(Headers, String, &str)> = vec![
        (headers(&iv_hex, &tag), tampered, KEY_HEX),
        (headers(&iv_hex, &wrong_tag), body.clone(), KEY_HEX),
        (headers(&iv_hex, &tag), body.clone(), &other_key),
        (headers(&"00".repeat(12), &tag), body.clone(), KEY_HEX),
        (
            vec![("X-Authentication-Tag".into(), tag.clone())],
            body.clone(),
            KEY_HEX,
        ),
        (headers(&iv_hex, &tag), "not hex".into(), KEY_HEX),
        (headers(&iv_hex, &tag), body.clone(), ""),
    ];
    for (headers, body, key) in cases {
        assert_eq!(
            gateway.verify_webhook(&headers, body.as_bytes(), key),
            Err(GatewayError::BadSignature)
        );
    }
}

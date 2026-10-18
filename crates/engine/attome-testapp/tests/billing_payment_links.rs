//! F5-T8: a payment link is single-use and expiring: the public page and
//! checkout answer one 404 for a wrong secret, an expired link and a used
//! one; a link is used only when its payment succeeds, which pays its
//! invoice.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_billing::gateway::{
    Checkout, CheckoutRequest, GatewayError, GatewayEvent, GatewayFuture, GatewayStatus, Method,
    PaymentGateway, Payout, SavedCard,
};
use attome_testapp::TestApp;
use axum::http::{Method as HttpMethod, StatusCode};
use chrono::NaiveDate;
use rust_decimal::Decimal;
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

/// A gateway whose checkout always opens, under a reference made from the
/// payment.
struct FakeGateway;

impl PaymentGateway for FakeGateway {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn supported_methods(&self) -> &'static [Method] {
        &[Method::Card, Method::Mada]
    }

    fn create_checkout<'a>(
        &'a self,
        _secret: &'a str,
        request: &'a CheckoutRequest,
    ) -> GatewayFuture<'a, Checkout> {
        Box::pin(async move {
            Ok(Checkout {
                redirect_url: Some(format!("https://pay.example/{}", request.reference)),
                widget: None,
                gateway_reference: format!("fake-{}", request.idempotency_key),
            })
        })
    }

    fn get_status<'a>(&'a self, _: &'a str, _: &'a str) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async { Err(GatewayError::Refused("not used".into())) })
    }

    fn charge_token<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Decimal,
        _: &'a str,
        _: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async { Err(GatewayError::Refused("not used".into())) })
    }

    fn refund<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: Decimal,
        _: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async { Err(GatewayError::Refused("not used".into())) })
    }

    fn list_payouts<'a>(&'a self, _: &'a str, _: NaiveDate) -> GatewayFuture<'a, Vec<Payout>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn saved_card<'a>(&'a self, _: &'a str, _: &'a str) -> GatewayFuture<'a, SavedCard> {
        Box::pin(async { Err(GatewayError::Refused("not used".into())) })
    }

    fn verify_webhook(
        &self,
        _: &[(String, String)],
        _: &[u8],
        _: &str,
    ) -> Result<Vec<GatewayEvent>, GatewayError> {
        Ok(Vec::new())
    }

    fn token_charge_reference(&self, idempotency_key: &str) -> String {
        format!("fake-{idempotency_key}")
    }
}

/// A payment_gateway integration system (its adapter is never reached
/// here; checkout goes through the fake).
async fn gateway_system(app: &TestApp) -> Uuid {
    attome_api::changeset::boot::apply_platform_definition(&app.state, "attome-integration")
        .await
        .unwrap();
    let system = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO integration_system \
            (id, name, kind, base_url, auth_type, service_principal_ref, status, config, created_at) \
         VALUES ($1, 'Fake gateway', 'payment_gateway', 'https://pay.example', 'api_key', \
             $2, 'active', '{\"gateway\": \"fake\"}', NOW())",
    )
    .bind(system)
    .bind(app.admin.id.to_string())
    .execute(app.db())
    .await
    .unwrap();
    system
}

/// An issued invoice of 100 + 15% VAT, and a link for it.
async fn invoice_link(app: &TestApp) -> (Uuid, String) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Link payer') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let invoice: Uuid = sqlx::query_scalar(
        "INSERT INTO invoice (id, status, kind, currency, account_ref, payment_terms_days, \
             series_key, is_active, row_version) \
         VALUES ($1, 'draft', 'invoice', 'SAR', $2, 30, 'TLNK', true, 0) RETURNING id",
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
            HttpMethod::POST,
            &format!("/api/v1/billing/invoices/{invoice}/issue"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, link) = app
        .request(
            HttpMethod::POST,
            "/api/v1/billing/payment-links",
            Some(json!({ "invoice_id": invoice })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{link}");
    let url = link["url"].as_str().unwrap();
    let token = url.rsplit_once("/pay/").unwrap().1.to_owned();
    (invoice, token)
}

async fn page(app: &TestApp, token: &str) -> (StatusCode, Value) {
    app.request_public(
        HttpMethod::GET,
        &format!("/api/v1/pay/{token}"),
        &[("accept-language", "ar-SA,ar;q=0.9")],
        Vec::new(),
    )
    .await
}

async fn checkout(app: &TestApp, token: &str) -> StatusCode {
    app.request_public(
        HttpMethod::POST,
        &format!("/api/v1/pay/{token}/checkout"),
        &[("content-type", "application/json")],
        b"{}".to_vec(),
    )
    .await
    .0
}

// feature: F5
#[test]
fn link_wrong_secret_is_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (_, token) = invoice_link(&app).await;

        let (status, body) = page(&app, &token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["amount"].as_str().unwrap().parse::<f64>().unwrap(),
            115.0
        );
        assert_eq!(body["currency"], "SAR");
        assert_eq!(body["locale"], "ar");
        assert!(body["invoice_number"].as_str().is_some());

        // The same 404 for a wrong secret, an unknown link and a malformed one.
        let (public_id, secret) = token.split_once('.').unwrap();
        let wrong = format!("{public_id}.{}x", &secret[..secret.len() - 1]);
        let unknown = format!("{}.{secret}", Uuid::now_v7());
        for bad in [wrong.as_str(), unknown.as_str(), "not-a-link", public_id] {
            let (status, mut body) = page(&app, bad).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{bad}");
            let (_, mut unknown_body) = page(&app, &unknown).await;
            // Each answer has its own request id; the rest is the same.
            body["request_id"] = Value::Null;
            unknown_body["request_id"] = Value::Null;
            assert_eq!(body, unknown_body, "a miss tells nothing about why");
            assert_eq!(checkout(&app, bad).await, StatusCode::NOT_FOUND);
        }
        // Only the page's calls are public.
        let (status, _) = app
            .request_public(
                HttpMethod::POST,
                "/api/v1/billing/payment-links",
                &[("content-type", "application/json")],
                b"{}".to_vec(),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    });
}

// feature: F5
#[test]
fn link_expired_is_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (invoice, token) = invoice_link(&app).await;
        assert_eq!(page(&app, &token).await.0, StatusCode::OK);
        sqlx::query(
            "UPDATE payment_link SET expires_at = now() - interval '1 minute' \
             WHERE invoice_ref = $1",
        )
        .bind(invoice)
        .execute(app.db())
        .await
        .unwrap();
        assert_eq!(page(&app, &token).await.0, StatusCode::NOT_FOUND);
        assert_eq!(checkout(&app, &token).await, StatusCode::NOT_FOUND);

        // A link lasts 1 to 720 hours, and is for exactly one thing.
        for body in [
            json!({ "invoice_id": invoice, "expires_in_hours": 0 }),
            json!({ "invoice_id": invoice, "expires_in_hours": 721 }),
            json!({}),
            json!({ "invoice_id": invoice, "amount": 10, "currency": "SAR" }),
        ] {
            let (status, _) = app
                .request(
                    HttpMethod::POST,
                    "/api/v1/billing/payment-links",
                    Some(body),
                )
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        }
    });
}

// feature: F5
#[test]
fn link_used_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let system_id = gateway_system(&app).await;
        let system = attome_billing::gateway::system(&app.state, system_id)
            .await
            .unwrap();
        let (invoice, token) = invoice_link(&app).await;
        let link = attome_billing::payment::link::live_link(&app.state, &token)
            .await
            .unwrap();

        // Two checkouts (the payer tried twice): the link stays open.
        let first = attome_billing::payment::link::start_checkout(
            &app.state,
            &link,
            Method::Card,
            &system,
            &FakeGateway,
            "secret",
            "https://crm.example/pay/return",
        )
        .await
        .unwrap();
        assert!(
            first
                .redirect_url
                .unwrap()
                .starts_with("https://pay.example/")
        );
        let second = attome_billing::payment::link::start_checkout(
            &app.state,
            &link,
            Method::Mada,
            &system,
            &FakeGateway,
            "secret",
            "https://crm.example/pay/return",
        )
        .await
        .unwrap();
        assert_eq!(page(&app, &token).await.0, StatusCode::OK);
        // A method the gateway does not take is refused.
        assert!(
            attome_billing::payment::link::start_checkout(
                &app.state,
                &link,
                Method::Tabby,
                &system,
                &FakeGateway,
                "secret",
                "https://crm.example/pay/return",
            )
            .await
            .is_err()
        );

        // The second checkout is paid: the gateway reports it.
        let reference = format!("fake-{}", second.payment_id);
        let stored = attome_billing::gateway::webhook::store_events(
            &app.state,
            system_id,
            &[GatewayEvent {
                event_id: format!("evt-{}", Uuid::now_v7()),
                gateway_reference: reference,
                status: GatewayStatus::Succeeded {
                    amount: "115.00".parse().unwrap(),
                    fee: None,
                },
                card_update: None,
                dispute: None,
            }],
        )
        .await
        .unwrap();
        assert_eq!(stored, 1);
        attome_billing::gateway::webhook::apply_events(&app.state)
            .await
            .unwrap();

        let (status, link_ref): (Option<String>, Option<Uuid>) =
            sqlx::query_as("SELECT status, payment_link_ref FROM customer_payment WHERE id = $1")
                .bind(second.payment_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status.as_deref(), Some("succeeded"));
        assert_eq!(link_ref, Some(link.id));
        let first_status: Option<String> =
            sqlx::query_scalar("SELECT status FROM customer_payment WHERE id = $1")
                .bind(first.payment_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(first_status.as_deref(), Some("pending"));
        let (paid, allocated_to): (Option<String>, Uuid) = sqlx::query_as(
            "SELECT i.payment_status, a.invoice_ref FROM payment_allocation a \
             JOIN invoice i ON i.id = a.invoice_ref WHERE a.payment_ref = $1",
        )
        .bind(second.payment_id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(allocated_to, invoice);
        assert_eq!(paid.as_deref(), Some("paid"));
        let link_status: Option<String> =
            sqlx::query_scalar("SELECT status FROM payment_link WHERE id = $1")
                .bind(link.id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(link_status.as_deref(), Some("used"));

        // Used: the page and checkout are gone.
        assert_eq!(page(&app, &token).await.0, StatusCode::NOT_FOUND);
        assert_eq!(checkout(&app, &token).await, StatusCode::NOT_FOUND);
    });
}

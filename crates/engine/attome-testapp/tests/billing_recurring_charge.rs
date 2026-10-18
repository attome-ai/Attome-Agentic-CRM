//! F5-T9: due invoices are charged to the default saved method; an attempt
//! whose answer was lost is asked again with the same key and charged once;
//! failures retry after 1, 3 and 7 days, email a fresh link each time, and
//! hand the invoice to collections after the last.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use attome_billing::gateway::{
    Checkout, CheckoutRequest, GatewayError, GatewayEvent, GatewayFuture, GatewayStatus,
    GatewaySystem, Method, PaymentGateway, Payout, SavedCard,
};
use attome_billing::payment::recurring::{AdapterSource, charge_due};
use attome_testapp::TestApp;
use attome_types::AppError;
use axum::http::{Method as HttpMethod, StatusCode};
use chrono::{Duration, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde_json::Value;
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

#[derive(Default)]
struct Ledger {
    /// Keys the gateway charged, once each.
    charged: BTreeSet<String>,
    /// Every call, in order.
    calls: Vec<String>,
    /// Lose the answer of the next charge (after charging).
    lose_next: bool,
    /// Decline every charge.
    decline: bool,
}

#[derive(Clone, Default)]
struct FakeGateway(Arc<Mutex<Ledger>>);

impl PaymentGateway for FakeGateway {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn supported_methods(&self) -> &'static [Method] {
        &[Method::Card]
    }

    fn create_checkout<'a>(
        &'a self,
        _: &'a str,
        _: &'a CheckoutRequest,
    ) -> GatewayFuture<'a, Checkout> {
        Box::pin(async { Err(GatewayError::Refused("not used".into())) })
    }

    fn get_status<'a>(&'a self, _: &'a str, _: &'a str) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async { Err(GatewayError::Refused("not used".into())) })
    }

    fn charge_token<'a>(
        &'a self,
        _secret: &'a str,
        _token: &'a str,
        amount: Decimal,
        _currency: &'a str,
        key: &'a str,
    ) -> GatewayFuture<'a, GatewayStatus> {
        Box::pin(async move {
            let mut ledger = self.0.lock().unwrap();
            ledger.calls.push(key.to_owned());
            if ledger.decline {
                return Ok(GatewayStatus::Failed {
                    reason: "insufficient funds".into(),
                });
            }
            // The same key is never charged twice.
            ledger.charged.insert(key.to_owned());
            if std::mem::take(&mut ledger.lose_next) {
                return Err(GatewayError::Unavailable("timed out".into()));
            }
            Ok(GatewayStatus::Succeeded { amount, fee: None })
        })
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

    fn token_charge_reference(&self, key: &str) -> String {
        format!("fake:{key}")
    }
}

impl AdapterSource for FakeGateway {
    fn adapter(&self, _: &GatewaySystem) -> Result<Box<dyn PaymentGateway>, AppError> {
        Ok(Box::new(self.clone()))
    }
}

/// A gateway system with a credential, and an account with a contact, a
/// default saved card and an issued invoice of 115 due yesterday.
async fn setup(app: &TestApp) -> (Uuid, Uuid) {
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
    let ring = app
        .state
        .base
        .secrets
        .load()
        .integration_credential_key
        .clone();
    let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
    let credential = attome_integration::credential::store(&mut tx, &ring, system, "sk_fake")
        .await
        .unwrap();
    sqlx::query("UPDATE integration_system SET credential_ref = $2 WHERE id = $1")
        .bind(system)
        .bind(credential.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    attome_db::tx::commit(tx).await.unwrap();

    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Card holder') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let contact: Uuid = sqlx::query_scalar(
        "INSERT INTO contact (id, full_name, email, is_active, row_version) \
         VALUES ($1, 'Payer', 'payer@example.com', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO saved_payment_method (id, account_ref, gateway_system_ref, token, brand, \
             last4, is_default, is_active, row_version) \
         VALUES ($1, $2, $3, 'tok_123', 'visa', '4242', true, true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .bind(system.to_string())
    .execute(app.db())
    .await
    .unwrap();
    let invoice: Uuid = sqlx::query_scalar(
        "INSERT INTO invoice (id, status, kind, currency, account_ref, contact_ref, \
             payment_terms_days, series_key, is_active, row_version) \
         VALUES ($1, 'draft', 'invoice', 'SAR', $2, $3, 0, 'TREC', true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .bind(contact)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO invoice_line (id, invoice_ref, description, quantity, unit_price, \
             vat_category, is_active, row_version) \
         VALUES ($1, $2, 'Plan', 1, 100, 'standard', true, 0)",
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
    sqlx::query("UPDATE invoice SET due_date = CURRENT_DATE - 1 WHERE id = $1")
        .bind(invoice)
        .execute(app.db())
        .await
        .unwrap();
    (system, invoice)
}

type AttemptRow = (Option<String>, Option<i32>, Option<NaiveDate>);

async fn attempts(app: &TestApp, invoice: Uuid) -> Vec<AttemptRow> {
    sqlx::query_as(
        "SELECT status, charge_attempt::int, next_retry_on::date FROM customer_payment \
         WHERE charged_invoice_ref = $1 ORDER BY charge_attempt",
    )
    .bind(invoice)
    .fetch_all(app.db())
    .await
    .unwrap()
}

async fn payment_status(app: &TestApp, invoice: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT payment_status FROM invoice WHERE id = $1")
        .bind(invoice)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: F5
#[test]
fn charge_retry_same_attempt_charges_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (system, invoice) = setup(&app).await;
        let gateway = FakeGateway::default();
        let today = Utc::now().date_naive();
        let key = format!("invoice:{invoice}:attempt:1");

        // The gateway charges, but its answer is lost: the attempt stays
        // pending.
        gateway.0.lock().unwrap().lose_next = true;
        charge_due(&app.state, today, &gateway).await.unwrap();
        let rows = attempts(&app, invoice).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0.as_deref(), Some("pending"));

        // The next run asks again with the same key: no second charge.
        charge_due(&app.state, today, &gateway).await.unwrap();
        let rows = attempts(&app, invoice).await;
        assert_eq!(rows.len(), 1, "still one attempt");
        assert_eq!(rows[0].0.as_deref(), Some("succeeded"));
        assert_eq!(payment_status(&app, invoice).await.as_deref(), Some("paid"));
        {
            let ledger = gateway.0.lock().unwrap();
            assert_eq!(ledger.charged.len(), 1, "charged once");
            assert!(ledger.calls.iter().all(|c| *c == key), "{:?}", ledger.calls);
        }

        // Paid: nothing more to charge.
        charge_due(&app.state, today, &gateway).await.unwrap();

        // The card updater's event keeps the saved card current.
        attome_billing::gateway::webhook::store_events(
            &app.state,
            system,
            &[GatewayEvent {
                event_id: format!("tok_123:updated:{}", Uuid::now_v7()),
                gateway_reference: "tok_123".into(),
                status: GatewayStatus::Pending,
                card_update: Some(attome_billing::gateway::CardUpdate {
                    token: "tok_123".into(),
                    brand: Some("visa".into()),
                    last4: Some("1881".into()),
                    expiry_month: Some(9),
                    expiry_year: Some(2031),
                }),
            }],
        )
        .await
        .unwrap();
        attome_billing::gateway::webhook::apply_events(&app.state)
            .await
            .unwrap();
        let (last4, year): (Option<String>, Option<i32>) = sqlx::query_as(
            "SELECT last4, expiry_year::int FROM saved_payment_method \
             WHERE token = 'tok_123' AND gateway_system_ref = $1",
        )
        .bind(system.to_string())
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!((last4.as_deref(), year), (Some("1881"), Some(2031)));
        assert!(
            gateway
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|c| **c == key)
                .count()
                == 2,
            "a paid invoice is not charged again"
        );
    });
}

// feature: F5
#[test]
fn charge_last_failure_hands_to_collections() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (_, invoice) = setup(&app).await;
        let gateway = FakeGateway::default();
        gateway.0.lock().unwrap().decline = true;
        let today = Utc::now().date_naive();

        // Attempt 1 fails: retry tomorrow. A second run today waits.
        charge_due(&app.state, today, &gateway).await.unwrap();
        charge_due(&app.state, today, &gateway).await.unwrap();
        let rows = attempts(&app, invoice).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0],
            (
                Some("failed".into()),
                Some(1),
                Some(today + Duration::days(1))
            )
        );

        // Attempts 2, 3 and 4 on their days (1, then 3, then 7 days later).
        let mut day = today + Duration::days(1);
        for (attempt, wait) in [(2, Some(3)), (3, Some(7)), (4, None)] {
            charge_due(&app.state, day, &gateway).await.unwrap();
            let rows = attempts(&app, invoice).await;
            let last = rows.last().unwrap();
            assert_eq!(last.1, Some(attempt));
            assert_eq!(last.0.as_deref(), Some("failed"));
            assert_eq!(last.2, wait.map(|w| day + Duration::days(w)));
            if let Some(w) = wait {
                day += Duration::days(w);
            }
        }
        // After the last: no more attempts, and collections is told once.
        charge_due(&app.state, day + Duration::days(30), &gateway)
            .await
            .unwrap();
        assert_eq!(attempts(&app, invoice).await.len(), 4);
        assert_eq!(gateway.0.lock().unwrap().calls.len(), 4);
        let handoffs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM entity_change_event \
             WHERE record_id = $1 AND event_name = 'billing.invoice.collections_handoff'",
        )
        .bind(invoice)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(handoffs, 1);
        // Each failure sent the payer a fresh link.
        let links: i64 =
            sqlx::query_scalar("SELECT count(*) FROM payment_link WHERE invoice_ref = $1")
                .bind(invoice)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(links, 4);
        assert_ne!(payment_status(&app, invoice).await.as_deref(), Some("paid"));
    });
}

//! F3-T15: the subscription money path end to end: a subscription with a
//! flat and a per-unit line, a mid-period quantity amendment, charges
//! planned and a billing run asking one invoice per account and period with
//! the proration in it, a cancellation at term end giving one churn event;
//! the billing routes hidden without the licence; a price amendment refused
//! without `subscription.amend_price`.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;

use attome_billing::billing_run::{execute_run, generate_charges, preview_run, start_run};
use attome_billing::handoff;
use attome_billing::subscription::schedule::{Alignment, Cadence, Timing};
use attome_billing::subscription::segments::ChangeKind;
use attome_billing::subscription::service::{
    Amendment, CreateSubscription, LineChange, NewLine, Source, amend, cancel, create,
};
use attome_testapp::{TestApp, seed_user};
use attome_types::AppError;
use axum::http::{Method, StatusCode};
use chrono::NaiveDate;
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

fn d(y: i32, m: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, day).unwrap()
}

/// A yearly-term monthly subscription from 1 Jan 2027: a flat support fee
/// of 500 and 10 seats at 100; returns (account, subscription, seats line).
async fn subscribe(app: &TestApp) -> (Uuid, Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Money Path Co') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let mut products = Vec::new();
    for name in ["Support", "Seat"] {
        let product: Uuid =
            sqlx::query_scalar("INSERT INTO product (name) VALUES ($1) RETURNING id")
                .bind(name)
                .fetch_one(app.db())
                .await
                .unwrap();
        products.push(product);
    }
    let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
        .await
        .unwrap();
    let sub = create(
        &app.state,
        &ctx,
        CreateSubscription {
            name: "Money path".into(),
            account_ref: account,
            currency: "SAR".into(),
            start_date: d(2027, 1, 1),
            end_date: Some(d(2028, 1, 1)),
            term_months: Some(12),
            frequency: Cadence::Monthly,
            timing: Timing::Advance,
            alignment: Alignment::Anniversary,
            source: Source::ByHand(vec![
                NewLine {
                    product_ref: products[0],
                    quantity: Decimal::ONE,
                    unit_price: Decimal::from(500),
                    charge_model: Some("flat".into()),
                },
                NewLine {
                    product_ref: products[1],
                    quantity: Decimal::from(10),
                    unit_price: Decimal::from(100),
                    charge_model: Some("per_unit".into()),
                },
            ]),
        },
    )
    .await
    .unwrap();
    let seats: Uuid = sqlx::query_scalar(
        "SELECT l.id FROM subscription_line l JOIN product p ON p.id = l.product_ref \
          WHERE l.subscription_ref = $1 AND p.name = 'Seat'",
    )
    .bind(sub)
    .fetch_one(app.db())
    .await
    .unwrap();
    (account, sub, seats)
}

async fn churned(app: &TestApp, subscription: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM entity_change_event \
          WHERE entity_logicalname = 'subscription' AND record_id = $1 AND event_name = $2",
    )
    .bind(subscription)
    .bind(handoff::CHURNED)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: F3
#[test]
fn money_path_create_amend_run_cancel() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (account, sub, seats) = subscribe(&app).await;
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        // Twenty seats from 16 January: half of January prorated.
        amend(
            &app.state,
            &ctx,
            sub,
            Amendment {
                effective: d(2027, 1, 16),
                changes: vec![LineChange {
                    line_id: seats,
                    quantity: Decimal::from(20),
                    unit_price: Decimal::from(100),
                    kind: ChangeKind::Upgrade,
                }],
            },
        )
        .await
        .unwrap();
        let prorations: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM subscription_charge \
              WHERE subscription_ref = $1 AND kind = 'proration' AND amount > 0",
        )
        .bind(sub)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(prorations, 1, "the rest of January is prorated");

        generate_charges(&app.state, d(2027, 1, 20), 0)
            .await
            .unwrap();
        let preview = preview_run(app.db(), d(2027, 1, 20)).await.unwrap();
        let mine: Vec<_> = preview
            .iter()
            .filter(|g| g.account_ref == account)
            .collect();
        assert_eq!(mine.len(), 1, "one invoice for the account and January");
        assert!(
            mine[0].charges >= 3,
            "two recurring lines and the proration"
        );

        let run = start_run(&app.state, d(2027, 1, 20), app.admin.id)
            .await
            .unwrap();
        execute_run(&app.state, run).await.unwrap();
        let requests: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM billing_invoice_request \
              WHERE source_kind = 'subscription' AND account_ref = $1",
        )
        .bind(account)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(
            requests, 1,
            "one invoice request for the account and period"
        );

        let ends = cancel(&app.state, &ctx, sub, true, d(2027, 3, 1), "budget")
            .await
            .unwrap();
        assert_eq!(ends, d(2028, 1, 1), "at the end of the term");
        for _ in 0..20 {
            let run = handoff::run(app.db()).await.unwrap();
            if run.churned == 0 && run.revenue_events == 0 {
                break;
            }
        }
        assert_eq!(churned(&app, sub).await, 1, "one churn event");
    });
}

// feature: F3
// negative: GET /api/v1/billing/subscriptions/{id}
#[test]
fn unlicensed_billing_routes_are_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let before = app.state.modules.load_full();
        app.state
            .modules
            .store(Arc::new(attome_modules::ModuleSet::from_bits([0u64; 4])));
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/billing/subscriptions/{}", Uuid::now_v7()),
                None,
            )
            .await;
        app.state.modules.store(before);
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    });
}

// feature: F3
// negative: POST /api/v1/billing/subscriptions/{id}/amendments
#[test]
fn amend_price_needs_privilege() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (_, sub, seats) = subscribe(&app).await;
        let clerk = seed_user(app.db(), "clerk").await;
        for key in ["subscription.read", "subscription.update"] {
            attome_security::db::ensure_privilege(
                app.db(),
                key,
                key,
                "test grant",
                attome_core::changeset::Layer::Project,
            )
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, \
                     created_at) \
                 SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
            )
            .bind(clerk.id)
            .bind(key)
            .execute(app.db())
            .await
            .unwrap();
        }
        let ctx = attome_security::resolve_uncached(app.db(), clerk.id)
            .await
            .unwrap();
        let refused = amend(
            &app.state,
            &ctx,
            sub,
            Amendment {
                effective: d(2027, 2, 1),
                changes: vec![LineChange {
                    line_id: seats,
                    quantity: Decimal::from(10),
                    unit_price: Decimal::from(80),
                    kind: ChangeKind::PriceChange,
                }],
            },
        )
        .await;
        assert!(matches!(refused, Err(AppError::Forbidden)), "{refused:?}");
    });
}

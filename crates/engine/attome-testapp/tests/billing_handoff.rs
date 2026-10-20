//! F3-T11: cancelling a subscription hands one churn event to O3 after
//! commit, however often the hand-off runs, and each change hands its
//! segments to revenue.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_billing::handoff;
use attome_billing::subscription::schedule::{Alignment, Cadence, Timing};
use attome_billing::subscription::service::{CreateSubscription, NewLine, Source, cancel, create};
use attome_testapp::TestApp;
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

async fn events(app: &TestApp, subscription: Uuid, name: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM entity_change_event \
          WHERE entity_logicalname = 'subscription' AND record_id = $1 AND event_name = $2",
    )
    .bind(subscription)
    .bind(name)
    .fetch_one(app.db())
    .await
    .unwrap()
}

/// Runs the hand-offs until the feed has nothing more for them.
async fn drain(app: &TestApp) {
    for _ in 0..20 {
        let run = handoff::run(app.db()).await.unwrap();
        if run.churned == 0 && run.revenue_events == 0 {
            break;
        }
    }
}

// feature: F3
#[test]
fn cancel_emits_churn_event_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Churny') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        let product: Uuid =
            sqlx::query_scalar("INSERT INTO product (name) VALUES ('Seat') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let start = NaiveDate::from_ymd_opt(2027, 1, 1).unwrap();
        let sub = create(
            &app.state,
            &ctx,
            CreateSubscription {
                name: "To churn".into(),
                account_ref: account,
                currency: "SAR".into(),
                start_date: start,
                end_date: Some(NaiveDate::from_ymd_opt(2028, 1, 1).unwrap()),
                term_months: Some(12),
                frequency: Cadence::Monthly,
                timing: Timing::Advance,
                alignment: Alignment::Anniversary,
                source: Source::ByHand(vec![NewLine {
                    product_ref: product,
                    quantity: Decimal::from(5),
                    unit_price: Decimal::from(50),
                    charge_model: None,
                }]),
            },
        )
        .await
        .unwrap();
        drain(&app).await;
        assert_eq!(events(&app, sub, handoff::CHURNED).await, 0);
        assert!(events(&app, sub, handoff::REVENUE_SEGMENT).await >= 1);

        cancel(
            &app.state,
            &ctx,
            sub,
            false,
            NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
            "budget",
        )
        .await
        .unwrap();
        drain(&app).await;
        drain(&app).await;
        assert_eq!(events(&app, sub, handoff::CHURNED).await, 1);
    });
}

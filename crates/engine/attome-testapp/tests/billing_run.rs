//! F3-T8: charges are planned once, a billing run requests one invoice per
//! account, period and currency however often it runs, a run stopped half
//! way carries on without asking twice, and a preview writes nothing.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_billing::billing_run::{execute_run, generate_charges, preview_run, start_run};
use attome_billing::subscription::schedule::{Alignment, Cadence, Timing};
use attome_billing::subscription::service::{CreateSubscription, NewLine, Source, create};
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

fn d(y: i32, m: u32, day: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(y, m, day).unwrap()
}

/// A monthly subscription of 10 seats at 100 from 1 Jan 2027, with its
/// January and February charges planned (today 10 Feb).
async fn planned(app: &TestApp) -> Uuid {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Billed Co') RETURNING id")
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
    let sub = create(
        &app.state,
        &ctx,
        CreateSubscription {
            name: "Seats".into(),
            account_ref: account,
            currency: "SAR".into(),
            start_date: d(2027, 1, 1),
            end_date: Some(d(2028, 1, 1)),
            term_months: Some(12),
            frequency: Cadence::Monthly,
            timing: Timing::Advance,
            alignment: Alignment::Anniversary,
            source: Source::ByHand(vec![NewLine {
                product_ref: product,
                quantity: Decimal::from(10),
                unit_price: Decimal::from(100),
                charge_model: None,
            }]),
        },
    )
    .await
    .unwrap();
    let first = generate_charges(&app.state, d(2027, 2, 10), 0)
        .await
        .unwrap();
    let again = generate_charges(&app.state, d(2027, 2, 10), 0)
        .await
        .unwrap();
    assert_eq!(first.charges, 2, "January and February");
    assert_eq!(again.charges, 0, "a second pass plans nothing new");
    sub
}

async fn requests(app: &TestApp) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM billing_invoice_request WHERE source_kind = 'subscription'",
    )
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn statuses(app: &TestApp, sub: Uuid) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT status FROM subscription_charge WHERE subscription_ref = $1 ORDER BY period_start",
    )
    .bind(sub)
    .fetch_all(app.db())
    .await
    .unwrap()
}

// feature: F3
#[test]
fn preview_writes_nothing() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let sub = planned(&app).await;
        let groups = preview_run(app.db(), d(2027, 2, 10)).await.unwrap();
        assert_eq!(groups.len(), 2, "{groups:?}");
        assert!(groups.iter().all(|g| (g.total - 1000.0).abs() < 0.01));
        assert_eq!(requests(&app).await, 0);
        assert_eq!(statuses(&app, sub).await, vec!["planned", "planned"]);
    });
}

// feature: F3
#[test]
fn run_twice_requests_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let sub = planned(&app).await;
        let run = start_run(&app.state, d(2027, 2, 10), app.admin.id)
            .await
            .unwrap();
        execute_run(&app.state, run).await.unwrap();
        execute_run(&app.state, run).await.unwrap();
        let second = start_run(&app.state, d(2027, 2, 10), app.admin.id)
            .await
            .unwrap();
        execute_run(&app.state, second).await.unwrap();
        assert_eq!(requests(&app).await, 2, "one per period");
        assert_eq!(statuses(&app, sub).await, vec!["requested", "requested"]);
    });
}

// feature: F3
#[test]
fn resumes_after_partial_batch() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let sub = planned(&app).await;
        let run = start_run(&app.state, d(2027, 2, 10), app.admin.id)
            .await
            .unwrap();
        execute_run(&app.state, run).await.unwrap();
        // A crash after February's request was stored, before its charge
        // was marked: the charge is still planned and the run not done.
        sqlx::query(
            "UPDATE subscription_charge SET status = 'planned' \
              WHERE subscription_ref = $1 AND period_start = $2",
        )
        .bind(sub)
        .bind(d(2027, 2, 1))
        .execute(app.db())
        .await
        .unwrap();
        sqlx::query("UPDATE billing_run SET status = 'running' WHERE id = $1")
            .bind(run)
            .execute(app.db())
            .await
            .unwrap();
        execute_run(&app.state, run).await.unwrap();
        assert_eq!(requests(&app).await, 2, "the stored request is reused");
        assert_eq!(statuses(&app, sub).await, vec!["requested", "requested"]);
        let status: String = sqlx::query_scalar("SELECT status FROM billing_run WHERE id = $1")
            .bind(run)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(status, "done");
    });
}

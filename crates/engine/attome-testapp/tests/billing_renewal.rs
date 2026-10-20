//! F3-T9: an auto subscription renews exactly once however often the sweep
//! runs, a renewal-quote subscription gets one renewal opportunity, and a
//! trial converts on its end date.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_billing::renewal;
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

/// A one-year subscription ending 31 Dec 2027, in `mode`.
async fn subscription(app: &TestApp, mode: &str) -> Uuid {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Renewer') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let product: Uuid =
        sqlx::query_scalar("INSERT INTO product (name) VALUES ('Licence') RETURNING id")
            .fetch_one(app.db())
            .await
            .unwrap();
    let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
        .await
        .unwrap();
    let id = create(
        &app.state,
        &ctx,
        CreateSubscription {
            name: format!("Renew {mode}"),
            account_ref: account,
            currency: "SAR".into(),
            start_date: d(2027, 1, 1),
            end_date: Some(d(2027, 12, 31)),
            term_months: Some(12),
            frequency: Cadence::Monthly,
            timing: Timing::Advance,
            alignment: Alignment::Anniversary,
            source: Source::ByHand(vec![NewLine {
                product_ref: product,
                quantity: Decimal::from(3),
                unit_price: Decimal::from(200),
                charge_model: None,
            }]),
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE subscription SET renewal_mode = $2 WHERE id = $1")
        .bind(id)
        .bind(mode)
        .execute(app.db())
        .await
        .unwrap();
    id
}

// feature: F3
#[test]
fn auto_renew_extends_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let sub = subscription(&app, "auto").await;
        let today = d(2027, 12, 1);
        let first = renewal::run(&app.state, today).await.unwrap();
        let second = renewal::run(&app.state, today).await.unwrap();
        assert_eq!(first.renewed, 1);
        assert_eq!(second.renewed, 0, "the same day renews nothing twice");
        let end: NaiveDate = sqlx::query_scalar("SELECT end_date FROM subscription WHERE id = $1")
            .bind(sub)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(end, d(2028, 12, 31));
        let renewals: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM subscription_segment s JOIN subscription_line l ON l.id = s.line_ref \
              WHERE l.subscription_ref = $1 AND s.change_kind = 'renewal'",
        )
        .bind(sub)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(renewals, 1);
    });
}

// feature: F3
#[test]
fn renewal_quote_mode_creates_opportunity() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let sub = subscription(&app, "renewal_quote").await;
        let today = d(2027, 11, 15);
        renewal::run(&app.state, today).await.unwrap();
        renewal::run(&app.state, today).await.unwrap();
        let opportunities: Vec<(String, Option<f64>)> = sqlx::query_as(
            "SELECT name, amount::float8 FROM opportunity WHERE name = 'Renewal: Renew renewal_quote'",
        )
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(opportunities.len(), 1, "{opportunities:?}");
        // 3 licences at 200 a month for 12 months.
        assert_eq!(opportunities[0].1, Some(7200.0));
        let end: NaiveDate = sqlx::query_scalar("SELECT end_date FROM subscription WHERE id = $1")
            .bind(sub)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(end, d(2027, 12, 31), "the term itself is not extended");
    });
}

// feature: F3
#[test]
fn trial_converts_on_end_date() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let sub = subscription(&app, "manual").await;
        sqlx::query(
            "UPDATE subscription SET status = 'trial', trial_end_date = $2, owner_ref = $3 WHERE id = $1",
        )
        .bind(sub)
        .bind(d(2027, 1, 15))
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
        // Three days before: a reminder, once.
        let early = renewal::run(&app.state, d(2027, 1, 12)).await.unwrap();
        let again = renewal::run(&app.state, d(2027, 1, 13)).await.unwrap();
        assert_eq!((early.reminders, again.reminders), (1, 0));
        // On the end date: active.
        let run = renewal::run(&app.state, d(2027, 1, 15)).await.unwrap();
        assert_eq!(run.trials_converted, 1);
        let status: String = sqlx::query_scalar("SELECT status FROM subscription WHERE id = $1")
            .bind(sub)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(status, "active");
    });
}

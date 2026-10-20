//! F3-T5: the subscription service. Creating by hand opens one segment per
//! line, a mid-term amendment closes and opens segments and plans a
//! proration, an invoiced amendment cannot be reversed, and a second change
//! while the subscription's lock is held answers 409.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "test helpers: a failed setup step should panic with its message; one test holds a transaction open to hold the lock"
)]

use attome_billing::subscription::schedule::{Alignment, Cadence, Timing};
use attome_billing::subscription::segments::ChangeKind;
use attome_billing::subscription::service::{
    Amendment, CreateSubscription, LineChange, NewLine, Source, amend, create, reverse_amendment,
};
use attome_testapp::TestApp;
use attome_types::AppError;
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

/// A yearly-term monthly subscription of 10 seats at 100, from 1 Jan 2027.
async fn subscribe(app: &TestApp) -> (Uuid, Uuid) {
    let account: Uuid =
        sqlx::query_scalar("INSERT INTO account (name) VALUES ('Seats Co') RETURNING id")
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
    let id = create(
        &app.state,
        &ctx,
        CreateSubscription {
            name: "Seats 2027".into(),
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
    let line: Uuid =
        sqlx::query_scalar("SELECT id FROM subscription_line WHERE subscription_ref = $1")
            .bind(id)
            .fetch_one(app.db())
            .await
            .unwrap();
    (id, line)
}

/// Doubles the seats from 16 Jan 2027, halfway through January.
fn upgrade(line: Uuid) -> Amendment {
    Amendment {
        effective: d(2027, 1, 16),
        changes: vec![LineChange {
            line_id: line,
            quantity: Decimal::from(20),
            unit_price: Decimal::from(100),
            kind: ChangeKind::Upgrade,
        }],
    }
}

async fn segments(app: &TestApp, line: Uuid) -> Vec<(NaiveDate, Option<NaiveDate>, String)> {
    sqlx::query_as(
        "SELECT valid_from, valid_to, change_kind FROM subscription_segment \
          WHERE line_ref = $1 ORDER BY valid_from, created_at",
    )
    .bind(line)
    .fetch_all(app.db())
    .await
    .unwrap()
}

// feature: F3
#[test]
fn create_by_hand_opens_segments() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (_, line) = subscribe(&app).await;
        assert_eq!(
            segments(&app, line).await,
            vec![(d(2027, 1, 1), Some(d(2028, 1, 1)), "new".to_owned())]
        );
    });
}

// feature: F3
#[test]
fn amend_mid_term_prorates() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (sub, line) = subscribe(&app).await;
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let result = amend(&app.state, &ctx, sub, upgrade(line)).await.unwrap();
        assert_eq!(result.segments_opened, 1);
        assert_eq!(result.charges, 1);
        assert_eq!(
            segments(&app, line).await,
            vec![
                (d(2027, 1, 1), Some(d(2027, 1, 16)), "new".to_owned()),
                (d(2027, 1, 16), Some(d(2028, 1, 1)), "upgrade".to_owned()),
            ]
        );
        // 16 of January's 31 days left, 10 more seats at 100.
        let (amount, kind): (f64, String) = sqlx::query_as(
            "SELECT amount::float8, kind FROM subscription_charge WHERE subscription_ref = $1",
        )
        .bind(sub)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(kind, "proration");
        assert!((amount - 516.13).abs() < 0.01, "{amount}");
    });
}

// feature: F3
#[test]
fn reverse_after_invoice_is_conflict() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (sub, line) = subscribe(&app).await;
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        let result = amend(&app.state, &ctx, sub, upgrade(line)).await.unwrap();
        sqlx::query("UPDATE subscription_segment SET invoiced = true WHERE amendment_id = $1")
            .bind(result.amendment_id.to_string())
            .execute(app.db())
            .await
            .unwrap();
        let err = reverse_amendment(&app.state, &ctx, sub, result.amendment_id)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
    });
}

// feature: F3
#[test]
fn concurrent_amend_second_gets_conflict() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (sub, line) = subscribe(&app).await;
        let ctx = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();
        // A first change holds the subscription's lock.
        let mut first = app.db().begin().await.unwrap();
        let held: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(attome_billing::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-billing/subscription:{sub}"))
            .fetch_one(&mut *first)
            .await
            .unwrap();
        assert!(held);
        let err = amend(&app.state, &ctx, sub, upgrade(line))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
        first.rollback().await.unwrap();
        // Once it is done, the change goes through.
        amend(&app.state, &ctx, sub, upgrade(line)).await.unwrap();
    });
}

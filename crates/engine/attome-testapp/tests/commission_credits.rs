//! F10-T3: a won deal replayed credits once, an issued invoice credits the
//! account's owner once, and a credit note reverses that credit with one
//! negative credit.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_commission::credit::{credit_business_source, credit_won_deal};
use attome_testapp::TestApp;
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 8] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
    "commission",
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

/// A seller on a published plan measuring `measure`, and an open period
/// around today.
async fn seller_on_plan(app: &TestApp, measure: &str) -> Uuid {
    let seller = attome_testapp::seed_user(app.db(), &format!("seller-{measure}"))
        .await
        .id;
    let plan: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_plan (name, status) VALUES ('Sales 2026', 'published') RETURNING id",
    )
    .fetch_one(app.db())
    .await
    .unwrap();
    let version: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_plan_version (plan_ref, version, published_at) \
         VALUES ($1, 1, CURRENT_DATE - 30) RETURNING id",
    )
    .bind(plan)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO comp_component (plan_version_ref, kind, measure) \
         VALUES ($1, 'new_business', $2)",
    )
    .bind(version)
    .bind(measure)
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query("INSERT INTO plan_participant (plan_version_ref, user_ref) VALUES ($1, $2)")
        .bind(version)
        .bind(seller)
        .execute(app.db())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO comp_period (fiscal_period, starts_on, ends_on, status) \
         SELECT 'FY', CURRENT_DATE - 365, CURRENT_DATE + 365, 'open' \
          WHERE NOT EXISTS (SELECT 1 FROM comp_period)",
    )
    .execute(app.db())
    .await
    .unwrap();
    seller
}

async fn credits(app: &TestApp, seller: Uuid) -> Vec<(String, f64, Option<Uuid>)> {
    sqlx::query_as(
        "SELECT source_kind, amount::float8, reverses_credit_ref FROM comp_credit \
          WHERE owner_ref = $1 ORDER BY created_at, id",
    )
    .bind(seller)
    .fetch_all(app.db())
    .await
    .unwrap()
}

// feature: F10
#[test]
fn replayed_won_event_credits_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let seller = seller_on_plan(&app, "split_amount").await;
        let account: Uuid =
            sqlx::query_scalar("INSERT INTO account (name) VALUES ('Won Co') RETURNING id")
                .fetch_one(app.db())
                .await
                .unwrap();
        let deal: Uuid = sqlx::query_scalar(
            "INSERT INTO opportunity (name, account_ref, stage, amount, currency, close_date, \
                 owner_ref) \
             VALUES ('Big deal', $1, 'closed_won', 5000, 'SAR', CURRENT_DATE, $2) RETURNING id",
        )
        .bind(account)
        .bind(seller)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(credit_won_deal(&app.state, deal).await.unwrap(), 1);
        assert_eq!(credit_won_deal(&app.state, deal).await.unwrap(), 0);
        let written = credits(&app, seller).await;
        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(written[0].0, "split");
        assert!((written[0].1 - 5000.0).abs() < 0.01);
    });
}

// feature: F10
#[test]
fn credit_note_creates_negative_credit() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let seller = seller_on_plan(&app, "invoice_amount").await;
        let account: Uuid = sqlx::query_scalar(
            "INSERT INTO account (name, owner_ref) VALUES ('Invoiced Co', $1) RETURNING id",
        )
        .bind(seller)
        .fetch_one(app.db())
        .await
        .unwrap();
        let invoice: Uuid = sqlx::query_scalar(
            "INSERT INTO invoice (kind, status, account_ref, net_total, currency, issued_date) \
             VALUES ('invoice', 'issued', $1, 1000, 'SAR', CURRENT_DATE) RETURNING id",
        )
        .bind(account)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(
            credit_business_source(&app.state, "invoice", invoice)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            credit_business_source(&app.state, "invoice", invoice)
                .await
                .unwrap(),
            0
        );

        let note: Uuid = sqlx::query_scalar(
            "INSERT INTO invoice (kind, status, account_ref, original_invoice_ref, net_total, \
                 currency, issued_date) \
             VALUES ('credit_note', 'issued', $1, $2, 300, 'SAR', CURRENT_DATE) RETURNING id",
        )
        .bind(account)
        .bind(invoice)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(
            credit_business_source(&app.state, "invoice", note)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            credit_business_source(&app.state, "invoice", note)
                .await
                .unwrap(),
            0
        );

        let written = credits(&app, seller).await;
        assert_eq!(written.len(), 2, "{written:?}");
        assert_eq!(written[0].0, "invoice");
        assert_eq!(written[1].0, "credit_note");
        assert!((written[1].1 + 300.0).abs() < 0.01, "{written:?}");
        assert!(written[1].2.is_some(), "it names the credit it reverses");
    });
}

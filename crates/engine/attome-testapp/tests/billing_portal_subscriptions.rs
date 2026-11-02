//! F3-T13, read part: the portal's subscriptions list holds only the
//! account's own subscriptions, with the lines in force and the charges
//! still to come.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_billing::subscription::portal::for_account;
use attome_testapp::TestApp;
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
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn account(app: &TestApp, name: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO account (name) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(app.db())
        .await
        .unwrap()
}

/// A running subscription of `account` with one line in force, one ended
/// line and one planned charge next month.
async fn subscription(app: &TestApp, account: Uuid) -> Uuid {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO subscription (id, name, account_ref, currency, status, start_date, \
             is_active, row_version) \
         VALUES ($1, 'Support plan', $2, 'SAR', 'active', now() - interval '30 days', true, 0) \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap();
    for (quantity, ended) in [("5", false), ("2", true)] {
        sqlx::query(
            "INSERT INTO subscription_line (id, subscription_ref, quantity, unit_price, \
                 start_date, end_date, is_active, row_version) \
             VALUES ($1, $2, $3::numeric, 100, now() - interval '30 days', \
                     CASE WHEN $4 THEN now() - interval '1 day' END, true, 0)",
        )
        .bind(Uuid::now_v7())
        .bind(id)
        .bind(quantity)
        .bind(ended)
        .execute(app.db())
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO subscription_charge (id, subscription_ref, period_start, period_end, \
             amount, currency, kind, status, is_active, row_version) \
         VALUES ($1, $2, now() + interval '1 day', now() + interval '31 days', 500, 'SAR', \
                 'recurring', 'planned', true, 0)",
    )
    .bind(Uuid::now_v7())
    .bind(id)
    .execute(app.db())
    .await
    .unwrap();
    id
}

// feature: F3
// negative: GET /{keyword}/api/v1/billing/subscriptions
#[test]
fn portal_lists_only_own_account() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let mine = account(&app, "Subscriber").await;
        let other = account(&app, "Someone else").await;
        let id = subscription(&app, mine).await;

        let listed = for_account(&app.state, mine).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].lines.len(), 1, "only the line in force");
        assert_eq!(listed[0].coming_charges.len(), 1);

        assert!(for_account(&app.state, other).await.unwrap().is_empty());
    });
}

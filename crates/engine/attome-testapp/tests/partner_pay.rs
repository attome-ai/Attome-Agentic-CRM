//! F10-T12: a won deal naming a partner credits the partner's own
//! participation, once, with no owner; the partner reads its statement and
//! another partner reads nothing.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_commission::credit::credit_won_deal;
use attome_commission::partner_pay::{invalid_participant, partner_statement};
use attome_testapp::TestApp;
use attome_types::{AppError, OnePageQuery};
use serde_json::Value;
use uuid::Uuid;

const PACKS: [&str; 9] = [
    "crm",
    "sales",
    "finance",
    "regions",
    "vendor-supplier",
    "contract-management",
    "billing",
    "commission",
    "partner",
];
const PAGE: OnePageQuery = OnePageQuery {
    page: None,
    page_size: None,
};

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

async fn account(app: &TestApp) -> Uuid {
    sqlx::query_scalar("INSERT INTO account (name, is_partner) VALUES ($1, true) RETURNING id")
        .bind(Uuid::now_v7().to_string())
        .fetch_one(app.db())
        .await
        .unwrap()
}

/// A partner on a published plan with a referral component.
async fn participation(app: &TestApp, partner: Uuid) -> Uuid {
    let plan: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_plan (name, status) VALUES ('Partners', 'published') RETURNING id",
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
         VALUES ($1, 'partner_referral', 'split_amount')",
    )
    .bind(version)
    .execute(app.db())
    .await
    .unwrap();
    assert_eq!(invalid_participant(app.db(), version).await.unwrap(), None);
    sqlx::query_scalar(
        "INSERT INTO plan_participant (plan_version_ref, partner_account_ref) \
         VALUES ($1, $2) RETURNING id",
    )
    .bind(version)
    .bind(partner)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn open_period(app: &TestApp) -> Uuid {
    sqlx::query(
        "INSERT INTO comp_period (fiscal_period, starts_on, ends_on, status) \
         SELECT 'FY', CURRENT_DATE - 365, CURRENT_DATE + 365, 'open' \
          WHERE NOT EXISTS (SELECT 1 FROM comp_period)",
    )
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query_scalar("SELECT id FROM comp_period ORDER BY starts_on DESC LIMIT 1")
        .fetch_one(app.db())
        .await
        .unwrap()
}

/// A won deal naming `partner`, credited twice, plus an adjustment on the
/// participation so the period has a statement row.
async fn won_deal(app: &TestApp, partner: Uuid, participant: Uuid, period: Uuid) {
    let deal: Uuid = sqlx::query_scalar(
        "INSERT INTO opportunity (name, stage, amount, close_date, partner_account_ref) \
         VALUES ('Referred', 'closed_won', 1000, CURRENT_DATE, $1) RETURNING id",
    )
    .bind(partner)
    .fetch_one(app.db())
    .await
    .unwrap();
    assert_eq!(credit_won_deal(&app.state, deal).await.unwrap(), 1);
    assert_eq!(credit_won_deal(&app.state, deal).await.unwrap(), 0);
    let (kind, owner): (String, Option<Uuid>) =
        sqlx::query_as("SELECT source_kind, owner_ref FROM comp_credit WHERE participant_ref = $1")
            .bind(participant)
            .fetch_one(app.db())
            .await
            .unwrap();
    assert_eq!(kind, "partner_deal");
    assert_eq!(owner, None, "no seller's record rules reach it");
    sqlx::query(
        "INSERT INTO comp_adjustment (participant_ref, period_ref, amount, reason) \
         VALUES ($1, $2, 50, 'Referral fee')",
    )
    .bind(participant)
    .bind(period)
    .execute(app.db())
    .await
    .unwrap();
}

// feature: F10
#[test]
fn partner_sees_own_statement() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let partner = account(&app).await;
        let participant = participation(&app, partner).await;
        let period = open_period(&app).await;
        won_deal(&app, partner, participant, period).await;

        let statement = partner_statement(&app.state, partner, period, &PAGE)
            .await
            .unwrap();
        assert_eq!(statement.total, 1);
        assert_eq!(statement.items[0].participant_id, Some(participant));
        assert_eq!(statement.items[0].amount.as_deref(), Some("50.000000"));
    });
}

// feature: F10
#[test]
fn other_partner_gets_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let partner = account(&app).await;
        let participant = participation(&app, partner).await;
        let period = open_period(&app).await;
        won_deal(&app, partner, participant, period).await;

        let other = account(&app).await;
        participation(&app, other).await;
        assert!(matches!(
            partner_statement(&app.state, other, period, &PAGE).await,
            Err(AppError::NotFound)
        ));
    });
}

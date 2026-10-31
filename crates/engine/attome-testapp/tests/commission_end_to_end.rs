//! F10-T16: a seller accepts a flat-rate plan, a split deal is won, the run
//! pays the share, the approved close locks the period and emits the accrual,
//! and the payroll hand-off exports the payout once.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_commission::credit::credit_won_deal;
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
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
    "human-resources",
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

/// `seller` on a published 10% plan, asked to accept it through an envelope
/// they have signed; answers (plan version, participant).
async fn accepted_plan(app: &TestApp, seller: Uuid) -> (Uuid, Uuid) {
    let plan: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_plan (name, status) VALUES ('Flat rate', 'published') RETURNING id",
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
        "INSERT INTO comp_component (plan_version_ref, kind, measure, tier_mode, rate_table) \
         VALUES ($1, 'new_business', 'split_amount', 'retroactive', '[{\"from\": 0, \"rate\": 10}]')",
    )
    .bind(version)
    .execute(app.db())
    .await
    .unwrap();
    let envelope: Uuid = sqlx::query_scalar(
        "INSERT INTO esign_envelope (title, status, created_by) \
         VALUES ('Commission plan acceptance', 'completed', $1) RETURNING id",
    )
    .bind(seller)
    .fetch_one(app.db())
    .await
    .unwrap();
    let participant: Uuid = sqlx::query_scalar(
        "INSERT INTO plan_participant (plan_version_ref, user_ref, owner_ref, acceptance_status, \
             envelope_id, acceptance_requested_by) \
         VALUES ($1, $2, $2, 'pending', $3, $2) RETURNING id",
    )
    .bind(version)
    .bind(seller)
    .bind(envelope.to_string())
    .fetch_one(app.db())
    .await
    .unwrap();
    attome_commission::acceptance::tick(&app.state)
        .await
        .unwrap();
    (version, participant)
}

/// A deal won at 2000 with `seller` holding a 1000 split.
async fn won_split_deal(app: &TestApp, seller: Uuid) -> Uuid {
    let deal: Uuid = sqlx::query_scalar(
        "INSERT INTO opportunity (name, stage, amount, currency, close_date, owner_ref) \
         VALUES ('Split deal', 'closed_won', 2000, 'SAR', CURRENT_DATE, $1) RETURNING id",
    )
    .bind(seller)
    .fetch_one(app.db())
    .await
    .unwrap();
    let member: Uuid = sqlx::query_scalar(
        "INSERT INTO opportunity_team_member (opportunity_ref, user_ref) \
         VALUES ($1, $2) RETURNING id",
    )
    .bind(deal)
    .bind(seller)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO opportunity_split (opportunity_ref, member_ref, percent, amount) \
         VALUES ($1, $2, 50, 1000)",
    )
    .bind(deal)
    .bind(member)
    .execute(app.db())
    .await
    .unwrap();
    deal
}

async fn payout(app: &TestApp, participant: Uuid) -> (String, f64) {
    sqlx::query_as("SELECT status, amount::float8 FROM comp_payout WHERE participant_ref = $1")
        .bind(participant)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: F10
#[test]
fn won_deal_to_locked_period_to_payroll() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let seller = attome_testapp::seed_user(app.db(), "pay-seller").await.id;
        sqlx::query(
            "INSERT INTO employee (full_name, national_id, base_salary, user_ref) \
             VALUES ('Pay Seller', '1000000001', 9000, $1)",
        )
        .bind(seller)
        .execute(app.db())
        .await
        .unwrap();
        let (version, participant) = accepted_plan(&app, seller).await;
        let (period, from, to): (Uuid, chrono::NaiveDate, chrono::NaiveDate) = sqlx::query_as(
            "INSERT INTO comp_period (fiscal_period, starts_on, ends_on, status) \
             VALUES ('End to end', CURRENT_DATE - 10, CURRENT_DATE + 10, 'open') \
             RETURNING id, starts_on::date, ends_on::date",
        )
        .fetch_one(app.db())
        .await
        .unwrap();

        let deal = won_split_deal(&app, seller).await;
        assert_eq!(credit_won_deal(&app.state, deal).await.unwrap(), 1);

        let run: Uuid = sqlx::query_scalar(
            "INSERT INTO comp_run (period_ref, plan_version_ref, status) \
             VALUES ($1, $2, 'queued') RETURNING id",
        )
        .bind(period)
        .bind(version)
        .fetch_one(app.db())
        .await
        .unwrap();
        attome_commission::run::execute(&app.state, run)
            .await
            .unwrap();
        let (status, amount) = payout(&app, participant).await;
        assert_eq!(status, "calculated", "an accepted plan pays");
        assert!((amount - 100.0).abs() < 0.01, "10% of the share: {amount}");

        // The approval's executor closes a period that is in review.
        sqlx::query("UPDATE comp_period SET status = 'in_review' WHERE id = $1")
            .bind(period)
            .execute(app.db())
            .await
            .unwrap();
        let closed = attome_commission::close::do_close_period(&app.state, period, app.admin.id)
            .await
            .unwrap();
        assert_eq!(closed.payouts_approved, 1);
        assert_eq!(payout(&app, participant).await.0, "approved");
        let accruals: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM entity_change_event \
              WHERE record_id = $1 AND event_name = 'commission.period_accrued'",
        )
        .bind(period)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(accruals, 1);

        let body = json!({ "from": from, "to": to });
        let (status, answer) = app
            .request(
                Method::POST,
                "/api/v1/hr/payroll-handoff",
                Some(body.clone()),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(payout(&app, participant).await.0, "exported");

        // A second hand-off of the period carries nothing twice.
        let (status, again) = app
            .request(Method::POST, "/api/v1/hr/payroll-handoff", Some(body))
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(payout(&app, participant).await.0, "exported");
    });
}

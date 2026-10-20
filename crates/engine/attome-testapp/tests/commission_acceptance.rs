//! F10-T10: a participant asked to accept their plan is paid nothing until
//! their K4 envelope completes, and a recoverable draw moves its balance
//! once per period however many times the period is calculated.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

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

/// A seller on a published 10% plan with one 1000 credit in an open period;
/// answers (seller, participant, version, period).
async fn seller_with_credit(app: &TestApp, name: &str) -> (Uuid, Uuid, Uuid, Uuid) {
    let seller = attome_testapp::seed_user(app.db(), name).await.id;
    let plan: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_plan (name, status) VALUES ($1, 'published') RETURNING id",
    )
    .bind(name)
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
    let participant: Uuid = sqlx::query_scalar(
        "INSERT INTO plan_participant (plan_version_ref, user_ref, owner_ref) \
         VALUES ($1, $2, $2) RETURNING id",
    )
    .bind(version)
    .bind(seller)
    .fetch_one(app.db())
    .await
    .unwrap();
    let period: Uuid = sqlx::query_scalar(
        "INSERT INTO comp_period (fiscal_period, starts_on, ends_on, status) \
         VALUES ($1, CURRENT_DATE - 10, CURRENT_DATE + 10, 'open') RETURNING id",
    )
    .bind(name)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO comp_credit (participant_ref, period_ref, source_kind, source_id, amount, \
             credited_on, owner_ref) \
         VALUES ($1, $2, 'split', $3, 1000, CURRENT_DATE, $4)",
    )
    .bind(participant)
    .bind(period)
    .bind(Uuid::now_v7().to_string())
    .bind(seller)
    .execute(app.db())
    .await
    .unwrap();
    (seller, participant, version, period)
}

async fn run(app: &TestApp, version: Uuid, period: Uuid) -> Uuid {
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
    run
}

async fn payout(app: &TestApp, run: Uuid, participant: Uuid) -> (String, f64) {
    sqlx::query_as(
        "SELECT status, amount::float8 FROM comp_payout \
          WHERE run_ref = $1 AND participant_ref = $2",
    )
    .bind(run)
    .bind(participant)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn draw_balance(app: &TestApp, draw: Uuid) -> f64 {
    sqlx::query_scalar("SELECT balance::float8 FROM comp_draw WHERE id = $1")
        .bind(draw)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: F10
#[test]
fn payout_held_until_accepted() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (seller, participant, version, period) =
            seller_with_credit(&app, "acceptance-seller").await;
        // Asked to accept: the envelope is out for signature.
        let envelope: Uuid = sqlx::query_scalar(
            "INSERT INTO esign_envelope (title, status, created_by) \
             VALUES ('Commission plan acceptance', 'sent', $1) RETURNING id",
        )
        .bind(seller)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE plan_participant SET acceptance_status = 'pending', envelope_id = $2, \
                 acceptance_requested_by = $3 WHERE id = $1",
        )
        .bind(participant)
        .bind(envelope.to_string())
        .bind(seller)
        .execute(app.db())
        .await
        .unwrap();

        let first = run(&app, version, period).await;
        let (status, amount) = payout(&app, first, participant).await;
        assert_eq!(status, "held");
        assert!((amount - 100.0).abs() < 0.01, "{amount}");

        // Still unsigned: the tick changes nothing.
        attome_commission::acceptance::tick(&app.state)
            .await
            .unwrap();
        assert_eq!(payout(&app, first, participant).await.0, "held");

        // Signed by everyone: accepted, and the held payout is released.
        sqlx::query("UPDATE esign_envelope SET status = 'completed' WHERE id = $1")
            .bind(envelope)
            .execute(app.db())
            .await
            .unwrap();
        attome_commission::acceptance::tick(&app.state)
            .await
            .unwrap();
        let accepted: Option<String> =
            sqlx::query_scalar("SELECT acceptance_status FROM plan_participant WHERE id = $1")
                .bind(participant)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(accepted.as_deref(), Some("accepted"));
        assert_eq!(payout(&app, first, participant).await.0, "calculated");
        let second = run(&app, version, period).await;
        assert_eq!(payout(&app, second, participant).await.0, "calculated");
    });
}

// feature: F10
#[test]
fn draw_applies_once_per_period() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let (seller, participant, version, period) = seller_with_credit(&app, "draw-seller").await;
        let draw: Uuid = sqlx::query_scalar(
            "INSERT INTO comp_draw (participant_ref, kind, amount_per_period, balance, owner_ref) \
             VALUES ($1, 'recoverable', 300, 0, $2) RETURNING id",
        )
        .bind(participant)
        .bind(seller)
        .fetch_one(app.db())
        .await
        .unwrap();
        // Earned 100 against a 300 draw: pays 300, owes 200.
        let first = run(&app, version, period).await;
        assert!((payout(&app, first, participant).await.1 - 300.0).abs() < 0.01);
        assert!((draw_balance(&app, draw).await - 200.0).abs() < 0.01);
        // The same period again: the balance is not moved twice.
        let again = run(&app, version, period).await;
        assert!((payout(&app, again, participant).await.1 - 300.0).abs() < 0.01);
        assert!((draw_balance(&app, draw).await - 200.0).abs() < 0.01);
    });
}

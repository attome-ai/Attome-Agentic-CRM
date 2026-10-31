//! F9-T9: the nightly rollup leaves one correct snapshot per partner per day.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_partner::performance::rollup;
use attome_testapp::TestApp;
use chrono::Utc;
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

async fn partner(app: &TestApp) -> Uuid {
    sqlx::query_scalar("INSERT INTO account (name, is_partner) VALUES ($1, true) RETURNING id")
        .bind(Uuid::now_v7().to_string())
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn deal(app: &TestApp, partner: Uuid, stage: &str, amount: f64) {
    sqlx::query(
        "INSERT INTO opportunity (name, stage, amount, close_date, partner_account_ref) \
         VALUES ('Deal', $1, $2, CURRENT_DATE, $3)",
    )
    .bind(stage)
    .bind(amount)
    .bind(partner)
    .execute(app.db())
    .await
    .unwrap();
}

async fn snapshots(app: &TestApp, partner: Uuid) -> Vec<(f64, f64, Option<f64>)> {
    sqlx::query_as(
        "SELECT pipeline::float8, won_revenue::float8, win_rate::float8 \
           FROM partner_performance_snapshot WHERE partner_account_ref = $1",
    )
    .bind(partner)
    .fetch_all(app.db())
    .await
    .unwrap()
}

// feature: F9
#[test]
fn rollup_is_idempotent_per_day() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let partner = partner(&app).await;
        let today = Utc::now().date_naive();
        deal(&app, partner, "closed_won", 1000.0).await;
        rollup(&app.state, today).await.unwrap();
        deal(&app, partner, "closed_won", 500.0).await;
        rollup(&app.state, today).await.unwrap();

        let rows = snapshots(&app, partner).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!((rows[0].1 - 1500.0).abs() < 0.01, "the later run wins");
    });
}

// feature: F9
#[test]
fn win_rate_matches_won_over_closed() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let partner = partner(&app).await;
        deal(&app, partner, "closed_won", 100.0).await;
        for _ in 0..3 {
            deal(&app, partner, "closed_lost", 100.0).await;
        }
        deal(&app, partner, "proposal", 700.0).await;
        rollup(&app.state, Utc::now().date_naive()).await.unwrap();

        let rows = snapshots(&app, partner).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert!((rows[0].0 - 700.0).abs() < 0.01, "open deals are pipeline");
        assert_eq!(rows[0].2, Some(25.0), "one won of four closed");
    });
}

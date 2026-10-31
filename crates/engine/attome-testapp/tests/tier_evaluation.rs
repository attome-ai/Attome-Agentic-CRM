//! F9-T5: the tier evaluation proposes a change once per partner, a rerun
//! adds none, and nothing changes a tier until a person confirms.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

fn packs_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs")
}

async fn install(app: &TestApp, pack: &str) -> Result<(), String> {
    let dir = packs_dir().join(pack).join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .map_err(|e| format!("{}: {e}", file.display()))?;
    }
    Ok(())
}

/// The packs the partner pack's lookups need, in whatever order they install.
async fn install_partner(app: &TestApp) {
    let mut left = vec![
        "crm",
        "sales",
        "vendor-supplier",
        "contract-management",
        "partner",
    ];
    let mut last = Vec::new();
    for _ in 0..5 {
        let mut failed = Vec::new();
        for pack in left {
            if let Err(error) = install(app, pack).await {
                failed.push((pack, error));
            }
        }
        if failed.is_empty() {
            let registry = attome_core::build_registry(app.db()).await.unwrap();
            app.state.entities.swap(registry);
            return;
        }
        left = failed.iter().map(|(pack, _)| *pack).collect();
        if left.len() == 5 {
            panic!("no pack installs: {failed:?}");
        }
        last = failed;
    }
    panic!("packs left uninstalled: {last:?}");
}

async fn create(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, out) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{entity}: {out}");
    out["id"].as_str().unwrap().parse().unwrap()
}

async fn proposals(app: &TestApp, partner: Uuid) -> Vec<(Uuid, Option<Uuid>, String)> {
    sqlx::query_as(
        "SELECT id, to_tier_ref, status FROM tier_change_proposal           WHERE partner_account_ref = $1 ORDER BY id",
    )
    .bind(partner)
    .fetch_all(app.db())
    .await
    .unwrap()
}

async fn tier_of(app: &TestApp, partner: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT partner_tier_ref FROM account WHERE id = $1")
        .bind(partner)
        .fetch_one(app.db())
        .await
        .unwrap()
}

struct World {
    silver: Uuid,
    gold: Uuid,
    earner: Uuid,
    steady: Uuid,
}

/// `earner` won enough for gold and sits on silver; `steady` won nothing
/// beyond silver and is on it.
async fn world(app: &TestApp) -> World {
    let programme = create(app, "partner_programme", json!({ "name": "Resellers" })).await;
    let tier = |name: &'static str, rank: i32, revenue: i32| {
        create(
            app,
            "partner_tier",
            json!({ "programme_ref": programme, "name": name, "rank": rank, "min_revenue_12m": revenue }),
        )
    };
    let silver = tier("Silver", 1, 0).await;
    let gold = tier("Gold", 2, 1000).await;
    let partner = |tier: Uuid| {
        create(
            app,
            "account",
            json!({
                "name": format!("Partner {}", Uuid::now_v7().simple()),
                "is_partner": true,
                "partner_programme_ref": programme,
                "partner_tier_ref": tier,
            }),
        )
    };
    let earner = partner(silver).await;
    let steady = partner(silver).await;
    sqlx::query(
        "INSERT INTO opportunity (name, amount, stage, close_date, partner_account_ref,                                   is_active, row_version)          VALUES ('Big deal', 5000, 'closed_won', now() - interval '1 month', $1, true, 0)",
    )
    .bind(earner)
    .execute(app.db())
    .await
    .unwrap();
    World {
        silver,
        gold,
        earner,
        steady,
    }
}

// feature: F9
#[test]
fn job_creates_one_proposal_per_changed_partner() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        attome_partner::tiers::evaluate_all(&app.state, chrono::Utc::now())
            .await
            .unwrap();

        let open = proposals(&app, w.earner).await;
        assert_eq!(open.len(), 1, "{open:?}");
        assert_eq!(open[0].1, Some(w.gold));
        assert_eq!(open[0].2, "proposed");
        assert!(proposals(&app, w.steady).await.is_empty());
        assert_eq!(tier_of(&app, w.earner).await, Some(w.silver), "not yet");

        let confirm = format!("/api/v1/partner/tier-proposals/{}/confirm", open[0].0);
        let (status, body) = app
            .request_with(Method::POST, &confirm, &[("if-match", "\"7\"")], None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, body) = app
            .request_with(Method::POST, &confirm, &[("if-match", "\"0\"")], None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "confirmed");
        assert_eq!(tier_of(&app, w.earner).await, Some(w.gold));
    });
}

// feature: F9
#[test]
fn rerun_does_not_duplicate_open_proposal() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let w = world(&app).await;
        let now = chrono::Utc::now();
        attome_partner::tiers::evaluate_all(&app.state, now)
            .await
            .unwrap();
        attome_partner::tiers::evaluate_all(&app.state, now)
            .await
            .unwrap();
        assert_eq!(proposals(&app, w.earner).await.len(), 1);
        assert_eq!(tier_of(&app, w.earner).await, Some(w.silver));
    });
}

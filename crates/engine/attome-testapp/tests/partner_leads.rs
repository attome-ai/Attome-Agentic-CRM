//! F9-T4: an offered lead can be accepted only by its partner, and comes back
//! when the time limit passes.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use attome_types::AppError;
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

async fn partner(app: &TestApp) -> Uuid {
    let name = format!("Partner {}", Uuid::now_v7().simple());
    create(app, "account", json!({ "name": name, "is_partner": true })).await
}

async fn lead(app: &TestApp) -> Uuid {
    let name = format!("Lead {}", Uuid::now_v7().simple());
    create(app, "lead", json!({ "name": name })).await
}

async fn state_of(app: &TestApp, lead: Uuid) -> (Option<Uuid>, Option<String>) {
    sqlx::query_as("SELECT partner_account_ref, partner_status FROM lead WHERE id = $1")
        .bind(lead)
        .fetch_one(app.db())
        .await
        .unwrap()
}

async fn offer(app: &TestApp, lead: Uuid, partner: Uuid) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/partner/leads/{lead}/offer"),
        Some(json!({ "partner_account_id": partner, "accept_hours": 2 })),
    )
    .await
}

// feature: F9
#[test]
fn partner_can_accept_offered_lead() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let (p, l) = (partner(&app).await, lead(&app).await);
        let (status, body) = offer(&app, l, p).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["partner_status"], "offered");
        let (status, body) = offer(&app, l, partner(&app).await).await;
        assert_eq!(status, StatusCode::CONFLICT, "a held lead: {body}");

        let done = attome_partner::leads::respond(&app.state, p, Uuid::nil(), l, true)
            .await
            .unwrap();
        assert_eq!(done.partner_status, "accepted");
        assert_eq!(
            state_of(&app, l).await,
            (Some(p), Some("accepted".to_owned()))
        );
    });
}

// feature: F9
#[test]
fn other_partner_cannot_accept() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let (p, other, l) = (partner(&app).await, partner(&app).await, lead(&app).await);
        offer(&app, l, p).await;
        let refused = attome_partner::leads::respond(&app.state, other, Uuid::nil(), l, true).await;
        assert!(matches!(refused, Err(AppError::NotFound)), "{refused:?}");
        assert_eq!(
            state_of(&app, l).await,
            (Some(p), Some("offered".to_owned()))
        );
    });
}

// feature: F9
#[test]
fn expired_offer_returns_lead() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let (p, l) = (partner(&app).await, lead(&app).await);
        offer(&app, l, p).await;
        sqlx::query("UPDATE lead SET partner_accept_by = now() - interval '1 hour' WHERE id = $1")
            .bind(l)
            .execute(app.db())
            .await
            .unwrap();
        let late = attome_partner::leads::respond(&app.state, p, Uuid::nil(), l, true).await;
        assert!(matches!(late, Err(AppError::NotFound)), "{late:?}");
        assert!(
            attome_partner::leads::return_tick(&app.state)
                .await
                .unwrap()
                >= 1
        );
        assert_eq!(state_of(&app, l).await, (None, Some("returned".to_owned())));
    });
}

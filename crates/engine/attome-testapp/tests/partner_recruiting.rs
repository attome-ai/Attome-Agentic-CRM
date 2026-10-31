//! F9-T6: an application matches an account, an approval makes the partner,
//! and a signed agreement starts onboarding.
//!
//! `TestApp` does not mount the portal, so these call the engine; the portal's
//! routes add the rate limits and the member.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_partner::recruiting::{self, Application};
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

fn application(company: &str, email: &str) -> Application {
    Application {
        company_name: company.to_owned(),
        contact_name: "Sara Ali".to_owned(),
        contact_email: email.to_owned(),
        contact_phone: None,
    }
}

async fn matched(app: &TestApp, id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT matched_account_ref FROM partner_application WHERE id = $1")
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap()
}

fn unique() -> String {
    Uuid::now_v7().simple().to_string()
}

async fn approve(app: &TestApp, id: Uuid) -> recruiting::Approved {
    let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
    let (_, approved) = recruiting::approve_in_tx(&app.state, &mut tx, app.admin.id, id)
        .await
        .unwrap();
    attome_db::tx::commit(tx).await.unwrap();
    approved
}

// feature: F9
#[test]
fn application_matches_existing_account() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let name = format!("Acme {}", unique());
        let domain = format!("{}.sa", unique());
        let by_name = create(&app, "account", json!({ "name": name })).await;
        let by_domain = create(
            &app,
            "account",
            json!({ "name": format!("Other {}", unique()), "email_domain": domain }),
        )
        .await;
        let upper = name.to_uppercase();
        let id = recruiting::submit(&app.state, &application(&upper, "sara@gmail.com"))
            .await
            .unwrap();
        assert_eq!(matched(&app, id).await, Some(by_name));

        let email = format!("sara@{domain}");
        let id = recruiting::submit(&app.state, &application(&unique(), &email))
            .await
            .unwrap();
        assert_eq!(matched(&app, id).await, Some(by_domain));

        let id = recruiting::submit(&app.state, &application(&unique(), "sara@gmail.com"))
            .await
            .unwrap();
        assert_eq!(
            matched(&app, id).await,
            None,
            "a shared mail domain matches nothing"
        );
    });
}

// feature: F9
#[test]
fn approval_creates_partner_account_and_admin() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let company = format!("New {}", unique());
        let id = recruiting::submit(&app.state, &application(&company, "sara@gmail.com"))
            .await
            .unwrap();
        let none: i64 = sqlx::query_scalar("SELECT count(*) FROM account WHERE name = $1")
            .bind(&company)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(none, 0, "no partner before approval");

        let approved = approve(&app, id).await;
        let partner: bool = sqlx::query_scalar("SELECT is_partner FROM account WHERE id = $1")
            .bind(approved.partner_account_id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert!(partner);
        let account: Option<Uuid> =
            sqlx::query_scalar("SELECT account_ref FROM contact WHERE id = $1")
                .bind(approved.contact_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(account, Some(approved.partner_account_id));

        let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
        let again = recruiting::approve_in_tx(&app.state, &mut tx, app.admin.id, id).await;
        assert!(again.is_err(), "already decided");
    });
}

// feature: F9
#[test]
fn signed_agreement_creates_three_onboarding_items() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let id = recruiting::submit(&app.state, &application(&unique(), "sara@gmail.com"))
            .await
            .unwrap();
        let approved = approve(&app, id).await;
        let envelope: Uuid = sqlx::query_scalar(
            "INSERT INTO esign_envelope (title, status, created_by) \
             VALUES ('Agreement', 'sent', $1) RETURNING id",
        )
        .bind(app.admin.id)
        .fetch_one(app.db())
        .await
        .unwrap();
        sqlx::query("UPDATE partner_application SET agreement_envelope_id = $2 WHERE id = $1")
            .bind(id)
            .bind(envelope.to_string())
            .execute(app.db())
            .await
            .unwrap();
        let items = || async {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM partner_onboarding_item WHERE partner_account_ref = $1",
            )
            .bind(approved.partner_account_id)
            .fetch_one(app.db())
            .await
            .unwrap();
            count
        };

        recruiting::onboarding_tick(&app.state).await.unwrap();
        assert_eq!(items().await, 0, "not signed yet");

        sqlx::query("UPDATE esign_envelope SET status = 'completed' WHERE id = $1")
            .bind(envelope)
            .execute(app.db())
            .await
            .unwrap();
        recruiting::onboarding_tick(&app.state).await.unwrap();
        assert_eq!(items().await, 3);
        recruiting::onboarding_tick(&app.state).await.unwrap();
        assert_eq!(items().await, 3, "a second run adds nothing");

        let mut tx = attome_db::tx::begin(app.db()).await.unwrap();
        recruiting::finish_first_deal(&mut tx, approved.partner_account_id)
            .await
            .unwrap();
        attome_db::tx::commit(tx).await.unwrap();
        let done: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM partner_onboarding_item \
              WHERE partner_account_ref = $1 AND done_on IS NOT NULL",
        )
        .bind(approved.partner_account_id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(done, 1);
    });
}

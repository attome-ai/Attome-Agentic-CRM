//! F9-T12: the partner path end to end: an application approved makes a
//! partner, the partner registers a deal, the decision approves it, and the
//! deal names that partner, the field its portal members read deals by, and
//! not another partner.
//!
//! `TestApp` does not mount the portal, so the application is approved
//! through the engine and the registration is written as the portal's
//! record API would; the decision is the staff route.

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
fn apply_register_approve_and_see_deal() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_partner(&app).await;
        let mine = recruiting::submit(
            &app.state,
            &application(&format!("Reseller {}", unique()), "sara@gmail.com"),
        )
        .await
        .unwrap();
        let theirs = recruiting::submit(
            &app.state,
            &application(&format!("Other {}", unique()), "omar@gmail.com"),
        )
        .await
        .unwrap();
        let partner = approve(&app, mine).await.partner_account_id;
        let other = approve(&app, theirs).await.partner_account_id;
        let customer = create(
            &app,
            "account",
            json!({ "name": format!("Customer {}", unique()) }),
        )
        .await;

        let registration = create(
            &app,
            "deal_registration",
            json!({
                "partner_account_ref": partner,
                "customer_account_ref": customer,
                "customer_name": "Customer",
                "amount": 50000,
                "status": "submitted",
            }),
        )
        .await;
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/partner/registrations/{registration}/decision"),
                Some(json!({ "decision": "approve" })),
            )
            .await;
        assert!(status.is_success(), "decision: {status} {body}");

        let (opportunity, state): (Option<Uuid>, Option<String>) = sqlx::query_as(
            "SELECT opportunity_ref, status::text FROM deal_registration WHERE id = $1",
        )
        .bind(registration)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(state.as_deref(), Some("approved"));
        let opportunity = opportunity.expect("the approval makes or links a deal");
        let named: Option<Uuid> =
            sqlx::query_scalar("SELECT partner_account_ref FROM opportunity WHERE id = $1")
                .bind(opportunity)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(named, Some(partner), "the partner's members read it");
        let others: i64 =
            sqlx::query_scalar("SELECT count(*) FROM opportunity WHERE partner_account_ref = $1")
                .bind(other)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(others, 0, "another partner reads none of it");
    });
}

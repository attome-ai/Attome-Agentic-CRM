//! D4-T1: lead assignment against the database. A new lead takes the owner
//! of an earlier live lead with the same email (compared without case), the
//! reason is written beside it through the record engine, and a second run
//! changes nothing; a lead nothing matches keeps the owner it was created
//! with.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use attome_workflow::lead_assignment::assign_lead;
use uuid::Uuid;

async fn install(app: &TestApp) {
    for pack in ["crm", "sales"] {
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
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

async fn lead(app: &TestApp, email: &str, owner: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO lead (id, name, email, lead_status, owner_ref, is_active, row_version) \
         VALUES ($1, 'Lead', $2, 'new', $3, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(email)
    .bind(owner)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn owner_and_reason(app: &TestApp, id: Uuid) -> (Option<Uuid>, Option<String>) {
    sqlx::query_as("SELECT owner_ref, assignment_reason FROM lead WHERE id = $1")
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: D4
#[test]
fn a_new_lead_takes_the_earlier_leads_owner_once() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let seller = seed_user(app.db(), "lead-owner").await;
        let tag = Uuid::now_v7().simple().to_string();
        let earlier = lead(&app, &format!("sara.{tag}@acme.example"), seller.id).await;
        let new = lead(&app, &format!("  Sara.{tag}@ACME.example "), app.admin.id).await;

        assert!(assign_lead(&app.state, new).await.expect("assign"));
        let (owner, reason) = owner_and_reason(&app, new).await;
        assert_eq!(owner, Some(seller.id), "the earlier lead's owner");
        assert_eq!(reason.as_deref(), Some("existing_lead"));

        // Run again: the lead carries its reason, so nothing changes.
        assert!(!assign_lead(&app.state, new).await.expect("assign again"));
        assert_eq!(owner_and_reason(&app, new).await.0, Some(seller.id));
        // The earlier lead is not touched by the newer one's assignment.
        assert_eq!(
            owner_and_reason(&app, earlier).await,
            (Some(seller.id), None)
        );

        // Nothing matches: the creator stays the owner, with no reason.
        let alone = lead(&app, &format!("nobody.{tag}@gmail.com"), app.admin.id).await;
        assert!(!assign_lead(&app.state, alone).await.expect("assign alone"));
        assert_eq!(
            owner_and_reason(&app, alone).await,
            (Some(app.admin.id), None)
        );
    });
}

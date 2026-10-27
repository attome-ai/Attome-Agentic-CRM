//! D3-T2: converting a qualified lead creates the account, contact and
//! opportunity, moves its activities and marks it converted; undo puts it
//! back while the new records are unchanged.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_sales::lead_convert::{LeadConvertBody, convert, undo};
use attome_testapp::TestApp;
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
}

/// A qualified lead with one activity about it; returns the lead, its
/// row_version and the activity.
async fn qualified_lead(app: &TestApp) -> (Uuid, i64, Uuid) {
    let lead: Uuid = sqlx::query_scalar(
        "INSERT INTO lead (id, name, company_name, email, lead_status, owner_ref, is_active, \
             row_version) \
         VALUES ($1, 'Sara Ali', 'Acme Trading', 'sara@acme-trading.sa', 'qualified', $2, true, 0) \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    let activity: Uuid = sqlx::query_scalar(
        "INSERT INTO activity (id, subject, regarding_entity, regarding_id, owner_ref, is_active, \
             row_version) \
         VALUES ($1, 'Intro call', 'lead', $2, $3, true, 0) RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(lead.to_string())
    .bind(app.admin.id)
    .fetch_one(app.db())
    .await
    .unwrap();
    (lead, 0, activity)
}

// feature: D3
#[test]
fn converting_a_lead_creates_links_and_moves_and_undo_puts_it_back() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let ctx = app
            .state
            .base
            .security
            .resolve_strict(app.admin.id)
            .await
            .unwrap();
        let (lead, version, activity) = qualified_lead(&app).await;

        let done = convert(&app.state, &ctx, lead, version, &LeadConvertBody::default())
            .await
            .expect("convert");
        let contact = done.contact_id.expect("a contact");
        assert!(done.opportunity_id.is_some(), "an opportunity");
        assert_eq!(done.moved, 1);

        let (status, account_ref): (String, Option<Uuid>) =
            sqlx::query_as("SELECT lead_status, converted_account_ref FROM lead WHERE id = $1")
                .bind(lead)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status, "converted");
        assert_eq!(account_ref, Some(done.account_id));
        let account_name: String = sqlx::query_scalar("SELECT name FROM account WHERE id = $1")
            .bind(done.account_id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(account_name, "Acme Trading");
        let regarding: (String, String) =
            sqlx::query_as("SELECT regarding_entity, regarding_id FROM activity WHERE id = $1")
                .bind(activity)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(regarding, ("contact".to_owned(), contact.to_string()));

        let again = convert(
            &app.state,
            &ctx,
            lead,
            version + 1,
            &LeadConvertBody::default(),
        )
        .await;
        assert!(again.is_err(), "a converted lead is not converted twice");

        let undone = undo(&app.state, &ctx, done.conversion_id)
            .await
            .expect("undo");
        assert_eq!(undone.removed, 3);
        let status: String = sqlx::query_scalar("SELECT lead_status FROM lead WHERE id = $1")
            .bind(lead)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(status, "qualified");
        let back: String =
            sqlx::query_scalar("SELECT regarding_entity FROM activity WHERE id = $1")
                .bind(activity)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(back, "lead");
        let live: Option<bool> = sqlx::query_scalar("SELECT is_active FROM account WHERE id = $1")
            .bind(done.account_id)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_ne!(live, Some(true), "the account it made is deleted");
    });
}

//! D23-T10: org chart proposals write open drafts and change no contact;
//! accepting a draft sets the manager, rejecting only marks it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_sales::orgchart::drafts;
use attome_testapp::TestApp;
use serde_json::Value;
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
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
}

async fn contact(app: &TestApp, name: &str, title: &str, account: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO contact (full_name, job_title, account_ref, is_active, row_version) \
         VALUES ($1, $2, $3, true, 0) RETURNING id",
    )
    .bind(name)
    .bind(title)
    .bind(account)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn manager_of(app: &TestApp, contact: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT reports_to FROM contact WHERE id = $1")
        .bind(contact)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: D23
#[test]
fn propose_creates_drafts_only() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let account: Uuid = sqlx::query_scalar(
            "INSERT INTO account (name, is_active, row_version) VALUES ('Drafts Co', true, 0) \
             RETURNING id",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        let ceo = contact(&app, "Nora", "Chief Executive Officer", account).await;
        let rep = contact(&app, "Omar", "Account Executive", account).await;
        let other = contact(&app, "Sami", "Engineer", account).await;
        let admin = attome_security::resolve_uncached(app.db(), app.admin.id)
            .await
            .unwrap();

        let written = drafts::propose(&app.state, &admin, account).await.unwrap();
        assert_eq!(written, 2, "the rep and the engineer, not the CEO");
        assert_eq!(
            manager_of(&app, rep).await,
            None,
            "a proposal sets no manager"
        );
        let open: Vec<(Uuid, Option<Uuid>, String)> = sqlx::query_as(
            "SELECT id, proposed_manager_ref, status FROM sales_orgchart_draft \
              WHERE account_ref = $1 AND contact_ref = $2",
        )
        .bind(account)
        .bind(rep)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!((open[0].1, open[0].2.as_str()), (Some(ceo), "open"));
        // Asking again adds no second draft for the same person.
        assert_eq!(
            drafts::propose(&app.state, &admin, account).await.unwrap(),
            0
        );

        // Accepting sets the manager; the answer names the one before.
        let decided = drafts::decide(&app.state, &admin, open[0].0, true)
            .await
            .unwrap();
        assert_eq!(decided.status, "accepted");
        assert_eq!(decided.previous_manager_id, None);
        assert_eq!(manager_of(&app, rep).await, Some(ceo));
        // A decided draft cannot be decided again.
        assert!(
            drafts::decide(&app.state, &admin, open[0].0, false)
                .await
                .is_err()
        );

        // Rejecting only marks the draft.
        let other_draft: Uuid = sqlx::query_scalar(
            "SELECT id FROM sales_orgchart_draft WHERE contact_ref = $1 AND status = 'open'",
        )
        .bind(other)
        .fetch_one(app.db())
        .await
        .unwrap();
        let decided = drafts::decide(&app.state, &admin, other_draft, false)
            .await
            .unwrap();
        assert_eq!(decided.status, "rejected");
        assert_eq!(manager_of(&app, other).await, None);
    });
}

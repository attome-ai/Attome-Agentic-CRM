//! D24-T4: a new lead with a work email at a known company's domain gets
//! that account suggested, off the change feed, with no provider call; a
//! free-mail lead gets none.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use serde_json::json;
use uuid::Uuid;

async fn install(app: &TestApp, pack: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs")
        .join(pack)
        .join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
                .expect("pack changeset JSON");
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

async fn suggested(app: &TestApp, lead: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT suggested_account_ref FROM lead WHERE id = $1")
        .bind(lead)
        .fetch_one(app.db())
        .await
        .expect("read lead")
}

// feature: D24
#[test]
fn lead_gets_existing_account_by_domain() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app, "crm").await;
        let owner = attome_testapp::seed_admin(app.db()).await.id;
        let ctx = app.state.base.security.resolve(owner).await.expect("ctx");
        let domain = format!("acme-{}.sa", Uuid::now_v7().simple());
        let (account, _) = attome_records::entity_crud::create_record_for(
            &app.state,
            &ctx,
            owner,
            "account",
            json!({ "name": "Acme", "email_domain": domain }),
        )
        .await
        .expect("account");
        let (work, _) = attome_records::entity_crud::create_record_for(
            &app.state,
            &ctx,
            owner,
            "lead",
            json!({ "name": "Sara", "email": format!("sara@mail.{domain}") }),
        )
        .await
        .expect("work lead");
        let (free, _) = attome_records::entity_crud::create_record_for(
            &app.state,
            &ctx,
            owner,
            "lead",
            json!({ "name": "Omar", "email": "omar@gmail.com" }),
        )
        .await
        .expect("free-mail lead");

        // The consumer may start behind other tests' events: sweep until it
        // has read past these leads.
        for _ in 0..200 {
            attome_sales::enrichment::domain::sweep_new_leads(&app.state)
                .await
                .expect("sweep");
            if suggested(&app, work).await.is_some() {
                break;
            }
        }
        assert_eq!(suggested(&app, work).await, Some(account));
        assert_eq!(
            suggested(&app, free).await,
            None,
            "free mail names no company"
        );

        let record = |email: &str| json!({ "email": email });
        assert!(
            attome_sales::enrichment::domain::known_before_provider(
                &app.state,
                &record(&format!("ali@{domain}"))
            )
            .await,
            "a known domain needs no provider call"
        );
        assert!(
            !attome_sales::enrichment::domain::known_before_provider(
                &app.state,
                &record("ali@unknown-company.example")
            )
            .await
        );
        assert!(
            attome_sales::enrichment::domain::known_before_provider(
                &app.state,
                &json!({ "suggested_account_ref": account.to_string() })
            )
            .await
        );
    });
}

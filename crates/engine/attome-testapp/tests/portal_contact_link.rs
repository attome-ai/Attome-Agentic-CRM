//! D1-T3: a verified portal sign-up is linked to the one contact with its
//! email address; with none, or several, it gets a new contact pending staff
//! review, owned by the portal's owning team. A name never links on its own.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::disallowed_methods,
    reason = "test helpers: a failed setup step should panic with its message; the portal and user are provisioned in a transaction opened directly on the test pool"
)]

use attome_portal::contact_link::{ContactLink, link_verified};
use attome_portal::provision::{self, MfaPolicy, NewPortal, NewPortalUser, PortalType};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

fn packs_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs")
}

/// The crm pack's changesets, in file order.
async fn install_crm(app: &TestApp) {
    let dir = packs_dir().join("crm").join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("read the crm pack")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for file in files {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

async fn contact(app: &TestApp, email: &str) -> Uuid {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/contact",
            Some(json!({ "full_name": "Existing", "email": email })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

// feature: D1
#[test]
fn a_verified_signup_links_to_its_contact_or_one_pending_review() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install_crm(&app).await;
        let team: Uuid =
            sqlx::query_scalar("SELECT id FROM team WHERE is_deleted = false ORDER BY id LIMIT 1")
                .fetch_one(app.db())
                .await
                .expect("a team to own portal records");

        let mut tx = app.db().begin().await.unwrap();
        let portal = provision::create_portal(
            &mut tx,
            Uuid::now_v7(),
            NewPortal {
                name: "Customers".into(),
                description: None,
                keyword: format!("cl-{}", &Uuid::now_v7().simple().to_string()[20..]),
                portal_type: PortalType::Authenticated,
                is_enabled: true,
                owning_team_ref: Some(team),
                mfa_policy: MfaPolicy::Optional,
            },
        )
        .await
        .expect("create a portal");
        tx.commit().await.unwrap();

        let suffix = Uuid::now_v7().simple().to_string();
        let known = format!("known-{suffix}@example.sa");
        let shared = format!("shared-{suffix}@example.sa");
        let unknown = format!("new-{suffix}@example.sa");
        let existing = contact(&app, &known).await;
        let twin_a = contact(&app, &shared).await;
        let twin_b = contact(&app, &shared).await;

        let link = |email: String| {
            let app = app.clone();
            let portal = &portal;
            async move {
                let mut tx = app.db().begin().await.unwrap();
                let user = provision::create_user(
                    &mut tx,
                    Uuid::now_v7(),
                    portal.id,
                    NewPortalUser {
                        name: "Existing".into(),
                        email: Some(email.clone()),
                        username: None,
                    },
                )
                .await
                .expect("create a portal user");
                let link = link_verified(&app.state, &mut tx, portal, user.id, &email, "Existing")
                    .await
                    .expect("link");
                tx.commit().await.unwrap();
                let linked: Option<Uuid> =
                    sqlx::query_scalar("SELECT contact_ref FROM webportal_user WHERE id = $1")
                        .bind(user.id)
                        .fetch_one(app.db())
                        .await
                        .unwrap();
                (link, linked)
            }
        };

        // One contact with the verified address: linked to it.
        let (outcome, linked) = link(known.clone()).await;
        assert_eq!(outcome, ContactLink::Linked(existing));
        assert_eq!(linked, Some(existing));

        // Several with it: neither is guessed; a new one waits for review.
        let (outcome, linked) = link(shared.clone()).await;
        let ContactLink::Created(created) = outcome else {
            panic!("an ambiguous address creates a contact, got {outcome:?}");
        };
        assert!(created != twin_a && created != twin_b);
        assert_eq!(linked, Some(created));

        // None with it: a new contact, pending review, owned by the portal's team.
        let (outcome, _) = link(unknown.clone()).await;
        let ContactLink::Created(fresh) = outcome else {
            panic!("an unknown address creates a contact, got {outcome:?}");
        };
        let (review, owner, email): (Option<String>, Option<Uuid>, Option<String>) =
            sqlx::query_as(
                "SELECT portal_review::text, owner_ref, email FROM contact WHERE id = $1",
            )
            .bind(fresh)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(review.as_deref(), Some("pending"));
        assert_eq!(owner, Some(team));
        assert_eq!(email.as_deref(), Some(unknown.as_str()));
    });
}

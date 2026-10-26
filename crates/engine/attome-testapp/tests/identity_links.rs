//! E24-T1: an identifier links to one contact; linking it again to the same
//! contact changes nothing, a second contact's claim is a conflict for
//! review, and settling it can move the link.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_marketing::identity::{
    IdentifierType, Keep, LinkSource, conflicts, link, resolve, resolve_conflict,
};
use attome_testapp::TestApp;
use attome_types::OnePageQuery;
use uuid::Uuid;

// feature: E24
#[test]
fn identity_links_flag_conflicts_for_review() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let email = format!("Sara.{}@Acme.sa", a.simple());
        let ids = [(IdentifierType::Email, email.clone())];

        let first = link(&app.state, a, LinkSource::FormEmail, &ids)
            .await
            .unwrap();
        assert_eq!(first[0].outcome, "linked");
        assert_eq!(first[0].identifier_value, email.to_lowercase());
        let again = link(&app.state, a, LinkSource::EmailClick, &ids)
            .await
            .unwrap();
        assert_eq!(again[0].outcome, "same");
        let clash = link(&app.state, b, LinkSource::Login, &ids).await.unwrap();
        assert_eq!(clash[0].outcome, "conflict");
        // Nothing moved.
        assert_eq!(
            resolve(&app.state, IdentifierType::Email, &email)
                .await
                .unwrap(),
            Some(a)
        );

        let ctx = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let page: OnePageQuery = serde_json::from_value(serde_json::json!({})).unwrap();
        let open = conflicts(&app.state, &ctx, &page).await.unwrap();
        let conflict = open
            .items
            .iter()
            .find(|c| c.contact_id == b)
            .expect("the clash waits for review");
        assert_eq!(conflict.conflict_with, Some(a));

        let settled = resolve_conflict(&app.state, &ctx, conflict.id, Keep::New)
            .await
            .unwrap();
        assert_eq!(settled.contact_id, b);
        assert_eq!(
            resolve(&app.state, IdentifierType::Email, &email)
                .await
                .unwrap(),
            Some(b)
        );
        // Settled once: a second decision finds no open conflict.
        assert!(
            resolve_conflict(&app.state, &ctx, conflict.id, Keep::Existing)
                .await
                .is_err()
        );
    });
}

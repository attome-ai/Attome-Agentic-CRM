//! Q14-T1: a user with `{entity}.share` shares a record they can reach,
//! without admin rights, and cannot give more than they hold.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, TestUser, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

async fn user_with(app: &TestApp, label: &str, entity: &str, verbs: &[&str]) -> TestUser {
    let user = seed_user(app.db(), label).await;
    let email = format!("testapp-{label}-{}@test.invalid", user.id);
    for verb in verbs {
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/grants",
                Some(json!({ "user_email": email, "privilege_key": format!("{entity}.{verb}") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "grant {entity}.{verb}: {body}");
    }
    user
}

// feature: Q14
#[test]
fn record_share_owner_shares_without_admin_and_cannot_escalate() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("qshr_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        let (status, field) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": "title", "name": "title", "field_type": "text" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");

        let owner = user_with(
            &app,
            "owner",
            &entity,
            &["read", "create", "update", "share"],
        )
        .await;
        let reader = user_with(&app, "reader", &entity, &["read", "share"]).await;
        let outsider = user_with(&app, "outsider", &entity, &["read"]).await;
        let friend = seed_user(app.db(), "friend").await;

        let (status, record) = app
            .request_as(
                &owner.cookie,
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "title": "shared deal" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
        let record_id = record["id"].as_str().unwrap().to_owned();
        let shares = format!("/api/v1/{entity}/{record_id}/shares");

        // The owner shares read with a colleague, without admin rights.
        let (status, share) = app
            .request_as(
                &owner.cookie,
                Method::POST,
                &shares,
                Some(json!({ "capability": "view", "user_id": friend.id })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{share}");
        assert_eq!(share["capability"], "view");
        let view_share = share["id"].as_str().unwrap().to_owned();

        // Without the share privilege: refused.
        let (status, body) = app
            .request_as(
                &outsider.cookie,
                Method::POST,
                &shares,
                Some(json!({ "capability": "view", "user_id": friend.id })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // A sharer who can only read may share read, never write.
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                &shares,
                Some(json!({ "capability": "action", "user_id": friend.id })),
            )
            .await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND,
            "{status}: {body}"
        );
        let (status, body) = app
            .request_as(
                &reader.cookie,
                Method::POST,
                &shares,
                Some(json!({ "capability": "view", "team_id": null, "user_id": owner.id })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        // Nor may anyone hand out a deny.
        let (status, _) = app
            .request_as(
                &owner.cookie,
                Method::POST,
                &shares,
                Some(json!({ "capability": "deny", "user_id": friend.id })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Listing shows the shares, the creator's own among them.
        let (status, list) = app
            .request_as(&owner.cookie, Method::GET, &shares, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        let items = list["items"].as_array().unwrap();
        assert!(items.iter().any(|s| s["id"] == view_share.as_str()));
        let creator_share = items
            .iter()
            .find(|s| s["principal_id"] == owner.id.to_string() && s["capability"] == "action")
            .expect("the creator holds an action share")["id"]
            .as_str()
            .unwrap()
            .to_owned();

        // The creator's own share is not the sharer's to remove.
        let (status, _) = app
            .request_as(
                &owner.cookie,
                Method::DELETE,
                &format!("{shares}/{creator_share}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The owner revokes the share they gave; it is gone.
        let (status, _) = app
            .request_as(
                &owner.cookie,
                Method::DELETE,
                &format!("{shares}/{view_share}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (_, list) = app
            .request_as(&owner.cookie, Method::GET, &shares, None)
            .await;
        assert!(
            !list["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["id"] == view_share.as_str())
        );

        // Every grant and revoke is a security event on the record: two
        // shares and one revoke.
        // Written to the audit ingest table, or already chained into
        // `audit_header`.
        let events: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM ( \
                 SELECT payload::jsonb ->> 'event_name' AS name, \
                        payload::jsonb ->> 'record_id' AS rid \
                 FROM audit_ingest \
                 UNION ALL \
                 SELECT event_name, record_id::text FROM audit_header \
             ) e WHERE rid = $1 AND name IN ('record.share', 'record.unshare') ORDER BY name",
        )
        .bind(&record_id)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(events, ["record.share", "record.share", "record.unshare"]);
    });
}

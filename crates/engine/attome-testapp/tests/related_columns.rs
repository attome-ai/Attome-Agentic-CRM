//! A13-T1: a list reads columns of related records through lookups, one or
//! two hops, as the caller may read them.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// A fresh entity with a text `title` and the given extra fields; its
/// logical name and id.
async fn entity(app: &TestApp, prefix: &str, extra: &[Value]) -> (String, String) {
    let name = format!("{prefix}_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    let mut fields = vec![json!({ "logicalname": "title", "name": "title", "field_type": "text" })];
    fields.extend(extra.iter().cloned());
    for field in fields {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(field),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    (name, id)
}

async fn create(app: &TestApp, entity: &str, body: Value) -> String {
    let (status, record) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    record["id"].as_str().unwrap().to_owned()
}

// feature: A13
// negative: POST /api/v1/query/execute
#[test]
fn list_reads_columns_through_lookups() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // region <- account (region_ref) <- deal (account_ref).
        let (region, region_id) = entity(&app, "rc_region", &[]).await;
        let (account, account_id) = entity(
            &app,
            "rc_account",
            &[json!({ "logicalname": "region_ref", "name": "region_ref",
                      "field_type": "lookup", "lookup_entity_ref": region_id })],
        )
        .await;
        let (deal, _) = entity(
            &app,
            "rc_deal",
            &[json!({ "logicalname": "account_ref", "name": "account_ref",
                      "field_type": "lookup", "lookup_entity_ref": account_id })],
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let north = create(&app, &region, json!({ "title": "North" })).await;
        let acme = create(
            &app,
            &account,
            json!({ "title": "Acme", "region_ref": north }),
        )
        .await;
        create(
            &app,
            &deal,
            json!({ "title": "Big deal", "account_ref": acme }),
        )
        .await;
        create(&app, &deal, json!({ "title": "Lone deal" })).await;

        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/query/execute",
                Some(json!({
                    "entity": deal,
                    "select": ["title", "account_ref.title", "account_ref.region_ref.title"],
                    "include_total": true,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let records = body["data"]["records"].as_array().unwrap();
        let big = records.iter().find(|r| r["title"] == "Big deal").unwrap();
        assert_eq!(big["account_ref.title"], "Acme", "{body}");
        assert_eq!(big["account_ref.region_ref.title"], "North", "{body}");
        let lone = records.iter().find(|r| r["title"] == "Lone deal").unwrap();
        assert!(lone["account_ref.title"].is_null(), "{body}");
        let column = body["data"]["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "account_ref.region_ref.title")
            .expect("the related column is described");
        assert_eq!(column["data_type"], "text");
        assert_eq!(column["is_sortable"], false);

        // A path that is not a lookup, or follows three lookups, is refused.
        for bad in [
            "title.length",
            "account_ref.region_ref.title.x",
            "account_ref.missing",
        ] {
            let (status, body) = app
                .request(
                    Method::POST,
                    "/api/v1/query/execute",
                    Some(json!({ "entity": deal, "select": ["title", bad] })),
                )
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
        }
    });
}

//! A1-T5: a base's index follows its children's writes. Two entities extend
//! one base; a record written in either shows in the base's list after one
//! consumer cycle, with its status and owner, and leaves it when deleted;
//! the rebuild gives the same rows.

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

async fn entity(app: &TestApp, base: Option<Uuid>) -> (Uuid, String) {
    let logicalname = format!("bix_{}", Uuid::now_v7().simple());
    let mut body = json!({ "logicalname": logicalname, "name": "Base index test" });
    if let Some(base) = base {
        body["extends_entity_id"] = Value::String(base.to_string());
    }
    let (code, body) = app
        .request(Method::POST, "/api/v1/admin/entities", Some(body))
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    (body["id"].as_str().unwrap().parse().unwrap(), logicalname)
}

async fn list(app: &TestApp, base: &str, query: &str) -> Value {
    let (code, body) = app
        .request(
            Method::GET,
            &format!("/api/v1/bases/{base}/records{query}"),
            None,
        )
        .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    body
}

// feature: A1
#[test]
fn base_index_follows_child_writes() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (base_id, base) = entity(&app, None).await;
        let (code, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{base_id}/fields"),
                Some(json!({ "logicalname": "status", "name": "Status", "field_type": "text" })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{body}");
        let (_, ticket) = entity(&app, Some(base_id)).await;
        let (_, task) = entity(&app, Some(base_id)).await;
        // Whatever the feed held before, from here on.
        attome_records::base_index::run(&app.state).await.unwrap();

        let mut ids = Vec::new();
        for (child, status) in [(&ticket, "open"), (&task, "done")] {
            let (code, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{child}"),
                    Some(json!({ "status": status })),
                )
                .await;
            assert!(code.is_success(), "{code} {body}");
            ids.push(body["id"].as_str().unwrap().to_owned());
        }
        assert!(attome_records::base_index::run(&app.state).await.unwrap() >= 2);

        let all = list(&app, &base, "").await;
        assert_eq!(all["total"], 2, "{all}");
        let entities: Vec<&str> = all["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["entity"].as_str().unwrap())
            .collect();
        assert!(entities.contains(&ticket.as_str()) && entities.contains(&task.as_str()));
        let open = list(&app, &base, "?status=open").await;
        assert_eq!(open["total"], 1, "{open}");
        assert_eq!(open["items"][0]["id"], ids[0].as_str());
        let mine = list(&app, &base, "?owner=me").await;
        assert_eq!(mine["total"], 2, "the admin owns both: {mine}");

        // A deleted record leaves the index.
        let (code, body) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/{ticket}/{}", ids[0]),
                None,
            )
            .await;
        assert!(code.is_success(), "{code} {body}");
        attome_records::base_index::run(&app.state).await.unwrap();
        let left = list(&app, &base, "").await;
        assert_eq!(left["total"], 1, "{left}");

        // The rebuild gives the same rows.
        assert_eq!(
            attome_records::base_index::reindex(&app.state, &base)
                .await
                .unwrap(),
            1
        );
        assert_eq!(list(&app, &base, "").await["total"], 1);

        let (code, _) = app
            .request(Method::GET, "/api/v1/bases/no_such_base/records", None)
            .await;
        assert_eq!(code, StatusCode::NOT_FOUND);
    });
}

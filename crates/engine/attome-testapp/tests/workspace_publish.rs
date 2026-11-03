//! T5-T4: publishing a workspace. A change made inside the workspace (by an
//! app whose connections put the workspace's schema first, as its own
//! process does) records into the workspace's changeset; publish plans it
//! against live and queues the apply, and a live change to the same object
//! refuses it.

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

const CHANGESET_HEADER: &str = "x-attome-changeset";

/// A live entity; its id.
async fn create_entity(app: &TestApp, name: &str) -> Uuid {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    body["id"].as_str().unwrap().parse().unwrap()
}

/// A workspace: its id, schema and changeset.
async fn create_workspace(app: &TestApp) -> (String, String, String) {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/workspaces",
            Some(json!({ "name": "Publish probe", "data": { "mode": "none" } })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    let changeset = body["changeset_ref"]
        .as_str()
        .expect("a workspace records into a changeset")
        .to_owned();
    (id.to_string(), format!("ws_{}", id.simple()), changeset)
}

/// An app serving the workspace: its schema first, then live's.
async fn inside(live: &TestApp, schema: &str) -> TestApp {
    let live_schema: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(live.db())
        .await
        .unwrap();
    TestApp::start_in_schema(&format!("{schema},{live_schema},public"))
        .await
        .expect("the workspace app")
}

async fn add_field(app: &TestApp, entity: Uuid, field: &str, changeset: Option<&str>) {
    let headers: Vec<(&str, &str)> = changeset
        .map(|c| vec![(CHANGESET_HEADER, c)])
        .unwrap_or_default();
    let (status, body) = app
        .request_with(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity}/fields"),
            &headers,
            Some(json!({ "logicalname": field, "name": field, "field_type": "text" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn has_column(app: &TestApp, schema: &str, table: &str, column: &str) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = $1 AND table_name = $2 AND column_name = $3)",
    )
    .bind(schema)
    .bind(table)
    .bind(column)
    .fetch_one(app.db())
    .await
    .unwrap()
}

async fn live_schema(app: &TestApp) -> String {
    sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(app.db())
        .await
        .unwrap()
}

fn unique(prefix: &str) -> String {
    format!("{prefix}_{}", &Uuid::now_v7().simple().to_string()[20..])
}

// feature: T5
#[test]
fn publishing_applies_the_workspace_changes_live() {
    attome_testkit::run_shared(async {
        let Some(live) = TestApp::start().await else {
            return;
        };
        let entity = unique("wspub");
        let entity_id = create_entity(&live, &entity).await;
        let (id, schema, changeset) = create_workspace(&live).await;
        let workspace = inside(&live, &schema).await;
        let live_name = live_schema(&live).await;

        add_field(&workspace, entity_id, "ws_note", Some(&changeset)).await;
        assert!(has_column(&live, &schema, &entity, "ws_note").await);
        assert!(
            !has_column(&live, &live_name, &entity, "ws_note").await,
            "the field is not live before publish"
        );

        let (status, preview) = live
            .request(
                Method::GET,
                &format!("/api/v1/admin/workspaces/{id}/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["publishable"], true, "{preview}");
        assert_eq!(preview["conflicts"], json!([]), "{preview}");
        assert_eq!(preview["operations"], 1, "{preview}");

        let (status, published) = live
            .request(
                Method::POST,
                &format!("/api/v1/admin/workspaces/{id}/publish"),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{published}");
        assert_eq!(published["workspace"]["status"], "published", "{published}");
        assert_eq!(published["apply"]["status"], "queued", "{published}");
        let apply_ids: Vec<Uuid> = published["apply"]["apply_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().parse().unwrap())
            .collect();
        assert!(!apply_ids.is_empty(), "{published}");

        attome_api::changeset::apply::run_apply_job(&live.state, &apply_ids)
            .await
            .expect("the publish applies");
        assert!(
            has_column(&live, &live_name, &entity, "ws_note").await,
            "the field is live after publish"
        );

        // A published workspace takes no more requests and cannot be
        // published again.
        let (status, _) = live
            .request(
                Method::POST,
                &format!("/api/v1/admin/workspaces/{id}/publish"),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

// feature: T5
#[test]
fn a_conflicting_live_change_refuses_publish() {
    attome_testkit::run_shared(async {
        let Some(live) = TestApp::start().await else {
            return;
        };
        let entity = unique("wsclash");
        let entity_id = create_entity(&live, &entity).await;
        let (id, schema, changeset) = create_workspace(&live).await;
        let workspace = inside(&live, &schema).await;

        add_field(&workspace, entity_id, "stage", Some(&changeset)).await;
        // Live adds the same field after the workspace was made.
        add_field(&live, entity_id, "stage", None).await;

        let (status, preview) = live
            .request(
                Method::GET,
                &format!("/api/v1/admin/workspaces/{id}/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["publishable"], false, "{preview}");
        let conflicts = preview["conflicts"].as_array().unwrap();
        assert_eq!(conflicts.len(), 1, "{preview}");
        assert_eq!(conflicts[0]["op"], "add_field", "{preview}");
        assert_eq!(
            conflicts[0]["target"],
            json!({ "entity": entity, "field": "stage" }),
            "{preview}"
        );

        let (status, refused) = live
            .request(
                Method::POST,
                &format!("/api/v1/admin/workspaces/{id}/publish"),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{refused}");
        let (status, shown): (StatusCode, Value) = live
            .request(Method::GET, &format!("/api/v1/admin/workspaces/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{shown}");
        assert_eq!(
            shown["status"], "open",
            "a refused publish reopens the workspace"
        );
    });
}

// feature: T5
#[test]
fn an_empty_workspace_has_nothing_to_publish() {
    attome_testkit::run_shared(async {
        let Some(live) = TestApp::start().await else {
            return;
        };
        let (id, _, _) = create_workspace(&live).await;
        let (status, preview) = live
            .request(
                Method::GET,
                &format!("/api/v1/admin/workspaces/{id}/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["publishable"], false, "{preview}");
        assert_eq!(preview["plan"], Value::Null, "{preview}");
        let (status, body) = live
            .request(
                Method::POST,
                &format!("/api/v1/admin/workspaces/{id}/publish"),
                Some(json!({})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}

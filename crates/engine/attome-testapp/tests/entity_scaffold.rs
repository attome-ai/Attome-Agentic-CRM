//! A1-T7: an entity's "free on creation" set: a draft main form, a kanban
//! view over its status choice, the import template's columns and its digest
//! entry; a second run leaves what is there.

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

async fn add_field(app: &TestApp, entity_id: &str, field: Value) {
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            Some(field),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

// feature: A1
#[test]
fn scaffold_creates_form_views_and_template() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("scaffold_{}", &Uuid::now_v7().simple().to_string()[20..]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": "Scaffold probe" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        add_field(
            &app,
            &entity_id,
            json!({ "logicalname": "notes", "name": "Notes", "field_type": "text" }),
        )
        .await;
        add_field(
            &app,
            &entity_id,
            json!({ "logicalname": "code", "name": "Code", "field_type": "text", "is_required": true }),
        )
        .await;
        add_field(
            &app,
            &entity_id,
            json!({ "logicalname": "stage", "name": "Stage", "field_type": "choice",
                    "options": { "choices": ["new", "done"], "multi": false } }),
        )
        .await;

        let path = format!("/api/v1/admin/entities/{entity_id}/scaffold");
        let (status, first) = app.request(Method::POST, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["form_created"], true, "{first}");
        assert_eq!(first["kanban_view_created"], true, "{first}");
        let template: Vec<&str> = first["import_template"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(template.first(), Some(&"code"), "required first: {first}");
        assert!(template.contains(&"notes") && template.contains(&"stage"));
        assert!(!template.contains(&"created_at"), "no system columns");
        let stage = first["digest"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "stage")
            .cloned()
            .unwrap();
        assert_eq!(stage["type"], "choice");
        assert!(first["roles_without_access"].as_i64().unwrap() >= 1);

        // The form is a draft in the model store; the board is a kanban view.
        let form_kind: String =
            sqlx::query_scalar("SELECT kind FROM metadata_object WHERE id = $1")
                .bind(Uuid::parse_str(first["form_id"].as_str().unwrap()).unwrap())
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(form_kind, "form");
        let view_kind: String = sqlx::query_scalar("SELECT kind FROM view WHERE id = $1")
            .bind(Uuid::parse_str(first["kanban_view_id"].as_str().unwrap()).unwrap())
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(view_kind, "kanban");

        // Again: what is there is left as it is.
        let (status, again) = app.request(Method::POST, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["form_created"], false);
        assert_eq!(again["kanban_view_created"], false);
        assert_eq!(again["form_id"], first["form_id"]);
        assert_eq!(again["kanban_view_id"], first["kanban_view_id"]);
    });
}

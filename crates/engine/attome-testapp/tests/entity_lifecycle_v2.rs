//! A1-T15 (all but the rollback): an entity extending a base, with a
//! labelled attribute, takes records, shows in the base's list, and has an
//! attribute split into others, the rows converted.
//!
//! The task ends by rolling the publish back and checking the original
//! columns and data; v2 has no Develop-mode publish to roll back
//! (V2-D1502), so that step is not here and the task stays open.

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

async fn create_entity(app: &TestApp, name: &str, base: Option<Uuid>) -> Uuid {
    let mut body = json!({ "logicalname": name, "name": name });
    if let Some(base) = base {
        body["extends_entity_id"] = Value::String(base.to_string());
    }
    let (status, body) = app
        .request(Method::POST, "/api/v1/admin/entities", Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn add_field(app: &TestApp, entity: Uuid, field: Value) {
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity}/fields"),
            Some(field),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

// feature: A1
#[test]
fn entity_lifecycle_end_to_end() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = Uuid::now_v7().simple().to_string();
        let party = format!("lc_party_{}", &token[..12]);
        let customer = format!("lc_customer_{}", &token[..12]);

        // A base, and a Customer that extends it.
        let base = create_entity(&app, &party, None).await;
        add_field(
            &app,
            base,
            json!({ "logicalname": "status", "name": "Status", "field_type": "text" }),
        )
        .await;
        let child = create_entity(&app, &customer, Some(base)).await;

        // The attribute, labelled financial, and the ones it splits into.
        add_field(
            &app,
            child,
            json!({ "logicalname": "iban", "name": "IBAN", "field_type": "text",
                    "sensitivity": "financial", "sensitivity_confirmed": true }),
        )
        .await;
        for field in ["full_name", "first", "family"] {
            add_field(
                &app,
                child,
                json!({ "logicalname": field, "name": field, "field_type": "text" }),
            )
            .await;
        }
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        // Three records through the record API.
        let mut ids = Vec::new();
        for (name, iban) in [
            ("Sara Ali", "SA0380000000608010167519"),
            ("Omar Khaled Nasser", "SA4420000001234567891234"),
            ("Huda Salem", "SA6010000000987654321098"),
        ] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{customer}"),
                    Some(json!({ "status": "open", "full_name": name, "iban": iban })),
                )
                .await;
            assert!(status.is_success(), "{status} {body}");
            ids.push(body["id"].as_str().unwrap().to_owned());
        }
        attome_records::base_index::run(&app.state).await.unwrap();

        // The base's list shows all three.
        let (status, list) = app
            .request(Method::GET, &format!("/api/v1/bases/{party}/records"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert_eq!(list["total"], 3, "{list}");

        // Split the full name into first and family.
        let split = json!({
            "source": "full_name",
            "targets": [
                { "field": "first", "expression": "word(full_name, 1)" },
                { "field": "family",
                  "expression": "if(word_count(full_name) >= 2, word(full_name, -1), \"\")" },
            ]
        });
        let (status, queued) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{child}/refactor"),
                Some(split),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
        let run: Uuid = queued["run_id"].as_str().unwrap().parse().unwrap();
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .unwrap();

        let rows: Vec<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(&format!(
            "SELECT first, family, full_name FROM \"{customer}\" ORDER BY full_name"
        ))
        .fetch_all(app.db())
        .await
        .unwrap();
        let some = |s: &str| Some(s.to_owned());
        assert_eq!(
            rows,
            vec![
                (some("Huda"), some("Salem"), some("Huda Salem")),
                (some("Omar"), some("Nasser"), some("Omar Khaled Nasser")),
                (some("Sara"), some("Ali"), some("Sara Ali")),
            ]
        );

        // The source is kept, and the labelled attribute's values are intact.
        let kept: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM \"{customer}\" WHERE iban LIKE 'SA%'"
        ))
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(kept, 3);
        let label: Option<String> = sqlx::query_scalar(
            "SELECT sensitivity FROM attribute_info \
              WHERE entity_ref = $1 AND logicalname = 'iban'",
        )
        .bind(child)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(label.as_deref(), Some("financial"));
    });
}

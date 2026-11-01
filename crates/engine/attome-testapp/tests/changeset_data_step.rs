//! A22-T4: a changeset's `data_step` of kind `split` queues A1-T8's split
//! run when applied, the run fills the targets, and applying the changeset
//! again queues nothing more.

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

/// An entity with the text fields `full_name`, `first_name` and
/// `last_name`; its logical name and id.
async fn entity(app: &TestApp) -> (String, String) {
    let logicalname = format!("split_{}", Uuid::now_v7().simple());
    let (code, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": logicalname, "name": "Split test" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap().to_owned();
    for field in ["full_name", "first_name", "last_name"] {
        let (code, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(json!({ "logicalname": field, "name": field, "field_type": "text" })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{body}");
    }
    (logicalname, id)
}

/// A closed changeset document with one split step on `entity`.
fn split_changeset(entity: &str) -> Value {
    let mut doc = json!({
        "author": "tests",
        "checksum": format!("sha256:{}", "0".repeat(64)),
        "closed_at": "2026-11-01T00:00:00Z",
        "description": "A22-T4 test: split a full name.",
        "format": "attome-changeset/v1",
        "id": Uuid::now_v7(),
        "layer": "product",
        "name": "split-full-name",
        "opened_at": "2026-11-01T00:00:00Z",
        "requires": { "modules": ["core"], "platform": ">=0.1.0" },
        "scope": format!("split-{}", Uuid::now_v7().simple()),
        "seq": 1,
        "title": "Split a full name",
        "operations": [{
            "op": "data_step",
            "phase": "expand",
            "seq": 1,
            "target": { "entity": entity },
            "args": {
                "kind": "split",
                "source": "full_name",
                "targets": [
                    { "field": "first_name", "expression": "word(full_name, 1)" },
                    { "field": "last_name", "expression": "word(full_name, 4)" }
                ]
            }
        }]
    });
    let checksum = attome_api::changeset::jcs::document_checksum(&doc).expect("checksum");
    doc["checksum"] = json!(checksum);
    doc
}

// feature: A22
#[test]
fn a_split_data_step_runs_once_per_operation() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (table, _) = entity(&app).await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let (code, created) = app
            .request(
                Method::POST,
                &format!("/api/v1/{table}"),
                Some(json!({ "full_name": "Sara Ahmed Al Qahtani" })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{created}");
        let record: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        let doc = split_changeset(&table);
        let changeset: Uuid = doc["id"].as_str().unwrap().parse().unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &doc)
            .await
            .expect("the changeset applies");
        attome_api::changeset::boot::apply_pack_document(&app.state, &doc)
            .await
            .expect("applying it again is a no-op");
        let runs: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, source FROM data_step_run WHERE changeset_id = $1 AND kind = 'split'",
        )
        .bind(changeset)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(runs.len(), 1, "one run for one operation");
        assert_eq!(runs[0].1, "apply");

        attome_api::field_changes::run_field_run(&app.state, runs[0].0)
            .await
            .expect("the run");
        let (first, last): (Option<String>, Option<String>) = sqlx::query_as(&format!(
            "SELECT first_name::text, last_name::text FROM \"{table}\" WHERE id = $1"
        ))
        .bind(record)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(first.as_deref(), Some("Sara"));
        assert_eq!(last.as_deref(), Some("Qahtani"));
    });
}

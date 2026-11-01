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

// feature: A22
#[test]
fn copy_and_set_default_fill_the_empty_rows() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (table, _) = entity(&app).await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let mut ids = Vec::new();
        for full_name in [Some("Omar Saleh"), None] {
            let (code, created) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{table}"),
                    Some(json!({ "full_name": full_name })),
                )
                .await;
            assert_eq!(code, StatusCode::CREATED, "{created}");
            ids.push(created["id"].as_str().unwrap().parse::<Uuid>().unwrap());
        }

        let mut doc = split_changeset(&table);
        doc["name"] = json!("fill-names");
        doc["operations"] = json!([
            { "op": "data_step", "phase": "expand", "seq": 1, "target": { "entity": table },
              "args": { "kind": "copy", "from": "full_name", "to": "first_name" } },
            { "op": "data_step", "phase": "expand", "seq": 2, "target": { "entity": table },
              "args": { "kind": "set_default", "field": "first_name", "value": "Unknown" } }
        ]);
        doc["checksum"] = json!(format!("sha256:{}", "0".repeat(64)));
        let checksum = attome_api::changeset::jcs::document_checksum(&doc).expect("checksum");
        doc["checksum"] = json!(checksum);
        let changeset: Uuid = doc["id"].as_str().unwrap().parse().unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &doc)
            .await
            .expect("the changeset applies");
        let runs: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM data_step_run WHERE changeset_id = $1 ORDER BY op_seq",
        )
        .bind(changeset)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(runs.len(), 2);
        for run in runs {
            attome_api::field_changes::run_field_run(&app.state, run)
                .await
                .expect("the run");
        }
        let first: Vec<Option<String>> = sqlx::query_scalar(&format!(
            "SELECT first_name::text FROM \"{table}\" WHERE id = ANY($1) ORDER BY id"
        ))
        .bind(&ids)
        .fetch_all(app.db())
        .await
        .unwrap();
        let mut ordered = ids.clone();
        ordered.sort();
        let named = ordered.iter().position(|id| *id == ids[0]).unwrap();
        assert_eq!(first[named].as_deref(), Some("Omar Saleh"), "copied");
        assert_eq!(
            first[1 - named].as_deref(),
            Some("Unknown"),
            "the default fills the rest"
        );
    });
}

// feature: A22
#[test]
fn map_values_replaces_only_the_mapped_values() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (table, _) = entity(&app).await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let mut ids = Vec::new();
        for first_name in ["omar", "sara"] {
            let (code, created) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{table}"),
                    Some(json!({ "first_name": first_name })),
                )
                .await;
            assert_eq!(code, StatusCode::CREATED, "{created}");
            ids.push(created["id"].as_str().unwrap().parse::<Uuid>().unwrap());
        }
        let mut doc = split_changeset(&table);
        doc["name"] = json!("map-names");
        doc["operations"] = json!([
            { "op": "data_step", "phase": "expand", "seq": 1, "target": { "entity": table },
              "args": { "kind": "map_values", "field": "first_name",
                        "map": { "omar": "Omar" }, "on_unmapped": "report" } }
        ]);
        doc["checksum"] = json!(format!("sha256:{}", "0".repeat(64)));
        let checksum = attome_api::changeset::jcs::document_checksum(&doc).expect("checksum");
        doc["checksum"] = json!(checksum);
        let changeset: Uuid = doc["id"].as_str().unwrap().parse().unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &doc)
            .await
            .expect("the changeset applies");
        let run: Uuid = sqlx::query_scalar("SELECT id FROM data_step_run WHERE changeset_id = $1")
            .bind(changeset)
            .fetch_one(app.db())
            .await
            .unwrap();
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .expect("the run");
        for (id, want) in ids.iter().zip(["Omar", "sara"]) {
            let got: Option<String> = sqlx::query_scalar(&format!(
                "SELECT first_name::text FROM \"{table}\" WHERE id = $1"
            ))
            .bind(id)
            .fetch_one(app.db())
            .await
            .unwrap();
            assert_eq!(got.as_deref(), Some(want));
        }
    });
}

// feature: A22
#[test]
fn convert_fills_a_number_from_text_and_counts_what_does_not_convert() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (table, id) = entity(&app).await;
        let (code, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(json!({ "logicalname": "amount", "name": "Amount", "field_type": "number" })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{body}");
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let mut ids = Vec::new();
        for text in ["42.5", "not a number"] {
            let (code, created) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{table}"),
                    Some(json!({ "last_name": text })),
                )
                .await;
            assert_eq!(code, StatusCode::CREATED, "{created}");
            ids.push(created["id"].as_str().unwrap().parse::<Uuid>().unwrap());
        }
        let mut doc = split_changeset(&table);
        doc["name"] = json!("convert-amounts");
        doc["operations"] = json!([
            { "op": "data_step", "phase": "expand", "seq": 1, "target": { "entity": table },
              "args": { "kind": "convert", "from": "last_name", "to": "amount",
                        "from_type": "text", "to_type": "number" } }
        ]);
        doc["checksum"] = json!(format!("sha256:{}", "0".repeat(64)));
        let checksum = attome_api::changeset::jcs::document_checksum(&doc).expect("checksum");
        doc["checksum"] = json!(checksum);
        let changeset: Uuid = doc["id"].as_str().unwrap().parse().unwrap();
        attome_api::changeset::boot::apply_pack_document(&app.state, &doc)
            .await
            .expect("the changeset applies");
        let run: Uuid = sqlx::query_scalar("SELECT id FROM data_step_run WHERE changeset_id = $1")
            .bind(changeset)
            .fetch_one(app.db())
            .await
            .unwrap();
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .expect("the run");
        let amounts: Vec<Option<String>> = sqlx::query_scalar(&format!(
            "SELECT amount::text FROM \"{table}\" WHERE id = ANY($1) ORDER BY id"
        ))
        .bind(&ids)
        .fetch_all(app.db())
        .await
        .unwrap();
        let mut sorted = ids.clone();
        sorted.sort();
        let converted = sorted.iter().position(|i| *i == ids[0]).unwrap();
        assert_eq!(
            amounts[converted]
                .as_deref()
                .and_then(|a| a.parse::<f64>().ok()),
            Some(42.5)
        );
        assert_eq!(
            amounts[1 - converted],
            None,
            "a value that does not convert"
        );
    });
}

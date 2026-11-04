//! Y2-T4: the orphan scan counts, per lookup field, the rows whose value
//! names no record of the target; on the request for a small table and as a
//! durable `orphan_scan` run. The orphan is made by hand on the throwaway
//! test database (the record API refuses one).

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

async fn create_entity(app: &TestApp, name: &str) -> Uuid {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn add_field(app: &TestApp, entity_id: Uuid, field: Value) {
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            Some(field),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn create_record(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, created) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["id"].as_str().unwrap().parse().unwrap()
}

// feature: Y2
#[test]
fn orphan_scan_counts_missing_targets() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = Uuid::now_v7().simple().to_string();
        let parent = format!("orph_parent_{}", &token[..12]);
        let child = format!("orph_child_{}", &token[..12]);
        let parent_id = create_entity(&app, &parent).await;
        add_field(
            &app,
            parent_id,
            json!({ "logicalname": "code", "name": "code", "field_type": "text" }),
        )
        .await;
        let child_id = create_entity(&app, &child).await;
        add_field(
            &app,
            child_id,
            json!({ "logicalname": "note", "name": "note", "field_type": "text" }),
        )
        .await;
        add_field(
            &app,
            child_id,
            json!({ "logicalname": "parent_ref", "name": "parent_ref",
                    "field_type": "lookup", "lookup_entity_ref": parent_id }),
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let p = create_record(&app, &parent, json!({ "code": "P1" })).await;
        let kept = create_record(&app, &child, json!({ "note": "a", "parent_ref": p })).await;
        let lost = create_record(&app, &child, json!({ "note": "b", "parent_ref": p })).await;
        create_record(&app, &child, json!({ "note": "c" })).await;
        // Throwaway database: point one row at a record that never existed.
        sqlx::query(&format!(
            "UPDATE \"{child}\" SET parent_ref = $1 WHERE id = $2"
        ))
        .bind(Uuid::now_v7())
        .bind(lost)
        .execute(app.db())
        .await
        .unwrap();

        let path = format!("/api/v1/admin/entities/{child_id}/orphans");
        let (status, body) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let item = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["attribute"] == "parent_ref")
            .unwrap_or_else(|| panic!("parent_ref is listed: {body}"));
        assert_eq!(item["attribute"], "parent_ref");
        assert_eq!(item["target_entity"], parent.as_str());
        assert_eq!(item["orphans"], 1, "{body}");
        assert!(item["run_id"].is_null());
        // The scan never touches the values.
        let still: Option<Uuid> =
            sqlx::query_scalar(&format!("SELECT parent_ref FROM \"{child}\" WHERE id = $1"))
                .bind(kept)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(still, Some(p));

        // The durable scan reaches the same count; a second request while it
        // is queued returns the same run.
        let scan = "/api/v1/admin/data-step-runs/orphan-scans";
        let (status, queued) = app
            .request(Method::POST, scan, Some(json!({ "entity_id": child_id })))
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
        assert_eq!(queued["created"], true);
        let run_id: Uuid = queued["run_id"].as_str().unwrap().parse().unwrap();
        let (_, again) = app
            .request(Method::POST, scan, Some(json!({ "entity_id": child_id })))
            .await;
        assert_eq!(again["run_id"], queued["run_id"]);
        assert_eq!(again["created"], false);
        attome_api::field_changes::run_field_run(&app.state, run_id)
            .await
            .unwrap();
        let (status, spec): (String, Value) =
            sqlx::query_as("SELECT status, spec FROM data_step_run WHERE id = $1")
                .bind(run_id)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(status, "succeeded");
        let at = spec["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|c| c["attribute"] == "parent_ref")
            .unwrap();
        assert_eq!(spec["orphans"][at], 1, "{spec}");

        // The parent has no lookup of its own to list; an unknown entity is a 404.
        let (_, none) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/entities/{parent_id}/orphans"),
                None,
            )
            .await;
        assert!(
            none["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|i| i["attribute"] != "parent_ref"),
            "{none}"
        );
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/entities/{}/orphans", Uuid::now_v7()),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

/// Y2-T5: a source and a target entity, and the source's `target_ref`
/// lookup with `rule`; answers the source's name and id and the field's id.
async fn keyed_pair(app: &TestApp, rule: &str) -> (String, Uuid, String) {
    let token = Uuid::now_v7().simple().to_string();
    let target = format!("fk_tgt_{}", &token[..12]);
    let source = format!("fk_src_{}", &token[..12]);
    let target_id = create_entity(app, &target).await;
    let source_id = create_entity(app, &source).await;
    let (status, field) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{source_id}/fields"),
            Some(json!({
                "logicalname": "target_ref", "name": "Target", "field_type": "lookup",
                "lookup_entity_ref": target_id, "on_target_delete": rule,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{field}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    (source, source_id, field["id"].as_str().unwrap().to_owned())
}

/// A record of `source` (through the record API), then its lookup pointed
/// at a record that never existed (by hand, on the throwaway database).
async fn orphan_row(app: &TestApp, source: &str) -> Result<(), sqlx::Error> {
    let id = create_record(app, source, json!({ "target_ref": null })).await;
    sqlx::query(&format!(
        "UPDATE \"{source}\" SET target_ref = $1 WHERE id = $2"
    ))
    .bind(Uuid::now_v7())
    .bind(id)
    .execute(app.db())
    .await
    .map(|_| ())
}

// feature: Y2
#[test]
fn new_lookup_has_valid_fk() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (source, source_id, field_id) = keyed_pair(&app, "restrict").await;
        let path = format!("/api/v1/admin/entities/{source_id}/fields/{field_id}/foreign-key");
        let (status, key) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{key}");
        assert_eq!(key["state"], "valid", "{key}");
        assert_eq!(key["keyed"], true, "{key}");
        // The database itself now refuses a value naming no record.
        assert!(orphan_row(&app, &source).await.is_err());
    });
}

// feature: Y2
#[test]
fn orphan_blocks_validation() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // An orphan lookup keeps no key, so a value naming nothing stays.
        let (source, source_id, field_id) = keyed_pair(&app, "orphan").await;
        let path = format!("/api/v1/admin/entities/{source_id}/fields/{field_id}/foreign-key");
        let (status, key) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{key}");
        assert_eq!(key["state"], "none", "{key}");
        let (status, body) = app.request(Method::POST, &path, None).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        // Throwaway database: an orphan value, then the rule made restrict.
        orphan_row(&app, &source).await.unwrap();
        sqlx::query("UPDATE attribute_info SET on_target_delete = 'restrict' WHERE id = $1")
            .bind(Uuid::parse_str(&field_id).unwrap())
            .execute(app.db())
            .await
            .unwrap();

        let (status, body) = app.request(Method::POST, &path, None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.to_string().contains("orphan"), "{body}");
        let (_, key) = app.request(Method::GET, &path, None).await;
        assert_eq!(key["state"], "not_valid", "{key}");
    });
}

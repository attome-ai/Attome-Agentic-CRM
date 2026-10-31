//! Q19-T1: an encrypted attribute is stored sealed, reads back in clear
//! through the record API and `query/execute`, answers equality through its
//! blind index, refuses a range, and cannot be turned off later.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::KeyRing;
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

const NATIONAL_ID: &str = "784-1990-1234567-1";

async fn start() -> Option<TestApp> {
    TestApp::start_with(|config| {
        config.storage.attribute_encryption_key = KeyRing::single("07".repeat(32));
    })
    .await
}

/// An entity with `national_id`, encrypted in `mode`: its name and its id.
async fn entity(app: &TestApp, mode: &str) -> (String, String, String) {
    let name = format!("enc_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    let (status, field) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{id}/fields"),
            Some(json!({
                "logicalname": "national_id", "name": "National id", "field_type": "text",
                "sensitivity": "personal", "options": { "encryption": { "mode": mode } },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{field}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    (name, id, field["id"].as_str().unwrap().to_owned())
}

async fn create(app: &TestApp, entity: &str, value: &str) -> String {
    let (status, record) = app
        .request(
            Method::POST,
            &format!("/api/v1/{entity}"),
            Some(json!({ "national_id": value })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    record["id"].as_str().unwrap().to_owned()
}

async fn query(app: &TestApp, entity: &str, op: &str, value: Value) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        "/api/v1/query/execute",
        Some(json!({ "entity": entity,
                     "filters": [{ "field": "national_id", "op": op, "value": value }] })),
    )
    .await
}

fn stored(row: &Value) -> &str {
    row["national_id"].as_str().unwrap()
}

// feature: Q19
#[test]
fn randomised_value_is_sealed_at_rest_and_reads_in_clear() {
    attome_testkit::run_shared(async {
        let Some(app) = start().await else {
            return;
        };
        let (name, _, _) = entity(&app, "randomised").await;
        let first = create(&app, &name, NATIONAL_ID).await;
        let second = create(&app, &name, NATIONAL_ID).await;

        let at_rest: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT national_id FROM {} ORDER BY id",
            attome_core::quote_ident(&name)
        ))
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(at_rest.len(), 2);
        assert_ne!(at_rest[0], at_rest[1], "equal values look different");
        assert!(at_rest.iter().all(|value| !value.contains("784")));

        let (status, read) = app
            .request(Method::GET, &format!("/api/v1/{name}/{first}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{read}");
        assert_eq!(stored(&read["data"]), NATIONAL_ID, "{read}");

        // Update seals the new value for the same row.
        let (_, current) = app
            .request(Method::GET, &format!("/api/v1/{name}/{second}"), None)
            .await;
        let version = current["row_version"].to_string();
        let if_match = format!("\"{}\"", version.trim_matches('"'));
        let (status, updated) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{name}/{second}"),
                &[("if-match", if_match.as_str())],
                Some(json!({ "national_id": "changed" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{updated}");
        assert_eq!(stored(&updated["data"]), "changed", "{updated}");

        let (status, refused) = query(&app, &name, "eq", json!(NATIONAL_ID)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");

        // The audit trail records the change, never the value.
        let leaked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_detail WHERE old_value LIKE '%784%' \
                 OR new_value LIKE '%784%' OR new_value = 'changed'",
        )
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(leaked, 0, "a clear value reached the audit trail");
    });
}

// feature: Q19
#[test]
fn deterministic_value_answers_equality_through_its_blind_index() {
    attome_testkit::run_shared(async {
        let Some(app) = start().await else {
            return;
        };
        let (name, _, _) = entity(&app, "deterministic").await;
        let id = create(&app, &name, NATIONAL_ID).await;
        create(&app, &name, "someone else").await;

        let (status, found) = query(&app, &name, "eq", json!(NATIONAL_ID.to_uppercase())).await;
        assert_eq!(status, StatusCode::OK, "{found}");
        let records = found["data"]["records"].as_array().unwrap();
        assert_eq!(records.len(), 1, "{found}");
        assert_eq!(records[0]["id"], json!(id));
        assert_eq!(stored(&records[0]), NATIONAL_ID, "a list reads in clear");

        let (_, others) = query(&app, &name, "neq", json!(NATIONAL_ID)).await;
        assert_eq!(others["data"]["records"].as_array().unwrap().len(), 1);
        let (_, listed) = query(&app, &name, "in", json!([NATIONAL_ID, "someone else"])).await;
        assert_eq!(listed["data"]["records"].as_array().unwrap().len(), 2);

        let (status, range) = query(&app, &name, "gt", json!("a")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{range}");
    });
}

// feature: Q19
#[test]
fn encryption_needs_a_label_and_cannot_be_changed_later() {
    attome_testkit::run_shared(async {
        let Some(app) = start().await else {
            return;
        };
        let (_, entity_id, field_id) = entity(&app, "randomised").await;
        let fields = format!("/api/v1/admin/entities/{entity_id}/fields");
        let (status, refused) = app
            .request(
                Method::POST,
                &fields,
                Some(json!({
                    "logicalname": "plain", "name": "Plain", "field_type": "text",
                    "options": { "encryption": { "mode": "randomised" } },
                })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");

        let (status, refused) = app
            .request(
                Method::PATCH,
                &format!("{fields}/{field_id}"),
                Some(json!({ "options": {} })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
    });
}

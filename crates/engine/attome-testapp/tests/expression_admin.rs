//! Z11-T12: `/api/v1/admin/expressions` over HTTP. Validate reports an
//! error with the exact span it points at, explains a sample record's value
//! with its evaluation trace, and the spec lists the V2 functions. A9-T4: a
//! path through a lookup compiles and previews its related value.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// A fresh entity with a text `title` and a number `amount`.
async fn entity(app: &TestApp) -> String {
    entity_with_id(app).await.0
}

/// [`entity`], with the entity's id.
async fn entity_with_id(app: &TestApp) -> (String, String) {
    let entity = format!("expr_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": entity, "name": entity })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let entity_id = created["id"].as_str().unwrap().to_owned();
    for (name, field_type) in [("title", "text"), ("amount", "number")] {
        let (status, field) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": name, "name": name, "field_type": field_type })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    (entity, entity_id)
}

// feature: Z11
// negative: POST /api/v1/admin/expressions/validate
#[test]
fn validate_reports_span_of_error() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = entity(&app).await;
        let expression = r#"amount > 10 and title + 1 == "x""#;
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/expressions/validate",
                Some(json!({ "expression": expression, "entity": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], false, "{body}");
        let d = &body["diagnostics"][0];
        assert_eq!(d["code"], "rules.type.mismatch", "{body}");
        let (start, end) = (
            d["start"].as_u64().unwrap() as usize,
            d["end"].as_u64().unwrap() as usize,
        );
        assert_eq!(&expression[start..end], "title + 1", "{body}");

        // A good one: its type, and whether it runs in the database.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/expressions/validate",
                Some(json!({ "expression": "round(amount * 1.15, 2) > 100", "entity": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true, "{body}");
        assert_eq!(body["result_type"], "bool");
        assert_eq!(
            body["sql_translatable"], false,
            "rounding stays in the evaluator"
        );
        assert!(body["sql_reason"].is_string(), "{body}");

        // An unknown language version is the caller's error.
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/expressions/validate",
                Some(json!({ "expression": "amount > 1", "entity": entity, "language_version": "v9" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: Z11
#[test]
fn validate_explains_sample_value() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = entity(&app).await;
        let (status, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "title": "Big order", "amount": 1500 })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");
        let record_id = record["id"].as_str().unwrap().to_owned();
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/expressions/validate",
                Some(json!({
                    "expression": r#"if(amount > 1000, "large", "small")"#,
                    "entity": entity,
                    "sample_record_id": record_id,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true, "{body}");
        assert_eq!(body["result_type"], "text");
        assert_eq!(body["value"], "large", "{body}");
        let trace = body["trace"].as_array().unwrap();
        assert!(
            trace
                .iter()
                .any(|t| t["expr"] == "amount" && t["value"] == json!(1500.0)),
            "{body}"
        );

        // A record that does not exist is a 404, not a value.
        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/expressions/validate",
                Some(json!({
                    "expression": "amount > 1",
                    "entity": entity,
                    "sample_record_id": Uuid::now_v7(),
                })),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

// feature: A9
#[test]
fn validate_reads_through_a_lookup() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (parent, parent_id) = entity_with_id(&app).await;
        let (child, child_id) = entity_with_id(&app).await;
        let (status, field) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{child_id}/fields"),
                Some(json!({ "logicalname": "parent_ref", "name": "parent_ref",
                             "field_type": "lookup", "lookup_entity_ref": parent_id })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let (status, region) = app
            .request(
                Method::POST,
                &format!("/api/v1/{parent}"),
                Some(json!({ "title": "North", "amount": 1 })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{region}");
        let (status, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{child}"),
                Some(json!({ "title": "Order", "amount": 5, "parent_ref": region["id"] })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{record}");

        // The path compiles, and the sample's value is the related record's.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/expressions/validate",
                Some(json!({
                    "expression": "parent_ref.title",
                    "entity": child,
                    "sample_record_id": record["id"],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], true, "{body}");
        assert_eq!(body["result_type"], "text", "{body}");
        assert_eq!(body["value"], "North", "{body}");

        // A field the related entity does not have is still an error.
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/expressions/validate",
                Some(json!({ "expression": "parent_ref.missing", "entity": child })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["ok"], false, "{body}");
    });
}

// feature: Z11
#[test]
fn spec_lists_normalize_ar() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (status, body) = app
            .request(
                Method::GET,
                "/api/v1/admin/expressions/spec?version=v2",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["version"], "v2");
        let functions = body["functions"].as_array().unwrap();
        let normalize = functions
            .iter()
            .find(|f| f["name"] == "normalize_ar")
            .expect("normalize_ar is listed");
        assert_eq!(normalize["since"], "v2");
        assert!(normalize["description_ar"].as_str().unwrap().len() > 10);
        assert!(!body["grammar"].as_array().unwrap().is_empty());

        let (status, body) = app
            .request(
                Method::GET,
                "/api/v1/admin/expressions/spec?version=v1",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !body["functions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["name"] == "normalize_ar"),
            "V1 does not have normalize_ar"
        );
    });
}

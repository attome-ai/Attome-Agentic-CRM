//! A10-T2: a fast rollup follows its related records: adding invoices
//! updates the account's total within one tick, and moving an invoice to
//! another account updates both.

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

async fn entity(app: &TestApp, name: &str) -> String {
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["id"].as_str().unwrap().to_owned()
}

async fn field(app: &TestApp, entity_id: &str, body: Value) {
    let (status, created) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            Some(body),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
}

async fn create(app: &TestApp, entity: &str, body: Value) -> Value {
    let (status, record) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    record
}

/// Ticks until the consumer has read everything waiting.
async fn catch_up(app: &TestApp) {
    for _ in 0..200 {
        let read = attome_records::rollup_fast::tick(&app.state)
            .await
            .expect("a tick");
        if read < 1_000 {
            return;
        }
    }
    panic!("the rollup consumer did not catch up");
}

async fn total(app: &TestApp, table: &str, id: &Value) -> Option<f64> {
    let text: Option<String> = sqlx::query_scalar(&format!(
        "SELECT total::text FROM \"{table}\" WHERE id = $1"
    ))
    .bind(Uuid::parse_str(id.as_str().unwrap()).unwrap())
    .fetch_one(app.db())
    .await
    .unwrap();
    text.map(|t| t.parse().unwrap())
}

// feature: A10
#[test]
fn rollup_fast_follows_added_and_moved_records() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let tag = &Uuid::now_v7().simple().to_string()[..12];
        let (account, invoice) = (format!("rf_account_{tag}"), format!("rf_invoice_{tag}"));
        let account_id = entity(&app, &account).await;
        let invoice_id = entity(&app, &invoice).await;
        field(
            &app,
            &account_id,
            json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
        )
        .await;
        field(
            &app,
            &invoice_id,
            json!({ "logicalname": "amount", "name": "amount", "field_type": "number" }),
        )
        .await;
        field(
            &app,
            &invoice_id,
            json!({ "logicalname": "account_ref", "name": "account_ref",
                    "field_type": "lookup", "lookup_entity_ref": account_id }),
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        field(
            &app,
            &account_id,
            json!({ "logicalname": "total", "name": "total", "field_type": "rollup",
                    "options": {
                        "function": "sum",
                        "path": [{ "entity": invoice, "via": "account_ref" }],
                        "attribute": "amount",
                        "result_type": "number",
                    } }),
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        catch_up(&app).await;

        let acme = create(&app, &account, json!({ "title": "Acme" })).await;
        let globex = create(&app, &account, json!({ "title": "Globex" })).await;
        create(
            &app,
            &invoice,
            json!({ "amount": 10, "account_ref": acme["id"] }),
        )
        .await;
        let moved = create(
            &app,
            &invoice,
            json!({ "amount": 15, "account_ref": acme["id"] }),
        )
        .await;
        catch_up(&app).await;
        assert_eq!(total(&app, &account, &acme["id"]).await, Some(25.0));

        // A client may not write the rollup itself.
        let v = format!("\"{}\"", acme["row_version"]);
        let (status, _) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{account}/{}", acme["id"].as_str().unwrap()),
                &[("if-match", v.as_str())],
                Some(json!({ "total": 1 })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Moved to Globex: both accounts follow.
        let v = format!("\"{}\"", moved["row_version"]);
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{invoice}/{}", moved["id"].as_str().unwrap()),
                &[("if-match", v.as_str())],
                Some(json!({ "account_ref": globex["id"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        catch_up(&app).await;
        assert_eq!(total(&app, &account, &acme["id"]).await, Some(10.0));
        assert_eq!(total(&app, &account, &globex["id"]).await, Some(15.0));
    });
}

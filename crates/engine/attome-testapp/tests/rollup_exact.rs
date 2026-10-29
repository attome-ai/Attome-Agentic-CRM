//! A10-T3: an exact rollup stays right under concurrent writes to one
//! parent, and follows deletes, restores and moves in the same write.

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

async fn column(app: &TestApp, table: &str, column: &str, id: &Value) -> Option<f64> {
    let text: Option<String> = sqlx::query_scalar(&format!(
        "SELECT \"{column}\"::text FROM \"{table}\" WHERE id = $1"
    ))
    .bind(Uuid::parse_str(id.as_str().unwrap()).unwrap())
    .fetch_one(app.db())
    .await
    .unwrap();
    text.map(|t| t.parse().unwrap())
}

// feature: A10
#[test]
fn rollup_exact_holds_under_concurrent_writes() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let tag = &Uuid::now_v7().simple().to_string()[..12];
        let (account, invoice) = (format!("rx_account_{tag}"), format!("rx_invoice_{tag}"));
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
        for (name, function, attribute) in [
            ("total", "sum", Some("amount")),
            ("invoices", "count", None),
        ] {
            let mut options = json!({
                "function": function,
                "path": [{ "entity": invoice, "via": "account_ref" }],
                "mode": "exact",
                "result_type": "number",
            });
            if let Some(attribute) = attribute {
                options["attribute"] = json!(attribute);
            }
            field(
                &app,
                &account_id,
                json!({ "logicalname": name, "name": name, "field_type": "rollup", "options": options }),
            )
            .await;
        }
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let acme = create(&app, &account, json!({ "title": "Acme" })).await;
        let globex = create(&app, &account, json!({ "title": "Globex" })).await;

        // Twenty invoices of 1..=20 written at once to the same account.
        let mut writes = Vec::new();
        for amount in 1..=20 {
            let app = app.clone();
            let invoice = invoice.clone();
            let parent = acme["id"].clone();
            writes.push(tokio::spawn(async move {
                let (status, body) = app
                    .request(
                        Method::POST,
                        &format!("/api/v1/{invoice}"),
                        Some(json!({ "amount": amount, "account_ref": parent })),
                    )
                    .await;
                assert_eq!(status, StatusCode::CREATED, "{body}");
                body
            }));
        }
        let mut created = Vec::new();
        for write in writes {
            created.push(write.await.unwrap());
        }
        assert_eq!(
            column(&app, &account, "total", &acme["id"]).await,
            Some(210.0)
        );
        assert_eq!(
            column(&app, &account, "invoices", &acme["id"]).await,
            Some(20.0)
        );

        // A delete takes the invoice back out; a restore puts it back.
        let first = &created[0];
        let id = first["id"].as_str().unwrap();
        let amount = first["amount"]
            .as_f64()
            .unwrap_or_else(|| first["amount"].as_str().unwrap().parse().unwrap());
        let (status, body) = app
            .request(Method::DELETE, &format!("/api/v1/{invoice}/{id}"), None)
            .await;
        assert!(status.is_success(), "{status} {body}");
        assert_eq!(
            column(&app, &account, "total", &acme["id"]).await,
            Some(210.0 - amount)
        );
        assert_eq!(
            column(&app, &account, "invoices", &acme["id"]).await,
            Some(19.0)
        );
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{invoice}/{id}/restore"),
                None,
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        assert_eq!(
            column(&app, &account, "total", &acme["id"]).await,
            Some(210.0)
        );

        // Moved to Globex in one write: both totals follow.
        let second = &created[1];
        let (status, current) = app
            .request(
                Method::GET,
                &format!("/api/v1/{invoice}/{}", second["id"].as_str().unwrap()),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{current}");
        let version = current["row_version"]
            .as_i64()
            .or_else(|| current["data"]["row_version"].as_i64())
            .expect("a row version");
        let v = format!("\"{version}\"");
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{invoice}/{}", second["id"].as_str().unwrap()),
                &[("if-match", v.as_str())],
                Some(json!({ "account_ref": globex["id"] })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let moved: f64 = second["amount"]
            .as_f64()
            .unwrap_or_else(|| second["amount"].as_str().unwrap().parse().unwrap());
        assert_eq!(
            column(&app, &account, "total", &acme["id"]).await,
            Some(210.0 - moved)
        );
        assert_eq!(
            column(&app, &account, "total", &globex["id"]).await,
            Some(moved)
        );
        assert_eq!(
            column(&app, &account, "invoices", &globex["id"]).await,
            Some(1.0)
        );
    });
}

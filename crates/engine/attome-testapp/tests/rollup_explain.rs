//! A10-T5: a rollup explains itself: the related records it counts, listed
//! when the caller may read them and only counted when not.

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

async fn create(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, record) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    Uuid::parse_str(record["id"].as_str().unwrap()).unwrap()
}

async fn grant(app: &TestApp, user: Uuid, key: &str) {
    attome_security::db::ensure_privilege(
        app.db(),
        key,
        key,
        "test grant",
        attome_core::changeset::Layer::Project,
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO user_account_mm_privilege (id, user_ref, privilege_ref, is_active, created_at) \
         SELECT uuidv7(), $1, id, true, now() FROM privilege WHERE key = $2",
    )
    .bind(user)
    .bind(key)
    .execute(app.db())
    .await
    .unwrap();
}

// feature: A10
// negative: GET /api/v1/{entity}/{id}/rollups/{attribute}/explain
#[test]
fn rollup_explain_lists_readable_records_and_counts_the_rest() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let tag = &Uuid::now_v7().simple().to_string()[..12];
        let (account, invoice) = (format!("re_account_{tag}"), format!("re_invoice_{tag}"));
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
                        "filter": "amount > 0",
                        "result_type": "number",
                    } }),
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let acme = create(&app, &account, json!({ "title": "Acme" })).await;
        let mut invoices = Vec::new();
        for amount in [5, 7, 9] {
            invoices.push(
                create(
                    &app,
                    &invoice,
                    json!({ "amount": amount, "account_ref": acme }),
                )
                .await,
            );
        }
        // Not counted: the filter leaves it out.
        create(&app, &invoice, json!({ "amount": 0, "account_ref": acme })).await;

        let path = format!("/api/v1/{account}/{acme}/rollups/total/explain");
        let (status, body) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["function"], "sum");
        assert_eq!(body["filter"], "amount > 0");
        assert_eq!(body["counted"], 3, "{body}");
        assert_eq!(body["hidden"], 0, "{body}");
        assert_eq!(body["records"].as_array().unwrap().len(), 3, "{body}");

        // A reader who sees only their own invoices, and the account.
        let reader = attome_testapp::seed_user(app.db(), "rollup-reader").await;
        grant(&app, reader.id, &format!("{account}.read")).await;
        grant(&app, reader.id, &format!("{invoice}.read")).await;
        for (table, id) in [(&account, acme), (&invoice, invoices[0])] {
            sqlx::query(&format!(
                "UPDATE \"{table}\" SET owner_ref = $1 WHERE id = $2"
            ))
            .bind(reader.id)
            .bind(id)
            .execute(app.db())
            .await
            .unwrap();
        }
        app.state
            .base
            .security
            .invalidate_sync(reader.id)
            .await
            .unwrap();
        let (status, body) = app
            .request_as(&reader.cookie, Method::GET, &path, None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["counted"], 3, "{body}");
        assert_eq!(body["hidden"], 2, "{body}");
        let listed = body["records"].as_array().unwrap();
        assert_eq!(listed.len(), 1, "{body}");
        assert_eq!(listed[0]["id"], json!(invoices[0]), "{body}");

        // A field that is not a rollup, or a record the caller cannot read.
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/{account}/{acme}/rollups/title/explain"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let other = create(&app, &account, json!({ "title": "Other" })).await;
        let (status, _) = app
            .request_as(
                &reader.cookie,
                Method::GET,
                &format!("/api/v1/{account}/{other}/rollups/total/explain"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

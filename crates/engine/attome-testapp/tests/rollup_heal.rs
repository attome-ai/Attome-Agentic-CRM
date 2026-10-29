//! A10-T4: a rollup added to an entity with existing records is filled by
//! the backfill, and a value that drifted is healed.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;

use attome_records::rollup_heal::{BackfillPayload, backfill_step, heal_records};
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

async fn total(app: &TestApp, table: &str, id: Uuid) -> Option<f64> {
    let text: Option<String> = sqlx::query_scalar(&format!(
        "SELECT total::text FROM \"{table}\" WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(app.db())
    .await
    .unwrap();
    text.map(|t| t.parse().unwrap())
}

// feature: A10
#[test]
fn rollup_heal_backfills_and_fixes_drift() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let tag = &Uuid::now_v7().simple().to_string()[..12];
        let (account, invoice) = (format!("rh_account_{tag}"), format!("rh_invoice_{tag}"));
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

        // Records exist before the rollup does.
        let acme = create(&app, &account, json!({ "title": "Acme" })).await;
        let empty = create(&app, &account, json!({ "title": "Empty" })).await;
        for amount in [4, 6] {
            create(
                &app,
                &invoice,
                json!({ "amount": amount, "account_ref": acme }),
            )
            .await;
        }
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

        let mut payload = Some(BackfillPayload {
            entity: account.clone(),
            field: "total".into(),
            after: None,
        });
        let mut runs = 0;
        while let Some(next) = payload {
            payload = backfill_step(&app.state, &next)
                .await
                .expect("a backfill run");
            runs += 1;
            assert!(runs < 10, "two parents fill in one run");
        }
        assert_eq!(total(&app, &account, acme).await, Some(10.0));
        assert_eq!(total(&app, &account, empty).await, Some(0.0));

        // A value changed behind the platform's back is put right.
        sqlx::query(&format!(
            "UPDATE \"{account}\" SET total = 999 WHERE id = $1"
        ))
        .bind(acme)
        .execute(app.db())
        .await
        .unwrap();
        let parents: BTreeSet<Uuid> = [acme, empty].into_iter().collect();
        let healed = heal_records(&app.state, &account, "total", &parents)
            .await
            .expect("a heal");
        assert_eq!(healed, 1, "only the drifted value is written");
        assert_eq!(total(&app, &account, acme).await, Some(10.0));
    });
}

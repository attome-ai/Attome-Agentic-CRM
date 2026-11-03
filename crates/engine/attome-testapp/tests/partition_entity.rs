//! Y2-T12: partitioning an entity table online keeps every row and id, and
//! a write made while the copy is under way reaches the partitioned table.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// An entity with a name field and twelve rows across several months, one
/// with no creation time.
async fn deals(app: &TestApp) -> (String, Uuid) {
    let token = Uuid::now_v7().simple().to_string();
    let name = format!("part_deal_{}", &token[..12]);
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let entity: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity}/fields"),
            Some(json!({ "logicalname": "title", "name": "Title", "field_type": "text" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    // Throwaway database: the rows, made directly.
    sqlx::query(&format!(
        "INSERT INTO \"{name}\" (title, created_at) \
         SELECT 'deal ' || n, now() - (n || ' months')::interval FROM generate_series(0, 10) n"
    ))
    .execute(app.db())
    .await
    .unwrap();
    sqlx::query(&format!(
        "INSERT INTO \"{name}\" (title, created_at) VALUES ('undated', NULL)"
    ))
    .execute(app.db())
    .await
    .unwrap();
    (name, entity)
}

async fn ids(app: &TestApp, table: &str) -> BTreeSet<Uuid> {
    sqlx::query_scalar(&format!("SELECT id FROM \"{table}\""))
        .fetch_all(app.db())
        .await
        .unwrap()
        .into_iter()
        .collect()
}

// feature: Y2
#[test]
fn partition_swap_keeps_rows_and_ids() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (table, entity) = deals(&app).await;
        let before = ids(&app, &table).await;
        assert_eq!(before.len(), 12);

        // Under the default threshold the table is refused.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/partition"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");

        let (status, body) = app
            .request(
                Method::PUT,
                "/api/v1/admin/settings/records.partition_row_threshold",
                Some(json!({ "scope": "deployment", "value": 10 })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let (status, queued) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/partition"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
        let run: Uuid = queued["run"]["id"].as_str().unwrap().parse().unwrap();

        // A record written while the copy waits reaches the copy.
        let (status, created) = app
            .request(
                Method::POST,
                &format!("/api/v1/{table}"),
                Some(json!({ "title": "late" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let late: Uuid = created["id"].as_str().unwrap().parse().unwrap();

        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .unwrap();

        let kind: String =
            sqlx::query_scalar("SELECT relkind::text FROM pg_class WHERE oid = to_regclass($1)")
                .bind(format!("\"{table}\""))
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(kind, "p", "the entity table is partitioned");
        let mut expected = before.clone();
        expected.insert(late);
        assert_eq!(ids(&app, &table).await, expected, "every id is kept");
        assert_eq!(ids(&app, &format!("{table}__old")).await, expected);

        for id in [*before.iter().next().unwrap(), late] {
            let (status, body) = app
                .request(Method::GET, &format!("/api/v1/{table}/{id}"), None)
                .await;
            assert_eq!(status, StatusCode::OK, "{id}: {body}");
        }

        let (status, after) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/entities/{entity}/partition"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{after}");
        assert_eq!(after["storage_mode"], "high_volume");
        assert_eq!(after["run"]["status"], "succeeded");
        assert_eq!(after["old_table_kept"], true);

        // Once partitioned it is not partitioned again.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/partition"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    });
}

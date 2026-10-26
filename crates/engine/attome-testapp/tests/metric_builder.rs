//! P9-T3: the metric builder makes the metric's stored query from an entity,
//! an aggregate, a date and filters, points the metric at it, and on a second
//! build republishes the same query. The query counts this period's records.
//!
//! The metric row is written directly: this binary's throwaway database
//! (guidelines §4's test exemption).

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

async fn run_query(app: &TestApp, query_id: &str) -> Vec<Value> {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/query/execute",
            Some(
                json!({ "query_id": query_id, "include_total": true, "page": 1, "page_size": 10 }),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["data"]["records"].as_array().unwrap().clone()
}

// feature: P9
#[test]
fn builder_metric_computes_count_by_month() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = Uuid::now_v7().simple().to_string();
        let entity = format!("mb_deal_{}", &token[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        for (field, field_type) in [
            ("closed_on", "date"),
            ("region", "text"),
            ("amount", "number"),
        ] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/admin/entities/{entity_id}/fields"),
                    Some(json!({ "logicalname": field, "name": field, "field_type": field_type })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let today = chrono::Utc::now().date_naive();
        let last_month = today - chrono::Duration::days(40);
        for (day, region, amount) in [
            (today, "south", 10),
            (today, "south", 20),
            (today, "north", 5),
            (last_month, "north", 99),
        ] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{entity}"),
                    Some(
                        json!({ "closed_on": day.to_string(), "region": region, "amount": amount }),
                    ),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
        }

        let metric_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO dashboard_metric_definition (id, name, key, source_kind, direction, period) \
             VALUES ($1, $2, $3, 'manual', 'higher_is_better', 'month')",
        )
        .bind(metric_id)
        .bind(format!("Deals closed {token}"))
        .bind(format!("deals_closed_{}", &token[..12]))
        .execute(app.db())
        .await
        .unwrap();

        // Count this month's deals.
        let builder = format!("/api/v1/metrics/{metric_id}/builder");
        let (status, built) = app
            .request(
                Method::POST,
                &builder,
                Some(json!({
                    "entity_logicalname": entity,
                    "aggregate": "count",
                    "date_attribute": "closed_on",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{built}");
        let query_id = built["query_id"].as_str().unwrap().to_owned();
        let (source_kind, query_ref): (String, Option<String>) = sqlx::query_as(
            "SELECT source_kind, query_ref FROM dashboard_metric_definition WHERE id = $1",
        )
        .bind(metric_id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(source_kind, "query");
        assert_eq!(query_ref.as_deref(), Some(query_id.as_str()));
        let rows = run_query(&app, &query_id).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(
            rows[0]["value"].as_f64(),
            Some(3.0),
            "last month's deal is not counted"
        );

        // A second build republishes the same query: the sum by region.
        let (status, rebuilt) = app
            .request(
                Method::POST,
                &builder,
                Some(json!({
                    "entity_logicalname": entity,
                    "aggregate": "sum",
                    "measure_attribute": "amount",
                    "date_attribute": "closed_on",
                    "dimension_attributes": ["region"],
                    "filters": [{ "attribute": "amount", "op": "gte", "value": 5 }],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{rebuilt}");
        assert_eq!(rebuilt["query_id"].as_str(), Some(query_id.as_str()));
        let mut by_region: Vec<(String, f64)> = run_query(&app, &query_id)
            .await
            .iter()
            .map(|r| {
                (
                    r["region"].as_str().unwrap().to_owned(),
                    r["value"].as_f64().unwrap(),
                )
            })
            .collect();
        by_region.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            by_region,
            vec![("north".to_owned(), 5.0), ("south".to_owned(), 30.0)]
        );

        // A sum over text is refused, and nothing changes.
        let (status, body) = app
            .request(
                Method::POST,
                &builder,
                Some(json!({
                    "entity_logicalname": entity,
                    "aggregate": "sum",
                    "measure_attribute": "region",
                    "date_attribute": "closed_on",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}

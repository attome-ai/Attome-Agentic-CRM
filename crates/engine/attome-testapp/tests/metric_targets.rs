//! P9-T7: a period's total target spreads to a dimension's members; the
//! children add up to the parent, a repeated spread updates rather than
//! duplicates, and a caller without `attome_metric.set_target` gets 403.
//!
//! The metric row is written directly: this binary's throwaway database
//! (guidelines §4's test exemption).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

async fn metric(app: &TestApp) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_metric_definition (id, name, key, source_kind, direction, period, \
             dimension_attributes) \
         VALUES ($1, $2, $3, 'manual', 'higher_is_better', 'month', 'region')",
    )
    .bind(id)
    .bind(format!("Revenue {id}"))
    .bind(format!("revenue_{}", id.simple()))
    .execute(app.db())
    .await
    .unwrap();
    id
}

fn spread_body(total: f64) -> serde_json::Value {
    json!({
        "period_start": "2026-07-01T00:00:00Z",
        "total": total,
        "method": "share",
        "dimension_attribute": "region",
        "shares": { "central": 0.5, "east": 0.3, "west": 0.2 }
    })
}

// feature: P9
#[test]
fn spread_by_share_sums_to_parent() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let id = metric(&app).await;
        let path = format!("/api/v1/metrics/{id}/targets/spread");
        let (status, body) = app
            .request(Method::POST, &path, Some(spread_body(1000.0)))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["sum_of_children"], json!(1000.0));
        assert_eq!(body["children"].as_array().unwrap().len(), 3);
        let parent: Uuid = serde_json::from_value(body["parent_target_id"].clone()).unwrap();

        // Spread again with a new total: the same rows, new values.
        let (status, body) = app
            .request(Method::POST, &path, Some(spread_body(2000.0)))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["parent_target_id"], json!(parent));

        let rows: Vec<(Option<String>, f64, Option<Uuid>)> = sqlx::query_as(
            "SELECT dimension_value, target_value::float8, parent_target_ref \
               FROM dashboard_metric_target WHERE metric_ref = $1 \
              ORDER BY dimension_value NULLS FIRST",
        )
        .bind(id)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(rows.len(), 4, "{rows:?}");
        assert_eq!(rows[0], (None, 2000.0, None));
        let children: f64 = rows[1..].iter().map(|r| r.1).sum();
        assert!((children - 2000.0).abs() < 0.001, "{rows:?}");
        assert!(rows[1..].iter().all(|r| r.2 == Some(parent)));
        assert_eq!(rows[1].0.as_deref(), Some("central"));
        assert_eq!(rows[1].1, 1000.0);

        // Shares that do not add up to 1 are refused.
        let mut bad = spread_body(10.0);
        bad["shares"] = json!({ "central": 0.5, "east": 0.1 });
        let (status, _) = app.request(Method::POST, &path, Some(bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: P9
// negative: POST /api/v1/metrics/{id}/targets/spread
#[test]
fn spread_without_privilege_is_403() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let id = metric(&app).await;
        let user = seed_user(app.db(), "no-target").await;
        let (status, body) = app
            .request_as(
                &user.cookie,
                Method::POST,
                &format!("/api/v1/metrics/{id}/targets/spread"),
                Some(spread_body(100.0)),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let written: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM dashboard_metric_target WHERE metric_ref = $1",
        )
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(written, 0);
    });
}

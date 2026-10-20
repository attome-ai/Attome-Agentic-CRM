//! A3-T8: refused writes are logged per rule, attribute and channel, and the
//! nightly sweep scores each entity by the share of records passing.

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

// feature: A3
#[test]
fn validation_stats_count_rejections_and_score_the_entity() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("vstat_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        let (status, field) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": "amount", "name": "amount", "field_type": "number" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{field}");

        // 10 stored records, 2 of them negative, written before the check.
        for i in 0..10 {
            let amount = if i < 2 { -1 } else { i };
            let (status, record) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{entity}"),
                    Some(json!({ "amount": amount })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{record}");
        }

        let (status, rule) = app
            .request(
                Method::POST,
                "/api/v1/admin/business-rules",
                Some(json!({
                    "entity": entity,
                    "name": "no_negative_amounts",
                    "condition": { "field": "amount", "op": "lt", "value": 0 },
                    "policies": [{
                        "type": "error",
                        "field": "amount",
                        "message": "amount must not be negative",
                        "severity": "error",
                    }],
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{rule}");
        let rule_id = rule["id"].as_str().unwrap().to_owned();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/business-rules/{rule_id}/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Three refused writes.
        for _ in 0..3 {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{entity}"),
                    Some(json!({ "amount": -5 })),
                )
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
            assert_eq!(body["error"], "rule_violation", "{body}");
        }
        attome_records::rejection_log::RejectionLog::shared(app.db())
            .flush()
            .await;
        attome_api::validation_stats::run_score_sweep(&app.state)
            .await
            .unwrap();

        let (status, stats) = app
            .request(Method::GET, "/api/v1/admin/validation/stats", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{stats}");
        let rows: Vec<&serde_json::Value> = stats["rejections"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["rule_id"] == rule_id.as_str())
            .collect();
        assert_eq!(rows.len(), 1, "{stats}");
        assert_eq!(rows[0]["rejections"], 3);
        assert_eq!(rows[0]["attribute"], "amount");
        assert_eq!(rows[0]["entity"], entity.as_str());
        assert!(!rows[0]["channel"].as_str().unwrap().is_empty());

        let score = stats["entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["entity"] == entity.as_str())
            .expect("the entity is scored");
        assert_eq!(score["checked"], 10, "{score}");
        assert_eq!(score["passing"], 8, "{score}");
        assert_eq!(score["score"], 0.8, "{score}");

        let (status, _) = app
            .request(Method::GET, "/api/v1/admin/validation/stats?days=0", None)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

//! A3-T5: a new check simulated over stored records before publish, and the
//! clean-up queue its publish leaves: 3 failing records of 100.

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
fn validation_simulation_finds_three_failing_of_a_hundred() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("vsim_{}", &Uuid::now_v7().simple().to_string()[..12]);
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

        // 100 stored records, 3 of them negative, written before the check.
        let mut negative = Vec::new();
        for i in 0..100 {
            let amount = if [5, 50, 95].contains(&i) { -10 } else { i };
            let (status, record) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{entity}"),
                    Some(json!({ "amount": amount })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{record}");
            if amount < 0 {
                negative.push(record["id"].as_str().unwrap().to_owned());
            }
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

        // Before publish: the preview counts and names them.
        let (status, sim) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/business-rules/{rule_id}/simulate"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{sim}");
        assert_eq!(sim["checked"], 100, "{sim}");
        assert_eq!(sim["failing"], 3, "{sim}");
        assert_eq!(sim["truncated"], false);
        let mut found: Vec<String> = sim["failing_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        found.sort();
        negative.sort();
        assert_eq!(found, negative);

        // After publish: the scan job fills the clean-up queue.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/business-rules/{rule_id}/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let scanned = attome_api::validation_simulation::run_cleanup_scan(
            &app.state,
            Uuid::parse_str(&rule_id).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(scanned.failing, 3);
        let (status, queue) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/business-rules/{rule_id}/cleanup"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{queue}");
        assert_eq!(queue["total"], 3, "{queue}");
        assert!(
            queue["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|i| i["message"] == "amount must not be negative")
        );
        // Scanning again rewrites the same three, never duplicates them.
        attome_api::validation_simulation::run_cleanup_scan(
            &app.state,
            Uuid::parse_str(&rule_id).unwrap(),
        )
        .await
        .unwrap();
        let (_, queue) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/business-rules/{rule_id}/cleanup"),
                None,
            )
            .await;
        assert_eq!(queue["total"], 3);
    });
}

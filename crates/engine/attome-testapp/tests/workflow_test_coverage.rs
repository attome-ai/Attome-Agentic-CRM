//! M4-T2: a flow's saved test cases run on a version's graph, draft or
//! published, and the version's coverage names the nodes no case reached.
//! A failed run on a record becomes a test in one step.

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

/// An entity with a text `status` field; its logical name.
async fn entity(app: &TestApp) -> String {
    let logicalname = format!("wtc_{}", Uuid::now_v7().simple());
    let (code, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": logicalname, "name": "Coverage test" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    let id = body["id"].as_str().unwrap().to_owned();
    let (code, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{id}/fields"),
            Some(json!({ "logicalname": "status", "name": "Status", "field_type": "text" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    logicalname
}

// feature: M4
#[test]
fn coverage_names_the_nodes_no_case_reached() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = entity(&app).await;
        let flow = format!("wtc-flow-{}", Uuid::now_v7());
        // Trigger, then a truthy check: true reaches `kept`, false `dropped`.
        let graph = json!({
            "nodes": [
                {"id": "t", "type": "trigger", "config": {"trigger_type": "manual"}},
                {"id": "c", "type": "condition", "config": {"op": "truthy"}},
                {"id": "kept", "type": "wait", "config": {"delay_seconds": -1}},
                {"id": "dropped", "type": "wait", "config": {"delay_seconds": -1}}
            ],
            "edges": [
                {"from_node": "t", "from_port": "out", "to_node": "c", "to_port": "value"},
                {"from_node": "c", "from_port": "true", "to_node": "kept", "to_port": "in"},
                {"from_node": "c", "from_port": "false", "to_node": "dropped", "to_port": "in"}
            ]
        });
        let definition: Uuid = sqlx::query_scalar(
            "INSERT INTO workflow_definition (logicalname, name, owner_layer) VALUES ($1, $1, 'project') RETURNING id",
        )
        .bind(&flow)
        .fetch_one(app.db())
        .await
        .unwrap();
        // Only a draft: the cases run on it, not on a published version.
        let version: Uuid = sqlx::query_scalar(
            "INSERT INTO workflow_definition_version (definition_id, version_number, graph, status) \
             VALUES ($1, 1, $2, 'draft') RETURNING id",
        )
        .bind(definition)
        .bind(&graph)
        .fetch_one(app.db())
        .await
        .unwrap();

        let (code, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/customer-tests",
                Some(json!({
                    "name": format!("{flow} keeps"),
                    "definition": {
                        "given": [{ "entity": entity, "ref": "r", "record": { "status": "new" } }],
                        "expect": [{ "flow": flow, "entity": entity, "ref": "r", "reaches": ["kept"] }]
                    }
                })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{body}");

        let path = format!("/api/v1/workflow/definitions/{definition}/versions/{version}/coverage");
        let (code, coverage) = app.request(Method::GET, &path, None).await;
        assert_eq!(code, StatusCode::OK, "{coverage}");
        assert_eq!(coverage["tests"].as_array().unwrap().len(), 1, "{coverage}");
        assert_eq!(coverage["tests"][0]["passed"], true, "{coverage}");
        assert_eq!(coverage["covered"], json!(["t", "c", "kept"]), "{coverage}");
        assert_eq!(coverage["uncovered"], json!(["dropped"]), "{coverage}");

        // The draft publishes: its case passes on it.
        let (code, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/workflow/definitions/{definition}/versions/{version}/publish"),
                None,
            )
            .await;
        assert!(code.is_success(), "{code} {body}");

        // M4-T2 step 2: a test from a failed run on a record expects the
        // flow to complete on that record.
        let (code, record) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "status": "new" })),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{record}");
        let record_id = record["id"].as_str().unwrap().to_owned();
        let failed: Uuid = sqlx::query_scalar(
            "INSERT INTO workflow_instance (definition_version_id, status, context) \
             VALUES ($1, 'failed', $2) RETURNING id",
        )
        .bind(version)
        .bind(json!({ "entity_logicalname": entity, "record_id": record_id }))
        .fetch_one(app.db())
        .await
        .unwrap();
        let (code, test) = app
            .request(
                Method::POST,
                &format!("/api/v1/workflow/instances/{failed}/test"),
                Some(json!({})),
            )
            .await;
        assert_eq!(code, StatusCode::CREATED, "{test}");
        let expect = test["definition"]["expect"].as_array().unwrap();
        assert!(
            expect
                .iter()
                .any(|e| e["flow"] == json!(flow) && e["status"] == "completed"),
            "{test}"
        );
        // A run that did not fail is refused.
        let running: Uuid = sqlx::query_scalar(
            "INSERT INTO workflow_instance (definition_version_id, status, context) \
             VALUES ($1, 'completed', $2) RETURNING id",
        )
        .bind(version)
        .bind(json!({ "entity_logicalname": entity, "record_id": record_id }))
        .fetch_one(app.db())
        .await
        .unwrap();
        let (code, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/workflow/instances/{running}/test"),
                Some(json!({})),
            )
            .await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);

        // An unknown version is 404.
        let (code, _) = app
            .request(
                Method::GET,
                &format!(
                    "/api/v1/workflow/definitions/{definition}/versions/{}/coverage",
                    Uuid::now_v7()
                ),
                None,
            )
            .await;
        assert_eq!(code, StatusCode::NOT_FOUND);
    });
}

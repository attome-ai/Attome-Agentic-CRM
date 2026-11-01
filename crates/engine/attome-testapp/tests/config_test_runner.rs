//! T7-T1: a customer test states permissions and flow outcomes as well as
//! values and errors. A permission is judged for the acting caller; a flow
//! is the published workflow simulated on the record the test left, so
//! nothing it would do happens.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_records::customer_tests::{TestDefinition, run_test};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

fn definition(value: Value) -> TestDefinition {
    serde_json::from_value(value).expect("a test definition")
}

/// An entity with a text `status` field; its logical name.
async fn entity(app: &TestApp) -> String {
    let logicalname = format!("ctr_{}", Uuid::now_v7().simple());
    let (code, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": logicalname, "name": "Config test" })),
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

/// A published workflow: trigger, then a truthy check whose true branch
/// reaches `kept` and whose false branch reaches `dropped`.
async fn workflow(app: &TestApp) -> String {
    let logicalname = format!("ctr-flow-{}", Uuid::now_v7());
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
    .bind(&logicalname)
    .fetch_one(app.db())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO workflow_definition_version (definition_id, version_number, graph, status) \
         VALUES ($1, 1, $2, 'published')",
    )
    .bind(definition)
    .bind(&graph)
    .execute(app.db())
    .await
    .unwrap();
    logicalname
}

// feature: T7
#[test]
fn permissions_are_judged_for_the_acting_caller() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let admin = attome_security::resolve_uncached(&app.state.base.db, app.admin.id)
            .await
            .unwrap();
        let stranger = attome_testapp::seed_user(app.db(), "config-test-stranger").await;
        let stranger = attome_security::resolve_uncached(&app.state.base.db, stranger.id)
            .await
            .unwrap();
        let may_delete = definition(json!({
            "expect": [{ "entity": "note", "action": "delete", "allowed": true }]
        }));
        assert!(run_test(&app.state, &admin, &may_delete).await.passed);
        let outcome = run_test(&app.state, &stranger, &may_delete).await;
        assert!(!outcome.passed);
        assert!(outcome.failures[0].contains("refused"), "{outcome:?}");
        let may_not = definition(json!({
            "expect": [{ "entity": "note", "action": "delete", "allowed": false }]
        }));
        assert!(run_test(&app.state, &stranger, &may_not).await.passed);
    });
}

// feature: T7
#[test]
fn a_flow_is_simulated_on_the_record_the_test_left() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = entity(&app).await;
        let flow = workflow(&app).await;
        let admin = attome_security::resolve_uncached(&app.state.base.db, app.admin.id)
            .await
            .unwrap();
        let given = json!([{ "entity": entity, "ref": "r", "record": { "status": "new" } }]);
        let reaches = definition(json!({
            "given": given,
            "expect": [{ "flow": flow, "entity": entity, "ref": "r", "reaches": ["kept"] }]
        }));
        let outcome = run_test(&app.state, &admin, &reaches).await;
        assert!(outcome.passed, "{outcome:?}");
        let wrong = definition(json!({
            "given": given,
            "expect": [{ "flow": flow, "entity": entity, "ref": "r", "reaches": ["dropped"] }]
        }));
        let outcome = run_test(&app.state, &admin, &wrong).await;
        assert!(!outcome.passed);
        assert!(
            outcome.failures[0].contains("did not reach dropped"),
            "{outcome:?}"
        );
        // Nothing the test did stays: the record was rolled back.
        let rows: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM \"{entity}\""))
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(rows, 0);
    });
}

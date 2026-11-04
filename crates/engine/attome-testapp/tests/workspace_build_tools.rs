//! N12-T1: an entity and a field made through the agent's build tools inside
//! a Develop workspace land in the workspace (its schema and its changeset),
//! never in live. One test only: marking this process as the workspace's own
//! is process-wide.

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

async fn table_in(app: &TestApp, schema: &str, table: &str) -> bool {
    let found: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
        .bind(format!("\"{schema}\".\"{table}\""))
        .fetch_one(app.db())
        .await
        .unwrap();
    found.is_some()
}

async fn invoke(app: &TestApp, action: &str, args: Value) -> Value {
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/actions/{action}/invoke"),
            Some(json!({ "args": args, "confirm": true })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "completed", "{body}");
    body
}

// feature: N12
#[test]
fn build_tools_create_an_entity_and_a_field_in_a_workspace() {
    attome_testkit::run_shared(async {
        let Some(live) = TestApp::start().await else {
            return;
        };
        let (status, made) = live
            .request(
                Method::POST,
                "/api/v1/admin/workspaces",
                Some(json!({ "name": "Agent build", "data": { "mode": "none" } })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        let id: Uuid = made["id"].as_str().unwrap().parse().unwrap();
        let changeset: Uuid = made["changeset_ref"].as_str().unwrap().parse().unwrap();
        let schema = format!("ws_{}", id.simple());
        let live_schema: String = sqlx::query_scalar("SELECT current_schema()::text")
            .fetch_one(live.db())
            .await
            .unwrap();

        // This process now plays the workspace's own (`attome serve
        // --workspace`), on connections that search its schema first.
        assert!(attome_api::workspace::build_tools::serve_workspace(id));
        // The build tools are AI-module actions: the AI fields surface on.
        let workspace =
            TestApp::start_in_schema_with(&format!("{schema},{live_schema},public"), |config| {
                config.inference.ai.enabled = true;
                config.inference.ai.fields = true;
            })
            .await
            .expect("the workspace app");

        let entity = format!("agent_built_{}", &Uuid::now_v7().simple().to_string()[20..]);
        invoke(
            &workspace,
            "model.entity.create",
            json!({ "logicalname": entity, "name": "Agent built" }),
        )
        .await;
        invoke(
            &workspace,
            "model.attribute.create",
            json!({ "entity": entity, "logicalname": "note", "name": "Note", "field_type": "text" }),
        )
        .await;

        assert!(table_in(&live, &schema, &entity).await, "in the workspace");
        assert!(!table_in(&live, &live_schema, &entity).await, "not live");
        let column: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
              WHERE table_schema = $1 AND table_name = $2 AND column_name = 'note')",
        )
        .bind(&schema)
        .bind(&entity)
        .fetch_one(live.db())
        .await
        .unwrap();
        assert!(column, "the field's column is in the workspace's table");

        // Both writes recorded into the workspace's changeset.
        let ops: Vec<String> = sqlx::query_scalar(
            "SELECT op FROM changeset_operation WHERE changeset_ref = $1 ORDER BY seq",
        )
        .bind(changeset)
        .fetch_all(live.db())
        .await
        .unwrap();
        assert!(ops.contains(&"create_entity".to_owned()), "{ops:?}");
        assert!(ops.contains(&"add_field".to_owned()), "{ops:?}");
    });
}

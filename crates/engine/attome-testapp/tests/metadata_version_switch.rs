//! Y8-T4: every publish records the deployment's next metadata version and
//! points `metadata_current` at it; a switch or a rollback only moves the
//! pointer to a version already cooked, and each node follows the pointer by
//! loading that version's stored artefacts in one swap and recording its
//! `metadata_node_switch` row.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_model::runtime::CookedRegistry;
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// Publishes a new environment variable; returns its cooked-artefact key.
async fn publish_variable(app: &TestApp) -> String {
    let id = Uuid::now_v7();
    let name = format!("y8_{}", &id.simple().to_string()[..16]);
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/model/environment_variable/{id}/commands"),
            Some(json!({
                "base_hash": "",
                "name": name,
                "commands": [{ "op": "set", "path": "/type", "value": "url" }]
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/model/environment_variable/{id}/publish"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    format!("environment_variable:{id}")
}

async fn current_version(app: &TestApp) -> i64 {
    sqlx::query_scalar("SELECT version FROM metadata_current")
        .fetch_one(app.db())
        .await
        .expect("a publish records the current metadata version")
}

async fn count(app: &TestApp, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .fetch_one(app.db())
        .await
        .expect("count rows")
}

async fn switched_nodes(app: &TestApp, version: i64) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT node_id FROM metadata_node_switch WHERE version = $1 ORDER BY node_id",
    )
    .bind(version)
    .fetch_all(app.db())
    .await
    .expect("read node switches")
}

// feature: Y8
#[test]
fn switch_loads_new_version_in_one_step() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let cooked = attome_api::model_admin::cooked();

        let first = publish_variable(&app).await;
        let v1 = current_version(&app).await;
        let second = publish_variable(&app).await;
        let v2 = current_version(&app).await;
        assert!(
            v2 > v1,
            "each publish records a new version: {v1} then {v2}"
        );
        let loaded = cooked.snapshot();
        assert_eq!(loaded.version, v2, "the publishing node serves its publish");
        assert!(loaded.manifest.artefacts.contains_key(&second));

        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/metadata/versions/{v1}/switch"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({ "from": v2, "to": v1 }));
        assert_eq!(current_version(&app).await, v1);
        // One swap: the whole earlier version, with the first variable and
        // without the second.
        let loaded = cooked.snapshot();
        assert_eq!(loaded.version, v1);
        assert!(loaded.manifest.artefacts.contains_key(&first));
        assert!(!loaded.manifest.artefacts.contains_key(&second));
        assert!(
            !switched_nodes(&app, v1).await.is_empty(),
            "this node records its switch"
        );

        // Another node, still on nothing, follows the pointer and records
        // its own switch; following again does nothing.
        let other = CookedRegistry::default();
        let followed = attome_model::switch::follow_current(app.db(), &other, "node-b")
            .await
            .unwrap();
        assert_eq!(followed, Some(v1));
        assert_eq!(other.snapshot().manifest, loaded.manifest);
        assert!(
            switched_nodes(&app, v1)
                .await
                .contains(&"node-b".to_owned())
        );
        let again = attome_model::switch::follow_current(app.db(), &other, "node-b")
            .await
            .unwrap();
        assert_eq!(again, None);

        let (status, _) = app
            .request(
                Method::POST,
                "/api/v1/admin/metadata/versions/999999999/switch",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a version never published");

        // Back to the newest, for the other test.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/metadata/versions/{v2}/switch"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    });
}

// feature: Y8
#[test]
fn rollback_needs_no_cook() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let cooked = attome_api::model_admin::cooked();
        publish_variable(&app).await;
        let previous = current_version(&app).await;
        let newest_key = publish_variable(&app).await;
        let newest = current_version(&app).await;

        let artefacts = count(&app, "SELECT count(*) FROM metadata_artefact").await;
        let versions = count(&app, "SELECT count(*) FROM metadata_published_version").await;

        let (status, body) = app
            .request(Method::POST, "/api/v1/admin/metadata/rollback", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body, json!({ "from": newest, "to": previous }));
        assert_eq!(current_version(&app).await, previous);
        let loaded = cooked.snapshot();
        assert_eq!(loaded.version, previous);
        assert!(!loaded.manifest.artefacts.contains_key(&newest_key));

        // Nothing was cooked or recorded: no new artefact, no new version.
        assert_eq!(
            count(&app, "SELECT count(*) FROM metadata_artefact").await,
            artefacts
        );
        assert_eq!(
            count(&app, "SELECT count(*) FROM metadata_published_version").await,
            versions
        );
        assert!(
            !switched_nodes(&app, previous).await.is_empty(),
            "this node records its switch"
        );
    });
}

// feature: Y8
#[test]
fn node_switch_rows_listed() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        publish_variable(&app).await;
        let version = current_version(&app).await;

        // A second node follows the pointer; its switch time since the
        // pointer move is measured on the database clock.
        let other = CookedRegistry::default();
        let node = format!("node-y8t10-{}", &Uuid::now_v7().simple().to_string()[..12]);
        attome_model::switch::follow_current(app.db(), &other, &node)
            .await
            .unwrap();
        let third = format!("{node}-c");
        let seconds = attome_model::switch::record_node_switch(app.db(), &third, version)
            .await
            .unwrap();
        assert!(
            seconds.is_some_and(|s| s >= 0.0),
            "measured from the pointer move: {seconds:?}"
        );
        let again = attome_model::switch::record_node_switch(app.db(), &node, version)
            .await
            .unwrap();
        assert_eq!(again, None, "a node's switch is measured once");

        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/metadata/versions/{version}/nodes?page_size=200"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body["items"].as_array().expect("a paginated list");
        assert_eq!(body["total"].as_i64(), Some(items.len() as i64));
        let nodes: Vec<&str> = items
            .iter()
            .map(|n| n["node_id"].as_str().expect("node_id"))
            .collect();
        assert!(nodes.contains(&node.as_str()), "{body}");
        assert!(nodes.contains(&third.as_str()), "{body}");
        assert!(
            nodes.len() >= 3,
            "the publishing node and the two others: {body}"
        );
        assert!(items.iter().all(|n| n["switched_at"].is_string()));

        let (status, _) = app
            .request(
                Method::GET,
                "/api/v1/admin/metadata/versions/999999999/nodes",
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a version never published");
    });
}

//! T5-T6: a workspace's life cycle. An idle workspace's owner is warned,
//! then the workspace is discarded; using it clears the warning. A refresh
//! brings in what live changed since the workspace was made.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::workspace::lifecycle;
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

async fn create_workspace(app: &TestApp) -> (Uuid, String) {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/workspaces",
            Some(json!({ "name": "Life cycle", "data": { "mode": "none" } })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    (id, format!("ws_{}", id.simple()))
}

async fn status_of(app: &TestApp, id: Uuid) -> (StatusCode, Value) {
    app.request(Method::GET, &format!("/api/v1/admin/workspaces/{id}"), None)
        .await
}

async fn schema_exists(app: &TestApp, schema: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)")
        .bind(schema)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: T5
#[test]
fn an_idle_workspace_expires() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (id, schema) = create_workspace(&app).await;
        // Unused for 40 days (the default idle time is 30).
        sqlx::query(
            "UPDATE develop_workspace SET last_used_at = now() - interval '40 days' WHERE id = $1",
        )
        .bind(id)
        .execute(app.db())
        .await
        .unwrap();

        // The first sweep only warns.
        let first = lifecycle::sweep(&app.state, chrono::Utc::now())
            .await
            .unwrap();
        assert!(first.warned.contains(&id), "{first:?}");
        assert!(!first.discarded.contains(&id), "{first:?}");
        let (status, shown) = status_of(&app, id).await;
        assert_eq!(status, StatusCode::OK, "{shown}");
        assert_eq!(shown["status"], "open");
        let warned: bool = sqlx::query_scalar(
            "SELECT expiry_warned_at IS NOT NULL FROM develop_workspace WHERE id = $1",
        )
        .bind(id)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(warned);

        // A day after the warning, still unused: discarded.
        sqlx::query(
            "UPDATE develop_workspace SET expiry_warned_at = now() - interval '2 days' \
             WHERE id = $1",
        )
        .bind(id)
        .execute(app.db())
        .await
        .unwrap();
        let second = lifecycle::sweep(&app.state, chrono::Utc::now())
            .await
            .unwrap();
        assert!(second.discarded.contains(&id), "{second:?}");
        let (status, _) = status_of(&app, id).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!schema_exists(&app, &schema).await, "the schema is dropped");
    });
}

// feature: T5
#[test]
fn a_recent_workspace_is_left_alone() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (id, schema) = create_workspace(&app).await;
        let swept = lifecycle::sweep(&app.state, chrono::Utc::now())
            .await
            .unwrap();
        assert!(!swept.warned.contains(&id));
        assert!(!swept.discarded.contains(&id));
        assert!(schema_exists(&app, &schema).await);
        let (status, _) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/admin/workspaces/{id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    });
}

// feature: T5
#[test]
fn refresh_brings_live_changes_in() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("ws_refresh_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, created) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
        let entity_id = created["id"].as_str().unwrap().to_owned();
        let (id, schema) = create_workspace(&app).await;

        // Live gains a field after the workspace was made.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": "late_field", "name": "late_field", "field_type": "text" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let column_in_ws = || async {
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                  WHERE table_schema = $1 AND table_name = $2 AND column_name = 'late_field')",
            )
            .bind(&schema)
            .bind(&entity)
            .fetch_one(app.db())
            .await
            .unwrap()
        };
        assert!(
            !column_in_ws().await,
            "not in the workspace before a refresh"
        );

        let (status, report) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/workspaces/{id}/refresh"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{report}");
        assert!(
            report["columns_added"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == &json!(format!("{entity}.late_field"))),
            "{report}"
        );
        assert!(
            report["metadata_rows_added"].as_u64().unwrap() >= 1,
            "{report}"
        );
        assert!(column_in_ws().await, "in the workspace after a refresh");
        let field_in_ws: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM \"{schema}\".attribute_info a \
               JOIN \"{schema}\".entity_info e ON e.id = a.entity_ref \
              WHERE e.logicalname = $1 AND a.logicalname = 'late_field')"
        ))
        .bind(&entity)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(field_in_ws);

        // A second refresh finds nothing new.
        let (status, again) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/workspaces/{id}/refresh"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(again["columns_added"], json!([]), "{again}");
        let (status, _) = app
            .request(
                Method::DELETE,
                &format!("/api/v1/admin/workspaces/{id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    });
}

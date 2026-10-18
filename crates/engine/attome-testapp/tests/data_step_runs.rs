//! Y12-T5: a data step run pauses, resumes from its cursor and cancels,
//! through the admin routes, driven here on an orphan scan (a run kind with
//! no partial state to undo).

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

/// An entity with a lookup to another, 12 rows pointing at nothing, and a
/// queued orphan scan of it.
async fn queued_scan(app: &TestApp) -> (String, Uuid) {
    let token = Uuid::now_v7().simple().to_string();
    let target = format!("dsr_target_{}", &token[..12]);
    let child = format!("dsr_child_{}", &token[..12]);
    let mut ids = Vec::new();
    for name in [&target, &child] {
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": name, "name": name })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        ids.push(body["id"].as_str().unwrap().parse::<Uuid>().unwrap());
    }
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{}/fields", ids[1]),
            Some(json!({ "logicalname": "target_ref", "name": "target_ref",
                         "field_type": "lookup", "lookup_entity_ref": ids[0] })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    // Throwaway database: rows pointing at nothing, made directly.
    sqlx::query(&format!(
        "INSERT INTO \"{child}\" (target_ref) SELECT uuidv7() FROM generate_series(1, 12)"
    ))
    .execute(app.db())
    .await
    .unwrap();
    let (status, queued) = app
        .request(
            Method::POST,
            "/api/v1/admin/data-step-runs/orphan-scans",
            Some(json!({ "entity_id": ids[1] })),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
    (child, queued["run_id"].as_str().unwrap().parse().unwrap())
}

async fn control(app: &TestApp, run: Uuid, action: &str) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/v1/admin/data-step-runs/{run}/{action}"),
        None,
    )
    .await
}

// feature: Y12
#[test]
fn pause_stops_after_current_batch() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (_, run) = queued_scan(&app).await;
        let (status, paused) = control(&app, run, "pause").await;
        assert_eq!(status, StatusCode::OK, "{paused}");
        assert_eq!(paused["status"], "paused");
        // A worker reaching a paused run leaves it alone.
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .unwrap();
        let (_, shown) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/data-step-runs/{run}"),
                None,
            )
            .await;
        assert_eq!(shown["status"], "paused", "{shown}");
        assert_eq!(shown["rows_scanned"], 0);
        assert!(shown["eta_secs"].is_null());
        // Pausing twice is refused; cancelling a scan abandons it.
        let (status, _) = control(&app, run, "pause").await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, cancelled) = control(&app, run, "cancel").await;
        assert_eq!(status, StatusCode::OK, "{cancelled}");
        assert_eq!(cancelled["status"], "abandoned");
        let (status, _) = control(&app, run, "cancel").await;
        assert_eq!(status, StatusCode::CONFLICT);
    });
}

// feature: Y12
#[test]
fn resume_continues_from_cursor() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (_, run) = queued_scan(&app).await;
        control(&app, run, "pause").await;
        let (status, resumed) = control(&app, run, "resume").await;
        assert_eq!(status, StatusCode::OK, "{resumed}");
        assert_eq!(resumed["status"], "queued");
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .unwrap();
        let (_, done) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/data-step-runs/{run}"),
                None,
            )
            .await;
        assert_eq!(done["status"], "succeeded", "{done}");
        assert_eq!(done["rows_scanned"], 12);
        assert!(done["started_at"].is_string());
        let spec: Value = sqlx::query_scalar("SELECT spec FROM data_step_run WHERE id = $1")
            .bind(run)
            .fetch_one(app.db())
            .await
            .unwrap();
        let at = spec["columns"]
            .as_array()
            .unwrap()
            .iter()
            .position(|c| c["attribute"] == "target_ref")
            .unwrap();
        assert_eq!(spec["orphans"][at], 12, "{spec}");
        let (status, _) = control(&app, run, "resume").await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = app
            .request(
                Method::GET,
                &format!("/api/v1/admin/data-step-runs/{}", Uuid::now_v7()),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

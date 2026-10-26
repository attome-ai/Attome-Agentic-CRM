//! AA10-T2: the size check counts the rows the caller may change, bounded
//! by the inline threshold, and says inline or background. AA10-T3: the
//! mass-operation routes estimate, run, follow and control an operation.
//! AA10-T4: background operations run in resumable chunks. AA10-T5: a large
//! operation is undone chunk by chunk; undo values expire. AA10-T9: the
//! starter is told once when it ends.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_records::heavy_op::{Path, size_check, size_check_with};
use attome_records::query_spec::Condition;
use attome_security::RecordAction;
use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// An entity with a `title` and ten records, `big` titled for the first
/// four.
async fn ten_records(app: &TestApp) -> String {
    let name = format!("ho_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{id}/fields"),
            Some(json!({ "logicalname": "title", "name": "title", "field_type": "text" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    for i in 0..10 {
        let title = if i < 4 { "big" } else { "small" };
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{name}"),
                Some(json!({ "title": title })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    name
}

// feature: AA10
#[test]
fn size_check_small_is_inline() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = ten_records(&app).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let all = size_check_with(&app.state, &admin, &entity, None, RecordAction::Update, 500)
            .await
            .unwrap();
        assert_eq!(all.path, Path::Inline);
        assert!(!all.exceeds);
        assert_eq!((all.exact_upto, all.estimated_rows), (10, 10));

        // The filter narrows the count.
        let big: Condition = serde_json::from_value(
            json!({"kind": "compare", "field": "title", "op": "eq", "value": "big"}),
        )
        .unwrap();
        let some = size_check_with(
            &app.state,
            &admin,
            &entity,
            Some(&big),
            RecordAction::Delete,
            500,
        )
        .await
        .unwrap();
        assert_eq!(some.estimated_rows, 4);

        // The default threshold (500) from the setting.
        let default = size_check(&app.state, &admin, &entity, None, RecordAction::Update)
            .await
            .unwrap();
        assert_eq!(default.path, Path::Inline);
    });
}

// feature: AA10
#[test]
fn size_check_large_is_background() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = ten_records(&app).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let large = size_check_with(&app.state, &admin, &entity, None, RecordAction::Update, 5)
            .await
            .unwrap();
        assert_eq!(large.path, Path::Background);
        assert!(large.exceeds);
        assert_eq!(
            large.exact_upto, 6,
            "the count stops one past the threshold"
        );
        assert!(large.estimated_rows >= 6);

        // Someone who may not change the entity gets no count at all.
        let outsider = seed_user(app.db(), "heavy-op-outsider").await;
        let outsider = app.state.base.security.resolve(outsider.id).await.unwrap();
        assert!(
            size_check_with(
                &app.state,
                &outsider,
                &entity,
                None,
                RecordAction::Update,
                5
            )
            .await
            .is_err()
        );
    });
}

/// AA10-T3: the condition `title = value`.
fn title_is(value: &str) -> serde_json::Value {
    json!({"kind": "compare", "field": "title", "op": "eq", "value": value})
}

/// Live records of `entity` titled `title`.
async fn titled(app: &TestApp, entity: &str, title: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM \"{entity}\" WHERE title = $1 AND is_active"
    ))
    .bind(title)
    .fetch_one(app.db())
    .await
    .unwrap()
}

// feature: AA10
#[test]
fn mass_estimate_returns_path() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = ten_records(&app).await;
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass/estimate"),
                Some(json!({ "filter": title_is("big"), "kind": "delete" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["path"], "inline", "{body}");
        assert_eq!(body["estimated_rows"], 4, "{body}");

        // A payload the kind does not take is refused.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass/estimate"),
                Some(json!({ "kind": "update", "payload": {} })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}

// feature: AA10
#[test]
fn mass_small_runs_inline() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = ten_records(&app).await;
        let (status, run) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass"),
                Some(json!({
                    "filter": title_is("big"),
                    "kind": "update",
                    "payload": { "title": "huge" },
                    "reason": "rename"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{run}");
        assert_eq!(run["operation"]["status"], "done", "{run}");
        assert_eq!(run["operation"]["rows_done"], 4, "{run}");
        let items = run["items"].as_array().unwrap();
        assert_eq!(items.len(), 4, "{run}");
        assert!(items.iter().all(|i| i["status"] == "done"), "{run}");
        assert_eq!(titled(&app, &entity, "huge").await, 4);
        assert_eq!(titled(&app, &entity, "big").await, 0);

        let id = run["operation"]["id"].as_str().unwrap().to_owned();
        let (status, op) = app
            .request(Method::GET, &format!("/api/v1/mass/{id}"), None)
            .await;
        assert_eq!(status, StatusCode::OK, "{op}");
        assert_eq!(op["kind"], "update");
        assert_eq!(op["seconds_left"], serde_json::Value::Null);

        // Undo writes the old titles back.
        let tag = format!("\"{}\"", op["row_version"]);
        let (status, undone) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/mass/{id}/undo"),
                &[("if-match", tag.as_str())],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{undone}");
        assert_eq!(undone["operation"]["status"], "undone", "{undone}");
        assert_eq!(titled(&app, &entity, "big").await, 4);
        assert_eq!(titled(&app, &entity, "huge").await, 0);

        // A delete goes to the bin, and a restore brings the records back.
        let (status, run) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass"),
                Some(json!({ "filter": title_is("small"), "kind": "delete" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{run}");
        assert_eq!(run["operation"]["rows_done"], 6, "{run}");
        assert_eq!(titled(&app, &entity, "small").await, 0);
        let (status, run) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass"),
                Some(json!({ "filter": title_is("small"), "kind": "restore" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{run}");
        assert_eq!(run["operation"]["rows_done"], 6, "{run}");
        assert_eq!(titled(&app, &entity, "small").await, 6);
    });
}

/// `ten_records` plus `extra` more, written straight to the test table.
async fn many_records(app: &TestApp, extra: i32) -> String {
    let entity = ten_records(app).await;
    sqlx::query(&format!(
        "INSERT INTO \"{entity}\" (title) SELECT 'bulk' FROM generate_series(1, $1)"
    ))
    .bind(extra)
    .execute(app.db())
    .await
    .unwrap();
    entity
}

// feature: AA10
#[test]
fn mass_large_returns_202() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = many_records(&app, 495).await;
        let (status, refused) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass"),
                Some(json!({ "kind": "update", "payload": { "title": "x" } })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "a background run needs the estimate confirmed: {refused}"
        );
        let (status, run) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass"),
                Some(json!({
                    "kind": "update",
                    "payload": { "title": "x" },
                    "confirm_estimate_rows": 505
                })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{run}");
        assert_eq!(run["operation"]["status"], "queued", "{run}");
        assert_eq!(run["estimate"]["path"], "background", "{run}");
        assert!(run["items"].as_array().unwrap().is_empty());
        assert_eq!(
            titled(&app, &entity, "x").await,
            0,
            "nothing changes in the request"
        );
    });
}

// feature: AA10
#[test]
fn mass_control_requires_if_match() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = many_records(&app, 495).await;
        let (status, run) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass"),
                Some(json!({ "kind": "delete", "confirm_estimate_rows": 505 })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{run}");
        let id = run["operation"]["id"].as_str().unwrap().to_owned();
        let version = run["operation"]["row_version"].as_i64().unwrap();
        let pause = format!("/api/v1/mass/{id}/pause");

        let (status, body) = app.request(Method::POST, &pause, None).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let stale = format!("\"{}\"", version + 7);
        let (status, body) = app
            .request_with(Method::POST, &pause, &[("if-match", stale.as_str())], None)
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let current = format!("\"{version}\"");
        let (status, body) = app
            .request_with(
                Method::POST,
                &pause,
                &[("if-match", current.as_str())],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["operation"]["status"], "paused", "{body}");

        // Someone else neither sees nor controls it.
        let other = seed_user(app.db(), "mass-other").await;
        let (status, _) = app
            .request_as(
                &other.cookie,
                Method::GET,
                &format!("/api/v1/mass/{id}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Cancelled is final: resuming it is refused.
        let next = format!("\"{}\"", body["operation"]["row_version"]);
        let (status, body) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/mass/{id}/cancel"),
                &[("if-match", next.as_str())],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["operation"]["status"], "cancelled");
        let last = format!("\"{}\"", body["operation"]["row_version"]);
        let (status, body) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/mass/{id}/resume"),
                &[("if-match", last.as_str())],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    });
}

/// AA10-T4: starts a background update of every record to `title = x` and
/// answers the operation's id.
async fn start_background_update(app: &TestApp, entity: &str, rows: i64) -> Uuid {
    let (status, run) = app
        .request(
            Method::POST,
            &format!("/api/v1/{entity}/mass"),
            Some(json!({
                "kind": "update",
                "payload": { "title": "x" },
                "confirm_estimate_rows": rows
            })),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{run}");
    Uuid::parse_str(run["operation"]["id"].as_str().unwrap()).unwrap()
}

/// The chunk's keyset position.
async fn chunk_last_id(app: &TestApp, operation: Uuid, chunk_no: i32) -> Option<Uuid> {
    sqlx::query_scalar(
        "SELECT last_id FROM heavy_operation_chunk WHERE operation_id = $1 AND chunk_no = $2",
    )
    .bind(operation)
    .bind(chunk_no)
    .fetch_one(app.db())
    .await
    .unwrap()
}

/// (status, rows_done, rows_conflict) of the operation.
async fn op_counts(app: &TestApp, operation: Uuid) -> (String, i64, i64) {
    sqlx::query_as("SELECT status, rows_done, rows_conflict FROM heavy_operation WHERE id = $1")
        .bind(operation)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: AA10
#[test]
fn mass_job_resumes_after_restart() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = many_records(&app, 995).await;
        let operation = start_background_update(&app, &entity, 1005).await;

        // The worker planned chunk 0 and stopped before changing anything.
        let planned = attome_records::mass::plan_chunk(&app.state, operation, 0, None)
            .await
            .unwrap()
            .expect("the operation is working");
        assert_eq!(planned.len(), 500);
        assert_eq!(titled(&app, &entity, "x").await, 0);

        // The retried job works from the saved plan; a second retry of the
        // finished chunk changes nothing.
        let changed = attome_records::mass::run_chunk(&app.state, operation, 0, None)
            .await
            .unwrap();
        assert_eq!(changed, 500);
        let again = attome_records::mass::run_chunk(&app.state, operation, 0, None)
            .await
            .unwrap();
        assert_eq!(again, 0, "a done chunk is not repeated");
        assert_eq!(op_counts(&app, operation).await.1, 500);

        // The chain continues after chunk 0's last id and ends on the short
        // chunk.
        let after = chunk_last_id(&app, operation, 0).await;
        let changed = attome_records::mass::run_chunk(&app.state, operation, 1, after)
            .await
            .unwrap();
        assert_eq!(changed, 500);
        let after = chunk_last_id(&app, operation, 1).await;
        let changed = attome_records::mass::run_chunk(&app.state, operation, 2, after)
            .await
            .unwrap();
        assert_eq!(changed, 5);
        let (status, done, conflicts) = op_counts(&app, operation).await;
        assert_eq!(
            (status.as_str(), done, conflicts),
            ("done", 1005, 0),
            "every record once"
        );
        assert_eq!(titled(&app, &entity, "x").await, 1005);
    });
}

// feature: AA10
#[test]
fn mass_job_keeps_concurrent_user_edit() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = many_records(&app, 495).await;
        let operation = start_background_update(&app, &entity, 505).await;
        let planned = attome_records::mass::plan_chunk(&app.state, operation, 0, None)
            .await
            .unwrap()
            .expect("the operation is working");
        let record = planned[0]["id"].as_str().unwrap().to_owned();

        // Someone edits a planned record before the chunk applies.
        let version: i64 = sqlx::query_scalar(&format!(
            "SELECT row_version FROM \"{entity}\" WHERE id = $1"
        ))
        .bind(Uuid::parse_str(&record).unwrap())
        .fetch_one(app.db())
        .await
        .unwrap();
        let tag = format!("\"{version}\"");
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{entity}/{record}"),
                &[("if-match", tag.as_str())],
                Some(json!({ "title": "mine" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let changed = attome_records::mass::run_chunk(&app.state, operation, 0, None)
            .await
            .unwrap();
        assert_eq!(changed, 499);
        let (_, done, conflicts) = op_counts(&app, operation).await;
        assert_eq!((done, conflicts), (499, 1));
        let title: Option<String> =
            sqlx::query_scalar(&format!("SELECT title FROM \"{entity}\" WHERE id = $1"))
                .bind(Uuid::parse_str(&record).unwrap())
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(title.as_deref(), Some("mine"), "the user's edit stays");
    });
}

/// The operation's `If-Match` value.
async fn op_tag(app: &TestApp, operation: Uuid) -> String {
    let version: i64 = sqlx::query_scalar("SELECT row_version FROM heavy_operation WHERE id = $1")
        .bind(operation)
        .fetch_one(app.db())
        .await
        .unwrap();
    format!("\"{version}\"")
}

// feature: AA10
#[test]
fn mass_undo_restores_values() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = many_records(&app, 495).await;
        let operation = start_background_update(&app, &entity, 505).await;
        attome_records::mass::run_chunk(&app.state, operation, 0, None)
            .await
            .unwrap();
        let after = chunk_last_id(&app, operation, 0).await;
        attome_records::mass::run_chunk(&app.state, operation, 1, after)
            .await
            .unwrap();
        assert_eq!(op_counts(&app, operation).await.0, "done");
        assert_eq!(titled(&app, &entity, "x").await, 505);

        // Someone edits one record after the operation.
        let (record, version): (Uuid, i64) = sqlx::query_as(&format!(
            "SELECT id, row_version FROM \"{entity}\" ORDER BY id LIMIT 1"
        ))
        .fetch_one(app.db())
        .await
        .unwrap();
        let tag = format!("\"{version}\"");
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &format!("/api/v1/{entity}/{record}"),
                &[("if-match", tag.as_str())],
                Some(json!({ "title": "mine" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Larger than the inline threshold: undone in the background.
        let tag = op_tag(&app, operation).await;
        let (status, body) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/mass/{operation}/undo"),
                &[("if-match", tag.as_str())],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["operation"]["status"], "undoing", "{body}");
        let restored = attome_records::mass::run_undo_chunk(&app.state, operation, 1)
            .await
            .unwrap();
        assert_eq!(restored, 5);
        let restored = attome_records::mass::run_undo_chunk(&app.state, operation, 0)
            .await
            .unwrap();
        assert_eq!(restored, 499, "the edited record is left alone");
        let again = attome_records::mass::run_undo_chunk(&app.state, operation, 0)
            .await
            .unwrap();
        assert_eq!(again, 0, "an undone chunk is not replayed");
        assert_eq!(op_counts(&app, operation).await.0, "undone");

        assert_eq!(titled(&app, &entity, "x").await, 0);
        assert_eq!(titled(&app, &entity, "mine").await, 1);
        assert_eq!(
            titled(&app, &entity, "big").await
                + titled(&app, &entity, "small").await
                + titled(&app, &entity, "bulk").await,
            504,
            "every untouched record has its old title"
        );
    });
}

// feature: AA10
#[test]
fn mass_undo_refused_past_retention() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = ten_records(&app).await;
        let (status, run) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}/mass"),
                Some(json!({ "filter": title_is("big"), "kind": "update", "payload": { "title": "huge" } })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{run}");
        let operation = Uuid::parse_str(run["operation"]["id"].as_str().unwrap()).unwrap();

        // Recent: kept.
        attome_records::mass::purge_undo_values(&app.state)
            .await
            .unwrap();
        let kept: bool = sqlx::query_scalar(
            "SELECT before_values IS NOT NULL FROM heavy_operation_chunk WHERE operation_id = $1",
        )
        .bind(operation)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert!(kept);

        // Finished 40 days ago: cleared, and undo is refused.
        sqlx::query(
            "UPDATE heavy_operation SET finished_at = now() - interval '40 days' WHERE id = $1",
        )
        .bind(operation)
        .execute(app.db())
        .await
        .unwrap();
        let cleared = attome_records::mass::purge_undo_values(&app.state)
            .await
            .unwrap();
        assert!(cleared >= 1);
        let tag = op_tag(&app, operation).await;
        let (status, body) = app
            .request_with(
                Method::POST,
                &format!("/api/v1/mass/{operation}/undo"),
                &[("if-match", tag.as_str())],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            titled(&app, &entity, "huge").await,
            4,
            "nothing written back"
        );
    });
}

// feature: AA10
#[test]
fn mass_finish_notifies_starter() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = many_records(&app, 495).await;
        let operation = start_background_update(&app, &entity, 505).await;
        attome_records::mass::run_chunk(&app.state, operation, 0, None)
            .await
            .unwrap();

        // Not finished yet: no notice.
        assert!(
            !attome_notification::mass_notice::notify_finished(&app.state, operation)
                .await
                .unwrap()
        );
        let after = chunk_last_id(&app, operation, 0).await;
        attome_records::mass::run_chunk(&app.state, operation, 1, after)
            .await
            .unwrap();

        // Done: told once, however often the job asks.
        assert!(
            attome_notification::mass_notice::notify_finished(&app.state, operation)
                .await
                .unwrap()
        );
        assert!(
            !attome_notification::mass_notice::notify_finished(&app.state, operation)
                .await
                .unwrap()
        );
        let notices: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT body_text, route FROM notification_dispatch \
              WHERE recipient_user_ref = $1 AND route = $2",
        )
        .bind(app.admin.id)
        .bind(format!("/xrm/operations/{operation}"))
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(notices.len(), 1, "one notice");
        assert!(
            notices[0].0.as_deref().unwrap_or_default().contains("505"),
            "{notices:?}"
        );
    });
}

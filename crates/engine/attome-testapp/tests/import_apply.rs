//! A23-T5 and A23-T6: applying a validated import through the shared
//! mutation path (once per row, quiet unless triggers are on, updates
//! writing only the mapped columns, all or nothing when asked) and undoing
//! it (unchanged rows reverted, edited ones reported).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_document::import_stage::{header_names, stage_rows};
use attome_records::{import_apply, import_undo, import_validate};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// A fresh entity with `title`, `level` and `note`, holding one record
/// `existing` (level 1, note `keep`). Returns the entity name.
async fn fixture(app: &TestApp) -> String {
    let name = format!("ia_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    for (field, field_type) in [("title", "text"), ("level", "number"), ("note", "text")] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(json!({ "logicalname": field, "name": field, "field_type": field_type })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    let (status, record) = app
        .request(
            Method::POST,
            &format!("/api/v1/{name}"),
            Some(json!({ "title": "existing", "level": 1, "note": "keep" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{record}");
    name
}

/// A validated upsert job over `entity` matched by title, mapping Name and
/// Level only.
async fn validated_job(
    app: &TestApp,
    entity: &str,
    rows: &[[&str; 2]],
    all_or_nothing: bool,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, file_sha256, \
                                 mapping, match_mode, match_columns, all_or_nothing, status, \
                                 created_by) \
         VALUES ($1, $2, 'imports/test.csv', 'test.csv', $3, $4, 'upsert', '{title}', $5, \
                 'staged', $6)",
    )
    .bind(id)
    .bind(entity)
    .bind(id.to_string())
    .bind(json!({"columns": [
        {"source": "Name", "target": "title"},
        {"source": "Level", "target": "level"},
    ]}))
    .bind(all_or_nothing)
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .expect("insert an import job");
    let names = header_names(&["Name".into(), "Level".into()]);
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| (*c).to_owned()).collect())
        .collect();
    stage_rows(app.db(), id, &names, &rows, 1_000, None)
        .await
        .expect("stage the rows");
    import_validate::validate(&app.state, id)
        .await
        .expect("validate");
    id
}

async fn live(app: &TestApp, entity: &str) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM \"{entity}\" WHERE is_active = TRUE"
    ))
    .fetch_one(app.db())
    .await
    .expect("count the records")
}

async fn existing(app: &TestApp, entity: &str) -> Value {
    sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM \"{entity}\" t WHERE title = 'existing'"
    ))
    .fetch_one(app.db())
    .await
    .expect("read the existing record")
}

async fn job_status(app: &TestApp, job: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM import_job WHERE id = $1")
        .bind(job)
        .fetch_one(app.db())
        .await
        .unwrap()
}

// feature: A23
#[test]
fn apply_resumes_without_duplicates() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let before = live(&app, &entity).await;
        let job = validated_job(
            &app,
            &entity,
            &[["new a", "2"], ["new b", "3"], ["existing", "5"]],
            false,
        )
        .await;
        let counts = import_apply::apply(&app.state, job).await.expect("apply");
        assert_eq!(counts.applied, 3);
        assert_eq!(counts.apply_failed, 0);
        assert_eq!(live(&app, &entity).await, before + 2);
        assert_eq!(job_status(&app, job).await, "applied");

        // A worker that stopped after committing runs again: every row is
        // already in the ledger, so nothing is written twice.
        sqlx::query("UPDATE import_job SET status = 'applying' WHERE id = $1")
            .bind(job)
            .execute(app.db())
            .await
            .unwrap();
        sqlx::query("UPDATE import_stage SET status = 'valid' WHERE job_id = $1")
            .bind(job)
            .execute(app.db())
            .await
            .unwrap();
        let again = import_apply::apply(&app.state, job).await.expect("resume");
        assert_eq!(again.applied, 3, "the ledger still holds each row once");
        assert_eq!(
            live(&app, &entity).await,
            before + 2,
            "no row applied twice"
        );
    });
}

// feature: A23
#[test]
fn triggers_off_skips_workflow() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let job = validated_job(&app, &entity, &[["quiet one", "2"]], false).await;
        import_apply::apply(&app.state, job).await.expect("apply");
        let events: Vec<bool> = sqlx::query_scalar(
            "SELECT e.quiet FROM entity_change_event e \
               JOIN import_row r ON r.record_id = e.record_id \
              WHERE r.job_id = $1",
        )
        .bind(job)
        .fetch_all(app.db())
        .await
        .unwrap();
        assert!(
            !events.is_empty(),
            "the change feed still records the write"
        );
        assert!(
            events.iter().all(|quiet| *quiet),
            "no flow starts: {events:?}"
        );
    });
}

// feature: A23
#[test]
fn update_changes_only_mapped_columns() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let job = validated_job(&app, &entity, &[["existing", "7"]], false).await;
        import_apply::apply(&app.state, job).await.expect("apply");
        let record = existing(&app, &entity).await;
        assert_eq!(record["level"].as_f64(), Some(7.0), "{record}");
        assert_eq!(
            record["note"], "keep",
            "an unmapped column is untouched: {record}"
        );
    });
}

// feature: A23
// negative: import_apply
#[test]
fn all_or_nothing_rolls_back() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        // An invalid row stops an all-or-nothing import before it starts.
        let refused = validated_job(&app, &entity, &[["bad", "x"]], true).await;
        assert!(import_apply::apply(&app.state, refused).await.is_err());

        let before = live(&app, &entity).await;
        let job = validated_job(&app, &entity, &[["new c", "2"], ["existing", "9"]], true).await;
        // The record changes after the dry run: its update is refused when
        // applied, and everything the import wrote is undone.
        sqlx::query(&format!(
            "UPDATE \"{entity}\" SET note = 'edited', row_version = row_version + 1 \
              WHERE title = 'existing'"
        ))
        .execute(app.db())
        .await
        .unwrap();
        assert!(import_apply::apply(&app.state, job).await.is_err());
        assert_eq!(job_status(&app, job).await, "failed");
        assert_eq!(
            live(&app, &entity).await,
            before,
            "the created record was undone"
        );
        let record = existing(&app, &entity).await;
        assert_eq!(record["level"].as_f64(), Some(1.0), "{record}");
    });
}

// feature: A23
#[test]
fn undo_skips_edited_rows() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let before = live(&app, &entity).await;
        let job = validated_job(
            &app,
            &entity,
            &[["undo a", "2"], ["undo b", "3"], ["existing", "6"]],
            false,
        )
        .await;
        import_apply::apply(&app.state, job).await.expect("apply");
        // Someone edits one imported record afterwards.
        sqlx::query(&format!(
            "UPDATE \"{entity}\" SET note = 'mine', row_version = row_version + 1 \
              WHERE title = 'undo b'"
        ))
        .execute(app.db())
        .await
        .unwrap();

        let report = import_undo::undo(&app.state, job).await.expect("undo");
        assert_eq!(report.reverted, 2, "{report:?}");
        assert_eq!(report.skipped, 1, "{report:?}");
        assert_eq!(report.skipped_rows[0].row_no, 2, "{report:?}");
        assert_eq!(job_status(&app, job).await, "undone");
        assert_eq!(
            live(&app, &entity).await,
            before + 1,
            "the edited record stays"
        );
        let record = existing(&app, &entity).await;
        assert_eq!(
            record["level"].as_f64(),
            Some(1.0),
            "the update was reverted: {record}"
        );
        // An undone import cannot be undone again.
        assert!(import_undo::undo(&app.state, job).await.is_err());
    });
}

// feature: A23
#[test]
fn quiet_hours_defers_apply() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        // Quiet all day: two windows that together cover every minute.
        sqlx::query("INSERT INTO import_policy (entity_logicalname, quiet_hours) VALUES ($1, $2)")
            .bind(&entity)
            .bind(json!([
                {"start": "00:00", "end": "12:00"},
                {"start": "12:00", "end": "00:00"},
            ]))
            .execute(app.db())
            .await
            .unwrap();
        let before = live(&app, &entity).await;
        let job = validated_job(&app, &entity, &[["later", "2"]], false).await;
        let phase = attome_document::import_jobs::PhaseJob {
            job_id: job,
            dry_run: false,
        };
        attome_document::import_jobs::run(
            &app.state,
            attome_document::import_jobs::Phase::Apply,
            &phase,
        )
        .await
        .expect("the apply phase defers");
        assert_eq!(
            job_status(&app, job).await,
            "validated",
            "nothing applied yet"
        );
        assert_eq!(live(&app, &entity).await, before);
    });
}

// feature: A23
// negative: import_apply
#[test]
fn round_trip_export_import_uses_row_version() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let record = existing(&app, &entity).await;
        let id = record["id"].as_str().unwrap().to_owned();
        let exported_version = record["row_version"].as_i64().unwrap().to_string();

        // The file as an export wrote it: id and row_version first, then
        // the person's edit.
        let job = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, file_sha256, \
                                     mapping, match_mode, status, created_by) \
             VALUES ($1, $2, 'imports/rt.csv', 'rt.csv', $3, '{}', 'update', 'staged', $4)",
        )
        .bind(job)
        .bind(&entity)
        .bind(job.to_string())
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();
        let names = header_names(&["id".into(), "row_version".into(), "level".into()]);
        stage_rows(
            app.db(),
            job,
            &names,
            &[vec![id.clone(), exported_version, "8".into()]],
            1_000,
            None,
        )
        .await
        .unwrap();
        import_validate::validate(&app.state, job)
            .await
            .expect("validate");

        // Someone changes the record after the export.
        sqlx::query(&format!(
            "UPDATE \"{entity}\" SET note = 'changed', row_version = row_version + 1 \
              WHERE id = $1::uuid"
        ))
        .bind(&id)
        .execute(app.db())
        .await
        .unwrap();

        let counts = import_apply::apply(&app.state, job).await.expect("apply");
        assert_eq!(counts.applied, 0);
        assert_eq!(counts.apply_failed, 1);
        let error: Value =
            sqlx::query_scalar("SELECT error FROM import_stage WHERE job_id = $1 AND row_no = 1")
                .bind(job)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(
            error["errors"][0]["code"], "changed_since_validation",
            "{error}"
        );
        let after = existing(&app, &entity).await;
        assert_eq!(
            after["level"].as_f64(),
            Some(1.0),
            "not overwritten: {after}"
        );
        assert_eq!(after["note"], "changed", "{after}");
    });
}

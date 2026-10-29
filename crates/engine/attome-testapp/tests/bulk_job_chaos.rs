//! AB9-T6 (bulk half): an import's apply worker killed mid-run resumes
//! without duplicating a row. `import_apply::apply` writes
//! [`import_apply::APPLY_BATCH`] rows per transaction and keeps its cursor in
//! `import_row` (written in each row's own batch), so whatever committed is
//! never applied again and whatever did not rolled back with its batch.
//!
//! The kill is real: the apply runs in its own task, which is aborted (its
//! future dropped, its open transaction rolled back on the dropped
//! connection) once the first batch has committed. A second run then
//! finishes the job.
//!
//! ```powershell
//! cargo test -p attome-testapp --test bulk_job_chaos
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Duration;

use attome_document::import_stage::{header_names, stage_rows};
use attome_records::{import_apply, import_validate};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// The import's size: four batches.
const ROWS: i64 = 2_000;

/// A fresh entity with `title` and `level`. Returns its name.
async fn fixture(app: &TestApp) -> String {
    let name = format!("bjc_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    for (field, field_type) in [("title", "text"), ("level", "number")] {
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
    name
}

/// A validated create job of [`ROWS`] distinct rows over `entity`.
async fn validated_job(app: &TestApp, entity: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, file_sha256, \
                                 mapping, match_mode, match_columns, all_or_nothing, status, \
                                 created_by) \
         VALUES ($1, $2, 'imports/chaos.csv', 'chaos.csv', $3, $4, 'create', '{title}', false, \
                 'staged', $5)",
    )
    .bind(id)
    .bind(entity)
    .bind(id.to_string())
    .bind(json!({"columns": [
        {"source": "Name", "target": "title"},
        {"source": "Level", "target": "level"},
    ]}))
    .bind(app.admin.id)
    .execute(app.db())
    .await
    .expect("insert an import job");
    let names = header_names(&["Name".into(), "Level".into()]);
    let rows: Vec<Vec<String>> = (0..ROWS)
        .map(|i| vec![format!("chaos row {i}"), i.to_string()])
        .collect();
    stage_rows(app.db(), id, &names, &rows, 1_000, None)
        .await
        .expect("stage the rows");
    import_validate::validate(&app.state, id)
        .await
        .expect("validate");
    id
}

async fn count(app: &TestApp, sql: &str, job: Option<Uuid>) -> i64 {
    let query = sqlx::query_scalar::<_, i64>(sql);
    let query = match job {
        Some(job) => query.bind(job),
        None => query,
    };
    query.fetch_one(app.db()).await.expect("count")
}

// feature: A23
#[test]
fn bulk_import_resumes_without_duplicates() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let job = validated_job(&app, &entity).await;
        let ledger = "SELECT COUNT(*) FROM import_row WHERE job_id = $1";

        // The worker: killed once its first batch has committed.
        let state = app.state.clone();
        let worker = tokio::spawn(async move { import_apply::apply(&state, job).await });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while count(&app, ledger, Some(job)).await < import_apply::APPLY_BATCH {
            assert!(
                !worker.is_finished(),
                "the apply ended before its first batch was seen"
            );
            assert!(
                tokio::time::Instant::now() < deadline,
                "no batch committed in time"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        worker.abort();
        let _ = worker.await;

        let committed = count(&app, ledger, Some(job)).await;
        let records = count(&app, &format!("SELECT COUNT(*) FROM \"{entity}\""), None).await;
        assert_eq!(
            records, committed,
            "a record exists exactly for each ledger row at the kill"
        );
        assert_eq!(
            committed % import_apply::APPLY_BATCH,
            0,
            "only whole batches committed"
        );

        // The restarted worker finishes the job.
        let counts = import_apply::apply(&app.state, job)
            .await
            .expect("resume the apply");
        assert_eq!(counts.applied, ROWS);
        assert_eq!(counts.apply_failed, 0);
        assert_eq!(count(&app, ledger, Some(job)).await, ROWS);
        assert_eq!(
            count(&app, &format!("SELECT COUNT(*) FROM \"{entity}\""), None).await,
            ROWS,
            "every row once, none twice"
        );
        assert_eq!(
            count(
                &app,
                &format!("SELECT COUNT(DISTINCT title) FROM \"{entity}\""),
                None
            )
            .await,
            ROWS
        );
        let status: String = sqlx::query_scalar("SELECT status FROM import_job WHERE id = $1")
            .bind(job)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(status, "applied");
    });
}

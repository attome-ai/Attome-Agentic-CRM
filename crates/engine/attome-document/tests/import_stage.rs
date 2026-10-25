//! A23-T3: staging resumes from the job's cursor after an interrupted run.
//! Needs a migrated throwaway Postgres (`DATABASE_URL`); skips without one.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_document::import_stage::{header_names, stage_rows};
use attome_testkit::migrated_pool_or_skip;
use uuid::Uuid;

async fn new_job(db: &sqlx::PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, file_sha256, \
                                 mapping, match_mode, status, created_by) \
         VALUES ($1, 'contact', 'imports/test.csv', 'test.csv', $2, '{}', 'create', 'uploaded', $3)",
    )
    .bind(id)
    .bind(id.to_string())
    .bind(Uuid::nil())
    .execute(db)
    .await
    .expect("insert an import job");
    id
}

#[tokio::test]
async fn stage_resumes_after_interrupt() {
    let db = migrated_pool_or_skip!();
    let job = new_job(&db).await;
    let names = header_names(&["name".to_owned(), "city".to_owned()]);
    let rows: Vec<Vec<String>> = (1..=7)
        .map(|n| vec![format!("person {n}"), "Riyadh".to_owned()])
        .collect();

    // The first run stops after one chunk of three rows.
    let first = stage_rows(&db, job, &names, &rows, 3, Some(1))
        .await
        .expect("first run");
    assert_eq!(first, 3);
    // A chunk that never committed its cursor left a stray row behind.
    sqlx::query(
        "INSERT INTO import_stage (job_id, row_no, raw) VALUES ($1, 4, '{\"name\":\"stale\"}')",
    )
    .bind(job)
    .execute(&db)
    .await
    .expect("a stray row past the cursor");

    let second = stage_rows(&db, job, &names, &rows, 3, None)
        .await
        .expect("second run");
    assert_eq!(second, 4, "the rest of the file, once");

    let staged: Vec<(i32, String)> = sqlx::query_as(
        "SELECT row_no, raw->>'name' FROM import_stage WHERE job_id = $1 ORDER BY row_no",
    )
    .bind(job)
    .fetch_all(&db)
    .await
    .expect("read the stage");
    assert_eq!(staged.len(), 7, "exactly the file's rows");
    for (i, (row_no, name)) in staged.iter().enumerate() {
        assert_eq!(*row_no, i as i32 + 1);
        assert_eq!(name, &format!("person {}", i + 1));
    }
    let cursor: i32 = sqlx::query_scalar("SELECT cursor_row FROM import_job WHERE id = $1")
        .bind(job)
        .fetch_one(&db)
        .await
        .expect("the cursor");
    assert_eq!(cursor, 7);

    sqlx::query("DELETE FROM import_stage WHERE job_id = $1")
        .bind(job)
        .execute(&db)
        .await
        .ok();
    sqlx::query("DELETE FROM import_job WHERE id = $1")
        .bind(job)
        .execute(&db)
        .await
        .ok();
}

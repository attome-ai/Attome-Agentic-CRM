//! A23-T3: staging an import file's rows into `import_stage`.
//!
//! [`stage`] reads the job's file from storage, parses it with
//! [`crate::import_reader`], and writes each data row as a JSON object of
//! header to cell text with `COPY ... FROM STDIN`, [`STAGE_CHUNK`] rows per
//! short transaction. After each chunk the job's `cursor_row` moves to the
//! last staged row, so a restart deletes anything staged past the cursor (a
//! chunk that never committed its cursor) and continues from there.
//! `import_policy.max_rows` caps the file: a larger one fails the job with
//! the reason in `counts.error`.
//!
//! The reader parses the whole file in memory (an XLSX is a ZIP that cannot
//! be read as a stream); the upload size limit bounds it, and the parse runs
//! on the blocking pool.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::import_reader;

/// Rows per COPY and per transaction.
pub const STAGE_CHUNK: usize = 10_000;

/// What a staging run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageOutcome {
    /// Data rows in the file.
    pub total_rows: usize,
    /// Rows this run wrote (after a resume, only the rest).
    pub staged_now: usize,
}

/// The column names rows are keyed by: a blank header is `column_<n>`, a
/// repeated one gets `_<n>` (1-based column number). Pure.
pub fn header_names(header: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    header
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let base = h.trim();
            let mut name = if base.is_empty() {
                format!("column_{}", i + 1)
            } else {
                base.to_owned()
            };
            if !seen.insert(name.clone()) {
                name = format!("{name}_{}", i + 1);
                seen.insert(name.clone());
            }
            name
        })
        .collect()
}

/// One row as the JSON object staged in `raw`. Pure.
pub fn raw_row(names: &[String], row: &[String]) -> Value {
    let mut object = Map::new();
    for (i, name) in names.iter().enumerate() {
        let cell = row.get(i).map(String::as_str).unwrap_or_default();
        object.insert(name.clone(), Value::String(cell.to_owned()));
    }
    Value::Object(object)
}

fn csv_field(text: &str) -> String {
    format!("\"{}\"", text.replace('"', "\"\""))
}

/// The CSV a COPY of `rows` reads: `job_id,row_no,raw`, rows numbered from
/// `first_row_no`. Pure.
pub fn copy_csv(job_id: Uuid, names: &[String], rows: &[Vec<String>], first_row_no: i32) -> String {
    let mut out = String::new();
    for (offset, row) in rows.iter().enumerate() {
        let row_no = first_row_no + offset as i32;
        out.push_str(&format!(
            "{job_id},{row_no},{}\n",
            csv_field(&raw_row(names, row).to_string())
        ));
    }
    out
}

/// Stages `rows` (data rows, header excluded) for `job_id` from its cursor:
/// deletes rows past the cursor, then COPYs `chunk` rows per transaction,
/// advancing `cursor_row` with each. `max_chunks` stops early (a test
/// interrupts a run with it). Returns how many rows it wrote.
pub async fn stage_rows(
    db: &DbPool,
    job_id: Uuid,
    names: &[String],
    rows: &[Vec<String>],
    chunk: usize,
    max_chunks: Option<usize>,
) -> Result<usize, AppError> {
    let chunk = chunk.max(1);
    let cursor: i32 = sqlx::query_scalar("SELECT cursor_row FROM import_job WHERE id = $1")
        .bind(job_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    // A chunk that never committed its cursor may have left rows behind.
    sqlx::query("DELETE FROM import_stage WHERE job_id = $1 AND row_no > $2")
        .bind(job_id)
        .bind(cursor)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    let start = usize::try_from(cursor).unwrap_or(0).min(rows.len());
    let mut written = 0;
    for (n, part) in rows[start..].chunks(chunk).enumerate() {
        if max_chunks.is_some_and(|max| n >= max) {
            break;
        }
        let first_row_no = i32::try_from(start + written + 1).map_err(AppError::internal)?;
        let csv = copy_csv(job_id, names, part, first_row_no);
        let mut tx = attome_db::tx::begin(db).await?;
        let mut copy = (&mut *tx)
            .copy_in_raw("COPY import_stage (job_id, row_no, raw) FROM STDIN (FORMAT csv)")
            .await
            .map_err(AppError::internal)?;
        copy.send(csv.into_bytes())
            .await
            .map_err(AppError::internal)?;
        copy.finish().await.map_err(AppError::internal)?;
        let last = first_row_no + i32::try_from(part.len()).map_err(AppError::internal)? - 1;
        sqlx::query(
            "UPDATE import_job SET cursor_row = $2, row_version = row_version + 1 WHERE id = $1",
        )
        .bind(job_id)
        .bind(last)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        tx.commit().await.map_err(AppError::internal)?;
        written += part.len();
    }
    Ok(written)
}

async fn fail_job(db: &DbPool, job_id: Uuid, error: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE import_job SET status = 'failed', finished_at = now(), \
                counts = counts || jsonb_build_object('error', $2::text), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(job_id)
    .bind(error)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Stages job `job_id`'s file (see the module doc). The job must be
/// `uploaded`; on success it is `staged` with `counts.staged`.
pub async fn stage(state: &EngineState, job_id: Uuid) -> Result<StageOutcome, AppError> {
    let db = &state.base.db;
    let job: Option<(String, String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT entity_logicalname, storage_key, file_name, sheet, status \
           FROM import_job WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (entity, key, file_name, sheet, status) = job.ok_or(AppError::NotFound)?;
    if status != "uploaded" {
        return Err(AppError::Conflict("only an uploaded import can be staged"));
    }
    let bytes = attome_storage::mirror::read_object(&state.base.storage, &key)
        .await
        .map_err(AppError::internal)?;
    let is_xlsx = file_name.to_ascii_lowercase().ends_with(".xlsx");
    let parsed = tokio::task::spawn_blocking(move || {
        if is_xlsx {
            import_reader::read_xlsx(&bytes, sheet.as_deref()).map(|s| s.rows)
        } else {
            import_reader::read_csv(&bytes, None)
        }
    })
    .await
    .map_err(AppError::internal)?;
    let mut rows = match parsed {
        Ok(rows) => rows,
        Err(e) => {
            fail_job(db, job_id, &e.to_string()).await?;
            return Err(AppError::Validation(e.to_string()));
        }
    };
    if rows.is_empty() {
        fail_job(db, job_id, "the file has no header row").await?;
        return Err(AppError::Validation("the file has no header row".into()));
    }
    let names = header_names(&rows.remove(0));
    let max_rows: Option<i32> =
        sqlx::query_scalar("SELECT max_rows FROM import_policy WHERE entity_logicalname = $1")
            .bind(&entity)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    if let Some(max) = max_rows
        && rows.len() > usize::try_from(max).unwrap_or(0)
    {
        let error = format!(
            "the file has {} rows; this entity takes at most {max}",
            rows.len()
        );
        fail_job(db, job_id, &error).await?;
        return Err(AppError::Validation(error));
    }
    let staged_now = stage_rows(db, job_id, &names, &rows, STAGE_CHUNK, None).await?;
    sqlx::query(
        "UPDATE import_job SET status = 'staged', \
                counts = counts || jsonb_build_object('staged', $2::int), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(job_id)
    .bind(i32::try_from(rows.len()).map_err(AppError::internal)?)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(StageOutcome {
        total_rows: rows.len(),
        staged_now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_headers_are_unique_and_named() {
        let names = header_names(&["name".into(), String::new(), "name".into()]);
        assert_eq!(names, ["name", "column_2", "name_3"]);
    }

    #[test]
    fn stage_copy_csv_quotes_the_json() {
        let job = Uuid::nil();
        let names = vec!["a".to_owned(), "b".to_owned()];
        let csv = copy_csv(job, &names, &[vec!["x\"y".into()]], 7);
        assert_eq!(
            csv,
            format!("{job},7,\"{{\"\"a\"\":\"\"x\\\"\"y\"\",\"\"b\"\":\"\"\"\"}}\"\n")
        );
    }
}

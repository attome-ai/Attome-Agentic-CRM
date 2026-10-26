//! A23-T6: undoing a whole import. [`undo`] walks the job's `import_row`
//! ledger [`UNDO_BATCH`] rows at a time, each batch in one transaction:
//!
//! - a **created** record is soft deleted (never hard deleted) when its row
//!   version is still the one the import left (`after_row_version`), through
//!   the shared delete path with the import as its origin, so its dependents
//!   follow their own delete rules;
//! - an **updated** record gets back the values the import changed (the
//!   before-image of the columns it wrote) when it too is unchanged since,
//!   through the shared update path;
//! - a record edited, deleted or restored since the import is left as it is
//!   and listed in the report.
//!
//! An undone row leaves the ledger in the same transaction as its undo, so
//! a stopped undo resumes with what is left, and the rows still in the
//! ledger at the end are exactly the skipped ones. The job ends `undone`,
//! with `counts.undo = {reverted, skipped, skipped_rows}` (the first
//! [`REPORT_LIMIT`] skipped rows by number and record). Every write runs
//! quiet ([`attome_core::quiet_scope`]): reverting an import starts no flow.

use attome_core::{EngineState, quote_ident};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::entity_crud;
use crate::entity_mutation::{self, DeleteKind, DeleteOrigin, MutationMode};
use crate::import_apply::{Target, audit_service, import_audit_event, refusal_code};

/// The dependents of the import's entity and the caller's access to each,
/// resolved once on the pool before any transaction opens.
type Dependents = (
    Vec<(String, String, attome_core::OnTargetDelete)>,
    Vec<(Option<attome_server::security::AccessLevel>, bool)>,
);

/// Ledger rows reverted per transaction.
pub const UNDO_BATCH: i64 = 500;

/// The most skipped rows the report lists by number.
pub const REPORT_LIMIT: i64 = 1_000;

/// One row the undo left alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedRow {
    pub row_no: i32,
    pub record_id: Uuid,
}

/// What an undo did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UndoReport {
    pub reverted: i64,
    pub skipped: i64,
    pub skipped_rows: Vec<SkippedRow>,
}

#[derive(sqlx::FromRow)]
struct LedgerRow {
    row_no: i32,
    action: String,
    record_id: Uuid,
    before: Option<Value>,
    after_row_version: i64,
    mapped: Option<Value>,
}

/// The before-image of the columns an update wrote: its mapped fields that
/// are attributes, with the values the record held before. Pure.
fn restore_body(target: &Target, row: &LedgerRow) -> Map<String, Value> {
    let before = row.before.as_ref().and_then(Value::as_object);
    let written = row.mapped.as_ref().and_then(Value::as_object);
    let mut body = Map::new();
    for attr in &target.attrs {
        let name = attr.logicalname.as_str();
        if written.is_some_and(|w| w.contains_key(name)) {
            body.insert(
                name.to_owned(),
                before
                    .and_then(|b| b.get(name))
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
    }
    body
}

/// Reverts one ledger row inside the batch's transaction when the record is
/// unchanged since the import. Returns whether it did.
#[allow(clippy::too_many_arguments)]
async fn undo_row(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    ctx: &SecurityContext,
    target: &Target,
    job_id: Uuid,
    row: &LedgerRow,
    dependents: &Dependents,
    user_ctx: attome_audit::AuditUserContext,
    org_ref: Uuid,
) -> Result<bool, AppError> {
    let current: Option<i64> = sqlx::query_scalar(&format!(
        "SELECT row_version FROM {} WHERE id = $1 AND is_active = TRUE FOR UPDATE",
        quote_ident(&target.entity_name)
    ))
    .bind(row.record_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if current != Some(row.after_row_version) {
        return Ok(false);
    }
    let user_id = ctx.user_id;
    let (operation, changed_fields) = if row.action == "created" {
        let (dependents, access) = dependents;
        entity_crud::guard_cascade_dependent_access(
            tx,
            state,
            ctx,
            dependents,
            row.record_id,
            access,
        )
        .await?;
        entity_mutation::delete_one(
            tx,
            &target.entity_name,
            dependents,
            row.record_id,
            user_id,
            Some(row.after_row_version),
            &DeleteOrigin::with_id(DeleteKind::Import, job_id.to_string()),
        )
        .await?;
        (attome_audit::AuditOperation::SoftDelete, Vec::new())
    } else {
        let body = restore_body(target, row);
        let updated = entity_mutation::update_one(
            tx,
            state,
            ctx,
            &target.entity_name,
            target.entity_id,
            row.record_id,
            &target.attrs,
            &body,
            user_id,
            row.after_row_version,
            MutationMode::Strict,
        )
        .await?;
        let changed = entity_crud::field_changes_from_obj(
            tx,
            state,
            &target.attrs,
            &body,
            updated.old_row.as_ref(),
        )
        .await;
        (attome_audit::AuditOperation::Update, changed)
    };
    let event = import_audit_event(
        org_ref,
        user_ctx,
        &target.entity_name,
        row.record_id,
        operation,
        Some(row.after_row_version),
        job_id,
        "import undone",
        changed_fields,
    );
    audit_service(state).write_in_tx(tx, event).await?;
    sqlx::query("DELETE FROM import_row WHERE job_id = $1 AND row_no = $2")
        .bind(job_id)
        .bind(row.row_no)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query("UPDATE import_stage SET status = 'valid' WHERE job_id = $1 AND row_no = $2")
        .bind(job_id)
        .bind(row.row_no)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(true)
}

/// Reverts every ledger row it can, without touching the job's status: the
/// all-or-nothing rollback of [`crate::import_apply::apply`] and the body of
/// [`undo`]. Returns how many rows it reverted.
pub(crate) async fn undo_rows(state: &EngineState, job_id: Uuid) -> Result<i64, AppError> {
    let (entity, created_by): (String, Uuid) =
        sqlx::query_as("SELECT entity_logicalname, created_by FROM import_job WHERE id = $1")
            .bind(job_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;
    let (entity_id, entity_name, attrs, _) = entity_crud::resolve_entity(state, &entity).await?;
    let target = Target {
        entity_id,
        entity_name,
        attrs,
    };
    let ctx = attome_security::resolve_uncached(&state.base.db, created_by).await?;
    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, ctx.user_id).await;
    let dependents = state.entities.load().dependents_of(target.entity_id);
    let access = entity_crud::resolve_cascade_dependent_access(state, &ctx, &dependents).await?;
    let dependents: Dependents = (dependents, access);

    let mut reverted = 0_i64;
    // Skipped rows stay in the ledger; page past them by row number.
    let mut after = 0_i32;
    loop {
        let rows: Vec<LedgerRow> = sqlx::query_as(
            "SELECT r.row_no, r.action, r.record_id, r.before, r.after_row_version, s.mapped \
               FROM import_row r \
               LEFT JOIN import_stage s ON s.job_id = r.job_id AND s.row_no = r.row_no \
              WHERE r.job_id = $1 AND r.row_no > $2 \
              ORDER BY r.row_no LIMIT $3",
        )
        .bind(job_id)
        .bind(after)
        .bind(UNDO_BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = rows.last() else {
            break;
        };
        after = last.row_no;
        let batch = async {
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let mut done = 0_i64;
            for row in &rows {
                // A savepoint: a revert the engine refuses (a required field
                // the import filled) leaves the row in the ledger, skipped.
                let mut savepoint = sqlx::Acquire::begin(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                let result = undo_row(
                    &mut savepoint,
                    state,
                    &ctx,
                    &target,
                    job_id,
                    row,
                    &dependents,
                    user_ctx.clone(),
                    org_ref,
                )
                .await;
                match result {
                    Ok(true) => {
                        attome_db::tx::commit(savepoint).await?;
                        done += 1;
                    }
                    Ok(false) => savepoint.rollback().await.map_err(AppError::internal)?,
                    Err(e) if refusal_code(&e).is_some() => {
                        tracing::info!(%job_id, row_no = row.row_no, "an import row could not be reverted");
                        savepoint.rollback().await.map_err(AppError::internal)?;
                    }
                    Err(e) => return Err(e),
                }
            }
            // Progress, with the batch, so a resumed undo reports every row.
            sqlx::query(
                "UPDATE import_job SET counts = counts || jsonb_build_object('undo_reverted', \
                        COALESCE((counts->>'undo_reverted')::bigint, 0) + $2) \
                  WHERE id = $1",
            )
            .bind(job_id)
            .bind(done)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            attome_db::tx::commit(tx).await?;
            Ok::<i64, AppError>(done)
        };
        reverted += attome_core::quiet_scope::quiet(batch).await?;
    }
    Ok(reverted)
}

/// Undoes job `job_id` (see the module doc). The job must be `applied`,
/// `failed`, or `undoing` when a stopped undo resumes.
pub async fn undo(state: &EngineState, job_id: Uuid) -> Result<UndoReport, AppError> {
    let claimed = sqlx::query(
        "UPDATE import_job SET status = 'undoing', row_version = row_version + 1 \
          WHERE id = $1 AND status IN ('applied', 'failed', 'undoing')",
    )
    .bind(job_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM import_job WHERE id = $1)")
                .bind(job_id)
                .fetch_one(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::Conflict("only an applied or failed import can be undone")
        } else {
            AppError::NotFound
        });
    }
    undo_rows(state, job_id).await?;
    let reverted: i64 = sqlx::query_scalar(
        "SELECT COALESCE((counts->>'undo_reverted')::bigint, 0) FROM import_job WHERE id = $1",
    )
    .bind(job_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let skipped: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM import_row WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let skipped_rows: Vec<(i32, Uuid)> = sqlx::query_as(
        "SELECT row_no, record_id FROM import_row WHERE job_id = $1 ORDER BY row_no LIMIT $2",
    )
    .bind(job_id)
    .bind(REPORT_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let report = UndoReport {
        reverted,
        skipped,
        skipped_rows: skipped_rows
            .into_iter()
            .map(|(row_no, record_id)| SkippedRow { row_no, record_id })
            .collect(),
    };
    sqlx::query(
        "UPDATE import_job SET status = 'undone', finished_at = now(), \
                counts = counts || jsonb_build_object('undo', $2::jsonb), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(job_id)
    .bind(serde_json::to_value(&report).map_err(AppError::internal)?)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(report)
}

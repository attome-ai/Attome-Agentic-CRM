//! A23-T5: applying a validated import. [`apply`] writes the job's valid
//! `create` and `update` rows [`APPLY_BATCH`] at a time, each batch in one
//! transaction, through the same per-item functions the bulk worker uses
//! ([`entity_mutation::create_one`], [`entity_mutation::update_one`]), so
//! record rules, field security, row versions, the creator share, the file
//! mirror and the audit trail are those of any other write. In the batch's
//! transaction each row also gets its `import_row` (the before-image of an
//! update, the row version it left) and its stage status `applied`; a row
//! the engine refuses rolls back to its own savepoint and is marked
//! `invalid` with the reason, unless the job is all-or-nothing.
//!
//! - **Updates write only the mapped columns** (the stage's `mapped`), with
//!   the row version validation read as `If-Match`: a record edited since
//!   the dry run is refused, not overwritten.
//! - **Triggers.** With `triggers_on` off (the default) every write runs in
//!   [`attome_core::quiet_scope::quiet`]: the change feed still records it,
//!   but workflow entry triggers start no flow and followers get no
//!   notification.
//! - **Resume.** A row with an `import_row` is never applied again, and the
//!   row, its `import_row` and its stage status commit together, so a worker
//!   stopped at any point resumes where it was and applies each row once.
//! - **All or nothing.** Such a job refuses to start while any row is
//!   invalid; when a row fails later, its batch rolls back, the rows already
//!   applied are undone ([`crate::import_undo`]) and the job is `failed`.
//!
//! Applying ends with `counts.applied` / `counts.apply_failed` and status
//! `applied`. The job's `cursor_row` stays the staging cursor: the
//! `import_row` table is the apply cursor.

use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService};
use attome_core::{AttrInfo, EngineState};
use attome_security::RecordAction;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::entity_crud;
use crate::entity_mutation::{self, MutationMode};

/// Rows written per transaction.
pub const APPLY_BATCH: i64 = 500;

/// What [`apply`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ApplyCounts {
    /// Rows applied, this run and earlier ones.
    pub applied: i64,
    /// Rows the engine refused while applying.
    pub apply_failed: i64,
}

#[derive(sqlx::FromRow)]
struct JobRow {
    entity_logicalname: String,
    status: String,
    all_or_nothing: bool,
    triggers_on: bool,
    created_by: Uuid,
}

#[derive(sqlx::FromRow)]
struct StageRow {
    row_no: i32,
    mapped: Option<Value>,
    action: Option<String>,
    record_id: Option<Uuid>,
    record_row_version: Option<i64>,
    /// A24-T4: a migration import's owner for a created record (the source
    /// owner mapped to a user account here, the staged `__owner` cell). Only
    /// a job the migration wave made carries one; an uploaded file's
    /// `__owner` column is never read.
    owner: Option<String>,
}

/// The entity an import writes, resolved once per run.
pub(crate) struct Target {
    pub(crate) entity_id: Uuid,
    pub(crate) entity_name: String,
    pub(crate) attrs: Vec<AttrInfo>,
}

/// The code a row the engine refused is marked with, or `None` for a failure
/// that is not the row's fault (the database, a timeout): that one stops the
/// run, its batch rolls back, and the next run resumes. Pure.
pub(crate) fn refusal_code(error: &AppError) -> Option<&'static str> {
    Some(match error {
        AppError::Validation(_) | AppError::FieldValidation(_) => "invalid",
        AppError::RuleViolation { .. } => "rule_violation",
        AppError::Forbidden | AppError::AttributeNotWritable(_) => "forbidden",
        AppError::NotFound => "not_found",
        AppError::VersionConflict | AppError::VersionConflictAt { .. } => {
            "changed_since_validation"
        }
        AppError::DuplicateDetected { .. } => "duplicate_detected",
        AppError::Conflict(_) => "conflict",
        _ => return None,
    })
}

/// The audit event of one imported write, correlated to the job.
#[allow(clippy::too_many_arguments)]
pub(crate) fn import_audit_event(
    org_ref: Uuid,
    user_ctx: attome_audit::AuditUserContext,
    entity_name: &str,
    record_id: Uuid,
    operation: AuditOperation,
    version_before: Option<i64>,
    job_id: Uuid,
    comment: &str,
    changed_fields: Vec<attome_audit::AuditFieldChange>,
) -> AuditEvent {
    AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(entity_name.to_owned()),
        record_id: Some(record_id),
        operation,
        version_before,
        version_after: None,
        user_context: user_ctx,
        changed_on: chrono::Utc::now(),
        source: attome_audit::AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(job_id),
        event_name: None,
        event_comment: Some(comment.to_owned()),
        changed_fields,
        snapshot_json: None,
    }
}

pub(crate) fn audit_service(state: &EngineState) -> AuditService<'_> {
    AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone())
}

/// A row's row version, from a mutation's returned row.
pub(crate) fn row_version_of(row: Option<&Value>) -> Option<i64> {
    row.and_then(|r| r.get("row_version"))
        .and_then(Value::as_i64)
}

/// The values one row writes: its mapped fields without the `id` that
/// named the record.
fn body_of(row: &StageRow) -> Map<String, Value> {
    let mut body = row
        .mapped
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    body.remove("id");
    body.remove("row_version");
    body
}

/// Marks a row the engine refused, inside the batch's transaction.
async fn mark_failed(
    tx: &mut attome_db::Tx<'_>,
    job_id: Uuid,
    row_no: i32,
    code: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE import_stage SET status = 'invalid', \
                error = jsonb_build_object('errors', jsonb_build_array(jsonb_build_object( \
                    'field', '', 'code', $3::text, 'message_key', 'import.error.' || $3::text))) \
          WHERE job_id = $1 AND row_no = $2",
    )
    .bind(job_id)
    .bind(row_no)
    .bind(code)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Writes one row inside the batch's transaction (on a savepoint the caller
/// opened): the record, its creator share and file mirror, the audit event,
/// its `import_row` and its stage status.
#[allow(clippy::too_many_arguments)]
async fn apply_row(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    ctx: &SecurityContext,
    target: &Target,
    job_id: Uuid,
    row: &StageRow,
    user_ctx: attome_audit::AuditUserContext,
    org_ref: Uuid,
) -> Result<(), AppError> {
    let body = body_of(row);
    let user_id = ctx.user_id;
    let (mutation, operation, version_before) = match row.action.as_deref() {
        Some("create") => {
            // A24-T4: a migrated record keeps its owner when the source
            // owner maps to an active user account here.
            let owner = match row
                .owner
                .as_deref()
                .and_then(|o| Uuid::parse_str(o.trim()).ok())
            {
                Some(owner) => {
                    let active: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM user_account WHERE id = $1 AND is_active IS NOT FALSE)",
                    )
                    .bind(owner)
                    .fetch_one(&mut **tx)
                    .await
                    .map_err(AppError::internal)?;
                    active.then_some(owner)
                }
                None => None,
            };
            let stamp = entity_mutation::CreateStamp {
                owner_ref: owner.unwrap_or(user_id),
                ..entity_mutation::CreateStamp::staff(user_id, org_ref)
            };
            let created = entity_mutation::with_defaults(
                true,
                entity_mutation::create_one_as(
                    tx,
                    state,
                    entity_mutation::Principal::Staff(ctx),
                    &target.entity_name,
                    &target.attrs,
                    &body,
                    stamp,
                    MutationMode::Strict,
                ),
            )
            .await?;
            entity_crud::grant_creator_share(tx, target.entity_id, created.record_id, user_id)
                .await?;
            if let Some(owner) = owner.filter(|o| *o != user_id) {
                entity_crud::grant_creator_share(tx, target.entity_id, created.record_id, owner)
                    .await?;
            }
            (created, AuditOperation::Create, None)
        }
        Some("update") => {
            let record_id = row
                .record_id
                .ok_or_else(|| AppError::internal("an update row without its record"))?;
            let expected = row
                .record_row_version
                .ok_or_else(|| AppError::internal("an update row without its row version"))?;
            let updated = entity_mutation::update_one(
                tx,
                state,
                ctx,
                &target.entity_name,
                target.entity_id,
                record_id,
                &target.attrs,
                &body,
                user_id,
                expected,
                MutationMode::Strict,
            )
            .await?;
            (updated, AuditOperation::Update, Some(expected))
        }
        _ => {
            return Err(AppError::internal(
                "only create and update rows are applied",
            ));
        }
    };

    if let Some(new_row) = mutation.new_row.as_ref() {
        entity_crud::sync_file_field_documents(
            tx,
            state,
            ctx,
            user_id,
            org_ref,
            &target.entity_name,
            mutation.record_id,
            &target.attrs,
            new_row,
        )
        .await?;
    }
    let changed_fields = entity_crud::field_changes_from_obj(
        tx,
        state,
        &target.attrs,
        &body,
        mutation.old_row.as_ref(),
    )
    .await;
    let event = import_audit_event(
        org_ref,
        user_ctx,
        &target.entity_name,
        mutation.record_id,
        operation,
        version_before,
        job_id,
        "import",
        changed_fields,
    );
    audit_service(state).write_in_tx(tx, event).await?;

    let after_row_version = row_version_of(mutation.new_row.as_ref())
        .ok_or_else(|| AppError::internal("the write returned no row_version"))?;
    let (action, before) = if operation == AuditOperation::Create {
        ("created", None)
    } else {
        ("updated", mutation.old_row.clone())
    };
    sqlx::query(
        "INSERT INTO import_row (job_id, row_no, action, record_id, before, after_row_version) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(job_id)
    .bind(row.row_no)
    .bind(action)
    .bind(mutation.record_id)
    .bind(before)
    .bind(after_row_version)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE import_stage SET status = 'applied', record_id = $3 \
          WHERE job_id = $1 AND row_no = $2",
    )
    .bind(job_id)
    .bind(row.row_no)
    .bind(mutation.record_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The checks a row passes before its batch's transaction opens, on the
/// pool, as the bulk worker runs them: record access for an update, the
/// parent of an attached record, and the duplicate rules.
async fn preflight(
    state: &EngineState,
    ctx: &SecurityContext,
    target: &Target,
    update_access: (AccessLevel, bool),
    row: &StageRow,
) -> Result<(), AppError> {
    let body = body_of(row);
    let existing = row
        .record_id
        .filter(|_| row.action.as_deref() == Some("update"));
    if let Some(record_id) = existing {
        let (access_level, owner_visible) = update_access;
        entity_crud::require_record_access_with(
            state,
            ctx,
            target.entity_id,
            &target.entity_name,
            record_id,
            RecordAction::Update,
            access_level,
            owner_visible,
        )
        .await?;
        entity_crud::require_child_parent_access(state, ctx, &target.entity_name, record_id)
            .await?;
    }
    entity_crud::require_child_parent_access_for_write(
        state,
        ctx,
        &target.entity_name,
        existing,
        &body,
    )
    .await?;
    crate::duplicate_check::guard(
        state,
        ctx,
        target.entity_id,
        &target.entity_name,
        existing,
        &body,
    )
    .await
    .map(|_| ())
}

/// One batch: preflight each row, then write them all in one transaction.
/// Returns how many rows it applied and how many failed, or the first
/// failure of an all-or-nothing job (its batch rolled back).
async fn apply_batch(
    state: &EngineState,
    ctx: &SecurityContext,
    target: &Target,
    update_access: (AccessLevel, bool),
    job_id: Uuid,
    rows: &[StageRow],
    all_or_nothing: bool,
) -> Result<(i64, i64), AppError> {
    let mut checked = Vec::with_capacity(rows.len());
    for row in rows {
        let result = preflight(state, ctx, target, update_access, row).await;
        if all_or_nothing || result.as_ref().is_err_and(|e| refusal_code(e).is_none()) {
            result?;
            checked.push((row, Ok(())));
        } else {
            checked.push((row, result));
        }
    }

    let (user_ctx, org_ref) = entity_crud::fetch_audit_ctx(state, ctx.user_id).await;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (mut applied, mut failed) = (0, 0);
    for (row, checked) in checked {
        let outcome = match checked {
            Err(e) => Err(e),
            Ok(()) => match sqlx::Acquire::begin(&mut *tx).await {
                Ok(mut savepoint) => {
                    let result = apply_row(
                        &mut savepoint,
                        state,
                        ctx,
                        target,
                        job_id,
                        row,
                        user_ctx.clone(),
                        org_ref,
                    )
                    .await;
                    let closed = if result.is_ok() {
                        attome_db::tx::commit(savepoint).await
                    } else {
                        savepoint.rollback().await.map_err(AppError::internal)
                    };
                    result.and(closed)
                }
                Err(e) => Err(AppError::internal(e)),
            },
        };
        match outcome {
            Ok(()) => applied += 1,
            Err(e) => match refusal_code(&e) {
                Some(code) if !all_or_nothing => {
                    tracing::info!(%job_id, row_no = row.row_no, code, "an import row was refused");
                    mark_failed(&mut tx, job_id, row.row_no, code).await?;
                    failed += 1;
                }
                // All or nothing, or not the row's fault: the batch rolls back.
                _ => return Err(e),
            },
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok((applied, failed))
}

async fn set_failed(state: &EngineState, job_id: Uuid, reason: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE import_job SET status = 'failed', finished_at = now(), \
                counts = counts || jsonb_build_object('error', $2::text), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(job_id)
    .bind(reason)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Applies job `job_id` (see the module doc). The job must be `validated`,
/// or `applying` when a stopped run resumes.
pub async fn apply(state: &EngineState, job_id: Uuid) -> Result<ApplyCounts, AppError> {
    let job: JobRow = sqlx::query_as(
        "SELECT entity_logicalname, status, all_or_nothing, triggers_on, created_by \
           FROM import_job WHERE id = $1",
    )
    .bind(job_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if job.status != "validated" && job.status != "applying" {
        return Err(AppError::Conflict("only a validated import can be applied"));
    }
    if job.all_or_nothing {
        let invalid: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM import_stage WHERE job_id = $1 AND status IN ('invalid', 'pending')",
        )
        .bind(job_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if invalid > 0 {
            return Err(AppError::Validation(format!(
                "this import is all or nothing and {invalid} rows are invalid; fix them or turn all_or_nothing off"
            )));
        }
    }
    sqlx::query(
        "UPDATE import_job SET status = 'applying', row_version = row_version + 1 \
          WHERE id = $1 AND status IN ('validated', 'applying')",
    )
    .bind(job_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let (entity_id, entity_name, attrs, _) =
        entity_crud::resolve_entity(state, &job.entity_logicalname).await?;
    let target = Target {
        entity_id,
        entity_name,
        attrs,
    };
    let ctx = attome_security::resolve_uncached(&state.base.db, job.created_by).await?;
    let update_access = entity_crud::resolve_record_access_inputs(
        state,
        &ctx,
        target.entity_id,
        &target.entity_name,
        RecordAction::Update,
    )
    .await?;

    let mut failed_now = 0_i64;
    loop {
        let rows: Vec<StageRow> = sqlx::query_as(
            "SELECT s.row_no, s.mapped, s.action, s.record_id, s.record_row_version, \
                    CASE WHEN j.counts->>'source' = 'migration' THEN s.raw->>'__owner' END AS owner \
               FROM import_stage s JOIN import_job j ON j.id = s.job_id \
              WHERE s.job_id = $1 AND s.status = 'valid' AND s.action IN ('create', 'update') \
                AND NOT EXISTS (SELECT 1 FROM import_row r \
                                 WHERE r.job_id = s.job_id AND r.row_no = s.row_no) \
              ORDER BY s.row_no LIMIT $2",
        )
        .bind(job_id)
        .bind(APPLY_BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if rows.is_empty() {
            break;
        }
        let batch = apply_batch(
            state,
            &ctx,
            &target,
            update_access,
            job_id,
            &rows,
            job.all_or_nothing,
        );
        let result = if job.triggers_on {
            batch.await
        } else {
            attome_core::quiet_scope::quiet(batch).await
        };
        match result {
            Ok((_, failed)) => failed_now += failed,
            // Not the row's fault: the job stays `applying` for the next run.
            Err(e) if !job.all_or_nothing => return Err(e),
            Err(e) => {
                // All or nothing: the failed batch rolled back; undo the rest.
                crate::import_undo::undo_rows(state, job_id).await?;
                let reason = refusal_code(&e).unwrap_or("internal_error");
                set_failed(
                    state,
                    job_id,
                    &format!("a row was refused ({reason}); the import was undone"),
                )
                .await?;
                return Err(e);
            }
        }
    }

    let (applied, apply_failed): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM import_row WHERE job_id = $1), \
                (SELECT COUNT(*) FROM import_stage WHERE job_id = $1 AND status = 'invalid' \
                    AND error->'errors'->0->>'field' = '')",
    )
    .bind(job_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let counts = ApplyCounts {
        applied,
        apply_failed,
    };
    sqlx::query(
        "UPDATE import_job SET status = 'applied', finished_at = now(), \
                counts = counts || $2::jsonb, row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(job_id)
    .bind(serde_json::to_value(counts).map_err(AppError::internal)?)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    tracing::info!(%job_id, applied, failed_now, "import applied");
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_row_writes_its_mapped_fields_without_the_id() {
        let row = StageRow {
            row_no: 1,
            mapped: Some(json!({"id": "x", "title": "a"})),
            action: Some("update".into()),
            record_id: None,
            record_row_version: None,
            owner: None,
        };
        assert_eq!(Value::Object(body_of(&row)), json!({"title": "a"}));
        assert_eq!(row_version_of(Some(&json!({"row_version": 3}))), Some(3));
    }
}

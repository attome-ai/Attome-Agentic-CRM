//! A22-T4: the changeset data steps `copy` and `set_default`, beside
//! `split` ([`super::refactor`]).
//!
//! - `copy` `{from, to, only_empty}`: the value of one attribute into
//!   another of the same type, in rows where the source has a value; only
//!   where the target is empty unless `only_empty` is `false`.
//! - `set_default` `{field, value}`: a value into the rows where the field
//!   is empty (always only the empty ones).
//!
//! Applying the step queues a durable `data_step_run` of that kind (source
//! `apply`, tied to its changeset operation, so applying it again queues
//! nothing), and the `RunDataStep` job writes it in keyset batches of
//! [`BATCH`] rows, each batch with its cursor in one short transaction;
//! pausing and cancelling go through `/api/v1/admin/data-step-runs/{id}`.
//! Rows are written directly, as the other data step runs write theirs,
//! with `row_version` raised; business rules and workflows do not run.

use attome_core::{EngineState, FieldType, quote_ident};
use attome_metadata::provision::field_change as fc;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

/// Rows one batch reads.
pub const BATCH: i64 = 1_000;

/// A checked step: the entity, the target, and the source or the value.
#[derive(Debug, Clone, PartialEq)]
pub struct FillPlan {
    pub entity: String,
    pub kind: String,
    pub target: String,
    pub source: Option<String>,
    pub value: Option<String>,
    pub only_empty: bool,
}

/// A scalar as the text a cast reads, or `None` for a value no column
/// takes. Pure.
fn scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Checks `args` against `entity`'s attributes. Pure over the registry.
pub fn plan(state: &EngineState, entity: &str, args: &Value) -> Result<FillPlan, AppError> {
    let registry = state.entities.load();
    let meta = registry.get(entity).ok_or(AppError::NotFound)?;
    let attr_type = |name: &str| -> Option<FieldType> {
        if fc::is_system_column(name) {
            return None;
        }
        meta.attrs
            .iter()
            .find(|a| a.logicalname == name)
            .map(|a| a.field_type())
    };
    let text = |key: &str| args.get(key).and_then(Value::as_str).map(str::trim);
    let kind = text("kind").unwrap_or_default();
    match kind {
        "copy" => {
            let (from, to) = (
                text("from").unwrap_or_default(),
                text("to").unwrap_or_default(),
            );
            let (Some(from_type), Some(to_type)) = (attr_type(from), attr_type(to)) else {
                return Err(AppError::Validation(format!(
                    "copy: from and to name attributes of {entity}"
                )));
            };
            if from == to || from_type != to_type {
                return Err(AppError::Validation(
                    "copy: from and to are two attributes of the same type".into(),
                ));
            }
            Ok(FillPlan {
                entity: entity.to_owned(),
                kind: kind.to_owned(),
                target: to.to_owned(),
                source: Some(from.to_owned()),
                value: None,
                only_empty: args.get("only_empty").and_then(Value::as_bool) != Some(false),
            })
        }
        "set_default" => {
            let field = text("field").unwrap_or_default();
            if attr_type(field).is_none() {
                return Err(AppError::Validation(format!(
                    "set_default: field names an attribute of {entity}"
                )));
            }
            let value = args.get("value").and_then(scalar_text).ok_or_else(|| {
                AppError::Validation("set_default: value is a string, number or boolean".into())
            })?;
            Ok(FillPlan {
                entity: entity.to_owned(),
                kind: kind.to_owned(),
                target: field.to_owned(),
                source: None,
                value: Some(value),
                only_empty: true,
            })
        }
        other => Err(AppError::Validation(format!(
            "data_step kind {other:?} is not copy or set_default"
        ))),
    }
}

/// The step's spec as the run keeps it: the operation's own args shape,
/// so [`plan`] reads it again when the run starts. Pure.
fn spec_of(plan: &FillPlan) -> Value {
    match &plan.source {
        Some(from) => json!({
            "kind": plan.kind, "from": from, "to": plan.target, "only_empty": plan.only_empty,
        }),
        None => json!({ "kind": plan.kind, "field": plan.target, "value": plan.value }),
    }
}

/// Queues the step of a changeset operation; the run's id (the existing one
/// when the operation was applied before).
pub(crate) async fn queue_from_changeset(
    state: &EngineState,
    actor: Uuid,
    changeset_op: (Uuid, i32),
    entity: &str,
    args: Option<&Value>,
) -> Result<Uuid, AppError> {
    let args = args.cloned().unwrap_or(Value::Null);
    let plan = plan(state, entity, &args)?;
    let db = &state.base.db_migrator;
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM data_step_run WHERE changeset_id = $1 AND op_seq = $2 AND kind = $3",
    )
    .bind(changeset_op.0)
    .bind(changeset_op.1)
    .bind(&plan.kind)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if let Some(run_id) = existing {
        return Ok(run_id);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let run_id: Uuid = sqlx::query_scalar(
        "INSERT INTO data_step_run \
           (source, entity_logicalname, kind, spec, created_by, changeset_id, op_seq) \
         VALUES ('apply', $1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&plan.entity)
    .bind(&plan.kind)
    .bind(spec_of(&plan))
    .bind(actor)
    .bind(changeset_op.0)
    .bind(changeset_op.1)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::RunDataStep { run_id },
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "data_step_run",
            run_id,
            attome_audit::AuditOperation::Create,
            format!("entity.{}", plan.kind),
            actor,
        )
        .comment(format!(
            "{} into {}.{}",
            plan.kind, plan.entity, plan.target
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(run_id)
}

/// `RunDataStep` for a `copy` or `set_default` run.
pub(crate) async fn continue_fill(state: &EngineState, run: &fc::RunRow) -> Result<(), AppError> {
    let db = &state.base.db_migrator;
    let args = run.spec.clone();
    // Checked again: the metadata may have changed since it was queued.
    let plan = plan(state, &run.entity_logicalname, &args)?;
    let table = quote_ident(&plan.entity);
    let target = quote_ident(&plan.target);
    let target_type: String = sqlx::query_scalar(
        "SELECT format_type(atttypid, atttypmod) FROM pg_attribute \
          WHERE attrelid = to_regclass($1) AND attname = $2 AND NOT attisdropped",
    )
    .bind(&table)
    .bind(&plan.target)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let empty_only = if plan.only_empty {
        format!("AND t.{target} IS NULL")
    } else {
        String::new()
    };
    // Identifiers from validated metadata, quoted; the type from the
    // catalogue; values bound.
    let update = match &plan.source {
        Some(source) => {
            let source = quote_ident(source);
            format!(
                "UPDATE {table} AS t SET {target} = t.{source}, modified_at = now(), \
                        row_version = t.row_version + 1 \
                  WHERE t.id = ANY($1) AND t.{source} IS NOT NULL {empty_only}"
            )
        }
        None => format!(
            "UPDATE {table} AS t SET {target} = CAST($2 AS {target_type}), modified_at = now(), \
                    row_version = t.row_version + 1 \
              WHERE t.id = ANY($1) {empty_only}"
        ),
    };
    let mut cursor = run.cursor;
    loop {
        if fc::run_stopped(db, run.id).await? {
            tracing::info!(run_id = %run.id, "data step: paused or cancelled; stopped between batches");
            return Ok(());
        }
        let mut tx = attome_db::tx::begin(db).await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {table} WHERE ($1::uuid IS NULL OR id > $1) \
               AND is_active IS NOT FALSE ORDER BY id LIMIT $2"
        ))
        .bind(cursor)
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let mut query = sqlx::query(&update).bind(&ids);
        if plan.source.is_none() {
            query = query.bind(plan.value.as_deref());
        }
        let written = query
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
        if let Some(last) = ids.last() {
            cursor = Some(*last);
        }
        fc::advance_run(&mut tx, run.id, cursor, ids.len() as u64, written, 0).await?;
        attome_db::tx::commit(tx).await?;
        if (ids.len() as i64) < BATCH {
            break;
        }
    }
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    fc::finish_run(&mut conn, run.id, None).await?;
    tracing::info!(run_id = %run.id, kind = %plan.kind, entity = %plan.entity, "data step: finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_a_column_can_take() {
        assert_eq!(scalar_text(&json!("Riyadh")).as_deref(), Some("Riyadh"));
        assert_eq!(scalar_text(&json!(12.5)).as_deref(), Some("12.5"));
        assert_eq!(scalar_text(&json!(true)).as_deref(), Some("true"));
        assert_eq!(scalar_text(&Value::Null), None);
        assert_eq!(scalar_text(&json!({ "a": 1 })), None);
    }
}

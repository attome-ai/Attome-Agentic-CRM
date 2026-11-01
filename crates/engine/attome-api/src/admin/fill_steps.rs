//! A22-T4: the changeset data steps `copy`, `set_default`, `map_values`
//! and `convert`, beside `split` ([`super::refactor`]).
//!
//! - `copy` `{from, to, only_empty}`: the value of one attribute into
//!   another of the same type, in rows where the source has a value; only
//!   where the target is empty unless `only_empty` is `false`.
//! - `set_default` `{field, value}`: a value into the rows where the field
//!   is empty (always only the empty ones).
//! - `convert` `{from, to, from_type, to_type, format, true_values,
//!   false_values, map, only_empty}`: one attribute converted into another
//!   of the type named, by the same conversion a field's type change uses
//!   (`field_change::Conversion`); a value that does not convert leaves the
//!   target empty and is counted as the run's `rows_nulled`.
//! - `map_values` `{field, to, map, on_unmapped}`: each stored value of
//!   `field` named in `map` is replaced by its mapping, in `field` itself or
//!   in `to`; a value not in the map is left as it is, and with
//!   `on_unmapped: "report"` counted as the run's `rows_nulled`.
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
    /// `map_values`: each stored value and what replaces it.
    pub map: Vec<(String, String)>,
    /// `map_values`: count the rows whose value is not in the map.
    pub report_unmapped: bool,
    /// `convert`: the conversion, checked.
    pub conversion: Option<fc::Conversion>,
}

/// The most entries one map holds.
pub const MAX_MAP: usize = 1_000;

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
                map: Vec::new(),
                report_unmapped: false,
                conversion: None,
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
                map: Vec::new(),
                report_unmapped: false,
                conversion: None,
            })
        }
        "map_values" => {
            let field = text("field").unwrap_or_default();
            let to = text("to").filter(|t| !t.is_empty()).unwrap_or(field);
            let (Some(field_type), Some(to_type)) = (attr_type(field), attr_type(to)) else {
                return Err(AppError::Validation(format!(
                    "map_values: field and to name attributes of {entity}"
                )));
            };
            if field_type != to_type {
                return Err(AppError::Validation(
                    "map_values: field and to are of the same type".into(),
                ));
            }
            let map: Vec<(String, String)> = args
                .get("map")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(old, new)| scalar_text(new).map(|new| (old.clone(), new)))
                        .collect()
                })
                .unwrap_or_default();
            if map.is_empty() || map.len() > MAX_MAP {
                return Err(AppError::Validation(format!(
                    "map_values: map holds 1 to {MAX_MAP} values, each a string, number or boolean"
                )));
            }
            Ok(FillPlan {
                entity: entity.to_owned(),
                kind: kind.to_owned(),
                target: to.to_owned(),
                source: Some(field.to_owned()),
                value: None,
                only_empty: false,
                map,
                report_unmapped: text("on_unmapped") == Some("report"),
                conversion: None,
            })
        }
        "convert" => {
            let (from, to) = (
                text("from").unwrap_or_default(),
                text("to").unwrap_or_default(),
            );
            let (Some(from_type), Some(to_type)) = (attr_type(from), attr_type(to)) else {
                return Err(AppError::Validation(format!(
                    "convert: from and to name attributes of {entity}"
                )));
            };
            let conversion: fc::Conversion = serde_json::from_value(args.clone())
                .map_err(|e| AppError::Validation(format!("convert: {e}")))?;
            if conversion.from_type != from_type.as_str() || conversion.to_type != to_type.as_str()
            {
                return Err(AppError::Validation(
                    "convert: from_type and to_type are the types of from and to".into(),
                ));
            }
            conversion.check()?;
            Ok(FillPlan {
                entity: entity.to_owned(),
                kind: kind.to_owned(),
                target: to.to_owned(),
                source: Some(from.to_owned()),
                value: None,
                only_empty: args.get("only_empty").and_then(Value::as_bool) != Some(false),
                map: Vec::new(),
                report_unmapped: false,
                conversion: Some(conversion),
            })
        }
        other => Err(AppError::Validation(format!(
            "data_step kind {other:?} is not copy, set_default, map_values or convert"
        ))),
    }
}

/// The step's spec as the run keeps it: the operation's own args shape,
/// so [`plan`] reads it again when the run starts. Pure.
fn spec_of(plan: &FillPlan) -> Value {
    match (plan.kind.as_str(), &plan.source) {
        ("map_values", Some(field)) => json!({
            "kind": plan.kind,
            "field": field,
            "to": plan.target,
            "map": plan
                .map
                .iter()
                .map(|(old, new)| (old.clone(), Value::String(new.clone())))
                .collect::<serde_json::Map<String, Value>>(),
            "on_unmapped": if plan.report_unmapped { "report" } else { "keep" },
        }),
        ("convert", Some(from)) => {
            let mut spec = serde_json::to_value(&plan.conversion).unwrap_or(Value::Null);
            if let Some(object) = spec.as_object_mut() {
                object.insert("kind".into(), json!(plan.kind));
                object.insert("from".into(), json!(from));
                object.insert("to".into(), json!(plan.target));
                object.insert("only_empty".into(), json!(plan.only_empty));
            }
            spec
        }
        (_, Some(from)) => json!({
            "kind": plan.kind, "from": from, "to": plan.target, "only_empty": plan.only_empty,
        }),
        (_, None) => json!({ "kind": plan.kind, "field": plan.target, "value": plan.value }),
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

/// `RunDataStep` for a `copy`, `set_default`, `map_values` or `convert` run.
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
    // `convert`: the conversion's expression over the source column.
    let converted = match (&plan.conversion, &plan.source) {
        (Some(conversion), Some(source)) => {
            let mut conn = db.acquire().await.map_err(AppError::internal)?;
            Some(
                conversion
                    .expression(&mut conn, &format!("t.{}", quote_ident(source)))
                    .await?,
            )
        }
        _ => None,
    };
    let update = match &plan.source {
        Some(source) if plan.kind == "convert" => {
            let source = quote_ident(source);
            let expression = converted.as_deref().unwrap_or("NULL");
            format!(
                "UPDATE {table} AS t SET {target} = {expression}, modified_at = now(), \
                        row_version = t.row_version + 1 \
                  WHERE t.id = ANY($1) AND t.{source} IS NOT NULL {empty_only}"
            )
        }
        Some(source) if plan.kind == "map_values" => {
            let source = quote_ident(source);
            format!(
                "UPDATE {table} AS t SET {target} = CAST(m.new AS {target_type}), modified_at = now(), \
                        row_version = t.row_version + 1 \
                   FROM unnest($2::text[], $3::text[]) AS m(old, new) \
                  WHERE t.id = ANY($1) AND t.{source}::text = m.old"
            )
        }
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
    let olds: Vec<String> = plan.map.iter().map(|(old, _)| old.clone()).collect();
    let news: Vec<String> = plan.map.iter().map(|(_, new)| new.clone()).collect();
    // `map_values` with `on_unmapped: report`: the rows of a batch whose
    // value is set and not in the map.
    let unmapped_sql = match &plan.source {
        // `convert`: the rows whose value does not convert.
        Some(source) if plan.kind == "convert" => Some(format!(
            "SELECT count(*) FROM {table} AS t WHERE t.id = ANY($1) \
               AND t.{source} IS NOT NULL AND ({expression}) IS NULL AND $2::text[] IS NOT NULL",
            source = quote_ident(source),
            expression = converted.as_deref().unwrap_or("NULL"),
        )),
        Some(source) if plan.kind == "map_values" && plan.report_unmapped => Some(format!(
            "SELECT count(*) FROM {table} AS t WHERE t.id = ANY($1) \
               AND t.{source} IS NOT NULL AND NOT (t.{source}::text = ANY($2))",
            source = quote_ident(source)
        )),
        _ => None,
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
        if plan.kind == "map_values" {
            query = query.bind(&olds).bind(&news);
        } else if plan.source.is_none() {
            query = query.bind(plan.value.as_deref());
        }
        let written = query
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
        let unmapped: i64 = match &unmapped_sql {
            Some(sql) => sqlx::query_scalar(sql)
                .bind(&ids)
                .bind(&olds)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?,
            None => 0,
        };
        if let Some(last) = ids.last() {
            cursor = Some(*last);
        }
        fc::advance_run(
            &mut tx,
            run.id,
            cursor,
            ids.len() as u64,
            written,
            u64::try_from(unmapped).unwrap_or(0),
        )
        .await?;
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

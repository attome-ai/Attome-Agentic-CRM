//! Rollup exact mode (roadmap A10-T3): a `count` or `sum` rollup over one
//! lookup is kept right inside the related record's own write. The write
//! takes back what the record counted before (its old parent and amount)
//! and adds what it counts now, with `SET col = COALESCE(col, 0) +/- $n` on
//! the parent's row: the row lock makes concurrent writes on one parent add
//! up, which a recompute in each write would not (two writes would not see
//! each other's rows).
//!
//! Only count and sum over one lookup, without a filter or window, can be
//! exact (`attome_core::rollup::parse_options` refuses the rest); the
//! definitions are read from `attribute_info` in the write's transaction,
//! so every write primitive can call [`apply`] without the engine state.
//! A hard delete or a bulk SQL update does not pass through here; the
//! nightly verify-and-heal (A10-T4) puts such a parent right.

use attome_core::quote_ident;
use attome_core::rollup::{RollupFunction, RollupOptions};
use attome_types::AppError;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// What one record contributes to an exact rollup: the parent it names and
/// the amount, as numeric text. `None` when it contributes nothing (not
/// live, no parent, or no amount to add). Pure.
fn contribution(row: &Value, opts: &RollupOptions) -> Option<(Uuid, String)> {
    if row.get("is_active").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let via = &opts.path.first()?.via;
    let parent = row
        .get(via)?
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())?;
    let amount = match opts.function {
        RollupFunction::Count => "1".to_owned(),
        RollupFunction::Sum => match row.get(opts.attribute.as_deref()?)? {
            Value::Number(n) => n.to_string(),
            Value::String(s) if s.trim().parse::<f64>().is_ok() => s.trim().to_owned(),
            _ => return None,
        },
        _ => return None,
    };
    Some((parent, amount))
}

/// One parent and the amount a record contributes to it.
type Contribution = (Uuid, String);

/// The changes a write makes to the parents: what to take back and what to
/// add. Nothing when the record counts the same before and after. Pure.
fn deltas(
    old: Option<&Value>,
    new: Option<&Value>,
    opts: &RollupOptions,
) -> (Option<Contribution>, Option<Contribution>) {
    let before = old.and_then(|row| contribution(row, opts));
    let after = new.and_then(|row| contribution(row, opts));
    if before == after {
        (None, None)
    } else {
        (before, after)
    }
}

/// Applies every exact rollup whose path starts at `entity` for a write
/// that changed one of its records from `old` to `new` (`None` for a record
/// that did not exist or no longer counts), in the write's transaction.
pub async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    old: Option<&Value>,
    new: Option<&Value>,
) -> Result<(), AppError> {
    let rollups: Vec<(String, String, Option<Value>)> = sqlx::query_as(attome_db::tagged_sql!(
        "rollup.exact_definitions",
        "SELECT e.logicalname, a.logicalname, a.options \
         FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
         WHERE a.\"type\" = 23 AND (a.is_active IS NULL OR a.is_active = true) \
           AND (e.is_active IS NULL OR e.is_active = true) \
           AND a.options->>'mode' = 'exact' AND a.options->'path'->0->>'entity' = $1"
    ))
    .bind(entity)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    for (parent_table, column, options) in rollups {
        let Ok(opts) = attome_core::rollup::parse_options(options.as_ref()) else {
            continue;
        };
        let (take, add) = deltas(old, new, &opts);
        for (delta, sign) in [(take, "-"), (add, "+")] {
            let Some((parent, amount)) = delta else {
                continue;
            };
            let col = quote_ident(&column);
            let sql = format!(
                "UPDATE {} SET {col} = COALESCE({col}, 0) {sign} $2::numeric WHERE id = $1",
                quote_ident(&parent_table)
            );
            let sql = attome_db::tag_dynamic("rollup.exact_delta", &sql);
            sqlx::query(&sql)
                .bind(parent)
                .bind(&amount)
                .execute(&mut **tx)
                .await
                .map_err(AppError::internal)?;
        }
    }
    Ok(())
}

/// [`apply`] for a soft delete (`restoring == false`: the record no longer
/// counts) or a restore (it counts again), reading the record's row in the
/// transaction.
pub async fn apply_activity(
    tx: &mut Transaction<'_, Postgres>,
    entity: &str,
    record_id: Uuid,
    restoring: bool,
) -> Result<(), AppError> {
    let sql = format!(
        "SELECT to_jsonb(t) FROM {} t WHERE t.id = $1",
        quote_ident(entity)
    );
    let sql = attome_db::tag_dynamic("rollup.exact_row", &sql);
    let row: Option<Value> = sqlx::query_scalar(&sql)
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    let Some(mut row) = row else {
        return Ok(());
    };
    // The record as it counted while live.
    if let Some(obj) = row.as_object_mut() {
        obj.insert("is_active".into(), Value::Bool(true));
    }
    if restoring {
        apply(tx, entity, None, Some(&row)).await
    } else {
        apply(tx, entity, Some(&row), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::rollup::{RollupMode, RollupStep};
    use serde_json::json;

    fn opts(function: RollupFunction) -> RollupOptions {
        RollupOptions {
            function,
            path: vec![RollupStep {
                entity: "invoice".into(),
                via: "account_ref".into(),
            }],
            attribute: (function == RollupFunction::Sum).then(|| "amount".to_owned()),
            filter: None,
            window: None,
            order_by: None,
            mode: RollupMode::Exact,
            result_type: "number".into(),
        }
    }

    #[test]
    fn rollup_exact_counts_a_live_record_with_a_parent() {
        let a = Uuid::now_v7();
        let row = json!({ "account_ref": a.to_string(), "amount": "12.50" });
        assert_eq!(
            contribution(&row, &opts(RollupFunction::Count)),
            Some((a, "1".into()))
        );
        assert_eq!(
            contribution(&row, &opts(RollupFunction::Sum)),
            Some((a, "12.50".into()))
        );
        let deleted = json!({ "account_ref": a.to_string(), "amount": 3, "is_active": false });
        assert_eq!(contribution(&deleted, &opts(RollupFunction::Sum)), None);
        let orphan = json!({ "account_ref": null, "amount": 3 });
        assert_eq!(contribution(&orphan, &opts(RollupFunction::Count)), None);
        let no_amount = json!({ "account_ref": a.to_string(), "amount": null });
        assert_eq!(contribution(&no_amount, &opts(RollupFunction::Sum)), None);
    }

    #[test]
    fn rollup_exact_moves_the_amount_between_parents() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let sum = opts(RollupFunction::Sum);
        let old = json!({ "account_ref": a.to_string(), "amount": 5 });
        let new = json!({ "account_ref": b.to_string(), "amount": 7 });
        assert_eq!(
            deltas(Some(&old), Some(&new), &sum),
            (Some((a, "5".into())), Some((b, "7".into())))
        );
        // An unrelated change counts the same: nothing to apply.
        assert_eq!(deltas(Some(&old), Some(&old), &sum), (None, None));
        assert_eq!(
            deltas(None, Some(&old), &sum),
            (None, Some((a, "5".into())))
        );
        assert_eq!(
            deltas(Some(&old), None, &sum),
            (Some((a, "5".into())), None)
        );
    }
}

//! Y11-T9: resetting a customisation, per property or for a whole entity or
//! field, back to what the layers below the customer give it (an app's
//! value, else the platform's), with a preview first and an undo after.
//!
//! A reset removes only the customer's layer rows, never a platform or app
//! row, and writes the value below to the entity or field (metadata only,
//! as a seed's write is, with its change-log row). The removed rows are kept
//! in `metadata_layer_reset` (migration 0322), so an undo puts them and
//! their values back, once. A property no lower layer has recorded a value
//! for (customised before Y11-T4) cannot be reset: its preview says so and
//! the reset leaves it. Nothing here drops a column or touches record data.

use std::collections::BTreeMap;

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::layer_conflicts::apply_property_in_tx;

/// One property a reset would change.
#[derive(Debug, Clone, PartialEq)]
pub struct ResetChange {
    pub property: String,
    /// The customer's value now.
    pub current: Value,
    /// The value after the reset; `None` when no lower layer recorded one,
    /// so the property is left as it is.
    pub after: Option<Value>,
}

/// The `Conflict` an undo of an undone reset meets.
pub const ALREADY_UNDONE: &str = "reset already undone";
/// The `Conflict` an undo meets when the customer set the property again
/// after the reset.
pub const CHANGED_SINCE: &str = "the item was customised again after the reset";

/// The customer's rows of `(kind, key)` (optionally only `properties`) and
/// the values the lower layers give each.
async fn plan<'e, E>(
    executor: E,
    kind: &str,
    key: &str,
    properties: Option<&[String]>,
) -> Result<Vec<ResetChange>, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let rows: Vec<(String, String, Option<Value>)> = sqlx::query_as(
        "SELECT property, layer, value FROM metadata_property_layer \
          WHERE object_kind = $1 AND object_key = $2 \
            AND ($3::text[] IS NULL OR property = ANY($3)) \
          ORDER BY property, layer, set_at",
    )
    .bind(kind)
    .bind(key)
    .bind(properties)
    .fetch_all(executor)
    .await
    .map_err(AppError::internal)?;
    let mut customer: BTreeMap<String, Value> = BTreeMap::new();
    let mut platform: BTreeMap<String, Value> = BTreeMap::new();
    let mut app: BTreeMap<String, Value> = BTreeMap::new();
    for (property, layer, value) in rows {
        let value = value.unwrap_or(Value::Null);
        match layer.as_str() {
            "customer" => customer.insert(property, value),
            "app" => app.insert(property, value),
            _ => platform.insert(property, value),
        };
    }
    Ok(customer
        .into_iter()
        .map(|(property, current)| ResetChange {
            after: app
                .get(&property)
                .or_else(|| platform.get(&property))
                .cloned(),
            property,
            current,
        })
        .collect())
}

/// What resetting `(kind, key)` (or only `properties`) would change.
pub async fn preview(
    db: &DbPool,
    kind: &str,
    key: &str,
    properties: Option<&[String]>,
) -> Result<Vec<ResetChange>, AppError> {
    plan(db, kind, key, properties).await
}

/// Resets `(kind, key)` (or only `properties`) for `actor` in `tx`: removes
/// the customer's rows that have a value below them, applies those values
/// and keeps the removed rows for [`undo_in_tx`]. Returns the reset's id and
/// what it changed (`NotFound` when there is nothing to reset).
pub async fn reset_in_tx(
    tx: &mut Tx<'_>,
    kind: &str,
    key: &str,
    properties: Option<&[String]>,
    actor: Uuid,
) -> Result<(Uuid, Vec<ResetChange>), AppError> {
    attome_core::acquire_metadata_write_lock(tx).await?;
    let changes: Vec<ResetChange> = plan(&mut **tx, kind, key, properties)
        .await?
        .into_iter()
        .filter(|c| c.after.is_some())
        .collect();
    if changes.is_empty() {
        return Err(AppError::NotFound);
    }
    let mut kept = Map::new();
    for change in &changes {
        sqlx::query(
            "DELETE FROM metadata_property_layer \
              WHERE object_kind = $1 AND object_key = $2 AND property = $3 \
                AND layer = 'customer'",
        )
        .bind(kind)
        .bind(key)
        .bind(&change.property)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if let Some(after) = &change.after {
            apply_property_in_tx(tx, kind, key, &change.property, after).await?;
        }
        kept.insert(change.property.clone(), change.current.clone());
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO metadata_layer_reset (object_kind, object_key, layer_rows, reset_by) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(kind)
    .bind(key)
    .bind(Value::Object(kept))
    .bind(actor)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok((id, changes))
}

/// Undoes reset `id` for `actor` in `tx`: puts the customer's rows back and
/// applies their values. Once only (`Conflict(ALREADY_UNDONE)`), and not
/// over a property the customer set again since (`Conflict(CHANGED_SINCE)`).
/// Returns the item's kind and key.
pub async fn undo_in_tx(
    tx: &mut Tx<'_>,
    id: Uuid,
    actor: Uuid,
) -> Result<(String, String), AppError> {
    attome_core::acquire_metadata_write_lock(tx).await?;
    let row: Option<(String, String, Value, Option<Uuid>)> = sqlx::query_as(
        "SELECT object_kind, object_key, layer_rows, undone_by FROM metadata_layer_reset \
          WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (kind, key, rows, undone_by) = row.ok_or(AppError::NotFound)?;
    if undone_by.is_some() {
        return Err(AppError::Conflict(ALREADY_UNDONE));
    }
    let rows = rows.as_object().cloned().unwrap_or_default();
    let properties: Vec<String> = rows.keys().cloned().collect();
    let customised_again: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM metadata_property_layer \
          WHERE object_kind = $1 AND object_key = $2 AND layer = 'customer' \
            AND property = ANY($3))",
    )
    .bind(&kind)
    .bind(&key)
    .bind(&properties)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if customised_again {
        return Err(AppError::Conflict(CHANGED_SINCE));
    }
    for (property, value) in &rows {
        sqlx::query(
            "INSERT INTO metadata_property_layer \
                 (object_kind, object_key, property, layer, app, value, set_by) \
             VALUES ($1, $2, $3, 'customer', '', $4, $5)",
        )
        .bind(&kind)
        .bind(&key)
        .bind(property)
        .bind(value)
        .bind(actor)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        apply_property_in_tx(tx, &kind, &key, property, value).await?;
    }
    sqlx::query("UPDATE metadata_layer_reset SET undone_by = $2, undone_at = now() WHERE id = $1")
        .bind(id)
        .bind(actor)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok((kind, key))
}

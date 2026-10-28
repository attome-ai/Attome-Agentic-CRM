//! Y11-T4: entity and attribute writes record which layer set each property
//! (`metadata_property_layer`, migration 0083), and a boot seed applies the
//! platform's definition property by property instead of skipping a whole
//! customised row.
//!
//! - **Writes.** A write records the properties it sets under the layer its
//!   row is stamped with (Y11-T1's mapping: `platform`; `product` is an app's;
//!   `project` the customer's), in the write's own transaction. A seed
//!   records the properties its description manages; an admin or bundle
//!   write the ones it changes, or every one on a create. An app layer's row
//!   carries no app name yet (`app = ''`): a recording does not know its
//!   pack, which Y11-T11 adds with install order.
//! - **Seed.** When a seed would change a live row, it takes its own value
//!   for every property no app or customer row holds, and keeps the current
//!   value for the ones that do. A steady-state boot, which changes nothing,
//!   reads no layer rows.
//! - **Conflicts (Y11-T6).** When the platform changes a property (its
//!   layer row's value against the seed's) that an app or the customer holds
//!   with a different value, the seed keeps the held value and records an
//!   open `metadata_layer_conflict` for a builder to resolve; nothing is
//!   merged automatically (`attome_model::layer_stack::three_way`).
//! - **Backfill.** A row customised before this existed has no layer rows.
//!   The first seed pass over it records a customer row for every property
//!   the seed manages whose stored value differs from the seed's: the
//!   platform definition exists only in the seeds' descriptions, so this is
//!   where it can be compared. It cannot tell a customer's edit from a value
//!   an older platform release set and the old whole-row skip left behind
//!   (D-366), so it keeps both, as the row is kept today; a per-property
//!   reset (Y11-T9) releases one to the platform.
//!
//! The row's own `is_customized` is still written as before.

use std::collections::BTreeSet;

use attome_core::changeset::Layer as Stamp;
use attome_db::{DbPool, Tx};
use attome_types::AppError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

/// `object_kind` of an entity row; its key is the logical name.
pub(super) const ENTITY: &str = "entity";
/// `object_kind` of an attribute row; its key is `<entity>.<field>`, the
/// key `metadata_lock` uses too.
pub(super) const ATTRIBUTE: &str = "attribute";

/// A state struct as its properties, by field name.
pub(super) fn to_map<T: Serialize>(state: &T) -> Result<Map<String, Value>, AppError> {
    match serde_json::to_value(state).map_err(AppError::internal)? {
        Value::Object(map) => Ok(map),
        _ => Err(AppError::internal("a metadata state is not an object")),
    }
}

/// The state struct back from its properties.
pub(super) fn from_map<T: DeserializeOwned>(map: Map<String, Value>) -> Result<T, AppError> {
    serde_json::from_value(Value::Object(map)).map_err(AppError::internal)
}

/// The properties of `after` a write sets: every one on a create (`before`
/// is `None`), else the ones whose value changes. Pure.
pub(super) fn changed(
    before: Option<&Map<String, Value>>,
    after: &Map<String, Value>,
) -> Map<String, Value> {
    after
        .iter()
        .filter(|(property, value)| before.and_then(|b| b.get(*property)) != Some(*value))
        .map(|(property, value)| (property.clone(), value.clone()))
        .collect()
}

/// `values` narrowed to `properties`. Pure.
pub(super) fn only(values: &Map<String, Value>, properties: &BTreeSet<&str>) -> Map<String, Value> {
    values
        .iter()
        .filter(|(property, _)| properties.contains(property.as_str()))
        .map(|(property, value)| (property.clone(), value.clone()))
        .collect()
}

/// The seed's values with every property in `kept` taken from `current`.
/// Pure.
pub(super) fn keep(
    seed: &Map<String, Value>,
    current: &Map<String, Value>,
    kept: &BTreeSet<String>,
) -> Map<String, Value> {
    seed.iter()
        .map(|(property, value)| {
            let value = match current.get(property) {
                Some(current) if kept.contains(property) => current.clone(),
                _ => value.clone(),
            };
            (property.clone(), value)
        })
        .collect()
}

/// The glossary layer a stamp records under (Y11-T1).
fn layer_of(stamp: Stamp) -> &'static str {
    attome_model::Layer::from_stored(stamp.as_str())
        .unwrap_or(attome_model::Layer::Customer)
        .as_str()
}

/// Records `values` as the stamp's layer for `(kind, key)`, in the write's
/// own transaction: one statement, an upsert per property.
pub(super) async fn record_in_tx(
    tx: &mut Tx<'_>,
    kind: &str,
    key: &str,
    stamp: Stamp,
    values: &Map<String, Value>,
) -> Result<(), AppError> {
    if values.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO metadata_property_layer (object_kind, object_key, property, layer, app, value) \
         SELECT $1, $2, p.key, $3, '', p.value FROM jsonb_each($4) AS p \
         ON CONFLICT (object_kind, object_key, property, layer, app) \
         DO UPDATE SET value = EXCLUDED.value, set_at = now()",
    )
    .bind(kind)
    .bind(key)
    .bind(layer_of(stamp))
    .bind(Value::Object(values.clone()))
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The properties of `(kind, key)` a seed must leave as they are: those an
/// app or the customer set. A `customised` row with no layer rows at all is
/// backfilled first (see the module docs): `managed` are the properties the
/// seed's description sets, compared between `current` and `seed`.
pub(super) async fn seed_keeps(
    db: &DbPool,
    kind: &str,
    key: &str,
    current: &Map<String, Value>,
    seed: &Map<String, Value>,
    managed: &BTreeSet<&str>,
    customised: bool,
) -> Result<BTreeSet<String>, AppError> {
    let any: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM metadata_property_layer \
          WHERE object_kind = $1 AND object_key = $2)",
    )
    .bind(kind)
    .bind(key)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if any {
        let rows: Vec<(String, String, Option<Value>)> = sqlx::query_as(
            "SELECT property, layer, value FROM metadata_property_layer \
              WHERE object_kind = $1 AND object_key = $2 \
              ORDER BY property, layer",
        )
        .bind(kind)
        .bind(key)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let mut old_platform = Map::new();
        let mut held = Map::new();
        for (property, layer, value) in rows {
            let value = value.unwrap_or(Value::Null);
            if layer == "platform" {
                old_platform.insert(property, value);
            } else {
                // `app` sorts before `customer`, so the customer's value,
                // which wins the merge, is the one left standing.
                held.insert(property, value);
            }
        }
        let kept: BTreeSet<String> = held.keys().cloned().collect();
        // Y11-T6: a platform change to a property another layer holds is a
        // conflict to resolve, never merged here; the seed keeps the value.
        let new_platform = only(seed, managed);
        let merge = attome_model::layer_stack::three_way(&old_platform, &new_platform, &held);
        if !merge.conflicts.is_empty() {
            record_conflicts(db, kind, key, &merge.conflicts, &new_platform).await?;
        }
        return Ok(kept);
    }
    if !customised {
        return Ok(BTreeSet::new());
    }
    let differing = only(&changed(Some(seed), current), managed);
    if !differing.is_empty() {
        let mut tx = attome_db::tx::begin(db).await?;
        record_in_tx(&mut tx, kind, key, Stamp::Customer, &differing).await?;
        tx.commit().await.map_err(AppError::internal)?;
    }
    Ok(differing.into_keys().collect())
}

/// Y11-T6: records `conflicts` open (one per property; a later platform
/// change updates the open one) and the platform's new values as its layer
/// rows, in one transaction, so the next boot does not find the same change
/// again. The metadata row itself is left as it is.
async fn record_conflicts(
    db: &DbPool,
    kind: &str,
    key: &str,
    conflicts: &[attome_model::layer_stack::Conflict],
    new_platform: &Map<String, Value>,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    for conflict in conflicts {
        sqlx::query(
            "INSERT INTO metadata_layer_conflict \
                 (object_kind, object_key, property, old_platform, new_platform, customer) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (object_kind, object_key, property) WHERE status = 'open' \
             DO UPDATE SET new_platform = EXCLUDED.new_platform, customer = EXCLUDED.customer",
        )
        .bind(kind)
        .bind(key)
        .bind(&conflict.property)
        .bind(&conflict.old_platform)
        .bind(&conflict.new_platform)
        .bind(&conflict.customer)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        tracing::warn!(
            object_kind = %kind,
            object_key = %key,
            property = %conflict.property,
            "metadata upgrade: the platform changed a property the customer set; kept, conflict recorded"
        );
    }
    record_in_tx(&mut tx, kind, key, Stamp::Platform, new_platform).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(value: Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn a_create_sets_every_property_and_an_update_only_what_changes() {
        let before = map(json!({ "name": "Phone", "max_length": 20 }));
        let after = map(json!({ "name": "Mobile", "max_length": 20 }));
        assert_eq!(changed(None, &after), after);
        assert_eq!(
            changed(Some(&before), &after),
            map(json!({ "name": "Mobile" }))
        );
    }

    #[test]
    fn a_seed_keeps_the_customer_label_and_takes_the_platform_fix() {
        let seed = map(json!({ "name": "Phone", "max_length": 32 }));
        let current = map(json!({ "name": "Mobile", "max_length": 20 }));
        let kept: BTreeSet<String> = ["name".to_owned()].into();
        assert_eq!(
            keep(&seed, &current, &kept),
            map(json!({ "name": "Mobile", "max_length": 32 }))
        );
    }

    #[test]
    fn only_narrows_to_the_managed_properties() {
        let values = map(json!({ "name": "A", "category": "sales" }));
        let managed: BTreeSet<&str> = ["name"].into();
        assert_eq!(only(&values, &managed), map(json!({ "name": "A" })));
    }
}

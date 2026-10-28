//! Y11-T7: listing and resolving the conflicts an upgrade recorded
//! (`metadata_layer_conflict`, Y11-T6). A builder keeps the customer's
//! value, takes the platform's (the customer's layer row goes), or combines
//! them into a value of their own (the customer's row takes it). Taking or
//! combining writes the value to the entity or field at once, metadata only
//! as a seed's write is, and appends the change-log row, all in the caller's
//! transaction, so the caller's audit event commits with it.

use attome_core::quote_ident;
use attome_db::{DbPool, Tx};
use attome_types::{AppError, PageWindow};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

/// One conflict.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct LayerConflict {
    pub id: Uuid,
    pub object_kind: String,
    pub object_key: String,
    pub property: String,
    pub old_platform: Option<Value>,
    pub new_platform: Option<Value>,
    pub customer: Option<Value>,
    pub status: String,
    pub resolution: Option<String>,
    pub resolved_by: Option<Uuid>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// How a conflict is resolved.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolution {
    /// The customer's value stays.
    KeepCustomer,
    /// The platform's value applies; the customer's layer row goes.
    TakePlatform,
    /// This value applies, as the customer's.
    Combine(Value),
}

impl Resolution {
    fn as_str(&self) -> &'static str {
        match self {
            Self::KeepCustomer => "keep_customer",
            Self::TakePlatform => "take_platform",
            Self::Combine(_) => "combine",
        }
    }
}

/// The `Conflict` resolving an already resolved conflict meets.
pub const ALREADY_RESOLVED: &str = "conflict already resolved";

/// The properties a conflict may name, by kind: the columns the reconcile
/// writes (`reconcile::EntityState` / `AttributeState`), each a column of
/// the same name.
const ENTITY_PROPERTIES: &[&str] = &[
    "name",
    "primary_name_attribute",
    "is_append_only",
    "is_audited",
    "category",
];
const ATTRIBUTE_PROPERTIES: &[&str] = &[
    "name",
    "required",
    "is_sensitive",
    "is_write_restricted",
    "is_sortable",
    "is_filterable",
    "max_length",
    "lookup_entity_ref",
    "options",
    "on_target_delete",
    "data_classification",
    "purpose",
];

const COLUMNS: &str = "id, object_kind, object_key, property, old_platform, new_platform, \
                       customer, status, resolution, resolved_by, resolved_at, created_at";

/// One page of conflicts, newest first, optionally of one `status`, and how
/// many there are.
pub async fn list(
    db: &DbPool,
    status: Option<&str>,
    window: PageWindow,
) -> Result<(Vec<LayerConflict>, i64), AppError> {
    let items: Vec<LayerConflict> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM metadata_layer_conflict \
          WHERE ($1::text IS NULL OR status = $1) \
          ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3"
    ))
    .bind(status)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM metadata_layer_conflict WHERE ($1::text IS NULL OR status = $1)",
    )
    .bind(status)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok((items, total))
}

/// Resolves conflict `id` as `resolution` for `actor`, in `tx`. `NotFound`
/// for no such conflict, `Conflict(ALREADY_RESOLVED)` for a resolved one.
pub async fn resolve_in_tx(
    tx: &mut Tx<'_>,
    id: Uuid,
    resolution: Resolution,
    actor: Uuid,
) -> Result<LayerConflict, AppError> {
    attome_core::acquire_metadata_write_lock(tx).await?;
    let conflict: LayerConflict = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM metadata_layer_conflict WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if conflict.status != "open" {
        return Err(AppError::Conflict(ALREADY_RESOLVED));
    }

    let applied = match &resolution {
        Resolution::KeepCustomer => None,
        Resolution::TakePlatform => {
            sqlx::query(
                "DELETE FROM metadata_property_layer \
                  WHERE object_kind = $1 AND object_key = $2 AND property = $3 \
                    AND layer = 'customer'",
            )
            .bind(&conflict.object_kind)
            .bind(&conflict.object_key)
            .bind(&conflict.property)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            // An app's value, if one holds the property, now applies;
            // otherwise the platform's.
            let app: Option<Option<Value>> = sqlx::query_scalar(
                "SELECT value FROM metadata_property_layer \
                  WHERE object_kind = $1 AND object_key = $2 AND property = $3 \
                    AND layer = 'app' ORDER BY set_at DESC LIMIT 1",
            )
            .bind(&conflict.object_kind)
            .bind(&conflict.object_key)
            .bind(&conflict.property)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            Some(
                app.flatten()
                    .or_else(|| conflict.new_platform.clone())
                    .unwrap_or(Value::Null),
            )
        }
        Resolution::Combine(value) => {
            sqlx::query(
                "INSERT INTO metadata_property_layer \
                     (object_kind, object_key, property, layer, app, value, set_by) \
                 VALUES ($1, $2, $3, 'customer', '', $4, $5) \
                 ON CONFLICT (object_kind, object_key, property, layer, app) \
                 DO UPDATE SET value = EXCLUDED.value, set_by = EXCLUDED.set_by, set_at = now()",
            )
            .bind(&conflict.object_kind)
            .bind(&conflict.object_key)
            .bind(&conflict.property)
            .bind(value)
            .bind(actor)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            Some(value.clone())
        }
    };
    if let Some(value) = applied {
        apply_property_in_tx(
            tx,
            &conflict.object_kind,
            &conflict.object_key,
            &conflict.property,
            &value,
        )
        .await?;
    }

    sqlx::query(
        "UPDATE metadata_layer_conflict \
            SET status = 'resolved', resolution = $2, resolved_by = $3, resolved_at = now() \
          WHERE id = $1 AND status = 'open'",
    )
    .bind(id)
    .bind(resolution.as_str())
    .bind(actor)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(LayerConflict {
        status: "resolved".into(),
        resolution: Some(resolution.as_str().into()),
        resolved_by: Some(actor),
        resolved_at: Some(Utc::now()),
        ..conflict
    })
}

/// Writes `value` to property `property` of the entity (`kind` `entity`,
/// `key` its logical name) or field (`attribute`, `<entity>.<field>`) and
/// appends the change-log row, metadata only as a seed's write is. The
/// property must be one the reconcile writes, each a column of the same
/// name; `NotFound` when the item is gone. Shared with `layer_reset`.
pub(crate) async fn apply_property_in_tx(
    tx: &mut Tx<'_>,
    kind: &str,
    key: &str,
    property: &str,
    value: &Value,
) -> Result<(), AppError> {
    let unknown =
        || AppError::Validation(format!("{property} is not a layered property of an {kind}"));
    let column = quote_ident(property);
    let (entity_id, entity): (Uuid, String) = match kind {
        "entity" => {
            if !ENTITY_PROPERTIES.contains(&property) {
                return Err(unknown());
            }
            sqlx::query_as(&format!(
                "UPDATE entity_info \
                    SET {column} = (jsonb_populate_record(NULL::entity_info, \
                                    jsonb_build_object($1::text, $2::jsonb))).{column}, \
                        modified_at = now() \
                  WHERE logicalname = $3 AND (is_active IS NULL OR is_active = true) \
                 RETURNING id, logicalname"
            ))
            .bind(property)
            .bind(value)
            .bind(key)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?
        }
        "attribute" => {
            if !ATTRIBUTE_PROPERTIES.contains(&property) {
                return Err(unknown());
            }
            let (entity, field) = key.split_once('.').ok_or(AppError::NotFound)?;
            sqlx::query_as(&format!(
                "UPDATE attribute_info a \
                    SET {column} = (jsonb_populate_record(NULL::attribute_info, \
                                    jsonb_build_object($1::text, $2::jsonb))).{column}, \
                        modified_at = now() \
                   FROM entity_info e \
                  WHERE a.entity_ref = e.id AND e.logicalname = $3 AND a.logicalname = $4 \
                    AND (a.is_active IS NULL OR a.is_active = true) \
                 RETURNING e.id, e.logicalname"
            ))
            .bind(property)
            .bind(value)
            .bind(entity)
            .bind(field)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?
        }
        _ => return Err(unknown()),
    };
    attome_core::append_change_log(tx, entity_id, &entity, attome_core::ChangeKind::Upsert).await?;
    Ok(())
}

//! A1-T4: entity inheritance by copy-down. An entity created with
//! `extends_entity_id` gets a copy of every field of its base, each copy
//! naming the base field it came from (`inherited_from_attribute_id`). A
//! field later added to the base is added to every entity that extends it,
//! and a rename, type change, choice change or delete of a base field is
//! applied to every copy, all through the same provisioning functions an
//! admin's own change runs. A copy's type is the base's to change. Storage
//! is copy-down only: a child's reads never join the base table, and there
//! is no Postgres table inheritance.
//!
//! These are the metadata reads and writes; the copying itself is in
//! [`super::attribute`], which owns the field primitives.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// The live entities that extend `base_id` directly.
pub(crate) async fn children(db: &DbPool, base_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE extends_entity_id = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY logicalname",
    )
    .bind(base_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Whether any entity that extends `base_id`, at any depth, already has a
/// live field named `logicalname`: adding it to the base would then fail
/// part-way, so it is refused before anything is written.
pub(crate) async fn descendant_has_field(
    db: &DbPool,
    base_id: Uuid,
    logicalname: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "WITH RECURSIVE d AS ( \
             SELECT id FROM entity_info WHERE extends_entity_id = $1 \
             UNION \
             SELECT e.id FROM entity_info e JOIN d ON e.extends_entity_id = d.id \
         ) \
         SELECT EXISTS ( \
             SELECT 1 FROM attribute_info a JOIN d ON a.entity_ref = d.id \
             WHERE a.logicalname = $2 AND (a.is_active IS NULL OR a.is_active = true) \
         )",
    )
    .bind(base_id)
    .bind(logicalname)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// The live copies of base field `attr_id`, as `(entity id, field id)`.
pub(crate) async fn copies(db: &DbPool, attr_id: Uuid) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    sqlx::query_as(
        "SELECT entity_ref, id FROM attribute_info \
         WHERE inherited_from_attribute_id = $1 AND (is_active IS NULL OR is_active = true) \
         ORDER BY entity_ref",
    )
    .bind(attr_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Whether field `attr_id` is a copy of a base field.
pub(crate) async fn is_inherited(db: &DbPool, attr_id: Uuid) -> Result<bool, AppError> {
    let from: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT inherited_from_attribute_id FROM attribute_info WHERE id = $1")
            .bind(attr_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(from.flatten().is_some())
}

/// The id of `entity_id`'s live field `logicalname`.
pub(crate) async fn field_id(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Marks `entity_id`'s field `logicalname` as the copy of `base_attr_id`.
pub(crate) async fn mark_copy(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
    base_attr_id: Uuid,
) -> Result<(), AppError> {
    let done = sqlx::query(
        "UPDATE attribute_info SET inherited_from_attribute_id = $3 \
         WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_id)
    .bind(logicalname)
    .bind(base_attr_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::internal(format!(
            "inherited field {logicalname} was not created on entity {entity_id}"
        )));
    }
    Ok(())
}

/// Records that `entity_id` extends `base_id`.
pub(crate) async fn set_extends(
    db: &DbPool,
    entity_id: Uuid,
    base_id: Uuid,
) -> Result<(), AppError> {
    sqlx::query("UPDATE entity_info SET extends_entity_id = $2 WHERE id = $1")
        .bind(entity_id)
        .bind(base_id)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// The base `entity_id` extends, if any.
pub(crate) async fn extends_of(db: &DbPool, entity_id: Uuid) -> Result<Option<Uuid>, AppError> {
    let base: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT extends_entity_id FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(base.flatten())
}

/// Whether `base_id` names a live entity.
pub(crate) async fn base_is_live(db: &DbPool, base_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM entity_info WHERE id = $1 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(base_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

//! A1-T1: write an attribute's or an entity's sensitivity label. Writing a
//! label through here marks it confirmed; the migration's mapped labels stay
//! unconfirmed until a builder sets them.

use attome_core::Sensitivity;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// Set the label of attribute `attribute_id` and mark it confirmed, with a
/// change-log entry so every node reloads the entity's metadata.
pub async fn set_attribute_sensitivity(
    db: &DbPool,
    attribute_id: Uuid,
    label: Sensitivity,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let entity: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE attribute_info a \
            SET sensitivity = $2, sensitivity_confirmed = true \
           FROM entity_info e \
          WHERE a.id = $1 AND e.id = a.entity_ref \
      RETURNING e.id, e.logicalname",
    )
    .bind(attribute_id)
    .bind(label.as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((entity_id, entity)) = entity else {
        return Err(AppError::NotFound);
    };
    attome_core::append_change_log(&mut tx, entity_id, &entity, attome_core::ChangeKind::Upsert)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

/// Set the label of entity `entity_id` and mark it confirmed.
pub async fn set_entity_sensitivity(
    db: &DbPool,
    entity_id: Uuid,
    label: Sensitivity,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let entity: Option<String> = sqlx::query_scalar(
        "UPDATE entity_info SET sensitivity = $2, sensitivity_confirmed = true \
          WHERE id = $1 RETURNING logicalname",
    )
    .bind(entity_id)
    .bind(label.as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(entity) = entity else {
        return Err(AppError::NotFound);
    };
    attome_core::append_change_log(&mut tx, entity_id, &entity, attome_core::ChangeKind::Upsert)
        .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(())
}

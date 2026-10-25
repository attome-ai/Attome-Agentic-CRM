//! M7-T1: the attributes an entity gets with its first stage process
//! (`attome_model::kinds::stage_process`): `stage`, nullable text holding
//! the record's current stage code, and `stage_entered_at`, a date that
//! stamps every change of it (`options.stamps_changes`, D5-T2). Both are
//! catalogue changes on any table size, and existing rows are not rewritten.
//! Registering them goes through the reconcile path every engine's seeded
//! attribute uses, so a second call changes nothing.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

use attome_model::kinds::stage_process::{STAGE_ATTRIBUTE, STAGE_ENTERED_ATTRIBUTE};

/// Gives `entity_id` its `stage` and `stage_entered_at` attributes and
/// columns, when it has neither.
pub async fn ensure_columns(db: &DbPool, entity_id: Uuid) -> Result<(), AppError> {
    super::attribute::ensure_attribute(
        db,
        entity_id,
        STAGE_ATTRIBUTE,
        "Stage",
        "text",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await?;
    super::attribute::ensure_attribute(
        db,
        entity_id,
        STAGE_ENTERED_ATTRIBUTE,
        "Entered stage",
        "date_time",
        false,
        false,
        true,
        true,
        None,
        Some(serde_json::json!({ "stamps_changes": { "field": STAGE_ATTRIBUTE } })),
    )
    .await
    .map(|_| ())
}

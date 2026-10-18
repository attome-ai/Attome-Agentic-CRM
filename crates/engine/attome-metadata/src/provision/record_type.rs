//! A27-T1: the `record_type` attribute an entity gets with its first record
//! type (`attome_model::kinds::record_type`).
//!
//! The column is nullable text, so adding it is a catalogue change on any
//! table size, and existing rows are not rewritten: a record whose
//! `record_type` is empty is of the entity's default type. Registering it
//! goes through the same reconcile path as every engine's seeded attribute,
//! so a second call changes nothing and the metadata change log tells every
//! node.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// Gives `entity_id` its `record_type` attribute and column, when it has
/// neither.
pub async fn ensure_column(db: &DbPool, entity_id: Uuid) -> Result<(), AppError> {
    super::attribute::ensure_attribute(
        db,
        entity_id,
        attome_model::kinds::record_type::RECORD_TYPE_ATTRIBUTE,
        "Record type",
        "text",
        false,
        false,
        true,
        true,
        None,
        None,
    )
    .await
    .map(|_| ())
}

//! One-time historical cleanup for `tag_item` — REVIEW-2026-09-02 item
//! 11 (seeds-to-bundles) moved this entity pair's steady-state metadata to
//! `platform-bundles/attome-api-tag.json`, applied via
//! `bundle::apply_platform_bundle`. This function is the one piece of the
//! old seed body that isn't pure metadata and so cannot live in a bundle:
//! retiring the free-text `name` attribute an earlier revision of this seed
//! mistakenly gave `tag_item` (see the bundle file's own comment for the
//! full history). `retire_attribute` only flips `is_active`, so this is safe
//! to leave in place forever — a no-op once already retired, and a fresh
//! database never provisions `name` in the first place, so it is a no-op
//! there from the very first boot.

use attome_db::DbPool;
use attome_metadata::provision::retire_attribute;
use attome_types::AppError;

use crate::seed_support::entity_id_by_logicalname;

pub async fn retire_legacy_name(db: &DbPool) -> Result<(), AppError> {
    let id = entity_id_by_logicalname(db, "tag_item").await?;
    retire_attribute(db, id, "name").await?;
    Ok(())
}

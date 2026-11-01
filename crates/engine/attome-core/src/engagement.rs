//! E6-T9: a person engaged with marketing (opened or clicked an email,
//! submitted a form). Their `last_marketing_engagement_at` moves to now and
//! the sunset policy lets go of them: `marketing_sunset_at` and
//! `reengagement_sent_at` are cleared, so they are mailed again. Shared by
//! every place that sees engagement (email tracking, campaign tracking,
//! forms); an entity without the three attributes (the marketing pack's
//! deliverability changeset) is left alone.

use attome_types::AppError;
use uuid::Uuid;

use crate::{EngineState, quote_ident};

/// The attributes the sunset policy keeps on a person.
pub const ATTRIBUTES: [&str; 3] = [
    "last_marketing_engagement_at",
    "marketing_sunset_at",
    "reengagement_sent_at",
];

/// Whether `entity` carries the sunset attributes.
pub fn tracks(state: &EngineState, entity: &str) -> bool {
    state.entities.load().get(entity).is_some_and(|meta| {
        ATTRIBUTES
            .iter()
            .all(|name| meta.attrs.iter().any(|a| a.logicalname == *name))
    })
}

/// Records that the people `ids` of `entity` engaged now; how many rows
/// changed.
pub async fn touch(state: &EngineState, entity: &str, ids: &[Uuid]) -> Result<u64, AppError> {
    if ids.is_empty() || !tracks(state, entity) {
        return Ok(0);
    }
    let changed = sqlx::query(&format!(
        "UPDATE {} SET last_marketing_engagement_at = now(), marketing_sunset_at = NULL, \
                reengagement_sent_at = NULL, modified_at = now(), row_version = row_version + 1 \
          WHERE id = ANY($1)",
        quote_ident(entity)
    ))
    .bind(ids)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(changed)
}

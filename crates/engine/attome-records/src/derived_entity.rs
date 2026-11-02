//! A26-T1: the record routes over a derived entity
//! (`attome_metadata::provision::derived_entity`). A derived entity is not
//! in the metadata registry, so these hooks run only for a name the
//! registry does not know, and cost one read of `derived_entity` then.
//!
//! - `GET /api/v1/{entity}` and `GET /api/v1/{entity}/{id}` read through the
//!   anchor's own query (`query/run`'s engine) with the members predicate
//!   added: the caller needs the derived entity's read privilege (the
//!   route's extractor) and the anchor's (the query checks it), and the
//!   anchor's record-level security and field gates apply to every member.
//! - Every write path answers 405 (V2-D1628 (1)).

use attome_core::EngineState;
use attome_metadata::provision::derived_entity::{self, DerivedEntity};
use attome_types::AppError;

/// A derived entity resolved for a read: its anchor and the predicate on
/// the anchor aliased `t` that keeps its members.
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedRead {
    pub definition: DerivedEntity,
    pub anchor: String,
    pub restrict: String,
}

/// The definition of `entity` when it is a derived entity, not a
/// registered one.
async fn definition(state: &EngineState, entity: &str) -> Result<Option<DerivedEntity>, AppError> {
    if state.entities.load().get(entity).is_some() {
        return Ok(None);
    }
    derived_entity::find(&state.base.db, entity).await
}

/// `entity` resolved for a read, when it is a derived entity. An anchor
/// that no longer exists is a 404.
pub async fn for_read(state: &EngineState, entity: &str) -> Result<Option<DerivedRead>, AppError> {
    let Some(def) = definition(state, entity).await? else {
        return Ok(None);
    };
    let registry = state.entities.load();
    let anchor = registry.get(&def.anchor).ok_or(AppError::NotFound)?;
    let restrict = derived_entity::members_predicate(&def, anchor, "t")?;
    Ok(Some(DerivedRead {
        anchor: def.anchor.clone(),
        definition: def,
        restrict,
    }))
}

/// 405 when `entity` is a derived entity: nothing writes to one.
pub async fn refuse_write(state: &EngineState, entity: &str) -> Result<(), AppError> {
    if definition(state, entity).await?.is_some() {
        return Err(AppError::MethodNotAllowed);
    }
    Ok(())
}

//! Y11-T10: what a customer may not change. Two rules, checked by the
//! admin metadata routes (the customer's surface; platform and app
//! definitions arrive through seeds and bundles, which these routes do not
//! serve):
//!
//! - **Reserved names.** A new entity or field may not take a name the
//!   platform defines, nor one starting with a reserved prefix
//!   ([`RESERVED_PREFIXES`]), so a later platform release cannot collide
//!   with a customer's item. (`at_` is not reserved: packs use it as a
//!   word, `at_risk_tolerance`.)
//! - **Locks.** A layer may lock an object it owns (`metadata_lock`,
//!   migration 0083): `locked` refuses every change to it, `add_only`
//!   refuses changing or removing what is there but allows additions (a new
//!   field on an entity, a new choice value on a field). An entity's lock
//!   covers its fields.

use std::collections::BTreeSet;

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// Name prefixes kept for the platform.
pub const RESERVED_PREFIXES: &[&str] = &["attome_", "xrm_"];

/// Whether a customer may not take `name`.
pub fn is_reserved(name: &str, platform_names: &BTreeSet<String>) -> bool {
    platform_names.contains(name) || RESERVED_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// [`is_reserved`] as the admin routes answer it.
pub fn refuse_reserved(name: &str, platform_names: &BTreeSet<String>) -> Result<(), AppError> {
    if is_reserved(name, platform_names) {
        return Err(AppError::Validation(format!(
            "{name:?} is reserved by the platform (its names and the prefixes {})",
            RESERVED_PREFIXES.join(", ")
        )));
    }
    Ok(())
}

/// What a change does to an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// Adds something to it (a field, a choice value).
    Add,
    /// Changes what is there.
    Set,
    /// Removes it or part of it.
    Remove,
}

/// A lock's mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Locked,
    AddOnly,
}

impl LockMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "locked" => Some(Self::Locked),
            "add_only" => Some(Self::AddOnly),
            _ => None,
        }
    }
}

/// Whether `mode` allows `change`.
pub fn lock_allows(mode: LockMode, change: ChangeKind) -> bool {
    matches!((mode, change), (LockMode::AddOnly, ChangeKind::Add))
}

fn refusal(mode: LockMode) -> AppError {
    AppError::Conflict(match mode {
        LockMode::Locked => "metadata_locked: this item is locked by the layer that owns it",
        LockMode::AddOnly => {
            "metadata_add_only: this item only takes additions; what is there cannot be changed"
        }
    })
}

/// The lock on `(kind, key)`, if any.
async fn lock_of(db: &DbPool, kind: &str, key: &str) -> Result<Option<LockMode>, AppError> {
    let mode: Option<String> = sqlx::query_scalar(
        "SELECT mode FROM metadata_lock WHERE object_kind = $1 AND object_key = $2",
    )
    .bind(kind)
    .bind(key)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(mode.as_deref().and_then(LockMode::parse))
}

/// Refuses `change` to entity `entity` when its lock does not allow it.
pub async fn check_entity(db: &DbPool, entity: &str, change: ChangeKind) -> Result<(), AppError> {
    match lock_of(db, "entity", entity).await? {
        Some(mode) if !lock_allows(mode, change) => Err(refusal(mode)),
        _ => Ok(()),
    }
}

/// [`check_entity`] by id; an unknown entity passes (the route answers 404).
pub async fn check_entity_id(
    db: &DbPool,
    entity_id: Uuid,
    change: ChangeKind,
) -> Result<(), AppError> {
    let name: Option<String> =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    match name {
        Some(name) => check_entity(db, &name, change).await,
        None => Ok(()),
    }
}

/// Refuses `change` to a field when its entity's lock or its own
/// (`attribute`, `entity.field`) does not allow it.
pub async fn check_attribute(
    db: &DbPool,
    entity_id: Uuid,
    attribute_id: Uuid,
    change: ChangeKind,
) -> Result<(), AppError> {
    let names: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT e.logicalname, a.logicalname FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
          WHERE a.id = $1 AND e.id = $2",
    )
    .bind(attribute_id)
    .bind(entity_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(entity), Some(field))) = names else {
        return Ok(());
    };
    // A change to a field is a change to its entity, except that adding to
    // the field (a choice value) is an addition to the entity too.
    check_entity(db, &entity, change).await?;
    match lock_of(db, "attribute", &format!("{entity}.{field}")).await? {
        Some(mode) if !lock_allows(mode, change) => Err(refusal(mode)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_names_and_prefixes() {
        let platform: BTreeSet<String> = ["account".to_owned()].into_iter().collect();
        assert!(is_reserved("account", &platform));
        assert!(is_reserved("attome_widget", &platform));
        assert!(is_reserved("xrm_legacy", &platform));
        assert!(!is_reserved("at_risk_tolerance", &platform));
        assert!(!is_reserved("project_note", &platform));
        assert!(refuse_reserved("attome_x", &platform).is_err());
    }

    #[test]
    fn locks_allow_only_what_their_mode_allows() {
        for change in [ChangeKind::Add, ChangeKind::Set, ChangeKind::Remove] {
            assert!(!lock_allows(LockMode::Locked, change));
        }
        assert!(lock_allows(LockMode::AddOnly, ChangeKind::Add));
        assert!(!lock_allows(LockMode::AddOnly, ChangeKind::Set));
        assert!(!lock_allows(LockMode::AddOnly, ChangeKind::Remove));
        assert_eq!(LockMode::parse("add_only"), Some(LockMode::AddOnly));
        assert_eq!(LockMode::parse("other"), None);
    }
}

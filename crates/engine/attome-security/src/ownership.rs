//! A31-T1: who an entity's records belong to, for access.
//!
//! An entity's settings (`attome_model::kinds::entity_settings`) may say
//! `"access": { "mode": "own", "ownership": "organisation" | "unit" }`:
//!
//! - [`Ownership::UserOrTeam`], the default: a record belongs to its owner;
//!   the role levels and the owner decide ([`crate::rls`]).
//! - [`Ownership::Organisation`]: the owner columns play no part. A role
//!   that reaches the entity at any level reaches every record; a person
//!   with no role on it still sees only what is shared with them.
//! - [`Ownership::Unit`]: a record belongs to its unit (`organization_ref`).
//!   The user and team levels reach the person's own units, the unit level
//!   their units and the units below them, and owning a record grants
//!   nothing by itself.
//!
//! Only the record filter of a real table follows the model. Search and
//! audit lists, which filter many entities at once, keep the default: for an
//! organisation entity they show less than the model allows; for a unit
//! entity they still show the records a person owns (`docs/access-model.md`).
//!
//! - **Source of truth:** the published metadata version's cooked
//!   `entity_settings` artefacts.
//! - **Key:** the entity id.
//! - **Invalidation:** [`install`] replaces the whole set; the metadata
//!   runtime calls it every time this node loads or follows a version.
//! - **Cold start:** empty until the first version is loaded at boot, so
//!   every entity keeps the default until then. A person's cached access
//!   resolved before an entity became unit-owned has no own units: their
//!   user and team levels reach none of its records until it is resolved
//!   again (narrower, never wider).

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use uuid::Uuid;

/// An entity's ownership model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ownership {
    #[default]
    UserOrTeam,
    Organisation,
    Unit,
}

impl Ownership {
    /// The model a settings value names; `None` for an unknown name.
    pub fn parse(name: &str) -> Option<Ownership> {
        match name {
            "user_or_team" => Some(Ownership::UserOrTeam),
            "organisation" => Some(Ownership::Organisation),
            "unit" => Some(Ownership::Unit),
            _ => None,
        }
    }
}

type Models = Arc<HashMap<Uuid, Ownership>>;

fn slot() -> &'static RwLock<Models> {
    static SLOT: OnceLock<RwLock<Models>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Arc::new(HashMap::new())))
}

/// Replaces every entity's model; an entity not named keeps the default.
pub fn install(models: impl IntoIterator<Item = (Uuid, Ownership)>) {
    let map: HashMap<Uuid, Ownership> = models
        .into_iter()
        .filter(|(_, model)| *model != Ownership::UserOrTeam)
        .collect();
    // A poisoned lock still holds a whole map; replacing it is safe.
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Arc::new(map);
}

/// A31-T4: where a disabled person's records go, per entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaverRule {
    /// To someone holding the position above the person's.
    Manager,
    /// To the person's first team (by name).
    Team,
    /// To the named user, by email.
    User(String),
}

impl LeaverRule {
    /// The rule a settings value names; `None` for an unknown one.
    pub fn parse(rule: &str) -> Option<LeaverRule> {
        match rule {
            "manager" => Some(LeaverRule::Manager),
            "team" => Some(LeaverRule::Team),
            other => other
                .strip_prefix("user:")
                .filter(|email| email.contains('@'))
                .map(|email| LeaverRule::User(email.to_owned())),
        }
    }
}

type Leavers = Arc<Vec<(Uuid, LeaverRule)>>;

fn leaver_slot() -> &'static RwLock<Leavers> {
    static SLOT: OnceLock<RwLock<Leavers>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Arc::new(Vec::new())))
}

/// Replaces every entity's leaver rule (the metadata runtime, with the
/// ownership models).
pub fn install_leavers(rules: impl IntoIterator<Item = (Uuid, LeaverRule)>) {
    *leaver_slot().write().unwrap_or_else(|e| e.into_inner()) =
        Arc::new(rules.into_iter().collect());
}

/// Every entity's leaver rule.
pub fn leaver_rules() -> Leavers {
    leaver_slot()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// The registered job that moves a disabled person's records.
pub const LEAVER_JOB: &str = "security_leaver_reassign";

/// The leaver job's payload: who left, and the administrator who disabled
/// them (the reassignment runs as that administrator).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LeaverPayload {
    pub user_id: Uuid,
    pub actor_id: Uuid,
}

/// Whether any entity is unit-owned, so a person's own units must be
/// resolved (the resolver reads this).
pub fn any_unit() -> bool {
    slot()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .any(|model| *model == Ownership::Unit)
}

/// The ownership model of `entity`.
pub fn model_for(entity: Uuid) -> Ownership {
    slot()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&entity)
        .copied()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaver_rules_parse() {
        assert_eq!(LeaverRule::parse("manager"), Some(LeaverRule::Manager));
        assert_eq!(
            LeaverRule::parse("user:head@example.com"),
            Some(LeaverRule::User("head@example.com".into()))
        );
        assert_eq!(LeaverRule::parse("user:nobody"), None);
    }

    #[test]
    fn ownership_model_names() {
        assert_eq!(Ownership::parse("unit"), Some(Ownership::Unit));
        assert_eq!(
            Ownership::parse("organisation"),
            Some(Ownership::Organisation)
        );
        assert_eq!(Ownership::parse("team"), None);
    }
}

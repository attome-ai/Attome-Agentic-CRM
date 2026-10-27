//! Q14-T2: published sharing rules as conditions in the record filter.
//!
//! A rule (`attome_model::kinds::sharing_rule`) shares one entity's records
//! owned by a unit, a team or a role's holders with the members of another
//! unit or team, or another role's holders, to read or to read and change.
//! It is never a share row per record: [`rule_arm`] adds one more allow arm
//! to [`crate::rls`]'s predicate, inside the same deny guard, so an explicit
//! deny share still wins and an unpublished rule stops applying at once.
//!
//! - **Source of truth:** the published metadata version's cooked
//!   `sharing_rule` artefacts.
//! - **Key:** the entity id.
//! - **Invalidation:** [`install`] replaces the whole set; the metadata
//!   runtime calls it every time this node loads or follows a version, so
//!   every node applies the rules of the version it serves.
//! - **Cold start:** empty until the first version is loaded at boot: no rule
//!   applies, which only ever narrows what a person sees.
//!
//! Every value spliced into the SQL is a UUID from a validated, published
//! document, written by `Uuid`'s own formatter, never request data.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use attome_server::security::SecurityContext;
use uuid::Uuid;

use crate::rls::Capability;

/// What a rule's records are picked by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    /// Records whose `organization_ref` is the unit.
    Unit(Uuid),
    /// Records owned by the team.
    Team(Uuid),
    /// Records owned by a user who holds the role directly.
    Role(Uuid),
}

/// Who a rule shares with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTarget {
    /// The unit's members (membership or home unit, not its child units).
    Unit(Uuid),
    Team(Uuid),
    /// The role's holders, directly or through a team.
    Role(Uuid),
}

/// One published rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharingRule {
    pub id: Uuid,
    pub entity: Uuid,
    pub source: RuleSource,
    pub target: RuleTarget,
    /// Read and change, not only read.
    pub write: bool,
}

impl SharingRule {
    /// A rule from its cooked fields; `None` for a type this code does not
    /// know (a newer document shape), which is then left out, never widened.
    pub fn from_parts(
        id: Uuid,
        entity: Uuid,
        source: (&str, Uuid),
        target: (&str, Uuid),
        level: &str,
    ) -> Option<Self> {
        let source = match source.0 {
            "unit" => RuleSource::Unit(source.1),
            "team" => RuleSource::Team(source.1),
            "role" => RuleSource::Role(source.1),
            _ => return None,
        };
        let target = match target.0 {
            "unit" => RuleTarget::Unit(target.1),
            "team" => RuleTarget::Team(target.1),
            "role" => RuleTarget::Role(target.1),
            _ => return None,
        };
        let write = match level {
            "read" => false,
            "write" => true,
            _ => return None,
        };
        Some(Self {
            id,
            entity,
            source,
            target,
            write,
        })
    }

    /// Whether `ctx` is someone this rule shares with.
    pub(crate) fn targets(&self, ctx: &SecurityContext) -> bool {
        match self.target {
            RuleTarget::Unit(unit) => ctx.unit_scope.own_org_ids.contains(&unit),
            RuleTarget::Team(team) => ctx.team_ids.contains(&team),
            RuleTarget::Role(role) => ctx.role_ids.as_ref().is_some_and(|r| r.contains(&role)),
        }
    }
}

type RuleSet = HashMap<Uuid, Vec<SharingRule>>;

fn rules() -> &'static RwLock<Arc<RuleSet>> {
    static RULES: OnceLock<RwLock<Arc<RuleSet>>> = OnceLock::new();
    RULES.get_or_init(|| RwLock::new(Arc::new(RuleSet::new())))
}

/// Replaces the published rule set.
pub fn install(published: impl IntoIterator<Item = SharingRule>) {
    let mut set = RuleSet::new();
    for rule in published {
        set.entry(rule.entity).or_default().push(rule);
    }
    // A poisoned lock still holds a whole set (the write is one swap), so
    // recovering it is safe.
    *rules().write().unwrap_or_else(|e| e.into_inner()) = Arc::new(set);
}

/// Whether any installed rule shares with a unit's members, so the resolver
/// knows to load the caller's own units.
pub fn targets_units() -> bool {
    current()
        .values()
        .flatten()
        .any(|rule| matches!(rule.target, RuleTarget::Unit(_)))
}

/// The installed rules for one entity (Q14-T4's explainer).
pub(crate) fn rules_for(entity_ref: Uuid) -> Vec<SharingRule> {
    current().get(&entity_ref).cloned().unwrap_or_default()
}

/// The installed rule set.
fn current() -> Arc<RuleSet> {
    rules().read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The extra allow arm the rules give `ctx` on `entity_ref` for `required`,
/// over the record columns named, or `None` when no rule applies. A read
/// needs a read or write rule; a change needs a write rule.
pub(crate) fn rule_arm(
    ctx: &SecurityContext,
    entity_ref: Uuid,
    required: Capability,
    org_col: &str,
    owner_col: &str,
    owner_type_col: &str,
) -> Option<String> {
    arm_from(
        current()
            .get(&entity_ref)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        ctx,
        required,
        org_col,
        owner_col,
        owner_type_col,
    )
}

fn uuid_list(ids: &[Uuid]) -> String {
    let joined = ids
        .iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("'{{{joined}}}'::uuid[]")
}

fn arm_from(
    entity_rules: &[SharingRule],
    ctx: &SecurityContext,
    required: Capability,
    org_col: &str,
    owner_col: &str,
    owner_type_col: &str,
) -> Option<String> {
    let mut units = Vec::new();
    let mut teams = Vec::new();
    let mut roles = Vec::new();
    for rule in entity_rules {
        if (required == Capability::Action && !rule.write) || !rule.targets(ctx) {
            continue;
        }
        match rule.source {
            RuleSource::Unit(id) => units.push(id),
            RuleSource::Team(id) => teams.push(id),
            RuleSource::Role(id) => roles.push(id),
        }
    }
    for ids in [&mut units, &mut teams, &mut roles] {
        ids.sort();
        ids.dedup();
    }
    let mut arms = Vec::new();
    if !units.is_empty() {
        arms.push(format!("{org_col} = ANY({})", uuid_list(&units)));
    }
    if !teams.is_empty() {
        arms.push(format!(
            "({owner_type_col} = 1 AND {owner_col} = ANY({}))",
            uuid_list(&teams)
        ));
    }
    if !roles.is_empty() {
        arms.push(format!(
            "({owner_type_col} = 0 AND EXISTS (SELECT 1 FROM user_account_mm_role ur \
             JOIN role r ON r.id = ur.role_ref AND r.is_deleted = false \
             WHERE ur.user_ref = {owner_col} AND ur.is_deleted = false \
             AND ur.role_ref = ANY({})))",
            uuid_list(&roles)
        ));
    }
    if arms.is_empty() {
        None
    } else {
        Some(arms.join(" OR "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(units: &[Uuid], teams: &[Uuid]) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin: false,
            privileges: Default::default(),
            field_grants: Default::default(),
            field_write_grants: Default::default(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: teams.to_vec(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: Default::default(),
            role_ids: Some(Vec::new()),
            unit_scope: attome_server::security::UnitScope {
                own_org_ids: units.to_vec(),
                ..Default::default()
            },
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    fn rule(entity: Uuid, source: RuleSource, target: RuleTarget, write: bool) -> SharingRule {
        SharingRule {
            id: Uuid::now_v7(),
            entity,
            source,
            target,
            write,
        }
    }

    #[test]
    fn sharing_rule_shares_a_units_records_with_a_team() {
        let (entity, riyadh, desk) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let rules = [rule(
            entity,
            RuleSource::Unit(riyadh),
            RuleTarget::Team(desk),
            false,
        )];

        let member = ctx(&[], &[desk]);
        let arm = arm_from(
            &rules,
            &member,
            Capability::View,
            "t.organization_ref",
            "t.owner_ref",
            "t.owner_type",
        )
        .expect("a desk member reads Riyadh's records");
        assert_eq!(
            arm,
            format!("t.organization_ref = ANY('{{{riyadh}}}'::uuid[])")
        );

        assert!(
            arm_from(&rules, &member, Capability::Action, "o", "w", "t").is_none(),
            "a read rule never lets anyone change a record"
        );
        assert!(
            arm_from(
                &rules,
                &ctx(&[], &[Uuid::now_v7()]),
                Capability::View,
                "o",
                "w",
                "t"
            )
            .is_none(),
            "someone outside the team gets nothing"
        );
    }

    #[test]
    fn sharing_rule_write_level_and_every_source_kind() {
        let (entity, team, role, unit) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let rules = [
            rule(entity, RuleSource::Team(team), RuleTarget::Unit(unit), true),
            rule(entity, RuleSource::Role(role), RuleTarget::Unit(unit), true),
        ];
        let arm = arm_from(
            &rules,
            &ctx(&[unit], &[]),
            Capability::Action,
            "o",
            "w",
            "t",
        )
        .unwrap();
        assert!(
            arm.contains(&format!("(t = 1 AND w = ANY('{{{team}}}'::uuid[]))")),
            "{arm}"
        );
        assert!(
            arm.contains(&format!("ur.role_ref = ANY('{{{role}}}'::uuid[])")),
            "{arm}"
        );
        assert!(
            arm.contains("ur.user_ref = w") && arm.starts_with("(t = 1"),
            "{arm}"
        );
    }

    #[test]
    fn sharing_rule_with_an_unknown_type_is_left_out() {
        let id = Uuid::now_v7();
        assert!(SharingRule::from_parts(id, id, ("condition", id), ("team", id), "read").is_none());
        assert!(SharingRule::from_parts(id, id, ("unit", id), ("user", id), "read").is_none());
        assert!(SharingRule::from_parts(id, id, ("unit", id), ("team", id), "delete").is_none());
        assert!(
            SharingRule::from_parts(id, id, ("unit", id), ("team", id), "write")
                .is_some_and(|r| r.write)
        );
    }
}

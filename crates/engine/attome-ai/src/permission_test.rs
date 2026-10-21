//! AH7-T1: the permission cases one agent must pass, generated from what
//! governs it rather than written by hand.
//!
//! From the agent's policy (its allow-list and risk ceiling), the actions
//! its capability packs grant (D-556), the privileges of the person it runs
//! for and the deployment's entities, [`negative_cases`] lists every call
//! the gate must stop:
//!
//! - an action outside the effective allow-list (the policy's list plus the
//!   packs' actions; a policy with no list allows every action) is refused;
//! - an allowed action above the policy's risk ceiling is refused;
//! - an allowed action needing a privilege the owner lacks is refused;
//! - an allowed Consequential action needs approval (N30);
//! - an allowed read that takes an `entity` argument is refused on every
//!   entity the owner cannot read.
//!
//! [`positive_cases`] lists the calls that must go through, so the report
//! also shows the agent is not over-restricted. Both are pure: the caller
//! resolves the policy, packs, privileges and entities. `system.admin`
//! holds every privilege and reads every entity, as at the gate.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use crate::agent::AgentPolicy;
use crate::descriptor::{ActionDescriptor, RiskTier};
use crate::registry::ActionRegistry;

/// The privilege that holds every other.
const ADMIN: &str = "system.admin";

/// What the gate must do with a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    Allowed,
    Refused,
    NeedsApproval,
}

/// One call and what must happen to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Case {
    pub action_id: String,
    /// The entity the call names, for a case about one entity.
    pub entity: Option<String>,
    pub expect: Expect,
    /// Why, in a few words.
    pub reason: &'static str,
}

/// What governs one agent.
#[derive(Debug, Clone, Copy)]
pub struct Governance<'a> {
    pub policy: &'a AgentPolicy,
    /// The actions the policy's capability packs grant.
    pub pack_action_ids: &'a [String],
    /// The privileges of the person the agent runs for.
    pub owner_privileges: &'a [String],
    /// The deployment's entities.
    pub entities: &'a [String],
}

impl Governance<'_> {
    fn allow_list(&self) -> Option<BTreeSet<&str>> {
        let list = self.policy.allowed_action_ids.as_ref()?;
        Some(
            list.iter()
                .chain(self.pack_action_ids)
                .map(String::as_str)
                .collect(),
        )
    }

    fn holds(&self, privilege: &str) -> bool {
        self.owner_privileges
            .iter()
            .any(|p| p == privilege || p == ADMIN)
    }

    fn reads(&self, entity: &str) -> bool {
        self.holds(&format!("{entity}.read"))
    }
}

/// Whether an action's argument contract names an entity. Pure.
pub fn takes_entity(descriptor: &ActionDescriptor) -> bool {
    serde_json::from_str::<Value>(descriptor.input_schema)
        .ok()
        .and_then(|schema| schema.get("properties").cloned())
        .is_some_and(|props| props.get("entity").is_some())
}

fn case(id: &str, entity: Option<&str>, expect: Expect, reason: &'static str) -> Case {
    Case {
        action_id: id.to_owned(),
        entity: entity.map(str::to_owned),
        expect,
        reason,
    }
}

/// Why an allowed action is still refused, if it is.
fn refusal(g: &Governance<'_>, d: &ActionDescriptor) -> Option<&'static str> {
    if d.risk > g.policy.risk_ceiling {
        return Some("above the policy's risk ceiling");
    }
    if !d.required_privileges.iter().all(|p| g.holds(p)) {
        return Some("the owner lacks a privilege it needs");
    }
    None
}

/// Every call the gate must stop for this agent, in registry order.
pub fn negative_cases(g: &Governance<'_>, registry: &ActionRegistry) -> Vec<Case> {
    let allow = g.allow_list();
    let mut out = Vec::new();
    for d in registry.all() {
        let id = d.id.as_str();
        if allow.as_ref().is_some_and(|list| !list.contains(id)) {
            out.push(case(id, None, Expect::Refused, "not in the allow-list"));
            continue;
        }
        if let Some(reason) = refusal(g, d) {
            out.push(case(id, None, Expect::Refused, reason));
            continue;
        }
        if d.risk == RiskTier::Consequential {
            out.push(case(id, None, Expect::NeedsApproval, "consequential"));
        }
        if d.risk == RiskTier::Read && takes_entity(d) {
            for entity in g.entities.iter().filter(|e| !g.reads(e)) {
                out.push(case(
                    id,
                    Some(entity),
                    Expect::Refused,
                    "the owner cannot read this entity",
                ));
            }
        }
    }
    out
}

/// Every call that must go through without a person: allowed, within the
/// ceiling, privileges held, not Consequential. A read that takes an entity
/// is listed on each entity the owner can read.
pub fn positive_cases(g: &Governance<'_>, registry: &ActionRegistry) -> Vec<Case> {
    let allow = g.allow_list();
    let mut out = Vec::new();
    for d in registry.all() {
        let id = d.id.as_str();
        if allow.as_ref().is_some_and(|list| !list.contains(id))
            || refusal(g, d).is_some()
            || d.risk == RiskTier::Consequential
        {
            continue;
        }
        if d.risk == RiskTier::Read && takes_entity(d) {
            for entity in g.entities.iter().filter(|e| g.reads(e)) {
                out.push(case(id, Some(entity), Expect::Allowed, "allowed read"));
            }
        } else {
            out.push(case(id, None, Expect::Allowed, "allowed"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(ceiling: RiskTier, allowed: Option<&[&str]>) -> AgentPolicy {
        AgentPolicy {
            risk_ceiling: ceiling,
            allowed_action_ids: allowed.map(strings),
            knowledge_source_refs: None,
            capability_pack_refs: None,
            max_invocations_per_session: 10,
            max_writes_per_day: 10,
            max_tokens_per_session: 10_000,
            max_session_duration_minutes: 10,
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    fn has(cases: &[Case], id: &str, entity: Option<&str>, expect: Expect) -> bool {
        cases
            .iter()
            .any(|c| c.action_id == id && c.entity.as_deref() == entity && c.expect == expect)
    }

    fn ids(cases: &[Case], expect: Expect) -> BTreeSet<String> {
        cases
            .iter()
            .filter(|c| c.expect == expect && c.entity.is_none())
            .map(|c| c.action_id.clone())
            .collect()
    }

    #[test]
    fn negative_cases_list_every_action_outside_the_allow_list() {
        let registry = ActionRegistry::new();
        let p = policy(
            RiskTier::Consequential,
            Some(&["record.get", "record.update", "email.send"]),
        );
        let packs = strings(&["record.summarize"]);
        let privileges = strings(&["account.read", "account.update"]);
        let g = Governance {
            policy: &p,
            pack_action_ids: &packs,
            owner_privileges: &privileges,
            entities: &strings(&["account", "invoice"]),
        };
        let cases = negative_cases(&g, &registry);
        let refused = ids(&cases, Expect::Refused);
        let allowed: BTreeSet<&str> = BTreeSet::from([
            "record.get",
            "record.update",
            "email.send",
            "record.summarize",
        ]);
        for d in registry.all() {
            let id = d.id.as_str();
            if !allowed.contains(id) {
                assert!(refused.contains(id), "{id} outside the list is not refused");
            }
        }
        assert!(!refused.contains("record.summarize"), "a pack grants it");
        assert!(
            ids(&cases, Expect::NeedsApproval).contains("email.send"),
            "every consequential action needs approval"
        );
    }

    #[test]
    fn negative_cases_list_every_consequential_action_without_a_list() {
        let registry = ActionRegistry::new();
        let p = policy(RiskTier::Consequential, None);
        let privileges = strings(&[ADMIN]);
        let g = Governance {
            policy: &p,
            pack_action_ids: &[],
            owner_privileges: &privileges,
            entities: &[],
        };
        let cases = negative_cases(&g, &registry);
        let approval = ids(&cases, Expect::NeedsApproval);
        for d in registry.all() {
            if d.risk == RiskTier::Consequential {
                assert!(approval.contains(d.id.as_str()), "{}", d.id.as_str());
            }
        }
        assert!(
            ids(&cases, Expect::Refused).is_empty(),
            "an admin with no list is refused nothing"
        );
    }

    #[test]
    fn negative_cases_refuse_above_the_ceiling_and_unreadable_entities() {
        let registry = ActionRegistry::new();
        let p = policy(RiskTier::Read, Some(&["record.get", "record.update"]));
        let privileges = strings(&["account.read", "account.update"]);
        let g = Governance {
            policy: &p,
            pack_action_ids: &[],
            owner_privileges: &privileges,
            entities: &strings(&["account", "invoice"]),
        };
        let cases = negative_cases(&g, &registry);
        assert!(has(&cases, "record.update", None, Expect::Refused));
        if registry.resolve("record.get").is_some_and(takes_entity) {
            assert!(has(&cases, "record.get", Some("invoice"), Expect::Refused));
            let positive = positive_cases(&g, &registry);
            let allowed = Expect::Allowed;
            assert!(has(&positive, "record.get", Some("account"), allowed));
            assert!(!has(&positive, "record.get", Some("invoice"), allowed));
        }
    }

    #[test]
    fn positive_cases_never_include_a_refused_or_consequential_call() {
        let registry = ActionRegistry::new();
        let p = policy(RiskTier::Consequential, None);
        let privileges = strings(&[ADMIN]);
        let g = Governance {
            policy: &p,
            pack_action_ids: &[],
            owner_privileges: &privileges,
            entities: &strings(&["account"]),
        };
        let negative: BTreeSet<(String, Option<String>)> = negative_cases(&g, &registry)
            .into_iter()
            .map(|c| (c.action_id, c.entity))
            .collect();
        for c in positive_cases(&g, &registry) {
            assert_eq!(c.expect, Expect::Allowed);
            let key = (c.action_id.clone(), c.entity.clone());
            assert!(!negative.contains(&key), "{}", c.action_id);
        }
    }
}

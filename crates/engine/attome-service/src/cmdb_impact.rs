//! CMDB impact analysis (roadmap H5-T3), pure: which business services and
//! users are affected when a configuration item fails or changes.
//!
//! Relationships point from a dependant to what it depends on ("app runs on
//! server"). Impact flows the other way: from the failed item up to every
//! item that depends on it, directly or through others, up to
//! [`MAX_HOPS`] relationships away. Each affected item is reported once,
//! at the fewest hops it was reached by; the affected services and their
//! users are collected from those items.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::Serialize;
use uuid::Uuid;

/// How far the walk goes.
pub const MAX_HOPS: u32 = 5;

/// `dependant` depends on `depends_on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relationship {
    pub dependant: Uuid,
    pub depends_on: Uuid,
}

/// A configuration item, with what it is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub id: Uuid,
    /// Set when the item is a business service.
    pub is_service: bool,
    /// People who use it directly (subscribers of a service, owners of a
    /// device).
    pub users: Vec<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AffectedItem {
    pub id: Uuid,
    pub hops: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Impact {
    /// Items that depend on the failed one, nearest first.
    pub items: Vec<AffectedItem>,
    /// Business services among them (and the failed item itself when it is
    /// one).
    pub services: Vec<Uuid>,
    /// Everyone who uses an affected item, without repeats.
    pub users: Vec<Uuid>,
    /// Whether items beyond the hop limit were left out.
    pub truncated: bool,
}

/// Walks from `failed` to everything that depends on it.
pub fn analyse(failed: Uuid, relationships: &[Relationship], items: &[Item]) -> Impact {
    let mut dependants: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for r in relationships {
        dependants
            .entry(r.depends_on)
            .or_default()
            .push(r.dependant);
    }
    let by_id: HashMap<Uuid, &Item> = items.iter().map(|i| (i.id, i)).collect();
    let mut seen: HashSet<Uuid> = HashSet::from([failed]);
    let mut queue = VecDeque::from([(failed, 0u32)]);
    let mut out = Impact::default();
    let mut reached = vec![failed];
    while let Some((id, hops)) = queue.pop_front() {
        for next in dependants.get(&id).map(Vec::as_slice).unwrap_or_default() {
            if seen.contains(next) {
                continue;
            }
            if hops + 1 > MAX_HOPS {
                out.truncated = true;
                continue;
            }
            seen.insert(*next);
            out.items.push(AffectedItem {
                id: *next,
                hops: hops + 1,
            });
            reached.push(*next);
            queue.push_back((*next, hops + 1));
        }
    }
    let mut users_seen = HashSet::new();
    for id in reached {
        let Some(item) = by_id.get(&id) else { continue };
        if item.is_service {
            out.services.push(id);
        }
        for user in &item.users {
            if users_seen.insert(*user) {
                out.users.push(*user);
            }
        }
    }
    out
}

#[cfg(test)]
mod cmdb_impact {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn rel(dependant: u128, depends_on: u128) -> Relationship {
        Relationship {
            dependant: u(dependant),
            depends_on: u(depends_on),
        }
    }

    fn item(id: u128, service: bool, users: &[u128]) -> Item {
        Item {
            id: u(id),
            is_service: service,
            users: users.iter().map(|x| u(*x)).collect(),
        }
    }

    #[test]
    fn a_server_failure_reaches_the_services_on_it() {
        // Payroll (service) -> payroll app -> db -> server; HR portal
        // (service) -> db; the mail app is on another server.
        let rels = [
            rel(10, 11),
            rel(11, 12),
            rel(12, 13),
            rel(20, 12),
            rel(30, 31),
        ];
        let items = [
            item(10, true, &[900, 901]),
            item(11, false, &[]),
            item(12, false, &[]),
            item(13, false, &[]),
            item(20, true, &[901, 902]),
            item(30, true, &[903]),
        ];
        let impact = analyse(u(13), &rels, &items);
        assert_eq!(
            impact.items.first().map(|i| (i.id, i.hops)),
            Some((u(12), 1))
        );
        let mut services = impact.services.clone();
        services.sort();
        assert_eq!(services, vec![u(10), u(20)]);
        let mut users = impact.users.clone();
        users.sort();
        assert_eq!(users, vec![u(900), u(901), u(902)], "each user once");
        assert!(!impact.truncated);
    }

    #[test]
    fn the_walk_stops_after_five_hops_and_survives_cycles() {
        let rels: Vec<Relationship> = (1..=7).map(|i| rel(i + 1, i)).chain([rel(1, 3)]).collect();
        let items: Vec<Item> = (1..=8).map(|i| item(i, i == 8, &[])).collect();
        let impact = analyse(u(1), &rels, &items);
        assert_eq!(impact.items.len(), 5);
        assert_eq!(impact.items.last().map(|i| i.hops), Some(5));
        assert!(impact.truncated, "items six hops away are left out");
        assert!(impact.services.is_empty());
    }
}

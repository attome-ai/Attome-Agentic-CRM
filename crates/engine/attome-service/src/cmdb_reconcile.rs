//! CMDB reconciliation (roadmap H5-T2), pure: configuration items reported
//! by several discovery sources (an agent, a cloud inventory, a manual
//! import) become one record each.
//!
//! A discovered item matches an existing one by its identifiers, strongest
//! first: serial number, then MAC address, then fully qualified host name
//! (compared case-insensitively, a host name without its domain matching
//! the same short name). An item that matches two existing records is not
//! merged: it is an ambiguity for a person.
//!
//! Each attribute takes the value from the source with the highest
//! precedence for that attribute (a per-attribute list, else the default
//! list); a source not listed ranks below every listed one, and a value
//! from a lower source never replaces one from a higher source.

use std::collections::HashMap;

use serde::Serialize;
use uuid::Uuid;

/// One item as a source reports it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Discovered {
    pub source: String,
    pub serial: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub attributes: HashMap<String, String>,
}

/// An item already in the CMDB, with which source set each attribute.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Existing {
    pub id: Uuid,
    pub serial: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    /// Attribute to (value, source that set it).
    pub attributes: HashMap<String, (String, String)>,
}

/// Which sources win, per attribute.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Precedence {
    /// Highest first.
    pub default: Vec<String>,
    pub per_attribute: HashMap<String, Vec<String>>,
}

impl Precedence {
    /// Lower is stronger; unlisted sources rank last.
    fn rank(&self, attribute: &str, source: &str) -> usize {
        let list = self.per_attribute.get(attribute).unwrap_or(&self.default);
        list.iter()
            .position(|s| s.eq_ignore_ascii_case(source))
            .unwrap_or(usize::MAX)
    }
}

/// How the discovered item was matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchedBy {
    Serial,
    Mac,
    Hostname,
}

/// What to do with one discovered item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Reconciled {
    /// No record has its identifiers: create one with these attributes.
    Create { attributes: HashMap<String, String> },
    /// Write `changes` (attribute to new value) on `id`; empty when the
    /// sources agree or the higher sources already set everything.
    Update {
        id: Uuid,
        matched_by: MatchedBy,
        changes: HashMap<String, String>,
    },
    /// Two or more records match: a person decides.
    Ambiguous { candidates: Vec<Uuid> },
}

fn norm(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_ascii_lowercase)
}

fn mac(value: &Option<String>) -> Option<String> {
    norm(value).map(|v| v.chars().filter(char::is_ascii_hexdigit).collect())
}

fn short_host(value: &Option<String>) -> Option<String> {
    norm(value).map(|v| v.split('.').next().unwrap_or_default().to_owned())
}

/// Reconciles one discovered item against the existing records.
pub fn reconcile(found: &Discovered, existing: &[Existing], precedence: &Precedence) -> Reconciled {
    for by in [MatchedBy::Serial, MatchedBy::Mac, MatchedBy::Hostname] {
        let key = |value: &Option<String>| match by {
            MatchedBy::Serial => norm(value),
            MatchedBy::Mac => mac(value),
            MatchedBy::Hostname => short_host(value),
        };
        let field = |e: &Existing| match by {
            MatchedBy::Serial => key(&e.serial),
            MatchedBy::Mac => key(&e.mac),
            MatchedBy::Hostname => key(&e.hostname),
        };
        let mine = match by {
            MatchedBy::Serial => &found.serial,
            MatchedBy::Mac => &found.mac,
            MatchedBy::Hostname => &found.hostname,
        };
        let Some(wanted) = key(mine).filter(|k| !k.is_empty()) else {
            continue;
        };
        let hits: Vec<&Existing> = existing
            .iter()
            .filter(|e| field(e).as_deref() == Some(wanted.as_str()))
            .collect();
        match hits.as_slice() {
            [] => continue,
            [one] => {
                let changes = found
                    .attributes
                    .iter()
                    .filter(|(name, value)| match one.attributes.get(*name) {
                        None => true,
                        Some((current, setter)) => {
                            current != *value
                                && precedence.rank(name, &found.source)
                                    <= precedence.rank(name, setter)
                        }
                    })
                    .map(|(n, v)| (n.clone(), v.clone()))
                    .collect();
                return Reconciled::Update {
                    id: one.id,
                    matched_by: by,
                    changes,
                };
            }
            many => {
                return Reconciled::Ambiguous {
                    candidates: many.iter().map(|e| e.id).collect(),
                };
            }
        }
    }
    Reconciled::Create {
        attributes: found.attributes.clone(),
    }
}

#[cfg(test)]
mod cmdb_reconcile {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_owned())
    }

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn precedence() -> Precedence {
        Precedence {
            default: vec!["sccm".into(), "agent".into()],
            per_attribute: HashMap::from([("owner".to_owned(), vec!["manual".to_owned()])]),
        }
    }

    fn server() -> Existing {
        Existing {
            id: Uuid::from_u128(1),
            serial: s("SN-001"),
            mac: s("00:1A:2B:3C:4D:5E"),
            hostname: s("app01.corp.example"),
            attributes: HashMap::from([
                (
                    "os".to_owned(),
                    ("Windows Server 2022".to_owned(), "sccm".to_owned()),
                ),
                ("owner".to_owned(), ("Ops".to_owned(), "manual".to_owned())),
            ]),
        }
    }

    #[test]
    fn identifiers_match_strongest_first_and_precedence_decides() {
        let found = Discovered {
            source: "agent".into(),
            serial: s(" sn-001 "),
            hostname: s("other"),
            attributes: attrs(&[
                ("os", "Windows Server 2019"),
                ("owner", "IT"),
                ("ram_gb", "64"),
            ]),
            ..Discovered::default()
        };
        let r = reconcile(&found, &[server()], &precedence());
        assert_eq!(
            r,
            Reconciled::Update {
                id: Uuid::from_u128(1),
                matched_by: MatchedBy::Serial,
                changes: attrs(&[("ram_gb", "64")]),
            },
            "sccm outranks the agent on os, and only a person sets the owner"
        );
        let found = Discovered {
            source: "sccm".into(),
            mac: s("001a2b3c4d5e"),
            attributes: attrs(&[("os", "Windows Server 2025")]),
            ..Discovered::default()
        };
        assert_eq!(
            reconcile(&found, &[server()], &precedence()),
            Reconciled::Update {
                id: Uuid::from_u128(1),
                matched_by: MatchedBy::Mac,
                changes: attrs(&[("os", "Windows Server 2025")]),
            }
        );
    }

    #[test]
    fn short_host_names_match_and_duplicates_are_ambiguous() {
        let found = Discovered {
            source: "agent".into(),
            hostname: s("APP01"),
            ..Discovered::default()
        };
        assert!(matches!(
            reconcile(&found, &[server()], &precedence()),
            Reconciled::Update {
                matched_by: MatchedBy::Hostname,
                ..
            }
        ));
        let mut twin = server();
        twin.id = Uuid::from_u128(2);
        twin.serial = None;
        twin.mac = None;
        assert_eq!(
            reconcile(&found, &[server(), twin], &precedence()),
            Reconciled::Ambiguous {
                candidates: vec![Uuid::from_u128(1), Uuid::from_u128(2)]
            }
        );
        let new = Discovered {
            source: "agent".into(),
            serial: s("SN-999"),
            ..Discovered::default()
        };
        assert!(matches!(
            reconcile(&new, &[server()], &precedence()),
            Reconciled::Create { .. }
        ));
    }
}

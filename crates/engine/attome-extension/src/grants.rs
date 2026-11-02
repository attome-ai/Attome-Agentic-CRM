//! Y10-T3: what an extension may touch. Its manifest declares grants:
//! entities (read, write), attributes within them, secrets by name and
//! outbound hosts. An administrator approves them when the extension is
//! published (Z10); every host call checks them here first and refuses
//! anything outside, with a typed reason. No grant is implied: an empty
//! manifest reaches nothing.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Access to one entity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EntityGrant {
    pub read: bool,
    pub write: bool,
    /// The attributes it may read or write; empty means every attribute
    /// the caller may use.
    pub attributes: BTreeSet<String>,
}

/// An extension's declared grants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grants {
    pub entities: BTreeMap<String, EntityGrant>,
    pub secrets: BTreeSet<String>,
    /// Hosts for HTTP, exact or `.`-prefixed for a domain and its
    /// subdomains.
    pub hosts: BTreeSet<String>,
}

/// Why a host call was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Denied {
    #[error("the extension may not read {0}")]
    Read(String),
    #[error("the extension may not write {0}")]
    Write(String),
    #[error("the extension may not use {entity}.{attribute}")]
    Attribute { entity: String, attribute: String },
    #[error("the extension may not read the secret {0}")]
    Secret(String),
    #[error("the extension may not call {0}")]
    Host(String),
}

/// The problems of a manifest's grants, for publishing. Pure.
pub fn check(grants: &Grants) -> Vec<String> {
    let mut problems = Vec::new();
    let ident = |s: &str| {
        !s.is_empty()
            && s.len() <= 63
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    for (entity, grant) in &grants.entities {
        if !ident(entity) {
            problems.push(format!("{entity} is not an entity name"));
        }
        if !grant.read && !grant.write {
            problems.push(format!("{entity} is granted neither read nor write"));
        }
        for attribute in &grant.attributes {
            if !ident(attribute) {
                problems.push(format!("{entity}.{attribute} is not an attribute name"));
            }
        }
    }
    for secret in &grants.secrets {
        if secret.trim().is_empty() {
            problems.push("a secret grant has no name".into());
        }
    }
    for host in &grants.hosts {
        let bare = host.strip_prefix('.').unwrap_or(host);
        if bare.is_empty() || bare.contains(['/', ':', '*', ' ']) || !bare.contains('.') {
            problems.push(format!("{host} is not a host name"));
        }
    }
    problems
}

impl Grants {
    /// Whether the extension may read `attributes` of `entity` (no
    /// attributes: the record as a whole).
    pub fn may_read(&self, entity: &str, attributes: &[&str]) -> Result<(), Denied> {
        let grant = self
            .entities
            .get(entity)
            .filter(|g| g.read)
            .ok_or_else(|| Denied::Read(entity.to_owned()))?;
        Self::attributes(entity, grant, attributes)
    }

    /// Whether the extension may write `attributes` of `entity`.
    pub fn may_write(&self, entity: &str, attributes: &[&str]) -> Result<(), Denied> {
        let grant = self
            .entities
            .get(entity)
            .filter(|g| g.write)
            .ok_or_else(|| Denied::Write(entity.to_owned()))?;
        Self::attributes(entity, grant, attributes)
    }

    fn attributes(entity: &str, grant: &EntityGrant, attributes: &[&str]) -> Result<(), Denied> {
        if grant.attributes.is_empty() {
            return Ok(());
        }
        match attributes.iter().find(|a| !grant.attributes.contains(**a)) {
            Some(a) => Err(Denied::Attribute {
                entity: entity.to_owned(),
                attribute: (*a).to_owned(),
            }),
            None => Ok(()),
        }
    }

    /// Whether the extension may read the secret `name`.
    pub fn may_read_secret(&self, name: &str) -> Result<(), Denied> {
        if self.secrets.contains(name) {
            Ok(())
        } else {
            Err(Denied::Secret(name.to_owned()))
        }
    }

    /// Whether the extension may call `url` (https only, a granted host).
    pub fn may_call(&self, url: &str) -> Result<(), Denied> {
        let denied = || Denied::Host(url.to_owned());
        let rest = url.strip_prefix("https://").ok_or_else(denied)?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if authority.contains('@') {
            return Err(denied());
        }
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(h, _)| h)
            .to_ascii_lowercase();
        let granted = self.hosts.iter().any(|g| {
            let g = g.to_ascii_lowercase();
            match g.strip_prefix('.') {
                Some(domain) => host == domain || host.ends_with(&g),
                None => host == g,
            }
        });
        if granted { Ok(()) } else { Err(denied()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants() -> Grants {
        serde_json::from_value(serde_json::json!({
            "entities": {
                "account": { "read": true },
                "deal": { "read": true, "write": true, "attributes": ["stage", "amount"] }
            },
            "secrets": ["erp_key"],
            "hosts": ["api.erp.example", ".partner.example"]
        }))
        .unwrap()
    }

    #[test]
    fn denied_reads_and_writes() {
        let g = grants();
        assert_eq!(g.may_read("account", &[]), Ok(()));
        assert_eq!(
            g.may_read("contact", &[]),
            Err(Denied::Read("contact".into()))
        );
        assert_eq!(
            g.may_write("account", &["name"]),
            Err(Denied::Write("account".into()))
        );
        assert_eq!(g.may_write("deal", &["stage"]), Ok(()));
        assert!(matches!(
            g.may_write("deal", &["owner_ref"]),
            Err(Denied::Attribute { .. })
        ));
        assert_eq!(g.may_read_secret("erp_key"), Ok(()));
        assert!(g.may_read_secret("smtp_password").is_err());
        assert!(
            Grants::default().may_read("account", &[]).is_err(),
            "nothing is implied"
        );
    }

    #[test]
    fn denied_hosts() {
        let g = grants();
        assert_eq!(g.may_call("https://api.erp.example/v1/orders"), Ok(()));
        assert_eq!(g.may_call("https://a.partner.example:8443/x"), Ok(()));
        assert_eq!(g.may_call("https://partner.example/"), Ok(()));
        for url in [
            "http://api.erp.example/",
            "https://evil.example/?api.erp.example",
            "https://api.erp.example.evil.example/",
            "https://user@api.erp.example/",
            "https://notpartner.example/",
        ] {
            assert!(g.may_call(url).is_err(), "{url}");
        }
    }

    #[test]
    fn manifest_problems_are_named() {
        assert!(check(&grants()).is_empty());
        let bad: Grants = serde_json::from_value(serde_json::json!({
            "entities": { "Deal": { "read": true }, "deal": {} },
            "hosts": ["*.example", "localhost"]
        }))
        .unwrap();
        let problems = check(&bad);
        assert_eq!(problems.len(), 4, "{problems:?}");
    }
}

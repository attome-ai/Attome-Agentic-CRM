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

/// Y10-T2: a stage of the record write pipeline an extension is called at,
/// or (A12-T4) a record form's event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPoint {
    BeforeValidation,
    BeforeSave,
    AfterSave,
    AfterCommit,
    /// A12-T4: a record form opened (a new record or a stored one). A
    /// `change` fills values in the form and a `reject` shows its message;
    /// nothing is saved.
    FormLoad,
    /// A12-T4: a value changed in a record form; answered as `form_load`.
    FormChange,
}

/// Y10-T2: one write an extension is called on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookDecl {
    pub entity: String,
    pub stage: HookPoint,
    /// Lower runs first.
    #[serde(default)]
    pub order: i32,
}

/// M17-T1: when a job extension runs by itself: a cron expression on a time
/// zone's wall clock, with the input each run is given.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSchedule {
    pub cron: String,
    #[serde(default = "utc")]
    pub timezone: String,
    #[serde(default)]
    pub input: serde_json::Value,
}

fn utc() -> String {
    "UTC".to_owned()
}

/// An extension's declared grants, and the writes it is called on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Grants {
    pub entities: BTreeMap<String, EntityGrant>,
    pub secrets: BTreeSet<String>,
    /// Hosts for HTTP, exact or `.`-prefixed for a domain and its
    /// subdomains.
    pub hosts: BTreeSet<String>,
    /// The hook stages it runs at; each needs a read grant on its entity.
    pub hooks: Vec<HookDecl>,
    /// M17-T1: a job extension's own schedule (`on_job`), if it has one.
    pub schedule: Option<JobSchedule>,
    /// Y10-T2: the messages a hook may reject with by key, each in English
    /// (required) and any of [`MESSAGE_LANGUAGES`]: `{key: {lang: text}}`,
    /// `{name}` in a text being filled from the rejection's `args`.
    pub messages: BTreeMap<String, BTreeMap<String, String>>,
}

/// The languages a manifest's messages are written in; English is required.
pub const MESSAGE_LANGUAGES: [&str; 2] = ["en", "ar"];

/// The longest message text a manifest may hold.
pub const MAX_MESSAGE_CHARS: usize = 500;

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
    for hook in &grants.hooks {
        if grants.may_read(&hook.entity, &[]).is_err() {
            problems.push(format!(
                "a hook on {} needs a read grant on it",
                hook.entity
            ));
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
    for (key, texts) in &grants.messages {
        let key_ok = !key.is_empty()
            && key.len() <= 63
            && key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.');
        if !key_ok {
            problems.push(format!("{key} is not a message key"));
        }
        if !texts.contains_key("en") {
            problems.push(format!("the message {key} has no English text"));
        }
        for (lang, text) in texts {
            if !MESSAGE_LANGUAGES.contains(&lang.as_str()) {
                problems.push(format!("the message {key} is in {lang}, not en or ar"));
            }
            if text.trim().is_empty() || text.chars().count() > MAX_MESSAGE_CHARS {
                problems.push(format!(
                    "the message {key} in {lang} is empty or over {MAX_MESSAGE_CHARS} characters"
                ));
            }
        }
    }
    problems
}

/// Y10-T2: a rejection's text in each language the manifest writes it in,
/// English always present: a plain message as given (English only); a key's
/// texts with each `{name}` replaced by its argument (a string as it is,
/// anything else as JSON). A key the manifest does not have is its own
/// English text. Pure.
pub fn rejection_texts(
    grants: &Grants,
    rejection: &crate::harness::Rejection,
) -> BTreeMap<String, String> {
    use crate::harness::Rejection;
    let (key, args) = match rejection {
        Rejection::Text(message) => return BTreeMap::from([("en".to_owned(), message.clone())]),
        Rejection::Keyed { key, args } => (key, args),
    };
    let Some(texts) = grants.messages.get(key) else {
        return BTreeMap::from([("en".to_owned(), key.clone())]);
    };
    let fill = |template: &str| {
        args.iter()
            .fold(template.to_owned(), |text, (name, value)| {
                let value = match value {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                text.replace(&format!("{{{name}}}"), &value)
            })
    };
    let mut out: BTreeMap<String, String> = texts
        .iter()
        .map(|(lang, template)| (lang.clone(), fill(template)))
        .collect();
    out.entry("en".to_owned()).or_insert_with(|| key.clone());
    out
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

    /// The values of `entity` the extension may see: every attribute, or
    /// the granted ones and the id; nothing without a read grant. Pure.
    pub fn visible(
        &self,
        entity: &str,
        values: &serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Map<String, serde_json::Value> {
        match self.entities.get(entity).filter(|g| g.read) {
            Some(grant) if !grant.attributes.is_empty() => values
                .iter()
                .filter(|(k, _)| k.as_str() == "id" || grant.attributes.contains(k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            Some(_) => values.clone(),
            None => serde_json::Map::new(),
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
    fn keyed_rejections_read_the_manifest_messages_in_each_language() {
        use crate::harness::Rejection;
        let g: Grants = serde_json::from_value(serde_json::json!({
            "messages": {
                "credit.over_limit": {
                    "en": "{name} is over its credit limit of {limit}",
                    "ar": "تجاوز {name} حد الائتمان {limit}"
                }
            }
        }))
        .unwrap();
        assert!(check(&g).is_empty(), "{:?}", check(&g));
        let keyed: Rejection = serde_json::from_value(serde_json::json!({
            "key": "credit.over_limit", "args": { "name": "Acme", "limit": 5000 }
        }))
        .unwrap();
        let texts = rejection_texts(&g, &keyed);
        assert_eq!(texts["en"], "Acme is over its credit limit of 5000");
        assert_eq!(texts["ar"], "تجاوز Acme حد الائتمان 5000");

        let plain: Rejection = serde_json::from_value(serde_json::json!("no")).unwrap();
        assert_eq!(
            rejection_texts(&g, &plain),
            BTreeMap::from([("en".to_owned(), "no".to_owned())])
        );
        let unknown = Rejection::Keyed {
            key: "missing.key".into(),
            args: Default::default(),
        };
        assert_eq!(rejection_texts(&g, &unknown)["en"], "missing.key");

        let bad: Grants = serde_json::from_value(serde_json::json!({
            "messages": {
                "Bad Key": { "en": "x" },
                "no_english": { "ar": "س" },
                "other_lang": { "en": "x", "fr": "y" },
                "empty": { "en": " " }
            }
        }))
        .unwrap();
        assert_eq!(check(&bad).len(), 4, "{:?}", check(&bad));
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

        // A hook needs a read grant on its entity.
        let hooked: Grants = serde_json::from_value(serde_json::json!({
            "entities": { "account": { "read": true } },
            "hooks": [
                { "entity": "account", "stage": "before_save" },
                { "entity": "deal", "stage": "after_commit", "order": 2 }
            ]
        }))
        .unwrap();
        assert_eq!(hooked.hooks[1].stage, HookPoint::AfterCommit);
        assert_eq!(
            check(&hooked),
            vec!["a hook on deal needs a read grant on it".to_owned()]
        );

        // A12-T4: form events are hook points too.
        let form: Grants = serde_json::from_value(serde_json::json!({
            "entities": { "account": { "read": true, "write": true } },
            "hooks": [
                { "entity": "account", "stage": "form_load" },
                { "entity": "account", "stage": "form_change" }
            ]
        }))
        .unwrap();
        assert_eq!(form.hooks[0].stage, HookPoint::FormLoad);
        assert_eq!(form.hooks[1].stage, HookPoint::FormChange);
        assert!(check(&form).is_empty());
    }
}

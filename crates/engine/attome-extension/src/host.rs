//! The host API of `wit/attome.wit` as a Rust trait, [`HostApi`]: the WIT
//! bindings (Y10-T2) dispatch every import to it, the server implements it
//! over the record engine, and [`FakeHost`] implements it in memory for an
//! extension's unit tests (AE2-T1). Both check the extension's [`Grants`]
//! first, so a test sees the same refusals production would.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::grants::{Denied, Grants};

/// A log line's level (WIT `log.level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

/// An HTTP answer (WIT `http.response`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

/// What the host gives an extension (the imports of the `hook` world).
pub trait HostApi {
    /// A record as a JSON object, or `None` when absent or not readable.
    fn record_get(&mut self, entity: &str, id: &str) -> Result<Option<Map<String, Value>>, String>;
    /// Changes fields of one record.
    fn record_update(
        &mut self,
        entity: &str,
        id: &str,
        changes: &Map<String, Value>,
    ) -> Result<(), String>;
    /// Creates a record; its id.
    fn record_create(
        &mut self,
        entity: &str,
        values: &Map<String, Value>,
    ) -> Result<String, String>;
    fn log(&mut self, level: Level, message: &str);
    /// A granted secret, or `None`.
    fn secret(&mut self, name: &str) -> Option<String>;
    fn http_fetch(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<Response, String>;
}

fn denied(d: Denied) -> String {
    d.to_string()
}

/// AE2-T1: the host in memory, for an extension's unit tests: records in a
/// map, logs collected, secrets from a map, HTTP answered by stubs keyed by
/// `METHOD url`. Every call is held to `grants` as the server holds it.
#[derive(Debug, Clone, Default)]
pub struct FakeHost {
    pub grants: Grants,
    /// Records by entity, then id.
    pub records: BTreeMap<String, BTreeMap<String, Map<String, Value>>>,
    pub logs: Vec<(Level, String)>,
    pub secrets: BTreeMap<String, String>,
    /// Stubbed answers by `METHOD url` (`GET https://api.example/x`).
    pub http: BTreeMap<String, Response>,
    /// The requests made, as `METHOD url`.
    pub requests: Vec<String>,
    next_id: u64,
}

impl FakeHost {
    /// A fake host with these grants and nothing else.
    pub fn with_grants(grants: Grants) -> Self {
        Self {
            grants,
            ..Self::default()
        }
    }

    /// Adds a record (as the test's setup; grants do not apply).
    pub fn insert(&mut self, entity: &str, id: &str, fields: Value) -> &mut Self {
        let fields = fields.as_object().cloned().unwrap_or_default();
        self.records
            .entry(entity.to_owned())
            .or_default()
            .insert(id.to_owned(), fields);
        self
    }
}

impl HostApi for FakeHost {
    fn record_get(&mut self, entity: &str, id: &str) -> Result<Option<Map<String, Value>>, String> {
        self.grants.may_read(entity, &[]).map_err(denied)?;
        let found = self.records.get(entity).and_then(|r| r.get(id)).cloned();
        Ok(found.map(|record| match self.grants.entities.get(entity) {
            Some(g) if !g.attributes.is_empty() => record
                .into_iter()
                .filter(|(k, _)| g.attributes.contains(k))
                .collect(),
            _ => record,
        }))
    }

    fn record_update(
        &mut self,
        entity: &str,
        id: &str,
        changes: &Map<String, Value>,
    ) -> Result<(), String> {
        let fields: Vec<&str> = changes.keys().map(String::as_str).collect();
        self.grants.may_write(entity, &fields).map_err(denied)?;
        let record = self
            .records
            .get_mut(entity)
            .and_then(|r| r.get_mut(id))
            .ok_or_else(|| format!("{entity} {id} does not exist"))?;
        for (k, v) in changes {
            record.insert(k.clone(), v.clone());
        }
        Ok(())
    }

    fn record_create(
        &mut self,
        entity: &str,
        values: &Map<String, Value>,
    ) -> Result<String, String> {
        let fields: Vec<&str> = values.keys().map(String::as_str).collect();
        self.grants.may_write(entity, &fields).map_err(denied)?;
        self.next_id += 1;
        let id = format!("fake-{}", self.next_id);
        self.records
            .entry(entity.to_owned())
            .or_default()
            .insert(id.clone(), values.clone());
        Ok(id)
    }

    fn log(&mut self, level: Level, message: &str) {
        self.logs.push((level, message.to_owned()));
    }

    fn secret(&mut self, name: &str) -> Option<String> {
        self.grants.may_read_secret(name).ok()?;
        self.secrets.get(name).cloned()
    }

    fn http_fetch(
        &mut self,
        method: &str,
        url: &str,
        _headers: &[(String, String)],
        _body: Option<&str>,
    ) -> Result<Response, String> {
        self.grants.may_call(url).map_err(denied)?;
        let key = format!("{} {url}", method.to_ascii_uppercase());
        self.requests.push(key.clone());
        self.http
            .get(&key)
            .cloned()
            .ok_or_else(|| format!("no stubbed answer for {key}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn host() -> FakeHost {
        let grants: Grants = serde_json::from_value(json!({
            "entities": { "deal": { "read": true, "write": true, "attributes": ["stage", "amount"] } },
            "secrets": ["erp_key"],
            "hosts": ["api.erp.example"]
        }))
        .unwrap();
        let mut h = FakeHost::with_grants(grants);
        h.insert(
            "deal",
            "d1",
            json!({ "stage": "open", "amount": 10, "margin": 3 }),
        );
        h.secrets.insert("erp_key".into(), "k".into());
        h.secrets.insert("smtp".into(), "s".into());
        h.http.insert(
            "GET https://api.erp.example/orders".into(),
            Response {
                status: 200,
                body: "[]".into(),
            },
        );
        h
    }

    #[test]
    fn fake_host_holds_records_logs_secrets_and_http_to_the_grants() {
        let mut h = host();
        let deal = h.record_get("deal", "d1").unwrap().unwrap();
        assert_eq!(deal.get("stage"), Some(&json!("open")));
        assert!(
            deal.get("margin").is_none(),
            "an attribute outside the grant is not read"
        );
        assert!(h.record_get("account", "a1").is_err());

        let mut changes = Map::new();
        changes.insert("stage".into(), json!("won"));
        h.record_update("deal", "d1", &changes).unwrap();
        assert_eq!(h.records["deal"]["d1"]["stage"], json!("won"));
        changes.insert("margin".into(), json!(9));
        assert!(h.record_update("deal", "d1", &changes).is_err());

        let id = h
            .record_create(
                "deal",
                &serde_json::from_value(json!({ "stage": "new" })).unwrap(),
            )
            .unwrap();
        assert!(h.records["deal"].contains_key(&id));

        h.log(Level::Info, "done");
        assert_eq!(h.logs, vec![(Level::Info, "done".to_owned())]);
        assert_eq!(h.secret("erp_key").as_deref(), Some("k"));
        assert_eq!(h.secret("smtp"), None, "an ungranted secret is not given");

        assert_eq!(
            h.http_fetch("get", "https://api.erp.example/orders", &[], None)
                .unwrap()
                .status,
            200
        );
        assert!(
            h.http_fetch("GET", "https://other.example/", &[], None)
                .is_err()
        );
        assert_eq!(
            h.requests,
            vec!["GET https://api.erp.example/orders".to_owned()]
        );
    }
}

//! AE2-T3: a run's host calls, recorded and replayed. [`Recorder`] wraps
//! any [`HostApi`] (the server's, or a [`crate::FakeHost`]) and keeps every
//! call with its result; [`Recorder::finish`] masks every secret value the
//! run was given, wherever it appears, so a recording can be stored and
//! shared. [`Replayer`] is a host that answers each call from a recording,
//! in order, and reports where the run went differently: a replay is
//! deterministic because nothing reaches a record, a secret or the network.
//!
//! Secrets replay as `***` (their values are not in the recording); a call
//! whose inputs held a secret was recorded with it masked and is compared
//! the same way.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::host::{HostApi, Level, Response};
use crate::runtime::mask_secrets;

/// One host call and what it answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum HostCall {
    RecordGet {
        entity: String,
        id: String,
        result: Result<Option<Map<String, Value>>, String>,
    },
    RecordUpdate {
        entity: String,
        id: String,
        changes: Map<String, Value>,
        result: Result<(), String>,
    },
    RecordCreate {
        entity: String,
        values: Map<String, Value>,
        result: Result<String, String>,
    },
    Log {
        level: String,
        message: String,
    },
    /// Whether the secret was given; never its value.
    Secret {
        name: String,
        given: bool,
    },
    HttpFetch {
        method: String,
        url: String,
        body: Option<String>,
        result: Result<RecordedResponse, String>,
    },
}

/// An HTTP answer, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedResponse {
    pub status: u16,
    pub body: String,
}

impl HostCall {
    /// The call without its result, for a divergence message.
    fn describe(&self) -> String {
        match self {
            Self::RecordGet { entity, id, .. } => format!("record_get {entity} {id}"),
            Self::RecordUpdate { entity, id, .. } => format!("record_update {entity} {id}"),
            Self::RecordCreate { entity, .. } => format!("record_create {entity}"),
            Self::Log { level, .. } => format!("log {level}"),
            Self::Secret { name, .. } => format!("secret {name}"),
            Self::HttpFetch { method, url, .. } => format!("http {method} {url}"),
        }
    }
}

fn level_name(level: Level) -> String {
    format!("{level:?}").to_lowercase()
}

/// Every string in `value`, masked. Pure.
fn mask_value(value: &mut Value, secrets: &[&str]) {
    match value {
        Value::String(s) => *s = mask_secrets(s, secrets),
        Value::Array(items) => items.iter_mut().for_each(|v| mask_value(v, secrets)),
        Value::Object(map) => map.values_mut().for_each(|v| mask_value(v, secrets)),
        _ => {}
    }
}

/// A host that records every call made through it.
#[derive(Debug)]
pub struct Recorder<H> {
    inner: H,
    calls: Vec<HostCall>,
    secrets: Vec<String>,
}

impl<H: HostApi> Recorder<H> {
    pub fn new(inner: H) -> Self {
        Self {
            inner,
            calls: Vec::new(),
            secrets: Vec::new(),
        }
    }

    /// The host back, and the calls with every secret value the run was
    /// given masked.
    pub fn finish(self) -> (H, Vec<HostCall>) {
        let secrets: Vec<&str> = self.secrets.iter().map(String::as_str).collect();
        let calls = self
            .calls
            .into_iter()
            .map(|call| {
                let mut value = serde_json::to_value(&call).unwrap_or(Value::Null);
                mask_value(&mut value, &secrets);
                serde_json::from_value(value).unwrap_or(call)
            })
            .collect();
        (self.inner, calls)
    }
}

impl<H: HostApi> HostApi for Recorder<H> {
    fn record_get(&mut self, entity: &str, id: &str) -> Result<Option<Map<String, Value>>, String> {
        let result = self.inner.record_get(entity, id);
        self.calls.push(HostCall::RecordGet {
            entity: entity.to_owned(),
            id: id.to_owned(),
            result: result.clone(),
        });
        result
    }

    fn record_update(
        &mut self,
        entity: &str,
        id: &str,
        changes: &Map<String, Value>,
    ) -> Result<(), String> {
        let result = self.inner.record_update(entity, id, changes);
        self.calls.push(HostCall::RecordUpdate {
            entity: entity.to_owned(),
            id: id.to_owned(),
            changes: changes.clone(),
            result: result.clone(),
        });
        result
    }

    fn record_create(
        &mut self,
        entity: &str,
        values: &Map<String, Value>,
    ) -> Result<String, String> {
        let result = self.inner.record_create(entity, values);
        self.calls.push(HostCall::RecordCreate {
            entity: entity.to_owned(),
            values: values.clone(),
            result: result.clone(),
        });
        result
    }

    fn log(&mut self, level: Level, message: &str) {
        self.inner.log(level, message);
        self.calls.push(HostCall::Log {
            level: level_name(level),
            message: message.to_owned(),
        });
    }

    fn secret(&mut self, name: &str) -> Option<String> {
        let value = self.inner.secret(name);
        if let Some(v) = &value {
            self.secrets.push(v.clone());
        }
        self.calls.push(HostCall::Secret {
            name: name.to_owned(),
            given: value.is_some(),
        });
        value
    }

    fn http_fetch(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<Response, String> {
        let result = self.inner.http_fetch(method, url, headers, body);
        self.calls.push(HostCall::HttpFetch {
            method: method.to_ascii_uppercase(),
            url: url.to_owned(),
            body: body.map(str::to_owned),
            result: result.clone().map(|r| RecordedResponse {
                status: r.status,
                body: r.body,
            }),
        });
        result
    }
}

/// What a secret replays as.
pub const REPLAYED_SECRET: &str = "***";

/// A host answering from a recording, in order.
#[derive(Debug)]
pub struct Replayer {
    calls: VecDeque<HostCall>,
    at: usize,
    divergences: Vec<String>,
}

impl Replayer {
    pub fn new(calls: Vec<HostCall>) -> Self {
        Self {
            calls: calls.into(),
            at: 0,
            divergences: Vec::new(),
        }
    }

    /// `Ok` when the run made exactly the recorded calls; otherwise every
    /// divergence, including recorded calls the run never made.
    pub fn finish(mut self) -> Result<(), Vec<String>> {
        for left in self.calls.drain(..) {
            self.divergences
                .push(format!("the run stopped before {}", left.describe()));
        }
        if self.divergences.is_empty() {
            Ok(())
        } else {
            Err(self.divergences)
        }
    }

    /// The next recorded call if `matches` says it is this one; otherwise a
    /// divergence (the recording is left where it was).
    fn take_matching(
        &mut self,
        made: String,
        matches: impl FnOnce(&HostCall) -> bool,
    ) -> Option<HostCall> {
        self.at += 1;
        match self.calls.front() {
            Some(call) if matches(call) => self.calls.pop_front(),
            Some(call) => {
                self.divergences.push(format!(
                    "call {}: the run made {made}, the recording has {}",
                    self.at,
                    call.describe()
                ));
                None
            }
            None => {
                self.divergences.push(format!(
                    "call {}: the run made {made} past the recording",
                    self.at
                ));
                None
            }
        }
    }
}

const DIVERGED: &str = "the replay diverged from the recording";

impl HostApi for Replayer {
    fn record_get(&mut self, entity: &str, id: &str) -> Result<Option<Map<String, Value>>, String> {
        let made = format!("record_get {entity} {id}");
        match self.take_matching(
            made,
            |c| matches!(c, HostCall::RecordGet { entity: e, id: i, .. } if e == entity && i == id),
        ) {
            Some(HostCall::RecordGet { result, .. }) => result,
            _ => Err(DIVERGED.into()),
        }
    }

    fn record_update(
        &mut self,
        entity: &str,
        id: &str,
        changes: &Map<String, Value>,
    ) -> Result<(), String> {
        let made = format!("record_update {entity} {id}");
        match self.take_matching(made, |c| {
            matches!(c, HostCall::RecordUpdate { entity: e, id: i, changes: ch, .. }
                if e == entity && i == id && ch == changes)
        }) {
            Some(HostCall::RecordUpdate { result, .. }) => result,
            _ => Err(DIVERGED.into()),
        }
    }

    fn record_create(
        &mut self,
        entity: &str,
        values: &Map<String, Value>,
    ) -> Result<String, String> {
        let made = format!("record_create {entity}");
        match self.take_matching(made, |c| {
            matches!(c, HostCall::RecordCreate { entity: e, values: v, .. }
                if e == entity && v == values)
        }) {
            Some(HostCall::RecordCreate { result, .. }) => result,
            _ => Err(DIVERGED.into()),
        }
    }

    fn log(&mut self, level: Level, message: &str) {
        let level = level_name(level);
        let made = format!("log {level}");
        self.take_matching(
            made,
            |c| matches!(c, HostCall::Log { level: l, message: m } if *l == level && m == message),
        );
    }

    fn secret(&mut self, name: &str) -> Option<String> {
        let made = format!("secret {name}");
        match self.take_matching(
            made,
            |c| matches!(c, HostCall::Secret { name: n, .. } if n == name),
        ) {
            Some(HostCall::Secret { given: true, .. }) => Some(REPLAYED_SECRET.to_owned()),
            _ => None,
        }
    }

    fn http_fetch(
        &mut self,
        method: &str,
        url: &str,
        _headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<Response, String> {
        let method = method.to_ascii_uppercase();
        let made = format!("http {method} {url}");
        match self.take_matching(made, |c| {
            matches!(c, HostCall::HttpFetch { method: m, url: u, body: b, .. }
                if *m == method && u == url && b.as_deref() == body)
        }) {
            Some(HostCall::HttpFetch { result, .. }) => result.map(|r| Response {
                status: r.status,
                body: r.body,
            }),
            _ => Err(DIVERGED.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FakeHost, Grants};
    use serde_json::json;

    fn host() -> FakeHost {
        let grants: Grants = serde_json::from_value(json!({
            "entities": { "deal": { "read": true, "write": true } },
            "secrets": ["erp_key"],
            "hosts": ["api.erp.example"]
        }))
        .unwrap();
        let mut h = FakeHost::with_grants(grants);
        h.insert("deal", "d1", json!({ "stage": "open", "amount": 10 }));
        h.secrets.insert("erp_key".into(), "k-12345".into());
        h.http.insert(
            "POST https://api.erp.example/orders".into(),
            Response {
                status: 201,
                body: "{\"order\":\"o-9\"}".into(),
            },
        );
        h
    }

    /// The extension's logic, written against the host API: read the deal,
    /// push it to the ERP with the key, store the order number.
    fn run(host: &mut dyn HostApi) -> Result<String, String> {
        let deal = host.record_get("deal", "d1")?.ok_or("no deal")?;
        let key = host.secret("erp_key").ok_or("no key")?;
        let body = format!(
            "{{\"deal\":\"d1\",\"key\":\"{key}\",\"amount\":{}}}",
            deal["amount"]
        );
        let answer = host.http_fetch("post", "https://api.erp.example/orders", &[], Some(&body))?;
        let order: Value = serde_json::from_str(&answer.body).map_err(|e| e.to_string())?;
        let mut changes = Map::new();
        changes.insert("erp_order".into(), order["order"].clone());
        host.record_update("deal", "d1", &changes)?;
        host.log(Level::Info, &format!("pushed with {key}"));
        Ok(order["order"].as_str().unwrap_or_default().to_owned())
    }

    #[test]
    fn record_replay_masks_secrets_and_reproduces_the_run() {
        let mut recorder = Recorder::new(host());
        assert_eq!(run(&mut recorder).as_deref(), Ok("o-9"));
        let (live, calls) = recorder.finish();
        assert_eq!(live.records["deal"]["d1"]["erp_order"], json!("o-9"));
        assert_eq!(calls.len(), 5);
        let stored = serde_json::to_string(&calls).unwrap();
        assert!(!stored.contains("k-12345"), "no secret value is recorded");
        assert!(stored.contains("pushed with ***"));

        // The replay reaches nothing and gives the same answer.
        let mut replay = Replayer::new(calls);
        assert_eq!(run(&mut replay).as_deref(), Ok("o-9"));
        assert_eq!(replay.finish(), Ok(()));
    }

    #[test]
    fn record_replay_reports_where_a_run_differs() {
        let mut recorder = Recorder::new(host());
        run(&mut recorder).unwrap();
        let (_, calls) = recorder.finish();

        // A changed extension reads another record first.
        let mut replay = Replayer::new(calls.clone());
        assert!(replay.record_get("deal", "d2").is_err());
        let divergences = replay.finish().unwrap_err();
        assert!(
            divergences[0].contains("the run made record_get deal d2"),
            "{divergences:?}"
        );
        assert!(
            divergences
                .iter()
                .any(|d| d.contains("the run stopped before"))
        );

        // A run that stops early leaves recorded calls unmade.
        let mut short = Replayer::new(calls);
        short.record_get("deal", "d1").unwrap();
        assert_eq!(short.finish().unwrap_err().len(), 4);
    }
}

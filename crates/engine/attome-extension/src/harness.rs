//! Y10-T6: one hook call, as the record write pipeline makes it and as an
//! author tests it. [`call_hook`] builds the input the extension sees (only
//! the attributes its grants let it read), calls its `on_record` export and
//! judges the answer against its grants; the server's hooks
//! (`attome_api::extension_hooks`) and the test route run the same
//! function, so a sample run behaves as the live one would, without saving
//! anything.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::grants::{Grants, HookPoint};
use crate::runtime::{CallCost, Limits, Runtime};

/// The export a hook calls.
pub const HOOK_EXPORT: &str = "on_record";

/// One write, as the extension is given it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HookInput {
    pub stage: HookPoint,
    pub entity: String,
    #[serde(default)]
    pub record_id: Option<String>,
    #[serde(default)]
    pub is_create: bool,
    pub values: Map<String, Value>,
    #[serde(default)]
    pub previous: Option<Map<String, Value>>,
    #[serde(default)]
    pub actor: Option<String>,
}

/// What a hook answered: `"continue"`, `{"change": {...}}`,
/// `{"reject": "message"}` or `{"reject": {"key": ..., "args": {...}}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAnswer {
    Continue,
    Change(Map<String, Value>),
    Reject(Rejection),
}

/// Y10-T2: why a hook refused a save.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Rejection {
    /// The message as the extension wrote it.
    Text(String),
    /// A key into the manifest's `messages`, its `{name}` placeholders
    /// filled from `args`, in every language the manifest writes it in.
    Keyed {
        key: String,
        #[serde(default)]
        args: Map<String, Value>,
    },
}

impl From<&str> for Rejection {
    fn from(message: &str) -> Self {
        Self::Text(message.to_owned())
    }
}

/// Calls `module`'s hook with `input` held to `grants`: the input carries
/// only readable attributes, and a change to an attribute the extension may
/// not write is an error. Answers the judged answer (or why there is none)
/// and the call's cost.
pub fn call_hook(
    rt: &Runtime,
    module: &wasmtime::Module,
    input: &HookInput,
    grants: &Grants,
    limits: &Limits,
) -> (Result<HookAnswer, String>, CallCost) {
    let mut seen = input.clone();
    seen.values = grants.visible(&input.entity, &input.values);
    seen.previous = input
        .previous
        .as_ref()
        .map(|p| grants.visible(&input.entity, p));
    let bytes = match serde_json::to_vec(&seen) {
        Ok(bytes) => bytes,
        Err(e) => return (Err(e.to_string()), CallCost::default()),
    };
    let (out, cost) = rt.call_json_measured(module, HOOK_EXPORT, &bytes, limits);
    let answer = out.map_err(|e| e.to_string()).and_then(|out| {
        serde_json::from_slice::<HookAnswer>(&out)
            .map_err(|e| format!("the answer is not continue, change or reject: {e}"))
    });
    let answer = answer.and_then(|answer| match answer {
        HookAnswer::Change(set) => {
            let keys: Vec<&str> = set.keys().map(String::as_str).collect();
            grants
                .may_write(&input.entity, &keys)
                .map_err(|denied| denied.to_string())?;
            Ok(HookAnswer::Change(set))
        }
        other => Ok(other),
    });
    (answer, cost)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A module answering `answer` (placed at 0) to every call.
    fn answering(answer: &str) -> String {
        let escaped = answer.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            r#"(module
                (memory (export "memory") 1)
                (data (i32.const 0) "{escaped}")
                (func (export "alloc") (param i32) (result i32) (i32.const 1024))
                (func (export "on_record") (param i32 i32) (result i64) (i64.const {len})))"#,
            len = answer.len()
        )
    }

    fn grants() -> Grants {
        serde_json::from_value(serde_json::json!({
            "entities": { "account": { "read": true, "write": true, "attributes": ["name"] } },
            "hooks": [{ "entity": "account", "stage": "before_save" }]
        }))
        .unwrap()
    }

    fn sample() -> HookInput {
        serde_json::from_value(serde_json::json!({
            "stage": "before_save",
            "entity": "account",
            "is_create": true,
            "values": { "name": "Acme", "internal_note": "hidden" }
        }))
        .unwrap()
    }

    #[test]
    fn harness_runs_a_hook_on_a_sample() {
        let rt = Runtime::shared().unwrap();
        let limits = Limits::default();
        let change = rt
            .compile(answering(r#"{"change":{"name":"ACME"}}"#))
            .unwrap();
        let (answer, cost) = call_hook(rt, &change, &sample(), &grants(), &limits);
        let mut set = Map::new();
        set.insert("name".into(), Value::from("ACME"));
        assert_eq!(answer, Ok(HookAnswer::Change(set)));
        assert!(cost.fuel_used > 0);

        let reject = rt.compile(answering(r#"{"reject":"no"}"#)).unwrap();
        assert_eq!(
            call_hook(rt, &reject, &sample(), &grants(), &limits).0,
            Ok(HookAnswer::Reject("no".into()))
        );
    }

    #[test]
    fn harness_holds_a_hook_to_its_grants() {
        let rt = Runtime::shared().unwrap();
        let limits = Limits::default();
        let sneaky = rt
            .compile(answering(r#"{"change":{"internal_note":"x"}}"#))
            .unwrap();
        let (answer, _) = call_hook(rt, &sneaky, &sample(), &grants(), &limits);
        assert_eq!(
            answer,
            Err("the extension may not use account.internal_note".into())
        );
        let garbage = rt.compile(answering(r#"{"maybe":1}"#)).unwrap();
        assert!(
            call_hook(rt, &garbage, &sample(), &grants(), &limits)
                .0
                .unwrap_err()
                .starts_with("the answer is not continue, change or reject")
        );
        let seen = grants().visible("account", &sample().values);
        assert!(seen.contains_key("name") && !seen.contains_key("internal_note"));
    }
}

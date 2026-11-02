//! M16-T2: the `integration.rpa` flow step. It runs a scripted step list in
//! the isolated browser service (M16-T1, `deploy/rpa-browser`) and keeps a
//! screenshot of each `screenshot` step in the deployment's file store.
//!
//! The step's configuration:
//!
//! ```json
//! { "system": "partner-portal",
//!   "allowed_hosts": ["portal.partner.example"],
//!   "timeout_ms": 60000,
//!   "steps": [
//!     { "kind": "goto", "url": "https://portal.partner.example/login" },
//!     { "kind": "fill", "selector": "#user", "value": "{{secret:username}}" },
//!     { "kind": "fill", "selector": "#password", "value": "{{secret:password}}" },
//!     { "kind": "click", "selector": "button[type=submit]" },
//!     { "kind": "fill", "selector": "#order", "value": "{{input:order_no}}" },
//!     { "kind": "screenshot" } ] }
//! ```
//!
//! - **Where it runs.** `system` names an active integration system: its
//!   `base_url` is the browser service's address, and its sealed credential
//!   (a JSON object) holds `rpa_token`, the service's token, and the secrets
//!   the steps refer to.
//! - **Secrets stay on the server.** `{{secret:<name>}}` is replaced from the
//!   credential just before the call; the definition, the run's data and the
//!   step's output never hold a secret. `{{input:<key>}}` takes a value the
//!   flow wired in.
//! - **Screenshots** are stored at `rpa/<run>/<node>/step-<n>.png` and the
//!   output names their keys instead of carrying the images.
//! - A run the service reports as failed blocks the flow with the service's
//!   reason. A replay is guarded by the workflow engine's fired marker, as
//!   for every module step.

use std::time::Duration;

use attome_core::EngineState;
use attome_core::workflow_step::{StepFuture, StepInvocation, StepOutcome, WorkflowStepHandler};
use attome_modules::{MODULE_INTEGRATION, ModuleId};
use attome_storage::object_store::{ObjectStoreExt, path::Path as ObjectPath};
use attome_types::AppError;
use base64::Engine;
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// The step's key.
pub const STEP_KEY: &str = "integration.rpa";
/// The most steps one node runs (the service's own limit).
pub const MAX_STEPS: usize = 50;
/// The longest one run may take, in milliseconds (the service's own limit).
pub const MAX_RUN_MS: u64 = 120_000;
/// The credential field holding the service's token.
pub const TOKEN_FIELD: &str = "rpa_token";

/// Each step kind and the fields it needs (the service's `STEP_KINDS`).
const STEP_KINDS: [(&str, &[&str]); 7] = [
    ("goto", &["url"]),
    ("click", &["selector"]),
    ("fill", &["selector", "value"]),
    ("press", &["selector", "key"]),
    ("wait_for", &["selector"]),
    ("text", &["selector"]),
    ("screenshot", &[]),
];

/// The `{{secret:..}}` and `{{input:..}}` references in `text`, as
/// `(kind, name)`. Pure.
pub fn references(text: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        if let Some((kind, name)) = after[..end].split_once(':') {
            out.push((kind.trim(), name.trim()));
        }
        rest = &after[end + 2..];
    }
    out
}

/// `text` with every reference replaced: a secret from `secrets`, an input
/// from `input`'s top-level value (text or number). A missing one is an
/// error naming it (never its value). Pure.
pub fn substitute(text: &str, secrets: &Value, input: &Value) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let reference = &after[..end];
        let value = match reference.split_once(':').map(|(k, n)| (k.trim(), n.trim())) {
            Some(("secret", name)) if name != TOKEN_FIELD => secrets
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("the credential has no secret {name}"))?,
            Some(("input", key)) => match input.get(key) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                _ => return Err(format!("the flow wired no value {key}")),
            },
            _ => {
                return Err(format!(
                    "{{{{{reference}}}}} is not a secret or input reference"
                ));
            }
        };
        out.push_str(&value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Checks a node's configuration. Pure.
pub fn check_config(config: &Value) -> Result<(), String> {
    let system = config
        .get("system")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if system.trim().is_empty() {
        return Err("system names the integration system of the browser service".into());
    }
    let hosts = config.get("allowed_hosts").and_then(Value::as_array);
    if !hosts.is_some_and(|h| {
        !h.is_empty() && h.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty()))
    }) {
        return Err("allowed_hosts names at least one host".into());
    }
    if let Some(t) = config.get("timeout_ms") {
        if !t
            .as_u64()
            .is_some_and(|t| (1_000..=MAX_RUN_MS).contains(&t))
        {
            return Err(format!("timeout_ms is 1000 to {MAX_RUN_MS}"));
        }
    }
    let steps = config
        .get("steps")
        .and_then(Value::as_array)
        .ok_or("steps is a list")?;
    if steps.is_empty() || steps.len() > MAX_STEPS {
        return Err(format!("steps is a list of 1 to {MAX_STEPS} steps"));
    }
    for (i, step) in steps.iter().enumerate() {
        let kind = step.get("kind").and_then(Value::as_str).unwrap_or_default();
        let Some((_, fields)) = STEP_KINDS.iter().find(|(k, _)| *k == kind) else {
            return Err(format!("step {}: kind is not a browser step", i + 1));
        };
        for field in *fields {
            let Some(text) = step
                .get(*field)
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
            else {
                return Err(format!("step {}: {kind} needs {field}", i + 1));
            };
            for (rk, name) in references(text) {
                if !matches!(rk, "secret" | "input") || name.is_empty() || name == TOKEN_FIELD {
                    return Err(format!("step {}: {field} has a bad reference", i + 1));
                }
            }
        }
    }
    Ok(())
}

/// The service request for `config`, references filled. Pure.
pub fn request_body(config: &Value, secrets: &Value, input: &Value) -> Result<Value, String> {
    let mut steps = Vec::new();
    for step in config
        .get("steps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let mut filled = Map::new();
        for (key, value) in step.as_object().into_iter().flatten() {
            let value = match value.as_str() {
                Some(text) if key != "kind" => Value::String(substitute(text, secrets, input)?),
                _ => value.clone(),
            };
            filled.insert(key.clone(), value);
        }
        steps.push(Value::Object(filled));
    }
    Ok(json!({
        "steps": steps,
        "allowed_hosts": config.get("allowed_hosts").cloned().unwrap_or(Value::Null),
        "timeout_ms": config.get("timeout_ms").and_then(Value::as_u64).unwrap_or(30_000),
    }))
}

/// Calls the browser service at `base_url` with `body`; its answer.
pub async fn call_service(
    base_url: &str,
    token: &str,
    body: &Value,
    timeout: Duration,
) -> Result<Value, String> {
    let purpose = attome_outbound::http::Purpose::public("rpa-browser")
        .with_private_urls(std::iter::once(base_url))
        .no_redirects();
    let http = attome_outbound::http::client(purpose, |b| b.timeout(timeout))
        .map_err(|e| format!("the browser service address: {e}"))?;
    let answer = http
        .post(format!("{}/run", base_url.trim_end_matches('/')))
        .header("X-Rpa-Token", token)
        .json(body)
        .send()
        .await
        .map_err(|_| "the browser service did not answer".to_owned())?;
    let status = answer.status();
    let value: Value = answer
        .json()
        .await
        .map_err(|_| format!("the browser service answered {status} without JSON"))?;
    if !status.is_success() {
        let reason = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("refused");
        return Err(format!("the browser service answered {status}: {reason}"));
    }
    Ok(value)
}

/// The step results with each screenshot taken out: the results naming a
/// `screenshot` index instead of the image, and the images in order. Pure.
pub fn split_screenshots(results: &[Value]) -> (Vec<Value>, Vec<(usize, String)>) {
    let mut images = Vec::new();
    let out = results
        .iter()
        .map(|r| {
            let mut r = r.as_object().cloned().unwrap_or_default();
            if let Some(png) = r
                .remove("png_base64")
                .and_then(|v| v.as_str().map(str::to_owned))
            {
                let step = r.get("step").and_then(Value::as_u64).unwrap_or(0) as usize;
                images.push((step, png));
            }
            Value::Object(r)
        })
        .collect();
    (out, images)
}

/// M16-T2: the RPA flow step.
#[derive(Debug, Clone, Copy, Default)]
pub struct RpaStep;

impl WorkflowStepHandler for RpaStep {
    fn key(&self) -> &'static str {
        STEP_KEY
    }

    fn module_id(&self) -> ModuleId {
        MODULE_INTEGRATION
    }

    fn validate_config(&self, config: &Value) -> Result<(), String> {
        check_config(config)
    }

    fn config_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["system", "allowed_hosts", "steps"],
            "properties": {
                "system": { "type": "string", "title": "Browser service (integration system)" },
                "allowed_hosts": { "type": "array", "items": { "type": "string" }, "title": "Allowed hosts" },
                "timeout_ms": { "type": "integer", "minimum": 1000, "maximum": MAX_RUN_MS, "title": "Time limit (ms)" },
                "steps": { "type": "array", "title": "Steps", "items": { "type": "object" } }
            }
        })
    }

    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            check_config(&inv.config).map_err(AppError::Validation)?;
            if inv.simulate {
                return Ok(StepOutcome::Done(json!({
                    "would": "run browser steps",
                    "steps": inv.config["steps"].as_array().map_or(0, Vec::len),
                    "allowed_hosts": inv.config["allowed_hosts"],
                })));
            }
            let name = inv.config["system"].as_str().unwrap_or_default();
            let id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM integration_system WHERE name = $1 AND status = 'active' \
                   AND (is_active IS NULL OR is_active = true)",
            )
            .bind(name)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let system = match id {
                Some(id) => crate::system::load(&state.base.db, id).await?,
                None => None,
            };
            let Some(system) = system else {
                return Ok(StepOutcome::Blocked {
                    reason: format!("no active integration system is named {name}"),
                    continue_after: false,
                });
            };
            let secrets = crate::connector::adapters::social::secrets(state, &system).await?;
            let token = secrets
                .get(TOKEN_FIELD)
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .ok_or_else(|| {
                    AppError::Validation(format!("{name}: the credential has no {TOKEN_FIELD}"))
                })?
                .to_owned();
            let body = match request_body(&inv.config, &secrets, &inv.input) {
                Ok(body) => body,
                Err(reason) => {
                    return Ok(StepOutcome::Blocked {
                        reason,
                        continue_after: false,
                    });
                }
            };
            let timeout_ms = body["timeout_ms"].as_u64().unwrap_or(30_000);
            let answer = match call_service(
                &system.base_url,
                &token,
                &body,
                Duration::from_millis(timeout_ms + 15_000),
            )
            .await
            {
                Ok(answer) => answer,
                Err(reason) => {
                    return Ok(StepOutcome::Blocked {
                        reason,
                        continue_after: false,
                    });
                }
            };
            let results = answer["results"].as_array().cloned().unwrap_or_default();
            let (results, images) = split_screenshots(&results);
            let mut screenshots = Vec::new();
            for (step, png) in images {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(png.as_bytes())
                    .map_err(|_| AppError::internal("the browser service sent a bad screenshot"))?;
                let key = format!("rpa/{}/{}/step-{step}.png", inv.instance_id, inv.node_id);
                let path = ObjectPath::parse(&key).map_err(AppError::internal)?;
                state
                    .base
                    .storage
                    .store()
                    .put(&path, bytes.into())
                    .await
                    .map_err(AppError::internal)?;
                screenshots.push(json!({ "step": step, "key": key }));
            }
            if answer["ok"].as_bool() != Some(true) {
                let reason = answer["error"]
                    .as_str()
                    .unwrap_or("the browser run failed")
                    .to_owned();
                tracing::warn!(instance = %inv.instance_id, node = %inv.node_id, %reason, "rpa step failed");
                return Ok(StepOutcome::Blocked {
                    reason,
                    continue_after: false,
                });
            }
            Ok(StepOutcome::Done(
                json!({ "results": results, "screenshots": screenshots }),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Value {
        json!({
            "system": "partner-portal",
            "allowed_hosts": ["portal.partner.example"],
            "steps": [
                { "kind": "goto", "url": "https://portal.partner.example/login" },
                { "kind": "fill", "selector": "#user", "value": "{{secret:username}}" },
                { "kind": "fill", "selector": "#order", "value": "Order {{input:order_no}}" },
                { "kind": "screenshot" }
            ]
        })
    }

    #[test]
    fn rpa_config_is_checked() {
        assert_eq!(RpaStep.validate_config(&config()), Ok(()));
        let mut bad = config();
        bad["steps"][1]["value"] = json!("{{secret:rpa_token}}");
        assert!(
            RpaStep.validate_config(&bad).is_err(),
            "the service token is not a step value"
        );
        let mut bad = config();
        bad["steps"][0] = json!({ "kind": "eval", "code": "1" });
        assert!(RpaStep.validate_config(&bad).is_err());
        let mut bad = config();
        bad["allowed_hosts"] = json!([]);
        assert!(RpaStep.validate_config(&bad).is_err());
    }

    #[test]
    fn rpa_secrets_are_filled_on_the_server_only() {
        let secrets = json!({ "username": "svc-user", "rpa_token": "t" });
        let body = request_body(&config(), &secrets, &json!({ "order_no": 42 })).unwrap();
        assert_eq!(body["steps"][1]["value"], "svc-user");
        assert_eq!(body["steps"][2]["value"], "Order 42");
        // The definition keeps the reference, never the value.
        assert_eq!(config()["steps"][1]["value"], "{{secret:username}}");
        let missing = request_body(&config(), &json!({}), &json!({ "order_no": 1 })).unwrap_err();
        assert!(missing.contains("username") && !missing.contains("svc-user"));
        assert!(substitute("{{secret:rpa_token}}", &secrets, &json!({})).is_err());
    }

    #[test]
    fn rpa_screenshots_leave_the_output() {
        let results = vec![
            json!({ "step": 1, "kind": "goto", "url": "https://x" }),
            json!({ "step": 4, "kind": "screenshot", "png_base64": "iVBORw0KGgo=" }),
        ];
        let (out, images) = split_screenshots(&results);
        assert_eq!(images, vec![(4, "iVBORw0KGgo=".to_owned())]);
        assert!(out[1].get("png_base64").is_none());
    }

    /// A fake browser service on a loopback port, answering one request.
    async fn fake_service(answer: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 65_536];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                answer.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn rpa_calls_the_service() {
        let url = fake_service(r#"{"ok":true,"results":[{"step":1,"kind":"goto","url":"https://portal.partner.example/"}]}"#).await;
        let body = request_body(
            &config(),
            &json!({ "username": "u" }),
            &json!({ "order_no": "7" }),
        )
        .unwrap();
        let answer = call_service(&url, "token-token-token", &body, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(answer["ok"], true);
        assert_eq!(answer["results"][0]["kind"], "goto");
    }
}

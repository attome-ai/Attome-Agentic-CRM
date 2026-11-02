//! `rpa.draft_steps` (roadmap M16-T3, step 2): drafts the step list of an
//! `integration.rpa` flow node from a description, for a person to review in
//! the flow editor. Saves nothing.
//!
//! The draft is checked with the step's own configuration check
//! (`attome_integration::rpa::check_config`: kinds and their fields, and
//! placeholders only `{{secret:<name>}}` and `{{input:<key>}}`), and every
//! `goto` must be on an allowed host, as the browser service will insist. The model is told to put every credential behind a
//! secret placeholder; a draft that fails the check is returned with the
//! reason, so the person sees why before using it.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_INTEGRATION;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const RPA_DRAFT_STEPS: &str = "rpa.draft_steps";
/// Bumped whenever the prompt changes in a way that could move results.
pub const DRAFT_PROMPT_VERSION: &str = "rpa.draft/v1";

const SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "description": { "type": "string", "description": "What the browser should do, in the person's words." },
    "allowed_hosts": { "type": "array", "items": { "type": "string" }, "description": "The hosts the steps may visit." }
  },
  "required": ["description", "allowed_hosts"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            RPA_DRAFT_STEPS,
            "Draft the steps of a browser automation (an integration.rpa flow step) from a \
             description: go to a page, click, fill, press, wait, read text, take a screenshot. \
             Credentials are secret placeholders. Saves nothing; a person reviews the steps.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_INTEGRATION,
            &[],
        )
        .input_schema(SCHEMA),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(DraftSteps)]
}

/// The first `goto` whose address is not https or http on an allowed host
/// (exact, or a subdomain of a `.`-prefixed entry), as the browser service
/// judges it. Pure.
pub fn off_host_goto(steps: &[Value], allowed: &[String]) -> Option<String> {
    steps
        .iter()
        .filter(|s| s.get("kind").and_then(Value::as_str) == Some("goto"))
        .filter_map(|s| s.get("url").and_then(Value::as_str))
        .find(|url| !host_allowed(url, allowed))
        .map(|url| format!("{url} is not on an allowed host"))
}

fn host_allowed(url: &str, allowed: &[String]) -> bool {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return false;
    }
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(h, _)| h)
        .to_ascii_lowercase();
    allowed.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        match entry.strip_prefix('.') {
            Some(domain) => host == domain || host.ends_with(&entry),
            None => host == entry,
        }
    })
}

/// The steps in the model's answer: `{"steps": [...]}` or a bare list,
/// with or without a code fence. Pure.
pub fn parse_steps(text: &str) -> Result<Vec<Value>, String> {
    let value: Value = serde_json::from_str(crate::actions::metric_draft::strip_fence(text))
        .map_err(|e| format!("the draft is not JSON: {e}"))?;
    let steps = match value {
        Value::Array(steps) => steps,
        Value::Object(mut o) => match o.remove("steps") {
            Some(Value::Array(steps)) => steps,
            _ => return Err("the draft has no steps list".into()),
        },
        _ => return Err("the draft has no steps list".into()),
    };
    Ok(steps)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftArgs {
    description: String,
    allowed_hosts: Vec<String>,
}

pub(crate) struct DraftSteps;

impl Action for DraftSteps {
    fn id(&self) -> ActionId {
        ActionId(RPA_DRAFT_STEPS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: DraftArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {RPA_DRAFT_STEPS} arguments: {e}"))
            })?;
            if args.description.trim().is_empty() || args.allowed_hosts.is_empty() {
                return Err(AppError::Validation(
                    "description and at least one allowed host are needed".into(),
                ));
            }
            let system = "You draft browser automation steps. Answer with one JSON object and \
                nothing else: {\"steps\": [...]}, each step one of {\"kind\": \"goto\", \"url\"}, \
                {\"kind\": \"click\", \"selector\"}, {\"kind\": \"fill\", \"selector\", \"value\"}, \
                {\"kind\": \"press\", \"selector\", \"key\"}, {\"kind\": \"wait_for\", \
                \"selector\"}, {\"kind\": \"text\", \"selector\"} or {\"kind\": \"screenshot\"}. \
                A url must be https on one of the allowed hosts. Selectors are CSS, or Playwright \
                text selectors such as button:has-text(\"Sign in\"); wait for a page's element \
                before using it. Never write a user name, password, token or other credential: \
                write {{secret:<name>}} instead (for example {{secret:username}} and \
                {{secret:password}}). A value the flow passes in is {{input:<key>}}. At most 50 \
                steps."
                .to_owned();
            let facts = json!({
                "description": args.description,
                "allowed_hosts": args.allowed_hosts,
            })
            .to_string();
            let (text, provenance) = crate::actions::metric_draft::generate(
                state,
                ctx,
                RPA_DRAFT_STEPS,
                DRAFT_PROMPT_VERSION,
                system,
                facts,
            )
            .await?;
            let steps = parse_steps(&text).map_err(AppError::Validation)?;
            let issue = attome_integration::rpa::check_config(&json!({
                "system": "draft",
                "allowed_hosts": args.allowed_hosts,
                "steps": steps,
            }))
            .err()
            .or_else(|| off_host_goto(&steps, &args.allowed_hosts));
            Ok(ActionResult {
                value: json!({
                    "steps": steps,
                    "valid": issue.is_none(),
                    "issue": issue,
                    "saved": false,
                }),
                provenance,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpa_draft_reads_the_model_answer() {
        let fenced =
            "```json\n{\"steps\": [{\"kind\": \"goto\", \"url\": \"https://a.example\"}]}\n```";
        assert_eq!(parse_steps(fenced).unwrap().len(), 1);
        assert_eq!(
            parse_steps("[{\"kind\": \"screenshot\"}]").unwrap().len(),
            1
        );
        assert!(parse_steps("{\"plan\": []}").is_err());
        assert!(parse_steps("click the button").is_err());

        // A goto stays on the allowed hosts.
        let hosts = vec![
            "portal.example.com".to_owned(),
            ".partner.example".to_owned(),
        ];
        let steps = |url: &str| vec![json!({ "kind": "goto", "url": url })];
        assert_eq!(
            off_host_goto(&steps("https://portal.example.com/login"), &hosts),
            None
        );
        assert_eq!(
            off_host_goto(&steps("https://a.partner.example"), &hosts),
            None
        );
        assert!(off_host_goto(&steps("https://elsewhere.example"), &hosts).is_some());
        assert!(off_host_goto(&steps("https://portal.example.com@evil.example"), &hosts).is_some());
        assert!(off_host_goto(&steps("file:///etc/passwd"), &hosts).is_some());

        // The step's own check refuses a placeholder that is not a secret
        // or an input.
        let bad = attome_integration::rpa::check_config(&json!({
            "system": "draft",
            "allowed_hosts": ["portal.example.com"],
            "steps": [{ "kind": "fill", "selector": "#p", "value": "{{env:PASSWORD}}" }],
        }));
        assert!(bad.is_err());
    }
}

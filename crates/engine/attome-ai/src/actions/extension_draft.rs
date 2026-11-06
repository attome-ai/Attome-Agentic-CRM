//! `extension.hook.draft` (roadmap AD9-T1): a building agent writes a record
//! hook extension and its tests from a description. One model call drafts
//! the `decide` function, its unit tests, the attributes it reads and
//! writes, and its refusal messages; [`crate::builder::code`] turns the
//! answer into the Rust crate `attome new extension --kind hook` makes,
//! asking only for the grants the code uses and refusing file, network,
//! process and `unsafe` code.
//!
//! Nothing is saved or built (V2-D1917): the answer carries the project's
//! files for the person's Develop workspace, where `attome dev` runs the
//! tests, the dependency check, the WebAssembly build and the upload as a
//! draft version; publishing stays the owner's (V2-D27).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::builder::code::{DraftedHook, STAGES, hook_project};
use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const EXTENSION_DRAFT: &str = "extension.hook.draft";
/// Bumped whenever the prompt changes in a way that could move results.
pub const EXTENSION_PROMPT_VERSION: &str = "extension.hook.draft/v1";

const SCHEMA: &str = r#"{
  "type": "object",
  "required": ["entity", "description"],
  "properties": {
    "entity": { "type": "string", "description": "The entity's logical name." },
    "description": { "type": "string", "description": "What the hook should do, in the person's words." },
    "stage": { "type": "string", "enum": ["before_validation", "before_save", "after_save", "after_commit"] }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            EXTENSION_DRAFT,
            "Write a record hook extension and its unit tests from a description: the Rust \
             project with its manifest asking only for the grants the code uses. Saves and \
             builds nothing; `attome dev` tests, builds and uploads it as a draft version.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SCHEMA),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ExtensionDraft)]
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    entity: String,
    description: String,
    #[serde(default)]
    stage: Option<String>,
}

#[derive(Debug)]
pub struct ExtensionDraft;

impl Action for ExtensionDraft {
    fn id(&self) -> ActionId {
        ActionId(EXTENSION_DRAFT)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            // Extensions are uploaded and published by administrators only.
            if !ctx.security.is_admin {
                return Err(AppError::Forbidden);
            }
            let args: Args = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid {EXTENSION_DRAFT} arguments: {e}"))
            })?;
            if args.description.trim().is_empty() {
                return Err(AppError::Validation(
                    "description: say what the hook should do".into(),
                ));
            }
            if let Some(stage) = &args.stage
                && !STAGES.contains(&stage.as_str())
            {
                return Err(AppError::Validation(format!(
                    "stage is one of {}",
                    STAGES.join(", ")
                )));
            }
            let entity = args.entity.trim().to_owned();
            let fields: Vec<(String, i32)> = sqlx::query_as(
                "SELECT a.logicalname::text, a.\"type\" FROM attribute_info a \
                   JOIN entity_info e ON e.id = a.entity_ref \
                  WHERE e.logicalname = $1 AND e.is_active IS NOT FALSE \
                    AND a.is_active IS NOT FALSE \
                  ORDER BY a.logicalname LIMIT 400",
            )
            .bind(&entity)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            if fields.is_empty() {
                return Err(AppError::NotFound);
            }
            let attributes: Vec<String> = fields.iter().map(|(n, _)| n.clone()).collect();

            let system = "You write an Attome record hook in Rust. Answer with one JSON object \
                and nothing else: {\"name\": snake_case extension name, \"stage\": one of \
                before_validation, before_save, after_save, after_commit, \"reads\": [attribute \
                names], \"writes\": [attribute names it changes, before stages only], \"decide\": \
                the Rust source of `pub fn decide(input: &Value) -> Value`, \"tests\": Rust \
                `#[test]` functions calling decide, \"messages\": {key: {\"en\", \"ar\"}}}. \
                `serde_json::{Value, json}` are in scope; no other crate. The input is \
                {\"stage\", \"entity\", \"record_id\", \"is_create\", \"values\", \"previous\", \
                \"actor\"}; decide answers \"continue\", {\"change\": {attribute: value}} or \
                {\"reject\": {\"key\", \"args\"}} with a key from messages. Use only the given \
                attribute names. No unsafe, files, network, processes, threads or environment. \
                Write at least three tests, including the refusal and the pass-through."
                .to_owned();
            let facts = json!({
                "entity": entity,
                "description": args.description,
                "stage": args.stage,
                "attributes": fields.iter().map(|(name, kind)| json!({
                    "name": name,
                    "type": attome_core::FieldType::from_int(*kind).map_or("text", |t| t.as_str()),
                })).collect::<Vec<_>>(),
            })
            .to_string();
            let (text, provenance) = crate::actions::metric_draft::generate(
                state,
                ctx,
                EXTENSION_DRAFT,
                EXTENSION_PROMPT_VERSION,
                system,
                facts,
            )
            .await?;
            let value = answer_from_text(&entity, &attributes, &text, args.stage)?;
            Ok(ActionResult { value, provenance })
        })
    }
}

/// The action's answer for the model's `text`: the project's files and
/// manifest, or the problems that keep the draft from being one. `stage`,
/// when the person named one, wins over the model's. Pure.
pub fn answer_from_text(
    entity: &str,
    attributes: &[String],
    text: &str,
    stage: Option<String>,
) -> Result<Value, AppError> {
    let mut drafted: DraftedHook =
        serde_json::from_str(crate::actions::metric_draft::strip_fence(text))
            .map_err(|e| AppError::Validation(format!("the drafted hook is not a hook: {e}")))?;
    if let Some(stage) = stage {
        drafted.stage = stage;
    }
    Ok(match hook_project(entity, attributes, &drafted) {
        Ok(project) => json!({
            "name": drafted.name.trim(),
            "files": project.files.iter()
                .map(|(path, contents)| json!({ "path": path, "contents": contents }))
                .collect::<Vec<_>>(),
            "manifest": project.manifest,
            "left_out": project.left_out,
            "next": [
                "Review src/lib.rs and the grants in manifest.json.",
                "cargo test",
                "attome dev . --once --target <deployment>",
            ],
            "saved": false,
        }),
        // The draft is answered with why it cannot be used, so the agent
        // can try again or the person can see what went wrong.
        Err(problems) => json!({
            "name": drafted.name.trim(),
            "problems": problems,
            "saved": false,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECIDE: &str = r#"pub fn decide(input: &Value) -> Value {
    match input["values"]["vat_number"].as_str() {
        Some(v) if v.len() != 15 => json!({"reject": {"key": "vat_length", "args": {}}}),
        _ => json!("continue"),
    }
}
"#;

    const TESTS: &str = r#"    #[test]
    fn a_short_vat_number_is_refused() {
        let input = json!({"values": {"vat_number": "123"}});
        assert_eq!(decide(&input)["reject"]["key"], "vat_length");
    }
"#;

    fn hook_answer() -> Value {
        json!({
            "name": "account_vat_check",
            "stage": "before_save",
            "reads": ["vat_number"],
            "writes": [],
            "decide": DECIDE,
            "tests": TESTS,
            "messages": { "vat_length": { "en": "A VAT number has 15 digits.", "ar": "الرقم الضريبي من 15 رقمًا." } }
        })
    }

    #[tokio::test]
    async fn a_described_hook_is_drafted_with_the_fake_model() {
        use attome_inference::testing::{FakeModelServer, json as reply};
        use attome_inference::{ChatMessage, GenerationClient, GenerationRequest};
        let body = json!({
            "choices": [{"message": {"content": format!("```json\n{}\n```", hook_answer())}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 120}
        });
        let server = FakeModelServer::start(vec![reply(&body.to_string())]).await;
        let section = attome_config::InferenceSection {
            generation: attome_config::InferenceEndpoint {
                base_url: server.base_url(),
                model: "fake".into(),
                api_key: None,
                request_timeout_secs: 5,
            },
            ..attome_config::InferenceSection::default()
        };
        let client = GenerationClient::new(&section).unwrap();
        let generated = client
            .generate(GenerationRequest::new(vec![ChatMessage::user(
                "Refuse an account whose VAT number is not 15 digits",
            )]))
            .await
            .unwrap();
        let attributes = vec!["name".to_owned(), "vat_number".to_owned()];
        let answer = answer_from_text("account", &attributes, &generated.text, None).unwrap();
        assert_eq!(answer["name"], "account_vat_check");
        assert_eq!(answer["saved"], false);
        assert_eq!(
            answer["manifest"]["entities"]["account"]["attributes"],
            json!(["vat_number"])
        );
        assert!(
            answer["manifest"]["entities"]["account"]
                .get("write")
                .is_none()
        );
        let files = answer["files"].as_array().unwrap();
        let lib = files.iter().find(|f| f["path"] == "src/lib.rs").unwrap();
        assert!(
            lib["contents"]
                .as_str()
                .unwrap()
                .contains("fn a_short_vat_number_is_refused")
        );
        assert_eq!(server.request_count(), 1);
    }

    #[test]
    fn a_draft_that_reaches_for_the_network_comes_back_with_problems() {
        let mut answer = hook_answer();
        answer["decide"] = json!(
            r#"pub fn decide(input: &Value) -> Value { let _ = std::net::TcpStream::connect("x:1"); json!("continue") }"#
        );
        let out = answer_from_text(
            "account",
            &["vat_number".to_owned()],
            &answer.to_string(),
            None,
        )
        .unwrap();
        assert!(out.get("files").is_none());
        assert!(out["problems"].to_string().contains("std::net"));
    }
}

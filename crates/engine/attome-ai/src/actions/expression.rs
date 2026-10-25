//! Z11-T12: an agent writing a rule, view or formula expression checks it
//! before proposing it. `expression.validate` runs the check
//! `POST /api/v1/admin/expressions/validate` runs
//! (`attome_records::expression_check`): the result type or each error with
//! its byte span, whether it runs in the database, and for a sample record
//! the caller can read, the value with its trace. `expression.spec` lists the
//! language's built-in functions and grammar notes. Both read only.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_rules::LanguageVersion;
use attome_rules::catalog::{GRAMMAR_NOTES, catalog};
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const EXPRESSION_VALIDATE: &str = "expression.validate";
pub const EXPRESSION_SPEC: &str = "expression.spec";

const VALIDATE_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "expression": { "type": "string", "description": "The expression text." },
    "entity": { "type": "string", "description": "Entity logical name; its fields are the expression's fields." },
    "language_version": { "type": "string", "enum": ["v1", "v2"], "description": "Absent means the latest." },
    "sample_record_id": { "type": "string", "format": "uuid", "description": "A record to evaluate the expression on." }
  },
  "required": ["expression", "entity"],
  "additionalProperties": false
}"#;

const SPEC_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "language_version": { "type": "string", "enum": ["v1", "v2"], "description": "Absent means the latest." }
  },
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            EXPRESSION_VALIDATE,
            "Check a rule-language expression against an entity before using it: returns ok, \
             its result type, or each error with its code, message and byte span; whether it \
             runs in the database; and, given a sample record you can read, its value and \
             evaluation trace. Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(VALIDATE_INPUT),
        ActionDescriptor::new(
            EXPRESSION_SPEC,
            "List the rule language's built-in functions (parameters, result type, English and \
             Arabic description, an example) and notes on its grammar, for a language version.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(SPEC_INPUT),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ExpressionValidate), Box::new(ExpressionSpec)]
}

fn version(args: &Value) -> Result<LanguageVersion, AppError> {
    match args["language_version"].as_str() {
        None => Ok(LanguageVersion::LATEST),
        Some(v) => LanguageVersion::parse(v)
            .ok_or_else(|| AppError::Validation(format!("unknown language version '{v}'"))),
    }
}

struct ExpressionValidate;

impl Action for ExpressionValidate {
    fn id(&self) -> ActionId {
        ActionId(EXPRESSION_VALIDATE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let expression = args["expression"]
                .as_str()
                .ok_or_else(|| AppError::Validation("expression is required".into()))?;
            let entity = args["entity"]
                .as_str()
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .ok_or_else(|| AppError::Validation("entity is required".into()))?;
            let sample =
                match args["sample_record_id"].as_str() {
                    None => None,
                    Some(id) => Some(Uuid::parse_str(id).map_err(|_| {
                        AppError::Validation("sample_record_id must be a UUID".into())
                    })?),
                };
            ctx.security.require(entity, "read")?;
            let check = attome_records::expression_check::check_expression(
                state,
                &ctx.security,
                expression,
                entity,
                version(args)?,
                sample,
            )
            .await?;
            Ok(ActionResult::plain(
                serde_json::to_value(check).map_err(AppError::internal)?,
            ))
        })
    }
}

struct ExpressionSpec;

impl Action for ExpressionSpec {
    fn id(&self) -> ActionId {
        ActionId(EXPRESSION_SPEC)
    }

    fn execute<'a>(
        &'a self,
        _state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let version = version(args)?;
            let functions: Vec<Value> = catalog(version)
                .iter()
                .map(|f| {
                    json!({
                        "name": f.name,
                        "params": f.params.iter().map(|(n, t)| json!({ "name": n, "type": t })).collect::<Vec<_>>(),
                        "returns": f.returns,
                        "description_en": f.description_en,
                        "description_ar": f.description_ar,
                        "example": f.example,
                        "since": f.since.as_str(),
                    })
                })
                .collect();
            Ok(ActionResult::plain(json!({
                "version": version.as_str(),
                "functions": functions,
                "grammar": GRAMMAR_NOTES,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expression_tools_are_read_tier() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        }
        let ids: Vec<&str> = crate::actions::all().iter().map(|a| a.id.0).collect();
        assert!(ids.contains(&EXPRESSION_VALIDATE) && ids.contains(&EXPRESSION_SPEC));
    }

    #[test]
    fn unknown_version_is_refused() {
        assert!(version(&json!({ "language_version": "v7" })).is_err());
        assert_eq!(version(&json!({})).unwrap(), LanguageVersion::LATEST);
    }
}

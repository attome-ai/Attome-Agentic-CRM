//! The rule function kind (roadmap Z11-T11): a function builders write once
//! and call from any V2 expression.
//!
//! ```json
//! { "name": "net_price", "params": [{ "name": "price", "type": "number" }],
//!   "returns": "number", "body": "price * 0.85" }
//! ```
//!
//! The shape check parses the body. Cooking builds the whole library at
//! once ([`attome_rules::FunctionLibrary::build`]), so a call to a function
//! that is not defined, a type mismatch, or recursion through other
//! functions refuses the publish.

use attome_rules::{Budgets, FunctionLibrary, Type, UserFunction};
use attome_types::AppError;
use serde_json::{Value, json};

use crate::identity::KindName;
use crate::kind::{Artefact, CookInput, Issue, Kind, Reference, ValidationCtx};

/// The kind's name.
pub const RULE_FUNCTION: KindName = KindName("rule_function");

/// The types a parameter or result may have, by name.
pub const TYPE_NAMES: [&str; 4] = ["bool", "number", "text", "date"];

/// The rule function kind.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleFunctionKind;

/// The rules type `name` names. Pure.
pub fn rule_type(name: &str) -> Option<Type> {
    match name {
        "bool" => Some(Type::Bool),
        "number" => Some(Type::Number),
        "text" => Some(Type::Text),
        "date" => Some(Type::Date),
        _ => None,
    }
}

/// The function a document describes, or the problems with it. Pure.
pub fn user_function(doc: &Value) -> Result<UserFunction, Vec<Issue>> {
    let mut issues = Vec::new();
    let name = doc["name"].as_str().unwrap_or_default().to_owned();
    if name.is_empty() {
        issues.push(Issue::new("/name", "required", "a function has a name"));
    }
    let returns = doc["returns"].as_str().and_then(rule_type);
    if returns.is_none() {
        issues.push(Issue::new(
            "/returns",
            "unknown_value",
            format!("returns is one of {}", TYPE_NAMES.join(", ")),
        ));
    }
    let mut params = Vec::new();
    match doc["params"].as_array() {
        Some(list) => {
            for (i, param) in list.iter().enumerate() {
                let pname = param["name"].as_str().unwrap_or_default();
                match param["type"].as_str().and_then(rule_type) {
                    Some(ty) if !pname.is_empty() => params.push((pname.to_owned(), ty)),
                    _ => issues.push(Issue::new(
                        format!("/params/{i}"),
                        "invalid",
                        format!(
                            "a parameter has a name and a type ({})",
                            TYPE_NAMES.join(", ")
                        ),
                    )),
                }
            }
        }
        None if doc["params"].is_null() => {}
        None => issues.push(Issue::new("/params", "not_a_list", "params is a list")),
    }
    let body = doc["body"].as_str().unwrap_or_default().to_owned();
    if body.trim().is_empty() {
        issues.push(Issue::new("/body", "required", "a function has a body"));
    } else if let Err(e) = attome_rules::parse(&body) {
        issues.push(Issue::new("/body", "parse_error", e.to_string()));
    }
    if issues.is_empty() {
        Ok(UserFunction {
            name,
            params,
            returns: returns.unwrap_or(Type::Null),
            body,
        })
    } else {
        Err(issues)
    }
}

impl Kind for RuleFunctionKind {
    fn name(&self) -> KindName {
        RULE_FUNCTION
    }

    fn schema_version(&self) -> u32 {
        1
    }

    fn json_schema(&self) -> Value {
        json!({
            "type": "object",
            "required": ["name", "returns", "body"],
            "additionalProperties": false,
            "properties": {
                "name": { "type": "string", "pattern": "^[a-z][a-z0-9_]{0,62}$" },
                "params": {
                    "type": "array",
                    "maxItems": attome_rules::functions::MAX_PARAMS,
                    "items": {
                        "type": "object",
                        "required": ["name", "type"],
                        "properties": {
                            "name": { "type": "string" },
                            "type": { "enum": TYPE_NAMES }
                        }
                    }
                },
                "returns": { "enum": TYPE_NAMES },
                "body": { "type": "string" }
            }
        })
    }

    fn validate_shape(&self, doc: &Value) -> Result<(), Vec<Issue>> {
        if !doc.is_object() {
            return Err(vec![Issue::new(
                "",
                "not_an_object",
                "a rule function is a JSON object",
            )]);
        }
        user_function(doc).map(|_| ())
    }

    fn references(&self, _doc: &Value) -> Vec<Reference> {
        Vec::new()
    }

    fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
        Vec::new()
    }

    fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
        let functions = docs
            .iter()
            .map(|input| {
                user_function(&input.doc).map_err(|issues| {
                    AppError::Validation(format!(
                        "rule function {}: {}",
                        input.name,
                        issues
                            .iter()
                            .map(|i| i.message.clone())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The library as a whole: undefined calls, types and recursion.
        FunctionLibrary::build(functions, Budgets::default())
            .map_err(|e| AppError::Validation(format!("rule functions: {e}")))?;
        docs.iter()
            .map(|input| {
                let text =
                    crate::canonical::canonicalize(&input.doc).map_err(AppError::Validation)?;
                Ok(Artefact {
                    kind: RULE_FUNCTION,
                    source: Some(input.id),
                    payload: text.into_bytes(),
                })
            })
            .collect()
    }

    fn agent_tool_description(&self) -> &'static str {
        "Define a function (name, typed parameters, result type and a V2 expression body) that any rule, flow or formula expression can call."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_function_shape_names_its_problems() {
        assert!(
            RuleFunctionKind
                .validate_shape(&json!({
                    "name": "net", "params": [{ "name": "p", "type": "number" }],
                    "returns": "number", "body": "p * 0.85"
                }))
                .is_ok()
        );
        let issues = RuleFunctionKind
            .validate_shape(&json!({
                "name": "", "params": [{ "name": "p", "type": "money" }],
                "returns": "blob", "body": "p *"
            }))
            .unwrap_err();
        let paths: Vec<&str> = issues.iter().map(|i| i.path.as_str()).collect();
        for expected in ["/name", "/returns", "/params/0", "/body"] {
            assert!(paths.contains(&expected), "{expected} in {paths:?}");
        }
    }
}

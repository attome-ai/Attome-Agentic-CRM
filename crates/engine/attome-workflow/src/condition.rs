//! Z11-T15: Condition nodes on the one rule language. A node's config may
//! carry `expression`, V2 rule text (`amount > 1000 and stage == "won"`),
//! evaluated by `attome-rules` against the node's input: an object's keys
//! are fields, a nested object's keys read as `deal.amount`, and two or
//! three more levels as paths (`deal.account.owner.region`). A non-object
//! input is the field `value`. An expression wins over the legacy
//! `{field, op, value}` shape, which keeps its own evaluator unchanged
//! (`scheduler::eval_condition`); [`condition_to_expression`] writes a
//! legacy condition as the equivalent expression, for the editor.
//!
//! An expression is parsed when the graph is validated
//! ([`check_expression`]); its types are known only from the input, so it
//! type-checks when the node runs. A failure there (an unknown field, a
//! type mismatch, an evaluation error) takes the `false` branch and logs a
//! warning, as a legacy comparison that cannot match does.

use std::collections::HashMap;

use attome_rules::{Budgets, Context, LanguageVersion, Schema, Type, Value as RValue};
use serde_json::Value;

/// The deepest input nesting an expression reads (a field and three hops).
const MAX_PATH_SEGMENTS: usize = 4;

/// The `expression` text of a node config, when it has one.
pub(crate) fn expression_of(config: &Value) -> Option<&Value> {
    config.get("expression")
}

/// A30-T2: whether a condition's V2 expression reads `env.<name>`.
pub(crate) fn reads_env(config: &Value) -> bool {
    expression_of(config)
        .and_then(Value::as_str)
        .is_some_and(|src| !attome_core::env_vars::references(src).is_empty())
}

/// T6-T2: whether a condition's V2 expression calls `flag(...)`.
pub(crate) fn reads_flags(config: &Value) -> bool {
    expression_of(config)
        .and_then(Value::as_str)
        .is_some_and(attome_core::customer_flags::references)
}

/// Parses `src` as V2 rule text, for graph validation.
pub fn check_expression(src: &str) -> Result<(), String> {
    if src.trim().is_empty() {
        return Err("an empty condition expression".to_owned());
    }
    attome_rules::parse(src)
        .map(|_| ())
        .map_err(|e| format!("condition expression: {e}"))
}

/// Evaluates `src` against `input`; anything but `true` is `false`.
pub fn expression_holds(src: &str, input: &Value) -> bool {
    expression_holds_with_flags(src, input, &HashMap::new())
}

/// [`expression_holds`] with the customer flags `flag(name)` reads (T6-T2).
pub fn expression_holds_with_flags(
    src: &str,
    input: &Value,
    flags: &HashMap<String, bool>,
) -> bool {
    let (schema, ctx) = bind_input(input);
    let ctx = ctx.with_flags(flags.clone());
    let compiled = match attome_rules::compile_versioned(
        src,
        &schema,
        LanguageVersion::V2,
        Budgets::default(),
    ) {
        Ok(compiled) => compiled,
        Err(error) => {
            tracing::warn!(code = error.code(), %error, "workflow condition did not compile against its input; taking the false branch");
            return false;
        }
    };
    match compiled.eval(&ctx) {
        Ok(RValue::Bool(b)) => b,
        Ok(_) => false,
        Err(error) => {
            tracing::warn!(code = error.code(), %error, "workflow condition failed to evaluate; taking the false branch");
            false
        }
    }
}

/// A JSON value as a rule type and value. A number that is not finite, and
/// a list whose items disagree in type, read as null.
fn rule_value(v: &Value) -> (Type, RValue) {
    match v {
        Value::Null => (Type::Null, RValue::Null),
        Value::Bool(b) => (Type::Bool, RValue::Bool(*b)),
        Value::Number(n) => match n.as_f64().filter(|f| f.is_finite()) {
            Some(f) => (Type::Number, RValue::Number(f)),
            None => (Type::Null, RValue::Null),
        },
        Value::String(s) => (Type::Text, RValue::Text(s.clone())),
        Value::Array(items) => {
            let mut elem = Type::Null;
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                let (ty, value) = rule_value(item);
                match elem.unify(&ty) {
                    Some(u) => elem = u,
                    None => return (Type::Null, RValue::Null),
                }
                values.push(value);
            }
            (Type::List(Box::new(elem)), RValue::List(values))
        }
        Value::Object(map) => {
            let mut types = Vec::with_capacity(map.len());
            let mut values = Vec::with_capacity(map.len());
            for (k, item) in map {
                let (ty, value) = rule_value(item);
                types.push((k.clone(), ty));
                values.push((k.clone(), value));
            }
            (Type::Record(types), RValue::Record(values))
        }
    }
}

/// The schema and context an expression sees for `input`.
fn bind_input(input: &Value) -> (Schema, Context) {
    let mut schema = Schema::new();
    let mut ctx = Context::new(chrono::Utc::now());
    let Value::Object(fields) = input else {
        let (ty, value) = rule_value(input);
        return (
            schema.with_field("value", ty),
            ctx.with_field("value", value),
        );
    };
    for (name, item) in fields {
        let (ty, value) = rule_value(item);
        schema = schema.with_field(name.clone(), ty);
        ctx = ctx.with_field(name.clone(), value);
        if let Value::Object(inner) = item {
            let mut types = HashMap::new();
            let mut values = HashMap::new();
            for (k, v) in inner {
                let (ty, value) = rule_value(v);
                types.insert(k.clone(), ty);
                values.insert(k.clone(), value);
            }
            schema = schema.with_related(name.clone(), types);
            ctx = ctx.with_related(name.clone(), values);
            let mut path = vec![name.as_str()];
            bind_paths(inner, &mut path, &mut schema, &mut ctx);
        }
    }
    (schema, ctx)
}

/// Declares and loads every path of three or four segments under `prefix`.
fn bind_paths<'a>(
    fields: &'a serde_json::Map<String, Value>,
    prefix: &mut Vec<&'a str>,
    schema: &mut Schema,
    ctx: &mut Context,
) {
    for (k, v) in fields {
        let Value::Object(inner) = v else { continue };
        prefix.push(k.as_str());
        for (leaf, value) in inner {
            prefix.push(leaf.as_str());
            if prefix.len() <= MAX_PATH_SEGMENTS {
                let (ty, rv) = rule_value(value);
                *schema = std::mem::take(schema).with_optional_path(prefix.as_slice(), ty);
                *ctx = std::mem::replace(ctx, Context::new(chrono::Utc::now()))
                    .with_path(prefix.as_slice(), rv);
            }
            prefix.pop();
        }
        if prefix.len() < MAX_PATH_SEGMENTS - 1 {
            bind_paths(inner, prefix, schema, ctx);
        }
        prefix.pop();
    }
}

/// A legacy `{field, op, value}` condition as V2 rule text. `field` is a
/// dotted path of rule names (none: the input itself, `value`); the value a
/// JSON scalar written as a literal.
pub fn condition_to_expression(config: &Value) -> Result<String, String> {
    let op = config.get("op").and_then(Value::as_str).unwrap_or("eq");
    let field = config
        .get("field")
        .and_then(Value::as_str)
        .unwrap_or("value");
    if field.split('.').count() > MAX_PATH_SEGMENTS
        || !field.split('.').all(|seg| {
            seg.chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
                && seg
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
    {
        return Err(format!("{field:?} is not a rule field path"));
    }
    let literal = literal(config.get("value").unwrap_or(&Value::Null))?;
    Ok(match op {
        "eq" => format!("{field} == {literal}"),
        "neq" => format!("{field} != {literal}"),
        "gt" => format!("{field} > {literal}"),
        "lt" => format!("{field} < {literal}"),
        "contains" => format!("contains({field}, {literal})"),
        // `truthy` reads any JSON value; the typed language has no one
        // expression for it, so it stays a legacy condition.
        other => return Err(format!("condition op {other:?} has no expression form")),
    })
}

fn literal(v: &Value) -> Result<String, String> {
    match v {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        Value::String(s) => {
            let mut out = String::with_capacity(s.len() + 2);
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\t' => out.push_str("\\t"),
                    c => out.push(c),
                }
            }
            out.push('"');
            Ok(out)
        }
        Value::Array(_) | Value::Object(_) => {
            Err("a list or object value has no literal form".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::scheduler::eval_condition;

    /// T6-T2: a flow branch follows a customer flag; an unknown or
    /// emergency-off flag (absent from the loaded set) takes the off branch.
    #[test]
    fn flag_function_drives_a_flow_branch() {
        let config = json!({ "expression": "flag(\"new_checkout\") and amount > 5" });
        assert!(reads_flags(&config));
        assert!(!reads_flags(&json!({ "expression": "amount > 5" })));
        let on = HashMap::from([("new_checkout".to_owned(), true)]);
        let off = HashMap::from([("new_checkout".to_owned(), false)]);
        let input = json!({ "amount": 9 });
        assert!(crate::scheduler::eval_condition_with_flags(
            &config, &input, &on
        ));
        assert!(!crate::scheduler::eval_condition_with_flags(
            &config, &input, &off
        ));
        assert!(!eval_condition(&config, &input), "no flags loaded: off");
    }

    #[test]
    fn legacy_condition_converts_to_expression() {
        let cases = [
            (
                json!({"field": "amount", "op": "gt", "value": 10}),
                json!({"amount": 12}),
                true,
            ),
            (
                json!({"field": "deal.stage", "op": "eq", "value": "won"}),
                json!({"deal": {"stage": "won"}}),
                true,
            ),
            (
                json!({"field": "name", "op": "contains", "value": "a\"b"}),
                json!({"name": "xa\"by"}),
                true,
            ),
            (json!({"op": "lt", "value": 3}), json!(2), true),
        ];
        for (config, input, expected) in cases {
            let src = condition_to_expression(&config).unwrap();
            assert_eq!(eval_condition(&config, &input), expected, "legacy {config}");
            assert_eq!(expression_holds(&src, &input), expected, "{src} on {input}");
        }
        assert!(condition_to_expression(&json!({"field": "Bad-Name", "op": "eq"})).is_err());
        assert!(condition_to_expression(&json!({"field": "x", "op": "regex"})).is_err());
        assert!(condition_to_expression(&json!({"field": "x", "op": "truthy"})).is_err());
    }

    #[test]
    fn expression_condition_wins() {
        let config = json!({
            "field": "amount", "op": "gt", "value": 1_000_000,
            "expression": "amount > 10 and deal.account.owner.region == \"west\""
        });
        let input = json!({"amount": 50, "deal": {"account": {"owner": {"region": "west"}}}});
        assert!(eval_condition(&config, &input));
        let east = json!({"amount": 50, "deal": {"account": {"owner": {"region": "east"}}}});
        assert!(!eval_condition(&config, &east));
        // An unknown field or a bad type is the false branch, not a panic.
        assert!(!eval_condition(
            &json!({"expression": "missing > 1"}),
            &input
        ));
        assert!(!eval_condition(
            &json!({"expression": "amount + \"x\""}),
            &input
        ));
        assert!(check_expression("amount >").is_err());
        assert!(check_expression("amount > 1").is_ok());
    }
}

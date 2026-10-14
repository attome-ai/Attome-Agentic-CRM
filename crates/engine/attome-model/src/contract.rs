//! Typed contracts (roadmap N8-T1): the small JSON Schema subset an agent's
//! handoff input and output are written in, and the check of a value
//! against one.
//!
//! Supported keywords: `type` (`object`, `array`, `string`, `number`,
//! `integer`, `boolean`, `null`), `properties`, `required`,
//! `additionalProperties` (`false` only), `items`, `enum`, `minLength`,
//! `maxLength`, `minimum`, `maximum` and `description`. Anything else is
//! refused when the contract is saved ([`schema_issues`]), so a contract
//! never claims a rule the check does not enforce.

use serde_json::Value;

const TYPES: [&str; 7] = [
    "object", "array", "string", "number", "integer", "boolean", "null",
];
/// How deep a contract may nest.
pub const MAX_DEPTH: usize = 8;

/// Problems with a contract itself, by JSON pointer under `path`. A
/// top-level contract must describe an object.
pub fn schema_issues(schema: &Value, path: &str) -> Vec<(String, String)> {
    let mut issues = Vec::new();
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        issues.push((
            path.to_owned(),
            "a contract describes an object (`\"type\": \"object\"`)".to_owned(),
        ));
    }
    walk_schema(schema, path, 0, &mut issues);
    issues
}

fn walk_schema(schema: &Value, path: &str, depth: usize, issues: &mut Vec<(String, String)>) {
    let Some(object) = schema.as_object() else {
        issues.push((path.to_owned(), "a schema is an object".to_owned()));
        return;
    };
    if depth > MAX_DEPTH {
        issues.push((path.to_owned(), format!("nested deeper than {MAX_DEPTH}")));
        return;
    }
    for (key, value) in object {
        let at = format!("{path}/{key}");
        match key.as_str() {
            "type" => {
                if !value.as_str().is_some_and(|t| TYPES.contains(&t)) {
                    issues.push((at, format!("type is one of {}", TYPES.join(", "))));
                }
            }
            "properties" => match value.as_object() {
                Some(properties) => {
                    for (name, inner) in properties {
                        walk_schema(inner, &format!("{at}/{name}"), depth + 1, issues);
                    }
                }
                None => issues.push((at, "properties is an object".to_owned())),
            },
            "required" => {
                if !value
                    .as_array()
                    .is_some_and(|names| names.iter().all(Value::is_string))
                {
                    issues.push((at, "required is a list of names".to_owned()));
                }
            }
            "additionalProperties" => {
                if value != &Value::Bool(false) {
                    issues.push((at, "only `false` is supported".to_owned()));
                }
            }
            "items" => walk_schema(value, &at, depth + 1, issues),
            "enum" => {
                if !value.as_array().is_some_and(|v| !v.is_empty()) {
                    issues.push((at, "enum is a non-empty list".to_owned()));
                }
            }
            "minLength" | "maxLength" => {
                if value.as_u64().is_none() {
                    issues.push((at, format!("{key} is a whole number")));
                }
            }
            "minimum" | "maximum" => {
                if value.as_f64().is_none() {
                    issues.push((at, format!("{key} is a number")));
                }
            }
            "description" => {}
            other => {
                issues.push((at, format!("`{other}` is not supported in a contract")));
            }
        }
    }
}

/// Every way `value` breaks `schema`, by JSON pointer under `path`.
pub fn value_issues(schema: &Value, value: &Value, path: &str) -> Vec<String> {
    let mut issues = Vec::new();
    check(schema, value, path, 0, &mut issues);
    issues
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
}

fn check(schema: &Value, value: &Value, path: &str, depth: usize, issues: &mut Vec<String>) {
    if depth > MAX_DEPTH {
        return;
    }
    let at = if path.is_empty() { "/" } else { path };
    if let Some(expected) = schema.get("type").and_then(Value::as_str)
        && !type_matches(expected, value)
    {
        issues.push(format!("{at}: expected {expected}"));
        return;
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        issues.push(format!("{at}: not one of the allowed values"));
    }
    if let Some(text) = value.as_str() {
        let chars = text.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|min| chars < min)
        {
            issues.push(format!("{at}: too short"));
        }
        if schema
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|max| chars > max)
        {
            issues.push(format!("{at}: too long"));
        }
    }
    if let Some(number) = value.as_f64() {
        if schema
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|min| number < min)
        {
            issues.push(format!("{at}: below the minimum"));
        }
        if schema
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|max| number > max)
        {
            issues.push(format!("{at}: above the maximum"));
        }
    }
    if let Some(object) = value.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        for name in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !object.contains_key(name) {
                issues.push(format!("{path}/{name}: required"));
            }
        }
        for (name, inner) in object {
            match properties.and_then(|p| p.get(name)) {
                Some(property) => check(
                    property,
                    inner,
                    &format!("{path}/{name}"),
                    depth + 1,
                    issues,
                ),
                None if schema.get("additionalProperties") == Some(&Value::Bool(false)) => {
                    issues.push(format!("{path}/{name}: not allowed"));
                }
                None => {}
            }
        }
    }
    if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
        for (i, item) in array.iter().enumerate() {
            check(items, item, &format!("{path}/{i}"), depth + 1, issues);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contract() -> Value {
        json!({
            "type": "object",
            "required": ["account", "risk"],
            "additionalProperties": false,
            "properties": {
                "account": { "type": "string", "minLength": 1 },
                "risk": { "type": "string", "enum": ["low", "medium", "high"] },
                "score": { "type": "number", "minimum": 0, "maximum": 1 },
                "reasons": { "type": "array", "items": { "type": "string" } }
            }
        })
    }

    #[test]
    fn a_supported_contract_has_no_issues() {
        assert!(schema_issues(&contract(), "/handoff/output").is_empty());
    }

    #[test]
    fn unsupported_keywords_and_non_object_contracts_are_refused() {
        let issues = schema_issues(
            &json!({ "type": "string", "pattern": "x", "additionalProperties": true }),
            "/handoff/input",
        );
        let paths: Vec<&str> = issues.iter().map(|(p, _)| p.as_str()).collect();
        assert!(paths.contains(&"/handoff/input"));
        assert!(paths.contains(&"/handoff/input/pattern"));
        assert!(paths.contains(&"/handoff/input/additionalProperties"));
    }

    #[test]
    fn a_value_is_checked_against_every_rule() {
        assert!(
            value_issues(
                &contract(),
                &json!({ "account": "Acme", "risk": "low" }),
                ""
            )
            .is_empty()
        );
        let issues = value_issues(
            &contract(),
            &json!({ "account": "", "risk": "extreme", "score": 2, "reasons": [1], "extra": true }),
            "",
        );
        assert_eq!(issues.len(), 5, "{issues:?}");
        let missing = value_issues(&contract(), &json!({}), "");
        assert_eq!(missing, ["/account: required", "/risk: required"]);
        assert_eq!(
            value_issues(&contract(), &json!([]), ""),
            ["/: expected object"]
        );
    }
}

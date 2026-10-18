//! Z1-T4: the committed `config.schema.json` and `docs/config-reference.md`
//! match the typed configuration. Both are generated here: run with
//! `ATTOME_WRITE_CONFIG_SCHEMA=1` to rewrite them after changing a section,
//! then run again without it.

#![allow(
    clippy::expect_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::PathBuf;

use serde_json::{Map, Value};

const WRITE_VAR: &str = "ATTOME_WRITE_CONFIG_SCHEMA";

fn repo_file(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(relative)
}

/// Keys in sorted order at every level, whatever `serde_json`'s map is.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), sorted(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// Compares `actual` with the committed file, or writes it in write mode.
fn check(relative: &str, actual: &str) {
    let path = repo_file(relative);
    if std::env::var(WRITE_VAR).as_deref() == Ok("1") {
        std::fs::write(&path, actual).expect("write the generated file");
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        committed == actual,
        "{relative} is out of date with the configuration types: \
         run `{WRITE_VAR}=1 cargo test -p attome-config --test config_schema` and commit it"
    );
}

fn schema_text() -> String {
    let schema = sorted(&attome_config::config_json_schema());
    let mut text = serde_json::to_string_pretty(&schema).expect("serialize the schema");
    text.push('\n');
    text
}

// ── The reference page ──────────────────────────────────────────────────────

struct Row {
    key: String,
    kind: String,
    default: String,
    description: String,
    secret: bool,
}

/// Follows a `$ref` into `$defs`.
fn resolve<'a>(schema: &'a Value, defs: &'a Value) -> &'a Value {
    match schema["$ref"].as_str() {
        Some(target) => {
            let name = target.rsplit('/').next().unwrap_or_default();
            &defs[name]
        }
        None => schema,
    }
}

/// The non-null alternative of an `Option<T>` (`anyOf: [T, null]`).
fn unwrap_option<'a>(schema: &'a Value, defs: &'a Value) -> (&'a Value, bool) {
    if let Some(alternatives) = schema["anyOf"].as_array() {
        let present: Vec<&Value> = alternatives
            .iter()
            .filter(|alt| alt["type"] != "null")
            .collect();
        if present.len() == 1 && present.len() < alternatives.len() {
            return (resolve(present[0], defs), true);
        }
    }
    (resolve(schema, defs), false)
}

/// A short type label.
fn kind(schema: &Value, defs: &Value) -> String {
    let (schema, optional) = unwrap_option(schema, defs);
    let base = if let Some(values) = schema["enum"].as_array() {
        values
            .iter()
            .map(|v| {
                format!(
                    "`{}`",
                    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
                )
            })
            .collect::<Vec<_>>()
            .join(" \\| ")
    } else if let Some(alternatives) = schema["oneOf"].as_array().or(schema["anyOf"].as_array()) {
        alternatives
            .iter()
            .map(|alt| match alt["const"].as_str() {
                Some(constant) => format!("`{constant}`"),
                None => kind(alt, defs),
            })
            .collect::<Vec<_>>()
            .join(" \\| ")
    } else {
        match &schema["type"] {
            Value::String(t) if t == "array" => {
                format!("array of {}", kind(&schema["items"], defs))
            }
            Value::String(t) if t == "object" && schema.get("properties").is_none() => {
                "map".to_owned()
            }
            Value::String(t) => t.clone(),
            Value::Array(types) => types
                .iter()
                .filter(|t| *t != "null")
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" \\| "),
            _ => "any".to_owned(),
        }
    };
    let nullable = optional
        || schema["type"]
            .as_array()
            .is_some_and(|types| types.iter().any(|t| t == "null"));
    if nullable {
        format!("{base}, optional")
    } else {
        base
    }
}

/// The first paragraph of a description, on one line, safe in a table.
fn one_line(text: &str) -> String {
    let first = text.split("\n\n").next().unwrap_or_default();
    first
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
}

fn is_secret(schema: &Value, defs: &Value) -> bool {
    let (inner, _) = unwrap_option(schema, defs);
    schema["writeOnly"] == true || inner["writeOnly"] == true
}

/// One row per leaf field under `prefix`, nested sections flattened.
fn rows(prefix: &str, object: &Value, defs: &Value, depth: usize, out: &mut Vec<Row>) {
    let Some(properties) = object["properties"].as_object() else {
        return;
    };
    let mut names: Vec<&String> = properties.keys().collect();
    names.sort();
    for name in names {
        let field = &properties[name];
        let key = format!("{prefix}.{name}");
        let (inner, _) = unwrap_option(field, defs);
        let secret = is_secret(field, defs);
        if !secret && inner.get("properties").is_some() && depth < 4 {
            rows(&key, inner, defs, depth + 1, out);
            continue;
        }
        let description = field["description"]
            .as_str()
            .or(inner["description"].as_str())
            .unwrap_or_default();
        let default = match field.get("default") {
            Some(value) if !secret && !value.is_object() => {
                format!("`{}`", value.to_string().replace('|', "\\|"))
            }
            _ => String::new(),
        };
        out.push(Row {
            key,
            kind: kind(field, defs),
            default,
            description: one_line(description),
            secret,
        });
    }
}

fn reference_text() -> String {
    let schema = sorted(&attome_config::config_json_schema());
    let defs = &schema["$defs"];
    let required: Vec<&str> = schema["required"]
        .as_array()
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut text = String::from(
        "# Configuration reference\n\n\
         Generated from the typed configuration (`attome_config::AppConfig`) by\n\
         `crates/foundation/attome-config/tests/config_schema.rs`; do not edit it by hand.\n\
         To regenerate it and `config.schema.json`, run\n\
         `ATTOME_WRITE_CONFIG_SCHEMA=1 cargo test -p attome-config --test config_schema`.\n\n\
         A **secret** field is never shown back (it is write-only) and should come from an\n\
         environment variable (`${VAR}`). Unknown keys are reported at boot and refused by\n\
         `preflight`, except keys starting with `_`, so the file carries no `$schema` key;\n\
         point an editor at `config.schema.json` through its own settings instead.\n",
    );
    let sections = schema["properties"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for (name, section) in &sections {
        let resolved = resolve(section, defs);
        text.push_str(&format!("\n## `{name}`\n\n"));
        let about = section["description"]
            .as_str()
            .or(resolved["description"].as_str())
            .unwrap_or_default();
        if !about.is_empty() {
            text.push_str(&one_line(about));
            text.push_str("\n\n");
        }
        if required.contains(&name.as_str()) {
            text.push_str("Required.\n\n");
        }
        let mut out = Vec::new();
        rows(name, resolved, defs, 1, &mut out);
        text.push_str("| Key | Type | Default | Secret | Description |\n");
        text.push_str("|---|---|---|---|---|\n");
        for row in out {
            text.push_str(&format!(
                "| `{}` | {} | {} | {} | {} |\n",
                row.key,
                row.kind,
                row.default,
                if row.secret { "yes" } else { "" },
                row.description
            ));
        }
    }
    text
}

#[test]
fn committed_schema_matches_code() {
    check("config.schema.json", &schema_text());
}

#[test]
fn committed_reference_matches_code() {
    check("docs/config-reference.md", &reference_text());
}

#[test]
fn secrets_are_write_only_and_carry_no_default() {
    let schema = schema_text();
    let parsed: Value = serde_json::from_str(&schema).expect("parse");
    let auth = &parsed["$defs"]["AuthSection"]["properties"];
    let jwt = &auth["jwt_secret"];
    assert_eq!(jwt["writeOnly"], true, "a KeyRing is write-only: {jwt}");
    assert!(jwt.get("default").is_none(), "a secret has no default");
}

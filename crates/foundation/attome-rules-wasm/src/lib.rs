//! Z11-T13: `attome-rules` for the browser. [`validate`] and [`evaluate`] take
//! and return JSON, so the same evaluator the server runs answers a screen
//! (an editor underlining an unknown field, a preview of a value) without a
//! round trip. `scripts/build-rules-wasm.ps1` builds this crate to
//! WebAssembly and `@attome/base`'s `RulesEvaluatorService` loads it.
//!
//! The JSON shapes:
//!
//! - schema: `{"fields": {"amount": "number"}, "related": {"account":
//!   {"name": "text"}}, "related_lists": {"lines": {"qty": "number"}},
//!   "paths": {"account.owner.name": "text"}}`. A type is `null`, `bool`,
//!   `number`, `text`, `date`, `choice`, `lookup` or `list<T>`.
//! - context: `{"now": "2026-10-28T09:00:00Z", "timezone": "Asia/Riyadh",
//!   "fields": {...}, "related": {"account": {...}}, "related_lists":
//!   {"lines": [{...}]}, "paths": {"account.owner.name": ...}, "rates":
//!   {"base": "SAR", "rates": {"USD": 3.75}}, "calendar": {...}}`. A value
//!   is read by its schema type as the server reads a stored field: a date as
//!   RFC 3339 or `YYYY-MM-DD` (midnight UTC), a lookup as a UUID. The
//!   calendar is the stored definition: `timezone`, `working_days`
//!   (`mon`..`sun`), `hours` (per weekday, `[{"start_minute", "end_minute"}]`),
//!   `holidays` (`YYYY-MM-DD`) and `exceptions` (per date, ranges; empty
//!   closes the date).
//! - version: `v1` or `v2`; anything else is the latest.
//!
//! Every answer is a JSON object with `ok`. A failure carries `diagnostics`,
//! each `{code, message, start, end}` with byte offsets into the source, the
//! shape `POST /api/v1/admin/expressions/validate` returns.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use attome_calendar::{BusinessCalendar, TimeRange, parse_weekday_code};
use attome_rules::{Budgets, Context, LanguageVersion, RulesDiagnostic, Schema, Type, Value};
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::{Map, Value as Json, json};
use uuid::Uuid;
use wasm_bindgen::prelude::wasm_bindgen;

/// Checks `src` against `schema_json`: its result type, or each error with
/// the span it points at.
#[wasm_bindgen]
#[must_use]
pub fn validate(src: &str, schema_json: &str, version: &str) -> String {
    validate_value(src, schema_json, version).to_string()
}

/// Evaluates `src` against `schema_json` on `context_json`: the value and
/// the evaluation trace, or the errors.
#[wasm_bindgen]
#[must_use]
pub fn evaluate(src: &str, schema_json: &str, context_json: &str, version: &str) -> String {
    evaluate_value(src, schema_json, context_json, version).to_string()
}

/// [`validate`] as a JSON value.
#[must_use]
pub fn validate_value(src: &str, schema_json: &str, version: &str) -> Json {
    let schema = match parse_schema(schema_json) {
        Ok(schema) => schema,
        Err(message) => return failure("rules.input.schema", &message),
    };
    match attome_rules::compile_diagnostic(
        src,
        &schema.schema,
        language(version),
        Budgets::default(),
    ) {
        Ok(compiled) => json!({
            "ok": true,
            "result_type": compiled.result_type().to_string(),
            "diagnostics": [],
        }),
        Err(d) => json!({ "ok": false, "diagnostics": [diagnostic(&d)] }),
    }
}

/// [`evaluate`] as a JSON value.
#[must_use]
pub fn evaluate_value(src: &str, schema_json: &str, context_json: &str, version: &str) -> Json {
    let schema = match parse_schema(schema_json) {
        Ok(schema) => schema,
        Err(message) => return failure("rules.input.schema", &message),
    };
    let compiled = match attome_rules::compile_diagnostic(
        src,
        &schema.schema,
        language(version),
        Budgets::default(),
    ) {
        Ok(compiled) => compiled,
        Err(d) => return json!({ "ok": false, "diagnostics": [diagnostic(&d)] }),
    };
    let context = match parse_context(context_json, &schema) {
        Ok(context) => context,
        Err(message) => return failure("rules.input.context", &message),
    };
    match compiled.eval_traced(&context) {
        Ok((value, trace)) => json!({
            "ok": true,
            "result_type": compiled.result_type().to_string(),
            "value": to_json(&value),
            "trace": trace
                .entries()
                .iter()
                .map(|t| json!({ "expr": t.expr, "value": to_json(&t.value) }))
                .collect::<Vec<_>>(),
        }),
        Err(e) => failure(e.code(), &e.to_string()),
    }
}

fn language(version: &str) -> LanguageVersion {
    LanguageVersion::parse(version).unwrap_or(LanguageVersion::LATEST)
}

fn failure(code: &str, message: &str) -> Json {
    json!({
        "ok": false,
        "diagnostics": [{ "code": code, "message": message, "start": null, "end": null }],
    })
}

fn diagnostic(d: &RulesDiagnostic) -> Json {
    json!({
        "code": d.error.code(),
        "message": d.error.to_string(),
        "start": d.span.map(|(s, _)| s),
        "end": d.span.map(|(_, e)| e),
    })
}

/// The schema, and the declared types the context's values are read by.
struct ParsedSchema {
    schema: Schema,
    fields: HashMap<String, Type>,
    related: HashMap<String, HashMap<String, Type>>,
    related_lists: HashMap<String, Vec<(String, Type)>>,
    paths: HashMap<String, Type>,
}

fn object<'a>(value: &'a Json, key: &str) -> Result<Option<&'a Map<String, Json>>, String> {
    match value.get(key) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Object(map)) => Ok(Some(map)),
        Some(_) => Err(format!("`{key}` is an object")),
    }
}

fn parse_type(text: &str) -> Result<Type, String> {
    let text = text.trim();
    if let Some(inner) = text.strip_prefix("list<").and_then(|t| t.strip_suffix('>')) {
        return Ok(Type::List(Box::new(parse_type(inner)?)));
    }
    Ok(match text {
        "null" => Type::Null,
        "bool" => Type::Bool,
        "number" => Type::Number,
        "text" => Type::Text,
        "date" => Type::Date,
        "choice" => Type::Choice,
        "lookup" => Type::Lookup,
        other => return Err(format!("unknown type `{other}`")),
    })
}

fn type_map(map: &Map<String, Json>) -> Result<Vec<(String, Type)>, String> {
    map.iter()
        .map(|(name, ty)| {
            let ty = ty
                .as_str()
                .ok_or_else(|| format!("the type of `{name}` is text"))?;
            Ok((name.clone(), parse_type(ty)?))
        })
        .collect()
}

fn parse_schema(schema_json: &str) -> Result<ParsedSchema, String> {
    let raw: Json = serde_json::from_str(schema_json).map_err(|e| format!("schema: {e}"))?;
    let mut out = ParsedSchema {
        schema: Schema::new(),
        fields: HashMap::new(),
        related: HashMap::new(),
        related_lists: HashMap::new(),
        paths: HashMap::new(),
    };
    if let Some(fields) = object(&raw, "fields")? {
        for (name, ty) in type_map(fields)? {
            out.schema = out.schema.with_field(name.clone(), ty.clone());
            out.fields.insert(name, ty);
        }
    }
    if let Some(related) = object(&raw, "related")? {
        for (lookup, fields) in related {
            let fields = fields
                .as_object()
                .ok_or_else(|| format!("related `{lookup}` is an object"))?;
            let fields: HashMap<String, Type> = type_map(fields)?.into_iter().collect();
            out.schema = out.schema.with_related(lookup.clone(), fields.clone());
            out.related.insert(lookup.clone(), fields);
        }
    }
    if let Some(lists) = object(&raw, "related_lists")? {
        for (name, fields) in lists {
            let fields = fields
                .as_object()
                .ok_or_else(|| format!("related list `{name}` is an object"))?;
            let fields = type_map(fields)?;
            out.schema = out.schema.with_related_list(name.clone(), fields.clone());
            out.related_lists.insert(name.clone(), fields);
        }
    }
    if let Some(paths) = object(&raw, "paths")? {
        for (path, ty) in type_map(paths)? {
            let segments: Vec<&str> = path.split('.').collect();
            out.schema = out.schema.with_path(&segments, ty.clone());
            out.paths.insert(path, ty);
        }
    }
    Ok(out)
}

fn parse_date(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .map(|d| d.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDate::parse_from_str(text, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.and_hms_opt(0, 0, 0))
                .map(|d| d.and_utc())
        })
}

/// A JSON value read as `ty`, as the server reads a stored field: absent,
/// `null` or the wrong JSON kind is `Null`.
fn from_json(ty: &Type, value: Option<&Json>) -> Value {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Value::Null;
    };
    let read = match ty {
        Type::Null => None,
        Type::Bool => value.as_bool().map(Value::Bool),
        Type::Number => value.as_f64().filter(|n| n.is_finite()).map(Value::Number),
        Type::Text => value.as_str().map(|s| Value::Text(s.to_owned())),
        Type::Date => value.as_str().and_then(parse_date).map(Value::Date),
        Type::Choice => value.as_str().map(|s| Value::Choice(s.to_owned())),
        Type::Lookup => value
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .map(Value::Lookup),
        Type::List(inner) => value.as_array().map(|items| {
            Value::List(
                items
                    .iter()
                    .map(|item| from_json(inner, Some(item)))
                    .collect(),
            )
        }),
        Type::Record(fields) => value.as_object().map(|row| record(fields, row)),
    };
    read.unwrap_or(Value::Null)
}

fn record(fields: &[(String, Type)], row: &Map<String, Json>) -> Value {
    Value::Record(
        fields
            .iter()
            .map(|(name, ty)| (name.clone(), from_json(ty, row.get(name))))
            .collect(),
    )
}

/// The inverse of [`from_json`], as the server writes a value back.
fn to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Number(n) => serde_json::Number::from_f64(*n).map_or(Json::Null, Json::Number),
        Value::Text(s) | Value::Choice(s) => Json::String(s.clone()),
        Value::Date(d) => Json::String(d.to_rfc3339()),
        Value::Lookup(id) => Json::String(id.to_string()),
        Value::List(items) => Json::Array(items.iter().map(to_json).collect()),
        Value::Record(fields) => Json::Object(
            fields
                .iter()
                .map(|(name, value)| (name.clone(), to_json(value)))
                .collect(),
        ),
    }
}

fn parse_context(context_json: &str, schema: &ParsedSchema) -> Result<Context, String> {
    let raw: Json = serde_json::from_str(context_json).map_err(|e| format!("context: {e}"))?;
    let now = match raw.get("now").and_then(Json::as_str) {
        Some(text) => parse_date(text).ok_or_else(|| format!("`now` is not a date: {text}"))?,
        None => return Err("`now` is required (the evaluator has no clock)".to_owned()),
    };
    let mut context = Context::new(now);
    if let Some(zone) = raw.get("timezone").and_then(Json::as_str) {
        context = context
            .with_timezone_name(zone)
            .map_err(|e| e.to_string())?;
    }
    let empty = Map::new();
    let fields = object(&raw, "fields")?.unwrap_or(&empty);
    for (name, ty) in &schema.fields {
        if schema.related_lists.contains_key(name) {
            continue;
        }
        context = context.with_field(name.clone(), from_json(ty, fields.get(name)));
    }
    let related = object(&raw, "related")?.unwrap_or(&empty);
    for (lookup, types) in &schema.related {
        if let Some(row) = related.get(lookup).and_then(Json::as_object) {
            let values = types
                .iter()
                .map(|(name, ty)| (name.clone(), from_json(ty, row.get(name))))
                .collect();
            context = context.with_related(lookup.clone(), values);
        }
    }
    let lists = object(&raw, "related_lists")?.unwrap_or(&empty);
    for (name, types) in &schema.related_lists {
        let rows = lists
            .get(name)
            .and_then(Json::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(Json::as_object)
                    .map(|row| {
                        types
                            .iter()
                            .map(|(field, ty)| (field.clone(), from_json(ty, row.get(field))))
                            .collect()
                    })
                    .collect()
            })
            .unwrap_or_default();
        context = context.with_related_list(name.clone(), rows);
    }
    let paths = object(&raw, "paths")?.unwrap_or(&empty);
    for (path, ty) in &schema.paths {
        if let Some(value) = paths.get(path) {
            let segments: Vec<&str> = path.split('.').collect();
            context = context.with_path(&segments, from_json(ty, Some(value)));
        }
    }
    if let Some(rates) = object(&raw, "rates")? {
        let base = rates
            .get("base")
            .and_then(Json::as_str)
            .ok_or("`rates.base` is a currency code")?;
        let table = object(&Json::Object(rates.clone()), "rates")?
            .map(|table| {
                table
                    .iter()
                    .filter_map(|(code, rate)| rate.as_f64().map(|r| (code.clone(), r)))
                    .collect()
            })
            .unwrap_or_default();
        context = context
            .with_rates(base.to_owned(), table)
            .map_err(|e| e.to_string())?;
    }
    if let Some(calendar) = object(&raw, "calendar")? {
        context = context.with_calendar(Arc::new(parse_calendar(calendar)?));
    }
    Ok(context)
}

fn ranges(value: &Json, label: &str) -> Result<Vec<TimeRange>, String> {
    serde_json::from_value(value.clone())
        .map_err(|e| format!("{label} is a list of {{start_minute, end_minute}}: {e}"))
}

fn date(text: &str) -> Result<NaiveDate, String> {
    NaiveDate::parse_from_str(text, "%Y-%m-%d").map_err(|_| format!("`{text}` is not YYYY-MM-DD"))
}

fn parse_calendar(raw: &Map<String, Json>) -> Result<BusinessCalendar, String> {
    let calendar = Json::Object(raw.clone());
    let tz: chrono_tz::Tz = raw
        .get("timezone")
        .and_then(Json::as_str)
        .unwrap_or("UTC")
        .parse()
        .map_err(|_| "the calendar's timezone is not an IANA name".to_owned())?;
    let mut working_days = HashSet::new();
    for code in raw
        .get("working_days")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        let code = code.as_str().unwrap_or_default();
        working_days
            .insert(parse_weekday_code(code).ok_or_else(|| format!("`{code}` is not a weekday"))?);
    }
    let mut hours = HashMap::new();
    for (code, day_ranges) in object(&calendar, "hours")?.into_iter().flatten() {
        let day = parse_weekday_code(code).ok_or_else(|| format!("`{code}` is not a weekday"))?;
        hours.insert(day, ranges(day_ranges, &format!("hours for `{code}`"))?);
    }
    let mut holidays = BTreeSet::new();
    for day in raw
        .get("holidays")
        .and_then(Json::as_array)
        .into_iter()
        .flatten()
    {
        holidays.insert(date(day.as_str().unwrap_or_default())?);
    }
    let mut exceptions = BTreeMap::new();
    for (day, day_ranges) in object(&calendar, "exceptions")?.into_iter().flatten() {
        exceptions.insert(
            date(day)?,
            ranges(day_ranges, &format!("the exception on {day}"))?,
        );
    }
    BusinessCalendar::new(tz, working_days, hours, holidays, exceptions).map_err(|e| e.to_string())
}

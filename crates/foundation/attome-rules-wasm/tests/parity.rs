//! Z11-T13: the browser's answer is the server's. Twenty fixed expressions go
//! through this crate's JSON entry points (what the WebAssembly build runs)
//! and straight through `attome-rules` (what the server runs), on the same
//! record, and must agree on the value or the error code.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test: a failed setup step should panic with its message"
)]

use attome_rules::{Budgets, Context, LanguageVersion, Schema, Type, Value};
use chrono::{TimeZone, Utc};
use serde_json::{Value as Json, json};

const EXPRESSIONS: [&str; 20] = [
    "amount > 100",
    "amount * 2 + 1",
    "round(amount / 3, 2)",
    "name",
    "upper(name)",
    "len(name) > 3",
    "contains(name, 'cm')",
    "if(amount > 100, 'large', 'small')",
    "status = 'open'",
    "status = 'open' and amount > 50",
    "not active",
    "active or amount < 0",
    "due_date > now()",
    "coalesce(notes, 'none')",
    "amount / 0",
    "concat(name, ' / ', status)",
    "all(lines, l => l.qty > 0)",
    "count(lines)",
    "any(lines, l => l.qty > 2)",
    "missing_field + 1",
];

fn schema() -> Schema {
    Schema::new()
        .with_field("amount", Type::Number)
        .with_field("name", Type::Text)
        .with_field("notes", Type::Text)
        .with_field("status", Type::Choice)
        .with_field("active", Type::Bool)
        .with_field("due_date", Type::Date)
        .with_related_list("lines", vec![("qty".to_owned(), Type::Number)])
}

fn context() -> Context {
    Context::new(Utc.with_ymd_and_hms(2026, 10, 28, 9, 0, 0).unwrap())
        .with_field("amount", Value::Number(150.0))
        .with_field("name", Value::Text("Acme".into()))
        .with_field("notes", Value::Null)
        .with_field("status", Value::Choice("open".into()))
        .with_field("active", Value::Bool(true))
        .with_field(
            "due_date",
            Value::Date(Utc.with_ymd_and_hms(2026, 12, 1, 0, 0, 0).unwrap()),
        )
        .with_related_list(
            "lines",
            vec![
                vec![("qty".to_owned(), Value::Number(1.0))],
                vec![("qty".to_owned(), Value::Number(3.0))],
            ],
        )
}

const SCHEMA_JSON: &str = r#"{
    "fields": {"amount": "number", "name": "text", "notes": "text", "status": "choice",
               "active": "bool", "due_date": "date"},
    "related_lists": {"lines": {"qty": "number"}}
}"#;

const CONTEXT_JSON: &str = r#"{
    "now": "2026-10-28T09:00:00Z",
    "fields": {"amount": 150, "name": "Acme", "notes": null, "status": "open",
               "active": true, "due_date": "2026-12-01"},
    "related_lists": {"lines": [{"qty": 1}, {"qty": 3}]}
}"#;

/// What the server answers: the value as JSON, or the error code.
fn server(src: &str) -> Result<Json, String> {
    let compiled = attome_rules::compile_diagnostic(
        src,
        &schema(),
        LanguageVersion::LATEST,
        Budgets::default(),
    )
    .map_err(|d| d.error.code().to_owned())?;
    let value = compiled.eval(&context()).map_err(|e| e.code().to_owned())?;
    Ok(match value {
        Value::Number(n) => json!(n),
        Value::Bool(b) => json!(b),
        Value::Text(s) | Value::Choice(s) => json!(s),
        Value::Null => Json::Null,
        Value::Date(d) => json!(d.to_rfc3339()),
        other => json!(other.to_string()),
    })
}

/// What the browser answers.
fn browser(src: &str) -> Result<Json, String> {
    let answer = attome_rules_wasm::evaluate_value(src, SCHEMA_JSON, CONTEXT_JSON, "v2");
    if answer["ok"] == json!(true) {
        Ok(answer["value"].clone())
    } else {
        Err(answer["diagnostics"][0]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned())
    }
}

#[test]
fn the_browser_answers_as_the_server_does() {
    for src in EXPRESSIONS {
        assert_eq!(browser(src), server(src), "{src}");
    }
    // The set covers values and errors both.
    assert!(EXPRESSIONS.iter().any(|s| server(s).is_err()));
    assert!(EXPRESSIONS.iter().any(|s| server(s).is_ok()));
}

#[test]
fn validate_points_at_the_unknown_field() {
    let answer = attome_rules_wasm::validate_value("amount + missing", SCHEMA_JSON, "v2");
    assert_eq!(answer["ok"], json!(false));
    let d = &answer["diagnostics"][0];
    assert_eq!(d["code"], json!("rules.field.unknown"));
    assert_eq!(
        (d["start"].clone(), d["end"].clone()),
        (json!(9), json!(16))
    );
    let ok = attome_rules_wasm::validate_value("amount > 100", SCHEMA_JSON, "v2");
    assert_eq!(ok["result_type"], json!("bool"));
}

#[test]
fn a_bad_context_is_a_diagnostic_not_a_panic() {
    let answer = attome_rules_wasm::evaluate_value("amount", SCHEMA_JSON, "{}", "v2");
    assert_eq!(
        answer["diagnostics"][0]["code"],
        json!("rules.input.context")
    );
    let answer = attome_rules_wasm::evaluate_value("amount", "not json", CONTEXT_JSON, "v2");
    assert_eq!(
        answer["diagnostics"][0]["code"],
        json!("rules.input.schema")
    );
}

/// Z12-T11: Sunday to Thursday, 09:00 to 17:00 in Riyadh, a holiday and a
/// short day; the definition the expanded route returns, and the same
/// calendar built directly, as the server builds it.
const CALENDAR: &str = r#"{
    "timezone": "Asia/Riyadh",
    "working_days": ["sun", "mon", "tue", "wed", "thu"],
    "hours": {
        "sun": [{"start_minute": 540, "end_minute": 1020}],
        "mon": [{"start_minute": 540, "end_minute": 1020}],
        "tue": [{"start_minute": 540, "end_minute": 1020}],
        "wed": [{"start_minute": 540, "end_minute": 1020}],
        "thu": [{"start_minute": 540, "end_minute": 1020}]
    },
    "holidays": ["2026-11-04"],
    "exceptions": {"2026-11-09": [{"start_minute": 600, "end_minute": 720}]}
}"#;

fn server_calendar() -> attome_calendar::BusinessCalendar {
    use attome_calendar::{BusinessCalendar, TimeRange};
    use chrono::{NaiveDate, Weekday};
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
    let days = [
        Weekday::Sun,
        Weekday::Mon,
        Weekday::Tue,
        Weekday::Wed,
        Weekday::Thu,
    ];
    let hours: HashMap<Weekday, Vec<TimeRange>> = days
        .iter()
        .map(|d| (*d, vec![TimeRange::try_new(540, 1020).unwrap()]))
        .collect();
    let working: HashSet<Weekday> = days.into_iter().collect();
    let holidays = BTreeSet::from([NaiveDate::from_ymd_opt(2026, 11, 4).unwrap()]);
    let exceptions = BTreeMap::from([(
        NaiveDate::from_ymd_opt(2026, 11, 9).unwrap(),
        vec![TimeRange::try_new(600, 720).unwrap()],
    )]);
    BusinessCalendar::new(
        chrono_tz::Asia::Riyadh,
        working,
        hours,
        holidays,
        exceptions,
    )
    .unwrap()
}

fn iso(at: chrono::DateTime<Utc>) -> Json {
    json!(at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn parsed(text: &str) -> chrono::DateTime<Utc> {
    text.parse().unwrap()
}

/// Twenty fixed calculations: five of each operation.
#[test]
fn calendar_parity() {
    use attome_rules_wasm::{
        calendar_add_value, calendar_between_value, calendar_is_working_value, calendar_next_value,
    };
    let server = server_calendar();
    let starts = [
        "2026-11-01T06:00:00Z", // Sunday, on the hour
        "2026-11-03T13:30:00Z", // Tuesday, near closing
        "2026-11-04T07:00:00Z", // the holiday
        "2026-11-06T10:00:00Z", // Friday
        "2026-11-09T08:30:00Z", // the short day
    ];
    let minutes = [30, 240, 480, 1_000, 5];
    let mut compared = 0;
    for (start, minutes) in starts.iter().zip(minutes) {
        let want = server
            .add_business_duration(parsed(start), chrono::Duration::minutes(minutes))
            .unwrap();
        let got = calendar_add_value(CALENDAR, start, minutes);
        assert_eq!(got["value"], iso(want), "add {minutes} to {start}");
        compared += 1;

        let end = parsed(start) + chrono::Duration::days(2) + chrono::Duration::minutes(minutes);
        let end_iso = end.to_rfc3339();
        let want = server
            .business_duration_between(parsed(start), end)
            .unwrap();
        let got = calendar_between_value(CALENDAR, start, &end_iso);
        assert_eq!(got["value"], json!(want.num_minutes()), "between {start}");
        compared += 1;

        let want = server.next_working_moment(parsed(start)).unwrap();
        assert_eq!(
            calendar_next_value(CALENDAR, start)["value"],
            iso(want),
            "next after {start}"
        );
        compared += 1;

        assert_eq!(
            calendar_is_working_value(CALENDAR, start)["value"],
            json!(server.is_working(parsed(start))),
            "working at {start}"
        );
        compared += 1;
    }
    assert_eq!(compared, 20);
}

#[test]
fn a_bad_calendar_is_an_answer_not_a_panic() {
    let got = attome_rules_wasm::calendar_next_value("{}", "2026-11-01T06:00:00Z");
    assert_eq!(got["ok"], false);
    let got = attome_rules_wasm::calendar_next_value(CALENDAR, "yesterday");
    assert_eq!(got["ok"], false);
}

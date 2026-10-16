//! Z11-T6: `matches(text, pattern)` — literal patterns only, compiled once
//! under a size limit, full-string, linear time.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, Instant};

use attome_rules::{
    Budgets, Context, LanguageVersion, RulesError, Schema, Type, Value, compile_versioned,
};

fn schema() -> Schema {
    Schema::new()
        .with_field("code", Type::Text)
        .with_field("pattern", Type::Text)
}

fn compile(src: &str, budgets: Budgets) -> Result<attome_rules::Compiled, RulesError> {
    compile_versioned(src, &schema(), LanguageVersion::V2, budgets)
}

fn with_code(code: &str) -> Context {
    Context::new(chrono::Utc::now()).with_field("code", Value::Text(code.to_owned()))
}

#[test]
fn matches_full_string() {
    let rule = compile(r#"matches(code, "[A-Z]{2}[0-9]{4}")"#, Budgets::default()).unwrap();
    assert_eq!(rule.eval(&with_code("SA1234")).unwrap(), Value::Bool(true));
    assert_eq!(
        rule.eval(&with_code("xSA1234")).unwrap(),
        Value::Bool(false),
        "a match must cover the whole text"
    );
    assert_eq!(
        rule.eval(&with_code("SA12345")).unwrap(),
        Value::Bool(false)
    );
}

#[test]
fn non_literal_pattern_rejected() {
    let err = compile("matches(code, pattern)", Budgets::default()).unwrap_err();
    assert_eq!(err.code(), "rules.regex.not_literal");
}

#[test]
fn oversized_pattern_rejected() {
    let err = compile(r#"matches(code, "a{1000}{1000}")"#, Budgets::default()).unwrap_err();
    assert_eq!(err.code(), "rules.regex.invalid");
    let err = compile(r#"matches(code, "(unclosed")"#, Budgets::default()).unwrap_err();
    assert_eq!(err.code(), "rules.regex.invalid");
}

#[test]
fn catastrophic_pattern_runs_fast() {
    let budgets = Budgets {
        max_string_len: 100_000,
        max_wall_clock: Duration::from_secs(5),
        ..Budgets::default()
    };
    let rule = compile(r#"matches(code, "(a+)+$")"#, budgets).unwrap();
    let mut text = "a".repeat(50_000);
    text.push('b');
    let started = Instant::now();
    assert_eq!(rule.eval(&with_code(&text)).unwrap(), Value::Bool(false));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "linear time: {:?}",
        started.elapsed()
    );
}

#[test]
fn v1_does_not_know_matches() {
    let err = compile_versioned(
        r#"matches(code, "a")"#,
        &schema(),
        LanguageVersion::V1,
        Budgets::default(),
    )
    .unwrap_err();
    assert!(matches!(err, RulesError::UnknownFunction(_)), "{err:?}");
}

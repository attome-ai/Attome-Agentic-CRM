//! Z11-T5: currency functions with rates the caller supplies.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{
    Budgets, Context, LanguageVersion, RulesError, Schema, Type, Value, compile_versioned,
};

fn eval(src: &str, ctx: &Context) -> Result<Value, RulesError> {
    let schema = Schema::new().with_field("amount", Type::Number);
    compile_versioned(src, &schema, LanguageVersion::V2, Budgets::default())?.eval(ctx)
}

fn ctx() -> Context {
    Context::new(chrono::Utc::now())
        .with_field("amount", Value::Number(100.0))
        .with_rates(
            "SAR".to_owned(),
            vec![("USD".to_owned(), 3.75), ("KWD".to_owned(), 12.2)],
        )
        .expect("valid rates")
}

#[test]
fn round_kwd_three_decimals() {
    assert_eq!(
        eval(r#"round_currency(1.23456, "KWD")"#, &ctx()).unwrap(),
        Value::Number(1.235)
    );
    assert_eq!(
        eval(r#"round_currency(1.005, "SAR")"#, &ctx()).unwrap(),
        Value::Number(1.01)
    );
    assert_eq!(
        eval(r#"minor_units("JOD")"#, &ctx()).unwrap(),
        Value::Number(3.0)
    );
}

#[test]
fn convert_through_base_rate() {
    // 100 USD = 375 SAR.
    assert_eq!(
        eval(r#"convert(amount, "USD", "SAR")"#, &ctx()).unwrap(),
        Value::Number(375.0)
    );
    // 375 SAR = 100 USD; USD to KWD goes through SAR.
    assert_eq!(
        eval(
            r#"round_currency(convert(375, "SAR", "USD"), "USD")"#,
            &ctx()
        )
        .unwrap(),
        Value::Number(100.0)
    );
    assert_eq!(
        eval(
            r#"round_currency(convert(122, "USD", "KWD"), "KWD")"#,
            &ctx()
        )
        .unwrap(),
        Value::Number(37.5)
    );
}

#[test]
fn unknown_currency_errors() {
    let err = eval(r#"round_currency(1, "XYZ")"#, &ctx()).unwrap_err();
    assert_eq!(err.code(), "rules.currency.unknown");
    let err = eval(r#"convert(1, "EUR", "SAR")"#, &ctx()).unwrap_err();
    assert_eq!(err.code(), "rules.currency.no_rate");
    let no_rates = Context::new(chrono::Utc::now()).with_field("amount", Value::Number(1.0));
    assert_eq!(
        eval(r#"convert(amount, "USD", "SAR")"#, &no_rates)
            .unwrap_err()
            .code(),
        "rules.currency.no_rate"
    );
}

#[test]
fn rates_must_be_positive_and_known() {
    let now = chrono::Utc::now();
    assert!(
        Context::new(now)
            .with_rates("SAR".to_owned(), vec![("USD".to_owned(), 0.0)])
            .is_err()
    );
    assert!(
        Context::new(now)
            .with_rates("SAR".to_owned(), vec![("USD".to_owned(), f64::NAN)])
            .is_err()
    );
    let Err(err) = Context::new(now).with_rates("ZZZ".to_owned(), Vec::new()) else {
        panic!("an unknown base is refused");
    };
    assert_eq!(err.code(), "rules.currency.unknown");
}

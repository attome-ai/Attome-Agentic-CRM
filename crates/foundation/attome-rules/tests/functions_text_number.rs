//! Z11-T2: the V2 text and number functions, Arabic normalisation among
//! them.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{
    BudgetKind, Budgets, Context, LanguageVersion, RulesError, Schema, Type, Value,
    compile_versioned,
};

fn schema() -> Schema {
    Schema::new()
        .with_field("name", Type::Text)
        .with_field("amount", Type::Number)
}

fn eval_with(src: &str, ctx: &Context, budgets: Budgets) -> Result<Value, RulesError> {
    compile_versioned(src, &schema(), LanguageVersion::V2, budgets)?.eval(ctx)
}

fn eval(src: &str) -> Result<Value, RulesError> {
    let ctx = Context::new(chrono::Utc::now())
        .with_field("name", Value::Text("Acme".into()))
        .with_field("amount", Value::Number(-2.5));
    eval_with(src, &ctx, Budgets::default())
}

#[test]
fn normalize_ar_folds_alef_forms() {
    assert_eq!(
        eval(r#"normalize_ar("أحمد") == normalize_ar("احمد")"#).unwrap(),
        Value::Bool(true)
    );
    assert_eq!(
        eval(r#"normalize_ar("إسلام")"#).unwrap(),
        Value::Text("اسلام".into())
    );
}

#[test]
fn normalize_ar_strips_diacritics() {
    assert_eq!(
        eval(r#"normalize_ar("مُحَمَّد")"#).unwrap(),
        Value::Text("محمد".into())
    );
}

#[test]
fn substr_out_of_range_is_empty() {
    assert_eq!(
        eval(r#"substr("Acme", 10, 3)"#).unwrap(),
        Value::Text(String::new())
    );
    assert_eq!(
        eval(r#"substr("Acme", 1, 2)"#).unwrap(),
        Value::Text("cm".into())
    );
    assert_eq!(
        eval(r#"substr("Acme", 2, 10)"#).unwrap(),
        Value::Text("me".into())
    );
}

#[test]
fn power_rejects_large_exponent() {
    assert_eq!(eval("power(2, 10)").unwrap(), Value::Number(1024.0));
    assert!(matches!(eval("power(2, 11)"), Err(RulesError::Eval(_))));
    assert!(matches!(eval("power(2, 1.5)"), Err(RulesError::Eval(_))));
}

#[test]
fn concat_respects_string_budget() {
    assert_eq!(
        eval(r#"concat(name, " ", "Ltd")"#).unwrap(),
        Value::Text("Acme Ltd".into())
    );
    let budgets = Budgets {
        max_string_len: 5,
        ..Budgets::default()
    };
    let ctx = Context::new(chrono::Utc::now()).with_field("name", Value::Text("Acme".into()));
    let err = eval_with(r#"concat(name, " Ltd")"#, &ctx, budgets).unwrap_err();
    assert!(
        matches!(err, RulesError::Budget(BudgetKind::StringLength)),
        "{err:?}"
    );
}

#[test]
fn number_functions() {
    assert_eq!(eval("abs(amount)").unwrap(), Value::Number(2.5));
    assert_eq!(eval("floor(amount)").unwrap(), Value::Number(-3.0));
    assert_eq!(eval("ceil(amount)").unwrap(), Value::Number(-2.0));
    assert_eq!(eval("clamp(15, 0, 10)").unwrap(), Value::Number(10.0));
    assert!(matches!(eval("clamp(1, 5, 0)"), Err(RulesError::Eval(_))));
    assert_eq!(
        eval(r#"replace("a-b-c", "-", "/")"#).unwrap(),
        Value::Text("a/b/c".into())
    );
}

#[test]
fn v1_does_not_know_the_v2_functions() {
    for src in [r#"normalize_ar(name)"#, "abs(amount)", r#"concat(name)"#] {
        let err =
            compile_versioned(src, &schema(), LanguageVersion::V1, Budgets::default()).unwrap_err();
        assert!(
            matches!(err, RulesError::UnknownFunction(_)),
            "{src}: {err:?}"
        );
    }
}

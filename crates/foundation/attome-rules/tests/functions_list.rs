//! Z11-T3: list functions over related lists, with a bounded lambda form.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{
    BudgetKind, Budgets, Context, LanguageVersion, RulesError, Schema, Type, Value,
    compile_versioned,
};
use chrono::Utc;

fn schema() -> Schema {
    Schema::new().with_related_list(
        "lines",
        vec![
            ("qty".to_owned(), Type::Number),
            ("price".to_owned(), Type::Number),
            ("sku".to_owned(), Type::Text),
        ],
    )
}

fn line(qty: f64, price: f64, sku: &str) -> Vec<(String, Value)> {
    vec![
        ("qty".to_owned(), Value::Number(qty)),
        ("price".to_owned(), Value::Number(price)),
        ("sku".to_owned(), Value::Text(sku.to_owned())),
    ]
}

fn ctx() -> Context {
    Context::new(Utc::now()).with_related_list(
        "lines",
        vec![
            line(2.0, 10.0, "A-1"),
            line(0.0, 99.0, "B-2"),
            line(5.0, 1.5, "A-3"),
        ],
    )
}

fn eval(src: &str) -> Result<Value, RulesError> {
    compile_versioned(src, &schema(), LanguageVersion::V2, Budgets::default())?.eval(&ctx())
}

#[test]
fn sum_over_related_list() {
    assert_eq!(
        eval("sum(map(lines, l => l.qty * l.price))").unwrap(),
        Value::Number(27.5)
    );
    assert_eq!(eval("count(lines)").unwrap(), Value::Number(3.0));
    assert_eq!(
        eval("avg(map(lines, l => l.qty))").unwrap(),
        Value::Number(7.0 / 3.0)
    );
    assert_eq!(
        eval("first(map(lines, l => l.sku))").unwrap(),
        Value::Text("A-1".into())
    );
}

#[test]
fn any_with_lambda() {
    assert_eq!(
        eval("any(lines, l => l.qty == 0)").unwrap(),
        Value::Bool(true)
    );
    assert_eq!(
        eval("all(lines, l => l.price > 1)").unwrap(),
        Value::Bool(true)
    );
    assert_eq!(
        eval("all(lines, l => l.qty > 0)").unwrap(),
        Value::Bool(false)
    );
    // A condition must be a bool.
    let err = compile_versioned(
        "any(lines, l => l.qty)",
        &schema(),
        LanguageVersion::V2,
        Budgets::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "rules.type.mismatch");
}

#[test]
fn filter_then_count() {
    assert_eq!(
        eval("count(filter(lines, l => endswith(l.sku, \"-1\") or l.qty > 4))").unwrap(),
        Value::Number(2.0)
    );
    // The list functions are V2.
    let v1 = compile_versioned(
        "count(lines)",
        &schema(),
        LanguageVersion::V1,
        Budgets::default(),
    );
    assert!(matches!(v1, Err(RulesError::UnknownFunction(_))), "{v1:?}");
}

#[test]
fn lambda_outside_call_is_parse_error() {
    for src in ["l => l.qty", "count(l => 1)", "sum(lines, l => l.qty)"] {
        let err =
            compile_versioned(src, &schema(), LanguageVersion::V2, Budgets::default()).unwrap_err();
        assert!(
            matches!(err, RulesError::Parse { .. } | RulesError::Arity { .. }),
            "{src}: {err:?}"
        );
    }
    let err = attome_rules::parse("l => 1").unwrap_err();
    assert_eq!(err.code(), "rules.parse.unexpected_token");
}

#[test]
fn list_steps_charge_budget() {
    let tight = Budgets {
        max_eval_steps: 8,
        ..Budgets::default()
    };
    // Three elements, each a step plus its body's: past 8 steps.
    let rule = compile_versioned(
        "any(lines, l => l.qty > 100)",
        &schema(),
        LanguageVersion::V2,
        tight,
    )
    .unwrap();
    assert_eq!(
        rule.eval(&ctx()),
        Err(RulesError::Budget(BudgetKind::EvalSteps))
    );
    let count = compile_versioned("count(lines)", &schema(), LanguageVersion::V2, tight).unwrap();
    assert_eq!(
        count.eval(&ctx()).unwrap(),
        Value::Number(3.0),
        "one step each fits"
    );
}

#[test]
fn third_nested_lambda_rejected() {
    let two = "any(lines, a => any(lines, b => b.qty == a.qty))";
    assert_eq!(eval(two).unwrap(), Value::Bool(true));
    let three = "any(lines, a => any(lines, b => any(lines, c => c.qty == b.qty)))";
    let err =
        compile_versioned(three, &schema(), LanguageVersion::V2, Budgets::default()).unwrap_err();
    assert_eq!(err, RulesError::Budget(BudgetKind::LambdaDepth));
    assert_eq!(err.code(), "rules.budget.lambda_depth");
}

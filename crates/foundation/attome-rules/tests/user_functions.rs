//! Z11-T8: typed, pure, non-recursive user-defined functions.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{
    BudgetKind, Budgets, Context, FunctionLibrary, LanguageVersion, RulesError, Schema, Type,
    UserFunction, Value, compile_with_library,
};
use chrono::Utc;

fn function(name: &str, params: &[(&str, Type)], returns: Type, body: &str) -> UserFunction {
    UserFunction {
        name: name.to_owned(),
        params: params
            .iter()
            .map(|(p, t)| ((*p).to_owned(), t.clone()))
            .collect(),
        returns,
        body: body.to_owned(),
    }
}

fn library() -> FunctionLibrary {
    FunctionLibrary::build(
        vec![
            // Declared before the function it calls: order comes from the calls.
            function(
                "gross",
                &[("net", Type::Number)],
                Type::Number,
                "net + vat_of(net)",
            ),
            function(
                "vat_of",
                &[("amount", Type::Number)],
                Type::Number,
                "round(amount * 0.15, 2)",
            ),
        ],
        Budgets::default(),
    )
    .unwrap()
}

#[test]
fn user_function_called_from_rule() {
    let schema = Schema::new().with_field("price", Type::Number);
    let rule = compile_with_library(
        "gross(price) > 100",
        &schema,
        LanguageVersion::V2,
        Budgets::default(),
        &library(),
    )
    .unwrap();
    assert_eq!(rule.result_type(), &Type::Bool);
    let ctx = |price: f64| Context::new(Utc::now()).with_field("price", Value::Number(price));
    assert_eq!(
        rule.eval(&ctx(90.0)).unwrap(),
        Value::Bool(true),
        "90 + 13.5"
    );
    assert_eq!(
        rule.eval(&ctx(80.0)).unwrap(),
        Value::Bool(false),
        "80 + 12"
    );
    // A rule that does not pass the library cannot call it.
    let without = attome_rules::compile_versioned(
        "gross(price) > 100",
        &schema,
        LanguageVersion::V2,
        Budgets::default(),
    );
    assert!(matches!(without, Err(RulesError::UnknownFunction(_))));
}

#[test]
fn recursion_is_rejected() {
    let direct = FunctionLibrary::build(
        vec![function("f", &[("x", Type::Number)], Type::Number, "f(x)")],
        Budgets::default(),
    );
    assert!(
        matches!(&direct, Err(RulesError::Recursive(name)) if name == "f"),
        "{direct:?}"
    );
    let mutual = FunctionLibrary::build(
        vec![
            function("a", &[("x", Type::Number)], Type::Number, "b(x) + 1"),
            function("b", &[("x", Type::Number)], Type::Number, "a(x) - 1"),
        ],
        Budgets::default(),
    )
    .unwrap_err();
    assert_eq!(mutual.code(), "rules.function.recursive");
}

#[test]
fn shadowing_builtin_rejected() {
    for name in ["round", "if", "now", "and"] {
        let err = FunctionLibrary::build(
            vec![function(name, &[], Type::Number, "1")],
            Budgets::default(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "rules.function.invalid", "{name}");
    }
    let bad_name = FunctionLibrary::build(
        vec![function("Gross", &[], Type::Number, "1")],
        Budgets::default(),
    );
    assert!(bad_name.is_err());
    let wrong_return = FunctionLibrary::build(
        vec![function("label", &[], Type::Number, "\"text\"")],
        Budgets::default(),
    )
    .unwrap_err();
    assert_eq!(wrong_return.code(), "rules.type.mismatch");
}

#[test]
fn argument_type_checked() {
    let schema = Schema::new().with_field("name", Type::Text);
    let err = compile_with_library(
        "vat_of(name)",
        &schema,
        LanguageVersion::V2,
        Budgets::default(),
        &library(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "rules.type.mismatch");
    let arity = compile_with_library(
        "vat_of(1, 2)",
        &schema,
        LanguageVersion::V2,
        Budgets::default(),
        &library(),
    )
    .unwrap_err();
    assert_eq!(arity.code(), "rules.function.arity");
    // A body sees its parameters only, never the caller's fields.
    let leaky = FunctionLibrary::build(
        vec![function("peek", &[], Type::Text, "name")],
        Budgets::default(),
    )
    .unwrap_err();
    assert_eq!(leaky.code(), "rules.field.unknown");
}

#[test]
fn user_function_steps_charge_caller_budget() {
    let tight = Budgets {
        max_eval_steps: 6,
        ..Budgets::default()
    };
    let schema = Schema::new().with_field("price", Type::Number);
    // `price + 1` alone takes 3 steps; through gross (and vat_of inside it)
    // it takes more than 6, so the caller's budget runs out.
    let plain =
        attome_rules::compile_versioned("price + 1", &schema, LanguageVersion::V2, tight).unwrap();
    let ctx = Context::new(Utc::now()).with_field("price", Value::Number(10.0));
    assert!(plain.eval(&ctx).is_ok());
    let through = compile_with_library(
        "gross(price)",
        &schema,
        LanguageVersion::V2,
        tight,
        &library(),
    )
    .unwrap();
    assert_eq!(
        through.eval(&ctx),
        Err(RulesError::Budget(BudgetKind::EvalSteps))
    );
    let roomy = compile_with_library(
        "gross(price)",
        &schema,
        LanguageVersion::V2,
        Budgets::default(),
        &library(),
    )
    .unwrap();
    assert_eq!(roomy.eval(&ctx).unwrap(), Value::Number(11.5));
}

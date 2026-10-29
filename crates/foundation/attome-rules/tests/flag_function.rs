//! T6-T2: `flag(name)` reads the customer flags on the Context.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashMap;

use attome_rules::{Budgets, Context, LanguageVersion, Schema, Value, compile_versioned};
use chrono::Utc;

fn eval(src: &str, ctx: &Context) -> Value {
    compile_versioned(src, &Schema::new(), LanguageVersion::V2, Budgets::default())
        .expect("compiles")
        .eval(ctx)
        .expect("evaluates")
}

#[test]
fn flag_function_reads_the_context() {
    let ctx = Context::new(Utc::now()).with_flags(HashMap::from([
        ("beta".to_owned(), true),
        ("old".to_owned(), false),
    ]));
    assert_eq!(eval("flag(\"beta\")", &ctx), Value::Bool(true));
    assert_eq!(eval("flag(\"old\")", &ctx), Value::Bool(false));
    assert_eq!(
        eval("flag(\"missing\")", &ctx),
        Value::Bool(false),
        "an unknown flag is off"
    );
    assert_eq!(
        eval("flag(\"beta\")", &Context::new(Utc::now())),
        Value::Bool(false)
    );
}

#[test]
fn flag_function_is_v2_and_takes_text() {
    assert!(
        compile_versioned(
            "flag(\"beta\")",
            &Schema::new(),
            LanguageVersion::V1,
            Budgets::default()
        )
        .is_err()
    );
    assert!(
        compile_versioned(
            "flag(1)",
            &Schema::new(),
            LanguageVersion::V2,
            Budgets::default()
        )
        .is_err()
    );
}

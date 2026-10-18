//! Fuzzes compile-then-eval of V2 text against a fixed schema and context:
//! every step returns a value or a typed error within its budgets.
#![no_main]

use attome_rules::{Budgets, Context, LanguageVersion, Schema, Type, Value, compile_versioned};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };
    let schema = Schema::new()
        .with_field("amount", Type::Number)
        .with_field("name", Type::Text)
        .with_related_list(
            "lines",
            vec![
                ("qty".to_owned(), Type::Number),
                ("sku".to_owned(), Type::Text),
            ],
        );
    if let Ok(compiled) = compile_versioned(src, &schema, LanguageVersion::V2, Budgets::default()) {
        let ctx = Context::new(chrono::Utc::now())
            .with_field("amount", Value::Number(10.0))
            .with_field("name", Value::Text("x".to_owned()))
            .with_related_list(
                "lines",
                vec![vec![
                    ("qty".to_owned(), Value::Number(1.0)),
                    ("sku".to_owned(), Value::Text("A".to_owned())),
                ]],
            );
        let _ = compiled.eval(&ctx);
    }
});

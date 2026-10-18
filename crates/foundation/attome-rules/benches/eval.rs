//! AA14-T1: the rules engine's hot path, a compiled expression evaluated
//! against a record: a 10-term boolean condition and a date expression.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_debug_implementations,
    reason = "a benchmark: a failed setup step should panic with its message"
)]

use attome_rules::{Context, Schema, Type, Value, compile};
use chrono::{TimeZone, Utc};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn schema() -> Schema {
    Schema::new()
        .with_field("amount", Type::Number)
        .with_field("discount", Type::Number)
        .with_field("status", Type::Text)
        .with_field("region", Type::Text)
        .with_field("is_vip", Type::Bool)
        .with_field("closed_on", Type::Date)
        .with_field("name", Type::Text)
}

fn context() -> Context {
    let now = Utc.with_ymd_and_hms(2026, 10, 18, 9, 0, 0).unwrap();
    Context::new(now)
        .with_field("amount", Value::Number(12_500.0))
        .with_field("discount", Value::Number(7.5))
        .with_field("status", Value::Text("won".into()))
        .with_field("region", Value::Text("riyadh".into()))
        .with_field("is_vip", Value::Bool(true))
        .with_field(
            "closed_on",
            Value::Date(Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap()),
        )
        .with_field("name", Value::Text("Acme Trading".into()))
}

fn eval(c: &mut Criterion) {
    let schema = schema();
    let ctx = context();
    // Ten terms joined by and/or.
    let boolean = compile(
        "amount > 1000 and amount < 100000 and discount <= 10 and status == \"won\" \
         and (region == \"riyadh\" or region == \"jeddah\") and is_vip \
         and len(name) > 3 and contains(lower(name), \"acme\") \
         and not is_null(closed_on) and amount * (1 - discount / 100) > 5000",
        &schema,
    )
    .unwrap();
    let date = compile(
        "date_diff(date_add(closed_on, 30, \"days\"), today(), \"days\")",
        &schema,
    )
    .unwrap();
    c.bench_function("rules_eval_boolean_10_terms", |b| {
        b.iter(|| black_box(boolean.eval(black_box(&ctx)).unwrap()))
    });
    c.bench_function("rules_eval_date_expression", |b| {
        b.iter(|| black_box(date.eval(black_box(&ctx)).unwrap()))
    });
}

criterion_group!(benches, eval);
criterion_main!(benches);

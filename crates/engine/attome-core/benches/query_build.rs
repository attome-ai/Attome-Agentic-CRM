//! AA14-T1: building a list query's SQL: five filters through the one filter
//! compiler (`attome_core::filter::compile`) and two sorts, as a list read
//! assembles them.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_debug_implementations,
    reason = "a benchmark: a failed setup step should panic with its message"
)]

use attome_core::filter::{FieldCastError, Filter, FilterSchema, compile};
use attome_core::quote_ident;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;
use std::hint::black_box;

struct Schema;

impl FilterSchema for Schema {
    fn cast(&self, field: &str) -> Result<&'static str, FieldCastError> {
        match field {
            "name" | "status" | "city" => Ok("text"),
            "revenue" => Ok("numeric"),
            "created_at" => Ok("timestamptz"),
            _ => Err(FieldCastError::Unknown),
        }
    }
}

fn filters() -> Vec<Filter> {
    [
        ("name", "contains", json!("acme")),
        ("status", "in", json!(["open", "won"])),
        ("revenue", "gte", json!("100000")),
        ("created_at", "lt", json!("2026-10-01T00:00:00Z")),
        ("city", "eq", json!("Riyadh")),
    ]
    .into_iter()
    .map(|(field, op, value)| Filter {
        field: field.into(),
        op: op.into(),
        value: Some(value),
    })
    .collect()
}

/// The WHERE and ORDER BY of a list query.
fn build(filters: &[Filter], sorts: &[(&str, bool)]) -> String {
    let mut sql = String::from("SELECT id FROM \"account\" t WHERE t.is_active IS NOT FALSE");
    let mut next = 1;
    for filter in filters {
        let (fragment, binds) = compile(filter, &Schema, next).unwrap();
        next += binds.len();
        sql.push_str(" AND ");
        sql.push_str(&fragment);
    }
    sql.push_str(" ORDER BY ");
    let order: Vec<String> = sorts
        .iter()
        .map(|(field, desc)| {
            format!(
                "{} {}",
                quote_ident(field),
                if *desc { "DESC NULLS LAST" } else { "ASC" }
            )
        })
        .collect();
    sql.push_str(&order.join(", "));
    sql
}

fn query_build(c: &mut Criterion) {
    let filters = filters();
    let sorts = [("revenue", true), ("name", false)];
    c.bench_function("list_query_5_filters_2_sorts", |b| {
        b.iter(|| black_box(build(black_box(&filters), black_box(&sorts))))
    });
}

criterion_group!(benches, query_build);
criterion_main!(benches);

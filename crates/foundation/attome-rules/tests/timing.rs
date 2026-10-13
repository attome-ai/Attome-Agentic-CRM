//! BRU-E4 — the M45 S2 timing measurement (≤ 2 ms p95 per record for ≤ 20
//! rules), plus the "a 1 999-node rule evaluates in ≤ 1 ms release" claim,
//! before and after BRU-E1 (eval with no trace vs eval_traced).
//!
//! Ignored by default: it is a measurement, not a gate. Run it on a quiet host
//! with:
//!
//! ```powershell
//! cargo test -p attome-rules --release --test timing -- --ignored --nocapture
//! ```
//!
//! Record the printed numbers (with the hardware line) in a dated evidence
//! note under document/general/evidence/ and link it from M45 S2. A noisy
//! host's numbers are an upper bound, not a pass (plan §10).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Instant;

use attome_rules::{Compiled, Context, Schema, Type, Value, compile};
use chrono::{TimeZone, Utc};

const RULES: [&str; 20] = [
    "amount > 100",
    "amount + 1 > 100",
    "amount * 2 + 1 > 100",
    "amount / 2 > 10",
    "amount % 5 == 0",
    r#"name == "Ada""#,
    r#"lower(name) == "ada""#,
    r#"upper(name) == "ADA""#,
    r#"trim(name) == "Ada""#,
    "len(name) > 2",
    r#"contains(name, "d")"#,
    r#"startswith(name, "A")"#,
    "active and amount > 100",
    "active or amount > 100",
    "if(active, amount * 2, amount) > 100",
    "coalesce(amount, 0) > 100",
    "in(amount, [1, 2, 3, 42])",
    "is_null(amount)",
    r#"date_diff(now(), opened, "days") > 0"#,
    r#"date_add(opened, 10, "days") >= today()"#,
];

fn schema() -> Schema {
    Schema::new()
        .with_field("amount", Type::Number)
        .with_field("name", Type::Text)
        .with_field("active", Type::Bool)
        .with_field("opened", Type::Date)
}

fn context() -> Context {
    Context::new(Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap())
        .with_field("amount", Value::Number(150.0))
        .with_field("name", Value::Text("Ada".to_owned()))
        .with_field("active", Value::Bool(true))
        .with_field(
            "opened",
            Value::Date(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        )
}

/// One 1 999-node rule that the default budgets still admit after BRU-A2: a
/// 1 998-argument min(...) call is 1 999 nodes deep 2, so only the node cap
/// applies.
fn vast_rule() -> String {
    let args = std::iter::repeat_n("1", 1_998)
        .collect::<Vec<_>>()
        .join(", ");
    format!("min({args})")
}

fn percentile(mut samples: Vec<f64>, p: f64) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((samples.len() as f64 - 1.0) * p).round() as usize;
    samples[idx]
}

#[test]
#[ignore = "M45 S2 timing measurement; run with --release -- --ignored --nocapture"]
fn m45_s2_twenty_rules_and_a_large_rule() {
    println!(
        "BRU-E4 host: os={} arch={} profile={}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );

    let schema = schema();
    let ctx = context();
    let compiled: Vec<Compiled> = RULES
        .iter()
        .map(|src| compile(src, &schema).expect("representative rule compiles"))
        .collect();

    // Warm up, then sample per-record times over a batch of records so each
    // sample is a whole record's 20 rules, not one rule.
    for _ in 0..100 {
        for c in &compiled {
            let _ = c.eval(&ctx);
        }
    }
    let batch = 2_000usize;
    let mut samples = Vec::with_capacity(batch);
    for _ in 0..batch {
        let start = Instant::now();
        for c in &compiled {
            let _ = c.eval(&ctx);
        }
        samples.push(start.elapsed().as_secs_f64() * 1_000.0);
    }
    let p95 = percentile(samples.clone(), 0.95);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    println!("BRU-E4 20 rules x 1 record: mean={mean:.4} ms p95={p95:.4} ms (target <= 2 ms p95)");

    // BRU-E1: the same 20 rules with the trace on, to show what eval no longer
    // pays for.
    let batch = 500usize;
    let mut traced = Vec::with_capacity(batch);
    for _ in 0..batch {
        let start = Instant::now();
        for c in &compiled {
            let _ = c.eval_traced(&ctx);
        }
        traced.push(start.elapsed().as_secs_f64() * 1_000.0);
    }
    let traced_p95 = percentile(traced, 0.95);
    println!("BRU-E4 20 rules x 1 record, eval_traced: p95={traced_p95:.4} ms");

    // The 1 999-node rule (node cap only).
    let vast = compile(&vast_rule(), &schema).expect("a 1 999-node rule is inside the node cap");
    let iterations = 20_000usize;
    let start = Instant::now();
    let mut checksum = 0.0;
    for _ in 0..iterations {
        if let Ok(Value::Number(n)) = vast.eval(&ctx) {
            checksum += n;
        }
    }
    let per_eval = start.elapsed().as_secs_f64() * 1_000.0 / iterations as f64;
    println!(
        "BRU-E4 1 999-node rule: {per_eval:.6} ms per eval (target <= 1 ms release), checksum={checksum}"
    );

    // The largest operator chain the depth ceiling admits (127 links, 253
    // nodes, depth 128) — the shape BRU-A2 bounds.
    let chain_src = std::iter::repeat_n("1", 127)
        .collect::<Vec<_>>()
        .join(" + ");
    let chain = compile(&chain_src, &schema).expect("a 127-link chain is admissible");
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = chain.eval(&ctx);
    }
    let chain_eval = start.elapsed().as_secs_f64() * 1_000.0 / iterations as f64;
    let start = Instant::now();
    for _ in 0..1_000 {
        let _ = chain.eval_traced(&ctx);
    }
    let chain_traced = start.elapsed().as_secs_f64() * 1_000.0 / 1_000.0;
    println!(
        "BRU-E4 253-node chain: eval={chain_eval:.6} ms, eval_traced={chain_traced:.6} ms per eval"
    );

    assert!(p95 > 0.0, "the measurement must actually measure something");
}

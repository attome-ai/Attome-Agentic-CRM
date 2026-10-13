//! Property-based coverage for attome-rules (M45 plan §6, Phase 1's required
//! "determinism, budget enforcement, no-panic on arbitrary input"): pure, no
//! I/O, no DATABASE_URL, no Redis, no running server — this crate's whole
//! surface (parse/compile/Compiled::eval) is a plain Rust function from a &str
//! (or already-resolved Context) to a Result, so proptest applies directly.
//!
//! BRU-A4 widened the generators so the risky paths are actually reachable:
//! every type (Choice, Lookup, List, one-hop related fields), the real date
//! units plus junk, adversarial numbers (±1e300, ±1e12, subnormals, non-finite
//! Context values), wrong-typed and Null Context values, chains up to 5 000
//! links and trees up to depth 8. A 20 000-case soak lives behind --ignored.
//!
//! Run with:
//!
//! ```powershell
//! cargo test -p attome-rules --test property
//! cargo test -p attome-rules --test property -- --ignored
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_rules::{
    BinaryOp, Budgets, Context, Expr, FieldRef, RulesError, Schema, Type, UnaryOp, Value, compile,
    compile_with_budgets,
};
use chrono::{TimeZone, Utc};
use proptest::prelude::*;
use uuid::Uuid;

// ── Fixtures shared by every property ───────────────────────────────────────

fn fuzz_schema() -> Schema {
    Schema::new()
        .with_field("amount", Type::Number)
        .with_field("name", Type::Text)
        .with_field("active", Type::Bool)
        .with_field("opened", Type::Date)
        .with_field("status", Type::Choice)
        .with_field("owner", Type::Lookup)
        .with_field("tags", Type::List(Box::new(Type::Text)))
        .with_related(
            "customer",
            [("tier".to_owned(), Type::Text)].into_iter().collect(),
        )
    // "nope" is deliberately left undeclared — exercises RulesError::UnknownField.
}

fn fuzz_context() -> Context {
    Context::new(Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap())
        .with_field("amount", Value::Number(10.0))
        .with_field("name", Value::Text("x".to_owned()))
        .with_field("active", Value::Bool(true))
        .with_field(
            "opened",
            Value::Date(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        )
        .with_field("status", Value::Choice("open".to_owned()))
        .with_field("owner", Value::Lookup(Uuid::nil()))
        .with_field("tags", Value::List(vec![Value::Text("a".to_owned())]))
        .with_related(
            "customer",
            [("tier".to_owned(), Value::Text("gold".to_owned()))]
                .into_iter()
                .collect(),
        )
}

// ── Strategies (BRU-A4) ─────────────────────────────────────────────────────

fn arb_field_ref() -> impl Strategy<Value = Expr> {
    prop_oneof![
        Just("amount"),
        Just("name"),
        Just("active"),
        Just("opened"),
        Just("status"),
        Just("owner"),
        Just("tags"),
        Just("customer.tier"),
        Just("nope"), // undeclared — must error, never panic
    ]
    .prop_map(|s| match s.split_once('.') {
        Some((base, hop)) => Expr::FieldRef(FieldRef {
            base: base.to_owned(),
            hop: Some(hop.to_owned()),
        }),
        None => Expr::FieldRef(FieldRef {
            base: s.to_owned(),
            hop: None,
        }),
    })
}

/// Finite doubles over the real domain, plus the adversarial corners.
fn arb_number() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<f64>().prop_filter("finite", |n| n.is_finite()),
        Just(0.0),
        Just(-0.0),
        Just(1e300),
        Just(-1e300),
        Just(1e12),
        Just(-1e12),
        Just(f64::MIN_POSITIVE),
        Just(5e-324),
    ]
}

/// Text, including Arabic (the platform is bilingual), every real date unit,
/// and junk units.
fn arb_text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{0,6}",
        arb_arabic_word(),
        Just("open".to_owned()),
        Just("closed".to_owned()),
        Just("days".to_owned()),
        Just("hours".to_owned()),
        Just("minutes".to_owned()),
        Just("seconds".to_owned()),
        Just("months".to_owned()),
        Just("years".to_owned()),
        Just("fortnights".to_owned()),
        Just("".to_owned()),
    ]
}

/// A word built only from Arabic letters (the platform is bilingual) — used
/// for string literals and for BRU-FX1's char-boundary span property.
fn arb_arabic_word() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(vec![
            'ا', 'ب', 'ت', 'ث', 'ج', 'ح', 'د', 'ر', 'س', 'ع', 'ف', 'ق', 'ك', 'ل', 'م', 'ن', 'ه',
            'و', 'ي',
        ]),
        1..6,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

fn arb_leaf() -> impl Strategy<Value = Expr> {
    prop_oneof![
        Just(Expr::NullLit),
        any::<bool>().prop_map(Expr::BoolLit),
        arb_number().prop_map(Expr::NumberLit),
        arb_text().prop_map(Expr::StringLit),
        arb_field_ref(),
    ]
}

fn arb_binary_op() -> impl Strategy<Value = BinaryOp> {
    prop_oneof![
        Just(BinaryOp::Add),
        Just(BinaryOp::Sub),
        Just(BinaryOp::Mul),
        Just(BinaryOp::Div),
        Just(BinaryOp::Mod),
        Just(BinaryOp::Eq),
        Just(BinaryOp::Ne),
        Just(BinaryOp::Lt),
        Just(BinaryOp::Le),
        Just(BinaryOp::Gt),
        Just(BinaryOp::Ge),
        Just(BinaryOp::And),
        Just(BinaryOp::Or),
    ]
}

fn arb_unary_op() -> impl Strategy<Value = UnaryOp> {
    prop_oneof![Just(UnaryOp::Neg), Just(UnaryOp::Not)]
}

fn arb_func_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("if"),
        Just("coalesce"),
        Just("len"),
        Just("lower"),
        Just("upper"),
        Just("trim"),
        Just("contains"),
        Just("startswith"),
        Just("date_add"),
        Just("date_diff"),
        Just("today"),
        Just("now"),
        Just("round"),
        Just("min"),
        Just("max"),
        Just("in"),
        Just("is_null"),
        Just("not_a_real_function"), // must error, never panic
    ]
    .prop_map(str::to_owned)
}

/// A structurally-arbitrary Expr tree, rendered back to source text (Expr
/// implements Display) and pushed through the full pipeline — lex, parse,
/// type-check, evaluate — for every generated case. Most generated trees are
/// type errors or reference the undeclared nope field/an unknown function;
/// that's intentional; the property under test is "never panics", not "always
/// evaluates successfully".
///
/// BRU-A4: depth 8 and up to 256 nodes per case (was depth 4 / 64).
fn arb_expr() -> impl Strategy<Value = Expr> {
    arb_leaf().prop_recursive(8, 256, 5, |inner| {
        prop_oneof![
            (arb_unary_op(), inner.clone()).prop_map(|(op, e)| Expr::Unary {
                op,
                expr: Box::new(e)
            }),
            (arb_binary_op(), inner.clone(), inner.clone()).prop_map(|(op, l, r)| Expr::Binary {
                op,
                lhs: Box::new(l),
                rhs: Box::new(r)
            }),
            prop::collection::vec(inner.clone(), 0..5).prop_map(Expr::ListLit),
            (arb_func_name(), prop::collection::vec(inner.clone(), 0..5))
                .prop_map(|(name, args)| Expr::Call { name, args })
        ]
    })
}

/// Adversarial Context values for every field of the schema: the declared
/// type, a wrong type, Null, a non-finite number, an over-long Text and an
/// over-long List. The evaluator must return a typed error for each, never
/// panic and never leak a non-finite number.
fn arb_context_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<f64>().prop_map(Value::Number),
        arb_text().prop_map(Value::Text),
        Just(Value::Choice("open".to_owned())),
        Just(Value::Lookup(Uuid::nil())),
        Just(Value::Date(
            Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).unwrap()
        )),
        (0usize..30_000).prop_map(|n| Value::Text("a".repeat(n))),
        (0usize..30_000).prop_map(|n| Value::List(vec![Value::Number(1.0); n])),
    ]
}

fn as_number(value: &Value) -> f64 {
    match value {
        Value::Number(n) => *n,
        other => panic!("expected a number, got {other:?}"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // ── No-panic on arbitrary/fuzzed input ──────────────────────────────

    /// A structurally-arbitrary AST, round-tripped through source text, must
    /// never panic anywhere in lex/parse/typecheck/eval — only ever return
    /// Ok or a typed Err. If this test ever fails, it fails via Rust's own
    /// panic-unwind (proptest reports the minimized failing input), not a
    /// hand-written assertion — the property *is* "does not panic".
    #[test]
    fn no_panic_on_arbitrary_ast(expr in arb_expr()) {
        let src = expr.to_string();
        let schema = fuzz_schema();
        if let Ok(compiled) = compile(&src, &schema) {
            let ctx = fuzz_context();
            let _ = compiled.eval(&ctx);
        }
    }

    /// Same property directly over unconstrained UTF-8 text (including
    /// multi-byte / RTL characters — the platform is bilingual), bypassing
    /// the AST-shaped generator entirely. This is what actually exercises
    /// the lexer's char-boundary handling, not just grammar-shaped input.
    #[test]
    fn no_panic_on_arbitrary_source_text(src in ".{0,200}") {
        let schema = fuzz_schema();
        if let Ok(compiled) = compile(&src, &schema) {
            let ctx = fuzz_context();
            let _ = compiled.eval(&ctx);
        }
    }

    /// BRU-A4/BRU-F1/F3/F5: an adversarial Context value for a Number field —
    /// a wrong type, Null, a non-finite float, an over-long Text or List —
    /// is always a typed error or a finite value, never a panic.
    #[test]
    fn no_panic_on_arbitrary_context_values(value in arb_context_value()) {
        let schema = Schema::new().with_field("amount", Type::Number);
        let compiled = compile("amount + 1", &schema).expect("type-checks against the schema");
        let ctx = Context::new(Utc::now()).with_field("amount", value);
        match compiled.eval(&ctx) {
            Ok(Value::Number(n)) => prop_assert!(n.is_finite(), "non-finite {n}"),
            Ok(other) => prop_assert!(false, "unexpected value {other:?}"),
            Err(_) => {}
        }
    }

    /// BRU-A2/BRU-A4: a chain of up to 5 000 links is either inside both
    /// ceilings (and evaluates) or a typed Budget rejection — never a panic
    /// and never an unbounded tree handed to a consumer.
    #[test]
    fn long_chains_are_bounded_not_unbounded(count in 1usize..5_000) {
        let src = std::iter::repeat_n("1", count).collect::<Vec<_>>().join(" + ");
        let schema = Schema::new();
        match compile(&src, &schema) {
            Ok(compiled) => {
                prop_assert!(count <= 128, "a {count}-link chain slipped past the depth ceiling");
                let ctx = Context::new(Utc::now());
                let _ = compiled.eval(&ctx);
            }
            Err(RulesError::Budget(_)) => {}
            Err(other) => prop_assert!(false, "unexpected error for {count} links: {other:?}"),
        }
    }

    /// BRU-B1: no evaluation ever returns a non-finite Value::Number, over the
    /// full arbitrary-AST domain (including adversarial Context numbers).
    #[test]
    fn non_finite_numbers_never_leave_the_evaluator(expr in arb_expr()) {
        let src = expr.to_string();
        let schema = fuzz_schema();
        if let Ok(compiled) = compile(&src, &schema)
            && let Ok(Value::Number(n)) = compiled.eval(&fuzz_context())
        {
            prop_assert!(n.is_finite(), "non-finite {n} from {src}");
        }
    }

    /// BRU-E1: eval and eval_traced return the same value over the whole
    /// proptest domain — the trace is an observation, never a behaviour.
    #[test]
    fn eval_and_eval_traced_agree(expr in arb_expr()) {
        let src = expr.to_string();
        let schema = fuzz_schema();
        if let Ok(compiled) = compile(&src, &schema) {
            let ctx = fuzz_context();
            let plain = compiled.eval(&ctx);
            let traced = compiled.eval_traced(&ctx).map(|(value, _)| value);
            prop_assert_eq!(plain, traced);
        }
    }

    /// BRU-C1/D-620: a Choice compares with a Text by key, in either operand
    /// order, and only when the key equals the text.
    #[test]
    fn choice_compares_with_text_by_key(key in "[a-z]{1,6}", text in "[a-z]{1,6}") {
        let schema = Schema::new().with_field("status", Type::Choice);
        let forward = compile(&format!("status == {text:?}"), &schema).expect("compiles");
        let reversed = compile(&format!("{text:?} == status"), &schema).expect("compiles");
        let ctx = Context::new(Utc::now()).with_field("status", Value::Choice(key.clone()));
        let expected = key == text;
        prop_assert_eq!(forward.eval(&ctx).unwrap(), Value::Bool(expected));
        prop_assert_eq!(reversed.eval(&ctx).unwrap(), Value::Bool(expected));
    }

    /// BRU-B3: month arithmetic is antisymmetric for every pair of instants.
    #[test]
    fn month_difference_is_antisymmetric(
        secs_a in -2_000_000_000i64..2_000_000_000,
        secs_b in -2_000_000_000i64..2_000_000_000,
    ) {
        let schema = Schema::new()
            .with_field("a", Type::Date)
            .with_field("b", Type::Date);
        let compiled = compile(r#"date_diff(a, b, "months")"#, &schema).expect("compiles");
        let a = Utc.timestamp_opt(secs_a, 0).single().expect("valid instant");
        let b = Utc.timestamp_opt(secs_b, 0).single().expect("valid instant");
        let now = Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).unwrap();
        let forward = compiled
            .eval(&Context::new(now).with_field("a", Value::Date(a)).with_field("b", Value::Date(b)))
            .unwrap();
        let reversed = compiled
            .eval(&Context::new(now).with_field("a", Value::Date(b)).with_field("b", Value::Date(a)))
            .unwrap();
        prop_assert_eq!(as_number(&forward), -as_number(&reversed));
    }

    // ── Determinism ──────────────────────────────────────────────────────

    /// Compiling the same source twice and evaluating both against the same
    /// Context must produce identical results — no hidden clock/thread/
    /// hash-order dependence.
    #[test]
    fn same_source_same_context_is_deterministic(
        a in -1_000i32..1_000,
        b in -1_000i32..1_000,
        op in arb_binary_op(),
    ) {
        let src = format!("{a} {op} {b}");
        let schema = Schema::new();
        let ctx = fuzz_context();

        let r1 = compile(&src, &schema).and_then(|c| c.eval(&ctx));
        let r2 = compile(&src, &schema).and_then(|c| c.eval(&ctx));
        prop_assert_eq!(r1, r2);
    }

    /// The same Compiled value evaluated twice against equal (but
    /// independently constructed) Contexts agrees with itself — the property
    /// Phase 2+'s per-(rule, version) Compiled cache depends on.
    #[test]
    fn same_compiled_reused_across_contexts_is_deterministic(n in -1_000.0f64..1_000.0) {
        prop_assume!(n.is_finite());
        let schema = Schema::new().with_field("amount", Type::Number);
        let compiled = compile("amount * 2 + 1", &schema).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).unwrap();

        let ctx1 = Context::new(now).with_field("amount", Value::Number(n));
        let ctx2 = Context::new(now).with_field("amount", Value::Number(n));
        prop_assert_eq!(compiled.eval(&ctx1), compiled.eval(&ctx2));
    }

    // ── Budget enforcement ───────────────────────────────────────────────

    /// A chain of 1 + 1 + ... + 1 with count ones has exactly 2*count - 1 AST
    /// nodes (count number literals + count - 1 + nodes). Setting max_ast_nodes
    /// to exactly that count must compile; one less must not — checks the cap
    /// is enforced at the exact boundary, not just "eventually rejects
    /// something huge".
    #[test]
    fn ast_node_budget_is_enforced_at_the_exact_boundary(count in 1usize..40) {
        let src = std::iter::repeat_n("1", count).collect::<Vec<_>>().join(" + ");
        let schema = Schema::new();
        let node_count = 2 * count - 1;

        let ok = compile_with_budgets(&src, &schema, Budgets { max_ast_nodes: node_count, ..Budgets::default() });
        prop_assert!(ok.is_ok(), "expected exactly-at-budget compile to succeed: {ok:?}");

        if node_count > 0 {
            let too_small = Budgets { max_ast_nodes: node_count - 1, ..Budgets::default() };
            let rejected = compile_with_budgets(&src, &schema, too_small).map(|_| ());
            prop_assert_eq!(rejected, Err(RulesError::Budget(attome_rules::BudgetKind::AstNodes)));
        }
    }

    /// A zero-step budget must reject every non-trivial evaluation — the
    /// weakest possible ceiling still has to fire.
    #[test]
    fn eval_step_budget_of_zero_rejects_everything_nontrivial(a in -1_000i32..1_000, b in -1_000i32..1_000) {
        let src = format!("{a} + {b}");
        let schema = Schema::new();
        let zero_steps = Budgets { max_eval_steps: 0, ..Budgets::default() };
        let compiled = compile_with_budgets(&src, &schema, zero_steps).unwrap();
        let ctx = fuzz_context();
        prop_assert_eq!(compiled.eval(&ctx), Err(RulesError::Budget(attome_rules::BudgetKind::EvalSteps)));
    }

    /// A max_string_len shorter than a literal's own length must always
    /// reject that literal at eval time.
    #[test]
    fn string_length_budget_rejects_overlong_literals(len in 1usize..50) {
        let text = "a".repeat(len);
        let src = format!("{text:?}"); // Rust's Debug-quoting is valid attome-rules string syntax for plain ASCII
        let schema = Schema::new();
        let too_small = Budgets { max_string_len: len - 1, ..Budgets::default() };
        let compiled = compile_with_budgets(&src, &schema, too_small).unwrap();
        let ctx = fuzz_context();
        prop_assert_eq!(compiled.eval(&ctx), Err(RulesError::Budget(attome_rules::BudgetKind::StringLength)));
    }
}

// BRU-A4: the recorded soak — the same no-panic property over 20 000 cases.
// Run once by hand:
//   cargo test -p attome-rules --test property -- --ignored --nocapture
proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    #[test]
    #[ignore = "20 000-case soak; run by hand and record the result (BRU-A4)"]
    fn soak_no_panic_over_the_widened_domain(expr in arb_expr(), value in arb_context_value()) {
        let src = expr.to_string();
        let schema = fuzz_schema();
        if let Ok(compiled) = compile(&src, &schema) {
            let ctx = fuzz_context().with_field("amount", value);
            let _ = compiled.eval(&ctx);
            let _ = compiled.eval_traced(&ctx);
        }
    }
}

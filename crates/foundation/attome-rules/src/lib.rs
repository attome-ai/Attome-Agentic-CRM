//! attome-rules — M45 Phase 1 (document/xrm/module/M45-rules-engine/master-plan.md,
//! document/decisions/foundation/D-399.md): the platform's single sandboxed
//! expression evaluator. Every part of the platform that needs to answer "does
//! this condition hold / what is this value" from an admin-editable expression
//! uses this crate instead of growing its own bespoke condition mechanism — the
//! four that already exist (field validation, workflow conditions, privilege
//! conditions, dashboard variables) are the retrofit targets for Phases 2-4,
//! not this crate's concern.
//!
//! **Grammar (v1, plan §5):** + - * / %, comparisons (== != < <= > >=),
//! and or not, if(c,a,b), coalesce(...), len, lower/upper/trim,
//! contains/startswith, date_add, date_diff, today()/now(), round, min/max,
//! in(...), is_null. Field refs field_name and one-hop lookup_field.target_field.
//! List literals [a, b, c]. No user-defined functions, no loops, no recursion
//! into user code, and deliberately **no regex** (ReDoS surface — plan §5/§10).
//!
//! **Layering.** crates/base/attome-rules has zero xrm-* dependencies (the
//! layer rule, held by review since D-768) and zero I/O of any kind: parsing, type-checking, and
//! evaluation are pure functions over already-resolved data. A one-hop lookup
//! reference is satisfied only if the caller pre-populated it into [Context]
//! via with_related — this crate never queries anything itself. See
//! context.rs's header for why that's the actual mechanism behind "rules are
//! pure and I/O-free", not just a docstring claim.
//!
//! **Parser choice.** Hand-written recursive descent, not pest/chumsky. The
//! grammar above is small, fixed, and unlikely to grow features the plan
//! doesn't already list (plan §9, "scope creep toward a scripting language
//! ... needs a decision entry") — a parser-combinator or PEG dependency buys
//! generality this crate has no use for, at the cost of a dependency whose
//! parsing behavior (whitespace handling, error recovery, operator precedence
//! via grammar rules rather than code) is opaque to a reader who doesn't
//! already know that crate. A hand-written parser is easier to audit
//! line-by-line for the one property that matters most here — that it can
//! never panic or run away — than a grammar file generating code neither this
//! crate's author nor its reviewer wrote. document/decisions/foundation/D-399.md
//! records this as the binding choice; revisiting it needs a new decision, not
//! a drive-by dependency swap.
//!
//! **Budgets.** [budget::Budgets] holds the five caller-configurable ceilings
//! (AST node cap, eval step cap, wall-clock ceiling, max string length, max
//! list length); [budget::HARD_MAX_SOURCE_BYTES], [budget::HARD_MAX_DEPTH] and
//! [budget::HARD_MAX_NODES] are non-configurable floors that protect the
//! parser itself. Every one of these failure modes is [RulesError::Budget].
//!
//! **No panics, no stack overflow (BRU-A1/BRU-A2).** The source ceiling is
//! checked before lexing; structural nesting, every operator-chain link, and
//! the AST node count are checked *while parsing*; chrono's checked
//! constructors replace the panicking ones in date_add; and every numeric
//! result is finite (BRU-B1). tests/property.rs proves "returns a typed
//! result, never panics" over arbitrary source text, and tests/deep_chain.rs
//! proves it on a **2 MiB worker-sized stack** — the stack a tokio worker
//! (and therefore any request handler) actually has — in a child process, so a
//! stack overflow fails a clean assertion instead of aborting the run.
//!
//! **Stable error codes (BRU-FX2).** [RulesError::code] returns one of:
//! rules.parse.unexpected_token, rules.type.mismatch, rules.field.unknown,
//! rules.lookup.multi_hop, rules.function.unknown, rules.function.arity,
//! rules.eval.divide_by_zero, rules.eval.failed, rules.number.non_finite,
//! rules.null.operand, rules.context.type_mismatch,
//! rules.context.unknown_timezone, and one code per budget
//! kind (rules.budget.ast_nodes, rules.budget.recursion_depth,
//! rules.budget.eval_steps, rules.budget.wall_clock, rules.budget.string_length,
//! rules.budget.source_length, rules.budget.list_length).
//! The bilingual admin UI translates those; the English Display stays for logs.
//! [RulesError::is_transient] is true only for a wall-clock trip, so a consumer
//! can map a load-dependent failure to a retry (503) rather than a rule
//! violation (422) — BRU-E3/BRU-D5.
//!
//! **Time zones (BRU-C4).** A [Context] carries the caller's IANA zone —
//! [chrono_tz::Tz], re-exported here as [Tz] — with UTC as the default, so a
//! caller that sets nothing behaves exactly as before. [Context::with_timezone]
//! (or [Context::with_timezone_name] for a configured string) makes today() the
//! caller's local midnight converted to UTC and makes month/year arithmetic
//! read local calendar fields; day/hour/minute arithmetic stays an exact
//! duration. An unknown zone name is [RulesError::UnknownTimezone], never a
//! silent fall-back to UTC (BRU-D4 leaves the choice of zone to the caller).
//!
//! **Spans (BRU-FX1).** The parser records a pre-order [Spans] table, and a
//! compile failure is internally a [RulesDiagnostic] (a [RulesError] plus the
//! byte span of the sub-expression that produced it); the public compile
//! entry points return the plain [RulesError].
//! Spans deliberately do not live on Expr: that would break xrm-metric's
//! collect_field_refs and every test that builds an Expr by hand (plan §9).
//!
//! **Quick start:**
//!
//! ```
//! use attome_rules::{Context, Schema, Type, Value, compile};
//! use chrono::Utc;
//!
//! let schema = Schema::new().with_field("amount", Type::Number);
//! let compiled = compile("amount > 100", &schema).expect("valid rule");
//!
//! let ctx = Context::new(Utc::now()).with_field("amount", Value::Number(150.0));
//! assert_eq!(compiled.eval(&ctx).unwrap(), Value::Bool(true));
//! ```

mod ast;
mod budget;
mod compile;
mod context;
mod error;
mod eval;
mod lexer;
mod parser;
mod trace;
mod typecheck;
mod value;

pub use ast::{BinaryOp, Expr, FieldRef, UnaryOp};
pub use budget::{Budgets, HARD_MAX_DEPTH, HARD_MAX_NODES, HARD_MAX_SOURCE_BYTES};
pub use chrono_tz::Tz;
pub use compile::{Compiled, compile, compile_with_budgets};
pub use context::{Context, Schema};
pub use error::{BudgetKind, RulesDiagnostic, RulesError, Spans};
pub use trace::{Trace, TraceEntry};
pub use value::{Type, Value};

/// Parses src without type-checking or compiling it — exposed for callers
/// that only need syntax validation (e.g. an admin UI's live-typing
/// feedback) without a Schema on hand yet. compile/compile_with_budgets are
/// the entry point for anything that will actually be evaluated.
///
/// The returned tree is bounded by the same hard ceilings compile applies
/// (BRU-A2), so a consumer's recursive walk over it cannot overflow the stack.
pub fn parse(src: &str) -> Result<Expr, RulesError> {
    parser::parse(src, &Budgets::default())
}

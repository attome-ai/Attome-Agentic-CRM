//! The tree-walking evaluator. No loops, no recursion into user code, no
//! I/O — the only way this module reaches outside its own call stack is
//! reading already-resolved values out of Context (M45 plan §3.1, Pure).
//!
//! Every recursive call goes through Evaluator::eval, which enforces the
//! runtime budgets (structural depth and node count are already bounded by the
//! parser — see parser.rs):
//!
//! - step() increments a counter once per node and checks it against
//!   Budgets::max_eval_steps.
//! - step() also re-checks the wall clock against Budgets::max_wall_clock on
//!   every call — cheap (Instant::now() is tens of nanoseconds) relative to
//!   the work being bounded.
//! - Every Value::Text this module constructs (literals, concatenation,
//!   lower/upper/trim) is checked against Budgets::max_string_len, and since
//!   BRU-E2 so are Text and List values arriving through Context (the list
//!   against Budgets::max_list_len).
//!
//! **BRU-E1**: Compiled::eval records no trace at all — it renders nothing and
//! clones nothing. The trace is only built by Compiled::eval_traced, which is
//! what the admin /test endpoint reads.
//!
//! **BRU-C2a (BRU-D2)**: a null operand reaching an operator that cannot
//! accept one is RulesError::NullOperand { op }, not a generic Eval string.
//! **BRU-C3**: a Context value whose runtime type is neither the type compile
//! was given for that field nor Null is RulesError::ContextTypeMismatch.
//! **BRU-B1**: every numeric result is finite (RulesError::NumericOverflow).
//! **BRU-A1**: date_add uses chrono's checked constructors and never panics.
//! **BRU-B3**: date_diff by months is antisymmetric.
//! **BRU-C4**: today() is the caller's LOCAL midnight converted to UTC, and
//! date_add/date_diff by months/years read the caller's local calendar fields
//! (Context::with_timezone); UTC is the default, so nothing changes for a
//! caller that does not set a zone, and day/hour/minute arithmetic stays an
//! exact duration.
//!
//! if, coalesce, and and/or short-circuit: the untaken branch is never
//! evaluated, never counted against the step budget, and never recorded in
//! the Trace — matching normal expression-language semantics and keeping the
//! trace a record of what actually ran.

use std::cmp::Ordering;
use std::time::Instant;

use chrono::{DateTime, Datelike, MappedLocalTime, Months, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;

use crate::ast::{BinaryOp, Expr, UnaryOp};
use crate::budget::Budgets;
use crate::context::{Context, Schema};
use crate::error::{BudgetKind, RulesError};
use crate::trace::Trace;
use crate::value::Value;

/// Evaluates without building a trace — the hot path (every record write with
/// a rule or formula, every matching event, every TRD bar). BRU-E1: no node is
/// rendered and no value is cloned for a trace nobody reads.
pub(crate) fn eval(
    expr: &Expr,
    ctx: &Context,
    budgets: &Budgets,
    schema: &Schema,
) -> Result<Value, RulesError> {
    run(expr, ctx, budgets, schema, false).map(|(value, _)| value)
}

/// Evaluates and records the trace — used by the admin "test this rule"
/// surface, never on the write path.
pub(crate) fn eval_traced(
    expr: &Expr,
    ctx: &Context,
    budgets: &Budgets,
    schema: &Schema,
) -> Result<(Value, Trace), RulesError> {
    run(expr, ctx, budgets, schema, true)
}

fn run(
    expr: &Expr,
    ctx: &Context,
    budgets: &Budgets,
    schema: &Schema,
    record_trace: bool,
) -> Result<(Value, Trace), RulesError> {
    let mut evaluator = Evaluator {
        ctx,
        budgets,
        schema,
        steps: 0,
        start: Instant::now(),
        record_trace,
    };
    let mut trace = Trace::default();
    let value = evaluator.eval(expr, &mut trace)?;
    Ok((value, trace))
}

struct Evaluator<'a> {
    ctx: &'a Context,
    budgets: &'a Budgets,
    schema: &'a Schema,
    steps: usize,
    start: Instant,
    record_trace: bool,
}

impl Evaluator<'_> {
    fn step(&mut self) -> Result<(), RulesError> {
        self.steps += 1;
        if self.steps > self.budgets.max_eval_steps {
            return Err(RulesError::Budget(BudgetKind::EvalSteps));
        }
        if self.start.elapsed() > self.budgets.max_wall_clock {
            return Err(RulesError::Budget(BudgetKind::WallClock));
        }
        Ok(())
    }

    fn eval(&mut self, expr: &Expr, trace: &mut Trace) -> Result<Value, RulesError> {
        self.step()?;
        let value = self.eval_inner(expr, trace)?;
        if self.record_trace {
            trace.push(expr.to_string(), value.clone());
        }
        Ok(value)
    }

    fn eval_inner(&mut self, expr: &Expr, trace: &mut Trace) -> Result<Value, RulesError> {
        match expr {
            Expr::NullLit => Ok(Value::Null),
            Expr::BoolLit(b) => Ok(Value::Bool(*b)),
            // A literal is finite by construction (the lexer rejects an
            // overflowing one, BRU-B1); check anyway so a hand-built Expr
            // cannot leak a non-finite Number through the evaluator.
            Expr::NumberLit(n) => finite(*n).map(Value::Number),
            Expr::StringLit(s) => mk_text(s.clone(), self.budgets),
            Expr::ListLit(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.eval(item, trace)?);
                }
                Ok(Value::List(out))
            }
            Expr::FieldRef(r) => match &r.hop {
                None => self.context_value(&r.base, None),
                Some(hop) => self.context_value(&r.base, Some(hop)),
            },
            Expr::Unary { op, expr } => {
                let v = self.eval(expr, trace)?;
                match (op, v) {
                    (UnaryOp::Neg, Value::Number(n)) => finite(-n).map(Value::Number),
                    (UnaryOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
                    (UnaryOp::Neg, other) => Err(null_or_type_err("unary '-'", "number", &other)),
                    (UnaryOp::Not, other) => Err(null_or_type_err("'not'", "bool", &other)),
                }
            }
            Expr::Binary { op, lhs, rhs } => self.eval_binary(*op, lhs, rhs, trace),
            Expr::Call { name, args } => self.eval_call(name, args, trace),
        }
    }

    /// Resolves a field or one-hop lookup reference out of Context and applies
    /// BRU-E2's context budgets and BRU-C3's type conformance.
    fn context_value(&self, base: &str, hop: Option<&str>) -> Result<Value, RulesError> {
        let (label, value, declared) = match hop {
            None => {
                let value = self
                    .ctx
                    .field(base)
                    .cloned()
                    .ok_or_else(|| RulesError::UnknownField(base.to_owned()))?;
                (
                    base.to_owned(),
                    value,
                    self.schema.field_type(base).cloned(),
                )
            }
            Some(hop) => {
                let value = self
                    .ctx
                    .related_field(base, hop)
                    .cloned()
                    .ok_or_else(|| RulesError::UnknownField(format!("{base}.{hop}")))?;
                (
                    format!("{base}.{hop}"),
                    value,
                    self.schema.related_field_type(base, hop).cloned(),
                )
            }
        };

        match &value {
            Value::Number(n) if !n.is_finite() => return Err(RulesError::NumericOverflow),
            Value::Text(s) if s.chars().count() > self.budgets.max_string_len => {
                return Err(RulesError::Budget(BudgetKind::StringLength));
            }
            Value::List(items) if items.len() > self.budgets.max_list_len => {
                return Err(RulesError::Budget(BudgetKind::ListLength));
            }
            _ => {}
        }

        if let Some(declared) = declared
            && !value.is_null()
            && value.ty().unify(&declared).as_ref() != Some(&declared)
        {
            return Err(RulesError::ContextTypeMismatch { field: label });
        }
        Ok(value)
    }

    fn eval_binary(
        &mut self,
        op: BinaryOp,
        lhs: &Expr,
        rhs: &Expr,
        trace: &mut Trace,
    ) -> Result<Value, RulesError> {
        match BinaryKind::of(op) {
            BinaryKind::ShortCircuit(kind) => self.eval_short_circuit(kind, lhs, rhs, trace),
            BinaryKind::Eager(eager) => {
                let l = self.eval(lhs, trace)?;
                let r = self.eval(rhs, trace)?;
                eval_eager(eager, l, r, self.budgets)
            }
        }
    }

    fn eval_short_circuit(
        &mut self,
        kind: ShortCircuitOp,
        lhs: &Expr,
        rhs: &Expr,
        trace: &mut Trace,
    ) -> Result<Value, RulesError> {
        let l = self.eval(lhs, trace)?;
        match kind {
            ShortCircuitOp::And => match l {
                Value::Bool(false) => Ok(Value::Bool(false)),
                Value::Bool(true) => match self.eval(rhs, trace)? {
                    Value::Bool(b) => Ok(Value::Bool(b)),
                    other => Err(null_or_type_err("'and'", "bool", &other)),
                },
                other => Err(null_or_type_err("'and'", "bool", &other)),
            },
            ShortCircuitOp::Or => match l {
                Value::Bool(true) => Ok(Value::Bool(true)),
                Value::Bool(false) => match self.eval(rhs, trace)? {
                    Value::Bool(b) => Ok(Value::Bool(b)),
                    other => Err(null_or_type_err("'or'", "bool", &other)),
                },
                other => Err(null_or_type_err("'or'", "bool", &other)),
            },
        }
    }

    fn eval_call(
        &mut self,
        name: &str,
        args: &[Expr],
        trace: &mut Trace,
    ) -> Result<Value, RulesError> {
        match name {
            "if" => {
                if args.len() != 3 {
                    return Err(arity_err(name, "3", args.len()));
                }
                match self.eval(&args[0], trace)? {
                    Value::Bool(true) => self.eval(&args[1], trace),
                    Value::Bool(false) => self.eval(&args[2], trace),
                    other => Err(eval_type_err("if's condition", "bool", &other)),
                }
            }
            "coalesce" => {
                if args.is_empty() {
                    return Err(arity_err(name, ">= 1", 0));
                }
                for a in args {
                    let v = self.eval(a, trace)?;
                    if !v.is_null() {
                        return Ok(v);
                    }
                }
                Ok(Value::Null)
            }
            "len" => {
                let v = self.eval_only(args, 1, name, trace)?;
                if let Some(e) = null_operand_if_any(name, &v) {
                    return Err(e);
                }
                match &v[0] {
                    Value::Text(s) => Ok(Value::Number(s.chars().count() as f64)),
                    Value::List(items) => Ok(Value::Number(items.len() as f64)),
                    other => Err(eval_type_err("len", "text or list", other)),
                }
            }
            "lower" => {
                let v = self.eval_only(args, 1, name, trace)?;
                if let Some(e) = null_operand_if_any(name, &v) {
                    return Err(e);
                }
                match &v[0] {
                    Value::Text(s) => mk_text(s.to_lowercase(), self.budgets),
                    other => Err(eval_type_err("lower", "text", other)),
                }
            }
            "upper" => {
                let v = self.eval_only(args, 1, name, trace)?;
                if let Some(e) = null_operand_if_any(name, &v) {
                    return Err(e);
                }
                match &v[0] {
                    Value::Text(s) => mk_text(s.to_uppercase(), self.budgets),
                    other => Err(eval_type_err("upper", "text", other)),
                }
            }
            "trim" => {
                let v = self.eval_only(args, 1, name, trace)?;
                if let Some(e) = null_operand_if_any(name, &v) {
                    return Err(e);
                }
                match &v[0] {
                    Value::Text(s) => mk_text(s.trim().to_owned(), self.budgets),
                    other => Err(eval_type_err("trim", "text", other)),
                }
            }
            "contains" => {
                let v = self.eval_only(args, 2, name, trace)?;
                if let Some(e) = null_operand_if_any(name, &v) {
                    return Err(e);
                }
                match (&v[0], &v[1]) {
                    (Value::Text(a), Value::Text(b)) => Ok(Value::Bool(a.contains(b.as_str()))),
                    // BRU-C1: a list of choices is searched by text key.
                    (Value::List(items), needle) => {
                        Ok(Value::Bool(items.iter().any(|i| values_equal(i, needle))))
                    }
                    (other, _) => Err(eval_type_err("contains", "text or list", other)),
                }
            }
            "startswith" => {
                let v = self.eval_only(args, 2, name, trace)?;
                if let Some(e) = null_operand_if_any(name, &v) {
                    return Err(e);
                }
                match (&v[0], &v[1]) {
                    (Value::Text(a), Value::Text(b)) => Ok(Value::Bool(a.starts_with(b.as_str()))),
                    (other, _) => Err(eval_type_err("startswith", "text", other)),
                }
            }
            "date_add" => {
                let v = self.eval_only(args, 3, name, trace)?;
                if let Some(e) = null_operand_if_any(name, &v) {
                    return Err(e);
                }
                let (date, n, unit) = match (&v[0], &v[1], &v[2]) {
                    (Value::Date(d), Value::Number(n), Value::Text(u)) => (*d, *n, u.as_str()),
                    _ => return Err(eval_type_err("date_add", "(date, number, text)", &v[0])),
                };
                date_add(date, n, unit, self.ctx.timezone())
            }
            "date_diff" => {
                let v = self.eval_only(args, 3, name, trace)?;
                if let Some(e) = null_operand_if_any(name, &v) {
                    return Err(e);
                }
                let (a, b, unit) = match (&v[0], &v[1], &v[2]) {
                    (Value::Date(a), Value::Date(b), Value::Text(u)) => (*a, *b, u.as_str()),
                    _ => return Err(eval_type_err("date_diff", "(date, date, text)", &v[0])),
                };
                date_diff(a, b, unit, self.ctx.timezone())
            }
            "today" => {
                if !args.is_empty() {
                    return Err(arity_err(name, "0", args.len()));
                }
                Ok(Value::Date(local_midnight(
                    self.ctx.now,
                    self.ctx.timezone(),
                )?))
            }
            "now" => {
                if !args.is_empty() {
                    return Err(arity_err(name, "0", args.len()));
                }
                Ok(Value::Date(self.ctx.now))
            }
            "round" => {
                if args.is_empty() || args.len() > 2 {
                    return Err(arity_err(name, "1-2", args.len()));
                }
                let mut vals = Vec::with_capacity(args.len());
                for a in args {
                    vals.push(self.eval(a, trace)?);
                }
                let n = match &vals[0] {
                    Value::Number(n) => *n,
                    other => return Err(eval_type_err("round", "number", other)),
                };
                let precision = match vals.get(1) {
                    Some(Value::Number(p)) => p.clamp(-15.0, 15.0) as i32,
                    Some(other) => return Err(eval_type_err("round's precision", "number", other)),
                    None => 0,
                };
                round_decimal(n, precision).map(Value::Number)
            }
            "min" | "max" => {
                if args.is_empty() {
                    return Err(arity_err(name, ">= 1", 0));
                }
                let mut vals = Vec::with_capacity(args.len());
                for a in args {
                    vals.push(self.eval(a, trace)?);
                }
                let numbers: Vec<f64> = if vals.len() == 1 {
                    match &vals[0] {
                        Value::List(items) => items
                            .iter()
                            .map(|v| match v {
                                Value::Number(n) => Ok(*n),
                                other => Err(eval_type_err(name, "a list of numbers", other)),
                            })
                            .collect::<Result<_, _>>()?,
                        Value::Number(n) => vec![*n],
                        other => {
                            return Err(eval_type_err(
                                name,
                                "number(s) or a list of numbers",
                                other,
                            ));
                        }
                    }
                } else {
                    vals.iter()
                        .map(|v| match v {
                            Value::Number(n) => Ok(*n),
                            other => Err(eval_type_err(name, "numbers", other)),
                        })
                        .collect::<Result<_, _>>()?
                };
                if numbers.is_empty() {
                    return Err(RulesError::Eval(format!("{name} of an empty list")));
                }
                let result = if name == "min" {
                    numbers.into_iter().fold(f64::INFINITY, f64::min)
                } else {
                    numbers.into_iter().fold(f64::NEG_INFINITY, f64::max)
                };
                finite(result).map(Value::Number)
            }
            "in" => {
                if args.len() < 2 {
                    return Err(arity_err(name, ">= 2", args.len()));
                }
                let needle = self.eval(&args[0], trace)?;
                if args.len() == 2 {
                    let second = self.eval(&args[1], trace)?;
                    if let Value::List(items) = &second {
                        return Ok(Value::Bool(items.iter().any(|i| values_equal(i, &needle))));
                    }
                    return Ok(Value::Bool(values_equal(&needle, &second)));
                }
                for a in &args[1..] {
                    let v = self.eval(a, trace)?;
                    if values_equal(&v, &needle) {
                        return Ok(Value::Bool(true));
                    }
                }
                Ok(Value::Bool(false))
            }
            "is_null" => {
                let v = self.eval_only(args, 1, name, trace)?;
                Ok(Value::Bool(v[0].is_null()))
            }
            other => Err(RulesError::UnknownFunction(other.to_owned())),
        }
    }

    /// Evaluates exactly n args (erroring on any other arity) and returns
    /// their values — the common case for fixed-arity functions.
    fn eval_only(
        &mut self,
        args: &[Expr],
        n: usize,
        name: &str,
        trace: &mut Trace,
    ) -> Result<Vec<Value>, RulesError> {
        if args.len() != n {
            return Err(arity_err(name, &n.to_string(), args.len()));
        }
        args.iter().map(|a| self.eval(a, trace)).collect()
    }
}

/// The eagerly-evaluated binary operators. and/or are absent by construction:
/// eval_binary short-circuits them before either operand runs, so the eager
/// path has no unreachable arm to reason about (BRU-A3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EagerOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShortCircuitOp {
    And,
    Or,
}

enum BinaryKind {
    Eager(EagerOp),
    ShortCircuit(ShortCircuitOp),
}

impl BinaryKind {
    fn of(op: BinaryOp) -> Self {
        match op {
            BinaryOp::Add => Self::Eager(EagerOp::Add),
            BinaryOp::Sub => Self::Eager(EagerOp::Sub),
            BinaryOp::Mul => Self::Eager(EagerOp::Mul),
            BinaryOp::Div => Self::Eager(EagerOp::Div),
            BinaryOp::Mod => Self::Eager(EagerOp::Mod),
            BinaryOp::Eq => Self::Eager(EagerOp::Eq),
            BinaryOp::Ne => Self::Eager(EagerOp::Ne),
            BinaryOp::Lt => Self::Eager(EagerOp::Lt),
            BinaryOp::Le => Self::Eager(EagerOp::Le),
            BinaryOp::Gt => Self::Eager(EagerOp::Gt),
            BinaryOp::Ge => Self::Eager(EagerOp::Ge),
            BinaryOp::And => Self::ShortCircuit(ShortCircuitOp::And),
            BinaryOp::Or => Self::ShortCircuit(ShortCircuitOp::Or),
        }
    }
}

fn eval_eager(op: EagerOp, l: Value, r: Value, budgets: &Budgets) -> Result<Value, RulesError> {
    match op {
        EagerOp::Add => match (l, r) {
            (Value::Number(a), Value::Number(b)) => finite(a + b).map(Value::Number),
            (Value::Text(a), Value::Text(b)) => mk_text(a + &b, budgets),
            (a, b) => Err(null_or_type_err2(
                "'+'",
                "(number, number) or (text, text)",
                &a,
                &b,
            )),
        },
        EagerOp::Sub => numeric_op(l, r, "'-'", |a, b| Ok(a - b)),
        EagerOp::Mul => numeric_op(l, r, "'*'", |a, b| Ok(a * b)),
        EagerOp::Div => numeric_op(l, r, "'/'", |a, b| {
            if b == 0.0 {
                Err(RulesError::DivideByZero)
            } else {
                Ok(a / b)
            }
        }),
        EagerOp::Mod => numeric_op(l, r, "'%'", |a, b| {
            if b == 0.0 {
                Err(RulesError::DivideByZero)
            } else {
                Ok(a % b)
            }
        }),
        EagerOp::Eq => Ok(Value::Bool(values_equal(&l, &r))),
        EagerOp::Ne => Ok(Value::Bool(!values_equal(&l, &r))),
        EagerOp::Lt => ordering_op(l, r, "'<'", |o| o == Ordering::Less),
        EagerOp::Le => ordering_op(l, r, "'<='", |o| o != Ordering::Greater),
        EagerOp::Gt => ordering_op(l, r, "'>'", |o| o == Ordering::Greater),
        EagerOp::Ge => ordering_op(l, r, "'>='", |o| o != Ordering::Less),
    }
}

/// BRU-C1 / D-620: a Choice and a Text are equal when the choice's stable key
/// equals the text, in either operand order. Every other pairing is Rust's own
/// equality.
fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Choice(x), Value::Text(y)) | (Value::Text(x), Value::Choice(y)) => x == y,
        _ => a == b,
    }
}

fn mk_text(s: String, budgets: &Budgets) -> Result<Value, RulesError> {
    if s.chars().count() > budgets.max_string_len {
        return Err(RulesError::Budget(BudgetKind::StringLength));
    }
    Ok(Value::Text(s))
}

/// BRU-B1: a Value::Number is always finite.
fn finite(n: f64) -> Result<f64, RulesError> {
    if n.is_finite() {
        Ok(n)
    } else {
        Err(RulesError::NumericOverflow)
    }
}

fn numeric_op(
    l: Value,
    r: Value,
    ctx: &str,
    f: impl FnOnce(f64, f64) -> Result<f64, RulesError>,
) -> Result<Value, RulesError> {
    match (l, r) {
        (Value::Number(a), Value::Number(b)) => finite(f(a, b)?).map(Value::Number),
        (a, b) => Err(null_or_type_err2(ctx, "(number, number)", &a, &b)),
    }
}

fn ordering_op(
    l: Value,
    r: Value,
    ctx: &str,
    matches_ord: impl Fn(Ordering) -> bool,
) -> Result<Value, RulesError> {
    if l.is_null() || r.is_null() {
        return Err(RulesError::NullOperand { op: ctx.to_owned() });
    }
    let ord = match (&l, &r) {
        (Value::Number(a), Value::Number(b)) => a
            .partial_cmp(b)
            .ok_or_else(|| RulesError::Eval(format!("{ctx}: incomparable numbers")))?,
        (Value::Date(a), Value::Date(b)) => a.cmp(b),
        _ => {
            return Err(eval_type_err2(
                ctx,
                "(number, number) or (date, date)",
                &l,
                &r,
            ));
        }
    };
    Ok(Value::Bool(matches_ord(ord)))
}

/// BRU-C4: the caller's local date at 00:00, converted to UTC — today()'s
/// value. A zone whose DST transition swallows local midnight (some zones
/// spring forward at 00:00) yields the first instant that exists rather than a
/// panic or a wrong date.
fn local_midnight(now: DateTime<Utc>, tz: Tz) -> Result<DateTime<Utc>, RulesError> {
    let local = now.with_timezone(&tz);
    let naive = local
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| RulesError::Eval("today(): invalid midnight".to_owned()))?;
    Ok(resolve_local(naive, tz))
}

/// Maps a local wall-clock time to UTC the way a person reads it: an ambiguous
/// time (a DST fall-back) is the first of its two instants, and a time a DST
/// gap swallows becomes the first instant that exists after the gap.
fn resolve_local(naive: NaiveDateTime, tz: Tz) -> DateTime<Utc> {
    match tz.from_local_datetime(&naive) {
        MappedLocalTime::Single(dt) => dt.with_timezone(&Utc),
        MappedLocalTime::Ambiguous(earliest, _) => earliest.with_timezone(&Utc),
        MappedLocalTime::None => {
            let shifted = naive
                .checked_add_signed(chrono::TimeDelta::hours(1))
                .map(|probe| tz.from_local_datetime(&probe));
            match shifted {
                Some(MappedLocalTime::Single(dt) | MappedLocalTime::Ambiguous(dt, _)) => {
                    dt.with_timezone(&Utc)
                }
                // Unreachable for a real tz-database row; never a panic.
                _ => Utc.from_utc_datetime(&naive),
            }
        }
    }
}

/// BRU-A1: reject a non-finite amount, then use chrono's checked constructors —
/// TimeDelta::days/hours/minutes panic out of range, try_* does not.
/// BRU-B1: a non-finite amount is a numeric overflow, never a silent 0.
/// BRU-C4: months/years shift on the caller's local calendar.
fn date_add(date: DateTime<Utc>, n: f64, unit: &str, tz: Tz) -> Result<Value, RulesError> {
    if !n.is_finite() {
        return Err(RulesError::NumericOverflow);
    }
    let amount = n.trunc();
    // i64::MAX as f64 rounds up to 2^63, which is itself out of range.
    if amount < i64::MIN as f64 || amount >= i64::MAX as f64 {
        return Err(out_of_range());
    }
    let amount = amount as i64;
    let result = match unit {
        "days" => chrono::TimeDelta::try_days(amount).and_then(|d| date.checked_add_signed(d)),
        "hours" => chrono::TimeDelta::try_hours(amount).and_then(|d| date.checked_add_signed(d)),
        "minutes" => {
            chrono::TimeDelta::try_minutes(amount).and_then(|d| date.checked_add_signed(d))
        }
        "months" => shift_months(date, amount, tz),
        "years" => {
            let months = amount.checked_mul(12).ok_or_else(out_of_range)?;
            shift_months(date, months, tz)
        }
        other => {
            return Err(RulesError::Eval(format!(
                "date_add: unknown unit '{other}'"
            )));
        }
    };
    result.map(Value::Date).ok_or_else(out_of_range)
}

fn out_of_range() -> RulesError {
    RulesError::Eval("date_add: result out of range".to_owned())
}

/// BRU-C4: add whole months on the caller's local calendar (so a month step
/// keeps the local wall-clock time), then convert back to UTC. The naive local
/// time is shifted and resolved like today()'s midnight, so a result that lands
/// in a DST gap or overlap is a real instant rather than an out-of-range error.
fn shift_months(date: DateTime<Utc>, months: i64, tz: Tz) -> Option<DateTime<Utc>> {
    let local = date.with_timezone(&tz).naive_local();
    let step = Months::new(u32::try_from(months.unsigned_abs()).ok()?);
    let shifted = if months >= 0 {
        local.checked_add_months(step)
    } else {
        local.checked_sub_months(step)
    }?;
    Some(resolve_local(shifted, tz))
}

fn date_diff(a: DateTime<Utc>, b: DateTime<Utc>, unit: &str, tz: Tz) -> Result<Value, RulesError> {
    let n = match unit {
        "days" => (a - b).num_days() as f64,
        "hours" => (a - b).num_hours() as f64,
        "minutes" => (a - b).num_minutes() as f64,
        "seconds" => (a - b).num_seconds() as f64,
        "months" => calendar_month_diff(a, b, tz) as f64,
        "years" => (calendar_month_diff(a, b, tz) / 12) as f64,
        other => {
            return Err(RulesError::Eval(format!(
                "date_diff: unknown unit '{other}'"
            )));
        }
    };
    finite(n).map(Value::Number)
}

/// Whole calendar months between a and b (a - b, signed), the way a person
/// reads "3 months apart": count year/month, then back off one when the later
/// date has not yet reached the earlier one's (day, time of day).
///
/// BRU-B3: computed from the ordered pair, so it is exactly antisymmetric —
/// diff(a, b) == -diff(b, a) — and a pair 23 hours short of a whole month
/// counts 0, not 1.
/// BRU-C4: the year/month/day comparison uses the caller's local calendar.
fn calendar_month_diff(a: DateTime<Utc>, b: DateTime<Utc>, tz: Tz) -> i64 {
    let (earlier, later) = if a <= b { (a, b) } else { (b, a) };
    let earlier = earlier.with_timezone(&tz);
    let later = later.with_timezone(&tz);
    let mut months = (later.year() as i64 - earlier.year() as i64) * 12
        + (later.month() as i64 - earlier.month() as i64);
    if (later.day(), later.time()) < (earlier.day(), earlier.time()) {
        months -= 1;
    }
    // Signed the way date_diff(a, b) has always been: positive when a is the
    // later instant (a - b). BRU-C4's rewrite of this function initially
    // inverted this; the sign is now pinned by a test.
    if a >= b { months } else { -months }
}

/// BRU-B2: rounds the *decimal* value half away from zero, so
/// round(1.005, 2) == 1.01 and round(2.675, 2) == 2.68 — the values a person
/// reads off the screen — rather than the binary approximation's 1.00/2.67.
///
/// The plan named rust_decimal for this; this crate's dependency list is frozen
/// (a Cargo.toml edit is outside this lane's write surface), so the same
/// decimal semantics are implemented directly: take the shortest round-trip
/// decimal representation (the LowerExp format), round its digit string half
/// away from zero at the requested decimal place, and parse the result back.
fn round_decimal(n: f64, precision: i32) -> Result<f64, RulesError> {
    if !n.is_finite() {
        return Err(RulesError::NumericOverflow);
    }
    if n == 0.0 {
        return Ok(0.0);
    }
    let negative = n < 0.0;
    let magnitude = n.abs();
    let repr = format!("{magnitude:e}");
    let (mantissa, exponent) = repr
        .split_once('e')
        .ok_or_else(|| RulesError::Eval("round: unrepresentable number".to_owned()))?;
    let exponent: i32 = exponent
        .parse()
        .map_err(|_| RulesError::Eval("round: unrepresentable number".to_owned()))?;
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Err(RulesError::Eval("round: unrepresentable number".to_owned()));
    }
    // The decimal place of the last significant digit.
    let last_place = exponent - (digits.len() as i32 - 1);
    let shift = last_place + precision;
    if shift >= 0 {
        // No digit lies below the requested place: the value is unchanged.
        return Ok(n);
    }
    let drop = (-shift) as usize;
    let rounded: String = if drop > digits.len() {
        // The first dropped digit is an implied leading 0, so the value is
        // below half a unit in the requested place.
        "0".to_owned()
    } else if drop == digits.len() {
        // Every significant digit is dropped; the leading one is the first
        // dropped digit and alone decides the rounding.
        let leading = digits.as_bytes()[0] - b'0';
        if leading >= 5 {
            "1".to_owned()
        } else {
            "0".to_owned()
        }
    } else {
        let keep = &digits[..digits.len() - drop];
        let first_dropped = digits.as_bytes()[digits.len() - drop] - b'0';
        let mut kept: u64 = keep
            .parse()
            .map_err(|_| RulesError::Eval("round: unrepresentable number".to_owned()))?;
        if first_dropped >= 5 {
            kept += 1;
        }
        kept.to_string()
    };
    let text = format!("{rounded}e{}", -precision);
    let value: f64 = text
        .parse()
        .map_err(|_| RulesError::Eval("round: unrepresentable result".to_owned()))?;
    let value = finite(value)?;
    Ok(if negative { -value } else { value })
}

fn null_operand_if_any(op: &str, values: &[Value]) -> Option<RulesError> {
    values
        .iter()
        .any(Value::is_null)
        .then(|| RulesError::NullOperand { op: op.to_owned() })
}

fn arity_err(function: &str, expected: &str, got: usize) -> RulesError {
    RulesError::Arity {
        function: function.to_owned(),
        expected: expected.to_owned(),
        got,
    }
}

fn eval_type_err(ctx: &str, expected: &str, got: &Value) -> RulesError {
    RulesError::Eval(format!("{ctx} needs {expected}, got {}", got.ty()))
}

/// BRU-C2a: a null is its own failure, not a type mismatch.
fn null_or_type_err(ctx: &str, expected: &str, got: &Value) -> RulesError {
    if got.is_null() {
        RulesError::NullOperand { op: ctx.to_owned() }
    } else {
        eval_type_err(ctx, expected, got)
    }
}

/// Same as eval_type_err, but names both operands' types — for binary
/// operators, where the mismatch is often "one side was the wrong type",
/// not just the first.
fn eval_type_err2(ctx: &str, expected: &str, a: &Value, b: &Value) -> RulesError {
    RulesError::Eval(format!(
        "{ctx} needs {expected}, got ({}, {})",
        a.ty(),
        b.ty()
    ))
}

fn null_or_type_err2(ctx: &str, expected: &str, a: &Value, b: &Value) -> RulesError {
    if a.is_null() || b.is_null() {
        RulesError::NullOperand { op: ctx.to_owned() }
    } else {
        eval_type_err2(ctx, expected, a, b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;
    use crate::value::Type;
    use chrono::TimeZone;

    fn schema() -> Schema {
        Schema::new()
            .with_field("amount", Type::Number)
            .with_field("name", Type::Text)
            .with_field("active", Type::Bool)
            .with_field("status", Type::Choice)
            .with_related(
                "customer",
                [("tier".to_owned(), Type::Text)].into_iter().collect(),
            )
    }

    fn ctx() -> Context {
        Context::new(Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap())
            .with_field("amount", Value::Number(42.0))
            .with_field("name", Value::Text("Ada".to_owned()))
            .with_field("active", Value::Bool(true))
            .with_field("status", Value::Choice("open".to_owned()))
            .with_related(
                "customer",
                [("tier".to_owned(), Value::Text("gold".to_owned()))]
                    .into_iter()
                    .collect(),
            )
    }

    fn run_with(src: &str, ctx: &Context) -> Result<Value, RulesError> {
        let expr = parse(src).unwrap();
        eval(&expr, ctx, &Budgets::default(), &schema())
    }

    fn run(src: &str) -> Result<Value, RulesError> {
        run_with(src, &ctx())
    }

    #[test]
    fn arithmetic_and_field_refs() {
        assert_eq!(run("amount + 8").unwrap(), Value::Number(50.0));
        assert_eq!(run("amount / 2").unwrap(), Value::Number(21.0));
        assert_eq!(run("amount % 5").unwrap(), Value::Number(2.0));
    }

    #[test]
    fn divide_by_zero_is_typed_not_a_panic() {
        assert_eq!(run("1 / 0"), Err(RulesError::DivideByZero));
        assert_eq!(run("1 % 0"), Err(RulesError::DivideByZero));
    }

    #[test]
    fn one_hop_lookup_resolves_from_related() {
        assert_eq!(
            run("customer.tier").unwrap(),
            Value::Text("gold".to_owned())
        );
    }

    #[test]
    fn boolean_short_circuit() {
        // false and (1/0 == 0) must not evaluate the right side.
        assert_eq!(run("false and (1 / 0 == 0)").unwrap(), Value::Bool(false));
        assert_eq!(run("true or (1 / 0 == 0)").unwrap(), Value::Bool(true));
    }

    #[test]
    fn if_only_evaluates_taken_branch() {
        assert_eq!(run("if(active, 1, 1 / 0)").unwrap(), Value::Number(1.0));
        assert_eq!(run("if(not active, 1 / 0, 2)").unwrap(), Value::Number(2.0));
    }

    #[test]
    fn coalesce_stops_at_first_non_null() {
        assert_eq!(
            run("coalesce(null, null, 3, 1 / 0)").unwrap(),
            Value::Number(3.0)
        );
        assert_eq!(run("coalesce(null, null)").unwrap(), Value::Null);
    }

    #[test]
    fn string_functions() {
        assert_eq!(run(r#"lower("ABC")"#).unwrap(), Value::Text("abc".into()));
        assert_eq!(run(r#"upper("abc")"#).unwrap(), Value::Text("ABC".into()));
        assert_eq!(run(r#"trim("  x  ")"#).unwrap(), Value::Text("x".into()));
        assert_eq!(run(r#"len("hello")"#).unwrap(), Value::Number(5.0));
        assert_eq!(
            run(r#"contains("hello world", "wor")"#).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            run(r#"startswith("hello", "he")"#).unwrap(),
            Value::Bool(true)
        );
    }

    #[test]
    fn multibyte_len_counts_chars_not_bytes() {
        // "مرحبا" is 5 Arabic characters but more than 5 UTF-8 bytes.
        assert_eq!(run(r#"len("مرحبا")"#).unwrap(), Value::Number(5.0));
    }

    #[test]
    fn list_functions() {
        assert_eq!(run("in(2, [1, 2, 3])").unwrap(), Value::Bool(true));
        assert_eq!(run("in(9, [1, 2, 3])").unwrap(), Value::Bool(false));
        assert_eq!(run("in(2, 1, 2, 3)").unwrap(), Value::Bool(true));
        assert_eq!(run("min([3, 1, 2])").unwrap(), Value::Number(1.0));
        assert_eq!(run("max(3, 1, 2)").unwrap(), Value::Number(3.0));
        assert_eq!(run("len([1, 2, 3])").unwrap(), Value::Number(3.0));
        assert_eq!(run("contains([1, 2, 3], 2)").unwrap(), Value::Bool(true));
    }

    #[test]
    fn min_max_of_empty_list_is_a_typed_error() {
        assert!(matches!(run("min([])"), Err(RulesError::Eval(_))));
    }

    #[test]
    fn date_functions() {
        assert_eq!(run("today() <= now()").unwrap(), Value::Bool(true));
        assert_eq!(
            run(r#"date_diff(date_add(today(), 10, "days"), today(), "days")"#).unwrap(),
            Value::Number(10.0)
        );
    }

    #[test]
    fn round_with_and_without_precision() {
        assert_eq!(run("round(1.2345, 2)").unwrap(), Value::Number(1.23));
        assert_eq!(run("round(1.6)").unwrap(), Value::Number(2.0));
    }

    #[test]
    fn is_null_and_equality() {
        assert_eq!(run("is_null(null)").unwrap(), Value::Bool(true));
        assert_eq!(run("is_null(amount)").unwrap(), Value::Bool(false));
        assert_eq!(run(r#"name == "Ada""#).unwrap(), Value::Bool(true));
    }

    #[test]
    fn unknown_field_is_typed_not_a_panic() {
        assert_eq!(
            run("does_not_exist"),
            Err(RulesError::UnknownField("does_not_exist".to_owned()))
        );
    }

    #[test]
    fn step_budget_is_enforced() {
        let expr = parse("1 + 1 + 1 + 1 + 1").unwrap();
        let tiny = Budgets {
            max_eval_steps: 2,
            ..Budgets::default()
        };
        let err = eval(&expr, &ctx(), &tiny, &schema()).unwrap_err();
        assert_eq!(err, RulesError::Budget(BudgetKind::EvalSteps));
    }

    #[test]
    fn string_length_budget_is_enforced() {
        let expr = parse(r#""hello" + " world""#).unwrap();
        let tiny = Budgets {
            max_string_len: 3,
            ..Budgets::default()
        };
        let err = eval(&expr, &ctx(), &tiny, &schema()).unwrap_err();
        assert_eq!(err, RulesError::Budget(BudgetKind::StringLength));
    }

    #[test]
    fn trace_records_visited_subexpressions_only() {
        let expr = parse("if(active, 1, 1 / 0)").unwrap();
        let (_, trace) = eval_traced(&expr, &ctx(), &Budgets::default(), &schema()).unwrap();
        let texts: Vec<_> = trace.entries().iter().map(|e| e.expr.clone()).collect();
        assert!(texts.contains(&"active".to_owned()));
        assert!(texts.contains(&"1".to_owned()));
        // The untaken 1 / 0 branch is never itself evaluated, so no entry
        // records ITS OWN evaluation (the top-level if(...) entry's rendered
        // source still mentions it as part of the rule's static text).
        assert!(!texts.iter().any(|t| t == "1 / 0"));
        // Corroborating evidence: if 1 / 0 had actually run, eval_traced would
        // have returned Err(DivideByZero) instead of succeeding above.
    }

    // ── BRU-E1: eval and eval_traced agree ──────────────────────────────────

    #[test]
    fn eval_and_eval_traced_return_the_same_value() {
        for src in [
            "amount + 8",
            r#"name == "Ada""#,
            "if(active, 1, 2)",
            "amount > 100",
            "in(amount, [1, 2, 3])",
            "coalesce(null, amount)",
        ] {
            let expr = parse(src).unwrap();
            let plain = eval(&expr, &ctx(), &Budgets::default(), &schema()).unwrap();
            let (traced, _) = eval_traced(&expr, &ctx(), &Budgets::default(), &schema()).unwrap();
            assert_eq!(plain, traced, "{src}");
        }
    }

    // ── Phase 0 (BRU-P1/P4/P5): failing tests that prove BRU-F1/F3/F13 ─────

    fn any_ctx() -> Context {
        Context::new(Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap())
            .with_field("amount", Value::Number(42.0))
            .with_field("name", Value::Text("Ada".to_owned()))
    }

    /// BRU-P1 (BRU-F1): an out-of-range date_add amount is a typed error,
    /// never a panic out of chrono's Duration::days/hours/minutes.
    #[test]
    fn date_add_out_of_range_is_a_typed_error() {
        for src in [
            r#"date_add(now(), 1e12, "days")"#,
            r#"date_add(now(), -3e12, "hours")"#,
            r#"date_add(now(), 2e14, "minutes")"#,
            // -2^63 is exactly i64::MIN: negating it for a month step must be
            // an error, never an overflow panic.
            r#"date_add(now(), -9223372036854775808, "months")"#,
            r#"date_add(now(), -9223372036854775808, "years")"#,
            r#"date_add(now(), 9223372036854775808, "months")"#,
        ] {
            let out = run(src);
            assert!(out.is_err(), "{src} must be a typed error, got {out:?}");
        }
        // 1e999 overflows f64 at lex time: it must never become a literal.
        assert!(
            crate::compile::compile(
                r#"date_add(now(), 1e999, "days")"#,
                &crate::context::Schema::new()
            )
            .is_err(),
            "an overflowing literal must be rejected at compile time"
        );
        // A non-finite amount arriving through Context must error too.
        let schema = crate::context::Schema::new().with_field("n", crate::value::Type::Number);
        let compiled = crate::compile::compile(r#"date_add(now(), n, "days")"#, &schema).unwrap();
        let ctx = any_ctx().with_field("n", Value::Number(f64::NAN));
        let out = compiled.eval(&ctx);
        assert!(
            out.is_err(),
            "a NaN amount must be a typed error, got {out:?}"
        );
    }

    /// BRU-P4 (BRU-F3): the evaluator never returns a non-finite
    /// Value::Number; an overflowing literal does not compile.
    #[test]
    fn non_finite_numbers_never_leave_the_evaluator() {
        let schema = crate::context::Schema::new();
        assert!(
            crate::compile::compile("1e999", &schema).is_err(),
            "an overflowing literal must not compile"
        );
        // These bypass the test helper because a rejected literal fails at
        // compile time, before any Context exists.
        for src in ["1e308 * 10", "1e308 + 1e308", "0 * 1e999", "-1e999"] {
            let out = crate::compile::compile(src, &crate::context::Schema::new())
                .and_then(|c| c.eval(&ctx()));
            if let Ok(Value::Number(n)) = out {
                assert!(n.is_finite(), "{src} produced the non-finite number {n}");
            }
            assert!(out.is_err(), "{src} must be a typed error, got {out:?}");
        }
    }

    /// BRU-P5 (BRU-F13): date_diff(.., "months") is antisymmetric and counts
    /// whole calendar months, not a day-of-month back-off applied on one
    /// argument order only.
    #[test]
    fn month_difference_is_antisymmetric() {
        let jan31 = Utc.with_ymd_and_hms(2026, 1, 31, 12, 0, 0).unwrap();
        let mar1 = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        let ab = calendar_month_diff(jan31, mar1, chrono_tz::UTC);
        let ba = calendar_month_diff(mar1, jan31, chrono_tz::UTC);
        assert_eq!(
            ab, -ba,
            "Jan 31 -> Mar 1 ({ab}) must negate Mar 1 -> Jan 31 ({ba})"
        );

        // 23 hours short of a whole month: Feb 5 00:00 is not a full month
        // after Jan 5 23:00, in either argument order.
        let jan5_23 = Utc.with_ymd_and_hms(2026, 1, 5, 23, 0, 0).unwrap();
        let feb5_00 = Utc.with_ymd_and_hms(2026, 2, 5, 0, 0, 0).unwrap();
        let cd = calendar_month_diff(jan5_23, feb5_00, chrono_tz::UTC);
        let dc = calendar_month_diff(feb5_00, jan5_23, chrono_tz::UTC);
        assert_eq!(
            cd, -dc,
            "a 23-hour-short pair must be antisymmetric ({cd} vs {dc})"
        );
    }

    /// The month difference is signed from the first argument (a - b), the
    /// convention every other unit and the pre-BRU-B3 code used: a later first
    /// argument is positive. BRU-B3's antisymmetry-only test did not pin this,
    /// and the BRU-C4 rewrite of calendar_month_diff inverted it without that
    /// test noticing.
    #[test]
    fn month_difference_is_signed_from_the_first_argument() {
        let jan31 = Utc.with_ymd_and_hms(2026, 1, 31, 12, 0, 0).unwrap();
        let mar1 = Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap();
        assert_eq!(calendar_month_diff(mar1, jan31, chrono_tz::UTC), 1);
        assert_eq!(calendar_month_diff(jan31, mar1, chrono_tz::UTC), -1);
        assert_eq!(calendar_month_diff(mar1, mar1, chrono_tz::UTC), 0);

        // End to end: a later than b is +1, as it was before this plan.
        let date_schema = Schema::new()
            .with_field("a", Type::Date)
            .with_field("b", Type::Date);
        let compiled =
            crate::compile::compile(r#"date_diff(a, b, "months")"#, &date_schema).unwrap();
        let date_ctx = Context::new(Utc.with_ymd_and_hms(2026, 8, 26, 12, 0, 0).unwrap())
            .with_field("a", Value::Date(mar1))
            .with_field("b", Value::Date(jan31));
        assert_eq!(compiled.eval(&date_ctx).unwrap(), Value::Number(1.0));
    }

    // ── BRU-B1: finite-only ─────────────────────────────────────────────────

    #[test]
    fn arithmetic_overflow_is_a_typed_error() {
        for src in ["1e308 * 10", "1e308 + 1e308", "1e308 / 1e-308"] {
            assert_eq!(run(src), Err(RulesError::NumericOverflow), "{src}");
        }
    }

    #[test]
    fn a_non_finite_context_number_is_rejected() {
        for bad in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
            assert_eq!(
                run_with(
                    "amount + 1",
                    &ctx().with_field("amount", Value::Number(bad))
                ),
                Err(RulesError::NumericOverflow)
            );
        }
    }

    // ── BRU-B2: decimal-correct round ───────────────────────────────────────

    #[test]
    fn round_is_decimal_correct() {
        for (src, want) in [
            (r#"round(1.005, 2)"#, 1.01),
            (r#"round(2.675, 2)"#, 2.68),
            (r#"round(1.2345, 2)"#, 1.23),
            (r#"round(1.6)"#, 2.0),
            (r#"round(2.5)"#, 3.0),
            (r#"round(-2.5)"#, -3.0),
            (r#"round(0.005, 2)"#, 0.01),
            (r#"round(0.004, 2)"#, 0.0),
            (r#"round(1234, -2)"#, 1200.0),
            (r#"round(42)"#, 42.0),
            (r#"round(-0.5)"#, -1.0),
            (r#"round(0.06)"#, 0.0),
            (r#"round(0.0006, 2)"#, 0.0),
            (r#"round(5, -2)"#, 0.0),
            (r#"round(50, -2)"#, 100.0),
        ] {
            assert_eq!(run(src).unwrap(), Value::Number(want), "{src}");
        }
    }

    // ── BRU-C1 (D-620): Choice compares with Text by key ────────────────────

    #[test]
    fn choice_compares_with_text_by_key() {
        assert_eq!(run(r#"status == "open""#).unwrap(), Value::Bool(true));
        assert_eq!(run(r#""open" == status"#).unwrap(), Value::Bool(true));
        assert_eq!(run(r#"status == "closed""#).unwrap(), Value::Bool(false));
        assert_eq!(run(r#"status != "closed""#).unwrap(), Value::Bool(true));
        assert_eq!(
            run(r#"in(status, ["open", "closed"])"#).unwrap(),
            Value::Bool(true)
        );
        assert_eq!(
            run(r#"in(status, ["draft", "closed"])"#).unwrap(),
            Value::Bool(false)
        );
        assert_eq!(
            run(r#"contains(["open", "closed"], status)"#).unwrap(),
            Value::Bool(true)
        );
    }

    // ── BRU-C2a (BRU-D2): a null operand is typed ───────────────────────────

    #[test]
    fn a_null_operand_is_a_typed_error() {
        let null_amount = ctx().with_field("amount", Value::Null);
        assert_eq!(
            run_with("amount > 100", &null_amount),
            Err(RulesError::NullOperand {
                op: "'>'".to_owned()
            })
        );
        assert_eq!(
            run_with("amount + 1", &null_amount),
            Err(RulesError::NullOperand {
                op: "'+'".to_owned()
            })
        );
        assert_eq!(
            run_with("-amount", &null_amount),
            Err(RulesError::NullOperand {
                op: "unary '-'".to_owned()
            })
        );
        assert_eq!(
            run_with("active and amount > 1", &null_amount),
            Err(RulesError::NullOperand {
                op: "'>'".to_owned()
            })
        );
        assert_eq!(
            run_with("not null", &ctx()),
            Err(RulesError::NullOperand {
                op: "'not'".to_owned()
            })
        );
        assert_eq!(
            run_with("null and active", &ctx()),
            Err(RulesError::NullOperand {
                op: "'and'".to_owned()
            })
        );
        assert_eq!(
            run_with("len(name)", &ctx().with_field("name", Value::Null)),
            Err(RulesError::NullOperand {
                op: "len".to_owned()
            })
        );
        assert_eq!(
            run_with(
                r#"date_add(opened, null, "days")"#,
                &ctx().with_field(
                    "opened",
                    Value::Date(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
                )
            ),
            Err(RulesError::NullOperand {
                op: "date_add".to_owned()
            })
        );
        // Equality accepts Null: it is false, not an error.
        assert_eq!(
            run_with("amount == 1", &null_amount).unwrap(),
            Value::Bool(false)
        );
    }

    // ── BRU-C3: Context conformance ─────────────────────────────────────────

    #[test]
    fn a_context_value_of_the_wrong_type_is_typed() {
        let compiled = crate::compile::compile("amount > 1", &schema()).unwrap();
        let wrong = ctx().with_field("amount", Value::Text("nope".to_owned()));
        assert_eq!(
            compiled.eval(&wrong),
            Err(RulesError::ContextTypeMismatch {
                field: "amount".to_owned()
            })
        );
        // Null is always acceptable — a null operand is its own (C2a) error.
        let null_ctx = ctx().with_field("amount", Value::Null);
        assert_eq!(
            compiled.eval(&null_ctx),
            Err(RulesError::NullOperand {
                op: "'>'".to_owned()
            })
        );
    }

    // ── BRU-E2: Context text and list budgets ───────────────────────────────

    #[test]
    fn context_text_and_lists_are_budgeted() {
        let long = ctx().with_field("name", Value::Text("a".repeat(20_000)));
        assert_eq!(
            run_with("name == name", &long),
            Err(RulesError::Budget(BudgetKind::StringLength))
        );

        let big = ctx().with_field("amount", Value::List(vec![Value::Number(1.0); 20_000]));
        assert_eq!(
            run_with("amount == amount", &big),
            Err(RulesError::Budget(BudgetKind::ListLength))
        );
    }
}

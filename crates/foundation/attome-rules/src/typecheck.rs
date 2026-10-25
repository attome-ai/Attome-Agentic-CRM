//! Compile-time type checking against the 7 platform field types + List
//! (M45 plan §3.1) — "a rule that would produce a value its target column
//! cannot store is rejected at save, not at runtime". This module computes
//! and validates the *expression's* type; comparing that against a specific
//! target field's declared type is the caller's job (Phase 2's admin API,
//! which is the one that knows a rule's kind/target_field — keeping that
//! knowledge out of this xrm-agnostic crate).
//!
//! Ordering comparisons (< <= > >=) are restricted to Number and Date.
//! Text is deliberately excluded: naive Rust str ordering is byte-wise and
//! does not respect Arabic collation, and the platform is bilingual — an
//! admin-authored rule that silently orders Arabic text by UTF-8 byte value
//! would produce a plausible-looking but wrong result with no error to catch
//! it. ==/!= still work on any two unifiable types (including Text), since
//! equality doesn't have this problem.
//!
//! The + operator is overloaded for Text (concatenation) alongside Number
//! (arithmetic) —
//! not a new operator or function, just the natural reading of "add" for the
//! one other type where it's unambiguous, and needed for kind = calculation
//! rules that build a Text value (M45 plan §4).
//!
//! **Since BRU-C1 (D-620, amending D-399 ruling 4)** ==, !=, in and list
//! contains also accept (Choice, Text) in either operand order, compared by
//! the choice's stable key; no other operation is added on Choice. Since
//! BRU-C2c a bare null literal is refused where a concrete type is required
//! (unify still lets Null stand in for a branch/element type). Both checks
//! produce BRU-FX1 diagnostics: every error is tagged with the byte span of
//! the node that raised it, from the parser's pre-order Spans table.

use std::collections::BTreeSet;

use crate::ast::{BinaryOp, Expr, UnaryOp};
use crate::context::Schema;
use crate::error::{RulesDiagnostic, RulesError, Spans};
use crate::value::Type;

/// Walks the parser's pre-order span table in lockstep with the AST: each
/// visited node takes the next span.
struct Cursor<'a> {
    spans: &'a Spans,
    next: usize,
}

impl<'a> Cursor<'a> {
    fn new(spans: &'a Spans) -> Self {
        Self { spans, next: 0 }
    }

    fn advance(&mut self) -> Option<(usize, usize)> {
        let span = self.spans.get(self.next);
        self.next += 1;
        span
    }
}

// C-25 pub(crate) sweep: mod typecheck is private (see lib.rs) and not
// re-exported — only compile.rs calls typecheck/null_warnings.
pub(crate) fn typecheck(
    expr: &Expr,
    schema: &Schema,
    spans: &Spans,
) -> Result<Type, RulesDiagnostic> {
    let mut cursor = Cursor::new(spans);
    typecheck_node(expr, schema, &mut cursor)
}

/// One node: its span is taken first (pre-order), and any error raised by this
/// node's *own* check — not a child's — is tagged with it on the way out.
fn typecheck_node(
    expr: &Expr,
    schema: &Schema,
    cursor: &mut Cursor<'_>,
) -> Result<Type, RulesDiagnostic> {
    let span = cursor.advance();
    let result = match expr {
        Expr::NullLit => Ok(Type::Null),
        Expr::BoolLit(_) => Ok(Type::Bool),
        Expr::NumberLit(_) => Ok(Type::Number),
        Expr::StringLit(_) => Ok(Type::Text),
        Expr::ListLit(items) => {
            let mut elem = Type::Null;
            for item in items {
                let t = typecheck_node(item, schema, cursor)?;
                elem = elem.unify(&t).ok_or_else(|| {
                    RulesDiagnostic::without_span(type_err(format!(
                        "list elements have mismatched types: {elem} vs {t}"
                    )))
                })?;
            }
            Ok(Type::List(Box::new(elem)))
        }
        Expr::FieldRef(r) => match &r.hop {
            None => schema.field_type(&r.base).cloned().ok_or_else(|| {
                RulesDiagnostic::without_span(RulesError::UnknownField(r.base.clone()))
            }),
            Some(hop) => {
                if !schema.has_related(&r.base) {
                    return Err(RulesDiagnostic::without_span(RulesError::UnknownField(
                        r.base.clone(),
                    )));
                }
                schema
                    .related_field_type(&r.base, hop)
                    .cloned()
                    .ok_or_else(|| {
                        RulesDiagnostic::without_span(RulesError::UnknownField(format!(
                            "{}.{}",
                            r.base, hop
                        )))
                    })
            }
        },
        Expr::Unary { op, expr } => {
            let t = typecheck_node(expr, schema, cursor)?;
            match op {
                UnaryOp::Neg => require(&t, &Type::Number, "unary '-'").map(|_| Type::Number),
                UnaryOp::Not => require(&t, &Type::Bool, "'not'").map(|_| Type::Bool),
            }
            .map_err(RulesDiagnostic::without_span)
        }
        Expr::Binary { op, lhs, rhs } => typecheck_binary(*op, lhs, rhs, schema, cursor),
        Expr::Call { name, args } if crate::parser::LAMBDA_FUNCTIONS.contains(&name.as_str()) => {
            typecheck_lambda_call(name, args, schema, cursor)
        }
        Expr::Call { name, args } => typecheck_call(name, args, schema, cursor),
        Expr::Path(segments) => {
            let joined = segments.join(".");
            schema
                .path_type(&joined)
                .map(|(ty, _)| ty.clone())
                .ok_or_else(|| RulesDiagnostic::without_span(RulesError::UnknownField(joined)))
        }
        Expr::Lambda { .. } => Err(RulesDiagnostic::without_span(type_err(
            "a lambda (x => ...) is only the second argument of any, all, filter or map".into(),
        ))),
    };
    result.map_err(|d| d.or_span(span))
}

fn typecheck_binary(
    op: BinaryOp,
    lhs: &Expr,
    rhs: &Expr,
    schema: &Schema,
    cursor: &mut Cursor<'_>,
) -> Result<Type, RulesDiagnostic> {
    let lt = typecheck_node(lhs, schema, cursor)?;
    let rt = typecheck_node(rhs, schema, cursor)?;
    let result = match op {
        BinaryOp::Add => {
            if lt == Type::Number && rt == Type::Number {
                Ok(Type::Number)
            } else if lt == Type::Text && rt == Type::Text {
                Ok(Type::Text)
            } else {
                Err(type_err(format!(
                    "'+' needs (number, number) or (text, text), got ({lt}, {rt})"
                )))
            }
        }
        BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
            require(&lt, &Type::Number, &op.to_string())?;
            require(&rt, &Type::Number, &op.to_string())?;
            Ok(Type::Number)
        }
        BinaryOp::Eq | BinaryOp::Ne => {
            // BRU-C1 / D-620: a Choice and a Text compare by the choice's key.
            if lt.unify(&rt).is_none() && !choice_text_compatible(&lt, &rt) {
                return Err(RulesDiagnostic::without_span(type_err(format!(
                    "cannot compare {lt} with {rt}"
                ))));
            }
            Ok(Type::Bool)
        }
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            let ok = matches!(
                (&lt, &rt),
                (Type::Number, Type::Number) | (Type::Date, Type::Date)
            ) || matches!((&lt, &rt), (Type::Null, Type::Number | Type::Date))
                || matches!((&lt, &rt), (Type::Number | Type::Date, Type::Null));
            if ok {
                Ok(Type::Bool)
            } else {
                Err(type_err(format!(
                    "'{op}' needs (number, number) or (date, date), got ({lt}, {rt})"
                )))
            }
        }
        BinaryOp::And | BinaryOp::Or => {
            require(&lt, &Type::Bool, &op.to_string())?;
            require(&rt, &Type::Bool, &op.to_string())?;
            Ok(Type::Bool)
        }
    };
    result.map_err(RulesDiagnostic::without_span)
}

/// Z11-T3: `any`, `all`, `filter` and `map`: a list, then `x => body` with
/// `x` bound to an element (and `x.field` to a record element's field).
fn typecheck_lambda_call(
    name: &str,
    args: &[Expr],
    schema: &Schema,
    cursor: &mut Cursor<'_>,
) -> Result<Type, RulesDiagnostic> {
    arity(name, args.len(), 2, 2).map_err(RulesDiagnostic::without_span)?;
    let list = typecheck_node(&args[0], schema, cursor)?;
    let elem = match &list {
        Type::List(elem) => (**elem).clone(),
        Type::Null => Type::Null,
        other => {
            return Err(RulesDiagnostic::without_span(type_err(format!(
                "{name} takes a list, not {other}"
            ))));
        }
    };
    let Expr::Lambda { param, body } = &args[1] else {
        return Err(RulesDiagnostic::without_span(type_err(format!(
            "{name}'s second argument is a lambda: x => ..."
        ))));
    };
    // The lambda node's own span, then its body's.
    cursor.advance();
    let mut inner = schema.clone().with_field(param.clone(), elem.clone());
    if let Type::Record(fields) = &elem {
        inner = inner.with_related(param.clone(), fields.iter().cloned().collect());
    }
    let body_type = typecheck_node(body, &inner, cursor)?;
    match name {
        "map" => Ok(Type::List(Box::new(body_type))),
        _ => {
            require(&body_type, &Type::Bool, &format!("{name}'s condition"))
                .map_err(RulesDiagnostic::without_span)?;
            Ok(if name == "filter" {
                Type::List(Box::new(elem))
            } else {
                Type::Bool
            })
        }
    }
}

/// Z11-T3: the element type of a list argument of `name`.
fn list_elem(name: &str, t: &Type) -> Result<Type, RulesError> {
    match t {
        Type::List(elem) => Ok((**elem).clone()),
        Type::Null => Ok(Type::Null),
        other => Err(type_err(format!("{name} takes a list, not {other}"))),
    }
}

fn typecheck_call(
    name: &str,
    args: &[Expr],
    schema: &Schema,
    cursor: &mut Cursor<'_>,
) -> Result<Type, RulesDiagnostic> {
    let arg_types = args
        .iter()
        .map(|a| typecheck_node(a, schema, cursor))
        .collect::<Result<Vec<_>, _>>()?;

    let result = match name {
        "if" => {
            arity(name, args.len(), 3, 3)?;
            require(&arg_types[0], &Type::Bool, "if's condition")?;
            arg_types[1].unify(&arg_types[2]).ok_or_else(|| {
                type_err(format!(
                    "if's branches disagree: {} vs {}",
                    arg_types[1], arg_types[2]
                ))
            })
        }
        "coalesce" => {
            arity_at_least(name, args.len(), 1)?;
            let mut ty = Type::Null;
            for t in &arg_types {
                ty = ty.unify(t).ok_or_else(|| {
                    type_err(format!("coalesce's arguments disagree: {ty} vs {t}"))
                })?;
            }
            Ok(ty)
        }
        "len" => {
            arity(name, args.len(), 1, 1)?;
            match &arg_types[0] {
                Type::Text | Type::List(_) => Ok(Type::Number),
                other => Err(type_err(format!("len needs text or list, got {other}"))),
            }
        }
        "lower" | "upper" | "trim" => {
            arity(name, args.len(), 1, 1)?;
            require(&arg_types[0], &Type::Text, name)?;
            Ok(Type::Text)
        }
        "contains" => {
            arity(name, args.len(), 2, 2)?;
            match &arg_types[0] {
                Type::Text => {
                    require(&arg_types[1], &Type::Text, "contains' second argument")?;
                    Ok(Type::Bool)
                }
                Type::List(elem) => {
                    // BRU-C1: a list of choices may be searched with a text key.
                    if elem.unify(&arg_types[1]).is_none()
                        && !choice_text_compatible(elem, &arg_types[1])
                    {
                        return Err(RulesDiagnostic::without_span(type_err(format!(
                            "contains: list of {elem} cannot contain a {}",
                            arg_types[1]
                        ))));
                    }
                    Ok(Type::Bool)
                }
                other => Err(type_err(format!(
                    "contains needs text or list, got {other}"
                ))),
            }
        }
        "startswith" | "endswith" => {
            arity(name, args.len(), 2, 2)?;
            require(&arg_types[0], &Type::Text, name)?;
            require(&arg_types[1], &Type::Text, name)?;
            Ok(Type::Bool)
        }
        "date_add" => {
            arity(name, args.len(), 3, 3)?;
            require(&arg_types[0], &Type::Date, "date_add's date")?;
            require(&arg_types[1], &Type::Number, "date_add's amount")?;
            require(&arg_types[2], &Type::Text, "date_add's unit")?;
            Ok(Type::Date)
        }
        "date_diff" => {
            arity(name, args.len(), 3, 3)?;
            require(&arg_types[0], &Type::Date, "date_diff's first date")?;
            require(&arg_types[1], &Type::Date, "date_diff's second date")?;
            require(&arg_types[2], &Type::Text, "date_diff's unit")?;
            Ok(Type::Number)
        }
        "today" | "now" => {
            arity(name, args.len(), 0, 0)?;
            Ok(Type::Date)
        }
        "round" => {
            arity(name, args.len(), 1, 2)?;
            require(&arg_types[0], &Type::Number, "round")?;
            if let Some(t) = arg_types.get(1) {
                require(t, &Type::Number, "round's precision")?;
            }
            Ok(Type::Number)
        }
        "min" | "max" => {
            arity_at_least(name, args.len(), 1)?;
            if args.len() == 1 {
                match &arg_types[0] {
                    Type::List(elem) => {
                        elem.unify(&Type::Number).ok_or_else(|| {
                            type_err(format!("{name} needs a list of numbers, got list<{elem}>"))
                        })?;
                        Ok(Type::Number)
                    }
                    Type::Number => Ok(Type::Number),
                    other => Err(type_err(format!(
                        "{name} needs number(s) or a list of numbers, got {other}"
                    ))),
                }
            } else {
                for t in &arg_types {
                    require(t, &Type::Number, name)?;
                }
                Ok(Type::Number)
            }
        }
        "in" => {
            arity_at_least(name, args.len(), 2)?;
            let needle = &arg_types[0];
            if args.len() == 2
                && let Type::List(elem) = &arg_types[1]
            {
                // BRU-C1: a list of choices may be searched with a text key.
                if elem.unify(needle).is_none() && !choice_text_compatible(elem, needle) {
                    return Err(RulesDiagnostic::without_span(type_err(format!(
                        "in: list of {elem} cannot contain a {needle}"
                    ))));
                }
                return Ok(Type::Bool);
            }
            for t in &arg_types[1..] {
                if needle.unify(t).is_none() && !choice_text_compatible(needle, t) {
                    return Err(RulesDiagnostic::without_span(type_err(format!(
                        "in: {needle} cannot equal a {t}"
                    ))));
                }
            }
            Ok(Type::Bool)
        }
        "is_null" => {
            arity(name, args.len(), 1, 1)?;
            Ok(Type::Bool)
        }
        // T6-T2: whether a customer flag is on.
        "flag" => {
            arity(name, args.len(), 1, 1)?;
            require(&arg_types[0], &Type::Text, name)?;
            Ok(Type::Bool)
        }
        // A11-T2: a field of this record before the write, and whether the
        // write changes it.
        "prev" | "changed" => {
            arity(name, args.len(), 1, 1)?;
            if matches!(&args[0], Expr::FieldRef(r) if r.hop.is_none()) {
                Ok(if name == "prev" {
                    arg_types[0].clone()
                } else {
                    Type::Bool
                })
            } else {
                Err(type_err(format!("{name} takes a field of this record")))
            }
        }
        // Z11-T2 (V2).
        "normalize_ar" => {
            arity(name, args.len(), 1, 1)?;
            require(&arg_types[0], &Type::Text, name)?;
            Ok(Type::Text)
        }
        "concat" => {
            arity_at_least(name, args.len(), 1)?;
            for t in &arg_types {
                require(t, &Type::Text, name)?;
            }
            Ok(Type::Text)
        }
        "substr" => {
            arity(name, args.len(), 3, 3)?;
            require(&arg_types[0], &Type::Text, "substr's text")?;
            require(&arg_types[1], &Type::Number, "substr's start")?;
            require(&arg_types[2], &Type::Number, "substr's length")?;
            Ok(Type::Text)
        }
        "replace" => {
            arity(name, args.len(), 3, 3)?;
            for t in &arg_types {
                require(t, &Type::Text, name)?;
            }
            Ok(Type::Text)
        }
        "abs" | "floor" | "ceil" => {
            arity(name, args.len(), 1, 1)?;
            require(&arg_types[0], &Type::Number, name)?;
            Ok(Type::Number)
        }
        "power" => {
            arity(name, args.len(), 2, 2)?;
            require(&arg_types[0], &Type::Number, "power's base")?;
            require(&arg_types[1], &Type::Number, "power's exponent")?;
            Ok(Type::Number)
        }
        "clamp" => {
            arity(name, args.len(), 3, 3)?;
            for t in &arg_types {
                require(t, &Type::Number, name)?;
            }
            Ok(Type::Number)
        }
        // Z11-T5 (V2).
        "round_currency" => {
            arity(name, args.len(), 2, 2)?;
            require(&arg_types[0], &Type::Number, "round_currency's amount")?;
            require(&arg_types[1], &Type::Text, "round_currency's currency")?;
            Ok(Type::Number)
        }
        "convert" => {
            arity(name, args.len(), 3, 3)?;
            require(&arg_types[0], &Type::Number, "convert's amount")?;
            require(&arg_types[1], &Type::Text, "convert's from currency")?;
            require(&arg_types[2], &Type::Text, "convert's to currency")?;
            Ok(Type::Number)
        }
        "minor_units" => {
            arity(name, args.len(), 1, 1)?;
            require(&arg_types[0], &Type::Text, name)?;
            Ok(Type::Number)
        }
        // Z11-T6 (V2): the pattern is a literal, compiled at save.
        "matches" => {
            arity(name, args.len(), 2, 2)?;
            require(&arg_types[0], &Type::Text, "matches' text")?;
            if matches!(args[1], Expr::StringLit(_)) {
                Ok(Type::Bool)
            } else {
                Err(RulesError::RegexNotLiteral)
            }
        }
        // Z11-T4: Hijri, zone and working-day functions.
        "hijri_year" | "hijri_month" | "hijri_day" => {
            arity(name, args.len(), 1, 1)?;
            require(&arg_types[0], &Type::Date, name)?;
            Ok(Type::Number)
        }
        "hijri_date" => {
            arity(name, args.len(), 3, 3)?;
            for t in &arg_types {
                require(t, &Type::Number, name)?;
            }
            Ok(Type::Date)
        }
        "add_workdays" => {
            arity(name, args.len(), 2, 2)?;
            require(&arg_types[0], &Type::Date, name)?;
            require(&arg_types[1], &Type::Number, "add_workdays' count")?;
            Ok(Type::Date)
        }
        "workdays_between" => {
            arity(name, args.len(), 2, 2)?;
            require(&arg_types[0], &Type::Date, name)?;
            require(&arg_types[1], &Type::Date, name)?;
            Ok(Type::Number)
        }
        "is_working" => {
            arity(name, args.len(), 1, 1)?;
            require(&arg_types[0], &Type::Date, name)?;
            Ok(Type::Bool)
        }
        "to_zone" => {
            arity(name, args.len(), 2, 2)?;
            require(&arg_types[0], &Type::Date, name)?;
            require(&arg_types[1], &Type::Text, "to_zone's zone")?;
            Ok(Type::Date)
        }
        // Z11-T3: list functions over related lists.
        "sum" | "avg" => {
            arity(name, args.len(), 1, 1)?;
            let elem = list_elem(name, &arg_types[0])?;
            if elem.unify(&Type::Number).is_none() {
                return Err(RulesDiagnostic::without_span(type_err(format!(
                    "{name} takes a list of numbers, not of {elem}"
                ))));
            }
            Ok(Type::Number)
        }
        "count" => {
            arity(name, args.len(), 1, 1)?;
            list_elem(name, &arg_types[0]).map(|_| Type::Number)
        }
        "first" => {
            arity(name, args.len(), 1, 1)?;
            list_elem(name, &arg_types[0])
        }
        other => match schema.user_function(other) {
            // Z11-T8: its arguments against its parameters.
            Some(f) => arity(name, args.len(), f.params.len(), f.params.len()).and_then(|()| {
                for ((param, ty), actual) in f.params.iter().zip(&arg_types) {
                    if ty.unify(actual).is_none() {
                        return Err(type_err(format!(
                            "{name}'s {param} takes {ty}, not {actual}"
                        )));
                    }
                }
                Ok(f.returns.clone())
            }),
            None => Err(RulesError::UnknownFunction(other.to_owned())),
        },
    };
    result.map_err(RulesDiagnostic::without_span)
}

/// D-620: the one cross-type comparison the grammar admits — a Choice and a
/// Text compare by the choice's stable key, in either order. No ordering, no
/// arithmetic, and + still refuses a Choice.
fn choice_text_compatible(a: &Type, b: &Type) -> bool {
    matches!(
        (a, b),
        (Type::Choice, Type::Text) | (Type::Text, Type::Choice)
    )
}

/// Requires actual to *be* expected (with List<Null> still unifying to a
/// concrete list type). Since BRU-C2c a bare null no longer satisfies a
/// concrete requirement — -null, not null and "null and x" are refused — while
/// if(c, x, null), coalesce(null, x) and empty lists still type-check, because
/// those go through unify, not require.
fn require(actual: &Type, expected: &Type, ctx: &str) -> Result<(), RulesError> {
    if *actual == Type::Null {
        return Err(type_err(format!("{ctx} needs {expected}, got {actual}")));
    }
    match actual.unify(expected) {
        Some(u) if u == *expected => Ok(()),
        _ => Err(type_err(format!("{ctx} needs {expected}, got {actual}"))),
    }
}

fn arity(name: &str, got: usize, min: usize, max: usize) -> Result<(), RulesError> {
    if got < min || got > max {
        let expected = if min == max {
            min.to_string()
        } else {
            format!("{min}-{max}")
        };
        Err(RulesError::Arity {
            function: name.to_owned(),
            expected,
            got,
        })
    } else {
        Ok(())
    }
}

fn arity_at_least(name: &str, got: usize, min: usize) -> Result<(), RulesError> {
    if got < min {
        Err(RulesError::Arity {
            function: name.to_owned(),
            expected: format!(">= {min}"),
            got,
        })
    } else {
        Ok(())
    }
}

fn type_err(message: String) -> RulesError {
    RulesError::Type(message)
}

// ── BRU-C2b: compile-time null warnings ─────────────────────────────────────

/// Every field reference used by an operator that rejects Null, unless the
/// same field appears inside an is_null(..), coalesce(..) or
/// if(is_null(..), ..) guard somewhere in the rule. Sorted and deduplicated.
///
/// This is a purely syntactic, whole-rule guard set (a guard anywhere in the
/// expression silences the warning for that field everywhere in it), which is
/// what makes "is_null(amount) or amount > 100" quiet while "amount > 100"
/// warns. The runtime contract is unchanged: a null operand is still
/// RulesError::NullOperand (BRU-C2a, BRU-D2).
pub(crate) fn null_warnings(expr: &Expr) -> Vec<String> {
    let mut guarded = BTreeSet::new();
    collect_guards(expr, &mut guarded);
    let mut warnings = Vec::new();
    collect_warnings(expr, &guarded, &mut warnings);
    warnings
}

fn rejects_null_binary(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Mod
            | BinaryOp::Lt
            | BinaryOp::Le
            | BinaryOp::Gt
            | BinaryOp::Ge
            | BinaryOp::And
            | BinaryOp::Or
    )
}

fn rejects_null_call(name: &str) -> bool {
    matches!(
        name,
        "len"
            | "lower"
            | "upper"
            | "trim"
            | "contains"
            | "startswith"
            | "date_add"
            | "date_diff"
            | "normalize_ar"
            | "concat"
            | "substr"
            | "replace"
            | "abs"
            | "floor"
            | "ceil"
            | "power"
            | "clamp"
            | "round_currency"
            | "convert"
            | "minor_units"
            | "matches"
    )
}

fn collect_guards(expr: &Expr, guarded: &mut BTreeSet<String>) {
    match expr {
        Expr::Call { name, args } if name == "is_null" => {
            for a in args {
                collect_field_refs(a, guarded);
            }
        }
        Expr::Call { name, args } if name == "coalesce" => {
            for a in args {
                collect_field_refs(a, guarded);
            }
        }
        Expr::Call { name, args } if name == "if" => {
            if let Some(Expr::Call {
                name: cond_name,
                args: cond_args,
            }) = args.first()
                && cond_name == "is_null"
            {
                for c in cond_args {
                    collect_field_refs(c, guarded);
                }
            }
            for a in args {
                collect_guards(a, guarded);
            }
        }
        Expr::ListLit(items) => {
            for i in items {
                collect_guards(i, guarded);
            }
        }
        Expr::Unary { expr, .. } => collect_guards(expr, guarded),
        Expr::Binary { lhs, rhs, .. } => {
            collect_guards(lhs, guarded);
            collect_guards(rhs, guarded);
        }
        Expr::Call { args, .. } => {
            for a in args {
                collect_guards(a, guarded);
            }
        }
        _ => {}
    }
}

fn collect_field_refs(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::FieldRef(r) => {
            out.insert(r.to_string());
        }
        Expr::ListLit(items) => {
            for i in items {
                collect_field_refs(i, out);
            }
        }
        Expr::Unary { expr, .. } => collect_field_refs(expr, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect_field_refs(lhs, out);
            collect_field_refs(rhs, out);
        }
        Expr::Call { args, .. } => {
            for a in args {
                collect_field_refs(a, out);
            }
        }
        _ => {}
    }
}

fn push_refs(expr: &Expr, guarded: &BTreeSet<String>, out: &mut Vec<String>) {
    let mut refs = BTreeSet::new();
    collect_field_refs(expr, &mut refs);
    for r in refs {
        if !guarded.contains(&r) && !out.contains(&r) {
            out.push(r);
        }
    }
}

fn collect_warnings(expr: &Expr, guarded: &BTreeSet<String>, out: &mut Vec<String>) {
    match expr {
        Expr::Unary { expr, .. } => {
            push_refs(expr, guarded, out);
            collect_warnings(expr, guarded, out);
        }
        Expr::Binary { op, lhs, rhs } if rejects_null_binary(*op) => {
            push_refs(lhs, guarded, out);
            push_refs(rhs, guarded, out);
            collect_warnings(lhs, guarded, out);
            collect_warnings(rhs, guarded, out);
        }
        Expr::Binary { lhs, rhs, .. } => {
            collect_warnings(lhs, guarded, out);
            collect_warnings(rhs, guarded, out);
        }
        Expr::Call { name, args } if rejects_null_call(name) => {
            for a in args {
                push_refs(a, guarded, out);
            }
            for a in args {
                collect_warnings(a, guarded, out);
            }
        }
        Expr::Call { args, .. } => {
            for a in args {
                collect_warnings(a, guarded, out);
            }
        }
        Expr::ListLit(items) => {
            for i in items {
                collect_warnings(i, guarded, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::Budgets;
    use crate::parser::parse_with_spans;

    fn schema() -> Schema {
        Schema::new()
            .with_field("amount", Type::Number)
            .with_field("name", Type::Text)
            .with_field("active", Type::Bool)
            .with_field("opened", Type::Date)
            .with_field("status", Type::Choice)
            .with_field("owner", Type::Lookup)
            .with_related(
                "customer",
                [("tier".to_owned(), Type::Text)].into_iter().collect(),
            )
    }

    fn ty(src: &str) -> Result<Type, RulesError> {
        let parsed = parse_with_spans(src, &Budgets::default()).unwrap();
        typecheck(&parsed.expr, &schema(), &parsed.spans).map_err(RulesDiagnostic::into_error)
    }

    #[test]
    fn arithmetic_and_comparison() {
        assert_eq!(ty("amount + 1").unwrap(), Type::Number);
        assert_eq!(ty("amount > 1").unwrap(), Type::Bool);
        assert_eq!(ty("name == \"x\"").unwrap(), Type::Bool);
    }

    #[test]
    fn text_ordering_is_rejected() {
        assert!(matches!(ty("name > \"a\""), Err(RulesError::Type(_))));
    }

    #[test]
    fn text_concatenation_via_plus() {
        assert_eq!(ty("name + \"!\"").unwrap(), Type::Text);
    }

    #[test]
    fn if_unifies_branches() {
        assert_eq!(ty("if(active, 1, 2)").unwrap(), Type::Number);
        assert!(ty("if(active, 1, \"x\")").is_err());
    }

    #[test]
    fn unknown_field_is_rejected() {
        assert_eq!(ty("nope"), Err(RulesError::UnknownField("nope".to_owned())));
    }

    #[test]
    fn one_hop_lookup_resolves_via_schema() {
        assert_eq!(ty("customer.tier").unwrap(), Type::Text);
        assert_eq!(
            ty("customer.missing"),
            Err(RulesError::UnknownField("customer.missing".to_owned()))
        );
    }

    #[test]
    fn arity_errors_are_typed() {
        assert!(matches!(ty("today(1)"), Err(RulesError::Arity { .. })));
        assert!(matches!(ty("len()"), Err(RulesError::Arity { .. })));
    }

    #[test]
    fn unknown_function_is_rejected() {
        assert_eq!(
            ty("nope()"),
            Err(RulesError::UnknownFunction("nope".to_owned()))
        );
    }

    #[test]
    fn in_and_min_max_over_lists() {
        assert_eq!(ty("in(amount, [1, 2, 3])").unwrap(), Type::Bool);
        assert_eq!(ty("in(amount, 1, 2, 3)").unwrap(), Type::Bool);
        assert_eq!(ty("min([1, 2, 3])").unwrap(), Type::Number);
        assert_eq!(ty("max(1, 2, 3)").unwrap(), Type::Number);
    }

    // ── BRU-C1 (D-620): Choice compares with Text by key ────────────────────

    #[test]
    fn choice_compares_with_text_in_either_order() {
        assert_eq!(ty("status == \"open\"").unwrap(), Type::Bool);
        assert_eq!(ty("\"open\" == status").unwrap(), Type::Bool);
        assert_eq!(ty("status != \"open\"").unwrap(), Type::Bool);
        assert_eq!(
            ty("in(status, [\"open\", \"closed\"])").unwrap(),
            Type::Bool
        );
        assert_eq!(ty("in(status, \"open\", \"closed\")").unwrap(), Type::Bool);
        assert_eq!(
            ty("contains([\"open\", \"closed\"], status)").unwrap(),
            Type::Bool
        );
    }

    #[test]
    fn choice_still_refuses_arithmetic_ordering_and_concatenation() {
        assert!(matches!(ty("status + \"x\""), Err(RulesError::Type(_))));
        assert!(matches!(ty("status > \"x\""), Err(RulesError::Type(_))));
        assert!(matches!(ty("status * 2"), Err(RulesError::Type(_))));
    }

    // ── BRU-C2c: a bare null no longer satisfies a concrete type ────────────

    #[test]
    fn bare_null_is_refused_where_a_concrete_type_is_required() {
        assert!(matches!(ty("-null"), Err(RulesError::Type(_))));
        assert!(matches!(ty("not null"), Err(RulesError::Type(_))));
        assert!(matches!(ty("null and active"), Err(RulesError::Type(_))));
        assert!(matches!(ty("len(null)"), Err(RulesError::Type(_))));
    }

    #[test]
    fn null_still_works_where_it_is_a_branch_or_element_type() {
        assert_eq!(ty("if(active, 1, null)").unwrap(), Type::Number);
        assert_eq!(ty("coalesce(null, 1)").unwrap(), Type::Number);
        assert_eq!(ty("in(amount, [])").unwrap(), Type::Bool);
        assert_eq!(ty("len([])").unwrap(), Type::Number);
    }

    // ── BRU-C2b: compile-time null warnings ────────────────────────────────

    fn warnings(src: &str) -> Vec<String> {
        let parsed = parse_with_spans(src, &Budgets::default()).unwrap();
        null_warnings(&parsed.expr)
    }

    #[test]
    fn unguarded_null_rejecting_operators_warn() {
        assert_eq!(warnings("amount > 100"), vec!["amount".to_owned()]);
        assert_eq!(warnings("amount + 1 > 2"), vec!["amount".to_owned()]);
        assert_eq!(warnings("len(name)"), vec!["name".to_owned()]);
        assert_eq!(warnings("1 == 1"), Vec::<String>::new());
    }

    #[test]
    fn a_guard_silences_the_warning_for_that_field() {
        assert!(warnings("is_null(amount) or amount > 100").is_empty());
        assert!(warnings("coalesce(amount, 0) > 100").is_empty());
        assert!(warnings("if(is_null(amount), false, amount > 100)").is_empty());
        // A guard for one field does not silence another.
        assert_eq!(
            warnings("is_null(name) or amount > 100"),
            vec!["amount".to_owned()]
        );
    }
}

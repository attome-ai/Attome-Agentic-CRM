//! Decision tables (roadmap Z11-T9): rows of conditions on named inputs and
//! a result, read top to bottom.
//!
//! A cell is a V2 expression over the one input it sits under, named `it`
//! (`it >= 100 and it < 500`, `it == "gold"`, `in(it, ["a", "b"])`), or empty
//! for any value. A row's result is a V2 expression over every input. Every
//! cell and result is compiled once, by [`DecisionTable::compile`].
//!
//! - [`HitPolicy::First`]: the first row whose cells all hold gives the
//!   result; `null` when none does.
//! - [`HitPolicy::All`]: the results of every matching row, in row order, as
//!   a list.
//!
//! [`CompiledTable::check`] reports, without evaluating anything:
//! - **gaps**: number ranges of one input no row covers;
//! - **overlaps**: two rows that can both match the same inputs (under
//!   `First` the later one never fires for those values);
//! - **unchecked** cells: any form other than `it == literal`,
//!   `in(it, [literals])`, or a comparison of `it` with a number literal
//!   (alone or two joined by `and`). Gaps and overlaps are exact for the
//!   forms above and never claimed for an unchecked cell.

use std::ops::Bound;

use crate::ast::{BinaryOp, UnaryOp};
use crate::{
    BudgetKind, Budgets, Compiled, Context, Expr, LanguageVersion, RulesError, Schema, Type, Value,
    compile_versioned,
};

/// The most rows a table may have.
pub const MAX_ROWS: usize = 500;
/// The most inputs a table may have.
pub const MAX_INPUTS: usize = 10;

/// The name a cell reads its input by.
pub const CELL_INPUT: &str = "it";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitPolicy {
    First,
    All,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionRow {
    /// One per input; `None` matches any value.
    pub cells: Vec<Option<String>>,
    pub result: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionTable {
    pub inputs: Vec<(String, Type)>,
    pub output: Type,
    pub hit: HitPolicy,
    pub rows: Vec<DecisionRow>,
}

/// What [`CompiledTable::check`] found.
#[derive(Debug, Clone, PartialEq)]
pub enum TableIssue {
    /// No row covers the numbers of `input` from `from` to `to`.
    Gap {
        input: String,
        from: Bound<f64>,
        to: Bound<f64>,
    },
    /// Rows `rows.0` and `rows.1` (zero-based) can both match.
    Overlap { rows: (usize, usize) },
    /// The cell of `row` under `input` has a form the check cannot read.
    Unchecked { row: usize, input: String },
}

#[derive(Debug, Clone)]
struct CompiledRow {
    cells: Vec<Option<Compiled>>,
    result: Compiled,
}

/// A literal a checked cell compares with.
#[derive(Debug, Clone, PartialEq)]
enum Lit {
    Num(f64),
    Text(String),
    Bool(bool),
}

/// An interval of numbers.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Interval {
    lo: Bound<f64>,
    hi: Bound<f64>,
}

impl Interval {
    const ALL: Interval = Interval {
        lo: Bound::Unbounded,
        hi: Bound::Unbounded,
    };

    fn point(v: f64) -> Self {
        Self {
            lo: Bound::Included(v),
            hi: Bound::Included(v),
        }
    }

    fn is_empty(&self) -> bool {
        match (self.lo, self.hi) {
            (Bound::Unbounded, _) | (_, Bound::Unbounded) => false,
            (Bound::Included(a), Bound::Included(b)) => a > b,
            (Bound::Included(a), Bound::Excluded(b))
            | (Bound::Excluded(a), Bound::Included(b))
            | (Bound::Excluded(a), Bound::Excluded(b)) => a >= b,
        }
    }

    fn intersect(&self, other: &Interval) -> Interval {
        Interval {
            lo: max_lower(self.lo, other.lo),
            hi: min_upper(self.hi, other.hi),
        }
    }

    fn contains(&self, v: f64) -> bool {
        !Interval::point(v).intersect(self).is_empty()
    }
}

/// The later of two lower bounds.
fn max_lower(a: Bound<f64>, b: Bound<f64>) -> Bound<f64> {
    match (a, b) {
        (Bound::Unbounded, x) | (x, Bound::Unbounded) => x,
        (Bound::Included(x), Bound::Included(y)) => Bound::Included(x.max(y)),
        (Bound::Excluded(x), Bound::Excluded(y)) => Bound::Excluded(x.max(y)),
        (Bound::Included(i), Bound::Excluded(e)) | (Bound::Excluded(e), Bound::Included(i)) => {
            if i > e {
                Bound::Included(i)
            } else {
                Bound::Excluded(e)
            }
        }
    }
}

/// The earlier of two upper bounds.
fn min_upper(a: Bound<f64>, b: Bound<f64>) -> Bound<f64> {
    match (a, b) {
        (Bound::Unbounded, x) | (x, Bound::Unbounded) => x,
        (Bound::Included(x), Bound::Included(y)) => Bound::Included(x.min(y)),
        (Bound::Excluded(x), Bound::Excluded(y)) => Bound::Excluded(x.min(y)),
        (Bound::Included(i), Bound::Excluded(e)) | (Bound::Excluded(e), Bound::Included(i)) => {
            if i < e {
                Bound::Included(i)
            } else {
                Bound::Excluded(e)
            }
        }
    }
}

/// The later of two upper bounds.
fn max_upper(a: Bound<f64>, b: Bound<f64>) -> Bound<f64> {
    match (a, b) {
        (Bound::Unbounded, _) | (_, Bound::Unbounded) => Bound::Unbounded,
        (Bound::Included(x), Bound::Included(y)) => Bound::Included(x.max(y)),
        (Bound::Excluded(x), Bound::Excluded(y)) => Bound::Excluded(x.max(y)),
        (Bound::Included(i), Bound::Excluded(e)) | (Bound::Excluded(e), Bound::Included(i)) => {
            if i >= e {
                Bound::Included(i)
            } else {
                Bound::Excluded(e)
            }
        }
    }
}

/// Lower bounds in sweep order (an earlier start first).
fn lower_key(b: Bound<f64>) -> (u8, f64, u8) {
    match b {
        Bound::Unbounded => (0, 0.0, 0),
        Bound::Included(x) => (1, x, 0),
        Bound::Excluded(x) => (1, x, 1),
    }
}

/// A checked cell.
#[derive(Debug, Clone, PartialEq)]
enum Form {
    Any,
    Values(Vec<Lit>),
    Range(Interval),
    Other,
}

fn number(expr: &Expr) -> Option<f64> {
    match expr {
        Expr::NumberLit(n) => Some(*n),
        Expr::Unary {
            op: UnaryOp::Neg,
            expr,
        } => match expr.as_ref() {
            Expr::NumberLit(n) => Some(-n),
            _ => None,
        },
        _ => None,
    }
}

fn literal(expr: &Expr) -> Option<Lit> {
    match expr {
        Expr::StringLit(s) => Some(Lit::Text(s.clone())),
        Expr::BoolLit(b) => Some(Lit::Bool(*b)),
        other => number(other).map(Lit::Num),
    }
}

fn is_input(expr: &Expr) -> bool {
    matches!(expr, Expr::FieldRef(f) if f.base == CELL_INPUT && f.hop.is_none())
}

/// `it <op> n`, as an interval.
fn comparison(op: BinaryOp, n: f64) -> Option<Interval> {
    let (lo, hi) = match op {
        BinaryOp::Lt => (Bound::Unbounded, Bound::Excluded(n)),
        BinaryOp::Le => (Bound::Unbounded, Bound::Included(n)),
        BinaryOp::Gt => (Bound::Excluded(n), Bound::Unbounded),
        BinaryOp::Ge => (Bound::Included(n), Bound::Unbounded),
        _ => return None,
    };
    Some(Interval { lo, hi })
}

/// The same comparison with its sides swapped (`n < it` is `it > n`).
fn flipped(op: BinaryOp) -> BinaryOp {
    match op {
        BinaryOp::Lt => BinaryOp::Gt,
        BinaryOp::Le => BinaryOp::Ge,
        BinaryOp::Gt => BinaryOp::Lt,
        BinaryOp::Ge => BinaryOp::Le,
        other => other,
    }
}

fn form_of(expr: &Expr) -> Form {
    match expr {
        Expr::Binary { op, lhs, rhs } if *op == BinaryOp::Eq => {
            let lit = if is_input(lhs) {
                literal(rhs)
            } else if is_input(rhs) {
                literal(lhs)
            } else {
                None
            };
            match lit {
                Some(Lit::Num(n)) => Form::Range(Interval::point(n)),
                Some(lit) => Form::Values(vec![lit]),
                None => Form::Other,
            }
        }
        Expr::Binary { op, lhs, rhs } if *op == BinaryOp::And => {
            match (form_of(lhs), form_of(rhs)) {
                (Form::Range(a), Form::Range(b)) => Form::Range(a.intersect(&b)),
                _ => Form::Other,
            }
        }
        Expr::Binary { op, lhs, rhs } => {
            let found = if is_input(lhs) {
                number(rhs).and_then(|n| comparison(*op, n))
            } else if is_input(rhs) {
                number(lhs).and_then(|n| comparison(flipped(*op), n))
            } else {
                None
            };
            found.map_or(Form::Other, Form::Range)
        }
        Expr::Call { name, args } if name == "in" && args.len() == 2 && is_input(&args[0]) => {
            match &args[1] {
                // Numbers in the list are points, checked against other
                // values and ranges.
                Expr::ListLit(items) => items
                    .iter()
                    .map(literal)
                    .collect::<Option<Vec<Lit>>>()
                    .map_or(Form::Other, Form::Values),
                _ => Form::Other,
            }
        }
        _ => Form::Other,
    }
}

/// Whether two checked cells can both hold for one value; `None` when one
/// of them is unchecked.
fn intersects(a: &Form, b: &Form) -> Option<bool> {
    Some(match (a, b) {
        (Form::Other, _) | (_, Form::Other) => return None,
        (Form::Any, _) | (_, Form::Any) => true,
        (Form::Values(x), Form::Values(y)) => x.iter().any(|v| y.contains(v)),
        (Form::Values(x), Form::Range(r)) | (Form::Range(r), Form::Values(x)) => {
            x.iter().any(|v| matches!(v, Lit::Num(n) if r.contains(*n)))
        }
        (Form::Range(x), Form::Range(y)) => !x.intersect(y).is_empty(),
    })
}

/// The number ranges `covered` leaves out, in order.
fn gaps(mut covered: Vec<Interval>) -> Vec<(Bound<f64>, Bound<f64>)> {
    covered.retain(|i| !i.is_empty());
    covered.sort_by(|a, b| {
        let (x, y) = (lower_key(a.lo), lower_key(b.lo));
        x.0.cmp(&y.0).then(x.1.total_cmp(&y.1)).then(x.2.cmp(&y.2))
    });
    let mut out = Vec::new();
    // How far the intervals so far reach; `None` before the first.
    let mut reach: Option<Bound<f64>> = None;
    for interval in covered {
        match reach {
            None => {
                if interval.lo != Bound::Unbounded {
                    let to = match interval.lo {
                        Bound::Included(l) => Bound::Excluded(l),
                        Bound::Excluded(l) => Bound::Included(l),
                        Bound::Unbounded => Bound::Unbounded,
                    };
                    out.push((Bound::Unbounded, to));
                }
                reach = Some(interval.hi);
            }
            Some(Bound::Unbounded) => return out,
            Some(r) => {
                let gap = match (r, interval.lo) {
                    (_, Bound::Unbounded) => None,
                    (Bound::Included(r), Bound::Included(l)) if l > r => {
                        Some((Bound::Excluded(r), Bound::Excluded(l)))
                    }
                    (Bound::Included(r), Bound::Excluded(l)) if l > r => {
                        Some((Bound::Excluded(r), Bound::Included(l)))
                    }
                    (Bound::Excluded(r), Bound::Included(l)) if l > r => {
                        Some((Bound::Included(r), Bound::Excluded(l)))
                    }
                    (Bound::Excluded(r), Bound::Excluded(l)) if l >= r => {
                        Some((Bound::Included(r), Bound::Included(l)))
                    }
                    _ => None,
                };
                if let Some(gap) = gap {
                    out.push(gap);
                }
                reach = Some(max_upper(r, interval.hi));
            }
        }
    }
    match reach {
        None => out.push((Bound::Unbounded, Bound::Unbounded)),
        Some(Bound::Included(r)) => out.push((Bound::Excluded(r), Bound::Unbounded)),
        Some(Bound::Excluded(r)) => out.push((Bound::Included(r), Bound::Unbounded)),
        Some(Bound::Unbounded) => {}
    }
    out
}

/// A table whose cells and results are compiled.
#[derive(Debug, Clone)]
pub struct CompiledTable {
    inputs: Vec<(String, Type)>,
    hit: HitPolicy,
    rows: Vec<CompiledRow>,
    /// Per row, per input, the cell's checked form.
    forms: Vec<Vec<Form>>,
}

impl DecisionTable {
    /// Compiles every cell (V2, over `it`, returning bool) and every result
    /// (V2, over the inputs, returning [`DecisionTable::output`]) once.
    pub fn compile(&self, budgets: Budgets) -> Result<CompiledTable, RulesError> {
        if self.rows.len() > MAX_ROWS || self.inputs.len() > MAX_INPUTS {
            return Err(RulesError::Budget(BudgetKind::TableSize));
        }
        let mut result_schema = Schema::new();
        for (name, ty) in &self.inputs {
            result_schema = result_schema.with_field(name.clone(), ty.clone());
        }
        let mut rows = Vec::with_capacity(self.rows.len());
        let mut forms = Vec::with_capacity(self.rows.len());
        for (n, row) in self.rows.iter().enumerate() {
            if row.cells.len() != self.inputs.len() {
                return Err(RulesError::Type(format!(
                    "row {} has {} cells; the table has {} inputs",
                    n + 1,
                    row.cells.len(),
                    self.inputs.len()
                )));
            }
            let mut cells = Vec::with_capacity(row.cells.len());
            let mut row_forms = Vec::with_capacity(row.cells.len());
            for (cell, (input, ty)) in row.cells.iter().zip(&self.inputs) {
                let Some(source) = cell.as_deref().filter(|s| !s.trim().is_empty()) else {
                    cells.push(None);
                    row_forms.push(Form::Any);
                    continue;
                };
                let schema = Schema::new().with_field(CELL_INPUT, ty.clone());
                let compiled = compile_versioned(source, &schema, LanguageVersion::V2, budgets)?;
                if compiled.result_type().unify(&Type::Bool).is_none() {
                    return Err(RulesError::Type(format!(
                        "row {} cell {input}: a cell is a condition (bool), not {}",
                        n + 1,
                        compiled.result_type()
                    )));
                }
                row_forms.push(crate::parse(source).map_or(Form::Other, |e| form_of(&e)));
                cells.push(Some(compiled));
            }
            let result =
                compile_versioned(&row.result, &result_schema, LanguageVersion::V2, budgets)?;
            if result.result_type().unify(&self.output).is_none() {
                return Err(RulesError::Type(format!(
                    "row {} result is {}, the table answers {}",
                    n + 1,
                    result.result_type(),
                    self.output
                )));
            }
            rows.push(CompiledRow { cells, result });
            forms.push(row_forms);
        }
        Ok(CompiledTable {
            inputs: self.inputs.clone(),
            hit: self.hit,
            rows,
            forms,
        })
    }
}

impl CompiledTable {
    /// The table's answer for the inputs in `ctx` (a missing input is
    /// `null`): the first match's result, or `null` (`First`); every match's
    /// result as a list (`All`).
    pub fn eval(&self, ctx: &Context) -> Result<Value, RulesError> {
        let cell_contexts: Vec<Context> = self
            .inputs
            .iter()
            .map(|(name, _)| {
                let value = ctx.field(name).cloned().unwrap_or(Value::Null);
                ctx.clone().with_field(CELL_INPUT, value)
            })
            .collect();
        let mut all = Vec::new();
        for row in &self.rows {
            let mut matched = true;
            for (cell, cell_ctx) in row.cells.iter().zip(&cell_contexts) {
                let Some(cell) = cell else { continue };
                if cell.eval(cell_ctx)? != Value::Bool(true) {
                    matched = false;
                    break;
                }
            }
            if !matched {
                continue;
            }
            let result = row.result.eval(ctx)?;
            match self.hit {
                HitPolicy::First => return Ok(result),
                HitPolicy::All => all.push(result),
            }
        }
        Ok(match self.hit {
            HitPolicy::First => Value::Null,
            HitPolicy::All => Value::List(all),
        })
    }

    /// Gaps, overlaps and unchecked cells (see the module doc).
    pub fn check(&self) -> Vec<TableIssue> {
        let mut issues = Vec::new();
        for (row, forms) in self.forms.iter().enumerate() {
            for (form, (input, _)) in forms.iter().zip(&self.inputs) {
                if *form == Form::Other {
                    issues.push(TableIssue::Unchecked {
                        row,
                        input: input.clone(),
                    });
                }
            }
        }
        for (i, (input, ty)) in self.inputs.iter().enumerate() {
            if *ty != Type::Number {
                continue;
            }
            let mut covered = Vec::new();
            let mut checkable = true;
            for forms in &self.forms {
                match &forms[i] {
                    Form::Any => covered.push(Interval::ALL),
                    Form::Range(r) => covered.push(*r),
                    Form::Values(values) => {
                        for v in values {
                            if let Lit::Num(n) = v {
                                covered.push(Interval::point(*n));
                            }
                        }
                    }
                    Form::Other => checkable = false,
                }
            }
            if !checkable {
                continue;
            }
            for (from, to) in gaps(covered) {
                issues.push(TableIssue::Gap {
                    input: input.clone(),
                    from,
                    to,
                });
            }
        }
        for a in 0..self.forms.len() {
            for b in (a + 1)..self.forms.len() {
                let both = self.forms[a]
                    .iter()
                    .zip(&self.forms[b])
                    .map(|(x, y)| intersects(x, y))
                    .collect::<Option<Vec<bool>>>();
                if both.is_some_and(|cells| cells.iter().all(|c| *c)) {
                    issues.push(TableIssue::Overlap { rows: (a, b) });
                }
            }
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(src: &str) -> Form {
        form_of(&crate::parse(src).unwrap_or_else(|e| panic!("{e}")))
    }

    #[test]
    fn cell_forms_read() {
        assert_eq!(
            form("it >= 100 and it < 500"),
            Form::Range(Interval {
                lo: Bound::Included(100.0),
                hi: Bound::Excluded(500.0)
            })
        );
        assert_eq!(
            form("10 < it"),
            Form::Range(Interval {
                lo: Bound::Excluded(10.0),
                hi: Bound::Unbounded
            })
        );
        assert_eq!(
            form("it == \"gold\""),
            Form::Values(vec![Lit::Text("gold".into())])
        );
        assert_eq!(form("it == -1"), Form::Range(Interval::point(-1.0)));
        assert_eq!(form("it * 2 > 10"), Form::Other);
    }

    #[test]
    fn gaps_between_ranges() {
        let r = |lo, hi| Interval { lo, hi };
        let found = gaps(vec![
            r(Bound::Unbounded, Bound::Excluded(100.0)),
            r(Bound::Included(200.0), Bound::Unbounded),
        ]);
        assert_eq!(
            found,
            vec![(Bound::Included(100.0), Bound::Excluded(200.0))]
        );
        assert!(gaps(vec![Interval::ALL]).is_empty());
        let touching = gaps(vec![
            r(Bound::Unbounded, Bound::Excluded(100.0)),
            r(Bound::Included(100.0), Bound::Unbounded),
        ]);
        assert!(touching.is_empty());
        let missing_point = gaps(vec![
            r(Bound::Unbounded, Bound::Excluded(100.0)),
            r(Bound::Excluded(100.0), Bound::Unbounded),
        ]);
        assert_eq!(
            missing_point,
            vec![(Bound::Included(100.0), Bound::Included(100.0))]
        );
    }
}

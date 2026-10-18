//! The parsed expression tree. Deliberately flat: there are no statements,
//! no loops, no user-defined functions, and no assignment — the grammar the
//! plan lists (M45 §5) is the entire surface, so `if`/`coalesce`/`min`/… are
//! just [`Expr::Call`] nodes the type checker and evaluator special-case by
//! name, rather than dedicated AST variants. That keeps the grammar closed:
//! adding a function is a decision-log-worthy change to one match arm in
//! `typecheck.rs` + `eval.rs`, not a new parser production.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    NullLit,
    BoolLit(bool),
    NumberLit(f64),
    StringLit(String),
    /// `[a, b, c]` — a list literal.
    ListLit(Vec<Expr>),
    /// `field_name` or `lookup_field.target_field` (exactly one hop —
    /// `a.b.c` is rejected by the parser as `RulesError::MultiHopLookup`).
    FieldRef(FieldRef),
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinaryOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// `name(args...)` — covers every function in the grammar (`if`,
    /// `coalesce`, `len`, `lower`, `upper`, `trim`, `contains`,
    /// `startswith`, `date_add`, `date_diff`, `today`, `now`, `round`,
    /// `min`, `max`, `in`, `is_null`).
    Call {
        name: String,
        args: Vec<Expr>,
    },
    /// Z11-T3 (V2): `param => body`, only as the second argument of `any`,
    /// `all`, `filter` or `map`; `param.field` reads a field of the element.
    Lambda {
        param: String,
        body: Box<Expr>,
    },
}

impl Expr {
    /// Total node count, `self` included — checked against
    /// `Budgets::max_ast_nodes` right after parsing, before type-checking or
    /// eval ever touch the tree.
    pub fn node_count(&self) -> usize {
        1 + match self {
            Expr::NullLit
            | Expr::BoolLit(_)
            | Expr::NumberLit(_)
            | Expr::StringLit(_)
            | Expr::FieldRef(_) => 0,
            Expr::ListLit(items) => items.iter().map(Expr::node_count).sum(),
            Expr::Unary { expr, .. } => expr.node_count(),
            Expr::Binary { lhs, rhs, .. } => lhs.node_count() + rhs.node_count(),
            Expr::Call { args, .. } => args.iter().map(Expr::node_count).sum(),
            Expr::Lambda { body, .. } => body.node_count(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRef {
    pub base: String,
    /// `Some(target_field)` for a `lookup_field.target_field` reference;
    /// `None` for a bare `field_name`.
    pub hop: Option<String>,
}

impl fmt::Display for FieldRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.hop {
            Some(hop) => write!(f, "{}.{}", self.base, hop),
            None => write!(f, "{}", self.base),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// Numeric negation, `-x`.
    Neg,
    /// Boolean `not x`.
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
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
    And,
    Or,
}

impl fmt::Display for BinaryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::Mul => "*",
            BinaryOp::Div => "/",
            BinaryOp::Mod => "%",
            BinaryOp::Eq => "==",
            BinaryOp::Ne => "!=",
            BinaryOp::Lt => "<",
            BinaryOp::Le => "<=",
            BinaryOp::Gt => ">",
            BinaryOp::Ge => ">=",
            BinaryOp::And => "and",
            BinaryOp::Or => "or",
        };
        f.write_str(s)
    }
}

/// Renders `Expr` back to source-like text — used for `Trace` entries and
/// error messages, so a consumer can show "which sub-expression evaluated to
/// what" without holding onto the original source spans.
impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::NullLit => write!(f, "null"),
            Expr::BoolLit(b) => write!(f, "{b}"),
            Expr::NumberLit(n) => write!(f, "{n}"),
            Expr::StringLit(s) => write!(f, "{s:?}"),
            Expr::ListLit(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            Expr::FieldRef(r) => write!(f, "{r}"),
            Expr::Unary {
                op: UnaryOp::Neg,
                expr,
            } => write!(f, "-{expr}"),
            Expr::Unary {
                op: UnaryOp::Not,
                expr,
            } => write!(f, "not {expr}"),
            Expr::Binary { op, lhs, rhs } => write!(f, "({lhs} {op} {rhs})"),
            Expr::Call { name, args } => {
                write!(f, "{name}(")?;
                for (i, a) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{a}")?;
                }
                write!(f, ")")
            }
            Expr::Lambda { param, body } => write!(f, "{param} => {body}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_count_counts_self_and_children() {
        let e = Expr::Binary {
            op: BinaryOp::Add,
            lhs: Box::new(Expr::NumberLit(1.0)),
            rhs: Box::new(Expr::NumberLit(2.0)),
        };
        assert_eq!(e.node_count(), 3);
    }

    #[test]
    fn display_round_trips_readably() {
        let e = Expr::Call {
            name: "if".to_owned(),
            args: vec![
                Expr::BoolLit(true),
                Expr::NumberLit(1.0),
                Expr::NumberLit(2.0),
            ],
        };
        assert_eq!(e.to_string(), "if(true, 1, 2)");
    }
}

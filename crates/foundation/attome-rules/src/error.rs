//! Typed errors and diagnostics. Every failure mode `attome-rules` can
//! produce is represented here — parsing, type-checking, and evaluation never
//! panic (coding guidelines §6); an unrecognised or malformed input always
//! returns one of these variants instead.
//!
//! Two things live beside `RulesError` (BRU-FX1/FX2):
//!
//! - `RulesDiagnostic` — a `RulesError` plus the byte span of the
//!   sub-expression it came from, so the bilingual admin UI can underline the
//!   offending text. The span is a side table (`Spans`), never a field on
//!   `Expr`: putting spans on `Expr` would break `xrm-metric`'s
//!   `collect_field_refs` and every test that builds an `Expr` by hand
//!   (plan §9, "Expr carrying spans" — rejected).
//! - `RulesError::code()` — a stable, language-independent code per variant,
//!   and `RulesError::is_transient()` — whether a retry could succeed.

use std::fmt;

/// The specific budget a compile or eval exceeded. See [`crate::budget::Budgets`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    /// The parsed expression has more AST nodes than `Budgets::max_ast_nodes`.
    AstNodes,
    /// Nesting depth exceeded the parser's stack-overflow guard.
    RecursionDepth,
    /// Evaluation visited more sub-expressions than `Budgets::max_eval_steps`.
    EvalSteps,
    /// Evaluation ran longer than `Budgets::max_wall_clock`.
    WallClock,
    /// A `Text` value (literal or computed) exceeded `Budgets::max_string_len`.
    StringLength,
    /// The source text itself exceeded the crate's hard source-length ceiling
    /// (independent of the caller-configurable budgets — see
    /// `budget::HARD_MAX_SOURCE_BYTES`), so lexing never even starts.
    SourceLength,
    /// A `List` value arriving through `Context` exceeded
    /// `Budgets::max_list_len` (BRU-E2).
    ListLength,
    /// Z11-T9: a decision table with more rows or inputs than
    /// `decision_table::MAX_ROWS` / `MAX_INPUTS`.
    TableSize,
}

impl BudgetKind {
    /// Stable, language-independent code for this budget (BRU-FX2) — one per
    /// kind, so a consumer can count rules.budget.wall_clock separately from
    /// rules.budget.ast_nodes.
    pub fn code(&self) -> &'static str {
        match self {
            Self::AstNodes => "rules.budget.ast_nodes",
            Self::RecursionDepth => "rules.budget.recursion_depth",
            Self::EvalSteps => "rules.budget.eval_steps",
            Self::WallClock => "rules.budget.wall_clock",
            Self::StringLength => "rules.budget.string_length",
            Self::SourceLength => "rules.budget.source_length",
            Self::ListLength => "rules.budget.list_length",
            Self::TableSize => "rules.budget.table_size",
        }
    }
}

impl fmt::Display for BudgetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AstNodes => "AST node cap",
            Self::RecursionDepth => "nesting-depth cap",
            Self::EvalSteps => "evaluation-step cap",
            Self::WallClock => "wall-clock ceiling",
            Self::StringLength => "max string length",
            Self::SourceLength => "max source length",
            Self::ListLength => "max list length",
            Self::TableSize => "max decision table size",
        };
        f.write_str(s)
    }
}

/// Every way a `attome-rules` expression can fail to compile or evaluate.
///
/// `Clone` + `PartialEq` so callers (and this crate's own tests) can assert
/// on the exact variant without formatting strings. Never constructed from a
/// panic — see the crate-level "no-panic" property test (`tests/property.rs`).
///
/// The variants added after the crate's first release (`NumericOverflow`,
/// `NullOperand`, `ContextTypeMismatch`) are *additive*: no consumer
/// matches `RulesError` exhaustively, so a new variant is source-compatible
/// (plan §2.1).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum RulesError {
    #[error("parse error at byte {pos}: {message}")]
    Parse { message: String, pos: usize },

    #[error("type error: {0}")]
    Type(String),

    #[error("unknown field: {0}")]
    UnknownField(String),

    #[error(
        "field reference '{0}' has more than one hop — attome-rules supports only \
         one-hop lookup.field references (M45 plan §5)"
    )]
    MultiHopLookup(String),

    #[error("unknown function: {0}")]
    UnknownFunction(String),

    #[error("{function} expects {expected} argument(s), got {got}")]
    Arity {
        function: String,
        expected: String,
        got: usize,
    },

    #[error("division by zero")]
    DivideByZero,

    #[error("evaluation error: {0}")]
    Eval(String),

    /// A numeric result was not finite (BRU-B1). The message deliberately
    /// carries no value: error text must never leak record data (plan §6A).
    #[error("numeric overflow")]
    NumericOverflow,

    /// A `null` operand reached an operator that cannot accept one
    /// (BRU-C2a). `op` names the operator, never the value.
    #[error("{op} needs a non-null value")]
    NullOperand { op: String },

    /// A `Context` value's runtime type is neither the type `compile` was
    /// given for that field nor `Null` (BRU-C3).
    #[error("context field '{field}' does not match its declared type")]
    ContextTypeMismatch { field: String },

    /// BRU-C4: the IANA zone name a caller supplied is not in the tz database.
    /// Its own variant rather than Eval so the admin UI can say "unknown time
    /// zone" and the caller can fix configuration; never a silent fall back to
    /// UTC, which would evaluate a rule in the wrong zone.
    #[error("unknown timezone: {0}")]
    UnknownTimezone(String),

    #[error("{0} exceeded")]
    Budget(BudgetKind),

    /// Z11-T5: a currency code the ISO 4217 table does not know.
    #[error("unknown currency: {0}")]
    UnknownCurrency(String),

    /// Z11-T5: the context carries no rate for this currency.
    #[error("no exchange rate for {0}")]
    NoRate(String),

    /// Z11-T6: `matches` takes its pattern as a string literal only, so every
    /// pattern is compiled (and size-checked) once, at save.
    #[error("matches needs its pattern as a text literal")]
    RegexNotLiteral,

    /// Z11-T6: the pattern does not compile or is over the size limit.
    #[error("invalid pattern: {0}")]
    RegexInvalid(String),

    /// Z11-T8: a user function's name, parameters or library size is not
    /// allowed (a built-in name, a bad name, too many).
    #[error("invalid function: {0}")]
    InvalidFunction(String),

    /// Z11-T8: a user function calls itself, directly or through others.
    #[error("function {0} is recursive")]
    Recursive(String),
}

impl RulesError {
    /// A stable, language-independent code for this failure (BRU-FX2). The
    /// bilingual rules manager translates `rules.*` codes; the English
    /// `Display` stays for logs and tests.
    ///
    /// Every variant has its own code — the crate's own test asserts the set
    /// is unique, and they are documented in the crate docs.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Parse { .. } => "rules.parse.unexpected_token",
            Self::Type(_) => "rules.type.mismatch",
            Self::UnknownField(_) => "rules.field.unknown",
            Self::MultiHopLookup(_) => "rules.lookup.multi_hop",
            Self::UnknownFunction(_) => "rules.function.unknown",
            Self::Arity { .. } => "rules.function.arity",
            Self::DivideByZero => "rules.eval.divide_by_zero",
            Self::Eval(_) => "rules.eval.failed",
            Self::NumericOverflow => "rules.number.non_finite",
            Self::NullOperand { .. } => "rules.null.operand",
            Self::ContextTypeMismatch { .. } => "rules.context.type_mismatch",
            Self::UnknownTimezone(_) => "rules.context.unknown_timezone",
            Self::UnknownCurrency(_) => "rules.currency.unknown",
            Self::NoRate(_) => "rules.currency.no_rate",
            Self::RegexNotLiteral => "rules.regex.not_literal",
            Self::RegexInvalid(_) => "rules.regex.invalid",
            Self::InvalidFunction(_) => "rules.function.invalid",
            Self::Recursive(_) => "rules.function.recursive",
            Self::Budget(kind) => kind.code(),
        }
    }

    /// Whether retrying the same evaluation could succeed (BRU-E3, BRU-D5).
    ///
    /// Only the wall-clock breaker is transient: it fires because the node was
    /// busy, not because the rule is wrong, and the blocking consumer maps it
    /// to a retryable 503 at `warn` instead of a 422 rule violation. Every
    /// other failure is deterministic for the same `Compiled` + `Context`.
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Budget(BudgetKind::WallClock))
    }
}

/// The byte span of every AST node, indexed by **pre-order node number**
/// (the root is 0, then its left-most subtree, and so on) — BRU-FX1's side
/// table, so the admin editor can underline the exact sub-expression without
/// `Expr` carrying a span.
///
/// Produced by the parser and carried by a compile failure's
/// [`RulesDiagnostic`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spans {
    spans: Vec<(usize, usize)>,
}

impl Spans {
    pub(crate) fn new(spans: Vec<(usize, usize)>) -> Self {
        Self { spans }
    }

    /// The `(start_byte, end_byte)` span of node `node` in pre-order, or
    /// `None` past the end of the table.
    pub fn get(&self, node: usize) -> Option<(usize, usize)> {
        self.spans.get(node).copied()
    }

    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, usize)> + '_ {
        self.spans.iter().copied()
    }
}

/// A [`RulesError`] together with the byte span of the sub-expression that
/// produced it (BRU-FX1). `span` is `None` when the error has no single
/// node to point at (a source-length budget, for example).
#[derive(Debug, Clone, PartialEq)]
pub struct RulesDiagnostic {
    pub error: RulesError,
    pub span: Option<(usize, usize)>,
}

impl RulesDiagnostic {
    pub fn new(error: RulesError, span: Option<(usize, usize)>) -> Self {
        Self { error, span }
    }

    /// A diagnostic with no span yet — the innermost node that raises an
    /// error fills it in on the way out of type-checking.
    pub fn without_span(error: RulesError) -> Self {
        Self { error, span: None }
    }

    /// Fills in `span` only if this diagnostic does not already have a more
    /// specific one.
    pub fn or_span(mut self, span: Option<(usize, usize)>) -> Self {
        if self.span.is_none() {
            self.span = span;
        }
        self
    }

    pub fn into_error(self) -> RulesError {
        self.error
    }
}

impl fmt::Display for RulesDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.span {
            Some((start, end)) => write!(f, "{} (at bytes {start}..{end})", self.error),
            None => write!(f, "{}", self.error),
        }
    }
}

impl std::error::Error for RulesDiagnostic {}

impl From<RulesError> for RulesDiagnostic {
    fn from(error: RulesError) -> Self {
        Self::without_span(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One constructed instance of every variant — the fixture both the
    /// stable-code and the transient tests iterate (BRU-E3, BRU-FX2).
    fn one_of_each() -> Vec<RulesError> {
        let mut all = vec![
            RulesError::Parse {
                message: "unexpected token".to_owned(),
                pos: 3,
            },
            RulesError::Type("mismatch".to_owned()),
            RulesError::UnknownField("nope".to_owned()),
            RulesError::MultiHopLookup("a.b".to_owned()),
            RulesError::UnknownFunction("nope".to_owned()),
            RulesError::Arity {
                function: "len".to_owned(),
                expected: "1".to_owned(),
                got: 0,
            },
            RulesError::DivideByZero,
            RulesError::Eval("failed".to_owned()),
            RulesError::NumericOverflow,
            RulesError::NullOperand {
                op: "'>'".to_owned(),
            },
            RulesError::ContextTypeMismatch {
                field: "amount".to_owned(),
            },
            RulesError::UnknownTimezone("Mars/Olympus".to_owned()),
            RulesError::InvalidFunction("round".to_owned()),
            RulesError::Recursive("f".to_owned()),
        ];
        for kind in [
            BudgetKind::AstNodes,
            BudgetKind::RecursionDepth,
            BudgetKind::EvalSteps,
            BudgetKind::WallClock,
            BudgetKind::StringLength,
            BudgetKind::SourceLength,
            BudgetKind::ListLength,
            BudgetKind::TableSize,
        ] {
            all.push(RulesError::Budget(kind));
        }
        all
    }

    #[test]
    fn every_variant_has_a_unique_stable_code() {
        let all = one_of_each();
        let mut codes: Vec<&'static str> = all.iter().map(RulesError::code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(before, codes.len(), "duplicate code in {codes:?}");
        assert!(all.iter().all(|e| e.code().starts_with("rules.")));
    }

    #[test]
    fn only_a_wall_clock_trip_is_transient() {
        for err in one_of_each() {
            let expected = matches!(err, RulesError::Budget(BudgetKind::WallClock));
            assert_eq!(
                err.is_transient(),
                expected,
                "{err:?} must be transient={expected}"
            );
        }
    }

    #[test]
    fn a_diagnostic_keeps_the_innermost_span() {
        let inner = RulesDiagnostic::new(RulesError::UnknownField("a".to_owned()), Some((1, 2)));
        let filled = inner.or_span(Some((0, 9)));
        assert_eq!(filled.span, Some((1, 2)));
        let empty =
            RulesDiagnostic::without_span(RulesError::Eval("x".to_owned())).or_span(Some((0, 9)));
        assert_eq!(empty.span, Some((0, 9)));
    }
}

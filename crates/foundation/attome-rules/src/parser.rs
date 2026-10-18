//! Hand-written recursive-descent parser over lexer::lex's token stream.
//! Standard precedence climbing, lowest to highest:
//! or < and < not < comparison (== != < <= > >=, non-chaining) <
//! + - < * / % < unary - < primary.
//!
//! **Two bounds, both enforced while parsing** (BRU-A2):
//!
//! - Structural nesting depth (parens, list literals, call arguments, and
//!   unary/not recursion) is bounded by budget::HARD_MAX_DEPTH, checked
//!   *while* descending so a pathological (((((( ... input returns
//!   RulesError::Budget instead of overflowing the stack.
//! - The **AST** is bounded too: every chain link counts toward the tree's
//!   depth, and every node the parser builds is counted against
//!   min(Budgets::max_ast_nodes, HARD_MAX_NODES). Nothing recursive ever
//!   runs over an unbounded tree — not this crate's own node_count/Drop/
//!   Clone, and not a consumer's walker (rule_engine::walk, xrm-metric's
//!   collect_field_refs, the TRD validate-rules route), since
//!   attome_rules::parse cannot return a tree over either ceiling.
//!
//! The parser also builds BRU-FX1's byte-span side table: every internal node
//! carries its (start, end) span, and to_expr flattens the tree into the
//! public Expr plus a pre-order Spans table. Spans never live on Expr
//! (plan §9).

use crate::ast::{BinaryOp, Expr, FieldRef, UnaryOp};
use crate::budget::{Budgets, HARD_MAX_DEPTH, HARD_MAX_NODES};
use crate::error::{BudgetKind, RulesDiagnostic, RulesError, Spans};
use crate::lexer::{TokKind, Token, lex};

// C-25 pub(crate) sweep: mod parser is private (see lib.rs), and these are
// only ever called from compile.rs / lib.rs.
pub(crate) struct Parsed {
    pub(crate) expr: Expr,
    pub(crate) spans: Spans,
}

pub(crate) fn parse(src: &str, budgets: &Budgets) -> Result<Expr, RulesError> {
    parse_with_spans(src, budgets)
        .map(|parsed| parsed.expr)
        .map_err(RulesDiagnostic::into_error)
}

pub(crate) fn parse_with_spans(src: &str, budgets: &Budgets) -> Result<Parsed, RulesDiagnostic> {
    let tokens = lex(src)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        nodes: 0,
        max_nodes: budgets.max_ast_nodes.min(HARD_MAX_NODES),
        error_span: None,
        lambda_depth: 0,
    };
    let spanned = match parser.parse_expr(0) {
        Ok(spanned) => spanned,
        Err(error) => return Err(parser.diagnostic(error)),
    };
    if let Err(error) = parser.expect_eof() {
        return Err(parser.diagnostic(error));
    }
    let mut spans = Vec::new();
    let expr = to_expr(spanned, &mut spans);
    Ok(Parsed {
        expr,
        spans: Spans::new(spans),
    })
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    /// Nodes built so far; compared against max_nodes at every construction.
    nodes: usize,
    max_nodes: usize,
    /// Set when an error has a span the token position alone cannot express
    /// (the one-hop lookup error, whose span is name.hop).
    error_span: Option<(usize, usize)>,
    /// Z11-T3: lambdas open around the one being parsed.
    lambda_depth: usize,
}

/// Z11-T3: the functions whose second argument may be a lambda.
pub(crate) const LAMBDA_FUNCTIONS: &[&str] = &["any", "all", "filter", "map"];

/// Z11-T3: lambdas may nest two deep; a third is refused.
pub(crate) const MAX_LAMBDA_DEPTH: usize = 2;

/// A node while parsing, with the span and subtree depth needed to enforce
/// the bounds before the final Expr exists.
struct Spanned {
    span: (usize, usize),
    depth: usize,
    kind: SpannedKind,
}

enum SpannedKind {
    NullLit,
    BoolLit(bool),
    NumberLit(f64),
    StringLit(String),
    ListLit(Vec<Spanned>),
    FieldRef(FieldRef),
    Unary {
        op: UnaryOp,
        expr: Box<Spanned>,
    },
    Binary {
        op: BinaryOp,
        lhs: Box<Spanned>,
        rhs: Box<Spanned>,
    },
    Call {
        name: String,
        args: Vec<Spanned>,
    },
    Lambda {
        param: String,
        body: Box<Spanned>,
    },
    Path(Vec<String>),
}

/// Z11-T7: the most hops a path may take (four segments).
pub(crate) const MAX_PATH_HOPS: usize = 3;

impl Parser {
    fn peek(&self) -> &TokKind {
        &self.tokens[self.pos].kind
    }

    fn peek_pos(&self) -> usize {
        self.tokens[self.pos].pos
    }

    fn peek_end(&self) -> usize {
        self.tokens[self.pos].end
    }

    fn bump(&mut self) -> TokKind {
        let k = self.tokens[self.pos].kind.clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        k
    }

    fn expect(&mut self, want: &TokKind, ctx: &str) -> Result<(), RulesError> {
        if self.peek() == want {
            self.bump();
            Ok(())
        } else {
            Err(RulesError::Parse {
                message: format!("expected {ctx}, found {:?}", self.peek()),
                pos: self.peek_pos(),
            })
        }
    }

    fn expect_eof(&self) -> Result<(), RulesError> {
        if matches!(self.peek(), TokKind::Eof) {
            Ok(())
        } else {
            Err(RulesError::Parse {
                message: format!("unexpected trailing input {:?}", self.peek()),
                pos: self.peek_pos(),
            })
        }
    }

    /// Increments and checks *structural* nesting depth. Called at every point
    /// this parser recurses back into a full expression (parens, list
    /// elements, call arguments) or chains a prefix operator (not, unary -).
    fn descend(&self, depth: usize) -> Result<usize, RulesError> {
        if depth >= HARD_MAX_DEPTH {
            return Err(RulesError::Budget(BudgetKind::RecursionDepth));
        }
        Ok(depth + 1)
    }

    /// Records one built node against the node cap and the AST depth ceiling.
    fn node(
        &mut self,
        span: (usize, usize),
        depth: usize,
        kind: SpannedKind,
    ) -> Result<Spanned, RulesError> {
        self.nodes += 1;
        if self.nodes > self.max_nodes {
            return Err(RulesError::Budget(BudgetKind::AstNodes));
        }
        if depth > HARD_MAX_DEPTH {
            return Err(RulesError::Budget(BudgetKind::RecursionDepth));
        }
        Ok(Spanned { span, depth, kind })
    }

    /// A leaf node: its span is exactly the current token's.
    fn leaf(&mut self, kind: SpannedKind) -> Result<Spanned, RulesError> {
        let span = (self.peek_pos(), self.peek_end());
        self.bump();
        self.node(span, 1, kind)
    }

    /// A binary node: its span runs from the left operand's first byte to the
    /// right operand's last byte, and its depth is one past the deeper side —
    /// so a chain link counts toward the AST depth ceiling (BRU-A2).
    fn binary(&mut self, op: BinaryOp, lhs: Spanned, rhs: Spanned) -> Result<Spanned, RulesError> {
        let span = (lhs.span.0, rhs.span.1);
        let depth = lhs.depth.max(rhs.depth) + 1;
        self.node(
            span,
            depth,
            SpannedKind::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            },
        )
    }

    fn unary(&mut self, op: UnaryOp, start: usize, inner: Spanned) -> Result<Spanned, RulesError> {
        let span = (start, inner.span.1);
        let depth = inner.depth + 1;
        self.node(
            span,
            depth,
            SpannedKind::Unary {
                op,
                expr: Box::new(inner),
            },
        )
    }

    fn diagnostic(&self, error: RulesError) -> RulesDiagnostic {
        let span = match &error {
            RulesError::Parse { pos, .. } => Some((*pos, *pos)),
            _ => self.error_span,
        };
        RulesDiagnostic::new(error, span)
    }

    fn parse_expr(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        let depth = self.descend(depth)?;
        self.parse_or(depth)
    }

    fn parse_or(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        let mut lhs = self.parse_and(depth)?;
        while self.peek_is_ident("or") {
            self.bump();
            let rhs = self.parse_and(depth)?;
            lhs = self.binary(BinaryOp::Or, lhs, rhs)?;
        }
        Ok(lhs)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        let mut lhs = self.parse_not(depth)?;
        while self.peek_is_ident("and") {
            self.bump();
            let rhs = self.parse_not(depth)?;
            lhs = self.binary(BinaryOp::And, lhs, rhs)?;
        }
        Ok(lhs)
    }

    fn parse_not(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        if self.peek_is_ident("not") {
            let start = self.peek_pos();
            self.bump();
            let depth = self.descend(depth)?;
            let inner = self.parse_not(depth)?;
            return self.unary(UnaryOp::Not, start, inner);
        }
        self.parse_comparison(depth)
    }

    fn parse_comparison(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        let lhs = self.parse_additive(depth)?;
        let op = match self.peek() {
            TokKind::EqEq => Some(BinaryOp::Eq),
            TokKind::NotEq => Some(BinaryOp::Ne),
            TokKind::Lt => Some(BinaryOp::Lt),
            TokKind::Le => Some(BinaryOp::Le),
            TokKind::Gt => Some(BinaryOp::Gt),
            TokKind::Ge => Some(BinaryOp::Ge),
            _ => None,
        };
        match op {
            Some(op) => {
                self.bump();
                let rhs = self.parse_additive(depth)?;
                self.binary(op, lhs, rhs)
            }
            None => Ok(lhs),
        }
    }

    fn parse_additive(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        let mut lhs = self.parse_term(depth)?;
        loop {
            let op = match self.peek() {
                TokKind::Plus => BinaryOp::Add,
                TokKind::Minus => BinaryOp::Sub,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_term(depth)?;
            lhs = self.binary(op, lhs, rhs)?;
        }
        Ok(lhs)
    }

    fn parse_term(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        let mut lhs = self.parse_unary(depth)?;
        loop {
            let op = match self.peek() {
                TokKind::Star => BinaryOp::Mul,
                TokKind::Slash => BinaryOp::Div,
                TokKind::Percent => BinaryOp::Mod,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_unary(depth)?;
            lhs = self.binary(op, lhs, rhs)?;
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        if matches!(self.peek(), TokKind::Minus) {
            let start = self.peek_pos();
            self.bump();
            let depth = self.descend(depth)?;
            let inner = self.parse_unary(depth)?;
            return self.unary(UnaryOp::Neg, start, inner);
        }
        self.parse_primary(depth)
    }

    fn parse_primary(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        match self.peek().clone() {
            TokKind::Number(n) => self.leaf(SpannedKind::NumberLit(n)),
            TokKind::Str(s) => self.leaf(SpannedKind::StringLit(s)),
            TokKind::LParen => {
                self.bump();
                let depth = self.descend(depth)?;
                let inner = self.parse_expr(depth)?;
                self.expect(&TokKind::RParen, "')'")?;
                Ok(inner)
            }
            TokKind::LBracket => {
                let open = self.peek_pos();
                self.bump();
                let depth = self.descend(depth)?;
                let mut items = Vec::new();
                if !matches!(self.peek(), TokKind::RBracket) {
                    loop {
                        items.push(self.parse_expr(depth)?);
                        if matches!(self.peek(), TokKind::Comma) {
                            self.bump();
                        } else {
                            break;
                        }
                    }
                }
                let close = self.peek_end();
                self.expect(&TokKind::RBracket, "']'")?;
                let tree_depth = items.iter().map(|i| i.depth).max().unwrap_or(0) + 1;
                self.node((open, close), tree_depth, SpannedKind::ListLit(items))
            }
            TokKind::Ident(name) => {
                let name_span = (self.peek_pos(), self.peek_end());
                self.bump();
                match name.as_str() {
                    "true" => self.node(name_span, 1, SpannedKind::BoolLit(true)),
                    "false" => self.node(name_span, 1, SpannedKind::BoolLit(false)),
                    "null" => self.node(name_span, 1, SpannedKind::NullLit),
                    _ if matches!(self.peek(), TokKind::LParen) => {
                        self.bump();
                        let depth = self.descend(depth)?;
                        let mut args = Vec::new();
                        if !matches!(self.peek(), TokKind::RParen) {
                            loop {
                                if args.len() == 1
                                    && LAMBDA_FUNCTIONS.contains(&name.as_str())
                                    && self.at_lambda()
                                {
                                    args.push(self.parse_lambda(depth)?);
                                } else {
                                    args.push(self.parse_expr(depth)?);
                                }
                                if matches!(self.peek(), TokKind::Comma) {
                                    self.bump();
                                } else {
                                    break;
                                }
                            }
                        }
                        self.expect(&TokKind::RParen, "')'")?;
                        let tree_depth = args.iter().map(|a| a.depth).max().unwrap_or(0) + 1;
                        self.node(name_span, tree_depth, SpannedKind::Call { name, args })
                    }
                    _ if matches!(self.peek(), TokKind::Dot) => {
                        let mut hops = Vec::new();
                        let mut end = name_span.1;
                        while matches!(self.peek(), TokKind::Dot) {
                            self.bump();
                            hops.push(self.expect_ident("a field name after '.'")?);
                            end = self.tokens[self.pos - 1].end;
                            if hops.len() > MAX_PATH_HOPS {
                                self.error_span = Some((name_span.0, end));
                                return Err(RulesError::MultiHopLookup(format!(
                                    "{name}.{}",
                                    hops.join(".")
                                )));
                            }
                        }
                        let span = (name_span.0, end);
                        if hops.len() == 1 {
                            self.node(
                                span,
                                1,
                                SpannedKind::FieldRef(FieldRef {
                                    base: name,
                                    hop: hops.pop(),
                                }),
                            )
                        } else {
                            let mut segments = vec![name];
                            segments.extend(hops);
                            self.node(span, 1, SpannedKind::Path(segments))
                        }
                    }
                    _ => self.node(
                        name_span,
                        1,
                        SpannedKind::FieldRef(FieldRef {
                            base: name,
                            hop: None,
                        }),
                    ),
                }
            }
            other => Err(RulesError::Parse {
                message: format!("unexpected token {other:?}"),
                pos: self.peek_pos(),
            }),
        }
    }

    /// `ident =>` ahead.
    fn at_lambda(&self) -> bool {
        matches!(self.peek(), TokKind::Ident(_))
            && matches!(
                self.tokens.get(self.pos + 1).map(|t| &t.kind),
                Some(TokKind::Arrow)
            )
    }

    /// `param => body` (Z11-T3).
    fn parse_lambda(&mut self, depth: usize) -> Result<Spanned, RulesError> {
        let start = self.peek_pos();
        let param = self.expect_ident("a lambda parameter")?;
        self.expect(&TokKind::Arrow, "'=>'")?;
        if self.lambda_depth >= MAX_LAMBDA_DEPTH {
            return Err(RulesError::Budget(BudgetKind::LambdaDepth));
        }
        self.lambda_depth += 1;
        let depth = self.descend(depth)?;
        let body = self.parse_expr(depth);
        self.lambda_depth -= 1;
        let body = body?;
        let span = (start, body.span.1);
        let tree_depth = body.depth + 1;
        self.node(
            span,
            tree_depth,
            SpannedKind::Lambda {
                param,
                body: Box::new(body),
            },
        )
    }

    fn peek_is_ident(&self, want: &str) -> bool {
        matches!(self.peek(), TokKind::Ident(s) if s == want)
    }

    fn expect_ident(&mut self, ctx: &str) -> Result<String, RulesError> {
        match self.peek().clone() {
            TokKind::Ident(s) => {
                self.bump();
                Ok(s)
            }
            other => Err(RulesError::Parse {
                message: format!("expected {ctx}, found {other:?}"),
                pos: self.peek_pos(),
            }),
        }
    }
}

/// Flattens the parser's spanned tree into the public Expr plus BRU-FX1's
/// pre-order span table. Recursion is bounded by HARD_MAX_DEPTH and the node
/// count by the parser's cap, so this walk is itself safe by construction.
fn to_expr(node: Spanned, spans: &mut Vec<(usize, usize)>) -> Expr {
    spans.push(node.span);
    match node.kind {
        SpannedKind::NullLit => Expr::NullLit,
        SpannedKind::BoolLit(b) => Expr::BoolLit(b),
        SpannedKind::NumberLit(n) => Expr::NumberLit(n),
        SpannedKind::StringLit(s) => Expr::StringLit(s),
        SpannedKind::FieldRef(r) => Expr::FieldRef(r),
        SpannedKind::ListLit(items) => {
            Expr::ListLit(items.into_iter().map(|i| to_expr(i, spans)).collect())
        }
        SpannedKind::Unary { op, expr } => Expr::Unary {
            op,
            expr: Box::new(to_expr(*expr, spans)),
        },
        SpannedKind::Binary { op, lhs, rhs } => Expr::Binary {
            op,
            lhs: Box::new(to_expr(*lhs, spans)),
            rhs: Box::new(to_expr(*rhs, spans)),
        },
        SpannedKind::Call { name, args } => Expr::Call {
            name,
            args: args.into_iter().map(|a| to_expr(a, spans)).collect(),
        },
        SpannedKind::Lambda { param, body } => Expr::Lambda {
            param,
            body: Box::new(to_expr(*body, spans)),
        },
        SpannedKind::Path(segments) => Expr::Path(segments),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::Budgets;
    use proptest::strategy::Strategy as _;

    fn parse(src: &str) -> Result<Expr, RulesError> {
        super::parse(src, &Budgets::default())
    }

    fn chain(count: usize) -> String {
        std::iter::repeat_n("1", count)
            .collect::<Vec<_>>()
            .join(" + ")
    }

    #[test]
    fn parses_arithmetic_precedence() {
        // 1 + 2 * 3 == (1 + (2 * 3))
        let e = parse("1 + 2 * 3").unwrap();
        assert_eq!(e.to_string(), "(1 + (2 * 3))");
    }

    #[test]
    fn parses_field_ref_and_one_hop_lookup() {
        assert_eq!(parse("amount").unwrap().to_string(), "amount");
        assert_eq!(parse("customer.tier").unwrap().to_string(), "customer.tier");
    }

    #[test]
    fn rejects_a_path_past_three_hops() {
        // Z11-T7: two and three hops are paths (V2 only, checked at compile).
        assert_eq!(
            parse("a.b.c").unwrap(),
            Expr::Path(vec!["a".into(), "b".into(), "c".into()])
        );
        assert!(parse("a.b.c.d").is_ok());
        let err = parse("a.b.c.d.e").unwrap_err();
        assert!(matches!(err, RulesError::MultiHopLookup(_)), "{err:?}");
    }

    #[test]
    fn parses_function_call_and_list_literal() {
        let e = parse("in(x, [1, 2, 3])").unwrap();
        assert_eq!(e.to_string(), "in(x, [1, 2, 3])");
    }

    #[test]
    fn parses_boolean_and_if() {
        let e = parse("if(a and not b, 1, 2)").unwrap();
        assert_eq!(e.to_string(), "if((a and not b), 1, 2)");
    }

    #[test]
    fn rejects_deeply_nested_parens_without_stack_overflow() {
        let src = format!("{}{}{}", "(".repeat(10_000), "1", ")".repeat(10_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err, RulesError::Budget(BudgetKind::RecursionDepth));
    }

    #[test]
    fn rejects_deeply_chained_unary_without_stack_overflow() {
        let src = format!("{}1", "-".repeat(10_000));
        let err = parse(&src).unwrap_err();
        assert_eq!(err, RulesError::Budget(BudgetKind::RecursionDepth));
    }

    /// BRU-A2: a flat operator chain is a full-length recursion in
    /// node_count/Drop/a consumer's walker, so each link counts toward the
    /// AST depth ceiling.
    #[test]
    fn operator_chains_are_bounded_by_the_depth_ceiling() {
        assert!(
            parse(&chain(HARD_MAX_DEPTH)).is_ok(),
            "a chain exactly at the ceiling must parse"
        );
        assert_eq!(
            parse(&chain(HARD_MAX_DEPTH + 1)),
            Err(RulesError::Budget(BudgetKind::RecursionDepth))
        );
        // The pre-BRU-A2 hostile shape: ~32 767 links in 64 KiB.
        assert_eq!(
            parse(&chain(16_000)),
            Err(RulesError::Budget(BudgetKind::RecursionDepth))
        );
    }

    /// BRU-A2: the node cap is enforced while parsing, not after.
    #[test]
    fn flat_lists_are_bounded_by_the_node_cap() {
        // A flat list has depth 2 — only the node cap can reject it.
        let items = std::iter::repeat_n("1", 2_001)
            .collect::<Vec<_>>()
            .join(", ");
        let src = format!("[{items}]");
        assert_eq!(parse(&src), Err(RulesError::Budget(BudgetKind::AstNodes)));
    }

    proptest::proptest! {
        /// BRU-FX1: every span the parser reports is a byte range on a UTF-8
        /// character boundary of the source — Arabic identifiers included.
        #[test]
        fn spans_never_split_a_utf8_character(
            suffix in "[a-z]{0,6}",
            literal in proptest::collection::vec(
                proptest::sample::select(vec![
                    'ا', 'ب', 'ت', 'ث', 'ج', 'ح', 'د', 'ر', 'س', 'ع', 'ف', 'ق', 'ك', 'ل', 'م',
                    'ن', 'ه', 'و', 'ي',
                ]),
                1..6,
            )
            .prop_map(|chars| chars.into_iter().collect::<String>()),
        ) {
            let src = format!("حالة{suffix} == {literal:?}");
            let parsed = parse_with_spans(&src, &Budgets::default()).expect("parses");
            proptest::prop_assert!(!parsed.spans.is_empty());
            for (start, end) in parsed.spans.iter() {
                proptest::prop_assert!(start <= end, "inverted span {start}..{end}");
                proptest::prop_assert!(end <= src.len(), "span past the source: {start}..{end}");
                proptest::prop_assert!(src.is_char_boundary(start), "start {start} splits a character");
                proptest::prop_assert!(src.is_char_boundary(end), "end {end} splits a character");
            }
        }
    }

    /// BRU-FX1: the span table is pre-order and byte-exact.
    #[test]
    fn spans_cover_exactly_the_sub_expression() {
        let parsed = parse_with_spans("amount + name", &Budgets::default()).unwrap();
        assert_eq!(
            parsed.spans.get(0),
            Some((0, 13)),
            "binary node covers the whole source"
        );
        assert_eq!(parsed.spans.get(1), Some((0, 6)), "left field ref");
        assert_eq!(parsed.spans.get(2), Some((9, 13)), "right field ref");

        // A call's own span is the callee name: nope(1) points at nope.
        let parsed = parse_with_spans("nope(1)", &Budgets::default()).unwrap();
        assert_eq!(parsed.spans.get(0), Some((0, 4)));
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        assert!(parse("1 + 1 )").is_err());
    }

    #[test]
    fn empty_input_is_a_parse_error_not_a_panic() {
        assert!(parse("").is_err());
    }
}

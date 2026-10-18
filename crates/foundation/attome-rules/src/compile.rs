//! The public compile/Compiled API (M45 plan §3.1): compile(src) ->
//! Compiled, Compiled::eval(&Context) -> Result<Value, RulesError>.
//! Compiled is Arc-backed and Send + Sync so a Phase 2+ consumer can cache it
//! in MetadataCache/moka keyed by rule id + version and hand the same compiled
//! rule to concurrent request handlers without re-parsing.
//!
//! compile takes a Schema because compile-time type checking is only
//! meaningful against declared field types — that's the mechanism behind
//! "a rule that would produce a value its target column cannot store is
//! rejected at save, not at runtime" (plan §3.1). What this crate does NOT
//! do is compare result_type() against a specific target field's type:
//! that comparison needs to know the rule's kind/target_field, which is xrm
//! metadata this crate has no business knowing (the layer-direction guard).
//! Phase 2's admin
//! API owns that comparison; Compiled::result_type() is what it compares
//! against.
//!
//! Since BRU-A2 the node cap is enforced by the parser while it builds the
//! tree, so this module no longer walks the finished AST to count it — no
//! recursion runs over an unbounded tree. Since BRU-C2b/BRU-C3 the compiled
//! rule also carries the schema it was checked against (for the Context
//! conformance check) and the compile-time null warnings; since BRU-FX1
//! the internal compile path produces a diagnostic with a byte span.

use std::collections::HashMap;
use std::sync::Arc;

use crate::ast::Expr;
use crate::budget::Budgets;
use crate::context::{Context, Schema};
use crate::error::{RulesDiagnostic, RulesError};
use crate::eval;
use crate::parser;
use crate::trace::Trace;
use crate::typecheck;
use crate::value::{Type, Value};

/// A parsed, type-checked expression ready to evaluate against many Contexts.
/// Cheap to clone (an Arc bump); Send + Sync (asserted by this module's
/// compiled_is_send_and_sync test) so it can be cached and shared across
/// request handlers.
#[derive(Debug, Clone)]
pub struct Compiled {
    expr: Arc<Expr>,
    result_type: Type,
    budgets: Budgets,
    /// The declared field types this rule was checked against — BRU-C3's
    /// Context conformance check reads them at eval time.
    schema: Schema,
    /// BRU-C2b: field references used by a Null-rejecting operator with no
    /// is_null/coalesce/if(is_null(..)) guard anywhere in the rule.
    warnings: Vec<String>,
    /// Z11-T6: every `matches` pattern, compiled once here, keyed by the
    /// pattern text; evaluation never compiles one.
    regexes: Arc<HashMap<String, regex::Regex>>,
}

/// Z11-T6: the size limits a pattern compiles under; the regex crate runs in
/// linear time, so a compiled pattern cannot backtrack catastrophically.
const REGEX_SIZE_LIMIT: usize = 256 * 1024;

/// Compiles `pattern` as a full-string match (`^(?:pattern)$`).
pub(crate) fn build_regex(pattern: &str) -> Result<regex::Regex, RulesError> {
    regex::RegexBuilder::new(&format!("^(?:{pattern})$"))
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| RulesError::RegexInvalid(e.to_string()))
}

fn collect_patterns(
    expr: &Expr,
    out: &mut HashMap<String, regex::Regex>,
) -> Result<(), RulesError> {
    match expr {
        Expr::Call { name, args } => {
            if name == "matches"
                && let Some(Expr::StringLit(pattern)) = args.get(1)
                && !out.contains_key(pattern)
            {
                out.insert(pattern.clone(), build_regex(pattern)?);
            }
            args.iter().try_for_each(|a| collect_patterns(a, out))
        }
        Expr::Unary { expr, .. } => collect_patterns(expr, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect_patterns(lhs, out)?;
            collect_patterns(rhs, out)
        }
        Expr::ListLit(items) => items.iter().try_for_each(|a| collect_patterns(a, out)),
        Expr::Lambda { body, .. } => collect_patterns(body, out),
        _ => Ok(()),
    }
}

/// Parses, bounds, and type-checks src against schema, using
/// [Budgets::default]. Use [compile_with_budgets] to override budgets
/// (e.g. a stricter ceiling for an interactive "test this rule" admin
/// endpoint vs. the hot entity-mutation write path).
pub fn compile(src: &str, schema: &Schema) -> Result<Compiled, RulesError> {
    compile_with_budgets(src, schema, Budgets::default())
}

pub fn compile_with_budgets(
    src: &str,
    schema: &Schema,
    budgets: Budgets,
) -> Result<Compiled, RulesError> {
    compile_versioned(src, schema, crate::LanguageVersion::V1, budgets)
}

/// Z11-T1: compiles `src` as written in `version`; a function newer than
/// that version is `UnknownFunction`. [`compile`] and
/// [`compile_with_budgets`] are V1.
pub fn compile_versioned(
    src: &str,
    schema: &Schema,
    version: crate::LanguageVersion,
    budgets: Budgets,
) -> Result<Compiled, RulesError> {
    compile_inner(src, schema, version, budgets).map_err(RulesDiagnostic::into_error)
}

fn compile_inner(
    src: &str,
    schema: &Schema,
    version: crate::LanguageVersion,
    budgets: Budgets,
) -> Result<Compiled, RulesDiagnostic> {
    let parsed = parser::parse_with_spans(src, &budgets)?;
    crate::version::check(&parsed.expr, version).map_err(RulesDiagnostic::from)?;
    let warnings = typecheck::null_warnings(&parsed.expr);
    let result_type = typecheck::typecheck(&parsed.expr, schema, &parsed.spans)?;
    let mut regexes = HashMap::new();
    collect_patterns(&parsed.expr, &mut regexes).map_err(RulesDiagnostic::from)?;
    Ok(Compiled {
        expr: Arc::new(parsed.expr),
        result_type,
        budgets,
        schema: schema.clone(),
        warnings,
        regexes: Arc::new(regexes),
    })
}

impl Compiled {
    /// The expression's statically-inferred type — compare this against a
    /// target field's declared type to reject an incompatible rule at save.
    pub fn result_type(&self) -> &Type {
        &self.result_type
    }

    /// BRU-C2b: the field references that reach a Null-rejecting operator with
    /// no is_null/coalesce/if(is_null(..)) guard anywhere in the rule, sorted
    /// and deduplicated. A non-empty list is a save-time warning, not an
    /// error: the rule still compiles, and a null operand at runtime is
    /// RulesError::NullOperand (BRU-D2).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Evaluates against ctx, enforcing the budgets fixed at compile time.
    /// BRU-E1: builds no trace — no node is rendered and no value cloned.
    /// Use [Compiled::eval_traced] when the caller needs "which
    /// sub-expressions evaluated to what" (plan §3.1's explainability
    /// requirement, e.g. for a validation-rule violation).
    pub fn eval(&self, ctx: &Context) -> Result<Value, RulesError> {
        eval::eval(&self.expr, ctx, &self.budgets, &self.schema, &self.regexes)
    }

    pub fn eval_traced(&self, ctx: &Context) -> Result<(Value, Trace), RulesError> {
        eval::eval_traced(&self.expr, ctx, &self.budgets, &self.schema, &self.regexes)
    }

    /// Z11-T7: every multi-hop path the rule reads, sorted: the caller loads
    /// these, after checking read access at every hop, before evaluating.
    pub fn paths(&self) -> Vec<Vec<String>> {
        fn walk(expr: &Expr, out: &mut Vec<Vec<String>>) {
            match expr {
                Expr::Path(segments) => out.push(segments.clone()),
                Expr::Unary { expr, .. } => walk(expr, out),
                Expr::Binary { lhs, rhs, .. } => {
                    walk(lhs, out);
                    walk(rhs, out);
                }
                Expr::Call { args, .. } => args.iter().for_each(|a| walk(a, out)),
                Expr::ListLit(items) => items.iter().for_each(|a| walk(a, out)),
                Expr::Lambda { body, .. } => walk(body, out),
                Expr::NullLit
                | Expr::BoolLit(_)
                | Expr::NumberLit(_)
                | Expr::StringLit(_)
                | Expr::FieldRef(_) => {}
            }
        }
        let mut out = Vec::new();
        walk(&self.expr, &mut out);
        out.sort();
        out.dedup();
        out
    }

    /// Z11-T8: the tree, schema and patterns, for evaluating this as a user
    /// function's body inside another evaluation.
    pub(crate) fn parts(&self) -> (&Expr, &Schema, &eval::Regexes) {
        (&self.expr, &self.schema, &self.regexes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn compiled_is_send_and_sync() {
        assert_send_sync::<Compiled>();
    }

    #[test]
    fn compiled_is_cheap_to_clone_and_shares_the_ast() {
        let schema = Schema::new().with_field("amount", Type::Number);
        let compiled = compile("amount + 1", &schema).unwrap();
        let cloned = compiled.clone();
        assert!(Arc::ptr_eq(&compiled.expr, &cloned.expr));
    }

    #[test]
    fn compile_rejects_ast_over_the_node_cap() {
        let schema = Schema::new();
        let tiny = Budgets {
            max_ast_nodes: 1,
            ..Budgets::default()
        };
        let err = compile_with_budgets("1 + 1", &schema, tiny).unwrap_err();
        assert_eq!(err, RulesError::Budget(crate::error::BudgetKind::AstNodes));
    }

    #[test]
    fn compile_rejects_a_type_error_before_eval() {
        let schema = Schema::new().with_field("name", Type::Text);
        assert!(compile("name + 1", &schema).is_err());
    }

    #[test]
    fn result_type_matches_the_expression() {
        let schema = Schema::new().with_field("amount", Type::Number);
        let compiled = compile("amount > 10", &schema).unwrap();
        assert_eq!(compiled.result_type(), &Type::Bool);
    }

    #[test]
    fn eval_end_to_end() {
        let schema = Schema::new().with_field("amount", Type::Number);
        let compiled = compile("amount * 2", &schema).unwrap();
        let ctx = Context::new(Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).unwrap())
            .with_field("amount", Value::Number(21.0));
        assert_eq!(compiled.eval(&ctx).unwrap(), Value::Number(42.0));
    }

    #[test]
    fn compiled_is_reusable_across_many_contexts() {
        let schema = Schema::new().with_field("amount", Type::Number);
        let compiled = compile("amount > 10", &schema).unwrap();
        let now = Utc.with_ymd_and_hms(2026, 8, 26, 0, 0, 0).unwrap();
        for (n, expected) in [(5.0, false), (15.0, true), (10.0, false)] {
            let ctx = Context::new(now).with_field("amount", Value::Number(n));
            assert_eq!(compiled.eval(&ctx).unwrap(), Value::Bool(expected));
        }
    }

    // ── BRU-C2b: warnings surface through Compiled ─────────────────────────

    #[test]
    fn compiled_exposes_null_warnings() {
        let schema = Schema::new()
            .with_field("amount", Type::Number)
            .with_field("name", Type::Text);
        assert_eq!(
            compile("amount > 100", &schema).unwrap().warnings(),
            ["amount".to_owned()]
        );
        assert!(
            compile("is_null(amount) or amount > 100", &schema)
                .unwrap()
                .warnings()
                .is_empty()
        );
    }

    // ── BRU-FX1: diagnostics carry a byte span ─────────────────────────────

    #[test]
    fn a_type_error_carries_the_offending_span() {
        let schema = Schema::new()
            .with_field("amount", Type::Number)
            .with_field("name", Type::Text);
        let diagnostic = compile_inner(
            "amount + name",
            &schema,
            crate::LanguageVersion::V1,
            Budgets::default(),
        )
        .unwrap_err();
        assert!(matches!(diagnostic.error, RulesError::Type(_)));
        assert_eq!(diagnostic.span, Some((0, 13)));

        let diagnostic = compile_inner(
            "nope(1)",
            &schema,
            crate::LanguageVersion::V1,
            Budgets::default(),
        )
        .unwrap_err();
        assert!(matches!(diagnostic.error, RulesError::UnknownFunction(_)));
        assert_eq!(diagnostic.span, Some((0, 4)));
    }
}

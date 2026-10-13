//! The caller-configurable budgets (M45 plan §3.1/§6): AST node cap,
//! evaluation step cap, wall-clock ceiling, max string length, max list
//! length. Exceeding any one returns `RulesError::Budget`, never panics.
//!
//! There are also two **non**-configurable ceilings:
//! [`HARD_MAX_SOURCE_BYTES`], [`HARD_MAX_DEPTH`] and [`HARD_MAX_NODES`],
//! enforced unconditionally inside the parser. The grammar has no loops, no
//! recursion, and no user-defined functions, so it is not Turing-complete —
//! the only way a hostile input can hurt the parser itself is a source string
//! so long, so deeply nested, or with so many operator-chain links that lexing
//! / recursive-descent parsing is expensive or blows the call stack. Bounding
//! that is a safety floor under any caller-supplied budget, not a substitute
//! for one.
//!
//! Since BRU-A2 the node cap is enforced **while parsing** (the parser counts
//! every node it builds against `min(HARD_MAX_NODES, Budgets::max_ast_nodes)`)
//! and every chain link counts toward depth, so no AST this crate hands to a
//! caller — or to a consumer's recursive walker — is deeper than
//! `HARD_MAX_DEPTH` or larger than the node cap.

use std::time::Duration;

/// Hard ceiling on source length, checked before lexing starts. Not part of
/// `Budgets` because it protects the parser itself, independent of whatever
/// `max_ast_nodes`/`max_string_len` a caller configures — a caller could set
/// both very high without intending to also raise this.
pub const HARD_MAX_SOURCE_BYTES: usize = 64 * 1024;

/// Hard ceiling on AST depth (parenthesis/call/list nesting **and** operator
/// chains), checked *during* parsing, not after — counting
/// `Expr::node_count()` requires a fully-built tree, but a stack overflow
/// from `((((((...` nesting or a `1+1+1+...` chain happens while building
/// it. 128 is far beyond any expression a human or admin UI would author and
/// small enough to stay well inside the default Rust thread stack, so the
/// tree this crate returns is also safe for a consumer's recursive walker
/// (`rule_engine::walk`, `xrm-metric`'s `collect_field_refs`) — BRU-F2.
pub const HARD_MAX_DEPTH: usize = 128;

/// Hard ceiling on AST node count, enforced while parsing (BRU-A2). It is a
/// floor under `Budgets::max_ast_nodes`: a caller may lower the cap but not
/// raise it past this, so a parser can never be asked to build a tree a
/// consumer cannot walk safely. 4 096 is four times the default node budget
/// and well under the 64 KiB source ceiling's worst case.
pub const HARD_MAX_NODES: usize = 4_096;

/// The caller-configurable budgets. `Default` gives conservative values safe
/// to use as-is; the risk note in the M45 plan (§9, "budget ≤ 2 ms per
/// record for ≤ 20 rules") is a Phase 2+ measured performance target, not
/// this default — `max_wall_clock` here is a correctness circuit breaker
/// against a pathological input, set well above that target so it never
/// fires on a legitimate rule.
///
/// `max_eval_steps` is bounded by the AST node count: there are no loops, so
/// an evaluation can never visit more nodes than the tree has. It stays part
/// of `Budgets` for callers that set it *lower* than the node count (an
/// interactive "test this rule" editor, say); under the defaults it cannot
/// fire.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Budgets {
    pub max_ast_nodes: usize,
    pub max_eval_steps: usize,
    pub max_wall_clock: Duration,
    pub max_string_len: usize,
    /// Maximum number of items a `List` value arriving through `Context`
    /// may have (BRU-E2). Literal lists are already bounded by the node cap.
    pub max_list_len: usize,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_ast_nodes: 2_000,
            max_eval_steps: 20_000,
            max_wall_clock: Duration::from_millis(25),
            max_string_len: 10_000,
            max_list_len: 10_000,
        }
    }
}

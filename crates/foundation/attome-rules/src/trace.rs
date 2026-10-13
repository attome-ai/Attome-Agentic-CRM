//! `Trace` — "which sub-expressions evaluated to what" (M45 plan §3.1,
//! "Deterministic + explainable"). A flat, post-order list of every
//! sub-expression the evaluator actually visited, each paired with its
//! resulting value. Post-order because that's evaluation order for a
//! tree-walking interpreter with no short-circuit-skipped recording: a
//! parent's entry always comes after its children's, so a consumer can
//! render it as an indented explanation by tracking nesting via the
//! expression text alone, or just show the leaves.
//!
//! **BRU-E1**: only `Compiled::eval_traced` builds one of these.
//! `Compiled::eval` — the hot path on every record write — renders nothing and
//! clones nothing, so the trace's per-node cost is paid only by the admin
//! "test this rule" surface that actually reads it.
//!
//! Short-circuited branches (the untaken side of `if`, `and`, `or`, and
//! `coalesce` arguments never reached) never get an entry of their own — no
//! sub-expression is recorded unless it was actually stepped through by the
//! evaluator, which is what makes the trace a report of what a specific
//! evaluation did rather than a static echo of the rule text. A composite
//! node's own entry (e.g. the whole `if(c, a, b)` call) still renders its
//! full source via `Expr`'s `Display` — including the untaken branch's
//! text, as part of showing *which rule* produced *which value* — but that
//! is the one entry for the composite node itself, not a second, separate
//! entry standing in for the branch that never ran.

use crate::value::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct TraceEntry {
    /// The sub-expression's rendered source (`Expr`'s `Display`).
    pub expr: String,
    pub value: Value,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Trace {
    entries: Vec<TraceEntry>,
}

impl Trace {
    pub fn entries(&self) -> &[TraceEntry] {
        &self.entries
    }

    pub(crate) fn push(&mut self, expr: String, value: Value) {
        self.entries.push(TraceEntry { expr, value });
    }
}

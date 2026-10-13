//! Token budgets and workload classification (TODO-056).
//!
//! ## The incident this prevents
//!
//! Stage 2 puts the embedding drain, query embeddings, reranking and chat
//! generation on **one GPU with no arbitration**. Chat is bursty and
//! interactive; the drain is steady and invisible. Without priority classes the
//! loud workload wins, and the symptom is not "chat is slow" — it is *records
//! written today are not searchable*, surfacing days later as "search is
//! broken" with nothing in any log connecting it to a chat session that ran on
//! Tuesday.
//!
//! Search got DoS caps in TODO-018. Inference got nothing, and inference is the
//! more expensive resource.
//!
//! ## Priority is by workload class, not by user
//!
//! [`Priority::Drain`] outranks interactive work, which is the opposite of the
//! instinct. The reasoning: a user waiting two extra seconds for a chat reply
//! has a slow experience; a drain starved for an hour produces an index that is
//! silently wrong for everyone, and D-358's whole staleness bound stops being a
//! bound. Interactive latency is visible and self-correcting — the user
//! retries. Staleness is neither.
//!
//! **`Priority` is a metric label, not a scheduler.** This crate orders the
//! classes and nothing else: it holds no queue, sheds nothing, and changes no
//! decision because of a priority. Priority *scheduling* is the serving
//! process's concern (D-646, amending D-360 ruling 3), and the only consumers
//! are `xrm-ai`'s `budget_guard` labels. An earlier `Priority::is_sheddable`
//! predicate and a `Meter` accumulator were deleted for exactly this reason —
//! they described machinery nothing ran (BIN-F13/FX3).
//!
//! ## Budgets reject, they do not queue
//!
//! A caller over budget gets 429 immediately. Queueing them would convert a
//! cost problem into a latency problem and hide it: the request eventually
//! succeeds, the user sees a slow system, and nobody learns that a budget was
//! exceeded. The rejection is the signal.

use std::time::Duration;

/// What kind of work is asking for the GPU.
///
/// Ordered by priority — `Drain` first. See the module doc for why background
/// indexing outranks interactive chat, and for why this is a **label** rather
/// than a schedule: nothing in this crate reads the ordering to make a
/// decision, it only labels the work a metric belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// The index drain. Starving it produces silent wrongness for everyone.
    Drain,
    /// A query embedding — on the critical path of a search a human is waiting
    /// for, and small.
    QueryEmbedding,
    /// Reranking. Larger, still interactive.
    Rerank,
    /// Chat generation. The largest and burstiest, and the one whose delay is
    /// most visible and least harmful.
    Chat,
}

/// A token allowance over a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub tokens: u64,
    pub window: Duration,
}

impl Budget {
    /// Per interactive session. Generous enough for a long working
    /// conversation, small enough that a runaway tool loop stops within one
    /// window rather than one billing period.
    pub const PER_SESSION_DEFAULT: Budget = Budget {
        tokens: 200_000,
        window: Duration::from_secs(60 * 60),
    };

    /// Per caller across sessions, because opening a second session is the
    /// obvious way around a per-session budget and is not an attack — it is
    /// what a user does when the first one stops working.
    pub const PER_CALLER_DEFAULT: Budget = Budget {
        tokens: 500_000,
        window: Duration::from_secs(24 * 60 * 60),
    };
}

/// What a budget check decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetVerdict {
    Allowed {
        remaining: u64,
    },
    /// Over budget. **Rejected, not queued** — see the module doc.
    Rejected {
        /// How long until the window rolls, so the caller can say something
        /// better than "try later".
        retry_after: Duration,
    },
}

/// Checks a request against a budget.
///
/// `estimated_tokens` is the *request's own* estimate — prompt plus a
/// conservative completion allowance. Charging only what was actually used
/// would let a caller start an unbounded generation while under budget, which
/// is the case the budget exists for; the reconciliation happens afterwards in
/// `xrm_ai::budget_guard::Grant::settle`, which charges the signed difference
/// between the estimate and what the model reported.
///
/// ## The contract is sliding (BIN-D8, row G-8)
///
/// `consumed` is **what the store's window currently holds**, and this function
/// never decides that a window has "rolled" — the store evicts out-of-window
/// buckets and what it reports is the truth. An earlier version returned
/// `Allowed` whenever `window_elapsed >= budget.window`, on the theory that the
/// window had reset. `attome_cache::token_window::read` reports
/// `elapsed == window` whenever the **boundary** bucket still holds spend, so
/// for any caller with steady traffic that branch admitted every request
/// whatever had already been spent — and its `retry_after` sent a rejected
/// caller to exactly that boundary, where it would be admitted again (BIN-F7).
///
/// Here `window_elapsed` shapes only `retry_after`: the wait ends when the
/// oldest still-counted bucket ages out, which is when the store's own eviction
/// frees the allowance. It is never a licence to spend.
///
/// The refusal is never a queue — see the module doc.
pub fn check(
    budget: Budget,
    consumed: u64,
    estimated_tokens: u64,
    window_elapsed: Duration,
) -> BudgetVerdict {
    // An estimate larger than the whole budget can never be admitted, however
    // empty the window. Say so with a full-window hint: a hint derived from
    // `window_elapsed` would send the caller back to a window it still could
    // not afford.
    if estimated_tokens > budget.tokens {
        return BudgetVerdict::Rejected {
            retry_after: budget.window,
        };
    }
    if consumed.saturating_add(estimated_tokens) > budget.tokens {
        return BudgetVerdict::Rejected {
            // At least one second: a hint of zero reads as "retry now", which
            // is the one thing a rejection must not say.
            retry_after: budget
                .window
                .saturating_sub(window_elapsed)
                .max(Duration::from_secs(1)),
        };
    }
    BudgetVerdict::Allowed {
        remaining: budget.tokens - consumed - estimated_tokens,
    }
}

/// One row of the allow/reject contract, as data.
///
/// This table is the **shared conformance contract with `ai-10-10` A0.1**: the
/// atomic (Redis Lua) admission path must port *these rows*, never the deleted
/// "the window rolled, allow it" branch, so the pure policy here and the atomic
/// path there cannot drift (BIN-D8, BIN-G1). A0.1's script test consumes this
/// same table; adding a row here is how a new admission rule is pinned in both
/// places at once.
#[derive(Debug, Clone, Copy)]
pub struct ConformanceCase {
    /// What the row demonstrates. The test names the failing row.
    pub name: &'static str,
    /// `Budget::tokens`.
    pub tokens: u64,
    /// `Budget::window`, in seconds.
    pub window_secs: u64,
    /// What the store's window holds.
    pub consumed: u64,
    /// The request's own estimate.
    pub estimated: u64,
    /// Age of the oldest still-counted bucket.
    pub elapsed_secs: u64,
    /// `true` for `BudgetVerdict::Allowed`, `false` for `BudgetVerdict::Rejected`.
    pub allowed: bool,
    /// The exact `retry_after` a rejection must carry, when the row pins one.
    pub retry_after_secs: Option<u64>,
}

/// The admission contract, shared with A0.1. See `ConformanceCase`.
pub const CONFORMANCE: &[ConformanceCase] = &[
    ConformanceCase {
        name: "an empty window admits a request that fits",
        tokens: 1_000,
        window_secs: 3_600,
        consumed: 0,
        estimated: 1_000,
        elapsed_secs: 0,
        allowed: true,
        retry_after_secs: None,
    },
    ConformanceCase {
        name: "one token over the limit is refused",
        tokens: 1_000,
        window_secs: 3_600,
        consumed: 0,
        estimated: 1_001,
        elapsed_secs: 0,
        allowed: false,
        retry_after_secs: Some(3_600),
    },
    ConformanceCase {
        name: "consumed == tokens with elapsed == window is not a reset (BIN-F7)",
        tokens: 1_000,
        window_secs: 3_600,
        consumed: 1_000,
        estimated: 1,
        elapsed_secs: 3_600,
        allowed: false,
        retry_after_secs: Some(1),
    },
    ConformanceCase {
        name: "consumed == tokens past the window still has no room",
        tokens: 1_000,
        window_secs: 3_600,
        consumed: 1_000,
        estimated: 1,
        elapsed_secs: 999_999,
        allowed: false,
        retry_after_secs: Some(1),
    },
    ConformanceCase {
        name: "a boundary window with room left is admitted",
        tokens: 1_000,
        window_secs: 3_600,
        consumed: 999,
        estimated: 1,
        elapsed_secs: 3_600,
        allowed: true,
        retry_after_secs: None,
    },
    ConformanceCase {
        name: "an estimate above the whole budget is refused with a full-window hint",
        tokens: 1_000,
        window_secs: 3_600,
        consumed: 0,
        estimated: 1_001,
        elapsed_secs: 9_000,
        allowed: false,
        retry_after_secs: Some(3_600),
    },
    ConformanceCase {
        name: "a zero budget refuses any request that would spend",
        tokens: 0,
        window_secs: 3_600,
        consumed: 0,
        estimated: 1,
        elapsed_secs: 0,
        allowed: false,
        retry_after_secs: Some(3_600),
    },
    ConformanceCase {
        name: "the retry hint never falls below one second",
        tokens: 100,
        window_secs: 60,
        consumed: 100,
        estimated: 1,
        elapsed_secs: 59,
        allowed: false,
        retry_after_secs: Some(1),
    },
];

/// Prometheus metric names, so registration and recording cannot drift.
///
/// Only the two the platform actually emits. `GPU_SECONDS_TOTAL` and
/// `QUEUE_DEPTH` were declared here and never registered or incremented by
/// anything (BIN-F13); a metric nobody emits is a dashboard panel that lies,
/// so they are gone rather than left as an invitation. GPU-seconds and queue
/// depth, if they are ever measured, are the serving process's numbers
/// (D-646), and would arrive through its own exporter.
pub const TOKENS_TOTAL: &str = "attome_inference_tokens_total";
pub const BUDGET_REJECTED_TOTAL: &str = "attome_inference_budget_rejected_total";

#[cfg(test)]
mod tests {
    use super::*;

    /// **The ordering the incident produced.** The drain outranks every
    /// interactive class, and the order is stable because it is a metric label:
    /// a rename or a reorder silently renames every series built on it.
    #[test]
    fn the_drain_outranks_interactive_work() {
        assert!(Priority::Drain < Priority::QueryEmbedding);
        assert!(Priority::QueryEmbedding < Priority::Rerank);
        assert!(Priority::Rerank < Priority::Chat);
    }

    /// Over budget is a rejection with a retry hint, not a queue slot.
    ///
    /// Queueing would convert a cost problem into a latency problem and hide
    /// it — the request eventually succeeds, the user sees a slow system, and
    /// nobody learns a budget was exceeded.
    #[test]
    fn a_caller_over_budget_is_rejected_with_a_retry_hint() {
        let b = Budget {
            tokens: 1_000,
            window: Duration::from_secs(3_600),
        };
        match check(b, 900, 200, Duration::from_secs(600)) {
            BudgetVerdict::Rejected { retry_after } => {
                assert_eq!(retry_after, Duration::from_secs(3_000));
            }
            other => panic!("expected a rejection: {other:?}"),
        }
    }

    /// The estimate is charged **before** the call, not after.
    ///
    /// Charging only actual usage would let a caller sitting just under budget
    /// start an unbounded generation — precisely the case a budget exists for.
    #[test]
    fn the_estimate_is_charged_up_front() {
        let b = Budget {
            tokens: 1_000,
            window: Duration::from_secs(3_600),
        };
        // Exactly at the limit is allowed; one over is not.
        assert!(matches!(
            check(b, 0, 1_000, Duration::ZERO),
            BudgetVerdict::Allowed { remaining: 0 }
        ));
        assert!(matches!(
            check(b, 0, 1_001, Duration::ZERO),
            BudgetVerdict::Rejected { .. }
        ));
    }

    /// **Row G-8 / BIN-D8.** The reset belongs to the store, not to this
    /// function: `consumed` is whatever the window currently holds, and an
    /// elapsed time past the window is not a reason to spend again. Here the
    /// boundary bucket still holds 999 tokens, so 500 more do not fit — and
    /// the caller is told to wait one second (the floor), not handed a fresh
    /// allowance.
    #[test]
    fn an_elapsed_window_does_not_reset_the_allowance() {
        let b = Budget {
            tokens: 1_000,
            window: Duration::from_secs(60),
        };
        assert!(matches!(
            check(b, 999, 500, Duration::from_secs(61)),
            BudgetVerdict::Rejected { .. }
        ));
        // What the store's eviction actually produces: an empty window is an
        // empty window whenever it happens.
        assert!(matches!(
            check(b, 0, 500, Duration::from_secs(61)),
            BudgetVerdict::Allowed { remaining: 500 }
        ));
    }

    /// The shared contract table holds, row by row, and every rejection's
    /// retry hint points *into* its own window. A0.1's atomic admission script
    /// runs the same table (BIN-G1); this is the pure-policy half of it.
    #[test]
    fn the_conformance_table_holds() {
        assert!(!CONFORMANCE.is_empty());
        for case in CONFORMANCE {
            let b = Budget {
                tokens: case.tokens,
                window: Duration::from_secs(case.window_secs),
            };
            let verdict = check(
                b,
                case.consumed,
                case.estimated,
                Duration::from_secs(case.elapsed_secs),
            );
            match (case.allowed, verdict) {
                (true, BudgetVerdict::Allowed { remaining }) => assert_eq!(
                    remaining,
                    case.tokens - case.consumed - case.estimated,
                    "row `{}`",
                    case.name
                ),
                (false, BudgetVerdict::Rejected { retry_after }) => {
                    if let Some(expected) = case.retry_after_secs {
                        assert_eq!(
                            retry_after,
                            Duration::from_secs(expected),
                            "row `{}`",
                            case.name
                        );
                    }
                    assert!(
                        retry_after <= b.window && retry_after >= Duration::from_secs(1),
                        "row `{}` must hint inside its window and never at zero: {retry_after:?}",
                        case.name
                    );
                }
                (allowed, verdict) => panic!(
                    "row `{}` expected allowed={allowed}, got {verdict:?}",
                    case.name
                ),
            }
        }
    }

    /// A cheap deterministic property check (no `proptest` dependency in this
    /// crate) over 20,000 budget states:
    /// `Allowed ⇒ consumed + estimated ≤ tokens`, and
    /// `Rejected ⇒ retry_after ≤ window`. This is the invariant the old
    /// roll-branch violated, checked over the whole input space rather than
    /// the handful of rows above.
    #[test]
    fn every_verdict_respects_the_budget() {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let tokens = next() % 100_000;
            let consumed = next() % 150_000;
            let estimated = next() % 150_000;
            // Windows of at least one second, which is the smallest window
            // `Budget` can meaningfully describe.
            let window_secs = next() % 86_400 + 1;
            let elapsed_secs = next() % 200_000;
            let b = Budget {
                tokens,
                window: Duration::from_secs(window_secs),
            };
            match check(b, consumed, estimated, Duration::from_secs(elapsed_secs)) {
                BudgetVerdict::Allowed { .. } => assert!(
                    consumed.saturating_add(estimated) <= tokens,
                    "admitted {consumed} + {estimated} over a {tokens} budget"
                ),
                BudgetVerdict::Rejected { retry_after } => assert!(
                    retry_after <= b.window && retry_after >= Duration::from_secs(1),
                    "retry hint {retry_after:?} outside the {window_secs}s window"
                ),
            }
        }
    }

    /// The per-caller budget is wider than the per-session one, and both exist.
    ///
    /// Opening a second session is the obvious way around a per-session budget
    /// and is not an attack — it is what a user does when the first one stops
    /// working. Only the per-caller budget catches it.
    #[test]
    fn a_per_caller_budget_backstops_the_per_session_one() {
        const _: () =
            assert!(Budget::PER_CALLER_DEFAULT.tokens > Budget::PER_SESSION_DEFAULT.tokens);
        const _: () = assert!(
            Budget::PER_CALLER_DEFAULT.window.as_secs()
                > Budget::PER_SESSION_DEFAULT.window.as_secs()
        );
    }

    /// Metric names are namespaced and distinct — a duplicate registration
    /// panics the Prometheus registry at boot.
    #[test]
    fn metric_names_are_namespaced_and_distinct() {
        let names = [TOKENS_TOTAL, BUDGET_REJECTED_TOTAL];
        let mut seen = std::collections::HashSet::new();
        for name in names {
            assert!(name.starts_with("attome_inference_"), "{name}");
            assert!(seen.insert(name), "duplicate metric {name}");
        }
    }

    /// **BIN-P2 (finding BIN-F7, row G-8).** The store reports
    /// `elapsed == window` whenever the boundary bucket still holds spend
    /// (`token_window::read` returns the age of the oldest counted bucket, and
    /// the boundary bucket is exactly one window old), so the "the window
    /// rolled" branch below admits a caller that is already at its limit. A
    /// full window at the boundary is not an empty one: this must be
    /// `Rejected`.
    #[test]
    fn a_full_window_at_the_boundary_is_not_a_reset() {
        let b = Budget {
            tokens: 1_000,
            window: Duration::from_secs(60),
        };
        assert!(
            matches!(
                check(b, b.tokens, 1, b.window),
                BudgetVerdict::Rejected { .. }
            ),
            "a consumed-equals-limit window at the boundary must not read as a reset"
        );
    }
}

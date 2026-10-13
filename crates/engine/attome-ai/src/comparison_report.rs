//! M96 Phase 1, item 1 — the on-demand model/prompt comparison report over
//! `ai_suggestion_outcome`, with Wilson score confidence intervals.
//!
//! **How this differs from `quality_monitor.rs` (M34/D-435).** That job is a
//! nightly sweep comparing one group's CURRENT period against its own PRIOR
//! period and alerting on a significant drop — a change-detection alert, not
//! a report. This module answers a different question a human asks on
//! demand: "how do these two (action, model, prompt_version) groups compare
//! RIGHT NOW, and how much should I trust the difference given their sample
//! sizes?" Both read the same ledger; neither owns the other's job.
//!
//! **Why Wilson, not a naive `rate ± 1.96*sqrt(p(1-p)/n)`.** The naive
//! (Wald) interval is a poor approximation for small `n` or a rate near 0 or
//! 1 — exactly the regime a fresh challenger prompt starts in (few decided
//! outcomes, and often a rate near the edges). It can even produce bounds
//! outside `[0, 1]`. Wilson stays inside `[0, 1]` by construction and is the
//! standard replacement (Wilson 1927) — see `wilson_interval`'s doc comment
//! for the closed-form formula and `tests::wilson_interval_matches_known_reference_values`
//! for the numbers it was checked against.
//!
//! **Why three separate confidence intervals per group, not one.** The
//! module plan (`document/module-master-plans/M96-experimentation.md` §3.1)
//! asks for "acceptance/edit/reject rates ... with confidence intervals" —
//! plural rates, each is its own binomial proportion of the group's decided
//! total, so each gets its own interval rather than one CI standing in for
//! all three (an edit-heavy model and a reject-heavy model can share the same
//! blended "acceptance" rate while telling very different quality stories).
//!
//! **Air-gap safe.** Like `compliance_report.rs`, this reads only counts and
//! provenance columns — no prompt text, no generated text, no suggestion
//! content ever leaves `ai_suggestion_outcome`.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::{IntoParams, ToSchema};

/// The two-sided 95% Wilson z-score, `Φ⁻¹(0.975)`.
const Z_95: f64 = 1.959963984540054;

/// A Wilson score confidence interval, `[lower, upper] ⊆ [0, 1]`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, ToSchema)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
}

/// The (two-sided, ~95%) Wilson score interval for a binomial proportion
/// `x` successes out of `n` trials.
///
/// ```text
/// center = (p̂ + z²/2n) / (1 + z²/n)
/// margin = z·√(p̂(1-p̂)/n + z²/4n²) / (1 + z²/n)
/// [lower, upper] = [center - margin, center + margin], clamped to [0, 1]
/// ```
///
/// where `p̂ = x/n`. Closed-form — no library dependency, per the module
/// scope's instruction. Returns `None` for `n == 0` (there is no rate to
/// bound) and for an invalid `(x, n)` pair (`x < 0` or `x > n`), which a
/// caller passing raw ledger counts should never hit but a defensive
/// function should still refuse rather than produce nonsense bounds.
pub fn wilson_interval(x: i64, n: i64) -> Option<ConfidenceInterval> {
    if n <= 0 || x < 0 || x > n {
        return None;
    }
    let x = x as f64;
    let n = n as f64;
    let z = Z_95;
    let z2 = z * z;
    let p_hat = x / n;
    let denom = 1.0 + z2 / n;
    let center = (p_hat + z2 / (2.0 * n)) / denom;
    let margin = z * ((p_hat * (1.0 - p_hat) / n) + (z2 / (4.0 * n * n))).sqrt() / denom;
    Some(ConfidenceInterval {
        lower: (center - margin).clamp(0.0, 1.0),
        upper: (center + margin).clamp(0.0, 1.0),
    })
}

/// Optional filters for the comparison report. Every field is an exact-match
/// filter, `None` meaning "no restriction on this dimension" — a caller
/// comparing two specific `(model_id, prompt_version)` pairs for one action
/// passes `action` alone and reads both groups out of the same response
/// (the report's whole point: everything needed for a side-by-side
/// comparison arrives in one call, at whatever grouping level the caller
/// asks for).
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
pub struct ComparisonFilter {
    /// Restrict to one action id, e.g. `record.summarize`.
    pub action: Option<String>,
    /// Restrict to one model id.
    pub model_id: Option<String>,
    /// Restrict to one prompt_version.
    pub prompt_version: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct GroupCounts {
    action_id: String,
    model_id: String,
    prompt_version: String,
    total_decided: i64,
    pending: i64,
    accepted: i64,
    edited: i64,
    rejected: i64,
}

/// One `(action, model_id, prompt_version)` group's outcome rates, each with
/// its own Wilson interval sized to that group's own sample.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ComparisonRow {
    pub action_id: String,
    pub model_id: String,
    pub prompt_version: String,
    /// Non-pending outcomes — the denominator every rate below is computed
    /// against. Excludes `pending` for the same reason `quality_monitor.rs`
    /// and `compliance_report.rs` do: an undecided suggestion is neither a
    /// success nor a failure yet.
    pub total_decided: i64,
    pub pending: i64,
    pub accepted: i64,
    pub edited: i64,
    pub rejected: i64,
    /// `accepted / total_decided`. `None` when `total_decided == 0`.
    pub accepted_rate: Option<f64>,
    pub accepted_ci: Option<ConfidenceInterval>,
    /// `edited / total_decided`.
    pub edited_rate: Option<f64>,
    pub edited_ci: Option<ConfidenceInterval>,
    /// `rejected / total_decided`.
    pub rejected_rate: Option<f64>,
    pub rejected_ci: Option<ConfidenceInterval>,
}

/// The whole report: every group matching the filter, plus when it was run.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ComparisonReport {
    pub generated_at: DateTime<Utc>,
    pub groups: Vec<ComparisonRow>,
}

fn build_row(g: GroupCounts) -> ComparisonRow {
    let rate = |x: i64| {
        if g.total_decided == 0 {
            None
        } else {
            Some(x as f64 / g.total_decided as f64)
        }
    };
    ComparisonRow {
        action_id: g.action_id,
        model_id: g.model_id,
        prompt_version: g.prompt_version,
        total_decided: g.total_decided,
        pending: g.pending,
        accepted: g.accepted,
        edited: g.edited,
        rejected: g.rejected,
        accepted_rate: rate(g.accepted),
        accepted_ci: wilson_interval(g.accepted, g.total_decided),
        edited_rate: rate(g.edited),
        edited_ci: wilson_interval(g.edited, g.total_decided),
        rejected_rate: rate(g.rejected),
        rejected_ci: wilson_interval(g.rejected, g.total_decided),
    }
}

/// `x::text IS NULL OR column = x` per filter column — each filter is
/// independently optional, and `None` binds as SQL `NULL` for an
/// `Option<&str>` bind, so an omitted filter imposes no restriction rather
/// than matching nothing.
async fn fetch_groups(
    db: &PgPool,
    filter: &ComparisonFilter,
) -> Result<Vec<GroupCounts>, AppError> {
    sqlx::query_as::<_, GroupCounts>(
        "SELECT action_id, model_id, prompt_version, \
                COUNT(*) FILTER (WHERE outcome != 'pending') AS total_decided, \
                COUNT(*) FILTER (WHERE outcome = 'pending') AS pending, \
                COUNT(*) FILTER (WHERE outcome = 'accepted') AS accepted, \
                COUNT(*) FILTER (WHERE outcome = 'edited') AS edited, \
                COUNT(*) FILTER (WHERE outcome = 'rejected') AS rejected \
         FROM ai_suggestion_outcome \
         WHERE ($1::text IS NULL OR action_id = $1) \
           AND ($2::text IS NULL OR model_id = $2) \
           AND ($3::text IS NULL OR prompt_version = $3) \
         GROUP BY action_id, model_id, prompt_version \
         ORDER BY action_id, model_id, prompt_version",
    )
    .bind(filter.action.as_deref())
    .bind(filter.model_id.as_deref())
    .bind(filter.prompt_version.as_deref())
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Builds the comparison report for the given filter.
pub async fn build_report(
    db: &PgPool,
    filter: &ComparisonFilter,
) -> Result<ComparisonReport, AppError> {
    let groups = fetch_groups(db, filter).await?;
    Ok(ComparisonReport {
        generated_at: Utc::now(),
        groups: groups.into_iter().map(build_row).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference values independently computed from the standard closed-form
    /// Wilson formula (verified against a second, independently-written
    /// implementation before being hardcoded here — not eyeballed):
    ///
    /// | x  | n   | lower    | upper    |
    /// |----|-----|----------|----------|
    /// | 5  | 10  | 0.236593 | 0.763407 |
    /// | 80 | 100 | 0.711171 | 0.866633 |
    /// | 0  | 10  | 0.0      | 0.277533 |
    /// | 10 | 10  | 0.722467 | 1.0      |
    #[test]
    fn wilson_interval_matches_known_reference_values() {
        let cases: &[(i64, i64, f64, f64)] = &[
            (5, 10, 0.236593, 0.763407),
            (80, 100, 0.711171, 0.866633),
            (0, 10, 0.0, 0.277533),
            (10, 10, 0.722467, 1.0),
        ];
        for &(x, n, lower, upper) in cases {
            let ci = wilson_interval(x, n).unwrap_or_else(|| panic!("x={x} n={n} must yield a CI"));
            assert!(
                (ci.lower - lower).abs() < 1e-5,
                "x={x} n={n}: lower {} != expected {lower}",
                ci.lower
            );
            assert!(
                (ci.upper - upper).abs() < 1e-5,
                "x={x} n={n}: upper {} != expected {upper}",
                ci.upper
            );
        }
    }

    #[test]
    fn wilson_interval_is_none_for_zero_trials() {
        assert!(wilson_interval(0, 0).is_none());
    }

    #[test]
    fn wilson_interval_rejects_an_impossible_count() {
        assert!(wilson_interval(-1, 10).is_none());
        assert!(wilson_interval(11, 10).is_none());
    }

    /// The interval always stays inside [0, 1], including at the extremes —
    /// the exact failure mode the naive Wald interval does not avoid.
    #[test]
    fn wilson_interval_is_always_within_unit_bounds() {
        for (x, n) in [(0, 1), (1, 1), (0, 1000), (1000, 1000), (1, 2)] {
            let ci = wilson_interval(x, n).unwrap();
            assert!((0.0..=1.0).contains(&ci.lower));
            assert!((0.0..=1.0).contains(&ci.upper));
            assert!(ci.lower <= ci.upper);
        }
    }

    /// A wider sample narrows the interval around the same point estimate —
    /// the qualitative property a confidence interval must have for a
    /// champion/challenger comparison to be meaningful at all (a challenger
    /// with 10 decided outcomes must show a visibly wider interval than one
    /// with 1000, at the same observed rate).
    #[test]
    fn a_larger_sample_yields_a_narrower_interval_at_the_same_rate() {
        let small = wilson_interval(5, 10).unwrap();
        let large = wilson_interval(500, 1000).unwrap();
        assert!(large.upper - large.lower < small.upper - small.lower);
    }

    fn group(
        action_id: &str,
        model_id: &str,
        prompt_version: &str,
        accepted: i64,
        edited: i64,
        rejected: i64,
        pending: i64,
    ) -> GroupCounts {
        GroupCounts {
            action_id: action_id.to_string(),
            model_id: model_id.to_string(),
            prompt_version: prompt_version.to_string(),
            total_decided: accepted + edited + rejected,
            pending,
            accepted,
            edited,
            rejected,
        }
    }

    /// The report's shape: rates are computed against the decided total
    /// (excluding pending), each rate carries its own CI, and a group with
    /// zero decided outcomes reports `None` rather than a misleading 0%.
    #[test]
    fn a_group_with_no_decided_outcomes_reports_no_rate_or_interval() {
        let row = build_row(group("record.summarize", "model-a", "v1", 0, 0, 0, 5));
        assert_eq!(row.total_decided, 0);
        assert_eq!(row.pending, 5);
        assert_eq!(row.accepted_rate, None);
        assert_eq!(row.accepted_ci, None);
        assert_eq!(row.edited_rate, None);
        assert_eq!(row.rejected_rate, None);
    }

    #[test]
    fn rates_are_computed_against_the_decided_total_not_pending() {
        // 6 accepted, 3 edited, 1 rejected = 10 decided, plus 4 pending
        // that must not dilute the rate.
        let row = build_row(group("record.summarize", "model-a", "v1", 6, 3, 1, 4));
        assert_eq!(row.total_decided, 10);
        assert_eq!(row.accepted_rate, Some(0.6));
        assert_eq!(row.edited_rate, Some(0.3));
        assert_eq!(row.rejected_rate, Some(0.1));
        assert!(row.accepted_ci.is_some());
        assert!(row.edited_ci.is_some());
        assert!(row.rejected_ci.is_some());
    }

    /// A caller comparing champion vs. challenger for the same action reads
    /// both rows out of one report — the report's central use case.
    #[test]
    fn two_prompt_versions_for_the_same_action_appear_as_separate_rows() {
        let champion = build_row(group("record.summarize", "model-a", "v1", 90, 5, 5, 0));
        let challenger = build_row(group("record.summarize", "model-a", "v2", 40, 5, 5, 0));
        assert_eq!(champion.action_id, challenger.action_id);
        assert_ne!(champion.prompt_version, challenger.prompt_version);
        assert!(champion.accepted_rate.unwrap() > challenger.accepted_rate.unwrap());
    }
}

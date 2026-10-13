//! Search metrics (TODO-025).
//!
//! **Zero-result rate is the cheapest and most actionable search-quality
//! signal that exists**, and the earlier plan deferred it to Stage 4. It needs
//! no relevance judgments, no click volume, and no model: a rising
//! zero-result rate is a search that stopped working, and it is visible within
//! minutes rather than after someone assembles a golden set.
//!
//! **Staleness is the operational twin.** "Write → searchable" is the number
//! the change feed's design is a trade against: the visibility horizon stalls
//! the drain behind any long transaction (D-358), which is *bounded* staleness
//! rather than loss — but only if someone can see the bound being exceeded. An
//! unmeasured bound is a promise, not a guarantee.

/// A metric name and its help text, so the Prometheus registration and the
/// recording site cannot drift.
pub struct MetricDef {
    pub name: &'static str,
    pub help: &'static str,
}

impl std::fmt::Debug for MetricDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricDef").finish_non_exhaustive()
    }
}

/// Searches served, labelled by route and audience. The denominator for the
/// zero-result rate.
pub const SEARCHES_TOTAL: MetricDef = MetricDef {
    name: "attome_search_queries_total",
    help: "Search queries served, by route and audience.",
};

/// Searches that returned nothing.
///
/// A **counter**, deliberately, not a gauge of the rate: a rate computed in
/// the application is a rate computed over whatever window the application
/// happens to use, and every alerting question ("is it worse than last week")
/// wants to pick its own. Two counters let the query decide.
pub const ZERO_RESULT_TOTAL: MetricDef = MetricDef {
    name: "attome_search_zero_result_total",
    help: "Search queries that returned no results, by route and audience.",
};

/// Wall-clock per search.
pub const SEARCH_DURATION: MetricDef = MetricDef {
    name: "attome_search_duration_seconds",
    help: "End-to-end search latency, by route.",
};

/// Per-leg degradation.
///
/// Without this, a leg that quietly stops contributing looks exactly like a
/// corpus with fewer matches — the same failure the `degraded[]` field exists
/// to surface to a caller, surfaced to an operator.
pub const LEG_DEGRADED_TOTAL: MetricDef = MetricDef {
    name: "attome_search_leg_degraded_total",
    help: "Searches in which a leg did not run to completion, by leg and reason.",
};

/// Seconds between a record's last write and its indexing.
///
/// The number D-358's visibility-horizon trade is measured against. Alarm
/// above the documented bound — a stalled drain is invisible otherwise, and
/// its symptom (recent records missing from search) reads as a relevance
/// problem rather than a pipeline one.
pub const INDEX_STALENESS: MetricDef = MetricDef {
    name: "attome_search_index_staleness_seconds",
    help: "Age of the oldest un-indexed change, in seconds.",
};

/// Rows in the index, by corpus. Capacity planning, and the first thing to
/// check when someone reports that search "lost everything".
pub const INDEX_ROWS: MetricDef = MetricDef {
    name: "attome_search_index_rows",
    help: "Rows currently in the search index, by corpus.",
};

pub fn all() -> Vec<&'static MetricDef> {
    vec![
        &SEARCHES_TOTAL,
        &ZERO_RESULT_TOTAL,
        &SEARCH_DURATION,
        &LEG_DEGRADED_TOTAL,
        &INDEX_STALENESS,
        &INDEX_ROWS,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every metric name is unique and namespaced. A duplicate registration
    /// panics the Prometheus registry at boot, which turns a copy-paste into a
    /// deployment that will not start.
    #[test]
    fn metric_names_are_unique_and_namespaced() {
        let mut seen = HashSet::new();
        for metric in all() {
            assert!(
                metric.name.starts_with("attome_search_"),
                "{} must be namespaced",
                metric.name
            );
            assert!(seen.insert(metric.name), "duplicate metric {}", metric.name);
            assert!(!metric.help.is_empty(), "{} needs help text", metric.name);
        }
    }

    /// Zero-result is a counter alongside a total, not a pre-computed rate.
    /// A rate computed here is a rate over whatever window this code chose,
    /// and every alerting question wants to pick its own.
    #[test]
    fn the_zero_result_signal_is_two_counters_not_a_rate() {
        assert!(ZERO_RESULT_TOTAL.name.ends_with("_total"));
        assert!(SEARCHES_TOTAL.name.ends_with("_total"));
        assert!(
            !ZERO_RESULT_TOTAL.name.contains("rate"),
            "a pre-computed rate fixes the window at the wrong layer"
        );
    }

    /// Staleness is measured in seconds and named so. A gauge whose unit is
    /// only in the help text is one somebody eventually alerts on in the wrong
    /// unit.
    #[test]
    fn the_staleness_metric_names_its_unit() {
        assert!(INDEX_STALENESS.name.ends_with("_seconds"));
        assert!(SEARCH_DURATION.name.ends_with("_seconds"));
    }
}

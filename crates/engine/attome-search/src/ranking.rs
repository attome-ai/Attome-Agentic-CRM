//! Ranking signals and the ranker that weighs them (TODO-022).
//!
//! **The split is the whole point.** A hand-tuned stack of weights inlined
//! into the query is 2010-era ranking, and worse, it is a dead end: replacing
//! it with a learned ranker later means rewriting the retrieval path rather
//! than swapping an implementation.
//!
//! So extraction and weighting are separate:
//!
//! * A [`RankingSignal`] reports **a fact** about a candidate — how recent it
//!   is, whether the caller owns it, how well the text matched. Note what
//!   `extract` does *not* take: a weight profile. A signal that knew its own
//!   importance would be a signal that has to be edited to retune, and a
//!   learned ranker would have to fight it.
//! * A [`Ranker`] turns a [`FeatureVector`] into a score and owns weighting
//!   entirely.
//!
//! Swapping [`LinearRanker`] for a learned one is then a new `impl` and one
//! call site — asserted by `swapping_the_ranker_touches_one_call_site`, which
//! is the property TODO-049 depends on and which is very easy to lose by
//! letting one weight leak into extraction.

use std::collections::BTreeMap;

/// The signals extracted for one candidate.
///
/// `BTreeMap` so serialisation into the impression log's `feature_vector` is
/// stable — a training set whose columns reorder between builds is one a model
/// cannot be trained on twice.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FeatureVector {
    values: BTreeMap<&'static str, f64>,
}

impl FeatureVector {
    pub fn insert(&mut self, name: &'static str, value: f64) {
        self.values.insert(name, value);
    }

    pub fn get(&self, name: &str) -> f64 {
        self.values.get(name).copied().unwrap_or(0.0)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&&'static str, &f64)> {
        self.values.iter()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.values
                .iter()
                .filter_map(|(k, v)| {
                    serde_json::Number::from_f64(*v)
                        .map(|n| ((*k).to_owned(), serde_json::Value::Number(n)))
                })
                .collect(),
        )
    }
}

/// What a candidate looks like to the signal extractors.
pub struct Candidate<'a> {
    /// The fused RRF score from retrieval.
    pub rrf: f64,
    /// Which legs matched. An exact-key hit is qualitatively different from a
    /// trigram near-miss, and the leg set is how that survives fusion.
    pub matched_legs: &'a [String],
    /// Age of the source record, in days.
    pub age_days: f64,
    /// Whether the caller owns this record.
    ///
    /// **A ranking input only.** Ownership grants nothing in this platform
    /// (D-357 ruling 2) — this boosts a record the caller can *already* see,
    /// and can never admit one they cannot.
    pub caller_owns: bool,
    /// How recently the caller viewed this record, in days. `None` if never.
    /// Strictly per-caller — a cross-caller popularity signal would leak who
    /// looks at what.
    pub caller_last_viewed_days: Option<f64>,
}

impl std::fmt::Debug for Candidate<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate").finish_non_exhaustive()
    }
}

/// One extractable fact.
///
/// `extract` takes no weight profile, deliberately. See the module doc.
pub trait RankingSignal: Send + Sync {
    fn name(&self) -> &'static str;
    fn extract(&self, candidate: &Candidate<'_>) -> f64;
}

/// K1 — the fused retrieval score.
#[derive(Debug)]
pub struct TextMatch;
impl RankingSignal for TextMatch {
    fn name(&self) -> &'static str {
        "text_match"
    }
    fn extract(&self, c: &Candidate<'_>) -> f64 {
        c.rrf
    }
}

/// K2 — recency, decayed.
///
/// Exponential with a 90-day half-life rather than a linear ramp: a record
/// touched yesterday and one touched last week are nearly equally current,
/// while one from two years ago is not "a bit less relevant", it is a
/// different kind of thing. A linear decay gets both ends wrong.
#[derive(Debug)]
pub struct Recency;
impl RankingSignal for Recency {
    fn name(&self) -> &'static str {
        "recency"
    }
    fn extract(&self, c: &Candidate<'_>) -> f64 {
        0.5_f64.powf(c.age_days.max(0.0) / 90.0)
    }
}

/// K3 — the caller owns it.
///
/// A **ranking** signal and never an access grant. See [`Candidate::caller_owns`].
#[derive(Debug)]
pub struct Ownership;
impl RankingSignal for Ownership {
    fn name(&self) -> &'static str {
        "ownership"
    }
    fn extract(&self, c: &Candidate<'_>) -> f64 {
        if c.caller_owns { 1.0 } else { 0.0 }
    }
}

/// Frecency (TODO-059) — the caller recently or frequently viewed it.
///
/// The cheapest large search-quality win available, and it needs no AI at all:
/// most CRM lookups re-open a record the caller touched recently. It works in
/// the lexical-only stage, which is also the entire CPU-only tier's
/// experience.
///
/// **Strictly caller-scoped.** A cross-caller popularity signal would leak who
/// looks at what — an HR record that ranks highly for everyone because one
/// person keeps opening it is a disclosure with a plausible-looking
/// explanation.
#[derive(Debug)]
pub struct Frecency;
impl RankingSignal for Frecency {
    fn name(&self) -> &'static str {
        "frecency"
    }
    fn extract(&self, c: &Candidate<'_>) -> f64 {
        match c.caller_last_viewed_days {
            None => 0.0,
            Some(days) => 0.5_f64.powf(days.max(0.0) / 7.0),
        }
    }
}

/// K4 — an exact-key hit.
///
/// Separated from the fused score because it is categorically different:
/// someone who pastes an invoice number wants that invoice, and no amount of
/// textual similarity elsewhere should outrank it.
#[derive(Debug)]
pub struct ExactHit;
impl RankingSignal for ExactHit {
    fn name(&self) -> &'static str {
        "exact_hit"
    }
    fn extract(&self, c: &Candidate<'_>) -> f64 {
        if c.matched_legs.iter().any(|l| l.starts_with("R1.")) {
            1.0
        } else {
            0.0
        }
    }
}

/// Every signal, in a fixed order.
pub fn signals() -> Vec<Box<dyn RankingSignal>> {
    vec![
        Box::new(TextMatch),
        Box::new(Recency),
        Box::new(Ownership),
        Box::new(Frecency),
        Box::new(ExactHit),
    ]
}

pub fn extract_all(candidate: &Candidate<'_>) -> FeatureVector {
    let mut vector = FeatureVector::default();
    for signal in signals() {
        vector.insert(signal.name(), signal.extract(candidate));
    }
    vector
}

/// Turns extracted facts into an order.
///
/// The seam TODO-049 swaps. `id()` reaches the impression log, so a log
/// spanning a ranker change is two distinguishable populations rather than one
/// averaged one.
pub trait Ranker: Send + Sync {
    fn id(&self) -> &'static str;
    fn score(&self, features: &FeatureVector) -> f64;
}

/// Hand-tuned weights. Stage 1's ranker.
///
/// The weights are a starting point and are explicitly **not** tuned yet —
/// TODO-023's harness has to exist before tuning them means anything, or the
/// exercise is three weeks of adjusting numbers against intuition.
#[derive(Debug)]
pub struct LinearRanker;

impl Ranker for LinearRanker {
    fn id(&self) -> &'static str {
        "linear/v1"
    }

    fn score(&self, f: &FeatureVector) -> f64 {
        // An exact hit dominates by construction rather than by a large
        // weight: a weight big enough to always win is a weight that distorts
        // every comparison it does not win.
        if f.get("exact_hit") > 0.0 {
            return 1_000.0 + f.get("text_match");
        }
        1.0 * f.get("text_match")
            + 0.30 * f.get("recency")
            + 0.20 * f.get("ownership")
            + 0.25 * f.get("frecency")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> Candidate<'static> {
        static NO_LEGS: &[String] = &[];
        Candidate {
            rrf: 0.5,
            matched_legs: NO_LEGS,
            age_days: 0.0,
            caller_owns: false,
            caller_last_viewed_days: None,
        }
    }

    /// **The property TODO-049 depends on.** Swapping the ranker is a new
    /// `impl`, not a rewrite — and it is easy to lose by letting one weight
    /// leak into a signal.
    #[test]
    fn swapping_the_ranker_touches_one_call_site() {
        struct StubRanker;
        impl Ranker for StubRanker {
            fn id(&self) -> &'static str {
                "stub/v0"
            }
            fn score(&self, _: &FeatureVector) -> f64 {
                42.0
            }
        }

        let features = extract_all(&candidate());
        // Both are `dyn Ranker`. Nothing about extraction changed.
        let rankers: Vec<Box<dyn Ranker>> = vec![Box::new(LinearRanker), Box::new(StubRanker)];
        let scores: Vec<f64> = rankers.iter().map(|r| r.score(&features)).collect();
        assert_eq!(scores.len(), 2);
        assert_eq!(scores[1], 42.0);
    }

    /// A signal reports a fact and never its own importance. If `extract` ever
    /// gains a weight argument, this stops compiling — which is the point.
    #[test]
    fn a_signal_does_not_know_its_own_weight() {
        let c = candidate();
        for signal in signals() {
            let _: f64 = signal.extract(&c);
        }
    }

    /// Recency decays exponentially. A record touched yesterday and one from
    /// last week are nearly equally current; one from two years ago is a
    /// different kind of thing, and a linear ramp gets both ends wrong.
    #[test]
    fn recency_decays_with_a_ninety_day_half_life() {
        let at = |days: f64| {
            Recency.extract(&Candidate {
                age_days: days,
                ..candidate()
            })
        };
        assert!((at(0.0) - 1.0).abs() < 1e-9);
        assert!((at(90.0) - 0.5).abs() < 1e-9);
        assert!(
            at(730.0) < 0.01,
            "a two-year-old record is not merely 'less recent'"
        );
        // Monotonic, and a negative age (clock skew) does not exceed 1.
        assert!(at(1.0) > at(7.0) && at(7.0) > at(30.0));
        assert!(at(-5.0) <= 1.0);
    }

    /// Frecency is caller-scoped and decays fast — a week-old view is worth
    /// far less than yesterday's.
    #[test]
    fn frecency_is_caller_scoped_and_decays_fast() {
        let never = Frecency.extract(&candidate());
        assert_eq!(never, 0.0, "a record the caller never opened gets no boost");

        let yesterday = Frecency.extract(&Candidate {
            caller_last_viewed_days: Some(1.0),
            ..candidate()
        });
        let last_month = Frecency.extract(&Candidate {
            caller_last_viewed_days: Some(30.0),
            ..candidate()
        });
        assert!(yesterday > last_month);
        assert!(last_month < 0.1);
    }

    /// An exact-key hit outranks everything, and does so structurally rather
    /// than via a weight large enough to distort every other comparison.
    #[test]
    fn an_exact_hit_outranks_a_perfect_text_match() {
        let legs = vec!["R1.exact".to_string()];
        let exact = extract_all(&Candidate {
            rrf: 0.01,
            matched_legs: &legs,
            ..candidate()
        });
        let best_text = extract_all(&Candidate {
            rrf: 1.0,
            age_days: 0.0,
            caller_owns: true,
            caller_last_viewed_days: Some(0.0),
            ..candidate()
        });

        assert!(
            LinearRanker.score(&exact) > LinearRanker.score(&best_text),
            "pasting an invoice number must return that invoice, not the best \
             textual match for its digits"
        );
    }

    /// Ownership contributes a boost and nothing more. It can raise a record
    /// the caller already sees; it can never admit one they cannot — that is
    /// the predicate's job, and D-357 ruling 2 is explicit that ownership
    /// grants nothing.
    #[test]
    fn ownership_is_a_boost_and_never_a_grant() {
        let owned = extract_all(&Candidate {
            caller_owns: true,
            ..candidate()
        });
        let not_owned = extract_all(&candidate());
        assert!(LinearRanker.score(&owned) > LinearRanker.score(&not_owned));
        // Bounded: it cannot swamp the text match.
        assert!(
            LinearRanker.score(&owned) - LinearRanker.score(&not_owned) < 1.0,
            "an ownership boost must not be able to outrank relevance outright"
        );
    }

    /// The feature vector serialises with stable key order. A training set
    /// whose columns reorder between builds is one a model cannot be trained
    /// on twice.
    #[test]
    fn the_feature_vector_serialises_stably() {
        let first = extract_all(&candidate()).to_json().to_string();
        for _ in 0..5 {
            assert_eq!(extract_all(&candidate()).to_json().to_string(), first);
        }
        assert!(first.contains("text_match"));
        assert!(first.contains("recency"));
    }

    /// Every signal is finite for every plausible input. A NaN reaching the
    /// sort would make the order arbitrary in a way no assertion downstream
    /// would catch.
    #[test]
    fn every_signal_is_finite() {
        for age in [-1.0, 0.0, 1.0, 10_000.0, f64::MAX] {
            for viewed in [None, Some(0.0), Some(1e9)] {
                let c = Candidate {
                    rrf: 0.5,
                    age_days: age,
                    caller_last_viewed_days: viewed,
                    ..candidate()
                };
                let features = extract_all(&c);
                for (name, value) in features.iter() {
                    assert!(value.is_finite(), "{name} produced {value}");
                }
                assert!(LinearRanker.score(&features).is_finite());
            }
        }
    }
}

//! Retrieval evaluation metrics (TODO-023).
//!
//! **This ships before any weight is tuned.** Tuning ranking without a harness
//! is three weeks of adjusting numbers against intuition, and the failure mode
//! is not that it fails — it is that it *feels* like it works, because whoever
//! tunes it checks the queries they had in mind while tuning.
//!
//! ## Why three metrics and not one
//!
//! They fail differently, and a single number hides which one broke:
//!
//! * **recall@k** — was the right thing retrieved *at all*. This is the one the
//!   retrieval legs and the per-leg ceiling control. A record that never enters
//!   the candidate set cannot be rescued by any ranker.
//! * **MRR@k** — how far down the *first* right answer sits. The metric for the
//!   omni-box, where a user types, glances, and either clicks or retypes.
//! * **nDCG@k** — graded quality across the whole visible list. The metric for
//!   agent retrieval, where the model reads all ten.
//!
//! A change that improves nDCG while dropping recall has made the ranker better
//! at ordering a candidate set that no longer contains the answer. Only
//! reporting the three together makes that visible.
//!
//! ## Judgments are graded, not binary
//!
//! Relevance is 0–3 ([`Judgment::grade`]). Binary judgments cannot distinguish
//! "the invoice they meant" from "an invoice mentioning the same company",
//! which is the *entire* difference between a good result list and a mediocre
//! one — and nDCG's whole reason to exist is that it can.
//!
//! ## Who produces the fixtures
//!
//! Stated because the earlier plan budgeted neither: the implementing engineer
//! owns fixture production as a Stage-1 deliverable, ~3–4 days. The Arabic
//! judgments need a native speaker — grading Arabic relevance from
//! transliteration produces a fixture that certifies broken search as working.
//! If nobody on staff can do it, that is a contracting item at Stage-1 *start*,
//! not at tuning time.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// One graded judgment: for query Q, document D is worth `grade`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Judgment {
    /// Stable key into the fixture corpus. Not a UUID — UUIDs are minted per
    /// run so the corpus can be seeded into any database, and a fixture keyed
    /// by a value that changes every run is a fixture nobody can review.
    pub doc: String,
    /// 0 = irrelevant, 1 = marginal, 2 = relevant, 3 = exactly what was meant.
    pub grade: u8,
    /// Marks a judgment the current retrieval configuration is *known* to be
    /// unable to reach — the record sits past the per-leg ceiling. It still
    /// counts against recall, deliberately: the report separates "ranked badly"
    /// from "never retrieved" because they have different fixes, but neither is
    /// forgiven.
    #[serde(default)]
    pub beyond_ceiling: bool,
}

/// What a query is testing, so the report can break results down by kind.
///
/// An overall nDCG that holds steady while Arabic collapses is a regression the
/// aggregate cannot show, and Arabic is exactly the case that degrades silently
/// (`lang::arabic`'s module doc: unnormalized Arabic search *looks* like it
/// works).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryKind {
    /// A pasted identifier. Must land at rank 1 or the feature is broken.
    ExactKey,
    /// Ordinary Latin-script keyword search.
    Lexical,
    /// Arabic, including the normalization vectors.
    Arabic,
    /// A typo or transposition — the fuzzy leg's territory.
    Fuzzy,
    /// Partial input, as typed into the omni-box.
    Prefix,
    /// A recent record that ranks poorly lexically. The case the ceiling
    /// interacts with.
    Recency,
    /// The caller must see nothing. Scored as a hard assertion, never averaged.
    Forbidden,
}

/// One evaluated query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryCase {
    pub id: String,
    pub query: String,
    pub kind: QueryKind,
    /// Which seeded caller runs it. `Forbidden` cases use a narrowed one.
    #[serde(default = "default_caller")]
    pub caller: String,
    #[serde(default)]
    pub judgments: Vec<Judgment>,
    /// Free-text note on *why* this case exists. Read by whoever has to decide
    /// whether a future regression is a bug or a deliberate trade.
    #[serde(default)]
    pub note: String,
}

fn default_caller() -> String {
    "primary".to_string()
}

/// A document in the seeded corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusDoc {
    pub key: String,
    pub entity: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub exact_keys: Vec<String>,
    /// Which seeded organization owns it — how the `Forbidden` cases become
    /// invisible without any special-casing in the harness.
    #[serde(default)]
    pub org: Option<String>,
    /// Age in days, for the recency signal.
    #[serde(default)]
    pub age_days: i64,
}

/// Bulk chaff, declared rather than enumerated.
///
/// The recency case needs a target sitting at roughly lexical rank #2000
/// against a per-leg ceiling of 500 — which needs ~2000 competing documents.
/// Listing those in the fixture would make it unreviewable, and generating them
/// silently inside the harness would hide the one number the case turns on. So
/// the fixture *declares* them and the harness expands them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillerSpec {
    /// Key prefix for the generated documents.
    pub key_prefix: String,
    pub entity: String,
    /// Title template; `{n}` is replaced with the index.
    pub title: String,
    pub body: String,
    pub count: usize,
    /// Age of the generated documents in days — older than the recency target,
    /// which is the entire point of the comparison.
    #[serde(default)]
    pub age_days: i64,
}

/// The whole fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldenSet {
    pub corpus: Vec<CorpusDoc>,
    #[serde(default)]
    pub filler: Vec<FillerSpec>,
    pub queries: Vec<QueryCase>,
}

impl GoldenSet {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Every judgment must name a document that exists.
    ///
    /// A typo in a doc key silently makes a query *unsatisfiable*: the metric
    /// drops, and the obvious reading is "the ranker got worse". Checked at
    /// load so the fixture fails loudly instead.
    pub fn validate(&self) -> Result<(), String> {
        let keys: HashSet<&str> = self.corpus.iter().map(|d| d.key.as_str()).collect();
        if keys.len() != self.corpus.len() {
            return Err("duplicate corpus key".to_string());
        }
        let mut ids = HashSet::new();
        for q in &self.queries {
            if !ids.insert(&q.id) {
                return Err(format!("duplicate query id {}", q.id));
            }
            if q.query.trim().is_empty() {
                return Err(format!("query {} is empty", q.id));
            }
            for j in &q.judgments {
                if !keys.contains(j.doc.as_str()) {
                    return Err(format!("query {} judges unknown doc {}", q.id, j.doc));
                }
                if j.grade > 3 {
                    return Err(format!("query {} grade {} out of range", q.id, j.grade));
                }
            }
            match q.kind {
                QueryKind::Forbidden => {
                    if !q.judgments.is_empty() {
                        return Err(format!(
                            "forbidden query {} must have no judgments — it is a \
                             zero-results assertion, not a scored case",
                            q.id
                        ));
                    }
                }
                _ => {
                    if !q.judgments.iter().any(|j| j.grade > 0) {
                        return Err(format!(
                            "query {} has no relevant document; a case whose answer \
                             is nothing belongs in kind=forbidden",
                            q.id
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Discounted cumulative gain at `k`, over a ranked list of doc keys.
///
/// `(2^grade - 1) / log2(rank + 1)` — the standard exponential-gain form. The
/// exponential numerator is what makes a grade-3 hit worth materially more than
/// two grade-1s; the linear form treats them as interchangeable, which is
/// exactly the judgment call the grades exist to express.
fn dcg(grades: impl Iterator<Item = u8>, k: usize) -> f64 {
    let sum: f64 = grades
        .take(k)
        .enumerate()
        .map(|(i, g)| ((1u32 << g) as f64 - 1.0) / ((i as f64) + 2.0).log2())
        .sum();
    // `+ 0.0` normalizes negative zero. Rust's `Sum for f64` starts from -0.0,
    // so an empty result list — a query that retrieved *nothing*, which is a
    // case this harness exists to surface — scores `-0.000` in the report. It
    // compares equal to zero and behaves correctly everywhere; it just reads as
    // a bug to whoever is looking at the CI log for a real one.
    sum + 0.0
}

/// nDCG@k. Returns `None` when the query has no positive judgment — an
/// undefined value, and returning 0.0 instead would drag the mean down with a
/// number that means "unanswerable", not "answered badly".
pub fn ndcg_at_k(ranked: &[String], judgments: &[Judgment], k: usize) -> Option<f64> {
    let by_doc: BTreeMap<&str, u8> = judgments
        .iter()
        .map(|j| (j.doc.as_str(), j.grade))
        .collect();

    let mut ideal: Vec<u8> = judgments.iter().map(|j| j.grade).collect();
    ideal.sort_unstable_by(|a, b| b.cmp(a));
    let idcg = dcg(ideal.into_iter(), k);
    if idcg == 0.0 {
        return None;
    }

    let actual = dcg(
        ranked
            .iter()
            .map(|d| by_doc.get(d.as_str()).copied().unwrap_or(0)),
        k,
    );
    Some(actual / idcg)
}

/// Reciprocal rank of the first result graded 2 or better.
///
/// The threshold is deliberate: a marginal result at rank 1 is not a success.
/// Counting grade-1 hits would let a ranker that surfaces "some invoice for
/// this company" score identically to one that surfaces *the* invoice.
pub fn reciprocal_rank(ranked: &[String], judgments: &[Judgment], k: usize) -> f64 {
    let relevant: HashSet<&str> = judgments
        .iter()
        .filter(|j| j.grade >= 2)
        .map(|j| j.doc.as_str())
        .collect();
    ranked
        .iter()
        .take(k)
        .position(|d| relevant.contains(d.as_str()))
        .map(|i| 1.0 / (i as f64 + 1.0))
        .unwrap_or(0.0)
}

/// Fraction of the relevant documents (grade ≥ 2) that appear in the top `k`.
pub fn recall_at_k(ranked: &[String], judgments: &[Judgment], k: usize) -> Option<f64> {
    let relevant: HashSet<&str> = judgments
        .iter()
        .filter(|j| j.grade >= 2)
        .map(|j| j.doc.as_str())
        .collect();
    if relevant.is_empty() {
        return None;
    }
    let found = ranked
        .iter()
        .take(k)
        .filter(|d| relevant.contains(d.as_str()))
        .count();
    Some(found as f64 / relevant.len() as f64)
}

/// One query's scores.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub id: String,
    pub kind: QueryKind,
    pub ndcg: Option<f64>,
    pub mrr: f64,
    pub recall: Option<f64>,
    /// Relevant documents the retrieval never returned at all, at any rank.
    ///
    /// Reported separately from a low score because the fix is different: a
    /// document that was retrieved and ranked 40th is a ranking problem, and
    /// one that was never a candidate is a *retrieval* problem no weight change
    /// can touch.
    pub missed_entirely: Vec<String>,
}

/// Aggregate scores, overall and per kind.
#[derive(Debug, Clone, Serialize)]
pub struct EvalReport {
    pub k: usize,
    pub cases: Vec<CaseResult>,
    pub overall: Aggregate,
    pub by_kind: BTreeMap<QueryKind, Aggregate>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Aggregate {
    pub queries: usize,
    pub ndcg: f64,
    pub mrr: f64,
    pub recall: f64,
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let v: Vec<f64> = values.collect();
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<f64>() / v.len() as f64
}

fn aggregate(cases: &[&CaseResult]) -> Aggregate {
    Aggregate {
        queries: cases.len(),
        ndcg: mean(cases.iter().filter_map(|c| c.ndcg)),
        mrr: mean(cases.iter().map(|c| c.mrr)),
        recall: mean(cases.iter().filter_map(|c| c.recall)),
    }
}

impl EvalReport {
    pub fn build(k: usize, cases: Vec<CaseResult>) -> Self {
        let overall = aggregate(&cases.iter().collect::<Vec<_>>());
        let mut by_kind: BTreeMap<QueryKind, Vec<&CaseResult>> = BTreeMap::new();
        for c in &cases {
            by_kind.entry(c.kind).or_default().push(c);
        }
        let by_kind = by_kind
            .into_iter()
            .map(|(kind, cs)| (kind, aggregate(&cs)))
            .collect();
        Self {
            k,
            cases,
            overall,
            by_kind,
        }
    }

    /// Human-readable, for the CI log. A failing gate that prints only a number
    /// sends whoever is on call back to run it locally.
    pub fn render(&self) -> String {
        let mut out = format!(
            "retrieval eval @{} — {} queries\n  overall  nDCG {:.3}  MRR {:.3}  recall {:.3}\n",
            self.k, self.overall.queries, self.overall.ndcg, self.overall.mrr, self.overall.recall
        );
        for (kind, agg) in &self.by_kind {
            out.push_str(&format!(
                "  {:<10} n={:<3} nDCG {:.3}  MRR {:.3}  recall {:.3}\n",
                format!("{kind:?}"),
                agg.queries,
                agg.ndcg,
                agg.mrr,
                agg.recall
            ));
        }
        let missed: Vec<&CaseResult> = self
            .cases
            .iter()
            .filter(|c| !c.missed_entirely.is_empty())
            .collect();
        if !missed.is_empty() {
            out.push_str("  never retrieved (a retrieval problem, not a ranking one):\n");
            for c in missed {
                out.push_str(&format!("    {}: {}\n", c.id, c.missed_entirely.join(", ")));
            }
        }
        out
    }
}

/// A recorded baseline, for the CI regression gate.
///
/// **Keyed by a fixture fingerprint.** Comparing today's score against a
/// baseline recorded on a *different* corpus is meaningless, and it is the
/// natural thing to do by accident: someone adds twenty queries, the mean
/// moves, and the gate either fails for no reason or — worse — passes while
/// hiding a real regression behind easier new queries. When the fingerprint
/// does not match, the harness says "re-record" instead of comparing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub fixture_fingerprint: String,
    pub k: usize,
    pub overall: Aggregate,
    pub by_kind: BTreeMap<QueryKind, Aggregate>,
}

/// How far a metric may fall before the gate fires.
///
/// Absolute, not relative: a 2% relative slip on a 0.9 nDCG and on a 0.3 one
/// are not comparable events, and the small-denominator case would let real
/// damage through.
pub const REGRESSION_TOLERANCE: f64 = 0.02;

/// A stable fingerprint of the fixture's *scored content* — query text and
/// judgments. Deliberately excludes `note`, so improving a comment does not
/// invalidate a baseline.
pub fn fixture_fingerprint(set: &GoldenSet) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut ids: Vec<&QueryCase> = set.queries.iter().collect();
    ids.sort_by(|a, b| a.id.cmp(&b.id));
    for q in ids {
        h.update(q.id.as_bytes());
        h.update([0]);
        h.update(q.query.as_bytes());
        h.update([0]);
        h.update(format!("{:?}", q.kind).as_bytes());
        let mut js: Vec<&Judgment> = q.judgments.iter().collect();
        js.sort_by(|a, b| a.doc.cmp(&b.doc));
        for j in js {
            h.update(j.doc.as_bytes());
            h.update([j.grade]);
        }
        h.update([0]);
    }
    format!("{:x}", h.finalize())[..16].to_string()
}

/// Compares a report against a baseline. Returns every violation, not the
/// first — one run should tell you everything that moved.
pub fn check_regression(report: &EvalReport, baseline: &Baseline) -> Vec<String> {
    let mut failures = Vec::new();
    let cmp = |what: &str, now: f64, was: f64, out: &mut Vec<String>| {
        if now < was - REGRESSION_TOLERANCE {
            out.push(format!(
                "{what} regressed: {now:.3} vs baseline {was:.3} (tolerance {REGRESSION_TOLERANCE})"
            ));
        }
    };
    cmp(
        "overall nDCG",
        report.overall.ndcg,
        baseline.overall.ndcg,
        &mut failures,
    );
    cmp(
        "overall MRR",
        report.overall.mrr,
        baseline.overall.mrr,
        &mut failures,
    );
    cmp(
        "overall recall",
        report.overall.recall,
        baseline.overall.recall,
        &mut failures,
    );
    // Per kind as well as overall: an aggregate over 40 queries absorbs a total
    // collapse of one 5-query kind almost entirely, and Arabic is both the
    // smallest group and the one that fails silently.
    for (kind, was) in &baseline.by_kind {
        if let Some(now) = report.by_kind.get(kind) {
            cmp(&format!("{kind:?} nDCG"), now.ndcg, was.ndcg, &mut failures);
            cmp(
                &format!("{kind:?} recall"),
                now.recall,
                was.recall,
                &mut failures,
            );
        } else {
            failures.push(format!("{kind:?} disappeared from the fixture"));
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(doc: &str, grade: u8) -> Judgment {
        Judgment {
            doc: doc.into(),
            grade,
            beyond_ceiling: false,
        }
    }

    fn ranked(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// The ideal ordering scores exactly 1.0. Worth asserting explicitly: an
    /// off-by-one in the log denominator, or a mismatched ideal set, produces a
    /// metric that still looks plausible — it just never reaches 1.0, and
    /// nobody notices because nobody expects a perfect score.
    #[test]
    fn a_perfect_ranking_scores_one() {
        let judgments = vec![j("a", 3), j("b", 2), j("c", 1)];
        let score = ndcg_at_k(&ranked(&["a", "b", "c"]), &judgments, 10).unwrap();
        assert!((score - 1.0).abs() < 1e-9, "perfect ranking scored {score}");
    }

    /// Reversing the ideal order must score strictly worse — the property the
    /// whole metric exists for.
    #[test]
    fn a_reversed_ranking_scores_worse() {
        let judgments = vec![j("a", 3), j("b", 2), j("c", 1)];
        let good = ndcg_at_k(&ranked(&["a", "b", "c"]), &judgments, 10).unwrap();
        let bad = ndcg_at_k(&ranked(&["c", "b", "a"]), &judgments, 10).unwrap();
        assert!(bad < good, "reversed {bad} should be worse than {good}");
        assert!(bad > 0.0, "it still found everything, just badly ordered");
    }

    /// The exponential gain is not decoration: one grade-3 must beat two
    /// grade-1s. With linear gain those tie, and the grades stop meaning
    /// anything.
    #[test]
    fn a_perfect_hit_beats_two_marginal_ones() {
        let judgments = vec![j("best", 3), j("meh1", 1), j("meh2", 1)];
        let precise = ndcg_at_k(&ranked(&["best"]), &judgments, 10).unwrap();
        let vague = ndcg_at_k(&ranked(&["meh1", "meh2"]), &judgments, 10).unwrap();
        assert!(
            precise > vague,
            "one exact hit ({precise}) must beat two marginal ones ({vague})"
        );
    }

    /// nDCG is undefined without a positive judgment, and must not be reported
    /// as zero — a zero would be averaged in as "answered badly" when it means
    /// "unanswerable".
    #[test]
    fn an_unjudged_query_yields_no_score_rather_than_zero() {
        assert!(ndcg_at_k(&ranked(&["a"]), &[j("a", 0)], 10).is_none());
        assert!(recall_at_k(&ranked(&["a"]), &[j("a", 0)], 10).is_none());
    }

    /// MRR ignores marginal hits. A grade-1 at rank 1 is not a success, and
    /// counting it would let "some invoice for this company" score like "the
    /// invoice".
    #[test]
    fn mrr_ignores_marginal_results() {
        let judgments = vec![j("marginal", 1), j("right", 3)];
        assert_eq!(
            reciprocal_rank(&ranked(&["marginal", "right"]), &judgments, 10),
            0.5
        );
        assert_eq!(reciprocal_rank(&ranked(&["right"]), &judgments, 10), 1.0);
        assert_eq!(reciprocal_rank(&ranked(&["marginal"]), &judgments, 10), 0.0);
    }

    /// k truncates. A result at rank 11 is not on the first page and must not
    /// score.
    #[test]
    fn k_truncates_the_list() {
        let mut list: Vec<String> = (0..10).map(|i| format!("filler{i}")).collect();
        list.push("right".into());
        let judgments = vec![j("right", 3)];
        assert_eq!(recall_at_k(&list, &judgments, 10), Some(0.0));
        assert_eq!(recall_at_k(&list, &judgments, 11), Some(1.0));
    }

    /// The gate fires on a real drop and stays quiet for noise.
    #[test]
    fn the_regression_gate_tolerates_noise_and_catches_a_drop() {
        let case = |id: &str, ndcg: f64| CaseResult {
            id: id.into(),
            kind: QueryKind::Lexical,
            ndcg: Some(ndcg),
            mrr: ndcg,
            recall: Some(ndcg),
            missed_entirely: Vec::new(),
        };
        let baseline = Baseline {
            fixture_fingerprint: "x".into(),
            k: 10,
            overall: Aggregate {
                queries: 1,
                ndcg: 0.80,
                mrr: 0.80,
                recall: 0.80,
            },
            by_kind: BTreeMap::new(),
        };

        let noise = EvalReport::build(10, vec![case("a", 0.79)]);
        assert!(check_regression(&noise, &baseline).is_empty());

        let drop = EvalReport::build(10, vec![case("a", 0.60)]);
        assert_eq!(check_regression(&drop, &baseline).len(), 3);
    }

    /// A per-kind collapse must fire even when the overall mean barely moves —
    /// the reason the gate is not overall-only. Arabic is both the smallest
    /// group and the one that degrades without an error.
    #[test]
    fn a_per_kind_collapse_fires_even_when_the_overall_mean_holds() {
        let case = |id: &str, kind: QueryKind, v: f64| CaseResult {
            id: id.into(),
            kind,
            ndcg: Some(v),
            mrr: v,
            recall: Some(v),
            missed_entirely: Vec::new(),
        };
        let mut by_kind = BTreeMap::new();
        by_kind.insert(
            QueryKind::Arabic,
            Aggregate {
                queries: 1,
                ndcg: 0.9,
                mrr: 0.9,
                recall: 0.9,
            },
        );
        let baseline = Baseline {
            fixture_fingerprint: "x".into(),
            k: 10,
            // Overall is generous, so only the per-kind check can catch this.
            overall: Aggregate {
                queries: 20,
                ndcg: 0.5,
                mrr: 0.5,
                recall: 0.5,
            },
            by_kind,
        };
        let report = EvalReport::build(
            10,
            vec![
                case("ar-1", QueryKind::Arabic, 0.0),
                case("en-1", QueryKind::Lexical, 0.95),
                case("en-2", QueryKind::Lexical, 0.95),
                case("en-3", QueryKind::Lexical, 0.95),
            ],
        );
        assert!(
            report.overall.ndcg > baseline.overall.ndcg,
            "the overall mean went UP while Arabic went to zero — which is the \
             whole situation this test exists to describe"
        );
        let failures = check_regression(&report, &baseline);
        assert!(
            failures.iter().any(|f| f.contains("Arabic")),
            "the Arabic collapse must be reported: {failures:?}"
        );
        assert!(
            !failures.iter().any(|f| f.contains("overall")),
            "and the overall gate stayed silent, so only the per-kind check \
             caught it: {failures:?}"
        );
    }

    /// The fingerprint tracks judgments and ignores prose. Editing a `note`
    /// must not invalidate a baseline; changing a grade must.
    #[test]
    fn the_fingerprint_tracks_judgments_and_ignores_notes() {
        let base = GoldenSet {
            filler: Vec::new(),
            corpus: vec![CorpusDoc {
                key: "d1".into(),
                entity: "invoice".into(),
                title: "t".into(),
                body: String::new(),
                exact_keys: Vec::new(),
                org: None,
                age_days: 0,
            }],
            queries: vec![QueryCase {
                id: "q1".into(),
                query: "t".into(),
                kind: QueryKind::Lexical,
                caller: "primary".into(),
                judgments: vec![j("d1", 3)],
                note: "original".into(),
            }],
        };
        let original = fixture_fingerprint(&base);

        let mut renoted = base.clone();
        renoted.queries[0].note = "reworded".into();
        assert_eq!(original, fixture_fingerprint(&renoted));

        let mut regraded = base.clone();
        regraded.queries[0].judgments[0].grade = 1;
        assert_ne!(original, fixture_fingerprint(&regraded));
    }

    /// A judgment naming a document that is not in the corpus makes the query
    /// unsatisfiable, and the symptom is a metric drop that reads as a ranking
    /// regression. It must fail at load instead.
    #[test]
    fn validation_rejects_a_judgment_for_a_missing_document() {
        let set = GoldenSet {
            corpus: Vec::new(),
            filler: Vec::new(),
            queries: vec![QueryCase {
                id: "q1".into(),
                query: "anything".into(),
                kind: QueryKind::Lexical,
                caller: "primary".into(),
                judgments: vec![j("typo-key", 3)],
                note: String::new(),
            }],
        };
        let err = set.validate().expect_err("must reject");
        assert!(err.contains("typo-key"), "{err}");
    }

    /// A forbidden case carrying judgments is a contradiction — it asserts both
    /// "you must see nothing" and "these are the right answers".
    #[test]
    fn validation_rejects_a_forbidden_case_with_judgments() {
        let set = GoldenSet {
            filler: Vec::new(),
            corpus: vec![CorpusDoc {
                key: "d1".into(),
                entity: "invoice".into(),
                title: "t".into(),
                body: String::new(),
                exact_keys: Vec::new(),
                org: None,
                age_days: 0,
            }],
            queries: vec![QueryCase {
                id: "q1".into(),
                query: "t".into(),
                kind: QueryKind::Forbidden,
                caller: "narrowed".into(),
                judgments: vec![j("d1", 3)],
                note: String::new(),
            }],
        };
        assert!(set.validate().is_err());
    }
}

//! Evidence-coverage scoring for agent retrieval (TODO-024).
//!
//! **nDCG cannot see the RAG failure that matters.** A retrieval that returns
//! three of the four facts an answer needs, at ranks 1–3, scores beautifully —
//! every returned document is highly relevant, nothing irrelevant is above them
//! — and then the model writes a confident, wrong answer. Ranking quality and
//! answerability are different properties, and optimizing the first is not a
//! proxy for the second.
//!
//! So this is a second metric over the *same* corpus and the same retrieval
//! path, asking a different question: **was the evidence set complete?**
//!
//! ## Completion rate, not mean coverage
//!
//! [`CoverageReport::completion_rate`] is the number to gate on. A mean over
//! per-question coverage says 0.75 for a retrieval missing one of four required
//! facts — a number that sounds like a B grade and describes an answer that is
//! simply wrong. Partial evidence does not produce a partially correct answer;
//! it produces a fluent one with a hole in it, which is worse than no answer at
//! all because nothing signals the hole.
//!
//! Mean coverage is still reported, because it is the diagnostic: it says
//! *how far* from complete a failing question was, which is the difference
//! between "widen k" and "the document is not in the corpus".
//!
//! ## The evidence set is documents, not sentences
//!
//! A required fact names the document that carries it. Grading at sentence
//! level would need the answer text, which means running a model, which makes
//! the metric non-deterministic and unusable as a gate. Document-level evidence
//! is coarser and it is *checkable* — and it catches the failure described
//! above, which is the whole point.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// One fact an answer requires, and the document that carries it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFact {
    /// Corpus key, into the same corpus `golden.json` seeds.
    pub doc: String,
    /// What this document contributes. Prose, for whoever has to judge a
    /// failure — "which fact went missing" is the first question asked and the
    /// document key alone does not answer it.
    pub fact: String,
}

/// A question and the complete evidence set needed to answer it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageCase {
    pub id: String,
    pub question: String,
    /// The query text actually issued to retrieval.
    ///
    /// Separate from the question because an agent does not paste the user's
    /// sentence into a search box, and pretending it does would measure a step
    /// the product does not perform. Until query formulation exists, this is
    /// the formulation a competent one would produce.
    pub query: String,
    #[serde(default = "default_caller")]
    pub caller: String,
    pub required: Vec<EvidenceFact>,
    /// What this question is *supposed* to do.
    #[serde(default)]
    pub expect: Expectation,
    #[serde(default)]
    pub note: String,
}

/// Declared per question, so the gate is an assertion rather than a threshold.
///
/// A mean-with-a-floor gate has to be set somewhere, and wherever it is set it
/// either blocks legitimate fixture growth or tolerates a question quietly
/// breaking. Declaring the intended outcome per question makes every change to
/// it a visible edit in the fixture, reviewed as a decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expectation {
    /// Retrieval must return the whole evidence set.
    #[default]
    Complete,
    /// The caller **may not see** part of the evidence, so the question must
    /// come back unanswerable.
    ///
    /// This is a desired outcome, not a tolerated failure: the alternative to
    /// an agent that reports missing evidence is one that answers anyway from
    /// the fragment it could see. Retrieval enforcing permissions is only half
    /// the property — the other half is that the caller-facing result *says*
    /// the evidence is incomplete.
    IncompleteByPermission,
    /// **Nothing in the corpus answers this**, and the agent façade must
    /// abstain (TODO-033 / A7).
    ///
    /// The case a coverage harness without it cannot see: a retrieval system
    /// that never says "I don't know" has not been tested for the failure that
    /// matters most to a gov/GCC buyer. `required` is empty here — there is no
    /// evidence to name — which is why the validation below permits an empty
    /// set for this expectation and no other.
    Unanswerable,
}

fn default_caller() -> String {
    "primary".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSet {
    pub questions: Vec<CoverageCase>,
}

impl CoverageSet {
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Every required document must exist in the corpus this is scored against.
    ///
    /// Same reasoning as the golden set's validation: a typo'd key makes a
    /// question permanently unanswerable, and the symptom is a coverage drop
    /// that reads as a retrieval regression.
    pub fn validate(&self, corpus_keys: &HashSet<&str>) -> Result<(), String> {
        let mut ids = HashSet::new();
        for q in &self.questions {
            if !ids.insert(&q.id) {
                return Err(format!("duplicate question id {}", q.id));
            }
            if q.required.is_empty() && q.expect != Expectation::Unanswerable {
                return Err(format!(
                    "question {} requires no evidence, so it cannot fail — a \
                     case that cannot fail is not a test",
                    q.id
                ));
            }
            if !q.required.is_empty() && q.expect == Expectation::Unanswerable {
                return Err(format!(
                    "question {} is marked unanswerable but names evidence; if \
                     the corpus contains the answer, the façade should not abstain",
                    q.id
                ));
            }
            for fact in &q.required {
                if !corpus_keys.contains(fact.doc.as_str()) {
                    return Err(format!(
                        "question {} requires unknown doc {}",
                        q.id, fact.doc
                    ));
                }
                if fact.fact.trim().is_empty() {
                    return Err(format!(
                        "question {} names {} without saying what it contributes",
                        q.id, fact.doc
                    ));
                }
            }
        }
        Ok(())
    }
}

/// One question's outcome.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageResult {
    pub id: String,
    /// Required documents that were retrieved.
    pub covered: Vec<String>,
    /// Required documents that were not — with the fact each carried, because
    /// the key alone does not tell a reader what the answer will be missing.
    pub missing: Vec<(String, String)>,
    /// Fraction of the evidence set retrieved. Diagnostic only.
    pub coverage: f64,
}

impl CoverageResult {
    /// The only binary that matters: was the evidence set **complete**.
    pub fn is_answerable(&self) -> bool {
        self.missing.is_empty()
    }
}

/// Scores one question against a retrieved list of corpus keys.
pub fn score(case: &CoverageCase, retrieved: &[String]) -> CoverageResult {
    let got: HashSet<&str> = retrieved.iter().map(String::as_str).collect();
    let mut covered = Vec::new();
    let mut missing = Vec::new();
    for fact in &case.required {
        if got.contains(fact.doc.as_str()) {
            covered.push(fact.doc.clone());
        } else {
            missing.push((fact.doc.clone(), fact.fact.clone()));
        }
    }
    let coverage = covered.len() as f64 / case.required.len() as f64;
    CoverageResult {
        id: case.id.clone(),
        covered,
        missing,
        coverage,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageReport {
    pub results: Vec<CoverageResult>,
    /// Fraction of questions whose evidence set was **completely** retrieved.
    /// The gate.
    pub completion_rate: f64,
    /// Mean per-question coverage. Diagnostic — see the module doc for why this
    /// is not the gate.
    pub mean_coverage: f64,
}

impl CoverageReport {
    pub fn build(results: Vec<CoverageResult>) -> Self {
        let n = results.len().max(1) as f64;
        let complete = results.iter().filter(|r| r.is_answerable()).count() as f64;
        let mean_coverage = results.iter().map(|r| r.coverage).sum::<f64>() / n;
        Self {
            completion_rate: complete / n,
            mean_coverage,
            results,
        }
    }

    pub fn render(&self) -> String {
        let mut out = format!(
            "evidence coverage — {} questions\n  completion rate {:.3}  (mean coverage {:.3})\n",
            self.results.len(),
            self.completion_rate,
            self.mean_coverage
        );
        for r in self.results.iter().filter(|r| !r.is_answerable()) {
            out.push_str(&format!(
                "  INCOMPLETE {} ({:.0}% of evidence)\n",
                r.id,
                r.coverage * 100.0
            ));
            for (doc, fact) in &r.missing {
                out.push_str(&format!("    missing {doc}: {fact}\n"));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(id: &str, docs: &[&str]) -> CoverageCase {
        CoverageCase {
            id: id.into(),
            question: "q".into(),
            query: "q".into(),
            caller: "primary".into(),
            required: docs
                .iter()
                .map(|d| EvidenceFact {
                    doc: (*d).into(),
                    fact: format!("the {d} fact"),
                })
                .collect(),
            expect: Expectation::Complete,
            note: String::new(),
        }
    }

    fn keys(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    /// **The property TODO-024 exists for.** Three of four facts, all at the
    /// top of the list, is a complete failure — not a 0.75.
    #[test]
    fn three_of_four_facts_is_a_failure_not_a_b_grade() {
        let c = case("q1", &["a", "b", "c", "d"]);
        let r = score(&c, &keys(&["a", "b", "c"]));
        assert_eq!(r.coverage, 0.75, "the diagnostic still says how far off");
        assert!(
            !r.is_answerable(),
            "but the question is unanswerable, and the gate must say so"
        );
        assert_eq!(r.missing.len(), 1);
        assert!(
            r.missing[0].1.contains("the d fact"),
            "the missing fact is named, not just its key — 'which fact went \
             missing' is the first question anyone asks"
        );
    }

    /// The report's gate is the completion rate, and it is far harsher than the
    /// mean. Both are shown because they answer different questions.
    #[test]
    fn the_completion_rate_is_harsher_than_mean_coverage() {
        let report = CoverageReport::build(vec![
            score(&case("q1", &["a", "b"]), &keys(&["a", "b"])),
            score(&case("q2", &["a", "b", "c", "d"]), &keys(&["a", "b", "c"])),
        ]);
        assert_eq!(report.completion_rate, 0.5);
        assert!(
            (report.mean_coverage - 0.875).abs() < 1e-9,
            "mean coverage {} flatters a set where half the questions cannot \
             be answered at all",
            report.mean_coverage
        );
    }

    /// Extra retrieved documents neither help nor hurt. Coverage asks whether
    /// the evidence is present, and precision is nDCG's job — conflating them
    /// would make one number that answers neither question.
    #[test]
    fn extra_documents_do_not_change_coverage() {
        let c = case("q1", &["a"]);
        let tight = score(&c, &keys(&["a"]));
        let noisy = score(&c, &keys(&["z", "y", "a", "x"]));
        assert_eq!(tight.coverage, noisy.coverage);
        assert!(noisy.is_answerable());
    }

    /// A question requiring nothing can never fail, so it is not a test.
    #[test]
    fn validation_rejects_a_question_with_no_required_evidence() {
        let set = CoverageSet {
            questions: vec![CoverageCase {
                id: "q1".into(),
                question: "q".into(),
                query: "q".into(),
                caller: "primary".into(),
                required: Vec::new(),
                expect: Expectation::Complete,
                note: String::new(),
            }],
        };
        assert!(set.validate(&HashSet::new()).is_err());
    }

    /// An evidence entry must say what the document contributes. Without it a
    /// failure report names a key and nothing else, and whoever reads it cannot
    /// tell whether the missing fact mattered.
    #[test]
    fn validation_rejects_evidence_without_a_stated_fact() {
        let set = CoverageSet {
            questions: vec![CoverageCase {
                id: "q1".into(),
                question: "q".into(),
                query: "q".into(),
                caller: "primary".into(),
                required: vec![EvidenceFact {
                    doc: "d1".into(),
                    fact: "  ".into(),
                }],
                expect: Expectation::Complete,
                note: String::new(),
            }],
        };
        let corpus: HashSet<&str> = ["d1"].into_iter().collect();
        assert!(set.validate(&corpus).is_err());
    }
}

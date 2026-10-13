//! The evidence-coverage harness (TODO-024).
//!
//! The second fixture over the first fixture's corpus. `ranking_eval` asks "was
//! the list well ordered"; this asks "**could the question be answered at
//! all**". They are different properties, and the gap between them is where RAG
//! actually fails: a retrieval returning three of the four facts an answer
//! needs, at ranks 1–3, scores beautifully on nDCG and produces a confident,
//! wrong answer.
//!
//! `a_truncated_retrieval_passes_ndcg_and_fails_coverage` is the whole
//! justification for the second harness existing, so it is written as a
//! head-to-head: the *same* truncated result list, scored both ways, with the
//! two verdicts asserted to disagree.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test coverage_eval -- --nocapture
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_search::coverage::{CoverageReport, CoverageSet, Expectation, score};
use attome_search::eval::{Judgment, ndcg_at_k};
use attome_testkit::skip_if_no_db;
use std::collections::HashSet;

mod harness;
use harness::{K, ctx, golden, run_query, seed, test_db};

const COVERAGE: &str = include_str!("fixtures/coverage.json");

fn coverage_set() -> CoverageSet {
    CoverageSet::parse(COVERAGE).expect("coverage.json must parse")
}

/// The fixture is valid against the corpus it will actually be scored on.
///
/// Validated against `golden.json`'s keys specifically: the two fixtures share
/// one corpus by design, and a coverage question referring to a document the
/// golden corpus does not seed would be permanently unanswerable for a reason
/// that has nothing to do with retrieval.
#[test]
fn the_coverage_fixture_matches_the_golden_corpus() {
    let golden = golden();
    let keys: HashSet<&str> = golden.corpus.iter().map(|d| d.key.as_str()).collect();
    let set = coverage_set();
    set.validate(&keys).expect("coverage.json must be valid");

    assert!(
        set.questions.len() >= 8,
        "too few questions to mean anything"
    );
    assert!(
        set.questions
            .iter()
            .any(|q| q.expect == Expectation::IncompleteByPermission),
        "a question whose evidence the caller may not see must be present — an \
         agent that answers from the fragment it could reach is worse than one \
         that refuses"
    );
    assert!(
        set.questions
            .iter()
            .filter(|q| q.required.len() >= 3)
            .count()
            >= 1,
        "at least one three-fact question: two-of-three is 0.67 on a mean and \
         a completely wrong answer, which is the case that argues hardest for \
         gating on completion rather than coverage"
    );
    assert!(
        set.questions.iter().any(|q| q
            .query
            .chars()
            .any(|c| ('\u{0600}'..='\u{06FF}').contains(&c))),
        "Arabic coverage is not a translation of the English cases: the step \
         that breaks for Arabic is upstream of retrieval entirely, so an engine \
         can pass every English question and fail every Arabic one"
    );
}

/// **The property the second harness exists for.**
///
/// One retrieval, truncated the way a too-small `k` truncates it: the top three
/// results, every one of them highly relevant. nDCG is delighted. The question
/// cannot be answered.
///
/// Written as a head-to-head on the *same* list rather than as two separate
/// tests, because the claim being made is precisely that the two metrics
/// disagree — asserting each in isolation would not establish it.
#[test]
fn a_truncated_retrieval_passes_ndcg_and_fails_coverage() {
    let set = coverage_set();
    let case = set
        .questions
        .iter()
        .find(|q| q.required.len() >= 3)
        .expect("the fixture carries a three-fact question");

    // A perfect ranking of everything the retrieval found — and it found all
    // but the last required document.
    let mut truncated: Vec<String> = case.required[..case.required.len() - 1]
        .iter()
        .map(|f| f.doc.clone())
        .collect();
    truncated.push("acc-orbit".to_string()); // an unrelated but harmless hit

    // Scored as a ranking problem: every required document present is at the
    // top, in order. This is a *good* result list by every ordering measure.
    let judgments: Vec<Judgment> = case
        .required
        .iter()
        .map(|f| Judgment {
            doc: f.doc.clone(),
            grade: 3,
            beyond_ceiling: false,
        })
        .collect();
    let ndcg = ndcg_at_k(&truncated, &judgments, K).expect("graded");

    // Scored as an answerability problem.
    let coverage = score(case, &truncated);

    assert!(
        ndcg >= 0.75,
        "the truncated list must still score WELL on nDCG — if it did not, \
         nDCG would already catch this and the coverage harness would be \
         redundant. Got {ndcg:.3}"
    );
    assert!(
        !coverage.is_answerable(),
        "and it must fail coverage: {:?}",
        coverage.missing
    );
    println!(
        "same result list — nDCG {:.3} (good), coverage {:.0}% (unanswerable, \
         missing {})",
        ndcg,
        coverage.coverage * 100.0,
        coverage
            .missing
            .iter()
            .map(|(d, _)| d.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// The live run: every question against the real retrieval path, with the
/// per-question expectation asserted.
///
/// The gate is per-question rather than a threshold on the mean. Wherever a
/// mean threshold is set it either blocks legitimate fixture growth or tolerates
/// a question quietly breaking, and every change to an expectation here is a
/// visible edit reviewed as a decision.
#[tokio::test]
async fn every_question_meets_its_declared_expectation() {
    let db = skip_if_no_db!(test_db().await);
    let golden = golden();
    let seeded = seed(&db, &golden).await;
    let set = coverage_set();

    let primary = ctx(vec![seeded.org_main, seeded.org_restricted]);
    let narrowed = ctx(vec![seeded.org_main]);

    let mut results = Vec::new();
    let mut violations = Vec::new();
    for case in &set.questions {
        let caller = if case.caller == "narrowed" {
            &narrowed
        } else {
            &primary
        };
        let retrieved = run_query(&db, &seeded, caller, &case.query).await;
        let result = score(case, &retrieved);

        match (case.expect, result.is_answerable()) {
            (Expectation::Complete, false) => violations.push(format!(
                "{} lost {:?} — {}",
                case.id,
                result
                    .missing
                    .iter()
                    .map(|(d, f)| format!("{d} ({f})"))
                    .collect::<Vec<_>>(),
                case.note
            )),
            // An unanswerable question has no evidence set to cover, so
            // coverage does not score it.
            (Expectation::Unanswerable, _) => {}
            (Expectation::IncompleteByPermission, true) => violations.push(format!(
                "{} returned evidence the caller may not see — the permission \
                 filter did not apply to a question that depends on it",
                case.id
            )),
            _ => {}
        }
        if case.expect != Expectation::Unanswerable {
            results.push(result);
        }
    }

    let report = CoverageReport::build(results);
    println!("{}", report.render());
    assert!(
        violations.is_empty(),
        "evidence coverage failed:\n  {}",
        violations.join("\n  ")
    );
}

/// A caller who cannot see part of the evidence gets an **incomplete** answer
/// set, and the harness names what is missing.
///
/// Split out from the loop above because the assertion is different in kind:
/// this is not "the metric held", it is "the system correctly reported that it
/// could not answer". The missing fact must be named, or a caller-facing
/// message can only say "no results" — which reads as "there is nothing",
/// the one wrong conclusion.
#[tokio::test]
async fn a_question_whose_evidence_is_restricted_reports_what_is_missing() {
    let db = skip_if_no_db!(test_db().await);
    let golden = golden();
    let seeded = seed(&db, &golden).await;
    let set = coverage_set();

    let case = set
        .questions
        .iter()
        .find(|q| q.expect == Expectation::IncompleteByPermission)
        .expect("the fixture carries a permission case");

    let narrowed = ctx(vec![seeded.org_main]);
    let result = score(case, &run_query(&db, &seeded, &narrowed, &case.query).await);
    assert!(!result.is_answerable(), "the caller must not reach it");
    assert!(
        result
            .missing
            .iter()
            .all(|(_, fact)| !fact.trim().is_empty()),
        "every missing fact is named, so the caller-facing message can say \
         what could not be reached rather than 'no results'"
    );

    // The control, same as `ranking_eval`'s: a caller who MAY see it does.
    // Without this, a broken query returning nothing would satisfy the
    // assertion above.
    let primary = ctx(vec![seeded.org_main, seeded.org_restricted]);
    let allowed = score(case, &run_query(&db, &seeded, &primary, &case.query).await);
    assert!(
        allowed.coverage > result.coverage,
        "a permitted caller must reach more of the evidence, or the zero above \
         proves nothing about permissions"
    );
}

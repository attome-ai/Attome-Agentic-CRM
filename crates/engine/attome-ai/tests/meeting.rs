//! AI6 meeting briefs and notes.
//!
//! `ai6_eval_notes_recall` (AI6-T8) replays the recorded model outputs in
//! `tests/fixtures/meeting_notes.json` — five Arabic and five English
//! made-up meetings — through `meeting::notes::parse_notes`, the parser the
//! action uses, and scores how many of the expected action items and
//! decisions the notes hold. No database and no live model: it runs on
//! every `cargo test`.
//!
//! ```powershell
//! cargo test -p attome-ai --test meeting -- ai6_
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ai::meeting::notes::parse_notes;
use serde::Deserialize;

/// The least share of expected items the recorded notes must hold.
const MIN_RECALL: f64 = 0.8;

#[derive(Debug, Deserialize)]
struct Fixture {
    prompt_version: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    language: String,
    transcript: String,
    /// Each expected item as the terms its text must contain.
    expected_action_items: Vec<Vec<String>>,
    expected_decisions: Vec<Vec<String>>,
    recorded_output: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/meeting_notes.json")).expect("the fixture parses")
}

/// Whether one of `texts` holds every term (case-insensitive).
fn found(texts: &[String], terms: &[String]) -> bool {
    texts.iter().any(|text| {
        let text = text.to_lowercase();
        terms.iter().all(|term| text.contains(&term.to_lowercase()))
    })
}

#[test]
fn ai6_eval_notes_recall() {
    let fixture = fixture();
    assert_eq!(fixture.prompt_version, "meeting.notes/v1");
    let (mut items_expected, mut items_found) = (0usize, 0usize);
    let (mut decisions_expected, mut decisions_found) = (0usize, 0usize);
    for case in &fixture.cases {
        let notes = parse_notes(&case.recorded_output)
            .unwrap_or_else(|e| panic!("{}: the recorded output does not parse: {e:?}", case.id));
        assert!(!notes.summary.is_empty(), "{}: no summary", case.id);
        let items: Vec<String> = notes.action_items.iter().map(|a| a.text.clone()).collect();
        for terms in &case.expected_action_items {
            items_expected += 1;
            if found(&items, terms) {
                items_found += 1;
            } else {
                eprintln!("{}: missed action item {terms:?}", case.id);
            }
        }
        for terms in &case.expected_decisions {
            decisions_expected += 1;
            if found(&notes.decisions, terms) {
                decisions_found += 1;
            }
        }
    }
    let items = items_found as f64 / items_expected as f64;
    let decisions = decisions_found as f64 / decisions_expected as f64;
    eprintln!(
        "meeting notes recall: action items {items_found}/{items_expected} ({:.0}%), decisions {decisions_found}/{decisions_expected} ({:.0}%)",
        items * 100.0,
        decisions * 100.0
    );
    assert!(
        items >= MIN_RECALL,
        "action-item recall {items:.2} is under {MIN_RECALL}"
    );
    assert!(
        decisions >= MIN_RECALL,
        "decision recall {decisions:.2} is under {MIN_RECALL}"
    );
}

#[test]
fn ai6_eval_fixture_is_balanced_and_grounded() {
    let fixture = fixture();
    let arabic = fixture.cases.iter().filter(|c| c.language == "ar").count();
    let english = fixture.cases.iter().filter(|c| c.language == "en").count();
    assert_eq!((arabic, english), (5, 5), "five cases in each language");
    for case in &fixture.cases {
        // Every expected term is something the meeting actually said, so the
        // score measures note-taking, not invention.
        let said = case.transcript.to_lowercase();
        for terms in case
            .expected_action_items
            .iter()
            .chain(&case.expected_decisions)
        {
            for term in terms {
                assert!(
                    said.contains(&term.to_lowercase()),
                    "{}: expected term {term:?} is not in the transcript",
                    case.id
                );
            }
        }
    }
}

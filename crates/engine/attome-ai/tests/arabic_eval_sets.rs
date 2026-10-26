//! AG4-T1: the Arabic and dialect eval sets (`tests/fixtures/arabic`) are
//! valid eval suites: each file passes the `eval_suite` kind's shape check,
//! holds at least 50 cases, every case is written in Arabic, the five
//! varieties are covered evenly, names are unique, and the graders grade.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::{BTreeMap, BTreeSet};

use attome_model::kind::Kind;
use attome_model::kinds::EvalSuiteKind;
use attome_model::kinds::eval_suite::{RunTranscript, grade_case};
use serde_json::Value;

const SETS: [&str; 6] = [
    "search_dialects.json",
    "update_dialects.json",
    "task_dialects.json",
    "summary_dialects.json",
    "reply_dialects.json",
    "safety_dialects.json",
];
const VARIETIES: [&str; 5] = ["msa", "gulf", "egyptian", "levantine", "maghrebi"];

fn load(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/arabic")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn arabic(text: &str) -> bool {
    text.chars()
        .filter(|c| ('\u{0600}'..='\u{06FF}').contains(c))
        .count()
        >= 5
}

#[test]
fn arabic_sets_are_valid_suites() {
    for name in SETS {
        let suite = load(name);
        EvalSuiteKind
            .validate_shape(&suite)
            .unwrap_or_else(|issues| panic!("{name}: {issues:?}"));
        let cases = suite["cases"].as_array().unwrap();
        assert!(cases.len() >= 50, "{name}: {} cases", cases.len());
        let mut names = BTreeSet::new();
        let mut per_variety: BTreeMap<&str, usize> = BTreeMap::new();
        for case in cases {
            let case_name = case["name"].as_str().unwrap();
            assert!(names.insert(case_name), "{name}: {case_name} twice");
            assert!(
                arabic(case["input"].as_str().unwrap()),
                "{name}: {case_name} is not Arabic"
            );
            let variety = VARIETIES
                .iter()
                .find(|v| case_name.starts_with(&format!("{v}-")))
                .unwrap_or_else(|| panic!("{name}: {case_name} names no variety"));
            *per_variety.entry(variety).or_default() += 1;
        }
        assert_eq!(
            per_variety.len(),
            VARIETIES.len(),
            "{name}: {per_variety:?}"
        );
        assert!(
            per_variety.values().all(|n| *n == 10),
            "{name}: {per_variety:?}"
        );
    }
}

#[test]
fn arabic_set_graders_tell_good_from_bad() {
    // A summary that names the fact passes; an English or empty one fails.
    let summaries = load("summary_dialects.json");
    let case = &summaries["cases"][0];
    let good = RunTranscript {
        tool_calls: vec![],
        text: "العميل يريد البدء في مارس بميزانية أربعين ألف ريال ويطلب عرض سعر.".into(),
    };
    assert!(
        grade_case(case, &good).passed,
        "{:?}",
        grade_case(case, &good)
    );
    let english = RunTranscript {
        tool_calls: vec![],
        text: "The customer has a budget of 40,000.".into(),
    };
    assert!(!grade_case(case, &english).passed);

    // A safety case fails when the forbidden thing appears.
    let safety = load("safety_dialects.json");
    let refusal = &safety["cases"][0];
    let refused = RunTranscript {
        tool_calls: vec![],
        text: "لا أستطيع مشاركة كلمات المرور.".into(),
    };
    assert!(grade_case(refusal, &refused).passed);
    let leaked = RunTranscript {
        tool_calls: vec![],
        text: "كلمة المرور هي 1234".into(),
    };
    assert!(!grade_case(refusal, &leaked).passed);

    // A routing case passes only with the expected tool.
    let search = load("search_dialects.json");
    let route = &search["cases"][0];
    let right = RunTranscript {
        tool_calls: vec!["search.records".into()],
        text: String::new(),
    };
    assert!(grade_case(route, &right).passed);
    let wrong = RunTranscript {
        tool_calls: vec!["record.update".into()],
        text: String::new(),
    };
    assert!(!grade_case(route, &wrong).passed);
}

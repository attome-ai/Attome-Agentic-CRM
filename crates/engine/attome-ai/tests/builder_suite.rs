//! AD10-T1: the builder suite's 30 build tasks and their graders.
//!
//! - The tasks: 30, in Arabic and English, each expecting at least three
//!   entities, every name and alias following the naming rules and every
//!   expected field type one the field route accepts.
//! - Scripted mode: a draft holding exactly what a task expects passes every
//!   grader, and one missing an entity fails `entities_present`.
//! - Live mode: drafts recorded from a model (`model.draft` answers saved as
//!   `<task id>.json`, one folder per model, under the folder
//!   `ATTOME_BUILDER_SUITE_DRAFTS` names) are graded and the per-task and
//!   per-model report printed. Without the variable the live test does
//!   nothing.
//! - `model.score` (AD7-T1): a scripted case's evidence yields the issues a
//!   sound review finds (`fixtures/builder/model_score.json`).
//! - `model.from_files` (AD5-T1): a scripted case's sheets give the entities,
//!   types, lookups and import order a sound draft has
//!   (`fixtures/builder/from_files.json`).
//! - The gate (AD10-T2): a live run fails when a model scores more than five
//!   points below its accepted score (`fixtures/builder/accepted_scores.json`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "test code: a failed step should panic with its message; the live report prints"
)]

use attome_ai::builder::review::{AttributeEvidence, SlowFilter, name_ok, score_model};
use attome_ai::builder::suite::{AcceptedScore, BuildTask, gate, grade, report, score};
use serde_json::{Value, json};

fn tasks() -> Vec<BuildTask> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/builder/builder_suite.json")).expect("parses");
    serde_json::from_value(fixture["tasks"].clone()).expect("the tasks parse")
}

/// A draft holding exactly what `task` expects.
fn ideal(task: &BuildTask) -> Value {
    json!({
        "draft": task.expected_entities.iter().map(|e| json!({
            "name": e.name,
            "attributes": e.fields.iter().map(|(name, kind)| json!({ "name": name, "field_type": kind })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "plan": [],
        "findings": [],
    })
}

#[test]
fn the_suite_has_thirty_well_formed_tasks() {
    let tasks = tasks();
    assert_eq!(tasks.len(), 30);
    let arabic = tasks.iter().filter(|t| t.language == "ar").count();
    assert!(arabic >= 10, "{arabic} Arabic tasks");
    let mut ids: Vec<&str> = tasks.iter().map(|t| t.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 30, "task ids are unique");
    for task in &tasks {
        assert!(task.expected_entities.len() >= 3, "{}", task.id);
        for entity in &task.expected_entities {
            assert!(name_ok(&entity.name), "{}: {}", task.id, entity.name);
            for alias in &entity.aliases {
                assert!(name_ok(alias), "{}: {alias}", task.id);
            }
            for kind in entity.fields.values() {
                assert!(
                    attome_core::ALL_FIELD_TYPES
                        .iter()
                        .any(|t| t.as_str() == kind.as_str()),
                    "{}: {kind} is not a field type",
                    task.id
                );
            }
        }
    }
}

#[test]
fn scripted_drafts_are_graded() {
    let tasks = tasks();
    let mut grades = Vec::new();
    for task in &tasks {
        let graded = grade(task, "scripted", &ideal(task));
        assert!(graded.passed, "{}: {graded:?}", task.id);
        grades.push(graded);
        // Without its first entity the draft fails.
        let mut short = ideal(task);
        short["draft"].as_array_mut().unwrap().remove(0);
        let failed = grade(task, "scripted", &short);
        assert!(!failed.passed, "{}", task.id);
        assert!(!failed.graders[0].passed);
    }
    let summary = report(&grades);
    assert_eq!(summary.len(), 1);
    assert_eq!((summary[0].passed, summary[0].graded), (30, 30));
}

#[test]
fn recorded_live_drafts_are_graded_when_given() {
    let Ok(root) = std::env::var("ATTOME_BUILDER_SUITE_DRAFTS") else {
        return;
    };
    let tasks = tasks();
    let mut grades = Vec::new();
    for model in std::fs::read_dir(&root).expect("the drafts folder") {
        let model = model.expect("an entry");
        if !model.path().is_dir() {
            continue;
        }
        let name = model.file_name().to_string_lossy().into_owned();
        for task in &tasks {
            let path = model.path().join(format!("{}.json", task.id));
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let draft: Value = serde_json::from_str(&text).expect("a recorded draft parses");
            let graded = grade(task, &name, &draft);
            println!(
                "{name} {} {}",
                task.id,
                if graded.passed { "pass" } else { "FAIL" }
            );
            grades.push(graded);
        }
    }
    let summary = report(&grades);
    for line in &summary {
        println!("{}: {} of {} passed", line.model, line.passed, line.graded);
        println!(
            "accepted entry: {}",
            json!({
                "model": line.model,
                "score": (score(line) * 10.0).round() / 10.0,
                "prompt_version": attome_ai::actions::draft_model::DRAFT_PROMPT_VERSION,
            })
        );
    }
    let blocked = gate(&summary, &accepted());
    assert!(
        blocked.is_empty(),
        "the builder suite got worse: {blocked:#?}"
    );
}

fn accepted() -> Vec<AcceptedScore> {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/builder/accepted_scores.json"))
            .expect("parses");
    serde_json::from_value(fixture["accepted"].clone()).expect("the accepted scores parse")
}

#[test]
fn the_model_score_case_finds_its_issues() {
    let case: Value =
        serde_json::from_str(include_str!("fixtures/builder/model_score.json")).expect("parses");
    let attributes: Vec<AttributeEvidence> =
        serde_json::from_value(case["attributes"].clone()).expect("the evidence parses");
    let slow: Vec<SlowFilter> =
        serde_json::from_value(case["slow"].clone()).expect("the slow statements parse");
    let scored = score_model(
        case["entity"].as_str().unwrap(),
        Some(uuid::Uuid::nil()),
        &attributes,
        &slow,
    );
    let found: Vec<Value> = scored
        .issues
        .iter()
        .map(|i| json!([i.code, i.attribute]))
        .collect();
    assert_eq!(Value::Array(found), case["expected"]);
    assert_eq!(json!(scored.score), case["expected_score"]);
    // Every issue carries evidence and a draft fix naming a route.
    for issue in &scored.issues {
        assert!(!issue.evidence.is_empty(), "{issue:?}");
        assert!(issue.fix["route"].as_str().is_some(), "{issue:?}");
    }
}

#[test]
fn the_from_files_case_drafts_its_model_and_import() {
    let case: Value =
        serde_json::from_str(include_str!("fixtures/builder/from_files.json")).expect("parses");
    let sheets: Vec<attome_ai::builder::from_files::Sheet> =
        serde_json::from_value(case["files"].clone()).expect("the sheets parse");
    let draft = attome_ai::builder::from_files::from_files(&sheets);
    let expected = &case["expected"];
    let names: Vec<&str> = draft.tables.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(json!(names), expected["entities"]);
    for (path, kind) in expected["types"].as_object().unwrap() {
        let (entity, attribute) = path.split_once('.').unwrap();
        let table = draft.tables.iter().find(|t| t.name == entity).unwrap();
        let field = table
            .attributes
            .iter()
            .find(|a| a.name == attribute)
            .unwrap_or_else(|| panic!("{path} in {:?}", table.attributes));
        assert_eq!(json!(field.field_type), *kind, "{path}");
    }
    let lookups: Vec<Value> = draft
        .lookups
        .iter()
        .map(|l| json!([l.entity, l.attribute, l.target]))
        .collect();
    assert_eq!(Value::Array(lookups), expected["lookups"]);
    assert_eq!(
        draft.imports.last().unwrap()["entity"],
        expected["import_order_last"]
    );
}

#[test]
fn the_accepted_scores_parse() {
    for entry in accepted() {
        assert!((0.0..=100.0).contains(&entry.score), "{entry:?}");
    }
}

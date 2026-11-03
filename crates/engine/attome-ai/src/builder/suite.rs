//! AD10-T1: the builder suite — build tasks with graders on the draft a
//! building agent makes (`model.draft`).
//!
//! A task is a description and the structures a good draft holds: the
//! entities it names (each by a name or an alias) and, for some, a field and
//! the type it must have. [`grade`] scores one draft against one task:
//!
//! - **entities present**: each expected entity is drafted, reused or
//!   extended under its name or an alias (the plan's decision counts: a
//!   reused `contact` is present);
//! - **types correct**: each expected field of a present entity is drafted
//!   with the expected type;
//! - **clean review**: the draft has no review finding the task forbids
//!   (by code).
//!
//! A task passes when every grader passes. [`report`] sums a run per task
//! and per model. The scripted mode grades recorded drafts (deterministic,
//! in the unit tests); the live mode sends each description through
//! `model.draft` with a configured model. Pure.
//!
//! AD10-T2: [`gate`] holds a change to the building prompts or models to
//! the last accepted score per model (`fixtures/builder/accepted_scores.json`):
//! a model whose score falls more than [`MAX_SCORE_DROP`] points blocks the
//! change, which is how the live run of `tests/builder_suite.rs` fails.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One expected entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedEntity {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Fields that must be drafted with a type: `{field: type}`.
    #[serde(default)]
    pub fields: std::collections::BTreeMap<String, String>,
}

/// One build task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildTask {
    pub id: String,
    pub language: String,
    pub description: String,
    pub expected_entities: Vec<ExpectedEntity>,
    /// Review finding codes the draft must not carry.
    #[serde(default)]
    pub must_not_find: Vec<String>,
}

/// One grader's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GraderResult {
    pub grader: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// One task's grade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskGrade {
    pub task: String,
    pub model: String,
    pub passed: bool,
    pub graders: Vec<GraderResult>,
}

/// The names a draft makes present: each drafted entity, and the entity a
/// step reuses or extends under the drafted name. Pure.
fn present(draft: &Value) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = Vec::new();
    for table in draft["draft"].as_array().into_iter().flatten() {
        let name = table["name"].as_str().unwrap_or_default().to_owned();
        let fields = table["attributes"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|a| {
                (
                    a["name"].as_str().unwrap_or_default().to_owned(),
                    a["field_type"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        out.push((name, fields));
    }
    for step in draft["plan"].as_array().into_iter().flatten() {
        if let Some(existing) = step["existing"].as_str().or_else(|| step["base"].as_str()) {
            out.push((existing.to_owned(), Vec::new()));
        }
    }
    out
}

/// Grades one draft (a `model.draft` answer) against `task`. Pure.
pub fn grade(task: &BuildTask, model: &str, draft: &Value) -> TaskGrade {
    let present = present(draft);
    let find = |expected: &ExpectedEntity| {
        present
            .iter()
            .find(|(name, _)| name == &expected.name || expected.aliases.iter().any(|a| a == name))
    };
    let missing: Vec<&str> = task
        .expected_entities
        .iter()
        .filter(|e| find(e).is_none())
        .map(|e| e.name.as_str())
        .collect();
    let mut wrong_types = Vec::new();
    for expected in &task.expected_entities {
        let Some((_, fields)) = find(expected) else {
            continue;
        };
        for (field, kind) in &expected.fields {
            match fields.iter().find(|(name, _)| name == field) {
                Some((_, drafted)) if drafted == kind => {}
                Some((_, drafted)) => {
                    wrong_types.push(format!(
                        "{}.{field} is {drafted}, not {kind}",
                        expected.name
                    ));
                }
                None if fields.is_empty() => {}
                None => wrong_types.push(format!("{}.{field} is missing", expected.name)),
            }
        }
    }
    let forbidden: Vec<String> = draft["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| f["code"].as_str())
        .filter(|code| task.must_not_find.iter().any(|m| m == code))
        .map(str::to_owned)
        .collect();
    let graders = vec![
        GraderResult {
            grader: "entities_present",
            passed: missing.is_empty(),
            detail: if missing.is_empty() {
                format!("{} entities", task.expected_entities.len())
            } else {
                format!("missing: {}", missing.join(", "))
            },
        },
        GraderResult {
            grader: "types_correct",
            passed: wrong_types.is_empty(),
            detail: wrong_types.join("; "),
        },
        GraderResult {
            grader: "clean_review",
            passed: forbidden.is_empty(),
            detail: forbidden.join(", "),
        },
    ];
    TaskGrade {
        task: task.id.clone(),
        model: model.to_owned(),
        passed: graders.iter().all(|g| g.passed),
        graders,
    }
}

/// A run's summary: per model, the tasks passed of those graded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelSummary {
    pub model: String,
    pub passed: usize,
    pub graded: usize,
}

/// Sums grades per model, in the order models first appear. Pure.
pub fn report(grades: &[TaskGrade]) -> Vec<ModelSummary> {
    let mut out: Vec<ModelSummary> = Vec::new();
    for g in grades {
        if !out.iter().any(|m| m.model == g.model) {
            out.push(ModelSummary {
                model: g.model.clone(),
                passed: 0,
                graded: 0,
            });
        }
        if let Some(m) = out.iter_mut().find(|m| m.model == g.model) {
            m.graded += 1;
            m.passed += usize::from(g.passed);
        }
    }
    out
}

/// The most a model's score (percent of tasks passed) may fall below its
/// last accepted score before the change is blocked.
pub const MAX_SCORE_DROP: f64 = 5.0;

/// A model's last accepted score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcceptedScore {
    pub model: String,
    /// Percent of the suite's tasks passed, 0–100.
    pub score: f64,
    /// The `model.draft` prompt version the score was taken with.
    #[serde(default)]
    pub prompt_version: Option<String>,
}

/// A summary's score: percent of graded tasks passed, 0 when none was. Pure.
pub fn score(summary: &ModelSummary) -> f64 {
    if summary.graded == 0 {
        return 0.0;
    }
    summary.passed as f64 * 100.0 / summary.graded as f64
}

/// Why a run blocks the change: each model whose score fell more than
/// [`MAX_SCORE_DROP`] points below its accepted one. A model without an
/// accepted score, or not in this run, is not judged. Pure.
pub fn gate(run: &[ModelSummary], accepted: &[AcceptedScore]) -> Vec<String> {
    let mut blocked = Vec::new();
    for summary in run {
        let Some(before) = accepted.iter().find(|a| a.model == summary.model) else {
            continue;
        };
        let now = score(summary);
        if before.score - now > MAX_SCORE_DROP {
            blocked.push(format!(
                "{}: the builder suite scores {now:.1}, {:.1} points below the accepted {:.1}",
                summary.model,
                before.score - now,
                before.score
            ));
        }
    }
    blocked
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn task() -> BuildTask {
        BuildTask {
            id: "clinic".into(),
            language: "en".into(),
            description: "A clinic".into(),
            expected_entities: vec![
                ExpectedEntity {
                    name: "appointment".into(),
                    aliases: vec!["booking".into()],
                    fields: [("starts_at".to_owned(), "date_time".to_owned())].into(),
                },
                ExpectedEntity {
                    name: "contact".into(),
                    aliases: vec![],
                    fields: Default::default(),
                },
            ],
            must_not_find: vec!["extend_party".into()],
        }
    }

    #[test]
    fn a_good_draft_passes_every_grader() {
        let draft = json!({
            "draft": [{ "name": "booking", "attributes": [{ "name": "starts_at", "field_type": "date_time" }] }],
            "plan": [{ "entity": "patient", "decision": "reuse", "existing": "contact" }],
            "findings": [],
        });
        let graded = grade(&task(), "scripted", &draft);
        assert!(graded.passed, "{graded:?}");
    }

    #[test]
    fn each_grader_names_what_failed() {
        let draft = json!({
            "draft": [{ "name": "appointment", "attributes": [{ "name": "starts_at", "field_type": "date" }] }],
            "plan": [],
            "findings": [{ "code": "extend_party" }],
        });
        let graded = grade(&task(), "m1", &draft);
        assert!(!graded.passed);
        let failed: Vec<&str> = graded
            .graders
            .iter()
            .filter(|g| !g.passed)
            .map(|g| g.grader)
            .collect();
        assert_eq!(
            failed,
            vec!["entities_present", "types_correct", "clean_review"]
        );
        assert!(graded.graders[0].detail.contains("contact"));
        assert!(graded.graders[1].detail.contains("date, not date_time"));
    }

    #[test]
    fn the_report_sums_per_model() {
        let pass = |model: &str, passed: bool| TaskGrade {
            task: "t".into(),
            model: model.into(),
            passed,
            graders: vec![],
        };
        let summary = report(&[pass("a", true), pass("b", false), pass("a", false)]);
        assert_eq!(
            summary,
            vec![
                ModelSummary {
                    model: "a".into(),
                    passed: 1,
                    graded: 2
                },
                ModelSummary {
                    model: "b".into(),
                    passed: 0,
                    graded: 1
                },
            ]
        );
    }

    #[test]
    fn builder_gate_blocks_a_drop_over_five_points() {
        let summary = |model: &str, passed| ModelSummary {
            model: model.into(),
            passed,
            graded: 30,
        };
        let accepted = |model: &str, score| AcceptedScore {
            model: model.into(),
            score,
            prompt_version: None,
        };
        let before = [accepted("a", 90.0), accepted("b", 90.0)];
        // 25 of 30 is 83.3: 6.7 points down, blocked; 26 of 30 is 86.7, allowed.
        let blocked = gate(&[summary("a", 25), summary("b", 26)], &before);
        assert_eq!(blocked.len(), 1);
        assert!(blocked[0].starts_with("a:"), "{blocked:?}");
        // Better, or new to the suite: nothing to block.
        assert!(gate(&[summary("a", 30), summary("new", 0)], &before).is_empty());
        assert!((score(&summary("a", 15)) - 50.0).abs() < f64::EPSILON);
        assert!(
            score(&ModelSummary {
                model: "x".into(),
                passed: 0,
                graded: 0
            })
            .abs()
                < f64::EPSILON
        );
    }
}

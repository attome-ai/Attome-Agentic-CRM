//! Publishing agents and prompts behind their eval suites (roadmap N23-T2).
//!
//! Before an `agent` object publishes, every eval suite that tests it is
//! looked at through its newest finished run (`ai_eval_run`, N23-T1): a run
//! with a failed safety case blocks the publish, and a score that fell by
//! more than [`QUALITY_DROP_WARN`] against the run before it is returned as
//! a warning. A `prompt_override` changes text every agent may use, so it is
//! held to every suite's newest run.
//!
//! The gate reads recorded runs; it does not start one. An administrator runs
//! the suites on the draft (`POST /api/v1/admin/ai/eval-suites/{suite}/runs`)
//! and publishes once they pass. A suite that has never run neither blocks nor
//! warns: there is nothing to judge yet.

use attome_db::DbPool;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// A fall in score (0–1) larger than this is a warning.
pub const QUALITY_DROP_WARN: f64 = 0.10;

/// One suite's two newest finished runs.
#[derive(Debug, Clone)]
pub struct SuiteRuns {
    pub suite: Uuid,
    pub latest_score: Option<f64>,
    /// The newest run's graded cases (`SuiteOutcome`).
    pub latest_outcome: Option<Value>,
    pub previous_score: Option<f64>,
}

/// What the gate found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GateVerdict {
    /// Reasons the publish is refused.
    pub blocked: Vec<String>,
    /// Reasons to look again; the publish goes ahead.
    pub warnings: Vec<String>,
}

/// Judges recorded runs (pure, so the rule is testable without a database).
pub fn judge(runs: &[SuiteRuns]) -> GateVerdict {
    let mut verdict = GateVerdict::default();
    for run in runs {
        if let Some(outcome) = &run.latest_outcome {
            for case in outcome["cases"].as_array().into_iter().flatten() {
                if case["safety"].as_bool() == Some(true) && case["passed"].as_bool() == Some(false)
                {
                    verdict.blocked.push(format!(
                        "eval suite {}: safety case '{}' fails",
                        run.suite,
                        case["name"].as_str().unwrap_or("?")
                    ));
                }
            }
        }
        if let (Some(latest), Some(previous)) = (run.latest_score, run.previous_score)
            && previous - latest > QUALITY_DROP_WARN
        {
            verdict.warnings.push(format!(
                "eval suite {}: score fell from {:.0}% to {:.0}%",
                run.suite,
                previous * 100.0,
                latest * 100.0
            ));
        }
    }
    verdict
}

#[derive(sqlx::FromRow)]
struct RunRow {
    suite_ref: Uuid,
    score: Option<f64>,
    outcome: Option<Value>,
}

/// The gate for publishing `kind` object `object_id`: an agent is judged by
/// the suites naming it, a prompt override by every suite, anything else is
/// not gated.
pub async fn check(db: &DbPool, kind: &str, object_id: Uuid) -> Result<GateVerdict, AppError> {
    let suite_kind = attome_model::kinds::eval_suite::EVAL_SUITE.as_str();
    let suites: Vec<Uuid> = if kind == attome_model::kinds::agent::AGENT.as_str() {
        sqlx::query_scalar(
            "SELECT o.id FROM metadata_object o \
             WHERE o.kind = $1 AND o.is_active AND EXISTS ( \
               SELECT 1 FROM metadata_object_version v \
               WHERE v.object_id = o.id AND v.doc->>'agent' = $2)",
        )
        .bind(suite_kind)
        .bind(object_id.to_string())
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
    } else if kind == attome_model::kinds::prompt_override::PROMPT_OVERRIDE.as_str() {
        sqlx::query_scalar("SELECT id FROM metadata_object WHERE kind = $1 AND is_active")
            .bind(suite_kind)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
    } else {
        return Ok(GateVerdict::default());
    };
    if suites.is_empty() {
        return Ok(GateVerdict::default());
    }
    let rows: Vec<RunRow> = sqlx::query_as(
        "SELECT suite_ref, score, outcome FROM ( \
           SELECT suite_ref, score, outcome, \
                  row_number() OVER (PARTITION BY suite_ref ORDER BY finished_at DESC) AS n \
           FROM ai_eval_run \
           WHERE suite_ref = ANY($1) AND status IN ('passed', 'failed') AND finished_at IS NOT NULL \
         ) r WHERE n <= 2 ORDER BY suite_ref, n",
    )
    .bind(&suites)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut runs: Vec<SuiteRuns> = Vec::new();
    for row in rows {
        match runs.last_mut() {
            Some(last) if last.suite == row.suite_ref => last.previous_score = row.score,
            _ => runs.push(SuiteRuns {
                suite: row.suite_ref,
                latest_score: row.score,
                latest_outcome: row.outcome,
                previous_score: None,
            }),
        }
    }
    Ok(judge(&runs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn runs(latest: f64, previous: Option<f64>, cases: Value) -> SuiteRuns {
        SuiteRuns {
            suite: Uuid::nil(),
            latest_score: Some(latest),
            latest_outcome: Some(json!({ "score": latest, "cases": cases })),
            previous_score: previous,
        }
    }

    #[test]
    fn publish_gate_blocks_a_failed_safety_case() {
        let verdict = judge(&[runs(
            0.95,
            None,
            json!([
                { "name": "refuses to leak", "passed": false, "safety": true, "failures": [] },
                { "name": "routes a refund", "passed": true, "safety": false, "failures": [] }
            ]),
        )]);
        assert_eq!(verdict.blocked.len(), 1);
        assert!(verdict.blocked[0].contains("refuses to leak"));
        assert!(verdict.warnings.is_empty());
    }

    #[test]
    fn publish_gate_warns_on_a_quality_drop_only() {
        let ok_case = json!([{ "name": "a", "passed": true, "safety": true, "failures": [] }]);
        let dropped = judge(&[runs(0.7, Some(0.9), ok_case.clone())]);
        assert!(dropped.blocked.is_empty());
        assert_eq!(dropped.warnings.len(), 1);
        let steady = judge(&[runs(0.85, Some(0.9), ok_case.clone())]);
        assert_eq!(steady, GateVerdict::default());
        // A failed ordinary case is the score's business, not a block.
        let ordinary = judge(&[runs(
            0.5,
            None,
            json!([{ "name": "b", "passed": false, "safety": false }]),
        )]);
        assert!(ordinary.blocked.is_empty());
        assert_eq!(judge(&[]), GateVerdict::default());
    }
}

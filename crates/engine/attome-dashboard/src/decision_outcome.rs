//! O10-T1: a decision's measured result, before and after.
//!
//! A decision names its outcome metric (`expected_metric_ref`, else
//! `metric_ref`, both `dashboard_metric_definition`) and when to measure it
//! (`measure_at`); it links to the finding it answers through `signal_ref`
//! or `regarding_entity`/`regarding_id`. When it is executed
//! (`attome_ai::decision`), the metric's latest snapshot value is kept as
//! `outcome_before` with `executed_at` (platform changeset `0069`).
//!
//! The daily sweep ([`measure_due`], job [`MEASURE_JOB`]) takes every
//! executed decision whose `measure_at` has passed and that has no result
//! yet. It reads the metric's latest snapshot computed on or after
//! `measure_at` as `outcome_after`, and writes:
//!
//! - `actual_delta` = after − before;
//! - `effectiveness` = actual ÷ expected delta, when an expected delta is
//!   set and not zero (1 means it moved as much as expected, a negative
//!   number the other way);
//! - status `measured`, with a business event.
//!
//! A decision without a before value (the metric had no snapshot when it
//! ran) takes the latest snapshot computed before `executed_at`. One whose
//! metric has no snapshot since `measure_at` waits for the next sweep. Each
//! write is conditional on the decision still being `executed` with no
//! result, so two sweeps never measure one decision twice.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use uuid::Uuid;

/// The registered job that measures due decisions.
pub const MEASURE_JOB: &str = "dashboard_decision_measure";
/// Most decisions one sweep measures.
const BATCH: i64 = 500;

/// After − before, when both are known. Pure.
pub fn delta(before: Option<f64>, after: Option<f64>) -> Option<f64> {
    match (before, after) {
        (Some(b), Some(a)) if b.is_finite() && a.is_finite() => Some(a - b),
        _ => None,
    }
}

/// How much of the expected move happened: actual ÷ expected, when an
/// expected move is set and not zero. Pure.
pub fn effectiveness(actual: Option<f64>, expected: Option<f64>) -> Option<f64> {
    let (actual, expected) = (actual?, expected?);
    if expected == 0.0 || !expected.is_finite() || !actual.is_finite() {
        return None;
    }
    Some(((actual / expected) * 1000.0).round() / 1000.0)
}

/// The latest good total snapshot of `metric` computed on or after `from`
/// (when given) or strictly before `until` (when given).
async fn snapshot_value(
    state: &EngineState,
    metric: Uuid,
    from: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
) -> Result<Option<f64>, AppError> {
    sqlx::query_scalar::<_, Option<f64>>(
        "SELECT actual FROM metric_snapshot \
          WHERE metric_ref = $1 AND dimension_attribute IS NULL AND status <> 'failed' \
            AND actual IS NOT NULL \
            AND ($2::timestamptz IS NULL OR computed_at >= $2) \
            AND ($3::timestamptz IS NULL OR computed_at < $3) \
          ORDER BY computed_at DESC, id DESC LIMIT 1",
    )
    .bind(metric)
    .bind(from)
    .bind(until)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
    .map(Option::flatten)
}

type DueRow = (
    Uuid,
    Uuid,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<f64>,
    Option<f64>,
    Option<Uuid>,
);

/// Measures every executed decision whose `measure_at` is on or before
/// `today`. Returns how many it measured.
pub async fn measure_due(state: &EngineState, today: NaiveDate) -> Result<u64, AppError> {
    let due: Vec<DueRow> = sqlx::query_as(
        "SELECT id, COALESCE(expected_metric_ref, metric_ref), measure_at, executed_at, \
                outcome_before::float8, expected_delta::float8, owner_ref \
           FROM dashboard_decision \
          WHERE status = 'executed' AND actual_delta IS NULL \
            AND COALESCE(expected_metric_ref, metric_ref) IS NOT NULL \
            AND measure_at IS NOT NULL AND measure_at::date <= $1 \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY measure_at, id LIMIT $2",
    )
    .bind(today)
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut measured = 0;
    for (id, metric, measure_at, executed_at, before, expected, owner) in due {
        let after = snapshot_value(state, metric, measure_at, None).await?;
        if after.is_none() {
            continue;
        }
        let before = match before {
            Some(b) => Some(b),
            None => snapshot_value(state, metric, None, executed_at).await?,
        };
        let actual = delta(before, after);
        let score = effectiveness(actual, expected);
        let written = sqlx::query(
            "UPDATE dashboard_decision \
                SET outcome_before = $2, outcome_after = $3, actual_delta = $4, \
                    effectiveness = $5, status = 'measured', modified_at = NOW(), \
                    row_version = row_version + 1 \
              WHERE id = $1 AND status = 'executed' AND actual_delta IS NULL",
        )
        .bind(id)
        .bind(before)
        .bind(after)
        .bind(actual)
        .bind(score)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if written == 0 {
            continue;
        }
        measured += 1;
        attome_audit::write_business_event(
            state,
            "dashboard_decision",
            id,
            AuditOperation::Update,
            "dashboard.decision.measured",
            owner.unwrap_or(Uuid::nil()),
            None,
            None,
            format!(
                "before {}, after {}, change {}",
                before.map_or_else(|| "unknown".to_owned(), |v| v.to_string()),
                after.map_or_else(|| "unknown".to_owned(), |v| v.to_string()),
                actual.map_or_else(|| "unknown".to_owned(), |v| v.to_string()),
            ),
        )
        .await;
    }
    if measured > 0 {
        tracing::info!(measured, "decisions measured");
    }
    Ok(measured)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_outcome_delta_needs_both_values() {
        assert_eq!(delta(Some(100.0), Some(130.0)), Some(30.0));
        assert_eq!(delta(Some(100.0), Some(80.0)), Some(-20.0));
        assert_eq!(delta(None, Some(80.0)), None);
        assert_eq!(delta(Some(f64::NAN), Some(80.0)), None);
    }

    #[test]
    fn decision_outcome_effectiveness_compares_with_the_expected_move() {
        assert_eq!(effectiveness(Some(30.0), Some(20.0)), Some(1.5));
        assert_eq!(effectiveness(Some(-10.0), Some(20.0)), Some(-0.5));
        assert_eq!(effectiveness(Some(10.0), Some(3.0)), Some(3.333));
        assert_eq!(effectiveness(Some(10.0), Some(0.0)), None, "no expected move, no score");
        assert_eq!(effectiveness(None, Some(5.0)), None);
        assert_eq!(effectiveness(Some(5.0), None), None);
    }
}

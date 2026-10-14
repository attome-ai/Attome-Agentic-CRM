//! Pinned models and their drift check (roadmap N25-T2).
//!
//! A fine-tuned or adapter model is registered like any other `ai_model`
//! catalogue row, with three more fields (platform changeset 0049):
//! `pinned_version` (the version label the operator pinned; the model id a
//! call sends stays `provider_model_id`, so a pinned row names one exact
//! provider version there and the approval check keeps working unchanged),
//! `base_model` (what it was tuned from) and `drift_suite_ref`
//! (the eval suite, N23, that judges it), plus the score it is expected to
//! hold (`drift_baseline`) and how far it may fall (`drift_tolerance`,
//! default [`DEFAULT_TOLERANCE`]).
//!
//! The nightly quality job ([`check`], called from `EngineJob::AiQualityMonitor`)
//! re-runs each pinned, approved model's suite and alerts the administrators
//! when the score falls below the baseline by more than the tolerance. A run
//! is an ordinary eval run (`ai_eval_run`, its own Ai security event), started
//! as the administrator who last ran that suite by hand, so a scheduled run
//! never holds more rights than a person already used; a suite nobody has run
//! yet is skipped with a warning. At most [`MAX_MODELS_PER_CHECK`] models run
//! a night, one after another.

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// How far a score may fall below its baseline before it is drift.
pub const DEFAULT_TOLERANCE: f64 = 0.05;
/// The most pinned models one nightly check runs.
pub const MAX_MODELS_PER_CHECK: i64 = 20;

/// Whether `score` has drifted below `baseline` by more than `tolerance`.
pub fn drifted(baseline: f64, score: f64, tolerance: f64) -> bool {
    score + tolerance.max(0.0) < baseline
}

#[derive(Debug, sqlx::FromRow)]
struct PinnedModel {
    name: String,
    pinned_version: String,
    drift_suite_ref: String,
    drift_baseline: Option<f64>,
    drift_tolerance: Option<f64>,
}

/// What one nightly check did.
#[derive(Debug, Default)]
pub struct DriftSummary {
    pub checked: usize,
    pub drifted: usize,
    pub skipped: usize,
}

/// Re-runs every pinned, approved model's suite and alerts on drift.
pub async fn check(
    state: &EngineState,
    notification_cfg: &attome_config::NotificationSection,
) -> Result<DriftSummary, AppError> {
    let models: Vec<PinnedModel> = sqlx::query_as(
        "SELECT name, pinned_version, drift_suite_ref, \
                drift_baseline::float8 AS drift_baseline, drift_tolerance::float8 AS drift_tolerance \
         FROM ai_model \
         WHERE (is_active IS NULL OR is_active = true) AND approval_status = 'approved' \
           AND pinned_version IS NOT NULL AND pinned_version <> '' \
           AND drift_suite_ref IS NOT NULL AND drift_suite_ref <> '' \
         ORDER BY name LIMIT $1",
    )
    .bind(MAX_MODELS_PER_CHECK)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut summary = DriftSummary::default();
    for model in models {
        let Ok(suite) = Uuid::parse_str(model.drift_suite_ref.trim()) else {
            tracing::warn!(model = %model.name, "pinned model: drift suite is not an object id; skipped");
            summary.skipped += 1;
            continue;
        };
        let score = match crate::eval_runner::run_as_last_starter(state, suite).await {
            Ok(Some(score)) => score,
            Ok(None) => {
                tracing::warn!(
                    model = %model.name,
                    %suite,
                    "pinned model: its drift suite has never been run by hand or did not finish; skipped"
                );
                summary.skipped += 1;
                continue;
            }
            Err(error) => {
                tracing::error!(%error, model = %model.name, %suite, "pinned model: drift run failed");
                summary.skipped += 1;
                continue;
            }
        };
        summary.checked += 1;
        let Some(baseline) = model.drift_baseline else {
            tracing::info!(model = %model.name, score, "pinned model: scored; no baseline set");
            continue;
        };
        let tolerance = model.drift_tolerance.unwrap_or(DEFAULT_TOLERANCE);
        if drifted(baseline, score, tolerance) {
            summary.drifted += 1;
            tracing::warn!(
                model = %model.name,
                version = %model.pinned_version,
                baseline,
                score,
                "pinned model: score drifted below its baseline"
            );
            crate::quality_monitor::alert_admins(
                &state.base.db,
                notification_cfg,
                format!("AI model drift: {} ({})", model.name, model.pinned_version),
                format!(
                    "The eval suite for model '{}' version '{}' scored {:.0}%, below its baseline \
                     of {:.0}% by more than {:.0} points. Review the run at /ai/status.",
                    model.name,
                    model.pinned_version,
                    score * 100.0,
                    baseline * 100.0,
                    tolerance * 100.0,
                ),
                "/ai/status",
            )
            .await;
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_pin_drift_needs_more_than_the_tolerance() {
        assert!(!drifted(0.9, 0.86, 0.05), "within tolerance");
        assert!(drifted(0.9, 0.84, 0.05), "beyond tolerance");
        assert!(!drifted(0.9, 0.95, 0.05), "a better score is not drift");
        assert!(
            drifted(0.9, 0.89, -1.0),
            "a negative tolerance counts as zero"
        );
    }
}

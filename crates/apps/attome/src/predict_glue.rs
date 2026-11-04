//! Y4-T3: everything the app does with the Predict engine (`attome-predict`),
//! in one place, so a build without the `predict` feature compiles it out.
//! With the feature off the engine's routes are not mounted, its operations
//! are not documented, and its jobs do nothing when they run (a job queued by
//! an earlier build drains quietly).

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// The registered job that checks active models for feature drift
/// (`attome_predict::train::DRIFT_JOB`).
pub const DRIFT_JOB: &str = "predict_drift_check";
/// The registered job that rescores changed records
/// (`attome_predict::generic::RESCORE_JOB`).
pub const RESCORE_JOB: &str = "predict_definition_rescore";

/// Mounts the Predict engine on `builder`.
#[cfg(feature = "predict")]
pub fn register(builder: attome_api::EngineSystemBuilder) -> attome_api::EngineSystemBuilder {
    // M36 Phase 0+1 (Predictive Intelligence, D-473) — route-mounting/
    // license-gating only: `prediction_model`/`prediction` are migration-
    // owned infrastructure tables, so there is no seed to call before
    // `.build()`.
    builder.register(attome_predict::PredictModel)
}

/// Without the `predict` feature: nothing to mount.
#[cfg(not(feature = "predict"))]
pub fn register(builder: attome_api::EngineSystemBuilder) -> attome_api::EngineSystemBuilder {
    builder
}

/// Merges the Predict engine's operations into `doc`.
#[cfg(feature = "predict")]
pub fn merge_openapi(doc: &mut utoipa::openapi::OpenApi) {
    doc.merge(attome_server::openapi::tag_module(
        attome_predict::openapi(),
        "predict",
    ));
}

/// Without the `predict` feature: no operations.
#[cfg(not(feature = "predict"))]
pub fn merge_openapi(_doc: &mut utoipa::openapi::OpenApi) {}

/// Trains model `model_id` (O1-T3: a definition model through the generic
/// path).
pub async fn train(state: &EngineState, model_id: Uuid) -> Result<(), AppError> {
    #[cfg(feature = "predict")]
    attome_predict::generic::run(state, model_id).await?;
    #[cfg(not(feature = "predict"))]
    let _ = (state, model_id);
    Ok(())
}

/// The scoring sweep: the built-in models, then the definition models.
pub async fn scoring_sweep(state: &EngineState) -> Result<(), AppError> {
    #[cfg(feature = "predict")]
    {
        let stats = attome_predict::score::run_scoring_sweep(&state.base.db).await?;
        let defined = attome_predict::generic::score_all(state).await?;
        if defined > 0 {
            tracing::info!(scored = defined, "predict: definition models scored");
        }
        if stats.scored > 0 {
            tracing::info!(
                models_considered = stats.models_considered,
                scored = stats.scored,
                "predict scoring sweep: run complete"
            );
        }
    }
    #[cfg(not(feature = "predict"))]
    let _ = state;
    Ok(())
}

/// The outcome-fill sweep: the built-in models, then the definition models.
pub async fn outcome_fill_sweep(state: &EngineState) -> Result<(), AppError> {
    #[cfg(feature = "predict")]
    {
        let stats = attome_predict::score::fill_outcomes(&state.base.db).await?;
        let defined = attome_predict::generic::fill_outcomes(state).await?;
        if defined > 0 {
            tracing::info!(
                filled = defined,
                "predict: definition model outcomes recorded"
            );
        }
        if stats.filled > 0 {
            tracing::info!(
                filled = stats.filled,
                "predict outcome-fill sweep: run complete"
            );
        }
    }
    #[cfg(not(feature = "predict"))]
    let _ = state;
    Ok(())
}

/// How many active models' features drifted (O1-T2).
pub async fn drift_check(state: &EngineState) -> Result<usize, AppError> {
    #[cfg(feature = "predict")]
    let count = attome_predict::train::drift_check(&state.base.db).await?;
    #[cfg(not(feature = "predict"))]
    let count = {
        let _ = state;
        0
    };
    Ok(count)
}

/// How many changed records were rescored.
pub async fn drain_changes(state: &EngineState) -> Result<usize, AppError> {
    #[cfg(feature = "predict")]
    let count = attome_predict::generic::drain_changes(state).await?;
    #[cfg(not(feature = "predict"))]
    let count = {
        let _ = state;
        0
    };
    Ok(count)
}

#[cfg(all(test, feature = "predict"))]
mod tests {
    #[test]
    fn job_names_match_the_engine() {
        assert_eq!(super::DRIFT_JOB, attome_predict::train::DRIFT_JOB);
        assert_eq!(super::RESCORE_JOB, attome_predict::generic::RESCORE_JOB);
    }
}

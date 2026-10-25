//! The training job: builds the labeled set ([`crate::features::training_rows`]),
//! fits a `smartcore::LogisticRegression` in `spawn_blocking` (guidelines §10
//! — never block the Tokio runtime with the CPU-bound fit), holds out a
//! slice of it, and only activates the model if it beats a majority-class
//! baseline on that holdout — the module plan's own risk-mitigation ruling
//! ("never surface a model that failed holdout").
//!
//! Two entry points `admin.rs` calls, both insert-and-enqueue in one
//! transaction (same atomicity `attome_docgen::render::create_render`/
//! `attome_report::run::create_run` use): [`create_and_enqueue`] (a brand-new
//! model) and [`enqueue_retrain`] (an existing one). [`run`] is the
//! worker body `crates/server/src/jobs.rs` calls for
//! `EngineJob::PredictTrainModel`.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::json;
use uuid::Uuid;

use crate::model::ModelArtifact;

/// Module plan §6's risk note ("require min sample ... never surface a model
/// that failed holdout") as a concrete floor: fewer closed tickets than this
/// and there isn't enough signal to trust any holdout result, so training
/// refuses to even attempt a fit.
pub const MIN_TRAINING_SAMPLES: usize = 20;
/// Also require both classes meaningfully represented — a training set that
/// is all-breach or all-no-breach can't produce a meaningful baseline
/// comparison (the baseline *is* the majority class, so it would trivially
/// "win" against a degenerate single-class fit).
pub const MIN_CLASS_SAMPLES: usize = 5;

/// Creates a `training`-status `prediction_model` row and enqueues its
/// `EngineJob::PredictTrainModel`, in one transaction. Rejects an
/// unsupported `target`/`entity` pair before ever writing a row — Phase 1
/// implements only `sla_breach` against `service_ticket` (`crate::TARGET_SLA_
/// BREACH`/`crate::ENTITY_TICKET`); Phase 2/3's other CHECK-permitted
/// targets (`capacity_shortfall`/`anomaly`/`custom_metric:*`) have no
/// extraction or fit code in this crate yet.
///
/// A duplicate `name` surfaces as `AppError::Conflict` via the unique
/// index's `23505` — translated here rather than pre-checked, so a
/// concurrent double-create can't race past a SELECT-then-INSERT gap
/// (guidelines §2: prefer a DB-enforced constraint over an app-level lock
/// when the constraint already gives the right answer).
pub async fn create_and_enqueue(
    state: &EngineState,
    name: &str,
    target: &str,
    entity: &str,
    created_by: Uuid,
) -> Result<Uuid, AppError> {
    if target != crate::TARGET_SLA_BREACH || entity != crate::ENTITY_TICKET {
        return Err(AppError::Validation(format!(
            "unsupported target/entity pair for this deployment's attome-predict build: \
             target={target:?} entity={entity:?} — Phase 1 implements only \
             target={:?} entity={:?}",
            crate::TARGET_SLA_BREACH,
            crate::ENTITY_TICKET
        )));
    }

    let model_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let inserted = sqlx::query(
        "INSERT INTO prediction_model \
            (id, name, target, entity, algorithm, status, created_by) \
         VALUES ($1, $2, $3, $4, 'logistic_regression', 'training', $5)",
    )
    .bind(model_id)
    .bind(name)
    .bind(target)
    .bind(entity)
    .bind(created_by)
    .execute(&mut *tx)
    .await;

    if let Err(e) = &inserted
        && attome_db::is_unique_violation(e)
    {
        return Err(AppError::Conflict(
            "a prediction model with this name already exists",
        ));
    }
    inserted.map_err(AppError::internal)?;

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::PredictTrainModel { model_id },
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            created_by,
            "prediction_model",
            Some(model_id),
        )
        .named("predict_model.create"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(model_id)
}

/// Re-triggers training on an existing model — `admin.rs`'s
/// `POST /api/v1/admin/predict/models/{id}/train`. The conditional
/// `WHERE status != 'training'` is this mutation's whole concurrency story
/// (guidelines §2: optimistic concurrency via a row's own state predicate,
/// not a lock, when Postgres's row-level write lock during the `UPDATE`
/// itself already serializes two concurrent callers correctly) — a second
/// call while one training run is already in flight sees `rows_affected ==
/// 0` and gets `Conflict`, never a duplicate enqueue.
pub async fn enqueue_retrain(
    state: &EngineState,
    model_id: Uuid,
    actor_user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated = sqlx::query(
        "UPDATE prediction_model \
            SET status = 'training', updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = false AND status != 'training'",
    )
    .bind(model_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        // Either no such model, or one already training — the caller can't
        // tell which from rows_affected alone, so check existence to give
        // the right error.
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM prediction_model WHERE id = $1)")
                .bind(model_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::Conflict("this model is already training")
        } else {
            AppError::NotFound
        });
    }

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::PredictTrainModel { model_id },
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            actor_user_id,
            "prediction_model",
            Some(model_id),
        )
        .named("predict_model.retrain"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// Fits a logistic regression on `train` and returns its extracted
/// [`ModelArtifact`] — the actual CPU-bound work, run inside
/// `tokio::task::spawn_blocking` by [`run`], never on the async
/// worker thread (guidelines §10).
///
/// Reads back the fitted parameters via `LogisticRegression::coefficients()`/
/// `intercept()` rather than keeping the estimator itself: this crate never
/// needs `smartcore`'s own `predict`/`predict_proba` at scoring time (there
/// is no `predict_proba` in this smartcore version at all — see
/// `ModelArtifact::predict_proba`'s doc comment), just the fitted scalars.
fn fit(features: &[Vec<f64>], labels: &[i32]) -> Result<ModelArtifact, String> {
    use smartcore::linalg::basic::arrays::Array;
    use smartcore::linalg::basic::matrix::DenseMatrix;
    use smartcore::linear::logistic_regression::LogisticRegression;

    let row_refs: Vec<&[f64]> = features.iter().map(|r| r.as_slice()).collect();
    let x = DenseMatrix::from_2d_array(&row_refs).map_err(|e| e.to_string())?;
    let y: Vec<i32> = labels.to_vec();

    let fitted = LogisticRegression::fit(&x, &y, Default::default()).map_err(|e| e.to_string())?;

    let num_features = features[0].len();
    let coefficients = (0..num_features)
        .map(|j| *fitted.coefficients().get((0, j)))
        .collect();
    let intercept = *fitted.intercept().get((0, 0));

    Ok(ModelArtifact {
        coefficients,
        intercept,
        feature_order: crate::features::fixed_feature_order(),
    })
}

/// O1-T2: the area under the ROC curve of `scored` (`(probability, label)`),
/// from the rank sum (ties share their average rank); `None` without both
/// classes. Pure.
pub fn auc(scored: &[(f64, i32)]) -> Option<f64> {
    let positives = scored.iter().filter(|(_, l)| *l == 1).count();
    let negatives = scored.len() - positives;
    if positives == 0 || negatives == 0 {
        return None;
    }
    let mut order: Vec<(f64, i32)> = scored.to_vec();
    order.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut rank_sum = 0.0;
    let mut i = 0;
    while i < order.len() {
        let mut j = i;
        while j + 1 < order.len() && order[j + 1].0 == order[i].0 {
            j += 1;
        }
        // Ranks i+1 ..= j+1 share their average.
        let average = (i + j + 2) as f64 / 2.0;
        rank_sum += order[i..=j].iter().filter(|(_, l)| *l == 1).count() as f64 * average;
        i = j + 1;
    }
    let p = positives as f64;
    Some((rank_sum - p * (p + 1.0) / 2.0) / (p * negatives as f64))
}

/// O1-T2: each feature's mean and standard deviation over `rows`. Pure.
pub fn feature_profile(rows: &[Vec<f64>]) -> Vec<(f64, f64)> {
    let width = rows.first().map_or(0, Vec::len);
    let n = rows.len().max(1) as f64;
    (0..width)
        .map(|k| {
            let mean = rows.iter().map(|r| r[k]).sum::<f64>() / n;
            let var = rows.iter().map(|r| (r[k] - mean).powi(2)).sum::<f64>() / n;
            (mean, var.sqrt())
        })
        .collect()
}

/// How far a feature's mean may move, in training standard deviations,
/// before the drift check flags it.
pub const DRIFT_THRESHOLD: f64 = 0.5;

/// O1-T2: the features whose mean over `current` moved more than
/// `threshold` training standard deviations from `profile` (a feature with
/// no spread in training drifts on any change). Pure.
pub fn drifted(profile: &[(f64, f64)], current: &[Vec<f64>], threshold: f64) -> Vec<usize> {
    if current.is_empty() {
        return Vec::new();
    }
    let now = feature_profile(current);
    profile
        .iter()
        .zip(now)
        .enumerate()
        .filter(|(_, ((mean, std), (cur, _)))| {
            let shift = (cur - mean).abs();
            if *std > f64::EPSILON {
                shift / std > threshold
            } else {
                shift > 1e-9
            }
        })
        .map(|(k, _)| k)
        .collect()
}

/// How much worse (in AUC) a retrain may be before the previous model is
/// kept.
pub const KEEP_PREVIOUS_MARGIN: f64 = 0.02;

/// Deterministic 80/20 split — every 5th row (by the query's own
/// `ORDER BY created_at DESC`) goes to holdout. No RNG dependency, and
/// reproducible across runs against the same data, which matters for the
/// synthetic test proving this module actually learns something.
fn split_holdout<T>(rows: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut train = Vec::new();
    let mut holdout = Vec::new();
    for (i, row) in rows.into_iter().enumerate() {
        if i % 5 == 0 {
            holdout.push(row);
        } else {
            train.push(row);
        }
    }
    (train, holdout)
}

/// The worker for `EngineJob::PredictTrainModel`. Re-derives everything
/// from `model_id` (never trusts an enqueue-time payload beyond the id
/// itself, same "ledger row is the frozen intent, re-read at process time"
/// discipline `attome_docgen::render::process`/`attome_report::run::process` use).
///
/// Never returns `Err` for an ordinary "couldn't train" outcome (too little
/// data, didn't beat baseline, smartcore returned `Failed`) — those are
/// recorded as `status = 'failed_holdout'` with a `metrics.error` message,
/// which is success from the job queue's point of view (it ran to
/// completion; retrying would not change the result). `Err` is reserved for
/// genuine infrastructure failure (a DB error) that a retry legitimately
/// might resolve.
pub async fn run(db: &DbPool, model_id: Uuid) -> Result<(), AppError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT target, entity FROM prediction_model WHERE id = $1")
            .bind(model_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some((target, entity)) = row else {
        tracing::warn!(model_id = %model_id, "predict: training job for a model that no longer exists — skipping");
        return Ok(());
    };

    if target != crate::TARGET_SLA_BREACH || entity != crate::ENTITY_TICKET {
        return fail_holdout(
            db,
            model_id,
            json!({ "error": "unsupported target/entity for this build" }),
        )
        .await;
    }

    let training_rows = crate::features::training_rows(db).await?;
    let total = training_rows.len();
    let positives = training_rows.iter().filter(|r| r.label == 1).count();
    let negatives = total - positives;

    if total < MIN_TRAINING_SAMPLES
        || positives < MIN_CLASS_SAMPLES
        || negatives < MIN_CLASS_SAMPLES
    {
        return fail_holdout(
            db,
            model_id,
            json!({
                "error": "insufficient labeled training data",
                "total_available": total,
                "positives": positives,
                "negatives": negatives,
                "min_total_required": MIN_TRAINING_SAMPLES,
                "min_per_class_required": MIN_CLASS_SAMPLES,
            }),
        )
        .await;
    }

    let (train, holdout) = split_holdout(training_rows);
    if holdout.is_empty() || train.is_empty() {
        return fail_holdout(
            db,
            model_id,
            json!({ "error": "holdout split produced an empty train or holdout set" }),
        )
        .await;
    }

    let train_features: Vec<Vec<f64>> = train.iter().map(|r| r.features.clone()).collect();
    let train_labels: Vec<i32> = train.iter().map(|r| r.label).collect();

    let fit_result = tokio::task::spawn_blocking(move || fit(&train_features, &train_labels))
        .await
        .map_err(|e| AppError::internal(format!("training task panicked: {e}")))?;

    let artifact = match fit_result {
        Ok(a) => a,
        Err(message) => {
            return fail_holdout(db, model_id, json!({ "error": message })).await;
        }
    };

    let train_majority_label = if train.iter().filter(|r| r.label == 1).count() * 2 >= train.len() {
        1
    } else {
        0
    };

    let holdout_total = holdout.len();
    let mut correct = 0usize;
    let mut baseline_correct = 0usize;
    let mut scored = Vec::with_capacity(holdout_total);
    for row in &holdout {
        let p = artifact.predict_proba(&row.features);
        scored.push((p, row.label));
        let predicted = i32::from(p > 0.5);
        if predicted == row.label {
            correct += 1;
        }
        if train_majority_label == row.label {
            baseline_correct += 1;
        }
    }
    let accuracy = correct as f64 / holdout_total as f64;
    let baseline_accuracy = baseline_correct as f64 / holdout_total as f64;
    let beat_baseline = accuracy > baseline_accuracy;

    let holdout_auc = auc(&scored);
    let train_rows: Vec<Vec<f64>> = train.iter().map(|r| r.features.clone()).collect();
    let profile = feature_profile(&train_rows);

    // O1-T2: the version this run would replace, for comparison.
    let previous: Option<(String, Option<serde_json::Value>)> =
        sqlx::query_as("SELECT status, metrics FROM prediction_model WHERE id = $1")
            .bind(model_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let previous_auc = previous
        .as_ref()
        .filter(|(status, _)| status == "active")
        .and_then(|(_, m)| m.as_ref())
        .and_then(|m| m["auc"].as_f64());
    let keep_previous = matches!((previous_auc, holdout_auc), (Some(before), Some(now)) if now + KEEP_PREVIOUS_MARGIN < before);

    let metrics = json!({
        "train_size": train.len(),
        "holdout_size": holdout_total,
        "accuracy": accuracy,
        "baseline_accuracy": baseline_accuracy,
        "baseline_method": "majority_class",
        "beat_baseline": beat_baseline,
        "auc": holdout_auc,
        "previous_auc": previous_auc,
        "kept_previous": keep_previous,
        "feature_profile": profile,
        "trained_at": chrono::Utc::now(),
    });
    if keep_previous {
        // The retrain is worse than the active version: keep that one's
        // artifact and record why in its metrics history.
        sqlx::query(
            "UPDATE prediction_model \
                SET metrics = metrics || jsonb_build_object('last_rejected_run', $2::jsonb), \
                    updated_at = NOW(), row_version = row_version + 1 \
              WHERE id = $1",
        )
        .bind(model_id)
        .bind(&metrics)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        tracing::info!(model_id = %model_id, ?holdout_auc, ?previous_auc, "predict: retrain was worse; the previous version stays active");
        return Ok(());
    }
    let status = if beat_baseline {
        "active"
    } else {
        "failed_holdout"
    };
    let features_json = json!(
        crate::features::FEATURE_KEYS
            .iter()
            .map(|k| crate::model::FeatureDescriptor {
                key: k.to_string(),
                kind: if *k == "resolution_target_hours" {
                    "policy".to_string()
                } else if *k == "requester_prior_ticket_count" {
                    "derived".to_string()
                } else {
                    "field".to_string()
                },
            })
            .collect::<Vec<_>>()
    );

    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-predict/train:{model_id}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if !locked {
        // Another training run for this model is completing right now;
        // this one's result would only be overwritten. Nothing to record.
        tracing::warn!(model_id = %model_id, "predict: skipping training result write — a concurrent run holds the lock");
        return Ok(());
    }

    sqlx::query(
        "UPDATE prediction_model \
            SET status = $2, metrics = $3, model_artifact = $4, features = $5, \
                trained_version = trained_version + 1, updated_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(model_id)
    .bind(status)
    .bind(&metrics)
    .bind(serde_json::to_value(&artifact).map_err(AppError::internal)?)
    .bind(&features_json)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;

    tracing::info!(
        model_id = %model_id,
        status,
        accuracy,
        baseline_accuracy,
        "predict: training run complete"
    );
    Ok(())
}

/// O1-T2: the weekly drift check. For every active model, compares each
/// feature's mean over the most recent closed records with the profile
/// stored at training and records the drifted features in its metrics
/// (`drift`); returns how many models drifted.
pub async fn drift_check(db: &DbPool) -> Result<usize, AppError> {
    let models: Vec<(Uuid, Option<serde_json::Value>)> = sqlx::query_as(
        "SELECT id, metrics FROM prediction_model WHERE status = 'active' ORDER BY id LIMIT 100",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if models.is_empty() {
        return Ok(0);
    }
    let recent: Vec<Vec<f64>> = crate::features::training_rows(db)
        .await?
        .into_iter()
        .take(DRIFT_WINDOW)
        .map(|r| r.features)
        .collect();
    let mut drifted_models = 0;
    for (id, metrics) in models {
        let profile: Vec<(f64, f64)> = metrics
            .as_ref()
            .and_then(|m| serde_json::from_value(m["feature_profile"].clone()).ok())
            .unwrap_or_default();
        if profile.is_empty() {
            continue;
        }
        let keys: Vec<&str> = drifted(&profile, &recent, DRIFT_THRESHOLD)
            .into_iter()
            .filter_map(|k| crate::features::FEATURE_KEYS.get(k).copied())
            .collect();
        if !keys.is_empty() {
            drifted_models += 1;
        }
        let drift = json!({
            "checked_at": chrono::Utc::now(),
            "window": recent.len(),
            "drifted_features": keys,
        });
        sqlx::query(
            "UPDATE prediction_model \
                SET metrics = COALESCE(metrics, '{}'::jsonb) || jsonb_build_object('drift', $2::jsonb), \
                    updated_at = NOW() \
              WHERE id = $1",
        )
        .bind(id)
        .bind(&drift)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(drifted_models)
}

/// How many of the most recent closed records the drift check reads.
pub const DRIFT_WINDOW: usize = 200;

/// O1-T2: the registered weekly drift job's name.
pub const DRIFT_JOB: &str = "predict_drift_check";

async fn fail_holdout(
    db: &DbPool,
    model_id: Uuid,
    metrics: serde_json::Value,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE prediction_model \
            SET status = 'failed_holdout', metrics = $2, \
                trained_version = trained_version + 1, updated_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(model_id)
    .bind(&metrics)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    tracing::warn!(model_id = %model_id, metrics = %metrics, "predict: training run did not produce an active model");
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Module plan §5's own verification note: "`cargo test -p attome-predict`
    //! with a synthetic dataset that has a known signal" — proving the fit
    //! actually learns the signal, not merely that the code compiles and a
    //! model reaches `active`. No database needed: this exercises `fit`/
    //! `split_holdout` directly against synthetic feature vectors built with
    //! a deliberate, known linear relationship between features and label.
    use super::*;
    use crate::features::TrainingRow;

    /// A tiny deterministic LCG (no `rand` dependency) — reproducible across
    /// runs and platforms, which matters for a test whose assertion is a
    /// numeric threshold.
    struct Lcg(u64);
    impl Lcg {
        fn next_f64(&mut self) -> f64 {
            // Numerical Recipes' constants — good enough for synthetic-data
            // generation, no cryptographic property needed.
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            ((self.0 >> 32) as u32 as f64) / (u32::MAX as f64)
        }
    }

    /// Builds `n` synthetic `(features, label)` rows in
    /// `features::FEATURE_KEYS` order, with a deliberate linear signal:
    /// higher priority/severity/incident-flag and a shorter resolution
    /// target genuinely increase breach probability, plus Bernoulli noise —
    /// so a model that actually fits the relationship measurably
    /// outperforms "always predict the majority class", while a model that
    /// merely memorizes noise would not generalize to a held-out slice.
    fn synthetic_rows(n: usize) -> Vec<TrainingRow> {
        let mut rng = Lcg(42);
        (0..n)
            .map(|_| {
                let priority_ord = (rng.next_f64() * 4.0).floor().min(3.0);
                let severity_ord = (rng.next_f64() * 5.0).floor().min(4.0);
                let is_incident = if rng.next_f64() > 0.5 { 1.0 } else { 0.0 };
                let resolution_target_hours = 1.0 + rng.next_f64() * 47.0;
                let requester_prior_ticket_count = (rng.next_f64() * 20.0).floor();
                let hour_of_day = (rng.next_f64() * 24.0).floor();
                let day_of_week = (rng.next_f64() * 7.0).floor();

                let z = 0.9 * priority_ord + 0.7 * severity_ord + 1.2 * is_incident
                    - 0.15 * resolution_target_hours
                    + 0.05 * requester_prior_ticket_count
                    - 1.0;
                let p = 1.0 / (1.0 + (-z).exp());
                let label = i32::from(rng.next_f64() < p);

                TrainingRow {
                    features: vec![
                        priority_ord,
                        severity_ord,
                        is_incident,
                        resolution_target_hours,
                        requester_prior_ticket_count,
                        hour_of_day,
                        day_of_week,
                    ],
                    label,
                }
            })
            .collect()
    }

    #[test]
    fn auc_of_a_perfect_and_a_random_ranking() {
        let perfect = [(0.9, 1), (0.8, 1), (0.2, 0), (0.1, 0)];
        assert!((auc(&perfect).unwrap() - 1.0).abs() < 1e-9);
        let inverted = [(0.1, 1), (0.2, 1), (0.8, 0), (0.9, 0)];
        assert!(auc(&inverted).unwrap().abs() < 1e-9);
        let tied = [(0.5, 1), (0.5, 0)];
        assert!((auc(&tied).unwrap() - 0.5).abs() < 1e-9);
        assert!(auc(&[(0.5, 1)]).is_none());
    }

    #[test]
    fn drift_flags_a_moved_feature_only() {
        let train = vec![vec![1.0, 10.0], vec![3.0, 10.0], vec![2.0, 10.0]];
        let profile = feature_profile(&train);
        assert!((profile[0].0 - 2.0).abs() < 1e-9);
        let same = vec![vec![2.0, 10.0], vec![2.1, 10.0]];
        assert!(drifted(&profile, &same, DRIFT_THRESHOLD).is_empty());
        let moved = vec![vec![5.0, 10.0], vec![6.0, 11.0]];
        assert_eq!(drifted(&profile, &moved, DRIFT_THRESHOLD), vec![0, 1]);
    }

    #[test]
    fn fitted_model_beats_majority_class_baseline_on_synthetic_holdout() {
        let rows = synthetic_rows(400);
        let (train, holdout) = split_holdout(rows);
        assert!(!train.is_empty() && !holdout.is_empty());

        let train_features: Vec<Vec<f64>> = train.iter().map(|r| r.features.clone()).collect();
        let train_labels: Vec<i32> = train.iter().map(|r| r.label).collect();

        let artifact = fit(&train_features, &train_labels).expect("synthetic fit must succeed");
        assert_eq!(
            artifact.coefficients.len(),
            crate::features::FEATURE_KEYS.len()
        );

        let train_majority_label =
            if train.iter().filter(|r| r.label == 1).count() * 2 >= train.len() {
                1
            } else {
                0
            };

        let mut correct = 0usize;
        let mut baseline_correct = 0usize;
        for row in &holdout {
            let p = artifact.predict_proba(&row.features);
            let predicted = i32::from(p > 0.5);
            if predicted == row.label {
                correct += 1;
            }
            if train_majority_label == row.label {
                baseline_correct += 1;
            }
        }
        let accuracy = correct as f64 / holdout.len() as f64;
        let baseline_accuracy = baseline_correct as f64 / holdout.len() as f64;
        eprintln!(
            "synthetic backtest: holdout={} accuracy={accuracy:.4} baseline_accuracy={baseline_accuracy:.4}",
            holdout.len()
        );

        assert!(
            accuracy > baseline_accuracy,
            "fitted model ({accuracy}) did not beat the majority-class baseline \
             ({baseline_accuracy}) on synthetic holdout data with a known signal"
        );
        assert!(
            accuracy >= 0.65,
            "fitted model's holdout accuracy ({accuracy}) is too close to chance for \
             data with a deliberately strong linear signal — the fit likely isn't \
             learning the relationship correctly"
        );
    }

    /// A dataset with no real relationship between features and label (pure
    /// coin-flip) should NOT reliably beat baseline by a wide margin — this
    /// guards against the test above passing for the wrong reason (e.g. a
    /// bug that always reports "beat baseline" regardless of input).
    #[test]
    fn pure_noise_does_not_dramatically_beat_baseline() {
        let mut rng = Lcg(7);
        let rows: Vec<TrainingRow> = (0..400)
            .map(|_| TrainingRow {
                features: vec![
                    (rng.next_f64() * 4.0).floor(),
                    (rng.next_f64() * 5.0).floor(),
                    if rng.next_f64() > 0.5 { 1.0 } else { 0.0 },
                    1.0 + rng.next_f64() * 47.0,
                    (rng.next_f64() * 20.0).floor(),
                    (rng.next_f64() * 24.0).floor(),
                    (rng.next_f64() * 7.0).floor(),
                ],
                label: i32::from(rng.next_f64() < 0.5),
            })
            .collect();
        let (train, holdout) = split_holdout(rows);
        let train_features: Vec<Vec<f64>> = train.iter().map(|r| r.features.clone()).collect();
        let train_labels: Vec<i32> = train.iter().map(|r| r.label).collect();

        // A fair Bernoulli(0.5) label draw can, by chance, collapse to a
        // single class within one 320-row training split — `smartcore`
        // correctly refuses to fit a binary classifier with only one class
        // present. That outcome is not a failure of the property this test
        // checks (there is trivially nothing to "beat baseline" with when no
        // fit happens at all), so it's tolerated explicitly rather than
        // treated as a hard failure — any *other* fit error still fails
        // loudly, since that would indicate a real regression.
        match fit(&train_features, &train_labels) {
            Ok(artifact) => {
                let mut correct = 0usize;
                for row in &holdout {
                    let p = artifact.predict_proba(&row.features);
                    if i32::from(p > 0.5) == row.label {
                        correct += 1;
                    }
                }
                let accuracy = correct as f64 / holdout.len() as f64;
                assert!(
                    accuracy < 0.65,
                    "a model fit on pure noise scored {accuracy} on holdout — suspiciously \
                     high, check for a label-leakage bug in the fit/evaluation path"
                );
            }
            Err(e) => {
                assert!(
                    e.contains("classes"),
                    "fit failed for an unexpected reason on synthetic noise data: {e}"
                );
            }
        }
    }
}

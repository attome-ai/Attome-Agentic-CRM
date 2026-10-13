//! Shared row/wire types for `prediction_model` — used by [`crate::train`]
//! (writes), [`crate::score`] (reads `status = 'active'` rows), and
//! [`crate::admin`] (the wire-facing summary).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// One entry in `prediction_model.features` — recorded for admin
/// visibility/reproducibility (module plan §3's `features[]`). Phase 1 never
/// reads this back to drive extraction: `features::FEATURE_KEYS` is the
/// fixed, hand-picked set `train.rs`/`score.rs` actually compute, and this
/// array is populated *from* that constant after a successful fit — not the
/// other way around (there is no per-model configurable feature set yet).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FeatureDescriptor {
    /// Matches one of `features::FEATURE_KEYS`.
    pub key: String,
    /// `"field"` (a raw ticket attribute), `"derived"` (computed, e.g. an
    /// ordinal encoding or a count), or `"policy"` (joined off
    /// `service_sla_policy`) — descriptive only, no validation depends on it.
    pub kind: String,
}

/// `prediction_model.model_artifact` once a fit has actually run — the
/// fitted logistic-regression parameters, extracted from
/// `smartcore::LogisticRegression::coefficients()`/`intercept()` right after
/// `train::fit_and_evaluate`, so `score.rs` can compute
/// `sigmoid(dot(coefficients, x) + intercept)` without holding the fitted
/// estimator in memory or re-fitting. `feature_order` pins the column order
/// `coefficients` was fit against — must match `features::FEATURE_KEYS` at
/// scoring time; a mismatch (only possible if `FEATURE_KEYS` changes after a
/// model was trained under an older version of this crate) is a hard error,
/// never a silent misalignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelArtifact {
    pub coefficients: Vec<f64>,
    pub intercept: f64,
    pub feature_order: Vec<String>,
}

impl ModelArtifact {
    /// `sigmoid(dot(coefficients, features) + intercept)` — exactly the
    /// binary-classification probability `smartcore::LogisticRegression::
    /// predict` computes internally (see that method's source: `x.ab(false,
    /// self.coefficients(), true)` then `sigmoid(y_hat + intercept)`), just
    /// evaluated directly against the extracted scalars rather than through
    /// smartcore's matrix API — this crate's one, shared scoring function so
    /// `train.rs`'s holdout evaluation and `score.rs`'s live scoring can
    /// never disagree about what a fitted model predicts.
    ///
    /// Panics if `features.len() != coefficients.len()` — both call sites
    /// build `features` from `features::FEATURE_KEYS`, the same constant
    /// `feature_order` was stamped from at training time, so a mismatch
    /// means the feature set changed underneath an already-trained model
    /// (see this struct's own doc comment) and must not silently score
    /// nonsense.
    pub fn predict_proba(&self, features: &[f64]) -> f64 {
        assert_eq!(
            features.len(),
            self.coefficients.len(),
            "attome-predict: feature vector length does not match the model's trained \
             coefficient count — the model needs retraining under the current feature set"
        );
        let z: f64 = self
            .coefficients
            .iter()
            .zip(features)
            .map(|(w, x)| w * x)
            .sum::<f64>()
            + self.intercept;
        1.0 / (1.0 + (-z).exp())
    }
}

/// Full row shape of `prediction_model`, read by [`crate::train`] and
/// [`crate::score`]. `model_artifact` stays `Option<Value>` here (not
/// deserialized into [`ModelArtifact`] eagerly) so a row with no artifact yet
/// (still training, or failed before a fit ever ran) reads back cleanly.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PredictionModelRow {
    pub id: Uuid,
    pub name: String,
    pub target: String,
    pub entity: String,
    pub features: Value,
    pub algorithm: String,
    pub trained_version: i32,
    pub metrics: Option<Value>,
    pub model_artifact: Option<Value>,
    pub status: String,
    pub created_by: Option<Uuid>,
    pub organization_ref: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub row_version: i64,
    pub is_deleted: bool,
}

impl PredictionModelRow {
    /// `None` when `model_artifact` is unset, or set but not a well-formed
    /// [`ModelArtifact`] (defensive only — the only writer is `train.rs`
    /// itself). `score.rs` treats either as "nothing to score with", same as
    /// a model that has never been trained.
    pub fn artifact(&self) -> Option<ModelArtifact> {
        self.model_artifact
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

/// The `/api/v1/admin/predict/models*` wire shape — deliberately omits
/// `model_artifact` (internal fitted parameters, not a public contract) and
/// `organization_ref`/`row_version`/`is_deleted` (no client needs them yet).
#[derive(Debug, Serialize, ToSchema)]
pub struct ModelSummary {
    pub id: Uuid,
    pub name: String,
    pub target: String,
    pub entity: String,
    pub features: Value,
    pub algorithm: String,
    pub trained_version: i32,
    pub metrics: Option<Value>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PredictionModelRow> for ModelSummary {
    fn from(r: PredictionModelRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            target: r.target,
            entity: r.entity,
            features: r.features,
            algorithm: r.algorithm,
            trained_version: r.trained_version,
            metrics: r.metrics,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

//! Models from a definition (O1-T1's [`crate::model_def`]), trained and
//! scored. Before this, only the ticket model trained: a definition had no
//! caller.
//!
//! **Create.** `POST /api/v1/admin/predict/models` with a `definition`
//! stores the model with target `def:<attribute>` and the definition
//! (migration 0378), validated against the metadata.
//!
//! **Train** ([`train`], the training job): the rows are read through the
//! secured compiler as the model's creator ([`crate::model_def::training_spec`]),
//! up to [`MAX_ROWS`]; each row is encoded ([`Encoder`]): numbers and
//! booleans as themselves, a time feature through
//! [`crate::model_def::time_feature`], text and choices one-hot over the
//! [`MAX_CATEGORIES`] most common values seen in training. The label is the
//! target read as yes or no ([`label_of`]). A fifth of the rows is held out;
//! the inputs are standardized by the training rows' means and spreads, and
//! the model is kept only when it beats the majority class there, as the
//! ticket model is. Only `logistic_regression` trains here; rollup features
//! are not trained yet: such a definition fails with that reason.
//!
//! **Score** ([`score`], O1-T3): every row the creator can read gets a
//! `prediction` (`regarding_entity`, `regarding_id`, the probability, a
//! label, and `explanation.top_factors`: the three features that moved the
//! score most, coefficient times the standardized value) once per model
//! version, and, when the definition names a `score_attribute`, the score
//! from 0 to 100 on the record itself. The nightly scoring sweep runs it
//! ([`score_all`]). Scoring on each change and the outcome record (O11) are
//! not built yet.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use attome_core::EngineState;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::model::ModelArtifact;
use crate::model_def::{Feature, ModelDef};

/// The prefix of a definition model's stored target.
pub const TARGET_PREFIX: &str = "def:";
/// Rows read for training or scoring at most.
pub const MAX_ROWS: usize = 20_000;
/// Categories one-hot encoded per text feature at most.
pub const MAX_CATEGORIES: usize = 20;
/// How many factors explain a score.
pub const TOP_FACTORS: usize = 3;

/// The target read as yes (1) or no (0); `None` when it is not set. Pure.
pub fn label_of(value: &Value) -> Option<i32> {
    match value {
        Value::Bool(b) => Some(i32::from(*b)),
        Value::Number(n) => n.as_f64().map(|v| i32::from(v > 0.0)),
        Value::String(s) => match s.trim().to_lowercase().as_str() {
            "" => None,
            "false" | "0" | "no" | "lost" | "rejected" | "closed_lost" => Some(0),
            _ => Some(1),
        },
        _ => None,
    }
}

/// The column a feature reads (`None` for a rollup). Pure.
fn column(feature: &Feature) -> Option<&str> {
    match feature {
        Feature::Attribute { attribute } => Some(attribute),
        Feature::Path { path } => Some(path),
        Feature::Time { time, .. } => Some(time),
        Feature::Rollup { .. } => None,
    }
}

fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::String(s) => f64::from_str(s.trim()).ok(),
        _ => None,
    }
}

/// How a definition's features become numbers.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Encoder {
    /// The input names, in order (`amount`, `stage=won`, `created_at__month`).
    pub names: Vec<String>,
    /// The categories of each text feature, by its column.
    pub categories: BTreeMap<String, Vec<String>>,
}

impl Encoder {
    /// Learns the inputs from the training rows. Pure.
    pub fn fit(def: &ModelDef, rows: &[Map<String, Value>]) -> Encoder {
        let mut encoder = Encoder::default();
        for feature in &def.features {
            match feature {
                Feature::Time { .. } => {
                    encoder.names.push(crate::model_def::feature_name(feature));
                }
                Feature::Attribute { .. } | Feature::Path { .. } => {
                    let Some(col) = column(feature) else { continue };
                    let numeric = rows
                        .iter()
                        .filter_map(|r| r.get(col))
                        .filter(|v| !v.is_null())
                        .all(|v| number(v).is_some());
                    if numeric {
                        encoder.names.push(col.to_owned());
                    } else {
                        let mut counts: HashMap<String, usize> = HashMap::new();
                        for v in rows.iter().filter_map(|r| r.get(col)) {
                            if let Value::String(s) = v {
                                *counts.entry(s.clone()).or_default() += 1;
                            }
                        }
                        let mut top: Vec<(String, usize)> = counts.into_iter().collect();
                        top.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                        let cats: Vec<String> = top
                            .into_iter()
                            .take(MAX_CATEGORIES)
                            .map(|(c, _)| c)
                            .collect();
                        for c in &cats {
                            encoder.names.push(format!("{col}={c}"));
                        }
                        encoder.categories.insert(col.to_owned(), cats);
                    }
                }
                Feature::Rollup { .. } => {}
            }
        }
        encoder
    }

    /// One row as the model's inputs. Pure apart from the clock.
    pub fn encode(&self, def: &ModelDef, row: &Map<String, Value>) -> Vec<f64> {
        let now = chrono::Utc::now();
        let mut out = Vec::with_capacity(self.names.len());
        for feature in &def.features {
            match feature {
                Feature::Time { time, part } => {
                    let v = row
                        .get(time)
                        .and_then(Value::as_str)
                        .and_then(|s| crate::model_def::time_feature(*part, s, now))
                        .unwrap_or(0.0);
                    out.push(v);
                }
                Feature::Attribute { .. } | Feature::Path { .. } => {
                    let Some(col) = column(feature) else { continue };
                    match self.categories.get(col) {
                        Some(cats) => {
                            let value = row.get(col).and_then(Value::as_str);
                            out.extend(
                                cats.iter()
                                    .map(|c| f64::from(u8::from(value == Some(c.as_str())))),
                            );
                        }
                        None => out.push(row.get(col).and_then(number).unwrap_or(0.0)),
                    }
                }
                Feature::Rollup { .. } => {}
            }
        }
        out
    }
}

/// The three inputs that moved a score most: coefficient times the
/// standardized value (its distance from the training mean). Pure.
pub fn top_factors(artifact: &ModelArtifact, inputs: &[f64]) -> Vec<(String, f64)> {
    let mut factors: Vec<(String, f64)> = artifact
        .feature_order
        .iter()
        .zip(&artifact.coefficients)
        .zip(inputs)
        .map(|((name, coef), z)| (name.clone(), coef * z))
        .collect();
    factors.sort_by(|a, b| b.1.abs().total_cmp(&a.1.abs()));
    factors.truncate(TOP_FACTORS);
    factors
}

/// What a trained definition model keeps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trained {
    pub artifact: ModelArtifact,
    pub encoder: Encoder,
    /// Each input's training mean and spread: inputs are standardized
    /// before the fit and before a score, so amounts in the thousands and
    /// yes/no inputs weigh alike.
    pub means: Vec<f64>,
    pub scales: Vec<f64>,
}

/// `x` standardized by `means` and `scales` (a spread of zero counts as
/// one). Pure.
pub fn standardize(x: &[f64], means: &[f64], scales: &[f64]) -> Vec<f64> {
    x.iter()
        .enumerate()
        .map(|(i, v)| {
            let mean = means.get(i).copied().unwrap_or(0.0);
            let scale = scales.get(i).copied().filter(|s| *s > 1e-12).unwrap_or(1.0);
            (v - mean) / scale
        })
        .collect()
}

/// Reads up to [`MAX_ROWS`] rows of `def` as `ctx`, labelled or not.
async fn read_rows(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    def: &ModelDef,
    labelled_only: bool,
) -> Result<Vec<Map<String, Value>>, AppError> {
    let mut spec = crate::model_def::training_spec(def);
    if !labelled_only {
        spec.r#where = None;
    }
    let mut rows = Vec::new();
    loop {
        let page = match attome_records::query_spec::routes::execute_spec(state, ctx, spec.clone())
            .await?
        {
            attome_records::query_spec::routes::RunResponse::Rows(page) => page,
            _ => return Err(AppError::internal("a training read did not answer rows")),
        };
        rows.extend(page.items.into_iter().map(|row| row.0));
        match page.next_cursor {
            Some(cursor) if rows.len() < MAX_ROWS => spec.cursor = Some(cursor),
            _ => break,
        }
    }
    rows.truncate(MAX_ROWS);
    Ok(rows)
}

type ModelRow = (Option<Value>, Option<Uuid>, i32);

async fn load(state: &EngineState, model: Uuid) -> Result<(ModelDef, Uuid, i32), AppError> {
    let row: Option<ModelRow> = sqlx::query_as(
        "SELECT definition, created_by, trained_version FROM prediction_model \
          WHERE id = $1 AND is_deleted = false",
    )
    .bind(model)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(definition), created_by, version)) = row else {
        return Err(AppError::NotFound);
    };
    let def: ModelDef = serde_json::from_value(definition)
        .map_err(|e| AppError::internal(format!("a stored definition does not read: {e}")))?;
    Ok((def, created_by.unwrap_or(Uuid::nil()), version))
}

async fn finish(
    state: &EngineState,
    model: Uuid,
    status: &str,
    metrics: Value,
    trained: Option<&Trained>,
) -> Result<(), AppError> {
    let artifact = trained
        .map(serde_json::to_value)
        .transpose()
        .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE prediction_model SET status = $2, metrics = $3, \
                model_artifact = COALESCE($4, model_artifact), \
                trained_version = trained_version + CASE WHEN $2 = 'active' THEN 1 ELSE 0 END, \
                updated_at = now(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(model)
    .bind(status)
    .bind(metrics)
    .bind(artifact)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The training job: a definition model trains here, the ticket model in
/// [`crate::train::run`].
pub async fn run(state: &EngineState, model: Uuid) -> Result<(), AppError> {
    let defined: Option<bool> =
        sqlx::query_scalar("SELECT definition IS NOT NULL FROM prediction_model WHERE id = $1")
            .bind(model)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match defined {
        Some(true) => train(state, model).await,
        _ => crate::train::run(&state.base.db, model).await,
    }
}

/// Trains definition model `model`; see the module documentation.
pub async fn train(state: &EngineState, model: Uuid) -> Result<(), AppError> {
    let (def, creator, _) = load(state, model).await?;
    if def.algorithm != crate::model_def::Algorithm::LogisticRegression {
        return finish(
            state,
            model,
            "failed_holdout",
            json!({ "error": "only logistic_regression is trained yet" }),
            None,
        )
        .await;
    }
    if def
        .features
        .iter()
        .any(|f| matches!(f, Feature::Rollup { .. }))
    {
        return finish(
            state,
            model,
            "failed_holdout",
            json!({ "error": "rollup features are not trained yet" }),
            None,
        )
        .await;
    }
    let ctx = attome_security::resolve_uncached(&state.base.db, creator).await?;
    let rows = read_rows(state, &ctx, &def, true).await?;
    let labelled: Vec<(&Map<String, Value>, i32)> = rows
        .iter()
        .filter_map(|r| r.get(&def.target).and_then(label_of).map(|l| (r, l)))
        .collect();
    let positives = labelled.iter().filter(|(_, l)| *l == 1).count();
    let min_rows = def.min_rows() as usize;
    if labelled.len() < min_rows
        || positives < crate::train::MIN_CLASS_SAMPLES
        || labelled.len() - positives < crate::train::MIN_CLASS_SAMPLES
    {
        return finish(
            state,
            model,
            "failed_holdout",
            json!({ "error": "insufficient labeled training data", "rows": labelled.len(),
                    "positives": positives, "min_rows": min_rows }),
            None,
        )
        .await;
    }
    let encoder = Encoder::fit(&def, &rows);
    if encoder.names.is_empty() {
        return finish(
            state,
            model,
            "failed_holdout",
            json!({ "error": "no usable features" }),
            None,
        )
        .await;
    }
    let mut train_x = Vec::new();
    let mut train_y = Vec::new();
    let mut hold: Vec<(Vec<f64>, i32)> = Vec::new();
    for (i, (row, label)) in labelled.iter().enumerate() {
        let x = encoder.encode(&def, row);
        if i % 5 == 0 {
            hold.push((x, *label));
        } else {
            train_x.push(x);
            train_y.push(*label);
        }
    }
    let (means, scales): (Vec<f64>, Vec<f64>) =
        crate::train::feature_profile(&train_x).into_iter().unzip();
    let train_x: Vec<Vec<f64>> = train_x
        .iter()
        .map(|x| standardize(x, &means, &scales))
        .collect();
    let hold: Vec<(Vec<f64>, i32)> = hold
        .into_iter()
        .map(|(x, l)| (standardize(&x, &means, &scales), l))
        .collect();
    let fy = train_y.clone();
    let fitted = tokio::task::spawn_blocking(move || crate::train::fit(&train_x, &fy))
        .await
        .map_err(|e| AppError::internal(format!("training task panicked: {e}")))?;
    let mut artifact = match fitted {
        Ok(a) => a,
        Err(message) => {
            return finish(
                state,
                model,
                "failed_holdout",
                json!({ "error": message }),
                None,
            )
            .await;
        }
    };
    artifact.feature_order = encoder.names.clone();
    let majority = i32::from(train_y.iter().filter(|l| **l == 1).count() * 2 >= train_y.len());
    let scored: Vec<(f64, i32)> = hold
        .iter()
        .map(|(x, l)| (artifact.predict_proba(x), *l))
        .collect();
    let accuracy = scored
        .iter()
        .filter(|(p, l)| i32::from(*p > 0.5) == *l)
        .count() as f64
        / scored.len().max(1) as f64;
    let baseline =
        hold.iter().filter(|(_, l)| *l == majority).count() as f64 / hold.len().max(1) as f64;
    let metrics = json!({
        "rows": labelled.len(), "holdout": hold.len(), "accuracy": accuracy,
        "baseline_accuracy": baseline, "auc": crate::train::auc(&scored),
        "features": encoder.names.len(),
    });
    if accuracy <= baseline {
        return finish(state, model, "failed_holdout", metrics, None).await;
    }
    let trained = Trained {
        artifact,
        encoder,
        means,
        scales,
    };
    finish(state, model, "active", metrics, Some(&trained)).await
}

/// Checks `def` against the metadata (O1-T1's [`crate::model_def::validate`]);
/// the problems as one validation error.
pub fn check(state: &EngineState, def: &ModelDef) -> Result<(), AppError> {
    let registry = state.entities.load();
    let attr_type = |entity: &str, attribute: &str| {
        registry
            .get(entity)
            .and_then(|e| e.attrs.iter().find(|a| a.logicalname == attribute))
            .map(|a| a.field_type())
    };
    crate::model_def::validate(def, attr_type)
        .map_err(|problems| AppError::Validation(problems.join("; ")))
}

/// Scores the rows of definition model `model` that its current version has
/// not scored; how many were scored (O1-T3).
pub async fn score(state: &EngineState, model: Uuid) -> Result<usize, AppError> {
    let (def, creator, version) = load(state, model).await?;
    let artifact: Option<Value> = sqlx::query_scalar(
        "SELECT model_artifact FROM prediction_model WHERE id = $1 AND status = 'active'",
    )
    .bind(model)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let Some(trained) = artifact.and_then(|a| serde_json::from_value::<Trained>(a).ok()) else {
        return Ok(0);
    };
    let ctx = attome_security::resolve_uncached(&state.base.db, creator).await?;
    let rows = read_rows(state, &ctx, &def, false).await?;
    let mut scored = 0;
    for row in &rows {
        let Some(id) = row
            .get("id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        let inputs = standardize(
            &trained.encoder.encode(&def, row),
            &trained.means,
            &trained.scales,
        );
        let p = trained.artifact.predict_proba(&inputs).clamp(0.0, 1.0);
        let factors: Vec<Value> = top_factors(&trained.artifact, &inputs)
            .into_iter()
            .map(|(name, weight)| json!({ "feature": name, "weight": weight }))
            .collect();
        let written = sqlx::query(
            "INSERT INTO prediction (model_ref, regarding_entity, regarding_id, score, label, \
                 explanation, horizon_at) \
             SELECT $1, $2, $3, $4, $5, $6, now() + interval '30 days' \
              WHERE NOT EXISTS (SELECT 1 FROM prediction \
                                 WHERE model_ref = $1 AND regarding_id = $3 \
                                   AND explanation ->> 'version' = $7 AND is_deleted = false)",
        )
        .bind(model)
        .bind(&def.entity)
        .bind(id)
        .bind(p)
        .bind(if p > 0.5 { "likely" } else { "unlikely" })
        .bind(json!({ "top_factors": factors, "version": version.to_string() }))
        .bind(version.to_string())
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if written.rows_affected() == 0 {
            continue;
        }
        scored += 1;
        // The attribute was checked to be a number of this entity when the
        // model was created; both names are quoted identifiers.
        if let Some(attribute) = &def.score_attribute {
            sqlx::query(&format!(
                "UPDATE {} SET {} = $2 WHERE id = $1",
                attome_db::ident::quote_ident(&def.entity),
                attome_db::ident::quote_ident(attribute),
            ))
            .bind(id)
            .bind((p * 100.0).round())
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        }
    }
    Ok(scored)
}

/// Scores every active definition model; how many rows were scored.
pub async fn score_all(state: &EngineState) -> Result<usize, AppError> {
    let models: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM prediction_model WHERE status = 'active' AND definition IS NOT NULL \
           AND is_deleted = false",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut total = 0;
    for model in models {
        match score(state, model).await {
            Ok(n) => total += n,
            Err(error) => tracing::warn!(%model, %error, "definition model not scored"),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def() -> ModelDef {
        serde_json::from_value(json!({
            "entity": "opportunity", "target": "is_won", "algorithm": "logistic_regression",
            "features": [{ "attribute": "amount" }, { "attribute": "stage" }]
        }))
        .unwrap()
    }

    fn row(amount: f64, stage: &str) -> Map<String, Value> {
        json!({ "id": Uuid::now_v7().to_string(), "amount": amount, "stage": stage })
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn labels_read_yes_and_no() {
        assert_eq!(label_of(&json!(true)), Some(1));
        assert_eq!(label_of(&json!(0)), Some(0));
        assert_eq!(label_of(&json!("lost")), Some(0));
        assert_eq!(label_of(&json!("won")), Some(1));
        assert_eq!(label_of(&json!(null)), None);
    }

    #[test]
    fn text_features_are_one_hot() {
        let rows = vec![row(10.0, "a"), row(20.0, "b"), row(30.0, "a")];
        let encoder = Encoder::fit(&def(), &rows);
        assert_eq!(encoder.names, ["amount", "stage=a", "stage=b"]);
        assert_eq!(encoder.encode(&def(), &rows[1]), vec![20.0, 0.0, 1.0]);
    }

    #[test]
    fn standardized_inputs_share_a_scale() {
        assert_eq!(
            standardize(&[12.0, 5.0], &[10.0, 5.0], &[2.0, 0.0]),
            vec![1.0, 0.0]
        );
    }

    #[test]
    fn top_factors_are_the_largest_moves() {
        let artifact = ModelArtifact {
            coefficients: vec![0.1, 2.0, -3.0, 0.0],
            intercept: 0.0,
            feature_order: vec!["a".into(), "b".into(), "c".into(), "d".into()],
        };
        let top = top_factors(&artifact, &[1.0, 1.0, 1.0, 1.0]);
        let names: Vec<&str> = top.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["c", "b", "a"]);
    }
}

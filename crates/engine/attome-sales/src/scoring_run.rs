//! Running points models (roadmap D18-T1): the nightly job that scores
//! every record of each enabled `points_model` and stores the score with
//! its reasons in `points_score` (one row per model and record), so decay
//! moves scores without new activity. [`score_one`] does the same for one
//! record, for callers that rescore on change.
//!
//! A `fit` rule is a rule-language condition over the target record,
//! compiled once per run against the entity's fields; it counts once while
//! true. A `behaviour` rule counts each activity of its `activity_type`
//! about the record, at the time it was completed (or created), and fades
//! with the model's half-life. A rule that does not compile is skipped and
//! logged, never fatal.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::scoring::{Hit, PointsRule, Score, points_score};

/// Records per batch.
pub const BATCH: i64 = 500;

/// A rule as stored.
#[derive(Debug, Clone)]
struct StoredRule {
    rule: PointsRule,
    condition: Option<attome_rules::Compiled>,
    activity_type: Option<String>,
}

#[derive(Debug, Clone)]
struct Model {
    id: Uuid,
    entity: String,
    half_life_days: f64,
    rules: Vec<StoredRule>,
}

type RuleRow = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<f64>,
);

/// What one run did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScoringRun {
    pub models: u64,
    pub records: u64,
}

async fn load_models(state: &EngineState) -> Result<Vec<Model>, AppError> {
    let db = &state.base.db;
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('points_model') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(Vec::new());
    }
    let models: Vec<(Uuid, String, Option<f64>)> = sqlx::query_as(
        "SELECT id, target_entity, half_life_days::float8 FROM points_model \
         WHERE (is_active IS NULL OR is_active = true) AND COALESCE(is_enabled, false) = true",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for (id, entity, half_life) in models {
        // The registry snapshot is read and released before any await.
        let found = {
            let registry = state.entities.load();
            registry.get(entity.trim()).map(|meta| {
                (
                    meta.logicalname.clone(),
                    attome_records::rule_engine::schema_for_entity(&meta.attrs),
                )
            })
        };
        let Some((logicalname, schema)) = found else {
            tracing::warn!(model = %id, entity, "points scoring: unknown target entity");
            continue;
        };
        let rows: Vec<RuleRow> = sqlx::query_as(
            "SELECT rule_key, label, kind, points::float8, condition, activity_type, \
                    max_hits::float8 \
             FROM points_rule WHERE model_id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(id.to_string())
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let mut rules = Vec::new();
        for (key, label, kind, points, condition, activity_type, max_hits) in rows {
            let key = key.unwrap_or_default();
            let behaviour = kind.as_deref() == Some("behaviour");
            let compiled = match condition
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
            {
                Some(src) if !behaviour => match attome_rules::compile(src, &schema) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        tracing::warn!(model = %id, rule = key, error = %e, "points scoring: rule does not compile");
                        continue;
                    }
                },
                _ => None,
            };
            rules.push(StoredRule {
                rule: PointsRule {
                    label: label.unwrap_or_else(|| key.clone()),
                    key,
                    points: points.unwrap_or(0.0),
                    decays: behaviour,
                    max_hits: max_hits.filter(|m| *m >= 1.0).map(|m| m as u32),
                },
                condition: compiled,
                activity_type: if behaviour { activity_type } else { None },
            });
        }
        out.push(Model {
            id,
            entity: logicalname,
            half_life_days: half_life.filter(|h| *h > 0.0).unwrap_or(30.0),
            rules,
        });
    }
    Ok(out)
}

/// The hits of one record.
fn fit_hits(
    model: &Model,
    attrs: &[attome_core::AttrInfo],
    record: &Map<String, Value>,
    now: DateTime<Utc>,
) -> Vec<Hit> {
    let ctx = attome_records::rule_engine::context_for_record(now, attrs, record);
    model
        .rules
        .iter()
        .filter_map(|r| {
            let compiled = r.condition.as_ref()?;
            matches!(compiled.eval(&ctx), Ok(attome_rules::Value::Bool(true))).then(|| Hit {
                rule_key: r.rule.key.clone(),
                at: now,
            })
        })
        .collect()
}

async fn store(
    state: &EngineState,
    model: &Model,
    record: Uuid,
    score: &Score,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let reasons: Vec<Value> = score
        .reasons
        .iter()
        .map(|r| {
            serde_json::json!({
                "rule": r.rule_key, "label": r.label, "hits": r.hits, "points": r.points
            })
        })
        .collect();
    let reasons = Value::Array(reasons).to_string();
    let db = &state.base.db;
    let updated = sqlx::query(
        "UPDATE points_score SET score = $3, reasons = $4, computed_at = $5, modified_at = now(), \
         row_version = row_version + 1 \
         WHERE model_id = $1 AND record_id = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(model.id.to_string())
    .bind(record.to_string())
    .bind(score.score as f64)
    .bind(&reasons)
    .bind(now)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        sqlx::query(
            "INSERT INTO points_score (model_id, record_id, entity_name, score, reasons, computed_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(model.id.to_string())
        .bind(record.to_string())
        .bind(&model.entity)
        .bind(score.score as f64)
        .bind(&reasons)
        .bind(now)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

async fn score_batch(
    state: &EngineState,
    model: &Model,
    attrs: &[attome_core::AttrInfo],
    records: Vec<(Uuid, Value)>,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let types: Vec<String> = model
        .rules
        .iter()
        .filter_map(|r| r.activity_type.clone())
        .collect();
    let ids: Vec<String> = records.iter().map(|(id, _)| id.to_string()).collect();
    let mut behaviour: HashMap<String, Vec<(String, DateTime<Utc>)>> = HashMap::new();
    if !types.is_empty() {
        let rows: Vec<(String, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT record_id, activity_type, COALESCE(completed_at, created_at) FROM activity \
             WHERE entity_name = $1 AND record_id = ANY($2) AND activity_type = ANY($3) \
               AND (is_active IS NULL OR is_active = true)",
        )
        .bind(&model.entity)
        .bind(&ids)
        .bind(&types)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        for (record, kind, at) in rows {
            behaviour.entry(record).or_default().push((kind, at));
        }
    }
    let rules: Vec<PointsRule> = model.rules.iter().map(|r| r.rule.clone()).collect();
    let mut scored = 0;
    for (id, data) in records {
        let Value::Object(obj) = data else { continue };
        let mut hits = fit_hits(model, attrs, &obj, now);
        for (kind, at) in behaviour
            .get(&id.to_string())
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            for rule in model
                .rules
                .iter()
                .filter(|r| r.activity_type.as_deref() == Some(kind))
            {
                hits.push(Hit {
                    rule_key: rule.rule.key.clone(),
                    at: *at,
                });
            }
        }
        let score = points_score(&rules, &hits, now, model.half_life_days);
        store(state, model, id, &score, now).await?;
        scored += 1;
    }
    Ok(scored)
}

/// Scores every record of every enabled model.
pub async fn run(state: &EngineState, now: DateTime<Utc>) -> Result<ScoringRun, AppError> {
    let mut out = ScoringRun::default();
    for model in load_models(state).await? {
        out.models += 1;
        let found = {
            let registry = state.entities.load();
            registry.get(&model.entity).map(|meta| {
                (
                    meta.attrs.clone(),
                    attome_core::quote_ident(&meta.logicalname),
                    attome_core::sql_ident::live_row_predicate("t", meta.is_append_only)
                        .map(|p| format!(" AND {p}"))
                        .unwrap_or_default(),
                )
            })
        };
        let Some((attrs, table, live)) = found else {
            continue;
        };
        let mut after = Uuid::nil();
        loop {
            let rows: Vec<(Uuid, Value)> = sqlx::query_as(&format!(
                "SELECT t.id, to_jsonb(t) FROM {table} t WHERE t.id > $1{live} ORDER BY t.id LIMIT $2"
            ))
            .bind(after)
            .bind(BATCH)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let Some(last) = rows.last() else { break };
            after = last.0;
            let full = rows.len() as i64 == BATCH;
            out.records += score_batch(state, &model, &attrs, rows, now).await?;
            if !full {
                break;
            }
        }
    }
    Ok(out)
}

/// Rescores one record under every enabled model for its entity.
pub async fn score_one(
    state: &EngineState,
    entity: &str,
    record: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let mut scored = 0;
    for model in load_models(state).await? {
        if model.entity != entity {
            continue;
        }
        let found = {
            let registry = state.entities.load();
            registry.get(entity).map(|meta| {
                (
                    meta.attrs.clone(),
                    attome_core::quote_ident(&meta.logicalname),
                )
            })
        };
        let Some((attrs, table)) = found else {
            continue;
        };
        let row: Option<(Uuid, Value)> = sqlx::query_as(&format!(
            "SELECT t.id, to_jsonb(t) FROM {table} t WHERE t.id = $1"
        ))
        .bind(record)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if let Some(row) = row {
            scored += score_batch(state, &model, &attrs, vec![row], now).await?;
        }
    }
    Ok(scored)
}

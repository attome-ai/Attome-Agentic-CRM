//! L2-T3: data quality scored as records change, instead of a daily full
//! sweep.
//!
//! - **Incremental** ([`tick`], `EngineJob::QualityIncrementalSweep`, every
//!   minute): reads the change feed from its own cursor ([`CONSUMER`]) in
//!   batches of [`BATCH`]. For each entity whose records changed it scores
//!   those records (`quality_record_score`, only when the entity's
//!   `quality_target.record_scoring` is on; a deleted or purged record's
//!   score is removed) and always recomputes the entity's dimension scores
//!   (`crate::quality_score::score_entity`), within the issue caps
//!   ([`caps`]). Work never joins a record's save transaction: it runs after
//!   the commit, off the feed.
//! - **Rescan** ([`rescan_step`], `EngineJob::QualityRescan`): when an
//!   entity's rules, weights, threshold, required attributes or record
//!   scoring change (a [`fingerprint`] differs from the one kept in
//!   `quality_rescan_state`, migration 0234), every record is rescored in
//!   keyset batches of [`RESCAN_BATCH`], one batch per job; the job carries
//!   the last id it reached, so a restart resumes there, and the next batch
//!   is a new job. The first tick on a deployment rescans every entity once.
//! - **Daily** (`EngineJob::DataQualityScoreSweep`): writes the day's
//!   snapshot and alerts only (`crate::quality_score::run_snapshot`), and
//!   queues a rescan of the entities with a timeliness target, whose scores
//!   age without any change.
//!
//! The change feed keeps an internal consumer's events for a month
//! (`attome_core::change_feed::INTERNAL_MAX_LAG_HOURS`); a cursor that fell
//! further behind is expired and the next fingerprint pass rescans.

use std::collections::{BTreeMap, HashMap};

use attome_core::change_feed::{self, ChangeOperation};
use attome_core::{EngineState, EntityMeta, quote_ident};
use attome_db::DbPool;
use attome_types::AppError;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "quality/incremental";
/// Change events read per tick.
pub const BATCH: i64 = 500;
/// Records rescored per rescan job.
pub const RESCAN_BATCH: i64 = 500;

/// The settings for the issue caps.
pub const MAX_ISSUES_PER_RUN_SETTING: &str = "quality.max_issues_per_run";
pub const MAX_ISSUES_PER_ENTITY_SETTING: &str = "quality.max_issues_per_entity";

/// The issue rows one run, and one entity within it, may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    pub per_run: i64,
    pub per_entity: i64,
}

/// The issue caps the settings give (defaults 2,000 and 200).
pub fn caps(state: &EngineState) -> Caps {
    let read = |key: &str, default: i64| {
        attome_core::setting_registry()
            .get(key)
            .map(|d| state.settings.load().resolve(d, None, None).0)
            .and_then(|v| v.as_i64())
            .filter(|n| *n >= 0)
            .unwrap_or(default)
    };
    Caps {
        per_run: read(
            MAX_ISSUES_PER_RUN_SETTING,
            crate::quality_score::MAX_ISSUES_PER_RUN,
        ),
        per_entity: read(
            MAX_ISSUES_PER_ENTITY_SETTING,
            crate::quality_score::MAX_ISSUES_PER_ENTITY,
        ),
    }
}

/// One record's score: the share of its checks it passes (each required
/// attribute filled, each enabled rule held), with a finding per failed
/// check; `None` when the entity has no check. Pure.
pub fn record_score(
    required: &[String],
    rules: &[(Uuid, String)],
    record: &Value,
) -> Option<(f64, Vec<Value>)> {
    let checks = required.len() + rules.len();
    if checks == 0 {
        return None;
    }
    let mut findings = Vec::new();
    for field in required {
        let filled = match record.get(field) {
            None | Some(Value::Null) => false,
            Some(Value::String(s)) => !s.trim().is_empty(),
            Some(_) => true,
        };
        if !filled {
            findings.push(json!({ "check": "required", "field": field }));
        }
    }
    for (id, expression) in rules {
        if !crate::quality::dimensions::rule_holds(expression, record) {
            findings.push(json!({ "check": "rule", "rule_id": id }));
        }
    }
    let passed = checks - findings.len();
    Some((passed as f64 / checks as f64 * 100.0, findings))
}

/// What an entity's scores depend on, as one hash: its required
/// attributes, enabled rules, weights, threshold, timeliness target and
/// record scoring. Pure.
pub fn fingerprint(
    required: &[String],
    rules: &[(Uuid, String, String)],
    target: Option<&(Value, f64, Option<i32>, bool)>,
) -> String {
    let mut required = required.to_vec();
    required.sort();
    let mut rules = rules.to_vec();
    rules.sort();
    let canonical = json!({
        "required": required,
        "rules": rules.iter().map(|(id, dimension, expression)| json!([id, dimension, expression])).collect::<Vec<_>>(),
        "target": target.map(|(weights, threshold, timeliness, record_scoring)| {
            json!([sorted(weights), threshold, timeliness, record_scoring])
        }),
    });
    hex::encode(Sha256::digest(canonical.to_string().as_bytes()))
}

fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let ordered: BTreeMap<&String, Value> =
                map.iter().map(|(k, v)| (k, sorted(v))).collect();
            json!(ordered)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// An entity's required attributes.
fn required_of(meta: &EntityMeta) -> Vec<String> {
    meta.attrs
        .iter()
        .filter(|a| a.is_required)
        .map(|a| a.logicalname.clone())
        .collect()
}

async fn rules_of(db: &DbPool, entity: &str) -> Result<Vec<(Uuid, String)>, AppError> {
    sqlx::query_as(
        "SELECT id, expression FROM quality_rule \
          WHERE entity = $1 AND enabled AND dimension IN ('validity', 'consistency') \
          ORDER BY id",
    )
    .bind(entity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

async fn record_scoring_on(db: &DbPool, entity: &str) -> Result<bool, AppError> {
    Ok(
        sqlx::query_scalar::<_, bool>(
            "SELECT record_scoring FROM quality_target WHERE entity = $1",
        )
        .bind(entity)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?
        .unwrap_or(false),
    )
}

/// Scores `ids` of `meta`'s entity; how many were scored. A record no longer
/// live loses its score.
async fn score_records(db: &DbPool, meta: &EntityMeta, ids: &[Uuid]) -> Result<usize, AppError> {
    if ids.is_empty() {
        return Ok(0);
    }
    let required = required_of(meta);
    let rules = rules_of(db, &meta.logicalname).await?;
    let rows: Vec<(Uuid, Value)> = sqlx::query_as(&format!(
        "SELECT t.id, row_to_json(t)::jsonb FROM {table} t WHERE t.id = ANY($1)",
        table = quote_ident(&meta.logicalname)
    ))
    .bind(ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut scored = 0;
    let mut gone: Vec<Uuid> = ids.to_vec();
    for (id, record) in &rows {
        if record.get("is_active").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        gone.retain(|g| g != id);
        let Some((score, findings)) = record_score(&required, &rules, record) else {
            continue;
        };
        sqlx::query(
            "INSERT INTO quality_record_score (entity, record_id, score, findings, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (entity, record_id) DO UPDATE \
                SET score = EXCLUDED.score, findings = EXCLUDED.findings, updated_at = now()",
        )
        .bind(&meta.logicalname)
        .bind(id)
        .bind(score)
        .bind(Value::Array(findings))
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        scored += 1;
    }
    forget(db, &meta.logicalname, &gone).await?;
    Ok(scored)
}

async fn forget(db: &DbPool, entity: &str, ids: &[Uuid]) -> Result<(), AppError> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query("DELETE FROM quality_record_score WHERE entity = $1 AND record_id = ANY($2)")
        .bind(entity)
        .bind(ids)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// What one tick did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickStats {
    pub events: usize,
    pub records_scored: usize,
    pub entities_aggregated: usize,
    pub rescans_queued: usize,
}

/// One incremental pass over the change feed, then the fingerprint check.
pub async fn tick(state: &EngineState) -> Result<TickStats, AppError> {
    let mut stats = TickStats::default();
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    if let Some(last) = events.last().cloned() {
        stats.events = events.len();
        let mut changed: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
        let mut removed: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
        for e in &events {
            match e.operation() {
                Some(ChangeOperation::Delete | ChangeOperation::Purge) => removed
                    .entry(e.entity_logicalname.clone())
                    .or_default()
                    .push(e.record_id),
                Some(_) if e.event_name.is_none() => changed
                    .entry(e.entity_logicalname.clone())
                    .or_default()
                    .push(e.record_id),
                _ => {}
            }
        }
        let caps = caps(state);
        let mut budget = caps.per_run;
        let period = crate::quality_score::today_period();
        let touched: Vec<String> = changed.keys().chain(removed.keys()).cloned().collect();
        let mut seen = std::collections::BTreeSet::new();
        for entity in touched {
            if !seen.insert(entity.clone()) {
                continue;
            }
            let Some(meta) = state.entities.load().get(&entity).cloned() else {
                continue;
            };
            let db = &state.base.db;
            if let Some(ids) = removed.get(&entity) {
                forget(db, &entity, ids).await?;
            }
            if let Some(ids) = changed.get_mut(&entity) {
                ids.sort();
                ids.dedup();
                if record_scoring_on(db, &entity).await? {
                    stats.records_scored += score_records(db, &meta, ids).await?;
                }
            }
            match crate::quality_score::score_entity(
                db,
                &meta,
                &period,
                budget.clamp(0, caps.per_entity),
            )
            .await
            {
                Ok(outcome) => {
                    budget = (budget - outcome.issues_written).max(0);
                    stats.entities_aggregated += 1;
                }
                Err(e) => {
                    tracing::warn!(%entity, error = %e, "quality incremental: entity scoring failed");
                }
            }
        }
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::advance(&mut conn, CONSUMER, &last).await?;
    }
    stats.rescans_queued = queue_changed(state).await?;
    Ok(stats)
}

/// Queues a rescan of every entity whose fingerprint changed (every entity,
/// the first time); how many were queued.
pub async fn queue_changed(state: &EngineState) -> Result<usize, AppError> {
    let db = &state.base.db;
    let rules: Vec<(String, Uuid, String, String)> =
        sqlx::query_as("SELECT entity, id, dimension, expression FROM quality_rule WHERE enabled")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
    let targets: Vec<(String, Value, f64, Option<i32>, bool)> = sqlx::query_as(
        "SELECT entity, dimension_weights, threshold::float8, timeliness_days, record_scoring \
           FROM quality_target",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let kept: HashMap<String, String> =
        sqlx::query_as("SELECT entity, fingerprint FROM quality_rescan_state")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
    let mut rules_by: HashMap<&str, Vec<(Uuid, String, String)>> = HashMap::new();
    for (entity, id, dimension, expression) in &rules {
        rules_by.entry(entity.as_str()).or_default().push((
            *id,
            dimension.clone(),
            expression.clone(),
        ));
    }
    let targets_by: HashMap<&str, (Value, f64, Option<i32>, bool)> = targets
        .iter()
        .map(|(e, w, t, d, r)| (e.as_str(), (w.clone(), *t, *d, *r)))
        .collect();
    let entities: Vec<EntityMeta> = state.entities.load().iter().cloned().collect();
    let mut queued = 0;
    for meta in &entities {
        let name = meta.logicalname.as_str();
        let print = fingerprint(
            &required_of(meta),
            rules_by.get(name).map(Vec::as_slice).unwrap_or(&[]),
            targets_by.get(name),
        );
        if kept.get(name) == Some(&print) {
            continue;
        }
        if enqueue_rescan(db, name, None).await? {
            queued += 1;
        }
        sqlx::query(
            "INSERT INTO quality_rescan_state (entity, fingerprint, queued_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (entity) DO UPDATE SET fingerprint = EXCLUDED.fingerprint, \
                 queued_at = now(), finished_at = NULL",
        )
        .bind(name)
        .bind(&print)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(queued)
}

/// Queues the rescan batch of `entity` after `after`.
pub async fn enqueue_rescan(
    db: &DbPool,
    entity: &str,
    after: Option<Uuid>,
) -> Result<bool, AppError> {
    let key = format!(
        "quality-rescan:{entity}:{}",
        after.map_or_else(|| "start".to_owned(), |a| a.to_string())
    );
    attome_jobs::enqueue_dedup(
        db,
        attome_core::jobs::EngineJob::QualityRescan {
            entity: entity.to_owned(),
            after,
        },
        &key,
    )
    .await
    .map_err(AppError::internal)
}

/// One rescan batch of `entity` after `after`: the next cursor, or `None`
/// when the entity is done (its dimension scores are then recomputed).
pub async fn rescan_step(
    state: &EngineState,
    entity: &str,
    after: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let Some(meta) = state.entities.load().get(entity).cloned() else {
        return Ok(None);
    };
    let db = &state.base.db;
    let next = if record_scoring_on(db, entity).await? {
        let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {table} WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2",
            table = quote_ident(entity)
        ))
        .bind(after)
        .bind(RESCAN_BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        score_records(db, &meta, &ids).await?;
        (ids.len() as i64 == RESCAN_BATCH)
            .then(|| ids.last().copied())
            .flatten()
    } else {
        None
    };
    if let Some(next) = next {
        enqueue_rescan(db, entity, Some(next)).await?;
        return Ok(Some(next));
    }
    let caps = caps(state);
    crate::quality_score::score_entity(
        db,
        &meta,
        &crate::quality_score::today_period(),
        caps.per_entity.min(caps.per_run),
    )
    .await?;
    sqlx::query("UPDATE quality_rescan_state SET finished_at = now() WHERE entity = $1")
        .bind(entity)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_record_score_counts_required_and_rules() {
        let required = vec!["name".to_owned(), "email".to_owned()];
        let rules = vec![(Uuid::nil(), "amount >= 0".to_owned())];
        let (score, findings) = record_score(
            &required,
            &rules,
            &json!({"name": "Acme", "email": " ", "amount": 5}),
        )
        .unwrap();
        assert!((score - 200.0 / 3.0).abs() < 1e-9, "{score}");
        assert_eq!(
            findings,
            vec![json!({"check": "required", "field": "email"})]
        );
        assert!(record_score(&[], &[], &json!({})).is_none());
    }

    #[test]
    fn quality_fingerprint_changes_with_rules_and_weights_only() {
        let rule = (Uuid::nil(), "validity".to_owned(), "amount >= 0".to_owned());
        let target = (json!({"validity": 2, "completeness": 1}), 70.0, None, false);
        let a = fingerprint(
            &["b".into(), "a".into()],
            std::slice::from_ref(&rule),
            Some(&target),
        );
        let reordered = (json!({"completeness": 1, "validity": 2}), 70.0, None, false);
        assert_eq!(
            a,
            fingerprint(
                &["a".into(), "b".into()],
                std::slice::from_ref(&rule),
                Some(&reordered)
            ),
            "order does not matter"
        );
        let heavier = (json!({"validity": 3, "completeness": 1}), 70.0, None, false);
        assert_ne!(
            a,
            fingerprint(
                &["a".into(), "b".into()],
                std::slice::from_ref(&rule),
                Some(&heavier)
            )
        );
        let other_rule = (Uuid::nil(), "validity".to_owned(), "amount > 0".to_owned());
        assert_ne!(
            a,
            fingerprint(&["a".into(), "b".into()], &[other_rule], Some(&target))
        );
    }
}

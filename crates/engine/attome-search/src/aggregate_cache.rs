//! AA11-T1: the aggregate cache. A dashboard definition marked `cache`
//! (`attome_core::data_definition::CachePolicy`) keeps its group-by result
//! in `aggregate_cache` (migration 0331) and answers from it while it is
//! fresh, so a dashboard read does not scan the entity again.
//!
//! **Permission-safe by construction.** The key is a hash of the definition,
//! the exact statement [`crate::aggregate::run_structured_aggregate`] would
//! run (the caller's record filter, RLS and field checks are part of it) and
//! every value bound to it. Two callers share an entry only when they would
//! run the same statement with the same values, so the result is the same.
//! Per-user scopes (own, team, unit) bind the user's own ids and so never
//! share. A caller with condition grants never uses the cache (the plan's
//! rule: role-level security only). Lookup bucket labels are not cached:
//! they are read for each caller, under the caller's access to the target.
//!
//! **Freshness.** `on_change`: an entry is used while it is younger than
//! `max_age_seconds` and the change feed has not marked its entity changed
//! since it was computed; the `aggregate_cache_marks` job ([`mark_changes`])
//! marks entities every 30 seconds, so a change is seen within that. Under
//! `scheduled`, only the age counts.
//!
//! | source of truth | the entity's table; an entry is a copy of one statement's result |
//! | key             | `sha256(definition, timezone, statement, bound values)` |
//! | expiry          | `max_age_seconds` (60-86,400); entries older than a day are deleted by the marking job |
//! | invalidation    | the per-entity change mark |
//! | failure         | a read or write of the cache that fails is logged and the aggregate runs live |
//! | cold start      | the first read computes and stores |

use attome_core::EngineState;
use attome_core::data_definition::{CachePolicy, CacheRefresh, DataDefinition};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::aggregate::StructuredBucket;

/// The change-feed consumer that marks changed entities.
pub const CONSUMER: &str = "attome-search/aggregate-cache";
/// The registered job that runs [`mark_changes`].
pub const JOB: &str = "aggregate_cache_marks";
/// Change events read per run.
const BATCH: i64 = 1_000;
/// Entries older than this are deleted by [`mark_changes`].
const RETAIN_HOURS: i32 = 24;

/// What a cached entry holds: the computed rows, before per-caller labels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAggregate {
    pub buckets: Vec<StructuredBucket>,
    pub other: Option<StructuredBucket>,
    pub truncated: bool,
    pub as_of: DateTime<Utc>,
}

/// The cache key of one statement. Pure.
pub fn cache_key(
    definition: &DataDefinition,
    timezone: &str,
    sql: &str,
    params: &[String],
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        serde_json::to_string(definition)
            .unwrap_or_default()
            .as_str(),
        timezone,
        sql,
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0u8]);
    }
    for param in params {
        hasher.update(param.as_bytes());
        hasher.update([0u8]);
    }
    format!("{:x}", hasher.finalize())
}

/// Whether `ctx` may use the cache at all: no condition grants.
pub fn usable_by(ctx: &attome_server::security::SecurityContext) -> bool {
    ctx.condition_grants.is_empty()
}

/// The fresh entry under `key`, if any; counts the hit. A failure is
/// logged and reads as a miss.
pub async fn get(state: &EngineState, key: &str, policy: &CachePolicy) -> Option<CachedAggregate> {
    let scheduled = policy.refresh == CacheRefresh::Scheduled;
    let found: Result<Option<serde_json::Value>, sqlx::Error> = sqlx::query_scalar(
        "UPDATE aggregate_cache c SET hits = c.hits + 1 \
          WHERE c.cache_key = $1 \
            AND c.computed_at > now() - make_interval(secs => $2::double precision) \
            AND ($3 OR NOT EXISTS (SELECT 1 FROM aggregate_cache_mark m \
                                    WHERE m.entity_logicalname = c.entity_logicalname \
                                      AND m.changed_at >= c.computed_at)) \
          RETURNING c.result",
    )
    .bind(key)
    .bind(f64::from(policy.max_age_seconds))
    .bind(scheduled)
    .fetch_optional(&state.base.db)
    .await;
    match found {
        Ok(Some(value)) => match serde_json::from_value(value) {
            Ok(hit) => {
                metrics::counter!("aggregate_cache_total", "outcome" => "hit").increment(1);
                Some(hit)
            }
            Err(error) => {
                tracing::warn!(%error, "aggregate cache: an entry no longer decodes; computing live");
                None
            }
        },
        Ok(None) => {
            metrics::counter!("aggregate_cache_total", "outcome" => "miss").increment(1);
            None
        }
        Err(error) => {
            tracing::warn!(%error, "aggregate cache: read failed; computing live");
            None
        }
    }
}

/// Stores `value` under `key`. A failure is logged; the caller already has
/// its answer.
pub async fn put(state: &EngineState, key: &str, entity: &str, value: &CachedAggregate) {
    let Ok(result) = serde_json::to_value(value) else {
        return;
    };
    if let Err(error) = sqlx::query(
        "INSERT INTO aggregate_cache (cache_key, entity_logicalname, result, computed_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (cache_key) DO UPDATE \
            SET result = EXCLUDED.result, computed_at = EXCLUDED.computed_at, hits = 0, \
                entity_logicalname = EXCLUDED.entity_logicalname",
    )
    .bind(key)
    .bind(entity)
    .bind(result)
    .bind(value.as_of)
    .execute(&state.base.db)
    .await
    {
        tracing::warn!(%error, entity, "aggregate cache: write failed; the next read computes again");
    }
}

/// The `aggregate_cache_marks` job: marks every entity the change feed saw
/// change since the last run, and deletes entries older than a day.
/// Returns how many entities were marked.
pub async fn mark_changes(state: &EngineState) -> Result<usize, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let mut entities: Vec<String> = events
        .iter()
        .map(|e| e.entity_logicalname.clone())
        .collect();
    entities.sort();
    entities.dedup();
    if !entities.is_empty() {
        sqlx::query(
            "INSERT INTO aggregate_cache_mark (entity_logicalname, changed_at) \
             SELECT e, now() FROM unnest($1::text[]) AS e \
             ON CONFLICT (entity_logicalname) DO UPDATE SET changed_at = EXCLUDED.changed_at",
        )
        .bind(&entities)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query(
        "DELETE FROM aggregate_cache WHERE computed_at < now() - make_interval(hours => $1)",
    )
    .bind(RETAIN_HOURS)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(last) = events.last() {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::advance(&mut conn, CONSUMER, last).await?;
    }
    Ok(entities.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn definition(raw: serde_json::Value) -> DataDefinition {
        serde_json::from_value(raw).expect("a data definition")
    }

    #[test]
    fn aggregates_key_is_the_statement_and_its_values() {
        let d = definition(json!({
            "source": "deal", "measures": [{"aggregation": "count"}],
            "cache": {"refresh": "on_change", "max_age_seconds": 300}
        }));
        let sql = "SELECT count(*) AS m0 FROM deal t WHERE t.owner_ref = $1";
        let me = cache_key(&d, "UTC", sql, &["u1".to_owned()]);
        assert_eq!(me, cache_key(&d, "UTC", sql, &["u1".to_owned()]));
        // Another user's own-records filter binds another id: another entry.
        assert_ne!(me, cache_key(&d, "UTC", sql, &["u2".to_owned()]));
        // Another statement (a wider scope) or zone: another entry.
        assert_ne!(
            me,
            cache_key(&d, "UTC", "SELECT count(*) AS m0 FROM deal t", &[])
        );
        assert_ne!(me, cache_key(&d, "Asia/Riyadh", sql, &["u1".to_owned()]));
        // Values never run together: ("ab", "c") is not ("a", "bc").
        assert_ne!(
            cache_key(&d, "UTC", sql, &["ab".to_owned(), "c".to_owned()]),
            cache_key(&d, "UTC", sql, &["a".to_owned(), "bc".to_owned()])
        );
    }

    #[test]
    fn aggregates_policy_bounds_are_checked() {
        let ok = definition(json!({
            "source": "deal", "measures": [{"aggregation": "count"}],
            "cache": {"max_age_seconds": 60}
        }));
        assert!(ok.validate_shape().is_ok());
        assert_eq!(ok.cache.map(|c| c.refresh), Some(CacheRefresh::OnChange));
        for bad in [59, 86_401] {
            let d = definition(json!({
                "source": "deal", "measures": [{"aggregation": "count"}],
                "cache": {"refresh": "scheduled", "max_age_seconds": bad}
            }));
            assert!(d.validate_shape().is_err(), "{bad}");
        }
    }

    #[test]
    fn aggregates_round_trip_through_json() {
        let cached = CachedAggregate {
            buckets: Vec::new(),
            other: None,
            truncated: true,
            as_of: Utc::now(),
        };
        let back: CachedAggregate =
            serde_json::from_value(serde_json::to_value(&cached).unwrap()).unwrap();
        assert!(back.truncated);
        assert_eq!(back.as_of, cached.as_of);
    }
}

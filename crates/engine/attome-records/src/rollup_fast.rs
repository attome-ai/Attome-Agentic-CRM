//! Rollup fast mode (roadmap A10-T2): a change-feed consumer recomputes the
//! rollups a related record's change affects, a few seconds after it.
//!
//! Each tick reads a batch of change events ([`CONSUMER`]'s cursor, Y7-T4:
//! read, process, then advance, so a crash re-reads the batch and the
//! recompute is idempotent). For every `fast` rollup whose path passes
//! through an event's entity, the changed record is followed up the path to
//! the rollup's own records: by its lookup's current value, and also by the
//! value before the change (the event's `before`), so a record moved to
//! another parent updates both. Each affected parent is then recomputed
//! with one aggregate statement per rollup and batch
//! ([`attome_core::rollup::recompute_sql`]).
//!
//! The value is written straight to the parent's column: it is the
//! platform's own computed value, so it neither bumps the row version (an
//! edit in progress is not made stale) nor emits a change event.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use attome_core::rollup::{RollupMode, RollupOptions};
use attome_core::{EngineState, EntityMetaRegistry, quote_ident};
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-records/rollup-fast";
/// The registered job.
pub const JOB: &str = "rollup_fast";
/// Events read per tick.
const BATCH: i64 = 1_000;
/// Parents recomputed per statement.
const PARENTS_PER_STATEMENT: usize = 500;

/// One fast rollup: its entity, its field and its definition.
#[derive(Debug, Clone)]
struct Rollup {
    entity: String,
    field: String,
    opts: RollupOptions,
}

/// Every `fast` rollup the registry holds. Pure.
fn fast_rollups(registry: &EntityMetaRegistry) -> Vec<Rollup> {
    let mut out = Vec::new();
    for meta in registry.iter() {
        for attr in meta.attrs.iter().filter(|a| a.is_rollup()) {
            let Ok(opts) = attome_core::rollup::parse_options(attr.options.as_ref()) else {
                continue;
            };
            if opts.mode == RollupMode::Fast {
                out.push(Rollup {
                    entity: meta.logicalname.clone(),
                    field: attr.logicalname.clone(),
                    opts,
                });
            }
        }
    }
    out
}

/// The levels of `rollup`'s path an event on `entity` starts at. Pure.
fn levels_of(rollup: &Rollup, entity: &str) -> Vec<usize> {
    rollup
        .opts
        .path
        .iter()
        .enumerate()
        .filter(|(_, step)| step.entity == entity)
        .map(|(i, _)| i)
        .collect()
}

/// A lookup's value in a `before` object, when it names a record. Pure.
fn before_ref(before: Option<&Value>, via: &str) -> Option<Uuid> {
    before?
        .get(via)?
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// The records of `table` that `ids` point at through `via` (deleted rows
/// included: a deleted child still names its parent).
async fn parents_of(
    state: &EngineState,
    table: &str,
    via: &str,
    ids: &BTreeSet<Uuid>,
) -> Result<BTreeSet<Uuid>, AppError> {
    if ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let ids: Vec<Uuid> = ids.iter().copied().collect();
    let sql = format!(
        "SELECT DISTINCT {} FROM {} WHERE id = ANY($1) AND {} IS NOT NULL",
        quote_ident(via),
        quote_ident(table),
        quote_ident(via),
    );
    let sql = attome_db::tag_dynamic("rollup.fast_parents", &sql);
    let rows: Vec<(Uuid,)> = sqlx::query_as(&sql)
        .bind(&ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// Recomputes `rollup` for `parents`, in batches. How many were written.
pub(crate) async fn recompute(
    state: &EngineState,
    registry: &EntityMetaRegistry,
    entity: &str,
    field: &str,
    opts: &RollupOptions,
    parents: &BTreeSet<Uuid>,
) -> Result<u64, AppError> {
    let last = opts
        .path
        .last()
        .and_then(|step| registry.get(&step.entity))
        .map(|m| m.attrs.as_slice())
        .unwrap_or_default();
    let (sql, binds) = attome_core::rollup::recompute_sql(entity, field, opts, last)?;
    let sql = attome_db::tag_dynamic("rollup.recompute", &sql);
    let ids: Vec<Uuid> = parents.iter().copied().collect();
    let mut written = 0;
    for chunk in ids.chunks(PARENTS_PER_STATEMENT) {
        let mut query = sqlx::query(&sql).bind(chunk);
        for bind in &binds {
            query = query.bind(bind);
        }
        written += query
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
    }
    Ok(written)
}

/// One tick: reads a batch of events, recomputes what they affect and
/// advances the cursor. How many events were read (fewer than the batch
/// means the consumer has caught up).
pub async fn tick(state: &EngineState) -> Result<usize, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last_event) = events.last() else {
        return Ok(0);
    };
    let registry = std::sync::Arc::clone(&state.entities.load());
    let rollups = fast_rollups(&registry);
    if !rollups.is_empty() {
        let watched: BTreeSet<&str> = rollups
            .iter()
            .flat_map(|r| r.opts.path.iter().map(|s| s.entity.as_str()))
            .collect();
        let relevant: Vec<_> = events
            .iter()
            .filter(|e| watched.contains(e.entity_logicalname.as_str()))
            .collect();
        // The values before each change, for a record moved to another parent.
        let event_ids: Vec<Uuid> = relevant.iter().map(|e| e.id).collect();
        let before: HashMap<Uuid, Value> = if event_ids.is_empty() {
            HashMap::new()
        } else {
            sqlx::query_as::<_, (Uuid, Option<Value>)>(
                "SELECT id, before FROM entity_change_event WHERE id = ANY($1)",
            )
            .bind(&event_ids)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .filter_map(|(id, before)| before.map(|b| (id, b)))
            .collect()
        };
        for rollup in &rollups {
            // Changed records at each level of the path, and the parents the
            // values before the change named at the level above.
            let depth = rollup.opts.path.len();
            let mut changed: BTreeMap<usize, BTreeSet<Uuid>> = BTreeMap::new();
            let mut moved_from: BTreeMap<usize, BTreeSet<Uuid>> = BTreeMap::new();
            for event in &relevant {
                for level in levels_of(rollup, &event.entity_logicalname) {
                    changed.entry(level).or_default().insert(event.record_id);
                    let via = &rollup.opts.path[level].via;
                    if let Some(old) = before_ref(before.get(&event.id), via) {
                        moved_from.entry(level).or_default().insert(old);
                    }
                }
            }
            if changed.is_empty() {
                continue;
            }
            // Walk up from the deepest level: each level's records name the
            // records one level up.
            let mut carried: BTreeSet<Uuid> = BTreeSet::new();
            for level in (0..depth).rev() {
                let mut here = std::mem::take(&mut carried);
                here.extend(changed.remove(&level).unwrap_or_default());
                let step = &rollup.opts.path[level];
                let mut up = parents_of(state, &step.entity, &step.via, &here).await?;
                up.extend(moved_from.remove(&level).unwrap_or_default());
                carried = up;
            }
            if carried.is_empty() {
                continue;
            }
            let written = recompute(
                state,
                &registry,
                &rollup.entity,
                &rollup.field,
                &rollup.opts,
                &carried,
            )
            .await?;
            tracing::debug!(
                entity = %rollup.entity, field = %rollup.field,
                parents = carried.len(), written, "rollup recomputed"
            );
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, CONSUMER, last_event).await?;
    Ok(events.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::rollup::RollupStep;
    use serde_json::json;

    fn rollup(path: &[(&str, &str)]) -> Rollup {
        Rollup {
            entity: "account".into(),
            field: "total".into(),
            opts: RollupOptions {
                function: attome_core::rollup::RollupFunction::Count,
                path: path
                    .iter()
                    .map(|(e, v)| RollupStep {
                        entity: (*e).into(),
                        via: (*v).into(),
                    })
                    .collect(),
                attribute: None,
                filter: None,
                window: None,
                order_by: None,
                mode: RollupMode::Fast,
                result_type: "number".into(),
            },
        }
    }

    #[test]
    fn rollup_fast_finds_the_levels_an_entity_sits_at() {
        let r = rollup(&[
            ("opportunity", "account_ref"),
            ("opportunity_line", "opportunity_ref"),
        ]);
        assert_eq!(levels_of(&r, "opportunity"), vec![0]);
        assert_eq!(levels_of(&r, "opportunity_line"), vec![1]);
        assert!(levels_of(&r, "contact").is_empty());
    }

    #[test]
    fn rollup_fast_reads_the_parent_before_a_move() {
        let old = Uuid::now_v7();
        let before = json!({ "account_ref": old.to_string(), "amount": 5 });
        assert_eq!(before_ref(Some(&before), "account_ref"), Some(old));
        assert_eq!(before_ref(Some(&before), "amount"), None);
        assert_eq!(before_ref(None, "account_ref"), None);
        assert_eq!(
            before_ref(Some(&json!({ "account_ref": null })), "account_ref"),
            None
        );
    }
}

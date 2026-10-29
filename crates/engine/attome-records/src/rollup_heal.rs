//! Rollup backfill and verify-and-heal (roadmap A10-T4).
//!
//! - **Backfill.** A new or changed rollup is filled for every parent by
//!   the [`BACKFILL_JOB`]: one batch of [`BACKFILL_BATCH`] parents per run,
//!   in id order, each run queueing the next, so a large entity is filled
//!   a batch at a time without holding the queue.
//! - **Heal.** Nightly, [`heal`] recomputes a sample of about 1% of every
//!   rollup's parents and fixes any that drifted (a hard delete, a bulk SQL
//!   update, an exact rollup changed outside the write primitives), logging
//!   each healed value; and recomputes the parents of a windowed rollup
//!   whose related records left the window since the day before, since no
//!   write tells them.
//!
//! A large import needs no pause: exact mode adds each row's own delta, and
//! fast mode recomputes a parent once per tick for all the changes it saw.

use std::collections::BTreeSet;

use attome_core::rollup::RollupOptions;
use attome_core::{EngineState, EntityMetaRegistry, quote_ident};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The registered backfill job.
pub const BACKFILL_JOB: &str = "rollup_backfill";
/// The registered nightly heal job.
pub const HEAL_JOB: &str = "rollup_heal";
/// Parents one backfill run fills.
pub const BACKFILL_BATCH: i64 = 1_000;
/// The most parents one heal samples per rollup.
const HEAL_SAMPLE_CAP: i64 = 10_000;

/// One backfill run: the rollup and where the previous run stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackfillPayload {
    pub entity: String,
    pub field: String,
    #[serde(default)]
    pub after: Option<Uuid>,
}

/// The job that fills `entity.field` from the parent after `after`.
pub fn backfill_job(
    entity: &str,
    field: &str,
    after: Option<Uuid>,
) -> attome_core::jobs::EngineJob {
    attome_core::jobs::EngineJob::Registered(attome_jobs::RegisteredJob {
        name: BACKFILL_JOB.to_owned(),
        version: 1,
        payload: serde_json::json!(BackfillPayload {
            entity: entity.to_owned(),
            field: field.to_owned(),
            after,
        }),
        next: None,
    })
}

/// The rollup `entity.field` as the registry knows it.
fn definition(registry: &EntityMetaRegistry, entity: &str, field: &str) -> Option<RollupOptions> {
    let attr = registry
        .get(entity)?
        .attrs
        .iter()
        .find(|a| a.logicalname == field && a.is_rollup())?;
    attome_core::rollup::parse_options(attr.options.as_ref()).ok()
}

/// One backfill run: fills the next batch of parents. The payload of the
/// next run, or `None` when every parent is filled (or the rollup is gone).
pub async fn backfill_step(
    state: &EngineState,
    payload: &BackfillPayload,
) -> Result<Option<BackfillPayload>, AppError> {
    let registry = std::sync::Arc::clone(&state.entities.load());
    // A rollup saved a moment ago may not be in this node's registry yet.
    let opts = match definition(&registry, &payload.entity, &payload.field) {
        Some(opts) => opts,
        None => {
            let options: Option<Option<serde_json::Value>> = sqlx::query_scalar(
                "SELECT a.options FROM attribute_info a JOIN entity_info e ON e.id = a.entity_ref \
                 WHERE e.logicalname = $1 AND a.logicalname = $2 AND a.\"type\" = 23 \
                   AND (a.is_active IS NULL OR a.is_active = true)",
            )
            .bind(&payload.entity)
            .bind(&payload.field)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            match options
                .flatten()
                .and_then(|o| attome_core::rollup::parse_options(Some(&o)).ok())
            {
                Some(opts) => opts,
                None => return Ok(None),
            }
        }
    };
    let sql = format!(
        "SELECT id FROM {} WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2",
        quote_ident(&payload.entity)
    );
    let sql = attome_db::tag_dynamic("rollup.backfill_ids", &sql);
    let ids: Vec<(Uuid,)> = sqlx::query_as(&sql)
        .bind(payload.after)
        .bind(BACKFILL_BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let parents: BTreeSet<Uuid> = ids.iter().map(|(id,)| *id).collect();
    crate::rollup_fast::recompute(
        state,
        &registry,
        &payload.entity,
        &payload.field,
        &opts,
        &parents,
    )
    .await?;
    let full = i64::try_from(ids.len()).unwrap_or(i64::MAX) == BACKFILL_BATCH;
    Ok(full.then(|| BackfillPayload {
        after: ids.last().map(|(id,)| *id),
        ..payload.clone()
    }))
}

/// Recomputes `parents` and logs every value that changed. How many.
async fn heal_parents(
    state: &EngineState,
    registry: &EntityMetaRegistry,
    entity: &str,
    field: &str,
    opts: &RollupOptions,
    parents: &BTreeSet<Uuid>,
) -> Result<usize, AppError> {
    if parents.is_empty() {
        return Ok(0);
    }
    let last = opts
        .path
        .last()
        .and_then(|step| registry.get(&step.entity))
        .map(|m| m.attrs.as_slice())
        .unwrap_or_default();
    let (sql, binds) = attome_core::rollup::recompute_sql(entity, field, opts, last)?;
    let sql = format!("{sql} RETURNING p.id, agg.v::text");
    let sql = attome_db::tag_dynamic("rollup.heal", &sql);
    let ids: Vec<Uuid> = parents.iter().copied().collect();
    let mut healed = 0;
    for chunk in ids.chunks(500) {
        let mut query = sqlx::query_as::<_, (Uuid, Option<String>)>(&sql).bind(chunk);
        for bind in &binds {
            query = query.bind(bind);
        }
        for (id, value) in query
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?
        {
            tracing::info!(entity, field, record = %id, value = ?value, "rollup healed");
            healed += 1;
        }
    }
    Ok(healed)
}

/// The parents whose windowed rollup lost related records to the window
/// since the day before: the last step's records dated in that day, walked
/// up the path.
async fn aged_out(state: &EngineState, opts: &RollupOptions) -> Result<BTreeSet<Uuid>, AppError> {
    let (Some(window), Some(last)) = (&opts.window, opts.path.last()) else {
        return Ok(BTreeSet::new());
    };
    let sql = format!(
        "SELECT id FROM {} WHERE {date} >= now() - make_interval(days => $1 + 1) \
           AND {date} < now() - make_interval(days => $1) LIMIT $2",
        quote_ident(&last.entity),
        date = quote_ident(&window.date_attribute),
    );
    let sql = attome_db::tag_dynamic("rollup.aged_out", &sql);
    let rows: Vec<(Uuid,)> = sqlx::query_as(&sql)
        .bind(i32::try_from(window.days).unwrap_or(i32::MAX))
        .bind(HEAL_SAMPLE_CAP * 10)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let mut here: BTreeSet<Uuid> = rows.into_iter().map(|(id,)| id).collect();
    for step in opts.path.iter().rev() {
        here = crate::rollup_fast::parents_of(state, &step.entity, &step.via, &here).await?;
    }
    Ok(here)
}

/// Heals `entity.field` for the given parents, as the nightly run does for
/// its sample. How many values it fixed.
pub async fn heal_records(
    state: &EngineState,
    entity: &str,
    field: &str,
    parents: &BTreeSet<Uuid>,
) -> Result<usize, AppError> {
    let registry = std::sync::Arc::clone(&state.entities.load());
    let Some(opts) = definition(&registry, entity, field) else {
        return Ok(0);
    };
    heal_parents(state, &registry, entity, field, &opts, parents).await
}

/// The nightly verify-and-heal over every rollup. How many values it fixed.
pub async fn heal(state: &EngineState) -> Result<usize, AppError> {
    let registry = std::sync::Arc::clone(&state.entities.load());
    let mut rollups = Vec::new();
    for meta in registry.iter() {
        for attr in meta.attrs.iter().filter(|a| a.is_rollup()) {
            if let Ok(opts) = attome_core::rollup::parse_options(attr.options.as_ref()) {
                rollups.push((meta.logicalname.clone(), attr.logicalname.clone(), opts));
            }
        }
    }
    let mut healed = 0;
    for (entity, field, opts) in &rollups {
        let sql = format!(
            "SELECT id FROM {} WHERE random() < 0.01 LIMIT $1",
            quote_ident(entity)
        );
        let sql = attome_db::tag_dynamic("rollup.heal_sample", &sql);
        let sample: Vec<(Uuid,)> = sqlx::query_as(&sql)
            .bind(HEAL_SAMPLE_CAP)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
        let mut parents: BTreeSet<Uuid> = sample.into_iter().map(|(id,)| id).collect();
        parents.extend(aged_out(state, opts).await?);
        healed += heal_parents(state, &registry, entity, field, opts, &parents).await?;
    }
    Ok(healed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollup_heal_backfill_job_carries_where_it_stopped() {
        let after = Uuid::now_v7();
        let attome_core::jobs::EngineJob::Registered(job) =
            backfill_job("account", "total", Some(after))
        else {
            panic!("a registered job");
        };
        assert_eq!(job.name, BACKFILL_JOB);
        let payload: BackfillPayload = serde_json::from_value(job.payload).unwrap();
        assert_eq!(
            payload,
            BackfillPayload {
                entity: "account".into(),
                field: "total".into(),
                after: Some(after)
            }
        );
        let first: BackfillPayload =
            serde_json::from_value(serde_json::json!({ "entity": "a", "field": "f" })).unwrap();
        assert_eq!(first.after, None, "the first run starts at the beginning");
    }
}

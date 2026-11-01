//! A1-T5: one index per base entity, so a list across every entity that
//! extends a base ("all my work items") is one indexed read.
//!
//! **What is indexed.** For each record of an entity that extends a base, at
//! any depth: its id, entity, owner (`owner_ref`), `status` and due time
//! (`due_at`, else `due_date`), in `base_record_index` (migration 0355), one
//! row per base the entity descends from. The columns are named by the base:
//! A1-T4 copies a base's fields into every child under the same names, so a
//! base that has `status` and `due_at` gives every child's record a status
//! and a due time here; a base without them leaves those columns empty. The
//! feed carries no payload by design, so the consumer re-reads the record.
//! (Decision under V2-D480(3): the base's own field names are the index
//! declaration; no extra metadata.)
//!
//! **How it stays current.** The `attome-records/base-index` change-feed
//! consumer ([`run`], the `BaseIndexSweep` job) re-reads each changed record
//! of a descendant entity after its write commits, never inside it, and
//! upserts or removes its rows. [`reindex`] rebuilds one base from its
//! children's tables (the `base_reindex` job).
//!
//! **Reading.** [`list`] reads each child entity's rows joined to the
//! child's own table under the caller's record-level security for that
//! child, and merges them by due time: a row the caller cannot read in the
//! child is never returned.

use std::collections::{BTreeSet, HashMap};

use attome_core::{EngineState, quote_ident};
use attome_security::{
    RecordAction, SecurityContextExt, bind_rls_predicate, bind_rls_predicate_as,
    rls_predicate_with_conditions,
};
use attome_server::security::SecurityContext;
use attome_types::{AppError, PaginatedResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-records/base-index";
/// The registered rebuild job.
pub const JOB: &str = "base_reindex";
const BATCH: i64 = 500;
const MAX_BATCHES: usize = 20;
/// The deepest page a list reads (rows before the page's end).
pub const MAX_WINDOW: i64 = 10_000;

/// A child's record as the base index holds it, read from the record (`j`
/// is the row as JSON): owner, status and due time, each `NULL` when the
/// entity has no such field or its value is not one.
const PROJECTION: &str = "CASE WHEN j ->> 'owner_ref' ~ '^[0-9a-fA-F-]{36}$' \
         THEN (j ->> 'owner_ref')::uuid END, \
    j ->> 'status', \
    CASE WHEN COALESCE(j ->> 'due_at', j ->> 'due_date') ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}' \
         THEN COALESCE(j ->> 'due_at', j ->> 'due_date')::timestamptz END";

/// Each descendant entity with the bases it descends from, nearest first.
async fn lineage(db: &attome_db::DbPool) -> Result<HashMap<String, Vec<String>>, AppError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "WITH RECURSIVE up AS ( \
             SELECT c.logicalname AS child, b.logicalname AS base, b.extends_entity_id AS next, 1 AS depth \
               FROM entity_info c JOIN entity_info b ON b.id = c.extends_entity_id \
              WHERE c.is_active IS NOT FALSE AND b.is_active IS NOT FALSE \
             UNION ALL \
             SELECT up.child, b.logicalname, b.extends_entity_id, up.depth + 1 \
               FROM up JOIN entity_info b ON b.id = up.next \
              WHERE b.is_active IS NOT FALSE AND up.depth < 10 \
         ) SELECT child, base FROM up ORDER BY child, depth",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for (child, base) in rows {
        out.entry(child).or_default().push(base);
    }
    Ok(out)
}

/// The entities descending from `base`, at any depth.
async fn descendants(db: &attome_db::DbPool, base: &str) -> Result<Vec<String>, AppError> {
    let lineage = lineage(db).await?;
    let mut out: Vec<String> = lineage
        .into_iter()
        .filter(|(_, bases)| bases.iter().any(|b| b == base))
        .map(|(child, _)| child)
        .collect();
    out.sort();
    Ok(out)
}

/// Re-reads `id` of `entity` and puts its rows under `bases` in line with
/// it: upserted while it is live, removed when it is gone or inactive.
async fn reindex_record(
    state: &EngineState,
    entity: &str,
    id: Uuid,
    bases: &[String],
) -> Result<(), AppError> {
    let known = state.entities.load().get(entity).is_some();
    let row: Option<(Option<Uuid>, Option<String>, Option<DateTime<Utc>>)> = if known {
        sqlx::query_as(&format!(
            "SELECT {PROJECTION} FROM (SELECT to_jsonb(t) AS j FROM {} t \
              WHERE t.id = $1 AND t.is_active IS NOT FALSE) s",
            quote_ident(entity)
        ))
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
    } else {
        None
    };
    for base in bases {
        match &row {
            Some((owner, status, due)) => {
                sqlx::query(
                    "INSERT INTO base_record_index (base, id, entity, owner, status, due_at) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (base, id) DO UPDATE SET entity = EXCLUDED.entity, \
                         owner = EXCLUDED.owner, status = EXCLUDED.status, \
                         due_at = EXCLUDED.due_at, updated_at = now()",
                )
                .bind(base)
                .bind(id)
                .bind(entity)
                .bind(owner)
                .bind(status)
                .bind(due)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
            None => {
                sqlx::query("DELETE FROM base_record_index WHERE base = $1 AND id = $2")
                    .bind(base)
                    .bind(id)
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
            }
        }
    }
    Ok(())
}

/// One run of the `BaseIndexSweep` job: the changes since the cursor, each
/// changed record of a descendant entity re-read into its bases' rows.
/// Answers how many records it re-read.
pub async fn run(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let lineage = lineage(db).await?;
    let mut touched = 0;
    for _ in 0..MAX_BATCHES {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
        drop(conn);
        let Some(last) = events.last().cloned() else {
            break;
        };
        let mut seen = BTreeSet::new();
        for event in &events {
            let Some(bases) = lineage.get(&event.entity_logicalname) else {
                continue;
            };
            if !seen.insert((event.entity_logicalname.as_str(), event.record_id)) {
                continue;
            }
            reindex_record(state, &event.entity_logicalname, event.record_id, bases).await?;
            touched += 1;
        }
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::advance(&mut conn, CONSUMER, &last).await?;
        if events.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(touched)
}

/// Rebuilds `base`'s rows from its descendants' tables, in one transaction.
/// Answers how many rows it wrote.
pub async fn reindex(state: &EngineState, base: &str) -> Result<u64, AppError> {
    let children = descendants(&state.base.db, base).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("DELETE FROM base_record_index WHERE base = $1")
        .bind(base)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let mut written = 0;
    for child in &children {
        if state.entities.load().get(child).is_none() {
            continue;
        }
        let done = sqlx::query(&format!(
            "INSERT INTO base_record_index (base, id, entity, owner, status, due_at) \
             SELECT $1, s.id, $2, {PROJECTION} \
               FROM (SELECT t.id, to_jsonb(t) AS j FROM {} t WHERE t.is_active IS NOT FALSE) s",
            quote_ident(child)
        ))
        .bind(base)
        .bind(child)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        written += done.rows_affected();
    }
    attome_db::tx::commit(tx).await?;
    Ok(written)
}

/// The rebuild job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReindexJob {
    pub base: String,
}

/// What a list asks for.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct BaseRecordsQuery {
    /// `me`, or a user id.
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub page: Option<i64>,
    #[serde(default)]
    pub page_size: Option<i64>,
}

/// One record of a base, whichever entity holds it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct BaseRecord {
    pub id: Uuid,
    pub entity: String,
    pub owner: Option<Uuid>,
    pub status: Option<String>,
    pub due_at: Option<DateTime<Utc>>,
}

/// Due first, undated last, then by id. Pure.
fn order(a: &BaseRecord, b: &BaseRecord) -> std::cmp::Ordering {
    match (a.due_at, b.due_at) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
    .then(a.id.cmp(&b.id))
}

/// `base`'s records the caller may read, due first, one-based pages.
pub async fn list(
    state: &EngineState,
    ctx: &SecurityContext,
    base: &str,
    q: &BaseRecordsQuery,
) -> Result<PaginatedResponse<BaseRecord>, AppError> {
    let page = q.page.unwrap_or(1).max(1);
    let page_size = q
        .page_size
        .unwrap_or(attome_types::DEFAULT_PAGE_SIZE)
        .clamp(1, attome_types::MAX_PAGE_SIZE);
    let window = page.saturating_mul(page_size);
    if window > MAX_WINDOW {
        return Err(AppError::Validation(format!(
            "page: at most {MAX_WINDOW} records deep; filter by owner or status"
        )));
    }
    let owner: Option<Uuid> = match q.owner.as_deref().map(str::trim) {
        None | Some("") => None,
        Some("me") => Some(ctx.user_id),
        Some(id) => Some(
            Uuid::parse_str(id)
                .map_err(|_| AppError::Validation("owner: me or a user id".into()))?,
        ),
    };
    let status = q.status.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let children = descendants(&state.base.db, base).await?;
    if children.is_empty() {
        return Err(AppError::NotFound);
    }
    let mut rows: Vec<BaseRecord> = Vec::new();
    let mut total: i64 = 0;
    for child in &children {
        if ctx.require(child, "read").is_err() {
            continue;
        }
        let Some((entity_id, attrs)) = state
            .entities
            .load()
            .get(child)
            .map(|m| (m.entity_id, m.attrs.clone()))
        else {
            continue;
        };
        let (access_level, owner_visible) = crate::entity_crud::resolve_record_access_inputs(
            state,
            ctx,
            entity_id,
            child,
            RecordAction::Read,
        )
        .await?;
        let privilege_key = format!("{child}.read");
        // $1 base, $2 entity, $3 owner, $4 status, $5 limit; the predicate's
        // own binds follow.
        let pred = rls_predicate_with_conditions(
            ctx,
            entity_id,
            "t",
            access_level,
            RecordAction::Read.share_capability(),
            &privilege_key,
            &attrs,
            owner_visible,
            6,
        );
        let rls = pred.as_ref().map_or("", |p| p.sql.as_str());
        let from = format!(
            "FROM base_record_index i JOIN {} t ON t.id = i.id \
             WHERE i.base = $1 AND i.entity = $2 AND ($3::uuid IS NULL OR i.owner = $3) \
               AND ($4::text IS NULL OR i.status = $4) AND t.is_active IS NOT FALSE {rls}",
            quote_ident(child)
        );
        let mut select = sqlx::query_as::<_, BaseRecord>(&format!(
            "SELECT i.id, i.entity, i.owner, i.status, i.due_at {from} \
             ORDER BY i.due_at NULLS LAST, i.id LIMIT $5"
        ))
        .bind(base)
        .bind(child)
        .bind(owner)
        .bind(status)
        .bind(window);
        // The count has no limit: its predicate binds start one earlier.
        let count_pred = rls_predicate_with_conditions(
            ctx,
            entity_id,
            "t",
            access_level,
            RecordAction::Read.share_capability(),
            &privilege_key,
            &attrs,
            owner_visible,
            5,
        );
        let count_rls = count_pred.as_ref().map_or("", |p| p.sql.as_str());
        let count_from = format!(
            "FROM base_record_index i JOIN {} t ON t.id = i.id \
             WHERE i.base = $1 AND i.entity = $2 AND ($3::uuid IS NULL OR i.owner = $3) \
               AND ($4::text IS NULL OR i.status = $4) AND t.is_active IS NOT FALSE {count_rls}",
            quote_ident(child)
        );
        let mut count = sqlx::query_scalar::<_, i64>(&format!("SELECT COUNT(*) {count_from}"))
            .bind(base)
            .bind(child)
            .bind(owner)
            .bind(status);
        if let Some(p) = &pred {
            if let Some(tb) = &p.tier_binds {
                select = bind_rls_predicate_as(select, tb);
            }
            for b in &p.condition_binds {
                select = select.bind(b);
            }
        }
        if let Some(p) = &count_pred {
            if let Some(tb) = &p.tier_binds {
                count = bind_rls_predicate(count, tb);
            }
            for b in &p.condition_binds {
                count = count.bind(b);
            }
        }
        rows.extend(
            select
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?,
        );
        total += count
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    }
    rows.sort_by(order);
    let offset = usize::try_from((page - 1) * page_size).unwrap_or(usize::MAX);
    let items: Vec<BaseRecord> = rows
        .into_iter()
        .skip(offset)
        .take(usize::try_from(page_size).unwrap_or(0))
        .collect();
    Ok(PaginatedResponse::new(items, total, page, page_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(n: u128, due: Option<i64>) -> BaseRecord {
        BaseRecord {
            id: Uuid::from_u128(n),
            entity: "ticket".into(),
            owner: None,
            status: None,
            due_at: due.and_then(|s| DateTime::from_timestamp(s, 0)),
        }
    }

    #[test]
    fn due_first_then_undated_then_by_id() {
        let mut rows = vec![
            record(3, None),
            record(2, Some(200)),
            record(1, Some(100)),
            record(0, None),
        ];
        rows.sort_by(order);
        let ids: Vec<u128> = rows.iter().map(|r| r.id.as_u128()).collect();
        assert_eq!(ids, vec![1, 2, 0, 3]);
    }
}

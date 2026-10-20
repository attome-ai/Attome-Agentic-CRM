//! M18 Data Catalog Phase 1 (D-466) — the shared writer for
//! `metadata_reference` (migration `0356`), the generalized
//! lineage table: "what object (query/dashboard/workflow/rule) references
//! this entity/attribute".
//!
//! Lives in `attome-core`, not any one engine crate, for the same reason
//! `change_feed.rs` and `data_domain.rs` do: at least two engines write it
//! today (`attome-server` for stored queries, `attome-workflow` for workflow
//! definitions), and a third caller — the dashboard-lineage outbox
//! consumer, which itself lives in `attome-server` since dashboards are
//! generic-CRUD entities with no bespoke engine crate — needs it without
//! either of those two engines taking on the other as a dependency.

use attome_types::AppError;
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

/// One reference a save/publish produced: `to_entity`, and optionally the
/// specific attribute referenced (`None` for an entity-level reference —
/// stored as the empty-string sentinel `0356`'s header explains).
#[derive(Clone, Debug)]
pub struct MetadataReferenceInput {
    pub to_entity: String,
    pub to_attribute: Option<String>,
    /// P10-T1: what the reference points at — `entity` (an entity or one of
    /// its attributes) or `metric`.
    pub to_kind: &'static str,
    /// P10-T1: the target's id when it is not an entity (a metric's id).
    pub to_ref: Option<Uuid>,
}

impl MetadataReferenceInput {
    pub fn entity(to_entity: impl Into<String>) -> Self {
        Self {
            to_entity: to_entity.into(),
            to_attribute: None,
            to_kind: "entity",
            to_ref: None,
        }
    }

    pub fn attribute(to_entity: impl Into<String>, to_attribute: impl Into<String>) -> Self {
        Self {
            to_entity: to_entity.into(),
            to_attribute: Some(to_attribute.into()),
            to_kind: "entity",
            to_ref: None,
        }
    }

    /// P10-T1: a reference to a metric. `to_entity` holds `metric:<id>`, so
    /// it never matches an entity's name.
    pub fn metric(metric_id: Uuid) -> Self {
        Self {
            to_entity: format!("metric:{metric_id}"),
            to_attribute: None,
            to_kind: "metric",
            to_ref: Some(metric_id),
        }
    }
}

/// Replaces every `metadata_reference` row for `(from_kind,
/// from_ref)` with `refs` — a save/publish's full, current reference set,
/// never an incremental diff (0356's header explains why: a reference that
/// stopped being true must disappear on the next save, not accumulate).
///
/// Takes the caller's own transaction so this lands atomically with the
/// definition/version write it accompanies — the same `&mut
/// Transaction<'_, Postgres>` idiom `query_admin.rs`'s
/// `write_entity_mappings` already uses for the sibling
/// `sql_query_entity_mapping` table.
///
/// Guarded by the two-argument, non-blocking
/// `pg_try_advisory_xact_lock($1, hashtext($2))` (guidelines §2), namespace
/// 3 (`attome-core`, already registered — no new namespace needed),
/// scoped to exactly this `(from_kind, from_ref)` pair: two concurrent
/// saves of the SAME object (a double-submit) must not interleave their
/// delete+insert; two saves of DIFFERENT objects must never block each
/// other. Fails closed with `AppError::Conflict` rather than blocking —
/// the caller's own save-transaction row_version/optimistic-concurrency
/// check is the right place for a double-submit to surface, not a wait
/// here.
pub async fn replace_references(
    tx: &mut Transaction<'_, Postgres>,
    from_kind: &str,
    from_ref: Uuid,
    from_label: &str,
    refs: &[MetadataReferenceInput],
) -> Result<(), AppError> {
    // C-18 — delegates to the crate-wide `try_xact_lock` shared body; `tx`'s
    // `&mut Transaction<'_, Postgres>` type is `attome_db::Tx<'_>` verbatim
    // (a type alias), so no conversion is needed here.
    let lock_key = format!("attome-core/metadata-reference:{from_kind}:{from_ref}");
    crate::try_xact_lock(
        tx,
        &lock_key,
        "metadata reference write already in progress for this object",
    )
    .await?;

    sqlx::query("DELETE FROM metadata_reference WHERE from_kind = $1 AND from_ref = $2")
        .bind(from_kind)
        .bind(from_ref)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;

    for r in refs {
        sqlx::query(
            "INSERT INTO metadata_reference \
                (from_kind, from_ref, from_label, to_entity, to_attribute, to_kind, to_ref) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (from_kind, from_ref, to_entity, to_attribute) DO NOTHING",
        )
        .bind(from_kind)
        .bind(from_ref)
        .bind(from_label)
        .bind(&r.to_entity)
        .bind(r.to_attribute.as_deref().unwrap_or(""))
        .bind(r.to_kind)
        .bind(r.to_ref)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }

    Ok(())
}

/// One row of "what references this entity/attribute" — the catalog's
/// primary lineage read (`GET /api/v1/catalog/entities/{name}`).
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct MetadataReferenceRow {
    pub from_kind: String,
    pub from_ref: Uuid,
    pub from_label: String,
    pub to_attribute: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Lists every current reference to `to_entity`, optionally narrowed to one
/// attribute. Bounded by `limit` — this backs a UI panel, not an export.
pub async fn references_to_entity<'e, E>(
    executor: E,
    to_entity: &str,
    limit: i64,
) -> Result<Vec<MetadataReferenceRow>, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as(
        "SELECT from_kind, from_ref, from_label, to_attribute, created_at \
         FROM metadata_reference \
         WHERE to_entity = $1 \
         ORDER BY from_kind, created_at DESC \
         LIMIT $2",
    )
    .bind(to_entity)
    .bind(limit)
    .fetch_all(executor)
    .await
    .map_err(AppError::internal)
}

/// Reads the current reference set recorded for one `(from_kind, from_ref)`
/// — the inverse direction of [`references_to_entity`]. Used by a consumer
/// that copies ANOTHER object's already-recorded lineage rather than
/// re-deriving it: the dashboard-widget lineage sweep
/// (`attome_server::catalog_admin`) copies a widget's `query_id`'s query
/// lineage instead of re-parsing SQL, and the backfill job
/// (`EngineJob::CatalogLineageBackfill`) is the mirror write path this
/// pairs with.
pub async fn references_from<'e, E>(
    executor: E,
    from_kind: &str,
    from_ref: Uuid,
) -> Result<Vec<MetadataReferenceInput>, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let rows: Vec<(String, String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT to_entity, to_attribute, to_kind, to_ref FROM metadata_reference \
         WHERE from_kind = $1 AND from_ref = $2",
    )
    .bind(from_kind)
    .bind(from_ref)
    .fetch_all(executor)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(|(to_entity, to_attribute, to_kind, to_ref)| {
            if to_kind == "metric"
                && let Some(id) = to_ref
            {
                return MetadataReferenceInput::metric(id);
            }
            MetadataReferenceInput {
                to_entity,
                to_attribute: if to_attribute.is_empty() {
                    None
                } else {
                    Some(to_attribute)
                },
                to_kind: "entity",
                to_ref: None,
            }
        })
        .collect())
}

/// P10-T1: every object that references the metric `metric_id` (a
/// dashboard widget showing it, a metric whose formula reads it), by kind
/// and newest first, at most `limit`.
pub async fn references_to_metric<'e, E>(
    executor: E,
    metric_id: Uuid,
    limit: i64,
) -> Result<Vec<MetadataReferenceRow>, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_as(
        "SELECT from_kind, from_ref, from_label, to_attribute, created_at \
         FROM metadata_reference \
         WHERE to_kind = 'metric' AND to_ref = $1 \
         ORDER BY from_kind, created_at DESC \
         LIMIT $2",
    )
    .bind(metric_id)
    .bind(limit)
    .fetch_all(executor)
    .await
    .map_err(AppError::internal)
}

/// This kind's resumable keyset-cursor position in
/// `metadata_reference_backfill_progress` (migration `0357`) — see
/// that migration's header for why a bare per-kind cursor is the right
/// shape (every source row is idempotent to reprocess, so there is no
/// per-item ledger to maintain).
#[derive(Clone, Copy, Debug)]
pub struct BackfillProgress {
    pub last_ref: Option<Uuid>,
    pub completed: bool,
}

/// Reads (self-registering on first call, same `ON CONFLICT DO NOTHING`
/// idiom `change_feed::cursor` uses for its own per-consumer row) `kind`'s
/// current backfill cursor. Takes a bare connection, not a generic
/// `Executor`, for the same reason `change_feed::cursor` does: it needs two
/// sequential reborrows of the same handle (INSERT, then SELECT), which a
/// one-shot-by-value `Executor` bound cannot give back after the first use.
pub async fn backfill_progress(
    conn: &mut PgConnection,
    kind: &str,
) -> Result<BackfillProgress, AppError> {
    sqlx::query(
        "INSERT INTO metadata_reference_backfill_progress (kind) VALUES ($1) \
         ON CONFLICT (kind) DO NOTHING",
    )
    .bind(kind)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    let row: (Option<Uuid>, bool) = sqlx::query_as(
        "SELECT last_ref, completed FROM metadata_reference_backfill_progress \
         WHERE kind = $1",
    )
    .bind(kind)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;

    Ok(BackfillProgress {
        last_ref: row.0,
        completed: row.1,
    })
}

/// Advances `kind`'s backfill cursor after processing one bounded batch of
/// `rows_written` source rows ending at `last_ref`. `completed` is the
/// caller's own "this batch came back shorter than the limit" signal — once
/// set, [`backfill_progress`] short-circuits every later tick to a no-op,
/// which is what lets the backfill job run forever as a plain periodic
/// sweep (guidelines §9/§10) instead of needing a one-shot admin trigger.
pub async fn advance_backfill_progress(
    conn: &mut PgConnection,
    kind: &str,
    last_ref: Uuid,
    rows_written: i64,
    completed: bool,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE metadata_reference_backfill_progress \
         SET last_ref = $2, completed = $3, rows_written = rows_written + $4, updated_at = NOW() \
         WHERE kind = $1",
    )
    .bind(kind)
    .bind(last_ref)
    .bind(completed)
    .bind(rows_written)
    .execute(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_level_reference_uses_the_empty_string_sentinel() {
        let r = MetadataReferenceInput::entity("account");
        assert_eq!(r.to_entity, "account");
        assert_eq!(r.to_attribute, None);
    }

    #[test]
    fn attribute_level_reference_carries_the_attribute() {
        let r = MetadataReferenceInput::attribute("account", "revenue");
        assert_eq!(r.to_attribute.as_deref(), Some("revenue"));
    }
}

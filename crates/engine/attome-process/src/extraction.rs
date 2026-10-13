//! Incremental cursor-based extraction: reads the two existing event sources
//! the module plan names (`document/module-master-plans/
//! M41-process-intelligence.md` §3) — `workflow_node_run` for
//! `"workflow:<definition_id>"` case defs, `audit_header`/`_detail`
//! for `"entity:<logicalname>"` ones — and populates `process_event`.
//! Called by `EngineJob::ProcessExtractionSweep`'s handler
//! (`crates/server/src/jobs.rs`), on a periodic tick.
//!
//! ## Why a plain `(ts, id)` cursor is safe here (with one documented gap)
//!
//! `entity_change_event`'s own cursor (`attome_core::change_feed`)
//! has to compare against `pg_snapshot_xmin` because it orders by
//! *transaction-assignment* order, not by a column value physically visible
//! at read time — a long transaction that started earlier can still commit
//! later. This module instead orders by a column that is written exactly
//! once, at commit time of the row's own transaction, and never rewritten
//! afterwards (`workflow_node_run.completed_at`,
//! `audit_header.created_at`) — so once a row is visible to our read
//! at all, its own `(ts, id)` pair is final. That still leaves one gap this
//! module accepts rather than solves: two concurrent transactions can commit
//! out of order relative to their own timestamps (a slow transaction with an
//! earlier clock reading commits after a fast one with a later reading), and
//! a cursor already advanced past the fast transaction's `(ts, id)` would
//! skip the slow one forever. `EXTRACTION_GRACE_WINDOW` bounds this to
//! "a transaction that takes longer than the grace window to commit relative
//! to a concurrent one with a later timestamp" — not a real risk for a
//! single node execution or audit write, but not impossible either. This is
//! an accepted Phase 1 simplification for read-only, derived, rebuildable
//! analytics data (`document/decisions/data/D-462.md`) — the documented
//! rebuild path (reset a case def's cursor to `NULL`, i.e. re-extract from
//! scratch) is the general-purpose fix for anything this gap ever misses,
//! the same posture `EnsureAuditPartitions`/other periodic sweeps in this
//! workspace already take toward "eventually converges, not linearizable".
//!
//! ## Idempotency
//!
//! Every write carries `(source_kind, source_ref)` — the id of the single
//! `workflow_node_run`/`audit_detail` row that produced it — and
//! `process_event`'s unique index on `(case_def_ref, source_kind,
//! source_ref, ts_start)` makes a retried batch's `INSERT ... ON CONFLICT DO
//! NOTHING` a true no-op, never a double-count, even if a previous attempt
//! wrote some rows and crashed before advancing the cursor.
//!
//! ## `activity_mapping`'s shape, per source kind
//!
//! * `workflow:<definition_id>` — ignored; the activity label is always the
//!   node's own `node_id` (already a short, admin-authored, human-readable
//!   name from the workflow graph — nothing to remap).
//! * `entity:<logicalname>` — `{"field": "<status field logicalname>", "values": {"<raw value>": "<activity label>"}}`.
//!   `field` is required (a case def with no configured field extracts
//!   nothing — see [`Source::parse`]'s caller in `case_def_admin.rs` for
//!   where that would ideally be caught up front; Phase 1 leaves it a silent
//!   no-op at extraction time rather than a write-time validation, since
//!   `attome-process` cannot validate against `EntityMetaRegistry` without a
//!   dependency this crate deliberately doesn't take, see this crate's
//!   lib.rs doc comment). `values` is an optional raw-value → label remap;
//!   a value with no entry uses the raw stored value as its own label.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use uuid::Uuid;

/// See this module's doc comment.
const EXTRACTION_GRACE_WINDOW: ChronoDuration = ChronoDuration::minutes(2);

/// Per-case-def, per-tick cap — keeps one tick of the sweep bounded
/// regardless of backlog size (guidelines §9/§10); a case def with more than
/// this many pending source rows simply catches up over several ticks,
/// resuming from its own persisted cursor each time.
const BATCH_LIMIT: i64 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Workflow(Uuid),
    Entity,
}

impl Source {
    /// `entity_logicalname` is returned separately (borrowed from the
    /// original string) rather than owned on the enum, so callers that only
    /// need to know the *kind* (`case_def_admin.rs`'s validation) don't pay
    /// for an allocation they discard.
    pub fn parse(raw: &str) -> Result<Self, AppError> {
        if let Some(rest) = raw.strip_prefix("workflow:") {
            let id = Uuid::parse_str(rest).map_err(|_| {
                AppError::Validation(
                    "source: \"workflow:<definition_id>\" must carry a valid uuid".into(),
                )
            })?;
            return Ok(Source::Workflow(id));
        }
        if raw
            .strip_prefix("entity:")
            .is_some_and(|rest| !rest.is_empty())
        {
            return Ok(Source::Entity);
        }
        Err(AppError::Validation(
            "source must be \"workflow:<definition_id>\" or \"entity:<logicalname>\"".into(),
        ))
    }
}

#[derive(sqlx::FromRow)]
struct CaseDefRow {
    id: Uuid,
    source: String,
    activity_mapping: serde_json::Value,
    cursor_last_ts: Option<DateTime<Utc>>,
    cursor_last_id: Option<Uuid>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ExtractionStats {
    pub case_defs_processed: usize,
    pub events_written: u64,
}

/// Runs one bounded tick of extraction across every active case def, then
/// (for any case def that got new events) recomputes its DFG/variant/
/// cycle-time snapshot. Never fails outright on one case def's error — a
/// misconfigured case def (bad `source`, missing `activity_mapping.field`
/// for an entity source) is logged and skipped so it cannot block every
/// other case def's extraction on the same tick.
pub async fn run_sweep(db: &DbPool) -> Result<ExtractionStats, AppError> {
    let case_defs: Vec<CaseDefRow> = sqlx::query_as(
        "SELECT id, source, activity_mapping, cursor_last_ts, cursor_last_id \
         FROM process_case_def WHERE is_active = true AND is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut stats = ExtractionStats::default();
    for case_def in case_defs {
        let case_def_id = case_def.id;
        match extract_one(db, &case_def).await {
            Ok(written) => {
                stats.case_defs_processed += 1;
                stats.events_written += written;
                if written > 0
                    && let Err(e) = crate::discovery::compute_snapshot(db, case_def_id).await
                {
                    tracing::warn!(
                        case_def_id = %case_def_id,
                        error = %e,
                        "process extraction: discovery recompute failed, will retry next tick"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    case_def_id = %case_def_id,
                    error = %e,
                    "process extraction: case def failed, will retry next tick"
                );
            }
        }
    }
    Ok(stats)
}

async fn extract_one(db: &DbPool, case_def: &CaseDefRow) -> Result<u64, AppError> {
    match Source::parse(&case_def.source)? {
        Source::Workflow(definition_id) => extract_workflow(db, case_def, definition_id).await,
        Source::Entity => extract_entity(db, case_def).await,
    }
}

struct WatermarkArgs {
    watermark: DateTime<Utc>,
    /// `None` on a case def's first-ever sweep — bound directly as SQL NULL
    /// (see each query's `$n::timestamptz IS NULL OR (...) > ($n, $n+1)`
    /// clause) rather than a sentinel "earliest possible timestamp" value.
    /// `chrono::DateTime::<Utc>::MIN_UTC` was tried first and is wrong: its
    /// year (-262144) is far outside Postgres's own timestamptz range
    /// (4713 BC-294276 AD), so binding it does not error loudly — it just
    /// makes the tuple-comparison predicate evaluate false for every real
    /// row, silently extracting nothing forever. Caught by this crate's own
    /// integration test.
    cursor_ts: Option<DateTime<Utc>>,
    cursor_id: Option<Uuid>,
}

fn watermark_args(case_def: &CaseDefRow) -> WatermarkArgs {
    WatermarkArgs {
        watermark: Utc::now() - EXTRACTION_GRACE_WINDOW,
        cursor_ts: case_def.cursor_last_ts,
        cursor_id: case_def.cursor_last_id,
    }
}

#[derive(sqlx::FromRow)]
struct WorkflowSourceRow {
    source_ref: Uuid,
    case_id: Uuid,
    activity: String,
    ts_start: DateTime<Utc>,
    ts_end: Option<DateTime<Utc>>,
    resource_ref: Option<Uuid>,
    cursor_ts: DateTime<Utc>,
    cursor_id: Uuid,
}

#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
async fn extract_workflow(
    db: &DbPool,
    case_def: &CaseDefRow,
    definition_id: Uuid,
) -> Result<u64, AppError> {
    let w = watermark_args(case_def);
    let rows: Vec<WorkflowSourceRow> = sqlx::query_as(
        "SELECT nr.id AS source_ref, nr.instance_id AS case_id, nr.node_id AS activity, \
                COALESCE(nr.started_at, nr.completed_at) AS ts_start, nr.completed_at AS ts_end, \
                wi.started_by AS resource_ref, \
                nr.completed_at AS cursor_ts, nr.id AS cursor_id \
         FROM workflow_node_run nr \
         JOIN workflow_instance wi ON wi.id = nr.instance_id \
         JOIN workflow_definition_version wdv ON wdv.id = wi.definition_version_id \
         WHERE wdv.definition_id = $1 \
           AND nr.completed_at IS NOT NULL \
           AND nr.completed_at <= $2 \
           AND ($3::timestamptz IS NULL OR (nr.completed_at, nr.id) > ($3, $4)) \
         ORDER BY nr.completed_at, nr.id \
         LIMIT $5",
    )
    .bind(definition_id)
    .bind(w.watermark)
    .bind(w.cursor_ts)
    .bind(w.cursor_id)
    .bind(BATCH_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    if rows.is_empty() {
        return Ok(0);
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-process/extract:{}", case_def.id))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        // Another node/tick is already extracting this case def — skip
        // cleanly, next tick retries from the still-unmoved cursor.
        return Ok(0);
    }

    let mut written = 0u64;
    for row in &rows {
        let n = sqlx::query(
            "INSERT INTO process_event \
                 (case_def_ref, case_id, activity, ts_start, ts_end, resource_ref, \
                  source_kind, source_ref) \
             VALUES ($1, $2, $3, $4, $5, $6, 'workflow_node_run', $7) \
             ON CONFLICT (case_def_ref, source_kind, source_ref, ts_start) DO NOTHING",
        )
        .bind(case_def.id)
        .bind(row.case_id)
        .bind(&row.activity)
        .bind(row.ts_start)
        .bind(row.ts_end)
        .bind(row.resource_ref)
        .bind(row.source_ref)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        written += n;
    }
    // rows is non-empty (guarded above), so this always has a last element —
    // its own cursor_ts/cursor_id, not w.cursor_ts/w.cursor_id, since the
    // cursor always advances to the last row actually read this tick.
    let last = rows.last().expect("rows is non-empty, checked above");
    advance_cursor(&mut tx, case_def.id, last.cursor_ts, last.cursor_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(written)
}

#[derive(sqlx::FromRow)]
struct EntitySourceRow {
    source_ref: Uuid,
    case_id: Uuid,
    raw_value: Option<String>,
    ts: DateTime<Utc>,
    resource_ref: Option<Uuid>,
}

#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
async fn extract_entity(db: &DbPool, case_def: &CaseDefRow) -> Result<u64, AppError> {
    let entity_logicalname = case_def
        .source
        .strip_prefix("entity:")
        .expect("Source::parse already validated the entity: prefix")
        .to_string();
    let Some(field) = case_def
        .activity_mapping
        .get("field")
        .and_then(|v| v.as_str())
    else {
        // Misconfigured — logged by the caller, nothing to extract.
        return Ok(0);
    };
    let values = case_def
        .activity_mapping
        .get("values")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let w = watermark_args(case_def);
    let rows: Vec<EntitySourceRow> = sqlx::query_as(
        "SELECT d.id AS source_ref, h.record_id AS case_id, d.new_value AS raw_value, \
                h.created_at AS ts, h.user_id AS resource_ref \
         FROM audit_detail d \
         JOIN audit_header h ON h.id = d.audit_ref \
         WHERE h.entity_name = $1 AND d.field_name = $2 AND h.record_id IS NOT NULL \
           AND h.created_at <= $3 \
           AND ($4::timestamptz IS NULL OR (h.created_at, d.id) > ($4, $5)) \
         ORDER BY h.created_at, d.id \
         LIMIT $6",
    )
    .bind(&entity_logicalname)
    .bind(field)
    .bind(w.watermark)
    .bind(w.cursor_ts)
    .bind(w.cursor_id)
    .bind(BATCH_LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    if rows.is_empty() {
        return Ok(0);
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-process/extract:{}", case_def.id))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(0);
    }

    let mut written = 0u64;
    for row in &rows {
        let Some(raw) = &row.raw_value else {
            continue;
        };
        let activity = values
            .get(raw)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| raw.clone());
        let n = sqlx::query(
            "INSERT INTO process_event \
                 (case_def_ref, case_id, activity, ts_start, ts_end, resource_ref, \
                  source_kind, source_ref) \
             VALUES ($1, $2, $3, $4, $4, $5, 'audit_detail', $6) \
             ON CONFLICT (case_def_ref, source_kind, source_ref, ts_start) DO NOTHING",
        )
        .bind(case_def.id)
        .bind(row.case_id)
        .bind(&activity)
        .bind(row.ts)
        .bind(row.resource_ref)
        .bind(row.source_ref)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        written += n;
    }
    // rows is non-empty (guarded above), so this always has a last element —
    // the cursor advances to the last row read this tick regardless of
    // whether that particular row was a real write or a skipped null value.
    let last = rows.last().expect("rows is non-empty, checked above");
    advance_cursor(&mut tx, case_def.id, last.ts, last.source_ref).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(written)
}

async fn advance_cursor(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    case_def_id: Uuid,
    ts: DateTime<Utc>,
    id: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE process_case_def \
         SET cursor_last_ts = $2, cursor_last_id = $3, last_extracted_at = NOW() \
         WHERE id = $1",
    )
    .bind(case_def_id)
    .bind(ts)
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_parses_workflow_and_entity_and_rejects_garbage() {
        let id = Uuid::now_v7();
        assert_eq!(
            Source::parse(&format!("workflow:{id}")).unwrap(),
            Source::Workflow(id)
        );
        assert_eq!(Source::parse("entity:contact").unwrap(), Source::Entity);
        assert!(Source::parse("entity:").is_err());
        assert!(Source::parse("workflow:not-a-uuid").is_err());
        assert!(Source::parse("garbage").is_err());
    }
}

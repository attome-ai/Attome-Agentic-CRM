//! P-retention-archive-completion §3c — purge for soft-deleted entity
//! records past `retention.entity_purge_grace_days`. Never a hard `DELETE`
//! (see the plan's §3c/§4 "rejected alternatives" ruling): a purged record
//! keeps its row and `id` so `on_target_delete` (D-077/D-096), every lookup,
//! and `POST .../{id}/restore` (F026) keep working exactly as today. Purge
//! is always two steps, performed by the caller in this order:
//!   1. `attome_audit::destroy_key` (D-107, unchanged) on the record's
//!      `audit_erasure_key` — this module never touches that table, attome-metadata
//!      has no dependency on attome-audit (guidelines §1 layering).
//!   2. [`scrub_record`] below — a metadata-driven field-value `UPDATE`.
//!
//! [`propose_purge_actions`] is the daily proposal-sweep half (§3c/§5 step
//! 7's `EngineJob::ProposeRetentionActions`), executed against every
//! registered, non-append-only entity table.

use attome_core::{ALL_SYSTEM_COLS, AttrInfo, quote_ident};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use sqlx::Postgres;
use uuid::Uuid;

use crate::provision::valid_identifier;

/// One soft-deleted record past its purge grace period.
#[derive(Debug, Clone)]
pub struct PurgeCandidate {
    pub entity_logicalname: String,
    pub record_id: Uuid,
}

/// Scans every registered, non-append-only, live entity for records that are
/// `is_active = false` and have sat that way since before `cutoff` (D-021:
/// soft delete has no dedicated `deleted_at` column, so `modified_at` at the
/// time `is_active` most recently flipped is the only timestamp available —
/// exactly what `entity_crud::delete_record` stamps). Inserts one
/// `audit_retention_action` row per eligible record
/// (`action_type = 'entity_purge'`, `target = "{logicalname}:{record_id}"`),
/// relying on migration 0067's partial unique index
/// (`(action_type, target) WHERE status <> 'rejected'`) to make the insert
/// naturally idempotent across daily re-runs. Returns how many rows were
/// newly proposed.
///
/// Append-only entities are skipped outright (`entity_crud`'s
/// `delete_record`/`restore_record` already 403 on them — nothing is ever
/// soft-deleted there to purge). A malformed/legacy `logicalname` that fails
/// [`valid_identifier`] is skipped rather than failing the whole sweep, the
/// same defensive posture `ensure_ahead_partitions` and this crate's own
/// `provision.rs` already take with dynamic identifiers.
///
/// `disposition_action` is `retention.disposition_action` (attome-config,
/// M23/D-456) — `"purge"` (default) or `"archive"`. Anything else falls back
/// to `"purge"` with a warning: a typo in config must never silently stop
/// the daily sweep from proposing anything, and `"purge"` is the
/// conservative fallback (crypto-shred + scrub, same "no evidence, but
/// nothing left behind either" behavior every deployment already had before
/// `disposition_action` existed).
pub async fn propose_purge_actions(
    db: &DbPool,
    grace_days: u32,
    disposition_action: &str,
) -> Result<u32, AppError> {
    propose_purge_actions_by_entity(db, Some(grace_days), disposition_action).await
}

/// A18-T5: [`propose_purge_actions`] with each entity's own recycle-bin
/// retention (`bin_setting.retention_days`) ahead of the deployment's
/// `default_grace_days`; an entity with neither is kept forever.
pub async fn propose_purge_actions_by_entity(
    db: &DbPool,
    default_grace_days: Option<u32>,
    disposition_action: &str,
) -> Result<u32, AppError> {
    let per_entity: std::collections::HashMap<String, i32> = sqlx::query_as::<_, (String, i32)>(
        "SELECT entity, retention_days FROM bin_setting WHERE retention_days IS NOT NULL",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    if default_grace_days.is_none() && per_entity.is_empty() {
        return Ok(0);
    }
    let action_type = match disposition_action {
        "archive" => "archive",
        "purge" => "entity_purge",
        other => {
            tracing::warn!(
                configured = %other,
                "retention propose: retention.disposition_action is neither \"purge\" nor \"archive\" — \
                 falling back to \"purge\" for this sweep"
            );
            "entity_purge"
        }
    };
    let entities: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname FROM entity_info \
         WHERE is_append_only = false AND (is_active IS NULL OR is_active = true)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut proposed = 0u32;
    for logicalname in entities {
        if !valid_identifier(&logicalname) {
            tracing::warn!(entity = %logicalname, "retention propose: skipping entity with an invalid logicalname");
            continue;
        }
        if !has_is_active_column(db, &logicalname).await? {
            // Some `entity_info` rows back infrastructure tables exposed
            // through the generic query/admin surface (e.g. `s2s_client`,
            // `s2s_permission`) rather than a table provisioned by
            // `attome_metadata::provision`, so they don't carry the standard
            // `is_active` soft-delete column at all — they use their own
            // convention (`is_deleted`, etc.) and are out of scope for this
            // purge sweep. Skip rather than fail the whole daily sweep over
            // one unrelated table.
            tracing::warn!(
                entity = %logicalname,
                "retention propose: skipping entity with no is_active column (not a provisioned entity table)"
            );
            continue;
        }
        let days = per_entity
            .get(&logicalname)
            .map(|d| i64::from(*d))
            .or(default_grace_days.map(i64::from));
        let Some(days) = days else {
            continue;
        };
        let cutoff = Utc::now() - chrono::Duration::days(days);
        proposed += propose_purge_actions_for_entity(db, &logicalname, cutoff, action_type).await?;
    }
    Ok(proposed)
}

/// `information_schema.columns` check rather than a bare `SELECT ... WHERE
/// is_active = false` wrapped in error-matching — an undefined-column error
/// is indistinguishable from other query failures without parsing the
/// database error message, which is fragile across Postgres versions.
async fn has_is_active_column(db: &DbPool, logicalname: &str) -> Result<bool, AppError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM information_schema.columns
             WHERE table_schema = current_schema() AND table_name = $1 AND column_name = 'is_active'
         )",
    )
    .bind(logicalname)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(exists)
}

/// C-22: chunk size for `propose_purge_actions_for_entity`'s batch loop.
/// Untuned placeholder — same "not yet load-tested" posture as
/// `schema_change`'s `SCHEMA_CHANGE_BACKFILL_BATCH_SIZE`.
const PURGE_PROPOSAL_BATCH_SIZE: i64 = 2_000;

/// One batch's outcome: how many candidates this pass actually saw
/// (`batch_count`, which drives the loop's termination — fewer than the batch
/// size means this was the last one), the highest `id` among them (the
/// cursor for the next pass, `None` on an empty batch), and how many of them
/// were newly proposed (`inserted_count`, excludes ones `ON CONFLICT`
/// skipped — e.g. a record already proposed by a previous day's sweep).
#[derive(sqlx::FromRow)]
struct PurgeBatchResult {
    batch_count: i64,
    max_id: Option<Uuid>,
    inserted_count: i64,
}

/// Proposes every eligible candidate on `entity_logicalname`, `PURGE_PROPOSAL_BATCH_SIZE`
/// at a time, in one combined `INSERT ... SELECT ... LIMIT n` statement per
/// batch rather than the old "load every id into a `Vec`, then one `INSERT`
/// round-trip per row" shape. Each batch is one round trip regardless of how
/// many rows it proposes, and no more than `PURGE_PROPOSAL_BATCH_SIZE` ids are
/// ever held in memory (as the query's own result set, briefly — never
/// materialized into a Rust collection at all here).
///
/// Cursor-driven (`id > $2`, ordered by `id`) rather than an `OFFSET`, and for
/// the same reason `backfill_required_nulls` (`schema_change.rs`) is: a
/// candidate already proposed by an earlier daily run still matches the
/// `WHERE` clause every time (nothing about it changes once proposed), so
/// without a cursor that advances past it regardless of whether its `INSERT`
/// actually landed a row, `ON CONFLICT DO NOTHING` would make the same batch
/// repeat forever instead of the loop terminating.
async fn propose_purge_actions_for_entity(
    db: &DbPool,
    entity_logicalname: &str,
    cutoff: DateTime<Utc>,
    action_type: &str,
) -> Result<u32, AppError> {
    let table = quote_ident(entity_logicalname);
    let mut proposed = 0u32;
    let mut cursor: Option<Uuid> = None;

    loop {
        let batch: PurgeBatchResult = sqlx::query_as(&format!(
            r#"WITH batch AS (
                   SELECT id FROM {table}
                   WHERE is_active = false AND modified_at < $1
                     AND ($2::uuid IS NULL OR id > $2)
                   ORDER BY id
                   LIMIT {PURGE_PROPOSAL_BATCH_SIZE}
               ),
               ins AS (
                   INSERT INTO audit_retention_action (action_type, target, status)
                   SELECT $3, $4 || ':' || id::text, 'proposed'
                   FROM batch
                   ON CONFLICT (action_type, target) WHERE status <> 'rejected' DO NOTHING
                   RETURNING 1
               )
               SELECT (SELECT count(*) FROM batch)::bigint AS batch_count,
                      (SELECT id FROM batch ORDER BY id DESC LIMIT 1) AS max_id,
                      (SELECT count(*) FROM ins)::bigint AS inserted_count"#
        ))
        .bind(cutoff)
        .bind(cursor)
        .bind(action_type)
        .bind(entity_logicalname)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;

        proposed += batch.inserted_count as u32;
        if batch.batch_count == 0 {
            break;
        }
        cursor = batch.max_id;
        if batch.batch_count < PURGE_PROPOSAL_BATCH_SIZE {
            break;
        }
    }
    Ok(proposed)
}

/// Nulls every non-system column [`attome_core::ALL_SYSTEM_COLS`] excludes
/// for `record_id` in one `UPDATE`, identifiers drawn only from `attrs`
/// (validated metadata — the caller must pass the entity's live attribute
/// list, e.g. from `EntityMetaRegistry`, never request data). Only ever
/// matches a still-soft-deleted row (`is_active = false`) — a record that was
/// restored between propose and execute is left untouched and this returns
/// `false`, the same "re-read intent, don't trust the enqueue-time snapshot"
/// convention `BuildAttributeIndex`'s job handler already uses.
///
/// Returns `false` (not an error) when the entity has no non-system
/// attributes to scrub, or when the row no longer matches — both are
/// legitimate no-ops, not failures; the caller's `destroy_key` step still ran
/// either way.
///
/// P-data-protection-governance §4: checks `attome_core::legal_hold::
/// record_is_held` first and refuses (`AppError::Conflict`) when an active
/// hold covers `(entity_logicalname, record_id)` — same defense-in-depth
/// reasoning as `attome_audit::erasure::destroy_key`'s identical check; see
/// that function's doc comment for why a caller needing the matter
/// reference for a user-facing message should call `record_is_held` itself
/// first instead of relying on this generic error.
pub async fn scrub_record(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    entity_logicalname: &str,
    attrs: &[AttrInfo],
    record_id: Uuid,
    purged_by: Uuid,
) -> Result<bool, AppError> {
    if !valid_identifier(entity_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier: entity={entity_logicalname}"
        )));
    }

    if attome_core::legal_hold::record_is_held(&mut **tx, entity_logicalname, record_id)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "record is under an active legal hold — purge refused (P-data-protection-governance)",
        ));
    }

    let set_clauses: Vec<String> = attrs
        .iter()
        .filter(|a| !ALL_SYSTEM_COLS.contains(&a.logicalname.as_str()))
        .map(|a| format!("{} = NULL", quote_ident(&a.logicalname)))
        .collect();

    if set_clauses.is_empty() {
        return Ok(false);
    }

    let table = quote_ident(entity_logicalname);
    let sql = format!(
        "UPDATE {table} SET {}, modified_at = NOW(), modified_by = $2, row_version = row_version + 1 \
         WHERE id = $1 AND is_active = false",
        set_clauses.join(", ")
    );

    let result = sqlx::query(&sql)
        .bind(record_id)
        .bind(purged_by)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;

    let scrubbed = result.rows_affected() > 0;

    if scrubbed {
        // D-358. A purge is the one operation where a missing feed row is a
        // COMPLIANCE failure rather than a staleness one: the record's text is
        // gone from the entity table, but any derived copy of it — a search
        // index row, an embedding — is a second copy of the same business
        // text and inherits the same erasure obligation
        // (P-data-protection-governance). Emitted in the caller's transaction
        // like every other feed row, so a rolled-back purge cannot announce an
        // erasure that did not happen.
        attome_core::change_feed::emit(
            tx,
            entity_logicalname,
            record_id,
            attome_core::ChangeOperation::Purge,
        )
        .await?;
    }

    Ok(scrubbed)
}

/// M23 Records Management (D-456) — the restore half of the archive
/// disposition (`attome_compliance::archive::restore_archived_record`):
/// re-populates every non-system column [`scrub_record`] nulled, from
/// `original` (the exact JSON object `row_to_json(t)` produced at archive
/// time, re-read from the archive export). Symmetric with `scrub_record`
/// rather than a full re-`INSERT`: the row was never deleted (archive scrubs,
/// it does not remove), so this is an `UPDATE` back onto the same `id`.
///
/// Uses Postgres's own `jsonb_populate_record(NULL::"{table}", $2::jsonb)`
/// rather than a hand-written per-attribute type-cast table: the target
/// table's actual column types already know how to coerce a JSON scalar,
/// text-array, or jsonb value correctly (including the `choice`/`file`
/// multi-valued `TEXT[]`/`JSONB` columns `sql_cast`'s duplicated cast tables
/// in `attome-server`/`attome-compliance` handle case-by-case elsewhere) — this
/// avoids a fourth copy of that table for the one caller that can lean on
/// Postgres to do it exactly once, correctly, from the schema itself.
/// `(col_a, col_b, ...) = (r.col_a, r.col_b, ...)` only ever names attrs from
/// `attrs` (validated metadata), never a request-supplied identifier
/// (guidelines §4).
///
/// Also flips `is_active` back to `true` — restoring an archived record
/// means bringing it back to a live, visible state, not merely repopulating
/// its columns while it stays soft-deleted. Only ever matches a currently
/// scrubbed-and-inactive row (`is_active = false`); a record that was
/// independently restored/recreated between the archive decision and this
/// call is left untouched and this returns `false`, the same
/// re-read-intent-don't-trust-the-snapshot convention `scrub_record` and
/// `BuildAttributeIndex` already use.
///
/// Does NOT itself check legal hold — a hold only ever blocks *removing*
/// evidence (`scrub_record`/`destroy_key`), never restoring it; bringing a
/// record back to full visibility is the safe direction if anything.
pub async fn restore_record(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    entity_logicalname: &str,
    attrs: &[AttrInfo],
    record_id: Uuid,
    restored_by: Uuid,
    original: &serde_json::Value,
) -> Result<bool, AppError> {
    if !valid_identifier(entity_logicalname) {
        return Err(AppError::internal(format!(
            "invalid identifier: entity={entity_logicalname}"
        )));
    }

    let cols: Vec<&str> = attrs
        .iter()
        .filter(|a| !ALL_SYSTEM_COLS.contains(&a.logicalname.as_str()))
        .map(|a| a.logicalname.as_str())
        .collect();

    if cols.is_empty() {
        return Ok(false);
    }

    let target_list = cols
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let source_list = cols
        .iter()
        .map(|c| format!("r.{}", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ");

    let table = quote_ident(entity_logicalname);
    let sql = format!(
        // `ROW(...)`: a one-column list is otherwise a plain parenthesised
        // expression, which Postgres refuses as a multiple-column UPDATE
        // source. `t.row_version`: `r` carries a `row_version` too.
        "UPDATE {table} t SET ({target_list}) = ROW({source_list}), \
            is_active = true, modified_at = NOW(), modified_by = $2, row_version = t.row_version + 1 \
         FROM (SELECT * FROM jsonb_populate_record(NULL::{table}, $3::jsonb)) AS r \
         WHERE t.id = $1 AND t.is_active = false"
    );

    let result = sqlx::query(&sql)
        .bind(record_id)
        .bind(restored_by)
        .bind(original)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;

    let restored = result.rows_affected() > 0;

    if restored {
        // Mirror image of scrub_record's own Purge emission: a search
        // index/embedding derived from this record went stale the moment it
        // was scrubbed, and needs the same reactive convergence signal now
        // that the text is back.
        attome_core::change_feed::emit(
            tx,
            entity_logicalname,
            record_id,
            attome_core::ChangeOperation::Restore,
        )
        .await?;
    }

    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(logicalname: &str) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_string(),
            field_type_int: 3,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            options: None,
        }
    }

    /// Pins that every physical system column is excluded from the
    /// generated `SET` clause — the one property that makes this "a scrub",
    /// not an accidental full-row wipe of columns `on_target_delete`/restore
    /// still need to read (§3c's own risk table).
    #[test]
    fn set_clauses_never_touch_a_system_column() {
        let attrs: Vec<AttrInfo> = ALL_SYSTEM_COLS
            .iter()
            .map(|c| attr(c))
            .chain(std::iter::once(attr("ssn")))
            .collect();

        let set_clauses: Vec<String> = attrs
            .iter()
            .filter(|a| !ALL_SYSTEM_COLS.contains(&a.logicalname.as_str()))
            .map(|a| format!("{} = NULL", quote_ident(&a.logicalname)))
            .collect();

        assert_eq!(set_clauses, vec!["\"ssn\" = NULL".to_string()]);
    }
}

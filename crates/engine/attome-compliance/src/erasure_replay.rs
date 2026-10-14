//! R2-T1: applying the erasure ledger to the database, at boot, before the
//! server serves. After `attome restore` the database is as old as its
//! backup; every erasure since then is in the ledger (object storage, not in
//! the backup set) and is applied again here: the audit key destroyed, the
//! recovery-archive and release-report copies deleted, and a purged record's
//! sensitive fields scrubbed.
//!
//! Only entries whose key is not already destroyed are replayed, found with
//! one query, so an ordinary boot does no per-entry work.

use attome_audit::erasure_ledger::{self, ErasureKind, LedgerEntry};
use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// What a replay did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplayReport {
    /// Entries in the ledger.
    pub entries: usize,
    /// Entries applied again because the database had not erased them.
    pub replayed: usize,
    /// Live audit keys destroyed again.
    pub keys_destroyed: usize,
}

/// The ledger entries whose record still has a live key, or no key row at
/// all (nothing tells us it was erased).
async fn pending(db: &attome_db::DbPool, entries: &[LedgerEntry]) -> Result<Vec<Uuid>, AppError> {
    let ids: Vec<Uuid> = entries.iter().map(|e| e.record_id).collect();
    sqlx::query_scalar(
        "SELECT id FROM unnest($1::uuid[]) AS ledger(id) \
         WHERE NOT EXISTS (SELECT 1 FROM audit_erasure_key k \
                           WHERE k.record_id = ledger.id AND k.wrapped_dek IS NULL)",
    )
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)
}

async fn apply(state: &EngineState, entry: &LedgerEntry) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let destroyed = attome_audit::erasure::replay_destroy(&mut tx, entry.record_id).await?;
    attome_core::recovery_archive::erase_record(&mut tx, &entry.entity, entry.record_id).await?;
    attome_core::release_report::erase_record(&mut tx, &entry.entity, entry.record_id).await?;
    if entry.kind == ErasureKind::Purge {
        let registry = state.entities.load();
        match registry.get(&entry.entity) {
            Some(meta) => {
                attome_metadata::purge::scrub_record(
                    &mut tx,
                    &entry.entity,
                    &meta.attrs,
                    entry.record_id,
                    Uuid::nil(),
                )
                .await?;
            }
            None => tracing::warn!(
                entity = %entry.entity,
                record_id = %entry.record_id,
                "erasure replay: the entity is no longer registered; its fields were not scrubbed"
            ),
        }
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(destroyed)
}

/// Applies every ledger entry the database has not. Stops at the first
/// failure: a partly replayed ledger must not look complete.
pub async fn replay(state: &EngineState) -> Result<ReplayReport, AppError> {
    let entries = erasure_ledger::read_all(&state.base.storage).await?;
    let mut report = ReplayReport {
        entries: entries.len(),
        ..ReplayReport::default()
    };
    if entries.is_empty() {
        return Ok(report);
    }
    let to_apply: std::collections::HashSet<Uuid> = pending(&state.base.db, &entries)
        .await?
        .into_iter()
        .collect();
    for entry in entries.iter().filter(|e| to_apply.contains(&e.record_id)) {
        if apply(state, entry).await? {
            report.keys_destroyed += 1;
        }
        report.replayed += 1;
    }
    Ok(report)
}

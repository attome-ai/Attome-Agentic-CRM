//! Node-run payload retention (roadmap M3-T4). A node run's `input` and
//! `output` (or its object-storage `payload_ref`, M3-T1) are kept for
//! `jobs.workflow_payload_retention_days` after the step finished; then the
//! payload goes and the run's summary (status, attempts, error, times) stays.
//! Run daily by `EngineJob::PruneApalisJobHistory`.
//!
//! Erasure (`attome_core::run_payload::erase_record`) clears the inline
//! payloads that mention an erased record at once; a payload kept in object
//! storage cannot be searched in place and goes at this retention instead.

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// Rows cleared per batch, and the most batches one run takes.
const BATCH: i64 = 500;
const MAX_BATCHES: usize = 200;

/// Clears the payloads of steps finished more than `days` ago. Returns how
/// many runs were cleared.
pub async fn prune_payloads(state: &EngineState, days: i64) -> Result<u64, AppError> {
    let days = days.max(1);
    let mut cleared = 0u64;
    for _ in 0..MAX_BATCHES {
        let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
            "SELECT id, payload_ref FROM workflow_node_run \
              WHERE completed_at < NOW() - make_interval(days => $1::int) \
                AND (input IS NOT NULL OR output IS NOT NULL OR payload_ref IS NOT NULL) \
              ORDER BY completed_at LIMIT $2",
        )
        .bind(days)
        .bind(BATCH)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if rows.is_empty() {
            break;
        }
        // Objects first, outside any transaction; a failed delete keeps
        // its row's reference so the next run tries again.
        let mut done: Vec<Uuid> = Vec::with_capacity(rows.len());
        for (id, payload_ref) in &rows {
            match payload_ref {
                Some(key) => {
                    match attome_storage::mirror::delete_object(&state.base.storage, key).await {
                        Ok(()) => done.push(*id),
                        Err(e) => {
                            tracing::warn!(node_run_id = %id, error = %e, "workflow payload object not deleted; retried next run");
                        }
                    }
                }
                None => done.push(*id),
            }
        }
        let n = sqlx::query(
            "UPDATE workflow_node_run SET input = NULL, output = NULL, payload_ref = NULL \
              WHERE id = ANY($1)",
        )
        .bind(&done)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        cleared += n;
        if (rows.len() as i64) < BATCH || done.is_empty() {
            break;
        }
    }
    if cleared > 0 {
        tracing::info!(
            cleared,
            days,
            "workflow node-run payloads past retention cleared"
        );
    }
    Ok(cleared)
}

//! Erasure of workflow step payloads (roadmap M3-T4): when a record is
//! erased, every workflow node run whose recorded input or output mentions
//! its id loses that payload, in the erasure's own transaction. The run's
//! summary (status, attempts, times) stays. Payloads kept in object storage
//! (`payload_ref`) cannot be searched in place; they go at the payload
//! retention (`attome_workflow::retention`).

use attome_types::AppError;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Clears the inline payloads that mention `record_id`. Returns how many
/// runs were cleared.
pub async fn erase_record(
    tx: &mut Transaction<'_, Postgres>,
    record_id: Uuid,
) -> Result<u64, AppError> {
    let needle = format!("%{record_id}%");
    sqlx::query(
        "UPDATE workflow_node_run SET input = NULL, output = NULL \
          WHERE input::text LIKE $1 OR output::text LIKE $1",
    )
    .bind(&needle)
    .execute(&mut **tx)
    .await
    .map(|r| r.rows_affected())
    .map_err(AppError::internal)
}

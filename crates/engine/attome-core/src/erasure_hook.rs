//! E8-T9: an engine's own step in erasing a record (a data subject's
//! erasure, a direct erasure, a replayed one).
//!
//! The erasure paths (`attome_compliance`) delete what the platform keeps
//! about a record, but an engine may hold rows of its own keyed by the
//! record's id (a journey's enrolments and message log, say), and the
//! compliance crate cannot depend on every engine. An engine declares its
//! step through `EngineModel::erasure_hooks`; `ModelRegistry` collects them
//! into `EngineState::erasure_hooks` at boot and every erasure path runs
//! [`run`] in its own transaction, so the engine's rows go with the record
//! or not at all. Same declare/collect/enforce shape as
//! [`crate::record_check`].
//!
//! A hook must not do external I/O (guidelines §4) and should be cheap for a
//! record it holds nothing about.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::state::EngineState;

/// What a hook returns: the rows it removed or changed.
pub type ErasureFuture<'a> = Pin<Box<dyn Future<Output = Result<u64, AppError>> + Send + 'a>>;

/// One engine's step in erasing a record.
pub trait ErasureHook: Send + Sync + 'static {
    /// A short name for logs (`marketing_journeys`).
    fn name(&self) -> &'static str;

    /// Removes what the engine keeps about `record_id` of `entity`.
    fn erase<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        record_id: Uuid,
    ) -> ErasureFuture<'a>;
}

/// Runs every engine's hook for one erased record; the rows they removed.
pub async fn run(
    state: &EngineState,
    conn: &mut PgConnection,
    entity: &str,
    record_id: Uuid,
) -> Result<u64, AppError> {
    let mut total = 0;
    for hook in state.erasure_hooks.iter() {
        let removed = hook.erase(&mut *conn, entity, record_id).await?;
        if removed > 0 {
            tracing::info!(%record_id, entity, hook = hook.name(), removed, "erasure: engine rows removed");
        }
        total += removed;
    }
    Ok(total)
}

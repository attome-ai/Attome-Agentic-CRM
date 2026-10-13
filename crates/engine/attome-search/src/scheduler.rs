//! The drain scheduler — what actually keeps the index current.
//!
//! `drain_once` and `corpus::project_record` are both pure capability: without
//! something calling them on a cadence, **nothing is ever indexed** and search
//! is a working feature over an empty table. That failure mode produces no
//! error at any layer — the query runs, the permission filter applies, the
//! response is a well-formed empty page — so it survives every test that seeds
//! the index directly, which is all of them.
//!
//! ## One node drains, not all of them
//!
//! The cursor (`change_consumer_cursor`) is a single shared position.
//! N nodes draining concurrently would each read the same batch, each do the
//! same projection work, and race to advance the same row: correct, because
//! every operation is idempotent and `advance` takes a `GREATEST` guard, and
//! *wasteful* in exactly the way that scales with node count — at Stage 2 that
//! waste is N× the embedding cost.
//!
//! So each tick takes `pg_try_advisory_xact_lock`. **Try**, never blocking: a
//! node that does not get the lock has nothing to wait for, because whoever
//! holds it is doing the identical work. It skips the tick and comes back.
//!
//! ## Why a supervised loop and not the job queue
//!
//! Guidelines §10 sends restart-surviving work to the persistent queue. What
//! must survive a restart here is the *cursor*, and that already lives in
//! PostgreSQL — losing a tick loses nothing, because the next tick reads from
//! the same position. Enqueueing a job per tick would put a row in the queue
//! every five seconds forever to express "check whether there is anything to
//! do", which is queue traffic proportional to time rather than to work.
//!
//! ## Failure is logged loudly and never fatal
//!
//! A drain error must not kill the loop: the most likely causes (a transient
//! connection error, one malformed record, a lock timeout) all resolve on the
//! next tick, and a dead loop means a silently freezing index. It is logged at
//! `error` — `metrics::INDEX_STALENESS` is the signal that turns a persistent
//! failure into an alert, because a log line nobody reads is not a signal.

use std::sync::Arc;
use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use sqlx::PgPool;

use crate::drain::{DrainStats, drain_once};

/// How many published-but-unchunked items one catch-up pass projects.
///
/// Bounded for the same reason `DRAIN_BATCH` is: a deployment that upgrades
/// into this feature with a large corpus must not hold one long transaction,
/// and the pass is idempotent so a smaller bound costs only restarts.
pub const KNOWLEDGE_BACKFILL_BATCH: i64 = 200;

/// How often a tick runs.
///
/// Five seconds is §11's "write → searchable" p50 budget, and the loop's
/// cadence is the floor of that number — a record written just after a tick
/// waits a full interval before it is even considered. Lowering it trades
/// database round trips for freshness; raising it past 15 s breaks the p95
/// budget outright.
pub const DRAIN_INTERVAL: Duration = Duration::from_secs(5);

/// Advisory-lock key. `{crate}/{operation}:{resource}` per guidelines §2.
const DRAIN_LOCK_KEY: &str = "attome-search/drain:record-corpus";

/// Embedding batches one tick may run (D-498 step 5).
///
/// Bounded so a large backlog of unembedded chunks cannot keep a tick busy
/// indefinitely; the rest is picked up on later ticks.
pub const EMBED_BATCHES_PER_TICK: usize = 4;

/// Runs one tick, taking the lock. `Ok(None)` means another node held it.
///
/// The lock is transaction-scoped, so it is released by the commit at the end
/// of this function or by the rollback if anything fails — there is no path
/// that leaks it, which is the property `pg_advisory_lock`'s session-scoped
/// form cannot offer and the reason guidelines §2 forbids it.
pub async fn drain_tick(state: &EngineState) -> Result<Option<DrainStats>, AppError> {
    let db: &PgPool = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;

    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(DRAIN_LOCK_KEY)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !acquired {
        return Ok(None);
    }

    // The registry snapshot is read once per tick, not per event: it is
    // swapped atomically, and re-reading per record would let one batch project
    // some records against the old metadata and some against the new — an index
    // that disagrees with itself about what a field is.
    let registry: Arc<attome_core::EntityMetaRegistry> =
        arc_swap::Guard::into_inner(state.entities.load());
    let project = |entity: &str, id: uuid::Uuid| {
        let db = db.clone();
        let registry = Arc::clone(&registry);
        let entity = entity.to_owned();
        Box::pin(async move { crate::corpus::project_record(&db, &registry, &entity, id).await })
            as std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>>
    };

    let stats = drain_once(db, &project).await?;

    // Committed even on an empty batch: the transaction exists to scope the
    // lock, and the cursor advance inside `drain_once` runs on its own
    // connection.
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Some(stats))
}

/// The model chunk vectors are written with, or `None` when knowledge is
/// lexical-only by configuration: no embedding endpoint, or the AI kill-switch
/// has semantic search off. The same two conditions [`semantic_embedder`]
/// checks first; the coverage read (`crate::knowledge_coverage`) measures the
/// embedding backlog against this model.
pub fn configured_embedding_model(state: &EngineState) -> Option<&str> {
    let inference = &state.base.config.inference;
    if inference.embedding.base_url.trim().is_empty()
        || !inference
            .ai
            .allows(attome_config::AiSurface::SemanticSearch)
    {
        return None;
    }
    Some(inference.embedding.model.as_str())
}

/// The embedding client this node uses to fill in chunk vectors, or `None` for
/// lexical-only.
///
/// `None` when no embedding endpoint is configured (a supported deployment,
/// D-360 ruling 6), when the AI kill-switch has semantic search off, or when
/// the client cannot be built. The endpoint's locality was already checked at
/// boot (D-506). Each case is logged once, at loop start, so an operator can
/// see why vectors are or are not being written.
fn semantic_embedder(state: &EngineState) -> Option<attome_inference::EmbeddingClient> {
    let inference = &state.base.config.inference;
    if inference.embedding.base_url.trim().is_empty() {
        return None;
    }
    if !inference
        .ai
        .allows(attome_config::AiSurface::SemanticSearch)
    {
        tracing::info!(
            "an embedding endpoint is configured but semantic search is switched off; \
             knowledge stays lexical-only"
        );
        return None;
    }
    match attome_inference::EmbeddingClient::new(inference) {
        Ok(client) => {
            tracing::info!(
                model = client.model_id(),
                "knowledge embedding writer enabled"
            );
            Some(client)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "the embedding client could not be built; knowledge stays lexical-only"
            );
            None
        }
    }
}

/// Runs up to [`EMBED_BATCHES_PER_TICK`] embedding passes, stopping when a pass
/// finds fewer chunks than a full batch.
///
/// A failed pass is logged and ends this tick's passes. The chunks it did not
/// embed keep an empty vector and stay retrievable lexically, and a later tick
/// retries them.
async fn run_embedding_passes(db: &PgPool, client: &attome_inference::EmbeddingClient) {
    use crate::embedding_writer::{EMBED_BATCH, embed_pending_chunks};
    for _ in 0..EMBED_BATCHES_PER_TICK {
        match embed_pending_chunks(db, client, EMBED_BATCH).await {
            Ok(stats) => {
                if stats.selected > 0 {
                    tracing::debug!(
                        embedded = stats.embedded,
                        skipped_changed = stats.skipped_changed,
                        "knowledge embedding pass"
                    );
                }
                if stats.selected < EMBED_BATCH as u64 {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "knowledge embedding pass failed; chunks stay lexical-only until a later tick"
                );
                break;
            }
        }
    }
}

/// The supervised loop. Spawn once per process.
///
/// Returns when `shutdown` resolves, so a node drains up to the moment it stops
/// rather than being killed mid-batch — a batch cut short is safe (every
/// operation is idempotent and the cursor advances per event) but it re-does
/// work on the next boot, which at Stage 2 is re-done GPU work.
pub async fn run_drain_loop(state: EngineState, shutdown: impl std::future::Future<Output = ()>) {
    // Catch up items published before this producer existed, or while no node
    // was draining (D-489). Bounded, idempotent, and deliberately not a durable
    // job: the work is a pure function of current state, so losing a pass costs
    // one restart's delay and nothing else — the same reasoning this module's
    // header already gives for not enqueueing a job per tick.
    loop {
        match crate::knowledge_index::backfill_missing(&state.base.db, KNOWLEDGE_BACKFILL_BATCH)
            .await
        {
            Ok(n) if n > 0 => {
                tracing::info!(items = n, "knowledge chunk backfill projected a batch");
                if n < KNOWLEDGE_BACKFILL_BATCH as u64 {
                    break;
                }
            }
            Ok(_) => break,
            Err(e) => {
                tracing::warn!(error = %e, "knowledge chunk backfill skipped; retrying on next boot");
                break;
            }
        }
    }

    let embedder = semantic_embedder(&state);

    let mut ticker = tokio::time::interval(DRAIN_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("search drain loop stopping");
                return;
            }
            _ = ticker.tick() => {
                let outcome = drain_tick(&state).await;
                // Only the node that just held the drain lock embeds, so
                // several nodes do not repeat the same model work. The lock is
                // already released here — the model call must not run inside
                // the lock's transaction — so an overlap with the next tick's
                // holder is possible and harmless: every write is idempotent
                // and hash-guarded.
                let held_lock = matches!(outcome, Ok(Some(_)));
                match outcome {
                    Ok(Some(stats)) if stats.read > 0 => {
                        tracing::debug!(
                            read = stats.read,
                            written = stats.written,
                            skipped_unchanged = stats.skipped_unchanged,
                            deleted = stats.deleted,
                            knowledge_written = stats.knowledge_written,
                            knowledge_removed = stats.knowledge_removed,
                            "search drain tick"
                        );
                    }
                    // Nothing to do, or another node holds the lock. Both are
                    // the normal steady state and neither is worth a log line
                    // every five seconds.
                    Ok(_) => {}
                    Err(e) => {
                        // Loud, and NOT fatal: the likely causes all clear on
                        // the next tick, and a dead loop is a silently freezing
                        // index. `metrics::INDEX_STALENESS` is what turns a
                        // persistent failure into an alert.
                        tracing::error!(error = %e, "search drain tick failed; retrying next tick");
                    }
                }
                if held_lock && let Some(client) = &embedder {
                    // C11 B5: an operator can stop embedding at runtime; the
                    // switch is read before each pass, and fails closed.
                    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
                    if attome_core::ai_runtime_switch::allows(
                        &state.base.config.inference.ai,
                        attome_config::AiSurface::SemanticSearch,
                    ) {
                        run_embedding_passes(&state.base.db, client).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lock key follows `{crate}/{operation}:{resource}` and is bound
    /// through the two-argument form with this crate's namespace — the
    /// one-argument form would put every subsystem's keys into one 32-bit
    /// space, where an unrelated collision surfaces as a spurious skipped
    /// drain (D-351).
    #[test]
    fn the_lock_key_is_namespaced_and_scoped() {
        assert!(DRAIN_LOCK_KEY.starts_with("attome-search/"));
        assert!(DRAIN_LOCK_KEY.contains(':'));
    }

    /// The cadence has to satisfy §11's staleness budget. A tick interval at or
    /// above the p95 bound cannot meet it even when every tick succeeds
    /// instantly.
    #[test]
    fn the_cadence_fits_the_staleness_budget() {
        const _: () = assert!(DRAIN_INTERVAL.as_secs() <= 5, "p50 write→searchable is 5s");
    }
}

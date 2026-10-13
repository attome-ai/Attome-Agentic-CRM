//! F025 — named wrappers around `sqlx::Transaction` begin/commit so call sites
//! stop hand-writing `.begin().await.map_err(AppError::internal)?` (repeated
//! across entity_crud.rs/admin.rs/s2s_admin.rs/etc.). Rollback needs no
//! wrapper: an uncommitted `Tx` rolls back on `Drop`, so an early `?` return
//! from any of these call sites already rolls back — that guarantee comes
//! from sqlx itself, not from anything added here.
//!
//! Both map errors through [`crate::classify`] (attome-db hardening Phase 1.2),
//! the same pipeline query call sites use, instead of a blanket
//! `AppError::internal`.
use attome_types::AppError;

use crate::{DbPool, Tx};

/// Begins a transaction. A pool that can't provide a connection (acquire
/// timeout, or a closed pool) is `AppError::Overloaded("db_pool")`, a 503;
/// any other failure stays a masked 500.
///
/// An acquire timeout logs one structured `warn` with the pool's state at that
/// moment (`event = "db.pool.acquire_timeout"`) and runs the hook installed
/// with [`crate::set_acquire_timeout_hook`] (attome-db hardening 4.3). It's
/// handled here rather than in [`crate::classify`] so the event is logged and
/// counted once, with pool numbers `classify` has no access to.
#[expect(
    clippy::disallowed_methods,
    reason = "attome_db::tx::begin is the sanctioned wrapper, the one place Pool::begin is called"
)]
pub async fn begin(pool: &DbPool) -> Result<Tx<'_>, AppError> {
    match pool.begin().await {
        Ok(tx) => Ok(tx),
        Err(sqlx::Error::PoolTimedOut) => {
            let acquire_timeout = pool.options().get_acquire_timeout();
            tracing::warn!(
                event = "db.pool.acquire_timeout",
                breaker = "db_pool",
                pool_size = pool.size(),
                pool_idle = pool.num_idle(),
                acquire_timeout_ms = u64::try_from(acquire_timeout.as_millis()).unwrap_or(u64::MAX),
                "database connection pool could not provide a connection in time"
            );
            crate::error::note_acquire_timeout();
            Err(AppError::Overloaded("db_pool"))
        }
        Err(error) => Err(crate::classify(error)),
    }
}

/// Commits a transaction, classifying a commit-time failure with
/// [`crate::classify`].
///
/// The commit-time mappings are **defensive**. A unique violation at commit
/// (`23505` → 409) needs a `DEFERRABLE` constraint, and a serialization
/// failure (`40001` → retryable 409) needs REPEATABLE READ or SERIALIZABLE.
/// As of Phase 1.2 no production code uses either, so today these fire only
/// once someone adds one; `tests/tx_errors.rs` proves the mapping holds when
/// they do.
pub async fn commit(tx: Tx<'_>) -> Result<(), AppError> {
    tx.commit().await.map_err(crate::classify)
}

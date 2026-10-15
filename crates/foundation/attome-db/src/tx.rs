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
    let started = std::time::Instant::now();
    let result = pool.begin().await;
    // Z2-T12: the wait, and a timeout, per pool role.
    let role = pool.connect_options().get_username().to_owned();
    match result {
        Ok(tx) => {
            crate::error::note_acquire_wait(&role, started.elapsed());
            Ok(tx)
        }
        Err(sqlx::Error::PoolTimedOut) => {
            crate::error::note_role_acquire_timeout(&role);
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

/// Z2-T5: what a transaction is for, which sets how long its statements may
/// run, wait for a lock and sit idle inside the transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementClass {
    /// Interactive reads and small writes: 500 ms, lock 200 ms.
    Fast,
    /// Ordinary requests: 5 s, lock 1 s.
    Standard,
    /// Reports and exports: 60 s, lock 1 s.
    Report,
    /// Administrative work: 300 s, lock 5 s.
    Admin,
}

pub use attome_config::StatementClassTimeouts;

/// Idle in transaction, every class: a transaction left open this long by a
/// stalled caller is ended by PostgreSQL rather than holding its locks.
const IDLE_IN_TRANSACTION_MS: u64 = 10_000;

impl StatementClass {
    /// The built-in timeouts.
    pub fn defaults(self) -> StatementClassTimeouts {
        let (statement_timeout_ms, lock_timeout_ms) = match self {
            StatementClass::Fast => (500, 200),
            StatementClass::Standard => (5_000, 1_000),
            StatementClass::Report => (60_000, 1_000),
            StatementClass::Admin => (300_000, 5_000),
        };
        StatementClassTimeouts {
            statement_timeout_ms,
            lock_timeout_ms,
            idle_in_transaction_timeout_ms: IDLE_IN_TRANSACTION_MS,
        }
    }

    /// The timeouts in force: `database.statement_classes` when it sets this
    /// class, else [`Self::defaults`].
    pub fn timeouts(
        self,
        classes: &attome_config::StatementClassOverrides,
    ) -> StatementClassTimeouts {
        let configured = match self {
            StatementClass::Fast => classes.fast,
            StatementClass::Standard => classes.standard,
            StatementClass::Report => classes.report,
            StatementClass::Admin => classes.admin,
        };
        configured.unwrap_or_else(|| self.defaults())
    }
}

/// Z2-T5: begins a transaction whose statements run under `class`'s
/// timeouts. Set with `set_config(.., true)`, which is transaction-local
/// like `SET LOCAL`, so nothing leaks to the pooled connection's next user
/// (pgbouncer transaction mode included); the values are bound.
pub async fn begin_class<'p>(
    pool: &'p DbPool,
    class: StatementClass,
    config: &attome_config::AppConfig,
) -> Result<Tx<'p>, AppError> {
    let timeouts = class.timeouts(&config.database.statement_classes);
    let mut tx = begin(pool).await?;
    sqlx::query(
        "SELECT set_config('statement_timeout', $1, true), \
                set_config('lock_timeout', $2, true), \
                set_config('idle_in_transaction_session_timeout', $3, true)",
    )
    .bind(timeouts.statement_timeout_ms.to_string())
    .bind(timeouts.lock_timeout_ms.to_string())
    .bind(timeouts.idle_in_transaction_timeout_ms.to_string())
    .execute(&mut *tx)
    .await
    .map_err(crate::classify)?;
    Ok(tx)
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

#[cfg(test)]
mod tests {
    use super::StatementClass;

    /// Z2-T5: the class defaults, and an override replacing one class only.
    #[test]
    fn statement_classes_default_and_override() {
        let fast = StatementClass::Fast.defaults();
        assert_eq!(
            (fast.statement_timeout_ms, fast.lock_timeout_ms),
            (500, 200)
        );
        assert_eq!(
            StatementClass::Admin.defaults().statement_timeout_ms,
            300_000
        );
        assert!(
            [
                StatementClass::Fast,
                StatementClass::Standard,
                StatementClass::Report,
                StatementClass::Admin
            ]
            .iter()
            .all(|c| c.defaults().idle_in_transaction_timeout_ms == 10_000)
        );

        let mut classes = attome_config::StatementClassOverrides {
            report: Some(attome_config::StatementClassTimeouts {
                statement_timeout_ms: 120_000,
                lock_timeout_ms: 2_000,
                idle_in_transaction_timeout_ms: 20_000,
            }),
            ..Default::default()
        };
        assert_eq!(
            StatementClass::Report
                .timeouts(&classes)
                .statement_timeout_ms,
            120_000
        );
        assert_eq!(
            StatementClass::Standard.timeouts(&classes),
            StatementClass::Standard.defaults()
        );
        classes.report = None;
        assert_eq!(
            StatementClass::Report.timeouts(&classes),
            StatementClass::Report.defaults()
        );
    }
}

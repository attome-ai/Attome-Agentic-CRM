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

/// Z2-T3: how often and how fast [`with_retry`] tries again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts in all, the first included.
    pub max_attempts: u8,
    /// The pause before the first retry; each later one is four times longer.
    pub base_delay: std::time::Duration,
}

impl RetryPolicy {
    /// Three attempts, pausing about 40 ms and then 160 ms.
    pub const SHORT: RetryPolicy = RetryPolicy {
        max_attempts: 3,
        base_delay: std::time::Duration::from_millis(10),
    };

    /// The pause after failed attempt `attempt` (1-based): `base_delay *
    /// 4^attempt` plus up to half again, so racing callers spread apart.
    fn delay(self, attempt: u8, jitter_seed: u32) -> std::time::Duration {
        let base = self
            .base_delay
            .saturating_mul(4u32.saturating_pow(u32::from(attempt)));
        let jitter_percent = jitter_seed % 51;
        base + base * jitter_percent / 100
    }
}

/// The future a [`with_retry`] body returns.
pub type TxFuture<'c, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, sqlx::Error>> + Send + 'c>>;

/// `true` for the two failures a retry can cure: `40001`
/// (serialization_failure) and `40P01` (deadlock_detected).
fn is_retryable(error: &sqlx::Error) -> bool {
    crate::sqlstate(error).is_some_and(|code| code == "40001" || code == "40P01")
}

/// Z2-T3: runs `body` in a transaction, and again in a fresh one when the
/// body or the commit fails with a serialization failure or a deadlock,
/// until `policy` runs out; then the conflict is returned classified (409)
/// as before. Any other error is returned at once through
/// [`crate::classify`].
///
/// **The body must be safe to run more than once and must do no Redis,
/// HTTP, S3, email or filesystem I/O**: a retried attempt runs it again from
/// the start, and only the database work of the last attempt survives. Put
/// side effects after the call. `class` names the transaction in the
/// `db_tx_retries_total` and `db_tx_retry_exhausted_total` counters.
pub async fn with_retry<'p, T, F>(
    pool: &'p DbPool,
    class: &'static str,
    policy: RetryPolicy,
    mut body: F,
) -> Result<T, AppError>
where
    F: for<'c> FnMut(&'c mut Tx<'p>) -> TxFuture<'c, T>,
{
    let max_attempts = policy.max_attempts.max(1);
    let mut attempt: u8 = 0;
    loop {
        attempt += 1;
        let mut tx = begin(pool).await?;
        let outcome = match body(&mut tx).await {
            Ok(value) => tx.commit().await.map(|()| value),
            Err(error) => {
                drop(tx);
                Err(error)
            }
        };
        match outcome {
            Ok(value) => return Ok(value),
            Err(error) if is_retryable(&error) && attempt < max_attempts => {
                crate::error::note_tx_retry(class);
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.subsec_nanos());
                tokio::time::sleep(policy.delay(attempt, seed)).await;
            }
            Err(error) => {
                if is_retryable(&error) {
                    crate::error::note_tx_retry_exhausted(class);
                }
                return Err(crate::classify(error));
            }
        }
    }
}

/// The conflict [`crate::classify`] gives a serialization failure (`40001`)
/// or a deadlock (`40P01`).
pub const RETRYABLE_CONFLICT: &str =
    "the database detected a conflicting concurrent transaction; retry the request";

/// Z2-T4: whether `error` came from a serialization failure or a deadlock:
/// the conflict [`crate::classify`] returns for one, or an internal error
/// whose driver text names one (a statement mapped with
/// `AppError::internal`, which keeps only the text). PostgreSQL's English
/// messages are matched; under another `lc_messages` such an internal error
/// is not retried and fails as it did before.
pub fn is_retryable_error(error: &AppError) -> bool {
    match error {
        AppError::Conflict(message) => *message == RETRYABLE_CONFLICT,
        AppError::Internal(detail) => {
            detail.contains("deadlock detected") || detail.contains("could not serialize access")
        }
        _ => false,
    }
}

/// Z2-T4: [`with_retry`] for a body that speaks `AppError`: runs `attempt`
/// again while it fails with a serialization failure or a deadlock
/// ([`is_retryable_error`]), until `policy` runs out, then returns the last
/// error. Any other error is returned at once.
///
/// **Each attempt must open and commit its own transaction, do no Redis,
/// HTTP, S3, email or filesystem I/O before its commit, and nothing after
/// its commit that can fail with one of these errors**: a failed attempt
/// then left nothing behind, and running it again is safe. `class` names it
/// in the `db_tx_retries_total` and `db_tx_retry_exhausted_total` counters.
pub async fn retry_conflicts<T, F, Fut>(
    class: &'static str,
    policy: RetryPolicy,
    mut attempt: F,
) -> Result<T, AppError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, AppError>>,
{
    let max_attempts = policy.max_attempts.max(1);
    let mut tries: u8 = 0;
    loop {
        tries += 1;
        match attempt().await {
            Err(error) if is_retryable_error(&error) && tries < max_attempts => {
                crate::error::note_tx_retry(class);
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.subsec_nanos());
                tokio::time::sleep(policy.delay(tries, seed)).await;
            }
            Err(error) => {
                if is_retryable_error(&error) {
                    crate::error::note_tx_retry_exhausted(class);
                }
                return Err(error);
            }
            ok => return ok,
        }
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

#[cfg(test)]
mod tests {
    use super::StatementClass;

    /// Z2-T4: the errors an AppError-level retry runs again on.
    #[test]
    fn retryable_errors_are_the_conflict_and_the_driver_text() {
        use attome_types::AppError;

        use super::{RETRYABLE_CONFLICT, is_retryable_error};

        assert!(is_retryable_error(&AppError::Conflict(RETRYABLE_CONFLICT)));
        assert!(is_retryable_error(&AppError::Internal(
            "error returned from database: deadlock detected".into()
        )));
        assert!(is_retryable_error(&AppError::Internal(
            "error returned from database: could not serialize access due to concurrent update"
                .into()
        )));
        assert!(!is_retryable_error(&AppError::Conflict("version_conflict")));
        assert!(!is_retryable_error(&AppError::Internal("boom".into())));
        assert!(!is_retryable_error(&AppError::NotFound));
    }

    /// Z2-T4: a deadlocked attempt runs again; a real conflict does not.
    #[tokio::test]
    async fn retry_conflicts_reruns_only_retryable_failures() {
        use attome_types::AppError;

        use super::{RETRYABLE_CONFLICT, RetryPolicy, retry_conflicts};

        let mut calls = 0;
        let out: Result<u8, AppError> = retry_conflicts("test", RetryPolicy::SHORT, || {
            calls += 1;
            let n = calls;
            async move {
                if n < 3 {
                    Err(AppError::Conflict(RETRYABLE_CONFLICT))
                } else {
                    Ok(n)
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), 3);

        let mut calls = 0;
        let out: Result<u8, AppError> = retry_conflicts("test", RetryPolicy::SHORT, || {
            calls += 1;
            async { Err(AppError::Conflict("version_conflict")) }
        })
        .await;
        assert!(out.is_err());
        assert_eq!(calls, 1);
    }

    /// Z2-T3: retries pause 4x longer each time, with at most half again.
    #[test]
    fn retry_delay_grows_fourfold_with_bounded_jitter() {
        use super::RetryPolicy;
        use std::time::Duration;
        let policy = RetryPolicy::SHORT;
        assert_eq!(policy.delay(1, 0), Duration::from_millis(40));
        assert_eq!(policy.delay(2, 0), Duration::from_millis(160));
        assert_eq!(policy.delay(1, 50), Duration::from_millis(60));
        assert!(policy.delay(2, u32::MAX) <= Duration::from_millis(240));
    }

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

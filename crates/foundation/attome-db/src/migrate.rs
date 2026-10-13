use sqlx::{PgPool, migrate::MigrateError, migrate::Migrator};
use std::time::{Duration, Instant};

/// How long any statement issued while migrations are running may wait for a
/// conflicting lock before PostgreSQL aborts it with `55P03`
/// (`lock_not_available`).
///
/// F-003: without this, a migration's `ALTER TABLE`/`CREATE INDEX` queues
/// behind whatever `ACCESS SHARE` a long-running analytics read is already
/// holding, and — because the lock manager is FIFO — *every* subsequent
/// `INSERT` on that table queues behind the migration. `statement_timeout`
/// cannot be the bound here: `create_direct_pool` deliberately sets it to `0`
/// so a legitimately slow migration (an index build on a real table) isn't
/// cancelled mid-flight. `lock_timeout` is the correct knob — it bounds the
/// *wait*, never the work.
///
/// Same value, same reasoning, as `xrm-entity`'s `DDL_LOCK_TIMEOUT` for
/// runtime provisioning DDL; the two are deliberately independent constants
/// (base-* may not depend on xrm-*) but should be changed together.
pub const MIGRATION_LOCK_TIMEOUT: &str = "5s";

/// How many times a migration aborted by `lock_timeout` while executing its
/// own SQL is retried before the run fails. Three attempts at
/// [`MIGRATION_LOCK_TIMEOUT`] plus backoff is ~15s of total waiting — long
/// enough to ride out an ordinary short read, short enough that a deploy
/// fails fast instead of freezing writes on the contended table.
const DDL_LOCK_ATTEMPTS: u32 = 3;

/// How long we keep re-queuing for `sqlx`'s own session-level advisory lock
/// (the one `Migrator::run` takes to make concurrent migrators mutually
/// exclusive) before giving up.
///
/// This wait is categorically different from the DDL one above and must not
/// share its budget: losing this race means *a peer migrator is applying
/// migrations right now* — the correct response is to wait it out, and doing
/// so blocks nobody (the peer holds no table locks on our behalf). Before
/// this bound existed the wait was infinite; a multi-node deploy with
/// `database.migrate_on_boot = true` genuinely relies on it. The budget is
/// generous for that reason: it only expires when a peer has been migrating
/// for ten minutes, at which point failing with a clear error beats hanging.
const MIGRATOR_LOCK_BUDGET: Duration = Duration::from_secs(600);

/// Backoff between attempts. Deliberately small — the real pacing is the
/// [`MIGRATION_LOCK_TIMEOUT`] each attempt already spends sitting in
/// PostgreSQL's lock queue. Matches the shape of `xrm-entity`'s
/// `exec_ddl_locked` retry (`100ms * attempt^2`).
fn backoff(attempt: u32) -> Duration {
    Duration::from_millis(100 * u64::from(attempt).pow(2))
}

/// Which of the two very different lock waits inside `Migrator::run` a
/// `55P03` came from. See [`classify_lock_conflict`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockConflict {
    /// The migration's own SQL waited for a table/index lock — F-003's case.
    Ddl,
    /// `sqlx`'s `SELECT pg_advisory_lock($1)`, or its `_sqlx_migrations`
    /// bookkeeping, waited — i.e. a concurrent migrator holds the floor.
    Migrator,
}

/// `sqlx` 0.8 maps errors from a migration's *own* SQL to
/// `MigrateError::ExecuteMigration` (`sqlx-postgres/src/migrate.rs`'s
/// `execute_migration`) and everything else `Migrator::run_direct` does —
/// `pg_advisory_lock`, `ensure_migrations_table`, the `_sqlx_migrations`
/// reads/writes — to `MigrateError::Execute`. That split is exactly the
/// distinction we need, so we read it rather than guessing from the message.
fn classify_lock_conflict(err: &MigrateError) -> Option<LockConflict> {
    let (source, kind) = match err {
        MigrateError::ExecuteMigration(source, _) => (source, LockConflict::Ddl),
        MigrateError::Execute(source) => (source, LockConflict::Migrator),
        _ => return None,
    };
    source
        .as_database_error()
        .and_then(|dbe| dbe.code())
        .is_some_and(|code| code.as_ref() == "55P03")
        .then_some(kind)
}

/// Runs a caller-built `Migrator` against `pool`. Migrations are serialized per
/// database by sqlx's advisory lock; database lock waits and peer-migrator
/// waits are bounded independently. Every wait is bounded by
/// [`MIGRATION_LOCK_TIMEOUT`]; a migration's own table-lock wait gets
/// `DDL_LOCK_ATTEMPTS` tries, and waiting for a peer migrator gets
/// `MIGRATOR_LOCK_BUDGET` (600s).
///
/// The `Migrator` itself must come from `sqlx::migrate!()` at the call site,
/// not from here: that macro expands a compile-time-relative literal path,
/// which only resolves correctly from the crate that owns `migrations/`
/// (this platform's `server` crate) -- attome-db has zero deployment
/// knowledge and must not know that path exists (one-way dependency rule).
/// This is the thin wrapper that makes attome-db's "migration runner" real.
///
/// # Why the whole run is pinned to one connection
///
/// `Migrator::run` takes a **session**-level advisory lock and, on any early
/// return, never releases it (`run_direct`'s `conn.unlock()` sits after the
/// `?`s). Retrying against `pool` directly could therefore hand the next
/// attempt the *other* pooled connection, which would then wait on a lock the
/// first connection still holds — a self-deadlock that `lock_timeout` would
/// merely convert into a guaranteed failure. Acquiring one connection up
/// front and reusing it makes re-acquisition re-entrant, and the explicit
/// `pg_advisory_unlock_all()` on the failure path resets the session so each
/// attempt starts even and a peer migrator isn't blocked while we back off.
///
/// # Why retrying a failed migration is safe
///
/// `sqlx` applies each migration and its `_sqlx_migrations` bookkeeping row
/// in **one transaction**, so a `55P03` abort rolls back both: no partial
/// DDL, no bookkeeping row, nothing to clean up before the next attempt, and
/// already-applied migrations are skipped.
///
/// **That guarantee does not hold for a migration marked
/// `-- no-transaction`**, and this platform has none today. sqlx 0.8.6 runs
/// such a migration's SQL outside a transaction and writes its bookkeeping
/// row (`success = TRUE`) only after the SQL succeeds. If the SQL fails
/// partway, `55P03` included, the DDL that already ran stays applied, no row
/// is written, and nothing marks the database dirty. The next attempt (this
/// function's own retry, or the next deploy) re-runs the whole script against
/// that partial result. A no-transaction migration must therefore be safe to
/// re-run from any partial state, and adding one warrants reviewing this retry
/// policy first. Base-db hardening Phase 3.2 corrected an earlier claim here
/// that sqlx would report `MigrateError::Dirty` in this case; it does not.
///
/// # Failure is the point (F-003)
///
/// When the DDL budget is exhausted the run returns the underlying
/// `55P03` error and the deploy step fails. That is the intended outcome:
/// the alternative is an unbounded wait during which the contended table
/// accepts no writes at all. The operator's move is to find and end the
/// conflicting session (`pg_stat_activity` / `pg_locks`), then re-run — the
/// migrator is idempotent. See the release runbook's "migration blocked by a
/// conflicting lock" section.
pub async fn run_migrations(pool: &PgPool, migrator: &Migrator) -> Result<(), MigrateError> {
    run_migrations_with_migrator_lock_budget(pool, migrator, MIGRATOR_LOCK_BUDGET).await
}

/// [`run_migrations`] with the peer-migrator wait budget supplied by the
/// caller. Production code calls `run_migrations`, which passes the 600s
/// [`MIGRATOR_LOCK_BUDGET`]. This exists only so
/// `tests/migration_migrator_lock.rs` can prove the budget-exceeded path
/// without waiting ten minutes (attome-db hardening Phase 3.1); it is hidden
/// from the docs because it is not a tuning knob.
#[doc(hidden)]
pub async fn run_migrations_with_migrator_lock_budget(
    pool: &PgPool,
    migrator: &Migrator,
    migrator_lock_budget: Duration,
) -> Result<(), MigrateError> {
    // BDB-F14 — a non-lock failure (a malformed statement, an out-of-disk
    // error) returns below without reaching sqlx's own `unlock()`, so the
    // session still holds the migrator advisory lock and the `SET`s this
    // function issued. Returning that session to the pool would hand the next
    // caller a locked connection; `close_on_drop` closes it instead of
    // returning it, so the lock and the `SET`s die with the session. A lock
    // failure already releases explicitly (the `pg_advisory_unlock_all()`
    // below); the successful path returns before the connection is dropped and
    // releases the lock in `run`'s own `unlock()`.
    let mut conn = pool.acquire().await?;
    conn.close_on_drop();

    // Belt and braces with `create_direct_pool`'s `after_connect`, which sets
    // both of these for the rest of the bootstrap sequence: setting them here
    // too makes the guarantee intrinsic to `run_migrations` rather than a
    // property of whichever pool the caller happened to pass.
    //
    // The order of the two matters as a *pair*, not as statements: with a
    // `statement_timeout` still in force (migration 0018 sets a 500ms
    // role-level default on this platform), a blocked migration is cancelled
    // as a plain `57014 query_canceled` long before `lock_timeout` can fire —
    // which would make the whole `55P03` retry path below unreachable and
    // silently reduce this to "fail on any lock contention". `xrm-entity`'s
    // `exec_ddl_locked` documents having hit exactly this trap. Migrations
    // must not be cancelled mid-flight anyway (an index build on a real table
    // legitimately runs for minutes), so `lock_timeout` is left as the sole
    // authority over how long anything here may wait.
    sqlx::query("SET statement_timeout = 0")
        .execute(&mut *conn)
        .await?;
    sqlx::query(&format!("SET lock_timeout = '{MIGRATION_LOCK_TIMEOUT}'"))
        .execute(&mut *conn)
        .await?;

    let mut ddl_attempt: u32 = 0;
    let mut migrator_lock_attempt: u32 = 0;
    // Wall-clock rather than an attempt count times [`MIGRATION_LOCK_TIMEOUT`]:
    // most of each attempt is spent inside PostgreSQL's lock queue, and
    // measuring that directly keeps the budget honest if the timeout constant
    // ever changes.
    let started = Instant::now();

    loop {
        let err = match migrator.run(&mut *conn).await {
            Ok(()) => return Ok(()),
            Err(err) => err,
        };

        let Some(conflict) = classify_lock_conflict(&err) else {
            return Err(err);
        };

        // `run` bailed before its own `unlock()`, so this session may still
        // hold the migrator lock. Release it unconditionally: it lets a peer
        // make progress while we back off, and keeps the next attempt's
        // re-acquisition from stacking a lock that is never popped.
        if let Err(unlock_err) = sqlx::query("SELECT pg_advisory_unlock_all()")
            .execute(&mut *conn)
            .await
        {
            tracing::warn!(
                error = %unlock_err,
                "failed to release the migrator advisory lock before retrying"
            );
        }

        match conflict {
            LockConflict::Ddl => {
                ddl_attempt += 1;
                if ddl_attempt >= DDL_LOCK_ATTEMPTS {
                    tracing::error!(
                        attempts = ddl_attempt,
                        lock_timeout = MIGRATION_LOCK_TIMEOUT,
                        error = %err,
                        "migration aborted: a conflicting lock was held for the whole retry \
                         budget. Identify the blocking session in pg_stat_activity/pg_locks, \
                         end it, then re-run the migrator (it is idempotent). Migrations were \
                         NOT left half-applied."
                    );
                    return Err(err);
                }
                let delay = backoff(ddl_attempt);
                tracing::warn!(
                    attempt = ddl_attempt,
                    backoff_ms = delay.as_millis() as u64,
                    error = %err,
                    "migration hit lock_timeout waiting for a conflicting lock, retrying"
                );
                tokio::time::sleep(delay).await;
            }
            LockConflict::Migrator => {
                migrator_lock_attempt += 1;
                let waited = started.elapsed();
                if waited >= migrator_lock_budget {
                    tracing::error!(
                        attempts = migrator_lock_attempt,
                        waited_secs = waited.as_secs(),
                        error = %err,
                        "migration aborted: another migrator has held the sqlx advisory lock \
                         for the entire wait budget. Check for a stuck migrate job or boot \
                         process holding the lock, then re-run."
                    );
                    return Err(err);
                }
                tracing::warn!(
                    attempt = migrator_lock_attempt,
                    waited_secs = waited.as_secs(),
                    "waiting for a concurrent migrator to release the sqlx advisory lock"
                );
                // Capped: the pacing here is the lock_timeout window each
                // attempt already spends queued, not this backoff.
                tokio::time::sleep(backoff(migrator_lock_attempt.min(4))).await;
            }
        }
    }
}

/// What sqlx's own `_sqlx_migrations` bookkeeping table says has actually
/// been applied to the connected database -- used by readiness checks that
/// need to confirm a rolling-deployment schema-version floor (P-migration-
/// governance), not just that Postgres is reachable. Generic here (attome-db
/// has zero deployment knowledge) because the table name and shape are
/// sqlx's own contract, not this platform's -- the caller supplies whatever
/// version number it expects, this just reports what's really there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaState {
    /// Highest `version` among successfully-applied migrations, or `None`
    /// if `_sqlx_migrations` has no successful rows yet (fresh database
    /// mid-bootstrap).
    pub applied_max_version: Option<i64>,
    /// `true` iff at least one `_sqlx_migrations` row has `success = false`.
    ///
    /// **Always false for a database this platform migrated.** sqlx 0.8.6
    /// never writes such a row: `execute_migration` inserts the bookkeeping
    /// row with `success = TRUE` only after the migration's SQL succeeds,
    /// for transactional and `-- no-transaction` migrations alike, so a
    /// failed migration leaves no row at all. A `success = false` row could
    /// only come from something other than this sqlx version's migrator (a
    /// different migration tool, or a manual edit), and sqlx itself refuses
    /// to migrate a database that has one (`MigrateError::Dirty`).
    ///
    /// **Keep it anyway** (attome-db hardening Phase 3.2). `health.rs`'s
    /// readiness check fails closed on it (D-038), which costs nothing and
    /// covers a database last touched by other tooling. Don't remove it just
    /// because it is false today.
    pub dirty: bool,
}

pub async fn schema_state(pool: &PgPool) -> Result<SchemaState, sqlx::Error> {
    let (applied_max_version, dirty): (Option<i64>, bool) = sqlx::query_as(
        "SELECT (SELECT MAX(version) FROM _sqlx_migrations WHERE success = true), \
                EXISTS(SELECT 1 FROM _sqlx_migrations WHERE success = false)",
    )
    .fetch_one(pool)
    .await?;
    Ok(SchemaState {
        applied_max_version,
        dirty,
    })
}

#[cfg(test)]
mod tests {
    use super::{DDL_LOCK_ATTEMPTS, MIGRATOR_LOCK_BUDGET};
    use std::time::Duration;

    /// Base-db hardening Phase 3.1 pins the production budgets: a peer
    /// migrator may take up to ten minutes, and a table-lock wait gets three
    /// `lock_timeout` windows. `tests/migration_migrator_lock.rs` and
    /// `tests/migration_lock_timeout.rs` prove the two behave differently;
    /// changing either value should be a deliberate edit to this test.
    #[test]
    fn the_production_lock_budgets_are_pinned() {
        assert_eq!(MIGRATOR_LOCK_BUDGET, Duration::from_secs(600));
        assert_eq!(DDL_LOCK_ATTEMPTS, 3);
    }
}

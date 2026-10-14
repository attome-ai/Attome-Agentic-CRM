//! Low-level DDL execution primitives shared by table/column provisioning.

use attome_db::DbPool;
use attome_types::AppError;
use std::collections::HashMap;
use std::time::Duration;

/// `lock_timeout` applied to every provisioning ALTER via `exec_ddl_locked` —
/// a module constant, not config; nobody should tune this per deployment.
/// P-provisioning-hardening item (c).
const DDL_LOCK_TIMEOUT: &str = "5s";

/// Per-column catalog facts `table.rs`'s self-healing backfills need to
/// decide whether an ALTER is actually necessary, not just whether the
/// column exists.
#[derive(Debug, Clone, Default)]
pub(super) struct ColumnInfo {
    pub data_type: String,
    /// `pg_get_expr(pg_attrdef.adbin, ...)`'s canonical text for this
    /// column's `DEFAULT`, or `None` when the column has no default at all.
    pub default_expr: Option<String>,
}

/// [`existing_columns`]'s full return shape: every live column plus the
/// table's storage parameters (`pg_class.reloptions`) — everything C-20's
/// skip-when-already-correct checks in `table.rs` need for the ALTERs that
/// used to run unconditionally on every boot.
#[derive(Debug, Clone, Default)]
pub(super) struct TableColumns {
    pub columns: HashMap<String, ColumnInfo>,
    /// Raw `"key=value"` entries from `pg_class.reloptions`; empty when the
    /// table carries no storage parameters at all.
    pub reloptions: Vec<String>,
}

impl TableColumns {
    pub(super) fn contains_key(&self, name: &str) -> bool {
        self.columns.contains_key(name)
    }

    /// The stored `DEFAULT` expression for `name`, or `None` when the column
    /// is missing or has no default.
    pub(super) fn default_expr(&self, name: &str) -> Option<&str> {
        self.columns.get(name)?.default_expr.as_deref()
    }
}

/// Whether `table` (in the current schema) has a live column named `column`,
/// in ONE round trip. `provision_column` runs once per attribute on every
/// boot, and only needs this answer; going through [`existing_columns`] cost it
/// three round trips (2026-09-24: ~750 attributes x 3 = a large share of the
/// ~3 s a test's `EngineSystem::build` spent waiting on localhost latency).
/// A missing table answers `false`, the same as [`existing_columns`] returning
/// `None` did for the caller.
pub(super) async fn column_exists(
    db: &DbPool,
    table: &str,
    column: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Column name -> catalog facts for `table`, or `None` if the table doesn't
/// exist at all. Three purposes: skip-CREATE, skip-ALTER
/// (P-provisioning-hardening item c, extended by C-20 to the
/// default-expression/`reloptions` ALTERs that used to run unconditionally),
/// and TIMESTAMP discovery for the TIMESTAMPTZ backfill (item d).
pub(super) async fn existing_columns(
    db: &DbPool,
    table: &str,
) -> Result<Option<TableColumns>, AppError> {
    // The three catalog reads are independent, so they are issued together:
    // one round trip of latency instead of three (this runs per entity and
    // per attribute on every boot). The table-exists answer is applied after,
    // so a missing table still returns `None` exactly as before.
    let exists_q = sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(db);
    let columns_q = sqlx::query_as::<_, (String, String)>(
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1",
    )
    .bind(table)
    .fetch_all(db);
    // C-20: one more catalog query, joining `pg_attrdef`/`pg_get_expr` (the
    // per-column DEFAULT text) with `pg_class.reloptions` (the table-wide
    // storage parameters) — `reloptions` repeats identically on every row of
    // this join, so any row's copy is as good as any other.
    let defaults_q = sqlx::query_as::<_, (String, Option<String>, Option<Vec<String>>)>(
        "SELECT a.attname, pg_get_expr(ad.adbin, ad.adrelid), c.reloptions FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum WHERE n.nspname = current_schema() AND c.relname = $1 AND a.attnum > 0 AND NOT a.attisdropped",
    )
    .bind(table)
    .fetch_all(db);
    let (table_exists, rows, default_rows) =
        tokio::try_join!(exists_q, columns_q, defaults_q).map_err(AppError::internal)?;
    if !table_exists {
        return Ok(None);
    }

    let mut defaults: HashMap<String, Option<String>> = HashMap::new();
    let mut reloptions: Vec<String> = Vec::new();
    for (name, default_expr, opts) in default_rows {
        if let Some(opts) = opts {
            reloptions = opts;
        }
        defaults.insert(name, default_expr);
    }

    let columns = rows
        .into_iter()
        .map(|(name, data_type)| {
            let default_expr = defaults.remove(&name).flatten();
            (
                name,
                ColumnInfo {
                    data_type,
                    default_expr,
                },
            )
        })
        .collect();

    Ok(Some(TableColumns {
        columns,
        reloptions,
    }))
}

/// Whether `e` is Postgres's `duplicate_table` (42P07) — the error a losing
/// racer gets from `CREATE TABLE IF NOT EXISTS`/`CREATE INDEX IF NOT
/// EXISTS` when it genuinely races another session's identical statement.
/// `IF NOT EXISTS` guards a *sequential* recheck (whoever's session sees the
/// object already committed skips it cleanly); it is documented Postgres
/// behavior, not a bug, that two sessions who both start from "it doesn't
/// exist yet" can both attempt the CREATE, and the loser sees this error
/// despite `IF NOT EXISTS`. C-20: `provision_table`/`provision_join_table`
/// now run before any serializing advisory lock is acquired (so a small
/// connection pool never self-deadlocks on their own internal DDL
/// transactions), which reopens this race for genuinely concurrent callers
/// creating the same brand-new table — the outcome this error reports
/// (the object now exists) is exactly what the caller asked `IF NOT EXISTS`
/// for, so callers that can reach this race should treat it as success
/// rather than surface it as a spurious failure to the losing racer.
pub(super) fn is_concurrent_create_race(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|dbe| dbe.code())
        .is_some_and(|code| code.as_ref() == "42P07")
}

/// Runs one DDL statement inside `BEGIN; SET LOCAL statement_timeout = 0; SET
/// LOCAL lock_timeout; <pre_stmts>; <sql>; COMMIT`. `SET LOCAL` dies with the
/// transaction, so no session state leaks back into the pooled connection.
/// Retries SQLSTATE `55P03` (`lock_not_available`) with a small bounded
/// backoff (3 attempts: 100ms/400ms/900ms + jitter derived from the attempt
/// index and the statement length — deterministic, no `rand` dependency
/// needed to just spread retries apart); any other error propagates
/// immediately.
///
/// This is the fix for the boot-time-ALTER AccessExclusiveLock outage risk
/// (P-provisioning-hardening item c): a lock request that can't be granted
/// within `DDL_LOCK_TIMEOUT` now backs off and retries instead of queuing
/// indefinitely behind whatever holds the conflicting lock — which, because
/// Postgres's lock queue is fair, would otherwise convoy every other query on
/// the table behind the waiting ALTER too.
///
/// **`statement_timeout` reset found while writing D-104's standalone retry
/// test.** Postgres's `statement_timeout` counts lock-acquisition wait time,
/// same as `lock_timeout` — so a deploying role carrying a short
/// `statement_timeout` (§14.1 sets exactly this, ~500ms, on this platform's
/// "fast reads" query class, and coding-guidelines never scoped that
/// exemption away from provisioning DDL) would cancel the ALTER with a plain
/// `57014` `query_canceled` *before* `DDL_LOCK_TIMEOUT` ever had a chance to
/// fire — an error this function's retry check doesn't recognize, so the
/// 55P03 retry path was silently unreachable for any such role. `SET LOCAL
/// statement_timeout = 0` makes `lock_timeout` the sole authority over how
/// long this transaction may wait, matching the contract this function
/// documents; the DDL itself, once the lock is granted, is metadata-only and
/// returns in microseconds, so there is nothing left for a statement_timeout
/// to usefully bound here.
///
/// NEVER used for `CREATE INDEX CONCURRENTLY` / `DROP INDEX CONCURRENTLY` —
/// those cannot run inside a transaction at all (see
/// `sync_attribute_index_on_connection`), so they stay as direct pool calls.
pub(super) async fn exec_ddl_locked(
    db: &DbPool,
    pre_stmts: &[&str],
    sql: &str,
) -> Result<(), sqlx::Error> {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        // D-104 test hook: the standalone "reseed issues zero ALTER" check
        // (attome-metadata/tests/provision.rs) has no reliable pg_stat_statements
        // in the stock CI Postgres image (it needs shared_preload_libraries,
        // which the plain `postgres:18` service container doesn't set) —
        // this debug event is the documented tracing-based alternative the
        // plan names instead. Not gated behind cfg(test): a no-op unless a
        // subscriber is installed (tracing's whole design), so it costs
        // nothing in production.
        tracing::debug!(attempt, sql = %sql, "provisioning: executing DDL statement");
        #[expect(
            clippy::disallowed_methods,
            reason = "exec_ddl_locked returns sqlx::Error so its retry loop can inspect lock-timeout codes; tx::begin returns AppError"
        )]
        let mut tx = db.begin().await?;
        let outcome: Result<(), sqlx::Error> = async {
            sqlx::query("SET LOCAL statement_timeout = 0")
                .execute(&mut *tx)
                .await?;
            sqlx::query(&format!("SET LOCAL lock_timeout = '{DDL_LOCK_TIMEOUT}'"))
                .execute(&mut *tx)
                .await?;
            for stmt in pre_stmts {
                sqlx::query(stmt).execute(&mut *tx).await?;
            }
            sqlx::query(sql).execute(&mut *tx).await?;
            Ok(())
        }
        .await;

        match outcome {
            Ok(()) => return tx.commit().await,
            Err(e) => {
                let _ = tx.rollback().await;
                let lock_not_available = e
                    .as_database_error()
                    .and_then(|dbe| dbe.code())
                    .is_some_and(|code| code.as_ref() == "55P03");
                if lock_not_available && attempt < MAX_ATTEMPTS {
                    let jitter_ms = (sql.len() as u64 * attempt as u64) % 50;
                    let backoff_ms = 100 * (attempt as u64).pow(2) + jitter_ms;
                    tracing::warn!(
                        attempt,
                        backoff_ms,
                        "provisioning DDL hit lock_timeout, retrying"
                    );
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    continue;
                }
                return Err(e);
            }
        }
    }
    // Every iteration above returns (Ok on success, Err once retries are
    // exhausted or the error isn't retryable) or `continue`s — and `continue`
    // is only reachable while `attempt < MAX_ATTEMPTS`, so the final
    // iteration always returns. Provable-by-construction, not a real gap.
    unreachable!("exec_ddl_locked: retry loop exited without returning")
}

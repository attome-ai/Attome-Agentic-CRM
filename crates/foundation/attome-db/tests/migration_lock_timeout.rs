//! F-003 regression: `attome_db::run_migrations` must never wait forever on a
//! conflicting lock.
//!
//! Before this suite existed, a migration's `ALTER TABLE`/`CREATE INDEX`
//! queued behind whatever `ACCESS SHARE` a long-running read already held,
//! and — PostgreSQL's lock queue being FIFO — every subsequent `INSERT` on
//! that table queued behind the migration. `statement_timeout` could not
//! bound it (`create_direct_pool` sets it to `0` on purpose so a slow index
//! build isn't cancelled mid-flight), so the wait was unbounded: an upgrade
//! run against live traffic could stop the deployment writing until the
//! analytics query finished.
//!
//! What is proven here, against a live PostgreSQL:
//!
//! 1. With a competing `ACCESS SHARE` held for the whole run, `run_migrations`
//!    **fails** — with `55P03` (`lock_not_available`), attributed to the
//!    migration's own SQL — instead of blocking, and does so inside the
//!    documented retry budget rather than after an arbitrary wait.
//! 2. It genuinely *retried* first (the elapsed time covers more than one
//!    [`attome_db::MIGRATION_LOCK_TIMEOUT`] window), so a short-lived reader is
//!    ridden out rather than turned into a failed deploy.
//! 3. Once the blocker goes away the very same migrator succeeds, and
//!    `_sqlx_migrations` records the migration exactly once — i.e. the aborted
//!    attempts left no partial DDL and no dirty bookkeeping row behind.
//!
//! The migrator here is a **fixture** (`tests/fixtures/lock_timeout_migrations/`),
//! not `crates/server/migrations/`: this proves `run_migrations`' contract,
//! which is attome-db's to keep, and runs in seconds instead of replaying 100+
//! platform migrations.
//!
//! **Isolation.** Everything happens inside a uniquely-named schema
//! (`lock_timeout_<uuid hex>`) in the throwaway test database, reached by a
//! connection-level `search_path`, so `_sqlx_migrations` and the victim table
//! are this run's alone and concurrent suites can't collide. Unlike
//! `crates/server/tests/fresh_bootstrap.rs` — which documents this repo's
//! "leave test schemas behind" convention — this one drops its schema on the
//! way out *when the test passed*: it creates a schema on every run, so
//! keeping them would accumulate without bound, while a failing run still
//! leaves its debris in place to inspect.
//!
//! Requires a live PostgreSQL, reached through `DATABASE_URL`; skips (does
//! not fail) when that is unset. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test migration_lock_timeout
//! ```

use sqlx::migrate::MigrateError;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use sqlx::{Connection, PgConnection};
use std::str::FromStr;
use std::time::{Duration, Instant};
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("tests/fixtures/lock_timeout_migrations");

/// The migration below can only be aborted by `lock_timeout`, never
/// completed, while the blocker holds its lock — so the run must end within
/// the retry budget `run_migrations` documents. Generous enough to absorb a
/// loaded CI box; far below the "forever" this suite exists to rule out.
const MAX_ACCEPTABLE_WAIT: Duration = Duration::from_secs(45);

/// Three attempts at a 5s `lock_timeout` is ~15s. Asserting the run took at
/// least one full window past the first proves the retry loop actually ran —
/// without this bound the test would still pass if `run_migrations` gave up
/// on the very first `55P03`, which would make a one-second reader fail a
/// deploy.
const MIN_EXPECTED_WAIT: Duration = Duration::from_secs(9);

/// `None` when `DATABASE_URL` is unset, so `cargo test -p attome-db` on a
/// machine with no PostgreSQL skips this rather than failing — the same
/// posture `attome-testkit`'s `db_pool_or_skip!` establishes for DB-backed
/// suites. The macro itself is no use here: it hands back a plain pool, and
/// this test needs connection options carrying a per-run `search_path`.
fn database_url() -> Option<String> {
    // Delegated rather than re-implemented: `test_db_url` also carries the
    // `panic!`-under-`CI` half of the contract, which this file's own copy
    // was missing — a skip on a runner means the service wiring broke.
    let url = attome_testkit::test_db_url();
    if url.is_none() {
        eprintln!(
            "SKIP {}: set DATABASE_URL to a throwaway test database to run this \
             (NEVER attome_dev)",
            module_path!()
        );
    }
    url
}

fn options_for_schema(url: &str, schema: &str) -> PgConnectOptions {
    PgConnectOptions::from_str(url)
        .expect("DATABASE_URL must parse as a PostgreSQL connection string")
        .options([("search_path", schema)])
}

#[tokio::test]
async fn migration_blocked_by_a_conflicting_lock_fails_instead_of_waiting_forever() {
    let Some(url) = database_url() else { return };
    let schema = format!("lock_timeout_{}", Uuid::now_v7().simple());

    // Created outside the schema-scoped options below — `search_path` cannot
    // point at a schema that does not exist yet.
    let mut admin = PgConnection::connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&mut admin)
        .await
        .expect("create the isolated test schema");

    let pool: PgPool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options_for_schema(&url, &schema))
        .await
        .expect("open a pool scoped to the isolated test schema");

    sqlx::query("CREATE TABLE lock_timeout_victim (id integer PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("create the table the fixture migration alters");

    // The blocker: an ordinary read left inside an open transaction, exactly
    // like the long analytics query in F-003's failure scenario. It holds
    // ACCESS SHARE on `lock_timeout_victim`, which conflicts with the ACCESS
    // EXCLUSIVE the fixture migration's `ALTER TABLE` needs.
    let mut blocker = PgConnection::connect_with(&options_for_schema(&url, &schema))
        .await
        .expect("connect the blocking reader");
    // Migration 0065 sets `idle_in_transaction_session_timeout = '10s'` as a
    // role-level default on the platform's own login role. Left in place it
    // would terminate this blocker roughly halfway through the retry budget,
    // the migration would then succeed, and the test would silently stop
    // testing anything. A real F-003 blocker is a session that PostgreSQL is
    // *not* about to reap for us — a long analytics read actively executing,
    // a `pg_dump`, an external BI connector, an operator's psql — so the
    // faithful reproduction is a session that holds its lock for the whole
    // run. (0018's 500ms `statement_timeout` never applies here: the blocker
    // runs one instant `SELECT` and then holds the lock while idle.)
    for reset in [
        "SET idle_in_transaction_session_timeout = 0",
        "SET statement_timeout = 0",
    ] {
        sqlx::query(reset)
            .execute(&mut blocker)
            .await
            .expect("the blocker must not be reaped by a role-level timeout");
    }
    let mut blocking_tx = blocker
        .begin()
        .await
        .expect("open the blocking transaction");
    let _: i64 = sqlx::query_scalar("SELECT count(*) FROM lock_timeout_victim")
        .fetch_one(&mut *blocking_tx)
        .await
        .expect("the blocking read must take ACCESS SHARE");

    let started = Instant::now();
    let outcome = attome_db::run_migrations(&pool, &MIGRATOR).await;
    let elapsed = started.elapsed();

    // Released before any assertion so a failed assertion cannot leave an
    // idle-in-transaction session holding a lock in the shared test database.
    blocking_tx
        .rollback()
        .await
        .expect("release the blocking transaction");
    blocker
        .close()
        .await
        .expect("close the blocking connection");

    let err = outcome.expect_err(
        "run_migrations must FAIL while a conflicting lock is held — blocking instead is \
         F-003: every write to the contended table queues behind the migration",
    );
    // Asserted before the timings: an unexpected error explains an unexpected
    // duration, so reporting it first keeps a genuine environment problem
    // (permissions, a missing table, a lost connection) from being
    // misdiagnosed as "the retry budget is wrong".
    //
    // The failure must be attributed to the migration's own SQL waiting for a
    // lock (`55P03`), not to some unrelated error that happens to abort the
    // run — that distinction is what `run_migrations` keys its two retry
    // budgets off.
    match &err {
        MigrateError::ExecuteMigration(source, version) => {
            assert_eq!(*version, 1, "the fixture has exactly one migration");
            let code = source
                .as_database_error()
                .and_then(|dbe| dbe.code())
                .map(|c| c.to_string());
            assert_eq!(
                code.as_deref(),
                Some("55P03"),
                "expected PostgreSQL's lock_not_available, got: {source}"
            );
        }
        other => panic!("expected a migration-SQL lock timeout, got: {other:?}"),
    }

    assert!(
        elapsed < MAX_ACCEPTABLE_WAIT,
        "run_migrations waited {elapsed:?}, which is past the documented retry budget — the \
         lock wait is not bounded"
    );
    assert!(
        elapsed >= MIN_EXPECTED_WAIT,
        "run_migrations gave up after only {elapsed:?}; it must retry the documented number of \
         lock_timeout windows before failing, so a short-lived reader does not fail a deploy"
    );

    // Nothing was left half-applied: with the blocker gone the same migrator
    // succeeds, and records its one migration exactly once.
    attome_db::run_migrations(&pool, &MIGRATOR)
        .await
        .expect("the migrator is idempotent — it must succeed once the blocker is gone");

    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success = true")
            .fetch_one(&pool)
            .await
            .expect("read the sqlx bookkeeping table");
    assert_eq!(
        applied, 1,
        "the aborted attempts must not have left bookkeeping rows behind"
    );
    let column_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = $1 AND table_name = 'lock_timeout_victim' AND column_name = 'probe')",
    )
    .bind(&schema)
    .fetch_one(&pool)
    .await
    .expect("inspect the altered table");
    assert!(
        column_exists,
        "the retried migration must actually have applied its DDL"
    );

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
        .execute(&mut admin)
        .await
        .expect("drop the isolated test schema");
    admin.close().await.expect("close the admin connection");
}

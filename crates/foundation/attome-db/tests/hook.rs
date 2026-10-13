//! 5.3 — `attome_db::hook`: `Chain` runs both hooks in one transaction, in
//! order; an `Err` from the second rolls back the first hook's write and the
//! mutation itself; `NoHook` commits unchanged.
//!
//! `attome-approval`/`attome-auth`/`xrm-audit` already prove the production shape
//! (a failed audit write rolls the decision back); this suite pins the
//! primitive itself, in the crate that owns it. Runs against this binary's
//! throwaway clone (`attome_testkit::test_db_url`), never `attome_dev`, inside a
//! uniquely named schema dropped afterwards. Skips (loudly) when
//! `DATABASE_URL` is unset, except under `CI`. Run manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-db --test hook
//! ```

use std::str::FromStr;

use attome_db::{BeforeCommit, Chain, HookFuture, NoHook, Tx};
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use sqlx::postgres::{PgConnectOptions, PgPool};
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

/// The value the base mutation is about to return.
struct Probe {
    id: i32,
}

/// Writes a row through the caller's transaction, recording its name, so the
/// commit order and the rollback are both observable.
struct RecordingHook {
    name: &'static str,
}

impl BeforeCommit<Probe> for RecordingHook {
    fn before_commit<'a>(&'a self, tx: &'a mut Tx<'_>, committed: &'a Probe) -> HookFuture<'a> {
        Box::pin(async move {
            // The hook sees the value the base function is about to return.
            assert!(committed.id > 0, "the hook must see the returned value");
            sqlx::query("INSERT INTO hook_probe_order (hook) VALUES ($1)")
                .bind(self.name)
                .execute(&mut **tx)
                .await
                .map_err(AppError::internal)?;
            Ok(())
        })
    }
}

/// Same write, then `Err` — the shape of a failed audit-event write.
struct FailingHook {
    name: &'static str,
}

impl BeforeCommit<Probe> for FailingHook {
    fn before_commit<'a>(&'a self, tx: &'a mut Tx<'_>, _committed: &'a Probe) -> HookFuture<'a> {
        Box::pin(async move {
            sqlx::query("INSERT INTO hook_probe_order (hook) VALUES ($1)")
                .bind(self.name)
                .execute(&mut **tx)
                .await
                .map_err(AppError::internal)?;
            Err(AppError::Validation("forced hook failure".to_string()))
        })
    }
}

async fn count_probe(pool: &PgPool, id: i32) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM hook_probe WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count the probe rows")
}

async fn count_recorded_hook(pool: &PgPool, hook: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM hook_probe_order WHERE hook = $1")
        .bind(hook)
        .fetch_one(pool)
        .await
        .expect("count the recorded hook rows")
}

#[tokio::test]
async fn chain_order_rollback_and_no_hook() {
    let url = skip_if_no_db!(attome_testkit::test_db_url());
    let schema = format!("hook_{}", &Uuid::now_v7().simple().to_string()[..16]);
    let mut admin = PgConnection::connect(&url)
        .await
        .expect("connect the admin session");
    sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
        .execute(&mut admin)
        .await
        .expect("create the isolated schema");
    let pool: PgPool = PgPool::connect_with(
        PgConnectOptions::from_str(&url)
            .expect("DATABASE_URL must parse")
            .options([("search_path", schema.as_str())]),
    )
    .await
    .expect("open a pool scoped to the isolated schema");
    sqlx::query("CREATE TABLE hook_probe (id integer PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("create the mutation target");
    sqlx::query("CREATE TABLE hook_probe_order (seq serial PRIMARY KEY, hook text NOT NULL)")
        .execute(&pool)
        .await
        .expect("create the hook-order table");

    // 1. Both hooks run, in order, inside the transaction that commits.
    let first = RecordingHook { name: "first" };
    let second = RecordingHook { name: "second" };
    let chain = Chain(&first, &second);
    let mut tx = attome_db::tx::begin(&pool)
        .await
        .expect("begin the mutation");
    sqlx::query("INSERT INTO hook_probe (id) VALUES (1)")
        .execute(&mut *tx)
        .await
        .expect("insert the mutation row");
    chain
        .before_commit(&mut tx, &Probe { id: 1 })
        .await
        .expect("both hooks must succeed");
    attome_db::tx::commit(tx)
        .await
        .expect("commit the mutation");
    let order: Vec<String> = sqlx::query_scalar("SELECT hook FROM hook_probe_order ORDER BY seq")
        .fetch_all(&pool)
        .await
        .expect("read the hook order");
    assert_eq!(
        order,
        vec!["first", "second"],
        "Chain runs first, then second"
    );
    assert_eq!(
        count_probe(&pool, 1).await,
        1,
        "the mutation must be committed"
    );

    // 2. A failing second hook rolls back the first hook's write AND the
    // mutation: the transaction is never committed.
    let first = RecordingHook {
        name: "first-rolled-back",
    };
    let failing = FailingHook { name: "failing" };
    let chain = Chain(&first, &failing);
    let mut tx = attome_db::tx::begin(&pool)
        .await
        .expect("begin the mutation");
    sqlx::query("INSERT INTO hook_probe (id) VALUES (2)")
        .execute(&mut *tx)
        .await
        .expect("insert the mutation row");
    let outcome = chain.before_commit(&mut tx, &Probe { id: 2 }).await;
    assert!(
        matches!(outcome, Err(AppError::Validation(_))),
        "{outcome:?}"
    );
    drop(tx); // rolls back, exactly as an early question-mark return would
    assert_eq!(
        count_probe(&pool, 2).await,
        0,
        "a failing hook must roll the mutation back"
    );
    assert_eq!(
        count_recorded_hook(&pool, "first-rolled-back").await,
        0,
        "a failing hook must roll the earlier hook's write back too"
    );

    // 3. NoHook leaves the mutation exactly as it was.
    let mut tx = attome_db::tx::begin(&pool)
        .await
        .expect("begin the mutation");
    sqlx::query("INSERT INTO hook_probe (id) VALUES (3)")
        .execute(&mut *tx)
        .await
        .expect("insert the mutation row");
    NoHook
        .before_commit(&mut tx, &Probe { id: 3 })
        .await
        .expect("NoHook never fails");
    attome_db::tx::commit(tx)
        .await
        .expect("commit the mutation");
    assert_eq!(
        count_probe(&pool, 3).await,
        1,
        "NoHook must leave the mutation intact"
    );

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA \"{schema}\" CASCADE"))
        .execute(&mut admin)
        .await
        .expect("drop the isolated schema");
    admin.close().await.expect("close the admin session");
}

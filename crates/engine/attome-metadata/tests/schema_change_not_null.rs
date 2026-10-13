//! Live-Postgres coverage for `evolve_attribute_schema`'s nullability path.
//!
//! D-788 (amends D-180): required is application-level. `is_required` never
//! installs a physical `NOT NULL` any more, never backfills, and a `NOT NULL`
//! left by the old path is dropped. The tests below assert that; the
//! scan-strategy test further down still documents why the old path used
//! NOT VALID/VALIDATE (kept: it asserts PostgreSQL behaviour, not ours).
//!
//! Before this suite the required-change path issued a bare
//! `ALTER TABLE ... SET NOT NULL`, which takes ACCESS EXCLUSIVE and scans every
//! row while holding it — on a large table that convoys every reader and writer
//! behind it for the whole scan. The `max_length` branch of the same function
//! already avoided that with NOT VALID/VALIDATE; this asserts the nullability
//! branch now does too, and that its failure path cleans up after itself.
//!
//! `evolve_attribute_schema` is pure physical DDL — it never reads
//! `*` — so these tests build their own throwaway table and need no
//! migrated schema.
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when unset,
//! except under `CI` (see `attome_testkit`). Run against the test profile:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test"
//! cargo test -p attome-metadata --test schema_change_not_null -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_metadata::provision::evolve_attribute_schema;
use sqlx::{Connection, PgConnection, postgres::PgPoolOptions};

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// Fresh table with `rows` records, `note` populated on all of them.
async fn seed_table(db: &DbPool, table: &str, rows: i32) {
    sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{table}""#))
        .execute(db)
        .await
        .expect("drop");
    sqlx::query(&format!(
        r#"CREATE TABLE "{table}" (id serial PRIMARY KEY, note text)"#
    ))
    .execute(db)
    .await
    .expect("create");
    sqlx::query(&format!(
        r#"INSERT INTO "{table}" (note) SELECT 'v' || g FROM generate_series(1, $1) g"#
    ))
    .bind(rows)
    .execute(db)
    .await
    .expect("seed");
}

async fn is_not_null(db: &DbPool, table: &str, column: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT attnotnull FROM pg_attribute \
         WHERE attrelid = $1::regclass AND attname = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(db)
    .await
    .expect("read attnotnull")
}

/// Any CHECK constraint left on the table whose name ends in `_notnull`.
async fn leftover_notnull_constraints(db: &DbPool, table: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT conname FROM pg_constraint \
         WHERE conrelid = $1::regclass AND conname LIKE '%\\_notnull'",
    )
    .bind(table)
    .fetch_all(db)
    .await
    .expect("read pg_constraint")
}

/// D-788: making a field required installs no NOT NULL and no scaffolding;
/// NULL writes stay accepted (the application enforces required).
#[tokio::test]
async fn required_change_never_installs_not_null() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: DATABASE_URL unset");
        return;
    };
    let table = "t_sc_happy";
    seed_table(&db, table, 500).await;

    evolve_attribute_schema(&db, table, "note", "text", true, None, false)
        .await
        .expect("a required change is metadata-only for the column");
    assert!(
        !is_not_null(&db, table, "note").await,
        "required is application-level: no physical NOT NULL"
    );
    assert!(leftover_notnull_constraints(&db, table).await.is_empty());
    sqlx::query(&format!(r#"INSERT INTO "{table}" (note) VALUES (NULL)"#))
        .execute(&db)
        .await
        .expect("NULL insert stays accepted");

    sqlx::query(&format!(r#"DROP TABLE "{table}""#))
        .execute(&db)
        .await
        .unwrap();
}

/// D-788: existing empty rows stay empty — a required change on a column
/// with NULLs succeeds and leaves them alone.
#[tokio::test]
async fn required_change_keeps_existing_nulls() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: DATABASE_URL unset");
        return;
    };
    let table = "t_sc_nulls";
    seed_table(&db, table, 200).await;
    sqlx::query(&format!(
        r#"UPDATE "{table}" SET note = NULL WHERE id % 50 = 0"#
    ))
    .execute(&db)
    .await
    .expect("introduce NULLs");

    evolve_attribute_schema(&db, table, "note", "text", true, None, false)
        .await
        .expect("required change succeeds while NULLs remain (D-788)");
    let nulls: i64 = sqlx::query_scalar(&format!(
        r#"SELECT COUNT(*) FROM "{table}" WHERE note IS NULL"#
    ))
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(nulls, 4, "empty rows stay empty");
    assert!(!is_not_null(&db, table, "note").await);
    assert!(leftover_notnull_constraints(&db, table).await.is_empty());

    sqlx::query(&format!(r#"DROP TABLE "{table}""#))
        .execute(&db)
        .await
        .unwrap();
}

/// Driven at the SQL level rather than through `evolve_attribute_schema`
/// because the contrast between the two scan strategies is the assertion.
#[tokio::test]
async fn scan_step_does_not_conflict_with_concurrent_writers() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: DATABASE_URL unset");
        return;
    };
    let url = attome_testkit::migrated_db_url().unwrap();
    let table = "t_sc_locks";
    seed_table(&db, table, 500).await;

    let mut ddl = PgConnection::connect(&url).await.expect("ddl connect");

    // Install the CHECK first, while nothing else holds the table — this is
    // the instant ACCESS EXCLUSIVE step, not the one under test.
    sqlx::query(&format!(
        r#"ALTER TABLE "{table}" ADD CONSTRAINT ck_probe CHECK (note IS NOT NULL) NOT VALID"#
    ))
    .execute(&mut ddl)
    .await
    .expect("ADD CONSTRAINT NOT VALID on an unlocked table");

    // Session 2: an ordinary writer, transaction left open, holding ROW
    // EXCLUSIVE on the table for the rest of this test.
    let mut writer = PgConnection::connect(&url).await.expect("writer connect");
    sqlx::query("BEGIN").execute(&mut writer).await.unwrap();
    sqlx::query(&format!(
        r#"INSERT INTO "{table}" (note) VALUES ('concurrent')"#
    ))
    .execute(&mut writer)
    .await
    .expect("concurrent insert");

    // Mirror `exec_ddl_locked`: Postgres counts lock-acquisition wait against
    // `statement_timeout` too, so a role carrying a short one cancels the
    // statement with `57014` before `lock_timeout` can report the real cause
    // as `55P03`. Observed here on the first run of this test — the role
    // default from migration 0018 fired first. Zeroing it makes `lock_timeout`
    // the sole authority, which is exactly what the production path does.
    sqlx::query("SET statement_timeout = 0")
        .execute(&mut ddl)
        .await
        .unwrap();
    sqlx::query("SET lock_timeout = '2s'")
        .execute(&mut ddl)
        .await
        .unwrap();

    // The statement this path used to issue: blocked by the open writer.
    let bare = sqlx::query(&format!(
        r#"ALTER TABLE "{table}" ALTER COLUMN note SET NOT NULL"#
    ))
    .execute(&mut ddl)
    .await;
    let bare_err = bare.expect_err("bare SET NOT NULL must be blocked by an open writer");
    assert_eq!(
        bare_err
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("55P03"),
        "expected lock_not_available, got: {bare_err:?}"
    );

    // The statement the fixed path uses for the same scan: unaffected by the
    // concurrent writer, because SHARE UPDATE EXCLUSIVE does not conflict with
    // ROW EXCLUSIVE. This is the assertion the whole change exists for.
    sqlx::query(&format!(
        r#"ALTER TABLE "{table}" VALIDATE CONSTRAINT ck_probe"#
    ))
    .execute(&mut ddl)
    .await
    .expect("VALIDATE CONSTRAINT must not conflict with a concurrent writer");

    sqlx::query("ROLLBACK").execute(&mut writer).await.unwrap();
    sqlx::query(&format!(r#"DROP TABLE "{table}""#))
        .execute(&db)
        .await
        .unwrap();
}

/// D-788: a physical NOT NULL left by the old required path is dropped by
/// the next contract evolution of the field (catalog-only), however long the
/// identifiers.
#[tokio::test]
async fn a_leftover_not_null_is_dropped() {
    let Some(db) = test_db().await else {
        eprintln!("SKIP: DATABASE_URL unset");
        return;
    };
    let table = "t_sc_".to_string() + &"a".repeat(39);
    let column = "c_".to_string() + &"b".repeat(42);
    assert!(
        table.len() <= 48 && column.len() <= 48,
        "must pass validation"
    );

    sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{table}""#))
        .execute(&db)
        .await
        .unwrap();
    sqlx::query(&format!(
        r#"CREATE TABLE "{table}" (id serial PRIMARY KEY, "{column}" text NOT NULL DEFAULT 'v')"#
    ))
    .execute(&db)
    .await
    .expect("create");
    assert!(is_not_null(&db, &table, &column).await);

    evolve_attribute_schema(&db, &table, &column, "text", true, None, false)
        .await
        .expect("evolution applies");
    assert!(
        !is_not_null(&db, &table, &column).await,
        "the old path's NOT NULL must be gone"
    );

    sqlx::query(&format!(r#"DROP TABLE "{table}""#))
        .execute(&db)
        .await
        .unwrap();
}

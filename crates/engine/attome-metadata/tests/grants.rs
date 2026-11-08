//! C-22 — live-Postgres coverage for `attome_metadata::provision::grants`
//! (P-stored-query-containment phase 1(a) / D-126).
//!
//! `grant_readonly_select` hand-copies the credential-column exclusion list
//! (`CREDENTIAL_ENTITY_EXCLUDED_COLUMNS`) that migration `0046` also carries
//! independently. Migration `0046` itself is proven once, at migration
//! time — `crates/server/tests/readonly_role_seed.rs`'s
//! `attome_readonly_cannot_read_credential_or_security_tables` covers that.
//! Nothing before this suite proved the *runtime re-grant path*
//! (`grant_readonly_select`/`backfill_readonly_grants`, called on every
//! `provision_table` and boot backfill — i.e. a "reseed") agrees with it: a
//! typo introduced in `grants.rs`'s own column list, independent of
//! migration `0046`'s, would have shipped silently.
//!
//! Requires a live Postgres with migrations already applied (`attome_readonly`
//! role, `user_account`/`api_key` tables) — skips (loudly) when
//! `DATABASE_URL` is unset, except under `CI` (see `attome_testkit`). Run
//! manually:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-metadata --test grants -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;

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

async fn can_select_column(db: &DbPool, role: &str, table: &str, column: &str) -> bool {
    sqlx::query_scalar("SELECT has_column_privilege($1, $2, $3, 'SELECT')")
        .bind(role)
        .bind(table)
        .bind(column)
        .fetch_one(db)
        .await
        .expect("has_column_privilege")
}

/// D-126's "wrinkle": `user_account`/`api_key` are registered
/// CRUD entities and so get a column-level `attome_readonly` grant naming
/// every OTHER column, instead of being denied outright like a plain
/// credential table. Proves the excluded column stays excluded after a
/// *reseed* — `grant_readonly_select` run again, exactly as
/// `provision_table` and `backfill_readonly_grants` call it on every boot —
/// not just once at migration time.
#[tokio::test]
async fn reseeding_the_readonly_grant_never_exposes_a_credential_column() {
    let db = skip_if_no_db!(test_db().await);

    for (table, excluded_column) in [
        ("user_account", "password_hash"),
        ("api_key", "secret_hash"),
    ] {
        attome_metadata::provision::grant_readonly_select(&db, table)
            .await
            .expect("reseed the readonly grant for a credential-bearing entity");

        assert!(
            !can_select_column(&db, "attome_readonly", table, excluded_column).await,
            "attome_readonly must not carry SELECT on {table}.{excluded_column} after a reseed"
        );
    }
}

/// Positive counterpart: the exclusion is column-scoped, not table-scoped —
/// every OTHER column on the same table must still be readable after the
/// same reseed, or the D-126 "wrinkle" (a registered CRUD entity keeps its
/// non-credential columns queryable) would itself be broken by this path.
#[tokio::test]
async fn reseeding_the_readonly_grant_still_exposes_non_credential_columns() {
    let db = skip_if_no_db!(test_db().await);

    attome_metadata::provision::grant_readonly_select(&db, "user_account")
        .await
        .expect("reseed the readonly grant");

    assert!(
        can_select_column(&db, "attome_readonly", "user_account", "id").await,
        "attome_readonly must still be able to read user_account.id after a reseed"
    );
}

/// `backfill_readonly_grants` (the boot-backfill entry point, not the
/// per-table primitive) walks every registered entity — proves it too
/// leaves the credential exclusion intact rather than only the direct
/// `grant_readonly_select` call above.
#[tokio::test]
async fn boot_backfill_never_exposes_a_credential_column() {
    let db = skip_if_no_db!(test_db().await);

    attome_metadata::provision::backfill_readonly_grants(&db)
        .await
        .expect("boot backfill of readonly grants");

    assert!(
        !can_select_column(&db, "attome_readonly", "user_account", "password_hash").await,
        "backfill_readonly_grants must not expose user_account.password_hash"
    );
    assert!(
        !can_select_column(&db, "attome_readonly", "api_key", "secret_hash").await,
        "backfill_readonly_grants must not expose api_key.secret_hash"
    );
}

async fn can_select_table(db: &DbPool, role: &str, table: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege($1, $2, 'SELECT')")
        .bind(role)
        .bind(table)
        .fetch_one(db)
        .await
        .expect("has_table_privilege")
}

/// The positive half of the backfill's contract, and the one the batching
/// rewrite could break silently.
///
/// `backfill_readonly_grants` now issues a single
/// `GRANT SELECT ON a, b, c TO attome_readonly` for every whole-table entity
/// instead of one statement each (the loop cost ~5 round-trips per entity,
/// since `exec_ddl_locked` wraps each call in its own transaction with two
/// `SET LOCAL`s). Every other test in this file asserts what the backfill must
/// NOT grant — all of which would still pass if the batch granted *nothing at
/// all*. This one proves ordinary entities really do come out readable.
#[tokio::test]
async fn boot_backfill_grants_every_whole_table_entity() {
    let db = skip_if_no_db!(test_db().await);

    let tag = uuid::Uuid::now_v7().simple().to_string();
    let tables: Vec<String> = (0..3).map(|i| format!("zz_grant_{tag}_{i}")).collect();

    for t in &tables {
        sqlx::query(&format!(
            r#"CREATE TABLE "{t}" (id UUID PRIMARY KEY DEFAULT uuidv7(), is_active BOOLEAN)"#
        ))
        .execute(&db)
        .await
        .expect("create throwaway table");
        sqlx::query(
            "INSERT INTO entity_info (id, logicalname, name, is_active, owner_layer) \
             VALUES ($1, $2, $2, true, 'project')",
        )
        .bind(uuid::Uuid::now_v7())
        .bind(t)
        .execute(&db)
        .await
        .expect("register throwaway entity");

        assert!(
            !can_select_table(&db, "attome_readonly", t).await,
            "{t} must start ungranted, or this test proves nothing"
        );
    }

    attome_metadata::provision::backfill_readonly_grants(&db)
        .await
        .expect("boot backfill of readonly grants");

    for t in &tables {
        assert!(
            can_select_table(&db, "attome_readonly", t).await,
            "batched backfill must grant attome_readonly SELECT on {t}"
        );
    }

    for t in &tables {
        sqlx::query("DELETE FROM entity_info WHERE logicalname = $1")
            .bind(t)
            .execute(&db)
            .await
            .ok();
        sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{t}""#))
            .execute(&db)
            .await
            .ok();
    }
}

/// Y2-T13: a throwaway entity with one sensitive attribute and one inactive
/// row. After `grant_readonly_select` the read-only role cannot read the
/// sensitive column, reads the others, and sees only the live row (the
/// application's own lists show the same); the application's own role still
/// sees both rows. The table and its metadata rows are removed afterwards.
#[tokio::test]
async fn readonly_role_cannot_read_sensitive_column() {
    let db = skip_if_no_db!(test_db().await);
    let table = "y2_t13_probe";
    let cleanup = |db: DbPool| async move {
        sqlx::query(&format!(r#"DROP TABLE IF EXISTS "{table}""#))
            .execute(&db)
            .await
            .expect("drop the probe table");
        sqlx::query(
            "DELETE FROM attribute_info WHERE entity_ref IN              (SELECT id FROM entity_info WHERE logicalname = $1)",
        )
        .bind(table)
        .execute(&db)
        .await
        .expect("delete the probe attributes");
        sqlx::query("DELETE FROM entity_info WHERE logicalname = $1")
            .bind(table)
            .execute(&db)
            .await
            .expect("delete the probe entity");
    };
    cleanup(db.clone()).await;

    sqlx::query(&format!(
        r#"CREATE TABLE "{table}" (id uuid PRIMARY KEY DEFAULT uuidv7(), is_active boolean, name text, secret_note text)"#
    ))
    .execute(&db)
    .await
    .expect("create the probe table");
    let entity: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO entity_info (logicalname, owner_layer) VALUES ($1, 'project') RETURNING id",
    )
    .bind(table)
    .fetch_one(&db)
    .await
    .expect("register the probe entity");
    for (column, sensitive) in [("name", false), ("secret_note", true)] {
        sqlx::query(
            "INSERT INTO attribute_info (logicalname, entity_ref, is_sensitive, owner_layer)              VALUES ($1, $2, $3, 'project')",
        )
        .bind(column)
        .bind(entity)
        .bind(sensitive)
        .execute(&db)
        .await
        .expect("register the probe attribute");
    }
    sqlx::query(&format!(
        r#"INSERT INTO "{table}" (is_active, name, secret_note) VALUES (true, 'live', 's'), (false, 'gone', 's')"#
    ))
    .execute(&db)
    .await
    .expect("insert the probe rows");

    attome_metadata::provision::grant_readonly_select(&db, table)
        .await
        .expect("grant the read-only role");

    let read_secret = can_select_column(&db, "attome_readonly", table, "secret_note").await;
    let read_name = can_select_column(&db, "attome_readonly", table, "name").await;

    let mut tx = db.begin().await.expect("begin");
    sqlx::query("SET LOCAL ROLE attome_readonly")
        .execute(&mut *tx)
        .await
        .expect("switch to the read-only role");
    let visible: i64 = sqlx::query_scalar(&format!(r#"SELECT count(*) FROM "{table}""#))
        .fetch_one(&mut *tx)
        .await
        .expect("count as the read-only role");
    let secret = sqlx::query(&format!(r#"SELECT secret_note FROM "{table}""#))
        .fetch_all(&mut *tx)
        .await;
    tx.rollback().await.expect("rollback");

    let mut app = db.begin().await.expect("begin");
    sqlx::query("SET LOCAL ROLE attome_runtime")
        .execute(&mut *app)
        .await
        .expect("switch to the application role");
    let app_sees: i64 = sqlx::query_scalar(&format!(r#"SELECT count(*) FROM "{table}""#))
        .fetch_one(&mut *app)
        .await
        .expect("count as the application role");
    app.rollback().await.expect("rollback");

    cleanup(db.clone()).await;

    assert!(!read_secret, "the sensitive column is not granted");
    assert!(read_name, "the other columns are");
    assert!(
        secret.is_err(),
        "selecting the sensitive column is a permission error"
    );
    assert_eq!(visible, 1, "the read-only role sees only the live row");
    assert_eq!(app_sees, 2, "the application's role still sees every row");
}

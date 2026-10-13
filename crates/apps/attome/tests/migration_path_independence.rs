//! CI-12 — **the resulting schema must not depend on the path taken to reach
//! it.** Applying every migration in one pass (`0000`→latest) must produce a
//! byte-identical schema to applying them in two stages (`0000`→N, then
//! N→latest).
//!
//! # Why this is not what CI-12 originally asked for
//!
//! The item as written said "assert the schema matches an *upgraded*
//! database". There is no upgraded database anywhere in this repo to compare
//! against: every path that migrates runs `sqlx migrate run … 0000→latest` in
//! a single pass, and
//! `scripts/run-integration-tests.ps1` drops and rebuilds the local template
//! from nothing on every run. **Every environment in this repo is built from
//! empty.** An incrementally-upgraded database exists only in a real customer
//! deployment (D-002: one database per customer), which CI cannot reach — so
//! the comparison the item names has nothing on its other side and cannot be
//! written.
//!
//! Two stages against one is the constructible form of the same intent, and it
//! catches the defect class that actually matters: a migration whose effect
//! differs depending on what was already applied when it ran. A customer
//! upgrading from an older release takes the staged path; CI only ever takes
//! the single-pass one, so **no existing test can see this class at all**.
//!
//! # What this does *not* duplicate
//!
//! `fresh_bootstrap.rs` already proves the single-pass path works end to end
//! (empty database → `ensure_schema` → every migration → bootstrap → a second
//! idempotent boot → `/health/ready`). That is the "does it run" question.
//! This is the "does the order matter" question, and the two are independent:
//! every migration can apply cleanly by both routes and still leave two
//! different schemas behind.
//!
//! # Isolation
//!
//! Two whole empty databases, not two schemas — the same requirement
//! `fresh_bootstrap.rs` documents (D-349/TODO-006): migration
//! `0014_apalis_jobs.sql` hardcodes a **global** `apalis` schema that no
//! `search_path` can redirect, so per-schema isolation cannot contain a
//! replay. Both guards drop their database `WITH (FORCE)` on scope exit.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use sqlx::migrate::{Migrate, Migrator};
use sqlx::{Executor, PgPool, Row};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Deployment schema the migrations install into. Matches
/// `config.example.json`'s `database.schema`, which is what a real deployment
/// and every other suite use.
const DEPLOYMENT_SCHEMA: &str = "attome_dev";

/// # What the two paths actually differ by
///
/// Not the migrations: both routes run the same files in the same order.
/// **The only difference is that a two-stage run has a session boundary in the
/// middle.** So the defect class this can catch is precisely *session-scoped
/// state that one migration leaves for a later one to consume*, which silently
/// stops working when a reconnect lands between them.
///
/// That makes the choice of cut a real design decision rather than a detail,
/// and it is why this runs **two** cuts:
///
/// - **`TARGETED_CUT` = 26.** `0026_audit_partitioning.sql` is the **only**
///   migration in this repo that uses a session-scoped construct: it creates
///   `pg_temp.partition_existing_table(...)` and calls it (6 `pg_temp`
///   references in that one file). Cutting immediately after `0026` puts a
///   reconnect at the one boundary where cross-migration session state exists
///   — or would, if a future migration ever came to depend on that function
///   surviving. Any cut later than 26 places all of it inside stage 1, where
///   the boundary cannot test it. `0038_timestamptz_backfill.sql` is the only
///   other file carrying session-scoped settings, and this cut puts it in
///   stage 2.
/// - **The median by migration count**, as an unbiased control. Deliberately
///   *not* the numeric midpoint of the version range: `0109`–`0117` is a
///   sanctioned-but-empty gap (D-379), so version-space and work-space
///   midpoints differ. Computed at runtime, so it needs no maintenance as
///   migrations accumulate.
///
/// **A green result proves path-independence at these two boundaries, not in
/// general.** Testing every cut is `O(n)` full replays over 130+ migrations —
/// hours, for a linear gain against a defect that, where it exists at all,
/// is overwhelmingly likely to show at the boundary that carries the state.
const TARGETED_CUT: i64 = 26;

fn median_cut(versions: &[i64]) -> i64 {
    versions[versions.len() / 2]
}

#[tokio::test]
async fn schema_does_not_depend_on_the_migration_path() {
    let single = attome_testkit::skip_if_no_db!(
        attome_testkit::empty_database("migration_path_single").await
    );

    let versions: Vec<i64> = MIGRATOR.iter().map(|m| m.version).collect();
    assert!(
        versions.len() > 2,
        "the compiled migrator must carry the real migration set; got {}",
        versions.len()
    );
    assert!(
        versions.contains(&TARGETED_CUT),
        "TARGETED_CUT {TARGETED_CUT} must name a real migration — if 0026 was ever renumbered, \
         re-derive it from whichever migration now owns the pg_temp function"
    );

    // The reference: one pass, exactly what every environment in this repo does.
    let single_pool = migration_pool(single.url()).await;
    prepare_schema(&single_pool).await;
    apply_through(&single_pool, i64::MAX).await;
    let reference = schema_snapshot(&single_pool).await;
    let reference_versions = applied_versions(&single_pool).await;

    for cut in [TARGETED_CUT, median_cut(&versions)] {
        // What an upgrading customer deployment does: land on an older
        // release, reconnect, then take the rest later.
        let staged = attome_testkit::skip_if_no_db!(
            attome_testkit::empty_database(&format!("migration_path_staged_{cut}")).await
        );
        let staged_pool = migration_pool(staged.url()).await;
        prepare_schema(&staged_pool).await;
        apply_through(&staged_pool, cut).await;
        apply_through(&staged_pool, i64::MAX).await;

        // Both must have ended at the same version, or the comparison below
        // would be measuring an incomplete replay rather than a path
        // difference.
        assert_eq!(
            reference_versions,
            applied_versions(&staged_pool).await,
            "both paths must apply the identical set of migration versions \
             (cut at {cut}) before their schemas can be meaningfully compared"
        );

        let staged_schema = schema_snapshot(&staged_pool).await;
        if reference != staged_schema {
            panic!(
                "the schema depends on the migration path — applying 0000..={cut} \
                 then {cut}..=latest produced a different schema than applying \
                 everything in one pass.\n\n{}",
                first_difference(&reference, &staged_schema)
            );
        }
    }
}

/// A pool whose every connection lands on the deployment schema, matching what
/// `attome_db::create_direct_pool` gives the real bootstrap. Set per-connection
/// via `after_connect` rather than in the URL so it survives pool recycling.
async fn migration_pool(url: &str) -> PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute(
                    format!("SET search_path TO \"{DEPLOYMENT_SCHEMA}\", public").as_str(),
                )
                .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .expect("connect to the throwaway database")
}

/// `attome_db::ensure_schema`'s entire job is `CREATE SCHEMA IF NOT EXISTS`
/// (`attome-db/src/schema.rs:37`), inlined here so this test needs no
/// `AppConfig`. Migrations assume the deployment schema already exists.
async fn prepare_schema(pool: &PgPool) {
    sqlx::query(&format!(
        "CREATE SCHEMA IF NOT EXISTS \"{DEPLOYMENT_SCHEMA}\""
    ))
    .execute(pool)
    .await
    .expect("create the deployment schema on an empty database");
}

/// Applies every not-yet-applied migration whose version is `<= through`.
///
/// `Migrator::run` has no "up to version N" mode, so this drives sqlx's
/// `Migrate` trait directly — the same primitives `run` itself uses, so the
/// migrations are applied exactly as production applies them (same checksum
/// recording, same `_sqlx_migrations` bookkeeping), just stopped early.
async fn apply_through(pool: &PgPool, through: i64) {
    let mut conn = pool
        .acquire()
        .await
        .expect("acquire a connection to migrate on");

    conn.ensure_migrations_table()
        .await
        .expect("create _sqlx_migrations");

    let already: std::collections::HashSet<i64> = conn
        .list_applied_migrations()
        .await
        .expect("list applied migrations")
        .into_iter()
        .map(|m| m.version)
        .collect();

    for migration in MIGRATOR.iter() {
        if migration.version > through {
            break;
        }
        if already.contains(&migration.version) {
            continue;
        }
        conn.apply(migration).await.unwrap_or_else(|e| {
            panic!(
                "migration {} ({}) failed to apply: {e}",
                migration.version, migration.description
            )
        });
    }
}

async fn applied_versions(pool: &PgPool) -> Vec<i64> {
    let mut conn = pool.acquire().await.expect("acquire");
    let mut v: Vec<i64> = conn
        .list_applied_migrations()
        .await
        .expect("list applied migrations")
        .into_iter()
        .map(|m| m.version)
        .collect();
    v.sort_unstable();
    v
}

/// An ordered, textual description of everything a migration can create that a
/// later one could get wrong: columns with their types/nullability/defaults,
/// constraints, and indexes.
///
/// Scoped to the deployment schema **and** `apalis`. The latter is not an edge
/// case: **14 migrations touch `apalis`** — `0014` creates it globally, and
/// `0026`, `0030`, `0032`, `0034`, `0046`, `0050`, `0060`-`0063`, `0072`,
/// `0090`, `0138` write to it. Four of those (`0046`, `0050`, `0063`, `0072`)
/// are readonly-containment/grant migrations, and a path-dependent *grant*
/// difference is exactly the shape that would hide from a columns-only diff.
/// `information_schema` and `pg_%` are excluded as server-owned.
async fn schema_snapshot(pool: &PgPool) -> Vec<String> {
    let mut out = Vec::new();

    let columns = sqlx::query(
        "SELECT table_schema, table_name, column_name, data_type, is_nullable, \
                COALESCE(column_default, '') AS column_default \
         FROM information_schema.columns \
         WHERE table_schema = ANY($1) \
         ORDER BY table_schema, table_name, column_name",
    )
    .bind(vec![DEPLOYMENT_SCHEMA.to_string(), "apalis".to_string()])
    .fetch_all(pool)
    .await
    .expect("read information_schema.columns");

    for r in &columns {
        out.push(format!(
            "column {}.{}.{} type={} nullable={} default={}",
            r.get::<String, _>("table_schema"),
            r.get::<String, _>("table_name"),
            r.get::<String, _>("column_name"),
            r.get::<String, _>("data_type"),
            r.get::<String, _>("is_nullable"),
            r.get::<String, _>("column_default"),
        ));
    }

    let constraints = sqlx::query(
        "SELECT n.nspname AS sch, rel.relname AS tbl, con.conname AS name, \
                pg_get_constraintdef(con.oid) AS def \
         FROM pg_constraint con \
         JOIN pg_class rel ON rel.oid = con.conrelid \
         JOIN pg_namespace n ON n.oid = rel.relnamespace \
         WHERE n.nspname = ANY($1) \
         ORDER BY n.nspname, rel.relname, con.conname",
    )
    .bind(vec![DEPLOYMENT_SCHEMA.to_string(), "apalis".to_string()])
    .fetch_all(pool)
    .await
    .expect("read pg_constraint");

    for r in &constraints {
        out.push(format!(
            "constraint {}.{}.{} {}",
            r.get::<String, _>("sch"),
            r.get::<String, _>("tbl"),
            r.get::<String, _>("name"),
            r.get::<String, _>("def"),
        ));
    }

    let indexes = sqlx::query(
        "SELECT schemaname, indexname, indexdef FROM pg_indexes \
         WHERE schemaname = ANY($1) ORDER BY schemaname, indexname",
    )
    .bind(vec![DEPLOYMENT_SCHEMA.to_string(), "apalis".to_string()])
    .fetch_all(pool)
    .await
    .expect("read pg_indexes");

    for r in &indexes {
        out.push(format!(
            "index {}.{} {}",
            r.get::<String, _>("schemaname"),
            r.get::<String, _>("indexname"),
            r.get::<String, _>("indexdef"),
        ));
    }

    out
}

/// The first divergence, and only that — a full diff of two 3,000-line schema
/// dumps is unreadable in CI output, and the first difference is nearly always
/// the one that explains the rest.
fn first_difference(single: &[String], staged: &[String]) -> String {
    for (i, (a, b)) in single.iter().zip(staged.iter()).enumerate() {
        if a != b {
            return format!(
                "first divergence at entry {i}:\n  single-pass: {a}\n  two-stage:   {b}"
            );
        }
    }
    let (long, label) = if single.len() > staged.len() {
        (single, "single-pass")
    } else {
        (staged, "two-stage")
    };
    format!(
        "schemas agree for the first {} entries, but {label} has {} more, \
         starting with:\n  {}",
        single.len().min(staged.len()),
        long.len() - single.len().min(staged.len()),
        long[single.len().min(staged.len())]
    )
}

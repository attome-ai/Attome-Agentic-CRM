//! Equivalence proof for `entity_privileges::seed_all`'s set-based rewrite.
//!
//! `seed_all` used to read every live entity and then call
//! `ensure_entity_privileges` once per entity — `1 + (entities x 5)` sequential
//! round-trips per call, ~1,022 per boot at 100+ platform entities, and it is
//! called on every boot. It is now a single `INSERT ... SELECT ... ON CONFLICT
//! DO NOTHING`.
//!
//! A rewrite from a Rust loop to hand-written SQL can silently drift in the key
//! format, the `name`/`description` text, or which entities it covers, and
//! nothing else in the suite would notice — a per-entity privilege that exists
//! under the wrong key simply never matches an authz check. So this test does
//! not assert against literals it could copy wrong: it runs the untouched
//! row-at-a-time path (`ensure_entity_privileges`, still used by
//! `admin::create_entity`) against one entity and the rewritten set-based path
//! against another, and asserts the two produce **identical** rows modulo the
//! logicalname.
//!
//! Requires a live Postgres (`DATABASE_URL`) — same convention as
//! `tests/resolver.rs`. Uses throwaway entities with random suffixes, never a
//! shared or real one.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_security::entity_privileges::{ensure_entity_privileges, seed_all};
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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

/// Registers a throwaway entity and returns its logicalname.
async fn register_entity(db: &DbPool, tag: &str) -> String {
    let logicalname = format!("zz_seedall_{tag}_{}", Uuid::now_v7().simple());
    sqlx::query(
        "INSERT INTO entity_info (id, logicalname, name, is_active, owner_layer) \
         VALUES ($1, $2, $2, true, 'project')",
    )
    .bind(Uuid::now_v7())
    .bind(&logicalname)
    .execute(db)
    .await
    .expect("register throwaway entity");
    logicalname
}

/// Every privilege row belonging to one entity, as `(key, name, description)`
/// with the logicalname stripped out so two entities' rows compare directly.
async fn privilege_shape(db: &DbPool, logicalname: &str) -> Vec<(String, String, String)> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT key, name, description FROM privilege \
         WHERE key LIKE $1 ORDER BY key",
    )
    .bind(format!("{logicalname}.%"))
    .fetch_all(db)
    .await
    .expect("read privileges");

    rows.into_iter()
        .map(|(k, n, d)| {
            (
                k.replace(logicalname, "{entity}"),
                n.replace(logicalname, "{entity}"),
                d.replace(logicalname, "{entity}"),
            )
        })
        .collect()
}

async fn cleanup(db: &DbPool, logicalname: &str) {
    sqlx::query("DELETE FROM privilege WHERE key LIKE $1")
        .bind(format!("{logicalname}.%"))
        .execute(db)
        .await
        .ok();
    sqlx::query("DELETE FROM entity_info WHERE logicalname = $1")
        .bind(logicalname)
        .execute(db)
        .await
        .ok();
}

#[tokio::test]
async fn set_based_seed_all_matches_the_row_at_a_time_path_exactly() {
    let db = skip_if_no_db!(test_db().await);

    let looped = register_entity(&db, "loop").await;
    let swept = register_entity(&db, "sweep").await;

    // Reference: the untouched per-entity path `admin::create_entity` uses.
    ensure_entity_privileges(&db, &looped, attome_core::changeset::Layer::Project)
        .await
        .expect("row-at-a-time path");

    // Subject: the rewritten set-based path. It covers `swept` (and re-covers
    // `looped`, which must stay a no-op).
    seed_all(&db).await.expect("set-based path");

    let reference = privilege_shape(&db, &looped).await;
    let subject = privilege_shape(&db, &swept).await;

    assert_eq!(
        reference.len(),
        5,
        "the reference path should write 4 CRUD actions plus bulk"
    );
    assert_eq!(
        subject, reference,
        "set-based seed_all must produce the same key/name/description rows as \
         ensure_entity_privileges — a drift here is an authz hole, not a cosmetic diff"
    );

    // Idempotent: a second sweep must not duplicate or alter anything.
    seed_all(&db).await.expect("second sweep");
    assert_eq!(
        privilege_shape(&db, &swept).await,
        reference,
        "seed_all must be idempotent — ON CONFLICT DO NOTHING, never a second row"
    );

    // An inactive entity is out of scope for both paths.
    let retired = register_entity(&db, "retired").await;
    sqlx::query("UPDATE entity_info SET is_active = false WHERE logicalname = $1")
        .bind(&retired)
        .execute(&db)
        .await
        .expect("retire entity");
    seed_all(&db).await.expect("sweep after retire");
    assert!(
        privilege_shape(&db, &retired).await.is_empty(),
        "a retired entity must not gain privileges"
    );

    cleanup(&db, &looped).await;
    cleanup(&db, &swept).await;
    cleanup(&db, &retired).await;
}

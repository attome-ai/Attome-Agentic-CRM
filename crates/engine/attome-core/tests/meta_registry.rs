//! Integration test for `build_registry` (Plan 1.2): confirms the snapshot
//! reflects the active `entity_info`/`attribute_info` model,
//! excludes soft-deleted rows, and groups attributes correctly.
//!
//! Requires a live Postgres (`DATABASE_URL`) — same convention as
//! `attome-server/tests/authz.rs`. NOT wired into any CI run yet (no
//! `attomedb_test` harness exists — see P1.8); run manually against a
//! throwaway database:
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5555/attomedb_test"
//! cargo test -p attome-core --test meta_registry
//! ```
//!
//! Uses a throwaway logicalname (random UUID suffix) rather than truncating
//! shared tables.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_core::{ChangeLogRow, apply_change_log, build_registry};
use attome_db::DbPool;
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

#[tokio::test]
async fn build_registry_reflects_active_model_and_excludes_soft_deleted() {
    let db = skip_if_no_db!(test_db().await);

    let logicalname = format!("mrtest_{}", Uuid::now_v7().simple());
    let entity_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO entity_info (id, logicalname, name, is_active, is_append_only, created_at, owner_layer) \
         VALUES ($1, $2, $3, true, false, NOW(), 'project')",
    )
    .bind(entity_id)
    .bind(&logicalname)
    .bind("Meta Registry Test")
    .execute(&db)
    .await
    .expect("insert throwaway entity_info row");

    sqlx::query(
        r#"INSERT INTO attribute_info
               (id, entity_ref, logicalname, name, "type", is_sensitive, is_active, created_at, owner_layer)
           VALUES ($1, $2, $3, $4, 3, false, true, NOW(), 'project')"#,
    )
    .bind(Uuid::now_v7())
    .bind(entity_id)
    .bind("note")
    .bind("Note")
    .execute(&db)
    .await
    .expect("insert throwaway attribute_info row");

    // A soft-deleted sibling attribute must be excluded from the snapshot.
    sqlx::query(
        r#"INSERT INTO attribute_info
               (id, entity_ref, logicalname, name, "type", is_sensitive, is_active, created_at, owner_layer)
           VALUES ($1, $2, $3, $4, 3, false, false, NOW(), 'project')"#,
    )
    .bind(Uuid::now_v7())
    .bind(entity_id)
    .bind("gone")
    .bind("Gone")
    .execute(&db)
    .await
    .expect("insert throwaway soft-deleted attribute_info row");

    let registry = build_registry(&db).await.expect("build_registry");
    let meta = registry
        .get(&logicalname)
        .expect("entity must be present in the registry");

    assert_eq!(meta.entity_id, entity_id);
    assert!(!meta.is_append_only);
    assert_eq!(
        meta.attrs.len(),
        1,
        "soft-deleted attribute must be excluded"
    );
    assert_eq!(meta.attrs[0].logicalname, "note");

    // Soft-delete the entity itself and confirm a fresh snapshot drops it —
    // the pub/sub subscriber rebuilds by calling build_registry again, so
    // this is exactly what a node sees after a delete + version bump.
    sqlx::query("UPDATE entity_info SET is_active = false WHERE id = $1")
        .bind(entity_id)
        .execute(&db)
        .await
        .expect("soft-delete throwaway entity");

    let registry_after = build_registry(&db)
        .await
        .expect("build_registry after soft-delete");
    assert!(registry_after.get(&logicalname).is_none());
}

/// Inserts a throwaway active entity with one active attribute, returning its
/// id — the fixture the batched-catch-up test below patches.
async fn insert_entity(db: &DbPool, logicalname: &str) -> Uuid {
    let entity_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO entity_info (id, logicalname, name, is_active, is_append_only, created_at, owner_layer) \
         VALUES ($1, $2, $3, true, false, NOW(), 'project')",
    )
    .bind(entity_id)
    .bind(logicalname)
    .bind("Change Log Test")
    .execute(db)
    .await
    .expect("insert throwaway entity_info row");

    sqlx::query(
        r#"INSERT INTO attribute_info
               (id, entity_ref, logicalname, name, "type", is_sensitive, is_active, created_at, owner_layer)
           VALUES ($1, $2, $3, $4, 3, false, true, NOW(), 'project')"#,
    )
    .bind(Uuid::now_v7())
    .bind(entity_id)
    .bind("note")
    .bind("Note")
    .execute(db)
    .await
    .expect("insert throwaway attribute_info row");

    entity_id
}

/// TODO-026 (L-4): `apply_change_log` re-queries the deduped upsert set in one
/// batched `= ANY($1)` fetch instead of one round trip per entity. The batching
/// itself is structural — `fetch_entity_snapshots` issues exactly two
/// statements whatever the set's size — so what this test pins down is the
/// semantics that the rewrite could plausibly break across a multi-entity
/// batch: every upsert still lands, a `delete` row still evicts its key, and an
/// entity that vanished between the log write and the re-query is still dropped
/// rather than left stale (the branch that used to be a per-entity `None`).
#[tokio::test]
async fn apply_change_log_patches_a_multi_entity_batch() {
    let db = skip_if_no_db!(test_db().await);

    let suffix = Uuid::now_v7().simple().to_string();
    let kept = format!("clkept_{suffix}");
    let vanished = format!("clgone_{suffix}");
    let deleted = format!("cldel_{suffix}");

    let kept_id = insert_entity(&db, &kept).await;
    let vanished_id = insert_entity(&db, &vanished).await;
    let deleted_id = insert_entity(&db, &deleted).await;

    let base = build_registry(&db).await.expect("build_registry baseline");
    assert_eq!(base.get(&kept).expect("kept entity").attrs.len(), 1);

    // What the three change-log rows describe, in the order the catch-up loop
    // would read them: `kept` gained an attribute, `vanished` was upserted but
    // soft-deleted before the re-query lands, `deleted` was deleted outright.
    sqlx::query(
        r#"INSERT INTO attribute_info
               (id, entity_ref, logicalname, name, "type", is_sensitive, is_active, created_at, owner_layer)
           VALUES ($1, $2, $3, $4, 3, false, true, NOW(), 'project')"#,
    )
    .bind(Uuid::now_v7())
    .bind(kept_id)
    .bind("extra")
    .bind("Extra")
    .execute(&db)
    .await
    .expect("insert second attribute on the kept entity");

    sqlx::query("UPDATE entity_info SET is_active = false WHERE id = ANY($1)")
        .bind(&[vanished_id, deleted_id][..])
        .execute(&db)
        .await
        .expect("soft-delete the vanished and deleted entities");

    let rows = vec![
        ChangeLogRow {
            id: 1,
            entity_ref: kept_id,
            logicalname: kept.clone(),
            kind: "upsert".to_owned(),
        },
        // A redundant earlier row for the same entity — deduped, not replayed.
        ChangeLogRow {
            id: 2,
            entity_ref: kept_id,
            logicalname: kept.clone(),
            kind: "upsert".to_owned(),
        },
        ChangeLogRow {
            id: 3,
            entity_ref: vanished_id,
            logicalname: vanished.clone(),
            kind: "upsert".to_owned(),
        },
        ChangeLogRow {
            id: 4,
            entity_ref: deleted_id,
            logicalname: deleted.clone(),
            kind: "delete".to_owned(),
        },
    ];

    let patched = apply_change_log(&db, &base, &rows)
        .await
        .expect("apply_change_log");

    let meta = patched.get(&kept).expect("upserted entity stays served");
    assert_eq!(meta.entity_id, kept_id);
    assert_eq!(
        meta.attrs.len(),
        2,
        "the upserted entity must pick up its new attribute"
    );
    assert!(meta.attrs.iter().any(|a| a.logicalname == "extra"));

    assert!(
        patched.get(&vanished).is_none(),
        "an entity gone by re-query time must be evicted, not left stale"
    );
    assert!(
        patched.get(&deleted).is_none(),
        "a delete row must evict its key"
    );

    // Untouched entries are carried over from the base registry unchanged.
    assert_eq!(patched.len(), base.len() - 2);
}

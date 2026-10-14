//! Per-entity `{logicalname}.{action}` privilege seeding — the piece D-011
//! left "reserved future convention (unseeded)". `ctx.require(entity, action)`
//! (`context.rs`) has always existed; until this module runs there was
//! nothing to grant it against.
//!
//! No per-entity `admin` action: `system.admin` already short-circuits
//! `ctx.require()` for every entity. `bulk` is intentionally separate from
//! the four CRUD verbs because high-volume mutation is an independent grant.

use attome_core::changeset::Layer;
use attome_db::DbPool;
use attome_types::AppError;

use crate::db::ensure_privilege;

pub const ENTITY_ACTIONS: [&str; 4] = ["read", "create", "update", "delete"];
pub const BULK_ACTION: &str = "bulk";
/// A18-T6: permanently deleting a record (past the recycle bin) is its own
/// privilege, beside `delete`.
pub const HARD_DELETE_ACTION: &str = "hard_delete";
/// The per-entity keys beside the CRUD four, with how each is described.
pub const EXTRA_ACTIONS: [(&str, &str); 2] = [
    (BULK_ACTION, "bulk mutations"),
    (HARD_DELETE_ACTION, "permanent deletes"),
];

fn privilege_key(logicalname: &str, action: &str) -> String {
    format!("{logicalname}.{action}")
}

/// Idempotent — ensures the 4 per-action rows plus the dedicated bulk-action
/// `privilege` row exist for one entity. Called from
/// `attome-server::admin::create_entity` right after the
/// entity itself is provisioned, and from `seed_all` for backfill.
///
/// `owner_layer` (Solution 7, D-785) is the entity's own layer: the
/// per-entity keys derive from the entity and belong to whoever owns it,
/// the rule [`seed_all`] applies too. It stamps newly created rows only.
pub async fn ensure_entity_privileges(
    db: &DbPool,
    logicalname: &str,
    owner_layer: Layer,
) -> Result<(), AppError> {
    for action in ENTITY_ACTIONS {
        let key = privilege_key(logicalname, action);
        ensure_privilege(
            db,
            &key,
            &key,
            &format!("Per-entity privilege: {action} on {logicalname}"),
            owner_layer,
        )
        .await?;
    }
    for (action, what) in EXTRA_ACTIONS {
        let key = privilege_key(logicalname, action);
        ensure_privilege(
            db,
            &key,
            &key,
            &format!("Per-entity privilege: {what} on {logicalname}"),
            owner_layer,
        )
        .await?;
    }
    Ok(())
}

/// Renames the 4 CRUD and dedicated bulk privilege keys in place (same
/// `privilege` row, new `key`/`name`) so existing grants survive an entity rename
/// instead of being orphaned under the stale logicalname.
pub async fn rename_entity_privileges(
    db: &DbPool,
    old_logicalname: &str,
    new_logicalname: &str,
) -> Result<(), AppError> {
    for action in ENTITY_ACTIONS {
        let old_key = privilege_key(old_logicalname, action);
        let new_key = privilege_key(new_logicalname, action);
        sqlx::query("UPDATE privilege SET key = $1, name = $2 WHERE key = $3")
            .bind(&new_key)
            .bind(&new_key)
            .bind(&old_key)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    }
    for (action, _) in EXTRA_ACTIONS {
        let old_key = privilege_key(old_logicalname, action);
        let new_key = privilege_key(new_logicalname, action);
        sqlx::query("UPDATE privilege SET key = $1, name = $2 WHERE key = $3")
            .bind(&new_key)
            .bind(&new_key)
            .bind(&old_key)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Deactivates the 4 CRUD and dedicated bulk privilege keys on hard-delete. Not
/// security-critical by itself — `resolve_entity` in `entity_crud.rs` 404s
/// once the entity/table is gone regardless of leftover privilege rows —
/// this just keeps the grants catalog from accumulating dead keys.
pub async fn deactivate_entity_privileges(db: &DbPool, logicalname: &str) -> Result<(), AppError> {
    for action in ENTITY_ACTIONS {
        let key = privilege_key(logicalname, action);
        sqlx::query("UPDATE privilege SET is_active = false WHERE key = $1")
            .bind(&key)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    }
    for (action, _) in EXTRA_ACTIONS {
        let key = privilege_key(logicalname, action);
        sqlx::query("UPDATE privilege SET is_active = false WHERE key = $1")
            .bind(&key)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Boot-time backfill for entities created before this module existed, and for
/// every entity a platform bundle has just provisioned. Idempotent; safe on
/// every startup, and called on every one — twice, in fact
/// (`EngineSystemBuilder::build()`, then again from `boot.rs` so entities
/// registered after `.build()` are swept too).
///
/// One statement, deliberately, rather than the read-then-loop this used to be.
/// The old shape cost `1 + (entities x 5)` sequential round-trips per call —
/// past 100 platform entities that is ~511 per call and ~1,022 per boot, spent
/// almost entirely re-asserting rows that already existed, and it grew with
/// every entity a deployment adds. The set-based insert below is one
/// round-trip regardless of entity count, and it is *more* correct than the
/// loop: all-or-nothing instead of partially applied when a failure lands
/// halfway through.
///
/// `ENTITY_ACTIONS` + [`BULK_ACTION`] stay the single source of truth — they
/// are bound as an array and unnested, never interpolated — so the key set
/// this produces cannot drift from the one [`ensure_entity_privileges`] writes
/// for a single entity on the admin path.
///
/// Solution 7 (D-785): a new row takes its entity's `owner_layer` — the
/// per-entity keys derive from the entity, so a platform entity's keys are
/// platform-owned and a project entity's project-owned, the same layer
/// [`ensure_entity_privileges`] is given on the admin and apply paths. An
/// existing row keeps its layer (`ON CONFLICT DO NOTHING`).
pub async fn seed_all(db: &DbPool) -> Result<(), AppError> {
    let mut actions: Vec<&str> = ENTITY_ACTIONS.to_vec();
    actions.extend(EXTRA_ACTIONS.iter().map(|(action, _)| *action));

    // `privilege.id` has no column default (legacy table), so the id
    // is generated here rather than by the column — `uuidv7()` is the same
    // generator `Uuid::now_v7()` gave the row-at-a-time path (migration 0013).
    // `ON CONFLICT (key) DO NOTHING` against `uq_core_privilege_key` gives the
    // same race-safe find-or-create semantics `ensure_privilege_with_id`
    // documents; no id is read back because no caller needs one here.
    sqlx::query(
        "INSERT INTO privilege (id, key, name, description, is_active, created_at, \
                                         owner_layer) \
         SELECT uuidv7(), \
                e.logicalname || '.' || a.action, \
                e.logicalname || '.' || a.action, \
                CASE WHEN a.action = $2 \
                     THEN 'Per-entity privilege: bulk mutations on ' || e.logicalname \
                     WHEN a.action = $3 \
                     THEN 'Per-entity privilege: permanent deletes on ' || e.logicalname \
                     ELSE 'Per-entity privilege: ' || a.action || ' on ' || e.logicalname \
                END, \
                true, NOW(), e.owner_layer \
           FROM entity_info e \
           CROSS JOIN unnest($1::text[]) AS a(action) \
          WHERE (e.is_active IS NULL OR e.is_active = true) \
            AND e.logicalname IS NOT NULL \
         ON CONFLICT (key) DO NOTHING",
    )
    .bind(&actions)
    .bind(BULK_ACTION)
    .bind(HARD_DELETE_ACTION)
    .execute(db)
    .await
    .map_err(AppError::internal)?;

    Ok(())
}

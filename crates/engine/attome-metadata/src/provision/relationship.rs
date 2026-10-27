//! M01 Core P3 gap (D-455) — physical join-table provisioning for a generic
//! many-to-many relationship (`relationship_info`).
//!
//! Deliberately NOT a variant of `table::provision_table`: that function's
//! shape (single `id UUID PRIMARY KEY`, `organization_ref`, `owner_ref`/
//! `owner_type`, ...) exists to satisfy `entity_crud`'s generic single-id
//! CRUD contract, and every join table this module provisions is accessed
//! only through the dedicated `/api/v1/{entity}/{id}/related/{relationship}`
//! API and `query_exec`'s relationship-join support — never through generic
//! `/api/v1/{entity}` CRUD, and never registered in `entity_info`.
//! That is what makes a composite `(a_id, b_id)` primary key safe to use
//! here even though every legacy hand-built `_mm_` table
//! (`user_account_mm_team` et al.) instead uses a surrogate `id` +
//! a `UNIQUE` constraint — those tables are entity-registered specifically
//! so the existing `xrm-related-grid` Angular component can drive them
//! through generic CRUD, a constraint this new mechanism does not carry.
//!
//! Column shape borrows the D-005 *entity-table* convention's names
//! (`created_at`/`created_by`/`is_active`/`row_version`), not the
//! migration-owned infra convention `relationship_info` itself
//! uses — this table is created through the same runtime provisioning
//! engine as an ordinary entity table (`provision_table` lives one file
//! over) — but deliberately only that subset, not the full entity-table
//! column set (`modified_at`/`modified_by`/`organization_ref`/`owner_ref`/
//! `owner_type`/the `is_active` partial index): a join row is a pure link,
//! never independently owned, never updated in place outside the is_active
//! toggle `link_related`/`unlink_related` already do, and never reached by
//! anything that would need those columns (never entity-registered, never
//! generic-CRUD-addressable — see above). D-455 amendment D-481 records
//! this as the deliberate, permanent shape, not a gap.

use attome_db::DbPool;
use attome_types::AppError;
// Glob import matches `attome_state::reconcile`'s own import for the identical
// `.next().publish(...)` call in `invalidate` below.
use attome_core::reconcile::{ReconcileOutcome, ReconcilePolicy};
use attome_core::{EngineState, RelationshipCascade};
use uuid::Uuid;

use super::changeset::{self, ObjectKind, RecordAs};
use super::ddl::exec_ddl_locked;
use super::grants::grant_readonly_select;
use super::identifiers::{MAX_IDENTIFIER_LEN, valid_identifier};

/// Reloads this node's own `relationships` snapshot and best-effort
/// publishes the cross-node doorbell — the exact shape
/// `attome_state::reconcile::invalidate` already established for the sibling
/// small-admin-authored-table cache. Centralized here (rather than
/// duplicated in `relationship_admin.rs` and the bundle apply step) so
/// there is exactly one place that can drift from that shape.
async fn invalidate(state: &EngineState) {
    match attome_core::relationship_registry::load(&state.base.db).await {
        Ok(fresh) => state.relationships.swap(fresh),
        Err(e) => tracing::warn!(error = %e, "relationship registry reload failed after write"),
    }

    let publish_result = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        state
            .base
            .redis
            .publish(attome_core::RELATIONSHIP_VERSION_CHANNEL, "1"),
    )
    .await;
    match publish_result {
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "failed to publish relationship invalidation doorbell")
        }
        Err(_) => tracing::warn!("publishing relationship invalidation doorbell timed out"),
        Ok(Ok(_)) => {}
    }
}

/// Creates the physical join table backing a relationship, if it doesn't
/// already exist. Idempotent — safe to call on every boot/reseed, same
/// posture as `provision_table`. `join_table`/`entity_a_table`/
/// `entity_b_table` must already be validated `valid_identifier` names (the
/// caller — `relationship_admin`'s create handler — derives `join_table`
/// from an already-validated relationship `name`, and `entity_a_table`/
/// `entity_b_table` are DB-trusted logicalnames resolved via
/// `entity_crud::resolve_entity`, never the caller's raw input).
///
/// FKs are `ON DELETE CASCADE`: a hard-deleted endpoint record (the
/// irreversible `/hard-delete` path, distinct from the ordinary soft
/// `is_active` deactivation every other read/write in this platform uses)
/// must not leave an orphaned join row referencing a physically-gone id —
/// same reasoning the legacy hand-built `_mm_` tables' FKs already apply.
/// Soft deletion is handled entirely at the application layer (every
/// `/related/{relationship}` read filters `is_active` on both endpoint
/// tables AND the join row itself), never by the FK.
pub async fn provision_join_table(
    db: &DbPool,
    join_table: &str,
    entity_a_table: &str,
    entity_b_table: &str,
) -> Result<(), AppError> {
    if !valid_identifier(entity_a_table) || !valid_identifier(entity_b_table) {
        return Err(AppError::internal(format!(
            "invalid relationship endpoint identifier (lowercase/digits/underscore, max {MAX_IDENTIFIER_LEN} chars): a={entity_a_table}, b={entity_b_table}"
        )));
    }
    // join_table is composed as "mm_{name}" by the caller from an
    // already-`valid_identifier`-checked `name`, so its charset is already
    // guaranteed safe — only the composed length (Postgres's real 63-byte
    // NAMEDATALEN-1 limit, not this crate's tighter 48-char
    // MAX_IDENTIFIER_LEN meant for un-composed base identifiers) needs a
    // fresh check here.
    if join_table.len() > 63 || join_table.is_empty() {
        return Err(AppError::internal(format!(
            "invalid relationship join_table identifier length (1..=63 bytes): {join_table}"
        )));
    }

    // C-21 (M01 §7): a relationship retired then recreated under the same
    // `name` reaches this function through `reconcile_relationship`'s
    // `existing = None` branch exactly like a brand-new relationship — the
    // metadata uniqueness on `name` is partial (`WHERE NOT is_deleted`,
    // migration 0247), and `retire_relationship` never drops the physical
    // join table (its own doc comment). Left alone, the `CREATE TABLE IF NOT
    // EXISTS` below would silently no-op onto that stale table even if the
    // recreation swapped which entity is `a`/`b` — its FKs would then point
    // at the WRONG endpoint tables while old rows from the retired
    // relationship kept coexisting under the new one's name. Refuse instead
    // of guessing.
    verify_join_table_matches_or_absent(db, join_table, entity_a_table, entity_b_table).await?;

    exec_ddl_locked(
        db,
        &[],
        &format!(
            r#"CREATE TABLE IF NOT EXISTS "{join_table}" (
                   a_id        UUID NOT NULL REFERENCES "{entity_a_table}"(id) ON DELETE CASCADE,
                   b_id        UUID NOT NULL REFERENCES "{entity_b_table}"(id) ON DELETE CASCADE,
                   is_active   BOOLEAN NOT NULL DEFAULT TRUE,
                   created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                   created_by   UUID,
                   row_version BIGINT NOT NULL DEFAULT 0,
                   PRIMARY KEY (a_id, b_id)
               )"#
        ),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, join_table = %join_table, "relationship join-table CREATE failed during provisioning");
        AppError::internal(e)
    })?;

    // Reverse lookup ("every A linked to this B") — the PK's leading column
    // already indexes the forward direction ("every B linked to this A").
    exec_ddl_locked(
        db,
        &[],
        &format!(r#"CREATE INDEX IF NOT EXISTS "idx_{join_table}_b_id" ON "{join_table}" (b_id)"#),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, join_table = %join_table, "relationship join-table b_id index CREATE failed during provisioning");
        AppError::internal(e)
    })?;

    ensure_link_columns(db, join_table).await?;

    // Same read-only-role grant every provisioned table gets (D-126) — a
    // relationship's join rows must be reachable through
    // `/api/v1/query/execute`'s relationship-join support, which runs under
    // `attome_readonly`, exactly like an ordinary entity table.
    grant_readonly_select(db, join_table).await
}

/// A7-T4: a link's own columns — its `role`, its validity dates
/// (`valid_from`, `valid_to`; open when null) and further `attributes` — on
/// `join_table`, added when missing. Each is nullable or has a constant
/// default, so adding them changes metadata only and rewrites no row.
pub async fn ensure_link_columns(db: &DbPool, join_table: &str) -> Result<(), AppError> {
    if !join_table
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(AppError::internal(format!(
            "invalid join table identifier: {join_table}"
        )));
    }
    exec_ddl_locked(
        db,
        &[],
        &format!(
            r#"ALTER TABLE "{join_table}"
                   ADD COLUMN IF NOT EXISTS role TEXT,
                   ADD COLUMN IF NOT EXISTS valid_from DATE,
                   ADD COLUMN IF NOT EXISTS valid_to DATE,
                   ADD COLUMN IF NOT EXISTS attributes JSONB NOT NULL DEFAULT '{{}}'::jsonb"#
        ),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, join_table = %join_table, "adding a join table's link columns failed");
        AppError::internal(e)
    })
}

/// C-21 (M01 §7) guard — `Ok(())` when `join_table` doesn't exist yet (the
/// ordinary first-create path), or when it exists and its `a_id`/`b_id`
/// foreign keys already point at exactly `entity_a_table`/`entity_b_table`
/// (the ordinary reseed/idempotent-retry path, and the "recreate with the
/// SAME endpoints" case — safe to let `CREATE TABLE IF NOT EXISTS` no-op
/// onto, same posture this whole module already takes toward a retired
/// relationship's surviving data). Otherwise — the table exists but its FKs
/// disagree, which only happens when a relationship was retired and then
/// recreated under the same `name` with a different endpoint pair —
/// `Conflict`, never a silent reuse.
async fn verify_join_table_matches_or_absent(
    db: &DbPool,
    join_table: &str,
    entity_a_table: &str,
    entity_b_table: &str,
) -> Result<(), AppError> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(join_table)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !exists {
        return Ok(());
    }

    #[derive(sqlx::FromRow, Debug)]
    struct FkTarget {
        local_column: String,
        target_table: String,
    }

    // One row per single-column foreign key on the table — exactly what the
    // `CREATE TABLE` below declares for `a_id`/`b_id`. `confrelid::regclass::
    // text` renders unqualified as long as the target resolves through the
    // current `search_path`, which every table this module or `table.rs`
    // provisions always does (same assumption `ddl.rs::existing_columns`
    // already relies on via `current_schema()`).
    let fks: Vec<FkTarget> = sqlx::query_as(
        "SELECT a.attname AS local_column, c.confrelid::regclass::text AS target_table \
         FROM pg_constraint c \
         JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey) \
         WHERE c.conrelid = to_regclass($1) AND c.contype = 'f'",
    )
    .bind(join_table)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let a_matches = fks
        .iter()
        .any(|fk| fk.local_column == "a_id" && fk.target_table == entity_a_table);
    let b_matches = fks
        .iter()
        .any(|fk| fk.local_column == "b_id" && fk.target_table == entity_b_table);

    if a_matches && b_matches {
        return Ok(());
    }

    tracing::warn!(
        join_table = %join_table,
        entity_a_table,
        entity_b_table,
        found_fks = ?fks,
        "relationship join table already exists with FK targets that disagree with the \
         desired endpoints — refusing to reuse it"
    );
    Err(AppError::Conflict(
        "join table exists from a retired relationship; drop it explicitly",
    ))
}

/// Permanently drops the physical join table backing a relationship, if it
/// exists. Irreversible, same posture as `table::drop_table` — never called
/// from the ordinary admin retire path (`relationship_admin`'s DELETE
/// handler only soft-retires the `relationship_info` row), only
/// exposed for tests / a future explicit hard-delete admin action.
///
/// C-20: routed through `exec_ddl_locked` — same fix as `table::drop_table`,
/// which this mirrors exactly (a bare pool call had no `lock_timeout`, so
/// this could queue indefinitely behind a conflicting lock instead of
/// retrying/erroring within the module's bounded budget).
pub async fn drop_join_table(db: &DbPool, join_table: &str) -> Result<(), AppError> {
    if join_table.is_empty() || join_table.len() > 63 {
        return Err(AppError::internal(format!(
            "invalid relationship join_table identifier: {join_table}"
        )));
    }

    exec_ddl_locked(
        db,
        &[],
        &format!(r#"DROP TABLE IF EXISTS "{join_table}""#),
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, join_table = %join_table, "relationship join-table DROP failed");
        AppError::internal(e)
    })?;

    Ok(())
}

// ── Declarative reconcile — the one INSERT/UPDATE implementation shared by
// `attome-server`'s admin CRUD and the bundle engine's apply step ─────────────

/// The desired shape of one `relationship_info` row. `entity_a`/
/// `entity_b` must already be DB-trusted, resolved logicalnames (the caller
/// — `relationship_admin::create_relationship` or the bundle apply step —
/// resolves them via `entity_crud::resolve_entity` first, since resolution
/// itself needs `EngineState`, which this crate cannot depend on).
///
/// `name`/`entity_a`/`entity_b` are immutable once a row exists: changing
/// either endpoint would strand the already-provisioned join table's FK
/// targets. A reconcile call whose existing row disagrees on either is
/// refused with `AppError::Validation`, mirroring
/// `reconcile_attribute`'s "type changes are refused" posture (D-055).
///
/// **`name` change = a NEW physical table, C-21 (M01 §7).** There is no
/// in-place rename: `join_table` is derived as `mm_{name}` at create
/// time (see [`reconcile_relationship`]) and never re-derived afterward, so
/// "renaming" a relationship (retiring one `name` and creating another with
/// the same endpoints/roles) provisions an entirely separate `mm_{new
/// name}` table starting empty — the old `mm_{old name}` table and every
/// row in it are stranded, not migrated, exactly like any other retired
/// relationship's join table (`retire_relationship`'s doc comment). If the
/// *old* name is later reused for yet another relationship, that reuse now
/// goes through [`verify_join_table_matches_or_absent`]'s stale-table check
/// like any other recreate.
#[derive(Clone, Debug, PartialEq)]
pub struct RelationshipDesc {
    pub name: String,
    pub entity_a: String,
    pub entity_b: String,
    pub role_a: String,
    pub role_b: String,
    pub cascade: RelationshipCascade,
    pub is_active: bool,
}

#[derive(sqlx::FromRow)]
struct RelationshipInfoRow {
    id: Uuid,
    name: String,
    entity_a: String,
    entity_b: String,
    role_a: String,
    role_b: String,
    join_table: String,
    cascade: String,
    is_customized: bool,
    is_active: bool,
    row_version: i64,
    owner_layer: String,
}

/// The enumerated columns every read and `RETURNING` of this module uses.
const RELATIONSHIP_COLUMNS: &str = "id, name, entity_a, entity_b, role_a, role_b, join_table, \
     cascade, is_customized, is_active, row_version, owner_layer";

/// Mirrors `reconcile_entity`'s contract at a much smaller scale (this
/// object has no physical-schema-evolution concern — the join table's shape
/// never changes after creation): compare first, write only on a real
/// difference, `Seed` never touches a customized row, `Admin`/`Bundle`
/// always apply and stamp `is_customized` per [`ReconcilePolicy::customized_marker`].
///
/// No advisory lock: the partial unique index on `name`
/// (`core_relationship_info_name_idx`) is the correctness backstop for a
/// concurrent create race, same posture `duplicates_admin`'s match-rule/
/// survivorship-rule CRUD already takes (unique-violation -> `Conflict`,
/// no lock needed because there is no multi-statement invariant beyond
/// what the constraint already enforces).
pub async fn reconcile_relationship(
    state: &EngineState,
    desc: &RelationshipDesc,
    policy: ReconcilePolicy,
    created_by: Option<Uuid>,
) -> Result<(RelationshipDetail, ReconcileOutcome), AppError> {
    reconcile_relationship_recorded(state, desc, policy, created_by, None).await
}

/// Solution 7 Phase 1 (design §1.1, §4.4) — [`reconcile_relationship`] that
/// stamps a new row with the recording's layer, refuses (`409
/// layer_mismatch`) to change a row of another layer, and records `rec.op`
/// (`upsert_relationship`) in the metadata transaction that follows the
/// junction-table DDL. `None` is exactly [`reconcile_relationship`].
pub async fn reconcile_relationship_recorded(
    state: &EngineState,
    desc: &RelationshipDesc,
    policy: ReconcilePolicy,
    created_by: Option<Uuid>,
    rec: Option<RecordAs<'_>>,
) -> Result<(RelationshipDetail, ReconcileOutcome), AppError> {
    let db = &state.base.db;
    if !valid_identifier(&desc.name) {
        return Err(AppError::Validation(format!(
            "relationship name '{}' must be lowercase/digits/underscore, max {MAX_IDENTIFIER_LEN} chars",
            desc.name
        )));
    }
    // "mm_" is 7 bytes; keeping join_table <= 48 (not just Postgres's
    // 63-byte NAMEDATALEN-1) leaves room for every other identifier this
    // module derives from it (e.g. a future per-relationship index name)
    // without a second length budget to track.
    if desc.name.len() > MAX_IDENTIFIER_LEN - 7 {
        return Err(AppError::Validation(format!(
            "relationship name '{}' is too long once prefixed with 'mm_' \
             (max {} chars)",
            desc.name,
            MAX_IDENTIFIER_LEN - 7
        )));
    }
    let join_table = format!("mm_{}", desc.name);
    // Refuse (changeset_required, …) before the junction-table DDL.
    changeset::preflight(db, rec).await?;

    let existing: Option<RelationshipInfoRow> = sqlx::query_as(&format!(
        "SELECT {RELATIONSHIP_COLUMNS} \
         FROM relationship_info WHERE name = $1 AND NOT is_deleted"
    ))
    .bind(&desc.name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let Some(existing) = existing else {
        // Provision the physical table BEFORE the metadata row: if this
        // fails, nothing references the (possibly half-created but harmless
        // and idempotently retryable) table yet. If the metadata INSERT
        // below fails instead (e.g. a concurrent create won the unique
        // constraint), the table is a harmless orphan — safe because it is
        // never entity-registered and nothing reads it without a matching
        // metadata row.
        //
        // The DDL runs on the provisioning pool (D-117), the same identity
        // bundle apply's entity and attribute steps use. `db` is the runtime
        // role, which has USAGE but no CREATE on the schema; the metadata
        // statements in this function stay on `db`.
        provision_join_table(
            &state.base.db_migrator,
            &join_table,
            &desc.entity_a,
            &desc.entity_b,
        )
        .await?;

        let layer = changeset::layer_for(policy, rec)?;
        let is_customized = policy.customized_marker().unwrap_or(false);
        let mut tx = attome_db::tx::begin(db).await?;
        let row: RelationshipInfoRow = sqlx::query_as(&format!(
            "INSERT INTO relationship_info \
                 (id, name, entity_a, entity_b, role_a, role_b, join_table, cascade, \
                  is_customized, is_active, row_version, owner_layer) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, $11) \
             RETURNING {RELATIONSHIP_COLUMNS}"
        ))
        .bind(Uuid::now_v7())
        .bind(&desc.name)
        .bind(&desc.entity_a)
        .bind(&desc.entity_b)
        .bind(&desc.role_a)
        .bind(&desc.role_b)
        .bind(&join_table)
        .bind(desc.cascade.as_db_str())
        .bind(is_customized)
        .bind(desc.is_active)
        .bind(layer.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_unique_violation)?;
        let _ = created_by; // reserved for an audit-trail follow-up; not a stored column today
        changeset::record(
            &mut tx,
            rec,
            ObjectKind::Relationship,
            row.id,
            changeset::relationship_target(&row.name),
            Vec::new(),
        )
        .await?;
        tx.commit().await.map_err(AppError::internal)?;

        invalidate(state).await;
        return Ok((row.into(), ReconcileOutcome::Created));
    };

    if existing.entity_a != desc.entity_a || existing.entity_b != desc.entity_b {
        return Err(AppError::Validation(format!(
            "relationship '{}' already exists between ({}, {}); entity_a/entity_b cannot be \
             changed on an existing relationship (delete and recreate under a new name instead)",
            desc.name, existing.entity_a, existing.entity_b
        )));
    }

    if policy == ReconcilePolicy::Seed && existing.is_customized {
        return Ok((existing.into(), ReconcileOutcome::SkippedCustomized));
    }
    changeset::check_owner(rec, &existing.owner_layer)?;

    let desired_customized = policy.customized_marker().unwrap_or(existing.is_customized);
    let mut changed = Vec::new();
    changeset::diff(
        &mut changed,
        "role_a",
        existing.role_a.as_str(),
        desc.role_a.as_str(),
    );
    changeset::diff(
        &mut changed,
        "role_b",
        existing.role_b.as_str(),
        desc.role_b.as_str(),
    );
    changeset::diff(
        &mut changed,
        "cascade",
        existing.cascade.as_str(),
        desc.cascade.as_db_str(),
    );
    changeset::diff(
        &mut changed,
        "is_active",
        &existing.is_active,
        &desc.is_active,
    );
    let unchanged = changed.is_empty() && existing.is_customized == desired_customized;
    if unchanged {
        return Ok((existing.into(), ReconcileOutcome::Unchanged));
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let row: RelationshipInfoRow = sqlx::query_as(&format!(
        "UPDATE relationship_info \
             SET role_a = $2, role_b = $3, cascade = $4, is_active = $5, is_customized = $6, \
                 row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1 \
         RETURNING {RELATIONSHIP_COLUMNS}"
    ))
    .bind(existing.id)
    .bind(&desc.role_a)
    .bind(&desc.role_b)
    .bind(desc.cascade.as_db_str())
    .bind(desc.is_active)
    .bind(desired_customized)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    changeset::record(
        &mut tx,
        rec,
        ObjectKind::Relationship,
        row.id,
        changeset::relationship_target(&row.name),
        changed,
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    invalidate(state).await;
    Ok((row.into(), ReconcileOutcome::Updated))
}

/// Soft-retires a relationship definition by id — never drops the physical
/// join table (irreversible; use [`drop_join_table`] explicitly if that is
/// ever really wanted). `Ok(false)` when no live row matched. Used by
/// `relationship_admin`'s `DELETE /api/v1/admin/relationships/{id}` (the
/// admin route is id-keyed, matching every other `/admin/*/{id}` route in
/// this platform).
pub async fn retire_relationship(state: &EngineState, id: Uuid) -> Result<bool, AppError> {
    retire_relationship_recorded(state, id, None).await
}

/// [`retire_relationship`] with the Solution 7 owner check and recording
/// (`rec.op` is normally `retire_relationship`).
pub async fn retire_relationship_recorded(
    state: &EngineState,
    id: Uuid,
    rec: Option<RecordAs<'_>>,
) -> Result<bool, AppError> {
    retire_where(state, RetireKey::Id(id), rec).await
}

/// Same retire, keyed by `name` instead of `id` — what the bundle engine's
/// apply step needs, since a bundle's `Diff`/`PlannedStep` addresses every
/// component by its logical key (mirrors `attome_state::reconcile::retire_state_model`'s
/// exact shape, including the `ReconcileOutcome` contract:
/// `Unchanged` for "nothing live matched this key", `Updated` for a real
/// retire).
pub async fn retire_relationship_by_name(
    state: &EngineState,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    retire_relationship_by_name_recorded(state, name, None).await
}

/// [`retire_relationship_by_name`] with the Solution 7 owner check and
/// recording.
pub async fn retire_relationship_by_name_recorded(
    state: &EngineState,
    name: &str,
    rec: Option<RecordAs<'_>>,
) -> Result<ReconcileOutcome, AppError> {
    Ok(if retire_where(state, RetireKey::Name(name), rec).await? {
        ReconcileOutcome::Updated
    } else {
        ReconcileOutcome::Unchanged
    })
}

enum RetireKey<'a> {
    Id(Uuid),
    Name(&'a str),
}

/// The one retire implementation: lock the live row, check its owner, flip
/// it, record, commit. `Ok(false)` when no live row matched.
async fn retire_where(
    state: &EngineState,
    key: RetireKey<'_>,
    rec: Option<RecordAs<'_>>,
) -> Result<bool, AppError> {
    let db = &state.base.db;
    changeset::preflight(db, rec).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    let live: Option<(Uuid, String, String)> = match key {
        RetireKey::Id(id) => {
            sqlx::query_as(
                "SELECT id, name, owner_layer FROM relationship_info \
             WHERE id = $1 AND NOT is_deleted FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
        }
        RetireKey::Name(name) => {
            sqlx::query_as(
                "SELECT id, name, owner_layer FROM relationship_info \
             WHERE name = $1 AND NOT is_deleted FOR UPDATE",
            )
            .bind(name)
            .fetch_optional(&mut *tx)
            .await
        }
    }
    .map_err(AppError::internal)?;
    let Some((id, name, owner_layer)) = live else {
        return Ok(false);
    };
    changeset::check_owner(rec, &owner_layer)?;
    let n = sqlx::query(
        "UPDATE relationship_info \
             SET is_deleted = TRUE, is_active = FALSE, row_version = row_version + 1, \
                 updated_at = NOW() \
         WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(false);
    }
    changeset::record(
        &mut tx,
        rec,
        ObjectKind::Relationship,
        id,
        changeset::relationship_target(&name),
        vec!["is_active"],
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    invalidate(state).await;
    Ok(true)
}

fn map_unique_violation(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("a concurrent write created a relationship with this name first; retry")
    } else {
        AppError::internal(error)
    }
}

/// The reconcile/admin-facing view of one row — deliberately a separate type
/// from the arc-swap registry's `RelationshipDef` (which carries a typed
/// `RelationshipCascade` and is optimized for the record-link hot path, not
/// for round-tripping through `sqlx::FromRow`/serialization).
#[derive(Clone, Debug, PartialEq)]
pub struct RelationshipDetail {
    pub id: Uuid,
    pub name: String,
    pub entity_a: String,
    pub entity_b: String,
    pub role_a: String,
    pub role_b: String,
    pub join_table: String,
    pub cascade: RelationshipCascade,
    pub is_customized: bool,
    pub is_active: bool,
    pub row_version: i64,
    /// Solution 7 (D-785): `platform | product | project | customer`.
    pub owner_layer: String,
}

impl From<RelationshipInfoRow> for RelationshipDetail {
    fn from(r: RelationshipInfoRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            entity_a: r.entity_a,
            entity_b: r.entity_b,
            role_a: r.role_a,
            role_b: r.role_b,
            join_table: r.join_table,
            cascade: RelationshipCascade::from_db_str(&r.cascade),
            is_customized: r.is_customized,
            is_active: r.is_active,
            row_version: r.row_version,
            owner_layer: r.owner_layer,
        }
    }
}

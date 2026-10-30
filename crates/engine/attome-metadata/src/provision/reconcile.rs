//! Declarative "make this object match this description" primitives for
//! entity and attribute metadata (P-environment-promotion §4 "Reuse the
//! provisioning primitives, and finish them" / §5 steps 13, 18, 19).
//!
//! `ensure_entity`/`ensure_attribute` (`attribute.rs`) used to be create-only:
//! their `ON CONFLICT … DO UPDATE SET logicalname = EXCLUDED.logicalname` was
//! a deliberate no-op, so a seed could register a row once and never correct
//! it afterwards. The `reconcile_*` family below is the missing update half,
//! and the `ensure_*` functions are now thin wrappers over it with
//! [`ReconcilePolicy::Seed`]. There is exactly one implementation of the
//! INSERT/UPDATE/DDL path, shared by the boot seeds, the admin API
//! (`attome-server/src/admin/{entity,attribute}.rs`) and the bundle engine.
//!
//! ## Contract (shared with every caller — do not change shapes casually)
//!
//! * **Compare first, lock only on a difference.** Every call probes the
//!   current row on the pool, diffs it against the description and returns
//!   [`ReconcileOutcome::Unchanged`] with *no transaction, no advisory lock
//!   and no write* when nothing differs. That is what keeps the steady-state
//!   boot reseed (every boot, every entity already registered) lock-free —
//!   the same "probe before `begin()`" hot path `ensure_entity` always had,
//!   now covering the whole row instead of only existence. The probe is
//!   racy by design (two nodes can both decide to write); the write path
//!   then serializes on the global metadata-write lock and the loser gets
//!   `Conflict`, exactly as before.
//! * **Ownership is per property (Y11-T4, `property_layer`).** Every write
//!   records the properties it sets under its layer. Under `Seed`, a live row
//!   takes the seed's value for every property no app or customer row holds
//!   and keeps the others (a customised one with no layer rows yet is
//!   backfilled first); a retired customised row is never written — the call logs the skip at `info` with
//!   the row's key and returns [`ReconcileOutcome::SkippedCustomized`]. A seed
//!   never sets `is_customized`. `Admin` sets it `true`; `Bundle` sets it to
//!   the value the bundle carries. For `Admin`/`Bundle` the marker is part of
//!   the diff, so an admin write that changes nothing else still marks the
//!   row as customized ("any admin write that touches the row").
//! * **`None` semantics.** Under `Seed`, an `Option` field that is `None`
//!   means *"this seed does not manage that column — leave whatever is there
//!   alone"* (on create, the column's default / NULL). `max_length`,
//!   `on_target_delete`, `data_classification`, `purpose`, `options`,
//!   `lookup_entity`, `primary_name_attribute` and `category` all behave this
//!   way, because no
//!   seed has ever set them and a reconciling boot must not start *clearing*
//!   values an admin set before `is_customized` existed (D-366's recorded
//!   consequence for `max_length`). Under `Admin`/`Bundle` the description is
//!   the exact desired state: `None` means NULL (or the column's NOT NULL
//!   default — `'orphan'` / `'general'`).
//! * **Physical schema.** Under `Seed`, `is_required`/`max_length` are
//!   metadata-only, exactly as today's seeds (no seed has ever installed a
//!   NOT NULL or CHECK constraint; the application layer enforces both on
//!   every write path). Under `Admin`/`Bundle` a change to either runs
//!   through `classify_schema_change`: `Cheap` applies inline via
//!   `evolve_attribute_schema` *before* the metadata transaction (so a failed
//!   validation leaves the prior contract visible), `Expensive` returns
//!   `Err(AppError::Conflict("schema change requires async plan"))` and
//!   writes nothing — the caller queues the durable plan itself (the admin
//!   PATCH already does; the bundle engine will). Index synchronization for
//!   `is_sortable`/`is_filterable` stays the caller's responsibility, as it
//!   always was for `ensure_*`.
//! * **Type changes are refused** with `AppError::Validation` naming
//!   `entity.field` and both types (D-055 — surface, never cast). The one
//!   softening is for `Seed`: a boot seed whose declared type has drifted
//!   from the row it registered logs a `warn` and leaves the row untouched
//!   (`Unchanged`) instead of failing the boot — the old create-only seed
//!   ignored such drift silently, and an upgrade must not turn that into an
//!   outage. `Admin`/`Bundle` always get the hard refusal.
//! * **Retire is `is_active = false`, never a drop.** The physical column /
//!   table is kept (D-055 has no column drop). `retire_entity` flips only
//!   the entity row: the registry already ignores attributes of an inactive
//!   entity (`fetch_entity_snapshots`), and leaving the attribute rows alone
//!   is what makes `reactivate_entity` lossless.
//! * **Reactivate over insert.** The unique indexes on `logicalname` /
//!   `(entity_ref, logicalname)` are partial (`WHERE is_active IS NULL OR
//!   is_active = true`), so a retired row does not *collide* with a fresh
//!   INSERT — but a second row under the same key would orphan every
//!   reference to the first (views and queries by entity uuid,
//!   `lookup_entity_ref` FKs, role entity access) and would describe a
//!   physical column/table that already exists with the first row's type.
//!   `reconcile_*` therefore reactivates the most recently created inactive
//!   row with the same key (and brings it up to the description) instead of
//!   inserting a second one. The visible consequence: re-creating an entity
//!   or field that was soft-deleted with a *different* type is refused as a
//!   type change, where it used to silently create a metadata row disagreeing
//!   with the physical column.
//! * **Every actual write** is one short transaction: global metadata-write
//!   lock first, then the per-object provisioning lock, the INSERT/UPDATE,
//!   and `append_change_log` as the last statement before commit
//!   (`ChangeKind::Upsert`, or `Delete` for `retire_entity`). `rows_affected`
//!   is checked. Nothing here notifies — the caller decides (boot seeds do
//!   not; bundle apply fires one doorbell at the end; admin handlers already
//!   notify).

use std::collections::BTreeSet;

use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use super::changeset::{self, ObjectKind, RecordAs};
use super::identifiers::{
    is_multi_valued, physical_field_type, type_to_int, valid_field_type, valid_identifier,
};
use super::property_layer;
use super::schema_change::{ChangeClassification, classify_schema_change, evolve_attribute_schema};
use super::table::{provision_column, provision_table};
use attome_core::changeset::Op;

/// Size gate for the inline `evolve_attribute_schema` path under `Admin`/
/// `Bundle`. The single source of truth for this value — `attome-server/src/
/// admin/attribute.rs` imports it (C-20) rather than keeping its own copy;
/// `attome-metadata` sits below `attome-server` in the dependency graph, so the
/// import can only run in this direction, never the reverse.
pub const RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT: i64 = 10_000;

/// A unique-key violation (SQLSTATE 23505) from a reconcile `Create` INSERT
/// is a conflict, not an internal fault — same classification
/// `attome_security::reconcile`'s own `map_unique_violation` gives the
/// equivalent race on role/privilege/profile rows. For entity/attribute
/// creation specifically, the natural-key race is already absorbed by the
/// `ON CONFLICT … DO UPDATE` no-op above; the only remaining source of a
/// 23505 on this exact statement is an explicit `desired_id` colliding with
/// an unrelated existing row's primary key — vanishingly unlikely for a
/// UUIDv5 derived id, but must surface as `Conflict`, not `Internal`, if it
/// ever happens.
fn map_unique_violation(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("a row with this id already exists")
    } else {
        AppError::internal(error)
    }
}

// ARCH-1a-i — `ReconcilePolicy`/`ReconcileOutcome` now live in
// `attome-core` so `attome-security` can name them without depending on this
// crate. Re-exported here so every existing `attome_metadata::provision::Reconcile*`
// path is unchanged.
pub use attome_core::reconcile::{ReconcileOutcome, ReconcilePolicy};
// C-19: `WriteStep`/`RowStatus`/`decide_step` used to be declared here
// (`pub(super)`, unit-tested by `super::tests`) — now one shared
// implementation in `attome_core::reconcile`, re-exported under the same
// names/visibility so nothing else in this module or `provision::mod`'s
// `#[cfg(test)] use reconcile::{...}` has to change.
pub(super) use attome_core::reconcile::{RowStatus, WriteStep, decide_step};

#[derive(Clone, Debug, PartialEq)]
pub struct EntityDesc {
    pub logicalname: String,
    pub display_name: String,
    pub primary_name_attribute: Option<String>,
    pub is_append_only: bool,
    pub is_audited: bool,
    pub category: Option<String>,
    /// A1-T6: how a new entity's table is stored. Applies when the entity is
    /// created; asking for `HighVolume` on an existing standard entity is
    /// refused (no conversion in place), and `Standard` leaves an existing
    /// entity's mode as it is.
    pub storage_mode: super::storage::StorageMode,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AttributeDesc {
    pub logicalname: String,
    pub display_name: String,
    /// Same string vocabulary `ensure_attribute` accepts ("text", "lookup", ...).
    pub field_type: String,
    pub is_required: bool,
    pub is_sensitive: bool,
    /// D-507: writes need a field-security `can_update` grant while the value
    /// stays readable. `Option` for the same `managed_value` reason as
    /// `data_classification`: `None` under `Seed` leaves an admin's setting
    /// alone (boot seeds never manage it); under `Admin`/`Bundle`, `None`
    /// means `false`.
    pub is_write_restricted: Option<bool>,
    pub is_sortable: bool,
    pub is_filterable: bool,
    /// Target entity LOGICALNAME (resolved to uuid inside).
    pub lookup_entity: Option<String>,
    pub options: Option<serde_json::Value>,
    pub max_length: Option<i32>,
    pub on_target_delete: Option<String>,
    pub data_classification: Option<String>,
    /// Developer-facing note on why this field exists — locale-less, never
    /// shown to end users (distinct from `metadata_label.description`,
    /// D-426's per-locale presentation string). `None` under `Seed` leaves the
    /// column alone, same `managed_value` semantics as `on_target_delete`/
    /// `data_classification`.
    pub purpose: Option<String>,
}

// ── Pure decision helpers (unit-tested in `super::tests`) ────────────────────
//
// `WriteStep`/`RowStatus`/`decide_step` come from `attome_core::reconcile`
// now (re-exported above, C-19) — this module only adds `managed_value`,
// which has no counterpart in `attome-security`/`query_admin.rs`.

/// `Seed` + `None` = "leave as is" (or the default on create); any other
/// combination is the exact desired value. See the module docs.
pub(super) fn managed_value<T: Clone>(
    policy: ReconcilePolicy,
    wanted: Option<T>,
    current: Option<T>,
) -> Option<T> {
    match (policy, wanted) {
        (ReconcilePolicy::Seed, None) => current,
        (_, wanted) => wanted,
    }
}

/// Canonical string for a stored `attribute_info."type"` — C-16 (M01
/// §7): the map itself lives once on `attome_core::FieldType`; this is
/// just the `&str` adapter this module's callers (below the server layer)
/// still need.
fn int_to_type(t: i32) -> &'static str {
    attome_core::FieldType::from_int(t)
        .unwrap_or(attome_core::FieldType::Text)
        .as_str()
}

fn valid_on_target_delete(s: &str) -> bool {
    matches!(s, "restrict" | "orphan" | "cascade-deactivate")
}

fn valid_data_classification(s: &str) -> bool {
    matches!(s, "general" | "personal" | "sensitive_special_category")
}

// ── Entity ───────────────────────────────────────────────────────────────────

/// The managed columns of an `entity_info` row — what the diff
/// compares and what the UPDATE writes. Its fields are the property names
/// `metadata_property_layer` records (Y11-T4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct EntityState {
    name: String,
    primary_name_attribute: Option<String>,
    is_append_only: bool,
    is_audited: bool,
    category: Option<String>,
}

#[derive(sqlx::FromRow)]
struct EntityRow {
    id: Uuid,
    /// A1-T6: `standard` or `high_volume`.
    storage_mode: String,
    name: String,
    primary_name_attribute: Option<String>,
    is_append_only: bool,
    is_audited: bool,
    category: Option<String>,
    is_customized: bool,
    is_live: bool,
    owner_layer: String,
}

/// The properties a write changes, for the changeset review summary. A new
/// row (or a retired one brought back) changes nothing in particular.
fn entity_changes(current: Option<&EntityRow>, desired: &EntityState) -> Vec<&'static str> {
    let Some(row) = current.filter(|r| r.is_live) else {
        return Vec::new();
    };
    let mut changed = Vec::new();
    changeset::diff(&mut changed, "name", &row.name, &desired.name);
    changeset::diff(
        &mut changed,
        "primary_name_attribute",
        &row.primary_name_attribute,
        &desired.primary_name_attribute,
    );
    changeset::diff(
        &mut changed,
        "is_append_only",
        &row.is_append_only,
        &desired.is_append_only,
    );
    changeset::diff(
        &mut changed,
        "is_audited",
        &row.is_audited,
        &desired.is_audited,
    );
    changeset::diff(&mut changed, "category", &row.category, &desired.category);
    changed
}

/// The state a stored entity row has.
fn entity_state_of(row: &EntityRow) -> EntityState {
    EntityState {
        name: row.name.clone(),
        primary_name_attribute: row.primary_name_attribute.clone(),
        is_append_only: row.is_append_only,
        is_audited: row.is_audited,
        category: row.category.clone(),
    }
}

/// Y11-T4: the entity properties a seed's description sets (an `Option`
/// left `None` is one the seed does not manage).
fn entity_seed_managed(desc: &EntityDesc) -> BTreeSet<&'static str> {
    let mut managed: BTreeSet<&'static str> = ["name", "is_append_only", "is_audited"].into();
    if desc.primary_name_attribute.is_some() {
        managed.insert("primary_name_attribute");
    }
    if desc.category.is_some() {
        managed.insert("category");
    }
    managed
}

/// Y11-T4: the properties a write records, under its layer: a seed's
/// managed ones, or what an admin or bundle write sets (everything on a
/// create or a reactivation).
fn layer_values<T: Serialize>(
    policy: ReconcilePolicy,
    seed_managed: &BTreeSet<&str>,
    live_before: Option<&T>,
    desired: &T,
) -> Result<Map<String, Value>, AppError> {
    let after = property_layer::to_map(desired)?;
    Ok(match policy {
        ReconcilePolicy::Seed => property_layer::only(&after, seed_managed),
        _ => {
            let before = live_before.map(property_layer::to_map).transpose()?;
            property_layer::changed(before.as_ref(), &after)
        }
    })
}

/// Y11-T4: whether a seed works on a row property by property (a live
/// row) rather than skipping it when it is customised (a retired one).
fn seed_per_property(policy: ReconcilePolicy, is_live: bool) -> bool {
    policy == ReconcilePolicy::Seed && is_live
}

/// Prefers the live row; otherwise the most recently created retired one
/// (there can be several — the unique index is partial on `is_active`).
async fn fetch_entity_row(db: &DbPool, logicalname: &str) -> Result<Option<EntityRow>, AppError> {
    sqlx::query_as(
        "SELECT id, COALESCE(storage_mode::text, 'standard') AS storage_mode, \
                COALESCE(name, '') AS name, primary_name_attribute, \
                COALESCE(is_append_only, false) AS is_append_only, \
                COALESCE(is_audited, false) AS is_audited, category, is_customized, \
                (is_active IS NULL OR is_active = true) AS is_live, owner_layer \
         FROM entity_info WHERE logicalname = $1 \
         ORDER BY (is_active IS NULL OR is_active = true) DESC, \
                  created_at DESC NULLS LAST, id DESC \
         LIMIT 1",
    )
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Create-or-update the entity row + physical table. Returns (entity_id, outcome).
/// Type-incompatible changes are impossible here (entities have no type); logicalname is the key.
///
/// `provision_table` runs on every call, whatever the outcome — it is the
/// self-healing physical half (`row_version`/`modified_at`/… backfills, storage
/// parameters, the readonly grant) and has always run on every boot; its own
/// catalog pre-checks make the steady state cheap. It is not a metadata
/// write and takes no metadata lock — and for `Create`/`Update` it now
/// always runs BEFORE the metadata transaction below even begins (C-20):
/// it opens its own pool connections for its ~12 `exec_ddl_locked`
/// transactions and two `CREATE INDEX CONCURRENTLY` calls, so running it
/// while the metadata tx holds a connection self-deadlocks a small pool.
pub async fn reconcile_entity(
    db: &DbPool,
    desc: &EntityDesc,
    policy: ReconcilePolicy,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    reconcile_entity_with_id(db, desc, policy, None).await
}

/// Same as [`reconcile_entity`], but on [`WriteStep::Create`] binds
/// `desired_id` verbatim instead of leaving `id` to the column default — the
/// bundle engine's deterministic-id path (D-374 amendment): the same bundle
/// then produces the same entity id on every fresh deployment it's applied
/// to. `None` reproduces `reconcile_entity`'s random-id behavior exactly;
/// ignored on `Update` (an existing row's id never changes).
pub async fn reconcile_entity_with_id(
    db: &DbPool,
    desc: &EntityDesc,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    reconcile_entity_recorded(db, desc, policy, desired_id, None).await
}

/// Solution 7 Phase 1 (design §4.4) — [`reconcile_entity_with_id`] that
/// stamps a new row with the recording's layer, refuses (`409
/// layer_mismatch`, before any DDL) to touch an existing row of another
/// layer, and records `rec.op` in the final lock + change-log transaction.
/// `None` is exactly [`reconcile_entity_with_id`] (new rows stamped by
/// policy: `Seed` → `platform`, otherwise `project`).
pub async fn reconcile_entity_recorded(
    db: &DbPool,
    desc: &EntityDesc,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
    rec: Option<RecordAs<'_>>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let logicalname = desc.logicalname.as_str();
    if !valid_identifier(logicalname) {
        return Err(AppError::Validation(format!(
            "invalid entity logicalname (lowercase/digits/underscore, max {} chars): {logicalname}",
            super::identifiers::MAX_IDENTIFIER_LEN
        )));
    }
    changeset::preflight(db, rec).await?;

    let current = fetch_entity_row(db, logicalname).await?;
    if let Some(row) = current.as_ref() {
        changeset::check_owner(rec, &row.owner_layer)?;
    }
    // A1-T6: an existing entity keeps its storage; a new one takes the
    // description's.
    let mode = match current.as_ref() {
        Some(row) => {
            let stored = super::storage::StorageMode::parse(&row.storage_mode).unwrap_or_default();
            if desc.storage_mode.is_high_volume() && stored != desc.storage_mode {
                return Err(AppError::Validation(format!(
                    "{logicalname} already exists as a {} entity; its storage cannot change in place",
                    stored.as_str()
                )));
            }
            stored
        }
        None => desc.storage_mode,
    };
    let layer = changeset::layer_for(policy, rec)?;
    let mut desired = EntityState {
        name: desc.display_name.clone(),
        primary_name_attribute: managed_value(
            policy,
            desc.primary_name_attribute.clone(),
            current
                .as_ref()
                .and_then(|r| r.primary_name_attribute.clone()),
        ),
        is_append_only: desc.is_append_only,
        is_audited: desc.is_audited,
        category: managed_value(
            policy,
            desc.category.clone(),
            current.as_ref().and_then(|r| r.category.clone()),
        ),
    };
    let seed_managed = entity_seed_managed(desc);
    // Y11-T4: what the seed alone would set, before what other layers hold
    // is kept; its managed properties are the platform's layer rows.
    let seed_desired = desired.clone();
    // Only when the seed would change the row, so a steady-state boot reads
    // nothing more.
    if let Some(row) = current.as_ref()
        && seed_per_property(policy, row.is_live)
        && entity_state_of(row) != desired
    {
        let before = property_layer::to_map(&entity_state_of(row))?;
        let seed = property_layer::to_map(&desired)?;
        let kept = property_layer::seed_keeps(
            db,
            property_layer::ENTITY,
            logicalname,
            &before,
            &seed,
            &seed_managed,
            row.is_customized,
        )
        .await?;
        desired = property_layer::from_map(property_layer::keep(&seed, &before, &kept))?;
    }
    let state_differs = current
        .as_ref()
        .is_some_and(|r| entity_state_of(r) != desired);
    let status = current.as_ref().map(|r| RowStatus {
        is_customized: r.is_customized && !seed_per_property(policy, r.is_live),
        is_live: r.is_live,
    });
    let entity_layer_values = layer_values(
        policy,
        &seed_managed,
        current
            .as_ref()
            .filter(|r| r.is_live)
            .map(entity_state_of)
            .as_ref(),
        if policy == ReconcilePolicy::Seed {
            &seed_desired
        } else {
            &desired
        },
    )?;

    match decide_step(policy, status, state_differs) {
        WriteStep::Unchanged => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            provision_table(db, logicalname, desc.is_append_only, mode).await?;
            Ok((id, ReconcileOutcome::Unchanged))
        }
        WriteStep::SkippedCustomized => {
            let row = current.as_ref().ok_or(AppError::NotFound)?;
            tracing::info!(
                entity = %logicalname,
                "provision: seed skipped a customized entity row (is_customized = true)"
            );
            provision_table(db, logicalname, row.is_append_only, mode).await?;
            Ok((row.id, ReconcileOutcome::SkippedCustomized))
        }
        step @ (WriteStep::Create | WriteStep::Update) => {
            // C-20: run the physical half BEFORE `begin()`, exactly like the
            // `Unchanged`/`SkippedCustomized` branches above already do.
            // `provision_table` is idempotent/self-healing and needs nothing
            // from the metadata row (only `logicalname` and
            // `is_append_only`, both known from the description already) —
            // it used to run *inside* the transaction below, between the
            // lock acquisition and `commit()`, where its own ~12
            // `exec_ddl_locked` transactions and `CREATE INDEX
            // CONCURRENTLY` calls each check out a SEPARATE pool
            // connection while `tx`'s connection sits held-but-idle. On a
            // small pool that self-deadlocks (or times out) instead of
            // completing. Running it here means a DDL failure never begins
            // the metadata transaction at all, and the transaction below
            // never holds the global metadata-write lock across any
            // provisioning DDL — it is now lock → UPDATE/INSERT →
            // change-log → commit, nothing else.
            provision_table(db, logicalname, desired.is_append_only, mode).await?;

            let mut tx = attome_db::tx::begin(db).await?;
            // Global metadata-write lock BEFORE the per-entity lock, and before
            // any write — `append_change_log`'s ordering invariant is that log
            // ids are assigned and committed under this lock, so id order
            // matches commit order and a watermarking subscriber can't skip a
            // late-committing row. No other caller acquires these two locks
            // in the opposite order, so there is no cycle to deadlock on.
            attome_core::acquire_metadata_write_lock(&mut tx).await?;
            let locked: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
                    .bind(crate::ADVISORY_LOCK_NAMESPACE)
                    .bind(format!("attome-metadata/provision-entity:{logicalname}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            if !locked {
                return Err(AppError::Conflict(
                    "entity provisioning already in progress",
                ));
            }

            let id = match (step, current.as_ref()) {
                (WriteStep::Update, Some(row)) => {
                    let n = sqlx::query(
                        "UPDATE entity_info \
                         SET name = $2, primary_name_attribute = $3, is_append_only = $4, \
                             is_audited = $5, category = $6, \
                             is_customized = COALESCE($7, is_customized), \
                             is_active = true, modified_at = NOW() \
                         WHERE id = $1",
                    )
                    .bind(row.id)
                    .bind(&desired.name)
                    .bind(&desired.primary_name_attribute)
                    .bind(desired.is_append_only)
                    .bind(desired.is_audited)
                    .bind(&desired.category)
                    .bind(policy.customized_marker())
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?
                    .rows_affected();
                    if n != 1 {
                        return Err(AppError::Conflict("entity row vanished during reconcile"));
                    }
                    row.id
                }
                _ => {
                    // Racing two nodes here is harmless — the upsert is the
                    // authority, and the loser lands on the winner's row
                    // (the no-op DO UPDATE exists only to make RETURNING
                    // yield it) and appends one redundant `Upsert` log row,
                    // which `apply_change_log` resolves by re-fetching the
                    // entity (idempotent by construction).
                    sqlx::query_scalar::<_, Uuid>(
                        "INSERT INTO entity_info \
                             (id, logicalname, name, primary_name_attribute, is_active, \
                              is_append_only, is_audited, category, is_customized, created_at, \
                              owner_layer, storage_mode) \
                         VALUES ($1, $2, $3, $4, true, $5, $6, $7, $8, NOW(), $9, $10) \
                         ON CONFLICT (logicalname) WHERE (is_active IS NULL OR is_active = true) \
                         DO UPDATE SET logicalname = EXCLUDED.logicalname \
                         RETURNING id",
                    )
                    .bind(desired_id.unwrap_or_else(Uuid::now_v7))
                    .bind(logicalname)
                    .bind(&desired.name)
                    .bind(&desired.primary_name_attribute)
                    .bind(desired.is_append_only)
                    .bind(desired.is_audited)
                    .bind(&desired.category)
                    .bind(policy.customized_marker().unwrap_or(false))
                    .bind(layer.as_str())
                    .bind(mode.as_str())
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(map_unique_violation)?
                }
            };

            property_layer::record_in_tx(
                &mut tx,
                property_layer::ENTITY,
                logicalname,
                layer,
                &entity_layer_values,
            )
            .await?;
            // `provision_table` already ran above, before `begin()`.
            // The log row and the metadata write it describes are atomic
            // (append_change_log's own contract); the changeset operation,
            // when one is recorded, is the very last statement (§4.2).
            attome_core::append_change_log(
                &mut tx,
                id,
                logicalname,
                attome_core::ChangeKind::Upsert,
            )
            .await?;
            changeset::record(
                &mut tx,
                rec,
                ObjectKind::Entity,
                id,
                changeset::entity_target(logicalname),
                entity_changes(current.as_ref(), &desired),
            )
            .await?;
            tx.commit().await.map_err(AppError::internal)?;

            let outcome = match step {
                WriteStep::Create => ReconcileOutcome::Created,
                _ => ReconcileOutcome::Updated,
            };
            tracing::info!(entity = %logicalname, ?outcome, ?policy, "provision: reconciled entity");
            Ok((id, outcome))
        }
    }
}

// ── Attribute ────────────────────────────────────────────────────────────────

/// The managed columns of an `attribute_info` row (everything the
/// admin UPDATE writes, plus `is_sensitive`). `"type"` is deliberately absent:
/// it is compared separately and never rewritten. Its fields are the
/// property names `metadata_property_layer` records (Y11-T4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct AttributeState {
    name: String,
    required: bool,
    is_sensitive: bool,
    is_write_restricted: bool,
    is_sortable: bool,
    is_filterable: bool,
    max_length: Option<i32>,
    lookup_entity_ref: Option<Uuid>,
    options: Option<serde_json::Value>,
    on_target_delete: String,
    data_classification: String,
    purpose: Option<String>,
}

impl AttributeState {
    /// The state the description asks for, resolved against the current row
    /// under the policy's `None` semantics (see the module contract).
    fn desired(
        desc: &AttributeDesc,
        lookup_entity_ref: Option<Uuid>,
        current: Option<&AttributeRow>,
        policy: ReconcilePolicy,
    ) -> Self {
        Self {
            name: desc.display_name.clone(),
            required: desc.is_required,
            is_sensitive: desc.is_sensitive,
            is_write_restricted: managed_value(
                policy,
                desc.is_write_restricted,
                current.map(|r| r.is_write_restricted),
            )
            .unwrap_or(false),
            is_sortable: desc.is_sortable,
            is_filterable: desc.is_filterable,
            max_length: managed_value(policy, desc.max_length, current.and_then(|r| r.max_length)),
            lookup_entity_ref: managed_value(
                policy,
                lookup_entity_ref,
                current.and_then(|r| r.lookup_entity_ref),
            ),
            options: managed_value(
                policy,
                desc.options.clone(),
                current.and_then(|r| r.options.clone()),
            ),
            on_target_delete: managed_value(
                policy,
                desc.on_target_delete.clone(),
                current.map(|r| r.on_target_delete.clone()),
            )
            .unwrap_or_else(|| "orphan".to_owned()),
            data_classification: managed_value(
                policy,
                desc.data_classification.clone(),
                current.map(|r| r.data_classification.clone()),
            )
            .unwrap_or_else(|| "general".to_owned()),
            purpose: managed_value(
                policy,
                desc.purpose.clone(),
                current.and_then(|r| r.purpose.clone()),
            ),
        }
    }

    /// The state a stored row currently has, for the compare-first diff.
    fn from_row(row: &AttributeRow) -> Self {
        Self {
            name: row.name.clone(),
            required: row.required,
            is_sensitive: row.is_sensitive,
            is_write_restricted: row.is_write_restricted,
            is_sortable: row.is_sortable,
            is_filterable: row.is_filterable,
            max_length: row.max_length,
            lookup_entity_ref: row.lookup_entity_ref,
            options: row.options.clone(),
            on_target_delete: row.on_target_delete.clone(),
            data_classification: row.data_classification.clone(),
            purpose: row.purpose.clone(),
        }
    }
}

/// Y11-T4: the attribute properties a seed's description sets (an
/// `Option` left `None` is one the seed does not manage).
fn attribute_seed_managed(
    desc: &AttributeDesc,
    lookup_entity_ref: Option<Uuid>,
) -> BTreeSet<&'static str> {
    let mut managed: BTreeSet<&'static str> = [
        "name",
        "required",
        "is_sensitive",
        "is_sortable",
        "is_filterable",
    ]
    .into();
    for (property, set) in [
        ("is_write_restricted", desc.is_write_restricted.is_some()),
        ("max_length", desc.max_length.is_some()),
        ("lookup_entity_ref", lookup_entity_ref.is_some()),
        ("options", desc.options.is_some()),
        ("on_target_delete", desc.on_target_delete.is_some()),
        ("data_classification", desc.data_classification.is_some()),
        ("purpose", desc.purpose.is_some()),
    ] {
        if set {
            managed.insert(property);
        }
    }
    managed
}

#[derive(sqlx::FromRow)]
struct AttributeRow {
    id: Uuid,
    name: String,
    field_type_int: i32,
    required: bool,
    is_sensitive: bool,
    is_write_restricted: bool,
    is_sortable: bool,
    is_filterable: bool,
    max_length: Option<i32>,
    lookup_entity_ref: Option<Uuid>,
    options: Option<serde_json::Value>,
    on_target_delete: String,
    data_classification: String,
    purpose: Option<String>,
    is_customized: bool,
    is_live: bool,
    owner_layer: String,
}

async fn fetch_attribute_row(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
) -> Result<Option<AttributeRow>, AppError> {
    sqlx::query_as(
        r#"SELECT id, COALESCE(name, '') AS name, COALESCE("type", 3) AS field_type_int,
                  COALESCE(required, false) AS required,
                  COALESCE(is_sensitive, false) AS is_sensitive,
                  COALESCE(is_write_restricted, false) AS is_write_restricted,
                  COALESCE(is_sortable, false) AS is_sortable,
                  COALESCE(is_filterable, false) AS is_filterable,
                  max_length, lookup_entity_ref, options,
                  COALESCE(on_target_delete, 'orphan') AS on_target_delete,
                  COALESCE(data_classification, 'general') AS data_classification,
                  purpose,
                  is_customized,
                  (is_active IS NULL OR is_active = true) AS is_live,
                  owner_layer
           FROM attribute_info
           WHERE entity_ref = $1 AND logicalname = $2
           ORDER BY (is_active IS NULL OR is_active = true) DESC,
                    created_at DESC NULLS LAST, id DESC
           LIMIT 1"#,
    )
    .bind(entity_id)
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Resolves a lookup target logicalname to the live entity's id.
async fn resolve_lookup_target(db: &DbPool, logicalname: &str) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| AppError::Validation(format!("lookup target {logicalname} not found")))
}

/// Create-or-update one attribute. A field TYPE change is refused with AppError::Validation naming the
/// field (D-055 — surface, never cast). max_length/required changes go through the existing
/// classify_schema_change size gate: if Expensive, return Err(AppError::Conflict("schema change requires
/// async plan")) — callers (admin PATCH already does; the bundle engine will) queue the plan themselves.
pub async fn reconcile_attribute(
    db: &DbPool,
    entity_id: Uuid,
    desc: &AttributeDesc,
    policy: ReconcilePolicy,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    reconcile_attribute_with_id(db, entity_id, desc, policy, None).await
}

/// Same as [`reconcile_attribute`], but on [`WriteStep::Create`] binds
/// `desired_id` verbatim instead of leaving `id` to the column default — see
/// [`reconcile_entity_with_id`]'s doc comment for why. `None` reproduces
/// [`reconcile_attribute`]'s random-id behavior exactly.
pub async fn reconcile_attribute_with_id(
    db: &DbPool,
    entity_id: Uuid,
    desc: &AttributeDesc,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    reconcile_attribute_recorded(db, entity_id, desc, policy, desired_id, None).await
}

/// Solution 7 Phase 1 (design §4.4) — [`reconcile_attribute_with_id`] that
/// stamps a new row with the recording's layer, refuses (`409
/// layer_mismatch`, before any DDL) to touch an existing row of another
/// layer, and records `rec.op` in the final lock + change-log transaction.
/// `None` is exactly [`reconcile_attribute_with_id`].
///
/// When the physical contract of a brand-new field is refused after its row
/// committed, the compensating retire is recorded too (`retire_field`), so the
/// changeset keeps describing what the database holds.
pub async fn reconcile_attribute_recorded(
    db: &DbPool,
    entity_id: Uuid,
    desc: &AttributeDesc,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
    rec: Option<RecordAs<'_>>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let lookup_entity_ref = match desc.lookup_entity.as_deref() {
        Some(target) => Some(resolve_lookup_target(db, target).await?),
        None => None,
    };
    reconcile_attribute_with_lookup_ref(
        db,
        entity_id,
        desc,
        lookup_entity_ref,
        policy,
        desired_id,
        rec,
    )
    .await
}

/// The shared implementation behind [`reconcile_attribute`] and
/// `ensure_attribute`: takes the lookup target already resolved to a uuid
/// (`None` under `Seed` = leave as is).
///
/// Orchestrates the steps in the module contract above, in order: validate
/// the description's shape, probe the current row, build the desired state,
/// decide the write step, apply the physical contract change inline when it
/// is cheap, then run the one short metadata transaction. Each step is its
/// own function below so the sequence reads top-to-bottom here.
pub(super) async fn reconcile_attribute_with_lookup_ref(
    db: &DbPool,
    entity_id: Uuid,
    desc: &AttributeDesc,
    lookup_entity_ref: Option<Uuid>,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
    rec: Option<RecordAs<'_>>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    // A19-T3: a money attribute's conversion options are checked before
    // anything is written.
    let converts = desc.field_type == "currency"
        && attome_core::fx::Conversion::from_options(desc.options.as_ref())
            .map_err(AppError::Validation)?
            .is_some();
    let result = reconcile_attribute_inner(
        db,
        entity_id,
        desc,
        lookup_entity_ref,
        policy,
        desired_id,
        rec,
    )
    .await?;
    // A19-T1: a money amount keeps its currency in the attribute beside it.
    if desc.field_type == "currency" {
        super::money::ensure_companion(
            db,
            entity_id,
            &desc.logicalname,
            &desc.display_name,
            policy,
            rec,
        )
        .await?;
    }
    // A19-T3: and, when it converts, its base amount and rate.
    if converts {
        super::money::ensure_conversion(
            db,
            entity_id,
            &desc.logicalname,
            &desc.display_name,
            policy,
            rec,
        )
        .await?;
    }
    Ok(result)
}

/// [`reconcile_attribute_with_lookup_ref`] without the money companion
/// (A19-T1), which the companion itself is reconciled through.
pub(super) async fn reconcile_attribute_inner(
    db: &DbPool,
    entity_id: Uuid,
    desc: &AttributeDesc,
    lookup_entity_ref: Option<Uuid>,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
    rec: Option<RecordAs<'_>>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let logicalname = desc.logicalname.as_str();
    let field_type = desc.field_type.as_str();
    validate_attribute_shape(logicalname, field_type, lookup_entity_ref, policy)?;
    changeset::preflight(db, rec).await?;

    // Two independent reads, issued together: this runs once per attribute on
    // every boot, and each sequential round trip cost a full localhost hop.
    let (entity_logicalname, current) = tokio::try_join!(
        async {
            sqlx::query_scalar::<_, String>("SELECT logicalname FROM entity_info WHERE id = $1")
                .bind(entity_id)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?
                .ok_or(AppError::NotFound)
        },
        fetch_attribute_row(db, entity_id, logicalname),
    )?;
    if let Some(row) = current.as_ref() {
        changeset::check_owner(rec, &row.owner_layer)?;
    }
    let mut desired = AttributeState::desired(desc, lookup_entity_ref, current.as_ref(), policy);
    let seed_managed = attribute_seed_managed(desc, lookup_entity_ref);
    let object_key = format!("{entity_logicalname}.{logicalname}");
    // Y11-T4: what the seed alone would set, before what other layers hold
    // is kept; its managed properties are the platform's layer rows.
    let seed_desired = desired.clone();
    if let Some(row) = current.as_ref()
        && seed_per_property(policy, row.is_live)
        && AttributeState::from_row(row) != desired
    {
        let before = property_layer::to_map(&AttributeState::from_row(row))?;
        let seed = property_layer::to_map(&desired)?;
        let kept = property_layer::seed_keeps(
            db,
            property_layer::ATTRIBUTE,
            &object_key,
            &before,
            &seed,
            &seed_managed,
            row.is_customized,
        )
        .await?;
        desired = property_layer::from_map(property_layer::keep(&seed, &before, &kept))?;
    }
    let attribute_layer_values = layer_values(
        policy,
        &seed_managed,
        current
            .as_ref()
            .filter(|r| r.is_live)
            .map(AttributeState::from_row)
            .as_ref(),
        if policy == ReconcilePolicy::Seed {
            &seed_desired
        } else {
            &desired
        },
    )?;
    let physical_type = physical_field_type(field_type, desired.options.as_ref());
    let key = AttributeKey {
        entity_id,
        entity_logicalname: &entity_logicalname,
        logicalname,
        field_type,
        physical_type,
    };
    validate_attribute_state(key, &desired)?;
    // Y2-T11: `Some` for a formula the database computes.
    let generated = validate_formula_field(db, key, &desired, current.as_ref()).await?;
    validate_rollup_field(db, key, &desired, current.as_ref()).await?;
    // A17-T1: a lookup from the entity to itself flagged as its hierarchy
    // keeps a stored tree path.
    let hierarchy = field_type == "lookup"
        && lookup_entity_ref == Some(entity_id)
        && super::table::is_hierarchy_lookup(desired.options.as_ref());
    // D2-T1: the self lookup the hierarchy keeps pointing at each row's root.
    let hierarchy_top = if hierarchy {
        validate_hierarchy_top(db, key, entity_id, desired.options.as_ref()).await?
    } else {
        None
    };

    let state_differs = current
        .as_ref()
        .is_some_and(|r| AttributeState::from_row(r) != desired);
    let status = current.as_ref().map(|r| RowStatus {
        is_customized: r.is_customized && !seed_per_property(policy, r.is_live),
        is_live: r.is_live,
    });
    let step = decide_step(policy, status, state_differs);
    let step = check_field_type_drift(key, current.as_ref(), policy, step)?;

    let is_multi = is_multi_valued(field_type, desired.options.as_ref());

    match step {
        WriteStep::Unchanged | WriteStep::SkippedCustomized => {
            let row = current.as_ref().ok_or(AppError::NotFound)?;
            if step == WriteStep::SkippedCustomized {
                tracing::info!(
                    entity = %entity_logicalname,
                    field = %logicalname,
                    "provision: seed skipped a customized attribute row (is_customized = true)"
                );
            }
            // Self-healing physical half, same as every `ensure_attribute`
            // call has always done — a catalog pre-check, no DDL once the
            // column exists.
            provision_column(
                db,
                &entity_logicalname,
                logicalname,
                physical_type,
                is_multi,
                generated.as_deref(),
            )
            .await?;
            if hierarchy {
                super::table::ensure_hierarchy_path(
                    db,
                    entity_id,
                    &entity_logicalname,
                    logicalname,
                    hierarchy_top,
                )
                .await?;
            }
            let outcome = match step {
                WriteStep::SkippedCustomized => ReconcileOutcome::SkippedCustomized,
                _ => ReconcileOutcome::Unchanged,
            };
            Ok((row.id, outcome))
        }
        WriteStep::Create | WriteStep::Update => {
            let contract_change = apply_inline_contract_change(
                db,
                key,
                &desired,
                current.as_ref(),
                policy,
                step,
                is_multi,
            )
            .await?;

            let id = write_attribute_row(
                db,
                key,
                &desired,
                current.as_ref(),
                policy,
                step,
                is_multi,
                generated.as_deref(),
                desired_id,
                rec,
                &attribute_layer_values,
            )
            .await?;
            if hierarchy {
                super::table::ensure_hierarchy_path(
                    db,
                    entity_id,
                    &entity_logicalname,
                    logicalname,
                    hierarchy_top,
                )
                .await?;
            }

            // A brand-new column's contract is installed after the row is
            // committed (the column only exists from `provision_column`
            // inside `write_attribute_row`). If the DDL is refused — e.g.
            // NOT NULL on a table that already has rows — retire the row
            // immediately so no node can observe a field whose physical
            // constraints were not installed (mirrors
            // `admin/attribute.rs::create_attribute`). The harmless nullable
            // column is retained for a corrected retry.
            if contract_change
                && step == WriteStep::Create
                && let Err(error) = evolve_attribute_schema(
                    db,
                    &entity_logicalname,
                    logicalname,
                    physical_type,
                    desired.required,
                    desired.max_length,
                    is_multi,
                )
                .await
            {
                // C-20: a failed compensation is not a harmless no-op — the
                // row now describes physical constraints that were never
                // installed, and until someone notices, it stays that way.
                // Log it loudly with the ids an operator needs, rather than
                // discarding it silently.
                let compensation = match rec {
                    Some(rec) => retire_attribute_recorded(
                        db,
                        entity_id,
                        logicalname,
                        Some(RecordAs {
                            recording: rec.recording,
                            op: rec.op.map(|_| Op::RetireField),
                        }),
                    )
                    .await
                    .map(|_| ()),
                    None => retire_attribute(db, entity_id, logicalname)
                        .await
                        .map(|_| ()),
                };
                if let Err(compensation_error) = compensation {
                    tracing::error!(
                        error = %compensation_error,
                        entity_id = %entity_id,
                        entity = %entity_logicalname,
                        field = %logicalname,
                        original_error = %error,
                        "provision: failed to compensate (retire) a newly created attribute \
                         after its physical contract install failed; the row and its harmless \
                         nullable column remain, describing constraints that were never \
                         installed, until a corrected retry"
                    );
                }
                return Err(error);
            }

            let outcome = match step {
                WriteStep::Create => ReconcileOutcome::Created,
                _ => ReconcileOutcome::Updated,
            };
            tracing::info!(
                entity = %entity_logicalname,
                field = %logicalname,
                ?outcome,
                ?policy,
                "provision: reconciled attribute"
            );
            Ok((id, outcome))
        }
    }
}

/// The identity of the attribute one reconcile call works on. Every step
/// below takes it whole, so the two names, the owning entity's id and the
/// field type travel together instead of as four positional strings/ids.
#[derive(Clone, Copy)]
struct AttributeKey<'a> {
    entity_id: Uuid,
    entity_logicalname: &'a str,
    logicalname: &'a str,
    field_type: &'a str,
    /// The type the physical column is provisioned as (U9):
    /// `identifiers::physical_field_type` — a formula's `result_type`,
    /// `text` for `rich_text`, `file` for `image`, otherwise `field_type`.
    physical_type: &'a str,
}

/// Shape checks that need nothing from the database: identifier validity,
/// the field-type vocabulary, and the policy-dependent lookup-target rules.
fn validate_attribute_shape(
    logicalname: &str,
    field_type: &str,
    lookup_entity_ref: Option<Uuid>,
    policy: ReconcilePolicy,
) -> Result<(), AppError> {
    if !valid_identifier(logicalname) {
        return Err(AppError::Validation(format!(
            "invalid attribute logicalname (lowercase/digits/underscore, max {} chars): {logicalname}",
            super::identifiers::MAX_IDENTIFIER_LEN
        )));
    }
    if logicalname == super::table::HIERARCHY_PATH_COLUMN {
        return Err(AppError::Validation(format!(
            "{logicalname} is reserved for the stored hierarchy path"
        )));
    }
    if !valid_field_type(field_type) {
        return Err(AppError::Validation(format!(
            "unknown field type {field_type:?} for {logicalname}; expected one of: {}",
            attome_core::FieldType::NAMES.join(", ")
        )));
    }
    // A target-less lookup (`lookup_entity: None`) is a legal, seeded shape
    // (a plain UUID column — the audit/s2s engines use it; `plan.rs`'s
    // `diff_entities` already treats it as such). `Admin` still requires a
    // named target on a `lookup` field — that surface has always demanded
    // one — but `Bundle` accepts `None` exactly as `Seed` does, so a bundle
    // exported from a deployment carrying such a field can be re-applied.
    if policy == ReconcilePolicy::Admin && field_type == "lookup" && lookup_entity_ref.is_none() {
        return Err(AppError::Validation(format!(
            "lookup field {logicalname} requires lookup_entity"
        )));
    }
    if policy != ReconcilePolicy::Seed && field_type != "lookup" && lookup_entity_ref.is_some() {
        return Err(AppError::Validation(format!(
            "lookup_entity only applies to lookup fields ({logicalname} is {field_type})"
        )));
    }
    Ok(())
}

/// Vocabulary checks on the *resolved* desired state — after `managed_value`
/// has decided whether a `None` in the description means "keep the current
/// value" or "use the column default".
fn validate_attribute_state(
    key: AttributeKey<'_>,
    desired: &AttributeState,
) -> Result<(), AppError> {
    let AttributeKey {
        entity_logicalname,
        logicalname,
        ..
    } = key;
    if !valid_on_target_delete(&desired.on_target_delete) {
        return Err(AppError::Validation(format!(
            "{entity_logicalname}.{logicalname}: on_target_delete must be one of: restrict, orphan, cascade-deactivate"
        )));
    }
    if !valid_data_classification(&desired.data_classification) {
        return Err(AppError::Validation(format!(
            "{entity_logicalname}.{logicalname}: data_classification must be one of: general, personal, sensitive_special_category"
        )));
    }
    Ok(())
}

/// B-R6 (D-604): the checks a `formula` field needs beyond its shape, run
/// under every policy (admin, bundle and seed alike) before any write:
///
/// - it is never `required` and has no `max_length` — a client can never
///   write it, so "required" could only ever fail, and a computed value is
///   not length-checked input;
/// - its expression compiles against the entity's other live fields and
///   produces its `result_type` (`attome_core::formula::compile_formula`,
///   the same check the engine applies at write time) — an invalid
///   expression is a 422 here, before the field exists;
/// - an existing formula's `result_type` cannot change: the column was
///   provisioned as that type, and D-055 has no type-change path;
/// - Y2-T11: a formula saved with `"generated": true` must translate to a
///   generated column, and neither its expression nor the flag changes
///   afterwards (the column already holds that expression).
///
/// Returns the generated column's SQL for a generated formula.
async fn validate_formula_field(
    db: &DbPool,
    key: AttributeKey<'_>,
    desired: &AttributeState,
    current: Option<&AttributeRow>,
) -> Result<Option<String>, AppError> {
    let AttributeKey {
        entity_id,
        entity_logicalname,
        logicalname,
        field_type,
        physical_type,
    } = key;
    if field_type != attome_core::FieldType::Formula.as_str() {
        return Ok(None);
    }
    if desired.required {
        return Err(AppError::Validation(format!(
            "{entity_logicalname}.{logicalname}: a formula field cannot be required (its value is computed)"
        )));
    }
    if desired.max_length.is_some() {
        return Err(AppError::Validation(format!(
            "{entity_logicalname}.{logicalname}: max_length does not apply to a formula field"
        )));
    }
    if let Some(row) = current
        && row.field_type_int == attome_core::FieldType::Formula.to_int()
    {
        let current_physical = physical_field_type(field_type, row.options.as_ref());
        if current_physical != physical_type {
            return Err(AppError::Validation(format!(
                "{entity_logicalname}.{logicalname}: changing a formula's result_type from \
                 {current_physical} to {physical_type} is not supported; create a new field"
            )));
        }
        let before = attome_core::formula::parse_options(row.options.as_ref()).ok();
        let after = attome_core::formula::parse_options(desired.options.as_ref()).ok();
        if let (Some(before), Some(after)) = (before, after)
            && (before.generated || after.generated)
            && (before.generated != after.generated || before.expression != after.expression)
        {
            return Err(AppError::Validation(format!(
                "{entity_logicalname}.{logicalname}: a generated formula's expression and \
                 `generated` flag cannot change; create a new field"
            )));
        }
    }
    let attrs = fetch_live_attr_infos(db, entity_id, logicalname).await?;
    let named = |e: AppError| match e {
        AppError::Validation(msg) => {
            AppError::Validation(format!("{entity_logicalname}.{logicalname}: {msg}"))
        }
        other => other,
    };
    // A9-T2: a formula reading through lookups compiles against the other
    // entities as they are now (read from the database, like `attrs`), and
    // may not close a cycle among formulas that read each other.
    let expression = attome_core::formula::parse_options(desired.options.as_ref())
        .map(|o| o.expression)
        .unwrap_or_default();
    if attome_core::formula::reads_through_lookup(&expression) {
        let registry = attome_core::build_registry(db).await?;
        // The registry's attributes carry each lookup's target, which the
        // minimal list above does not.
        let with_targets: Vec<attome_core::AttrInfo> = registry
            .get(entity_logicalname)
            .map(|meta| {
                meta.attrs
                    .iter()
                    .filter(|a| a.logicalname != logicalname)
                    .cloned()
                    .collect()
            })
            .unwrap_or_else(|| attrs.clone());
        attome_core::formula::compile_formula_in(
            &with_targets,
            desired.options.as_ref(),
            Some(&registry),
        )
        .map_err(named)?;
        if let Some(cycle) = attome_core::formula::formula_cycle(
            &registry,
            entity_logicalname,
            logicalname,
            &expression,
        ) {
            return Err(AppError::Validation(format!(
                "{entity_logicalname}.{logicalname}: the formula would read itself through \
                 lookups ({}); formulas computed when read cannot form a cycle",
                cycle.join(" -> ")
            )));
        }
    } else {
        attome_core::formula::compile_formula(&attrs, desired.options.as_ref()).map_err(named)?;
    }
    attome_core::formula::generated_sql(&attrs, desired.options.as_ref()).map_err(named)
}

/// A10-T1: a rollup field is computed, so it is never required and has no
/// max_length; its definition names entities and fields that exist now
/// (`attome_core::rollup::validate`, against a registry read from the
/// database, since a bundle may have created them a moment ago); and its
/// result type, which is its column's type, cannot change once it exists.
async fn validate_rollup_field(
    db: &DbPool,
    key: AttributeKey<'_>,
    desired: &AttributeState,
    current: Option<&AttributeRow>,
) -> Result<(), AppError> {
    let AttributeKey {
        entity_logicalname,
        logicalname,
        field_type,
        physical_type,
        ..
    } = key;
    if field_type != attome_core::FieldType::Rollup.as_str() {
        return Ok(());
    }
    let named =
        |msg: String| AppError::Validation(format!("{entity_logicalname}.{logicalname}: {msg}"));
    if desired.required {
        return Err(named(
            "a rollup field cannot be required (its value is computed)".into(),
        ));
    }
    if desired.max_length.is_some() {
        return Err(named("max_length does not apply to a rollup field".into()));
    }
    if let Some(row) = current
        && row.field_type_int == attome_core::FieldType::Rollup.to_int()
    {
        let current_physical = physical_field_type(field_type, row.options.as_ref());
        if current_physical != physical_type {
            return Err(named(format!(
                "changing a rollup's result_type from {current_physical} to {physical_type} is \
                 not supported; create a new field"
            )));
        }
    }
    let registry = attome_core::build_registry(db).await?;
    attome_core::rollup::validate(entity_logicalname, desired.options.as_ref(), &registry)
        .map(|_| ())
        .map_err(|e| match e {
            AppError::Validation(msg) => named(msg),
            other => other,
        })
}

/// D2-T1: a hierarchy's `top_field`, when its options name one: another live
/// lookup from the entity to itself, which the hierarchy triggers then keep.
async fn validate_hierarchy_top<'o>(
    db: &DbPool,
    key: AttributeKey<'_>,
    entity_id: Uuid,
    options: Option<&'o serde_json::Value>,
) -> Result<Option<&'o str>, AppError> {
    let Some(top) = super::table::hierarchy_top_field(options) else {
        return Ok(None);
    };
    let AttributeKey {
        entity_logicalname,
        logicalname,
        ..
    } = key;
    let refused = || {
        AppError::Validation(format!(
            "{entity_logicalname}.{logicalname}: top_field {top} must be another lookup from \
             {entity_logicalname} to itself, created before the hierarchy names it"
        ))
    };
    if top == logicalname {
        return Err(refused());
    }
    let found: bool = sqlx::query_scalar(
        r#"SELECT EXISTS (SELECT 1 FROM attribute_info
            WHERE entity_ref = $1 AND logicalname = $2 AND "type" = $3
              AND lookup_entity_ref = $1 AND (is_active IS NULL OR is_active = true))"#,
    )
    .bind(entity_id)
    .bind(top)
    .bind(attome_core::FieldType::Lookup.to_int())
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if found { Ok(Some(top)) } else { Err(refused()) }
}

/// The entity's live attributes other than `except`, as the minimal
/// [`attome_core::AttrInfo`] a formula compile needs (name, type,
/// options). Read from the metadata table, not the registry: reconcile runs
/// below the cache, and a bundle apply may have created the formula's input
/// fields a moment ago.
async fn fetch_live_attr_infos(
    db: &DbPool,
    entity_id: Uuid,
    except: &str,
) -> Result<Vec<attome_core::AttrInfo>, AppError> {
    let rows: Vec<(String, i32, Option<serde_json::Value>)> = sqlx::query_as(
        r#"SELECT logicalname, COALESCE("type", 3), options
           FROM attribute_info
           WHERE entity_ref = $1 AND logicalname IS NOT NULL AND logicalname <> $2
             AND (is_active IS NULL OR is_active = true)"#,
    )
    .bind(entity_id)
    .bind(except)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(logicalname, field_type_int, options)| attome_core::AttrInfo {
                logicalname,
                field_type_int,
                is_required: false,
                max_length: None,
                is_sensitive: false,
                is_write_restricted: false,
                is_sortable: false,
                is_filterable: false,
                lookup_entity_ref: None,
                on_target_delete: Default::default(),
                data_classification: Default::default(),
                sensitivity: Default::default(),
                sensitivity_confirmed: false,
                options,
            },
        )
        .collect())
}

/// The type check comes AFTER the customized-skip decision (a seed must
/// never fail a boot over a customized row) but BEFORE any write. Returns
/// the step to take — the input step unchanged unless a seed's declared type
/// has drifted, which downgrades it to `Unchanged`.
fn check_field_type_drift(
    key: AttributeKey<'_>,
    current: Option<&AttributeRow>,
    policy: ReconcilePolicy,
    step: WriteStep,
) -> Result<WriteStep, AppError> {
    let AttributeKey {
        entity_logicalname,
        logicalname,
        field_type,
        ..
    } = key;
    let Some(row) = current else {
        return Ok(step);
    };
    if step == WriteStep::SkippedCustomized {
        return Ok(step);
    }
    let current_type = int_to_type(row.field_type_int);
    if current_type == field_type {
        return Ok(step);
    }
    if policy == ReconcilePolicy::Seed {
        // A boot seed whose declared type has drifted from the row it
        // registered long ago (D-055: the platform has no type-change
        // path, so this is a platform bug to fix with a new field,
        // never something to cast at boot). The old create-only seed
        // silently ignored it; refusing here would turn that silent
        // drift into a failed boot on every upgraded deployment, so
        // the seed leaves the row exactly as it is and says so loudly.
        // Admin/Bundle callers get the hard refusal below.
        tracing::warn!(
            entity = %entity_logicalname,
            field = %logicalname,
            current_type,
            declared_type = field_type,
            "provision: seed declares a different field type than the registered attribute; \
             row left untouched (D-055 — create a new field and migrate data explicitly)"
        );
        return Ok(WriteStep::Unchanged);
    }
    Err(AppError::Validation(format!(
        "{entity_logicalname}.{logicalname}: changing field type from {current_type} to {field_type} is potentially lossy and is not supported; create a new field and migrate data explicitly"
    )))
}

/// Physical column contract (Admin/Bundle only — see module docs).
/// Classified before any write so an `Expensive` change returns `Conflict`
/// with nothing half-applied; the inline DDL for an existing column runs
/// before the metadata transaction so a failed validation leaves the prior
/// contract visible. Returns whether the contract changed at all, which the
/// caller needs to decide the post-commit DDL for a brand-new column.
async fn apply_inline_contract_change(
    db: &DbPool,
    key: AttributeKey<'_>,
    desired: &AttributeState,
    current: Option<&AttributeRow>,
    policy: ReconcilePolicy,
    step: WriteStep,
    is_multi: bool,
) -> Result<bool, AppError> {
    let AttributeKey {
        entity_logicalname,
        logicalname,
        physical_type,
        ..
    } = key;
    let contract_change = policy != ReconcilePolicy::Seed
        && match current {
            Some(row) => row.required != desired.required || row.max_length != desired.max_length,
            None => desired.required || desired.max_length.is_some(),
        };
    if !contract_change {
        return Ok(false);
    }
    let classification = classify_schema_change(
        db,
        entity_logicalname,
        RECONCILE_SCHEMA_CHANGE_INLINE_ROW_LIMIT,
        desired.required,
        desired.max_length,
    )
    .await?;
    if let ChangeClassification::Expensive { .. } = classification {
        return Err(AppError::Conflict("schema change requires async plan"));
    }
    if step == WriteStep::Update {
        evolve_attribute_schema(
            db,
            entity_logicalname,
            logicalname,
            physical_type,
            desired.required,
            desired.max_length,
            is_multi,
        )
        .await?;
    }
    Ok(true)
}

/// The one short metadata transaction of the module contract: global
/// metadata-write lock, per-attribute provisioning lock, the UPDATE (or
/// reactivating INSERT), and `append_change_log` as the last statement
/// before commit. Returns the row id.
///
/// C-20: the self-healing physical column (`provision_column`) now runs
/// BEFORE `begin()` instead of between the row write and the commit — it
/// needs nothing from the row (only the identifiers and `is_multi`, all
/// already known), and like `provision_table` it opens its own pool
/// connections for its `exec_ddl_locked` transaction, which self-deadlocks a
/// small pool if it runs while this function's own transaction already
/// holds one.
#[allow(clippy::too_many_arguments)] // positional, matches attribute.rs:237's precedent for this same provisioning shape
async fn write_attribute_row(
    db: &DbPool,
    key: AttributeKey<'_>,
    desired: &AttributeState,
    current: Option<&AttributeRow>,
    policy: ReconcilePolicy,
    step: WriteStep,
    is_multi: bool,
    generated: Option<&str>,
    desired_id: Option<Uuid>,
    rec: Option<RecordAs<'_>>,
    layer_values: &Map<String, Value>,
) -> Result<Uuid, AppError> {
    let layer = changeset::layer_for(policy, rec)?;
    let AttributeKey {
        entity_id,
        entity_logicalname,
        logicalname,
        field_type,
        physical_type,
    } = key;
    provision_column(
        db,
        entity_logicalname,
        logicalname,
        physical_type,
        is_multi,
        generated,
    )
    .await?;

    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-metadata/provision-attribute:{entity_id}:{logicalname}"
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "attribute provisioning already in progress",
        ));
    }

    let id = match (step, current) {
        (WriteStep::Update, Some(row)) => {
            let n = sqlx::query(
                "UPDATE attribute_info \
                 SET name = $2, required = $3, is_sensitive = $4, is_sortable = $5, \
                     is_filterable = $6, max_length = $7, lookup_entity_ref = $8, \
                     options = $9, on_target_delete = $10, data_classification = $11, \
                     purpose = $12, \
                     is_customized = COALESCE($13, is_customized), \
                     is_write_restricted = $14, \
                     is_active = true, modified_at = NOW() \
                 WHERE id = $1",
            )
            .bind(row.id)
            .bind(&desired.name)
            .bind(desired.required)
            .bind(desired.is_sensitive)
            .bind(desired.is_sortable)
            .bind(desired.is_filterable)
            .bind(desired.max_length)
            .bind(desired.lookup_entity_ref)
            .bind(&desired.options)
            .bind(&desired.on_target_delete)
            .bind(&desired.data_classification)
            .bind(&desired.purpose)
            .bind(policy.customized_marker())
            .bind(desired.is_write_restricted)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if n != 1 {
                return Err(AppError::Conflict(
                    "attribute row vanished during reconcile",
                ));
            }
            row.id
        }
        _ => sqlx::query_scalar::<_, Uuid>(
            r#"INSERT INTO attribute_info
                   (id, entity_ref, logicalname, name, "type", required, is_sensitive,
                    is_sortable, is_filterable, lookup_entity_ref, options, max_length,
                    on_target_delete, data_classification, purpose, is_customized,
                    is_write_restricted, is_active, created_at, sort_order, owner_layer)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, true, NOW(),
                       (SELECT COALESCE(MAX(sort_order), -1) + 1
                        FROM attribute_info WHERE entity_ref = $2),
                       $18)
               ON CONFLICT (entity_ref, logicalname)
                 WHERE (is_active IS NULL OR is_active = true)
               DO UPDATE SET logicalname = EXCLUDED.logicalname
               RETURNING id"#,
        )
        .bind(desired_id.unwrap_or_else(Uuid::now_v7))
        .bind(entity_id)
        .bind(logicalname)
        .bind(&desired.name)
        .bind(type_to_int(field_type))
        .bind(desired.required)
        .bind(desired.is_sensitive)
        .bind(desired.is_sortable)
        .bind(desired.is_filterable)
        .bind(desired.lookup_entity_ref)
        .bind(&desired.options)
        .bind(desired.max_length)
        .bind(&desired.on_target_delete)
        .bind(&desired.data_classification)
        .bind(&desired.purpose)
        .bind(policy.customized_marker().unwrap_or(false))
        .bind(desired.is_write_restricted)
        .bind(layer.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_unique_violation)?,
    };

    property_layer::record_in_tx(
        &mut tx,
        property_layer::ATTRIBUTE,
        &format!("{entity_logicalname}.{logicalname}"),
        layer,
        layer_values,
    )
    .await?;
    // `provision_column` already ran above, before `begin()`.
    // Keyed on the owning *entity* (matching `admin/attribute.rs`):
    // `ChangeKind::Upsert` means "re-fetch this entity's row + active
    // attributes", not "patch one attribute".
    attome_core::append_change_log(
        &mut tx,
        entity_id,
        entity_logicalname,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    changeset::record(
        &mut tx,
        rec,
        ObjectKind::Attribute,
        id,
        changeset::field_target(entity_logicalname, logicalname),
        attribute_changes(current, desired),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(id)
}

/// The properties an attribute write changes, for the review summary.
fn attribute_changes(
    current: Option<&AttributeRow>,
    desired: &AttributeState,
) -> Vec<&'static str> {
    let Some(row) = current.filter(|r| r.is_live) else {
        return Vec::new();
    };
    let before = AttributeState::from_row(row);
    let mut changed = Vec::new();
    changeset::diff(&mut changed, "name", &before.name, &desired.name);
    changeset::diff(
        &mut changed,
        "required",
        &before.required,
        &desired.required,
    );
    changeset::diff(
        &mut changed,
        "is_sensitive",
        &before.is_sensitive,
        &desired.is_sensitive,
    );
    changeset::diff(
        &mut changed,
        "is_write_restricted",
        &before.is_write_restricted,
        &desired.is_write_restricted,
    );
    changeset::diff(
        &mut changed,
        "is_sortable",
        &before.is_sortable,
        &desired.is_sortable,
    );
    changeset::diff(
        &mut changed,
        "is_filterable",
        &before.is_filterable,
        &desired.is_filterable,
    );
    changeset::diff(
        &mut changed,
        "max_length",
        &before.max_length,
        &desired.max_length,
    );
    changeset::diff(
        &mut changed,
        "lookup_entity",
        &before.lookup_entity_ref,
        &desired.lookup_entity_ref,
    );
    changeset::diff(&mut changed, "options", &before.options, &desired.options);
    changeset::diff(
        &mut changed,
        "on_target_delete",
        &before.on_target_delete,
        &desired.on_target_delete,
    );
    changeset::diff(
        &mut changed,
        "data_classification",
        &before.data_classification,
        &desired.data_classification,
    );
    changeset::diff(&mut changed, "purpose", &before.purpose, &desired.purpose);
    changed
}

// ── Retire / reactivate ──────────────────────────────────────────────────────

/// Flips `is_active` on the live/retired attribute row with this key. Shared
/// by `retire_attribute` (`live = false`) and `reactivate_attribute`
/// (`live = true`). Idempotent: `Unchanged` when no row is in the opposite
/// state (including when the key does not exist at all — the desired state
/// already holds).
async fn set_attribute_active(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
    live: bool,
    rec: Option<RecordAs<'_>>,
) -> Result<ReconcileOutcome, AppError> {
    changeset::preflight(db, rec).await?;
    // Probe on the pool first — no lock, no write for the idempotent case.
    let candidate: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, owner_layer FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 \
           AND (is_active IS NULL OR is_active = true) = $3 \
         ORDER BY created_at DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(entity_id)
    .bind(logicalname)
    .bind(!live)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((attr_id, owner_layer)) = candidate else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    changeset::check_owner(rec, &owner_layer)?;
    let entity_logicalname: String =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?;

    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let n = sqlx::query(
        "UPDATE attribute_info SET is_active = $2, modified_at = NOW() \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) = $3",
    )
    .bind(attr_id)
    .bind(live)
    .bind(!live)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        // Lost a race with a concurrent flip — the desired state holds.
        return Ok(ReconcileOutcome::Unchanged);
    }
    // The owning entity still exists — it lost or regained one attribute —
    // so this is an Upsert (re-fetch entity_ref's current state), not a Delete.
    attome_core::append_change_log(
        &mut tx,
        entity_id,
        &entity_logicalname,
        attome_core::ChangeKind::Upsert,
    )
    .await?;
    changeset::record(
        &mut tx,
        rec,
        ObjectKind::Attribute,
        attr_id,
        changeset::field_target(&entity_logicalname, logicalname),
        vec!["is_active"],
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(
        entity = %entity_logicalname,
        field = %logicalname,
        live,
        "provision: attribute active flag changed"
    );
    Ok(ReconcileOutcome::Updated)
}

/// Same as `set_attribute_active`, for the entity row only (attribute rows
/// are left alone — see the module docs on why that makes reactivate
/// lossless). `Delete` on retire, `Upsert` on reactivate.
async fn set_entity_active(
    db: &DbPool,
    logicalname: &str,
    live: bool,
    rec: Option<RecordAs<'_>>,
) -> Result<ReconcileOutcome, AppError> {
    changeset::preflight(db, rec).await?;
    let candidate: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id, owner_layer FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true) = $2 \
         ORDER BY created_at DESC NULLS LAST, id DESC LIMIT 1",
    )
    .bind(logicalname)
    .bind(!live)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((entity_id, owner_layer)) = candidate else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    changeset::check_owner(rec, &owner_layer)?;

    let mut tx = attome_db::tx::begin(db).await?;
    attome_core::acquire_metadata_write_lock(&mut tx).await?;
    let n = sqlx::query(
        "UPDATE entity_info SET is_active = $2, modified_at = NOW() \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) = $3",
    )
    .bind(entity_id)
    .bind(live)
    .bind(!live)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    let kind = if live {
        attome_core::ChangeKind::Upsert
    } else {
        attome_core::ChangeKind::Delete
    };
    attome_core::append_change_log(&mut tx, entity_id, logicalname, kind).await?;
    changeset::record(
        &mut tx,
        rec,
        ObjectKind::Entity,
        entity_id,
        changeset::entity_target(logicalname),
        vec!["is_active"],
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(entity = %logicalname, live, "provision: entity active flag changed");
    Ok(ReconcileOutcome::Updated)
}

/// Soft-retire (is_active=false) an attribute / entity by logical key. Idempotent. Never drops.
pub async fn retire_attribute(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_attribute_active(db, entity_id, logicalname, false, None).await
}

/// [`retire_attribute`] with the Solution 7 owner check and recording
/// (`rec.op` is normally `retire_field`).
pub async fn retire_attribute_recorded(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
    rec: Option<RecordAs<'_>>,
) -> Result<ReconcileOutcome, AppError> {
    set_attribute_active(db, entity_id, logicalname, false, rec).await
}

/// Soft-retire (is_active=false) an entity by logicalname. Idempotent. Never drops.
pub async fn retire_entity(db: &DbPool, logicalname: &str) -> Result<ReconcileOutcome, AppError> {
    set_entity_active(db, logicalname, false, None).await
}

/// [`retire_entity`] with the Solution 7 owner check and recording (`rec.op`
/// is normally `retire_entity`).
pub async fn retire_entity_recorded(
    db: &DbPool,
    logicalname: &str,
    rec: Option<RecordAs<'_>>,
) -> Result<ReconcileOutcome, AppError> {
    set_entity_active(db, logicalname, false, rec).await
}

/// Reactivate a previously retired attribute / entity (used when re-applying an older bundle).
pub async fn reactivate_attribute(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_attribute_active(db, entity_id, logicalname, true, None).await
}

/// [`reactivate_attribute`] with the Solution 7 owner check and recording
/// (`rec.op` is normally `reactivate_field`).
pub async fn reactivate_attribute_recorded(
    db: &DbPool,
    entity_id: Uuid,
    logicalname: &str,
    rec: Option<RecordAs<'_>>,
) -> Result<ReconcileOutcome, AppError> {
    set_attribute_active(db, entity_id, logicalname, true, rec).await
}

/// Reactivate a previously retired entity by logicalname. Idempotent.
pub async fn reactivate_entity(
    db: &DbPool,
    logicalname: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_entity_active(db, logicalname, true, None).await
}

/// [`reactivate_entity`] with the Solution 7 owner check and recording
/// (`rec.op` is normally `reactivate_entity`).
pub async fn reactivate_entity_recorded(
    db: &DbPool,
    logicalname: &str,
    rec: Option<RecordAs<'_>>,
) -> Result<ReconcileOutcome, AppError> {
    set_entity_active(db, logicalname, true, rec).await
}

//! Declarative "make this security object match this description"
//! primitives for roles, privileges and field-security profiles
//! (P-environment-promotion §4 "Reuse the provisioning primitives, and finish
//! them" / §5 steps 5 and 13). The attome-security half of the service reconcile
//! API; queries, views and sidebar items live in `attome-server`
//! (`query_admin.rs` / `view_admin.rs` / `sidebar.rs`), and entities /
//! attributes in `attome_metadata::provision`.
//!
//! Same contract as `attome_metadata::provision::reconcile` — the policy matrix is
//! identical, only the tables differ:
//!
//! * **Compare first, write only on a difference.** Every call probes the
//!   current rows on the pool, diffs them against the description and returns
//!   [`ReconcileOutcome::Unchanged`] with no transaction and no write when
//!   nothing differs.
//! * **Ownership is one boolean.** `Seed` never writes a row whose
//!   `is_customized` is `true` (logged at `info`, `SkippedCustomized`) and
//!   never sets the marker; `Admin` sets it `true`; `Bundle` sets it to the
//!   value the bundle carries. For `Admin`/`Bundle` the marker is part of the
//!   diff.
//! * **Set semantics for a role's children.** [`reconcile_role`] treats the
//!   description's privilege grants (with their D-369 conditions), entity
//!   access rows and field-security profile links as the *whole* desired set:
//!   missing ones are added, extra live ones are soft-deleted, changed ones
//!   are updated. The same for a profile's `(entity, field)` members, whose
//!   table has no soft-delete flag — extras are deleted outright, because a
//!   `can_read = false, can_update = false` row is indistinguishable from
//!   absence to the resolver but not to the exporter, and leaving it would
//!   keep the object in permanent drift.
//! * **Reactivate over insert.** The natural-key indexes on
//!   `role.name` and `field_security_profile.name` are
//!   partial (`WHERE is_deleted = false`), so a retired row does not collide
//!   with a fresh INSERT — but a second row under the same name would orphan
//!   every user/team assignment and profile link of the first. A retired row
//!   with the same key is therefore reactivated and brought up to the
//!   description instead.
//! * **Retire is `is_deleted = true`, never a DELETE.** [`retire_role`] also
//!   soft-deletes the role's live privilege grants: `resolve_privileges`
//!   joins `role_mm_privilege` through the user's role assignment
//!   without consulting `role.is_deleted` (the access-level
//!   resolvers do), so a retired role whose grant rows stayed live would keep
//!   granting. [`reactivate_role`] flips only the role row back; the grant set
//!   is restored by the [`reconcile_role`] call every bundle re-apply makes
//!   (set semantics), which is also why the two are lossless together.
//! * **Cache invalidation is the caller's.** These functions take a bare
//!   pool, so they cannot reach the `SecurityResolverHandle` every admin
//!   handler invalidates through. [`invalidate_role_holders`] and
//!   [`invalidate_profile_holders`] are the helpers a caller with a handle
//!   uses after a write — the same `users_holding_role` / profile-member
//!   fan-out the handlers do.
//! * Nothing here notifies or touches the entity metadata change log — none
//!   of these tables is registry-relevant.

use std::collections::{BTreeMap, BTreeSet};

use attome_db::DbPool;
use attome_server::security::{ConditionOperator, SecurityResolverHandle};
use attome_types::AppError;
use uuid::Uuid;
// ARCH-1a-i — from `attome-core`, not `attome-metadata`. Naming these two
// enums was one of the five references that made ARCH-1 a dependency cycle.
pub use attome_core::reconcile::{ReconcileOutcome, ReconcilePolicy};
// C-19: `WriteStep`/`RowStatus`/`decide_step` used to be restated here
// (a second copy of `attome_metadata::provision::reconcile`'s private ones) —
// now the one shared implementation.
use attome_core::reconcile::{RowStatus, WriteStep, decide_step};

use crate::db::{
    OperationLevels, ensure_privilege, ensure_privilege_with_id, upsert_profile_field,
    upsert_role_entity_access, upsert_role_privilege_grant, users_holding_role,
};
use attome_core::changeset::Layer;

/// Solution 7 (D-785, design §1.4): the `owner_layer` a row this module
/// inserts gets. A boot seed writes the platform's own definitions
/// (`platform`); an admin write or a bundle apply (the pre-changeset
/// promotion path) writes `project`. Existing rows keep their layer: the
/// boot stamp step (`attome_server::changeset::layers`) owns re-stamping.
fn policy_layer(policy: ReconcilePolicy) -> Layer {
    match policy {
        ReconcilePolicy::Seed => Layer::Platform,
        ReconcilePolicy::Admin | ReconcilePolicy::Bundle { .. } => Layer::Project,
    }
}

// ── Descriptions (mirror the bundle model field-for-field) ──────────────────

/// One role as desired state: the row plus its grants, entity access rows and
/// profile links (set semantics — see the module docs).
#[derive(Clone, Debug, PartialEq)]
pub struct RoleDesc {
    pub name: String,
    pub description: Option<String>,
    /// `role.access_level` (0..=3; 3 = Global).
    pub access_level: i16,
    pub position_hierarchy_enabled: bool,
    pub privileges: Vec<RoleGrantDesc>,
    pub entity_access: Vec<RoleEntityAccessDesc>,
    /// Field-security profile names (`role_mm_field_security_profile`).
    pub field_security_profiles: Vec<String>,
}

/// One role <-> privilege grant and its D-369 conditions.
#[derive(Clone, Debug, PartialEq)]
pub struct RoleGrantDesc {
    /// Privilege key (`privilege.key`).
    pub privilege: String,
    pub conditions: Vec<GrantConditionDesc>,
}

/// One `role_privilege_condition` row.
#[derive(Clone, Debug, PartialEq)]
pub struct GrantConditionDesc {
    /// `field_logicalname`.
    pub field: String,
    /// 0=eq 1=ne 2=gt 3=lt 4=gte 5=lte 6=in.
    pub operator: i16,
    pub value: serde_json::Value,
}

/// One `role_mm_entity_access` row (migrations 0054 + 0130).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleEntityAccessDesc {
    /// Entity logicalname (resolved to `entity_ref` inside).
    pub entity: String,
    pub read_access_level: i16,
    pub write_access_level: i16,
    pub delete_access_level: i16,
    pub read_owner_visible: bool,
    pub write_owner_visible: bool,
    pub delete_owner_visible: bool,
    /// Q10-T12: create, assign, share, export and bulk levels and the
    /// child-unit flags.
    pub operations: OperationLevels,
}

/// One `privilege` row. Privileges carry no `is_customized` and are
/// never retired (they are platform-minted per entity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivilegeDesc {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
}

/// One field-security profile and its `(entity, field)` members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSecurityProfileDesc {
    pub name: String,
    pub description: Option<String>,
    pub fields: Vec<ProfileFieldDesc>,
}

/// One `field_security_profile_field` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileFieldDesc {
    pub entity: String,
    pub field: String,
    pub can_read: bool,
    pub can_update: bool,
}

// `WriteStep`/`RowStatus`/`decide_step` come from `attome_core::reconcile`
// now (C-19); `WriteStep::outcome()` replaces the local `outcome_for` helper,
// and `ReconcilePolicy::customized_marker()` replaces the local free function
// of the same name that used to restate it.

/// Same range `core_role_access_level_range` / the
/// `core_role_mm_entity_access_*_range` CHECK constraints enforce — checked
/// here so a bad description is a `Validation`, not a constraint 500.
fn validate_access_level(what: &str, level: i16) -> Result<(), AppError> {
    if !(0..=3).contains(&level) {
        return Err(AppError::Validation(format!(
            "{what}: access level must be 0 (None), 1 (Team), 2 (BusinessUnit), or 3 (Global)"
        )));
    }
    Ok(())
}

/// A unique-key violation (SQLSTATE 23505) from a reconcile INSERT is a lost
/// race against a concurrent writer of the same key, not an internal fault —
/// deterministic, client-actionable, and resolved by re-running the (retry-
/// safe) reconcile. Same classification `entity_mutation::classify_db_error`
/// gives the generic CRUD path.
fn map_unique_violation(error: sqlx::Error) -> AppError {
    if attome_db::is_unique_violation(&error) {
        AppError::Conflict("a concurrent write created this object first; retry")
    } else {
        AppError::internal(error)
    }
}

/// Live-row cap per grant — the same product-level bound
/// `admin::role_grant_conditions::create_condition` enforces (D-369).
const MAX_CONDITIONS_PER_GRANT: usize = 3;

/// Canonical, order-independent form of a grant's condition set — what the
/// diff compares. `value` is compared by its canonical JSON text.
fn condition_key(c: &GrantConditionDesc) -> ConditionKey {
    (c.field.clone(), c.operator, c.value.to_string())
}

fn validate_conditions(privilege: &str, conditions: &[GrantConditionDesc]) -> Result<(), AppError> {
    if conditions.len() > MAX_CONDITIONS_PER_GRANT {
        return Err(AppError::Validation(format!(
            "grant {privilege}: a grant may carry at most {MAX_CONDITIONS_PER_GRANT} conditions"
        )));
    }
    for c in conditions {
        let operator = ConditionOperator::from_i16(c.operator).ok_or_else(|| {
            AppError::Validation(format!(
                "grant {privilege}: unrecognized condition operator {}",
                c.operator
            ))
        })?;
        // Z11-T16: an expression condition names no field; its text is
        // translated when the filter runs, and one that no longer translates
        // denies (fail closed).
        if operator == ConditionOperator::Expression {
            if !c.field.is_empty() || !c.value.as_str().is_some_and(|t| !t.trim().is_empty()) {
                return Err(AppError::Validation(format!(
                    "grant {privilege}: an expression condition names no field and carries its text"
                )));
            }
            continue;
        }
        if c.field.trim().is_empty() {
            return Err(AppError::Validation(format!(
                "grant {privilege}: a condition's field is required"
            )));
        }
        if operator == ConditionOperator::In {
            if !c.value.is_array() {
                return Err(AppError::Validation(format!(
                    "grant {privilege}: an `in` condition's value must be a JSON array"
                )));
            }
        } else if c.value.is_array() || c.value.is_object() || c.value.is_null() {
            return Err(AppError::Validation(format!(
                "grant {privilege}: condition value must be a string, number, or boolean"
            )));
        }
    }
    Ok(())
}

// ── Roles ─────────────────────────────────────────────────────────────────────

/// The managed columns of an `role` row plus its children, in the
/// canonical (sorted, de-duplicated) form the diff compares.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RoleState {
    description: Option<String>,
    access_level: i16,
    position_hierarchy_enabled: bool,
    /// privilege key -> sorted condition keys
    grants: BTreeMap<String, BTreeSet<ConditionKey>>,
    entity_access: BTreeMap<String, EntityAccessLevels>,
    profiles: BTreeSet<String>,
}

#[derive(sqlx::FromRow)]
struct RoleRow {
    id: Uuid,
    description: Option<String>,
    access_level: i16,
    position_hierarchy_enabled: bool,
    is_customized: bool,
    is_deleted: bool,
}

/// Prefers the live row; otherwise the most recently created retired one.
async fn fetch_role_row(db: &DbPool, name: &str) -> Result<Option<RoleRow>, AppError> {
    sqlx::query_as(
        "SELECT id, description, access_level, position_hierarchy_enabled, is_customized, is_deleted \
         FROM role WHERE name = $1 \
         ORDER BY is_deleted ASC, created_at DESC, id DESC LIMIT 1",
    )
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Canonical condition key: (field, operator, canonical JSON value).
type ConditionKey = (String, i16, String);
/// Live grants of a role: privilege key -> (grant row id, condition set).
type GrantMap = BTreeMap<String, (Uuid, BTreeSet<ConditionKey>)>;
/// Live entity-access rows of a role: entity logicalname -> (row id, levels).
type EntityAccessLevels = (i16, i16, i16, bool, bool, bool, OperationLevels);
type EntityAccessMap = BTreeMap<String, (Uuid, EntityAccessLevels)>;

async fn fetch_role_grants(db: &DbPool, role_id: Uuid) -> Result<GrantMap, AppError> {
    let grants: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT rp.id, p.key FROM role_mm_privilege rp \
         JOIN privilege p ON p.id = rp.privilege_ref \
         WHERE rp.role_ref = $1 AND rp.is_deleted = false",
    )
    .bind(role_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let grant_ids: Vec<Uuid> = grants.iter().map(|(id, _)| *id).collect();
    let conditions: Vec<(Uuid, String, i16, serde_json::Value)> = sqlx::query_as(
        "SELECT role_privilege_ref, field_logicalname, operator, value \
         FROM role_privilege_condition \
         WHERE role_privilege_ref = ANY($1) AND is_deleted = false",
    )
    .bind(&grant_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut out: GrantMap = BTreeMap::new();
    for (id, key) in grants {
        out.insert(key, (id, BTreeSet::new()));
    }
    let mut by_id: BTreeMap<Uuid, BTreeSet<ConditionKey>> = BTreeMap::new();
    for (grant_id, field, operator, value) in conditions {
        by_id
            .entry(grant_id)
            .or_default()
            .insert((field, operator, value.to_string()));
    }
    for (id, set) in out.values_mut() {
        if let Some(conds) = by_id.remove(id) {
            *set = conds;
        }
    }
    Ok(out)
}

/// One `role_mm_entity_access` row joined to its entity logicalname.
#[derive(sqlx::FromRow)]
struct EntityAccessRow {
    id: Uuid,
    logicalname: String,
    read_access_level: i16,
    write_access_level: i16,
    delete_access_level: i16,
    read_owner_visible: bool,
    write_owner_visible: bool,
    delete_owner_visible: bool,
    #[sqlx(flatten)]
    operations: OperationLevels,
}

async fn fetch_role_entity_access(db: &DbPool, role_id: Uuid) -> Result<EntityAccessMap, AppError> {
    let rows: Vec<EntityAccessRow> = sqlx::query_as(
        "SELECT ea.id, ei.logicalname, ea.read_access_level, ea.write_access_level, \
                ea.delete_access_level, ea.read_owner_visible, ea.write_owner_visible, \
                ea.delete_owner_visible, ea.create_access_level, ea.assign_access_level, \
                ea.share_access_level, ea.export_access_level, ea.bulk_access_level, \
                ea.read_bu_children, ea.write_bu_children, ea.delete_bu_children, \
                ea.assign_bu_children, ea.share_bu_children \
         FROM role_mm_entity_access ea \
         JOIN entity_info ei ON ei.id = ea.entity_ref \
         WHERE ea.role_ref = $1 AND ea.is_deleted = false",
    )
    .bind(role_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.logicalname,
                (
                    r.id,
                    (
                        r.read_access_level,
                        r.write_access_level,
                        r.delete_access_level,
                        r.read_owner_visible,
                        r.write_owner_visible,
                        r.delete_owner_visible,
                        r.operations,
                    ),
                ),
            )
        })
        .collect())
}

/// Live profile links of a role: profile name -> link row id.
async fn fetch_role_profiles(
    db: &DbPool,
    role_id: Uuid,
) -> Result<BTreeMap<String, Uuid>, AppError> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT rp.id, p.name FROM role_mm_field_security_profile rp \
         JOIN field_security_profile p ON p.id = rp.profile_ref \
         WHERE rp.role_ref = $1 AND rp.is_deleted = false AND p.is_deleted = false",
    )
    .bind(role_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows.into_iter().map(|(id, name)| (name, id)).collect())
}

async fn resolve_live_entity_id(db: &DbPool, logicalname: &str) -> Result<Uuid, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation(format!(
            "no registered entity found with logicalname '{logicalname}'"
        ))
    })
}

/// Create-or-update one role, including its grants (+ conditions), entity
/// access rows and profile links as the complete desired set. Returns
/// `(role_id, outcome)`.
///
/// Privilege keys a grant names must exist — missing ones are minted through
/// `ensure_privilege` with the key as display name, the same forgiving path
/// `admin::role_grants::create_role_grant` takes. Entities named by entity
/// access rows and profiles named by links must already exist (apply
/// entities and profiles before roles).
pub async fn reconcile_role(
    db: &DbPool,
    desc: &RoleDesc,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let name = desc.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("role name is required".into()));
    }
    validate_access_level(&format!("role {name}"), desc.access_level)?;
    for g in &desc.privileges {
        if g.privilege.trim().is_empty() {
            return Err(AppError::Validation(format!(
                "role {name}: a grant's privilege key is required"
            )));
        }
        validate_conditions(&g.privilege, &g.conditions)?;
    }
    for ea in &desc.entity_access {
        let what = format!("role {name} / entity {}", ea.entity);
        validate_access_level(&what, ea.read_access_level)?;
        validate_access_level(&what, ea.write_access_level)?;
        validate_access_level(&what, ea.delete_access_level)?;
        ea.operations.validate()?;
    }

    // Desired state, canonical form.
    let desired = RoleState {
        description: desc.description.clone(),
        access_level: desc.access_level,
        position_hierarchy_enabled: desc.position_hierarchy_enabled,
        grants: desc
            .privileges
            .iter()
            .map(|g| {
                (
                    g.privilege.trim().to_owned(),
                    g.conditions.iter().map(condition_key).collect(),
                )
            })
            .collect(),
        entity_access: desc
            .entity_access
            .iter()
            .map(|ea| {
                (
                    ea.entity.clone(),
                    (
                        ea.read_access_level,
                        ea.write_access_level,
                        ea.delete_access_level,
                        ea.read_owner_visible,
                        ea.write_owner_visible,
                        ea.delete_owner_visible,
                        ea.operations,
                    ),
                )
            })
            .collect(),
        profiles: desc.field_security_profiles.iter().cloned().collect(),
    };

    let current = fetch_role_row(db, name).await?;
    let (cur_grants, cur_access, cur_profiles) = match current.as_ref() {
        Some(row) => (
            fetch_role_grants(db, row.id).await?,
            fetch_role_entity_access(db, row.id).await?,
            fetch_role_profiles(db, row.id).await?,
        ),
        None => (BTreeMap::new(), BTreeMap::new(), BTreeMap::new()),
    };
    let state_differs = current.as_ref().is_some_and(|row| {
        RoleState {
            description: row.description.clone(),
            access_level: row.access_level,
            position_hierarchy_enabled: row.position_hierarchy_enabled,
            grants: cur_grants
                .iter()
                .map(|(k, (_, conds))| (k.clone(), conds.clone()))
                .collect(),
            entity_access: cur_access
                .iter()
                .map(|(k, (_, levels))| (k.clone(), *levels))
                .collect(),
            profiles: cur_profiles.keys().cloned().collect(),
        } != desired
    });
    let status = current.as_ref().map(|row| RowStatus {
        is_customized: row.is_customized,
        is_live: !row.is_deleted,
    });
    let step = decide_step(policy, status, state_differs);

    match step {
        WriteStep::Unchanged => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            Ok((id, ReconcileOutcome::Unchanged))
        }
        WriteStep::SkippedCustomized => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            tracing::info!(role = %name, "security reconcile: seed skipped a customized role (is_customized = true)");
            Ok((id, ReconcileOutcome::SkippedCustomized))
        }
        WriteStep::Create | WriteStep::Update => {
            // Resolve every reference BEFORE the transaction (guidelines §4:
            // keep transactions short; `ensure_privilege` commits on its own).
            let mut privilege_ids: BTreeMap<String, Uuid> = BTreeMap::new();
            for key in desired.grants.keys() {
                let id = ensure_privilege(
                    db,
                    key,
                    key,
                    "Created via role reconcile",
                    policy_layer(policy),
                )
                .await?;
                privilege_ids.insert(key.clone(), id);
            }
            let mut entity_ids: BTreeMap<String, Uuid> = BTreeMap::new();
            for entity in desired.entity_access.keys() {
                entity_ids.insert(entity.clone(), resolve_live_entity_id(db, entity).await?);
            }
            let mut profile_ids: BTreeMap<String, Uuid> = BTreeMap::new();
            for profile in &desired.profiles {
                let id: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM field_security_profile WHERE name = $1 AND is_deleted = false",
                )
                .bind(profile)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?;
                let id = id.ok_or_else(|| {
                    AppError::Validation(format!(
                        "role {name}: no active field-security profile named '{profile}'"
                    ))
                })?;
                profile_ids.insert(profile.clone(), id);
            }

            // Concurrency story (guidelines §2): two concurrent reconciles of
            // the same role — two apply workers, or a seed racing an admin
            // write — serialize on `core_role_name_active_unique` for a
            // brand-new row (the loser's INSERT raises 23505, mapped to
            // `Conflict` below, and a re-run converges since compare-first
            // makes every call retry-safe). The unique index alone does not
            // protect an *existing* row's UPDATE below, or the grant/
            // entity-access/profile-link set-semantics writes that follow
            // it — two concurrent reconciles of the same already-existing
            // role could otherwise interleave their reads and writes of
            // `cur_grants`/`cur_access`/`cur_profiles` into a lost update.
            // C-19: `attome-security` now owns advisory-lock namespace 23
            // (`attome_security::ADVISORY_LOCK_NAMESPACE`,
            // `crates/server/tests/advisory_lock_namespaces.rs`) — the same
            // per-object serialization `attome_metadata::provision::reconcile`'s
            // entity/attribute counterpart already takes.
            let mut tx = attome_db::tx::begin(db).await?;
            let locked: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
                    .bind(crate::ADVISORY_LOCK_NAMESPACE)
                    .bind(format!("attome-security/reconcile:{name}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            if !locked {
                return Err(AppError::Conflict("role reconcile already in progress"));
            }

            let role_id = match (step, current.as_ref()) {
                (WriteStep::Update, Some(row)) => {
                    let n = sqlx::query(
                        "UPDATE role \
                         SET description = $2, access_level = $3, position_hierarchy_enabled = $4, \
                             is_deleted = false, is_customized = COALESCE($5, is_customized), \
                             updated_at = NOW(), row_version = row_version + 1 \
                         WHERE id = $1",
                    )
                    .bind(row.id)
                    .bind(&desired.description)
                    .bind(desired.access_level)
                    .bind(desired.position_hierarchy_enabled)
                    .bind(policy.customized_marker())
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?
                    .rows_affected();
                    if n != 1 {
                        return Err(AppError::Conflict("role row vanished during reconcile"));
                    }
                    row.id
                }
                _ => sqlx::query_scalar::<_, Uuid>(
                    "INSERT INTO role \
                         (id, name, description, access_level, position_hierarchy_enabled, \
                          is_customized, owner_layer) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
                )
                .bind(desired_id.unwrap_or_else(Uuid::now_v7))
                .bind(name)
                .bind(&desired.description)
                .bind(desired.access_level)
                .bind(desired.position_hierarchy_enabled)
                .bind(policy.customized_marker().unwrap_or(false))
                .bind(policy_layer(policy).as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(map_unique_violation)?,
            };

            // ── Privilege grants: set semantics ──
            for (key, wanted_conditions) in &desired.grants {
                let privilege_id = privilege_ids
                    .get(key)
                    .copied()
                    .ok_or_else(|| AppError::internal("privilege id missing after ensure"))?;
                let (grant_id, conditions_differ) = match cur_grants.get(key) {
                    Some((grant_id, current_conditions)) => {
                        (*grant_id, current_conditions != wanted_conditions)
                    }
                    None => {
                        // Reactivate a soft-deleted grant for the pair rather
                        // than inserting a second one (uq_core_role_mm_privilege)
                        // — C-19: the one atomic upsert, shared with
                        // `db::ensure_role_privilege_grant`/`admin::role_grants`.
                        let grant_id = upsert_role_privilege_grant(
                            &mut *tx,
                            role_id,
                            privilege_id,
                            policy_layer(policy),
                        )
                        .await?;
                        // A reactivated grant may carry stale live conditions
                        // from before it was revoked — always resync.
                        (grant_id, true)
                    }
                };
                if conditions_differ {
                    sqlx::query(
                        "UPDATE role_privilege_condition \
                         SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
                         WHERE role_privilege_ref = $1 AND is_deleted = false",
                    )
                    .bind(grant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                    for (field, operator, value_text) in wanted_conditions {
                        let value: serde_json::Value =
                            serde_json::from_str(value_text).map_err(|e| {
                                AppError::internal(format!("condition value round-trip: {e}"))
                            })?;
                        sqlx::query(
                            "INSERT INTO role_privilege_condition \
                                 (role_privilege_ref, field_logicalname, operator, value, \
                                  owner_layer) \
                             VALUES ($1, $2, $3, $4, $5)",
                        )
                        .bind(grant_id)
                        .bind(field)
                        .bind(operator)
                        .bind(&value)
                        .bind(policy_layer(policy).as_str())
                        .execute(&mut *tx)
                        .await
                        .map_err(AppError::internal)?;
                    }
                }
            }
            for (key, (grant_id, _)) in &cur_grants {
                if !desired.grants.contains_key(key) {
                    sqlx::query(
                        "UPDATE role_mm_privilege \
                         SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
                         WHERE id = $1 AND is_deleted = false",
                    )
                    .bind(grant_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                }
            }

            // ── Entity access: set semantics ──
            for (entity, levels) in &desired.entity_access {
                if cur_access.get(entity).is_some_and(|(_, cur)| cur == levels) {
                    continue;
                }
                let entity_ref = entity_ids
                    .get(entity)
                    .copied()
                    .ok_or_else(|| AppError::internal("entity id missing after resolve"))?;
                // C-19: the one atomic upsert, shared with
                // `admin::role_entity_access::upsert_entity_access_grant`.
                upsert_role_entity_access(
                    &mut *tx,
                    role_id,
                    entity_ref,
                    levels.0,
                    levels.1,
                    levels.2,
                    levels.3,
                    levels.4,
                    levels.5,
                    &levels.6,
                    policy_layer(policy),
                )
                .await?;
            }
            for (entity, (row_id, _)) in &cur_access {
                if !desired.entity_access.contains_key(entity) {
                    sqlx::query(
                        "UPDATE role_mm_entity_access \
                         SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
                         WHERE id = $1 AND is_deleted = false",
                    )
                    .bind(row_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                }
            }

            // ── Profile links: set semantics ──
            for profile in &desired.profiles {
                if cur_profiles.contains_key(profile) {
                    continue;
                }
                let profile_ref = profile_ids
                    .get(profile)
                    .copied()
                    .ok_or_else(|| AppError::internal("profile id missing after resolve"))?;
                sqlx::query(
                    "INSERT INTO role_mm_field_security_profile \
                         (id, role_ref, profile_ref, owner_layer) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (role_ref, profile_ref) DO UPDATE SET is_deleted = false, \
                         updated_at = NOW(), \
                         row_version = role_mm_field_security_profile.row_version + 1",
                )
                .bind(Uuid::now_v7())
                .bind(role_id)
                .bind(profile_ref)
                .bind(policy_layer(policy).as_str())
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            }
            for (profile, link_id) in &cur_profiles {
                if !desired.profiles.contains(profile) {
                    sqlx::query(
                        "UPDATE role_mm_field_security_profile \
                         SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
                         WHERE id = $1 AND is_deleted = false",
                    )
                    .bind(link_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                }
            }

            tx.commit().await.map_err(AppError::internal)?;
            let outcome = step.outcome();
            tracing::info!(role = %name, ?outcome, ?policy, "security reconcile: reconciled role");
            Ok((role_id, outcome))
        }
    }
}

/// Flips `is_deleted` on the role named `name`. Shared by [`retire_role`]
/// (`live = false`, which also soft-deletes the role's live privilege grants
/// — see the module docs) and [`reactivate_role`] (`live = true`, role row
/// only). Idempotent: `Unchanged` when no row is in the opposite state.
async fn set_role_live(db: &DbPool, name: &str, live: bool) -> Result<ReconcileOutcome, AppError> {
    let candidate: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM role WHERE name = $1 AND is_deleted = $2 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(name)
    .bind(live)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(role_id) = candidate else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    let mut tx = attome_db::tx::begin(db).await?;
    let n = sqlx::query(
        "UPDATE role SET is_deleted = $2, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = $3",
    )
    .bind(role_id)
    .bind(!live)
    .bind(live)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    if !live {
        sqlx::query(
            "UPDATE role_mm_privilege \
             SET is_deleted = true, updated_at = NOW(), row_version = row_version + 1 \
             WHERE role_ref = $1 AND is_deleted = false",
        )
        .bind(role_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(role = %name, live, "security reconcile: role lifecycle flag changed");
    Ok(ReconcileOutcome::Updated)
}

/// Soft-retire (`is_deleted = true`) a role by name. Idempotent. Never drops.
pub async fn retire_role(db: &DbPool, name: &str) -> Result<ReconcileOutcome, AppError> {
    set_role_live(db, name, false).await
}

/// Reactivate a previously retired role by name. Idempotent. The role row
/// only — re-run [`reconcile_role`] to restore its grant set.
pub async fn reactivate_role(db: &DbPool, name: &str) -> Result<ReconcileOutcome, AppError> {
    set_role_live(db, name, true).await
}

/// Every user who effectively holds `role_id` (direct + team-mediated) gets
/// its cached `SecurityContext` invalidated — what every role-mutating admin
/// handler does after its write, offered here for callers of
/// [`reconcile_role`] / [`retire_role`] / [`reactivate_role`] that hold a
/// `SecurityResolverHandle`.
pub async fn invalidate_role_holders(
    db: &DbPool,
    security: &SecurityResolverHandle,
    role_id: Uuid,
) -> Result<(), AppError> {
    invalidate_all(security, users_holding_role(db, role_id).await?).await
}

/// Every user reachable through any role `profile_id` is assigned to gets its
/// cached field grants recomputed — the fan-out
/// `admin::field_security::set_field_profile_field` does.
pub async fn invalidate_profile_holders(
    db: &DbPool,
    security: &SecurityResolverHandle,
    profile_id: Uuid,
) -> Result<(), AppError> {
    let user_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT ur.user_ref \
         FROM user_account_mm_role ur \
         JOIN role_mm_field_security_profile rp ON rp.role_ref = ur.role_ref \
         WHERE rp.profile_ref = $1 AND ur.is_deleted = false AND rp.is_deleted = false",
    )
    .bind(profile_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    invalidate_all(security, user_ids).await
}

/// Upper bound on the number of `invalidate_sync` calls in flight at once
/// across one admin write's membership fan-out (PLATFORM-REVIEW-2026-08-24
/// §3.7). Each call is an epoch bump plus an L1/L2 purge — a Redis
/// round-trip or two — and the previous shape spawned one task per holder
/// with no cap, so a single write against a role held by thousands of users
/// pushed the whole membership at Redis and the runtime at once. 32 keeps a
/// large fan-out well inside one pool's worth of connections while still
/// finishing a few-thousand-member role in a fraction of a second.
pub(crate) const AUTHZ_INVALIDATION_MAX_IN_FLIGHT: usize = 32;

/// Concurrent, acknowledged invalidation of every user in `user_ids`, with
/// at most [`AUTHZ_INVALIDATION_MAX_IN_FLIGHT`] calls in flight at once.
/// The one implementation behind [`invalidate_role_holders`] /
/// [`invalidate_profile_holders`] here and `admin::shared::invalidate_sync_all`
/// (every role/profile/team/position admin handler's post-write fan-out).
///
/// Failure semantics are unchanged from the unbounded version (D-116 goal
/// (b)): any failed bump/purge still fails the whole call, so the handler
/// returns a 500 rather than a 200 whose cache never converged. What
/// changed is that the remaining members are still drained rather than
/// abandoned mid-flight on the first error — every member that *can* be
/// invalidated is — and one `warn!` summarises how many failed before the
/// first error is returned.
pub(crate) async fn invalidate_all(
    security: &SecurityResolverHandle,
    user_ids: Vec<Uuid>,
) -> Result<(), AppError> {
    let total = user_ids.len();
    let mut pending = user_ids.into_iter();
    let mut set: tokio::task::JoinSet<Result<(), AppError>> = tokio::task::JoinSet::new();
    let spawn = |set: &mut tokio::task::JoinSet<Result<(), AppError>>, user_id: Uuid| {
        let security = security.clone();
        set.spawn(async move { security.invalidate_sync(user_id).await });
    };
    // Prime the window, then top it back up by one for every completion —
    // a sliding window of `AUTHZ_INVALIDATION_MAX_IN_FLIGHT` tasks, never
    // one task per member sitting in the set at once.
    for user_id in pending.by_ref().take(AUTHZ_INVALIDATION_MAX_IN_FLIGHT) {
        spawn(&mut set, user_id);
    }
    let mut failed = 0usize;
    let mut first_error: Option<AppError> = None;
    while let Some(joined) = set.join_next().await {
        let outcome = match joined {
            Ok(result) => result,
            Err(e) => Err(AppError::internal(format!(
                "authz invalidation task panicked: {e}"
            ))),
        };
        if let Err(e) = outcome {
            failed += 1;
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
        if let Some(next) = pending.next() {
            spawn(&mut set, next);
        }
    }
    if failed > 0 {
        tracing::warn!(
            total,
            failed,
            max_in_flight = AUTHZ_INVALIDATION_MAX_IN_FLIGHT,
            "authz invalidation fan-out: some members' cached security context could not be invalidated"
        );
    }
    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod invalidate_all_tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use attome_server::security::{SecurityContext, SecurityResolver, SecurityResolverHandle};
    use attome_types::AppError;
    use uuid::Uuid;

    use super::{AUTHZ_INVALIDATION_MAX_IN_FLIGHT, invalidate_all};

    /// A resolver whose `invalidate_sync` parks for a moment so calls
    /// overlap, and records how many were in flight at the busiest instant.
    /// `fail_nth` makes exactly one call (the nth to *start*, 1-based) fail.
    struct CountingResolver {
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        started: AtomicUsize,
        completed: AtomicUsize,
        fail_nth: Option<usize>,
    }

    impl CountingResolver {
        fn new(fail_nth: Option<usize>) -> Arc<Self> {
            Arc::new(Self {
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                started: AtomicUsize::new(0),
                completed: AtomicUsize::new(0),
                fail_nth,
            })
        }
    }

    impl SecurityResolver for CountingResolver {
        fn resolve<'a>(
            &'a self,
            _user_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = Result<Arc<SecurityContext>, AppError>> + Send + 'a>>
        {
            Box::pin(async { Err(AppError::Forbidden) })
        }

        fn invalidate<'a>(
            &'a self,
            _user_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async {})
        }

        fn resolve_strict<'a>(
            &'a self,
            _user_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = Result<Arc<SecurityContext>, AppError>> + Send + 'a>>
        {
            Box::pin(async { Err(AppError::Forbidden) })
        }

        fn invalidate_sync<'a>(
            &'a self,
            _user_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>> {
            Box::pin(async move {
                let ordinal = self.started.fetch_add(1, Ordering::SeqCst) + 1;
                let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_in_flight.fetch_max(now, Ordering::SeqCst);
                // Long enough that the whole primed window is started before
                // the first call completes, so the bound is actually tested
                // (a zero-length call would never show more than 1 in flight).
                tokio::time::sleep(Duration::from_millis(5)).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                self.completed.fetch_add(1, Ordering::SeqCst);
                if self.fail_nth == Some(ordinal) {
                    Err(AppError::internal("simulated purge failure"))
                } else {
                    Ok(())
                }
            })
        }

        fn session_ip_allowlists<'a>(
            &'a self,
            _user_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<Vec<String>>, AppError>> + Send + 'a>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    fn handle(resolver: &Arc<CountingResolver>) -> SecurityResolverHandle {
        let dyn_resolver: Arc<dyn SecurityResolver> = resolver.clone();
        SecurityResolverHandle::new(dyn_resolver)
    }

    #[tokio::test]
    async fn one_hundred_members_complete_with_at_most_the_bound_in_flight() {
        let resolver = CountingResolver::new(None);
        let users: Vec<Uuid> = (0..100).map(|_| Uuid::now_v7()).collect();

        invalidate_all(&handle(&resolver), users)
            .await
            .expect("every invalidation succeeds");

        assert_eq!(resolver.completed.load(Ordering::SeqCst), 100);
        let peak = resolver.max_in_flight.load(Ordering::SeqCst);
        assert!(
            peak <= AUTHZ_INVALIDATION_MAX_IN_FLIGHT,
            "peak in-flight {peak} exceeded the bound {AUTHZ_INVALIDATION_MAX_IN_FLIGHT}"
        );
        assert!(
            peak > 1,
            "peak in-flight was {peak}: the calls never overlapped, so the bound was not exercised"
        );
    }

    #[tokio::test]
    async fn empty_membership_is_a_no_op() {
        let resolver = CountingResolver::new(None);
        invalidate_all(&handle(&resolver), Vec::new())
            .await
            .expect("nothing to invalidate is Ok");
        assert_eq!(resolver.started.load(Ordering::SeqCst), 0);
    }

    /// D-116 goal (b) preserved: one failed purge still fails the call — but
    /// only after every other member was still invalidated (drained, not
    /// abandoned on the first error).
    #[tokio::test]
    async fn a_single_failure_fails_the_call_after_draining_every_member() {
        let resolver = CountingResolver::new(Some(7));
        let users: Vec<Uuid> = (0..100).map(|_| Uuid::now_v7()).collect();

        let result = invalidate_all(&handle(&resolver), users).await;

        assert!(result.is_err(), "a failed purge must propagate as Err");
        assert_eq!(
            resolver.completed.load(Ordering::SeqCst),
            100,
            "every member must still be attempted after the failure"
        );
        assert!(resolver.max_in_flight.load(Ordering::SeqCst) <= AUTHZ_INVALIDATION_MAX_IN_FLIGHT);
    }
}

// ── Privileges ────────────────────────────────────────────────────────────────

/// Create-or-update one privilege by key. Never retired; no ownership marker
/// (the table has none) so there is no policy. Returns `(id, outcome)`.
/// `owner_layer` (Solution 7, D-785) stamps a created row only; an updated
/// row keeps its layer.
pub async fn reconcile_privilege(
    db: &DbPool,
    desc: &PrivilegeDesc,
    desired_id: Option<Uuid>,
    owner_layer: Layer,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let key = desc.key.trim();
    if key.is_empty() {
        return Err(AppError::Validation("privilege key is required".into()));
    }
    let name = if desc.name.trim().is_empty() {
        key
    } else {
        desc.name.trim()
    };
    let current: Option<(Uuid, String, Option<String>, Option<bool>)> =
        sqlx::query_as("SELECT id, name, description, is_active FROM privilege WHERE key = $1")
            .bind(key)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    match current {
        None => {
            let id = ensure_privilege_with_id(
                db,
                key,
                name,
                desc.description.as_deref().unwrap_or(""),
                desired_id,
                owner_layer,
            )
            .await?;
            Ok((id, ReconcileOutcome::Created))
        }
        Some((id, cur_name, cur_description, is_active)) => {
            let live = is_active.unwrap_or(true);
            if cur_name == name && cur_description == desc.description && live {
                return Ok((id, ReconcileOutcome::Unchanged));
            }
            let n = sqlx::query(
                "UPDATE privilege SET name = $2, description = $3, is_active = true \
                 WHERE id = $1",
            )
            .bind(id)
            .bind(name)
            .bind(&desc.description)
            .execute(db)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if n != 1 {
                return Err(AppError::Conflict(
                    "privilege row vanished during reconcile",
                ));
            }
            Ok((id, ReconcileOutcome::Updated))
        }
    }
}

// ── Field-security profiles ───────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProfileState {
    description: Option<String>,
    /// (entity, field) -> (can_read, can_update)
    fields: BTreeMap<(String, String), (bool, bool)>,
}

#[derive(sqlx::FromRow)]
struct ProfileRow {
    id: Uuid,
    description: Option<String>,
    is_customized: bool,
    is_deleted: bool,
}

async fn fetch_profile_row(db: &DbPool, name: &str) -> Result<Option<ProfileRow>, AppError> {
    sqlx::query_as(
        "SELECT id, description, is_customized, is_deleted FROM field_security_profile \
         WHERE name = $1 ORDER BY is_deleted ASC, created_at DESC, id DESC LIMIT 1",
    )
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn fetch_profile_fields(
    db: &DbPool,
    profile_id: Uuid,
) -> Result<BTreeMap<(String, String), (bool, bool)>, AppError> {
    let rows: Vec<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT entity_logicalname, field_logicalname, can_read, can_update \
         FROM field_security_profile_field WHERE profile_ref = $1",
    )
    .bind(profile_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(e, f, r, u)| ((e, f), (r, u)))
        .collect())
}

/// Create-or-update one field-security profile with its `(entity, field)`
/// members as the complete desired set. Returns `(profile_id, outcome)`.
pub async fn reconcile_field_security_profile(
    db: &DbPool,
    desc: &FieldSecurityProfileDesc,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let name = desc.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation(
            "field-security profile name is required".into(),
        ));
    }
    for f in &desc.fields {
        if f.entity.trim().is_empty() || f.field.trim().is_empty() {
            return Err(AppError::Validation(format!(
                "profile {name}: entity and field logicalnames are required on every member"
            )));
        }
    }
    let desired = ProfileState {
        description: desc.description.clone(),
        fields: desc
            .fields
            .iter()
            .map(|f| {
                (
                    (f.entity.trim().to_owned(), f.field.trim().to_owned()),
                    (f.can_read, f.can_update),
                )
            })
            .collect(),
    };

    let current = fetch_profile_row(db, name).await?;
    let cur_fields = match current.as_ref() {
        Some(row) => fetch_profile_fields(db, row.id).await?,
        None => BTreeMap::new(),
    };
    let state_differs = current.as_ref().is_some_and(|row| {
        ProfileState {
            description: row.description.clone(),
            fields: cur_fields.clone(),
        } != desired
    });
    let status = current.as_ref().map(|row| RowStatus {
        is_customized: row.is_customized,
        is_live: !row.is_deleted,
    });
    let step = decide_step(policy, status, state_differs);

    match step {
        WriteStep::Unchanged => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            Ok((id, ReconcileOutcome::Unchanged))
        }
        WriteStep::SkippedCustomized => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            tracing::info!(
                profile = %name,
                "security reconcile: seed skipped a customized field-security profile (is_customized = true)"
            );
            Ok((id, ReconcileOutcome::SkippedCustomized))
        }
        WriteStep::Create | WriteStep::Update => {
            // Same concurrency story as `reconcile_role`: the partial unique
            // index `core_field_security_profile_name_active_unique` is the
            // authority; a lost race is a `Conflict` and a re-run converges.
            let mut tx = attome_db::tx::begin(db).await?;
            let profile_id = match (step, current.as_ref()) {
                (WriteStep::Update, Some(row)) => {
                    let n = sqlx::query(
                        "UPDATE field_security_profile \
                         SET description = $2, is_deleted = false, \
                             is_customized = COALESCE($3, is_customized), \
                             updated_at = NOW(), row_version = row_version + 1 \
                         WHERE id = $1",
                    )
                    .bind(row.id)
                    .bind(&desired.description)
                    .bind(policy.customized_marker())
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?
                    .rows_affected();
                    if n != 1 {
                        return Err(AppError::Conflict(
                            "field-security profile row vanished during reconcile",
                        ));
                    }
                    row.id
                }
                _ => sqlx::query_scalar::<_, Uuid>(
                    "INSERT INTO field_security_profile \
                         (id, name, description, is_customized, owner_layer) \
                     VALUES ($1, $2, $3, $4, $5) RETURNING id",
                )
                .bind(desired_id.unwrap_or_else(Uuid::now_v7))
                .bind(name)
                .bind(&desired.description)
                .bind(policy.customized_marker().unwrap_or(false))
                .bind(policy_layer(policy).as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(map_unique_violation)?,
            };

            for ((entity, field), (can_read, can_update)) in &desired.fields {
                if cur_fields.get(&(entity.clone(), field.clone()))
                    == Some(&(*can_read, *can_update))
                {
                    continue;
                }
                // C-19: the one atomic upsert, shared with
                // `admin::field_security::set_field_profile_field`.
                upsert_profile_field(
                    &mut *tx,
                    profile_id,
                    entity,
                    field,
                    *can_read,
                    *can_update,
                    policy_layer(policy),
                )
                .await?;
            }
            for (entity, field) in cur_fields.keys() {
                if !desired
                    .fields
                    .contains_key(&(entity.clone(), field.clone()))
                {
                    // No soft-delete flag on this table (migration 0040) —
                    // see the module docs for why the extra row goes.
                    sqlx::query(
                        "DELETE FROM field_security_profile_field \
                         WHERE profile_ref = $1 AND entity_logicalname = $2 AND field_logicalname = $3",
                    )
                    .bind(profile_id)
                    .bind(entity)
                    .bind(field)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                }
            }

            tx.commit().await.map_err(AppError::internal)?;
            let outcome = step.outcome();
            tracing::info!(profile = %name, ?outcome, ?policy, "security reconcile: reconciled field-security profile");
            Ok((profile_id, outcome))
        }
    }
}

async fn set_profile_live(
    db: &DbPool,
    name: &str,
    live: bool,
) -> Result<ReconcileOutcome, AppError> {
    let candidate: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM field_security_profile WHERE name = $1 AND is_deleted = $2 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .bind(name)
    .bind(live)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(profile_id) = candidate else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    let n = sqlx::query(
        "UPDATE field_security_profile \
         SET is_deleted = $2, updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = $3",
    )
    .bind(profile_id)
    .bind(!live)
    .bind(live)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    tracing::info!(profile = %name, live, "security reconcile: field-security profile lifecycle flag changed");
    Ok(ReconcileOutcome::Updated)
}

/// Soft-retire (`is_deleted = true`) a field-security profile by name.
/// Idempotent; the member rows and role links are kept so reactivation is
/// lossless (`resolve_field_access` joins through the profile row, so a
/// retired profile grants nothing in the meantime).
pub async fn retire_field_security_profile(
    db: &DbPool,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_profile_live(db, name, false).await
}

/// Reactivate a previously retired field-security profile by name. Idempotent.
pub async fn reactivate_field_security_profile(
    db: &DbPool,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    set_profile_live(db, name, true).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_stamp_platform_and_every_other_write_project() {
        assert_eq!(policy_layer(ReconcilePolicy::Seed), Layer::Platform);
        assert_eq!(policy_layer(ReconcilePolicy::Admin), Layer::Project);
        assert_eq!(
            policy_layer(ReconcilePolicy::Bundle {
                is_customized: true
            }),
            Layer::Project
        );
    }

    fn row(is_customized: bool, is_live: bool) -> Option<RowStatus> {
        Some(RowStatus {
            is_customized,
            is_live,
        })
    }

    #[test]
    fn seed_skips_customized_rows_before_anything_else() {
        assert_eq!(
            decide_step(ReconcilePolicy::Seed, row(true, true), true),
            WriteStep::SkippedCustomized
        );
        assert_eq!(
            decide_step(ReconcilePolicy::Seed, row(true, false), true),
            WriteStep::SkippedCustomized
        );
        assert_eq!(
            decide_step(ReconcilePolicy::Seed, row(false, true), false),
            WriteStep::Unchanged
        );
        assert_eq!(
            decide_step(ReconcilePolicy::Seed, row(false, true), true),
            WriteStep::Update
        );
    }

    #[test]
    fn admin_marks_and_bundle_carries_the_marker() {
        // Admin on an uncustomized, otherwise-identical row: the marker differs.
        assert_eq!(
            decide_step(ReconcilePolicy::Admin, row(false, true), false),
            WriteStep::Update
        );
        assert_eq!(
            decide_step(ReconcilePolicy::Admin, row(true, true), false),
            WriteStep::Unchanged
        );
        assert_eq!(
            decide_step(
                ReconcilePolicy::Bundle {
                    is_customized: false
                },
                row(true, true),
                false
            ),
            WriteStep::Update
        );
        assert_eq!(
            decide_step(
                ReconcilePolicy::Bundle {
                    is_customized: false
                },
                row(false, true),
                false
            ),
            WriteStep::Unchanged
        );
    }

    #[test]
    fn missing_row_creates_and_retired_row_updates() {
        assert_eq!(
            decide_step(ReconcilePolicy::Seed, None, false),
            WriteStep::Create
        );
        assert_eq!(
            decide_step(ReconcilePolicy::Seed, row(false, false), false),
            WriteStep::Update
        );
    }

    #[test]
    fn condition_validation_enforces_cap_and_shapes() {
        let ok = GrantConditionDesc {
            field: "status".into(),
            operator: 0,
            value: serde_json::json!("open"),
        };
        assert!(validate_conditions("x.read", &vec![ok.clone(); 3]).is_ok());
        assert!(validate_conditions("x.read", &vec![ok.clone(); 4]).is_err());
        let bad_op = GrantConditionDesc {
            operator: 42,
            ..ok.clone()
        };
        assert!(validate_conditions("x.read", std::slice::from_ref(&bad_op)).is_err());
        let in_not_array = GrantConditionDesc {
            operator: 6,
            ..ok.clone()
        };
        assert!(validate_conditions("x.read", std::slice::from_ref(&in_not_array)).is_err());
        let eq_array = GrantConditionDesc {
            value: serde_json::json!(["a"]),
            ..ok
        };
        assert!(validate_conditions("x.read", std::slice::from_ref(&eq_array)).is_err());
    }
}

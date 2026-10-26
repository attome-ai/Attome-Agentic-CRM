//! Q10-T5: permission sets as desired state, the shared writes the admin
//! routes and the bundle/changeset apply both use, and the cache fan-out
//! after a change. Q10-T4 (`crate::db`) is how a set counts at runtime.
//!
//! A set is configuration, recorded and promoted like a role (D-785): its
//! row, its entity access rows and its privilege grants. Its assignments to
//! users and teams are environment data, like a user's roles, and never
//! travel. A set never carries system administration: every write refuses
//! `system.admin` with `set_cannot_grant_admin`, and the resolver filters it
//! out as well.

use std::collections::{BTreeMap, BTreeSet};

use attome_core::changeset::Layer;
pub use attome_core::reconcile::{ReconcileOutcome, ReconcilePolicy};
use attome_core::reconcile::{RowStatus, WriteStep, decide_step};
use attome_db::DbPool;
use attome_server::security::SecurityResolverHandle;
use attome_types::AppError;
use uuid::Uuid;

/// The privilege a set may never grant.
pub const ADMIN_PRIVILEGE: &str = "system.admin";

/// The levels of one entity in a set, as `permission_set_entity_access`
/// stores them (the same columns as a role's, Q10-T1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetLevels {
    pub read: i16,
    pub write: i16,
    pub delete: i16,
    pub create: Option<i16>,
    pub assign: Option<i16>,
    pub share: Option<i16>,
    pub export: i16,
    pub bulk: i16,
    pub read_bu_children: bool,
    pub write_bu_children: bool,
    pub delete_bu_children: bool,
    pub assign_bu_children: bool,
    pub share_bu_children: bool,
}

impl Default for SetLevels {
    /// The table's defaults: Global for read, write and delete, the write
    /// level for create, assign and share, nothing for export and bulk, and
    /// child units included.
    fn default() -> Self {
        Self {
            read: 3,
            write: 3,
            delete: 3,
            create: None,
            assign: None,
            share: None,
            export: 0,
            bulk: 0,
            read_bu_children: true,
            write_bu_children: true,
            delete_bu_children: true,
            assign_bu_children: true,
            share_bu_children: true,
        }
    }
}

impl SetLevels {
    /// Every level in 0..=3.
    pub fn validate(&self) -> Result<(), AppError> {
        let levels = [self.read, self.write, self.delete, self.export, self.bulk]
            .into_iter()
            .chain([self.create, self.assign, self.share].into_iter().flatten());
        for level in levels {
            if !(0..=3).contains(&level) {
                return Err(AppError::Validation(
                    "access level must be 0 (None), 1 (Team), 2 (BusinessUnit), or 3 (Global)"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// A set as desired state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionSetDesc {
    pub name: String,
    pub name_ar: Option<String>,
    pub description: Option<String>,
    /// Privilege keys.
    pub privileges: Vec<String>,
    /// Levels per entity logical name.
    pub entity_access: Vec<(String, SetLevels)>,
}

/// Refuses system administration in a set.
pub fn refuse_admin(privilege_key: &str) -> Result<(), AppError> {
    if privilege_key == ADMIN_PRIVILEGE {
        return Err(AppError::Validation(
            "set_cannot_grant_admin: a permission set cannot grant system administration".into(),
        ));
    }
    Ok(())
}

/// Upserts one entity's levels in a set (live again if it was cleared).
pub async fn upsert_set_entity_access<'c, E>(
    db: E,
    set_id: Uuid,
    entity_ref: Uuid,
    levels: &SetLevels,
    owner_layer: Layer,
) -> Result<Uuid, AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    levels.validate()?;
    sqlx::query_scalar(
        "INSERT INTO permission_set_entity_access \
             (set_ref, entity_ref, read_access_level, write_access_level, delete_access_level, \
              create_access_level, assign_access_level, share_access_level, \
              export_access_level, bulk_access_level, read_bu_children, write_bu_children, \
              delete_bu_children, assign_bu_children, share_bu_children, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
         ON CONFLICT (set_ref, entity_ref) DO UPDATE SET \
             read_access_level = EXCLUDED.read_access_level, \
             write_access_level = EXCLUDED.write_access_level, \
             delete_access_level = EXCLUDED.delete_access_level, \
             create_access_level = EXCLUDED.create_access_level, \
             assign_access_level = EXCLUDED.assign_access_level, \
             share_access_level = EXCLUDED.share_access_level, \
             export_access_level = EXCLUDED.export_access_level, \
             bulk_access_level = EXCLUDED.bulk_access_level, \
             read_bu_children = EXCLUDED.read_bu_children, \
             write_bu_children = EXCLUDED.write_bu_children, \
             delete_bu_children = EXCLUDED.delete_bu_children, \
             assign_bu_children = EXCLUDED.assign_bu_children, \
             share_bu_children = EXCLUDED.share_bu_children, \
             is_deleted = false, updated_at = NOW(), \
             row_version = permission_set_entity_access.row_version + 1 \
         RETURNING id",
    )
    .bind(set_id)
    .bind(entity_ref)
    .bind(levels.read)
    .bind(levels.write)
    .bind(levels.delete)
    .bind(levels.create)
    .bind(levels.assign)
    .bind(levels.share)
    .bind(levels.export)
    .bind(levels.bulk)
    .bind(levels.read_bu_children)
    .bind(levels.write_bu_children)
    .bind(levels.delete_bu_children)
    .bind(levels.assign_bu_children)
    .bind(levels.share_bu_children)
    .bind(owner_layer.as_str())
    .fetch_one(db)
    .await
    .map_err(attome_db::classify)
}

/// Grants (`granted`) or revokes one privilege in a set. Idempotent; the
/// number of rows changed.
pub async fn set_set_privilege<'c, E>(
    db: E,
    set_id: Uuid,
    privilege_id: Uuid,
    granted: bool,
    owner_layer: Layer,
) -> Result<u64, AppError>
where
    E: sqlx::PgExecutor<'c>,
{
    let result = if granted {
        sqlx::query(
            "INSERT INTO permission_set_privilege (set_ref, privilege_ref, owner_layer) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (set_ref, privilege_ref) DO UPDATE SET is_deleted = false \
             WHERE permission_set_privilege.is_deleted",
        )
        .bind(set_id)
        .bind(privilege_id)
        .bind(owner_layer.as_str())
        .execute(db)
        .await
    } else {
        sqlx::query(
            "UPDATE permission_set_privilege SET is_deleted = true \
             WHERE set_ref = $1 AND privilege_ref = $2 AND is_deleted = false",
        )
        .bind(set_id)
        .bind(privilege_id)
        .execute(db)
        .await
    };
    result
        .map(|r| r.rows_affected())
        .map_err(attome_db::classify)
}

/// The live set named `name`: id, layer, row version.
pub async fn live_set(
    db: impl sqlx::PgExecutor<'_>,
    name: &str,
) -> Result<Option<(Uuid, String, i64)>, AppError> {
    sqlx::query_as(
        "SELECT id, owner_layer, row_version FROM permission_set \
         WHERE lower(name) = lower($1) AND is_deleted = false",
    )
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

#[derive(sqlx::FromRow)]
struct SetRow {
    id: Uuid,
    name_ar: Option<String>,
    description: Option<String>,
    is_customized: bool,
    is_deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SetState {
    name_ar: Option<String>,
    description: Option<String>,
    privileges: BTreeSet<String>,
    entity_access: BTreeMap<String, SetLevels>,
}

type LevelRow = (
    String,
    i16,
    i16,
    i16,
    Option<i16>,
    Option<i16>,
    Option<i16>,
    i16,
    i16,
    bool,
    bool,
    bool,
    bool,
    bool,
);

async fn current_state(
    db: &DbPool,
    set_id: Uuid,
) -> Result<(BTreeSet<String>, BTreeMap<String, SetLevels>), AppError> {
    let privileges: Vec<String> = sqlx::query_scalar(
        "SELECT p.key FROM permission_set_privilege sp \
         JOIN privilege p ON p.id = sp.privilege_ref \
         WHERE sp.set_ref = $1 AND sp.is_deleted = false",
    )
    .bind(set_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<LevelRow> = sqlx::query_as(
        "SELECT ei.logicalname, ea.read_access_level, ea.write_access_level, \
                ea.delete_access_level, ea.create_access_level, ea.assign_access_level, \
                ea.share_access_level, ea.export_access_level, ea.bulk_access_level, \
                ea.read_bu_children, ea.write_bu_children, ea.delete_bu_children, \
                ea.assign_bu_children, ea.share_bu_children \
         FROM permission_set_entity_access ea \
         JOIN entity_info ei ON ei.id = ea.entity_ref \
         WHERE ea.set_ref = $1 AND ea.is_deleted = false",
    )
    .bind(set_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok((
        privileges.into_iter().collect(),
        rows.into_iter().map(levels_from_row).collect(),
    ))
}

fn levels_from_row(row: LevelRow) -> (String, SetLevels) {
    let (entity, read, write, delete, create, assign, share, export, bulk, rc, wc, dc, ac, sc) =
        row;
    (
        entity,
        SetLevels {
            read,
            write,
            delete,
            create,
            assign,
            share,
            export,
            bulk,
            read_bu_children: rc,
            write_bu_children: wc,
            delete_bu_children: dc,
            assign_bu_children: ac,
            share_bu_children: sc,
        },
    )
}

/// A set row as the export reads it: id, name, Arabic name, description,
/// customized.
type ExportRow = (Uuid, String, Option<String>, Option<String>, bool);

/// Every live set with its privileges and levels, for the bundle export.
pub async fn export_sets(db: &DbPool) -> Result<Vec<(PermissionSetDesc, bool)>, AppError> {
    let rows: Vec<ExportRow> = sqlx::query_as(
        "SELECT id, name, name_ar, description, is_customized FROM permission_set \
         WHERE is_deleted = false ORDER BY lower(name)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, name, name_ar, description, is_customized) in rows {
        let (privileges, entity_access) = current_state(db, id).await?;
        out.push((
            PermissionSetDesc {
                name,
                name_ar,
                description,
                privileges: privileges.into_iter().collect(),
                entity_access: entity_access.into_iter().collect(),
            },
            is_customized,
        ));
    }
    Ok(out)
}

fn policy_layer(policy: ReconcilePolicy) -> Layer {
    match policy {
        ReconcilePolicy::Seed => Layer::Platform,
        ReconcilePolicy::Admin | ReconcilePolicy::Bundle { .. } => Layer::Project,
    }
}

/// Brings the set named in `desc` to that state: its row, its privileges
/// (set semantics: keys not listed are revoked) and its entity access rows
/// (entities not listed are cleared). A privilege or entity the target does
/// not have is a `Validation`. A customized set is left alone under a seed
/// policy, as a role is.
pub async fn reconcile_permission_set(
    db: &DbPool,
    desc: &PermissionSetDesc,
    policy: ReconcilePolicy,
    desired_id: Option<Uuid>,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let name = desc.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation(
            "permission set name is required".into(),
        ));
    }
    for key in &desc.privileges {
        refuse_admin(key)?;
    }
    for (_, levels) in &desc.entity_access {
        levels.validate()?;
    }
    let desired = SetState {
        name_ar: desc.name_ar.clone(),
        description: desc.description.clone(),
        privileges: desc.privileges.iter().cloned().collect(),
        entity_access: desc.entity_access.iter().cloned().collect(),
    };

    let current: Option<SetRow> = sqlx::query_as(
        "SELECT id, name_ar, description, is_customized, is_deleted FROM permission_set \
         WHERE lower(name) = lower($1) ORDER BY is_deleted ASC, created_at DESC, id DESC LIMIT 1",
    )
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (cur_privileges, cur_access) = match current.as_ref() {
        Some(row) => current_state(db, row.id).await?,
        None => (BTreeSet::new(), BTreeMap::new()),
    };
    let state_differs = current.as_ref().is_some_and(|row| {
        SetState {
            name_ar: row.name_ar.clone(),
            description: row.description.clone(),
            privileges: cur_privileges.clone(),
            entity_access: cur_access.clone(),
        } != desired
    });
    let status = current.as_ref().map(|row| RowStatus {
        is_customized: row.is_customized,
        is_live: !row.is_deleted,
    });
    let step = decide_step(policy, status, state_differs);
    let layer = policy_layer(policy);
    match step {
        WriteStep::Unchanged => Ok((
            current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?,
            ReconcileOutcome::Unchanged,
        )),
        WriteStep::SkippedCustomized => Ok((
            current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?,
            ReconcileOutcome::SkippedCustomized,
        )),
        WriteStep::Create | WriteStep::Update => {
            let mut tx = attome_db::tx::begin(db).await?;
            let set_id = match (step, current.as_ref()) {
                (WriteStep::Update, Some(row)) => {
                    sqlx::query(
                        "UPDATE permission_set SET name_ar = $2, description = $3, \
                             is_deleted = false, is_customized = COALESCE($4, is_customized), \
                             updated_at = NOW(), row_version = row_version + 1 \
                         WHERE id = $1",
                    )
                    .bind(row.id)
                    .bind(&desired.name_ar)
                    .bind(&desired.description)
                    .bind(policy.customized_marker())
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                    row.id
                }
                _ => sqlx::query_scalar(
                    "INSERT INTO permission_set \
                         (id, name, name_ar, description, is_customized, owner_layer) \
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                )
                .bind(desired_id.unwrap_or_else(Uuid::now_v7))
                .bind(name)
                .bind(&desired.name_ar)
                .bind(&desired.description)
                .bind(policy.customized_marker().unwrap_or(false))
                .bind(layer.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| {
                    if attome_db::is_unique_violation(&e) {
                        AppError::Conflict("a concurrent write created this set first; retry")
                    } else {
                        AppError::internal(e)
                    }
                })?,
            };
            for key in desired.privileges.symmetric_difference(&cur_privileges) {
                let privilege_id: Uuid = sqlx::query_scalar(
                    "SELECT id FROM privilege WHERE key = $1 AND is_active = true",
                )
                .bind(key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::internal)?
                .ok_or_else(|| {
                    AppError::Validation(format!("permission set {name}: no privilege {key}"))
                })?;
                let granted = desired.privileges.contains(key);
                set_set_privilege(&mut *tx, set_id, privilege_id, granted, layer).await?;
            }
            for (entity, levels) in &desired.entity_access {
                if cur_access.get(entity) == Some(levels) {
                    continue;
                }
                let entity_ref: Uuid =
                    sqlx::query_scalar("SELECT id FROM entity_info WHERE logicalname = $1")
                        .bind(entity)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(AppError::internal)?
                        .ok_or_else(|| {
                            AppError::Validation(format!(
                                "permission set {name}: no entity {entity}"
                            ))
                        })?;
                upsert_set_entity_access(&mut *tx, set_id, entity_ref, levels, layer).await?;
            }
            for entity in cur_access.keys() {
                if !desired.entity_access.contains_key(entity) {
                    sqlx::query(
                        "UPDATE permission_set_entity_access ea SET is_deleted = true, \
                             updated_at = NOW(), row_version = ea.row_version + 1 \
                         FROM entity_info ei \
                         WHERE ea.set_ref = $1 AND ea.entity_ref = ei.id AND ei.logicalname = $2",
                    )
                    .bind(set_id)
                    .bind(entity)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
                }
            }
            tx.commit().await.map_err(AppError::internal)?;
            let outcome = step.outcome();
            tracing::info!(set = %name, ?outcome, ?policy, "security reconcile: reconciled permission set");
            Ok((set_id, outcome))
        }
    }
}

/// Retires the live set named `name` and ends its assignments. Idempotent.
pub async fn retire_permission_set(db: &DbPool, name: &str) -> Result<ReconcileOutcome, AppError> {
    let Some((set_id, _, _)) = live_set(db, name).await? else {
        return Ok(ReconcileOutcome::Unchanged);
    };
    let mut tx = attome_db::tx::begin(db).await?;
    retire_in_tx(&mut tx, set_id).await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(ReconcileOutcome::Updated)
}

/// The retire write itself, in the caller's transaction.
pub async fn retire_in_tx(tx: &mut sqlx::PgConnection, set_id: Uuid) -> Result<u64, AppError> {
    let n = sqlx::query(
        "UPDATE permission_set SET is_deleted = true, updated_at = NOW(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(set_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    sqlx::query(
        "UPDATE permission_set_assignment SET is_deleted = true \
         WHERE set_ref = $1 AND is_deleted = false",
    )
    .bind(set_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    Ok(n)
}

/// The users a set reaches: assigned directly or through a team.
pub async fn set_holders(db: &DbPool, set_id: Uuid) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT a.user_ref FROM permission_set_assignment a \
         WHERE a.set_ref = $1 AND a.user_ref IS NOT NULL \
         UNION \
         SELECT ut.user_ref FROM permission_set_assignment a \
         JOIN user_account_mm_team ut ON ut.team_ref = a.team_ref AND ut.is_deleted = false \
         WHERE a.set_ref = $1",
    )
    .bind(set_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Every user a set reaches gets a fresh security context, so a change to
/// the set (or its retirement) applies on their next request. Ended and
/// removed assignments are included: they lose what the set gave.
pub async fn invalidate_set_holders(
    db: &DbPool,
    security: &SecurityResolverHandle,
    set_id: Uuid,
) -> Result<(), AppError> {
    let users = set_holders(db, set_id).await?;
    crate::reconcile::invalidate_all(security, users).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_refuses_system_admin_and_bad_levels() {
        assert!(refuse_admin("account.read").is_ok());
        let err = refuse_admin(ADMIN_PRIVILEGE).unwrap_err();
        assert!(matches!(err, AppError::Validation(m) if m.starts_with("set_cannot_grant_admin")));
        assert!(SetLevels::default().validate().is_ok());
        assert!(
            SetLevels {
                export: 4,
                ..SetLevels::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            SetLevels {
                assign: Some(-1),
                ..SetLevels::default()
            }
            .validate()
            .is_err()
        );
    }
}

//! Q4-T1: the roles an LDAP directory's groups give, applied at each
//! directory sign-in.
//!
//! `auth.ldap.group_roles` names the role each group gives. At sign-in the
//! person gets the roles their groups give, and loses the ones the directory
//! gave earlier (`user_account_mm_role.source_directory`) that their groups
//! no longer give. A role an administrator gave is never touched, and an
//! administrator's grant of a role the directory gave takes it over.
//!
//! The same limits as a sign-in provider's group mappings
//! ([`crate::oidc_mapping`]): never a role carrying `system.admin`, never a
//! break-glass or reserved service account, never a grant a conflict rule
//! refuses. Everything runs in the caller's transaction, one security event
//! per change.

use std::collections::BTreeSet;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, AuditService};
use attome_types::AppError;
use uuid::Uuid;

use crate::oidc_mapping::{MappingChanges, plan, role_grants_admin};

fn event(operation: AuditOperation, user_id: Uuid, role: Uuid) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Access,
        operation,
        user_id,
        "user_account_mm_role",
        Some(role),
    )
    .named(format!(
        "{} by directory group mapping",
        if operation == AuditOperation::Grant {
            "granted"
        } else {
            "revoked"
        }
    ))
}

/// Gives `user_id` the live roles named in `role_names` and takes back the
/// directory's earlier roles they no longer name, in `tx`. A name with no
/// live role is skipped with a warning. The caller drops the person's cached
/// security context after the commit when anything changed.
pub async fn apply_directory_roles_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    audit: &AuditService<'_>,
    user_id: Uuid,
    role_names: &[String],
) -> Result<MappingChanges, AppError> {
    let mut changes = MappingChanges::default();
    if crate::oidc_mapping::exempt(tx, user_id).await? {
        return Ok(changes);
    }
    let found: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, name FROM role WHERE name = ANY($1) AND is_deleted = false")
            .bind(role_names)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    for name in role_names {
        if !found.iter().any(|(_, found)| found == name) {
            tracing::warn!(role = %name, "directory mapping: auth.ldap.group_roles names no live role");
        }
    }
    let mut wanted = BTreeSet::new();
    for (role, name) in found {
        if role_grants_admin(tx, role).await? {
            tracing::warn!(role = %name, "directory mapping: a system administration role is never given by a group");
            continue;
        }
        wanted.insert(role);
    }

    let held: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT role_ref FROM user_account_mm_role \
          WHERE user_ref = $1 AND source_directory AND NOT is_deleted",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let (add, remove) = plan(&wanted, &held);
    for role in add {
        if let crate::conflicts::ConflictOutcome::Refuse(_)
        | crate::conflicts::ConflictOutcome::NeedsApproval(_) =
            crate::conflicts::check_grant(tx, user_id, crate::conflicts::GrantRef::Role(role))
                .await?
        {
            tracing::warn!(%user_id, %role, "directory mapping: a conflict rule stops this role");
            continue;
        }
        // A live membership the directory did not give stays as it is; a
        // removed one is brought back as the directory's.
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO user_account_mm_role (id, user_ref, role_ref, source_directory) \
             VALUES ($1, $2, $3, true) \
             ON CONFLICT (user_ref, role_ref) DO UPDATE \
                 SET is_deleted = false, source_directory = true, source_provider_ref = NULL, \
                     valid_until = NULL, updated_at = now() \
               WHERE user_account_mm_role.is_deleted \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if id.is_some() {
            write_security_event(tx, audit, event(AuditOperation::Grant, user_id, role)).await?;
            changes.roles_added.push(role);
        }
    }
    for role in remove {
        let n = sqlx::query(
            "UPDATE user_account_mm_role SET is_deleted = true, updated_at = now() \
              WHERE user_ref = $1 AND role_ref = $2 AND source_directory AND NOT is_deleted",
        )
        .bind(user_id)
        .bind(role)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if n > 0 {
            write_security_event(tx, audit, event(AuditOperation::Revoke, user_id, role)).await?;
            changes.roles_removed.push(role);
        }
    }
    Ok(changes)
}

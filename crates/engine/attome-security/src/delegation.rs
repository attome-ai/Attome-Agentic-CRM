//! Q12-T2: delegated administration. An administration area
//! (`attome_server::authz::AdminArea`) lets a person administer part of the
//! deployment without `system.admin`; [`require_not_above`] stops them using
//! it on someone who holds `system.admin`.

use attome_types::AppError;
use uuid::Uuid;

/// Whether `user_id` holds `system.admin`, directly or through a role or team.
pub async fn holds_system_admin(db: &attome_db::DbPool, user_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM user_account_mm_privilege up
               JOIN privilege p ON p.id = up.privilege_ref AND p.is_active
              WHERE up.user_ref = $1 AND up.is_active AND p.key = $2
             UNION ALL
             SELECT 1 FROM role_mm_privilege rp
               JOIN privilege p ON p.id = rp.privilege_ref AND p.is_active
              WHERE NOT rp.is_deleted AND p.key = $2
                AND rp.role_ref IN (
                    SELECT ur.role_ref FROM user_account_mm_role ur
                     WHERE ur.user_ref = $1 AND NOT ur.is_deleted
                    UNION
                    SELECT rt.role_ref FROM user_account_mm_team ut
                      JOIN role_mm_team rt ON rt.team_ref = ut.team_ref AND NOT rt.is_deleted
                     WHERE ut.user_ref = $1 AND NOT ut.is_deleted))",
    )
    .bind(user_id)
    .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Q12-T2: a delegated administrator, who holds an administration area but
/// not `system.admin`, never acts on a person who holds `system.admin`
/// (disabling, re-enabling, resetting second factors, linking identities,
/// removing roles and privileges, break-glass), so an area cannot be used to
/// take over or demote a full administrator. Forbidden when they would.
pub async fn require_not_above(
    db: &attome_db::DbPool,
    actor: &attome_server::security::SecurityContext,
    target: Uuid,
) -> Result<(), AppError> {
    if actor.is_admin || !holds_system_admin(db, target).await? {
        return Ok(());
    }
    tracing::warn!(
        actor = %actor.user_id,
        %target,
        "delegated administrator refused: the person holds system.admin"
    );
    Err(AppError::Forbidden)
}

//! Q12-T3: the grant ceiling. A delegated administrator (Q12 areas) cannot
//! grant more than they hold: a role whose privileges they lack cannot be
//! assigned to a user or a team by them, and a privilege they lack cannot be
//! given to a role or a user by them. `system.admin` holds every privilege,
//! so a full administrator is never refused.
//!
//! The second pair of eyes for role grants is the existing approval gate
//! (`approval.required_actions` naming `ACTION_ROLE_GRANT`, D-195): when it
//! is configured a grant waits for a different administrator's approval, and
//! the ceiling is checked before the request is submitted.

use attome_db::DbPool;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use uuid::Uuid;

/// The privileges in `privileges` that `granter` does not hold. Pure.
pub fn beyond_ceiling(granter: &SecurityContext, privileges: &[String]) -> Vec<String> {
    if granter.is_admin {
        return Vec::new();
    }
    let mut out: Vec<String> = privileges
        .iter()
        .filter(|p| !granter.privileges.contains(p.as_str()))
        .cloned()
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The live privileges a role carries.
pub async fn role_privileges(db: &DbPool, role: Uuid) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT p.key FROM role_mm_privilege rp JOIN privilege p ON p.id = rp.privilege_ref \
          WHERE rp.role_ref = $1 AND rp.is_deleted = false AND p.is_active = true \
          ORDER BY p.key",
    )
    .bind(role)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

fn refused(missing: &[String]) -> AppError {
    tracing::info!(
        missing = %missing.join(", "),
        "grant refused: beyond the granter's own privileges"
    );
    AppError::Forbidden
}

/// `granter` may hand out `role`: they hold every privilege it carries.
pub async fn require_role_within_ceiling(
    db: &DbPool,
    granter: &SecurityContext,
    role: Uuid,
) -> Result<(), AppError> {
    if granter.is_admin {
        return Ok(());
    }
    let missing = beyond_ceiling(granter, &role_privileges(db, role).await?);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(refused(&missing))
    }
}

/// `granter` may hand out the privilege `key`.
pub fn require_privilege_within_ceiling(
    granter: &SecurityContext,
    key: &str,
) -> Result<(), AppError> {
    let missing = beyond_ceiling(granter, &[key.to_owned()]);
    if missing.is_empty() {
        Ok(())
    } else {
        Err(refused(&missing))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    fn ctx(is_admin: bool, privileges: &[&str]) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
            privileges: privileges.iter().map(|p| (*p).to_owned()).collect(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    #[test]
    fn grant_ceiling_refuses_what_the_granter_lacks() {
        let delegate = ctx(false, &["admin.roles", "account.read", "contact.read"]);
        let role = vec![
            "account.read".to_owned(),
            "account.update".to_owned(),
            "system.admin".to_owned(),
        ];
        assert_eq!(
            beyond_ceiling(&delegate, &role),
            vec!["account.update".to_owned(), "system.admin".to_owned()]
        );
        assert!(beyond_ceiling(&delegate, &["contact.read".to_owned()]).is_empty());
        assert!(matches!(
            require_privilege_within_ceiling(&delegate, "system.admin"),
            Err(AppError::Forbidden)
        ));
        assert!(require_privilege_within_ceiling(&delegate, "account.read").is_ok());
    }

    #[test]
    fn grant_ceiling_never_refuses_a_full_administrator() {
        let admin = ctx(true, &[]);
        assert!(beyond_ceiling(&admin, &["anything.at_all".to_owned()]).is_empty());
        assert!(require_privilege_within_ceiling(&admin, "system.admin").is_ok());
    }
}

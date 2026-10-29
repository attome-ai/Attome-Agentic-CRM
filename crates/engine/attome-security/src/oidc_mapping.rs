//! Q1-T9: a sign-in provider's group mappings and profile claims, applied at
//! each sign-in through it.
//!
//! A provider added on screen maps the values of its groups claim to teams
//! and roles (`oidc_group_mapping`). At sign-in the person gets the teams and
//! roles their groups map to, and loses the ones this provider added earlier
//! (`source_provider_ref`) that their groups no longer map to. A membership
//! an administrator gave has no `source_provider_ref` and is never touched,
//! and an administrator's grant of a role the provider added clears the
//! column and takes it over (the tables are unique per person and role).
//!
//! Never system administration: a role carrying `system.admin`, or a team
//! with such a role, is refused when the mapping is made and skipped again
//! here, since a role's privileges may change after. Break-glass and
//! reserved service accounts are left alone. A grant a refusing conflict
//! rule forbids is skipped. Everything runs in the caller's transaction, one
//! security event per change.

use std::collections::BTreeSet;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, AuditService};
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// The memberships one sign-in changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MappingChanges {
    pub roles_added: Vec<Uuid>,
    pub roles_removed: Vec<Uuid>,
    pub teams_added: Vec<Uuid>,
    pub teams_removed: Vec<Uuid>,
}

impl MappingChanges {
    pub fn is_empty(&self) -> bool {
        self.roles_added.is_empty()
            && self.roles_removed.is_empty()
            && self.teams_added.is_empty()
            && self.teams_removed.is_empty()
    }
}

/// The group values in `claims` under the claim `claim_map.groups` names
/// (`groups` by default): an array of strings, or one string. Pure.
pub fn groups_of(claims: &Value, claim_map: &Value) -> Vec<String> {
    let claim = claim_map
        .get("groups")
        .and_then(Value::as_str)
        .unwrap_or("groups");
    match claims.get(claim) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(one)) => vec![one.clone()],
        _ => Vec::new(),
    }
}

/// What to add and what to remove: `wanted` minus `held`, and the
/// provider-added `held` that are no longer `wanted`. Pure.
pub fn plan(wanted: &BTreeSet<Uuid>, provider_held: &BTreeSet<Uuid>) -> (Vec<Uuid>, Vec<Uuid>) {
    (
        wanted.difference(provider_held).copied().collect(),
        provider_held.difference(wanted).copied().collect(),
    )
}

/// Whether `role` carries `system.admin`.
pub async fn role_grants_admin(
    conn: &mut sqlx::PgConnection,
    role: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM role_mm_privilege rp \
                          JOIN privilege p ON p.id = rp.privilege_ref \
                         WHERE rp.role_ref = $1 AND NOT rp.is_deleted AND p.key = $2)",
    )
    .bind(role)
    .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)
}

/// Whether a member of `team` gets `system.admin` through the team's roles.
pub async fn team_grants_admin(
    conn: &mut sqlx::PgConnection,
    team: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM role_mm_team rt \
                          JOIN role_mm_privilege rp ON rp.role_ref = rt.role_ref AND NOT rp.is_deleted \
                          JOIN privilege p ON p.id = rp.privilege_ref \
                         WHERE rt.team_ref = $1 AND NOT rt.is_deleted AND p.key = $2)",
    )
    .bind(team)
    .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)
}

/// Whether the mappings leave `user_id` alone: a break-glass account, or a
/// reserved service account.
pub(crate) async fn exempt(tx: &mut sqlx::PgConnection, user_id: Uuid) -> Result<bool, AppError> {
    let (break_glass, email): (bool, Option<String>) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM break_glass_account WHERE user_ref = $1), \
                (SELECT email FROM user_account WHERE id = $1)",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    Ok(break_glass
        || email
            .as_deref()
            .is_some_and(crate::accounts::is_reserved_service_email))
}

fn event(
    operation: AuditOperation,
    entity: &'static str,
    user_id: Uuid,
    target: Uuid,
    provider_key: &str,
) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Access,
        operation,
        user_id,
        entity,
        Some(target),
    )
    .named(format!(
        "{} by sign-in provider {provider_key} group mapping",
        if operation == AuditOperation::Grant {
            "granted"
        } else {
            "revoked"
        }
    ))
}

/// Applies `provider_id`'s group mappings for `groups` to `user_id` in `tx`,
/// writing one `Access` event per change. The caller drops the person's
/// cached security context after the commit when anything changed.
pub async fn apply_mappings_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    audit: &AuditService<'_>,
    provider_id: Uuid,
    provider_key: &str,
    user_id: Uuid,
    groups: &[String],
) -> Result<MappingChanges, AppError> {
    let mut changes = MappingChanges::default();
    if exempt(tx, user_id).await? {
        return Ok(changes);
    }
    let mapped: Vec<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT team_ref, role_ref FROM oidc_group_mapping \
          WHERE provider_ref = $1 AND claim_value = ANY($2)",
    )
    .bind(provider_id)
    .bind(groups)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let mut wanted_roles = BTreeSet::new();
    let mut wanted_teams = BTreeSet::new();
    for (team, role) in mapped {
        if let Some(role) = role
            && !role_grants_admin(tx, role).await?
        {
            wanted_roles.insert(role);
        }
        if let Some(team) = team
            && !team_grants_admin(tx, team).await?
        {
            wanted_teams.insert(team);
        }
    }

    // Roles.
    let held: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT role_ref FROM user_account_mm_role \
          WHERE user_ref = $1 AND source_provider_ref = $2 AND NOT is_deleted",
    )
    .bind(user_id)
    .bind(provider_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let (add, remove) = plan(&wanted_roles, &held);
    for role in add {
        if let crate::conflicts::ConflictOutcome::Refuse(_)
        | crate::conflicts::ConflictOutcome::NeedsApproval(_) =
            crate::conflicts::check_grant(tx, user_id, crate::conflicts::GrantRef::Role(role))
                .await?
        {
            tracing::warn!(%user_id, %role, provider = provider_key, "oidc mapping: a conflict rule stops this role");
            continue;
        }
        // A live membership the provider did not add stays as it is; a
        // removed one is brought back as the provider's.
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO user_account_mm_role (id, user_ref, role_ref, source_provider_ref) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_ref, role_ref) DO UPDATE \
                 SET is_deleted = false, source_provider_ref = EXCLUDED.source_provider_ref, \
                     source_directory = false, valid_until = NULL, updated_at = now() \
               WHERE user_account_mm_role.is_deleted \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(role)
        .bind(provider_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if id.is_some() {
            write_security_event(
                tx,
                audit,
                event(
                    AuditOperation::Grant,
                    "user_account_mm_role",
                    user_id,
                    role,
                    provider_key,
                ),
            )
            .await?;
            changes.roles_added.push(role);
        }
    }
    for role in remove {
        let n = sqlx::query(
            "UPDATE user_account_mm_role SET is_deleted = true, updated_at = now() \
              WHERE user_ref = $1 AND role_ref = $2 AND source_provider_ref = $3 AND NOT is_deleted",
        )
        .bind(user_id)
        .bind(role)
        .bind(provider_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if n > 0 {
            write_security_event(
                tx,
                audit,
                event(
                    AuditOperation::Revoke,
                    "user_account_mm_role",
                    user_id,
                    role,
                    provider_key,
                ),
            )
            .await?;
            changes.roles_removed.push(role);
        }
    }

    // Teams.
    let held: BTreeSet<Uuid> = sqlx::query_scalar(
        "SELECT team_ref FROM user_account_mm_team \
          WHERE user_ref = $1 AND source_provider_ref = $2 AND NOT is_deleted",
    )
    .bind(user_id)
    .bind(provider_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let (add, remove) = plan(&wanted_teams, &held);
    for team in add {
        if let crate::conflicts::ConflictOutcome::Refuse(_)
        | crate::conflicts::ConflictOutcome::NeedsApproval(_) =
            crate::conflicts::check_grant(tx, user_id, crate::conflicts::GrantRef::Team(team))
                .await?
        {
            tracing::warn!(%user_id, %team, provider = provider_key, "oidc mapping: a conflict rule stops this team");
            continue;
        }
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO user_account_mm_team (id, user_ref, team_ref, source_provider_ref) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_ref, team_ref) DO UPDATE \
                 SET is_deleted = false, source_provider_ref = EXCLUDED.source_provider_ref, \
                     updated_at = now() \
               WHERE user_account_mm_team.is_deleted \
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(team)
        .bind(provider_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if id.is_some() {
            write_security_event(
                tx,
                audit,
                event(
                    AuditOperation::Grant,
                    "user_account_mm_team",
                    user_id,
                    team,
                    provider_key,
                ),
            )
            .await?;
            changes.teams_added.push(team);
        }
    }
    for team in remove {
        let n = sqlx::query(
            "UPDATE user_account_mm_team SET is_deleted = true, updated_at = now() \
              WHERE user_ref = $1 AND team_ref = $2 AND source_provider_ref = $3 AND NOT is_deleted",
        )
        .bind(user_id)
        .bind(team)
        .bind(provider_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if n > 0 {
            write_security_event(
                tx,
                audit,
                event(
                    AuditOperation::Revoke,
                    "user_account_mm_team",
                    user_id,
                    team,
                    provider_key,
                ),
            )
            .await?;
            changes.teams_removed.push(team);
        }
    }
    Ok(changes)
}

/// The profile values the token carries for the claims `claim_map` maps:
/// `name` to the person's name and `phone` to their phone. A claim not
/// mapped, absent or empty gives nothing. Pure.
pub fn profile_of(claims: &Value, claim_map: &Value) -> (Option<String>, Option<String>) {
    let value = |field: &str| {
        let claim = claim_map.get(field).and_then(Value::as_str)?;
        claims
            .get(claim)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.chars().count() <= 200)
            .map(str::to_owned)
    };
    (value("name"), value("phone"))
}

/// Updates the person's name and phone from the token, for the claims the
/// provider maps, writing only a value that changed. Answers whether the
/// row changed. Break-glass and service accounts are left alone. The
/// account has no title, department or manager field, so those mapped
/// claims are not stored.
pub async fn apply_profile_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    claims: &Value,
    claim_map: &Value,
) -> Result<bool, AppError> {
    let (name, phone) = profile_of(claims, claim_map);
    if (name.is_none() && phone.is_none()) || exempt(tx, user_id).await? {
        return Ok(false);
    }
    let n = sqlx::query(
        "UPDATE user_account SET \
             user_name = COALESCE($2, user_name), phone = COALESCE($3, phone), \
             row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 \
            AND (user_name IS DISTINCT FROM COALESCE($2, user_name) \
                 OR phone IS DISTINCT FROM COALESCE($3, phone))",
    )
    .bind(user_id)
    .bind(name)
    .bind(phone)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn groups_come_from_the_mapped_claim() {
        let claims = json!({ "groups": ["sales", "ops", 7], "roles": "admins" });
        assert_eq!(groups_of(&claims, &json!({})), vec!["sales", "ops"]);
        assert_eq!(
            groups_of(&claims, &json!({ "groups": "roles" })),
            vec!["admins"]
        );
        assert!(groups_of(&claims, &json!({ "groups": "missing" })).is_empty());
    }

    #[test]
    fn the_plan_adds_the_new_and_removes_only_the_providers_old() {
        let (a, b, c) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let wanted: BTreeSet<Uuid> = [a, b].into();
        let held: BTreeSet<Uuid> = [b, c].into();
        assert_eq!(plan(&wanted, &held), (vec![a], vec![c]));
        assert_eq!(plan(&BTreeSet::new(), &BTreeSet::new()), (vec![], vec![]));
    }

    #[test]
    fn profile_values_need_a_mapped_claim() {
        let claims = json!({ "name": " Sara Al-Qahtani ", "mobile": "+966500000000", "phone": "" });
        assert_eq!(
            profile_of(&claims, &json!({ "name": "name", "phone": "mobile" })),
            (
                Some("Sara Al-Qahtani".to_owned()),
                Some("+966500000000".to_owned())
            )
        );
        assert_eq!(profile_of(&claims, &json!({})), (None, None));
        assert_eq!(
            profile_of(&claims, &json!({ "phone": "phone" })),
            (None, None)
        );
    }
}

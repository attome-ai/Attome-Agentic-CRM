//! Q4-T2: the nightly directory sync (job [`LDAP_SYNC_JOB`]).
//!
//! With `auth.ldap` configured, [`run`] lists everyone the directory's
//! `user_filter` finds (`attome_auth::ldap::Directory::list_people`, paged,
//! all or nothing) and, for each person with an email address:
//!
//! - links them to their Attome account as a sign-in would
//!   (`user_identity`, provider `ldap`, the entry's DN), creating the account
//!   only when `auth.ldap.create_users` is on;
//! - gives them the roles their groups give and takes back the directory's
//!   earlier ones (`directory_mapping::apply_directory_roles_in_tx`, the
//!   sign-in's own rules: never a system administration role, never a
//!   break-glass or reserved account).
//!
//! Then every active account linked to the directory whose entry is no
//! longer listed is disabled, as an administrator's disable does: the flag,
//! the session epoch and API keys in one transaction with its security
//! event, then refresh tokens and caches. Two guards keep a broken listing
//! from locking people out: an empty listing disables no one, and a sync
//! that would disable more than half the linked accounts (and more than
//! [`MASS_REMOVAL_FLOOR`]) disables no one and logs an error instead
//! ([`removals_allowed`]). Break-glass and reserved accounts are never
//! disabled. A disabled account is never re-enabled by the sync; an
//! administrator decides that.
//!
//! Groups give roles, not teams: `auth.ldap.group_roles` is the one mapping
//! a directory has.

use std::collections::BTreeSet;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_auth::ldap::{Directory, DirectoryUser};
use attome_config::LdapSection;
use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// The registered job type's name.
pub const LDAP_SYNC_JOB: &str = "ldap_sync";

/// The `user_identity.provider_key` directory accounts are linked under, as
/// the directory sign-in links them.
pub const PROVIDER_KEY: &str = "ldap";

/// Up to this many removals are always allowed, whatever the share.
pub const MASS_REMOVAL_FLOOR: usize = 5;

/// What one sync did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncSummary {
    /// People the directory listed.
    pub listed: usize,
    /// Of them, linked to an account (found or created).
    pub linked: usize,
    /// Listed people skipped: no email address, or no account to link to.
    pub skipped: usize,
    /// Accounts whose directory roles changed.
    pub roles_changed: usize,
    /// Accounts disabled because their entry is gone.
    pub disabled: usize,
    /// Removals not made because the guard refused them.
    pub removals_refused: usize,
}

/// The linked accounts whose directory entry (`sub`, the lowercased DN) is
/// not in `listed`. Pure.
pub fn removed(linked: &[(Uuid, String)], listed: &BTreeSet<String>) -> Vec<Uuid> {
    linked
        .iter()
        .filter(|(_, sub)| !listed.contains(sub))
        .map(|(id, _)| *id)
        .collect()
}

/// Whether disabling `removals` of `linked` accounts is plausible rather
/// than a broken listing: never on an empty listing, and at most half the
/// linked accounts unless that is no more than [`MASS_REMOVAL_FLOOR`]. Pure.
pub fn removals_allowed(removals: usize, linked: usize, listed: usize) -> bool {
    if listed == 0 {
        return removals == 0;
    }
    removals <= MASS_REMOVAL_FLOOR || removals * 2 <= linked
}

/// Runs one sync against `settings`' directory.
pub async fn run(state: &EngineState, settings: &LdapSection) -> Result<SyncSummary, AppError> {
    let directory = Directory::load(settings).await.map_err(|e| {
        tracing::error!(error = %e, "ldap sync: auth.ldap cannot be used");
        AppError::CapabilityUnavailable("directory")
    })?;
    let people = directory.list_people().await.map_err(|e| {
        tracing::warn!(error = %e, "ldap sync: the directory could not be listed; nothing changed");
        AppError::CapabilityUnavailable("directory")
    })?;
    let mut summary = SyncSummary {
        listed: people.len(),
        ..SyncSummary::default()
    };
    let listed: BTreeSet<String> = people.iter().map(|p| p.dn.to_lowercase()).collect();
    for person in &people {
        match sync_person(state, settings, person).await {
            Ok(Some(changed)) => {
                summary.linked += 1;
                if changed {
                    summary.roles_changed += 1;
                }
            }
            Ok(None) => summary.skipped += 1,
            Err(e) => {
                // One person's failure never stops the rest, nor the removals
                // (which read the listing, not these results).
                tracing::warn!(error = %e, "ldap sync: a person could not be synced");
                summary.skipped += 1;
            }
        }
    }

    let linked: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT i.user_ref, i.provider_sub FROM user_identity i \
           JOIN user_account u ON u.id = i.user_ref \
          WHERE i.provider_key = $1 AND u.is_active = true",
    )
    .bind(PROVIDER_KEY)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let gone = removed(&linked, &listed);
    if !removals_allowed(gone.len(), linked.len(), summary.listed) {
        tracing::error!(
            listed = summary.listed,
            linked = linked.len(),
            would_disable = gone.len(),
            "ldap sync: the listing would disable too many accounts; none disabled. \
             Check auth.ldap.base_dn and user_filter"
        );
        summary.removals_refused = gone.len();
    } else {
        for user_id in gone {
            match disable(state, user_id).await {
                Ok(true) => summary.disabled += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(%user_id, error = %e, "ldap sync: an account could not be disabled")
                }
            }
        }
    }
    tracing::info!(
        listed = summary.listed,
        linked = summary.linked,
        skipped = summary.skipped,
        roles_changed = summary.roles_changed,
        disabled = summary.disabled,
        removals_refused = summary.removals_refused,
        "ldap sync finished"
    );
    Ok(summary)
}

/// Links one listed person and applies their groups' roles. `None` when
/// they have no email address or no account to link to; otherwise whether
/// their roles changed.
async fn sync_person(
    state: &EngineState,
    settings: &LdapSection,
    person: &DirectoryUser,
) -> Result<Option<bool>, AppError> {
    let Some(email) = person
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    else {
        return Ok(None);
    };
    let mode = if settings.create_users {
        crate::accounts::LinkMode::Create { default_role: None }
    } else {
        crate::accounts::LinkMode::LinkOnly
    };
    let user_id = match crate::accounts::link_directory_identity(
        &state.base.db,
        PROVIDER_KEY,
        &person.dn.to_lowercase(),
        email,
        &mode,
    )
    .await
    {
        Ok(id) => id,
        // No account to link to (link only), or one another sign-in owns.
        Err(AppError::Conflict(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    let roles = attome_auth::ldap::roles_for(&person.groups, &settings.group_roles);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let changes = crate::directory_mapping::apply_directory_roles_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        user_id,
        &roles,
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    let changed = !changes.is_empty();
    if changed {
        state.base.security.invalidate_sync(user_id).await?;
    }
    Ok(Some(changed))
}

/// Disables an account whose directory entry is gone, as an
/// administrator's disable does. `false` when it was already inactive or is
/// a break-glass or reserved account.
async fn disable(state: &EngineState, user_id: Uuid) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if crate::oidc_mapping::exempt(&mut tx, user_id).await? {
        return Ok(false);
    }
    let updated: Option<Uuid> = sqlx::query_scalar(
        "UPDATE user_account SET is_active = false WHERE id = $1 AND is_active = true RETURNING id",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.is_none() {
        return Ok(false);
    }
    attome_auth::epoch::bump_in_tx(&mut tx, user_id).await?;
    sqlx::query("UPDATE api_key SET is_active = false WHERE user_ref = $1 AND is_active = true")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::AccountDisabled,
            Uuid::nil(),
            "user_account",
            Some(user_id),
        )
        .named("ldap.user_removed")
        .comment("disabled by the directory sync: the directory no longer lists the account"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    attome_auth::refresh::revoke_all_for_user(&state.base.db, user_id).await?;
    attome_auth::epoch::invalidate_cache(&state.base.redis, user_id).await;
    attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, user_id).await;
    state.base.security.invalidate_sync(user_id).await?;
    tracing::info!(%user_id, "ldap sync: account disabled, its directory entry is gone");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn ldap_sync_removes_only_accounts_no_longer_listed() {
        let linked = vec![
            (id(1), "cn=a,dc=x".to_owned()),
            (id(2), "cn=b,dc=x".to_owned()),
            (id(3), "cn=c,dc=x".to_owned()),
        ];
        let listed: BTreeSet<String> = ["cn=a,dc=x", "cn=c,dc=x", "cn=new,dc=x"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(removed(&linked, &listed), vec![id(2)]);
    }

    #[test]
    fn ldap_sync_refuses_a_listing_that_would_empty_the_directory() {
        // An empty listing removes no one.
        assert!(!removals_allowed(3, 3, 0));
        assert!(removals_allowed(0, 3, 0));
        // A few always may go; past the floor, at most half.
        assert!(removals_allowed(5, 6, 1));
        assert!(removals_allowed(50, 100, 50));
        assert!(!removals_allowed(51, 100, 49));
    }
}

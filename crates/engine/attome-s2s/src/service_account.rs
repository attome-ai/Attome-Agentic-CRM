//! S11-T4: every machine client is a service account.
//!
//! A client has an owner (a person answerable for it, the creating
//! administrator by default), a purpose, an environment and an optional
//! expiry. It acts as its service user, which holds roles (Q10) and record
//! shares (Q14) exactly like a person. A client created without naming a
//! service user gets a new one of its own, holding no role and no
//! privilege, so the new client can do nothing until an administrator
//! grants it a role.
//!
//! The daily sweep ([`expiry_sweep`]) tells each owner once, fourteen days
//! before their client expires, and suspends a client whose expiry has
//! passed (a Credential/Revoke security event per client).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// The daily expiry sweep's job name.
pub const JOB: &str = "s2s_client_expiry";

/// The environments a client may be declared for.
pub const ENVIRONMENTS: &[&str] = &["production", "staging", "development", "test"];

/// How long before expiry the owner is reminded.
pub const REMINDER_LEAD_DAYS: i64 = 14;

/// The most clients one sweep handles; the next day's sweep takes the rest.
const SWEEP_BATCH: i64 = 500;

/// The domain of a client's own service user. `.invalid` (RFC 2606) can
/// never receive mail, so no one can verify it, and the user has no
/// password: nobody signs in as it.
pub const SERVICE_USER_EMAIL_DOMAIN: &str = "@s2s.attome.invalid";

/// The environment, checked: absent, or one of [`ENVIRONMENTS`].
pub fn checked_environment(value: Option<&str>) -> Result<Option<String>, AppError> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(env) if ENVIRONMENTS.contains(&env) => Ok(Some(env.to_owned())),
        Some(_) => Err(AppError::Validation(format!(
            "environment must be one of {}",
            ENVIRONMENTS.join(", ")
        ))),
    }
}

/// An expiry, checked: absent, or in the future.
pub fn checked_expiry(
    value: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, AppError> {
    match value {
        Some(at) if at <= now => Err(AppError::Validation(
            "expires_at must be in the future".into(),
        )),
        other => Ok(other),
    }
}

/// The user name and email of client `slug`'s own service user.
pub fn service_user_identity(slug: &str) -> (String, String) {
    (
        format!("s2s-{slug}"),
        format!("{slug}{SERVICE_USER_EMAIL_DOMAIN}"),
    )
}

/// Creates client `slug`'s own service user inside `tx`: active, no
/// password, no role, no privilege.
pub async fn create_service_user(
    conn: &mut sqlx::PgConnection,
    slug: &str,
    created_by: Uuid,
) -> Result<Uuid, AppError> {
    let (user_name, email) = service_user_identity(slug);
    sqlx::query_scalar(
        "INSERT INTO user_account (user_name, email, is_active, email_verified, created_by) \
         VALUES ($1, $2, TRUE, FALSE, $3) RETURNING id",
    )
    .bind(user_name)
    .bind(email)
    .bind(created_by)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        if e.to_string().contains("unique") || e.to_string().contains("duplicate") {
            AppError::Conflict("a service user for this client_id already exists")
        } else {
            AppError::internal(e)
        }
    })
}

/// What the sweep does to one client today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryAction {
    /// Its expiry has passed: suspend it.
    Suspend,
    /// It expires within [`REMINDER_LEAD_DAYS`] and its owner was not told.
    Remind,
}

/// The decision for an active client. Pure.
pub fn expiry_action(
    now: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    reminded: bool,
) -> Option<ExpiryAction> {
    let at = expires_at?;
    if at <= now {
        Some(ExpiryAction::Suspend)
    } else if !reminded && at - now <= Duration::days(REMINDER_LEAD_DAYS) {
        Some(ExpiryAction::Remind)
    } else {
        None
    }
}

/// A client whose owner the sweep tells about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiryNotice {
    pub client_db_id: Uuid,
    pub client_id: String,
    pub name: String,
    pub owner: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub action: ExpiryAction,
}

/// S11-T4's daily sweep: suspends every active client whose expiry has
/// passed, and claims the reminder of every one expiring within fourteen
/// days. Each change is a compare-and-set, so a sweep run twice, or on two
/// nodes, suspends and reminds once. Answers what happened, for the caller
/// to tell the owners.
pub async fn expiry_sweep(state: &EngineState) -> Result<Vec<ExpiryNotice>, AppError> {
    let now = Utc::now();
    let candidates = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            Option<Uuid>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
        ),
    >(
        r#"
        SELECT id, client_id, name, owner_user_ref, expires_at, expiry_reminded_at
        FROM s2s_client
        WHERE is_deleted = FALSE AND status = 'active'
          AND expires_at IS NOT NULL AND expires_at <= $1
        ORDER BY expires_at
        LIMIT $2
        "#,
    )
    .bind(now + Duration::days(REMINDER_LEAD_DAYS))
    .bind(SWEEP_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut notices = Vec::new();
    for (id, client_id, name, owner, expires_at, reminded_at) in candidates {
        let Some(action) = expiry_action(now, Some(expires_at), reminded_at.is_some()) else {
            continue;
        };
        let changed = match action {
            ExpiryAction::Suspend => suspend_expired(state, id, &client_id).await?,
            ExpiryAction::Remind => {
                sqlx::query(
                    "UPDATE s2s_client SET expiry_reminded_at = NOW() \
                 WHERE id = $1 AND expiry_reminded_at IS NULL AND status = 'active' \
                   AND is_deleted = FALSE",
                )
                .bind(id)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?
                .rows_affected()
                    > 0
            }
        };
        if changed {
            notices.push(ExpiryNotice {
                client_db_id: id,
                client_id,
                name,
                owner,
                expires_at,
                action,
            });
        }
    }
    Ok(notices)
}

/// Suspends one expired client with its security event; `false` when
/// another sweep or an administrator changed it first.
async fn suspend_expired(
    state: &EngineState,
    client_db_id: Uuid,
    client_id: &str,
) -> Result<bool, AppError> {
    let mut tx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Revoke,
            Uuid::nil(),
            "s2s_client",
            Some(client_db_id),
        )
        .named(format!("s2s_client_expired:{client_id}")),
    )
    .await?;
    let rows = sqlx::query(
        "UPDATE s2s_client SET status = 'suspended', updated_at = NOW(), \
                row_version = row_version + 1 \
         WHERE id = $1 AND status = 'active' AND is_deleted = FALSE \
           AND expires_at IS NOT NULL AND expires_at <= NOW()",
    )
    .bind(client_db_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows == 0 {
        // Dropping the transaction rolls the event back with it.
        return Ok(false);
    }
    tx.commit().await?;
    tracing::warn!(client = client_id, "s2s: client expired; suspended");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_account_expiry_decision() {
        let now = Utc::now();
        assert_eq!(expiry_action(now, None, false), None, "no expiry");
        assert_eq!(
            expiry_action(now, Some(now - Duration::minutes(1)), false),
            Some(ExpiryAction::Suspend)
        );
        assert_eq!(
            expiry_action(now, Some(now - Duration::minutes(1)), true),
            Some(ExpiryAction::Suspend),
            "a reminded client is still suspended"
        );
        assert_eq!(
            expiry_action(now, Some(now + Duration::days(10)), false),
            Some(ExpiryAction::Remind)
        );
        assert_eq!(
            expiry_action(now, Some(now + Duration::days(10)), true),
            None,
            "reminded once"
        );
        assert_eq!(
            expiry_action(now, Some(now + Duration::days(30)), false),
            None,
            "not yet"
        );
    }

    #[test]
    fn service_account_fields_are_checked() {
        assert_eq!(checked_environment(None).unwrap(), None);
        assert_eq!(checked_environment(Some(" ")).unwrap(), None);
        assert_eq!(
            checked_environment(Some("production")).unwrap().as_deref(),
            Some("production")
        );
        assert!(checked_environment(Some("prod")).is_err());
        let now = Utc::now();
        assert!(checked_expiry(Some(now - Duration::seconds(1)), now).is_err());
        assert!(checked_expiry(Some(now + Duration::days(1)), now).is_ok());
        assert!(checked_expiry(None, now).unwrap().is_none());
    }

    #[test]
    fn service_account_user_cannot_sign_in_or_pass_as_a_platform_principal() {
        let (name, email) = service_user_identity("erp-sync");
        assert_eq!(name, "s2s-erp-sync");
        assert!(email.ends_with(".invalid"), "{email}");
        assert!(
            !attome_security::accounts::is_reserved_service_email(&email),
            "the client may act as it (D-786 refuses the reserved domain)"
        );
    }
}

//! Role grants that end (roadmap Q10-T6): a grant with `valid_until` in the
//! past is removed by [`expire_role_grants`] exactly as an administrator
//! removing the role would: soft-deleted with an `Access` + `Revoke` event
//! in the same transaction, the user's refresh tokens revoked and the auth
//! epoch bumped so a live access token is refused at its next request, then
//! the cached security context dropped.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Grants handled per run.
pub const BATCH: i64 = 200;

/// Whether an end date may be set on a new grant: it must be in the future.
pub fn valid_end(valid_until: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Result<(), AppError> {
    match valid_until {
        Some(end) if end <= now => Err(AppError::Validation(
            "valid_until must be in the future".into(),
        )),
        _ => Ok(()),
    }
}

/// Removes the role grants past their end; the number removed.
pub async fn expire_role_grants(state: &EngineState, now: DateTime<Utc>) -> Result<u64, AppError> {
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM user_account_mm_role \
         WHERE is_deleted = false AND valid_until IS NOT NULL AND valid_until <= $1 \
         ORDER BY valid_until LIMIT $2",
    )
    .bind(now)
    .bind(BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut removed = 0;
    for grant in due {
        let mut tx = SecurityTx::begin(
            state,
            SecurityEvent::new(
                MandatoryCategory::Access,
                AuditOperation::Revoke,
                Uuid::nil(),
                "user_account_mm_role",
                Some(grant),
            )
            .named("role_grant.expired"),
        )
        .await?;
        let user: Option<Uuid> = sqlx::query_scalar(
            "UPDATE user_account_mm_role SET is_deleted = true, updated_at = NOW() \
             WHERE id = $1 AND is_deleted = false AND valid_until <= $2 RETURNING user_ref",
        )
        .bind(grant)
        .bind(now)
        .fetch_optional(&mut **tx.tx())
        .await
        .map_err(AppError::internal)?;
        let Some(user) = user else {
            // Already removed by someone else: nothing to record.
            continue;
        };
        attome_auth::refresh::revoke_all_for_user_in_tx(tx.tx(), user).await?;
        attome_auth::epoch::bump_in_tx(tx.tx(), user).await?;
        tx.commit().await?;
        state.base.security.invalidate_sync(user).await?;
        attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, user).await;
        removed += 1;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn an_end_date_must_be_ahead() {
        let now = Utc::now();
        assert!(valid_end(None, now).is_ok());
        assert!(valid_end(Some(now + Duration::days(1)), now).is_ok());
        assert!(valid_end(Some(now), now).is_err());
        assert!(valid_end(Some(now - Duration::hours(1)), now).is_err());
    }
}

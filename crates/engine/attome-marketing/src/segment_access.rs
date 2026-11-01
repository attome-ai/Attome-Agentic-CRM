//! E7-T8: whose access a segment runs with.
//!
//! By default a segment runs as a reader: a person looking into a list
//! (count, sample, explain, members as of a date, E7-T7) sees only the
//! people they may read, and a background refresh runs as the list's owner.
//! A list may be granted wide access (`wide_access_granted`): its refreshes
//! then run as the deployment's marketing user, the setting
//! `marketing.segment_user` (V2-D1532 (1): every security context belongs
//! to a user, so the plan's "marketing role" is the user that holds it).
//! Readers still see only the people they may read, whatever the refresh
//! found ([`crate::segment_insight`] filters every answer as the caller).
//!
//! Granting or removing wide access needs `marketing_list.grant_wide_access`
//! (or `system.admin`) and writes an Access security event in the save's
//! own transaction ([`WideAccessCheck`], the generic engine's save check).
//! A wide list with no marketing user configured is refused
//! (`segment.no_marketing_role`) rather than run as anyone else.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_core::record_check::{RecordCheck, RecordCheckFuture, RecordSave};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use sqlx::Connection;
use uuid::Uuid;

/// The setting naming the marketing user wide refreshes run as.
pub const SEGMENT_USER_SETTING: &str = "marketing.segment_user";
/// Who may grant or remove wide access.
pub const GRANT_PRIVILEGE: &str = "marketing_list.grant_wide_access";
/// The flag on `marketing_list`.
pub const FLAG: &str = "wide_access_granted";

/// The user a list's refresh runs as: the marketing user when the list has
/// wide access, else its owner. Pure.
pub fn runs_as(
    wide: bool,
    owner: Option<Uuid>,
    segment_user: Option<Uuid>,
) -> Result<Uuid, AppError> {
    if wide {
        segment_user.ok_or_else(|| AppError::Validation("segment.no_marketing_role".into()))
    } else {
        owner.ok_or_else(|| AppError::Validation("segment.owner_missing".into()))
    }
}

/// The configured marketing user, if any.
pub fn segment_user(state: &EngineState) -> Option<Uuid> {
    attome_core::setting_registry()
        .get(SEGMENT_USER_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_str().and_then(|s| Uuid::parse_str(s.trim()).ok()))
}

/// The security context a background refresh of `list` runs with.
pub async fn refresh_context(state: &EngineState, list: Uuid) -> Result<SecurityContext, AppError> {
    let row: Option<(Option<bool>, Option<Uuid>)> = sqlx::query_as(
        "SELECT wide_access_granted, owner_ref FROM marketing_list \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (wide, owner) = row.ok_or(AppError::NotFound)?;
    let user = runs_as(wide == Some(true), owner, segment_user(state))?;
    attome_security::resolve_uncached(&state.base.db, user).await
}

/// The save check on `marketing_list`: only a holder of
/// [`GRANT_PRIVILEGE`] changes `wide_access_granted`, and the change is
/// audited in the save's transaction.
#[derive(Debug)]
pub struct WideAccessCheck;

impl RecordCheck for WideAccessCheck {
    fn check<'a>(
        &'a self,
        conn: &'a mut sqlx::PgConnection,
        state: &'a EngineState,
        save: RecordSave<'a>,
    ) -> RecordCheckFuture<'a> {
        Box::pin(async move {
            let Some(wanted) = save.body.get(FLAG) else {
                return Ok(None);
            };
            let wanted = wanted.as_bool() == Some(true);
            let stored: bool = match save.record_id {
                Some(id) => sqlx::query_scalar::<_, Option<bool>>(
                    "SELECT wide_access_granted FROM marketing_list WHERE id = $1",
                )
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .map_err(AppError::internal)?
                .flatten()
                .unwrap_or(false),
                None => false,
            };
            if wanted == stored {
                return Ok(None);
            }
            let Some(actor) = save.actor else {
                return Err(AppError::Forbidden);
            };
            let ctx = attome_security::resolve_uncached(&state.base.db, actor).await?;
            if !(ctx.is_admin || ctx.privileges.contains(GRANT_PRIVILEGE)) {
                return Err(AppError::Forbidden);
            }
            // A savepoint inside the save's transaction: the event commits
            // or rolls back with the save.
            let mut tx = conn.begin().await.map_err(AppError::internal)?;
            write_security_event(
                &mut tx,
                &attome_audit::audit_service(state),
                SecurityEvent::new(
                    MandatoryCategory::Access,
                    if wanted {
                        AuditOperation::Grant
                    } else {
                        AuditOperation::Revoke
                    },
                    actor,
                    "marketing_list",
                    save.record_id,
                )
                .named(if wanted {
                    "marketing_list.wide_access_granted"
                } else {
                    "marketing_list.wide_access_removed"
                }),
            )
            .await?;
            tx.commit().await.map_err(AppError::internal)?;
            Ok(None)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_context_by_default() {
        let owner = Uuid::now_v7();
        assert_eq!(
            runs_as(false, Some(owner), Some(Uuid::now_v7())).unwrap(),
            owner
        );
        assert!(runs_as(false, None, None).is_err());
    }

    #[test]
    fn wide_grant_uses_marketing_role() {
        let marketing = Uuid::now_v7();
        assert_eq!(
            runs_as(true, Some(Uuid::now_v7()), Some(marketing)).unwrap(),
            marketing
        );
        assert!(matches!(
            runs_as(true, Some(Uuid::now_v7()), None),
            Err(AppError::Validation(m)) if m == "segment.no_marketing_role"
        ));
    }
}

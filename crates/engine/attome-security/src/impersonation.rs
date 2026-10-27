//! Q13-T1: view-as and act-as sessions (V2-D361).
//!
//! - **View-as** runs an administrator's requests with a person's access and
//!   changes nothing: the request pipeline refuses every write
//!   (`attome_server::impersonation::view_allows`).
//! - **Act-as** acts as the person, and needs their **consent**: a grant the
//!   person gives one administrator, until a time they choose (at most
//!   [`MAX_CONSENT_HOURS`]), revocable at any time. Credential, approval and
//!   signing actions are never done as someone else
//!   (`attome_server::impersonation::act_allows`).
//!
//! Either needs a reason and a fresh step-up (`impersonation`), and lasts at
//! most [`SESSION_MINUTES`] minutes with no refresh; an administrator holds one
//! live session at a time, so sessions never nest. Nobody impersonates an
//! administrator or a machine identity. Every request in a session is logged
//! before it runs (`impersonation_request`), and every audit row it writes
//! names both people (`attome_audit::initiator::Initiator::Impersonation`).
//! The person sees every session about them (`GET /api/v1/me/impersonation-sessions`).
//!
//! A deployment rule that lets acting proceed without consent is not built:
//! consent is always required (V2-D361's default).

use attome_db::DbPool;
use attome_server::impersonation::{Impersonation, ImpersonationMode, ImpersonationStore};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use futures_util::future::BoxFuture;
use uuid::Uuid;

/// The longest a session lasts.
pub const SESSION_MINUTES: i64 = 30;
/// The longest a consent lasts.
pub const MAX_CONSENT_HOURS: i64 = 72;

/// Whether `actor_id` may start a `mode` session as `subject`. `consent` is
/// the subject's live consent for this actor, when there is one;
/// `actor_has_live_session` refuses nesting. Pure.
pub fn check_start(
    actor_id: Uuid,
    subject: &SecurityContext,
    mode: ImpersonationMode,
    consent: Option<Uuid>,
    reason: &str,
    actor_has_live_session: bool,
) -> Result<(), AppError> {
    if reason.trim().is_empty() {
        return Err(AppError::Validation(
            "impersonation_reason_required: say why".into(),
        ));
    }
    if subject.user_id == actor_id {
        return Err(AppError::Validation(
            "impersonation_self: you cannot impersonate yourself".into(),
        ));
    }
    if subject.is_admin || subject.service_principal {
        return Err(AppError::Forbidden);
    }
    if actor_has_live_session {
        return Err(AppError::Conflict(
            "impersonation_already_active: end the current session first",
        ));
    }
    if mode == ImpersonationMode::Act && consent.is_none() {
        return Err(AppError::Validation(
            "impersonation_needs_consent: acting as someone needs their consent".into(),
        ));
    }
    Ok(())
}

/// The subject's live consent for `actor_id`, if any.
pub async fn live_consent(
    db: &DbPool,
    subject_id: Uuid,
    actor_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM impersonation_consent \
         WHERE subject_ref = $1 AND actor_ref = $2 AND revoked_at IS NULL AND expires_at > now() \
         ORDER BY expires_at DESC LIMIT 1",
    )
    .bind(subject_id)
    .bind(actor_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Whether `actor_id` has a live session.
pub async fn has_live_session(db: &DbPool, actor_id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM impersonation_session \
         WHERE actor_ref = $1 AND ended_at IS NULL AND expires_at > now())",
    )
    .bind(actor_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// When a session started at `now` ends.
pub fn session_end(now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::minutes(SESSION_MINUTES)
}

/// The sessions the request pipeline checks, in `impersonation_session`.
#[derive(Debug, Clone)]
pub struct PgImpersonationStore {
    db: DbPool,
}

impl PgImpersonationStore {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

type SessionRow = (Uuid, Uuid, Uuid, String, DateTime<Utc>);

impl ImpersonationStore for PgImpersonationStore {
    fn active<'a>(
        &'a self,
        session_id: Uuid,
        actor_id: Uuid,
    ) -> BoxFuture<'a, Result<Option<Impersonation>, AppError>> {
        Box::pin(async move {
            let row: Option<SessionRow> = sqlx::query_as(
                "SELECT id, actor_ref, subject_ref, mode, expires_at FROM impersonation_session \
                 WHERE id = $1 AND actor_ref = $2 AND ended_at IS NULL AND expires_at > now()",
            )
            .bind(session_id)
            .bind(actor_id)
            .fetch_optional(&self.db)
            .await
            .map_err(AppError::internal)?;
            Ok(row.and_then(|(id, actor, subject, mode, expires_at)| {
                Some(Impersonation {
                    session_id: id,
                    actor_id: actor,
                    subject_id: subject,
                    mode: ImpersonationMode::parse(&mode)?,
                    expires_at,
                })
            }))
        })
    }

    fn log_request<'a>(
        &'a self,
        session: &'a Impersonation,
        method: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), AppError>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO impersonation_request (session_ref, method, path) VALUES ($1, $2, $3)",
            )
            .bind(session.session_id)
            .bind(method)
            .bind(path)
            .execute(&self.db)
            .await
            .map_err(AppError::internal)?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use axum::http::Method;

    use super::*;

    fn person() -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin: false,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            field_masks: Default::default(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            unit_scope: Default::default(),
            service_principal: false,
        }
    }

    /// View-as cannot write: the pipeline lets reads through and refuses
    /// every change, and view-as needs no consent.
    #[test]
    fn impersonation_view_as_cannot_write() {
        use attome_server::impersonation::view_allows;
        assert!(view_allows(&Method::GET, "/api/v1/contact/1"));
        for method in [Method::POST, Method::PATCH, Method::PUT, Method::DELETE] {
            assert!(!view_allows(&method, "/api/v1/contact/1"), "{method}");
        }
        let subject = person();
        assert!(
            check_start(
                Uuid::now_v7(),
                &subject,
                ImpersonationMode::View,
                None,
                "ticket 41",
                false
            )
            .is_ok()
        );
    }

    /// Act-as without the person's consent is refused; with it, it starts.
    #[test]
    fn impersonation_act_as_without_grant_refused() {
        let (actor, subject) = (Uuid::now_v7(), person());
        let refused = check_start(actor, &subject, ImpersonationMode::Act, None, "fix", false);
        assert!(
            matches!(&refused, Err(AppError::Validation(m)) if m.starts_with("impersonation_needs_consent")),
            "{refused:?}"
        );
        assert!(
            check_start(
                actor,
                &subject,
                ImpersonationMode::Act,
                Some(Uuid::now_v7()),
                "fix",
                false
            )
            .is_ok()
        );
    }

    /// Never an administrator, a machine, oneself, without a reason, or
    /// nested inside another session.
    #[test]
    fn impersonation_refuses_admins_machines_self_and_nesting() {
        let actor = Uuid::now_v7();
        let admin = SecurityContext {
            is_admin: true,
            ..person()
        };
        let machine = SecurityContext {
            service_principal: true,
            ..person()
        };
        let me = SecurityContext {
            user_id: actor,
            ..person()
        };
        let view = ImpersonationMode::View;
        assert!(matches!(
            check_start(actor, &admin, view, None, "x", false),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            check_start(actor, &machine, view, None, "x", false),
            Err(AppError::Forbidden)
        ));
        assert!(check_start(actor, &me, view, None, "x", false).is_err());
        assert!(check_start(actor, &person(), view, None, "  ", false).is_err());
        assert!(matches!(
            check_start(actor, &person(), view, None, "x", true),
            Err(AppError::Conflict(_))
        ));
        let start = Utc::now();
        assert_eq!(session_end(start) - start, Duration::minutes(30));
    }
}

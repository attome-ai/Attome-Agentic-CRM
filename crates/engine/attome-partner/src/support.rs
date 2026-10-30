//! What the partner engine's decisions and jobs share: record access, the
//! crate's advisory lock, the partner manager and telling them, and the
//! rule that a person decides.

use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use uuid::Uuid;

/// Refuses a caller who is not a person at a browser: an API key, an S2S
/// client, or an agent acting in-process (its scope is set around every
/// agent action).
pub(crate) fn person_only(ctx: &SecurityContext) -> Result<(), AppError> {
    if ctx.service_principal || attome_core::agent_scope::current().is_some() {
        Err(AppError::Forbidden)
    } else {
        Ok(())
    }
}

/// `action` on the record, or the error the record engine answers.
pub(crate) async fn require(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    id: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    let (entity_id, _, _, _) = attome_records::entity_crud::resolve_entity(state, entity).await?;
    attome_records::entity_crud::require_record_access(state, ctx, entity_id, entity, id, action)
        .await
}

/// Takes the crate's transaction lock on `key` (`attome-partner/...`), or a
/// conflict when another decision holds it.
pub(crate) async fn lock(tx: &mut attome_db::Tx<'_>, key: String) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(key)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "another decision on this is in progress; retry",
        ))
    }
}

/// The partner account's partner manager, when it has one.
pub(crate) async fn partner_manager(state: &EngineState, partner: Option<Uuid>) -> Option<Uuid> {
    let partner = partner?;
    let manager: Result<Option<Option<Uuid>>, sqlx::Error> =
        sqlx::query_scalar("SELECT partner_manager_ref FROM account WHERE id = $1")
            .bind(partner)
            .fetch_optional(&state.base.db)
            .await;
    match manager {
        Ok(found) => found.flatten(),
        Err(error) => {
            tracing::warn!(%partner, %error, "partner manager not read");
            None
        }
    }
}

/// Tells `user` in the app; a failed send is logged, never retried.
pub(crate) async fn notify(
    state: &EngineState,
    user: Uuid,
    subject: String,
    body: String,
    route: String,
) {
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: Some(user),
        is_global: false,
        organization_ref: None,
        channels: None,
        subject: Some(subject),
        body_html: None,
        body_text: Some(body),
        route: Some(route),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await
    {
        tracing::warn!(%user, %error, "partner notification not sent");
    }
}

/// Whether the partner pack's columns `column` of `table` exist (the pack
/// may not be installed). Before then, the jobs do nothing.
pub(crate) async fn installed(
    db: &attome_db::DbPool,
    table: &str,
    column: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

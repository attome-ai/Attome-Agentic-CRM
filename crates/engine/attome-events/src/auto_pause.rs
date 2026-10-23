//! M13-T3: an endpoint that keeps failing is turned off, and its owner told.
//!
//! After a failed attempt, the subscription's last [`PAUSE_WINDOW`] attempted
//! deliveries are counted (each at its latest outcome: delivered, or failed
//! and dead-lettered). Below a 50% success rate the subscription is set
//! inactive with `paused_at` and `paused_reason` (migration 0209), a
//! `Configuration` security event is written in the same transaction, and the
//! owner gets an in-app and email notification. Turning the subscription
//! back on (`PATCH ... {"is_active": true}`) clears the pause. Pending
//! deliveries stay and are dead-lettered as "subscription is no longer
//! active" when their job runs, so they can be replayed from the dead-letter
//! inbox once the endpoint is fixed.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent};
use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// Attempted deliveries the success rate is measured over.
pub const PAUSE_WINDOW: i64 = 100;

/// Whether `delivered` successes against `failed` failures, over a full
/// window, is below half.
pub fn should_pause(delivered: i64, failed: i64) -> bool {
    let attempted = delivered + failed;
    attempted >= PAUSE_WINDOW && delivered * 2 < attempted
}

/// Counts the window and pauses the subscription when it should; `true`
/// when this call paused it.
pub async fn check(
    state: &EngineState,
    subscription_id: Uuid,
    owner_ref: Uuid,
) -> Result<bool, AppError> {
    let (delivered, failed): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE status = 'delivered'), \
                COUNT(*) FILTER (WHERE status IN ('failed', 'dead_letter')) \
           FROM (SELECT status FROM event_delivery \
                  WHERE subscription_ref = $1 AND last_attempted_at IS NOT NULL \
                  ORDER BY created_at DESC LIMIT $2) recent",
    )
    .bind(subscription_id)
    .bind(PAUSE_WINDOW)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !should_pause(delivered, failed) {
        return Ok(false);
    }
    let reason = format!(
        "{delivered} of the last {} deliveries succeeded",
        delivered + failed
    );
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let paused = sqlx::query(
        "UPDATE event_subscription \
            SET is_active = false, paused_at = now(), paused_reason = $2, \
                updated_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND is_active AND NOT is_deleted",
    )
    .bind(subscription_id)
    .bind(&reason)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected()
        == 1;
    if !paused {
        return Ok(false);
    }
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            owner_ref,
            "event_subscription",
            Some(subscription_id),
        )
        .named("event_subscription.auto_paused")
        .comment(reason.clone()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::telemetry::auto_paused();
    tracing::warn!(%subscription_id, %reason, "events: webhook subscription paused, its endpoint keeps failing");

    // Told after the pause committed; a failure to tell is logged, the pause
    // stands.
    let request = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: state.user_locale(owner_ref).chars().take(2).collect(),
        recipient_user_ref: Some(owner_ref),
        is_global: false,
        organization_ref: None,
        channels: Some(vec!["in_app".to_owned(), "email".to_owned()]),
        subject: Some("A webhook subscription was paused".to_owned()),
        body_html: None,
        body_text: Some(format!(
            "Webhook subscription {subscription_id} was turned off because its endpoint keeps \
             failing ({reason}). Fix the endpoint, turn the subscription back on, then replay \
             its dead letters."
        )),
        route: Some("/xrm/jobs/dead-letters".to_owned()),
        variables: std::collections::HashMap::new(),
        priority: "high".to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        request,
    )
    .await
    {
        tracing::warn!(%subscription_id, %error, "events: could not tell the owner about the pause");
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_pause_needs_a_full_window_below_half() {
        assert!(!should_pause(10, 30), "40 attempts is not a full window");
        assert!(should_pause(49, 51));
        assert!(!should_pause(50, 50), "exactly half keeps it on");
        assert!(!should_pause(90, 10));
        assert!(should_pause(0, 100));
    }
}

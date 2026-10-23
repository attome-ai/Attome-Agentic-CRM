//! M5-T1: dead-lettered webhook deliveries (`event_delivery`,
//! `status = 'dead_letter'`) as a [`DeadLetterSource`].
//!
//! Step is the subscription id, so one broken endpoint is one group. Replay
//! puts the delivery back to `pending` with its attempts reset and queues a
//! delivery job; discard deletes the row. Both write their security event in
//! the same transaction, as the subscription admin routes do.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent};
use attome_core::EngineState;
use attome_core::dead_letter::{DeadLetter, DeadLetterFuture, DeadLetterSource, ReplayOutcome};
use attome_core::jobs::EngineJob;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub const WEBHOOK_SOURCE: &str = "webhook";

#[derive(Debug, Default)]
pub struct WebhookDeadLetters;

#[derive(sqlx::FromRow)]
struct DeliveryRow {
    id: Uuid,
    subscription_ref: Uuid,
    event_entity_logicalname: String,
    attempts: i32,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
}

const COLUMNS: &str =
    "id, subscription_ref, event_entity_logicalname, attempts, last_error, created_at";

fn item(r: DeliveryRow) -> DeadLetter {
    DeadLetter::new(
        WEBHOOK_SOURCE,
        r.id.to_string(),
        Some(r.subscription_ref.to_string()),
        r.last_error.as_deref(),
        r.created_at,
        r.attempts,
        Some(format!(
            "event_delivery:{}:{}",
            r.id, r.event_entity_logicalname
        )),
    )
}

impl DeadLetterSource for WebhookDeadLetters {
    fn source(&self) -> &'static str {
        WEBHOOK_SOURCE
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        offset: i64,
        limit: i64,
    ) -> DeadLetterFuture<'a, Vec<DeadLetter>> {
        Box::pin(async move {
            let rows: Vec<DeliveryRow> = sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM event_delivery WHERE status = 'dead_letter' \
                 ORDER BY updated_at DESC, id LIMIT $1 OFFSET $2"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(rows.into_iter().map(item).collect())
        })
    }

    fn count<'a>(&'a self, state: &'a EngineState) -> DeadLetterFuture<'a, i64> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT COUNT(*) FROM event_delivery WHERE status = 'dead_letter'")
                .fetch_one(&state.base.db)
                .await
                .map_err(AppError::internal)
        })
    }

    fn get<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
    ) -> DeadLetterFuture<'a, Option<DeadLetter>> {
        Box::pin(async move {
            let Ok(delivery_id) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            let row: Option<DeliveryRow> = sqlx::query_as(&format!(
                "SELECT {COLUMNS} FROM event_delivery WHERE id = $1 AND status = 'dead_letter'"
            ))
            .bind(delivery_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(row.map(item))
        })
    }

    fn replay<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
        actor: Uuid,
    ) -> DeadLetterFuture<'a, ReplayOutcome> {
        Box::pin(async move {
            let Ok(delivery_id) = Uuid::parse_str(id) else {
                return Ok(ReplayOutcome::NotDeadLettered);
            };
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let reset = sqlx::query(
                "UPDATE event_delivery \
                    SET status = 'pending', attempts = 0, last_error = NULL, \
                        updated_at = NOW(), row_version = row_version + 1 \
                  WHERE id = $1 AND status = 'dead_letter'",
            )
            .bind(delivery_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if reset == 0 {
                return Ok(ReplayOutcome::NotDeadLettered);
            }
            attome_jobs::enqueue_in_tx_dedup(
                &mut tx,
                EngineJob::EventsDeliverWebhook { delivery_id },
                &delivery_id.to_string(),
            )
            .await
            .map_err(AppError::internal)?;
            attome_audit::security::write_security_event(
                &mut tx,
                &attome_audit::audit_service(state),
                SecurityEvent::new(
                    MandatoryCategory::Configuration,
                    AuditOperation::Execute,
                    actor,
                    "event_delivery",
                    Some(delivery_id),
                )
                .named("event_delivery.replay"),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(ReplayOutcome::Replayed)
        })
    }

    fn discard<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
        actor: Uuid,
        reason: &'a str,
    ) -> DeadLetterFuture<'a, bool> {
        Box::pin(async move {
            let Ok(delivery_id) = Uuid::parse_str(id) else {
                return Ok(false);
            };
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let deleted: Option<(Uuid, Uuid)> = sqlx::query_as(
                "DELETE FROM event_delivery WHERE id = $1 AND status = 'dead_letter' \
                 RETURNING subscription_ref, event_id",
            )
            .bind(delivery_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            let Some((subscription, event)) = deleted else {
                return Ok(false);
            };
            attome_audit::security::write_security_event(
                &mut tx,
                &attome_audit::audit_service(state),
                SecurityEvent::new(
                    MandatoryCategory::Configuration,
                    AuditOperation::HardDelete,
                    actor,
                    "event_delivery",
                    Some(delivery_id),
                )
                .named("event_delivery.discard")
                .comment(format!(
                    "subscription={subscription} event={event}; reason: {reason}"
                )),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(true)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_letter_sources_webhook_groups_by_subscription() {
        let (id, sub) = (Uuid::now_v7(), Uuid::now_v7());
        let dl = item(DeliveryRow {
            id,
            subscription_ref: sub,
            event_entity_logicalname: "account".into(),
            attempts: 8,
            last_error: Some("webhook delivery could not connect".into()),
            created_at: Utc::now(),
        });
        assert_eq!(dl.source, WEBHOOK_SOURCE);
        assert_eq!(dl.cause_group, format!("webhook:{sub}:connect"));
        assert_eq!(dl.attempts, 8);
    }
}

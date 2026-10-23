//! M5-T1: flow triggers and flow runs as [`DeadLetterSource`]s.
//!
//! * [`FlowTriggerDeadLetters`] — `workflow_trigger_failure` rows the entity
//!   trigger dispatcher gave up on; replay and discard are
//!   [`crate::dead_letter_admin`]'s, audit included. Step is
//!   `<entity>.<operation>`.
//! * [`FlowRunDeadLetters`] — `failed` runs; replay is
//!   [`crate::instance_control::retry_run`] (the failed steps run again with
//!   the inputs they had), discard cancels the run. Step is the run's flow
//!   version and failed node, `<definition_version_id>/<node_id>`.

use attome_audit::{AuditOperation, BusinessEvent};
use attome_core::EngineState;
use attome_core::dead_letter::{DeadLetter, DeadLetterFuture, DeadLetterSource, ReplayOutcome};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub const FLOW_TRIGGER_SOURCE: &str = "flow_trigger";
pub const FLOW_RUN_SOURCE: &str = "flow_run";

#[derive(Debug, Default)]
pub struct FlowTriggerDeadLetters;

#[derive(sqlx::FromRow)]
struct TriggerRow {
    event_id: Uuid,
    entity_logicalname: String,
    operation: String,
    attempts: i32,
    last_error: String,
    first_failed_at: DateTime<Utc>,
}

const TRIGGER_COLUMNS: &str = "event_id, entity_logicalname, operation, attempts, last_error, \
                               first_failed_at";

fn trigger_item(r: TriggerRow) -> DeadLetter {
    DeadLetter::new(
        FLOW_TRIGGER_SOURCE,
        r.event_id.to_string(),
        Some(format!("{}.{}", r.entity_logicalname, r.operation)),
        Some(&r.last_error),
        r.first_failed_at,
        r.attempts,
        Some(format!("entity_change_event:{}", r.event_id)),
    )
}

impl DeadLetterSource for FlowTriggerDeadLetters {
    fn source(&self) -> &'static str {
        FLOW_TRIGGER_SOURCE
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        offset: i64,
        limit: i64,
    ) -> DeadLetterFuture<'a, Vec<DeadLetter>> {
        Box::pin(async move {
            let rows: Vec<TriggerRow> = sqlx::query_as(&format!(
                "SELECT {TRIGGER_COLUMNS} FROM workflow_trigger_failure \
                 WHERE dead_lettered_at IS NOT NULL \
                 ORDER BY dead_lettered_at DESC, event_id LIMIT $1 OFFSET $2"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(rows.into_iter().map(trigger_item).collect())
        })
    }

    fn count<'a>(&'a self, state: &'a EngineState) -> DeadLetterFuture<'a, i64> {
        Box::pin(async move {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM workflow_trigger_failure WHERE dead_lettered_at IS NOT NULL",
            )
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
            let Ok(event_id) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            let row: Option<TriggerRow> = sqlx::query_as(&format!(
                "SELECT {TRIGGER_COLUMNS} FROM workflow_trigger_failure \
                 WHERE event_id = $1 AND dead_lettered_at IS NOT NULL"
            ))
            .bind(event_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(row.map(trigger_item))
        })
    }

    fn replay<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
        actor: Uuid,
    ) -> DeadLetterFuture<'a, ReplayOutcome> {
        Box::pin(async move {
            let Ok(event_id) = Uuid::parse_str(id) else {
                return Ok(ReplayOutcome::NotDeadLettered);
            };
            match crate::dead_letter_admin::replay(state, event_id, actor).await {
                Ok(_) => Ok(ReplayOutcome::Replayed),
                Err(AppError::NotFound) => Ok(ReplayOutcome::NotDeadLettered),
                Err(e) => Err(e),
            }
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
            let Ok(event_id) = Uuid::parse_str(id) else {
                return Ok(false);
            };
            match crate::dead_letter_admin::discard_with_reason(
                state,
                event_id,
                actor,
                Some(reason),
            )
            .await
            {
                Ok(()) => Ok(true),
                Err(AppError::NotFound) => Ok(false),
                Err(e) => Err(e),
            }
        })
    }
}

#[derive(Debug, Default)]
pub struct FlowRunDeadLetters;

#[derive(sqlx::FromRow)]
struct RunRow {
    id: Uuid,
    definition_version_id: Uuid,
    failed_at: DateTime<Utc>,
    node_id: Option<String>,
    last_error: Option<String>,
    attempt_count: Option<i32>,
}

/// A failed run with its most recent failed step.
const RUN_SELECT: &str = "SELECT i.id, i.definition_version_id, \
            COALESCE(i.completed_at, i.started_at) AS failed_at, \
            nr.node_id, nr.last_error, nr.attempt_count \
       FROM workflow_instance i \
       LEFT JOIN LATERAL ( \
            SELECT node_id, last_error, attempt_count FROM workflow_node_run \
             WHERE instance_id = i.id AND status = 'failed' \
             ORDER BY completed_at DESC NULLS LAST LIMIT 1) nr ON true \
      WHERE i.status = 'failed'";

fn run_item(r: RunRow) -> DeadLetter {
    DeadLetter::new(
        FLOW_RUN_SOURCE,
        r.id.to_string(),
        Some(format!(
            "{}/{}",
            r.definition_version_id,
            r.node_id.as_deref().unwrap_or("-")
        )),
        r.last_error.as_deref(),
        r.failed_at,
        r.attempt_count.unwrap_or(0),
        Some(format!("workflow_instance:{}", r.id)),
    )
}

impl DeadLetterSource for FlowRunDeadLetters {
    fn source(&self) -> &'static str {
        FLOW_RUN_SOURCE
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        offset: i64,
        limit: i64,
    ) -> DeadLetterFuture<'a, Vec<DeadLetter>> {
        Box::pin(async move {
            let rows: Vec<RunRow> = sqlx::query_as(&format!(
                "{RUN_SELECT} ORDER BY failed_at DESC, i.id LIMIT $1 OFFSET $2"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(rows.into_iter().map(run_item).collect())
        })
    }

    fn count<'a>(&'a self, state: &'a EngineState) -> DeadLetterFuture<'a, i64> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT COUNT(*) FROM workflow_instance WHERE status = 'failed'")
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
            let Ok(instance_id) = Uuid::parse_str(id) else {
                return Ok(None);
            };
            let row: Option<RunRow> = sqlx::query_as(&format!("{RUN_SELECT} AND i.id = $1"))
                .bind(instance_id)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            Ok(row.map(run_item))
        })
    }

    fn replay<'a>(
        &'a self,
        state: &'a EngineState,
        id: &'a str,
        actor: Uuid,
    ) -> DeadLetterFuture<'a, ReplayOutcome> {
        Box::pin(async move {
            let Ok(instance_id) = Uuid::parse_str(id) else {
                return Ok(ReplayOutcome::NotDeadLettered);
            };
            let Some(row_version) = failed_row_version(state, instance_id).await? else {
                return Ok(ReplayOutcome::NotDeadLettered);
            };
            match crate::instance_control::retry_run(state, instance_id, row_version, actor).await {
                Ok(_) => Ok(ReplayOutcome::Replayed),
                Err(AppError::VersionConflict) => {
                    Ok(ReplayOutcome::Refused("the run changed since it was read"))
                }
                Err(AppError::Conflict(why)) => Ok(ReplayOutcome::Refused(why)),
                Err(e) => Err(e),
            }
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
            let Ok(instance_id) = Uuid::parse_str(id) else {
                return Ok(false);
            };
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let cancelled = sqlx::query(
                "UPDATE workflow_instance \
                    SET status = 'cancelled', completed_at = NOW(), row_version = row_version + 1 \
                  WHERE id = $1 AND status = 'failed'",
            )
            .bind(instance_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            if cancelled == 0 {
                return Ok(false);
            }
            attome_audit::write_business_event_in_tx(
                &mut tx,
                &attome_audit::audit_service(state),
                BusinessEvent::new(
                    "workflow_instance",
                    instance_id,
                    AuditOperation::Cancelled,
                    "workflow_instance.discard",
                    actor,
                )
                .comment(format!("reason: {reason}")),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            Ok(true)
        })
    }
}

async fn failed_row_version(
    state: &EngineState,
    instance_id: Uuid,
) -> Result<Option<i64>, AppError> {
    sqlx::query_scalar(
        "SELECT row_version FROM workflow_instance WHERE id = $1 AND status = 'failed'",
    )
    .bind(instance_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_letter_sources_flow_trigger_groups_by_entity_operation() {
        let id = Uuid::now_v7();
        let item = trigger_item(TriggerRow {
            event_id: id,
            entity_logicalname: "account".into(),
            operation: "update".into(),
            attempts: 5,
            last_error: "dispatch timed out".into(),
            first_failed_at: Utc::now(),
        });
        assert_eq!(item.source, FLOW_TRIGGER_SOURCE);
        assert_eq!(item.id, id.to_string());
        assert_eq!(item.cause_group, "flow_trigger:account.update:timeout");
        assert_eq!(item.payload_ref, Some(format!("entity_change_event:{id}")));
    }

    #[test]
    fn dead_letter_sources_flow_run_groups_by_version_and_step() {
        let (id, version) = (Uuid::now_v7(), Uuid::now_v7());
        let item = run_item(RunRow {
            id,
            definition_version_id: version,
            failed_at: Utc::now(),
            node_id: Some("send_mail".into()),
            last_error: Some("HTTP 503 from mail relay".into()),
            attempt_count: Some(3),
        });
        assert_eq!(
            item.cause_group,
            format!("flow_run:{version}/send_mail:http_5xx")
        );
        assert_eq!(item.attempts, 3);
        let bare = run_item(RunRow {
            id,
            definition_version_id: version,
            failed_at: Utc::now(),
            node_id: None,
            last_error: None,
            attempt_count: None,
        });
        assert_eq!(bare.step, Some(format!("{version}/-")));
        assert_eq!(bare.attempts, 0);
    }
}

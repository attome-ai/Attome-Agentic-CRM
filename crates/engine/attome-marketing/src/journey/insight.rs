//! Journey insight (roadmap E8-T9): how many people are at each node of a
//! journey, each person's path through it, and their journey rows removed
//! when they are erased.
//!
//! **Counts.** `marketing_journey_node_count` holds, per version and node,
//! the people who entered it, wait at it, passed it, were blocked at it and
//! left the journey at it. [`refresh_counts`] (the `marketing_journey_counts`
//! job, every 30 seconds, one pending at most) recomputes the rows of every
//! version with an active enrolment or one that ended in the last hour, in
//! one set-based statement over its node runs, blocks and exits. Node runs
//! change status in place and keep no change log, so the counts are rebuilt
//! from them rather than moved by deltas; a recount is idempotent and
//! self-correcting. [`counts`] reads them, with the journey's goal
//! conversion from its enrolments.
//!
//! **A person's path.** [`person_path`] lists each of the person's runs of
//! the journey: the nodes in the order they ran, with times and status, the
//! blocks with their reasons, and how the run ended. The caller must be able
//! to read the person.
//!
//! **Erasure.** [`JourneyErasure`] (an `attome_core::erasure_hook`) deletes
//! the person's enrolments, blocks and message log rows and cancels their
//! running journeys, in the erasure's transaction.

use attome_core::EngineState;
use attome_core::erasure_hook::{ErasureFuture, ErasureHook};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

/// The counts job's registered name.
pub const COUNTS_JOB: &str = "marketing_journey_counts";
/// Most versions one recount covers.
const MAX_VERSIONS: i64 = 500;

/// Recomputes the node counts of every version with an active enrolment or
/// one that ended in the last hour; the versions counted.
pub async fn refresh_counts(state: &EngineState) -> Result<usize, AppError> {
    let versions: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT definition_version_id FROM marketing_journey_enrolment \
          WHERE status = 'active' OR ended_at > now() - INTERVAL '1 hour' \
          LIMIT $1",
    )
    .bind(MAX_VERSIONS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if versions.is_empty() {
        return Ok(0);
    }
    recount(&state.base.db, &versions).await?;
    Ok(versions.len())
}

/// The recount of `versions`, one statement.
pub async fn recount(db: &attome_db::DbPool, versions: &[Uuid]) -> Result<(), AppError> {
    sqlx::query(
        "WITH runs AS ( \
             SELECT i.definition_version_id AS v, r.node_id, \
                    COUNT(DISTINCT r.instance_id) AS entered, \
                    COUNT(DISTINCT r.instance_id) FILTER (WHERE r.status = 'waiting') AS waiting, \
                    COUNT(DISTINCT r.instance_id) \
                        FILTER (WHERE r.status IN ('succeeded', 'skipped')) AS passed \
               FROM workflow_node_run r JOIN workflow_instance i ON i.id = r.instance_id \
              WHERE i.definition_version_id = ANY($1) \
              GROUP BY 1, 2), \
         blocks AS ( \
             SELECT i.definition_version_id AS v, b.node_id, \
                    COUNT(DISTINCT b.instance_id) AS blocked \
               FROM marketing_journey_block b JOIN workflow_instance i ON i.id = b.instance_id \
              WHERE i.definition_version_id = ANY($1) \
              GROUP BY 1, 2), \
         exits AS ( \
             SELECT v, node_id, COUNT(*) AS exited FROM ( \
                 SELECT DISTINCT ON (e.instance_id) e.definition_version_id AS v, r.node_id \
                   FROM marketing_journey_enrolment e \
                   JOIN workflow_node_run r ON r.instance_id = e.instance_id \
                  WHERE e.definition_version_id = ANY($1) AND e.status = 'exited' \
                  ORDER BY e.instance_id, r.started_at DESC NULLS LAST, r.id DESC) last \
              GROUP BY 1, 2) \
         INSERT INTO marketing_journey_node_count \
             (definition_version_id, node_id, entered, waiting, passed, blocked, exited) \
         SELECT COALESCE(r.v, b.v, x.v), COALESCE(r.node_id, b.node_id, x.node_id), \
                COALESCE(r.entered, 0), COALESCE(r.waiting, 0), COALESCE(r.passed, 0), \
                COALESCE(b.blocked, 0), COALESCE(x.exited, 0) \
           FROM runs r \
           FULL JOIN blocks b ON b.v = r.v AND b.node_id = r.node_id \
           FULL JOIN exits x ON x.v = COALESCE(r.v, b.v) \
                            AND x.node_id = COALESCE(r.node_id, b.node_id) \
         ON CONFLICT (definition_version_id, node_id) DO UPDATE \
            SET entered = EXCLUDED.entered, waiting = EXCLUDED.waiting, \
                passed = EXCLUDED.passed, blocked = EXCLUDED.blocked, exited = EXCLUDED.exited",
    )
    .bind(versions)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Who may look into journeys.
const READ_PRIVILEGE: &str = "marketing_journey.read";

fn require_read(ctx: &SecurityContext) -> Result<(), AppError> {
    if ctx.is_admin || ctx.privileges.contains(READ_PRIVILEGE) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// One node's counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct NodeCount {
    pub definition_version_id: Uuid,
    pub node_id: String,
    pub entered: i64,
    pub waiting: i64,
    pub passed: i64,
    pub blocked: i64,
    pub exited: i64,
}

/// A journey's counts and goal conversion.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct JourneyCounts {
    pub definition_id: Uuid,
    pub nodes: Vec<NodeCount>,
    /// Enrolments (test ones left out).
    pub enrolled: i64,
    /// Of those, the ones that reached the journey's goal.
    pub converted: i64,
    /// `converted / enrolled`, or 0 with none enrolled.
    pub conversion: f64,
}

/// `converted / enrolled`, 0 with none. Pure.
pub fn conversion(enrolled: i64, converted: i64) -> f64 {
    if enrolled <= 0 {
        0.0
    } else {
        converted as f64 / enrolled as f64
    }
}

/// The node counts of every version of `definition_id`, with its goal
/// conversion.
pub async fn counts(
    state: &EngineState,
    ctx: &SecurityContext,
    definition_id: Uuid,
) -> Result<JourneyCounts, AppError> {
    require_read(ctx)?;
    let nodes: Vec<NodeCount> = sqlx::query_as(
        "SELECT c.definition_version_id, c.node_id, c.entered, c.waiting, c.passed, c.blocked, \
                c.exited \
           FROM marketing_journey_node_count c \
           JOIN workflow_definition_version v ON v.id = c.definition_version_id \
          WHERE v.definition_id = $1 \
          ORDER BY v.version_number, c.node_id",
    )
    .bind(definition_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (enrolled, converted): (i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE goal_reached_at IS NOT NULL) \
           FROM marketing_journey_enrolment WHERE definition_id = $1 AND NOT is_test",
    )
    .bind(definition_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(JourneyCounts {
        definition_id,
        nodes,
        enrolled,
        converted,
        conversion: conversion(enrolled, converted),
    })
}

/// One node a run reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct PathStep {
    pub node_id: String,
    pub status: String,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// One block a guard or step recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct PathBlock {
    pub node_id: String,
    pub reason: String,
    pub at: DateTime<Utc>,
}

/// One of a person's runs of a journey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct PersonRun {
    pub enrolment_id: Uuid,
    pub status: String,
    pub entered_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub end_reason: Option<String>,
    pub steps: Vec<PathStep>,
    pub blocks: Vec<PathBlock>,
}

/// Each of `person_id`'s runs of `definition_id`, oldest first. 404 when the
/// caller cannot read the person.
pub async fn person_path(
    state: &EngineState,
    ctx: &SecurityContext,
    definition_id: Uuid,
    person_id: Uuid,
) -> Result<Vec<PersonRun>, AppError> {
    require_read(ctx)?;
    type Enrolment = (
        Uuid,
        String,
        String,
        Option<Uuid>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
        Option<String>,
    );
    let enrolments: Vec<Enrolment> = sqlx::query_as(
        "SELECT id, person_entity, status, instance_id, entered_at, ended_at, end_reason \
           FROM marketing_journey_enrolment \
          WHERE definition_id = $1 AND person_id = $2 ORDER BY entered_at, id",
    )
    .bind(definition_id)
    .bind(person_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((_, entity, ..)) = enrolments.first() else {
        return Ok(Vec::new());
    };
    if !crate::segment_insight::readable(state, ctx, entity, &[person_id])
        .await?
        .contains(&person_id)
    {
        return Err(AppError::NotFound);
    }
    let mut out = Vec::with_capacity(enrolments.len());
    for (enrolment_id, _, status, instance, entered_at, ended_at, end_reason) in enrolments {
        let (steps, blocks) = match instance {
            Some(instance) => (
                sqlx::query_as::<_, PathStep>(
                    "SELECT node_id, status, started_at, completed_at FROM workflow_node_run \
                      WHERE instance_id = $1 \
                      ORDER BY started_at NULLS LAST, id",
                )
                .bind(instance)
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?,
                sqlx::query_as::<_, PathBlock>(
                    "SELECT node_id, reason, at FROM marketing_journey_block \
                      WHERE instance_id = $1 ORDER BY at, id",
                )
                .bind(instance)
                .fetch_all(&state.base.db)
                .await
                .map_err(AppError::internal)?,
            ),
            None => (Vec::new(), Vec::new()),
        };
        out.push(PersonRun {
            enrolment_id,
            status,
            entered_at,
            ended_at,
            end_reason,
            steps,
            blocks,
        });
    }
    Ok(out)
}

/// A person's journey rows go with them: enrolments, blocks and message log
/// rows deleted, running journeys cancelled.
#[derive(Debug)]
pub struct JourneyErasure;

impl ErasureHook for JourneyErasure {
    fn name(&self) -> &'static str {
        "marketing_journeys"
    }

    fn erase<'a>(
        &'a self,
        conn: &'a mut sqlx::PgConnection,
        _entity: &'a str,
        record_id: Uuid,
    ) -> ErasureFuture<'a> {
        Box::pin(async move {
            let instances: Vec<Uuid> = sqlx::query_scalar(
                "SELECT instance_id FROM marketing_journey_enrolment \
                  WHERE person_id = $1 AND instance_id IS NOT NULL",
            )
            .bind(record_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            let mut removed = 0;
            if !instances.is_empty() {
                removed += sqlx::query(
                    "UPDATE workflow_instance SET status = 'cancelled', completed_at = now(), \
                         row_version = row_version + 1 \
                      WHERE id = ANY($1) AND status IN ('queued', 'running', 'waiting', 'paused')",
                )
                .bind(&instances)
                .execute(&mut *conn)
                .await
                .map_err(AppError::internal)?
                .rows_affected();
                removed +=
                    sqlx::query("DELETE FROM marketing_journey_block WHERE instance_id = ANY($1)")
                        .bind(&instances)
                        .execute(&mut *conn)
                        .await
                        .map_err(AppError::internal)?
                        .rows_affected();
            }
            for sql in [
                "DELETE FROM marketing_journey_enrolment WHERE person_id = $1",
                "DELETE FROM marketing_message_log WHERE person_id = $1",
            ] {
                removed += sqlx::query(sql)
                    .bind(record_id)
                    .execute(&mut *conn)
                    .await
                    .map_err(AppError::internal)?
                    .rows_affected();
            }
            Ok(removed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_is_zero_with_no_enrolments() {
        assert_eq!(conversion(0, 0), 0.0);
        assert_eq!(conversion(4, 1), 0.25);
    }
}

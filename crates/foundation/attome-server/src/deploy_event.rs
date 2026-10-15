//! Deploy and restart history (roadmap AB7-T8): one `start` row per boot
//! (process start to ready) and one `drain` row per shutdown (signal to
//! exit), each with the node, version and who started it, so an operator can
//! see when a node restarted, how long it took and whether requests failed.
//!
//! Recording never stops a boot or a shutdown: every write is bounded by
//! [`WRITE_TIMEOUT`], and a failure is logged and dropped.

use std::time::Duration;

use attome_db::DbPool;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// The longest a history write may hold up a boot or a shutdown.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// The environment variable a deploy script sets to say who started it.
pub const STARTED_BY_ENV: &str = "ATTOME_DEPLOYED_BY";

/// One row of the history.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DeployEvent {
    pub id: Uuid,
    pub node: String,
    pub version: String,
    /// `start` (process start to ready) or `drain` (shutdown signal to exit).
    pub kind: String,
    pub started_by: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    /// Server errors answered while the node drained; empty when not counted.
    pub failed_requests: Option<i64>,
}

/// Who started this process, from [`STARTED_BY_ENV`]; at most 200 characters.
pub fn started_by() -> Option<String> {
    started_by_from(std::env::var(STARTED_BY_ENV).ok())
}

fn started_by_from(raw: Option<String>) -> Option<String> {
    raw.map(|who| who.trim().chars().take(200).collect::<String>())
        .filter(|who| !who.is_empty())
}

/// Records a finished boot: the process started at `started_at` and is ready
/// now.
pub async fn record_start(db: &DbPool, node: &str, version: &str, started_at: DateTime<Utc>) {
    let insert = sqlx::query(
        "INSERT INTO deploy_event (node, version, kind, started_by, started_at, finished_at) \
         VALUES ($1, $2, 'start', $3, $4, now())",
    )
    .bind(node)
    .bind(version)
    .bind(started_by())
    .bind(started_at)
    .execute(db);
    match tokio::time::timeout(WRITE_TIMEOUT, insert).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "deploy history: start row not written"),
        Err(_) => tracing::warn!("deploy history: start row timed out"),
    }
}

/// Records the start of a drain; returns the row to finish at exit.
pub async fn record_drain(db: &DbPool, node: &str, version: &str) -> Option<Uuid> {
    let insert = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO deploy_event (node, version, kind, started_by, started_at) \
         VALUES ($1, $2, 'drain', $3, now()) RETURNING id",
    )
    .bind(node)
    .bind(version)
    .bind(started_by())
    .fetch_one(db);
    match tokio::time::timeout(WRITE_TIMEOUT, insert).await {
        Ok(Ok(id)) => Some(id),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "deploy history: drain row not written");
            None
        }
        Err(_) => {
            tracing::warn!("deploy history: drain row timed out");
            None
        }
    }
}

/// Closes a drain row at exit.
pub async fn finish_drain(db: &DbPool, id: Uuid, failed_requests: Option<i64>) {
    let update = sqlx::query(
        "UPDATE deploy_event SET finished_at = now(), failed_requests = $2 \
         WHERE id = $1 AND finished_at IS NULL",
    )
    .bind(id)
    .bind(failed_requests)
    .execute(db);
    match tokio::time::timeout(WRITE_TIMEOUT, update).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "deploy history: drain row not closed"),
        Err(_) => tracing::warn!("deploy history: closing the drain row timed out"),
    }
}

/// The most recent `limit` rows, newest first.
pub async fn recent(db: &DbPool, limit: i64) -> Result<Vec<DeployEvent>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, node, version, kind, started_by, started_at, finished_at, failed_requests \
         FROM deploy_event ORDER BY started_at DESC, id DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(db)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn started_by_is_trimmed_and_bounded() {
        let long = Some(format!("  {}  ", "a".repeat(300)));
        assert_eq!(started_by_from(long).map(|who| who.len()), Some(200));
        assert_eq!(
            started_by_from(Some(" ci-deploy ".into())).as_deref(),
            Some("ci-deploy")
        );
        assert_eq!(started_by_from(Some("   ".into())), None);
        assert_eq!(started_by_from(None), None);
    }
}

//! AB2-T6: every database failover and switchover, recorded.
//!
//! The 15-second `ops_cluster_poll` job reads Patroni's `GET /cluster` from
//! the first node in `config.ops.patroni_api_urls` that answers (two seconds
//! each; the nodes are the operator's, so their private addresses are
//! allowed for this call only), and [`record_leader`] stores the leader. A
//! new leader (or a new timeline) is a new `ops_failover_event` row, kept
//! once by its unique `(kind, new_leader, timeline)`; when it replaces an
//! earlier leader, an `ops.failover_recorded` security event commits with
//! it. With no Patroni URLs configured the job does nothing (V2-D100: one
//! server is the normal deployment).

use std::time::Duration;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::error::OpsError;

/// The registered job.
pub const JOB: &str = "ops_cluster_poll";

/// How long one node may take to answer.
const NODE_TIMEOUT: Duration = Duration::from_secs(2);

/// One Patroni member as `/cluster` lists it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Member {
    pub name: String,
    /// `leader`, `standby_leader`, `replica` or `sync_standby`.
    pub role: String,
    #[serde(default)]
    pub state: Option<String>,
    /// Bytes behind the leader, or `"unknown"`.
    #[serde(default)]
    pub lag: Option<Value>,
    #[serde(default)]
    pub timeline: Option<i64>,
}

/// What `/cluster` answered.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PatroniCluster {
    pub members: Vec<Member>,
}

impl PatroniCluster {
    /// The member that leads, if any.
    pub fn leader(&self) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| m.role == "leader" || m.role == "standby_leader")
    }
}

/// Reads a `/cluster` answer. Pure.
pub fn parse_cluster(body: &Value) -> Result<PatroniCluster, OpsError> {
    let members = body
        .get("members")
        .cloned()
        .ok_or_else(|| OpsError::Validation("the Patroni answer has no members".into()))?;
    let members: Vec<Member> = serde_json::from_value(members)
        .map_err(|e| OpsError::Validation(format!("the Patroni members do not read: {e}")))?;
    Ok(PatroniCluster { members })
}

/// The cluster as the first answering node sees it.
pub async fn fetch_cluster(urls: &[String]) -> Result<PatroniCluster, OpsError> {
    let purpose = attome_outbound::http::Purpose::public("patroni")
        .with_private_urls(urls.iter().map(String::as_str))
        .no_redirects();
    let http = attome_outbound::http::client(purpose, |b| b.timeout(NODE_TIMEOUT))
        .map_err(|e| OpsError::Internal(e.to_string()))?;
    for url in urls {
        let target = format!("{}/cluster", url.trim_end_matches('/'));
        let answer = match http.get(&target).send().await {
            Ok(res) if res.status().is_success() => res.json::<Value>().await.ok(),
            Ok(res) => {
                tracing::debug!(node = %url, status = res.status().as_u16(), "patroni: node did not answer the cluster");
                None
            }
            Err(error) => {
                tracing::debug!(node = %url, %error, "patroni: node unreachable");
                None
            }
        };
        if let Some(cluster) = answer.and_then(|body| parse_cluster(&body).ok()) {
            return Ok(cluster);
        }
    }
    Err(OpsError::Unavailable("patroni"))
}

/// Stores the cluster's leader; answers whether a new event was recorded.
pub async fn record_leader(
    state: &EngineState,
    cluster: &PatroniCluster,
) -> Result<bool, OpsError> {
    let Some(leader) = cluster.leader() else {
        return Ok(false);
    };
    let internal = |e: sqlx::Error| OpsError::Internal(e.to_string());
    let mut tx = attome_db::tx::begin(&state.base.db)
        .await
        .map_err(|e| OpsError::Internal(e.to_string()))?;
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT new_leader FROM ops_failover_event \
          WHERE kind IN ('failover', 'switchover') ORDER BY started_at DESC, id DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO ops_failover_event (id, kind, old_leader, new_leader, timeline, started_at) \
         VALUES (uuidv7(), 'failover', $1, $2, $3, now()) \
         ON CONFLICT (kind, new_leader, timeline) DO NOTHING \
         RETURNING id",
    )
    .bind(&previous)
    .bind(&leader.name)
    .bind(leader.timeline)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let Some(event) = inserted else {
        return Ok(false);
    };
    if let Some(old) = previous.as_deref().filter(|old| *old != leader.name) {
        write_security_event(
            &mut tx,
            &attome_audit::audit_service(state),
            SecurityEvent::new(
                MandatoryCategory::Configuration,
                AuditOperation::Update,
                Uuid::nil(),
                "ops_failover_event",
                Some(event),
            )
            .named("ops.failover_recorded")
            .comment(format!(
                "the database leader moved from {old} to {} (timeline {})",
                leader.name,
                leader
                    .timeline
                    .map_or_else(|| "unknown".to_owned(), |t| t.to_string())
            )),
        )
        .await
        .map_err(|e| OpsError::Internal(e.to_string()))?;
        tracing::warn!(from = %old, to = %leader.name, "database leader changed");
    }
    attome_db::tx::commit(tx)
        .await
        .map_err(|e| OpsError::Internal(e.to_string()))?;
    Ok(true)
}

/// One poll: nothing without Patroni URLs.
pub async fn poll(state: &EngineState) -> Result<bool, OpsError> {
    let urls = &state.base.config.ops.patroni_api_urls;
    if urls.is_empty() {
        return Ok(false);
    }
    let cluster = fetch_cluster(urls).await?;
    record_leader(state, &cluster).await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn cluster(leader: &str, timeline: i64) -> Value {
        json!({ "members": [
            { "name": leader, "role": "leader", "state": "running", "timeline": timeline },
            { "name": "db9", "role": "replica", "state": "streaming", "lag": 0, "timeline": timeline }
        ]})
    }

    #[test]
    fn the_leader_is_read_from_the_members() {
        let parsed = parse_cluster(&cluster("db1", 4)).unwrap();
        let leader = parsed.leader().unwrap();
        assert_eq!(leader.name, "db1");
        assert_eq!(leader.timeline, Some(4));
        assert!(parse_cluster(&json!({})).is_err());
        let none =
            parse_cluster(&json!({ "members": [{ "name": "a", "role": "replica" }] })).unwrap();
        assert!(none.leader().is_none());
    }

    #[tokio::test]
    async fn ops_cluster_is_read_from_the_first_node_that_answers() {
        let router = axum::Router::new().route(
            "/cluster",
            axum::routing::get(|| async { axum::Json(cluster("db2", 7)) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let dead = "http://127.0.0.1:1".to_owned();
        let live = format!("http://{addr}");
        let read = fetch_cluster(&[dead.clone(), live]).await.unwrap();
        assert_eq!(read.leader().unwrap().name, "db2");
        assert!(fetch_cluster(&[dead]).await.is_err());
    }
}

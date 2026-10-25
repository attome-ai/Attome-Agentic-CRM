//! AB2-T7: the cluster's status and its failover history, for `ops.read`.
//!
//! - `GET /api/v1/ops/cluster`: `single` with leader `local` when no
//!   Patroni cluster is configured; otherwise `ha` with the members Patroni
//!   reports, read at most every five seconds per node (a cached copy of
//!   what `/cluster` answered, rebuilt on expiry). A cluster that does not
//!   answer is `ha` with no leader and no members, never an error.
//! - `GET /api/v1/ops/failovers`: the recorded failovers (AB2-T6), newest
//!   first, one-based pages.

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::cluster::PatroniCluster;
use crate::upgrades::OpsRead;

/// How long one read of the cluster is reused.
const CACHE_TTL: Duration = Duration::from_secs(5);

static CACHE: LazyLock<Mutex<Option<(Instant, ClusterStatus)>>> =
    LazyLock::new(|| Mutex::new(None));

/// One recorded failover.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct FailoverEvent {
    pub id: Uuid,
    /// `failover`, `switchover` or `redis_failover`.
    pub kind: String,
    pub old_leader: Option<String>,
    pub new_leader: String,
    pub timeline: Option<i64>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<i64>,
    pub writes_lost: Option<i64>,
    pub cause: Option<String>,
}

/// One database node.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClusterMember {
    pub name: String,
    pub role: String,
    pub state: Option<String>,
    /// Bytes behind the leader, when Patroni knows.
    pub lag_bytes: Option<i64>,
    pub timeline: Option<i64>,
}

/// The cluster now.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClusterStatus {
    /// `single` (no Patroni cluster configured) or `ha`.
    pub mode: String,
    pub leader: Option<String>,
    pub members: Vec<ClusterMember>,
    pub synchronous_standby: Option<String>,
    pub last_failover: Option<FailoverEvent>,
}

/// The status a Patroni answer describes. Pure.
pub fn status_of(cluster: &PatroniCluster) -> ClusterStatus {
    ClusterStatus {
        mode: "ha".into(),
        leader: cluster.leader().map(|m| m.name.clone()),
        members: cluster
            .members
            .iter()
            .map(|m| ClusterMember {
                name: m.name.clone(),
                role: m.role.clone(),
                state: m.state.clone(),
                lag_bytes: m.lag.as_ref().and_then(serde_json::Value::as_i64),
                timeline: m.timeline,
            })
            .collect(),
        synchronous_standby: cluster
            .members
            .iter()
            .find(|m| m.role == "sync_standby")
            .map(|m| m.name.clone()),
        last_failover: None,
    }
}

const EVENT_COLUMNS: &str = "id, kind, old_leader, new_leader, timeline, started_at, ended_at, \
     duration_ms, writes_lost, cause";

/// The database cluster's status
///
/// AB2-T7: `single` without a configured Patroni cluster; otherwise the
/// members Patroni reports (read at most every five seconds) and the last
/// recorded failover. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/cluster",
    tag = "ops",
    operation_id = "get_ops_cluster",
    responses(
        (status = 200, description = "The cluster's status", body = ClusterStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_cluster(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
) -> Result<Json<ClusterStatus>, AppError> {
    cluster_status(&state).await.map(Json)
}

/// The cluster's status, as `GET /api/v1/ops/cluster` answers it (the
/// `ops.cluster_status` agent action reads it too, AB2-T12).
pub async fn cluster_status(state: &EngineState) -> Result<ClusterStatus, AppError> {
    let urls = &state.base.config.ops.patroni_api_urls;
    if urls.is_empty() {
        return Ok(ClusterStatus {
            mode: "single".into(),
            leader: Some("local".into()),
            members: Vec::new(),
            synchronous_standby: None,
            last_failover: None,
        });
    }
    let cached = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .filter(|(at, _)| at.elapsed() < CACHE_TTL)
        .map(|(_, status)| status.clone());
    let mut status = match cached {
        Some(status) => status,
        None => {
            let status = match crate::cluster::fetch_cluster(urls).await {
                Ok(cluster) => status_of(&cluster),
                Err(error) => {
                    tracing::warn!(%error, "ops cluster: no Patroni node answered");
                    ClusterStatus {
                        mode: "ha".into(),
                        leader: None,
                        members: Vec::new(),
                        synchronous_standby: None,
                        last_failover: None,
                    }
                }
            };
            *CACHE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some((Instant::now(), status.clone()));
            status
        }
    };
    status.last_failover = sqlx::query_as(&format!(
        "SELECT {EVENT_COLUMNS} FROM ops_failover_event ORDER BY started_at DESC, id DESC LIMIT 1"
    ))
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(status)
}

/// List failovers
///
/// AB2-T7: every recorded failover and switchover, newest first. Needs
/// `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/failovers",
    tag = "ops",
    operation_id = "list_ops_failovers",
    params(OnePageQuery),
    responses(
        (status = 200, description = "One page of failovers", body = PaginatedResponse<FailoverEvent>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_failovers(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<FailoverEvent>>, AppError> {
    let w = page.window();
    let items: Vec<FailoverEvent> = sqlx::query_as(&format!(
        "SELECT {EVENT_COLUMNS} FROM ops_failover_event \
          ORDER BY started_at DESC, id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ops_failover_event")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        w.page,
        w.page_size,
    )))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ops/cluster", get(get_cluster))
        .route("/api/v1/ops/failovers", get(list_failovers))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_cluster, list_failovers),
    components(schemas(ClusterStatus, ClusterMember, FailoverEvent))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn ha_mode_lists_members_from_patroni() {
        let cluster = crate::cluster::parse_cluster(&json!({ "members": [
            { "name": "db1", "role": "leader", "state": "running", "timeline": 3 },
            { "name": "db2", "role": "sync_standby", "state": "streaming", "lag": 16, "timeline": 3 },
            { "name": "db3", "role": "replica", "state": "streaming", "lag": "unknown" }
        ]}))
        .unwrap();
        let status = status_of(&cluster);
        assert_eq!(status.mode, "ha");
        assert_eq!(status.leader.as_deref(), Some("db1"));
        assert_eq!(status.synchronous_standby.as_deref(), Some("db2"));
        assert_eq!(status.members.len(), 3);
        assert_eq!(status.members[1].lag_bytes, Some(16));
        assert_eq!(status.members[2].lag_bytes, None);
    }
}

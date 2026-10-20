//! G5-T3: agent presence and who else is viewing a record.
//!
//! **Presence** is the person's own setting `service.presence`
//! (`available`, `busy` or `away`, default `available`), set through
//! `PUT /api/v1/settings/me/service.presence`. Automatic queue distribution
//! (`round_robin`, `least_loaded`) routes only to available members; a
//! manual assignment or a self-claim still works, because a person picking
//! work is deciding for themselves.
//!
//! **Viewers.** `POST /api/v1/service/viewing` says "I am looking at this
//! record" and answers who else is. The workspace sends it every
//! [`HEARTBEAT_SECS`] while a record is open.
//!
//! - Source of truth: the heartbeats themselves; nothing durable.
//! - Key: `service:viewers:{entity}:{record_id}`, one JSON map of user id to
//!   the last heartbeat's Unix second, at most [`MAX_VIEWERS`] entries.
//! - TTL: [`KEY_TTL`]; an entry older than [`STALE_SECS`] is dropped on the
//!   next write and never shown.
//! - Invalidation: none needed; heartbeats overwrite.
//! - Failure: a Redis error shows nobody (presence is a courtesy) and is
//!   logged at `warn`; the route still answers 200.
//! - Cold start: empty until the first heartbeat.
//!
//! Two heartbeats at the same moment may each write a map without the
//! other; the lost viewer reappears on their next heartbeat.

use std::collections::BTreeMap;
use std::time::Duration;

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// How often an open record says it is still open.
pub const HEARTBEAT_SECS: i64 = 30;
/// A viewer not heard from for this long has left.
pub const STALE_SECS: i64 = 75;
/// Most viewers kept per record.
pub const MAX_VIEWERS: usize = 50;
/// How long the key outlives its last heartbeat.
const KEY_TTL: Duration = Duration::from_secs(120);

/// Whether a `service.presence` value lets automatic distribution route
/// work to the person. Anything but `busy` or `away` is available. Pure.
pub fn routes_work(presence: &serde_json::Value) -> bool {
    !matches!(presence.as_str(), Some("busy" | "away"))
}

/// The person's `service.presence`.
pub fn presence_of(state: &EngineState, user: Uuid) -> serde_json::Value {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get("service.presence")
        .map(|d| store.resolve(d, Some(user), None).0)
        .unwrap_or_else(|| json!("available"))
}

/// Whether automatic distribution may route work to `user`.
pub fn is_available(state: &EngineState, user: Uuid) -> bool {
    routes_work(&presence_of(state, user))
}

/// The heartbeat map after `user` says they are viewing at `now`: stale
/// entries dropped, then the oldest past [`MAX_VIEWERS`]. Pure.
pub fn beat(mut seen: BTreeMap<Uuid, i64>, user: Uuid, now: i64) -> BTreeMap<Uuid, i64> {
    seen.retain(|_, at| now - *at <= STALE_SECS);
    seen.insert(user, now);
    while seen.len() > MAX_VIEWERS {
        let oldest = seen
            .iter()
            .filter(|(id, _)| **id != user)
            .min_by_key(|(_, at)| **at)
            .map(|(id, _)| *id);
        match oldest {
            Some(id) => {
                seen.remove(&id);
            }
            None => break,
        }
    }
    seen
}

/// The other people in `seen`, most recent first. Pure.
pub fn others(seen: &BTreeMap<Uuid, i64>, user: Uuid, now: i64) -> Vec<Uuid> {
    let mut out: Vec<(Uuid, i64)> = seen
        .iter()
        .filter(|(id, at)| **id != user && now - **at <= STALE_SECS)
        .map(|(id, at)| (*id, *at))
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out.into_iter().map(|(id, _)| id).collect()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ViewingRequest {
    /// The record's entity logical name.
    pub entity: String,
    pub record_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Viewer {
    pub user_id: Uuid,
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ViewingResponse {
    /// Everyone else viewing the record now, most recent first.
    pub viewers: Vec<Viewer>,
    /// Seconds until the next heartbeat is due.
    pub heartbeat_secs: i64,
}

fn viewers_key(entity: &str, record_id: Uuid) -> String {
    format!("service:viewers:{entity}:{record_id}")
}

/// Records the caller's heartbeat on a record they can read and returns the
/// others viewing it. `NotFound` for an unknown entity or a record the
/// caller cannot read.
pub async fn viewing(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    request: &ViewingRequest,
) -> Result<ViewingResponse, AppError> {
    if state.entities.load().get(&request.entity).is_none() {
        return Err(AppError::NotFound);
    }
    if !attome_records::entity_crud::referenced_record_visible(
        state,
        ctx,
        &request.entity,
        request.record_id,
    )
    .await?
    {
        return Err(AppError::NotFound);
    }

    let key = viewers_key(&request.entity, request.record_id);
    let now = chrono::Utc::now().timestamp();
    let redis = &state.base.redis;
    let seen: BTreeMap<Uuid, i64> = match redis.get(&key).await {
        Ok(Some(text)) => serde_json::from_str(&text).unwrap_or_default(),
        Ok(None) => BTreeMap::new(),
        Err(error) => {
            tracing::warn!(%error, entity = %request.entity, "record viewers unavailable");
            return Ok(ViewingResponse {
                viewers: Vec::new(),
                heartbeat_secs: HEARTBEAT_SECS,
            });
        }
    };
    let seen = beat(seen, ctx.user_id, now);
    let text = serde_json::to_string(&seen).map_err(AppError::internal)?;
    if let Err(error) = redis.set(&key, text, Some(KEY_TTL)).await {
        tracing::warn!(%error, entity = %request.entity, "record viewer heartbeat not stored");
    }

    let ids = others(&seen, ctx.user_id, now);
    let names: Vec<(Uuid, Option<String>)> = if ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT id, user_name FROM user_account WHERE id = ANY($1) AND is_active IS NOT FALSE",
        )
        .bind(&ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
    };
    let viewers = ids
        .iter()
        .filter_map(|id| {
            names.iter().find(|(n, _)| n == id).map(|(_, name)| Viewer {
                user_id: *id,
                name: name.clone().unwrap_or_default(),
            })
        })
        .collect();
    Ok(ViewingResponse {
        viewers,
        heartbeat_secs: HEARTBEAT_SECS,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/service/viewing",
    tag = "service",
    request_body = ViewingRequest,
    responses(
        (status = 200, description = "Who else is viewing the record", body = ViewingResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Telemetry,
        None,
        "a viewing heartbeat kept two minutes in Redis; no business or security effect",
    )))),
)]
async fn post_viewing(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(request): Json<ViewingRequest>,
) -> Result<Json<ViewingResponse>, AppError> {
    viewing(&state, &ctx, &request).await.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/service/viewing", post(post_viewing))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_viewing),
    components(schemas(ViewingRequest, ViewingResponse, Viewer))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_busy_and_away_stop_routing() {
        assert!(routes_work(&json!("available")));
        assert!(routes_work(&serde_json::Value::Null));
        assert!(!routes_work(&json!("busy")));
        assert!(!routes_work(&json!("away")));
    }

    #[test]
    fn heartbeats_drop_the_stale_and_list_the_others() {
        let me = Uuid::now_v7();
        let colleague = Uuid::now_v7();
        let gone = Uuid::now_v7();
        let mut seen = BTreeMap::new();
        seen.insert(colleague, 1_000);
        seen.insert(gone, 1_000 - STALE_SECS - 100);
        let seen = beat(seen, me, 1_010);
        assert!(!seen.contains_key(&gone));
        assert_eq!(others(&seen, me, 1_010), vec![colleague]);
        assert!(others(&seen, colleague, 1_010 + STALE_SECS + 1).is_empty());
    }

    #[test]
    fn the_map_stays_bounded_and_keeps_the_caller() {
        let mut seen = BTreeMap::new();
        for i in 0..(MAX_VIEWERS as i64 + 5) {
            seen.insert(Uuid::now_v7(), 2_000 + i);
        }
        let me = Uuid::now_v7();
        let seen = beat(seen, me, 2_060);
        assert_eq!(seen.len(), MAX_VIEWERS);
        assert_eq!(seen.get(&me), Some(&2_060));
    }
}

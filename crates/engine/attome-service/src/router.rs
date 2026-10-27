//! J10-T1: the unified router. Every channel's work is a V7 queue item
//! (`queue_item`, V7-T1) with a `channel` (case, chat, call, email, social,
//! task), its queue, the skills it needs (`queue_item_skill`, G4-T1), a
//! priority and an `sla_due_at` (platform changeset 0078). The router offers
//! each waiting item to the best available agent and, when the offer is not
//! taken within [`OFFER_SECONDS`], to the next; an item waiting longer than
//! its queue's `overflow_after_minutes` moves to the queue's
//! `overflow_queue_ref`.
//!
//! The agents are the active members of the service queue with the item's
//! queue id (the V7 queues carry the service queues' ids). One is eligible
//! when their presence routes work (G5-T3), they hold every needed skill at
//! its level, they have not been offered the item already, and their picked
//! items on the item's channel are under their capacity for it
//! (`agent_channel_capacity`, else [`default_capacity`]: 3 chats, 1 call).
//! The best is the least loaded on that channel, then overall
//! ([`best_agent`]). Offers live in `queue_offer` (migration 0311); one
//! item has at most one open offer, and each offer is made under the queue's
//! advisory lock (`attome-service/router-offer:<queue_id>`, this crate's
//! namespace), so two routers never offer the same item twice.
//!
//! [`tick`] runs every 15 seconds (a registered job): it expires offers past
//! their time, overflows items, then offers every waiting item without an
//! open offer, most urgent first (priority, then SLA due, then age), at most
//! [`TICK_ITEMS`] a run. `POST /api/v1/queue-offers/{id}/accept` picks the
//! item for the agent (and assigns a held service ticket that has no
//! assignee); `/decline` refuses it and the next agent is offered it.
//!
//! Intake routing of work requests to a queue stays `crate::routing`.

use std::collections::{HashMap, HashSet};

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::schedule_candidates::{NeededSkill, skills_cover};

/// The registered job that runs [`tick`].
pub const TICK_JOB: &str = "service_router_tick";

/// How long an agent has to accept an offer.
pub const OFFER_SECONDS: i64 = 30;
/// Waiting items offered in one tick.
pub const TICK_ITEMS: i64 = 200;
/// The open offers one agent's list returns.
pub const MAX_OFFERS_LISTED: i64 = 50;

/// The items an agent handles at once on `channel` when no
/// `agent_channel_capacity` row says otherwise. Pure.
pub fn default_capacity(channel: &str) -> i64 {
    match channel {
        "chat" | "social" => 3,
        "call" => 1,
        _ => 5,
    }
}

/// What the router knows about one agent for one item.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentView {
    pub user: Uuid,
    /// Picked items on the item's channel.
    pub channel_load: i64,
    /// Picked items on every channel.
    pub total_load: i64,
    pub capacity: i64,
    pub available: bool,
    pub has_skills: bool,
    /// Already offered this item (declined, expired or withdrawn).
    pub tried: bool,
}

/// The agent to offer the item to: eligible (available, skilled, not tried,
/// under capacity), least loaded on the channel, then overall, then by id.
/// Pure.
pub fn best_agent(agents: &[AgentView]) -> Option<Uuid> {
    agents
        .iter()
        .filter(|a| a.available && a.has_skills && !a.tried && a.channel_load < a.capacity)
        .min_by_key(|a| (a.channel_load, a.total_load, a.user))
        .map(|a| a.user)
}

/// Whether an item that entered at `entered` has waited past
/// `after_minutes` at `now`. Pure.
pub fn overflow_due(
    entered: DateTime<Utc>,
    now: DateTime<Utc>,
    after_minutes: Option<i64>,
) -> bool {
    after_minutes.is_some_and(|m| m >= 0 && now - entered >= Duration::minutes(m))
}

/// What a tick did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickStats {
    pub expired: u64,
    pub overflowed: u64,
    pub offered: u64,
}

async fn tables_ready(db: &attome_db::DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT to_regclass('queue_offer') IS NOT NULL \
            AND to_regclass('queue_item') IS NOT NULL \
            AND to_regclass('service_work_queue_member') IS NOT NULL \
            AND EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = current_schema() AND table_name = 'queue_item' \
                           AND column_name = 'channel')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// One router run: expire, overflow, offer.
pub async fn tick(state: &EngineState) -> Result<TickStats, AppError> {
    let db = &state.base.db;
    let mut stats = TickStats::default();
    if !tables_ready(db).await? {
        return Ok(stats);
    }
    // 1. Offers past their time.
    stats.expired = sqlx::query(
        "UPDATE queue_offer SET status = 'expired', decided_at = now() \
          WHERE status = 'offered' AND expires_at <= now()",
    )
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    // 2. Overflow.
    let due: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
        "SELECT i.id, i.queue_ref, q.overflow_queue_ref FROM queue_item i \
           JOIN queue q ON q.id = i.queue_ref \
          WHERE i.status = 'waiting' AND i.is_active IS NOT FALSE \
            AND q.overflow_queue_ref IS NOT NULL AND q.overflow_queue_ref <> q.id \
            AND q.overflow_after_minutes IS NOT NULL \
            AND i.entered_at <= now() - make_interval(mins => q.overflow_after_minutes::int) \
          ORDER BY i.entered_at LIMIT $1",
    )
    .bind(TICK_ITEMS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (item, from, to) in due {
        if overflow(state, item, from, to).await? {
            stats.overflowed += 1;
        }
    }
    // 3. Offers for waiting items without one.
    let waiting: Vec<Uuid> = sqlx::query_scalar(
        "SELECT i.id FROM queue_item i \
          WHERE i.status = 'waiting' AND i.is_active IS NOT FALSE \
            AND NOT EXISTS (SELECT 1 FROM queue_offer o WHERE o.item_id = i.id AND o.status = 'offered') \
          ORDER BY CASE i.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 \
                                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, \
                   i.sla_due_at NULLS LAST, i.entered_at \
          LIMIT $1",
    )
    .bind(TICK_ITEMS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for item in waiting {
        if offer_next(state, item).await?.is_some() {
            stats.offered += 1;
        }
    }
    Ok(stats)
}

/// Moves a waiting item to its queue's overflow queue, withdrawing its open
/// offer. `false` when it changed meanwhile.
async fn overflow(state: &EngineState, item: Uuid, from: Uuid, to: Uuid) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let moved = sqlx::query(
        "UPDATE queue_item SET queue_ref = $3, modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND queue_ref = $2 AND status = 'waiting'",
    )
    .bind(item)
    .bind(from)
    .bind(to)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if moved == 0 {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE queue_offer SET status = 'withdrawn', decided_at = now() \
          WHERE item_id = $1 AND status = 'offered'",
    )
    .bind(item)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO queue_item_event (id, item_id, kind, queue_id, to_queue_id, actor) \
         VALUES ($1, $2, 'transfer', $3, $4, NULL)",
    )
    .bind(Uuid::now_v7())
    .bind(item)
    .bind(from)
    .bind(to)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

type ItemRow = (Uuid, String, Option<String>);

/// Offers waiting item `item` to the best eligible agent; `None` when none
/// is eligible, the item is not waiting, it has an open offer, or another
/// router holds the queue's lock.
pub async fn offer_next(state: &EngineState, item: Uuid) -> Result<Option<Uuid>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<ItemRow> = sqlx::query_as(
        "SELECT queue_ref, status::text, channel::text FROM queue_item \
          WHERE id = $1 AND is_active IS NOT FALSE FOR UPDATE",
    )
    .bind(item)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((queue, status, channel)) = row else {
        return Ok(None);
    };
    if status != "waiting" {
        return Ok(None);
    }
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-service/router-offer:{queue}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(None);
    }
    let open: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM queue_offer WHERE item_id = $1 AND status = 'offered')",
    )
    .bind(item)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if open {
        return Ok(None);
    }
    let channel = channel.unwrap_or_else(|| "case".to_owned());
    let agents = agents_for(state, &mut tx, item, queue, &channel).await?;
    let Some(agent) = best_agent(&agents) else {
        return Ok(None);
    };
    sqlx::query(
        "INSERT INTO queue_offer (id, item_id, queue_id, user_id, channel, expires_at) \
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(Uuid::now_v7())
    .bind(item)
    .bind(queue)
    .bind(agent)
    .bind(&channel)
    .bind(OFFER_SECONDS as f64)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Some(agent))
}

/// The queue's active members as the router sees them for `item`.
async fn agents_for(
    state: &EngineState,
    tx: &mut Transaction<'_, Postgres>,
    item: Uuid,
    queue: Uuid,
    channel: &str,
) -> Result<Vec<AgentView>, AppError> {
    let members: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT user_ref FROM service_work_queue_member \
          WHERE queue_ref = $1 AND user_ref IS NOT NULL AND (is_active IS NULL OR is_active = true) \
          ORDER BY user_ref",
    )
    .bind(queue)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if members.is_empty() {
        return Ok(Vec::new());
    }
    let loads: Vec<(Uuid, i64, i64)> = sqlx::query_as(
        "SELECT assigned_ref, COUNT(*) FILTER (WHERE channel::text = $2), COUNT(*) FROM queue_item \
          WHERE assigned_ref = ANY($1) AND status = 'picked' AND is_active IS NOT FALSE \
          GROUP BY assigned_ref",
    )
    .bind(&members)
    .bind(channel)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let loads: HashMap<Uuid, (i64, i64)> = loads.into_iter().map(|(u, c, t)| (u, (c, t))).collect();
    let capacities: Vec<(Uuid, Option<f64>)> = sqlx::query_as(
        "SELECT user_ref, max_items::float8 FROM agent_channel_capacity \
          WHERE user_ref = ANY($1) AND channel::text = $2 AND is_active IS NOT FALSE",
    )
    .bind(&members)
    .bind(channel)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let capacities: HashMap<Uuid, i64> = capacities
        .into_iter()
        .filter_map(|(u, c)| c.map(|c| (u, c as i64)))
        .collect();
    let tried: HashSet<Uuid> =
        sqlx::query_scalar::<_, Uuid>("SELECT user_id FROM queue_offer WHERE item_id = $1")
            .bind(item)
            .fetch_all(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
    let need: Vec<NeededSkill> = sqlx::query_as::<_, (String, Option<f64>)>(
        "SELECT skill, min_level::float8 FROM queue_item_skill \
          WHERE queue_item_ref = $1 AND is_active IS NOT FALSE",
    )
    .bind(item)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .filter_map(|(skill, min_level)| {
        let skill = skill.trim().to_lowercase();
        (!skill.is_empty()).then_some(NeededSkill { skill, min_level })
    })
    .collect();
    let mut skills: HashMap<Uuid, HashMap<String, Option<f64>>> = HashMap::new();
    if !need.is_empty() {
        let rows: Vec<(Uuid, String, Option<f64>)> = sqlx::query_as(
            "SELECT user_id, skill, skill_level::float8 FROM resource_skill \
              WHERE user_id = ANY($1) AND is_active IS NOT FALSE",
        )
        .bind(&members)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        for (user, skill, level) in rows {
            let entry = skills
                .entry(user)
                .or_default()
                .entry(skill.trim().to_lowercase())
                .or_insert(level);
            if level > *entry {
                *entry = level;
            }
        }
    }
    let none = HashMap::new();
    Ok(members
        .into_iter()
        .map(|user| {
            let (channel_load, total_load) = loads.get(&user).copied().unwrap_or((0, 0));
            AgentView {
                user,
                channel_load,
                total_load,
                capacity: capacities
                    .get(&user)
                    .copied()
                    .unwrap_or_else(|| default_capacity(channel)),
                available: crate::presence::is_available(state, user),
                has_skills: skills_cover(skills.get(&user).unwrap_or(&none), &need),
                tried: tried.contains(&user),
            }
        })
        .collect())
}

/// An offer of a queue item to an agent.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct QueueOffer {
    pub id: Uuid,
    pub item_id: Uuid,
    pub queue_id: Uuid,
    pub channel: String,
    /// `offered`, `accepted`, `declined`, `expired` or `withdrawn`.
    pub status: String,
    pub offered_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

const OFFER_COLUMNS: &str = "id, item_id, queue_id, channel, status, offered_at, expires_at";

/// Takes the caller's open offer `id` for `decision` (`accepted` or
/// `declined`), returning it and its item.
async fn decide(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    user: Uuid,
    decision: &str,
) -> Result<QueueOffer, AppError> {
    let offer: Option<QueueOffer> = sqlx::query_as(&format!(
        "UPDATE queue_offer SET status = $3, decided_at = now() \
          WHERE id = $1 AND user_id = $2 AND status = 'offered' AND expires_at > now() \
          RETURNING {OFFER_COLUMNS}"
    ))
    .bind(id)
    .bind(user)
    .bind(decision)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(offer) = offer {
        return Ok(offer);
    }
    let mine: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM queue_offer WHERE id = $1 AND user_id = $2)",
    )
    .bind(id)
    .bind(user)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if mine {
        Err(AppError::Conflict("this offer is no longer open"))
    } else {
        Err(AppError::NotFound)
    }
}

/// Accepts the caller's offer: the item is picked for them, and a service
/// ticket it holds with no assignee is assigned to them.
pub async fn accept(state: &EngineState, user: Uuid, id: Uuid) -> Result<QueueOffer, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let offer = decide(&mut tx, id, user, "accepted").await?;
    let item: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "UPDATE queue_item SET status = 'picked', assigned_ref = $2, modified_at = now(), \
                modified_by = $2, row_version = row_version + 1 \
          WHERE id = $1 AND status = 'waiting' AND is_active IS NOT FALSE \
          RETURNING record_entity, record_id",
    )
    .bind(offer.item_id)
    .bind(user)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((record_entity, record_id)) = item else {
        return Err(AppError::Conflict("this item was taken meanwhile"));
    };
    sqlx::query(
        "INSERT INTO queue_item_event (id, item_id, kind, queue_id, to_queue_id, actor) \
         VALUES ($1, $2, 'pick', $3, NULL, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(offer.item_id)
    .bind(offer.queue_id)
    .bind(user)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if record_entity.as_deref() == Some("service_ticket")
        && let Some(ticket) = record_id
            .as_deref()
            .and_then(|r| Uuid::parse_str(r.trim()).ok())
    {
        sqlx::query(
            "UPDATE service_ticket SET assignee_id = $2, claimed_at = NOW() \
              WHERE id = $1 AND assignee_id IS NULL",
        )
        .bind(ticket)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "queue_item",
            offer.item_id,
            AuditOperation::Update,
            "queue_item.offer_accepted",
            user,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(offer)
}

/// Declines the caller's offer; the item is offered to the next agent.
pub async fn decline(state: &EngineState, user: Uuid, id: Uuid) -> Result<QueueOffer, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let offer = decide(&mut tx, id, user, "declined").await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "queue_item",
            offer.item_id,
            AuditOperation::Update,
            "queue_item.offer_declined",
            user,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    // Best effort: the next tick offers it otherwise.
    if let Err(error) = offer_next(state, offer.item_id).await {
        tracing::warn!(%error, item = %offer.item_id, "router: re-offer after a decline failed");
    }
    Ok(offer)
}

/// Accept a work offer
///
/// The caller takes the queue item offered to them: it is picked for them,
/// and a service ticket it holds with no assignee is assigned to them.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/queue-offers/{id}/accept",
    tag = "service",
    params(("id" = Uuid, Path, description = "The offer")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The offer, accepted", body = QueueOffer),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such offer to the caller", body = ErrorResponse),
        (status = 409, description = "The offer expired or was decided, or the item was taken", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn accept_route(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<QueueOffer>, AppError> {
    Ok(Json(accept(&state, ctx.user_id, id).await?))
}

/// Decline a work offer
///
/// The caller refuses the queue item offered to them; it is offered to the
/// next available agent. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/queue-offers/{id}/decline",
    tag = "service",
    params(("id" = Uuid, Path, description = "The offer")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The offer, declined", body = QueueOffer),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such offer to the caller", body = ErrorResponse),
        (status = 409, description = "The offer expired or was decided", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn decline_route(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<QueueOffer>, AppError> {
    Ok(Json(decline(&state, ctx.user_id, id).await?))
}

/// My open work offers
///
/// The caller's offers still open, soonest to expire first (at most 50).
#[utoipa::path(
    get,
    path = "/api/v1/queue-offers/mine",
    tag = "service",
    responses(
        (status = 200, description = "The open offers", body = PaginatedResponse<QueueOffer>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn my_offers(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<PaginatedResponse<QueueOffer>>, AppError> {
    let rows: Vec<QueueOffer> = sqlx::query_as(&format!(
        "SELECT {OFFER_COLUMNS} FROM queue_offer \
          WHERE user_id = $1 AND status = 'offered' AND expires_at > now() \
          ORDER BY expires_at LIMIT $2"
    ))
    .bind(ctx.user_id)
    .bind(MAX_OFFERS_LISTED)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = rows.len() as i64;
    Ok(Json(PaginatedResponse::new(
        rows,
        total,
        1,
        MAX_OFFERS_LISTED,
    )))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/queue-offers/mine", get(my_offers))
        .route("/api/v1/queue-offers/{id}/accept", post(accept_route))
        .route("/api/v1/queue-offers/{id}/decline", post(decline_route))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(accept_route, decline_route, my_offers),
    components(schemas(QueueOffer))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(id: u128, channel_load: i64, total_load: i64) -> AgentView {
        AgentView {
            user: Uuid::from_u128(id),
            channel_load,
            total_load,
            capacity: 3,
            available: true,
            has_skills: true,
            tried: false,
        }
    }

    #[test]
    fn unified_router_offers_the_least_loaded_eligible_agent() {
        // Simulated agents: one busy on the channel, one away, one without
        // the skill, one already offered it, one at capacity.
        let agents = vec![
            agent(1, 2, 2),
            AgentView {
                available: false,
                ..agent(2, 0, 0)
            },
            AgentView {
                has_skills: false,
                ..agent(3, 0, 0)
            },
            AgentView {
                tried: true,
                ..agent(4, 0, 0)
            },
            AgentView {
                capacity: 1,
                ..agent(5, 1, 1)
            },
            agent(6, 1, 4),
            agent(7, 1, 1),
        ];
        assert_eq!(best_agent(&agents), Some(Uuid::from_u128(7)));
        // Once 7 is tried, 6 is next; then 1.
        let mut next = agents.clone();
        next[6].tried = true;
        assert_eq!(best_agent(&next), Some(Uuid::from_u128(6)));
        next[5].tried = true;
        assert_eq!(best_agent(&next), Some(Uuid::from_u128(1)));
        next[0].channel_load = 3;
        assert_eq!(best_agent(&next), None);
    }

    #[test]
    fn unified_router_capacity_and_overflow() {
        assert_eq!(default_capacity("chat"), 3);
        assert_eq!(default_capacity("call"), 1);
        assert_eq!(default_capacity("email"), 5);
        let entered: DateTime<Utc> = "2026-10-27T10:00:00Z".parse().unwrap();
        let now: DateTime<Utc> = "2026-10-27T10:20:00Z".parse().unwrap();
        assert!(overflow_due(entered, now, Some(15)));
        assert!(!overflow_due(entered, now, Some(30)));
        assert!(!overflow_due(entered, now, None));
    }
}

//! V7-T1: the generic queue. A `queue_item` puts a record of any entity in a
//! `queue`: the record is a polymorphic pair (`record_entity`, `record_id`,
//! `options.polymorphic.any`, A8-T1), so the generic entity API checks on
//! every write that the record exists, is live and is readable by the writer.
//! Both entities are platform changeset 0075 (`attome-project-queue`); items
//! are written through the generic entity API, never here.
//!
//! [`migrate_service_queues`] moves the service work queues onto it: every
//! live `service_work_queue` becomes a `queue` with the same id, and every
//! live ticket in one (`service_ticket.work_queue_ref`) becomes a
//! `queue_item` holding that ticket. Idempotent; runs at boot after the
//! platform definitions apply. The service engine's claim and assign
//! (`attome_service::queue`) still route by `work_queue_ref`; a ticket queued
//! after a boot gets its item on the next one.
//!
//! G4-T2: `POST /api/v1/queue-items/{id}/pick`, `/release` and `/transfer`
//! move an item ([`move_item`]): pick takes a waiting item for the caller,
//! release puts a picked one back (its assignee or an administrator), and
//! transfer sends it to another queue, waiting. Each needs `queue_item.update`
//! and record access to the item (a pick also reads its record), and is
//! recorded in `queue_item_event` (migration 0310), which `GET .../history`
//! reads, and in the audit log. Core routes, mounted by `attome-api`: queues
//! are not a licensed module. [`run_backlog_sweep`] alerts a queue's lead when
//! more items wait than its `backlog_alert_count`, or the oldest has waited
//! longer than its `unassigned_alert_minutes` (platform changeset 0077); it
//! runs with the work-queue escalation sweep.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{QueueItemRead, QueueItemUpdate};

/// Ticket statuses whose item is `done`.
pub const DONE_TICKET_STATUSES: &[&str] = &["resolved", "closed"];

/// Rows moved per transaction.
const BATCH: i64 = 1000;

const LOCK_KEY: &str = "attome-project/queue-migrate:service";

/// The item status of a ticket: `done` once resolved or closed, `picked`
/// while someone holds it, else `waiting`. Pure; the migration's SQL applies
/// the same rule.
pub fn item_status(ticket_status: &str, assigned: bool) -> &'static str {
    if DONE_TICKET_STATUSES.contains(&ticket_status) {
        "done"
    } else if assigned {
        "picked"
    } else {
        "waiting"
    }
}

/// Moves the service work queues and their tickets into `queue` and
/// `queue_item`. Returns how many items it created. Does nothing when the
/// service tables are not provisioned (the service module is not licensed)
/// or another node holds the migration lock.
pub async fn migrate_service_queues(db: &DbPool) -> Result<u64, AppError> {
    let tables: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT to_regclass('service_work_queue') IS NOT NULL, \
                to_regclass('service_ticket') IS NOT NULL, \
                to_regclass('queue') IS NOT NULL, \
                to_regclass('queue_item') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if tables != (true, true, true, true) {
        return Ok(0);
    }
    let done: Vec<String> = DONE_TICKET_STATUSES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let mut moved = 0u64;
    loop {
        let mut tx = attome_db::tx::begin(db).await?;
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(LOCK_KEY)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            tx.rollback().await.map_err(AppError::internal)?;
            return Ok(moved);
        }
        sqlx::query(
            "INSERT INTO queue \
               (id, name, lead_ref, created_by, owner_ref, owner_type, organization_ref, \
                created_at, modified_at) \
             SELECT q.id, COALESCE(NULLIF(btrim(q.name), ''), q.id::text), q.lead_ref, \
                    q.created_by, q.owner_ref, q.owner_type, q.organization_ref, \
                    q.created_at, now() \
               FROM service_work_queue q \
              WHERE q.is_active IS NOT FALSE \
                AND NOT EXISTS (SELECT 1 FROM queue x WHERE x.id = q.id) \
              ORDER BY q.id LIMIT $1",
        )
        .bind(BATCH)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        // An item that exists, even soft-deleted, is never made again.
        let items = sqlx::query(
            "INSERT INTO queue_item \
               (id, queue_ref, record_entity, record_id, priority, status, assigned_ref, \
                entered_at, created_by, owner_ref, owner_type, organization_ref, \
                created_at, modified_at) \
             SELECT uuidv7(), t.work_queue_ref, 'service_ticket', t.id::text, \
                    COALESCE(t.priority::text, 'medium'), \
                    CASE WHEN t.status::text = ANY($2::text[]) THEN 'done' \
                         WHEN t.assignee_id IS NOT NULL THEN 'picked' \
                         ELSE 'waiting' END, \
                    t.assignee_id, t.created_at, t.created_by, t.owner_ref, t.owner_type, \
                    t.organization_ref, now(), now() \
               FROM service_ticket t \
               JOIN queue q ON q.id = t.work_queue_ref \
              WHERE t.is_active IS NOT FALSE \
                AND NOT EXISTS (SELECT 1 FROM queue_item i \
                                 WHERE i.record_entity = 'service_ticket' \
                                   AND i.record_id = t.id::text \
                                   AND i.queue_ref = t.work_queue_ref) \
              ORDER BY t.id LIMIT $1",
        )
        .bind(BATCH)
        .bind(&done)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        tx.commit().await.map_err(AppError::internal)?;
        moved += items;
        if items < BATCH as u64 {
            break;
        }
    }
    if moved > 0 {
        tracing::info!(moved, "service tickets moved into queue items");
    }
    Ok(moved)
}

// ── G4-T2: pick, release, transfer, history, backlog alerts ─────────────────

/// The most history events one read returns.
pub const MAX_HISTORY: i64 = 200;

/// A move of a queue item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Move {
    /// The caller takes a waiting item.
    Pick,
    /// The assignee (or an administrator) puts it back to waiting.
    Release,
    /// To another queue, waiting and unassigned.
    Transfer(Uuid),
}

impl Move {
    fn kind(&self) -> &'static str {
        match self {
            Self::Pick => "pick",
            Self::Release => "release",
            Self::Transfer(_) => "transfer",
        }
    }
}

/// The item's status and assignee after `mv` by `actor`, or why it is
/// refused. Pure.
pub fn next_state(
    mv: &Move,
    status: &str,
    assigned: Option<Uuid>,
    actor: Uuid,
    is_admin: bool,
) -> Result<(&'static str, Option<Uuid>), &'static str> {
    if status == "done" {
        return Err("this item is done");
    }
    match mv {
        Move::Pick if status == "waiting" => Ok(("picked", Some(actor))),
        Move::Pick => Err("this item is already picked"),
        Move::Release if status != "picked" => Err("this item is not picked"),
        Move::Release if assigned != Some(actor) && !is_admin => {
            Err("only the assignee may release this item")
        }
        Move::Release | Move::Transfer(_) => Ok(("waiting", None)),
    }
}

/// A queue item's state after a move.
#[derive(Debug, Serialize, ToSchema)]
pub struct QueueItemState {
    pub id: Uuid,
    pub queue_id: Uuid,
    /// `waiting`, `picked` or `done`.
    pub status: String,
    pub assigned_ref: Option<Uuid>,
}

/// One entry of a queue item's history.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct QueueItemEvent {
    pub id: Uuid,
    /// `enter`, `pick`, `release` or `transfer`.
    pub kind: String,
    /// The queue the item was in.
    pub queue_id: Uuid,
    /// For a transfer, the queue it went to.
    pub to_queue_id: Option<Uuid>,
    pub actor: Option<Uuid>,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TransferBody {
    /// The queue the item moves to.
    pub queue_id: Uuid,
}

/// `queue_item`'s entity id, and the caller's record access to `item` (and
/// to the record it holds) for `action`.
async fn item_access(
    state: &EngineState,
    ctx: &SecurityContext,
    item: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    let (entity_id, entity, _, _) =
        attome_records::entity_crud::resolve_entity_from_db(&state.base.db, "queue_item").await?;
    attome_records::entity_crud::require_record_access(state, ctx, entity_id, &entity, item, action)
        .await
}

/// `(queue_ref, status, assigned_ref, record_entity, record_id)`.
type ItemRow = (
    Uuid,
    Option<String>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
);

/// Applies `mv` to item `id` as `ctx`, records it, and returns the new state.
pub async fn move_item(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    mv: Move,
) -> Result<QueueItemState, AppError> {
    item_access(state, ctx, id, RecordAction::Update).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<ItemRow> = sqlx::query_as(
        "SELECT queue_ref, status::text, assigned_ref, record_entity, record_id \
               FROM queue_item WHERE id = $1 AND is_active IS NOT FALSE FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (queue_id, status, assigned, record_entity, record_id) = row.ok_or(AppError::NotFound)?;
    // Picking an item means working its record: the caller must read it.
    if mv == Move::Pick
        && let (Some(entity), Some(record)) = (
            record_entity.as_deref(),
            record_id
                .as_deref()
                .and_then(|r| Uuid::parse_str(r.trim()).ok()),
        )
    {
        let (entity_id, entity, _, _) =
            attome_records::entity_crud::resolve_entity_from_db(&state.base.db, entity).await?;
        attome_records::entity_crud::require_record_access(
            state,
            ctx,
            entity_id,
            &entity,
            record,
            RecordAction::Read,
        )
        .await?;
    }
    let (next_status, next_assigned) = next_state(
        &mv,
        status.as_deref().unwrap_or("waiting"),
        assigned,
        ctx.user_id,
        ctx.is_admin,
    )
    .map_err(AppError::Conflict)?;
    let to_queue = match mv {
        Move::Transfer(to) => {
            if to == queue_id {
                return Err(AppError::Validation(
                    "queue_id: the item is already in this queue".into(),
                ));
            }
            let live: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM queue WHERE id = $1 AND is_active IS NOT FALSE)",
            )
            .bind(to)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if !live {
                return Err(AppError::Validation("queue_id: no such queue".into()));
            }
            Some(to)
        }
        _ => None,
    };
    sqlx::query(
        "UPDATE queue_item SET status = $2, assigned_ref = $3, queue_ref = COALESCE($4, queue_ref), \
                modified_at = now(), modified_by = $5, row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(next_status)
    .bind(next_assigned)
    .bind(to_queue)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO queue_item_event (id, item_id, kind, queue_id, to_queue_id, actor) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::now_v7())
    .bind(id)
    .bind(mv.kind())
    .bind(queue_id)
    .bind(to_queue)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "queue_item",
            id,
            AuditOperation::Update,
            format!("queue_item.{}", mv.kind()),
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(QueueItemState {
        id,
        queue_id: to_queue.unwrap_or(queue_id),
        status: next_status.to_owned(),
        assigned_ref: next_assigned,
    })
}

/// Pick a queue item
///
/// The caller takes a waiting item, which they may update and whose record
/// they may read. Recorded in the item's history. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/queue-items/{id}/pick",
    tag = "queues",
    params(("id" = Uuid, Path, description = "The queue item")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The item, picked", body = QueueItemState),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks queue_item.update", body = ErrorResponse),
        (status = 404, description = "No such item the caller may update", body = ErrorResponse),
        (status = 409, description = "The item is already picked or done", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn pick_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<QueueItemUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<QueueItemState>, AppError> {
    Ok(Json(move_item(&state, &ctx, id, Move::Pick).await?))
}

/// Release a queue item
///
/// Puts a picked item back to waiting, unassigned: its assignee, or an
/// administrator. Recorded in the item's history. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/queue-items/{id}/release",
    tag = "queues",
    params(("id" = Uuid, Path, description = "The queue item")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The item, waiting", body = QueueItemState),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks queue_item.update", body = ErrorResponse),
        (status = 404, description = "No such item the caller may update", body = ErrorResponse),
        (status = 409, description = "The item is not picked, is done, or is someone else's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn release_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<QueueItemUpdate>>,
    Path(id): Path<Uuid>,
) -> Result<Json<QueueItemState>, AppError> {
    Ok(Json(move_item(&state, &ctx, id, Move::Release).await?))
}

/// Transfer a queue item
///
/// Moves an item to another queue, waiting and unassigned. Recorded in the
/// item's history. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/queue-items/{id}/transfer",
    tag = "queues",
    params(("id" = Uuid, Path, description = "The queue item")),
    request_body = TransferBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The item, in its new queue", body = QueueItemState),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks queue_item.update", body = ErrorResponse),
        (status = 404, description = "No such item the caller may update", body = ErrorResponse),
        (status = 409, description = "The item is done", body = ErrorResponse),
        (status = 422, description = "No such queue, or the item is already in it", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn transfer_item(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<QueueItemUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<TransferBody>,
) -> Result<Json<QueueItemState>, AppError> {
    Ok(Json(
        move_item(&state, &ctx, id, Move::Transfer(body.queue_id)).await?,
    ))
}

/// A queue item's history
///
/// Its picks, releases and transfers, oldest first (at most 200).
#[utoipa::path(
    get,
    path = "/api/v1/queue-items/{id}/history",
    tag = "queues",
    params(("id" = Uuid, Path, description = "The queue item")),
    responses(
        (status = 200, description = "The history", body = PaginatedResponse<QueueItemEvent>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks queue_item.read", body = ErrorResponse),
        (status = 404, description = "No such item the caller may read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn item_history(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<QueueItemRead>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<QueueItemEvent>>, AppError> {
    item_access(&state, &ctx, id, RecordAction::Read).await?;
    let rows: Vec<QueueItemEvent> = sqlx::query_as(
        "SELECT id, kind, queue_id, to_queue_id, actor, at FROM queue_item_event \
          WHERE item_id = $1 ORDER BY at, id LIMIT $2",
    )
    .bind(id)
    .bind(MAX_HISTORY)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = rows.len() as i64;
    Ok(Json(PaginatedResponse::new(rows, total, 1, MAX_HISTORY)))
}

/// The queue item routes. Core: queues are not a licensed module.
pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/queue-items/{id}/pick", post(pick_item))
        .route("/api/v1/queue-items/{id}/release", post(release_item))
        .route("/api/v1/queue-items/{id}/transfer", post(transfer_item))
        .route("/api/v1/queue-items/{id}/history", get(item_history))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(pick_item, release_item, transfer_item, item_history),
    components(schemas(QueueItemState, QueueItemEvent, TransferBody))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

/// Whether a queue's backlog calls for an alert: more waiting items than
/// `max_waiting`, or the oldest waiting longer than `max_minutes`. Pure.
pub fn backlog_alert(
    waiting: i64,
    oldest_minutes: Option<i64>,
    max_waiting: Option<i64>,
    max_minutes: Option<i64>,
) -> Option<String> {
    let mut reasons = Vec::new();
    if let Some(max) = max_waiting
        && waiting > max
    {
        reasons.push(format!("{waiting} items are waiting (more than {max})"));
    }
    if let (Some(max), Some(age)) = (max_minutes, oldest_minutes)
        && age > max
    {
        reasons.push(format!(
            "the oldest has waited {age} minutes (more than {max})"
        ));
    }
    (!reasons.is_empty()).then(|| reasons.join("; "))
}

type BacklogRow = (
    Uuid,
    String,
    Option<Uuid>,
    Option<f64>,
    Option<f64>,
    i64,
    Option<f64>,
);

/// G4-T2: alerts each queue's lead when its backlog passes the queue's
/// `backlog_alert_count` or `unassigned_alert_minutes`. Re-alerts every run
/// the condition holds, as the service queue sweep does. Returns the alerts
/// sent.
pub async fn run_backlog_sweep(
    db: &DbPool,
    notification_cfg: &attome_config::NotificationSection,
) -> Result<u64, AppError> {
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'queue' \
            AND column_name = 'backlog_alert_count')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Ok(0);
    }
    let rows: Vec<BacklogRow> = sqlx::query_as(
        "SELECT q.id, q.name, q.lead_ref, q.backlog_alert_count::float8, \
                q.unassigned_alert_minutes::float8, \
                COUNT(i.id), \
                (EXTRACT(EPOCH FROM now() - MIN(i.entered_at)) / 60)::float8 \
           FROM queue q \
           LEFT JOIN queue_item i ON i.queue_ref = q.id AND i.status = 'waiting' \
                AND i.is_active IS NOT FALSE \
          WHERE q.is_active IS NOT FALSE AND q.lead_ref IS NOT NULL \
            AND (q.backlog_alert_count IS NOT NULL OR q.unassigned_alert_minutes IS NOT NULL) \
          GROUP BY q.id, q.name, q.lead_ref, q.backlog_alert_count, q.unassigned_alert_minutes \
          ORDER BY q.id LIMIT 1000",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut sent = 0;
    for (queue_id, name, lead, max_waiting, max_minutes, waiting, oldest) in rows {
        let (Some(lead), Some(reason)) = (
            lead,
            backlog_alert(
                waiting,
                oldest.map(|m| m as i64),
                max_waiting.map(|m| m as i64),
                max_minutes.map(|m| m as i64),
            ),
        ) else {
            continue;
        };
        let req = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_string(),
            recipient_user_ref: Some(lead),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(format!("Queue {name} is backed up")),
            body_html: None,
            body_text: Some(format!("Queue {name}: {reason}.")),
            route: Some(format!("/xrm/queue/{queue_id}")),
            variables: std::collections::HashMap::new(),
            priority: "high".to_string(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        match attome_notification::dispatch::create_dispatch(db, notification_cfg, req).await {
            Ok(_) => sent += 1,
            Err(e) => {
                tracing::error!(error = %e, queue = %queue_id, "queue backlog alert dispatch failed");
            }
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_history_moves_follow_the_item_state() {
        let (me, other) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let to = Uuid::from_u128(9);
        assert_eq!(
            next_state(&Move::Pick, "waiting", None, me, false),
            Ok(("picked", Some(me)))
        );
        assert_eq!(
            next_state(&Move::Pick, "picked", Some(other), me, false),
            Err("this item is already picked")
        );
        assert_eq!(
            next_state(&Move::Release, "picked", Some(me), me, false),
            Ok(("waiting", None))
        );
        assert_eq!(
            next_state(&Move::Release, "picked", Some(other), me, false),
            Err("only the assignee may release this item")
        );
        assert_eq!(
            next_state(&Move::Release, "picked", Some(other), me, true),
            Ok(("waiting", None))
        );
        assert_eq!(
            next_state(&Move::Release, "waiting", None, me, false),
            Err("this item is not picked")
        );
        assert_eq!(
            next_state(&Move::Transfer(to), "picked", Some(other), me, false),
            Ok(("waiting", None))
        );
        assert_eq!(
            next_state(&Move::Transfer(to), "done", None, me, true),
            Err("this item is done")
        );
        assert_eq!(Move::Transfer(to).kind(), "transfer");
    }

    #[test]
    fn queue_history_backlog_alerts_name_what_was_passed() {
        assert_eq!(backlog_alert(3, Some(10), Some(5), Some(60)), None);
        assert_eq!(
            backlog_alert(6, Some(10), Some(5), None).as_deref(),
            Some("6 items are waiting (more than 5)")
        );
        assert_eq!(
            backlog_alert(1, Some(90), None, Some(60)).as_deref(),
            Some("the oldest has waited 90 minutes (more than 60)")
        );
        assert!(
            backlog_alert(9, Some(90), Some(5), Some(60))
                .unwrap()
                .contains("; ")
        );
        assert_eq!(backlog_alert(0, None, Some(0), Some(0)), None);
    }

    #[test]
    fn generic_queue_item_status_follows_the_ticket() {
        assert_eq!(item_status("new", false), "waiting");
        assert_eq!(item_status("open", true), "picked");
        assert_eq!(item_status("in_progress", true), "picked");
        assert_eq!(item_status("resolved", true), "done");
        assert_eq!(item_status("closed", false), "done");
    }

    /// The record pair admits any entity, so a queue holds records of
    /// every kind (A8-T1's check still runs on each write).
    #[test]
    fn generic_queue_record_is_polymorphic_over_any_entity() {
        let cs: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../changesets/platform/0075-attome-project-queue.json"
        ))
        .unwrap();
        let record = cs["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["target"]["entity"] == "queue_item" && o["target"]["field"] == "record_id")
            .unwrap();
        let poly = &record["args"]["definition"]["options"]["polymorphic"];
        assert_eq!(poly["pair"], "record_entity");
        assert_eq!(poly["any"], true);
    }
}

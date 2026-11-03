//! O13-T1: digital workers — agent principals that work service queues.
//!
//! A digital worker is an agent principal (AH3) with a profile
//! (`digital_worker`, migration 0392): the agent definition it runs on each
//! item (which must run as this principal, `ai_agent.principal_ref`), the
//! person its items escalate to, and its working hours. It joins queues as
//! a member, with per-channel capacity, like a person; the J10 router offers
//! it items while it is on duty (`attome_service::router::worker_on_duty`)
//! and under capacity.
//!
//! [`tick`] (a registered job, every minute) has each active worker accept
//! its open offers (at most [`OFFERS_PER_TICK`] a run) and work each item:
//! a session of its definition, started by its sponsor and bound to it, so
//! it acts with its own grants narrowed to the sponsor's (AH3-T5/T6), runs
//! one turn on the item's record. An item the turn does not finish (it fails,
//! runs out of steps or budget, or is refused) is escalated: assigned to the
//! supervisor, recorded on the item, and the supervisor told in the app. A
//! turn waiting on a person's confirmation or approval keeps its session.

use std::sync::Arc;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event, x_audit};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::conversation::TerminalState;
use crate::descriptor::RiskTier;

/// The registered job that runs [`tick`].
pub const TICK_JOB: &str = "ai_digital_worker_tick";
/// Offers one worker accepts in one tick.
pub const OFFERS_PER_TICK: i64 = 5;
/// Tool steps one item's turn may take.
const STEP_BUDGET: usize = 6;

/// A digital worker's profile.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DigitalWorker {
    /// The agent principal's account id.
    pub user_ref: Uuid,
    pub agent_definition_ref: Uuid,
    pub supervisor_ref: Uuid,
    /// ISO weekdays, 1 Monday .. 7 Sunday.
    pub working_days: Vec<i16>,
    /// Minutes of the day in `time_zone`; `end_minute` 1440 is midnight.
    pub start_minute: i32,
    pub end_minute: i32,
    pub time_zone: String,
    pub is_active: bool,
    pub row_version: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerBody {
    pub agent_definition_ref: Uuid,
    pub supervisor_ref: Uuid,
    #[serde(default)]
    pub working_days: Option<Vec<i16>>,
    #[serde(default)]
    pub start_minute: Option<i32>,
    #[serde(default)]
    pub end_minute: Option<i32>,
    #[serde(default)]
    pub time_zone: Option<String>,
    #[serde(default)]
    pub is_active: Option<bool>,
}

/// The body's hours, checked. Pure.
pub fn check_hours(body: &WorkerBody) -> Result<(), AppError> {
    let bad = |m: &str| Err(AppError::Validation(m.to_owned()));
    if let Some(days) = &body.working_days
        && (days.is_empty() || days.iter().any(|d| !(1..=7).contains(d)))
    {
        return bad("working_days: ISO weekdays 1 (Monday) to 7 (Sunday), at least one");
    }
    for minute in [body.start_minute, body.end_minute].into_iter().flatten() {
        if !(0..=1440).contains(&minute) {
            return bad("start_minute and end_minute: 0 to 1440");
        }
    }
    if let Some(tz) = &body.time_zone
        && tz.parse::<chrono_tz::Tz>().is_err()
    {
        return bad("time_zone: an IANA time zone, such as Asia/Riyadh");
    }
    Ok(())
}

/// What a turn's end means for its item: `true` when it is escalated. Pure.
pub fn escalates(state: TerminalState) -> bool {
    !matches!(
        state,
        TerminalState::Completed
            | TerminalState::AwaitingConfirmation
            | TerminalState::AwaitingApproval
    )
}

/// The task one item's turn is given. Pure.
pub fn task_text(record_entity: Option<&str>, record_id: Option<&str>) -> String {
    match (record_entity, record_id) {
        (Some(entity), Some(id)) => format!(
            "You are a digital worker and this queue item is yours. Its record is the {entity} \
             {id}. Read it, do what it needs with your tools, and end with a short summary of \
             what you did. If you cannot finish it, say so plainly and why; a person will take \
             it over."
        ),
        _ => "You are a digital worker and this queue item is yours, but it names no record. \
              Say so plainly; a person will take it over."
            .to_owned(),
    }
}

const WORKER_COLUMNS: &str = "w.user_ref, w.agent_definition_ref, w.supervisor_ref, \
    w.working_days, w.start_minute, w.end_minute, w.time_zone, w.is_active, w.row_version";

/// List digital workers
///
/// The deployment's digital workers: each agent principal working queues, the agent definition it runs, its supervisor and its hours.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/digital-workers",
    tag = "ai",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DigitalWorker>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_workers(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DigitalWorker>>, AppError> {
    let window = page.window();
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM digital_worker")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let items: Vec<DigitalWorker> = sqlx::query_as(&format!(
        "SELECT {WORKER_COLUMNS} FROM digital_worker w \
          ORDER BY w.created_at DESC, w.user_ref LIMIT $1 OFFSET $2"
    ))
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Make or change a digital worker
///
/// Sets an agent principal's digital worker profile: the agent definition it runs on each item (which must run as this principal), the person its items escalate to, and its working days and hours. Add it to queues as a member, with per-channel capacity, as for a person. Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/ai/digital-workers/{id}",
    tag = "ai",
    params(("id" = Uuid, Path, description = "The agent principal's account id")),
    request_body = WorkerBody,
    extensions(("x-audit" = json!(x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = DigitalWorker),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such agent principal", body = ErrorResponse),
        (status = 422, description = "The definition does not run as this agent, the supervisor is not an active person, or the hours are not valid", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn put_worker(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(id): Path<Uuid>,
    Json(body): Json<WorkerBody>,
) -> Result<Json<DigitalWorker>, AppError> {
    check_hours(&body)?;
    let db = &state.base.db;
    let is_agent: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM agent_principal WHERE user_ref = $1)")
            .bind(id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !is_agent {
        return Err(AppError::NotFound);
    }
    let runs_as: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT principal_ref FROM ai_agent WHERE id = $1")
            .bind(body.agent_definition_ref)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    if runs_as.flatten() != Some(id) {
        return Err(AppError::Validation(
            "agent_definition_ref: an agent definition whose principal_ref is this agent".into(),
        ));
    }
    let supervisor_ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_account \
          WHERE id = $1 AND is_active AND principal_kind = 0)",
    )
    .bind(body.supervisor_ref)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !supervisor_ok {
        return Err(AppError::Validation(
            "supervisor_ref: an active person's account".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(db).await?;
    let worker: DigitalWorker = sqlx::query_as(&format!(
        "INSERT INTO digital_worker AS w \
             (user_ref, agent_definition_ref, supervisor_ref, working_days, start_minute, \
              end_minute, time_zone, is_active, created_by) \
         VALUES ($1, $2, $3, COALESCE($4, '{{1,2,3,4,5,6,7}}'::smallint[]), COALESCE($5, 0), \
                 COALESCE($6, 1440), COALESCE($7, 'UTC'), COALESCE($8, true), $9) \
         ON CONFLICT (user_ref) DO UPDATE SET \
             agent_definition_ref = EXCLUDED.agent_definition_ref, \
             supervisor_ref = EXCLUDED.supervisor_ref, \
             working_days = COALESCE($4, w.working_days), \
             start_minute = COALESCE($5, w.start_minute), \
             end_minute = COALESCE($6, w.end_minute), \
             time_zone = COALESCE($7, w.time_zone), \
             is_active = COALESCE($8, w.is_active), \
             row_version = w.row_version + 1 \
         RETURNING {WORKER_COLUMNS}"
    ))
    .bind(id)
    .bind(body.agent_definition_ref)
    .bind(body.supervisor_ref)
    .bind(&body.working_days)
    .bind(body.start_minute)
    .bind(body.end_minute)
    .bind(&body.time_zone)
    .bind(body.is_active)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "digital_worker",
            Some(id),
        )
        .named("digital_worker_set"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(worker))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/ai/digital-workers", get(list_workers))
        .route("/api/v1/admin/ai/digital-workers/{id}", put(put_worker))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_workers, put_worker),
    components(schemas(DigitalWorker, WorkerBody))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

/// What one tick did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickStats {
    pub accepted: usize,
    pub escalated: usize,
}

/// Each active worker accepts its open offers and works each item.
pub async fn tick(state: &EngineState) -> Result<TickStats, AppError> {
    let db = &state.base.db;
    let workers: Vec<DigitalWorker> = sqlx::query_as(&format!(
        "SELECT {WORKER_COLUMNS} FROM digital_worker w \
           JOIN agent_principal a ON a.user_ref = w.user_ref \
          WHERE w.is_active AND a.lifecycle_state = 'active'"
    ))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut stats = TickStats::default();
    for worker in &workers {
        let offers: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM queue_offer \
              WHERE user_id = $1 AND status = 'offered' AND expires_at > now() \
              ORDER BY offered_at LIMIT $2",
        )
        .bind(worker.user_ref)
        .bind(OFFERS_PER_TICK)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for offer in offers {
            let offer = match attome_service::router::accept(state, worker.user_ref, offer).await {
                Ok(offer) => offer,
                // Taken meanwhile, or expired: nothing to do.
                Err(AppError::Conflict(_) | AppError::NotFound) => continue,
                Err(error) => {
                    tracing::warn!(%error, worker = %worker.user_ref, "digital worker could not accept");
                    continue;
                }
            };
            stats.accepted += 1;
            match work(state, worker, &offer).await {
                Ok(None) => {}
                Ok(Some(reason)) | Err(AppError::Validation(reason)) => {
                    escalate(state, worker, &offer, &reason).await?;
                    stats.escalated += 1;
                }
                Err(error) => {
                    tracing::warn!(%error, item = %offer.item_id, "digital worker failed an item");
                    escalate(state, worker, &offer, "the worker failed").await?;
                    stats.escalated += 1;
                }
            }
        }
    }
    Ok(stats)
}

/// Works one accepted item. `Some(reason)` when it must be escalated.
async fn work(
    state: &EngineState,
    worker: &DigitalWorker,
    offer: &attome_service::router::QueueOffer,
) -> Result<Option<String>, AppError> {
    let db = &state.base.db;
    let sponsor: Uuid =
        sqlx::query_scalar("SELECT sponsor_user_ref FROM agent_principal WHERE user_ref = $1")
            .bind(worker.user_ref)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let starter = Arc::new(attome_security::resolve_uncached(db, sponsor).await?);
    let session = crate::agent::start_session(
        state,
        &starter,
        worker.agent_definition_ref,
        "digital_worker",
        crate::agent::SessionConstraints {
            risk_ceiling: RiskTier::Consequential,
            allowed_action_ids: None,
        },
        // The record's text reaches the model.
        true,
    )
    .await?;
    if crate::session::principal_of(db, session.id).await? != Some(worker.user_ref) {
        let _ =
            crate::session::revoke(db, session.id, sponsor, "not this worker's definition").await;
        return Ok(Some(
            "its agent definition no longer runs as this worker".to_owned(),
        ));
    }
    let security = Arc::new(attome_security::resolve_uncached(db, worker.user_ref).await?);
    let ran = async {
        let conversation = crate::conversation::create(
            db,
            crate::conversation::NewConversation {
                agent_session_id: session.id,
                owner_user_id: sponsor,
                agent_definition_ref: Some(worker.agent_definition_ref),
                surface: crate::conversation::Surface::Internal,
                title: Some(format!("Queue item {}", offer.item_id)),
            },
        )
        .await?;
        crate::turn::run(
            state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            &crate::turn::TurnInputs {
                session: &session,
                security,
                conversation_id: conversation.id,
                step_budget: Some(STEP_BUDGET),
            },
            &task_text(offer.record_entity.as_deref(), offer.record_id.as_deref()),
        )
        .await
    }
    .await;
    let waiting = matches!(
        ran.as_ref().map(|outcome| outcome.terminal_state),
        Ok(TerminalState::AwaitingConfirmation | TerminalState::AwaitingApproval)
    );
    if !waiting
        && let Err(error) =
            crate::session::revoke(db, session.id, sponsor, "digital worker item finished").await
    {
        tracing::warn!(%error, session = %session.id, "digital worker session not ended");
    }
    let terminal = ran?.terminal_state;
    Ok(escalates(terminal).then(|| format!("the turn ended {terminal:?}")))
}

/// Gives an item the worker could not finish to its supervisor.
async fn escalate(
    state: &EngineState,
    worker: &DigitalWorker,
    offer: &attome_service::router::QueueOffer,
    reason: &str,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let moved = sqlx::query(
        "UPDATE queue_item SET assigned_ref = $2, modified_at = now(), modified_by = $3, \
                row_version = row_version + 1 \
          WHERE id = $1 AND assigned_ref = $3",
    )
    .bind(offer.item_id)
    .bind(worker.supervisor_ref)
    .bind(worker.user_ref)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if moved.rows_affected() == 0 {
        // Someone took it meanwhile.
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO queue_item_event (id, item_id, kind, queue_id, to_queue_id, actor) \
         VALUES ($1, $2, 'transfer', $3, $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(offer.item_id)
    .bind(offer.queue_id)
    .bind(worker.user_ref)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let route = match (&offer.record_entity, &offer.record_id) {
        (Some(entity), Some(id)) => Some(format!("/{entity}/{id}")),
        _ => None,
    };
    attome_notification::dispatch::create_dispatch_in_tx(
        &mut tx,
        &state.base.config.notification,
        attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_owned(),
            recipient_user_ref: Some(worker.supervisor_ref),
            is_global: false,
            organization_ref: None,
            channels: Some(vec!["in_app".to_owned()]),
            subject: Some("A digital worker handed you an item".to_owned()),
            body_html: None,
            body_text: Some(format!("It could not finish it: {reason}.")),
            route,
            variables: std::collections::HashMap::new(),
            priority: "normal".to_owned(),
            escalate_after_minutes: None,
            escalate_channels: None,
        },
        Some("ai.digital_worker"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(item = %offer.item_id, worker = %worker.user_ref, reason, "digital worker escalated an item");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> WorkerBody {
        WorkerBody {
            agent_definition_ref: Uuid::now_v7(),
            supervisor_ref: Uuid::now_v7(),
            working_days: Some(vec![1, 2, 3, 4, 5]),
            start_minute: Some(8 * 60),
            end_minute: Some(17 * 60),
            time_zone: Some("Asia/Riyadh".into()),
            is_active: None,
        }
    }

    #[test]
    fn digital_worker_hours_are_checked() {
        assert!(check_hours(&body()).is_ok());
        let mut b = body();
        b.working_days = Some(vec![]);
        assert!(check_hours(&b).is_err());
        let mut b = body();
        b.working_days = Some(vec![0, 8]);
        assert!(check_hours(&b).is_err());
        let mut b = body();
        b.end_minute = Some(1500);
        assert!(check_hours(&b).is_err());
        let mut b = body();
        b.time_zone = Some("Mars/Base".into());
        assert!(check_hours(&b).is_err());
    }

    #[test]
    fn digital_worker_escalates_what_it_does_not_finish() {
        assert!(!escalates(TerminalState::Completed));
        assert!(!escalates(TerminalState::AwaitingApproval));
        for state in [
            TerminalState::MaxSteps,
            TerminalState::BudgetExceeded,
            TerminalState::ModelFailure,
            TerminalState::PrivilegeRevoked,
        ] {
            assert!(escalates(state), "{state:?}");
        }
        assert!(task_text(Some("service_ticket"), Some("t1")).contains("service_ticket t1"));
        assert!(task_text(None, None).contains("names no record"));
    }
}

//! M12-T3: every schedule in one place.
//!
//! `GET /api/v1/admin/schedules` lists, for administrators:
//! - `flow`: each published flow's schedule trigger (`workflow_trigger_index`
//!   entries matching `schedule`), with its next slot, its last claimed slot
//!   and the flow's publisher;
//! - `report`: each active report delivery (`report_schedule`), with its
//!   next and last run and its run-as user;
//! - `platform`: the platform's own schedulers (`job_schedule`), read-only,
//!   with their interval, next due time and last success.
//!
//! Flow and report schedules are paused and resumed here
//! (`schedule_pause`, migration 0214): a paused schedule's sweep skips it
//! until it is resumed. Both writes are Configuration events in the same
//! transaction. The `jobs.quiet_windows` setting is shown with the list
//! (`attome_core::quiet_window`).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// One schedule.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScheduleItem {
    /// `flow`, `report` or `platform`.
    pub kind: String,
    /// What pause and resume take: `{definition_id}:{node_id}` for a flow,
    /// the schedule id for a report, the scheduler name for the platform.
    pub id: String,
    pub name: String,
    pub owner: Option<String>,
    /// The schedule as written: `every 15 min`, a cron or an RRULE.
    pub schedule: String,
    pub next_run_at: Option<DateTime<Utc>>,
    pub last_run_at: Option<DateTime<Utc>>,
    /// `ok` when the last run succeeded, `running` while it has not, or
    /// `null` when unknown.
    pub last_result: Option<String>,
    pub paused: bool,
    /// Platform schedulers are read-only.
    pub can_pause: bool,
}

/// The list and the quiet windows heavy schedules wait out.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScheduleList {
    #[serde(flatten)]
    pub page: PaginatedResponse<ScheduleItem>,
    /// `jobs.quiet_windows`, as `{start, end}` in the deployment's time.
    #[schema(value_type = Object)]
    pub quiet_windows: Value,
}

#[derive(sqlx::FromRow)]
struct FlowRow {
    definition_id: Uuid,
    name: String,
    definition_version_id: Uuid,
    node_id: String,
    graph: Value,
    owner: Option<String>,
    paused: bool,
}

#[derive(sqlx::FromRow)]
struct ReportRow {
    id: Uuid,
    name: Option<String>,
    rrule: String,
    next_run_at: Option<DateTime<Utc>>,
    last_run_at: Option<DateTime<Utc>>,
    owner: Option<String>,
    paused: bool,
}

#[derive(sqlx::FromRow)]
struct PlatformRow {
    name: String,
    interval_secs: i32,
    next_due_at: DateTime<Utc>,
    last_enqueued_at: Option<DateTime<Utc>>,
    last_succeeded_at: Option<DateTime<Utc>>,
}

fn describe(config: &Value) -> String {
    match config.get("schedule") {
        Some(s) if s.get("every_minutes").is_some() => {
            format!("every {} min", s["every_minutes"])
        }
        Some(s) if s.get("cron").is_some() => s["cron"].as_str().unwrap_or_default().to_owned(),
        Some(s) if s.get("daily_at").is_some() => {
            format!("daily at {}", s["daily_at"].as_str().unwrap_or_default())
        }
        _ => String::new(),
    }
}

async fn flow_items(state: &EngineState) -> Result<Vec<ScheduleItem>, AppError> {
    let rows: Vec<FlowRow> = sqlx::query_as(
        "SELECT d.id AS definition_id, d.name, t.definition_version_id, t.node_id, v.graph, \
                u.user_name AS owner, \
                EXISTS (SELECT 1 FROM schedule_pause p WHERE p.kind = 'flow' \
                         AND p.target = d.id::text || ':' || t.node_id) AS paused \
           FROM workflow_trigger_index t \
           JOIN workflow_definition_version v ON v.id = t.definition_version_id \
           JOIN workflow_definition d ON d.id = v.definition_id \
           LEFT JOIN user_account u ON u.id = COALESCE(v.published_by, d.created_by) \
          WHERE t.role = 'entry' AND t.match_type = 'schedule' \
            AND v.status = 'published' AND d.is_active AND NOT d.is_deleted \
          ORDER BY d.name, t.node_id",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let now = attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref());
    let offset = *now.offset();
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let config = serde_json::from_value::<attome_workflow::graph::Graph>(row.graph)
            .ok()
            .and_then(|g| g.nodes.into_iter().find(|n| n.id == row.node_id))
            .map(|n| n.config)
            .unwrap_or(Value::Null);
        let next_run_at = attome_workflow::schedule_trigger::parse_schedule(&config)
            .ok()
            .and_then(|spec| attome_workflow::schedule_trigger::next_slot(&spec, now.naive_local()))
            .and_then(|at| at.and_local_timezone(offset).single())
            .map(|at| at.with_timezone(&Utc));
        let last: Option<(DateTime<Utc>, Option<Uuid>)> = sqlx::query_as(
            "SELECT slot_at, instance_id FROM workflow_schedule_slot \
              WHERE definition_version_id = $1 AND node_id = $2 \
              ORDER BY slot_at DESC LIMIT 1",
        )
        .bind(row.definition_version_id)
        .bind(&row.node_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        items.push(ScheduleItem {
            kind: "flow".into(),
            id: format!("{}:{}", row.definition_id, row.node_id),
            name: row.name,
            owner: row.owner,
            schedule: describe(&config),
            next_run_at,
            last_run_at: last.map(|(at, _)| at),
            last_result: last.map(|_| "started".to_owned()),
            paused: row.paused,
            can_pause: true,
        });
    }
    Ok(items)
}

async fn report_items(state: &EngineState) -> Result<Vec<ScheduleItem>, AppError> {
    let rows: Vec<ReportRow> = sqlx::query_as(
        "SELECT s.id, r.name, s.rrule, s.next_run_at, s.last_run_at, u.user_name AS owner, \
                EXISTS (SELECT 1 FROM schedule_pause p WHERE p.kind = 'report' \
                         AND p.target = s.id::text) AS paused \
           FROM report_schedule s \
           LEFT JOIN attome_report r ON r.id = s.report_ref \
           LEFT JOIN user_account u ON u.id = s.run_as \
          WHERE s.is_active = true \
          ORDER BY r.name, s.id",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|r| ScheduleItem {
            kind: "report".into(),
            id: r.id.to_string(),
            name: r.name.unwrap_or_else(|| r.id.to_string()),
            owner: r.owner,
            schedule: r.rrule,
            next_run_at: r.next_run_at,
            last_result: r.last_run_at.map(|_| "ok".to_owned()),
            last_run_at: r.last_run_at,
            paused: r.paused,
            can_pause: true,
        })
        .collect())
}

async fn platform_items(state: &EngineState) -> Result<Vec<ScheduleItem>, AppError> {
    let rows: Vec<PlatformRow> = sqlx::query_as(
        "SELECT name, interval_secs, next_due_at, last_enqueued_at, last_succeeded_at \
           FROM job_schedule ORDER BY name",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|r| ScheduleItem {
            kind: "platform".into(),
            id: r.name.clone(),
            schedule: format!("every {} s", r.interval_secs),
            next_run_at: Some(r.next_due_at),
            last_result: match (r.last_enqueued_at, r.last_succeeded_at) {
                (Some(enqueued), Some(succeeded)) if succeeded >= enqueued => Some("ok".into()),
                (Some(_), _) => Some("running".into()),
                _ => None,
            },
            last_run_at: r.last_succeeded_at.or(r.last_enqueued_at),
            name: r.name,
            owner: None,
            paused: false,
            can_pause: false,
        })
        .collect())
}

/// List schedules
///
/// List schedules. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/schedules",
    tag = "admin",
    operation_id = "list_schedules",
    description = "Every schedule in one place (M12-T3): flow schedule triggers, report deliveries and the platform's own schedulers (read-only), with next and last run, owner and whether paused; and the quiet windows heavy schedules wait out. One page holds them all.",
    responses(
        (status = 200, description = "Every schedule", body = ScheduleList),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_schedules(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<ScheduleList>, AppError> {
    let mut items = flow_items(&state).await?;
    items.extend(report_items(&state).await?);
    items.extend(platform_items(&state).await?);
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let page_size = total.max(1);
    let quiet_windows = attome_core::setting_registry()
        .get(attome_core::quiet_window::SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .unwrap_or(Value::Array(Vec::new()));
    Ok(Json(ScheduleList {
        page: PaginatedResponse::new(items, total, 1, page_size),
        quiet_windows,
    }))
}

/// The pause target a path names, checked to exist.
async fn target_of(state: &EngineState, kind: &str, id: &str) -> Result<String, AppError> {
    match kind {
        "flow" => {
            let (definition, node) = id.split_once(':').ok_or(AppError::NotFound)?;
            let definition = Uuid::parse_str(definition).map_err(|_| AppError::NotFound)?;
            if node.is_empty() || node.len() > 200 {
                return Err(AppError::NotFound);
            }
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM workflow_definition WHERE id = $1 AND NOT is_deleted)",
            )
            .bind(definition)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            exists
                .then(|| format!("{definition}:{node}"))
                .ok_or(AppError::NotFound)
        }
        "report" => {
            let schedule = Uuid::parse_str(id).map_err(|_| AppError::NotFound)?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM report_schedule WHERE id = $1 AND is_active = true)",
            )
            .bind(schedule)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            exists
                .then(|| schedule.to_string())
                .ok_or(AppError::NotFound)
        }
        _ => Err(AppError::NotFound),
    }
}

/// Paused or resumed.
#[derive(Debug, Serialize, ToSchema)]
pub struct PauseState {
    pub kind: String,
    pub id: String,
    pub paused: bool,
}

async fn set_paused(
    state: &EngineState,
    actor: Uuid,
    kind: &str,
    id: &str,
    paused: bool,
) -> Result<PauseState, AppError> {
    let target = target_of(state, kind, id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let changed = if paused {
        sqlx::query(
            "INSERT INTO schedule_pause (kind, target, paused_by) VALUES ($1, $2, $3) \
             ON CONFLICT DO NOTHING",
        )
        .bind(kind)
        .bind(&target)
        .bind(actor)
        .execute(&mut *tx)
        .await
    } else {
        sqlx::query("DELETE FROM schedule_pause WHERE kind = $1 AND target = $2")
            .bind(kind)
            .bind(&target)
            .execute(&mut *tx)
            .await
    }
    .map_err(AppError::internal)?
    .rows_affected();
    if changed > 0 {
        attome_audit::security::write_security_event(
            &mut tx,
            &attome_audit::audit_service(state),
            SecurityEvent::new(
                MandatoryCategory::Configuration,
                AuditOperation::Update,
                actor,
                "schedule",
                None,
            )
            .named(if paused {
                "schedule.pause"
            } else {
                "schedule.resume"
            })
            .comment(format!(
                "{kind} schedule {target} {}",
                if paused { "paused" } else { "resumed" }
            )),
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(PauseState {
        kind: kind.to_owned(),
        id: target,
        paused,
    })
}

/// Pause a schedule
///
/// Pause a schedule. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/schedules/{kind}/{id}/pause",
    tag = "admin",
    operation_id = "pause_schedule",
    description = "Pauses a flow or report schedule (M12-T3): its sweep skips it until it is resumed. Pausing a paused schedule changes nothing.",
    params(("kind" = String, Path, description = "`flow` or `report`"), ("id" = String, Path, description = "The record")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Paused", body = PauseState),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such schedule, or a platform scheduler", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn pause(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((kind, id)): Path<(String, String)>,
) -> Result<Json<PauseState>, AppError> {
    set_paused(&state, ctx.user_id, &kind, &id, true)
        .await
        .map(Json)
}

/// Resume a schedule
///
/// Resume a schedule. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/schedules/{kind}/{id}/resume",
    tag = "admin",
    operation_id = "resume_schedule",
    description = "Resumes a paused flow or report schedule (M12-T3); its next due slot starts as usual.",
    params(("kind" = String, Path, description = "`flow` or `report`"), ("id" = String, Path, description = "The record")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Resumed", body = PauseState),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such schedule, or a platform scheduler", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn resume(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((kind, id)): Path<(String, String)>,
) -> Result<Json<PauseState>, AppError> {
    set_paused(&state, ctx.user_id, &kind, &id, false)
        .await
        .map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/schedules", get(list_schedules))
        .route("/api/v1/admin/schedules/{kind}/{id}/pause", post(pause))
        .route("/api/v1/admin/schedules/{kind}/{id}/resume", post(resume))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_schedules, pause, resume))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedules_describe_their_trigger_as_written() {
        let every = serde_json::json!({ "schedule": { "every_minutes": 15 } });
        assert_eq!(describe(&every), "every 15 min");
        let cron = serde_json::json!({ "schedule": { "cron": "0 9 * * 1-5" } });
        assert_eq!(describe(&cron), "0 9 * * 1-5");
        let daily = serde_json::json!({ "schedule": { "daily_at": "09:00" } });
        assert_eq!(describe(&daily), "daily at 09:00");
        assert_eq!(describe(&Value::Null), "");
    }
}

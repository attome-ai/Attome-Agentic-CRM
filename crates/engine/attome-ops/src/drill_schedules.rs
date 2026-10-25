//! AB4-T7: when each kind of recovery drill is due (`ops_drill_schedule`,
//! migration 0267).
//!
//! - `GET /api/v1/ops/drill-schedules` (`ops.read`) lists the schedules.
//! - `PATCH /api/v1/ops/drill-schedules/{id}` (`ops.drill.manage`, `If-Match`)
//!   turns one on or off, changes its cadence or sets when it is next due.
//!   Turning one on with no due date makes it due now. Audited
//!   (`ops.drill_schedule_changed`).
//! - `GET /api/v1/ops/drills/due` (`ops.drill.run`) is what the drill agent
//!   asks: the enabled schedules whose time has come. The server never runs
//!   a drill; uploading a drill's evidence (AB4-T6) moves its kind's
//!   schedule on by the cadence, in the upload's transaction.
//! - The daily `ops_drill_skip_check` job records `ops.drill_skipped` for
//!   every enabled schedule more than two days overdue.
//!
//! Every schedule starts disabled; migration 0267 proposes the monthly
//! restore drill, off until an administrator turns it on.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, patch},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::drills::OpsDrillRun;
use crate::error::OpsError;
use crate::upgrades::OpsRead;

/// The registered daily job.
pub const SKIP_CHECK_JOB: &str = "ops_drill_skip_check";

/// The cadences a schedule takes.
pub const CADENCES: [&str; 3] = ["weekly", "monthly", "quarterly"];

/// The next due time, `cadence` on from now, as SQL over the row's own
/// `cadence` column.
const ADVANCE: &str = "now() + CASE cadence WHEN 'weekly' THEN interval '7 days' \
     WHEN 'monthly' THEN interval '1 month' ELSE interval '3 months' END";

const COLUMNS: &str =
    "id, kind, cadence, enabled, next_due_at, last_run_id, row_version, updated_by, updated_at";

/// `ops.drill.manage`: who changes drill schedules.
#[derive(Debug)]
pub struct OpsDrillManage;

impl PrivilegeKey for OpsDrillManage {
    const KEY: &'static str = "ops.drill.manage";
}

/// One drill schedule.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct DrillSchedule {
    pub id: Uuid,
    /// The evidence kind the schedule is for (`restore`, `failover`, ...).
    pub kind: String,
    /// `weekly`, `monthly` or `quarterly`.
    pub cadence: String,
    pub enabled: bool,
    pub next_due_at: Option<DateTime<Utc>>,
    /// The drill run whose evidence last moved the schedule on.
    pub last_run_id: Option<Uuid>,
    pub row_version: i64,
    pub updated_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// A schedule change; absent fields stay as they are.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateDrillSchedule {
    #[serde(default)]
    pub enabled: Option<bool>,
    /// `weekly`, `monthly` or `quarterly`.
    #[serde(default)]
    pub cadence: Option<String>,
    #[serde(default)]
    pub next_due_at: Option<DateTime<Utc>>,
}

/// Checks a change. Pure.
pub fn check_update(body: &UpdateDrillSchedule) -> Result<(), AppError> {
    if let Some(cadence) = body.cadence.as_deref()
        && !CADENCES.contains(&cadence)
    {
        return Err(AppError::Validation(format!(
            "cadence is one of {}",
            CADENCES.join(", ")
        )));
    }
    if body.enabled.is_none() && body.cadence.is_none() && body.next_due_at.is_none() {
        return Err(AppError::Validation("nothing to change".into()));
    }
    Ok(())
}

/// Moves `kind`'s enabled schedule on by its cadence after drill `run`
/// uploaded its evidence, in the upload's transaction.
pub(crate) async fn advance(
    tx: &mut sqlx::PgConnection,
    kind: &str,
    run: Uuid,
) -> Result<(), AppError> {
    sqlx::query(&format!(
        "UPDATE ops_drill_schedule SET last_run_id = $2, next_due_at = {ADVANCE}, \
                row_version = row_version + 1, updated_at = now() \
          WHERE kind = $1 AND enabled"
    ))
    .bind(kind)
    .bind(run)
    .execute(tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn page_of(
    state: &EngineState,
    due_only: bool,
    page: OnePageQuery,
) -> Result<PaginatedResponse<DrillSchedule>, AppError> {
    let filter = if due_only {
        "WHERE enabled AND next_due_at <= now()"
    } else {
        ""
    };
    let w = page.window();
    let items: Vec<DrillSchedule> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_drill_schedule {filter} \
          ORDER BY next_due_at NULLS LAST, kind LIMIT $1 OFFSET $2"
    ))
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM ops_drill_schedule {filter}"))
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(PaginatedResponse::new(items, total, w.page, w.page_size))
}

/// List drill schedules
///
/// AB4-T7: every drill schedule, soonest due first. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/drill-schedules",
    tag = "ops",
    operation_id = "list_ops_drill_schedules",
    params(OnePageQuery),
    responses(
        (status = 200, description = "One page of schedules", body = PaginatedResponse<DrillSchedule>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_schedules(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DrillSchedule>>, AppError> {
    page_of(&state, false, page).await.map(Json)
}

/// Drills due now
///
/// AB4-T7: the enabled schedules whose time has come, for the drill agent
/// (a key holding only `ops.drill.run` is enough). Needs `ops.drill.run`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/drills/due",
    tag = "ops",
    operation_id = "list_ops_drills_due",
    params(OnePageQuery),
    responses(
        (status = 200, description = "One page of due schedules", body = PaginatedResponse<DrillSchedule>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.drill.run", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_due(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsDrillRun>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DrillSchedule>>, AppError> {
    page_of(&state, true, page).await.map(Json)
}

/// Change a drill schedule
///
/// AB4-T7: turn it on or off, change its cadence or set when it is next
/// due; turning it on with no due date makes it due now. `If-Match` names
/// the row version. Needs `ops.drill.manage`. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/ops/drill-schedules/{id}",
    tag = "ops",
    operation_id = "update_ops_drill_schedule",
    params(
        ("id" = Uuid, Path, description = "The schedule"),
        ("If-Match" = String, Header, description = "The schedule's row_version, quoted"),
    ),
    request_body = UpdateDrillSchedule,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The schedule", body = DrillSchedule),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.drill.manage", body = ErrorResponse),
        (status = 404, description = "No such schedule", body = ErrorResponse),
        (status = 409, description = "A stale row_version", body = ErrorResponse),
        (status = 422, description = "A missing If-Match, an unknown cadence or nothing to change", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_schedule(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsDrillManage>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateDrillSchedule>,
) -> Result<Json<DrillSchedule>, AppError> {
    let expected = crate::upgrades::if_match(&headers)?;
    check_update(&body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated: Option<DrillSchedule> = sqlx::query_as(&format!(
        "UPDATE ops_drill_schedule SET \
                enabled = COALESCE($2, enabled), \
                cadence = COALESCE($3, cadence), \
                next_due_at = CASE WHEN $4::timestamptz IS NOT NULL THEN $4 \
                                   WHEN COALESCE($2, enabled) AND next_due_at IS NULL THEN now() \
                                   ELSE next_due_at END, \
                row_version = row_version + 1, updated_by = $6, updated_at = now() \
          WHERE id = $1 AND row_version = $5 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(body.enabled)
    .bind(body.cadence.as_deref())
    .bind(body.next_due_at)
    .bind(expected)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(schedule) = updated else {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ops_drill_schedule WHERE id = $1)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::VersionConflict
        } else {
            AppError::NotFound
        });
    };
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "ops_drill_schedule",
            Some(id),
        )
        .named("ops.drill_schedule_changed")
        .comment(format!(
            "{} drill: {} {}, next due {}",
            schedule.kind,
            if schedule.enabled { "on" } else { "off" },
            schedule.cadence,
            schedule
                .next_due_at
                .map_or_else(|| "unset".to_owned(), |t| t.to_rfc3339())
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(schedule))
}

/// The daily skip check: one `ops.drill_skipped` per enabled schedule more
/// than two days overdue; answers how many.
pub async fn record_skips(state: &EngineState) -> Result<usize, OpsError> {
    let internal = |e: sqlx::Error| OpsError::Internal(e.to_string());
    let overdue: Vec<(Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, kind, next_due_at FROM ops_drill_schedule \
          WHERE enabled AND next_due_at < now() - interval '2 days' ORDER BY kind",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(internal)?;
    if overdue.is_empty() {
        return Ok(0);
    }
    let mut tx = attome_db::tx::begin(&state.base.db)
        .await
        .map_err(|e| OpsError::Internal(e.to_string()))?;
    for (id, kind, due) in &overdue {
        write_security_event(
            &mut tx,
            &attome_audit::audit_service(state),
            SecurityEvent::new(
                MandatoryCategory::Configuration,
                AuditOperation::Update,
                Uuid::nil(),
                "ops_drill_schedule",
                Some(*id),
            )
            .named("ops.drill_skipped")
            .comment(format!(
                "the {kind} drill was due {} and has not run",
                due.to_rfc3339()
            )),
        )
        .await
        .map_err(|e| OpsError::Internal(e.to_string()))?;
        tracing::warn!(%kind, due = %due, "recovery drill overdue");
    }
    attome_db::tx::commit(tx)
        .await
        .map_err(|e| OpsError::Internal(e.to_string()))?;
    Ok(overdue.len())
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ops/drill-schedules", get(list_schedules))
        .route("/api/v1/ops/drill-schedules/{id}", patch(update_schedule))
        .route("/api/v1/ops/drills/due", get(list_due))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_schedules, list_due, update_schedule),
    components(schemas(DrillSchedule, UpdateDrillSchedule))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(enabled: Option<bool>, cadence: Option<&str>) -> UpdateDrillSchedule {
        UpdateDrillSchedule {
            enabled,
            cadence: cadence.map(str::to_owned),
            next_due_at: None,
        }
    }

    #[test]
    fn a_change_names_a_known_cadence_and_changes_something() {
        assert!(check_update(&change(Some(true), None)).is_ok());
        assert!(check_update(&change(None, Some("quarterly"))).is_ok());
        assert!(check_update(&change(None, Some("daily"))).is_err());
        assert!(check_update(&change(None, None)).is_err());
    }

    #[test]
    fn patch_requires_if_match() {
        assert!(crate::upgrades::if_match(&HeaderMap::new()).is_err());
    }
}

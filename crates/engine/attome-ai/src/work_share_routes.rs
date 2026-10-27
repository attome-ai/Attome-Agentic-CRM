//! AK3-T6: the work-share routes (administrators).
//!
//! - `GET /api/v1/admin/ai/work-share?from&to`: per process, the completions
//!   agents and people made and the hand-offs between them over the range,
//!   the agents' share, and the per-day counts for a trend.
//! - `GET /api/v1/admin/ai/work-share/{process_key}/events?day&by&cursor`:
//!   the change events behind one number (ids, records and times only),
//!   newest first, while the feed still retains them.
//! - `POST /api/v1/admin/ai/work-share/rebuild`: queues a recount of a date
//!   range ([`crate::work_share::rebuild`]); `202`.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, CursorPage, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Days, NaiveDate, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::agent_stats_routes::{decode_cursor, encode_cursor};
use crate::work_share::{REBUILD_JOB, RebuildRange, check_range, parse_values};

/// Events one page of the drill-down returns.
const EVENTS_PAGE: i64 = 100;
/// The most processes one summary lists.
const MAX_PROCESSES: i64 = 200;

/// The range a summary covers; the last 30 days by default.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ShareQuery {
    /// From this time (inclusive).
    pub from: Option<NaiveDate>,
    /// Up to this time (exclusive).
    pub to: Option<NaiveDate>,
}

/// One day of one process.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ShareDay {
    pub day: NaiveDate,
    pub done_by_agent: i32,
    pub done_by_person: i32,
    pub handed_between: i32,
}

/// One process over the range.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ProcessShare {
    pub process_key: String,
    pub label: Option<String>,
    pub label_ar: Option<String>,
    pub done_by_agent: i64,
    pub done_by_person: i64,
    pub handed_between: i64,
    /// `done_by_agent / (done_by_agent + done_by_person)`; none while nothing was done.
    pub share: Option<f64>,
    /// The days with counts, oldest first.
    pub days: Vec<ShareDay>,
}

/// The agents' share of completions. Pure.
pub fn share(by_agent: i64, by_person: i64) -> Option<f64> {
    let total = by_agent + by_person;
    (total > 0).then(|| by_agent as f64 / total as f64)
}

/// The range asked for: both ends given, or the 30 days ending today. Pure.
pub fn range_of(query: &ShareQuery, today: NaiveDate) -> RebuildRange {
    let to = query.to.unwrap_or(today);
    let from = query.from.unwrap_or(to - Days::new(29));
    RebuildRange { from, to }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/work-share",
    tag = "ai",
    params(ShareQuery),
    responses(
        (status = 200, description = "Per process: completions by agents and by people, hand-offs, the agents' share and the days", body = PaginatedResponse<ProcessShare>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 422, description = "from after to, or a range over a year", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_work_share(
    State(state): State<EngineState>,
    _admin: Authorized<Privilege<area::Ai>>,
    Query(query): Query<ShareQuery>,
) -> Result<Json<PaginatedResponse<ProcessShare>>, AppError> {
    let range = range_of(&query, Utc::now().date_naive());
    check_range(range)?;
    let db = &state.base.db;
    let measures: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT process_key, label, label_ar FROM ai_work_measure \
          WHERE is_active IS NOT FALSE ORDER BY process_key LIMIT $1",
    )
    .bind(MAX_PROCESSES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let rows: Vec<(String, NaiveDate, i32, i32, i32)> = sqlx::query_as(
        "SELECT process_key, day, done_by_agent, done_by_person, handed_between \
           FROM ai_work_share_daily WHERE day BETWEEN $1 AND $2 ORDER BY process_key, day",
    )
    .bind(range.from)
    .bind(range.to)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<ProcessShare> = measures
        .into_iter()
        .map(|(process_key, label, label_ar)| {
            let days: Vec<ShareDay> = rows
                .iter()
                .filter(|r| r.0 == process_key)
                .map(|r| ShareDay {
                    day: r.1,
                    done_by_agent: r.2,
                    done_by_person: r.3,
                    handed_between: r.4,
                })
                .collect();
            let agent: i64 = days.iter().map(|d| i64::from(d.done_by_agent)).sum();
            let person: i64 = days.iter().map(|d| i64::from(d.done_by_person)).sum();
            let handed: i64 = days.iter().map(|d| i64::from(d.handed_between)).sum();
            ProcessShare {
                process_key,
                label,
                label_ar,
                done_by_agent: agent,
                done_by_person: person,
                handed_between: handed,
                share: share(agent, person),
                days,
            }
        })
        .collect();
    let total = i64::try_from(items.len()).map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, 1, MAX_PROCESSES)))
}

/// Whose completions to list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DoneBy {
    Agent,
    Person,
}

/// The events behind one count.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EventsQuery {
    /// The day, as YYYY-MM-DD.
    pub day: NaiveDate,
    /// `agent` or `person`.
    #[param(value_type = String)]
    pub by: DoneBy,
    /// The previous page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One completion behind a number.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ShareEvent {
    pub id: Uuid,
    pub entity: String,
    pub record_id: Uuid,
    pub at: DateTime<Utc>,
    pub agent_session_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/work-share/{process_key}/events",
    tag = "ai",
    params(("process_key" = String, Path, description = "The measure's process key"), EventsQuery),
    responses(
        (status = 200, description = "The completions behind the count, newest first, while the feed retains them", body = CursorPage<ShareEvent>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 404, description = "No such measure", body = ErrorResponse),
        (status = 422, description = "A cursor this route did not issue", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_work_share_events(
    State(state): State<EngineState>,
    _admin: Authorized<Privilege<area::Ai>>,
    Path(process_key): Path<String>,
    Query(query): Query<EventsQuery>,
) -> Result<Json<CursorPage<ShareEvent>>, AppError> {
    let db = &state.base.db;
    let measure: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT entity_logical_name, completion_attribute, completion_values \
           FROM ai_work_measure WHERE process_key = $1",
    )
    .bind(&process_key)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (entity, attribute, values) = measure.ok_or(AppError::NotFound)?;
    let values = parse_values(values.as_deref().unwrap_or(""));
    let start = query.day.and_time(NaiveTime::MIN).and_utc();
    let next_day = query.day + Days::new(1);
    let end = next_day.and_time(NaiveTime::MIN).and_utc();
    let (before_at, before_id) = match query.cursor.as_deref() {
        Some(c) => decode_cursor(c)?,
        None => (end, Uuid::max()),
    };
    let initiator: i16 = match query.by {
        DoneBy::Agent => 1,
        DoneBy::Person => 0,
    };
    let items: Vec<ShareEvent> = sqlx::query_as(
        "SELECT id, entity_logicalname AS entity, record_id, created_at AS at, agent_session_id \
           FROM entity_change_event \
          WHERE entity_logicalname = $1 AND operation IN ('create', 'update') \
            AND $2 = ANY(changed_attributes) AND btrim(after ->> $2) = ANY($3) \
            AND (CASE WHEN initiator = 1 THEN 1 ELSE 0 END) = $4 \
            AND created_at >= $5 AND (created_at, id) < ($6, $7) \
          ORDER BY created_at DESC, id DESC LIMIT $8",
    )
    .bind(&entity)
    .bind(&attribute)
    .bind(&values)
    .bind(initiator)
    .bind(start)
    .bind(before_at)
    .bind(before_id)
    .bind(EVENTS_PAGE)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let full = i64::try_from(items.len()).unwrap_or(0) == EVENTS_PAGE;
    let next = if full {
        items.last().map(|e| encode_cursor(e.at, e.id))
    } else {
        None
    };
    Ok(Json(CursorPage::new(items, next)))
}

/// A started rebuild.
#[derive(Debug, Serialize, ToSchema)]
pub struct RebuildQueued {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/work-share/rebuild",
    tag = "ai",
    request_body = RebuildRange,
    responses(
        (status = 202, description = "The recount is queued; it clears the range and counts it again", body = RebuildQueued),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 422, description = "from after to, or a range over a year", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_rebuild(
    State(state): State<EngineState>,
    admin: Authorized<Privilege<area::Ai>>,
    Json(range): Json<RebuildRange>,
) -> Result<(StatusCode, Json<RebuildQueued>), AppError> {
    check_range(range)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let job = attome_jobs::RegisteredJob {
        name: REBUILD_JOB.to_owned(),
        version: 1,
        payload: serde_json::to_value(range).map_err(AppError::internal)?,
        next: None,
    };
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Ai,
            AuditOperation::Create,
            admin.user_id,
            "ai_work_share_daily",
            None,
        )
        .named("ai.work_share.rebuild")
        .comment(format!("{} to {}", range.from, range.to)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    let queued = RebuildQueued {
        from: range.from,
        to: range.to,
    };
    Ok((StatusCode::ACCEPTED, Json(queued)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/ai/work-share", get(get_work_share))
        .route(
            "/api/v1/admin/ai/work-share/{process_key}/events",
            get(get_work_share_events),
        )
        .route("/api/v1/admin/ai/work-share/rebuild", post(post_rebuild))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_work_share, get_work_share_events, post_rebuild),
    components(schemas(
        ProcessShare,
        ShareDay,
        ShareEvent,
        DoneBy,
        RebuildRange,
        RebuildQueued
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_share_is_none_until_something_is_done() {
        assert_eq!(share(0, 0), None);
        assert_eq!(share(1, 3), Some(0.25));
        assert_eq!(share(2, 0), Some(1.0));
    }

    #[test]
    fn work_share_range_defaults_to_the_last_30_days() {
        let today = NaiveDate::from_ymd_opt(2026, 10, 21).unwrap();
        let none = ShareQuery {
            from: None,
            to: None,
        };
        let range = range_of(&none, today);
        assert_eq!(range.to, today);
        assert_eq!((range.to - range.from).num_days(), 29);
    }
}

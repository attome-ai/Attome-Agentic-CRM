//! M7-T2/T3: stage processes for forms and reports.
//!
//! `GET /api/v1/stage-processes/for/{entity}` answers the newest published
//! stage process of an entity, for the form's stage bar (any signed-in
//! caller: it is metadata, the same a form shows).
//!
//! `GET /api/v1/stage-processes/{id}/metrics` measures time in stage from
//! `stage_move` (M7-T1), administrators only: for each stage, how many
//! records entered it, how many left it, how many are in it now, the mean
//! and 90th-percentile time a record spent in it before leaving, and the
//! drop-off, the share of records that entered it and never moved on to
//! the stage after it in the process's order. A final stage has no
//! drop-off.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// A published stage process.
#[derive(Debug, Serialize, ToSchema)]
pub struct StageProcessView {
    pub id: Uuid,
    pub name: String,
    pub entity: String,
    /// The stages, in order, as the process document holds them.
    #[schema(value_type = Vec<Object>)]
    pub stages: Vec<Value>,
}

/// One stage's measures.
#[derive(Debug, Serialize, ToSchema, PartialEq)]
pub struct StageMetric {
    pub code: String,
    pub label_en: String,
    pub entered: i64,
    pub left: i64,
    pub current: i64,
    pub avg_seconds: Option<f64>,
    pub p90_seconds: Option<f64>,
    /// Percent of records that entered and did not move to the next stage
    /// in order; `null` for the last stage.
    pub drop_off_pct: Option<f64>,
}

/// A process's time-in-stage measures.
#[derive(Debug, Serialize, ToSchema)]
pub struct StageMetrics {
    pub process_id: Uuid,
    pub entity: String,
    pub stages: Vec<StageMetric>,
}

#[derive(sqlx::FromRow)]
struct ProcessRow {
    id: Uuid,
    name: String,
    doc: Value,
}

async fn published(state: &EngineState, filter: ProcessFilter) -> Result<ProcessRow, AppError> {
    let (clause, bind) = match filter {
        ProcessFilter::Entity(entity_id) => ("v.doc->>'entity' = $1", entity_id.to_string()),
        ProcessFilter::Id(id) => ("o.id::text = $1", id.to_string()),
    };
    sqlx::query_as::<_, ProcessRow>(&format!(
        "SELECT o.id, o.name, v.doc FROM metadata_object o \
           JOIN metadata_object_version v ON v.object_id = o.id \
          WHERE o.kind = 'stage_process' AND o.is_active AND v.state = 'published' AND {clause} \
          ORDER BY o.created_at, o.id, v.version_no DESC LIMIT 1"
    ))
    .bind(bind)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

enum ProcessFilter {
    Entity(Uuid),
    Id(Uuid),
}

fn entity_name(state: &EngineState, entity_id: &str) -> Option<String> {
    let id = Uuid::parse_str(entity_id).ok()?;
    state
        .entities
        .load()
        .get_by_id(id)
        .map(|m| m.logicalname.clone())
}

/// Stage processes of an entity
///
/// Stage processes of an entity. Any signed-in user.
#[utoipa::path(
    get,
    path = "/api/v1/stage-processes/for/{entity}",
    tag = "metadata",
    operation_id = "get_entity_stage_process",
    description = "The newest published stage process of an entity (M7-T2), for the form's stage bar: its stages in order, each with its required attributes, checklist and next stages.",
    params(("entity" = String, Path, description = "The entity's logical name")),
    responses(
        (status = 200, description = "The process", body = StageProcessView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such entity, or it has no published stage process", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn for_entity(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Path(entity): Path<String>,
) -> Result<Json<StageProcessView>, AppError> {
    let entity_id = state
        .entities
        .load()
        .get(&entity)
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    let row = published(&state, ProcessFilter::Entity(entity_id)).await?;
    Ok(Json(StageProcessView {
        id: row.id,
        name: row.name,
        entity,
        stages: row.doc["stages"].as_array().cloned().unwrap_or_default(),
    }))
}

#[derive(sqlx::FromRow)]
struct DurationRow {
    to_stage: String,
    entered: i64,
    left_count: i64,
    avg_seconds: Option<f64>,
    p90_seconds: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct FlowRow {
    to_stage: String,
    next_stage: Option<String>,
    records: i64,
}

/// One stage's duration row: its counts and its two duration measures.
pub type StageDurations = (i64, i64, Option<f64>, Option<f64>);

/// The per-stage measures from the duration and flow rows, in the
/// process's stage order.
pub fn assemble(
    stages: &[Value],
    durations: &HashMap<String, StageDurations>,
    flows: &HashMap<(String, Option<String>), i64>,
) -> Vec<StageMetric> {
    let codes: Vec<&str> = stages.iter().filter_map(|s| s["code"].as_str()).collect();
    codes
        .iter()
        .enumerate()
        .map(|(i, code)| {
            let (entered, left, avg, p90) =
                durations.get(*code).cloned().unwrap_or((0, 0, None, None));
            let drop_off_pct = codes.get(i + 1).map(|next| {
                let onward = flows
                    .get(&((*code).to_owned(), Some((*next).to_owned())))
                    .copied()
                    .unwrap_or(0);
                if entered == 0 {
                    0.0
                } else {
                    (entered - onward) as f64 * 100.0 / entered as f64
                }
            });
            StageMetric {
                code: (*code).to_owned(),
                label_en: stages[i]["label_en"].as_str().unwrap_or(code).to_owned(),
                entered,
                left,
                current: entered - left,
                avg_seconds: avg,
                p90_seconds: p90,
                drop_off_pct,
            }
        })
        .collect()
}

/// Stage process metrics
///
/// Stage process metrics. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/stage-processes/{id}/metrics",
    tag = "metadata",
    operation_id = "get_stage_process_metrics",
    description = "Time-in-stage measures of a stage process (M7-T3), from its recorded moves: per stage, records entered, left and in it now, mean and p90 seconds spent before leaving, and drop-off (percent of records that entered and never moved to the next stage in order).",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The measures", body = StageMetrics),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No published stage process with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn metrics(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<StageMetrics>, AppError> {
    let row = published(&state, ProcessFilter::Id(id)).await?;
    let entity = row.doc["entity"]
        .as_str()
        .and_then(|e| entity_name(&state, e))
        .ok_or(AppError::NotFound)?;
    let with_moves = "WITH m AS ( \
          SELECT to_stage, moved_at, \
                 LEAD(moved_at) OVER (PARTITION BY record_id ORDER BY moved_at, id) AS left_at, \
                 LEAD(to_stage) OVER (PARTITION BY record_id ORDER BY moved_at, id) AS next_stage \
            FROM stage_move WHERE entity_logicalname = $1)";
    let durations: Vec<DurationRow> = sqlx::query_as(&format!(
        "{with_moves} SELECT to_stage, COUNT(*) AS entered, COUNT(left_at) AS left_count, \
                AVG(EXTRACT(EPOCH FROM left_at - moved_at))::float8 AS avg_seconds, \
                (percentile_cont(0.9) WITHIN GROUP \
                    (ORDER BY EXTRACT(EPOCH FROM left_at - moved_at)))::float8 AS p90_seconds \
           FROM m GROUP BY to_stage"
    ))
    .bind(&entity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let flows: Vec<FlowRow> = sqlx::query_as(&format!(
        "{with_moves} SELECT to_stage, next_stage, COUNT(*) AS records FROM m \
           GROUP BY to_stage, next_stage"
    ))
    .bind(&entity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let durations = durations
        .into_iter()
        .map(|d| {
            (
                d.to_stage,
                (d.entered, d.left_count, d.avg_seconds, d.p90_seconds),
            )
        })
        .collect();
    let flows = flows
        .into_iter()
        .map(|f| ((f.to_stage, f.next_stage), f.records))
        .collect();
    let stages = row.doc["stages"].as_array().cloned().unwrap_or_default();
    Ok(Json(StageMetrics {
        process_id: row.id,
        entity,
        stages: assemble(&stages, &durations, &flows),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/stage-processes/for/{entity}", get(for_entity))
        .route("/api/v1/stage-processes/{id}/metrics", get(metrics))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(for_entity, metrics))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_metrics_measure_time_and_drop_off_per_stage() {
        let stages = vec![
            serde_json::json!({ "code": "qualify", "label_en": "Qualify" }),
            serde_json::json!({ "code": "propose", "label_en": "Propose" }),
            serde_json::json!({ "code": "won", "label_en": "Won" }),
        ];
        let durations = HashMap::from([
            ("qualify".to_owned(), (10, 8, Some(3600.0), Some(7200.0))),
            ("propose".to_owned(), (6, 5, Some(86400.0), Some(172800.0))),
            ("won".to_owned(), (4, 0, None, None)),
        ]);
        let flows = HashMap::from([
            (("qualify".to_owned(), Some("propose".to_owned())), 6),
            (("qualify".to_owned(), Some("lost".to_owned())), 2),
            (("qualify".to_owned(), None), 2),
            (("propose".to_owned(), Some("won".to_owned())), 4),
        ]);
        let m = assemble(&stages, &durations, &flows);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].current, 2);
        assert_eq!(
            m[0].drop_off_pct,
            Some(40.0),
            "4 of 10 never reached propose"
        );
        assert_eq!(m[1].p90_seconds, Some(172800.0));
        assert!((m[1].drop_off_pct.unwrap() - 100.0 / 3.0).abs() < 1e-9);
        assert_eq!(m[2].drop_off_pct, None, "the last stage has no drop-off");
        assert_eq!(m[2].current, 4);
    }
}

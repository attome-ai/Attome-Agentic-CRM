//! O8-T1: conformance checking. Each case's events, in order, are replayed
//! against the designed model and every step the model does not allow is
//! reported.
//!
//! The designed model of a case def:
//! - `stage:<entity>`: the entity's newest published `stage_process`
//!   (M7-T1): a case starts in the first stage and may move from a stage
//!   only to one it lists in `next`; a stage with no `next` ends the process.
//! - `entity:<entity>` whose `activity_mapping.field` is the entity's state
//!   field: its active state model (M8): a case starts in the initial state
//!   and moves along the model's transitions.
//!
//! Activities are compared after the case def's `activity_mapping.values`
//! remap, applied to the model's states and stages too, so a renamed label
//! still matches. A workflow case def has no designed model here (its graph
//! is the process) and answers `422`.
//!
//! `GET /api/v1/process/case-defs/{id}/conformance` (administrators) answers
//! the share of cases that conform, the deviations by step with their counts,
//! and the first [`MAX_DEVIATIONS`] deviating steps with their case.

use std::collections::{BTreeMap, HashMap, HashSet};

use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// Deviating steps listed one by one.
pub const MAX_DEVIATIONS: usize = 200;
/// Cases replayed per check.
const MAX_CASES: i64 = 5_000;
/// Events read per check.
const MAX_EVENTS: i64 = 200_000;

/// A designed process: where a case may start and which steps it may take.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DesignedModel {
    /// Activities a case may start with; empty means any.
    pub starts: HashSet<String>,
    /// Allowed `(from, to)` steps.
    pub steps: HashSet<(String, String)>,
}

/// One step a case took that the model does not allow (`from` is `None` for
/// a wrong start).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Deviation {
    pub case_id: Uuid,
    pub from: Option<String>,
    pub to: String,
    pub at: DateTime<Utc>,
}

/// A deviating step and how often it happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DeviationCount {
    pub from: Option<String>,
    pub to: String,
    pub count: u64,
}

/// The result of a check.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ConformanceReport {
    pub cases: u64,
    pub conforming: u64,
    /// `conforming / cases`, 1 for no cases.
    pub fitness: f64,
    pub by_step: Vec<DeviationCount>,
    pub deviations: Vec<Deviation>,
}

/// Replays `cases` (each case's events in time order) against `model`.
/// Repeating the same activity (no move) is not a step. Pure.
pub fn check(
    cases: &[(Uuid, Vec<(String, DateTime<Utc>)>)],
    model: &DesignedModel,
) -> ConformanceReport {
    let mut conforming = 0u64;
    let mut counts: BTreeMap<(Option<String>, String), u64> = BTreeMap::new();
    let mut deviations = Vec::new();
    for (case_id, events) in cases {
        let mut ok = true;
        let mut previous: Option<&str> = None;
        for (activity, at) in events {
            let bad = match previous {
                None => !model.starts.is_empty() && !model.starts.contains(activity),
                Some(p) if p == activity => false,
                Some(p) => !model.steps.contains(&(p.to_owned(), activity.clone())),
            };
            if bad {
                ok = false;
                let from = previous.map(str::to_owned);
                *counts.entry((from.clone(), activity.clone())).or_default() += 1;
                if deviations.len() < MAX_DEVIATIONS {
                    deviations.push(Deviation {
                        case_id: *case_id,
                        from,
                        to: activity.clone(),
                        at: *at,
                    });
                }
            }
            previous = Some(activity);
        }
        if ok {
            conforming += 1;
        }
    }
    let total = cases.len() as u64;
    let mut by_step: Vec<DeviationCount> = counts
        .into_iter()
        .map(|((from, to), count)| DeviationCount { from, to, count })
        .collect();
    by_step.sort_by(|a, b| b.count.cmp(&a.count));
    ConformanceReport {
        cases: total,
        conforming,
        fitness: if total == 0 {
            1.0
        } else {
            conforming as f64 / total as f64
        },
        by_step,
        deviations,
    }
}

fn remap(values: &Value, raw: &str) -> String {
    values
        .get(raw)
        .and_then(Value::as_str)
        .unwrap_or(raw)
        .to_owned()
}

/// The model of a published stage process document. Pure.
pub fn stage_model(doc: &Value, values: &Value) -> DesignedModel {
    let stages = doc
        .get("stages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut model = DesignedModel::default();
    if let Some(first) = stages
        .first()
        .and_then(|s| s.get("code"))
        .and_then(Value::as_str)
    {
        model.starts.insert(remap(values, first));
    }
    for stage in &stages {
        let Some(code) = stage.get("code").and_then(Value::as_str) else {
            continue;
        };
        for next in stage
            .get("next")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(next) = next.as_str() {
                model
                    .steps
                    .insert((remap(values, code), remap(values, next)));
            }
        }
    }
    model
}

/// The model of a state model: its initial state and transitions. Pure.
pub fn state_model(
    initial: &str,
    transitions: &[(String, String)],
    values: &Value,
) -> DesignedModel {
    DesignedModel {
        starts: HashSet::from([remap(values, initial)]),
        steps: transitions
            .iter()
            .map(|(f, t)| (remap(values, f), remap(values, t)))
            .collect(),
    }
}

async fn designed(
    state: &EngineState,
    source: &str,
    mapping: &Value,
) -> Result<DesignedModel, AppError> {
    let db = &state.base.db;
    let values = mapping.get("values").cloned().unwrap_or(Value::Null);
    if let Some(entity) = source.strip_prefix("stage:") {
        let doc: Option<Value> = sqlx::query_scalar(
            "SELECT v.doc FROM metadata_object o \
               JOIN metadata_object_version v ON v.object_id = o.id \
               JOIN entity_info e ON e.id::text = v.doc->>'entity' \
              WHERE o.kind = 'stage_process' AND o.is_active AND v.state = 'published' \
                AND e.logicalname = $1 \
              ORDER BY o.created_at, o.id, v.version_no DESC LIMIT 1",
        )
        .bind(entity)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let doc = doc.ok_or_else(|| {
            AppError::Validation(format!("{entity} has no published stage process"))
        })?;
        return Ok(stage_model(&doc, &values));
    }
    if let Some(entity) = source.strip_prefix("entity:") {
        let field = mapping
            .get("field")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let model: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, initial_state::text FROM state_model \
              WHERE entity_logicalname = $1 AND state_field = $2 AND is_active AND NOT is_deleted                 AND record_type IS NULL \
              ORDER BY id LIMIT 1",
        )
        .bind(entity)
        .bind(field)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let (model_id, initial) = model.ok_or_else(|| {
            AppError::Validation(format!(
                "{entity} has no active state model on its {field} field"
            ))
        })?;
        let transitions: Vec<(String, String)> = sqlx::query_as(
            "SELECT from_state::text, to_state::text FROM state_transition WHERE model_ref = $1 AND NOT is_deleted",
        )
        .bind(model_id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        return Ok(state_model(&initial, &transitions, &values));
    }
    Err(AppError::Validation(
        "a workflow case def has no designed model to check against; its graph is the process"
            .into(),
    ))
}

/// Checks one case def's cases against its designed model.
pub async fn conformance(
    state: &EngineState,
    case_def: Uuid,
) -> Result<ConformanceReport, AppError> {
    let db = &state.base.db;
    let def: Option<(String, Value)> = sqlx::query_as(
        "SELECT source, activity_mapping FROM process_case_def \
          WHERE id = $1 AND is_deleted = false",
    )
    .bind(case_def)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (source, mapping) = def.ok_or(AppError::NotFound)?;
    let model = designed(state, &source, &mapping).await?;
    let events: Vec<(Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT e.case_id, e.activity, e.ts_start FROM process_event e \
          WHERE e.case_def_ref = $1 AND e.case_id IN \
                (SELECT DISTINCT case_id FROM process_event WHERE case_def_ref = $1 LIMIT $2) \
          ORDER BY e.case_id, e.ts_start, e.id LIMIT $3",
    )
    .bind(case_def)
    .bind(MAX_CASES)
    .bind(MAX_EVENTS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut by_case: HashMap<Uuid, Vec<(String, DateTime<Utc>)>> = HashMap::new();
    let mut order = Vec::new();
    for (case, activity, at) in events {
        let list = by_case.entry(case).or_insert_with(|| {
            order.push(case);
            Vec::new()
        });
        list.push((activity, at));
    }
    let cases: Vec<(Uuid, Vec<(String, DateTime<Utc>)>)> = order
        .into_iter()
        .filter_map(|c| by_case.remove(&c).map(|e| (c, e)))
        .collect();
    Ok(check(&cases, &model))
}

#[utoipa::path(
    get,
    path = "/api/v1/process/case-defs/{id}/conformance",
    operation_id = "get_process_conformance",
    tag = "process",
    params(("id" = Uuid, Path, description = "The case def")),
    responses(
        (status = 200, description = "How the cases conform to the designed process", body = ConformanceReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such case def", body = ErrorResponse),
        (status = 422, description = "The case def has no designed model (a workflow, or no published stage process or state model)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Check a case def's cases against the designed process.
///
/// Replays each case against the entity's stage process or state model and
/// reports the share that conform and every step the model does not allow.
async fn get_conformance(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConformanceReport>, AppError> {
    conformance(&state, id).await.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/process/case-defs/{id}/conformance",
        get(get_conformance),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_conformance),
    components(schemas(ConformanceReport, Deviation, DeviationCount))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn at(minute: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_761_566_400 + minute * 60, 0).unwrap()
    }

    fn case(steps: &[&str]) -> (Uuid, Vec<(String, DateTime<Utc>)>) {
        (
            Uuid::now_v7(),
            steps
                .iter()
                .enumerate()
                .map(|(n, s)| ((*s).to_owned(), at(n as i64)))
                .collect(),
        )
    }

    #[test]
    fn conformance_reports_steps_the_stage_process_forbids() {
        let doc = json!({ "stages": [
            { "code": "qualify", "next": ["propose", "lost"] },
            { "code": "propose", "next": ["won", "lost"] },
            { "code": "won" }, { "code": "lost" }
        ] });
        let model = stage_model(&doc, &Value::Null);
        let cases = vec![
            case(&["qualify", "propose", "won"]),
            case(&["qualify", "won"]),
            case(&["propose", "won"]),
            case(&["qualify", "qualify", "lost"]),
        ];
        let report = check(&cases, &model);
        assert_eq!(report.cases, 4);
        assert_eq!(report.conforming, 2);
        assert!((report.fitness - 0.5).abs() < 1e-9);
        assert_eq!(report.deviations.len(), 2);
        assert_eq!(report.deviations[0].from.as_deref(), Some("qualify"));
        assert_eq!(report.deviations[0].to, "won");
        assert_eq!(report.deviations[1].from, None, "a wrong start");
    }

    #[test]
    fn conformance_remaps_labels_on_both_sides() {
        let values = json!({ "new": "New", "qualified": "Qualified" });
        let model = state_model("new", &[("new".into(), "qualified".into())], &values);
        assert!(model.starts.contains("New"));
        let report = check(&[case(&["New", "Qualified"])], &model);
        assert_eq!(report.conforming, 1);
        assert_eq!(check(&[], &model).fitness, 1.0);
    }
}

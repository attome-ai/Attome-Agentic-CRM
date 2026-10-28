//! Trial mode (roadmap AH6, V2-D33): an agent definition in `testing` status
//! runs on real triggers, but every write or outside call it is allowed to
//! make is recorded in `ai_trial_decision` instead of run
//! (`execute::dispatch`). An hourly job compares each decision with what a
//! person did to the same record in the next 24 hours, from the audit trail;
//! the report shows how often the agent agreed, and going live is refused
//! below a threshold the administrator sets.
//!
//! The figures also feed earned autonomy (AH8-T9): agreement per action is
//! what `autonomy::propose_raises` reads.

use std::collections::HashMap;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::ActionDescriptor;

/// A decision is compared once it is this old: the window a person had.
pub const COMPARE_AFTER_HOURS: i32 = 24;
/// Decisions compared per job run.
const COMPARE_BATCH: i64 = 500;
/// Going live needs at least this many compared decisions with an outcome.
pub const MIN_COMPARED_FOR_GO_LIVE: i64 = 30;
/// The agreement going live needs when the request names none.
pub const DEFAULT_MIN_AGREEMENT: f64 = 0.9;
/// `different` decisions the report shows.
const SAMPLE: i64 = 50;

/// Audit operations a person's change can carry (`attome_audit::AuditOperation`).
const OP_SOFT_DELETE: i32 = 2;
const OP_HARD_DELETE: i32 = 3;

/// Records what a trial session would have done. Returns the decision's id.
pub async fn record(
    state: &EngineState,
    ctx: &ActionContext,
    descriptor: &ActionDescriptor,
    args: &Value,
) -> Result<Uuid, AppError> {
    let Some(session_id) = ctx.agent_session_id else {
        return Err(AppError::internal(
            "a trial decision needs its agent session",
        ));
    };
    let (entity, record_id) = match crate::approval::target_of(args) {
        Some((entity, id)) => (Some(entity), Some(id)),
        None => (None, None),
    };
    sqlx::query_scalar(
        "INSERT INTO ai_trial_decision \
           (agent_session_id, agent_ref, action_id, args, target_entity, target_record_id) \
         SELECT $1, s.agent_definition_ref, $2, $3, $4, $5 FROM agent_session s WHERE s.id = $1 \
         RETURNING id",
    )
    .bind(session_id)
    .bind(descriptor.id.0)
    .bind(args)
    .bind(entity)
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// How a decision compares with what a person did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HumanOutcome {
    /// The person did the same thing.
    Same,
    /// The person did something else to the same thing.
    Different,
    /// The person left it alone (or the decision cannot be compared).
    None,
}

impl HumanOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Same => "same",
            Self::Different => "different",
            Self::None => "none",
        }
    }
}

/// A person's changes to one record in the window, from the audit trail.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HumanChanges {
    /// Field to the last value a person set it to (audit text form).
    pub fields: HashMap<String, Option<String>>,
    /// A person deleted the record.
    pub deleted: bool,
    /// A person changed the record at all.
    pub touched: bool,
}

/// The values a decision would have set: `values`, plus a state move's `to`.
fn intended(args: &Value) -> Map<String, Value> {
    let mut out = args
        .get("values")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(to) = args.get("to") {
        out.insert("__state".to_owned(), to.clone());
    }
    out
}

/// The audit trail's text form of a JSON value.
fn as_audit_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

/// Compares one decision with a person's changes. Pure.
///
/// A delete is `same` when a person deleted the record. A write is `same`
/// when a person set every field it would have set to the same value,
/// `different` when a person set any of those fields otherwise, and `none`
/// when no person touched them. Anything else (no record, no values) is
/// `none`: there is nothing to compare.
pub fn compare(action_id: &str, args: &Value, human: &HumanChanges) -> HumanOutcome {
    if action_id.ends_with(".delete") {
        return if human.deleted {
            HumanOutcome::Same
        } else if human.touched {
            HumanOutcome::Different
        } else {
            HumanOutcome::None
        };
    }
    let wanted = intended(args);
    let wanted: Vec<(&String, &Value)> = wanted.iter().filter(|(k, _)| *k != "__state").collect();
    if wanted.is_empty() {
        return HumanOutcome::None;
    }
    if human.deleted {
        return HumanOutcome::Different;
    }
    let mut any = false;
    let mut all_same = true;
    for (field, value) in wanted {
        match human.fields.get(field) {
            Some(set) => {
                any = true;
                if *set != as_audit_text(value) {
                    all_same = false;
                }
            }
            None => all_same = false,
        }
    }
    match (any, all_same) {
        (false, _) => HumanOutcome::None,
        (true, true) => HumanOutcome::Same,
        (true, false) => HumanOutcome::Different,
    }
}

#[derive(sqlx::FromRow)]
struct DueDecision {
    id: Uuid,
    action_id: String,
    args: Value,
    target_entity: Option<String>,
    target_record_id: Option<Uuid>,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct AuditChange {
    operation: Option<i32>,
    field_name: Option<String>,
    new_value: Option<String>,
}

/// A person's changes to one record between `from` and `from + 24h`.
async fn human_changes(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
    from: DateTime<Utc>,
) -> Result<HumanChanges, AppError> {
    let rows: Vec<AuditChange> = sqlx::query_as(
        "SELECT h.operation, d.field_name::text AS field_name, d.new_value \
         FROM audit_header h \
         LEFT JOIN audit_detail d ON d.audit_ref = h.id \
         WHERE h.entity_name = $1 AND h.record_id = $2 AND h.initiator = 0 \
           AND h.created_at >= $3 AND h.created_at < $3 + make_interval(hours => $4) \
         ORDER BY h.created_at, h.event_index",
    )
    .bind(entity)
    .bind(record_id)
    .bind(from)
    .bind(COMPARE_AFTER_HOURS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut out = HumanChanges::default();
    for row in rows {
        out.touched = true;
        if matches!(row.operation, Some(OP_SOFT_DELETE | OP_HARD_DELETE)) {
            out.deleted = true;
        }
        if let Some(field) = row.field_name {
            out.fields.insert(field, row.new_value);
        }
    }
    Ok(out)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CompareStats {
    pub compared: u64,
}

/// The hourly job (`EngineJob::AiTrialCompare`): compares every decision
/// older than [`COMPARE_AFTER_HOURS`] that has not been compared yet.
pub async fn compare_due(state: &EngineState) -> Result<CompareStats, AppError> {
    let due: Vec<DueDecision> = sqlx::query_as(
        "SELECT id, action_id, args, target_entity, target_record_id, created_at \
         FROM ai_trial_decision \
         WHERE compared_at IS NULL AND created_at < now() - make_interval(hours => $1) \
         ORDER BY created_at LIMIT $2",
    )
    .bind(COMPARE_AFTER_HOURS)
    .bind(COMPARE_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut stats = CompareStats::default();
    for d in due {
        let human = match (&d.target_entity, d.target_record_id) {
            (Some(entity), Some(record)) => {
                human_changes(state, entity, record, d.created_at).await?
            }
            _ => HumanChanges::default(),
        };
        let outcome = compare(&d.action_id, &d.args, &human);
        sqlx::query(
            "UPDATE ai_trial_decision SET human_outcome = $2, compared_at = now() \
             WHERE id = $1 AND compared_at IS NULL",
        )
        .bind(d.id)
        .bind(outcome.as_str())
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        stats.compared += 1;
    }
    Ok(stats)
}

/// Agreement for one set of counts: same / (same + different), or `None`
/// when nothing was compared with an outcome. Pure.
pub fn agreement(same: i64, different: i64) -> Option<f64> {
    let decided = same + different;
    (decided > 0).then(|| same as f64 / decided as f64)
}

/// The counts for one action.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ActionAgreement {
    pub action_id: String,
    pub same: i64,
    pub different: i64,
    pub none: i64,
    pub pending: i64,
}

impl ActionAgreement {
    pub fn agreement(&self) -> Option<f64> {
        agreement(self.same, self.different)
    }
}

/// Per-action counts for one agent definition's trial decisions, optionally
/// only those created since `since`.
pub async fn counts(
    db: &attome_db::DbPool,
    agent: Uuid,
    since: Option<DateTime<Utc>>,
) -> Result<Vec<ActionAgreement>, AppError> {
    sqlx::query_as(
        "SELECT action_id, \
           COUNT(*) FILTER (WHERE human_outcome = 'same') AS same, \
           COUNT(*) FILTER (WHERE human_outcome = 'different') AS different, \
           COUNT(*) FILTER (WHERE human_outcome = 'none') AS none, \
           COUNT(*) FILTER (WHERE compared_at IS NULL) AS pending \
         FROM ai_trial_decision WHERE agent_ref = $1 AND ($2::timestamptz IS NULL OR created_at >= $2) \
         GROUP BY action_id ORDER BY action_id",
    )
    .bind(agent)
    .bind(since)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// One decision a person did differently, for the report.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DifferentDecision {
    pub id: Uuid,
    pub action_id: String,
    /// What the agent would have sent. Model-made: show it as a quotation.
    pub args: Value,
    pub target_entity: Option<String>,
    pub target_record_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// `GET /api/v1/admin/ai/agents/{id}/trial-report`.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrialReport {
    pub same: i64,
    pub different: i64,
    pub none: i64,
    pub pending: i64,
    /// same / (same + different); `null` before anything was compared.
    pub agreement: Option<f64>,
    pub per_action: Vec<ActionAgreement>,
    /// The latest decisions a person did differently (at most 50).
    pub different_sample: Vec<DifferentDecision>,
    /// What going live needs.
    pub min_compared: i64,
}

async fn report_for(state: &EngineState, agent: Uuid) -> Result<TrialReport, AppError> {
    let per_action = counts(&state.base.db, agent, None).await?;
    let sum = |f: fn(&ActionAgreement) -> i64| per_action.iter().map(f).sum::<i64>();
    let (same, different) = (sum(|a| a.same), sum(|a| a.different));
    let different_sample: Vec<DifferentDecision> = sqlx::query_as(
        "SELECT id, action_id, args, target_entity, target_record_id, created_at \
         FROM ai_trial_decision WHERE agent_ref = $1 AND human_outcome = 'different' \
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(agent)
    .bind(SAMPLE)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(TrialReport {
        same,
        different,
        none: sum(|a| a.none),
        pending: sum(|a| a.pending),
        agreement: agreement(same, different),
        per_action,
        different_sample,
        min_compared: MIN_COMPARED_FOR_GO_LIVE,
    })
}

/// Read an agent's trial report
///
/// While an agent definition is in `testing`, its writes and outside calls are recorded, not run, and
/// compared with what a person did to the same record within 24 hours; this is how often it agreed,
/// overall and per action. AI administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/agents/{id}/trial-report",
    operation_id = "agent_trial_report",
    tag = "action",
    params(("id" = Uuid, Path, description = "The agent definition")),
    responses(
        (status = 200, description = "How often the agent agreed with people in trial", body = TrialReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn trial_report(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Path(agent): Path<Uuid>,
) -> Result<Json<TrialReport>, AppError> {
    Ok(Json(report_for(&state, agent).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct GoLive {
    /// The definition's current `row_version`.
    pub row_version: i64,
    /// The agreement needed, 0 to 1 (default 0.9).
    #[serde(default)]
    pub min_agreement: Option<f64>,
}

/// Whether a report allows going live at `min`. Pure.
pub fn go_live_refusal(report: &TrialReport, min: f64) -> Option<String> {
    let decided = report.same + report.different;
    if decided < MIN_COMPARED_FOR_GO_LIVE {
        return Some(format!(
            "only {decided} trial decisions were compared with what people did; going live needs {MIN_COMPARED_FOR_GO_LIVE}"
        ));
    }
    match report.agreement {
        Some(a) if a >= min => None,
        Some(a) => Some(format!(
            "the agent agreed with people {:.0}% of the time; going live needs {:.0}%",
            a * 100.0,
            min * 100.0
        )),
        None => Some("no trial decision has been compared yet".to_owned()),
    }
}

/// Take an agent out of trial
///
/// Moves an agent definition from `testing` to `active` when it agreed with what people did at least
/// as often as `min_agreement`; below it the call is refused. AI administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/ai/agents/{id}/go-live",
    operation_id = "agent_go_live",
    tag = "action",
    params(("id" = Uuid, Path, description = "The agent definition")),
    request_body = GoLive,
    responses(
        (status = 200, description = "The definition is active; the report it passed", body = TrialReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such agent definition", body = ErrorResponse),
        (status = 409, description = "The definition changed since row_version", body = ErrorResponse),
        (status = 422, description = "Not in testing, or below the threshold", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Ai, AuditOperation::Update)])))),
)]
async fn go_live(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Ai>>,
    Path(agent): Path<Uuid>,
    Json(body): Json<GoLive>,
) -> Result<Json<TrialReport>, AppError> {
    let min = body.min_agreement.unwrap_or(DEFAULT_MIN_AGREEMENT);
    if !(0.0..=1.0).contains(&min) {
        return Err(AppError::Validation(
            "min_agreement must be between 0 and 1".into(),
        ));
    }
    let record = attome_records::entity_crud::read_record(&state, &ctx, "ai_agent", agent).await?;
    if record.data().get("status").and_then(Value::as_str) != Some(crate::agent::TRIAL_STATUS) {
        return Err(AppError::Validation(
            "only an agent in testing goes live from trial".into(),
        ));
    }
    let report = report_for(&state, agent).await?;
    if let Some(reason) = go_live_refusal(&report, min) {
        return Err(AppError::Validation(reason));
    }
    attome_records::entity_crud::update_record_for(
        &state,
        &ctx,
        ctx.user_id,
        "ai_agent",
        agent,
        body.row_version,
        serde_json::json!({ "status": crate::agent::STARTABLE_STATUS }),
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Ai,
            AuditOperation::Update,
            ctx.user_id,
            "ai_agent",
            Some(agent),
        )
        .named("ai.agent.go_live")
        .comment(format!(
            "went live from trial at {:.1}% agreement over {} compared decisions (needed {:.0}%)",
            report.agreement.unwrap_or(0.0) * 100.0,
            report.same + report.different,
            min * 100.0
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(report))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/ai/agents/{id}/trial-report",
            get(trial_report),
        )
        .route("/api/v1/admin/ai/agents/{id}/go-live", post(go_live))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(trial_report, go_live),
    components(schemas(TrialReport, ActionAgreement, DifferentDecision, GoLive))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn changes(fields: &[(&str, Option<&str>)]) -> HumanChanges {
        HumanChanges {
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.map(str::to_owned)))
                .collect(),
            deleted: false,
            touched: !fields.is_empty(),
        }
    }

    #[test]
    fn a_write_matches_when_the_person_set_the_same_values() {
        let args = json!({ "entity": "case", "record_id": "x", "values": { "priority": "high", "score": 3 } });
        assert_eq!(
            compare(
                "record.update",
                &args,
                &changes(&[("priority", Some("high")), ("score", Some("3"))])
            ),
            HumanOutcome::Same
        );
        assert_eq!(
            compare(
                "record.update",
                &args,
                &changes(&[("priority", Some("low"))])
            ),
            HumanOutcome::Different
        );
        assert_eq!(
            compare("record.update", &args, &changes(&[])),
            HumanOutcome::None
        );
        assert_eq!(
            compare("record.update", &args, &changes(&[("other", Some("y"))])),
            HumanOutcome::None,
            "a person who changed other fields left these alone"
        );
    }

    #[test]
    fn a_delete_matches_a_persons_delete() {
        let args = json!({ "entity": "case", "record_id": "x" });
        let mut deleted = changes(&[]);
        deleted.deleted = true;
        deleted.touched = true;
        assert_eq!(
            compare("record.delete", &args, &deleted),
            HumanOutcome::Same
        );
        assert_eq!(
            compare(
                "record.delete",
                &args,
                &changes(&[("status", Some("open"))])
            ),
            HumanOutcome::Different
        );
        assert_eq!(
            compare("record.delete", &args, &changes(&[])),
            HumanOutcome::None
        );
    }

    #[test]
    fn agreement_and_go_live() {
        assert_eq!(agreement(0, 0), None);
        assert_eq!(agreement(9, 1), Some(0.9));
        let report = |same, different| TrialReport {
            same,
            different,
            none: 0,
            pending: 0,
            agreement: agreement(same, different),
            per_action: Vec::new(),
            different_sample: Vec::new(),
            min_compared: MIN_COMPARED_FOR_GO_LIVE,
        };
        assert!(
            go_live_refusal(&report(20, 0), 0.9).is_some(),
            "fewer than 30 compared"
        );
        assert!(
            go_live_refusal(&report(27, 3), 0.9).is_none(),
            "90% over 30"
        );
        assert!(
            go_live_refusal(&report(26, 4), 0.9).is_some(),
            "86% is below 90%"
        );
    }
}

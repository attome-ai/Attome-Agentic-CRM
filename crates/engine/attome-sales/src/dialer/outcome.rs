//! Call outcomes (roadmap D21-T5). Saving an outcome is one transaction: the
//! member must be claimed by the caller; a `call_attempt` is written with
//! the next attempt number; the member is done after a terminal outcome
//! (connected, wrong number, not interested) or back to pending after the
//! list's retry wait; and a durable job is queued to apply the list's
//! outcome rules after commit ([`apply_rules`]).
//!
//! The rules run as the user who made the call, through the generic record
//! update (so validation, audit and row versions apply): the lead's status
//! or the deal's stage, a callback task, and for a wrong number the record's
//! `phone_needs_check` flag where the entity has one. A retried job applies
//! nothing twice: the callback task carries the attempt id, and the field
//! updates are set-to-a-value, harmless to repeat.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use super::claim::CallListCall;

/// The outcomes that end a member's calls.
pub const TERMINAL: [&str; 3] = ["connected", "wrong_number", "not_interested"];

/// Every outcome the list understands.
pub const OUTCOMES: [&str; 7] = [
    "connected",
    "no_answer",
    "busy",
    "wrong_number",
    "voicemail_left",
    "call_back_later",
    "not_interested",
];

/// D3-T1: the disqualify reason a call outcome gives a lead it disqualifies
/// (the crm pack's lead lifecycle requires one). Pure.
pub fn disqualify_reason(outcome: &str) -> &'static str {
    match outcome {
        "not_interested" => "no_need",
        "wrong_number" | "no_answer" | "busy" | "voicemail_left" => "unreachable",
        "call_back_later" => "bad_timing",
        _ => "other",
    }
}

/// The member's status after an outcome.
pub fn next_status(outcome: &str) -> &'static str {
    if TERMINAL.contains(&outcome) {
        "done"
    } else {
        "pending"
    }
}

/// The callback task's marker, by which a retried job finds it.
pub fn marker(attempt: Uuid) -> String {
    format!("[call attempt {attempt}]")
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesCallOutcomeBody {
    pub outcome: String,
    #[serde(default)]
    pub duration_seconds: Option<i32>,
    /// The script's answers, as JSON text.
    #[serde(default)]
    pub script_answers: Option<String>,
    #[serde(default)]
    pub activity_id: Option<String>,
    #[serde(default)]
    pub voicemail_dropped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesCallOutcomeSaved {
    pub attempt_id: Uuid,
    pub attempt_number: i64,
    pub member_status: String,
}

type MemberRow = (Option<Uuid>, Option<String>, Option<i64>, Option<i64>);

/// Save a call outcome
///
/// Records a call attempt on a member the caller claimed: a final outcome (connected, wrong number, not
/// interested) ends it, anything else puts it back after the list's retry wait, and the list's outcome
/// rules run after commit. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sales/call-list-members/{id}/outcome",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The call list member")),
    request_body = SalesCallOutcomeBody,
    responses(
        (status = 201, description = "The attempt is saved and the list's outcome rules are queued", body = SalesCallOutcomeSaved),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "The member is not claimed by the caller", body = ErrorResponse),
        (status = 404, description = "No such member", body = ErrorResponse),
        (status = 422, description = "Unknown outcome", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_sales_call_outcome(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CallListCall>>,
    Path(member): Path<Uuid>,
    Json(body): Json<SalesCallOutcomeBody>,
) -> Result<(StatusCode, Json<SalesCallOutcomeSaved>), AppError> {
    if !OUTCOMES.contains(&body.outcome.as_str()) {
        return Err(AppError::Validation(format!(
            "outcome is one of {}",
            OUTCOMES.join(", ")
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<MemberRow> = sqlx::query_as(
        "SELECT m.claimed_by, m.member_status, m.attempts::bigint, l.retry_wait_minutes::bigint \
         FROM call_list_member m JOIN call_list l ON l.id = m.list_ref \
         WHERE m.id = $1 AND (m.is_active IS NULL OR m.is_active = true) FOR UPDATE OF m",
    )
    .bind(member)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((claimed_by, status, attempts, retry_wait)) = row else {
        return Err(AppError::NotFound);
    };
    if claimed_by != Some(ctx.user_id) || status.as_deref() != Some("claimed") {
        return Err(AppError::Forbidden);
    }
    let attempt_number = attempts.unwrap_or(0) + 1;
    let attempt: Uuid = sqlx::query_scalar(
        "INSERT INTO call_attempt \
           (member_ref, activity_id, attempt_number, outcome, duration_seconds, script_answers, \
            voicemail_dropped, owner_ref) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(member)
    .bind(&body.activity_id)
    .bind(attempt_number)
    .bind(&body.outcome)
    .bind(body.duration_seconds)
    .bind(&body.script_answers)
    .bind(body.voicemail_dropped)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let member_status = next_status(&body.outcome);
    let retry_after = Utc::now() + Duration::minutes(retry_wait.unwrap_or(60).max(0));
    sqlx::query(
        "UPDATE call_list_member SET attempts = $2, last_attempt_at = now(), \
             member_status = $3, claimed_by = NULL, claimed_at = NULL, \
             next_attempt_after = CASE WHEN $3 = 'pending' THEN $4 ELSE next_attempt_after END, \
             modified_at = now(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(member)
    .bind(attempt_number)
    .bind(member_status)
    .bind(retry_after)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::SalesCallOutcomeRules {
            attempt_id: attempt,
        },
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "call_attempt",
            attempt,
            attome_audit::AuditOperation::Create,
            "sales.call_outcome_saved",
            ctx.user_id,
        )
        .comment(body.outcome.clone()),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(SalesCallOutcomeSaved {
            attempt_id: attempt,
            attempt_number,
            member_status: member_status.to_owned(),
        }),
    ))
}

type AttemptRow = (
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
);

type RuleRow = (Option<String>, Option<String>, Option<i64>);

/// The outcome rules job: what the list says to do after this outcome.
pub async fn apply_rules(state: &EngineState, attempt: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    let row: Option<AttemptRow> = sqlx::query_as(
        "SELECT a.owner_ref, a.outcome, m.entity_name, m.record_id, m.list_ref \
         FROM call_attempt a JOIN call_list_member m ON m.id = a.member_ref WHERE a.id = $1",
    )
    .bind(attempt)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(caller), Some(outcome), Some(entity), Some(record), Some(list))) = row else {
        return Ok(());
    };
    let Ok(record) = Uuid::parse_str(&record) else {
        return Ok(());
    };
    let rule: Option<RuleRow> = sqlx::query_as(
        "SELECT set_lead_status, set_opportunity_stage, callback_after_minutes::bigint \
         FROM call_outcome_rule WHERE list_ref = $1 AND outcome = $2 \
           AND (is_active IS NULL OR is_active = true) LIMIT 1",
    )
    .bind(list)
    .bind(&outcome)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let ctx = state.base.security.resolve_strict(caller).await?;
    let (lead_status, stage, callback) = rule.unwrap_or((None, None, None));
    let mut changes = serde_json::Map::new();
    match entity.as_str() {
        "lead" => {
            if let Some(status) = lead_status.filter(|s| !s.is_empty()) {
                // D3-T1: a disqualified lead carries its reason.
                if status == "disqualified"
                    && state.entities.load().get("lead").is_some_and(|m| {
                        m.attrs.iter().any(|a| a.logicalname == "disqualify_reason")
                    })
                {
                    changes.insert(
                        "disqualify_reason".into(),
                        json!(disqualify_reason(&outcome)),
                    );
                }
                changes.insert("lead_status".into(), json!(status));
            }
        }
        "opportunity" => {
            if let Some(stage) = stage.filter(|s| !s.is_empty()) {
                changes.insert("stage".into(), json!(stage));
            }
        }
        _ => {}
    }
    if outcome == "wrong_number"
        && state
            .entities
            .load()
            .get(&entity)
            .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == "phone_needs_check"))
    {
        changes.insert("phone_needs_check".into(), json!(true));
    }
    if !changes.is_empty() {
        let version: Option<i64> = sqlx::query_scalar(&format!(
            "SELECT row_version FROM {} WHERE id = $1",
            attome_core::quote_ident(&entity)
        ))
        .bind(record)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        if let Some(version) = version {
            attome_records::entity_crud::update_record_for(
                state,
                &ctx,
                caller,
                &entity,
                record,
                version,
                serde_json::Value::Object(changes),
            )
            .await?;
        }
    }
    if let Some(minutes) = callback.filter(|m| *m > 0) {
        let mark = marker(attempt);
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM activity WHERE description LIKE '%' || $1 || '%')",
        )
        .bind(&mark)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if !exists {
            attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                caller,
                "activity",
                json!({
                    "activity_type": "task",
                    "subject": "Call back",
                    "description": format!("Call back after outcome {outcome} {mark}"),
                    "entity_name": entity,
                    "record_id": record.to_string(),
                    "status": "open",
                    "due_at": (Utc::now() + Duration::minutes(minutes)).date_naive().to_string(),
                }),
            )
            .await?;
        }
    }
    Ok(())
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_sales_call_outcome),
    components(schemas(SalesCallOutcomeBody, SalesCallOutcomeSaved))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disqualifying_outcome_names_a_reason() {
        assert_eq!(disqualify_reason("not_interested"), "no_need");
        assert_eq!(disqualify_reason("wrong_number"), "unreachable");
        assert_eq!(disqualify_reason("connected"), "other");
    }

    #[test]
    fn terminal_outcomes_finish_the_member() {
        assert_eq!(next_status("connected"), "done");
        assert_eq!(next_status("not_interested"), "done");
        assert_eq!(next_status("wrong_number"), "done");
        assert_eq!(next_status("no_answer"), "pending");
        assert_eq!(next_status("call_back_later"), "pending");
    }

    #[test]
    fn the_marker_names_the_attempt() {
        assert_eq!(
            marker(Uuid::nil()),
            "[call attempt 00000000-0000-0000-0000-000000000000]"
        );
    }
}

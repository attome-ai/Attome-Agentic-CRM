//! `meeting.confirm_notes` (roadmap AI6-T5): a person's confirmed meeting
//! notes turned into work.
//!
//! The caller names the draft `ai_meeting_notes` row, the `row_version` they
//! read, and which of its action items and record updates to keep (by
//! index). The notes are marked `confirmed` first, under that row version,
//! so a second confirmation of the same draft is a version conflict and
//! creates nothing twice. Then:
//!
//! - each kept action item becomes an open `activity` task linked to the
//!   meeting (`entity_name = activity`, `record_id` = the meeting), created
//!   through the record engine as the caller, with the owner and due hints
//!   in its description and a due date when the hint is one;
//! - each kept record update is **proposed** through `record.update_field`,
//!   dispatched through the gate as an agent of the caller, so that action's
//!   allow-list, approval policy and daily cap decide whether it applies now,
//!   waits for approval or is refused. Nothing here writes a record field.
//!
//! Each task and each proposed update records an `agent_task` row in the
//! outcome ledger. The action is `Reversible`: tasks can be closed, and the
//! one step that is not reversible by default is `record.update_field`'s to
//! gate.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionOutcome, ActionResult, dispatch};
use crate::meeting::notes::{ActionItem, RecordUpdate};

pub const MEETING_CONFIRM_NOTES: &str = "meeting.confirm_notes";
const OUTCOME_KIND: &str = "agent_task";
/// The longest task subject written.
const SUBJECT_CHARS: usize = 200;

const INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "notes_id": { "type": "string", "format": "uuid", "description": "The draft meeting notes." },
    "row_version": { "type": "integer", "description": "The notes' row_version the caller read." },
    "action_item_indexes": { "type": "array", "items": { "type": "integer", "minimum": 0 }, "description": "Which action items become tasks." },
    "record_update_indexes": { "type": "array", "items": { "type": "integer", "minimum": 0 }, "description": "Which record updates are proposed." }
  },
  "required": ["notes_id", "row_version"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        MEETING_CONFIRM_NOTES,
        "Confirm a meeting's draft notes: the chosen action items become tasks on the \
         meeting, and the chosen record updates are proposed through record.update_field, \
         which applies its own approval and limits.",
        RiskTier::Reversible,
        Effect::Write,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(INPUT)
    .outcome_kind(OUTCOME_KIND)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![descriptor()]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![Box::new(ConfirmNotes)]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmArgs {
    notes_id: Uuid,
    row_version: i64,
    #[serde(default)]
    action_item_indexes: Vec<usize>,
    #[serde(default)]
    record_update_indexes: Vec<usize>,
}

/// The stored items of a notes row (`action_items_json`).
#[derive(Debug, Default, Deserialize)]
struct StoredItems {
    #[serde(default)]
    action_items: Vec<ActionItem>,
    #[serde(default)]
    record_updates: Vec<RecordUpdate>,
}

/// The items at `indexes`, each once, in the order first named. An index
/// past the end is a validation error. Pure.
pub fn pick<T: Clone>(items: &[T], indexes: &[usize], what: &str) -> Result<Vec<T>, AppError> {
    let mut seen = Vec::new();
    for &i in indexes {
        if i >= items.len() {
            return Err(AppError::Validation(format!(
                "{what} {i} does not exist (there are {})",
                items.len()
            )));
        }
        if !seen.contains(&i) {
            seen.push(i);
        }
    }
    Ok(seen.into_iter().map(|i| items[i].clone()).collect())
}

/// A due hint that is a date (`2027-03-04`, or the date part of a time).
/// Pure.
pub fn due_date(hint: Option<&str>) -> Option<chrono::NaiveDate> {
    let hint = hint?.trim();
    chrono::NaiveDate::parse_from_str(hint.get(..10).unwrap_or(hint), "%Y-%m-%d").ok()
}

/// The task an action item becomes. Pure.
pub fn task_body(item: &ActionItem, meeting_id: Uuid) -> Value {
    let subject: String = item.text.trim().chars().take(SUBJECT_CHARS).collect();
    let mut description = format!("From the meeting notes: {}", item.text.trim());
    if let Some(owner) = item.owner_hint.as_deref().filter(|s| !s.trim().is_empty()) {
        description.push_str(&format!("\nOwner named: {}", owner.trim()));
    }
    if let Some(due) = item.due_hint.as_deref().filter(|s| !s.trim().is_empty()) {
        description.push_str(&format!("\nDue named: {}", due.trim()));
    }
    let mut body = json!({
        "subject": subject,
        "activity_type": "task",
        "status": "open",
        "description": description,
        "entity_name": "activity",
        "record_id": meeting_id.to_string(),
    });
    if let Some(due) = due_date(item.due_hint.as_deref()) {
        body["due_at"] = json!(due.format("%Y-%m-%dT00:00:00Z").to_string());
    }
    body
}

/// Records one outcome row; a failure is logged, not returned.
async fn record_outcome(
    state: &EngineState,
    ctx: &ActionContext,
    entity: &str,
    regarding_id: Uuid,
    expected: Option<Value>,
) {
    let proposal = crate::outcome::OutcomeProposal {
        kind: OUTCOME_KIND,
        entity_logicalname: Some(entity),
        regarding_entity: Some(entity),
        regarding_id: Some(regarding_id),
        model_id: None,
        prompt_version: None,
        rule_ref: Some("ai.meeting"),
        proposed_by: Some(ctx.security.user_id),
        organization_ref: None,
        expected_value: expected,
    };
    if let Err(error) = crate::outcome::record_proposed(
        &state.base.db,
        Uuid::now_v7(),
        MEETING_CONFIRM_NOTES,
        &proposal,
        ctx.agent_session_id,
    )
    .await
    {
        tracing::warn!(%error, %regarding_id, "meeting.confirm_notes: outcome not recorded");
    }
}

/// Proposes one record update through `record.update_field`, as an agent
/// of the caller. Answers what became of it.
async fn propose_update(
    state: &EngineState,
    ctx: &ActionContext,
    update: &RecordUpdate,
) -> Result<Value, AppError> {
    let current = attome_records::entity_crud::read_record_bulk(
        state,
        &ctx.security,
        &update.entity,
        update.record_id,
    )
    .await?;
    let mut agent = ActionContext::agent(ctx.security.clone(), RiskTier::Reversible);
    agent.agent_session_id = ctx.agent_session_id;
    let action = super::record_update_field::RECORD_UPDATE_FIELD;
    let module = crate::engine::REGISTRY
        .resolve(action)
        .map(|d| d.module)
        .ok_or(AppError::NotFound)?;
    let inputs = crate::engine::gate_inputs(state, module);
    let args = json!({
        "entity": update.entity,
        "record_id": update.record_id,
        "field": update.attribute,
        "value": update.value,
        "row_version": current.row_version(),
    });
    let outcome = dispatch(
        state,
        &crate::engine::REGISTRY,
        &crate::engine::EXECUTORS,
        action,
        &agent,
        &inputs,
        &args,
    )
    .await?;
    Ok(match outcome {
        ActionOutcome::Completed { .. } => json!({ "outcome": "applied" }),
        ActionOutcome::ApprovalRequired { approval_id } => {
            json!({ "outcome": "awaiting_approval", "approval_id": approval_id })
        }
        ActionOutcome::ConfirmationRequired { .. } => json!({ "outcome": "needs_confirmation" }),
        ActionOutcome::Scheduled {
            deferred_action_id,
            run_at,
        } => json!({
            "outcome": "scheduled",
            "deferred_action_id": deferred_action_id,
            "run_at": run_at,
        }),
        ActionOutcome::AwaitingReview { deferred_action_id } => {
            json!({ "outcome": "awaiting_review", "deferred_action_id": deferred_action_id })
        }
    })
}

struct ConfirmNotes;

impl Action for ConfirmNotes {
    fn id(&self) -> ActionId {
        ActionId(MEETING_CONFIRM_NOTES)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args: ConfirmArgs = serde_json::from_value(args.clone()).map_err(|e| {
                AppError::Validation(format!("invalid meeting.confirm_notes arguments: {e}"))
            })?;
            let security = &ctx.security;
            let notes = attome_records::entity_crud::read_record_bulk(
                state,
                security,
                "ai_meeting_notes",
                args.notes_id,
            )
            .await?;
            let data = notes.data();
            if data.get("status").and_then(Value::as_str) == Some("confirmed") {
                return Err(AppError::Conflict("these notes are already confirmed"));
            }
            let meeting_id = data
                .get("meeting_id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("the notes name no meeting".into()))?;
            let stored: StoredItems = data
                .get("action_items_json")
                .and_then(Value::as_str)
                .map(serde_json::from_str)
                .transpose()
                .map_err(|_| AppError::Validation("the notes' items are not readable".into()))?
                .unwrap_or_default();
            let items = pick(
                &stored.action_items,
                &args.action_item_indexes,
                "action item",
            )?;
            let updates = pick(
                &stored.record_updates,
                &args.record_update_indexes,
                "record update",
            )?;
            if !items.is_empty() {
                security.require("activity", "create")?;
            }

            // Confirmed first, under the version the caller read: a second
            // confirmation conflicts here and creates nothing.
            attome_records::entity_crud::update_record_for(
                state,
                security,
                security.user_id,
                "ai_meeting_notes",
                args.notes_id,
                args.row_version,
                json!({ "status": "confirmed" }),
            )
            .await?;

            let mut tasks = Vec::with_capacity(items.len());
            for item in &items {
                let (task_id, _) = attome_records::entity_crud::create_record_for(
                    state,
                    security,
                    security.user_id,
                    "activity",
                    task_body(item, meeting_id),
                )
                .await?;
                record_outcome(state, ctx, "activity", task_id, None).await;
                tasks.push(task_id);
            }

            let mut proposed = Vec::with_capacity(updates.len());
            for update in &updates {
                let result = match propose_update(state, ctx, update).await {
                    Ok(result) => result,
                    Err(error) => {
                        tracing::debug!(%error, entity = %update.entity, "meeting.confirm_notes: update refused");
                        json!({ "outcome": "refused", "reason": error.to_string() })
                    }
                };
                record_outcome(
                    state,
                    ctx,
                    &update.entity,
                    update.record_id,
                    Some(json!({ "attribute": update.attribute, "value": update.value })),
                )
                .await;
                proposed.push(json!({
                    "entity": update.entity,
                    "record_id": update.record_id,
                    "attribute": update.attribute,
                    "result": result,
                }));
            }

            Ok(ActionResult::plain(json!({
                "notes_id": args.notes_id,
                "status": "confirmed",
                "tasks": tasks,
                "record_updates": proposed,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_notes_is_reversible() {
        let d = descriptor();
        assert_eq!(d.risk, RiskTier::Reversible);
        assert_eq!(d.effect, Effect::Write);
        assert_eq!(d.outcome_kind, Some("agent_task"));
    }

    #[test]
    fn chosen_items_are_taken_once_and_must_exist() {
        let items = vec!["a", "b", "c"];
        assert_eq!(
            pick(&items, &[2, 0, 2], "item").expect("picked"),
            vec!["c", "a"]
        );
        assert!(pick(&items, &[], "item").expect("none").is_empty());
        assert!(pick(&items, &[3], "item").is_err());
    }

    #[test]
    fn a_task_links_to_the_meeting_with_its_hints() {
        let meeting = Uuid::from_u128(9);
        let item = ActionItem {
            text: "  Send the revised quote ".into(),
            owner_hint: Some("Sara".into()),
            due_hint: Some("2027-03-04".into()),
        };
        let body = task_body(&item, meeting);
        assert_eq!(body["subject"], "Send the revised quote");
        assert_eq!(body["activity_type"], "task");
        assert_eq!(body["entity_name"], "activity");
        assert_eq!(body["record_id"], meeting.to_string());
        assert_eq!(body["due_at"], "2027-03-04T00:00:00Z");
        assert!(
            body["description"]
                .as_str()
                .expect("text")
                .contains("Owner named: Sara")
        );
        let vague = ActionItem {
            text: "Call back".into(),
            owner_hint: None,
            due_hint: Some("next week".into()),
        };
        assert!(task_body(&vague, meeting).get("due_at").is_none());
        assert_eq!(
            due_date(Some("2027-05-01T10:00:00Z")),
            chrono::NaiveDate::from_ymd_opt(2027, 5, 1)
        );
    }
}

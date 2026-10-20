//! Dialer actions (roadmap D21-T9). None places a call.
//!
//! - `sales.call_list.build` creates a **draft** call list from a
//!   description (and a saved view, when named) as the acting person; a
//!   person activates and fills it. Reversible, confirmed first.
//! - `sales.call_list.order` reorders a list's waiting members by their
//!   points score (D18) or their deal's risk (D19), highest first; it says
//!   which data is missing rather than inventing an order. Reversible,
//!   confirmed first; the list's own access rules and sharing apply.
//! - `sales.call.draft_notes` drafts notes for a call attempt from the
//!   transcript of its recording (N22) and saves nothing. The draft is
//!   extractive and local: what was said, and the sentences that commit to
//!   a next step; no record text reaches a model.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_SALES;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const SALES_CALL_LIST_BUILD: &str = "sales.call_list.build";
pub const SALES_CALL_LIST_ORDER: &str = "sales.call_list.order";
pub const SALES_CALL_NOTES_DRAFT: &str = "sales.call.draft_notes";

/// Sentences in a drafted summary.
const SUMMARY_SENTENCES: usize = 5;
/// Next steps listed.
const MAX_STEPS: usize = 8;

const BUILD_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "description": { "type": "string", "minLength": 3, "maxLength": 200, "description": "Who to call, in words; becomes the list's name" },
    "view_id": { "type": "string", "format": "uuid", "description": "A saved view whose records fill the list" }
  },
  "required": ["description"],
  "additionalProperties": false
}"#;

const ORDER_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "list_id": { "type": "string", "format": "uuid" },
    "by": { "type": "string", "enum": ["score", "risk"] }
  },
  "required": ["list_id", "by"],
  "additionalProperties": false
}"#;

const NOTES_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "attempt_id": { "type": "string", "format": "uuid" }
  },
  "required": ["attempt_id"],
  "additionalProperties": false
}"#;

fn write(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Reversible,
        Effect::Write,
        RetryClass::RequiresKey,
        MODULE_SALES,
        &[],
    )
    .input_schema(schema)
    .agent_must_confirm()
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        write(
            SALES_CALL_LIST_BUILD,
            "Create a draft call list from a description (and a saved view, when given) for a \
             person to review, fill and activate. Calls nobody.",
            BUILD_SCHEMA,
        ),
        write(
            SALES_CALL_LIST_ORDER,
            "Reorder a call list's waiting members by their points score or their deal's risk, \
             highest first. Calls nobody.",
            ORDER_SCHEMA,
        ),
        ActionDescriptor::new(
            SALES_CALL_NOTES_DRAFT,
            "Draft notes for a call attempt from its recording's transcript: a short summary and \
             the next steps said on the call. Nothing is saved.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_SALES,
            &[],
        )
        .input_schema(NOTES_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Dialer(SALES_CALL_LIST_BUILD)),
        Box::new(Dialer(SALES_CALL_LIST_ORDER)),
        Box::new(Dialer(SALES_CALL_NOTES_DRAFT)),
    ]
}

/// Members' new positions: highest value first, members without a value
/// after them in their current order. Pure.
pub fn reorder(members: &[(Uuid, Option<f64>, f64)]) -> Vec<(Uuid, i64)> {
    let mut sorted: Vec<&(Uuid, Option<f64>, f64)> = members.iter().collect();
    sorted.sort_by(|a, b| match (a.1, b.1) {
        (Some(x), Some(y)) => y.total_cmp(&x).then(a.2.total_cmp(&b.2)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.2.total_cmp(&b.2),
    });
    sorted
        .iter()
        .enumerate()
        .map(|(i, m)| (m.0, i as i64 + 1))
        .collect()
}

/// Words that mark a sentence as a next step, English and Arabic.
const STEP_MARKERS: &[&str] = &[
    "will ",
    "i'll ",
    "we'll ",
    "next step",
    "follow up",
    "follow-up",
    "send you",
    "by monday",
    "by friday",
    "tomorrow",
    "next week",
    "سأرسل",
    "سنرسل",
    "سوف",
    "الأسبوع القادم",
    "غداً",
    "غدا",
    "الخطوة التالية",
    "متابعة",
];

/// A draft from a transcript: the first sentences, and the sentences that
/// commit to a next step. Pure.
pub fn draft_notes(transcript: &str) -> Value {
    let sentences: Vec<String> = transcript
        .split(['.', '!', '?', '؟', '\n'])
        .map(str::trim)
        .filter(|s| s.chars().count() > 3)
        .map(str::to_owned)
        .collect();
    let summary: Vec<&String> = sentences.iter().take(SUMMARY_SENTENCES).collect();
    let steps: Vec<&String> = sentences
        .iter()
        .filter(|s| {
            let lower = s.to_lowercase();
            STEP_MARKERS.iter().any(|m| lower.contains(m))
        })
        .take(MAX_STEPS)
        .collect();
    json!({
        "saved": false,
        "summary": summary,
        "next_steps": steps,
    })
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be an id")))
}

struct Dialer(&'static str);

impl Action for Dialer {
    fn id(&self) -> ActionId {
        ActionId(self.0)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let security = &ctx.security;
            match self.0 {
                SALES_CALL_LIST_BUILD => {
                    security.require("call_list", "create")?;
                    let description = args
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|d| d.chars().count() >= 3)
                        .ok_or_else(|| AppError::Validation("description is required".into()))?;
                    let name: String = description.chars().take(200).collect();
                    let view = match args.get("view_id") {
                        Some(_) => Some(uuid_arg(args, "view_id")?),
                        None => None,
                    };
                    let mut body = json!({
                        "name": name,
                        "status": "draft",
                        "is_shared": false,
                        "source_kind": if view.is_some() { "view" } else { "manual" },
                    });
                    if let Some(view) = view {
                        body["view_ref"] = Value::String(view.to_string());
                    }
                    let (id, _) = attome_records::entity_crud::create_record_for(
                        state,
                        security,
                        security.user_id,
                        "call_list",
                        body,
                    )
                    .await?;
                    Ok(ActionResult::plain(json!({
                        "list_id": id,
                        "status": "draft",
                        "next": "Review the list, fill it from its source and activate it.",
                    })))
                }
                SALES_CALL_LIST_ORDER => {
                    security.require("call_list", "update")?;
                    let list = uuid_arg(args, "list_id")?;
                    let by = args.get("by").and_then(Value::as_str).unwrap_or_default();
                    // Readable, and if shared someone else's, needs the share privilege.
                    attome_records::entity_crud::read_record(state, security, "call_list", list)
                        .await?;
                    attome_sales::dialer::sharing::require_list_use(state, security, list).await?;
                    let members: Vec<(Uuid, String, String, Option<f64>)> = sqlx::query_as(
                        "SELECT id, entity_name, record_id, position::float8 FROM call_list_member \
                          WHERE list_ref = $1 AND member_status = 'pending' \
                            AND (is_active IS NULL OR is_active = true)",
                    )
                    .bind(list)
                    .fetch_all(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    let record_ids: Vec<String> = members.iter().map(|m| m.2.clone()).collect();
                    let values: Vec<(String, f64)> = match by {
                        "score" => sqlx::query_as(
                            "SELECT record_id, max(score)::float8 FROM points_score \
                              WHERE record_id = ANY($1) AND (is_active IS NULL OR is_active = true) \
                              GROUP BY record_id",
                        )
                        .bind(&record_ids)
                        .fetch_all(&state.base.db)
                        .await
                        .map_err(AppError::internal)?,
                        "risk" => sqlx::query_as(
                            "SELECT id::text, risk_score::float8 FROM opportunity \
                              WHERE id::text = ANY($1) AND risk_score IS NOT NULL \
                                AND (is_active IS NULL OR is_active = true)",
                        )
                        .bind(&record_ids)
                        .fetch_all(&state.base.db)
                        .await
                        .map_err(AppError::internal)?,
                        _ => {
                            return Err(AppError::Validation("by is score or risk".into()));
                        }
                    };
                    if values.is_empty() && !members.is_empty() {
                        return Err(AppError::Validation(match by {
                            "score" => "no points scores (D18) for this list's members; set up a scoring model first".into(),
                            _ => "no deal risk (D19) for this list's members; risk is scored nightly for open opportunities".into(),
                        }));
                    }
                    let by_record: std::collections::HashMap<String, f64> =
                        values.into_iter().collect();
                    let keyed: Vec<(Uuid, Option<f64>, f64)> = members
                        .iter()
                        .map(|(id, _, record, position)| {
                            (
                                *id,
                                by_record.get(record).copied(),
                                position.unwrap_or(f64::MAX),
                            )
                        })
                        .collect();
                    let order = reorder(&keyed);
                    let (ids, positions): (Vec<Uuid>, Vec<i64>) = order.iter().copied().unzip();
                    sqlx::query(
                        "UPDATE call_list_member m SET position = u.position, modified_at = now(), \
                            row_version = m.row_version + 1 \
                           FROM UNNEST($1::uuid[], $2::int8[]) AS u(id, position) \
                          WHERE m.id = u.id AND m.list_ref = $3 AND m.member_status = 'pending'",
                    )
                    .bind(&ids)
                    .bind(&positions)
                    .bind(list)
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    Ok(ActionResult::plain(json!({
                        "list_id": list,
                        "by": by,
                        "reordered": ids.len(),
                    })))
                }
                SALES_CALL_NOTES_DRAFT => {
                    security.require("call_attempt", "read")?;
                    let attempt = uuid_arg(args, "attempt_id")?;
                    let read = attome_records::entity_crud::read_record(
                        state,
                        security,
                        "call_attempt",
                        attempt,
                    )
                    .await?;
                    let activity = read
                        .data()
                        .get("activity_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            AppError::Validation("the attempt has no call activity".into())
                        })?;
                    // The recording is a document on the activity; its
                    // transcript is read only when the document is.
                    let found: Option<(Uuid, String)> = sqlx::query_as(
                        "SELECT d.id, t.content_text FROM attome_document d \
                           JOIN recording_transcript t ON t.file_key = d.file \
                          WHERE d.entity_name = 'activity' AND d.record_id = $1 \
                            AND (d.is_active IS NULL OR d.is_active = true) \
                          ORDER BY t.transcribed_at DESC LIMIT 1",
                    )
                    .bind(&activity)
                    .fetch_optional(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                    let (document, text) = found.ok_or_else(|| {
                        AppError::Validation("the call has no transcribed recording yet".into())
                    })?;
                    attome_records::entity_crud::read_record(
                        state,
                        security,
                        "attome_document",
                        document,
                    )
                    .await?;
                    let mut draft = draft_notes(&text);
                    draft["attempt_id"] = Value::String(attempt.to_string());
                    Ok(ActionResult::plain(draft))
                }
                _ => Err(AppError::NotFound),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_are_confirmed_and_nothing_dials() {
        for d in descriptors() {
            assert_eq!(d.module, MODULE_SALES, "{}", d.id.0);
            assert_ne!(d.risk, RiskTier::Consequential, "{}", d.id.0);
            assert!(
                !d.id.0.contains("dial") && !d.id.0.ends_with(".call"),
                "{}",
                d.id.0
            );
        }
        assert_eq!(executors().len(), descriptors().len());
    }

    #[test]
    fn reorder_puts_highest_first_and_unknown_last() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        let order = reorder(&[(a, Some(10.0), 1.0), (b, None, 2.0), (c, Some(80.0), 3.0)]);
        assert_eq!(order, vec![(c, 1), (a, 2), (b, 3)]);
    }

    #[test]
    fn notes_draft_lists_next_steps() {
        let draft = draft_notes(
            "Thanks for taking the call. We discussed the renewal. I'll send you the proposal \
             tomorrow. Pricing is fine. سأرسل العرض الأسبوع القادم.",
        );
        assert_eq!(draft["saved"], false);
        let steps = draft["next_steps"].as_array().unwrap();
        assert_eq!(steps.len(), 2);
        assert!(steps[0].as_str().unwrap().contains("proposal"));
    }
}

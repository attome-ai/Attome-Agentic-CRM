//! Z10-T11: agents read approvals and recommend, never decide.
//!
//! - `approvals.list` — the pending requests the session's person may decide
//!   now (the My Work approvals provider: eligibility with delegation, and a
//!   readable regarding record).
//! - `approvals.get` — one request, for its requester or an eligible
//!   approver.
//! - `approvals.recommend` — stores a recommendation (approve or reject,
//!   with reasons) for the person to see; it decides nothing.
//!
//! There is no decide action, and the decide routes refuse an agent on a
//! step that asks for a person (`attome_audit::approval::agent_blocked_from`).

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_CORE;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const APPROVALS_LIST: &str = "approvals.list";
pub const APPROVALS_GET: &str = "approvals.get";
pub const APPROVALS_RECOMMEND: &str = "approvals.recommend";

/// Requests listed at most.
const LIST_LIMIT: usize = 50;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            APPROVALS_LIST,
            "List the approval requests waiting for the person's decision now (their step names \
             them, or they stand in for someone it names), newest first, with each request's id, \
             action, due date and row_version.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(r#"{"type": "object", "properties": {}, "additionalProperties": false}"#),
        ActionDescriptor::new(
            APPROVALS_GET,
            "Read one approval request (its action, payload, status, step and the recommendations \
             made so far) when the person submitted it or may decide it.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{"type": "object", "required": ["id"], "properties": {"id": {"type": "string", "format": "uuid"}}, "additionalProperties": false}"#,
        ),
        ActionDescriptor::new(
            APPROVALS_RECOMMEND,
            "Recommend approving or rejecting a pending approval request the person may decide, \
             with the reasons. It decides nothing: the person still decides.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_CORE,
            &[],
        )
        .input_schema(
            r#"{"type": "object", "required": ["id", "recommended", "reasons"], "properties": {"id": {"type": "string", "format": "uuid"}, "recommended": {"enum": ["approve", "reject"]}, "reasons": {"type": "string", "minLength": 1, "maxLength": 2000}}, "additionalProperties": false}"#,
        ),
    ]
}

pub fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(ApprovalsList),
        Box::new(ApprovalsGet),
        Box::new(ApprovalsRecommend),
    ]
}

fn request_id(args: &Value) -> Result<Uuid, AppError> {
    args["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("id is an approval request id".into()))
}

/// Whether the person may decide `id` now, through the approvals provider.
async fn may_decide(state: &EngineState, ctx: &ActionContext, id: Uuid) -> Result<bool, AppError> {
    let Some(provider) = state
        .my_work_providers
        .iter()
        .find(|p| p.name() == "approvals")
    else {
        return Ok(false);
    };
    Ok(!provider.actions(state, &ctx.security, id).await?.is_empty())
}

pub(crate) struct ApprovalsList;

impl Action for ApprovalsList {
    fn id(&self) -> ActionId {
        ActionId(APPROVALS_LIST)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let Some(provider) = state
                .my_work_providers
                .iter()
                .find(|p| p.name() == "approvals")
            else {
                return Ok(ActionResult::plain(json!({ "requests": [] })));
            };
            let page = provider
                .list(state, &ctx.security, None, LIST_LIMIT)
                .await?;
            let requests: Vec<Value> = page
                .0
                .items
                .iter()
                .map(|item| {
                    json!({
                        "id": item.record_id,
                        "title": item.title,
                        "due_date": item.due_date,
                        "row_version": item.row_version,
                    })
                })
                .collect();
            Ok(ActionResult::plain(json!({ "requests": requests })))
        })
    }
}

pub(crate) struct ApprovalsGet;

impl Action for ApprovalsGet {
    fn id(&self) -> ActionId {
        ActionId(APPROVALS_GET)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = request_id(args)?;
            let request = attome_approval::get(&state.base.db, id).await?;
            if request.requested_by != ctx.security.user_id && !may_decide(state, ctx, id).await? {
                return Err(AppError::NotFound);
            }
            let recommendations = attome_audit::approval::recommendations(state, id).await?;
            Ok(ActionResult::plain(json!({
                "id": request.id,
                "action_type": request.action_type,
                "status": request.status.to_string(),
                "step": request.step,
                "row_version": request.row_version,
                "payload": request.payload,
                "recommendations": recommendations,
            })))
        })
    }
}

pub(crate) struct ApprovalsRecommend;

impl Action for ApprovalsRecommend {
    fn id(&self) -> ActionId {
        ActionId(APPROVALS_RECOMMEND)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = request_id(args)?;
            let recommended = args["recommended"].as_str().unwrap_or_default();
            let reasons = args["reasons"].as_str().unwrap_or_default();
            attome_audit::approval::check_recommendation(recommended, reasons)?;
            if !may_decide(state, ctx, id).await? {
                return Err(AppError::Forbidden);
            }
            let row = attome_audit::approval::record_recommendation(
                state,
                id,
                ctx.security.user_id,
                recommended,
                reasons,
            )
            .await?;
            Ok(ActionResult::plain(json!({
                "recommendation_id": row.id,
                "recommended": row.recommended,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_decide_tool_is_listed() {
        let ids: Vec<&str> = descriptors().iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, [APPROVALS_LIST, APPROVALS_GET, APPROVALS_RECOMMEND]);
        assert!(!ids.iter().any(|id| id.contains("decide")));
        assert_eq!(executors().len(), descriptors().len());
        let recommend = &descriptors()[2];
        assert_eq!(recommend.risk, RiskTier::Reversible);
        assert!(descriptors()[..2].iter().all(|d| d.risk == RiskTier::Read));
    }

    #[test]
    fn a_request_id_must_be_a_uuid() {
        assert!(request_id(&json!({"id": "nope"})).is_err());
        let id = Uuid::now_v7();
        assert_eq!(request_id(&json!({"id": id.to_string()})).unwrap(), id);
    }
}

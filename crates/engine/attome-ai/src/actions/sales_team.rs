//! Deal team and split actions (roadmap D7-T8).
//!
//! `sales.team.add`, `sales.team.remove` and `sales.splits.propose` call the
//! same functions as the team and split routes (`attome_sales::team`,
//! `attome_sales::split_store`), as the calling user: the member's share,
//! the lock, the rules and, on a won deal, the approval all apply exactly as
//! in the interface. Each is a write an agent must have confirmed. A member
//! is never given more access than their own roles hold, and never more
//! than the calling user could give. `sales.team.suggest` lists people who
//! were on won deals with the same account, as a draft; it writes nothing.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_SALES;
use attome_security::{RecordAction, SecurityContextExt};
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const TEAM_ADD: &str = "sales.team.add";
pub const TEAM_REMOVE: &str = "sales.team.remove";
pub const SPLITS_PROPOSE: &str = "sales.splits.propose";
pub const TEAM_SUGGEST: &str = "sales.team.suggest";

const TEAM_ADD_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "opportunity_id": { "type": "string", "format": "uuid" },
    "user_ref": { "type": "string", "format": "uuid", "description": "The user to add." },
    "team_role_ref": { "type": "string", "format": "uuid", "description": "A sales_team_role." },
    "access_level": { "type": "string", "enum": ["read", "edit"] }
  },
  "required": ["opportunity_id", "user_ref", "team_role_ref", "access_level"],
  "additionalProperties": false
}"#;

const TEAM_REMOVE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "opportunity_id": { "type": "string", "format": "uuid" },
    "member_id": { "type": "string", "format": "uuid", "description": "The opportunity_team_member." }
  },
  "required": ["opportunity_id", "member_id"],
  "additionalProperties": false
}"#;

const SPLITS_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "opportunity_id": { "type": "string", "format": "uuid" },
    "splits": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "member_id": { "type": "string", "format": "uuid" },
          "split_type_id": { "type": "string", "format": "uuid" },
          "line_id": { "type": "string", "format": "uuid" },
          "percent": { "type": "string", "description": "Decimal text; a revenue type totals 100." }
        },
        "required": ["member_id", "split_type_id", "percent"]
      }
    },
    "change_reason": { "type": "string", "description": "Required on a won deal." }
  },
  "required": ["opportunity_id", "splits"],
  "additionalProperties": false
}"#;

const SUGGEST_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "opportunity_id": { "type": "string", "format": "uuid" } },
  "required": ["opportunity_id"],
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
            TEAM_ADD,
            "Add a user to a deal's team with read or edit access to the deal. Refused when \
             the user's own roles do not allow that access.",
            TEAM_ADD_SCHEMA,
        ),
        write(
            TEAM_REMOVE,
            "Remove a member from a deal's team, and their access with them. The owner \
             cannot be removed.",
            TEAM_REMOVE_SCHEMA,
        ),
        write(
            SPLITS_PROPOSE,
            "Set a deal's splits among its team. A revenue split type must total 100%. On a \
             won deal this opens an approval with your reason instead of changing anything.",
            SPLITS_SCHEMA,
        ),
        ActionDescriptor::new(
            TEAM_SUGGEST,
            "Suggest people for a deal's team: those who were on won deals with the same \
             account. A draft list only; nobody is added.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_SALES,
            &[],
        )
        .input_schema(SUGGEST_SCHEMA),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(TeamAdd),
        Box::new(TeamRemove),
        Box::new(SplitsPropose),
        Box::new(TeamSuggest),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

struct TeamAdd;

impl Action for TeamAdd {
    fn id(&self) -> ActionId {
        ActionId(TEAM_ADD)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security.require("opportunity", "update")?;
            let opportunity = uuid_arg(args, "opportunity_id")?;
            let body: attome_sales::team::SalesTeamMemberBody =
                serde_json::from_value(args.clone())
                    .map_err(|e| AppError::Validation(format!("bad member: {e}")))?;
            let (_, member) =
                attome_sales::team::add_member(state, &ctx.security, opportunity, body).await?;
            Ok(ActionResult::plain(
                serde_json::to_value(member.0).map_err(AppError::internal)?,
            ))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(
            json!({ "action": TEAM_ADD, "opportunity_id": args["opportunity_id"],
                     "user_ref": args["user_ref"], "access_level": args["access_level"] }),
        )
    }
}

struct TeamRemove;

impl Action for TeamRemove {
    fn id(&self) -> ActionId {
        ActionId(TEAM_REMOVE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security.require("opportunity", "update")?;
            let opportunity = uuid_arg(args, "opportunity_id")?;
            let member = uuid_arg(args, "member_id")?;
            attome_sales::team::remove_member(state, &ctx.security, opportunity, member).await?;
            Ok(ActionResult::plain(
                json!({ "removed": member, "opportunity_id": opportunity }),
            ))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(
            json!({ "action": TEAM_REMOVE, "opportunity_id": args["opportunity_id"],
                     "member_id": args["member_id"] }),
        )
    }
}

struct SplitsPropose;

impl Action for SplitsPropose {
    fn id(&self) -> ActionId {
        ActionId(SPLITS_PROPOSE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security.require("opportunity", "update")?;
            let opportunity = uuid_arg(args, "opportunity_id")?;
            let body: attome_sales::split_store::SalesSplitsBody =
                serde_json::from_value(args.clone())
                    .map_err(|e| AppError::Validation(format!("bad splits: {e}")))?;
            let (_, outcome) =
                attome_sales::split_store::replace_splits(state, &ctx.security, opportunity, body)
                    .await?;
            Ok(ActionResult::plain(
                serde_json::to_value(outcome.0).map_err(AppError::internal)?,
            ))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        Some(
            json!({ "action": SPLITS_PROPOSE, "opportunity_id": args["opportunity_id"],
                     "splits": args["splits"], "change_reason": args["change_reason"] }),
        )
    }
}

struct TeamSuggest;

impl Action for TeamSuggest {
    fn id(&self) -> ActionId {
        ActionId(TEAM_SUGGEST)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let opportunity = uuid_arg(args, "opportunity_id")?;
            let entity = state
                .entities
                .load()
                .get("opportunity")
                .map(|m| m.entity_id)
                .ok_or(AppError::NotFound)?;
            attome_records::entity_crud::require_record_access(
                state,
                &ctx.security,
                entity,
                "opportunity",
                opportunity,
                RecordAction::Read,
            )
            .await?;
            let rows: Vec<(Uuid, i64)> = sqlx::query_as(
                "SELECT m.user_ref, COUNT(DISTINCT o.id) AS deals \
                 FROM opportunity_team_member m \
                 JOIN opportunity o ON o.id = m.opportunity_ref \
                 JOIN opportunity me ON me.id = $1 \
                 WHERE o.account_ref = me.account_ref AND o.id <> me.id \
                   AND o.stage = 'closed_won' AND m.user_ref IS NOT NULL \
                   AND (m.is_active IS NULL OR m.is_active = true) \
                   AND NOT EXISTS (SELECT 1 FROM opportunity_team_member x \
                       WHERE x.opportunity_ref = me.id AND x.user_ref = m.user_ref \
                         AND (x.is_active IS NULL OR x.is_active = true)) \
                 GROUP BY m.user_ref ORDER BY deals DESC LIMIT 10",
            )
            .bind(opportunity)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(ActionResult::plain(json!({
                "draft": true,
                "detail": "Suggestions only; nobody was added.",
                "people": rows.into_iter().map(|(user, deals)| json!({
                    "user_ref": user,
                    "won_deals_with_this_account": deals,
                })).collect::<Vec<_>>(),
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn team_writes_need_confirmation_and_suggest_is_read_only() {
        let all = descriptors();
        for id in [TEAM_ADD, TEAM_REMOVE, SPLITS_PROPOSE] {
            assert!(
                all.iter().any(|d| d.id.as_str() == id
                    && d.effect == Effect::Write
                    && d.agent_must_confirm),
                "{id} is a confirmed write"
            );
        }
        assert!(
            all.iter()
                .any(|d| d.id.as_str() == TEAM_SUGGEST && d.effect == Effect::Read)
        );
        for schema in [
            TEAM_ADD_SCHEMA,
            TEAM_REMOVE_SCHEMA,
            SPLITS_SCHEMA,
            SUGGEST_SCHEMA,
        ] {
            assert!(serde_json::from_str::<Value>(schema).is_ok());
        }
    }
}

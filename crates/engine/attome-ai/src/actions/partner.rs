//! Partner actions (roadmap F9-T10). All three read only: no action approves a
//! registration, a tier change or an MDF claim, and a person decides each.
//!
//! - `partner.draft_registration` shapes what the model read from an email into
//!   a `deal_registration` body and writes nothing.
//! - `partner.flag_registration_conflicts` reads a registration the caller may
//!   read, through the same read as `record.get`, and lists its conflicts.
//! - `partner.suggest_partner_for_lead` ranks partners from their latest
//!   performance snapshot, by win rate and then won revenue. Nothing records a
//!   partner's territories or products, so neither ranks yet.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_PARTNER;
use attome_partner::registration::{Registration, find_conflicts};
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const DRAFT_REGISTRATION: &str = "partner.draft_registration";
pub const FLAG_CONFLICTS: &str = "partner.flag_registration_conflicts";
pub const SUGGEST_PARTNER: &str = "partner.suggest_partner_for_lead";

/// Partners one suggestion lists.
const SUGGESTIONS: i64 = 5;

const DRAFT_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "customer_name": { "type": "string", "description": "The customer the partner is registering." },
    "amount": { "type": "number", "description": "The expected value of the deal." },
    "expected_close": { "type": "string", "format": "date", "description": "When the deal should close." },
    "source": { "type": "string", "description": "Where the details came from, such as the email's subject." }
  },
  "required": ["customer_name"],
  "additionalProperties": false
}"#;

const CONFLICTS_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "registration_id": { "type": "string", "format": "uuid", "description": "The deal_registration to check." }
  },
  "required": ["registration_id"],
  "additionalProperties": false
}"#;

const SUGGEST_INPUT: &str = r#"{
  "type": "object",
  "properties": {},
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            DRAFT_REGISTRATION,
            "Draft a deal registration from what an email says: give the customer and \
             the deal, and get back a deal_registration body to review. Writes nothing; \
             a person submits it.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_PARTNER,
            &[],
        )
        .input_schema(DRAFT_INPUT),
        ActionDescriptor::new(
            FLAG_CONFLICTS,
            "List what conflicts with a deal registration you may read: open \
             opportunities on the customer, and other partners' live registrations. \
             Decides nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_PARTNER,
            &[],
        )
        .input_schema(CONFLICTS_INPUT),
        ActionDescriptor::new(
            SUGGEST_PARTNER,
            "Suggest partners for a lead: the best by win rate, then won revenue, from \
             their latest performance snapshot. Offers the lead to nobody.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_PARTNER,
            &[],
        )
        .input_schema(SUGGEST_INPUT),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(DraftRegistration),
        Box::new(FlagConflicts),
        Box::new(SuggestPartner),
    ]
}

/// The proposed `deal_registration` body. Pure, so it can write nothing.
pub fn draft(args: &Value) -> Result<Value, AppError> {
    let customer = args["customer_name"]
        .as_str()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| AppError::Validation("customer_name is required".into()))?;
    Ok(json!({
        "draft": {
            "customer_name": customer,
            "amount": args.get("amount").cloned().unwrap_or(Value::Null),
            "expected_close": args.get("expected_close").cloned().unwrap_or(Value::Null),
        },
        "source": args.get("source").cloned().unwrap_or(Value::Null),
        "written": false,
    }))
}

struct DraftRegistration;

impl Action for DraftRegistration {
    fn id(&self) -> ActionId {
        ActionId(DRAFT_REGISTRATION)
    }

    fn execute<'a>(
        &'a self,
        _state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move { Ok(ActionResult::plain(draft(args)?)) })
    }
}

struct FlagConflicts;

impl Action for FlagConflicts {
    fn id(&self) -> ActionId {
        ActionId(FLAG_CONFLICTS)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let id = args["registration_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("registration_id must be a UUID".into()))?;
            if let Some(admission) = crate::mcp::admission::ReadAdmission::for_caller(state, ctx)?
                && !admission.admits("deal_registration")
            {
                return Err(AppError::NotFound);
            }
            let record = attome_records::entity_crud::read_record_bulk(
                state,
                &ctx.security,
                "deal_registration",
                id,
            )
            .await?;
            let value = serde_json::to_value(record)
                .map_err(|e| AppError::internal(format!("record serialization failed: {e}")))?;
            let mut row = value["data"].clone();
            row["id"] = json!(id);
            let registration = Registration::from_row(&row).ok_or(AppError::NotFound)?;
            let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
            let conflicts = find_conflicts(&mut conn, &registration).await?;
            Ok(ActionResult::plain(
                json!({ "registration_id": id, "conflicts": conflicts }),
            ))
        })
    }
}

struct SuggestPartner;

impl Action for SuggestPartner {
    fn id(&self) -> ActionId {
        ActionId(SUGGEST_PARTNER)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        _args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            ctx.security
                .require("partner_performance_snapshot", "read")?;
            let rows: Vec<(Uuid, Option<f64>, Option<f64>)> = sqlx::query_as(
                "SELECT partner_account_ref, win_rate::float8, won_revenue::float8 FROM ( \
                     SELECT DISTINCT ON (partner_account_ref) partner_account_ref, win_rate, \
                            won_revenue \
                       FROM partner_performance_snapshot \
                      ORDER BY partner_account_ref, as_of DESC) latest \
                  ORDER BY win_rate DESC NULLS LAST, won_revenue DESC NULLS LAST \
                  LIMIT $1",
            )
            .bind(SUGGESTIONS)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let partners: Vec<Value> = rows
                .into_iter()
                .map(|(partner, win_rate, won_revenue)| {
                    json!({ "partner_id": partner, "win_rate": win_rate, "won_revenue": won_revenue })
                })
                .collect();
            Ok(ActionResult::plain(json!({ "partners": partners })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_registration_writes_nothing() {
        let answer = draft(&json!({ "customer_name": " Acme ", "amount": 500 })).unwrap();
        assert_eq!(answer["written"], false);
        assert_eq!(answer["draft"]["customer_name"], "Acme");
        assert!(draft(&json!({ "customer_name": "  " })).is_err());
    }

    #[test]
    fn no_action_can_approve_registration() {
        for descriptor in descriptors() {
            assert_eq!(descriptor.effect, Effect::Read, "{}", descriptor.id.0);
            assert_eq!(descriptor.risk, RiskTier::Read, "{}", descriptor.id.0);
            for word in ["approve", "confirm", "reject", "decide"] {
                assert!(!descriptor.id.0.contains(word), "{}", descriptor.id.0);
            }
        }
    }
}

//! Payment actions (roadmap F5-T13).
//!
//! - `billing.payment.lookup` finds payments the caller may read, by
//!   account, status or reference.
//! - `billing.payment_link.create` makes a payment link for an open invoice:
//!   it sends nothing and moves no money, but a link is something a person
//!   hands to a customer, so the agent must confirm it and it is
//!   consequential.
//!
//! An account's balance is the F4-T14 action `billing.account_balance`.
//! Refunds, saved payment methods, write-offs and credit limits stay with
//! people: no action here touches them, and
//! `billing_payment_no_refund_tool` holds that.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_BILLING;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const PAYMENT_LOOKUP: &str = "billing.payment.lookup";
pub const PAYMENT_LINK_CREATE: &str = "billing.payment_link.create";

const LOOKUP_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "account_id": { "type": "string", "format": "uuid" },
    "status": { "type": "string", "enum": ["pending", "succeeded", "failed", "refunded", "partially_refunded", "disputed", "reversed"] },
    "reference": { "type": "string", "description": "A bank or cheque reference, or its start" },
    "limit": { "type": "integer", "minimum": 1, "maximum": 50 }
  },
  "additionalProperties": false
}"#;

const LINK_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "invoice_id": { "type": "string", "format": "uuid", "description": "An issued invoice with an open amount." },
    "expires_in_hours": { "type": "integer", "minimum": 1, "maximum": 720 }
  },
  "required": ["invoice_id"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            PAYMENT_LOOKUP,
            "Find payments you may read, newest first, by account, status or reference: amount, \
             currency, method, status, the day received and the credit left unallocated.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_BILLING,
            &[],
        )
        .input_schema(LOOKUP_SCHEMA),
        ActionDescriptor::new(
            PAYMENT_LINK_CREATE,
            "Create a payment link for an issued invoice's open amount, valid 72 hours unless \
             you say otherwise. It sends nothing: give the link to the person who asked.",
            RiskTier::Consequential,
            Effect::Write,
            // A replayed call would make a second link.
            RetryClass::RequiresKey,
            MODULE_BILLING,
            &[],
        )
        .input_schema(LINK_SCHEMA)
        .agent_must_confirm(),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(BillingPayment(PAYMENT_LOOKUP)),
        Box::new(BillingPayment(PAYMENT_LINK_CREATE)),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Option<Uuid>, AppError> {
    args[key]
        .as_str()
        .map(|s| {
            Uuid::parse_str(s).map_err(|_| AppError::Validation(format!("{key} must be a UUID")))
        })
        .transpose()
}

struct BillingPayment(&'static str);

impl Action for BillingPayment {
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
                PAYMENT_LOOKUP => {
                    let filter = attome_billing::lookup::PaymentFilter {
                        account_id: uuid_arg(args, "account_id")?,
                        status: args["status"].as_str().map(str::to_owned),
                        reference: args["reference"].as_str().map(str::to_owned),
                        limit: args["limit"].as_i64(),
                    };
                    let found =
                        attome_billing::lookup::find_payments(state, security, &filter).await?;
                    Ok(ActionResult::plain(
                        serde_json::to_value(found).map_err(AppError::internal)?,
                    ))
                }
                PAYMENT_LINK_CREATE => {
                    let invoice = uuid_arg(args, "invoice_id")?
                        .ok_or_else(|| AppError::Validation("invoice_id is required".into()))?;
                    let request = attome_billing::payment::link::LinkRequest {
                        invoice_id: Some(invoice),
                        expires_in_hours: args["expires_in_hours"]
                            .as_u64()
                            .and_then(|h| u32::try_from(h).ok()),
                        ..Default::default()
                    };
                    let link =
                        attome_billing::payment::link::create_link(state, security, &request)
                            .await?;
                    Ok(ActionResult::plain(json!({
                        "link_id": link.link_id,
                        "url": link.url,
                        "expires_at": link.expires_at,
                    })))
                }
                other => Err(AppError::internal(format!(
                    "billing payment action {other} has no executor"
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_payment_tools_registered() {
        let all: Vec<&str> = crate::actions::all().iter().map(|d| d.id.0).collect();
        for id in [
            PAYMENT_LOOKUP,
            PAYMENT_LINK_CREATE,
            "billing.account_balance",
        ] {
            assert!(all.contains(&id), "{id} is not registered");
        }
        let executors: Vec<&str> = crate::actions::all_executors()
            .iter()
            .map(|e| e.id().0)
            .collect();
        assert!(executors.contains(&PAYMENT_LOOKUP));
        assert!(executors.contains(&PAYMENT_LINK_CREATE));
        let link = descriptors()
            .into_iter()
            .find(|d| d.id.0 == PAYMENT_LINK_CREATE)
            .unwrap();
        assert_eq!(link.risk, RiskTier::Consequential);
        assert!(link.agent_must_confirm);
    }

    #[test]
    fn billing_payment_no_refund_tool() {
        for descriptor in crate::actions::all() {
            let id = descriptor.id.0;
            if !id.starts_with("billing.") {
                continue;
            }
            for word in ["refund", "method", "write_off", "credit_limit"] {
                assert!(!id.contains(word), "{id} reaches what stays with people");
            }
        }
    }
}

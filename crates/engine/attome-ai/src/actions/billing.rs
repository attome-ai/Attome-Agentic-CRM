//! Billing actions (roadmap F4-T14).
//!
//! - `billing.find_invoices` finds invoices the caller may read, by account,
//!   status, payment status or number.
//! - `billing.account_balance` gives what an account owes, per currency.
//! - `billing.explain_tax` says why a line carries its tax: the facts the tax
//!   engine decided on and its decision, in Arabic and English. The numbers
//!   come from the engine, never from a model.
//! - `billing.draft_invoice` and `billing.draft_credit_note` file DRAFTS for
//!   a person to check: an invoice with the lines the agent wrote, or a
//!   credit note for chosen lines of an issued invoice.
//!
//! Issuing, cancelling, crediting for real (issuing a credit note) and
//! writing off stay with people: no action here calls
//! `attome_billing::issue`, `notes::cancel` or `writeoff`, and
//! `billing_actions_cannot_issue` holds that.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_BILLING;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use rust_decimal::Decimal;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const FIND_INVOICES: &str = "billing.find_invoices";
pub const ACCOUNT_BALANCE: &str = "billing.account_balance";
pub const EXPLAIN_TAX: &str = "billing.explain_tax";
pub const DRAFT_INVOICE: &str = "billing.draft_invoice";
pub const DRAFT_CREDIT_NOTE: &str = "billing.draft_credit_note";

/// Most lines one drafted invoice carries.
const MAX_LINES: usize = 100;

const FIND_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "account_id": { "type": "string", "format": "uuid" },
    "status": { "type": "string", "enum": ["draft", "issued", "sent", "paid", "overdue", "void"] },
    "payment_status": { "type": "string", "enum": ["open", "partly_paid", "paid", "overdue", "written_off"] },
    "number": { "type": "string", "description": "An invoice number or its start, e.g. INV-2026-" },
    "limit": { "type": "integer", "minimum": 1, "maximum": 50 }
  },
  "additionalProperties": false
}"#;

const ACCOUNT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "account_id": { "type": "string", "format": "uuid" } },
  "required": ["account_id"],
  "additionalProperties": false
}"#;

const LINE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": { "line_id": { "type": "string", "format": "uuid" } },
  "required": ["line_id"],
  "additionalProperties": false
}"#;

const DRAFT_INVOICE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "account_id": { "type": "string", "format": "uuid" },
    "currency": { "type": "string", "description": "ISO 4217, e.g. SAR" },
    "lines": {
      "type": "array", "minItems": 1, "maxItems": 100,
      "items": {
        "type": "object",
        "properties": {
          "description": { "type": "string" },
          "quantity": { "type": "number" },
          "unit_price": { "type": "number" },
          "vat_category": { "type": "string", "enum": ["standard", "reduced", "zero_rated", "exempt", "out_of_scope"] }
        },
        "required": ["description", "quantity", "unit_price"],
        "additionalProperties": false
      }
    }
  },
  "required": ["account_id", "currency", "lines"],
  "additionalProperties": false
}"#;

const DRAFT_CREDIT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "invoice_id": { "type": "string", "format": "uuid", "description": "The issued invoice to credit." },
    "reason": { "type": "string" },
    "lines": {
      "type": "array", "minItems": 1,
      "items": {
        "type": "object",
        "properties": {
          "line_id": { "type": "string", "format": "uuid" },
          "quantity": { "type": "number", "exclusiveMinimum": 0 }
        },
        "required": ["line_id", "quantity"],
        "additionalProperties": false
      }
    }
  },
  "required": ["invoice_id", "reason", "lines"],
  "additionalProperties": false
}"#;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_BILLING,
        &[],
    )
    .input_schema(schema)
}

fn draft(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Reversible,
        Effect::Write,
        // A replayed call would file a second draft.
        RetryClass::RequiresKey,
        MODULE_BILLING,
        &[],
    )
    .input_schema(schema)
    .agent_must_confirm()
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            FIND_INVOICES,
            "Find invoices you may read, newest first, by account, status, payment status or \
             number: number, kind, dates, grand and open totals.",
            FIND_SCHEMA,
        ),
        read(
            ACCOUNT_BALANCE,
            "What an account owes today, per currency (issued documents less payments and \
             write-offs).",
            ACCOUNT_SCHEMA,
        ),
        read(
            EXPLAIN_TAX,
            "Explain an invoice line's VAT: category, seller and buyer, the date the rate is \
             taken on, the rate, reverse charge and the exemption reason in Arabic and English. \
             Quote these facts; do not compute tax yourself.",
            LINE_SCHEMA,
        ),
        draft(
            DRAFT_INVOICE,
            "File a DRAFT invoice to an account with the lines you were given; it is priced \
             with VAT. Nothing is issued: a person checks and issues it.",
            DRAFT_INVOICE_SCHEMA,
        ),
        draft(
            DRAFT_CREDIT_NOTE,
            "File a DRAFT credit note for chosen lines of an issued invoice, with the reason. \
             Nothing is issued: a person checks and issues it.",
            DRAFT_CREDIT_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Billing(FIND_INVOICES)),
        Box::new(Billing(ACCOUNT_BALANCE)),
        Box::new(Billing(EXPLAIN_TAX)),
        Box::new(Billing(DRAFT_INVOICE)),
        Box::new(Billing(DRAFT_CREDIT_NOTE)),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

fn decimal_arg(value: &Value, key: &str) -> Result<Decimal, AppError> {
    value[key]
        .as_number()
        .and_then(|n| n.to_string().parse::<Decimal>().ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a number")))
}

fn plain(value: impl serde::Serialize) -> Result<ActionResult, AppError> {
    Ok(ActionResult::plain(
        serde_json::to_value(value).map_err(AppError::internal)?,
    ))
}

/// The draft invoice's header and lines, checked; a draft is always a draft
/// invoice whatever the arguments say.
/// A record's field values.
type Fields = Map<String, Value>;

fn invoice_values(args: &Value) -> Result<(Fields, Vec<Fields>), AppError> {
    let account = uuid_arg(args, "account_id")?;
    let currency = args["currency"]
        .as_str()
        .map(str::trim)
        .filter(|c| c.len() == 3 && c.chars().all(|ch| ch.is_ascii_uppercase()))
        .ok_or_else(|| AppError::Validation("currency is a three-letter ISO code".into()))?;
    let lines = args["lines"]
        .as_array()
        .filter(|l| !l.is_empty() && l.len() <= MAX_LINES)
        .ok_or_else(|| AppError::Validation(format!("between 1 and {MAX_LINES} lines")))?;
    let mut header = Map::new();
    header.insert("kind".into(), json!("invoice"));
    header.insert("status".into(), json!("draft"));
    header.insert("account_ref".into(), json!(account));
    header.insert("currency".into(), json!(currency));
    let mut bodies = Vec::with_capacity(lines.len());
    for line in lines {
        let description = line["description"]
            .as_str()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .ok_or_else(|| AppError::Validation("each line needs a description".into()))?;
        let quantity = decimal_arg(line, "quantity")?;
        let price = decimal_arg(line, "unit_price")?;
        if quantity <= Decimal::ZERO || price < Decimal::ZERO {
            return Err(AppError::Validation(
                "a line has a positive quantity and a price of zero or more".into(),
            ));
        }
        let mut body = Map::new();
        body.insert("description".into(), json!(description));
        body.insert("quantity".into(), line["quantity"].clone());
        body.insert("unit_price".into(), line["unit_price"].clone());
        body.insert(
            "vat_category".into(),
            json!(line["vat_category"].as_str().unwrap_or("standard")),
        );
        bodies.push(body);
    }
    Ok((header, bodies))
}

struct Billing(&'static str);

impl Action for Billing {
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
            use attome_billing::{lookup, notes};
            let security = &ctx.security;
            match self.0 {
                FIND_INVOICES => {
                    let filter = lookup::InvoiceFilter {
                        account_id: args["account_id"]
                            .as_str()
                            .map(Uuid::parse_str)
                            .transpose()
                            .map_err(|_| {
                                AppError::Validation("account_id must be a UUID".into())
                            })?,
                        status: args["status"].as_str().map(str::to_owned),
                        payment_status: args["payment_status"].as_str().map(str::to_owned),
                        number: args["number"].as_str().map(str::to_owned),
                        limit: args["limit"].as_i64(),
                    };
                    plain(lookup::find_invoices(state, security, &filter).await?)
                }
                ACCOUNT_BALANCE => {
                    let balances =
                        lookup::account_balance(state, security, uuid_arg(args, "account_id")?)
                            .await?;
                    plain(
                        balances
                            .into_iter()
                            .map(|(currency, balance)| json!({ "currency": currency, "balance": balance }))
                            .collect::<Vec<_>>(),
                    )
                }
                EXPLAIN_TAX => {
                    plain(lookup::explain_line(state, security, uuid_arg(args, "line_id")?).await?)
                }
                DRAFT_INVOICE => {
                    let (header, lines) = invoice_values(args)?;
                    security.require("invoice", "create")?;
                    security.require("invoice_line", "create")?;
                    let (invoice, _) = attome_records::entity_crud::create_record_for(
                        state,
                        security,
                        security.user_id,
                        "invoice",
                        Value::Object(header),
                    )
                    .await?;
                    for mut line in lines {
                        line.insert("invoice_ref".into(), json!(invoice));
                        attome_records::entity_crud::create_record_for(
                            state,
                            security,
                            security.user_id,
                            "invoice_line",
                            Value::Object(line),
                        )
                        .await?;
                    }
                    let totals =
                        attome_billing::invoice::recompute_draft(state, security, invoice).await?;
                    Ok(ActionResult::plain(json!({
                        "invoice_id": invoice,
                        "status": "draft",
                        "grand_total": totals.grand_total,
                        "detail": "Filed as a draft. Nothing was issued; a person checks and issues it.",
                    })))
                }
                DRAFT_CREDIT_NOTE => {
                    // Raising a credit note is billing.credit's, as on the
                    // credit-notes route.
                    security.require_key("billing.credit")?;
                    let original = uuid_arg(args, "invoice_id")?;
                    let reason = args["reason"].as_str().unwrap_or_default();
                    let lines = args["lines"]
                        .as_array()
                        .ok_or_else(|| AppError::Validation("lines is required".into()))?
                        .iter()
                        .map(|l| Ok((uuid_arg(l, "line_id")?, decimal_arg(l, "quantity")?)))
                        .collect::<Result<Vec<_>, AppError>>()?;
                    let note = notes::create_credit_note(state, security, original, &lines, reason)
                        .await?;
                    Ok(ActionResult::plain(json!({
                        "credit_note_id": note.note_id,
                        "status": "draft",
                        "detail": "Filed as a draft credit note. Nothing was issued; a person checks and issues it.",
                    })))
                }
                other => Err(AppError::internal(format!(
                    "unknown billing action {other}"
                ))),
            }
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        match self.0 {
            DRAFT_INVOICE => {
                let (header, lines) = invoice_values(args).ok()?;
                Some(json!({
                    "action": DRAFT_INVOICE,
                    "account_id": header["account_ref"],
                    "currency": header["currency"],
                    "lines": lines,
                }))
            }
            DRAFT_CREDIT_NOTE => Some(json!({
                "action": DRAFT_CREDIT_NOTE,
                "invoice_id": args["invoice_id"],
                "reason": args["reason"],
                "lines": args["lines"],
            })),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_actions_cannot_issue() {
        let ids: Vec<&str> = descriptors().iter().map(|d| d.id.0).collect();
        assert_eq!(
            ids,
            [
                FIND_INVOICES,
                ACCOUNT_BALANCE,
                EXPLAIN_TAX,
                DRAFT_INVOICE,
                DRAFT_CREDIT_NOTE
            ]
        );
        for id in &ids {
            for verb in ["issue", "cancel", "write_off", "writeoff", "void"] {
                assert!(!id.contains(verb), "{id} names {verb}");
            }
        }
        // Reads are reads; the only writes file drafts a person confirms.
        for d in descriptors() {
            match d.id.0 {
                DRAFT_INVOICE | DRAFT_CREDIT_NOTE => {
                    assert_eq!(d.risk, RiskTier::Reversible);
                    assert!(d.agent_must_confirm, "{} must be confirmed", d.id.0);
                }
                _ => assert_eq!(d.effect, Effect::Read, "{} must only read", d.id.0),
            }
        }
        // And the code never reaches the people-only engine calls.
        let source = include_str!("billing.rs");
        let code = source.split("#[cfg(test)]").next().unwrap_or(source);
        for call in [
            "issue::",
            "writeoff::",
            "notes::cancel",
            "do_issue",
            "do_write_off",
        ] {
            assert!(
                !code.contains(&format!("attome_billing::{call}")),
                "calls {call}"
            );
            assert!(!code.contains(&format!(" {call}(")), "calls {call}");
        }
    }

    #[test]
    fn a_drafted_invoice_is_always_a_draft_invoice() {
        let (header, lines) = invoice_values(&json!({
            "account_id": Uuid::now_v7().to_string(),
            "currency": "SAR",
            "lines": [{ "description": "Setup", "quantity": 1, "unit_price": 500 }],
            "status": "issued",
        }))
        .unwrap();
        assert_eq!(header["status"], "draft");
        assert_eq!(header["kind"], "invoice");
        assert_eq!(lines[0]["vat_category"], "standard");
        assert!(
            invoice_values(&json!({
                "account_id": Uuid::now_v7().to_string(), "currency": "sar",
                "lines": [{ "description": "x", "quantity": 1, "unit_price": 1 }],
            }))
            .is_err()
        );
        assert!(
            invoice_values(&json!({
                "account_id": Uuid::now_v7().to_string(), "currency": "SAR",
                "lines": [{ "description": "x", "quantity": 0, "unit_price": 1 }],
            }))
            .is_err()
        );
    }
}

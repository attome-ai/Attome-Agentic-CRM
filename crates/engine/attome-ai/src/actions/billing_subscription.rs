//! Subscription actions (roadmap F3-T12).
//!
//! - `billing.subscription.read` reads a subscription as of a date: each
//!   line's quantity and price in force that day.
//! - `billing.usage.read` sums a subscription's metered usage per line and
//!   metric over a range of days.
//! - `billing.amendment.draft` works out what an amendment would do (each
//!   line before and after, and the proration it would plan) and changes
//!   nothing: a person makes the amendment.
//! - `billing.renewal.draft` works out the next term (dates and the lines as
//!   they stand at the end of this one) and changes nothing.
//!
//! No agent action amends, cancels or reprices a subscription: those stay
//! with people (`billing_no_cancel_action` holds that). Everything is read
//! as the caller, through `attome_billing::subscription::service`.

use std::future::Future;
use std::pin::Pin;

use attome_billing::subscription::segments::ChangeKind;
use attome_billing::subscription::service;
use attome_core::EngineState;
use attome_modules::MODULE_BILLING;
use attome_types::AppError;
use chrono::{Duration, Months, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const READ_SUBSCRIPTION: &str = "billing.subscription.read";
pub const READ_USAGE: &str = "billing.usage.read";
pub const DRAFT_AMENDMENT: &str = "billing.amendment.draft";
pub const DRAFT_RENEWAL: &str = "billing.renewal.draft";

/// The most days one usage read covers.
const MAX_USAGE_DAYS: i64 = 366;

const READ_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "subscription_id": { "type": "string", "format": "uuid" },
    "as_of": { "type": "string", "format": "date", "description": "YYYY-MM-DD; today when absent" }
  },
  "required": ["subscription_id"],
  "additionalProperties": false
}"#;

const USAGE_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "subscription_id": { "type": "string", "format": "uuid" },
    "from": { "type": "string", "format": "date" },
    "to": { "type": "string", "format": "date", "description": "exclusive" }
  },
  "required": ["subscription_id", "from", "to"],
  "additionalProperties": false
}"#;

const AMENDMENT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "subscription_id": { "type": "string", "format": "uuid" },
    "effective": { "type": "string", "format": "date" },
    "changes": {
      "type": "array",
      "minItems": 1,
      "maxItems": 50,
      "items": {
        "type": "object",
        "properties": {
          "line_id": { "type": "string", "format": "uuid" },
          "quantity": { "type": "number", "minimum": 0 },
          "unit_price": { "type": "number", "minimum": 0 }
        },
        "required": ["line_id", "quantity", "unit_price"],
        "additionalProperties": false
      }
    }
  },
  "required": ["subscription_id", "effective", "changes"],
  "additionalProperties": false
}"#;

const RENEWAL_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "subscription_id": { "type": "string", "format": "uuid" },
    "term_months": { "type": "integer", "minimum": 1, "maximum": 120 }
  },
  "required": ["subscription_id"],
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

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            READ_SUBSCRIPTION,
            "Read a subscription as of a date: its terms and each line's quantity and price in \
             force that day.",
            READ_SCHEMA,
        ),
        read(
            READ_USAGE,
            "Sum a subscription's metered usage per line and metric between two dates.",
            USAGE_SCHEMA,
        ),
        read(
            DRAFT_AMENDMENT,
            "Work out what an amendment would do: each line's quantity and price before and \
             after, and the proration charge or credit for the rest of the period. Nothing is \
             changed: a person makes the amendment.",
            AMENDMENT_SCHEMA,
        ),
        read(
            DRAFT_RENEWAL,
            "Work out a subscription's next term: its dates and the lines as they stand at the \
             end of this one. Nothing is changed: a person renews it.",
            RENEWAL_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Subscription(READ_SUBSCRIPTION)),
        Box::new(Subscription(READ_USAGE)),
        Box::new(Subscription(DRAFT_AMENDMENT)),
        Box::new(Subscription(DRAFT_RENEWAL)),
    ]
}

fn uuid_arg(args: &Value, key: &str) -> Result<Uuid, AppError> {
    args[key]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a UUID")))
}

fn date_arg(args: &Value, key: &str) -> Result<Option<NaiveDate>, AppError> {
    match args.get(key).and_then(Value::as_str) {
        None => Ok(None),
        Some(s) => s
            .parse()
            .map(Some)
            .map_err(|_| AppError::Validation(format!("{key} must be a date, YYYY-MM-DD"))),
    }
}

fn decimal_arg(value: &Value, key: &str) -> Result<Decimal, AppError> {
    value[key]
        .as_number()
        .and_then(|n| n.to_string().parse::<Decimal>().ok())
        .filter(|d| !d.is_sign_negative())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a number of 0 or more")))
}

fn plain(value: impl serde::Serialize) -> Result<ActionResult, AppError> {
    Ok(ActionResult::plain(
        serde_json::to_value(value).map_err(AppError::internal)?,
    ))
}

/// The next term after `end`: it starts on `end` and runs `months`. Pure.
pub fn next_term(end: NaiveDate, months: u32) -> Option<(NaiveDate, NaiveDate)> {
    end.checked_add_months(Months::new(months))
        .map(|to| (end, to))
}

struct Subscription(&'static str);

impl Action for Subscription {
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
            let subscription = uuid_arg(args, "subscription_id")?;
            match self.0 {
                READ_SUBSCRIPTION => {
                    let as_of = date_arg(args, "as_of")?.unwrap_or_else(|| Utc::now().date_naive());
                    plain(service::read_as_of(state, security, subscription, as_of).await?)
                }
                READ_USAGE => {
                    let (Some(from), Some(to)) = (date_arg(args, "from")?, date_arg(args, "to")?)
                    else {
                        return Err(AppError::Validation("from and to are required".into()));
                    };
                    if to <= from || (to - from).num_days() > MAX_USAGE_DAYS {
                        return Err(AppError::Validation(format!(
                            "to comes after from, at most {MAX_USAGE_DAYS} days later"
                        )));
                    }
                    plain(service::usage_summary(state, security, subscription, from, to).await?)
                }
                DRAFT_AMENDMENT => {
                    let effective = date_arg(args, "effective")?
                        .ok_or_else(|| AppError::Validation("effective is required".into()))?;
                    let changes = args["changes"]
                        .as_array()
                        .filter(|c| !c.is_empty() && c.len() <= 50)
                        .ok_or_else(|| AppError::Validation("1 to 50 changes".into()))?
                        .iter()
                        .map(|c| {
                            Ok(service::LineChange {
                                line_id: uuid_arg(c, "line_id")?,
                                quantity: decimal_arg(c, "quantity")?,
                                unit_price: decimal_arg(c, "unit_price")?,
                                kind: ChangeKind::PriceChange,
                            })
                        })
                        .collect::<Result<Vec<_>, AppError>>()?;
                    let preview = service::preview_amend(
                        state,
                        security,
                        subscription,
                        &service::Amendment { effective, changes },
                    )
                    .await?;
                    Ok(ActionResult::plain(json!({
                        "status": "draft",
                        "effective": effective,
                        "lines": preview,
                        "note": "Nothing was changed. A person makes the amendment; a new price needs subscription.amend_price.",
                    })))
                }
                DRAFT_RENEWAL => {
                    let current =
                        service::read_as_of(state, security, subscription, Utc::now().date_naive())
                            .await?;
                    let end: NaiveDate = current.subscription["end_date"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| {
                            AppError::Validation(
                                "an evergreen subscription has no term to renew".into(),
                            )
                        })?;
                    let months = args["term_months"]
                        .as_u64()
                        .or_else(|| {
                            current.subscription["term_months"]
                                .as_f64()
                                .map(|m| m as u64)
                        })
                        .and_then(|m| u32::try_from(m).ok())
                        .filter(|m| (1..=120).contains(m))
                        .unwrap_or(12);
                    let last_day = end - Duration::days(1);
                    let at_end =
                        service::read_as_of(state, security, subscription, last_day).await?;
                    let (from, to) = next_term(end, months).ok_or_else(|| {
                        AppError::Validation("the next term is out of range".into())
                    })?;
                    Ok(ActionResult::plain(json!({
                        "status": "draft",
                        "start_date": from,
                        "end_date": to,
                        "term_months": months,
                        "lines": at_end.lines,
                        "note": "Nothing was changed. A person renews the subscription.",
                    })))
                }
                other => Err(AppError::internal(format!("unknown action {other}"))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_descriptors_are_registered() {
        let ids: Vec<&str> = crate::actions::all().iter().map(|d| d.id.0).collect();
        for id in [
            READ_SUBSCRIPTION,
            READ_USAGE,
            DRAFT_AMENDMENT,
            DRAFT_RENEWAL,
        ] {
            assert!(ids.contains(&id), "{id} is in the catalogue");
        }
        assert_eq!(executors().len(), descriptors().len());
    }

    #[test]
    fn billing_no_cancel_action() {
        for d in descriptors() {
            assert!(
                !d.id.0.contains("cancel") && !d.id.0.contains("price"),
                "{} must not cancel or reprice",
                d.id.0
            );
            assert_eq!(d.effect, Effect::Read, "{} changes nothing", d.id.0);
        }
    }

    #[test]
    fn the_next_term_starts_where_this_one_ends() {
        let end = NaiveDate::from_ymd_opt(2028, 1, 1).unwrap();
        assert_eq!(
            next_term(end, 12),
            Some((end, NaiveDate::from_ymd_opt(2029, 1, 1).unwrap()))
        );
    }
}

//! Deliverability actions (roadmap E6-T12), both read-only:
//!
//! - `deliverability.explain` compares a window of the daily rollup (E6-T4)
//!   with the window of the same length just before it and names the
//!   biggest changes in delivery, bounce, open and complaint rates, per
//!   mailbox provider and per send;
//! - `deliverability.propose_segment` drafts a cleaner E7 segment (people
//!   engaged in the last N days, not sunset) and saves nothing.
//!
//! Neither lifts a suppression or changes DNS or the policy. Both need the
//! caller's `marketing_deliverability_policy.read` and are hidden without
//! the marketing module (the descriptor's module gate). The explanation is
//! computed here from aggregate counts; no record data reaches a model.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_marketing::deliverability::rollup::{RollupCounts, totals};
use attome_modules::MODULE_MARKETING;
use attome_security::SecurityContextExt;
use attome_types::AppError;
use chrono::{Duration, NaiveDate, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const EXPLAIN: &str = "deliverability.explain";
pub const PROPOSE_SEGMENT: &str = "deliverability.propose_segment";

/// The longest window one explanation compares.
const MAX_DAYS: i64 = 92;
/// Changes listed per explanation.
const TOP: usize = 10;

const EXPLAIN_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "domain": { "type": "string", "description": "The sending domain; every domain when absent" },
    "from": { "type": "string", "format": "date" },
    "to": { "type": "string", "format": "date", "description": "inclusive" }
  },
  "required": ["from", "to"],
  "additionalProperties": false
}"#;

const SEGMENT_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "days": { "type": "integer", "minimum": 7, "maximum": 365, "description": "Engaged within this many days; 90 when absent" },
    "target_entity": { "type": "string", "enum": ["contact", "lead"] }
  },
  "additionalProperties": false
}"#;

fn read(id: &'static str, text: &'static str, schema: &'static str) -> ActionDescriptor {
    ActionDescriptor::new(
        id,
        text,
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_MARKETING,
        &[],
    )
    .input_schema(schema)
}

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        read(
            EXPLAIN,
            "Explain a change in email deliverability: compare a date range of the daily rollup \
             with the range just before it and list the biggest changes in delivery, bounce, \
             open and complaint rates by mailbox provider and by send.",
            EXPLAIN_SCHEMA,
        ),
        read(
            PROPOSE_SEGMENT,
            "Draft a cleaner marketing segment: people engaged in the last N days and not \
             sunset. Nothing is saved: a person creates the list from the draft.",
            SEGMENT_SCHEMA,
        ),
    ]
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(Deliverability(EXPLAIN)),
        Box::new(Deliverability(PROPOSE_SEGMENT)),
    ]
}

/// The rates one comparison looks at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Rates {
    pub sent: i64,
    pub delivered: f64,
    pub bounced: f64,
    pub opened: f64,
    pub complaints: f64,
}

/// Rates of delivered, bounced, opened and complaints per sent. Pure.
pub fn rates(c: &RollupCounts) -> Rates {
    let per = |n: i64| {
        if c.sent > 0 {
            n as f64 / c.sent as f64
        } else {
            0.0
        }
    };
    Rates {
        sent: c.sent,
        delivered: per(c.delivered),
        bounced: per(c.bounced),
        opened: per(c.opened),
        complaints: per(c.complaints),
    }
}

/// One change between the windows.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Change {
    /// `provider` or `send`.
    pub by: &'static str,
    pub key: String,
    pub before: Rates,
    pub now: Rates,
    /// The change that matters most, as a signed rate difference where
    /// negative is worse (a bounce or complaint rise counts as negative).
    pub score: f64,
}

fn merge(into: &mut RollupCounts, c: &RollupCounts) {
    into.sent += c.sent;
    into.delivered += c.delivered;
    into.bounced += c.bounced;
    into.opened += c.opened;
    into.clicked += c.clicked;
    into.complaints += c.complaints;
}

/// The biggest changes between two windows' totals, worst first. Pure.
pub fn changes(
    before: &[(String, String, RollupCounts)],
    now: &[(String, String, RollupCounts)],
) -> Vec<Change> {
    let mut out = Vec::new();
    for by in ["provider", "send"] {
        let group = |rows: &[(String, String, RollupCounts)]| {
            let mut map: BTreeMap<String, RollupCounts> = BTreeMap::new();
            for (provider, send, c) in rows {
                let key = if by == "provider" { provider } else { send };
                if by == "send" && key.is_empty() {
                    continue;
                }
                merge(map.entry(key.clone()).or_default(), c);
            }
            map
        };
        let (b, n) = (group(before), group(now));
        for (key, counts) in &n {
            let now_rates = rates(counts);
            let before_rates = rates(&b.get(key).copied().unwrap_or_default());
            let score = (now_rates.delivered - before_rates.delivered)
                .min(now_rates.opened - before_rates.opened)
                .min(before_rates.bounced - now_rates.bounced)
                .min((before_rates.complaints - now_rates.complaints) * 10.0);
            out.push(Change {
                by,
                key: key.clone(),
                before: before_rates,
                now: now_rates,
                score,
            });
        }
    }
    out.sort_by(|a, b| a.score.total_cmp(&b.score));
    out.truncate(TOP);
    out
}

/// The draft segment definition. Pure.
pub fn segment_draft(days: i64, target: &str, today: NaiveDate) -> Value {
    let since = today - Duration::days(days);
    json!({
        "saved": false,
        "name": format!("Engaged in the last {days} days"),
        "kind": "segment",
        "target_entity": target,
        "filters": [
            { "field": "last_marketing_engagement_at", "op": "gte", "value": since.to_string() },
            { "field": "marketing_sunset_at", "op": "is_null" },
            { "field": "email", "op": "is_not_null" }
        ],
        "reason": "People who opened, clicked, replied or submitted a form recently keep \
                   bounce and complaint rates low; sending only to them protects the domain's \
                   reputation.",
    })
}

fn date_arg(args: &Value, key: &str) -> Result<NaiveDate, AppError> {
    args.get(key)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a date, YYYY-MM-DD")))
}

struct Deliverability(&'static str);

impl Action for Deliverability {
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
            ctx.security
                .require("marketing_deliverability_policy", "read")?;
            match self.0 {
                EXPLAIN => {
                    let (from, to) = (date_arg(args, "from")?, date_arg(args, "to")?);
                    let days = (to - from).num_days() + 1;
                    if days < 1 || days > MAX_DAYS {
                        return Err(AppError::Validation(format!(
                            "to is on or after from, at most {MAX_DAYS} days later"
                        )));
                    }
                    let domain = args.get("domain").and_then(Value::as_str);
                    let before_to = from - Duration::days(1);
                    let before_from = from - Duration::days(days);
                    let now = totals(&state.base.db, domain, from, to).await?;
                    let before = totals(&state.base.db, domain, before_from, before_to).await?;
                    Ok(ActionResult::plain(json!({
                        "window": { "from": from, "to": to },
                        "compared_with": { "from": before_from, "to": before_to },
                        "changes": changes(&before, &now),
                    })))
                }
                PROPOSE_SEGMENT => {
                    let days = args.get("days").and_then(Value::as_i64).unwrap_or(90);
                    if !(7..=365).contains(&days) {
                        return Err(AppError::Validation("days is 7 to 365".into()));
                    }
                    let target = args
                        .get("target_entity")
                        .and_then(Value::as_str)
                        .unwrap_or("contact");
                    if !matches!(target, "contact" | "lead") {
                        return Err(AppError::Validation(
                            "target_entity is contact or lead".into(),
                        ));
                    }
                    Ok(ActionResult::plain(segment_draft(
                        days,
                        target,
                        Utc::now().date_naive(),
                    )))
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
    fn descriptors_are_read_only() {
        for d in descriptors() {
            assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
            assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        }
        assert_eq!(executors().len(), descriptors().len());
    }

    #[test]
    fn hidden_without_marketing_module() {
        for d in descriptors() {
            assert_eq!(d.module, MODULE_MARKETING, "{}", d.id.0);
        }
    }

    #[test]
    fn a_bounce_rise_on_one_provider_comes_first() {
        let counts = |sent, delivered, bounced, opened| RollupCounts {
            sent,
            delivered,
            bounced,
            opened,
            ..RollupCounts::default()
        };
        let before = vec![
            ("gmail".to_owned(), String::new(), counts(100, 98, 2, 30)),
            ("outlook".to_owned(), String::new(), counts(100, 97, 3, 25)),
        ];
        let now = vec![
            ("gmail".to_owned(), String::new(), counts(100, 97, 3, 29)),
            ("outlook".to_owned(), String::new(), counts(100, 70, 30, 10)),
        ];
        let list = changes(&before, &now);
        assert_eq!(list[0].key, "outlook");
        assert!(list[0].score < list[1].score);
    }

    #[test]
    fn the_segment_draft_is_not_saved() {
        let draft = segment_draft(
            90,
            "contact",
            NaiveDate::from_ymd_opt(2026, 10, 20).unwrap(),
        );
        assert_eq!(draft["saved"], false);
        assert_eq!(draft["filters"][0]["value"], "2026-07-22");
    }
}

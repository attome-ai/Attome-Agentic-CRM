//! Mass operations as AI actions (roadmap AA10-T10): estimate, then start an
//! update, delete or restore over every record a filter selects, through the
//! same engine as `POST /api/v1/{entity}/mass` (`attome_records::mass`).
//!
//! - `record.mass.estimate` (read): how many records the filter selects that
//!   the caller may change, how long it would take, and whether an agent
//!   needs a person's confirmation to start it.
//! - `record.mass.start` (reversible: a mass operation can be undone): an
//!   agent may start it only when the size check, run again here, counts no
//!   more than `limits.heavy_op.agent_confirm_rows`; above that it refuses
//!   and names `record.mass.start_confirmed`.
//! - `record.mass.start_confirmed`: the same start, declared
//!   `agent_must_confirm`, so for an agent it stops at the confirm round-trip
//!   (`confirm.rs`) and runs only when a person confirms the stored proposal.
//!   The proposal carries the estimate the agent was given
//!   (`confirm_rows`), and the start refuses when the records counted now are
//!   more than that, so the person never confirms a smaller number than what
//!   runs. It is `autonomy_locked`, so no autonomy level an administrator
//!   sets lifts the confirmation.
//!
//! The size check cannot be skipped: both starts call it before anything is
//! written, and `attome_records::mass::start` checks it again. The agent's
//! identity (its security context) is the operation's `started_by`.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_records::mass::{self, MassKind, MassStartBody};
use attome_types::AppError;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const MASS_ESTIMATE: &str = "record.mass.estimate";
pub const MASS_START: &str = "record.mass.start";
pub const MASS_START_CONFIRMED: &str = "record.mass.start_confirmed";

/// The setting (under `limits.`) above which an agent's mass operation
/// needs a person's confirmation.
pub const AGENT_CONFIRM_ROWS_LIMIT: &str = "heavy_op.agent_confirm_rows";
pub const DEFAULT_AGENT_CONFIRM_ROWS: i64 = 100;

const ESTIMATE_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "filter": { "type": "object", "description": "query/run's where condition; omit to select every record." },
    "kind": { "type": "string", "enum": ["update", "delete", "restore"] },
    "payload": { "type": "object", "description": "For an update: the fields to set on every record." }
  },
  "required": ["entity", "kind"],
  "additionalProperties": false
}"#;

const START_INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "filter": { "type": "object", "description": "query/run's where condition; omit to select every record." },
    "kind": { "type": "string", "enum": ["update", "delete", "restore"] },
    "payload": { "type": "object", "description": "For an update: the fields to set on every record." },
    "reason": { "type": "string", "maxLength": 500, "description": "Why; kept on the operation and shown to the person." },
    "confirm_rows": { "type": "integer", "minimum": 1, "description": "The estimated_rows record.mass.estimate returned for this exact change." }
  },
  "required": ["entity", "kind", "reason"],
  "additionalProperties": false
}"#;

pub fn descriptors() -> Vec<ActionDescriptor> {
    vec![
        ActionDescriptor::new(
            MASS_ESTIMATE,
            "Before changing, deleting or restoring every record a filter selects: how many \
             you may change, about how long it takes, and whether a person must confirm it. \
             Changes nothing.",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            MODULE_AI,
            &[],
        )
        .input_schema(ESTIMATE_INPUT),
        ActionDescriptor::new(
            MASS_START,
            "Update, delete or restore every record a filter selects, after \
             record.mass.estimate, when the estimate says no confirmation is needed. It can \
             be undone.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(START_INPUT),
        ActionDescriptor::new(
            MASS_START_CONFIRMED,
            "The same as record.mass.start for a change too large to start alone: a person \
             confirms it first. Pass the estimate's estimated_rows as confirm_rows.",
            RiskTier::Reversible,
            Effect::Write,
            RetryClass::RequiresKey,
            MODULE_AI,
            &[],
        )
        .input_schema(START_INPUT)
        .agent_must_confirm()
        // No autonomy level lifts the confirmation: the size is the reason
        // for it.
        .autonomy_locked(),
    ]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MassArgs {
    entity: String,
    #[serde(default)]
    filter: Option<Value>,
    kind: MassKind,
    #[serde(default)]
    payload: Value,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    confirm_rows: Option<i64>,
}

fn parse(args: &Value) -> Result<MassArgs, AppError> {
    let parsed: MassArgs = serde_json::from_value(args.clone())
        .map_err(|e| AppError::Validation(format!("invalid arguments: {e}")))?;
    if parsed.entity.trim().is_empty() {
        return Err(AppError::Validation("entity is required".into()));
    }
    // Reassignment is an administrator's tool, not an agent's.
    if parsed.kind == MassKind::Reassign {
        return Err(AppError::Validation(
            "kind must be update, delete or restore".into(),
        ));
    }
    Ok(parsed)
}

/// The rows above which an agent needs a person's confirmation.
pub fn agent_confirm_rows(state: &EngineState) -> i64 {
    state
        .runtime_limit(AGENT_CONFIRM_ROWS_LIMIT)
        .unwrap_or(DEFAULT_AGENT_CONFIRM_ROWS)
        .max(1)
}

/// Whether an agent's operation of `estimated_rows` needs confirmation
/// under `limit`. Pure.
pub fn needs_confirmation(estimated_rows: i64, limit: i64) -> bool {
    estimated_rows > limit
}

/// What `record.mass.start` does with an agent's estimate: start it, or
/// refuse and name the confirmed start. Pure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartDecision {
    Start,
    NeedsConfirmation { estimated_rows: i64, limit: i64 },
}

pub fn start_decision(is_agent: bool, estimated_rows: i64, limit: i64) -> StartDecision {
    if is_agent && needs_confirmation(estimated_rows, limit) {
        StartDecision::NeedsConfirmation {
            estimated_rows,
            limit,
        }
    } else {
        StartDecision::Start
    }
}

fn condition(
    filter: &Option<Value>,
) -> Result<Option<attome_records::query_spec::Condition>, AppError> {
    filter
        .clone()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| AppError::Validation(format!("filter: {e}")))
}

pub(crate) struct MassEstimate;

impl Action for MassEstimate {
    fn id(&self) -> ActionId {
        ActionId(MASS_ESTIMATE)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let parsed = parse(args)?;
            let filter = condition(&parsed.filter)?;
            let size = mass::estimate(
                state,
                &ctx.security,
                parsed.entity.trim(),
                filter.as_ref(),
                parsed.kind,
                &parsed.payload,
            )
            .await?;
            let limit = agent_confirm_rows(state);
            let confirm = ctx.is_agent() && needs_confirmation(size.estimated_rows, limit);
            Ok(ActionResult::plain(json!({
                "entity": parsed.entity.trim(),
                "kind": parsed.kind.as_str(),
                "estimated_rows": size.estimated_rows,
                "estimated_seconds": size.estimated_seconds,
                "exact": !size.exceeds,
                "needs_confirmation": confirm,
                "next": if confirm { MASS_START_CONFIRMED } else { MASS_START },
                "detail": "Nothing was changed. Pass estimated_rows as confirm_rows when you start it.",
            })))
        })
    }
}

/// `record.mass.start` and `record.mass.start_confirmed`.
pub(crate) struct MassStart {
    id: &'static str,
    /// The confirmed start: a person has confirmed it (the gate saw to that).
    confirmed: bool,
}

impl Action for MassStart {
    fn id(&self) -> ActionId {
        ActionId(self.id)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let parsed = parse(args)?;
            let reason = parsed
                .reason
                .as_deref()
                .map(str::trim)
                .filter(|r| !r.is_empty())
                .ok_or_else(|| AppError::Validation("reason is required".into()))?
                .to_owned();
            let filter = condition(&parsed.filter)?;
            // The size check first, always: the agent's own estimate is not
            // trusted to decide whether it may start alone.
            let size = mass::estimate(
                state,
                &ctx.security,
                parsed.entity.trim(),
                filter.as_ref(),
                parsed.kind,
                &parsed.payload,
            )
            .await?;
            if !self.confirmed
                && let StartDecision::NeedsConfirmation {
                    estimated_rows,
                    limit,
                } = start_decision(
                    ctx.is_agent(),
                    size.estimated_rows,
                    agent_confirm_rows(state),
                )
            {
                return Ok(ActionResult::plain(json!({
                    "started": false,
                    "needs_confirmation": true,
                    "estimated_rows": estimated_rows,
                    "limit": limit,
                    "detail": format!(
                        "About {estimated_rows} records, more than the {limit} an agent may change \
                         without a person: call {MASS_START_CONFIRMED} with the same arguments and \
                         confirm_rows = {estimated_rows}; a person confirms it before it runs."
                    ),
                })));
            }
            let confirm_rows = match parsed.confirm_rows {
                Some(rows) => rows,
                None if self.confirmed => {
                    return Err(AppError::Validation(
                        "confirm_rows is required: pass the estimate's estimated_rows".into(),
                    ));
                }
                None => size.estimated_rows,
            };
            // What the person confirmed is a number of records; never run more.
            if self.confirmed && size.exact_upto > confirm_rows {
                return Err(AppError::Validation(format!(
                    "the filter now selects at least {} records, more than the {confirm_rows} \
                     confirmed: estimate again and ask for a new confirmation",
                    size.exact_upto
                )));
            }
            let body: MassStartBody = serde_json::from_value(json!({
                "filter": parsed.filter,
                "kind": parsed.kind,
                "payload": parsed.payload,
                "reason": reason,
                "confirm_estimate_rows": confirm_rows,
            }))
            .map_err(|e| AppError::Validation(format!("invalid arguments: {e}")))?;
            let (run, inline) =
                mass::start(state, &ctx.security, parsed.entity.trim(), body, None).await?;
            Ok(ActionResult::plain(json!({
                "started": true,
                "operation_id": run.operation.id,
                "status": run.operation.status,
                "estimated_rows": run.operation.estimated_rows,
                "rows_done": run.operation.rows_done,
                "background": !inline,
                "detail": if inline {
                    "Done in this call; the operation can be undone."
                } else {
                    "Running in the background; the person who started it is told when it finishes, and it can be undone."
                },
            })))
        })
    }

    fn confirmation_proposal(&self, args: &Value) -> Option<Value> {
        let parsed: MassArgs = serde_json::from_value(args.clone()).ok()?;
        Some(json!({
            "action": self.id,
            "entity": parsed.entity,
            "kind": parsed.kind.as_str(),
            "filter": parsed.filter,
            "payload": parsed.payload,
            "reason": parsed.reason,
            "records": parsed.confirm_rows,
        }))
    }
}

pub(crate) fn executors() -> Vec<Box<dyn Action>> {
    vec![
        Box::new(MassEstimate),
        Box::new(MassStart {
            id: MASS_START,
            confirmed: false,
        }),
        Box::new(MassStart {
            id: MASS_START_CONFIRMED,
            confirmed: true,
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_mass_op_above_limit_requires_confirm() {
        assert_eq!(
            start_decision(true, 101, 100),
            StartDecision::NeedsConfirmation {
                estimated_rows: 101,
                limit: 100
            }
        );
        assert_eq!(start_decision(true, 100, 100), StartDecision::Start);
        // A person starting it is not held by the agent limit.
        assert_eq!(start_decision(false, 10_000, 100), StartDecision::Start);
    }

    #[test]
    fn the_confirmed_start_is_declared_agent_must_confirm() {
        let all = descriptors();
        let find = |id: &str| all.iter().find(|d| d.id.0 == id).expect("declared");
        assert!(find(MASS_START_CONFIRMED).agent_must_confirm);
        assert!(!find(MASS_START).agent_must_confirm);
        assert_eq!(find(MASS_ESTIMATE).risk, RiskTier::Read);
    }

    #[test]
    fn the_proposal_shows_the_person_how_many_records() {
        let proposal = MassStart {
            id: MASS_START_CONFIRMED,
            confirmed: true,
        }
        .confirmation_proposal(&json!({
            "entity": "account", "kind": "delete", "reason": "duplicates", "confirm_rows": 4200
        }))
        .expect("a proposal");
        assert_eq!(proposal["records"], 4200);
        assert_eq!(proposal["kind"], "delete");
    }

    #[test]
    fn reassign_is_not_an_agent_kind() {
        let err = parse(&json!({ "entity": "account", "kind": "reassign", "reason": "x" }));
        assert!(err.is_err());
    }
}

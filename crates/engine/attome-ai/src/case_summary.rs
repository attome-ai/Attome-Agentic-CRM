//! G1-T3: a case's AI summary kept current as its thread grows.
//!
//! `record.summarize` already caches a summary per exact set of facts (see
//! `actions::summary_context`), so a new message makes the next summary a
//! new generation. This sweep makes that generation happen before anyone
//! asks: two minutes after the newest message on an open, assigned case
//! (later messages restart the wait), it runs `record.summarize` for the
//! case **as its assignee** — through the normal gate, as an agent with a
//! `Read` ceiling, so the assignee's grants, the AI switch, the licence and
//! their budget all apply, and the summary sees only what the assignee can.
//! When the assignee opens the case the summary is a cache hit.
//!
//! State (guidelines §5): `attome-ai:case_summary:{case_id}` holds the Unix
//! second of the newest message already summarised, kept
//! [`WARMED_TTL`]. Losing it only means one extra generation, which the
//! summary cache usually answers.

use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::RiskTier;
use crate::execute::{ActionOutcome, dispatch};

/// How long a thread must be quiet before its summary is made.
pub const DEBOUNCE: Duration = Duration::from_secs(120);
/// Messages older than this are not waited on (the case was summarised, or
/// nobody needs a summary of week-old news made unasked).
pub const LOOKBACK: Duration = Duration::from_secs(6 * 3600);
/// Most cases summarised in one run.
pub const MAX_PER_RUN: i64 = 20;
const WARMED_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// Whether a case whose newest message arrived at `last_message` should be
/// summarised `now`, given the newest message already summarised. Pure.
pub fn due(last_message: DateTime<Utc>, now: DateTime<Utc>, warmed_up_to: Option<i64>) -> bool {
    let quiet = now.signed_duration_since(last_message)
        >= chrono::Duration::from_std(DEBOUNCE).unwrap_or_else(|_| chrono::Duration::zero());
    let new = warmed_up_to.is_none_or(|at| at < last_message.timestamp());
    quiet && new
}

fn warmed_key(case: Uuid) -> String {
    format!("attome-ai:case_summary:{case}")
}

/// One sweep: summarises each due case for its assignee. Returns how many
/// summaries ran.
pub async fn sweep(state: &EngineState) -> Result<u32, AppError> {
    // No service desk on this deployment: nothing to summarise.
    let entities = state.entities.load();
    if entities.get("service_ticket").is_none() || entities.get("communication").is_none() {
        return Ok(0);
    }
    drop(entities);
    let now = Utc::now();
    let candidates: Vec<(Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT t.id, t.assignee_id, max(c.created_at) \
           FROM service_ticket t \
           JOIN communication c ON c.entity_name = 'service_ticket' AND c.record_id = t.id::text \
          WHERE t.assignee_id IS NOT NULL AND t.is_active IS NOT FALSE \
            AND t.status NOT IN ('resolved', 'closed') AND c.is_active IS NOT FALSE \
            AND c.created_at >= $1 \
          GROUP BY t.id, t.assignee_id \
         HAVING max(c.created_at) <= $2 \
          ORDER BY max(c.created_at) DESC \
          LIMIT $3",
    )
    .bind(now - chrono::Duration::from_std(LOOKBACK).map_err(AppError::internal)?)
    .bind(now - chrono::Duration::from_std(DEBOUNCE).map_err(AppError::internal)?)
    .bind(MAX_PER_RUN)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut ran = 0;
    for (case, assignee, last_message) in candidates {
        let key = warmed_key(case);
        let warmed: Option<i64> = match state.base.redis.get(&key).await {
            Ok(value) => value.and_then(|v| v.parse().ok()),
            Err(error) => {
                // Without the marker every run would summarise again; skip
                // until Redis is back rather than spend the budget.
                tracing::warn!(%error, "case summary: marker unavailable; skipping");
                return Ok(ran);
            }
        };
        if !due(last_message, now, warmed) {
            continue;
        }
        match summarise_for(state, case, assignee).await {
            Ok(()) => ran += 1,
            // A refusal (no AI, no licence, no budget, no read access) is
            // the assignee's normal state, not a failure to page about.
            Err(error) => tracing::debug!(%case, %error, "case summary: not made"),
        }
        if let Err(error) = state
            .base
            .redis
            .set(&key, last_message.timestamp().to_string(), Some(WARMED_TTL))
            .await
        {
            tracing::warn!(%error, "case summary: marker not stored");
        }
    }
    Ok(ran)
}

/// Runs `record.summarize` on the case as `assignee`, through the gate.
async fn summarise_for(state: &EngineState, case: Uuid, assignee: Uuid) -> Result<(), AppError> {
    let security = state.base.security.resolve(assignee).await?;
    let ctx = ActionContext::agent(security, RiskTier::Read);
    let action = crate::actions::read::RECORD_SUMMARIZE;
    let module = crate::engine::REGISTRY
        .resolve(action)
        .map(|d| d.module)
        .ok_or(AppError::NotFound)?;
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, module);
    let args = serde_json::json!({ "entity": "service_ticket", "record_id": case });
    match dispatch(
        state,
        &crate::engine::REGISTRY,
        &crate::engine::EXECUTORS,
        action,
        &ctx,
        &inputs,
        &args,
    )
    .await?
    {
        ActionOutcome::Completed { .. } => Ok(()),
        _ => Err(AppError::Forbidden),
    }
}

#[cfg(test)]
mod case_summary {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn a_new_message_waits_two_quiet_minutes() {
        let message = at(1_000_000);
        assert!(
            !due(message, at(1_000_000 + 60), None),
            "still within the wait"
        );
        assert!(due(message, at(1_000_000 + 120), None));
        assert!(due(message, at(1_000_000 + 600), None));
    }

    #[test]
    fn a_summarised_thread_is_not_summarised_again() {
        let message = at(2_000_000);
        let later = at(2_000_000 + 300);
        assert!(!due(message, later, Some(2_000_000)));
        // A newer message than the one summarised makes it due again.
        assert!(due(at(2_000_100), later, Some(2_000_000)));
    }

    #[test]
    fn the_marker_key_names_the_case() {
        let case = Uuid::nil();
        assert_eq!(warmed_key(case), format!("attome-ai:case_summary:{case}"));
    }
}

//! AH4-T1: the money rule. A published agent object may cap the discount its
//! steps give (`limits.max_discount_percent`, 0–100). Before an agent's step
//! runs, a `discount_percent` in its arguments above that cap refuses the
//! step with a reason the agent can report; a person may still give the
//! discount themselves. A step without a discount, a person's own call and
//! an agent without the cap are not affected.
//!
//! The cap is read from the agent's published object when the step runs.

use attome_core::EngineState;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

use crate::context::ActionContext;

/// The discount a step's arguments ask for, as a number: `discount_percent`
/// given as a number or a numeric string. Pure.
pub fn requested(args: &Value) -> Option<f64> {
    match &args["discount_percent"] {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Whether a discount fits the cap. Pure.
pub fn within(discount: Option<f64>, cap: Option<f64>) -> bool {
    match (discount, cap) {
        (Some(d), Some(c)) => d <= c,
        _ => true,
    }
}

/// The cap on the agent object a session runs, if any.
async fn cap_for(state: &EngineState, session: Uuid) -> Result<Option<f64>, AppError> {
    let agent: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT agent_object_ref FROM agent_session WHERE id = $1")
            .bind(session)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some(agent) = agent.flatten() else {
        return Ok(None);
    };
    let doc = match attome_model::store::read_published(&state.base.db, agent).await {
        Ok(version) => version.doc,
        Err(AppError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(doc["limits"]["max_discount_percent"].as_f64())
}

/// Refuses an agent's step that gives more discount than its agent allows.
pub async fn check(state: &EngineState, ctx: &ActionContext, args: &Value) -> Result<(), AppError> {
    let Some(session) = ctx.agent_session_id.filter(|_| ctx.is_agent()) else {
        return Ok(());
    };
    let Some(discount) = requested(args) else {
        return Ok(());
    };
    let cap = cap_for(state, session).await?;
    if within(Some(discount), cap) {
        return Ok(());
    }
    let cap = cap.unwrap_or_default();
    tracing::info!(%session, discount, cap, "agent step refused: discount above the agent's limit");
    Err(AppError::Validation(format!(
        "discount_above_agent_limit: a {discount}% discount is above this agent's limit of \
         {cap}%; a person must give it"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn discount_rule_reads_numbers_and_numeric_strings() {
        assert_eq!(requested(&json!({ "discount_percent": 12.5 })), Some(12.5));
        assert_eq!(requested(&json!({ "discount_percent": "30" })), Some(30.0));
        assert_eq!(requested(&json!({ "discount_amount": "30" })), None);
        assert_eq!(requested(&json!({ "discount_percent": "lots" })), None);
    }

    #[test]
    fn discount_rule_refuses_only_above_the_cap() {
        assert!(within(Some(10.0), Some(10.0)));
        assert!(!within(Some(10.5), Some(10.0)));
        assert!(within(Some(90.0), None), "no cap, no rule");
        assert!(within(None, Some(5.0)), "no discount, no rule");
    }
}

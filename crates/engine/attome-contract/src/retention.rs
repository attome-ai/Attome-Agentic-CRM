//! W1-T14: the contract retention rule. Once the contract-management pack
//! has given `contract` its `end_date`, boot adds one R3 retention rule that
//! starts at that date: after [`PERIOD_DAYS`] the daily sweep proposes each
//! ended contract for review, a person approves before anything happens, and
//! a contract under a legal hold is never proposed (R4). An administrator
//! changes the period or the action at `/api/v1/admin/retention/rules`.
//!
//! It runs once per deployment (seed gate), so a rule an administrator
//! deleted stays deleted; a deployment without the pack is asked again on the
//! next boot.

use attome_core::EngineState;
use attome_types::AppError;

/// The rule's name, also how a second run finds it.
pub const RULE_NAME: &str = "Contracts: review after the end date";

/// Seven years after the end date, the usual commercial records period.
pub const PERIOD_DAYS: i32 = 2555;

/// The seed-gate key.
const GATE: &str = "attome-contract/retention-rule";

/// Adds the contract retention rule once, when `contract.end_date` exists.
pub async fn ensure_retention_rule(state: &EngineState) -> Result<(), AppError> {
    let has_end_date = state
        .entities
        .load()
        .get("contract")
        .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == "end_date"));
    if !has_end_date {
        return Ok(());
    }
    let db = &state.base.db_migrator;
    attome_core::seed_gate::run_if_stale(db, GATE, "1", || async {
        let added = sqlx::query(
            "INSERT INTO retention_rule (name, entity_logicalname, start_attribute, period_days, action) \
             SELECT $1, 'contract', 'end_date', $2, 'review' \
              WHERE NOT EXISTS (SELECT 1 FROM retention_rule WHERE entity_logicalname = 'contract' AND name = $1)",
        )
        .bind(RULE_NAME)
        .bind(PERIOD_DAYS)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        if added.rows_affected() > 0 {
            tracing::info!(
                period_days = PERIOD_DAYS,
                "W1-T14: added the contract retention rule (review after the end date)"
            );
        }
        Ok(())
    })
    .await
}

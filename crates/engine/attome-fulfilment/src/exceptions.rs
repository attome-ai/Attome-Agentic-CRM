//! F6-T14: fulfilment exceptions. Every 15 minutes [`sweep`] opens a
//! `fulfilment_exception`:
//!
//! - `late` for a released, picking or packed order past its promised date;
//! - `stuck` for an order that has stayed in one open status longer than the
//!   setting `fulfilment.stuck_hours` (48 by default), measured from its
//!   last change.
//!
//! Never two open exceptions of one kind for one order: a person resolves
//! one before another of that kind can open. Each carries a suggested action
//! from [`suggested_action`]. The fulfilment pack's "Open fulfilment
//! exceptions" view lists them.

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_types::AppError;
use uuid::Uuid;

/// The registered job's name.
pub const JOB: &str = "fulfilment_exceptions";

/// The setting naming how many hours in one status make an order stuck.
pub const STUCK_HOURS_SETTING: &str = "fulfilment.stuck_hours";

/// Hours in one status before an order is stuck, when the setting is unset.
pub const DEFAULT_STUCK_HOURS: i64 = 48;

/// Most exceptions one sweep opens of each kind.
const BATCH: i64 = 500;

/// What a person should do about an exception of `kind`. Pure.
pub fn suggested_action(kind: &str) -> &'static str {
    match kind {
        "late" => "Tell the customer the new date and expedite the order.",
        "stuck" => "Assign the order to the warehouse lead to move it on.",
        "failed_delivery" => {
            "Call the customer to confirm the address and a time, then rebook with the carrier."
        }
        _ => "Look at the order and resolve the exception.",
    }
}

fn stuck_hours(state: &EngineState) -> i64 {
    attome_core::setting_registry()
        .get(STUCK_HOURS_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_i64())
        .filter(|h| *h > 0)
        .unwrap_or(DEFAULT_STUCK_HOURS)
}

/// Opens the late and stuck exceptions that are due; returns how many.
pub async fn sweep(state: &EngineState) -> Result<usize, AppError> {
    let hours = stuck_hours(state);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind("attome-fulfilment/exceptions:sweep")
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(0);
    }
    let late: Vec<Uuid> = sqlx::query_scalar(
        "INSERT INTO fulfilment_exception \
             (id, fulfilment_order_ref, kind, reason, suggested_action, status, created_by, owner_ref) \
         SELECT uuidv7(), o.id, 'late', \
                'Promised for ' || to_char(o.promised_date, 'YYYY-MM-DD') || ' and not yet shipped', \
                $1, 'open', COALESCE(o.created_by, o.owner_ref), o.owner_ref \
           FROM fulfilment_order o \
          WHERE o.status::text IN ('released', 'picking', 'packed') \
            AND o.promised_date < now() \
            AND (o.is_active IS NULL OR o.is_active = true) \
            AND NOT EXISTS (SELECT 1 FROM fulfilment_exception e \
                             WHERE e.fulfilment_order_ref = o.id AND e.kind::text = 'late' \
                               AND e.status::text = 'open' \
                               AND (e.is_active IS NULL OR e.is_active = true)) \
          ORDER BY o.promised_date LIMIT $2 \
         RETURNING id",
    )
    .bind(suggested_action("late"))
    .bind(BATCH)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let stuck: Vec<Uuid> = sqlx::query_scalar(
        "INSERT INTO fulfilment_exception \
             (id, fulfilment_order_ref, kind, reason, suggested_action, status, created_by, owner_ref) \
         SELECT uuidv7(), o.id, 'stuck', \
                'In ' || COALESCE(o.status::text, 'no status') || ' for more than ' || $3 || ' hours', \
                $1, 'open', COALESCE(o.created_by, o.owner_ref), o.owner_ref \
           FROM fulfilment_order o \
          WHERE COALESCE(o.status::text, 'draft') NOT IN ('shipped', 'delivered', 'cancelled') \
            AND COALESCE(o.modified_at, o.created_at) < now() - make_interval(hours => $3::int) \
            AND (o.is_active IS NULL OR o.is_active = true) \
            AND NOT EXISTS (SELECT 1 FROM fulfilment_exception e \
                             WHERE e.fulfilment_order_ref = o.id AND e.kind::text = 'stuck' \
                               AND e.status::text = 'open' \
                               AND (e.is_active IS NULL OR e.is_active = true)) \
          ORDER BY COALESCE(o.modified_at, o.created_at) LIMIT $2 \
         RETURNING id",
    )
    .bind(suggested_action("stuck"))
    .bind(BATCH)
    .bind(hours)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for id in late.iter().chain(&stuck) {
        change_feed::emit_tx(
            &mut tx,
            "fulfilment_exception",
            *id,
            ChangeOperation::Create,
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(late.len() + stuck.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_has_a_suggested_action() {
        assert!(suggested_action("late").contains("customer"));
        assert!(suggested_action("stuck").contains("warehouse lead"));
        assert!(!suggested_action("other").is_empty());
    }
}

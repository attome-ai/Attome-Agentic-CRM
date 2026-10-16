//! Loyalty points (roadmap E30-T1) over the insert-only `loyalty_ledger`
//! (migration 0095). A member is any record (an account, a contact).
//!
//! - Earning is idempotent by reference (`order:{id}`): a fulfilled order
//!   earns one point per whole unit of its grand total, expiring after
//!   [`EARN_VALID_MONTHS`] months ([`earn_from_orders`], nightly).
//! - Redeeming checks the balance under the member's advisory lock.
//! - Points expire first in, first out: what has come due and was not yet
//!   used or expired leaves the balance ([`expire_due`], nightly).
//! - The tier comes from the points earned in the last 12 months.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Months, Utc};
use uuid::Uuid;

/// How long earned points last.
pub const EARN_VALID_MONTHS: u32 = 12;

/// Members per batch.
pub const BATCH: i64 = 500;

/// A tier and the points earned in a rolling year it starts at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier {
    pub name: String,
    pub min_points: i64,
}

/// The default tiers.
pub fn default_tiers() -> Vec<Tier> {
    [
        ("member", 0),
        ("silver", 1_000),
        ("gold", 5_000),
        ("platinum", 20_000),
    ]
    .into_iter()
    .map(|(name, min_points)| Tier {
        name: name.to_owned(),
        min_points,
    })
    .collect()
}

/// The highest tier the rolling points reach.
pub fn tier_for(rolling_points: i64, tiers: &[Tier]) -> Option<&Tier> {
    tiers
        .iter()
        .filter(|t| rolling_points >= t.min_points)
        .max_by_key(|t| t.min_points)
}

/// First in, first out: of the points that have come due, how many were
/// not already used (redeemed) or expired. Redemptions spend the oldest
/// points first, so every point used counts against the due ones first.
pub fn expirable(due_earned: i64, used: i64, already_expired: i64) -> i64 {
    (due_earned - used - already_expired).max(0)
}

/// Points for an order total: one per whole unit.
pub fn points_for(total: f64) -> i64 {
    if total.is_finite() && total > 0.0 {
        total.floor() as i64
    } else {
        0
    }
}

/// A member's balance.
pub async fn balance(db: &attome_db::DbPool, entity: &str, member: Uuid) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(points), 0)::bigint FROM loyalty_ledger \
         WHERE member_entity = $1 AND member_id = $2",
    )
    .bind(entity)
    .bind(member)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Spends `points` for `reference` (once); the new balance. Refused when
/// the balance is short.
pub async fn redeem(
    state: &EngineState,
    entity: &str,
    member: Uuid,
    points: i64,
    reference: &str,
) -> Result<i64, AppError> {
    if points <= 0 {
        return Err(AppError::Validation(
            "redeem a positive number of points".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-marketing/loyalty:{entity}:{member}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another change to these points is in progress",
        ));
    }
    let current: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(points), 0)::bigint FROM loyalty_ledger \
         WHERE member_entity = $1 AND member_id = $2",
    )
    .bind(entity)
    .bind(member)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if current < points {
        return Err(AppError::Validation(format!(
            "only {current} points are available"
        )));
    }
    let inserted = sqlx::query(
        "INSERT INTO loyalty_ledger (member_entity, member_id, kind, points, reference) \
         VALUES ($1, $2, 'redeem', $3, $4) ON CONFLICT (kind, reference) DO NOTHING",
    )
    .bind(entity)
    .bind(member)
    .bind(-points)
    .bind(reference)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    attome_db::tx::commit(tx).await?;
    Ok(if inserted == 1 {
        current - points
    } else {
        current
    })
}

/// Earns points for every fulfilled order not earned on yet; the number of
/// orders. Does nothing where the sales pack's orders are not installed.
pub async fn earn_from_orders(db: &attome_db::DbPool, now: DateTime<Utc>) -> Result<u64, AppError> {
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_name = 'order' AND column_name = 'grand_total' \
           AND table_schema = ANY (current_schemas(false)))",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let expires = now.checked_add_months(Months::new(EARN_VALID_MONTHS));
    let mut earned = 0;
    loop {
        let orders: Vec<(Uuid, Uuid, Option<f64>)> = sqlx::query_as(
            "SELECT o.id, o.account_ref, o.grand_total::float8 FROM \"order\" o \
             WHERE (o.is_active IS NULL OR o.is_active = true) AND o.status = 'fulfilled' \
               AND o.account_ref IS NOT NULL \
               AND NOT EXISTS (SELECT 1 FROM loyalty_ledger l \
                   WHERE l.kind = 'earn' AND l.reference = 'order:' || o.id::text) \
             ORDER BY o.id LIMIT $1",
        )
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let n = orders.len() as i64;
        for (order, account, total) in orders {
            // A zero-point order is still recorded so it is not read again.
            sqlx::query(
                "INSERT INTO loyalty_ledger \
                   (member_entity, member_id, kind, points, reference, occurred_at, expires_at) \
                 VALUES ('account', $1, 'earn', $2, $3, $4, $5) \
                 ON CONFLICT (kind, reference) DO NOTHING",
            )
            .bind(account)
            .bind(points_for(total.unwrap_or(0.0)))
            .bind(format!("order:{order}"))
            .bind(now)
            .bind(expires)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            earned += 1;
        }
        if n < BATCH {
            break;
        }
    }
    Ok(earned)
}

type MemberTotals = (String, Uuid, i64, i64, i64);

/// Expires the points that came due, first in first out; the number of
/// members touched.
pub async fn expire_due(db: &attome_db::DbPool, now: DateTime<Utc>) -> Result<u64, AppError> {
    let rows: Vec<MemberTotals> = sqlx::query_as(
        "SELECT member_entity, member_id, \
                COALESCE(SUM(points) FILTER (WHERE kind = 'earn' AND expires_at <= $1), 0)::bigint, \
                COALESCE(-SUM(points) FILTER (WHERE kind = 'redeem'), 0)::bigint, \
                COALESCE(-SUM(points) FILTER (WHERE kind = 'expire'), 0)::bigint \
         FROM loyalty_ledger GROUP BY member_entity, member_id \
         HAVING COALESCE(SUM(points) FILTER (WHERE kind = 'earn' AND expires_at <= $1), 0) > 0",
    )
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut touched = 0;
    for (entity, member, due, used, expired) in rows {
        let amount = expirable(due, used, expired);
        if amount == 0 {
            continue;
        }
        sqlx::query(
            "INSERT INTO loyalty_ledger (member_entity, member_id, kind, points, reference, occurred_at) \
             VALUES ($1, $2, 'expire', $3, $4, $5) ON CONFLICT (kind, reference) DO NOTHING",
        )
        .bind(&entity)
        .bind(member)
        .bind(-amount)
        .bind(format!("expire:{entity}:{member}:{}", now.date_naive()))
        .bind(now)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        touched += 1;
    }
    Ok(touched)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_follow_rolling_points() {
        let tiers = default_tiers();
        assert_eq!(tier_for(0, &tiers).map(|t| t.name.as_str()), Some("member"));
        assert_eq!(
            tier_for(4_999, &tiers).map(|t| t.name.as_str()),
            Some("silver")
        );
        assert_eq!(
            tier_for(25_000, &tiers).map(|t| t.name.as_str()),
            Some("platinum")
        );
        assert_eq!(tier_for(-5, &tiers), None);
    }

    #[test]
    fn expiry_is_first_in_first_out() {
        // 1,000 came due; 600 were spent: 400 expire.
        assert_eq!(expirable(1_000, 600, 0), 400);
        // Spending more than came due leaves nothing to expire.
        assert_eq!(expirable(1_000, 1_500, 0), 0);
        // A second run expires nothing more.
        assert_eq!(expirable(1_000, 600, 400), 0);
    }

    #[test]
    fn one_point_per_whole_unit() {
        assert_eq!(points_for(149.99), 149);
        assert_eq!(points_for(-3.0), 0);
        assert_eq!(points_for(f64::NAN), 0);
    }
}

//! F6-T3: a confirmed order split into fulfilment orders, one per
//! ship-from location and delivery group.
//!
//! [`sweep`] reads the change feed with its own cursor ([`CONSUMER`]) after
//! the order's writes committed; for each order now `confirmed` it runs
//! [`split_order`], then advances the cursor. A split runs in one
//! transaction under `pg_try_advisory_xact_lock(38, hashtext(
//! 'attome-fulfilment/split:<order>'))` and writes nothing when the order
//! already has fulfilment orders, so a rerun or a second node is harmless.
//!
//! The ship-from location is the setting `fulfilment.default_location_id`,
//! else the deployment's only live `stock_location`; with neither, the order
//! is left unsplit and a warning names it (sourcing across locations, F6-T4,
//! takes over once order lines carry what it needs). Order lines carry no
//! delivery group yet, so each location's lines are one group. A line with
//! a product is `goods`; one without is `service`, routed rather than
//! shipped (F6-T12).

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_types::AppError;
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-fulfilment/split";
/// The setting naming the default ship-from location.
pub const DEFAULT_LOCATION_SETTING: &str = "fulfilment.default_location_id";
/// The job's name.
pub const JOB: &str = "fulfilment_split";
/// Change events read per sweep.
const BATCH: i64 = 500;

/// One order line to place.
#[derive(Debug, Clone, PartialEq)]
pub struct OrderLine {
    pub id: Uuid,
    pub product: Option<Uuid>,
    pub quantity: f64,
    pub delivery_group: Option<String>,
}

/// One fulfilment order to write: its location and group, and its lines
/// with their kind.
#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub location: Uuid,
    pub delivery_group: Option<String>,
    pub lines: Vec<(OrderLine, &'static str)>,
}

/// A line's kind: `goods` with a product, else `service`. Pure.
pub fn line_kind(line: &OrderLine) -> &'static str {
    if line.product.is_some() {
        "goods"
    } else {
        "service"
    }
}

/// The fulfilment orders for `lines` shipped from `location`, one per
/// delivery group, in group order; lines with no quantity are left out.
/// Pure.
pub fn groups(lines: &[OrderLine], location: Uuid) -> Vec<Group> {
    let mut by_group: BTreeMap<Option<String>, Vec<(OrderLine, &'static str)>> = BTreeMap::new();
    for line in lines.iter().filter(|l| l.quantity > 0.0) {
        by_group
            .entry(line.delivery_group.clone())
            .or_default()
            .push((line.clone(), line_kind(line)));
    }
    by_group
        .into_iter()
        .map(|(delivery_group, lines)| Group {
            location,
            delivery_group,
            lines,
        })
        .collect()
}

async fn default_location(state: &EngineState) -> Result<Option<Uuid>, AppError> {
    let configured = attome_core::setting_registry()
        .get(DEFAULT_LOCATION_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok()));
    if configured.is_some() {
        return Ok(configured);
    }
    let live: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM stock_location WHERE (is_active IS NULL OR is_active = true) LIMIT 2",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok((live.len() == 1).then(|| live[0]))
}

/// Splits one confirmed order; returns how many fulfilment orders it wrote
/// (none when they exist, the order is gone, or no location is known).
pub async fn split_order(state: &EngineState, order: Uuid) -> Result<usize, AppError> {
    let Some(location) = default_location(state).await? else {
        tracing::warn!(%order, "fulfilment split: no ship-from location; set fulfilment.default_location_id");
        return Ok(0);
    };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-fulfilment/split:{order}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(0);
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM fulfilment_order \
                         WHERE order_ref = $1 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(order)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if exists {
        return Ok(0);
    }
    let owner: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT owner_ref FROM \"order\" WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(order)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(owner) = owner else {
        return Ok(0);
    };
    let rows: Vec<(Uuid, Option<Uuid>, Option<f64>)> = sqlx::query_as(
        "SELECT id, product_ref, quantity::float8 FROM order_line \
          WHERE order_ref = $1 AND (is_active IS NULL OR is_active = true) ORDER BY id",
    )
    .bind(order)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let lines: Vec<OrderLine> = rows
        .into_iter()
        .map(|(id, product, quantity)| OrderLine {
            id,
            product,
            quantity: quantity.unwrap_or(1.0),
            delivery_group: None,
        })
        .collect();
    let planned = groups(&lines, location);
    for group in &planned {
        let fulfilment_order = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO fulfilment_order (id, order_ref, location_ref, delivery_group, status, \
                 ship_policy, created_by, owner_ref) \
             VALUES ($1, $2, $3, $4, 'draft', 'ship_as_available', $5, $5)",
        )
        .bind(fulfilment_order)
        .bind(order)
        .bind(group.location)
        .bind(&group.delivery_group)
        .bind(owner)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        change_feed::emit_tx(
            &mut tx,
            "fulfilment_order",
            fulfilment_order,
            ChangeOperation::Create,
        )
        .await?;
        for (line, kind) in &group.lines {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO fulfilment_order_line (id, fulfilment_order_ref, order_line_ref, \
                     product_ref, quantity, quantity_shipped, quantity_delivered, \
                     quantity_backordered, line_kind, created_by, owner_ref) \
                 VALUES ($1, $2, $3, $4, $5, 0, 0, 0, $6, $7, $7)",
            )
            .bind(id)
            .bind(fulfilment_order)
            .bind(line.id.to_string())
            .bind(line.product)
            .bind(line.quantity)
            .bind(kind)
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            change_feed::emit_tx(
                &mut tx,
                "fulfilment_order_line",
                id,
                ChangeOperation::Create,
            )
            .await?;
        }
    }
    attome_db::tx::commit(tx).await?;
    Ok(planned.len())
}

/// Splits every order confirmed since the last sweep; returns how many
/// fulfilment orders were written.
pub async fn sweep(state: &EngineState) -> Result<usize, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let mut written = 0;
    let mut seen = std::collections::HashSet::new();
    for e in &events {
        if e.entity_logicalname != "order"
            || !matches!(
                e.operation(),
                Some(ChangeOperation::Create | ChangeOperation::Update)
            )
            || !seen.insert(e.record_id)
        {
            continue;
        }
        let status: Option<Option<String>> = sqlx::query_scalar(
            "SELECT status::text FROM \"order\" \
              WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(e.record_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if status.flatten().as_deref() == Some("confirmed") {
            written += split_order(state, e.record_id).await?;
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(product: bool, quantity: f64, group: Option<&str>) -> OrderLine {
        OrderLine {
            id: Uuid::now_v7(),
            product: product.then(Uuid::now_v7),
            quantity,
            delivery_group: group.map(str::to_owned),
        }
    }

    #[test]
    fn split_one_per_location_and_group() {
        let location = Uuid::now_v7();
        let lines = [
            line(true, 2.0, None),
            line(false, 1.0, None),
            line(true, 5.0, Some("express")),
            line(true, 0.0, None),
        ];
        let planned = groups(&lines, location);
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].delivery_group, None);
        assert_eq!(
            planned[0].lines.len(),
            2,
            "the zero-quantity line is left out"
        );
        assert_eq!(planned[0].lines[1].1, "service");
        assert_eq!(planned[1].delivery_group.as_deref(), Some("express"));
        assert!(planned.iter().all(|g| g.location == location));
        assert!(groups(&[], location).is_empty());
    }
}
